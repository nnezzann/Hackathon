import bcrypt from "bcrypt";
import crypto from "crypto";
import createDebug from "debug";
import User from "../models/User.js";
import { env } from "../config/env.js";
import { emailTokenCookieOptions } from "../utils/cookies.js";
import { signEmailToken, verifyEmailToken } from "../services/tokenService.js";
import {
  getDefaultSenderAddress,
  sendEmail,
} from "../services/emailService.js";

const debug = createDebug("app:password");

export const changePassword = async (req, res) => {
  try {
    const { email } = req.body || {};

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    const normalizedEmail = String(email).toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const passToken = crypto
      .randomInt(0, 100000000)
      .toString()
      .padStart(8, "0");
    const hashedToken = crypto
      .createHash("sha256")
      .update(passToken)
      .digest("hex");

    user.passToken = hashedToken;
    user.passVerified = false;
    user.passExpiresAt = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    const emailToken = signEmailToken(
      { userId: user._id, email: user.email, passToken: hashedToken },
      "10m",
    );

    res.cookie("emailToken", emailToken, {
      ...emailTokenCookieOptions,
      maxAge: 10 * 60 * 1000,
    });

    const sent = await sendEmail({
      from: getDefaultSenderAddress(),
      to: normalizedEmail,
      subject: "FlowBot password reset code",
      text: `Your reset code is ${passToken}. It expires in 10 minutes.`,
      html: `<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #f0f2f5; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
  <tr>
    <td align="center" style="padding: 40px 16px;">
      <table cellpadding="0" cellspacing="0" role="presentation" style="
          background: #ffffff;
          margin: 0 auto;
          max-width: 600px;
          width: 100%;
          border-radius: 12px;
          overflow: hidden;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        ">
        <tr>
          <td style="
              background: linear-gradient(135deg, #001f3f, #003366);
              padding: 30px;
              text-align: center;
              color: #ffffff;
            ">
            <h1 style="
                margin: 0;
                font-size: 22px;
                font-weight: 600;
                letter-spacing: 1px;
                text-transform: uppercase;
              ">
              Password Reset Request
            </h1>
          </td>
        </tr>

        <tr>
          <td style="padding: 40px 30px; text-align: center; background-color: #ffffff;">
            <p style="
                font-size: 16px;
                line-height: 1.6;
                color: #4b5563;
                margin: 0 0 24px;
              ">
              Welcome to <strong>FlowBOT</strong>. Recently you requested to reset your password, please use the verification code below.
            </p>

            <div style="
                display: inline-block;
                padding: 20px 40px;
                margin: 10px 0 25px;
                background-color: #f8fafc;
                border-radius: 8px;
                border: 2px solid #e2e8f0;
              ">
              <span style="
                  font-size: 32px;
                  font-weight: 800;
                  letter-spacing: 8px;
                  color: #001f3f;
                ">
                ${passToken}
              </span>
            </div>

            <p style="font-size: 14px; color: #9ca3af; margin-top: 10px;">
              This unique code is valid for <strong>8 minutes</strong>.
            </p>
          </td>
        </tr>

        <tr>
          <td style="
              background-color: #f1f5f9;
              padding: 24px;
              text-align: center;
              font-size: 13px;
              color: #64748b;
              border-top: 1px solid #e2e8f0;
            ">
            <p style="margin: 0 0 8px; line-height: 1.5;">
              If you did not request this code, please ignore this email or contact support if you have concerns.
            </p>
            <p style="margin: 0; font-weight: 600; color: #001f3f;">© 2026 FlowBot Inc. All rights reserved.</p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>`,
    }).catch((mailError) => {
      debug("changePassword email failed", mailError);
      return false;
    });

    if (sent) {
      return res.status(200).json({
        message: "Password reset code sent to your email",
      });
    }

    if (env.isProduction) {
      user.passToken = null;
      user.passVerified = false;
      user.passExpiresAt = null;
      await user.save();
      res.clearCookie("emailToken", {
        ...emailTokenCookieOptions,
        maxAge: undefined,
      });
      return res.status(500).json({ error: "Email service unavailable" });
    }

    return res.status(200).json({
      message:
        "Email service unavailable in local mode. Use devPassToken to continue.",
      devPassToken: passToken,
    });
  } catch (error) {
    debug("changePassword failed", error);
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const resetCodeVer = async (req, res) => {
  try {
    const { passToken } = req.body || {};
    if (!passToken) {
      return res.status(400).json({ error: "Reset code is required" });
    }

    const emailToken = req.cookies?.emailToken;
    if (!emailToken) {
      return res.status(401).json({ error: "Reset session not found" });
    }

    const decoded = verifyEmailToken(emailToken);
    const user = await User.findById(decoded.userId);

    if (!user || user.email !== decoded.email) {
      return res.status(404).json({ error: "User not found" });
    }

    if (
      !user.passToken ||
      !user.passExpiresAt ||
      user.passExpiresAt < new Date()
    ) {
      return res.status(401).json({ error: "Reset code expired" });
    }

    const hashedPassToken = crypto
      .createHash("sha256")
      .update(String(passToken).trim())
      .digest("hex");

    if (
      hashedPassToken !== user.passToken ||
      hashedPassToken !== decoded.passToken
    ) {
      return res.status(401).json({ error: "Invalid reset code" });
    }

    user.passVerified = true;
    await user.save();

    return res.status(200).json({
      message: "Code verified successfully. You can now reset your password.",
    });
  } catch (error) {
    if (error?.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Reset session expired" });
    }

    debug("resetCodeVer failed", error);
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { pass, confirm } = req.body || {};
    const emailToken = req.cookies?.emailToken;

    if (!emailToken) {
      return res.status(401).json({ error: "Reset session not found" });
    }

    if (!pass || !confirm) {
      return res
        .status(400)
        .json({ error: "New password and confirmation are required" });
    }

    if (pass !== confirm || String(pass).length < 8) {
      return res.status(400).json({
        error: "Password must match confirmation and be at least 8 characters",
      });
    }

    const decoded = verifyEmailToken(emailToken);
    const user = await User.findById(decoded.userId);

    if (!user || user.email !== decoded.email) {
      return res.status(404).json({ error: "User not found" });
    }

    if (
      !user.passVerified ||
      !user.passToken ||
      user.passToken !== decoded.passToken
    ) {
      return res
        .status(401)
        .json({ error: "Reset code verification required" });
    }

    if (!user.passExpiresAt || user.passExpiresAt < new Date()) {
      return res.status(401).json({ error: "Reset session expired" });
    }

    user.password = await bcrypt.hash(String(pass), 10);
    user.passVerified = false;
    user.passToken = null;
    user.passExpiresAt = null;
    await user.save();

    res.clearCookie("emailToken", {
      ...emailTokenCookieOptions,
      maxAge: undefined,
    });

    return res.status(200).json({
      message: "Password reset successfully",
    });
  } catch (error) {
    if (error?.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Reset session expired" });
    }

    debug("resetPassword failed", error);
    return res.status(500).json({ error: "Internal server error" });
  }
};

export const changePasswordAuthenticated = async (req, res) => {
  try {
    const user = req.user;
    const { currentPassword, newPassword, confirmPassword } = req.body || {};

    if (!user?._id) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!currentPassword || !newPassword || !confirmPassword) {
      return res.status(400).json({
        error: "currentPassword, newPassword and confirmPassword are required",
      });
    }

    if (String(newPassword).length < 8) {
      return res.status(400).json({
        error: "New password must be at least 8 characters",
      });
    }

    if (String(newPassword) !== String(confirmPassword)) {
      return res.status(400).json({
        error: "New password and confirmation do not match",
      });
    }

    const passwordMatches = await bcrypt.compare(
      String(currentPassword),
      user.password,
    );

    if (!passwordMatches) {
      return res.status(401).json({ error: "Current password is incorrect" });
    }

    user.password = await bcrypt.hash(String(newPassword), 10);
    await user.save();

    return res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    debug("changePasswordAuthenticated failed", error);
    return res.status(500).json({ error: "Internal server error" });
  }
};
