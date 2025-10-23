import crypto from "crypto";
import nodemailer from "nodemailer";
import db from "../db";
import { User, UserRow } from "../types/user";
import jwtUtils from "../utils/jwt";
import ejs from "ejs";
import bcrypt from "bcrypt"; //encontramos esta librería para hacer un hash de las contraseñas


const RESET_TTL = 1000 * 60 * 60; // 1h
const INVITE_TTL = 1000 * 60 * 60 * 24 * 7; // 7d

function buildActivationUrl(token: string, username: string) {
  const raw = process.env.FRONTEND_URL || "";
  const clean = raw.replace(/^['"]|['"]$/g, "");

  if (!clean) throw new Error("FRONTEND_URL not set on server");
  if (!/^https?:\/\//i.test(clean))
    throw new Error(`FRONTEND_URL must start with http(s). Got: ${clean}`);

  const base = new URL(clean);
  const url = new URL("/activate-user", base);
  url.search = new URLSearchParams({ token, username }).toString();
  return url.toString();
}

class AuthService {
  static async createUser(user: User) {
    const existing = await db<UserRow>("users")
      .where({ username: user.username })
      .orWhere({ email: user.email })
      .first();
    if (existing)
      throw new Error("User already exists with that username or email");

    const validateInput = (
      input: string,
      fieldName: string,
      maxLength: number = 50
    ): string => {
      if (!input || typeof input !== "string") {
        throw new Error(`${fieldName} is required and must be a string`);
      }

      if (input.length > maxLength) {
        throw new Error(`${fieldName} must be ${maxLength} characters or less`);
      }

      return input.trim();
    };

    const firstName = validateInput(user.first_name, "First name");
    const lastName = validateInput(user.last_name, "Last name");
    // create invite token
    const invite_token = crypto.randomBytes(6).toString("hex");
    const invite_token_expires = new Date(Date.now() + INVITE_TTL);
    // hashear la contraseña
    const hashedPassword = await bcrypt.hash(user.password, 10);

    await db<UserRow>("users").insert({
      username: user.username,
      password: hashedPassword, //almacenamos la contraseña hasheada
      email: user.email,
      first_name: firstName,
      last_name: lastName,
      invite_token,
      invite_token_expires,
      activated: false,
    });

    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const activationLink = buildActivationUrl(invite_token, user.username);

    const emailTemplate = `
    <html>
      <body>
        <h1>Hello <%= firstName %> <%= lastName %></h1>
        <p>Click <a href="<%= activationLink %>">here</a> to activate your account.</p>
      </body>
    </html>
  `;

    try {
      const htmlBody = ejs.render(emailTemplate, {
        firstName: firstName,
        lastName: lastName,
        activationLink: activationLink,
      });

      await transporter.sendMail({
        from: "info@example.com",
        to: user.email,
        subject: "Activate your account",
        html: htmlBody,
      });
    } catch (emailError) {
      console.error("Email sending error:", emailError);
      throw new Error("Failed to send activation email");
    }
  }

  static async updateUser(user: User) {
    const existing = await db<UserRow>("users").where({ id: user.id }).first();
    if (!existing) throw new Error("User not found");
    let updateData: any = {
      username: user.username,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
    };
    if (user.password) {
      updateData.password = await bcrypt.hash(user.password, 10);
    } // este cambio es para hashear la nueva contraseña
    await db<UserRow>("users").where({ id: user.id }).update(updateData);
    return existing;
  }

  static async authenticate(username: string, password: string) {
    const user = await db<UserRow>("users")
      .where({ username })
      .andWhere("activated", true)
      .first();
    if (!user) throw new Error("Invalid email or not activated");
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) throw new Error("Invalid password");
    return user;
  }

  static async sendResetPasswordEmail(email: string) {
    const user = await db<UserRow>("users")
      .where({ email })
      .andWhere("activated", true)
      .first();
    if (!user) throw new Error("No user with that email or not activated");

    const token = crypto.randomBytes(6).toString("hex");
    const expires = new Date(Date.now() + RESET_TTL);

    await db("users").where({ id: user.id }).update({
      reset_password_token: token,
      reset_password_expires: expires,
    });

    // send email with reset link using nodemailer and local SMTP server
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || "587"),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await transporter.sendMail({
      to: user.email,
      subject: "Your password reset link",
      html: `Click <a href="${link}">here</a> to reset your password.`,
    });
  }

  static async resetPassword(token: string, newPassword: string) {
    const row = await db<UserRow>("users")
      .where("reset_password_token", token)
      .andWhere("reset_password_expires", ">", new Date())
      .first();
    if (!row) throw new Error("Invalid or expired reset token");
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db("users").where({ id: row.id }).update({
      password: hashedPassword,
      reset_password_token: null,
      reset_password_expires: null,
    });
  }

  static async setPassword(token: string, newPassword: string) {
    const row = await db<UserRow>("users")
      .where("invite_token", token)
      .andWhere("invite_token_expires", ">", new Date())
      .first();
    if (!row) throw new Error("Invalid or expired invite token");
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db("users")
      .update({
        password: hashedPassword,
        invite_token: null,
        invite_token_expires: null,
        activated: true
      })
      .where({ id: row.id });
  }

  static generateJwt(userId: string): string {
    return jwtUtils.generateToken(userId);
  }
}

export default AuthService;
