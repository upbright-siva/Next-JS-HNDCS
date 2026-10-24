import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

export const USER_SESSION_COOKIE = "modern_ui_session";
const SESSION_SECONDS = 60 * 60 * 24 * 7;

function authSecret() {
    const secret = process.env.AUTH_SECRET;
    if (!secret || secret.length < 32) throw new Error("AUTH_SECRET must be set to at least 32 characters.");
    return secret;
}

export function hashPassword(password: string) {
    const salt = randomBytes(16).toString("hex");
    const hash = scryptSync(password, salt, 64).toString("hex");
    return `scrypt:${salt}:${hash}`;
}

export function verifyPassword(password: string, stored: string) {
    const [algorithm, salt, hash] = stored.split(":");
    if (algorithm !== "scrypt" || !salt || !hash || !/^[a-f0-9]{128}$/i.test(hash)) return false;
    const actual = scryptSync(password, salt, 64);
    return timingSafeEqual(actual, Buffer.from(hash, "hex"));
}