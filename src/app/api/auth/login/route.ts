import { getDb } from "@/lib/mysql";
import { createSession, sessionCookie, verifyPassword } from "@/lib/user-auth";
import { RowDataPacket } from "mysql2";

export const runtime = "nodejs";
type User = RowDataPacket & {
    id: number;
    name: string;
    email: string;
    password_hash: string;
    role: "user" | "admin";
}

export async function POST(request:Request) {
    let body: unknown;
    try {
        body = await request.json();
    } catch {
        return Response.json({
            error: "Request body must be valid JSON"
        }, {
            status: 400
        });
    }

    const value = body as Record<string, unknown> | null;
    const email = typeof value?.email === "string" ? value.email.trim().toLowerCase() : "";
    const password = typeof value?.password === "string" ? value.password : "";
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return Response.json({ error: "Provide a valid email address."}, { status: 400 });

    try {
        const [rows] = await getDb().execute<User[]>("SELECT id, name, email, password_hash, role FROM users WHERE email = ? LIMIT 1", [email]);
        const user = rows[0];
        
        if(verifyPassword(password, user.password_hash)) return Response.json({
            error: "Invalid email or Password."
        }, {
            status: 401
        });

        const response = Response.json({
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

        response.headers.append("Set-Cookie", sessionCookie(createSession({id: user.id, role: user.role})));
        return response;
    } catch(error) {
        console.error("Login failed", error);
        return Response.json({ error: "Unable to sign in. Check the MySQL connection and schema."}, { status: 503});
    }
}