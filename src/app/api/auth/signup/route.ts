import { getDb } from "@/lib/mysql";
import { createSession, hashPassword, sessionCookie } from "@/lib/user-auth";
import { ResultSetHeader } from "mysql2";

export const runtime = "nodejs";

/**
 * Method -> GET/POST/PUT/DELETE
 */

export async function POST(request: Request) {
    let body: unknown;

    try {
        body= await request.json();
    } catch {
        return Response.json({ error: "Request body must be valid JSON"}, { status: 400 });
    }

    const value = body as Record<string, unknown> | null;
    const name = typeof value?.name === "string" ? value.name.trim() : "";
    const email = typeof value?.email === "string" ? value.email.trim().toLowerCase() : "";
    const password = typeof value?.password === "string" ? value.password : "";

    if(name.length < 2 || name.length > 120) return Response.json({ error: "Name must be 2-120 characters."}, { status: 400 });
    if(email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return Response.json({ error: "Provide a valid email address."}, { status: 400 });

    try {
        const [result] = await getDb().execute<ResultSetHeader>("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", [name, email, hashPassword(password)]);
        const token = createSession({ id: result.insertId, role: "user"});
        const response = Response.json({ user: {
            id: result.insertId,
            name,
            email,
            role: "user"
        }}, { status: 201});
        response.headers.append("Set-Cookie", sessionCookie(token));
        return response;
    } catch(error) {
        if(typeof error === "object" && error && "code" in error && error.code === "ER_DUP_ENTRY") return Response.json({ error: "An account with that email already exists."}, { status: 409 });
        console.error("Signup failed: ", error);
        return Response.json({ error: "Unable to create account. Check the MYSQL connection and schema."}, { status: 503 });
    }
}