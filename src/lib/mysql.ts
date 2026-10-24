import mysql, { Pool } from "mysql2/promise";

const globalForMysql = globalThis as typeof globalThis & { mysqlPool?: Pool };

function createPool() {
    const { DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME } = process.env;
    if (!DB_HOST || !DB_USER || !DB_NAME) {
        throw new Error("Set DB_HOST, DB_USER, AND DB_NAME to connect to MYSQL.");
    }

    return mysql.createPool({
        host: DB_HOST,
        port: Number(DB_PORT || 3306),
        user: DB_USER,
        password: DB_PASSWORD || "",
        database: DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        timezone: "Z",
    });
}

export function getDb() {
    const pool = globalForMysql.mysqlPool ?? createPool();
    if (process.env.NODE_ENV !== "production") globalForMysql.mysqlPool = pool;
    return pool;
}