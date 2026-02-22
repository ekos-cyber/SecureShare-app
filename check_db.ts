import Database from "better-sqlite3";
const db = new Database("secrets.db");
const info = db.prepare("PRAGMA table_info(secrets)").all();
console.log(info);
