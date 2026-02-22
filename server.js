"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var express_1 = require("express");
var better_sqlite3_1 = require("better-sqlite3");
var uuid_1 = require("uuid");
var path_1 = require("path");
var fs_1 = require("fs");
var helmet_1 = require("helmet");
var express_rate_limit_1 = require("express-rate-limit");
var cors_1 = require("cors");
var zod_1 = require("zod");
var crypto_1 = require("crypto");
var ejs_1 = require("ejs");
/**
 * DATABASE INITIALIZATION
 * We use SQLite for lightweight, persistent storage.
 * The database stores encrypted blobs, expiration dates, and view limits.
 */
var getDatabase = function () {
    var dbPath = process.env.DB_PATH || path_1.default.join(process.cwd(), "secrets.db");
    try {
        return new better_sqlite3_1.default(dbPath);
    }
    catch (err) {
        // Fallback to /tmp for environments with read-only filesystems (like some Cloud Run setups)
        console.error("Failed to open database at ".concat(dbPath, ", trying /tmp/secrets.db"));
        return new better_sqlite3_1.default("/tmp/secrets.db");
    }
};
var db = getDatabase();
/**
 * SCHEMA DEFINITION
 * - encrypted_data: The AES-encrypted payload (client-side encrypted).
 * - password_hash: SHA-256 hash of the user password + salt (optional).
 * - salt: Random salt used for password hashing (optional).
 * - view_limit: Max number of times the secret can be opened.
 * - failed_attempts: Counter for brute-force protection on password-protected secrets.
 */
db.exec("\n  CREATE TABLE IF NOT EXISTS secrets (\n    id TEXT PRIMARY KEY,\n    encrypted_data TEXT NOT NULL,\n    password_hash TEXT,\n    salt TEXT,\n    expires_at DATETIME NOT NULL,\n    view_limit INTEGER DEFAULT 1,\n    view_count INTEGER DEFAULT 0,\n    failed_attempts INTEGER DEFAULT 0,\n    created_at DATETIME DEFAULT CURRENT_TIMESTAMP\n  )\n");
// Add index for TTL cleanup performance
db.exec("CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at)");
// Apply migrations for older database versions
try {
    db.exec("ALTER TABLE secrets ADD COLUMN salt TEXT");
}
catch (e) { }
try {
    db.exec("ALTER TABLE secrets ADD COLUMN failed_attempts INTEGER DEFAULT 0");
}
catch (e) { }
/**
 * INPUT VALIDATION
 * Using Zod to ensure all incoming data matches expected formats and sizes.
 */
var CreateSecretSchema = zod_1.z.object({
    encryptedData: zod_1.z.string().min(1).max(1024 * 1024), // Max 1MB payload
    passwordHash: zod_1.z.string().nullable().optional(),
    salt: zod_1.z.string().nullable().optional(),
    expirationHours: zod_1.z.union([zod_1.z.string(), zod_1.z.number()]).transform(function (v) { return Number(v); }),
    viewLimit: zod_1.z.union([zod_1.z.string(), zod_1.z.number()]).transform(function (v) { return Number(v); }),
});
var BurnSecretSchema = zod_1.z.object({
    passwordHash: zod_1.z.string().nullable().optional(),
});
function startServer() {
    return __awaiter(this, void 0, void 0, function () {
        var app, PORT, allowedOrigin, globalLimiter, createLimiter, authLimiter, isProd, createViteServer, vite_1, distPath_1;
        var _this = this;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    app = (0, express_1.default)();
                    PORT = 3000;
                    // Trust proxy is required for rate limiting and secure cookies to work behind Nginx/Cloud Run
                    app.set('trust proxy', 1);
                    // Generate a nonce for each request
                    app.use(function (req, res, next) {
                        res.locals.nonce = crypto_1.default.randomBytes(16).toString('hex');
                        next();
                    });
                    /**
                     * PRODUCTION SECURITY MIDDLEWARE
                     * Strict security headers for the standalone production environment.
                     */
                    app.use((0, helmet_1.default)({
                        contentSecurityPolicy: {
                            directives: {
                                defaultSrc: ["'self'"],
                                scriptSrc: ["'self'", function (req, res) { return "'nonce-".concat(res.locals.nonce, "'"); }],
                                styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                                fontSrc: ["'self'", "https://fonts.gstatic.com"],
                                imgSrc: ["'self'", "data:", "https://picsum.photos", "blob:", "https://*.aistudio.google.com"],
                                connectSrc: ["'self'", "https://*", "wss://*"],
                                frameAncestors: ["'self'", "https://*.google.com", "https://*.run.app", "https://*.aistudio.google.com"],
                            },
                        },
                        hsts: {
                            maxAge: 31536000,
                            includeSubDomains: true,
                            preload: true,
                        },
                        referrerPolicy: { policy: "strict-origin-when-cross-origin" },
                        noSniff: true,
                        crossOriginEmbedderPolicy: false,
                        frameguard: false, // Handled by CSP frame-ancestors
                    }));
                    // Add the Permissions-Policy header manually
                    app.use(function (req, res, next) {
                        res.setHeader('Permissions-Policy', 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()');
                        next();
                    });
                    allowedOrigin = process.env.APP_URL || true;
                    app.use((0, cors_1.default)({
                        origin: allowedOrigin,
                        methods: ["GET", "POST"],
                        credentials: true
                    }));
                    app.use(express_1.default.json({ limit: '1.1mb' }));
                    globalLimiter = (0, express_rate_limit_1.default)({
                        windowMs: 15 * 60 * 1000,
                        max: 2500, // Increased from 300 to allow security scanners
                        standardHeaders: true,
                        legacyHeaders: false,
                        message: { error: "Too many requests from this IP, please try again later." }
                    });
                    app.use(globalLimiter);
                    createLimiter = (0, express_rate_limit_1.default)({
                        windowMs: 60 * 60 * 1000,
                        max: 100, // Increased from 10 for better usability and testing
                        message: { error: "Creation limit reached. Please try again later." }
                    });
                    authLimiter = (0, express_rate_limit_1.default)({
                        windowMs: 15 * 60 * 1000,
                        max: 20, // Increased from 5 to allow for more testing attempts
                        skipSuccessfulRequests: true,
                        message: { error: "Too many failed attempts. Please wait 15 minutes." }
                    });
                    /**
                     * API ENDPOINTS
                     */
                    // Create a new secret
                    app.post("/api/secrets", createLimiter, function (req, res) {
                        var result = CreateSecretSchema.safeParse(req.body);
                        if (!result.success) {
                            return res.status(400).json({ error: "Invalid input data", details: result.error.format() });
                        }
                        var _a = result.data, encryptedData = _a.encryptedData, passwordHash = _a.passwordHash, salt = _a.salt, expirationHours = _a.expirationHours, viewLimit = _a.viewLimit;
                        // Enforce limits
                        if (expirationHours < 1 || expirationHours > 168) {
                            return res.status(400).json({ error: "Expiration must be between 1 and 168 hours" });
                        }
                        if (viewLimit < 1 || viewLimit > 10) {
                            return res.status(400).json({ error: "View limit must be between 1 and 10" });
                        }
                        var id = (0, uuid_1.v4)();
                        var expiresAt = new Date(Date.now() + expirationHours * 60 * 60 * 1000).toISOString();
                        try {
                            var stmt = db.prepare("\n        INSERT INTO secrets (id, encrypted_data, password_hash, salt, expires_at, view_limit)\n        VALUES (?, ?, ?, ?, ?, ?)\n      ");
                            stmt.run(id, encryptedData, passwordHash || null, salt || null, expiresAt, viewLimit);
                            res.json({ id: id });
                        }
                        catch (error) {
                            console.error("Database error:", error);
                            res.status(500).json({ error: "Internal server error" });
                        }
                    });
                    // Fetch secret metadata (encrypted blob + salt)
                    app.get("/api/secrets/:id", function (req, res) {
                        var id = req.params.id;
                        try {
                            var secret = db.prepare("SELECT * FROM secrets WHERE id = ?").get(id);
                            // Opaque response for non-existent or expired secrets to prevent enumeration
                            if (!secret || new Date(secret.expires_at) < new Date()) {
                                if (secret && new Date(secret.expires_at) < new Date()) {
                                    db.prepare("DELETE FROM secrets WHERE id = ?").run(id);
                                }
                                return res.status(404).json({ error: "Secret not found or expired" });
                            }
                            res.json({
                                encryptedData: secret.encrypted_data,
                                hasPassword: !!secret.password_hash,
                                salt: secret.salt
                            });
                        }
                        catch (error) {
                            res.status(500).json({ error: "Internal server error" });
                        }
                    });
                    // Verify access and "burn" the secret (increment view count or delete)
                    app.post("/api/secrets/:id/burn", authLimiter, function (req, res) {
                        var id = req.params.id;
                        var result = BurnSecretSchema.safeParse(req.body);
                        if (!result.success) {
                            return res.status(400).json({ error: "Invalid input data" });
                        }
                        var passwordHash = result.data.passwordHash;
                        try {
                            var secret = db.prepare("SELECT * FROM secrets WHERE id = ?").get(id);
                            if (!secret)
                                return res.status(404).json({ error: "Not found" });
                            /**
                             * BRUTE-FORCE PROTECTION
                             * If a password is set, we verify the hash.
                             * After 3 failed attempts, the secret is PERMANENTLY DELETED.
                             */
                            if (secret.password_hash) {
                                if (!passwordHash || passwordHash !== secret.password_hash) {
                                    var newFailedAttempts = (secret.failed_attempts || 0) + 1;
                                    var MAX_ATTEMPTS = 3;
                                    if (newFailedAttempts >= MAX_ATTEMPTS) {
                                        db.prepare("DELETE FROM secrets WHERE id = ?").run(id);
                                        console.log("[Security] Secret ".concat(id, " burned after ").concat(MAX_ATTEMPTS, " failed attempts."));
                                        return res.status(401).json({ error: "Too many failed attempts. Secret has been permanently deleted." });
                                    }
                                    else {
                                        db.prepare("UPDATE secrets SET failed_attempts = ? WHERE id = ?").run(newFailedAttempts, id);
                                        return res.status(401).json({
                                            error: "Invalid password. ".concat(MAX_ATTEMPTS - newFailedAttempts, " attempts remaining before permanent deletion.")
                                        });
                                    }
                                }
                            }
                            /**
                             * VIEW LIMIT LOGIC
                             * Increment view count. If limit reached, delete the secret.
                             */
                            var newCount = secret.view_count + 1;
                            var isBurned = newCount >= secret.view_limit;
                            var remaining = Math.max(0, secret.view_limit - newCount);
                            if (isBurned) {
                                db.prepare("DELETE FROM secrets WHERE id = ?").run(id);
                                console.log("[ViewLimit] Secret ".concat(id, " deleted after reaching view limit (").concat(secret.view_limit, ")."));
                            }
                            else {
                                db.prepare("UPDATE secrets SET view_count = ? WHERE id = ?").run(newCount, id);
                            }
                            res.json({
                                success: true,
                                burned: isBurned,
                                remaining: remaining
                            });
                        }
                        catch (error) {
                            res.status(500).json({ error: "Internal server error" });
                        }
                    });
                    /**
                     * PERIODIC CLEANUP
                     * Deletes expired secrets from the database every 5 minutes.
                     */
                    setInterval(function () {
                        try {
                            var now = new Date().toISOString();
                            var result = db.prepare("DELETE FROM secrets WHERE expires_at < ?").run(now);
                            if (result.changes > 0) {
                                console.log("[Cleanup] Deleted ".concat(result.changes, " expired secrets."));
                            }
                        }
                        catch (error) {
                            console.error("[Cleanup] Error cleaning up expired secrets:", error);
                        }
                    }, 5 * 60 * 1000);
                    isProd = process.env.NODE_ENV === "production";
                    if (!!isProd) return [3 /*break*/, 3];
                    return [4 /*yield*/, Promise.resolve().then(function () { return require("vite"); })];
                case 1:
                    createViteServer = (_a.sent()).createServer;
                    return [4 /*yield*/, createViteServer({
                            server: { middlewareMode: true },
                            appType: "spa",
                        })];
                case 2:
                    vite_1 = _a.sent();
                    app.use(vite_1.middlewares);
                    app.get('*', function (req, res, next) { return __awaiter(_this, void 0, void 0, function () {
                        var url, template, renderedHtml, e_1;
                        return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0:
                                    _a.trys.push([0, 2, , 3]);
                                    url = req.originalUrl;
                                    return [4 /*yield*/, vite_1.transformIndexHtml(url, fs_1.default.readFileSync(path_1.default.resolve(process.cwd(), 'index.html'), 'utf-8'))];
                                case 1:
                                    template = _a.sent();
                                    renderedHtml = ejs_1.default.render(template, { nonce: res.locals.nonce });
                                    res.status(200).set({ 'Content-Type': 'text/html' }).end(renderedHtml);
                                    return [3 /*break*/, 3];
                                case 2:
                                    e_1 = _a.sent();
                                    vite_1.ssrFixStacktrace(e_1);
                                    next(e_1);
                                    return [3 /*break*/, 3];
                                case 3: return [2 /*return*/];
                            }
                        });
                    }); });
                    return [3 /*break*/, 4];
                case 3:
                    distPath_1 = path_1.default.resolve(process.cwd(), "dist");
                    if (fs_1.default.existsSync(distPath_1)) {
                        app.engine('html', ejs_1.default.renderFile);
                        app.set('view engine', 'html');
                        app.set('views', distPath_1);
                        app.use(express_1.default.static(distPath_1));
                        app.get("*", function (req, res) {
                            res.render(path_1.default.resolve(distPath_1, "index.html"), { nonce: res.locals.nonce });
                        });
                    }
                    else {
                        console.warn("Production build 'dist' folder not found. Static files will not be served.");
                    }
                    _a.label = 4;
                case 4:
                    // Security.txt implementation (RFC 9116)
                    app.get(["/.well-known/security.txt", "/security.txt"], function (req, res) {
                        var securityTxt = "Contact: mailto:security@".concat(req.hostname, "\nExpires: ").concat(new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), "\nPreferred-Languages: en, pl\nCanonical: https://").concat(req.hostname, "/.well-known/security.txt\nPolicy: https://").concat(req.hostname, "/security-policy\n");
                        res.type('text/plain').send(securityTxt);
                    });
                    app.listen(PORT, "0.0.0.0", function () {
                        console.log("Server running on http://localhost:".concat(PORT));
                    });
                    return [2 /*return*/];
            }
        });
    });
}
startServer();
