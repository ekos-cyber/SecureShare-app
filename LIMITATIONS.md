# ⚠️ Security Limitations & Threat Model

This document outlines the security assumptions, limitations, and intended use cases for SecureShare. **Read this before deploying.**

## ❌ What this app is NOT
1.  **NOT a Password Manager**: Do not use this for long-term storage of credentials.
2.  **NOT a File Storage Service**: Designed for small text secrets (max 1MB), not large files.
3.  **NOT Anonymity Tool**: While we don't log IP addresses in the database, the server logs (Nginx/Cloud Run) might.
4.  **NOT Quantum-Safe**: Uses AES-256-GCM and PBKDF2-SHA256, which are standard today but not quantum-resistant.

## 🛡️ Security Architecture
-   **Client-Side Encryption**: Data is encrypted in the browser using **AES-256-GCM** (Web Crypto API).
-   **Zero-Knowledge Server**: The server never sees the decryption key. The key is part of the URL fragment (`#key`), which is never sent to the server.
-   **Atomic Destruction**: The "burn" operation (delete after read) is performed in a single database transaction to prevent race conditions.
-   **Strict CSP**: Content Security Policy prevents XSS attacks.
-   **HSTS**: Forces HTTPS connections.

## ⚠️ Known Limitations & Risks

### 1. The "Trusting the Server" Problem
Since this is a web application, you must trust the server to serve the correct, uncompromised JavaScript code.
*   **Risk**: A compromised server could serve malicious JS that steals the key or data.
*   **Mitigation**: Use Subresource Integrity (SRI) if possible (hard with dynamic builds), or use the Docker image on your own infrastructure.

### 2. URL History & Proxies
*   **Risk**: If a user copies the full URL (including the `#` fragment) into a tool that syncs history (e.g., browser sync), the key is stored in that history.
*   **Mitigation**: We use `Referrer-Policy: no-referrer` to prevent the URL from leaking to external sites, but we cannot control browser history or local extensions.

### 3. Ephemeral Storage
*   **Risk**: If the server crashes or restarts (in non-persistent environments like basic Cloud Run without volumes), secrets might be lost before they are read.
*   **Mitigation**: Use a persistent volume (SQLite file) or an external database (PostgreSQL) for critical deployments.

### 4. Denial of Service (DoS)
*   **Risk**: An attacker could generate millions of secrets to fill up the disk.
*   **Mitigation**: We implement Rate Limiting (100 creations/hour per IP), but a distributed attack could still be an issue.

## 🔍 Audit Recommendations Implemented
1.  **AES-GCM**: Switched from AES-CBC to AES-GCM for authenticated encryption.
2.  **Atomic Transactions**: Implemented `db.transaction()` for the burn logic to prevent race conditions.
3.  **No-Referrer**: Enforced `Referrer-Policy: no-referrer`.
4.  **Clear Warnings**: UI now explicitly warns about the risks of sharing links in public channels.

## 📝 Intended Use Case
-   Sharing a single password or API token with a colleague.
-   Sending sensitive configuration data that should self-destruct.
-   One-off secure communication where Signal/PGP is not feasible.
