# SecureShare - Enterprise-Grade Encrypted Secret Sharing

SecureShare is a high-security, end-to-end encrypted platform for sharing sensitive information like passwords, API keys, and private notes. It is designed with a "Zero-Knowledge" architecture, meaning the server never sees the raw secret or the master password.

## 🛡️ Security Architecture

### 1. End-to-End Encryption (E2EE)
- **Client-Side Encryption**: All encryption happens in the browser using the `crypto-js` library.
- **Algorithm**: AES-256.
- **Key Derivation**: SHA-256 based derivation with a unique salt for each secret.
- **Zero-Knowledge**: The decryption key is part of the URL fragment (`#`), which is never sent to the server.

### 2. Brute-Force Protection
- **Burn-on-Fail Policy**: Secrets protected by an access password are permanently deleted after **3 failed attempts**.
- **Rate Limiting**: 
    - Global protection against DDoS.
    - Limits on secret creation (100/hour per IP).
    - Limits on authentication attempts.

### 3. Ephemeral Storage
- **One-Time Links**: Secrets are automatically deleted after a configurable view limit (default: 1).
- **Remaining Views**: The recipient is informed how many views are left before the secret is destroyed.
- **Auto-Expiration**: Secrets are purged from the database after a set time (1h, 24h, or 7 days).
- **Periodic Cleanup**: A background worker ensures expired data is wiped every 5 minutes.

### 4. Infrastructure Security
- **Secure Headers**: Powered by `helmet` (CSP with Nonce, HSTS, XSS protection).
- **Permissions Policy**: Restricts browser features (camera, microphone, etc.).
- **Input Validation**: Strict schema validation using `zod`.
- **Proxy Trust**: Configured to work securely behind reverse proxies (Nginx, Traefik, Cloudflare).
- **Hardening**: It is recommended to set filesystem permissions for the database file to `600` and ensure the server runs under a non-privileged user.

## 🛡️ Threat Model
For a detailed analysis of security assumptions and mitigations, see [THREAT_MODEL.md](./THREAT_MODEL.md).

## 🚀 Deployment

### Docker (Recommended)
The easiest way to deploy SecureShare is using Docker.

```bash
# Build the image
docker build -t secureshare .

# Run the container
docker run -d \
  -p 3000:3000 \
  -v $(pwd)/data:/app/data \
  -e DB_PATH=/app/data/secrets.db \
  -e APP_URL=https://your-domain.com \
  -e NODE_ENV=production \
  secureshare
```

### Manual Production Build
1. Install dependencies: `npm install`
2. Build the frontend: `npm run build`
3. Start the server: `NODE_ENV=production npm start`

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Port to listen on | `3000` |
| `DB_PATH` | Path to SQLite database file | `secrets.db` |
| `APP_URL` | Your public domain (used for CORS and links) | `http://localhost:3000` |
| `NODE_ENV` | Environment (`production` / `development`) | `development` |

## 🛠️ Technology Stack
- **Frontend**: React, Tailwind CSS, Lucide Icons, Framer Motion.
- **Backend**: Node.js, Express, Better-SQLite3.
- **Security**: Crypto-JS, Zod, Helmet, Express-Rate-Limit.
