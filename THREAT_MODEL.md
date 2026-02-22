# Threat Model - SecureShare

This document outlines the security assumptions, trust boundaries, and threat mitigations for the SecureShare application.

## 1. Assets to Protect
- **Secret Content**: The primary payload (passwords, notes, keys).
- **Access Passwords**: The optional secondary layer of protection.
- **System Availability**: Protection against DDoS and resource exhaustion.

## 2. Trust Boundaries
- **Client Browser**: Trusted to perform encryption and handle the decryption key.
- **Network**: Untrusted. Assumed to be subject to eavesdropping (mitigated by HTTPS and E2EE).
- **Server**: Partially trusted. Trusted to store encrypted blobs and enforce TTL/view limits, but NOT trusted with the decryption key.

## 3. Threat Actors & Mitigations

### A. Network Eavesdropper (Man-in-the-Middle)
- **Threat**: Intercepting data in transit.
- **Mitigation**: Mandatory HTTPS (TLS 1.2+), HSTS, and End-to-End Encryption.

### B. Malicious Server Administrator / Compromised Server
- **Threat**: Accessing the database to read secrets.
- **Mitigation**: Zero-Knowledge Architecture. The server never receives the decryption key (stored in URL fragment `#`). Ciphertexts are useless without the key.

### C. Brute-Force Attacker
- **Threat**: Guessing the access password for a known secret ID.
- **Mitigation**: 
    - Server-side rate limiting (IP-based).
    - **Burn-on-Fail Policy**: The secret is permanently deleted after 3 failed password attempts.
    - PBKDF2 with 100,000 iterations for key derivation.

### D. Link Enumerator / Scraper
- **Threat**: Guessing secret IDs to find valid secrets.
- **Mitigation**: 
    - UUID v4 for secret IDs (virtually impossible to guess).
    - Opaque error messages (404 for both non-existent and expired secrets).

### E. Cross-Site Scripting (XSS)
- **Threat**: Injecting malicious scripts to steal the decryption key from the URL fragment.
- **Mitigation**: 
    - Strict Content Security Policy (CSP) with Nonce-based script execution.
    - No `unsafe-inline` or `unsafe-eval` allowed.

## 4. What we do NOT guarantee
- **Endpoint Security**: We cannot protect against keyloggers, screen scrapers, or compromised browsers on the user's device.
- **Social Engineering**: We cannot prevent a user from sharing a link with the wrong person.
- **Recipient Trust**: Once a recipient decrypts the secret, they can copy or screenshot it.
