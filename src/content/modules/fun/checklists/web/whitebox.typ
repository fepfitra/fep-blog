#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Whitebox Web Testing Checklist",
    description: "A comprehensive and ordered checklist for whitebox web application security testing.",
    date: "2025-12-26",
    order: 1,
  ),
)<frontmatter>

= Whitebox Web Testing Checklist

This checklist is designed for security auditors and developers performing whitebox testing (source code review and architectural analysis) on web applications.

== 1. Preparation & Architectural Review
- [ ] *Identify Tech Stack*: Document languages, frameworks, libraries, and databases used.
- [ ] *Understand Architecture*: Map out entry points, data flows, trust boundaries, and third-party integrations.
- [ ] *Identify Security Controls*: Locate implementations for AuthN, AuthZ, encryption, and logging.
- [ ] *Review API Documentation*: Examine OpenAPI/Swagger specs for hidden or internal endpoints.
- [ ] *Dependency Audit*: Scan for known vulnerabilities in third-party libraries (e.g., `npm audit`, `snyk`, `cargo audit`).

== 2. Authentication (AuthN)
- [ ] *Mechanism Audit*: Is it using JWT, Session Cookies, OAuth2, or custom logic?
- [ ] *Password Storage*: Verify use of strong hashing (Argon2, bcrypt, scrypt) with unique salts.
- [ ] *Multi-Factor Authentication (MFA)*: Check if MFA is implemented and if it can be bypassed.
- [ ] *Account Management*: Audit password reset, registration, and account lockout logic.
- [ ] *JWT Security*:
  - [ ] Check for `none` algorithm support.
  - [ ] Verify signature validation (RS256 preferred over HS256).
  - [ ] Check for hardcoded secrets or exposed public keys used symmetrically.
  - [ ] Check token expiration and revocation mechanisms.

== 3. Authorization (AuthZ)
- [ ] *Vertical Escalation (RBAC)*: Can a regular user access admin endpoints? Review middleware and decorators.
- [ ] *Horizontal Escalation (IDOR)*: Can a user access another user's resources by changing IDs? Look for missing ownership checks in database queries.
- [ ] *Insecure Direct Object References*: Check for UUIDs vs incremental IDs and proper authorization on every request.
- [ ] *Function Level Access Control*: Ensure every sensitive function has an explicit AuthZ check.

== 4. Input Validation & Data Handling
- [ ] *SQL Injection (SQLi)*: Search for raw query construction (`+`, `${}`, format strings). Ensure use of parameterized queries/ORMs.
- [ ] *Cross-Site Scripting (XSS)*:
  - [ ] Identify where user input is reflected in HTML.
  - [ ] Check for proper encoding/sanitization (e.g., `DOMPurify`, framework-level escaping).
  - [ ] Audit `dangerouslySetInnerHTML` or equivalent sinks.
- [ ] *Command Injection*: Find uses of `eval()`, `exec()`, `system()`, `child_process.spawn()` with user-controlled input.
- [ ] *Path Traversal / Local File Inclusion (LFI)*: Check file-related operations for unsanitized path inputs.
- [ ] *Server-Side Request Forgery (SSRF)*:
  - [ ] Audit functions that fetch external URLs.
  - [ ] Check for bypasses (IP encoding, DNS rebinding, internal network access).
- [ ] *XML External Entity (XXE)*: Verify XML parsers have DTD and external entity processing disabled.
- [ ] *Insecure Deserialization*: Audit use of `pickle.load()`, `node-serialize`, `JSON.parse` (if custom logic is applied), etc.

== 5. Business Logic & Workflows
- [ ] *Price/Quantity Manipulation*: Check for client-side trust in transactional data.
- [ ] *Step Bypassing*: Can a user skip steps in a multi-stage process (e.g., payment -> success)?
- [ ] *Race Conditions*: Audit concurrent updates to shared resources (e.g., bank balance, inventory).
- [ ] *Rate Limiting*: Check for protection against brute-force on sensitive endpoints (Login, OTP, Signup).

== 6. Cryptography & Data Protection
- [ ] *Weak Algorithms*: Check for MD5, SHA1, DES, or weak RSA key sizes.
- [ ] *Hardcoded Secrets*: Search for API keys, DB credentials, and salt values in the codebase.
- [ ] *TLS Configuration*: Ensure sensitive data is never sent over HTTP.
- [ ] *Information Leakage*: Check for sensitive data in logs, error messages (stack traces), or comments.

== 7. API & Microservices Security
- [ ] *CORS Policy*: Check for overly permissive `Access-Control-Allow-Origin: *`.
- [ ] *Mass Assignment*: Can a user update internal fields (e.g., `isAdmin: true`) through API JSON payloads?
- [ ] *Lack of Resources/Rate Limiting*: Check if an attacker can cause DoS by requesting large amounts of data.

== 8. Client-Side (Code Perspective)
- [ ] *Hardcoded Keys in JS*: Scan frontend bundles for leaked credentials.
- [ ] *PostMessage Vulnerabilities*: Check for `targetOrigin: '*'` in `window.postMessage`.
- [ ] *Sensitive Data in Web Storage*: Check if PII/Tokens are stored insecurely in `localStorage` or `sessionStorage`.

== 9. Dependency & Supply Chain
- [ ] *Outdated Packages*: Use tools to find CVEs in dependencies.
- [ ] *Typosquatting/Malicious Packages*: Audit `package.json` / `requirements.txt` for suspicious entries.
- [ ] *Dev Dependencies in Prod*: Ensure dev tools (debuggers, compilers) are not present in the production environment.

== 10. Audit Logs & Monitoring
- [ ] *Missing Logs*: Ensure critical actions (login, deletions, permission changes) are logged.
- [ ] *Log Injection*: Check if user input is logged without sanitization, allowing log forging.
- [ ] *PII in Logs*: Ensure no passwords or PII are written to log files.
