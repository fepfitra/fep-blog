#import "../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "AI BadBots: Authentication Bypass via NaN",
    description: "An explanation of the floating-point logic error in AI BadBots allowing authentication bypass.",
    date: "2025-12-26",
    order: 18,
  ),
)<frontmatter>

= AI BadBots: Authentication Bypass via NaN

== Introduction

The `ai-badbots` plugin for WordPress implements a custom "AI-based" trust scoring system. However, a flaw in how it handles floating-point operations and invalid mathematical inputs allows an attacker to completely bypass the authentication mechanism.

=== The Core Logic

The plugin calculates a "trust score" based on various HTTP request signals. One of these signals is `ip_entropy`, which attempts to detect header spoofing.

== Vulnerability Analysis

The vulnerability stems from the interaction between user-controlled input, a subtraction operation, and the behavior of the logarithm function in PHP.

=== Step 1: The Entropy Signal

The code calculates `ip_entropy` by subtracting the length of the `X-Forwarded-For` header (or similar headers) from the length of the `REMOTE_ADDR`.

```php
$xff = 0;
// ... (iterates headers like HTTP_X_FORWARDED_FOR)
if (array_key_exists($header, $_SERVER)) {
    $xff = $_SERVER[$header];
}
$this->signals['ip_entropy'] = strlen($ip) - strlen($xff);
```

If an attacker provides an `X-Forwarded-For` header that is longer than the IP address string, `ip_entropy` becomes a *negative number*.

=== Step 2: Normalization and NaN

The signals are normalized using a logarithmic scale:

```php
private function normalize($value)
{
    // ...
    return log($value) / log(10);
}
```

In PHP (and many other languages), the logarithm of a negative number is undefined for real numbers and results in `NAN` (Not A Number).

#figure(
  table(
    columns: (auto, auto, auto),
    inset: 10pt,
    align: center,
    [*Input Value*], [*Operation*], [*Result*],
    "10", `log(10)`, "2.302...",
    "0", "Adjusted to 1", "0",
    "-98", `log(-98)`, [*NAN*],
  ),
  caption: [Behavior of the normalize function.],
)

=== Step 3: Score Calculation

The final score is an average of normalized signals. If *any* signal is `NAN`, the arithmetic operations involving it will propagate `NAN`.

```php
$total += $this->normalize($value); // $total becomes NAN
// ...
$this->score = $total / ...; // $this->score becomes NAN
```

=== Step 4: The Validation Bypass

The validation function attempts to be "fail-closed" but fails to account for `NAN`'s unique properties.

```php
if (($this->score * 0) != 0 || $this->score > 0.95) {
    $this->grant_access();
    return;
}
```

The check `($this->score * 0) != 0` is intended to catch anomalous values. However, according to IEEE 754 floating-point standard:
1. `NAN * 0` results in `NAN`.
2. `NAN != 0` evaluates to *True*.

Because the condition evaluates to true, the code enters the `if` block and calls `grant_access()`, bypassing the check.

== Exploit

To exploit this, we simply send a request with an `X-Forwarded-For` header that is significantly longer than the IP address (typically > 15 characters).

```bash
curl -v "http://localhost:9188/?ai-trust-check=1" \
  -H "X-Forwarded-For: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
```

The server will respond with the flag (e.g., `CTF{...}`) instead of a 403 error.
