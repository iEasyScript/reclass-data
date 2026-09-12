# Content Server — On-Demand JS5 over HTTP (`/ms`) and the Port-80 Requirement

This documents the mobile client's **HTTP content-server fetch** — the second JS5 transport that runs
alongside TCP JS5 (port 43594). After the mobile client loads the bulk cache over TCP JS5, it makes
repeated HTTP GETs to the **content-server host on port 80** for on-demand groups. This is the fetch
that hangs against a Project X server that only serves `/ms` on the config port.

**Bottom line up front:** the content HTTP port is **hardcoded to `0x50` = 80** in the production path
``. No `jav_config` parameter can move it. The base URL is built as
`"http://" + <content_host> + ":80"`, with the host inserted **verbatim** — so putting a port in the
content-host param produces `http://IP:8829:80`, a malformed authority that hangs `getaddrinfo`
(the ~10s freeze the user observed). **Deployable fix: serve `/ms` on port 80 at the content host.**

---

## 1. The exact request

`` format string, `` used in `<in Ghidra DB>`:

```
%s/ms?m=0&a=%u&k=%d&g=%u&c=%d&v=%d
```

Resolved request:

```
GET http://<content_host>:80/ms?m=0&a=<archive>&k=<key>&g=<group>&c=<crc>&v=<version>
```

| Token | Source (in `<in Ghidra DB>`) | Meaning |
|---|---|---|
| `%s` (base) | eastl::string @ offset 0 of the HTTP queue `*(param_1+0x1c8)` | `http://<content_host>:80` (from `<in Ghidra DB>`) |
| `m` | literal `0` | mode/method — always 0 |
| `a` = `%u` | `*puVar30` | **archive / index id** |
| `k` = `%d` | `puVar30[0x38]` | key / request-type hint (Project X may ignore; tools send 0) |
| `g` = `%u` | `puVar30[1]` | **group id** |
| `c` = `%d` | `puVar30[2]` | **CRC32** of the container (signed `%d`) |
| `v` = `%d` | `puVar30[3]` | **group version** |

- **Method:** plain HTTP `GET`, no body. Executed via statically-linked **libcurl**
  (`<in Ghidra DB>` → `<in Ghidra DB>`) ``.
- **Response Content-Type must be `application/octet-stream`** — checked by `memcmp` in the completion
  poll of `<in Ghidra DB>` ``. A mismatch drops the response.
- **Response body** = raw JS5 container (`compression(1) + compressedSize(4) + [decompressedSize(4)] +
  payload(N)`) **followed by a 2-byte big-endian version suffix**. The client's CRC covers the
  container **without** the last 2 bytes. This matches the desktop finding in
  [../../net/js5-http-group-download.md](../../net/js5-http-group-download.md) and
  [../../cache/music-http.md](../../cache/music-http.md) — the mechanism is identical across ISA.
- **Master index over HTTP** is a valid request too: `a=255 (0xFF)`, `g=255 (0xFF)`.

This is the same `%s/ms?m=0&a=%u&k=%d&g=%u&c=%d&v=%d` string as the desktop build
`[VERIFIED — desktop rs2client 949-1`, so the request shape is cross-arch identical.

---

## 2. The base-URL builder and the hardcoded port — `<in Ghidra DB>`

`` A virtual method (vtable, dispatched builds a
server-node base URL into an output eastl::string via `sprintf`-style `"%s%s:%u"`:

```c
// param_2 = server-node descriptor:
//   param_2[0]      -> networking context (call it ctx)
//   param_2[1]      (int, +0x08)  = base port (dev path only)
//   *(int)(param_2+0x0c)          = type flag (1 => +12000, else +7000)
//   eastl::string @ param_2+0x10  = HOST  (SSO discriminator @ param_2+0x27)  <-- content host, VERBATIM
//   *(u16)(param_2+0x2a)          = HTTPS port (https path only)
// *(char)(ctx+0x468) = SSL flag

if (*(char)(ctx+0x468) != 0) {                 // HTTPS node
    sprintf(out, "%s%s:%u", "https://", host, *(u16)(param_2+0x2a));
} else if (*(void**)(ctx+0x10) == PTR_DAT_0113d2e8) {   // production networking singleton
    sprintf(out, "%s%s:%u", "http://", host, 0x50);      //  <-- PORT 80, HARDCODED
} else {                                        // dev/tool networking override
    port = param_2[1] + (type==1 ? 12000 : 7000);
    sprintf(out, "%s%s:%u", "http://", host, port);
}
```

Disassembly anchors: `<addr in DB> mov w9,#0x50` (port 80), `<addr in DB> mov w12,#0x2ee0` (12000),
`<addr in DB> mov w12,#0x1b58` (7000), scheme `http://`, format `"%s%s:%u"`.

`<in Ghidra DB>` is the accessor that returns this base URL (or a stored default) as an
eastl::string; its output is what lands in the HTTP queue's base-URL field consumed at `<addr in DB>`
``.

### Why `:%u` is always appended, and why `host:port` froze

The port is **not** optional — the format always emits `:<port>`. In production `<port>` is literally
`80`. The host is spliced in verbatim. So:

| Content-host param value | Base URL produced | Result |
|---|---|---|
| `10.69.69.50` | `http://10.69.69.50:80` | connects to `:80` (works if you serve `/ms` there) |
| `10.69.69.50:8829` | `http://10.69.69.50:8829:80` | malformed authority → blocking `getaddrinfo` on `"10.69.69.50:8829"` → ~10s DNS timeout → dead |

This is the exact freeze the user saw when setting `param=37=10.69.69.50:8829`. The client parses a
**bare host** and appends its own port; it does **not** accept a `host:port` authority in that param.

---

## 3. Is the port configurable? No.

`` The only non-80 HTTP path is the **dev/tool** branch, taken when the
networking-context object at `ctx+0x10` is a non-default override (set by the launch args
`-toolserver` / `-toolport` / `-httpport` / `-automate_*`, parsed in `<in Ghidra DB>`.
Those args arrive via the argument channel, which is **inert on mobile** — Intent extras are discarded
and only the `launchurl` deeplink is honored (see
[../android/startup-arguments.md](../android/startup-arguments.md)). So the dev port path is not
reachable from a normal mobile launch.

The `jav_config` port params (41–48 = `43594`/`443` pairs) are **game/TCP ports**, not the content
HTTP port. There is no `jav_config` key that sets the content HTTP port. `[VERIFIED — artifact,
docs/binary/jav-config.md param table]`

The HTTPS branch would use `https://host:<u16 @ node+0x2a>` (a configurable port) — but only if the
content node is flagged SSL (`ctx+0x468`), which then requires **TLS serving**, not plain HTTP. Not a
simpler fix than port 80.

---

## 4. Deployable fix

**Serve the on-demand `/ms` HTTP endpoint on port 80 of the content host** (the host emitted as
`jav_config` `param=37` / `param=49`, i.e. the Project X server IP). Concretely:

1. Keep `param=37`/`param=49` a **bare host** (`10.69.69.50`) — never `host:port` (freezes).
2. Bind an HTTP listener on **`:80`** of that host (or NAT/duplicate the existing config-port `/ms`
   handler onto `:80`) that answers:

   ```
   GET /ms?m=0&a=<archive>&k=<key>&g=<group>&c=<crc>&v=<version>
   ```

   Response:
   - `Content-Type: application/octet-stream` (**required** — the client memcmp-checks it).
   - Body = raw JS5 container bytes **+ 2-byte big-endian version suffix** (`(v>>8)&0xFF, v&0xFF`).
     The `v` query parameter carries the version to append; the client CRC-checks the container
     **excluding** those 2 bytes against `c`.
   - Also handle the **master index**: `a=255&g=255` → the master index container (+ version suffix).

3. No RSA/patching needed — this is plain HTTP, native libcurl, unaffected by the manifest cleartext
   restriction (native code never consults `NetworkSecurityPolicy`).

> Note: this reuses the exact `/ms` serving logic already documented for desktop
> ([../../net/js5-http-group-download.md](../../net/js5-http-group-download.md)); the only mobile-side
> action is **which port it listens on (80)**. Do not change server Kotlin here — this doc is the
> contract for the js5/config server owner.

Alternative considered and rejected: carrying a port in the content-host param (breaks — §2); a
config param for the port (none exists — §3); routing those archives over TCP JS5 instead (the
TCP-vs-HTTP choice is per-archive from archive settings set at registration, not config-controllable
— see [../../cache/music-http.md](../../cache/music-http.md)).

---

## 5. Desktop cross-check

The desktop build 949-1 has the **identical** request format string
`[VERIFIED — desktop` and the same two-transport architecture (`Js5NetQueue` TCP +
`Js5HTTPQueue` HTTP), documented at [../../net/js5-http-group-download.md](../../net/js5-http-group-download.md)
and [../../cache/music-http.md](../../cache/music-http.md). The desktop base URL is likewise
`http://<content_host>` with the default port 80.

So desktop uses the **same** content:80 `/ms` path. If a desktop Project X session does not hang on
`:80`, it is because that session either (a) already serves `/ms` on `:80` for the content host, or
(b) never routes a group to the HTTP queue in that session (the per-archive HTTP flag — e.g. index 40
music — was not exercised). It is **not** a protocol difference: mobile and desktop resolve the
content port identically to 80. `[UNCONFIRMED — hypothesis]` on which of (a)/(b) applies to the
current desktop setup — confirm on the Project X config/JS5 side.

---

## 6. Confirmed addresses (mobile target)

| Address | What | Tag |
|---|---|---|
| `<addr in DB>` | `"%s/ms?m=0&a=%u&k=%d&g=%u&c=%d&v=%d"` | `` |
| `<addr in DB>` | JS5 client tick; HTTP `/ms` request builder + curl-completion poll | `` |
| `<addr in DB>` | the `sprintf` of the `/ms` URL (base = HTTP queue `*(param_1+0x1c8)`+0) | `` |
| `<addr in DB>` | server-node base-URL builder `"%s%s:%u"` (scheme/host/port) | `` |
| `<addr in DB>` | `mov w9,#0x50` — **port 80 hardcoded** (HTTP production) | `` |
| `<addr in DB>` | base-URL accessor (calls `<addr in DB>`, else stored default) | `` |
| `<addr in DB>` | libcurl request executor (URL @+0x8, method @+0x260) | `` |
| `<addr in DB>` | dev-arg parser (`-server -port -httpport -toolserver …`) | `` |
| `<addr in DB>` | `"http://"` | `` |
| `<addr in DB>` | `"%s%s:%u"` format | `` |
