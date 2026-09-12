# Open Questions

Ranked by value toward the goal: **point the mobile client at a locally-run Project X server.**

Each entry has a concrete next step. Answering a question removes it from this file and moves the finding
into the relevant topic doc. **This file is always current.**

---

## 1. Is the `rs-launch://` config mechanism reachable on mobile, or vestigial?

**Why it matters:** `launchurl` (resolved — see [Resolved](#resolved)) gives **host:port control only**;
the path is hardcoded to `/jav_config.ws`. The `rs-launch` mechanism supplies a **full URL, host and
path**. Project X's Windows launcher already drives desktop this way
(`rs-launch://127.0.0.1:8829/jav_config.ws` as positional `argv[1]`). If it is reachable on mobile it is
the better redirect; if vestigial, `launchurl` is the only route and this can be closed out.

**What's known:** `` The mechanism exists in `<in Ghidra DB>`: it reads a URL from
an object at `param_1[0xa66f]` (offset `+`<in Ghidra DB>`, validity-checked against `param_1[0xa670]`), rewrites
`rs-launchs`→`https` / `rs-launch`→`http`, and appends `?binaryType=7`/`&binaryType=7`.
`[VERIFIED — artifact]` The manifest declares a matching filter on `MainActivity`:
`scheme="rs-launch" host="*runescape.com" pathPattern=".*jav_config.ws"`.

**The obstacle:** `rs-launch://…/jav_config.ws` does not contain `runescape.com/playnow`, so
`GetDeepLinkString` returns `""` for it — it cannot arrive that way. The natural candidate channel
(the argv vector, whose `argv[1]` would be the raw deeplink URI) is **provably never read**.

**Next step:**
1. Locate the writer of `param_1 + `<in Ghidra DB>`. The offset is too large for a scaled `STR` immediate, so
   the compiler must compute a base first — try xrefs on the vtable at `<addr in DB>` and walk the owning
   object's constructor.
2. Cross-check via desktop: `<in Ghidra DB>` takes the same object as `param_2`; find its callers
   (`MainLogic`, `<addr in DB>`) and see what supplies it there, then map to the mobile
   member.
3. **Cheap empirical test first** — it may close this outright:
   ```bash
   adb shell am start -n com.jagex.runescape.android/com.jagex.android.MainActivity \
     -a android.intent.action.VIEW -d 'rs-launch://127.0.0.1.runescape.com/jav_config.ws'
   ```
   A no-op result supports "vestigial".

**Docs to update:** [net/jav-config.md](net/jav-config.md), [android/startup-arguments.md](android/startup-arguments.md)

---

## 2. Does Project X's `jav_config.ws` handler switch on `binaryType`?

**Why it matters:** This is the **most likely first failure after a successful redirect**, and it is a
server-side fix, not a client one.

**What's known:** `` Mobile requests `binaryType=7`.
`[VERIFIED — desktop` Desktop requests `binaryType=4`. `[VERIFIED — artifact]` Project X's
tooling hardcodes `binaryType=4` (`tools/.../util/JavConfig.kt:6`).

**Next step:** Inspect Project X's lobby `jav_config.ws` handler (read-only). If it branches on
`binaryType`, it needs a `7` case; if it ignores the parameter, close this. Then determine what a mobile
`jav_config` must actually contain — `binary_name`/`download_*` for Android are likely irrelevant, but
`server_version` must still match the JS5 handshake.

**Docs to update:** [net/jav-config.md](net/jav-config.md)

---

## 2b. Which `OClient` offsets besides `CONNECTION_MANAGER` / `MAIN_STATE` diverge?

**Why it matters:** `` `` Mobile
`OClient::CONNECTION_MANAGER = `<in Ghidra DB>` (desktop `<in Ghidra DB>`) and `MAIN_STATE = `<in Ghidra DB>` (desktop
`<in Ghidra DB>`). The deltas differ (`+0x20` vs `+0x18`), so mobile's `Client` has **multiple** insertions —
this is not a uniform shift. **Every other value in Project X's `OClient` is therefore suspect**, and a
wrong one silently dereferences garbage.

**What's known:** Unidentified mobile `Client` members observed: `+`<in Ghidra DB>` (object with an int state at
`+0x28` compared against `30`), `+`<in Ghidra DB>`, `+`<in Ghidra DB>` `[UNCONFIRMED — hypothesis]`. Notably `<in Ghidra DB>` is
desktop's `PLAYER_VAR_DOMAIN`, so desktop values are actively misleading in this region.

**Next step:** Only resolve members as they are actually needed — do not bulk-port `OClient`. For each,
find a mobile function that uses it and read the immediate from **disassembly** (Ghidra's decompiler
renders these large offsets as bogus `__DT_RELA[...]` symbols and cannot be trusted here).

**Docs to update:** [net/packet-capture-hooks.md](net/packet-capture-hooks.md)

---

## 3. ~~Is the RSA modulus candidate real, and which handshake uses it?~~ — RESOLVED

**Answer:** The decimal candidate `72373001173…` is **NOT** the login modulus — it is only 512-bit (Pair D,
a secondary key used by `<in Ghidra DB>`, likely the world/game login) ``. The real
keys, both parsed once at static-init (`_INIT_254`) by `<in Ghidra DB>(bigint, ascii, radix)`:
- **LOGIN** — exp `<addr in DB>`=65537, mod `<addr in DB>`=**1024-bit** `83fec0…` (.rodata `<addr in DB>`),
  consumed by RSA-encrypt `<in Ghidra DB>` (`<addr in DB>`).
- **JS5** — exp `<addr in DB>`=65537, mod `<addr in DB>`=**4096-bit** `a4ba3320…` (`<in Ghidra DB>`), consumed
  by Whirlpool+RSA verify `<in Ghidra DB>` (`<addr in DB>`).

Not config-supplied — must be swapped in-process (frida hook on `<in Ghidra DB>` at init). **Landed in
[net/login-handshake.md](net/login-handshake.md).**

---

## 4. How are lobby and world endpoints parsed and selected?

**Why it matters:** Even with config redirected, the client must accept and connect to Project X's lobby/world
hosts. This is where that happens.

**What's known:** Two distinctive log format strings `[VERIFIED — artifact]` sit inside the parsers:
```
Client configured to connect to Lobby node %d on %.*s
Client configured to connect to World node %d on %.*s
```
The `%.*s` (length-counted) suggests a non-null-terminated string type — likely an `eastl::string` or a
span. Worth noting when reconstructing the struct.

**Next step:** `list_strings(filter="Client configured to connect")` → `get_xrefs_to` → decompile both
parsers. Document the host/port/node-id structure and where the values originate.

**Docs to update:** new `net/lobby-world-endpoints.md`

---

## 5. How is the JS5 endpoint selected, and can config override it?

**Why it matters:** The client needs cache data. Project X already has a JS5 server; the question is whether
mobile can be pointed at it via config alone.

**What's known:** `js5connect`, `js5connect_full`, `js5connect_outofdate` are config keys
`[VERIFIED — artifact]`. `Js5DiskCache`, `Js5WorkerThread`, `deletejs5caches` indicate the on-device cache
subsystem. `CacheInitialiser` seeds from `assets/mobile_cache` into `getExternalFilesDir(null)`.

**Next step:** Xref the `js5connect*` key strings; find the config consumer and the JS5 connection setup.
Determine whether the endpoint is config-driven or hardcoded.

**Docs to update:** new `net/js5.md`, `cache/` as needed

---

## 6. Does the mobile login handshake match desktop byte-for-byte? — LARGELY RESOLVED

**Answer (see [net/login-handshake.md](net/login-handshake.md)):** The direct username+password path is
mapped. Decision = `<in Ghidra DB>` (`isUserAuthenticated`/`<in Ghidra DB>` false → direct); creds read from a
`cfg+0x7690` map keyed `"username"`/`"password"`; entry `<in Ghidra DB>`. RSA block plaintext (`<in Ghidra DB>`
+`<in Ghidra DB>`+`<in Ghidra DB>`): `0x0a` magic, 4 ISAAC keys (u32 BE), 8-byte nonce, auth-mode, then
**password** RS-string; RSA-encrypted by `<in Ghidra DB>` with the login key. Username is written to the
XTEA tail. **How to force a direct login is now mapped and tooled** — see
[login-handshake.md §3a (Frida hook)](net/login-handshake.md) and
[§3b (deployable plan)](net/login-handshake.md). **On-device correction:** `jag::AttemptStoredLogin`
(`<addr in DB>`) does **not** auto-tick on a fresh launch (56s idle capture = zero fires), so seeding the
`cfg+0x7690` cred map has nothing to read it. The working mechanism captures `loginMgr` from the
`jag::LoginManager::LoginManager` ctor (`<addr in DB>`, X0) and calls **`jag::LoginManager::BeginLobbyLogin`
(`<addr in DB>`, `loginType=1`)** directly with the creds as args (no map), **gated on client main-state ==
10 (login screen)** at `client+`<in Ghidra DB>` via `jag::Client::SetMainState` (`<addr in DB>`). This emits the
**op19 LOBBY** login (Project X is lobby-first; the world variant `BeginDirectLogin`/`loginType=2` would go
straight in-world — see login-handshake.md §7). It only sets sub-step `loginMgr+0x1b8=-3`; the client's
per-frame login-manager tick drives connect→op19. The Java OAuth button (`RequestOAuth2Tokens`) is **not**
hookable from native (no gadget Java bridge; on-device the intercept never fired) — so it is ignored.
**Verified end-to-end on-device:** op16 world login parsed by the server (creds "meme" extracted); now
switched to lobby so the existing `LobbyLoginHandler` + lobby-details response apply.

**Still open:** (a) the exact XTEA start offset (verify against a forced direct-login capture); (b)
whether the `"directlogin"` jav_config binding registered by `<in Ghidra DB>` (`<addr in DB>`,
`<in Ghidra DB>(...,"directlogin")`) routes creds into `cfg+0x7690` or straight into `BeginDirectLogin` —
if so it is a **zero-hook, server/launcher-driven** deployable channel (decompile that binding's
callback next). Original text retained below for the remaining sub-questions.

### (historical)

**Why it matters:** Determines how much of Project X's existing login implementation works unmodified. Mobile
shows prominent OAuth2/SSO paths that may diverge from desktop's flow.

**What's known:** `[VERIFIED — artifact]` these strings exist:
```
Attempting to login to lobby
Attempting to login to world using OAuth2 credentials
Attempting direct login as: %s
Attempting direct login with sso credentials
Game World Login Result: %d (%s)
bad handshake length
digest requred for handshake isn't computed        ← [sic] — the typo makes it a distinctive anchor
app data in handshake
```
The presence of both `directlogin*` and `*-sso` variants suggests **multiple login paths**; which one mobile
takes by default is unknown.

**Progress — two login block builders located** (found incidentally while chasing ISAAC):

- `` `<in Ghidra DB>` — a login block builder. Gated on state `0x50` at entry, sets
  state `0x5a` on success; two variants branch on `*(param_1+0x20) == 2`. It builds the packet, then
  constructs the c2s/s2c Isaac pair (see
  [net/packet-capture-hooks.md](net/packet-capture-hooks.md#the-50-question--answered)). The 4 ISAAC keys
  live at `builder+0x48` (4×int32, 16 bytes).
- `` `<in Ghidra DB>` — the other login path, same Isaac-pair shape.
- `` `<in Ghidra DB>` is **XTEA**, not RSA: golden ratio `0x9e3779b9`, 32 rounds,
  8-byte blocks, big-endian in/out. Called as `<in Ghidra DB>(packet, builder+0x48, startOff, endOff)` —
  i.e. **the login block is XTEA-encrypted using the 4 ISAAC keys as the XTEA key**, over an offset range.
  This is standard RS behaviour and matches the desktop flow.

**Next step:** The RSA-encrypt call site is still unlocated (it is *not* `<in Ghidra DB>`). Look between
`<in Ghidra DB>(param_1, packet)` and the length patch at the tail of `<in Ghidra DB>`. Then xref the login
strings and trace the rest of the handshake. Compare against Project X's `re-resources/docs/net/` login docs
(read-only). **Document divergence explicitly** — a mobile/desktop difference is a finding.

**Docs to update:** new `net/login-handshake.md`

---

## 7. What do the five JNI exports actually do? — **hypothesis partly REFUTED**

**Why it matters:** Was assessed as low. The "all UI/input plumbing" assumption has been **shown wrong
for one of the five**, so the rest deserve a look.

**What's known:** `` `xd(String)` is **not** UI plumbing. It converts the jstring
to an `eastl::string` and forwards it to `<in Ghidra DB>`. Its Java caller is
`com/jagex/android/JagexMobileSDKWrapper.java:151` — `ru.xd(aVar.a)` inside an `o8.e<String>`
callback. This is the **JagexMobileSDK → native string channel**, `[UNCONFIRMED — hypothesis]` most
likely OAuth2/session-token delivery.

`[UNCONFIRMED — hypothesis]` The other four remain unexamined; all are called from
`com/jagex/android/b.java` (a thin dispatch shim), which is consistent with UI/input but unproven:
```
ax(String,int)  bu(int)  hx(int)  wv(int,int)
```

**Next step:** Decompile `<in Ghidra DB>` to determine what `xd`'s string becomes — if it is an auth
token, it connects to the `*-sso` login paths (Q6). Then decompile the remaining four.

**Docs to update:** [binary/target-binary.md](binary/target-binary.md), [android/apk-structure.md](android/apk-structure.md)

---

## Resolved

Questions closed by evidence, with a pointer to where the answer landed.

### ✅ Why does the mobile client hang on the content host `:80`, and can the port be moved via config?

**Answer: the content HTTP port is hardcoded to 80 (`0x50`); no `jav_config` param moves it; the
content-host param must be a bare host. Fix = serve `/ms` on port 80 at the content host.**
`` ``

The on-demand JS5-over-HTTP fetch is `GET http://<content_host>:80/ms?m=0&a&k&g&c&v`. The base URL is
built by `<in Ghidra DB>` as `"%s%s:%u"` = scheme + host + **always** `:<port>`, with the port literally
`0x50`=80 in the production HTTP path and the content host inserted verbatim. Setting the content-host
param to `IP:8829` yields `http://IP:8829:80` → malformed authority → blocking `getaddrinfo` → the ~10s
freeze. The only non-80 path is a dev/tool networking-override (launch args `-httpport`/`-toolserver`,
inert on mobile). Response must be `Content-Type: application/octet-stream`, body = raw container +
2-byte BE version suffix.

**Landed in:** [net/content-js5-http.md](net/content-js5-http.md). Also partially answers Q5 (the
`js5connect*` consumer is `<in Ghidra DB>`; content transport now fully documented).

### ✅ How does the lobby/world server detect a MOBILE client? (was Q3b)

**Answer: the mobile OS is carried in THREE fields of the C2S op19/op16 login descriptor (the
XTEA-enciphered tail); the login-details RESPONSE carries NO OS field.**
`` `` `` `[VERIFIED — artifact,
XTEA-decrypted capture]`

1. **`"NXT-Android"` client-name string** — in the machine-info block at XTEA-tail **off ~269 in both
   lobby and world** (desktop: `NXT-Windows`/`NXT-Linux`/`NXT-Mac`, `.rodata. Recommended
   signal: near-constant position across both branches → scan the decrypted tail for the literal.
2. **`binaryType` byte = `0x07`** (android; `8`=iOS) — the client's own mobile test `binaryType∈{7,8}`.
   Lobby off 377, world off 358.
3. **`platformType` byte = `0x02`** (`jag::GetPlatformType`; `3`=iOS; `0`/`5`=desktop), right after
   `binaryType`.

The response decoder `jag::LoginManager::LoginStepHandleLoginData` (`<in Ghidra DB>`, state 0x96; 1:1 with
desktop `<in Ghidra DB>`) reads **no** OS/platform field in either branch — the mobile UI is **inherent to the
binary**. The server acknowledges mobile by serving the mobile interface/var/script set post-login, not
via a response byte. Ghidra: renamed `SendLoginPacket`/`LoginStepHandleLoginData`/`GetPlatformType`/
`LoginManager`/`LoginStepDealWithFirstResponse`/`WriteLoginClientSettingsBlock` + decompiler comments.

**Landed in:** [net/login-handshake.md §6](net/login-handshake.md), [net/reference-captures.md](net/reference-captures.md)

### ✅ Where does a mobile packet sniffer hook, given `InitIncoming` has no mobile target?

**Answer: `<in Ghidra DB>`, on ENTER, `X0` = `ServerConnection*`**
``.

Two sub-answers, both confirmed:

1. **`TcpConnectionMessage::InitIncoming` is inlined into `TcpIn` on mobile** and cannot be hooked
   ``. Desktop has exactly one call site for it, so AArch64 Clang inlined it;
   the size-class ladder and every message field write appear inline in `TcpIn`. Project X's central
   capture design does not port.
2. **`TcpIn`'s exit is too late.** Before returning, `TcpIn` calls `<in Ghidra DB>(conn)`, which sets
   `CURRENT_OPCODE = -1` (after saving it to `conn+0x2e0`). An `onLeave` hook captures nothing.

`<in Ghidra DB>` has exactly two call sites, both inside `TcpIn` (`<addr in DB>` success, `<addr in DB>`
reject), so it fires once per packet with opcode/size/payload all intact, and the connection is `X0`
itself — no `activeConn` correlation needed.

**Landed in:** [net/packet-capture-hooks.md](net/packet-capture-hooks.md)

### ✅ Are the ISAAC keys `+50`-adjusted for the s2c stream, and what shape does `Isaac::Init` take?

**Answer: `Init(X0=Isaac*, X1=const int32_t keys[4])` — 4 keys, no count arg. `Init` does NOT adjust;
the caller does** `` ``.

The login block builder constructs two Isaacs: raw keys → `conn+0x40` (outbound/c2s), and each key
`+ 0x32` (50) → `conn+0x2b8` (inbound/s2c). `conn+0x2b8` is exactly the Isaac `TcpIn` reads, closing
the loop. A hook on `Init` sees both — first call raw, second call +50. Isaac object is `0x810` bytes.

**Landed in:** [net/packet-capture-hooks.md](net/packet-capture-hooks.md#isaac)

### ✅ What is the startup-argument key that sets the config URI?

**Answer: `launchurl` — and it is NOT an Intent extra.** It is a **query parameter on the launching
deeplink URI** ``.

The premise of the question was wrong in two ways, both now corrected:

1. **Native never compares Intent-extra keys against literals.** `jag::android::android_main` marshals the extras into an argv-style vector `["android", k0, v0, …]` and stores it
   at `jag::android::g_StartupArgumentsArgv` `` — which **nothing
   ever reads**. Established by two independent methods: Ghidra's reference graph (2 refs, both
   non-read) and a raw decode of all 52,250 `ADRP` instructions in `.text` (1 hit, the write).
   **`am start -e` cannot influence this client.**
2. **"No `configURI` string exists, so native uses another name" was invalid reasoning.** Neither the
   mobile `.so` nor the desktop `rs2client` contains `configURI` `[VERIFIED — artifact]`, yet desktop is
   demonstrably launched with `--configURI`. Per Project X's own notes it is a **launcher** flag
   (`rs3windows.exe`), never an rs2client flag — see the divergence flagged in
   [android/startup-arguments.md](android/startup-arguments.md#desktop-divergence--flagged-for-the-user).
   Generalised into a methodology rule:
   [re-methodology/cross-architecture-porting.md](re-methodology/cross-architecture-porting.md#the-absence-of-a-string-is-not-evidence-of-absence).

**Landed in:** [android/startup-arguments.md](android/startup-arguments.md)

### ✅ What feeds the `%s` host in the config URL?

**Answer: the verbatim value of the `launchurl` deeplink query parameter** ``.

`GetDeepLinkString` → `jag::ParseUrlQueryParameters` → memcmp against
`"launchurl"` → if the resulting host string is non-empty, format
`http://%s/jav_config.ws?binaryType=%s` with it and `"7"`; otherwise fall back to the hardcoded
`https://rs.config.runescape.com/…` default.

**The redirect is PROVEN by static analysis — no patching, no resigning, no root** (pending an
on-device run):

```bash
adb shell am start \
  -n com.jagex.runescape.android/com.jagex.android.MainActivity \
  -a android.intent.action.VIEW \
  -d 'https://secure.runescape.com/playnow/rs?launchurl=192.168.1.10:8829'
```

No percent-decoding occurs, so pass a bare `host:port`. **Host and port only — the path is hardcoded to
`/jav_config.ws`**, which already matches Project X's lobby. A binary patch is **not** required, so the
`.rodata` relocation / pointer-rewrite concern raised in the original question is **moot**.

**Landed in:** [net/jav-config.md](net/jav-config.md)
