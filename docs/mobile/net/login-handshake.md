# Login Handshake, RSA Keys, JS5 Verify — Mobile

Goal served: a fully self-hosted **username + password lobby login** against Project X (no OAuth, no
runescape.com traffic). Frida-gadget injection, so this doc is a set of hookable RVAs + exact structures.

All addresses are **RVAs** (image base 0; Ghidra addresses are RVAs directly). AArch64 / AAPCS64:
integer/pointer args `X0`–`X7`, `this`=`X0`, return in `X0`, `X8` = indirect struct-return.

Cross-arch reminder: the desktop `rs2client.949-1` (x86-64) is a **behavioural blueprint only** — addresses
and byte patterns do **not** port. Everything tagged `[VERIFIED @ 0x…]` below was read from the mobile
target itself.

---

## 0. TL;DR hook table

| Purpose | Function | RVA | Hook use |
|---|---|---|---|
| **RSA modpow** (core) `m^e mod n` | `<in Ghidra DB>` | `<addr in DB>` | `(X0=base BigInt, X1=exp BigInt, X2=mod BigInt, X3=out BigInt)`. Every RSA op passes through here. |
| **BigInteger string parse** (init) | `<in Ghidra DB>` | `<addr in DB>` | `(X0=BigInt*, X1=char* ascii, W2=radix)`. Swap a key by matching `X1` at static-init. |
| **Login block RSA-encrypt** | `<in Ghidra DB>` | `<addr in DB>` | `(X0=buf, X1=&expGlobal, X2=&modGlobal)`. Encrypts login RSA block in place; buf plaintext at `*(X0+0x10)`, len `*(X0+0x18)`. |
| **JS5 / container RSA-verify** | `<in Ghidra DB>` | `<addr in DB>` | `(X0=out, X1=exp BigInt, X2=mod BigInt, X3=packet)`. Whirlpool+RSA verify. Force-pass here. |
| **Login-mode decision / auto-login** | `jag::AttemptStoredLogin` | `<addr in DB>` | `(X0=clientObj)`. Selects SSO vs direct user/pass; ticked by the login-screen state machine. `credMap = *(clientObj+`<in Ghidra DB>`)+0x7690`. |
| **`isUserAuthenticated`** | `jag::IsUserAuthenticated` | `<addr in DB>` | `→ X0 = bool&1`. Hook to return **0** to force direct login. |
| **Lobby user+pass entry** (`loginType=1`) | `jag::LoginManager::BeginLobbyLogin` | `<addr in DB>` | `(X0=loginMgr, X1=&username, X2=&password, X3=&out, W4=mode)`. **op19 LOBBY** → lobby screen. **The hook uses THIS** (see §3a/§7); needs main-state 10 + the per-frame tick. |
| **World user+pass entry** (`loginType=2`) | `jag::LoginManager::BeginDirectLogin` | `<addr in DB>` | same sig; op16 WORLD → logged-in in-world. Reference (Project X is lobby-first). |
| **LoginManager ctor (capture loginMgr)** | `jag::LoginManager::LoginManager` | `<addr in DB>` | `X0=loginMgr` once at startup. |
| **Client main-state setter** | `jag::Client::SetMainState` | `<addr in DB>` | writes `client+`<in Ghidra DB>`; **10=login screen**, 0x1e=logged in. Poll this to gate the login. |
| **Cred-map setter (seed primitive)** | `jag::ConfigMap::SetString` | `<addr in DB>` | `(X0=map, X1=keyCstr, X2=valueData, X3=valueLen)`. NOTE: seeding does **not** trigger login (`AttemptStoredLogin` never ticks). |
| **Direct login w/ explicit creds** | `jag::DirectLoginWithCredentials` | `<addr in DB>` | persists creds to map + dispatches lobby/world. The form-submit handler. |
| **OAuth2 button (AVOID)** | `jag::android::RequestOAuth2Tokens` | `<addr in DB>` | JNI `JagexMobileSDK.requestOAuth2Tokens`; exits on isolated network. |
| **Login-state store** | `<in Ghidra DB>` | `<addr in DB>` | writes username→`+0x70`, password→`+0x88`, auth→`+0xa0`. |
| **Login-block serializer** | `<in Ghidra DB>` | `<addr in DB>` | state `0x50`→`0x5a`; builds the wire packet + ISAAC pair. |
| **RSA-plaintext header builder** | `<in Ghidra DB>` | `<addr in DB>` | writes magic/keys/nonce into the RSA plaintext. |
| **RSA-plaintext tail (pwd/token)** | `<in Ghidra DB>` | `<addr in DB>` | writes auth-mode + password, then calls the encrypt. |

---

## 1. Login RSA modulus + encrypt site  (coordinator task A/C)

### The key (Pair A — LOGIN)
`[VERIFIED @ `<in Ghidra DB>`xxx in _INIT_254]` Parsed once at C++ static-init by
`<in Ghidra DB>(bigint, ascii, radix)`:

| Role | ASCII source (.rodata) | Parsed-into global (holds `BigInteger*`) | Value |
|---|---|---|---|
| exponent `e` | `"10001"` radix 16 | `<addr in DB>` | **65537** |
| modulus `n` | `<addr in DB>` (256 hex chars) radix 16 | `<addr in DB>` | **1024-bit** `83fec000fd2e3d6f1555e4f1a3875dd9…c67d1d380cd` |

`` The 1024-bit modulus matches the captured lobby-login RSA block size
(`0x0081` = 2-byte length `00 81` + 129-byte `toByteArray`, i.e. 128 ciphertext bytes + a `0x00` sign
byte) `[VERIFIED — artifact, capture/…]`.

### Consumption timing (answers "is a late string patch enough?")
`` `_INIT_254` is a **C++ static constructor**. It runs at **library-load /
`dlopen` time**, before any socket work. It calls `<in Ghidra DB>(0x18)` (alloc a 0x18-byte BigInteger),
stores the pointer in the global, then `<in Ghidra DB>(bigint, "83fec0…", 16)` parses the ASCII **once**
into limb form. **After init the `.rodata` hex string is never read again.**

Consequence for frida:
- **Overwriting the `.rodata` hex string after this .so's ctors have run is USELESS** — the BigInteger is
  already built. For an embedded gadget in *this* .so, ctors run during load, so a string patch is almost
  always too late.
- Reliable options, in order:
  1. **Hook `<in Ghidra DB>` (`<addr in DB>`)**, match on `X1` == the known login/js5 ASCII prefix, and
     rewrite `X1` to point at Project X's ASCII before the trampoline. Runs at init, swaps the parsed bignum
     cleanly. `` signature `(X0=BigInt*, X1=char*, W2=radix)`.
  2. **Hook the encrypt `<in Ghidra DB>` / verify `<in Ghidra DB>`** and substitute the exp/mod BigInteger
     pointers (they are read from the globals at call time — see below), or re-encrypt yourself.
  3. Overwrite the **parsed BigInteger limbs** at the global's target (harder; layout of the 0x18-byte
     object not fully mapped).

### The encrypt site — `<in Ghidra DB>`
`` `void <in Ghidra DB>(buf* X0, BigInteger** exp X1, BigInteger** mod X2)`:

```c
m   = BigInteger(*(buf+0x10), *(buf+0x18));   // plaintext bytes → bignum   (<in Ghidra DB>)
c   = m ^ (*exp) mod (*mod);                   // <in Ghidra DB>  (RSA modpow)
out = c.toByteArray;                          // <in Ghidra DB>
buf.pos = 0; write u16 BE len; write out;       // [2-byte len][ciphertext] back into buf
```

Called from `<in Ghidra DB>`/<addr in DB>` with the **login key** `(&<addr in DB>, &<addr in DB>)`.
`` Two sibling encrypt paths also read the login key: `<in Ghidra DB>`
(`<addr in DB>`) and `<in Ghidra DB>` (`<addr in DB>`) — the world/reconnect variants.

**Frida C fallback:** hook `<addr in DB>` `onEnter`; `X0` is the plaintext buffer object — plaintext at
`*(X0+0x10)`, length `*(X0+0x18)` — capture it, then either let the client encrypt (after you've swapped
the key via option 1) or re-encrypt with Project X's key and rewrite the buffer. The exp/mod are `*X1`/`*X2`.

The core modpow `<in Ghidra DB>` (`<addr in DB>`, `(X0=base,X1=exp,X2=mod,X3=out)`) has exactly two
high-level callers: `<in Ghidra DB>` (login encrypt) and `<in Ghidra DB>` (verify) ``.

---

## 2. JS5 modulus + master-index verify  (coordinator task B — FIRST blocker)

### The key (Pair B — JS5)
`` Same init mechanism:

| Role | ASCII source | Parsed-into global | Value |
|---|---|---|---|
| exponent `e` | `"10001"` radix 16 | `<addr in DB>` | **65537** |
| modulus `n` | `<in Ghidra DB>` (1024 hex chars) radix 16 | `<addr in DB>` | **4096-bit** `a4ba332072d8ccdcff327ef42dc5be75…` |

`, <addr in DB>]` **`<in Ghidra DB>` reads BOTH JS5 globals** (mod `<addr in DB>`, exp `<addr in DB>`, adjacent) and stores them into the JS5 container-codec
object. That object's fields `+0x60`/`+0x68` (`obj[0xc]`/`obj[0xd]`) are the exp/mod the verify reads.

### The verify site — `<in Ghidra DB>`
``
`void <in Ghidra DB>(int* out X0, BigInteger* exp X1, BigInteger* mod X2, Packet* pkt X3)`

Behaviour (this is a **Whirlpool-then-RSA signature verify**, the JS5 master-index / version-table check):

```c
count = pkt[5];                       // number of entries
sigBlock = pkt+? (length-prefixed)    // the RSA signature bytes
sig = BigInteger(sigBlock);
dec = sig ^ (*exp) mod (*mod);        // <in Ghidra DB>  (RSA)  → expected 64-byte Whirlpool digest
h   = Whirlpool(pkt+5, count*0x50);   // <in Ghidra DB>/<in Ghidra DB>/<in Ghidra DB>, 0x40-byte digest
for i in 0..0x40:                     // byte-by-byte compare
    if dec[i] != h[i] : FAIL          // code_r<addr in DB>
```

`` The 0x40-byte (64) buffers and the three `<in Ghidra DB>/8c`+`<in Ghidra DB>`
calls are Whirlpool (Whirlpool = 512-bit/64-byte digest). The final `if (dec[i] != h[i]) goto fail`
loop is the signature check.

Called from **`<in Ghidra DB>`** at `<addr in DB>` (opcode `0x0a`) and `<addr in DB>` (opcode `0x28`)
`` — the JS5 container/version-table processor, `switch(typeByte)`. Both callsites
pass the key as `obj[0xc]`,`obj[0xd]` (i.e. the JS5 exp/mod stored by `<in Ghidra DB>`).

**Frida (highest priority — the client EOFs right after 255/255 if this fails):**
- Simplest force-pass: hook `<in Ghidra DB>` `onLeave` and **make the result "valid"** — but the result is
  written into `X0` (an entry array `int* out`), not a bool return, so a clean force-pass means either
  (a) swap the key so the real signature validates (preferred: use the `<in Ghidra DB>` init hook so
  Project X's JS5 private key can sign a valid master index), or (b) hook the compare so it always matches.
  Because the digest is compared byte-for-byte against the RSA-recovered value, **the cleanest path is to
  serve a master index that Project X actually signed with the private key matching whatever modulus is in
  effect** — hence swap the modulus at init (option 1 in §1) and sign server-side.
- `X3` = the raw JS5 container packet (position/data model `pkt+0x10`=data, `pkt+0x18`=pos).

`[UNCONFIRMED — hypothesis]` The precise store of the key globals into `obj+0x60/+0x68` inside
`<in Ghidra DB>` was inferred from the adjacent reads at `<addr in DB>/48`, not decompiled field-by-field.
The verify math and key-via-object-field are verified; the exact setup instruction is not yet pinned.

---

## 3. Direct-vs-OAuth decision + how to force direct  (task 3)

### The decision — `<in Ghidra DB>`
``

```c
if ( isUserAuthenticated &&                    // <in Ghidra DB> & 1
     ( hasOAuthToken(...) || (state-check && flag@*plVar1+0x169) ) ) {
    log("Attempting direct login with sso credentials");
    <in Ghidra DB>(loginMgr, &out, 0);             // SSO / OAuth2 path
} else {
    // DIRECT USERNAME + PASSWORD PATH
    u = configMap.get("username");               // <in Ghidra DB>(cfg+0x7690,"username")
    p = configMap.get("password");               // <in Ghidra DB>(cfg+0x7690,"password")
    if (!u || !p) log("No previous direct login attempt found - please login manually the first time");
    else {
        log("Attempting direct login as: %s", u);
        <in Ghidra DB>(loginMgr, &u, &p, &out, 0); // direct user+pass entry
    }
}
```

`` `<in Ghidra DB>` = **`isUserAuthenticated`** — it queries a config/session KV
store for key `"isUserAuthenticated"` (string `s_isUserAuthenticated_0011d9c2`) and returns `bool&1`.

`` The username/password come from a **config map at `cfgObj+0x7690`**, keyed by
literal `"username"` / `"password"`. `<in Ghidra DB>` (world direct-login, `<addr in DB>`) **writes** them
there via `<in Ghidra DB>(cfg+0x7690,"username"/"password",…)` — i.e. they are persisted after one manual
login, and can be seeded by us.

### The exact object graph (recovered from the mobile disassembly)
`` `jag::AttemptStoredLogin(clientObj)` (renamed from `<in Ghidra DB>`) is ticked
by the **login-screen state machine** — callers `<in Ghidra DB>`, `<in Ghidra DB>`, `<in Ghidra DB>`, all
passing the top-level **client object** as the sole arg. From its prologue
(`add x20,x0,#`<in Ghidra DB>`+#0x4b8`):

| Expression | Meaning | Confidence |
|---|---|---|
| `x20 = clientObj + `<in Ghidra DB>` | base for the login sub-fields | `` |
| `loginMgr = *(clientObj + `<in Ghidra DB>`)` | the LoginManager (arg0 of `BeginDirectLogin`) | `/<addr in DB>]` |
| `cfgObj = *(clientObj + `<in Ghidra DB>`)` | config object holding the cred map | `` |
| **`credMap = cfgObj + 0x7690`** | eastl `hashmap<string,string>`, keys `"username"`/`"password"` | `` |
| `logger = *(clientObj + `<in Ghidra DB>`)` (`x20+0x68`) | log sink | `` |

The `else` (direct) branch reads `credMap.get("username")` / `("password")`
(`jag::ConfigMap::FindString` = `<in Ghidra DB>`, `0` ⇒ key absent); if either is absent it logs
`"No previous direct login attempt found - please login manually the first time"` and **idles on the
login screen** (this is exactly the state a fresh private-server launch sits in). If both are present it
logs `"Attempting direct login as: %s"` and calls `jag::LoginManager::BeginDirectLogin` (`<addr in DB>`) →
op19.

### The credential map: who writes it (the bootstrap problem)
`[VERIFIED]` The **only** writer of `credMap` keys `"username"`/`"password"` is
`jag::DirectLoginWithCredentials` (`<addr in DB>`, renamed from `<in Ghidra DB>`) — the
direct-login-with-explicit-credentials handler that a **manual username/password form submit** calls
(callers `<in Ghidra DB>`/`<in Ghidra DB>`/`<in Ghidra DB>`/`<in Ghidra DB>`). It (1) persists the creds via
`jag::ConfigMap::SetString(credMap,"username"/"password",dataPtr,len)` then (2) logs in
(`mode&1==0` → lobby `BeginDirectLogin`; else world `<in Ghidra DB>`). So the creds only appear in the
map **after one manual direct login** → `AttemptStoredLogin` auto-logins on later launches. The two
other xrefs of the literals `"username"`/`"password"` are **red herrings**: `<in Ghidra DB>` is
statically-linked libcurl's `.netrc` parser, and `<in Ghidra DB>` is a JSON telemetry serializer using
`"username"` as a JSON field. `, <addr in DB>]`

`jag::ConfigMap::SetString` (`<addr in DB>`) signature — the seed primitive:
`uint64 SetString(void* map, const char* keyCstr, const void* valueData, size_t valueLen)`. Key hashed
FNV-1a (`<in Ghidra DB>` * 0x1000193`); inserts or overwrites. `valueData/valueLen` is a **raw char*+byte
length**, not an eastl::string. ``

### EASTL string layout (for any path that must build one)
`/<addr in DB>]` 24-byte SSO string: `+0x00` data ptr (or inline bytes), `+0x08`
size, `+0x10` capacity `| `<in Ghidra DB>`00000000` (heap flag = high bit of the byte at `+0x17`), `+0x17`
byte = `0x17 - length` when SSO. For creds ≤23 chars you can build one inline: write the bytes at
`+0x00`, NUL-terminate, set byte `+0x17 = 0x17 - len`. (The `SetString` seed path avoids this entirely
— it takes a plain C buffer.)

---

## 3a. DELIVERABLE 1 — force a working direct login NOW (Frida hook)

Two dead ends were eliminated on-device, then the real mechanism was found:

- `[VERIFIED — on-device]` **`jag::AttemptStoredLogin` never auto-ticks** (56s idle capture = zero fires),
  so seeding the cred map has nothing to read it.
- `[VERIFIED — on-device]` **The `"email/password"` button is Java-driven** (`JagexMobileSDK`); the native
  `jag::android::RequestOAuth2Tokens` (`<addr in DB>`) intercept **never fired** on a real tap, and the
  gadget has no Java bridge — so the button handler is unhookable from native. That intercept was removed.
- `[VERIFIED — on-device]` **Calling `BeginDirectLogin` at startup produced no op19** — its preconditions
  are already satisfied while the client is still booting, so it fired ~2.5s in, set `loginMgr+0x16c=3`,
  and the boot sequence then reset that step.

The working mechanism **calls `jag::LoginManager::BeginDirectLogin` (`<addr in DB>`) directly — but only once
the client is sitting on the login screen (main-state == 10)**. Wired into
[`mobile/rs3-capture.js`](../../../../mobile/rs3-capture.js) (`hookDirectLogin`) + RVAs in
[`mobile/rva.json`](../../../../mobile/rva.json). Run:

```
./mobile/run-hook.sh <HOST:PORT> --direct-login-user myuser --direct-login-pass mypass
```

### Client main-state (the gate) — ``
`jag::Client::SetMainState(client, newState)` (renamed from `<in Ghidra DB>`) writes the main-state at
**`client+`<in Ghidra DB>`** (logs `"MainState changed %d -> %d"`). Values: **`10` (0xa) = interactive LOGIN
SCREEN** (`<in Ghidra DB>` gates "only available on login screen" on `==10`; `<in Ghidra DB>` calls
`SetMainState(client,10)` to return here on abort), `0x1e` = LOGGED IN, `0x28` = a reconnect/transition
state. `client = *(loginMgr+0x18)`.

### Does `BeginLobbyLogin` drive op19? — NO, it needs the tick ``
`BeginLobbyLogin` (like `BeginDirectLogin`) does **not** connect or send op19. It calls
`jag::LoginManager::StoreLoginCredentials` (`<addr in DB>`), which copies the creds to
`loginMgr+0x70/+0x88/+0xa0` and sets the **login sub-step** according to credential content — for
`loginType==1` (lobby) that field is **`loginMgr+0x1b8`** (for `loginType!=1` it is `+0x16c`). The
**client's per-frame LoginManager tick** then dispatches the step handlers (connect → key exchange →
`jag::LoginManager::SendLoginPacket` `<addr in DB>`, the step-`0x50` table entry) to emit op19. That tick
runs while the client is at the login screen — the same path the desktop direct-login form uses. Calling
it *before* state 10 gets reset by the boot sequence, which is why the startup call produced nothing.

#### sub-step semantics — `-3` means SUCCESS, not empty `, <addr in DB>]`
`StoreLoginCredentials` reads each arg string's size with the EASTL formula (flag byte at `str+0x17`;
`flag>=0` → SSO `size = 0x17-flag`; `flag<0` → heap `size = *(str+8)`), then branches on emptiness (the
sub-step field is `+0x1b8` for the lobby login, `+0x16c` for the world login):

| username | password | result |
|---|---|---|
| non-empty | **non-empty** | sub-step `= `<in Ghidra DB>` (**-3**) + connection reset + `loginMgr+0x10 = 10` → **full login start** |
| empty | — | sub-step `= 3` (incomplete, no connect) |
| non-empty | empty | sub-step `= 3` (incomplete, no connect) |

So **sub-step `== -3` is the good path and PROVES both credentials landed non-empty** (watch `sub1b8` for
the lobby login, `sub16c` for the world one). The on-device observation `-2 → -3 → 13` with `state 10 → 0`
is the login **proceeding** with valid creds, not failing.

### The hook
1. **Capture `loginMgr`** — `Interceptor.attach` the `jag::LoginManager::LoginManager` ctor (`<addr in DB>`)
   `onEnter` → `loginMgr = X0` (runs once; sole caller = client ctor `<in Ghidra DB>` which
   stores the singleton). ``
2. **Poll for the login screen** — a 500 ms timer reads main-state (`*(*(loginMgr+0x18)+`<in Ghidra DB>`)`). The
   first time it is `10` **and** the login manager is idle (`directLoginReady`: `loginMgr+0x10==0`,
   `*(*(client+`<in Ghidra DB>`)+0x28)==0`), it calls **`BeginLobbyLogin(loginMgr, &user, &pass, &empty, 0)`**
   (`<addr in DB>`, `loginType=1`) once → **op19 LOBBY** login (see §7 for the lobby-vs-world decision).
3. **Diagnostics** — it emits `main-state` on every change; the loginMgr step fields before/after and for
   ~6s after; and a **credential read-back** (`readEastl`, same formula the client uses): the `built`
   line shows the size/text of the eastl args we constructed, and the `login` line shows the size/text
   read back out of `loginMgr+0x70`/`+0x88` **after** the call — proving the creds landed non-empty.

Args are EASTL strings from `makeEastlString`. **Layout verified against `StoreLoginCredentials`' own read
(`<addr in DB>`):** SSO for `<23` chars — write bytes at `+0`, NUL, set flag byte `+0x17 = 0x17-len` (size
reads back as `0x17-flag = len`); heap otherwise — `+0 data, +8 size, +0x10 capacity|`<in Ghidra DB>`00000000`.
RVAs used: `loginManagerCtor=<addr in DB>`, `beginLobbyLogin=<addr in DB>` (the hook calls the lobby variant;
`beginDirectLogin=<addr in DB>` is the world variant, kept in `rva.json` for reference).

`[CAVEAT]` The `BeginLobbyLogin` call is made from Frida's timer thread, not the client thread. The
earlier startup call from the same thread did not crash, so this is believed safe; if it proves flaky,
the alternative is to marshal it onto a client-thread hook (none fires reliably at the idle login screen,
which is why the timer is used).

**What to watch:** `captured loginMgr=…` (startup) → `client main-state -> 10` → `built args: user
size=5 'trent' …` (proves construction) → `BeginLobbyLogin fired … stored user size=5 'trent' …
sub1b8=-3` (proves the creds landed) → `post …` step progression → a **C→S op19 LOBBY** login block. If
the creds read back `size=0` the string build is wrong; if they read back non-empty (`sub1b8=-3`) but no
op19 appears, the blocker is downstream (connection to lobby, or the connect step) — **not** the creds.

`[UNVERIFIED — not yet re-run on device]` This state-10-gated hook supersedes both the seed-the-map and the
button-intercept approaches, which the on-device tests disproved.

## 3b. DELIVERABLE 2 — deployable per-user login (design, from full APK+binary investigation)

### What the login screen actually is
`[VERIFIED — binary + APK]` The login screen is **native/engine-drawn** (main-state 10, no Java UI). The
`"email/password"` option is a native→Java **JNI upcall** to `JagexMobileSDKWrapper.authenticateWithJagexWeb`
(`JagexMobileSDKWrapper.java:337`) → AppAuth **Custom Tab** launch at `g8/g.java:117`
(`startActivityForResult(authService.b(request,…), 3001)`), redirect `com.jagex.mobilesdk.android.rs:/oauth2redirect`.
`jag::android::RequestOAuth2Tokens` (`<addr in DB>`) is the token-*exchange* JNI, **not** the browser launch
— which is why the on-device native intercept never fired on a tap. There is **no Java login Activity**
and **no non-native UI form** anywhere in the APK (manifest = `NativeActivity` + OAuth/redirect/payment
Activities only).

### Building blocks that DO exist for a native form
`[VERIFIED]` (a) a **CS2 opcode** that calls `BeginLobbyLogin(user,pass,auth,mode)` from the clientscript
stack — `<in Ghidra DB>` `` (SSO twin `<in Ghidra DB>`); (b) the **`com/jagex/android/AndroidKeyboard`**
soft-keyboard bridge (``, native callers `<addr in DB>`–`<addr in DB>`) — a hidden
overlay `EditText` (`com/jagex/android/a.java:123`) feeds IME text into the native input queue, i.e.
interface text-fields CAN receive typed input. So the engine has everything to render an in-client
username/password form; only cache-side content (the login interface + its clientscript) is missing.

### The gadget, as currently baked
`[VERIFIED — APK]` `libgadget.config.so` is **`interaction:"listen"` + `on_load:"wait"`** (loopback:27042)
— it **freezes at load until a PC Frida client attaches** and **auto-loads no script** (`rs3-capture.js`
is not packaged). So the built `projectx-mobile.apk` **cannot log in standalone** today; it needs
`rs3-capture.py --gadget`. A bundled gadget script also **cannot use a Java bridge** (frida 17 removed it),
so it can only take creds from a **file it reads via frida `fs`** (SharedPreferences/Intent are unreachable
to it).

### The three deployable options, evaluated

1. **APK login Activity + gadget in script-mode — IMPLEMENTED & POLISHED (`build-projectx-mobile.sh --release`).**
   `com.jagex.projectx.LoginActivity` (**Java**, `mobile/projectx-login/LoginActivity.java`, compiled
   javac→d8→`classes2.dex`, multidex-injected) is the LAUNCHER in front of `MainActivity`. Features: a
   dark Project X-branded card UI (title, styled username/password fields, password show/hide, "Remember me"
   default-on, IME next→done), **remember-me + auto-login** (saved creds in `SharedPreferences`
   MODE_PRIVATE → skip the form and go straight to a "Logging in…" progress screen), "Switch account" to
   clear, and a **deferred error banner** driven by the status file (below). On submit/auto-login it writes
   `user\npass` to `getFilesDir/projectx-login.txt`, copies the bundled `assets/loginscript.js` to
   `getFilesDir/loginscript.js`, and starts `MainActivity` with the baked `launchurl` VIEW deeplink,
   staying on "Logging in…" for ~2.5s to cover the boot gap. The gadget config is **`type:"script"`** with
   the **absolute path** `/data/data/…/files/loginscript.js` (frida resolves relative paths against CWD `/`,
   so the asset-copy + absolute path is required; `extractNativeLibs=true`). The script reads creds via
   libc `open/read`, calls `BeginLobbyLogin` at main-state 10, then **watches the result** and writes
   `files/projectx-login-status.txt`. `--release` outputs `projectx-mobile-release.apk` (separate from the
   listen-mode capture `projectx-mobile.apk`, so the `rs3-capture.py --gadget` debug flow is preserved).
   No `.so` login patch. Launch:
   `am start -n com.jagex.runescape.android/com.jagex.projectx.LoginActivity`; logs via
   `logcat | grep projectx-login`.

   **Login-result status state machine** ` jag::LoginManager::LoginStepDealWithFirstResponse]`:
   the server's first-response result code lands at `loginMgr+0x184` (`2` = SUCCESS → proceeds to state
   `0x8c` for lobby / `0xfa` for world; other codes → logs "Login Failure Result", `SetMainState(client,10)`
   back to the login screen, sets an error sub-step). The gadget's `watchResult` therefore records:
   `ok` when main-state → `0x14` (lobby) / `0x1e` (world); `fail:<code>` when the login manager goes busy
   then returns to idle (`+0x10==0`) still at main-state `10` (reading the code from `+0x184`);
   `fail:timeout` after ~30 s. `LoginActivity` reads this file on the **next** launch: a `fail` shows the
   error banner and forces the manual form (no auto-login). **Live** errors on a failed login are the
   client's **own native login-screen error display** (the failure path calls `<in Ghidra DB>` + returns to
   the login screen) — the Android banner is the *deferred* surface only, since once the game is foreground
   the gadget cannot draw Android UI (frida 17, no Java bridge).

2. **Cache-served native login interface (cleanest long-term, no gadget).** Project X serves a login
   interface (text-field components + a "Login" button whose clientscript invokes the `BeginLobbyLogin`
   CS2 opcode, using `AndroidKeyboard` for input). Fully native, no gadget/APK login code. **Open risks:**
   whether the client renders Project X's login interface in place of the OAuth one (identify the login
   interface id it loads), and pinning the CS2 opcode number from the mobile opcode table. This is a
   **cache-library-engineer + content** effort, not a `.so` change — pursue it to eventually drop the
   gadget from production.

3. **Repurpose the Java OAuth method (NOT clean).** `authenticateWithJagexWeb` is Java-reachable, so a
   smali edit could make it pop our own form — but Java has **no path to call native `BeginLobbyLogin`**
   (it is an internal engine function, not a JNI export) or to write the native cred map, so it still
   needs the gadget or option 2 to complete the login. No advantage over option 1.

**Recommendation:** ship **option 1** (Activity + file + script-mode gadget) for a working standalone
per-user login now; pursue **option 2** (cache login interface) as the gadget-free production endgame.
Intent-extra creds via `StartupArguments` are ruled out — `GetArgumentValue` returns `null` whenever a
`VIEW` deeplink is set, which collides with the `launchurl` redirect, and a bundled gadget can't read
Intents anyway.

*(Optional static add-on for either: NOP the `IsUserAuthenticated` call at `<addr in DB>` →
`mov w0,#0` `00 00 80 52` LE to force the direct branch; usually unnecessary as it is already `0` on a
fresh private launch.)*

---

## 4. Direct-login block layout  (task 4)

Two-stage build. `<in Ghidra DB>`→`<in Ghidra DB>` stores creds into the **login-state** object; then the
serializer `<in Ghidra DB>` (state `0x50`→`0x5a`) writes the wire packet.

### Login-state offsets ``
| Offset | Field | Notes |
|---|---|---|
| `+0x20` | mode | `2` = direct (set by `<in Ghidra DB>`); `1` = the other variant |
| `+0x28/0x30` | connection object | |
| `+0x40` | **session nonce** (u64) | server-provided seed; goes into RSA block |
| `+0x48` | **4 ISAAC keys** (4×u32) | generated by `<in Ghidra DB>` from a seed Isaac |
| `+0x68` | seed Isaac* | source of the 4 keys |
| `+0x70` | **username** (eastl::string) | SSO byte `+0x87`, len `+0x78` |
| `+0x88` | **password** (eastl::string) | SSO byte `+0x9f`, len `+0x90` |
| `+0xa0` | **authenticator/2FA** (eastl::string) | SSO byte `+0xb7`; len `6` ⇒ TOTP |
| `+0x120` | token / **`-1` sentinel** | `<in Ghidra DB>` sets `-1` ⇒ username sent as string (direct) |
| `+0x140` | auth-token discriminator | `0` for basic direct login |

### RSA block plaintext (built by `<in Ghidra DB>` + `<in Ghidra DB>` + `<in Ghidra DB>`)
`` header, `` auth-mode, `` tail:

| Offset | Size | Type/Transform | Field | Source |
|---|---|---|---|---|
| `0x00` | 1 | raw `0x0a` | **magic** | literal |
| `0x01` | 4 | u32 **BE** | ISAAC key[0] | state`+0x48` |
| `0x05` | 4 | u32 BE | ISAAC key[1] | state`+0x4c` |
| `0x09` | 4 | u32 BE | ISAAC key[2] | state`+0x50` |
| `0x0d` | 4 | u32 BE | ISAAC key[3] | state`+0x54` |
| `0x11` | 8 | u64 BE | **session nonce** | state`+0x40` |
| `0x19` | var | — | **auth-mode block** (see below) | `<in Ghidra DB>` |
| … | 1 | raw | token discriminator (`0`) | state`+0x140` |
| … | var | RS-string | **password** | state`+0x88` |
| … | 8 | u64 BE | field | state`+0x130` (=0 for direct) |
| … | 8 | u64 BE | field | state`+0x138` |

Auth-mode block (`<in Ghidra DB>`, chooses by authenticator string length at state`+0xa0`):
- authenticator len == 6 → byte(`3` if trust-this-computer flag `+0xb8` else `1`) + 3-byte code
- else if flag `+0xb9` → byte `0x00` + u32 BE (`+0xbc`)
- else → byte `0x02`, then 4 skipped bytes (position `+5`)

Then the whole plaintext is RSA-encrypted (`<in Ghidra DB>`, login key) → `[u16 BE len][ciphertext]`,
which is memcpy'd into the main packet.

`` The 4 ISAAC keys are pulled live from the seed Isaac (`state+0x68`) at build
time; after the packet is sent, `<in Ghidra DB>` builds the c2s Isaac from the **raw** keys (`state+0x48`)
and the s2c Isaac from **keys+50** — see [packet-capture-hooks.md](packet-capture-hooks.md#isaac).

### Outside the RSA block (then XTEA-enciphered)
`` After the RSA ciphertext, `<in Ghidra DB>` writes (among version/client fields):
- the `state+0x120 == -1` flag byte (`1` for direct)
- because `+0x120 == -1`: the **username** as a NUL-terminated string (from state`+0x70`)
- device/hardware fingerprint block (`<in Ghidra DB>`, ~40 u32 fields)

Then **XTEA** (`<in Ghidra DB>`, `<addr in DB>`) enciphers a trailing range using the 4 ISAAC keys
(`state+0x48`) as the 128-bit XTEA key: `<in Ghidra DB>(packet, state+0x48, start, end)`, 32 rounds,
delta `0x9e3779b9`, 8-byte BE blocks. Finally a **u16 BE length** is patched at `packet+1`.

`[VERIFIED — artifact, XTEA-decrypted capture]` **RESOLVED:** XTEA covers the **entire tail starting
immediately after the RSA block** — i.e. from the `hasSessionToken` flag byte onward (flag + username +
whole descriptor + client-settings block). Confirmed by decrypting both real op19/op16 tails with the
captured ISAAC keys (which are the XTEA key); the plaintext parses cleanly from off 0 = the flag byte.
See §6.3 for the byte-map. (The desktop `SendLoginPacket` sets the tinyKeyEncrypt start `local_a8` to the
position right after the RSA append, matching this.)

---

## 5. Divergences flagged for the user (mobile vs Project X desktop blueprint)

1. **Login modulus differs from Jagex's desktop key.** Mobile login `n` = `83fec000…` (1024-bit) is
   embedded distinct from Project X's `JAGEX_*_HEX`. Project X patches desktop via LD_PRELOAD; **mobile has no
   patcher**, so jav_config `param=99`/`param=100` are ignored — the key must be swapped in-process
   (frida `<in Ghidra DB>` init-hook) and Project X must hold the matching private key.
2. **JS5 modulus is 4096-bit** (`a4ba3320…`), not the smaller desktop key — matches Project X's stated
   4096-bit JS5 size but is a different key. Same swap requirement.
3. **Password lives in the RSA block (`state+0x88`); username lives in the XTEA tail (`state+0x70`).**
   Confirm Project X's mobile lobby handler parses this order. Desktop's blueprint (authToken+password in the
   RSA tail, username in XTEA) matches structurally, but on mobile the RSA-tail string is the **password**
   (there is no separate authToken for a basic direct login; the `+0x140` discriminator is `0`).
4. **The direct trigger is `isUserAuthenticated == false`**, and creds come from a `cfg+0x7690` map keyed
   `"username"`/`"password"` — not directly from an OAuth-less command. Force via the `<in Ghidra DB>`→0
   hook + seeded creds.

## 6. Mobile detection signal — how the server tells a mobile login from desktop  (task 3b)

Answers OPEN-QUESTIONS **Q3b**. The op19 login descriptor (the XTEA-enciphered tail) carries the
client's OS/platform. There are **two** consecutive bytes near the end of the descriptor that encode it;
the response block carries **no** OS field. Everything below is read from the mobile binary; the desktop
`rs2client.949-1` is cited only to confirm field order and the enum.

### 6.1 The serializer, renamed

`` `<in Ghidra DB>` = **`jag::LoginManager::SendLoginPacket`** — login-state `0x50`.
It is 1:1 with desktop `rs2client.949-1` `jag::LoginManager::SendLoginPacket` (same
source, different ISA), which lets the mobile field order be cross-checked against the desktop's named
`Packet::pT<…>` calls. Branch: `*(LoginMgr+0x20) == 2` → **world**; else → **lobby** (`loginMode 1`).

### 6.2 Three indicators, ranked (ground-truth confirmed)

`[VERIFIED — artifact, XTEA-decrypted capture]` The coordinator recovered the plaintext of both real
op19/op16 tails (Pixel 6; ISAAC keys from the capture = the XTEA key). Every offset below is a **byte
position in the XTEA-decrypted tail** of the real LOBBY login. Three fields distinguish android:

| Rank | Field | LOBBY off | Type | Android | Desktop | Source |
|---|---|---|---|---|---|---|
| **1** | **`"NXT-Android"` client-name string** | **269** | CP1252 `NUL`-terminated, inside the machine-info block | `NXT-Android` | `NXT-Windows` / `NXT-Linux` / `NXT-Mac` | `.rodata "NXT-Android"`, via `<in Ghidra DB>` `` |
| **2** | **`binaryType` byte** | **377** | u8 | **`0x07`** | `0x00`–`0x06` (never 7/8) | `Client.binaryType` low byte (Ghidra `RELA[0xcb3]`) |
| **3** | **`platformType` byte** | **378** | u8 | **`0x02`** | `0x00` (or `0x05`) | `jag::GetPlatformType(Client*)` `` |

`` `jag::GetPlatformType` (renamed from `<in Ghidra DB>`; desktop twin `<in Ghidra DB>`
@ `rs2client <addr in DB>`, identical mapping):

```c
int GetPlatformType(Client* c) {
    if (<in Ghidra DB>(...) & 1) return 1;   // <in Ghidra DB> is a stub → 0 on mobile, so this is DEAD here
    int bt = c->binaryType;                // the same field written as the binaryType byte
    if (bt == 7) return 2;                 // ANDROID
    if (bt == 8) return 3;                 // iOS
    if (c->someObj && (c->someObj->flags@+0x169 & 1)) return 5;
    return 0;                              // desktop default
}
```

**Why `"NXT-Android"` is rank 1 for the server:** it sits at the **same spot (~off 269) in BOTH the lobby
and world tails** (world off 271; the small shift is the 2-byte head difference in §6.4), whereas the
`binaryType`/`platformType` bytes are at **different offsets** in lobby (377/378) vs world (358/359)
because the two branches order the surrounding fields differently. A server can therefore detect mobile
**uniformly** across lobby and world by scanning the XTEA-decrypted tail for the literal ASCII
`"NXT-Android"` (unique, desktop sends `NXT-Windows`/`NXT-Linux`/`NXT-Mac`). The two bytes are the
protocol-clean alternative: `binaryType == 7` is exactly the client's own mobile self-test — the
`hasSocialAuth` computation at the end of `SendLoginPacket` gates on `(binaryType - 7) < 2` (`7` or `8`
⇒ mobile) ``.

### 6.3 LOBBY tail byte-map (`loginMode==1`) — ground truth

`[VERIFIED — artifact]` from the decrypted 564-byte LOBBY tail (this session used OAuth/SSO, so the
username is empty; for a directlogin the name occupies the empty slot at off 1). All multi-byte ints are
**big-endian**. The op19 body before this tail is `[u16 size][int 0x3B5=949][int 1][u16 RSA-len][RSA
ciphertext]`; XTEA covers everything from off 0 below (see §4 — now empirically confirmed).

```
off 0    : 01              hasSessionToken / (loginToken@+0x120 == -1) flag
off 1    : 00              username RS-string — EMPTY here (just the NUL). directlogin puts the name here.
off 2    : 00              configByteA   (LOBBY-ONLY; first char of a client string, RELA[0xc80])
off 3    : 00              configByteB   (LOBBY-ONLY; first char of a client string, RELA[0xc85])
off 4    : 03              loginType     (3 = direct socket, 2 = WebSocket)
off 5-6  : 05 35           screenWidth   = 1333  (u16 BE)
off 7-8  : 02 58           screenHeight  = 600   (u16 BE)
off 9    : 00              displayMode
off 10-33: FF × 24         machineInfo24 (24-byte block; LOBBY = all-FF, WORLD = per-session UID/token)
off 34-77: "wwGl…Ovk"\0    clientInfo string (here a 43-char session token) [pStringNoConversion, CP1252+NUL]
off 78-79: 3a 26           machine-info block header word
off 80-329 machine-info hardware block (self-describing; contains, in order):
             "Mali-G78"\0                              GL renderer     (off 149)
             "OpenGL ES 3.2 v1.r54p1-…c5"\0            GL version      (off 170)
             "ARM64"\0 "ARM64"\0                       CPU              (off 235, 240)
           ★ "NXT-Android"\0                           CLIENT-NAME / OS (off 269-280)  ← RANK-1 INDICATOR
             "google / Pixel 6 (oriole / oriole) (Android 16)"\0   device (off 282-329)
off 330-339: 00 × 10        (padding / zeroed fields)
off 340-343: 0f da 7a 95    constant 0x0FDA7A95 (also present in the world tail)
off 344-376: "og55…qw"\0    client-token string (32-char) [pStringNoConversion]
off 377  : 07              ★ binaryType   (android=7; ios=8; desktop 0–6)   ← RANK-2 INDICATOR
off 378  : 02              ★ platformType (GetPlatformType; android=2; ios=3; desktop 0/5) ← RANK-3
off 379  : 00              hasSocialAuth
off 380-559: WriteLoginClientSettingsBlock — ~40 u32 BE client-config fields (<in Ghidra DB>)
off 560-563: 5b 15 7b e0    final settings field
```

The machine-info hardware block is now **exhaustively byte-mapped** in
[machine-info.md](machine-info.md) — it is three fixed-layout encoder sub-blocks
(`WriteMachineInfoBlock` 58-byte numeric, `WriteDeviceInfoBlock` device strings incl. `"NXT-Android"`,
`WriteLoginClientSettingsBlock` 46× u32). To reach the `binaryType` byte the server walks (lobby): `flag →
username(RSString) → configByteA → configByteB → loginType → w → h → displayMode → machineUid(24) →
clientInfo(RSString) → machineInfoLen+block(58) → deviceInfoBlock → configInt0 → js5Count+CRCs →
clientToken(RSString, empty) → configInt1 → configInt2(0x0FDA7A95) → sessionToken(RSString) → binaryType`.
Because the device block is variable, **scanning the decrypted tail for `"NXT-Android"` is the simpler,
equally-robust route** (§6.2). The **complete per-byte decoder contract** — every byte named + typed,
round-trip-verified to exactly 564 (lobby) / 583 (world) — is **[machine-info.md](machine-info.md)**.

### 6.4 Lobby vs world head difference & indicator positions

`[VERIFIED — artifact]` The two tails begin:
```
LOBBY: 01 00 00 00 03 05 35 02 58 00 …
WORLD: 01 00       03 05 35 02 58 00 …
```
Aligning on the common `03 05 35 02 58 00` (loginType/width/height/displayMode): both share the leading
`01 00` (`hasSessionToken` flag + empty username NUL), then **LOBBY inserts two extra bytes `00 00`** =
`configByteA` + `configByteB`, which the world branch does **not** emit ``. That
is the whole 2-byte head difference.

Consequently the byte indicators sit at **different offsets** per branch:

| | `"NXT-Android"` | `binaryType` | `platformType` | Order note |
|---|---|---|---|---|
| LOBBY (op19) | ~off 269 | off 377 | off 378 | binaryType/platform come **after** the 32-char client-token string |
| WORLD (op16) | ~off 271 | off 358 | off 359 | binaryType/platform come **before** `0x0FDA7A95` + the client-token; world then appends an int, a string, `hasSocialAuth`, and a trailing `u16` self index |

Both branches emit all three indicators; only `"NXT-Android"` holds a near-constant position across
both, which is why it is the recommended uniform signal.

### 6.5 Response side — there is NO OS field (honest verdict)

`` `<in Ghidra DB>` = **`jag::LoginManager::LoginStepHandleLoginData`** (login-state
`0x96`, found via the handler table built in `jag::LoginManager::LoginManager`. It is
1:1 with desktop `rs2client.949-1` (already field-mapped in
the desktop login-block layout in the Ghidra DB).

The mobile decoder reads, in the **lobby** branch: rights (`+8`), rightsFlags (`+0xc`), flags, signed
member medium (`+0x14`), staffMod (`+0x88`), member flags/`memberEndDate g8` (`+0x30`), the time math,
account flags (`+0x28/+0x29`), `+0x40`, `+0x44`, **playerIndex g2** (`+0x1c`), `+0x20`, `+0x60`, `+0x64`,
`+0x24`, `+0x38`, `+0x3c`, flag (`+0x18`), **displayName** jag-string (`+0x68`), `+0x84`, `+0x80`, then
the **world redirect** (worldId g2, host jag-string, port1 g2, port2 g2, sessionId1 g8 → `LoginMgr+0xf0`,
sessionId2 g8 → `+0xf8`). The world branch is the shorter variant. On completion it calls
`SetMainState(0x14)` (lobby) / `SetMainState(0x1e)` (logged-in).

**No byte in either branch is an OS / platform / layout selector.** The mobile client does **not** learn
"I am mobile" from the server; its mobile UI is **inherent to the binary**. The server "acknowledges"
mobile purely by serving the **mobile interface tops/subs + varps/varbits + clientscripts** *after* login
— which the client selects itself based on its own build — not by a response flag.

**Server implication:** Project X's lobby/world must (a) read `binaryType` from the C2S op19 descriptor to
know the session is mobile, and (b) serve the mobile interface/var/script set post-login. There is
nothing to add to the login-details response for OS; adding a spurious byte there would desync the
decoder (it consumes a fixed field list).

### 6.6 Ghidra symbols committed (mobile DB)

| Address | New name | Evidence |
|---|---|---|
| `<addr in DB>` | `jag::LoginManager::SendLoginPacket` | state 0x50; 1:1 desktop `<in Ghidra DB>` |
| `<addr in DB>` | `jag::LoginManager::LoginStepHandleLoginData` | state 0x96; 1:1 desktop `<in Ghidra DB>` |
| `<addr in DB>` | `jag::LoginManager::LoginStepDealWithFirstResponse` | state 0x60; result-code dispatch |
| `<addr in DB>` | `jag::LoginManager::LoginManager` | ctor; builds the state→handler table |
| `<addr in DB>` | `jag::GetPlatformType` | binaryType→platform enum; desktop twin `<in Ghidra DB>` |
| `<addr in DB>` | `jag::LoginManager::WriteLoginClientSettingsBlock` | 46 u32 BE client-config fields before XTEA |
| `<addr in DB>` | `jag::WriteMachineInfoBlock` | 58-byte platform capability block; desktop twin `<in Ghidra DB>` |
| `<addr in DB>` | `jag::WriteDeviceInfoBlock` | device strings block (incl. `"NXT-Android"`); desktop twin `<in Ghidra DB>` |
| `<addr in DB>` | `jag::AttemptStoredLogin` | login-mode decision; `credMap=*(clientObj+`<in Ghidra DB>`)+0x7690` |
| `<addr in DB>` | `jag::IsUserAuthenticated` | KV lookup `"isUserAuthenticated"`; hook→0 forces direct |
| `<addr in DB>` | `jag::LoginManager::BeginLobbyLogin` | direct user+pass entry, `loginType=1` (op19 LOBBY) — the hook uses THIS |
| `<addr in DB>` | `jag::LoginManager::BeginDirectLogin` | direct user+pass entry, `loginType=2` (op16 WORLD) |
| `<addr in DB>` | `jag::DirectLoginWithCredentials` | persists creds to map + logs in; form-submit handler |
| `<addr in DB>` | `jag::ConfigMap::SetString` | FNV-1a hashmap insert/update; the cred-seed primitive |
| `<addr in DB>` | `jag::ConfigMap::FindString` | cred-map lookup; `0` ⇒ key absent |
| `<addr in DB>` | `jag::android::RequestOAuth2Tokens` | JNI `JagexMobileSDK.requestOAuth2Tokens` (OAuth phase-1; button) |
| `<addr in DB>` | `jag::LoginManager::LoginManager` | ctor; X0=loginMgr singleton captured for the hook |
| `<addr in DB>` | `jag::LoginManager::BeginSsoLogin` | SSO login (OAuth phase-2; needs prior tokens) |
| `<addr in DB>` | `jag::Client::SetMainState` | writes main-state client+`<in Ghidra DB>`; 10=login screen, 0x1e=logged in |
| `<addr in DB>` | `jag::LoginManager::StoreLoginCredentials` | copies creds to +0x70/+0x88/+0xa0; sets +0x16c (-3=both present, 3=incomplete) |
| `<addr in DB>` | `jag::LoginManager::LoginStepHandleLoginData` | S→C login-details decoder; `loginType==2`→WORLD/short/`SetMainState(0x1e)` (§7) |

Full byte-exact field map (machine-info numeric block, device block, settings block, world deltas, Kotlin
decoder contract): **[machine-info.md](machine-info.md)**.

## 7. Login type — LOBBY-first (the hook uses `BeginLobbyLogin`)  (server-critical)

`, <addr in DB>, <addr in DB>, <addr in DB>]` There are **two** direct-login entries with
the **same signature** `(loginMgr, &username, &password, &authenticator, mode)`; they differ only in the
`loginType` (`loginMgr+0x20`) they store via `StoreLoginCredentials`:

| Function | RVA | `loginType` | C→S descriptor | S→C response branch | terminal |
|---|---|---|---|---|---|
| `jag::LoginManager::BeginLobbyLogin` | `<addr in DB>` | **1** | **op19 LOBBY** (username + configByteA/B) | LONG lobby (playerIndex, displayName, worldId+host+port1+port2+2×sessionId) | `SetMainState(0x14)` = **LOBBY screen** |
| `jag::LoginManager::BeginDirectLogin` | `<addr in DB>` | 2 | op16 WORLD | SHORT world | `SetMainState(0x1e)` = LOGGED IN in-world |

**Decision: Project X is lobby-first (separate lobby/world processes), so the mobile hook calls
`BeginLobbyLogin` (`<addr in DB>`, `loginType=1`).** The client then emits the **op19 LOBBY** block (the
format the existing `LobbyLoginHandler` decodes as `LoginMode.LOBBY`), the server replies with the
**LOBBY** login-details response (the ~103-byte block **with the world redirect**, ending
`SetMainState(0x14)` → lobby screen with the mobile ANDROID interface subset), and "Play" hands off to the
world like desktop. `LoginStepHandleLoginData` dispatch is `loginType==2 → world/short/0x1e`, **else
(incl. 1) → lobby/long/0x14**.

`jag::LoginManager::LoginStepHandleLoginData` (`<addr in DB>`) LOBBY branch = the desktop-mapped block in
the desktop login-block layout in the Ghidra DB (§6.5 lists the field
order: rights, rightsFlags, member medium, staffMod, memberEndDate g8, account flags, playerIndex g2
`+0x1c`, displayName jag-string `+0x68` **with version byte**, then worldId g2 + host jag-string + port1
g2 + port2 g2 + sessionId1 g8 `+0xf0` + sessionId2 g8 `+0xf8`). Note the LOBBY displayName/host use the
**version-byte** jag-string variant (`<in Ghidra DB>` mode 1), unlike the world branch's plain string.

### 7.1a op19 DIRECT login RSA-tail — the password (answers "where's the password")
`` The RSA plaintext is loginType-**independent** (the same builder runs for op19
and op16); it branches only on the **token discriminator** `state+0x140`. Full RSA plaintext:

```
<in Ghidra DB> : 0x0a magic + 4×u32 ISAAC keys (16B) + u64 nonce (8B)
<in Ghidra DB> : auth-mode/2FA block   (basic direct login, no authenticator => 0x02 + 4 bytes)
<in Ghidra DB> tail, when state+0x140 == 0 (DIRECT login):
   [1]   tokenDiscriminator = 0x00
   [var] PASSWORD: string bytes + NUL      (from state+0x88; CP1252, per-char via <in Ghidra DB>/2528)
   [8]   u64 BE  (state+0x130 = 0 for basic direct)
   [8]   u64 BE  (state+0x138)
```

For the **OAuth** login (`state+0x140 == 1`) the tail is instead `[disc=1][OAuth token + NUL]` — **no
password**. So the op19 DIRECT tail carries the password exactly where the op16 DIRECT tail did (the
coordinator already extracted `"meme"` from it); the only difference from the op19 **OAuth** tail is
`disc=0` + password (+ two u64s) in place of `disc=1` + token. **No new parsing needed** beyond routing on
the discriminator byte. `[VERIFIED — artifact, op16 tail decoded to "meme"]`

### 7.2 (reference only) WORLD login-details block (`loginType==2`) — after `[0x02 SUCCESS][u8 len]`
Not used by the lobby-first hook; kept for completeness (this is what `BeginDirectLogin`/`loginType=2`
expects). `` all multi-byte fields **big-endian**; `nameChangeFlag=0` (normal):
`` all multi-byte fields **big-endian**; `nameChangeFlag=0` (normal):

| Offset | Size | Type | Field | Target |
|---|---|---|---|---|
| 0 | 1 | u8 | **nameChangeFlag** (send `0`; `1` = ISAAC-enciphered rename block) | — |
| 1 | 1 | u8 | rights | account+0x08 |
| 2 | 1 | u8 | rightsFlags | account+0x0c |
| 3 | 1 | u8 | flag (bool) | account+0x10 |
| 4 | 1 | u8 | bool | account+0x19 |
| 5 | 1 | u8 | bool | account+0x1a |
| 6 | 1 | u8 | bool | details+0x08 |
| 7–8 | 2 | u16 | (g2) | account+0x48 |
| 9 | 1 | u8 | bool | account+0x28 |
| 10–12 | 3 | i24 signed | member medium (g3) | account+0x14 |
| 13 | 1 | u8 | bool | `<in Ghidra DB>(details)` |
| 14… | var | **CP1252 NUL-terminated string, NO version byte** | **displayName** | client+`<in Ghidra DB>` |
| +2 | 2 | u16 | member-end hi | account+0x90 (combined w/ server time) |
| +4 | 4 | u32 | member-end lo | account+0x90 |
| +8 | 8 | u64 | **sessionId1** | LoginMgr+0xf0 |
| +8 | 8 | u64 | **sessionId2** | LoginMgr+0xf8 |

**Total length = `37 + displayNameLen`.** `displayName` uses `<in Ghidra DB>` **mode 0** = raw CP1252 bytes
+ NUL, **no leading version byte** (the lobby branch's displayName/host use the version-byte variant —
do not confuse them). After decode → `SetMainState(0x1e)`; the client is in-world and expects world game
packets. The response carries **no** OS/platform field (§6.5).

`[UNCONFIRMED — hypothesis]` The semantics of the u16 `+0x48`, the three bools (`+0x19/+0x1a/+0x28`), and
the `details+0x08`/`<in Ghidra DB>` bools are not individually named; the **byte layout/types/order above
are verified** and are what the decoder consumes — safe placeholder values (0) parse cleanly.

## Cross-references
- ISAAC / capture hooks: [packet-capture-hooks.md](packet-capture-hooks.md)
- jav_config redirect: [jav-config.md](jav-config.md)
- Response block field table (desktop, ported): the Ghidra DB
- Ground rules: [../re-methodology/cross-architecture-porting.md](../re-methodology/cross-architecture-porting.md)
