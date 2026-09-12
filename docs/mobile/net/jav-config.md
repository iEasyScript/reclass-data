# `jav_config.ws` — Config Fetch, Redirect Surface, and URL Construction

The mobile client uses the **same `jav_config.ws` mechanism as the desktop client**
`[VERIFIED — artifact]`. Project X already serves `jav_config.ws`, and `jav_config` is what hands the
client its lobby/world hosts and RSA keys.

**Status: the config-URI host source is RESOLVED.** It is the `launchurl` query parameter of the
launching deeplink. See [android/startup-arguments.md](../android/startup-arguments.md) for the
channel; this document covers the URL construction itself.

## The builder: `<in Ghidra DB>`

Left unnamed in Ghidra — its precise `jag::` identity is not proven. It is a **virtual method**,
referenced from the vtable at `<addr in DB>` and dispatched indirectly from `<addr in DB>`
``. Desktop's structural twin `<in Ghidra DB>` is called directly from
`MainLogic` — an inlining/dispatch difference, not a behavioural one.

It is rate-limited (a `1000`-unit delta against a stored timestamp) and gated by a
"config already resolved" field at `param_1[0xa64f]` ``.

### Resolution order `, <addr in DB>]`

```c
host = "";                                        // eastl::string, SSO
deeplink = StartupArguments::GetDeepLinkString; // "" unless URI contains "runescape.com/playnow"

if (!deeplink.empty) {
    params = ParseUrlQueryParameters(deeplink);   // split on '?', then '=' and '&'
    for (kv : params)
        if (kv.key.size == 9 && memcmp(kv.key, "launchurl", 9) == 0) {
            host = kv.value;                      // VERBATIM — no percent-decoding
            break;
        }
}

if (host.size != 0)                             // ← the branch that matters
    sprintf(out, "http://%s/jav_config.ws?binaryType=%s", host, "7");
else
    sprintf(out, "https://rs.config.runescape.com/l=%i/jav_config.ws?binaryType=%s", lang, "7");
    // ... then the rs-launch mechanism below may still override `out`
```

The emptiness test is on the `eastl::string` **length**, decoded from the SSO discriminator byte at
`+0x17` (high bit set ⇒ heap, length at `+0x8`; else length is `0x17 - byte`).

### The strings and constants

| Address | Value | Role | Tag |
|---|---|---|---|
| `<addr in DB>` | `http://%s/jav_config.ws?binaryType=%s` | override URL — host substitutable, **plain HTTP** | `` |
| `<addr in DB>` | `https://rs.config.runescape.com/l=%i/jav_config.ws?binaryType=%s` | hardcoded production default | `` |
| `<addr in DB>` | `launchurl` | the query-parameter key (length 9) | `` |
| `<addr in DB>` | `7` | **binaryType for Android** | `` |
| `<addr in DB>` | `?` | query separator for the rs-launch join | `` |
| `<addr in DB>` | `&` | query separator for the rs-launch join | `` |
| `<addr in DB>` | `http://` | replaced with `""` in the rs-launch path | `` |
| `<addr in DB>` | `rs-launch` | scheme → rewritten to `http` | `` |
| `<addr in DB>` | `rs-launchs` | scheme → rewritten to `https` | `` |

`launchurl` sits at `<addr in DB>`, immediately after `GetArgumentCount` (`<addr in DB>`, 16 bytes + NUL)
— the two are adjacent in `.rodata`, which is itself a small corroboration that they belong to the
same startup-argument code.

### binaryType is 7 on mobile, 4 on desktop — action required

`` mobile emits `binaryType=7`. `[VERIFIED — desktop rs2client 949-1` desktop emits `binaryType=4`.

Project X's tooling is hardcoded to `binaryType=4`
(`tools/src/main/kotlin/org/projectx/tools/util/JavConfig.kt:6`) `[VERIFIED — artifact]`. If Project X's
lobby **switches on** the `binaryType` query parameter when serving `jav_config.ws`, it must learn to
answer `binaryType=7`, or the mobile client will get a desktop config (wrong `binary_name`,
`download_crc_*`, and possibly a client-out-of-date rejection). If the handler ignores the parameter,
nothing is needed. **Verify on the Project X side** — this is the most likely first failure after a
successful redirect.

## The redirect, resolved

```
am start -a VIEW -d 'https://secure.runescape.com/playnow/rs?launchurl=HOST:PORT'
      │
      ▼
StartupArguments.SetupMainActivity  → captures URI (VIEW action only)
      │
      ▼
GetDeepLinkString  → returns URI (contains "runescape.com/playnow")
      │
      ▼
ParseUrlQueryParameters → [("launchurl", "HOST:PORT")]
      │
      ▼
http://HOST:PORT/jav_config.ws?binaryType=7        ← plain HTTP, native libcurl
      │
      ▼
Project X jav_config.ws → lobby host, world host, RSA keys, JS5 endpoint
```

Full launch command and its three constraints:
[android/startup-arguments.md](../android/startup-arguments.md#the-answer-up-front).

### Cleartext is not a problem here `[VERIFIED — artifact]`

The manifest restricts cleartext at the Java layer, but this fetch happens in **native**: libcurl and
BoringSSL are statically linked into the `.so` and use raw sockets. Native code never consults
`NetworkSecurityPolicy`, so the Java-layer restriction does not apply. See
[../android/apk-structure.md](../android/apk-structure.md).

## The `rs-launch` mechanism — UNRESOLVED

`` A **second, independent** config-URI mechanism exists in the same function,
inside the branch taken when `launchurl` is absent. It reads an object at `param_1[0xa66f]` (with a
validity check against `param_1[0xa670]`), takes a URL from that object at `+0x18`, and:

- if the URL starts with `rs-launchs` → replace the scheme with `https`
- else if it starts with `rs-launch` → replace the scheme with `http`
- else (a containment test) → strip a leading `http://`
- then append `?binaryType=7` or `&binaryType=7` (`?` if the URL has no existing `?`, else `&`)

This is **strictly more powerful than `launchurl`**: it supplies a full URL — host *and path* — not
just an authority. It exactly matches the manifest's otherwise-unexplained intent-filter
`scheme="rs-launch" host="*runescape.com" pathPattern=".*jav_config.ws"` `[VERIFIED — artifact]`, and
it is exactly the mechanism Project X's Windows launcher already drives on desktop:

```
run-client.ps1:36   [string]$ConfigUri = "rs-launch://127.0.0.1:8829/jav_config.ws"
```
`[VERIFIED — artifact, Project X run-client.ps1]` — where the URL is passed as rs2client's **positional
`argv[1]`**.

`[UNCONFIRMED — hypothesis]` **The write site of `param_1[0xa66f]` (byte offset `+`<in Ghidra DB>`) has not
been located, so this path is not confirmed reachable on mobile.** The obstacle is real: an
`rs-launch://…/jav_config.ws` URI does not contain `runescape.com/playnow`, so `GetDeepLinkString`
returns `""` for it and it cannot arrive that way. The natural candidate is the argv vector
(`GetArgumentKey(0)` returns the raw deeplink URI when one is set, which would make it the mobile
`argv[1]`) — but that vector is **provably never read**
([startup-arguments.md](../android/startup-arguments.md#channel-1-intent-extras--collected-then-discarded)).

Two readings, not yet distinguished:

1. The manifest filter is **vestigial** — carried over from desktop's positional-argv design, with the
   mobile wiring never completed. The `launchurl` path is the only live one.
2. Some other, unlocated writer feeds `param_1[0xa66f]`, and `rs-launch://` deeplinks work.

Reading 1 is favoured by the evidence so far. **Resolving this is Q1 in
[OPEN-QUESTIONS](../OPEN-QUESTIONS.md)**, and it is worth resolving because reading 2 would give path
control, not just host control. It is also cheap to test empirically:

```bash
adb shell am start -n com.jagex.runescape.android/com.jagex.android.MainActivity \
  -a android.intent.action.VIEW -d 'rs-launch://127.0.0.1.runescape.com/jav_config.ws'
```
then watch for a fetch. A negative result supports reading 1.

## Config keys present `[VERIFIED — artifact]`

These string constants in the `.so` are `jav_config` keys and match the desktop set:

| Key | Role |
|---|---|
| `lobbyID` | lobby node identifier |
| `js5connect` | JS5 endpoint |
| `js5connect_full` | JS5 endpoint (full) |
| `js5connect_outofdate` | JS5 endpoint (client out of date) |
| `directlogin` | direct login endpoint |
| `directloginlobby` | direct login, lobby |
| `directlogin-lobby-sso` | direct login, lobby, SSO |
| `directlogin-game-sso` | direct login, game, SSO |

`[UNCONFIRMED — hypothesis]` The exact semantics and value format of each key — inferred from names
and desktop parity, not from decompiling the parser.

## Related endpoints `[VERIFIED — artifact]`

```
http://world2.runescape.com/error_game_%s.ws    ← error reporting
```

## Desktop cross-check — the strongest confirmation available

`[VERIFIED — desktop rs2client 949-1` Desktop's `<in Ghidra DB>` is a **structural twin**
of mobile's `<in Ghidra DB>`, across the ISA boundary:

| Behaviour | Mobile (AArch64) | Desktop (x86-64) |
|---|---|---|
| Deeplink/launch string source | `GetDeepLinkString` (JNI) | `<in Ghidra DB>` (from `<in Ghidra DB>`) |
| Query-param parser | `<in Ghidra DB>` | `<in Ghidra DB>` |
| Key searched | `"launchurl"` | `"launchurl"` |
| Pair layout | stride `0x30`, key `+0x00`, value `+0x18` | identical |
| Override URL | `http://%s/jav_config.ws?binaryType=%s` | same string |
| Default URL | `https://rs.config.runescape.com/l=%i/...` | same string |
| binaryType | `"7"` | `"4"` |
| rs-launch rewrite | present | present |
| Launch-URL object | member `param_1[0xa66f]` | parameter `param_2` |

Desktop is **949-4**, mobile **949-3** — same major, so the protocol matches, but architecture is NOT the only axis of difference. The
identical `launchurl` string, identical format strings, identical `0x30` pair stride and identical
two-branch structure make this a high-confidence match. See
[../re-methodology/cross-architecture-porting.md](../re-methodology/cross-architecture-porting.md).
</content>
