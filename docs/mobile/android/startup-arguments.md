# Startup Arguments — the Intent → Native Argument Channel

**Status: RESOLVED.** The argument key is **`launchurl`**, and it is **not an Intent extra** — it is a
**query parameter on the launching deeplink URI**.

This document supersedes the earlier hypothesis that native code compares Intent-extra keys against
string literals. It does not. See [Two channels](#two-channels-one-of-them-is-dead) below.

## The answer, up front

```bash
adb shell am start \
  -n com.jagex.runescape.android/com.jagex.android.MainActivity \
  -a android.intent.action.VIEW \
  -d 'https://secure.runescape.com/playnow/rs?launchurl=192.168.1.10:8829'
```

This yields a config fetch of `http://192.168.1.10:8829/jav_config.ws?binaryType=7`
`, <addr in DB>]`.

Three constraints, all of which the URI above satisfies:

| # | Constraint | Enforced by | Tag |
|---|---|---|---|
| 1 | Intent action **must** be `android.intent.action.VIEW` (or `org.chromium.arc.intent.action.VIEW`) | `StartupArguments.SetupMainActivity` | `[VERIFIED — artifact]` |
| 2 | The URI **must contain the substring `runescape.com/playnow`** | `StartupArguments.GetDeepLinkString` | `[VERIFIED — artifact]` |
| 3 | The URI must carry `?launchurl=<host[:port]>` | native memcmp | `` |

`-n` names the component explicitly, which bypasses intent-filter matching; `MainActivity` is exported
(it carries the `MAIN`/`LAUNCHER` filter), so the launch is accepted `[VERIFIED — artifact]`.

### The value is used verbatim — pass a bare authority

`jag::ParseUrlQueryParameters` performs **no percent-decoding** and no scheme
stripping ``. The value is substituted directly into the `%s` of
`http://%s/jav_config.ws?binaryType=%s`. Therefore:

- Correct: `launchurl=192.168.1.10:8829`
- Wrong: `launchurl=http://192.168.1.10:8829/` → produces `http://http://192.168.1.10:8829//jav_config.ws?...`
- Wrong: `launchurl=192.168.1.10%3A8829` → the `%3A` is **not** decoded and reaches the URL literally.

**You control host and port only — not the path.** The path is hardcoded to `/jav_config.ws`. This
happens to match Project X's lobby, which already serves `jav_config.ws` at
`http://127.0.0.1:8829/jav_config.ws` `[VERIFIED — artifact, Project X run-client.sh:13]`, so no server
change is needed.

## Two channels, one of them is dead

The native client has **two** ways Java hands it startup data. Only one is live.

```
                      ┌──────────────────────────────────────────────────────────┐
  Intent extras  ───► │ GetArgumentCount / GetArgumentKey(i) / GetArgumentValue(i)│
  (am start -e)       │        marshalled into an argv-style vector               │
                      │        ["android", k0, v0, k1, v1, ...]                   │
                      │        stored at g_StartupArgumentsArgv (<addr in DB>)      │
                      └──────────────────────────┬───────────────────────────────┘
                                                 │
                                          ✗ NEVER READ — inert

                      ┌──────────────────────────────────────────────────────────┐
  Deeplink URI   ───► │ GetDeepLinkString                        │
  (am start -a VIEW   │   → ParseUrlQueryParameters  ("?k=v&k=v")   │
   -d <uri>)          │   → memcmp key == "launchurl"             │
                      │   → host := value                                        │
                      │   → "http://%s/jav_config.ws?binaryType=%s" │
                      └──────────────────────────┬───────────────────────────────┘
                                                 │
                                          ✓ LIVE — this is the redirect
```

### Channel 1: Intent extras — collected, then discarded

`jag::android::android_main` `` enumerates
`0..GetArgumentCount-1`, calling `GetArgumentKey(i)` and `GetArgumentValue(i)`, and builds a
vector of `eastl::string`:

```
["android", key0, value0, key1, value1, ...]
```

`argv[0]` is the literal `"android"`, materialised from MOV immediates. The vector is then stored
into the global `jag::android::g_StartupArgumentsArgv` ``.

**Nothing ever reads that global** in build 949-1. Two independent checks agree:

1. Ghidra's reference graph holds exactly **two** references to `<addr in DB>`: the write at
   `<addr in DB>` and the `_INIT_8` static constructor at `<addr in DB>`. Fields `+0x8` and `+0x10` have
   **no** references at all.
2. A raw decode of **all 52,250 `ADRP` instructions** in `.text` (`<addr in DB>`–`<addr in DB>`),
   resolving every `ADRP`+`ADD`/`LDR` pair, found exactly **one** that lands on `<addr in DB>` — the
   write at `<addr in DB>`.

`` for the write. The **absence of a reader** is a negative established by
two methods; the raw scanner is approximate (linear register tracking can miss cross-block pairs),
but Ghidra's graph is authoritative and agrees.

**Consequence: `am start -e KEY VALUE` cannot influence this client.** Any effort spent guessing
extra key names is wasted.

Note the deeplink short-circuit interaction: when a deeplink *is* set, `GetArgumentCount` returns
`1`, `GetArgumentKey(0)` returns the whole URI, and `GetArgumentValue(0)` returns `null` — so the
vector degrades to `["android", "<deeplink URI>"]`. This mirrors desktop's positional `argv[1]`
launch URL (see [Desktop divergence](#desktop-divergence--flagged-for-the-user)), and is very likely
the vestige of a design where the native side parsed `argv`. In 949-1 it is not wired up.

### Channel 2: the deeplink — live

`jag::android::StartupArguments::GetDeepLinkString` `` is a JNI
upcall wrapper. It materialises `"com/jagex/bootstrap/StartupArguments"`, `"GetDeepLinkString"` and
`"Ljava/lang/String;"` and invokes the generic static-string-method helper `<in Ghidra DB>`, writing
the result through an out-parameter (AAPCS64: `X0` = pointer to the destination `eastl::string`).

The Java side `[VERIFIED — artifact]`
(`extracted/jadx/sources/com/jagex/bootstrap/StartupArguments.java`):

```java
public static void SetupMainActivity(NativeActivity a) {
    f9979a = a;
    Intent intent = a.getIntent;
    if (intent.getAction != null) {
        if ("android.intent.action.VIEW".equals(intent.getAction)
         || intent.getAction.equals("org.chromium.arc.intent.action.VIEW")) {
            f9980b = intent.getData.toString;     // capture the deeplink
        }
    }
}

public static String GetDeepLinkString {
    return f9980b.contains("runescape.com/playnow") ? f9980b : BuildConfig.FLAVOR;   // "" if no match
}
```

So the URI is captured only on a `VIEW` action, and surfaced to native only if it contains
`runescape.com/playnow`. **This substring gate is the only reason the URI must look like a RuneScape
URL** — the host in it is otherwise irrelevant, because the client never fetches it. It is parsed for
its query string and thrown away.

## Manifest surface `[VERIFIED — artifact]`

`com.jagex.android.MainActivity` (`android.app.lib_name` = `libs.hal.system.rs2client`) declares:

| Filter | Data |
|---|---|
| `MAIN` / `LAUNCHER` | — |
| `VIEW` / `DEFAULT` / `BROWSABLE` | scheme `rs-launch`, host `*runescape.com`, pathPattern `.*jav_config.ws` |
| `VIEW` / `DEFAULT` / `BROWSABLE`, `autoVerify=true` | scheme `https`, host `secure.runescape.com`, pathPrefix `/playnow/rs` |

The second row is the source of the `runescape.com/playnow` gate — `https://secure.runescape.com/playnow/rs`
is the production deeplink, and appending `?launchurl=...` to it is the intended-shaped override.

The **first row is the interesting one and is not yet explained** — see
[OPEN-QUESTIONS](../OPEN-QUESTIONS.md) Q1. An `rs-launch://<host>/jav_config.ws` URI does **not**
contain `runescape.com/playnow`, so `GetDeepLinkString` returns `""` for it and it cannot reach the
`launchurl` path. There is a *second*, separate native mechanism that consumes exactly that shape
(see [net/jav-config.md](../net/jav-config.md#the-rs-launch-mechanism--unresolved)), but the write
site that feeds it has not been located.

## Desktop divergence — flagged for the user

`[VERIFIED — artifact]` **Neither** `rs2client` (desktop, 949-1) **nor** the mobile `.so` contains the
byte sequence `configURI` anywhere — verified by raw grep over both full binaries, not just Ghidra's
defined-string list.

Project X's own notes resolve why. From `run-client.ps1` (read-only, quoted):

> `--configURI` is a LAUNCHER flag (rs3windows.exe); rs2client.exe only understands the positional
> `rs-launch://` URL, hence we do not pass `--configURI`.

So **`--configURI` was never an rs2client flag.** This contradicts the earlier statements in this
repo's own docs (now corrected) that described it as the desktop client's argument.

**Discrepancy to raise with the user:** `run-client.sh:70` (repo root) passes
`--configURI "$CONFIG_URI"` directly to the Linux `rs2client` binary, which per the PowerShell note
would be ignored by the client. The Linux path likely depends on `LD_PRELOAD=libprojectx_patcher.so`
setting the config URI in-process instead (desktop `<in Ghidra DB>` has an early-out
`if (config_already_set) goto skip;` consistent with that). **This is a read-only observation — no
Project X file has been modified.** Worth confirming on the Project X side.

## What was committed to Ghidra

| Address | Name | Basis |
|---|---|---|
| `<addr in DB>` | `jag::android::StartupArguments::GetDeepLinkString` | Builds the exact class/method/signature triple and invokes it |
| `<addr in DB>` | `jag::android::android_main` | `struct android_app*` shape (`activity` @ idx 3, `onAppCmd` @ idx 1, `onInputEvent` @ idx 2, `destroyRequested` @ +0x64), `ALooper_pollOnce` loop, thread named `AndrdEventLoop` |
| `<addr in DB>` | `jag::ParseUrlQueryParameters` | **Behavioural name, not recovered from symbols** — see note below |
| `<addr in DB>` | `jag::android::g_StartupArgumentsArgv` | Sole write site marshals the argv vector into it |

Left deliberately as `FUN_` with `HYPOTHESIS` comments: `<in Ghidra DB>` (the config-URI builder — its
precise `jag::` identity is unproven; it is a **virtual method**, reached via the vtable at
`<addr in DB>`, whereas desktop's equivalent is called directly from `MainLogic`).

`jag::ParseUrlQueryParameters` is a *descriptive* name. Its behaviour is verified conclusively, but no
symbol establishes its real name; the Ghidra comment records this explicitly so it is not mistaken for
a recovered symbol.
</content>
