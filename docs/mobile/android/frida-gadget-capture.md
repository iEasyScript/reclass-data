# Running the Capture on an Unrooted Device (frida-gadget)

The packet-capture hooks ([../net/packet-capture-hooks.md](../net/packet-capture-hooks.md)) run in-process
via Frida. On a **rooted** device you would push `frida-server` and attach. This document covers the
**unrooted** path: repack the APK with **frida-gadget** — a `.so` that embeds the Frida runtime inside the
app itself, so no root and no `frida-server` are needed. `[VERIFIED — artifact]`

## Why gadget works here without touching the native target

- `MainActivity` extends `NativeActivity` but is still a real Java class with a `<clinit>` static
  initializer `[VERIFIED — artifact]`. We inject `System.loadLibrary("gadget")` there, so the gadget loads
  before any game code. No edit to the 18 MB target `.so`.
- Native libs in the APK are **Deflated** and `extractNativeLibs` is **absent** from the manifest
  `[VERIFIED — artifact]`, i.e. the app relies on native-lib extraction. A Deflated gadget `.so` is
  therefore consistent with the app's own packaging — no STORED+page-aligned requirement.

## Prerequisites (all present on this box)

`apktool` 2.11.1 · `apksigner` · `zipalign` · `keytool` · `frida-tools` 17.15.5 (pipx).

The gadget **must match the frida-tools version exactly** — `frida-gadget-17.15.5-android-arm64.so`.
It lives (decompressed, renamed) at `tools/gadget/libgadget.so`, arm64-v8a, alongside
`tools/gadget/libgadget.config.so`.

## The gadget config — `tools/gadget/libgadget.config.so`

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
```

`on_load: wait` is deliberate: the gadget **holds the app at startup** until `rs3-capture.py --gadget`
attaches and resumes it. This guarantees every hook is installed **before the first packet**, including the
login/RSA handshake — which `ClientStream::Read`/`Write` capture and which happens within the first
moments of the connection. (The gadget's filename is `libgadget.config.so`, not `.json`: only `.so` files
survive in `lib/`, and the gadget resolves its config by swapping its own trailing `.so` for `.config.so`.)

## Build the repacked APK

```bash
tools/repack-gadget.sh                     # uses the bundled 949-3.0.8 APK
# or: tools/repack-gadget.sh /path/to/other.apk
```

Steps it performs `[VERIFIED — artifact, produced tools/rs3-gadget.apk]`:

1. `apktool d -r` — decode (**`-r`** keeps `resources.arsc`/`res/` raw, avoiding AAPT rebuild failures;
   smali is still decoded).
2. Inject `System.loadLibrary("gadget")` at the top of `MainActivity`'s `<clinit>` (idempotent; bumps
   `.locals` to ≥1 if needed; synthesizes a `<clinit>` if none exists).
3. Copy `libgadget.so` + `libgadget.config.so` into `lib/arm64-v8a/`.
4. `apktool b`.
5. `zipalign -p 4`.
6. Sign with a generated debug keystore (`tools/debug.keystore`, password `android`) using apksigner.

Output: **`tools/rs3-gadget.apk`** — signed with **APK Signature Scheme v2 + v3** (v1/JAR intentionally
absent; modern Android verifies v2+). `[VERIFIED — artifact]`

## Install and capture

```bash
# The Play Store build is signed by Jagex; our debug signer differs, so remove it first.
adb uninstall com.jagex.runescape.android
adb install -r tools/rs3-gadget.apk

# Launch. The gadget loads and WAITS (on_load=wait) — the app appears to hang at startup. Expected.
# Arm the redirect + launch in one shot:
adb shell am start \
  -n com.jagex.runescape.android/com.jagex.android.MainActivity \
  -a android.intent.action.VIEW \
  -d 'https://secure.runescape.com/playnow/rs?launchurl=<PC_LAN_IP>:<PROJECTX_HTTP_PORT>'

# Attach — this installs hooks, then resumes the held app:
tools/rs3-capture.py --gadget --host <PC_LAN_IP>:<PROJECTX_HTTP_PORT>
```

`--gadget` finds the waiting gadget process over USB, loads `rs3-capture.js`, initialises the hooks, then
calls `device.resume`. Because the app was held at load, the hooks are active before the client opens its
socket.

Notes:
- `--host` here is belt-and-suspenders: the redirect can be armed either by the `am start` deeplink **or**
  by the in-process Java hook on `GetDeepLinkString` (the `--host` flag). Either suffices; both is harmless.
- `<PC_LAN_IP>` must be the capture host's LAN address reachable from the phone (same Wi-Fi), not
  `127.0.0.1`. `<PROJECTX_HTTP_PORT>` is Project X's lobby HTTP port (its `jav_config.ws` listener).
- `adb reverse tcp:27042 tcp:27042` is **not** required — frida attaches to the gadget through the USB
  device transport, not a TCP socket, so the `listen` address stays loopback-only on the phone.

## Output

`tools/capture/mobile-<timestamp>/`:

| File | Contents |
|---|---|
| `packets.log` | Human-readable, **full** payload hex (untruncated) — decoded S→C/C→S opcodes + raw login streams |
| `packets.jsonl` | One JSON object per packet (`t`, `dir`, `op`, `size`, `src`, `hex`) + ISAAC key records — machine-readable input for decoder tooling |
| `stream-s2c.bin` / `stream-c2s.bin` | Raw login/handshake bytes (the RSA block + preamble, pre-TcpIn) |
| `wire-fd<N>-<dir>.bin` | Raw per-socket bytes, only with `--raw` |

The console shows truncated lines (`--width` controls how many bytes); the log and JSONL always hold the
full payload. `[DESYNC]` markers flag any packet the hook could not read cleanly.

## Self-contained "Project X Mobile" APK (recommended)

`tools/build-projectx-mobile.sh [BASE_APK] [--host HOST:PORT]` produces `tools/projectx-mobile.apk` with
everything baked in `[VERIFIED — artifact]`:

1. **Both RSA moduli swapped in the `.so`** → the server's keys (login 1024-bit + JS5 4096-bit), so no
   runtime RSA hook is needed. See [../binary/rsa-key-patching.md](../binary/rsa-key-patching.md).
2. frida-gadget + config (listen `:27042`, `on_load=wait`).
3. `System.loadLibrary("gadget")` in `MainActivity.<clinit>`.
4. Signed v2+v3 with the debug keystore.

**Launch is always plain; the capture flag picks the target** (no `am start -d` juggling needed — that would
require the Java bridge frida 17 dropped):

```bash
adb uninstall com.jagex.runescape.android
adb install -r tools/projectx-mobile.apk
adb shell am start -n com.jagex.runescape.android/com.jagex.android.MainActivity

# private server (redirect config to Project X):
tools/rs3-capture.py --gadget --host 10.69.69.50:8829
# live game (no redirect — for comparison dumps):
tools/rs3-capture.py --gadget --live
```

Because the moduli are patched into the binary, the login/JS5 keys are Project X's regardless of which target
you pick — so `--live` still hits the real game for its *config/JS5*, but the login RSA is Project X's. For a
clean live comparison dump of a real login, use the **unpatched** `rs3-gadget.apk` instead.

## Network isolation — `--host` alone does NOT stop phone-home

`[VERIFIED — artifact]` The config redirect only changes the `jav_config` fetch. Even in private mode, the
client still contacts these on their own hardcoded endpoints, which ignore `jav_config`:

| Vector | Destination | Layer |
|---|---|---|
| Crash / error report | `world2.runescape.com/error_game_%s.ws` | native (Jagex) |
| Native analytics | `initialiseAnalyticsService` / `sendAnalyticsEvent` / `addCrashlyticsLog` | native |
| Firebase + Crashlytics | `firebase-settings.crashlytics.com`, `app-measurement.com`, `firebase.google.com` | Java (Google) |
| Singular attribution | `sdk-api-v1.singular.net`, `exceptions.singular.net` | Java |
| Braze / Adjust / AppsFlyer / Google ads | `*.braze.com`, `googleadservices.com`, `pagead2.googlesyndication.com` | Java |
| OAuth/SSO (if it inits) | `secure.runescape.com`, `accounts.google.com` | Java/native |

To guarantee **nothing** leaves for Jagex or any third party, use `--isolate`. Every TCP connection — Java
SDK and native alike — goes through libc `connect`, so a `connect` allow-list catches all of it, no root
or router changes:

```bash
tools/rs3-capture.py --gadget --host 10.69.69.50:8829 --isolate
```

`--isolate` permits only the server IP (derived from `--host`) plus loopback; add more with `--allow IP`.
Every blocked attempt is logged as `[BLOCKED] -> host:port` — which doubles as a live inventory of exactly
what tried to phone home. `--isolate` refuses to run with `--live` (live needs Jagex) and requires a
`--host`/`--allow` to know what to permit.

Note: DNS lookups for those domains may still resolve (the query goes to your resolver, not Jagex), but no
TCP connection to them completes, so no data reaches them. For belt-and-suspenders, also block at the
router/DNS.

## Connecting to the REAL game (recommended for protocol RE)

Project X's lobby login is incomplete for the mobile client (it serves `jav_config` + JS5, then the lobby
login stalls and the client disconnects). To capture **correct, complete** traffic — the raw material for
writing the `register949` decoders — point the client at the live Jagex servers by simply **not**
redirecting:

```bash
adb shell am force-stop com.jagex.runescape.android
adb shell am start -n com.jagex.runescape.android/com.jagex.android.MainActivity   # no deeplink
tools/rs3-capture.py --gadget                                                       # no --host
```

Then log in through the app UI with a real Jagex account. The client uses its hardcoded
`rs.config.runescape.com` config, does the real OAuth + lobby + world flow, and every packet is captured
in-process.

**Caveat — client build vs live:** this APK is a fixed **949** build. If the live servers have moved past
949, they may reject it as out of date (`js5connect_outofdate` path). If real login is refused for that
reason, the fallback is to finish Project X's mobile lobby login using the handshake bytes captured in
`stream-c2s.bin` / `stream-s2c.bin` from the Project X run.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Play build still installed — `adb uninstall com.jagex.runescape.android` first. |
| App hangs at a black screen and never proceeds | Correct with `on_load: wait` — attach with `rs3-capture.py --gadget` to resume. |
| `no gadget process found` | The app isn't launched yet, or the gadget didn't load. Confirm with `frida-ps -Uai`; check `adb logcat | grep -i gadget`. |
| Frida version mismatch error | The gadget `.so` must match `frida --version` exactly. Re-pull the matching `frida-gadget-<ver>-android-arm64.so`. |
| No packets, only `[CONN]` lines | RVAs not loaded — confirm `tools/rva.json` is populated and the module resolved (`[+] ...base=...`). |
| Native crash on load | Gadget ABI mismatch — must be `android-arm64`. Re-verify with `file tools/gadget/libgadget.so`. |

## Alternative: rooted device

If a rooted device is available, skip all repacking:

```bash
adb push frida-server-17.15.5-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &'"
tools/rs3-capture.py --host <PC_LAN_IP>:<PROJECTX_HTTP_PORT>   # spawns the stock app
```

The stock (Play Store) APK is used unchanged; `rs3-capture.py` spawns it and installs hooks at spawn.
