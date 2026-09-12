# RS3 Mobile — RE Documentation Index

Reverse engineering of the RuneScape 3 Android client (build **949**, app **3.0.8**), targeting the ability
to point it at a locally-run Project X server.

**This index is always current.** Every doc below is listed; every new doc adds an entry in the same session
it is created.

## Confidence tags

Every factual claim in these docs carries one of these. An untagged claim is a defect.

| Tag | Meaning |
|---|---|
| `[VERIFIED @ 0xADDR]` | Confirmed in the mobile target at this address. Gold standard. |
| `[VERIFIED — artifact]` | Confirmed from the APK / manifest / dex / strings without Ghidra. |
| `[PREDICTED FROM DESKTOP — UNVERIFIED ON MOBILE]` | Desktop says so; not confirmed on mobile. **Not a fact.** |
| `[PATTERN HINT from librs2client.so]` | Old reference used for code-pattern confirmation only. |
| `[UNCONFIRMED — hypothesis]` | Suggestive evidence, not conclusive. |

## Documents

### Android platform (`android/`)
- [apk-structure.md](android/apk-structure.md) — APK contents, the native lib, ABI constraint, manifest, network security config.
- [startup-arguments.md](android/startup-arguments.md) — the Intent → native argument channel. **RESOLVED: the key is `launchurl`, a deeplink query parameter — Intent extras are inert.** Contains the working launch command.

### Networking (`net/`)
- [jav-config.md](net/jav-config.md) — the `jav_config.ws` fetch, URL construction, config keys, `binaryType=7`, and the unresolved `rs-launch` mechanism.
- [content-js5-http.md](net/content-js5-http.md) — **the on-demand JS5-over-HTTP `/ms` fetch to the content host.** The exact request (`GET http://<content_host>:80/ms?m=0&a&k&g&c&v`), the **port-80-hardcoded** base-URL builder (`<in Ghidra DB>` mov w9,#0x50`), why a `host:port` content param **freezes** (`http://IP:port:80` → getaddrinfo hang), that no `jav_config` param controls the port, and the deployable fix: **serve `/ms` on port 80**.
- [packet-capture-hooks.md](net/packet-capture-hooks.md) — **Frida hook points for an in-process packet sniffer.** RVAs + AAPCS64 signatures for `TcpIn`, `ClientStream::Read`/`Write`, `Isaac::Init`, `TcpConnectionMessage::Init`. Contains the confirmed `OServerConnection` / `OConnectionManager` offset table, and two divergences from Project X: **`InitIncoming` is inlined away on mobile**, and **two `OClient` offsets differ**.
- [login-handshake.md](net/login-handshake.md) — **RSA keys (login 1024-bit `83fec0…`, JS5 4096-bit `a4ba3320…`), the RSA-encrypt site (`<in Ghidra DB>`), the JS5 Whirlpool+RSA verify (`<in Ghidra DB>`), the direct-vs-OAuth decision (`<in Ghidra DB>` / `isUserAuthenticated`), and the byte-level direct-login block layout.** The deliverable for a self-hosted username+password lobby login. Includes the frida key-swap point (`<in Ghidra DB>` at static-init). **§6: the MOBILE-detection signal** — how the lobby/world server tells a mobile login from desktop (`"NXT-Android"` string + `binaryType=7`/`platformType=2` bytes in the op19/op16 XTEA tail; response side carries no OS field), ground-truth byte-mapped.
- [machine-info.md](net/machine-info.md) — **the exhaustive byte-exact field map of the entire op19/op16 login XTEA tail** (the `MachineInformation` decoder contract): top-level fields, the 58-byte machine-info numeric block (`WriteMachineInfoBlock`), the device-strings block (`WriteDeviceInfoBlock`, incl. `"NXT-Android"`), the 46× u32 client-settings block (`WriteLoginClientSettingsBlock` — structured telemetry, **not** a signature), lobby-vs-world deltas, and a Kotlin decoder sketch. Confirms the block layout is **platform-uniform** (one decoder for desktop + mobile).
- [reference-captures.md](net/reference-captures.md) — the real-game login/world capture under `data/client/android/captures/`, how to read/diff it, the gameval + cs2-dump workflow for decoding interface/var ids, and the **resolved** finding on **how the lobby detects a mobile client** (→ login-handshake.md §6).

### Binary (`binary/`)
- [target-binary.md](binary/target-binary.md) — target identity, layout, exports, linked libraries, crypto-constant candidates.
- [rsa-key-patching.md](binary/rsa-key-patching.md) — the two embedded RSA moduli (login 1024-bit @ `<in Ghidra DB>`, JS5 4096-bit @ `<in Ghidra DB>`), and how they're swapped for Project X's keys.

### Android platform (`android/`) — capture
- [frida-gadget-capture.md](android/frida-gadget-capture.md) — unrooted capture + the self-contained `build-projectx-mobile.sh` pipeline.

### Methodology (`re-methodology/`)
- [cross-architecture-porting.md](re-methodology/cross-architecture-porting.md) — what ports from the desktop RE work and what does not. **Read before using any desktop finding.** Both targets are build **949-1**, so architecture is the only axis of difference. Includes the hard-won rule that **a missing string proves nothing**.

### Status
- [OPEN-QUESTIONS.md](OPEN-QUESTIONS.md) — ranked unknowns, each with a concrete next step.

## Current state of the redirect goal

**The config redirect is solved by static analysis and needs no patching, resigning, or root**
``:

```bash
adb shell am start \
  -n com.jagex.runescape.android/com.jagex.android.MainActivity \
  -a android.intent.action.VIEW \
  -d 'https://secure.runescape.com/playnow/rs?launchurl=192.168.1.10:8829'
```

→ `http://192.168.1.10:8829/jav_config.ws?binaryType=7` (plain HTTP, native libcurl).

Not yet done: an on-device run to confirm; `binaryType=7` vs Project X's hardcoded `4`
([OPEN-QUESTIONS](OPEN-QUESTIONS.md) Q2); RSA modulus; lobby/world endpoints; JS5; login handshake.

## Packet capture

The hook points for a Frida-based sniffer are **resolved and documented** in
[net/packet-capture-hooks.md](net/packet-capture-hooks.md). The mobile design differs from Project X's
desktop one in two ways that matter: `TcpConnectionMessage::InitIncoming` is **inlined into `TcpIn`** and
so cannot be hooked, and **`OClient::CONNECTION_MANAGER` / `MAIN_STATE` differ from the desktop values**.
All `OServerConnection` and `OConnectionManager` offsets were confirmed identical.

## Not yet written

`cache/` has no documents. JS5 and cache-format analysis has not started — the redirect goal takes priority.

## Reading order for a newcomer

1. `re-methodology/cross-architecture-porting.md` — the ground rules.
2. `binary/target-binary.md` — what we're looking at.
3. `android/startup-arguments.md` + `net/jav-config.md` — the redirect, resolved.
4. `OPEN-QUESTIONS.md` — where the work is.

## Source of desktop knowledge

The desktop RE knowledge is a sibling in this same repo: protocol/format docs at `../` (the topical roots
`../net/`, `../cache/`, `../binary/`, `../re-methodology/`), symbol dumps at `../../symbols/`. Everything
there describes the **x86-64 desktop** client — see [re-methodology/cross-architecture-porting.md](re-methodology/cross-architecture-porting.md)
before relying on any of it. Desktop is **949-4**, mobile is **949-3** — same major, so protocol and cache formats are shared, but the sub-revisions differ and addresses never port across.
