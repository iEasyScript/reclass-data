# RSA Key Patching (mobile — no LD_PRELOAD)

To point the mobile client at Project X for **login** and **JS5**, the client's two embedded RSA public
moduli must be replaced with Project X's, so the client encrypts the login block / verifies the JS5 master
index against keys Project X holds the private half of. Desktop does this with the LD_PRELOAD patcher reading
`jav_config` `param=99`/`param=100`; **the mobile client ignores those params** (no launcher, no patcher),
so we patch in-process via frida-gadget instead.

## The two embedded moduli `[VERIFIED — artifact]`

Both are stored in `.rodata` as **ASCII hex strings** (not raw bytes, not decimal). File offsets; image base
is 0 so these are ~RVAs.

| Key | Bits | Hex chars | Offset | Starts |
|---|---|---|---|---|
| Login/world RSA | 1024 | 256 | `<addr in DB>` | `83fec000fd2e3d6f1555e4f1a3875dd9…` |
| JS5 RSA | 4096 | 1024 | `<addr in DB>` | `a4ba332072d8ccdcff327ef42dc5be75…` |

These are the **mobile client's own** Jagex keys — distinct from the desktop client's keys (Project X's
`JAGEX_LOGIN_RSA_MODULUS_HEX` / `JAGEX_JS5_RSA_MODULUS_HEX` constants do **not** appear in the mobile
binary). Their bit-sizes match Project X's key sizes exactly (login 1024, JS5 4096).

The decimal run `72373001173…` @ `<in Ghidra DB>` is only **512-bit** — **not** the login modulus. Unidentified;
`[UNCONFIRMED — hypothesis]` a secondary constant.

## The patch

Because the mobile moduli are hex strings and Project X's replacement moduli are the **same hex-char length**
(256 / 1024), it is a byte-for-byte in-place string swap — no relocation, no length juggling.

| Key | Replace mobile hex with Project X (`.env`) |
|---|---|
| Login | `PROJECTX_RSA_MODULUS` = `9eb6433eeb945284…` (256 hex) |
| JS5 | `PROJECTX_JS5_RSA_MODULUS` = `9506304ab7cc304c…` (1024 hex) |

Config lives in `tools/moduli.json` (`find`/`replace` pairs). Applied by `tools/rs3-capture.js`
`patchModuli`: `Memory.scanSync` for the mobile hex string in the module range → `Memory.protect` the
page to `rw-` → `writeByteArray` Project X's hex bytes. Runs at module-load (during the gadget hold), before
the client connects.

```bash
tools/rs3-capture.py --gadget --patch-rsa   # loads tools/moduli.json
```

Console prints `[+] RSA patched: login-rsa-1024 …` / `js5-rsa-4096 …` on success, or `not-found` /
`length mismatch` on failure.

## RESOLVED: bake the patch into the .so — runtime string-overwrite is too late ``

Both moduli are parsed **once at C++ static-init** (`_INIT_254` ≈ `<addr in DB>`) via the
BigInteger-from-ASCII parser `<in Ghidra DB>(BigInt* out, char* ascii, int radix)` into 0x18-byte
BigInteger globals (login exp `<addr in DB>` / mod `<addr in DB>`; JS5 exp `<addr in DB>` / mod `<addr in DB>`).
**After static-init the `.rodata` hex string is never read again** — the encrypt/verify use the parsed
globals.

Consequence for patching strategy:

- **Baking the swap into the `.so` at build time WORKS** — `_INIT_254` runs at `dlopen` and reads whatever
  string is in `.rodata`, so a patched binary builds Project X's BigInteger globals. This is what
  `build-projectx-mobile.sh` does, and it is the correct, reliable path. ``
- **Runtime `.rodata` string-overwrite (`--patch-rsa`) is INEFFECTIVE for an embedded gadget** — the target
  `.so`'s constructors run inside the `dlopen` call, which completes *before* any per-module frida hook can
  fire, so the globals are already built from the original string by the time we could patch it. `--patch-rsa`
  will report `not-found` on the baked APK (correct — the Jagex string is already gone) and would be a no-op
  even on the stock APK. Use the baked APK.
- A runtime alternative exists if ever needed: hook the RSA-encrypt (`<in Ghidra DB>`) / JS5-verify
  (`<in Ghidra DB>`) and substitute the modulus BigInteger pointer at call time — those run well after hooks
  are installed. Documented in [../net/login-handshake.md](../net/login-handshake.md). Not needed while
  baking works.

The JS5 verify is the first thing that breaks if the key is wrong: the client EOFs right after receiving
master index 255/255 (Project X's own `param=100` comment documents this exact failure, matching the earlier
Project X-run disconnect). Verify site: `<in Ghidra DB>` (Whirlpool digest + RSA modpow compare).

## Why this is needed (recap)

- **JS5:** client verifies the master index signature with the embedded JS5 key; wrong key → EOF right after
  255/255. This killed the first Project X attempt.
- **Login:** client RSA-encrypts the login block (ISAAC keys + credentials) with the embedded login key;
  Project X can't decrypt unless the client used Project X's key. Yields `BAD_SESSION_ID` otherwise.
