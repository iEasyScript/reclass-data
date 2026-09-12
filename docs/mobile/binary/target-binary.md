# Target Binary — `liblibs.hal.system.rs2client.so`

## Identity `[VERIFIED — artifact]`

| Property | Value |
|---|---|
| Path in APK | `lib/arm64-v8a/liblibs.hal.system.rs2client.so` |
| Extracted to | `extracted/lib/liblibs.hal.system.rs2client.so` |
| Size | 18,047,064 bytes |
| Format | ELF 64-bit LSB shared object, **ARM aarch64**, SYSV, dynamically linked |
| Min platform | Android 21 |
| Toolchain | NDK **r28c** (13676358) |
| BuildID | `1692ad6aa4a30671864d7d28d2089af06a8c2076` |
| SHA256 | `c475faf7cbf9bf9c3289843e9f45d6ae7591ff5de918865cc032a2e073ca8d25` |
| Symbols | **Stripped** — 504 GLOBAL FUNC entries survive in `.dynsym` |

The `rs2client` in the name is the giveaway: this is the **same NXT engine as the desktop client**,
recompiled for AArch64. The desktop RE work applies to the protocol; it does not apply to the machine code.
See [cross-architecture-porting.md](../re-methodology/cross-architecture-porting.md).

## Sections `[VERIFIED — artifact]`

```
.rela.plt  .rodata  .gcc_except_table  .eh_frame_hdr  .eh_frame  .text  .plt
.data.rel.ro  .fini_array  .init_array  .dynamic  .got  .got.plt  .relro_padding
.data  .bss  .shstrtab
```

No `.symtab` — stripped. `.eh_frame` is present and **useful**: unwind info gives function boundaries even
without symbols, which improves Ghidra's function recovery on a stripped target.

## Linked libraries `[VERIFIED — artifact]`

```
libandroid.so  libdl.so  liblog.so  libGLESv3.so  libEGL.so  libOpenSLES.so  libz.so  libm.so  libc.so
```

**Notably absent: `libssl.so` / `libcrypto.so`.** Both **libcurl** and **BoringSSL** are **statically linked
in** — evidenced by SOCKS4/SOCKS5 error strings, `https://curl.haxx.se/docs/http-cookies.html`, and
`BIO_get_accept_socket`.

Two consequences that matter:

1. **Android's network security config does not constrain native traffic.** Native code using raw sockets
   never consults `NetworkSecurityPolicy`, so the cleartext `http://%s/jav_config.ws` fetch is unaffected by
   the manifest's cleartext restriction. See [apk-structure.md](../android/apk-structure.md).
2. **TLS interception cannot be achieved by adding a system CA** for native traffic — the trust store is
   compiled in. (The Java layer is a different story; user CAs *are* trusted there.)

## Exports `[VERIFIED — artifact]`

504 GLOBAL FUNC entries in `.dynsym`. Among them, five JNI entry points, all in `com.jagex.android.ru`:

```
Java_com_jagex_android_ru_ax(String, int)   (1156 bytes)
Java_com_jagex_android_ru_bu(int)   (136 bytes)
Java_com_jagex_android_ru_hx(int)   (84 bytes)
Java_com_jagex_android_ru_wv(int, int)   (144 bytes)
Java_com_jagex_android_ru_xd(String)   (264 bytes)
```

`[UNCONFIRMED — hypothesis]` These are UI/input plumbing rather than networking — inferred from their
signatures (small int/string params), small bodies, and the obfuscated single-purpose class. Deprioritized.
Not yet confirmed by decompilation.

## String anchors `[VERIFIED — artifact]`

Strings are **identical across architectures**, making these the highest-value entry points into the
mobile binary. Xref these first.

### Config / URL

```
http://%s/jav_config.ws?binaryType=%s                            ← host is a format substitution
https://rs.config.runescape.com/l=%i/jav_config.ws?binaryType=%s ← hardcoded default
http://world2.runescape.com/error_game_%s.ws
https://runescape.wiki/w/Special:Search?...                      ← minimenu wiki lookup, not interesting
```

See [../net/jav-config.md](../net/jav-config.md).

### Lobby / world / login — prime xref targets

```
Client configured to connect to Lobby node %d on %.*s      ← the lobby endpoint parser
Client configured to connect to World node %d on %.*s      ← the world endpoint parser
Attempting to login to lobby
Attempting to login to world using OAuth2 credentials
Attempting direct login as: %s
Attempting direct login with sso credentials
Game World Login Result: %d (%s)
bad handshake length
digest requred for handshake isn't computed                ← [sic] — typo makes it distinctive
app data in handshake
```

### JS5

```
js5connect  js5connect_full  js5connect_outofdate
Js5DiskCache has been deleted
Js5WorkerThread
deletejs5caches
```

### Native → Java upcall targets

```
com/jagex/bootstrap/StartupArguments
GetArgumentCount  GetArgumentKey  GetArgumentValue  GetDeepLinkString  SetupMainActivity
```

See [../android/startup-arguments.md](../android/startup-arguments.md).

## Crypto constant candidates

### RSA modulus candidate `[UNCONFIRMED — hypothesis]`

A long decimal string, matching how the desktop client stores its modulus (desktop's patcher swaps it via
`PROJECTX_RSA_MODULUS`):

```
72373001173056674887071838617280527663581666550521377274397951912533401279550754…
```

**Not yet confirmed.** Right shape, right place, but its xrefs have not been checked. It is not yet known
whether this is the login modulus, the JS5 modulus, or something unrelated. **Do not treat as fact.**

Next step: xref the constant, identify the consuming function, determine which handshake uses it.

### Ruled out

```
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627…
```
`[VERIFIED — artifact]` A sequential byte table (0x00, 0x01, 0x02, …), not a key. Almost certainly a lookup
or test table.

### Embedded zlib blobs — ruled out `[VERIFIED — artifact]`

214 base64-encoded zlib streams (`eJ…` prefix = zlib header `78 9C`) are embedded in the binary. **All
decoded samples are GLSL shader source** (`UNIFORM_BUFFER_BEGIN`, `gl_FragColor`, `uViewProjMat`, …). Not
config, not keys. Ruled out as an analysis target.

## Ghidra notes

- **Do not run `list_functions`** — 18 MB will flood the context. Use `search_functions_by_name` or
  `list_methods` with pagination.
- Let auto-analysis finish before wiring up the MCP; the function list needs to be populated to be useful.
- `.eh_frame` should give Ghidra good function boundaries despite the strip.
- Prefer `disassemble_function` more often than on x86 — Ghidra's AArch64 decompiler obscures `REV`
  byte-swaps, `X8` struct returns, and ADRP pairs.
