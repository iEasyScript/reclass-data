# APK Structure

## The artifact `[VERIFIED — artifact]`

| | |
|---|---|
| File | `runescape-runescape-949-3-0-8.apk` |
| Size | 101,242,715 bytes |
| Build | **949** · app version **3.0.8** |
| Label | `RuneScape` · `RuneScape_949_3_0_8` |

Build **949** matters: it aligns the mobile client with the 949 data in the Project X project, so protocol
findings should correspond. **Verify the Project X project's active desktop build at session start** rather
than assuming — if it differs, desktop findings carry a version-drift caveat on top of the architecture
caveat.

## Contents `[VERIFIED — artifact]`

| Entry | Notes |
|---|---|
| `lib/arm64-v8a/liblibs.hal.system.rs2client.so` | **18 MB — THE TARGET.** See [../binary/target-binary.md](../binary/target-binary.md) |
| `classes.dex` | 6.3 MB — thin Android wrapper, mostly Play Services / Crashlytics |
| `res/` | 827 entries, obfuscated names (`res/4u.xml`, …) |
| `resources.arsc` | resource table |
| `assets/` | 11 entries, includes `mobile_cache` |
| `META-INF/` | 62 entries — signing |
| `lib/arm64-v8a/libcrashlytics*.so` | Crashlytics native — not interesting |
| `lib/arm64-v8a/libdatastore_shared_counter.so` | AndroidX datastore — not interesting |

**Effectively all networking, ISAAC, RSA, and packet handling lives in the native `.so`.** The dex is
plumbing. This is a native RE task with a small Java-layer detour, not an Android app-analysis task.

## The ABI constraint — arm64-v8a ONLY `[VERIFIED — artifact]`

```
lib/arm64-v8a/     ← the only ABI directory
```

There is **no x86_64 native lib**. This constrains where the client can run:

| Approach | Verdict |
|---|---|
| Real rooted arm64 Android device | **Best** — native speed, `frida-server` runs directly, no repacking |
| Unrooted arm64 device + `frida-gadget` repacked into the APK | Good fallback — no root, but repack + resign every iteration |
| Android Studio emulator, arm64 system image | Full CPU emulation — painfully slow for a 3D game |
| x86 emulator / Waydroid + ARM translation | Fragile; translation interacts badly with native hooking |

## Manifest `[VERIFIED — artifact]`

| | |
|---|---|
| Package | `com.jagex.runescape.android` |
| Main activity | `com.jagex.android.MainActivity` — extends `NativeActivity`, exported (launcher) |
| Deeplink host | `secure.runescape.com`, `*.runescape.com` |
| SDK redirect scheme | `com.jagex.mobilesdk.android.rs:/oauth2redirect` |

Permissions include `INTERNET`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`, `READ/WRITE_EXTERNAL_STORAGE`,
`POST_NOTIFICATIONS`, `VIBRATE`, `WAKE_LOCK`, plus Play Services / Firebase / ad-ID entries.

Other Jagex activities: `FederatedLoginAuthActivity`, `FederatedLoginLinkAccountActivity`,
`FederatedLoginLinkAccountRedirectUriReceiver`, `StoreActivity`, `LocalNotificationScheduler`,
`MobileNotificationService`.

## Network security config — `res/4u.xml` `[VERIFIED — artifact]`

Contents (recovered from the binary XML string pool):

```
base-config
  trust-anchors: system, user          ← user CAs ARE trusted
domain-config
  jagex.com         (includeSubdomains)
  jagex.network
  pin-set: SHA-256
    0C58jZAJ0Lq7kp7OQc4ZPOzMHagMqYX0aJHPzKge6oQ=
    G5wZdPKtf4V2YDLHVKg1pqNt/MSNwFPcOI9WOk95dsM=
  overridePins
```

Three consequences, all favorable:

1. **Pinning covers only `jagex.com` and `jagex.network`.** `runescape.com` is **not pinned** — and the
   config/game endpoints are `runescape.com`.
2. **`trust-anchors` includes `user`** in the base config → a user-installed CA is trusted, so **mitmproxy
   works against Java-layer HTTPS** (the Jagex SDK OAuth flows) with no patching.
3. **Cleartext is not explicitly permitted**, so the Java layer blocks plain HTTP by default. **This does
   not constrain the native client.** libcurl and BoringSSL are statically linked and use raw sockets;
   native code never consults `NetworkSecurityPolicy`. The cleartext `http://%s/jav_config.ws` fetch is
   unaffected.

The flip side of (3): because native TLS uses a **compiled-in** BoringSSL trust store, adding a system CA
will **not** intercept native HTTPS. Native TLS interception requires Frida or patching.

## The Java layer

### JNI class `com.jagex.android.ru` `[VERIFIED — artifact]`

`extracted/jadx/sources/com/jagex/android/ru.java` in full:

```java
public class ru {
    public static native boolean ax(String str, int i10);
    public static native void     bu(int i10);
    public static native void     hx(int i10);
    public static native void     wv(int i10, int i11);
    public static native void     xd(String str);
}
```

`[UNCONFIRMED — hypothesis]` UI/input plumbing, not networking — inferred from signatures and small native
body sizes. Deprioritized; not confirmed by decompilation.

### Other classes of interest `[VERIFIED — artifact]`

| Class | Role |
|---|---|
| `com.jagex.bootstrap.StartupArguments` | **The argument channel.** See [startup-arguments.md](startup-arguments.md) |
| `com.jagex.android.MainActivity` | `NativeActivity` host; window insets, display cutout handling |
| `com.jagex.android.CacheInitialiser` | Seeds cache from `assets/mobile_cache` into `getExternalFilesDir(null)` |
| `com.jagex.android.JagexMobileSDKWrapper` | Jagex mobile SDK bridge |
| `com.jagex.android.ApplicationContext` | context holder |
| `com.jagex.android.AndroidKeyboard` | soft keyboard |

`CacheInitialiser` is worth a second look when cache work starts — it establishes the on-device cache path,
which is where a locally-served JS5 cache would land.

## Extraction (already done — do not repeat)

```
extracted/lib/liblibs.hal.system.rs2client.so   # the target
extracted/dex/classes.dex, AndroidManifest.xml
extracted/jadx/sources/                          # 4,877 classes, jadx 1.5.5
```

jadx exited non-zero (3) with 1 error line, which is normal for a dex this size and did not prevent the
decompile. **Read from `extracted/jadx/sources/`; do not regenerate.**
