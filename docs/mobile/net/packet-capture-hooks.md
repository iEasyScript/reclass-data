# Packet Capture Hook Points (Frida)

Hook targets for an in-process packet sniffer on the mobile client — the mobile analogue of Project X's
injected `ServerPacketCapture` / `RawLoginDump`.

**Why in-process:** the RSA login plaintext is `0a <4 ISAAC keys, 16 bytes BE> 00 <8-byte session key> …`.
The ISAAC keys are RSA-encrypted before they hit the wire, so they exist **only inside the process**. A
network tap cannot decode the game stream. `[VERIFIED — artifact]` (Project X capture
`login-20260531-191837_s1/rsa-plaintext.bin`.)

## Addresses are RVAs

`` The image base is **0** — `list_segments` shows segments starting at
`00000000`; `.text` = `<addr in DB> – <addr in DB>`. **Every address in this document is an RVA** and Ghidra
addresses are RVAs directly.

```js
const base = Module.findBaseAddress("liblibs.hal.system.rs2client.so");
const addr = base.add(RVA);
```

AAPCS64 reminders: integer/pointer args in `X0`–`X7`; `this` is `X0` on member functions; return in `X0`;
`X8` is the indirect-result register (a by-value struct return uses it, **not** `X0`).

---

## Hook table

| # | Function | Mobile RVA | Signature (AAPCS64) | Confidence |
|---|----------|-----------|---------------------|------------|
| 1 | `jag::ConnectionManager::TcpIn` | **`<addr in DB>`** | `(X0=ConnectionManager*, X1=shared_ptr<ServerConnection>* handle)` → `X0`=bool | `` |
| 2 | `jag::ClientStream::Read` | **`<addr in DB>`** | `(X0=ClientStream* this, X1=uint8_t* buf, X2=size_t len)` → `X0`=**bytesCopied** | `` |
| 3 | `jag::ClientStream::Write` | **`<addr in DB>`** | `(X0=ClientStream* this, X1=uint8_t* buf, X2=size_t len)` → `X0`=bytesAccepted | `` |
| 4 | `jag::game::TcpConnectionMessage::Init` (outgoing) | **`<addr in DB>`** | `(X0=msg*, X1=protEntry*, W2=resolvedSize, X3=Isaac*)` → void | `` |
| 5 | `jag::ConnectionManager::ProcessConnections` | **`<addr in DB>`** | `(X0=ConnectionManager*, W1=bool drainInbound)` → void | `` |
| 6 | `jag::Isaac::Init` | **`<addr in DB>`** | `(X0=Isaac* this, X1=const int32_t keys[4])` → void | `` |
| 7 | `jag::Isaac::TakeNextValue` | **`<addr in DB>`** | `(X0=Isaac* this)` → `X0`=uint32 | `` |
| 8 | `jag::ClientStream::Flush` | **`<addr in DB>`** | `(X0=ClientStream* this)` → void | `` |
| — | **`TcpConnectionMessage::InitIncoming`** | **DOES NOT EXIST** | inlined into TcpIn — see below | `` |

Supporting functions, **deliberately not renamed** (semantics certain, real symbol name unknown — Cardinal
Rule 1). They carry `HYPOTHESIS:` comments in the Ghidra DB.

| Function | Mobile RVA | Role | Confidence |
|----------|-----------|------|------------|
| `<in Ghidra DB>` | `<addr in DB>` | Isaac **peek** — returns `randrsl[randcnt-1]` *without* decrementing | `` semantics / `[UNCONFIRMED — hypothesis]` name |
| `<in Ghidra DB>` | `<addr in DB>` | ClientStream receive pump (FIONREAD → recvfrom → ring) | same |
| `<in Ghidra DB>` | `<addr in DB>` | Isaac constructor — zeroes `randcnt/aa/bb/cc`, tail-calls `Init` | same |
| `<in Ghidra DB>` | `<addr in DB>` | `CreatePacket` — sole caller of `TcpConnectionMessage::Init` | same |
| `<in Ghidra DB>` | `<addr in DB>` | `ClientSocket` read — `recvfrom(fd, buf, len, flags)` | same |
| `<in Ghidra DB>` | `<addr in DB>` | `ClientSocket` write — `sendto(fd, buf, len, MSG_NOSIGNAL)` | same |
| `<in Ghidra DB>` | `<addr in DB>` | `ClientSocket` available — `ioctl(fd, FIONREAD, &n)` | same |

---

## FINDING 1 — `InitIncoming` does not exist on mobile

`` **Project X's primary hook has no mobile target.** AArch64 Clang **inlined**
`jag::game::TcpConnectionMessage::InitIncoming` into `ConnectionManager::TcpIn`.

Evidence:
- `[VERIFIED — desktop` Desktop `InitIncoming` has **exactly one** call site
  (`TcpIn` — a single-callsite function is precisely what Clang inlines.
- `` Its distinctive size-class ladder appears **inline inside mobile TcpIn**:
  `-1 → 0x104`, `-2 → 10000`, `<= 0x12 → 0x14`, else `0x62` / `0x104`. Located by scanning `.text` for
  `MOVZ Wd,#0x2710`; the only hit inside a TcpIn-shaped function is at `<addr in DB>`.
- Every message field write in mobile TcpIn matches desktop `InitIncoming` field-for-field:
  `msg+0x00`=opcode, `+0x04`=resolvedSize, `+0x10`/`+0x18`/`+0x20`/`+0x28` zeroed, `+0x30`=protEntry.
- The surrounding `MakeShared` (pool block, `msg = block+0x20`, refcounts `<in Ghidra DB>`1`, vtable at
  block+0) is identical in shape to `CreatePacket` `<in Ghidra DB>`, confirming TcpIn fuses
  MakeShared + InitIncoming.
- Mobile TcpIn's inline copy only emits the raw-opcode branch (no ISAAC add), consistent with desktop
  passing `isaac = 0` (desktop's own prototype comment calls it `unusedIsaac`).

**Consequence:** hook **`ConnectionManager::TcpIn` (`<addr in DB>`)** and read the decoded packet from the
`ServerConnection` directly. TcpIn *does* receive the connection (`X1`), so mobile does **not** need
Project X's `activeConn` correlation trick — the connection is unambiguous. This sidesteps the corruption
class Project X documented (guessing the connection from `(opcode,size)` stapled a stale buffer onto
`REBUILD_NORMAL`).

### Where to hook instead — `<in Ghidra DB>`

`` **This is the best S→C capture point on mobile.**

TcpIn's entry is too early (the packet has not been read yet) and its **exit is too late**: before
returning, TcpIn calls `<in Ghidra DB>(conn)`, the end-of-packet reset:

```c
if (*(int *)(conn + 0x2c) != -1) {
    *(int *)(conn + 0x2e0) = *(int *)(conn + 0x2c);  // saves LAST_OPCODE
}
*(undefined1 *)(conn + 0x35) = 0;
*(undefined4 *)(conn + 0x2c) = 0xffffffff;           // CURRENT_OPCODE = -1
*(undefined1 *)(conn + 0x28) = 0;
*(undefined4 *)(conn + 0x38) = 0;
*(undefined1 *)(conn + 0x3c) = 0;
```

An `onLeave` hook on TcpIn therefore reads `opcode == -1` and captures **nothing**.

`<in Ghidra DB>` has **exactly two call sites, both inside TcpIn** ``:

| Site | Path |
|------|------|
| `<addr in DB>` | success — after handler dispatch, before `return 1` |
| `<addr in DB>` | reject — unknown opcode / null handler, before `return 0` |

Nothing else calls it, so it fires **exactly once per packet** and at that instant opcode, size and
payload are all still intact.

```
FRIDA: hook <addr in DB> onEnter.  X0 = ServerConnection*
  if (*(int*)(X0 + 0x2c) == -1) return;          // nothing in flight
  opcode  = *(int*)(X0 + 0x2c)
  size    = *(int*)(X0 + 0x30)
  payload = *(void**)(X0 + 0x2d0), size bytes    // filled from offset 0
```

The connection is `X0` itself — **no `activeConn` correlation is needed**, so mobile is structurally
immune to the desync class Project X hit. Bonus: `conn+0x2e0` = `LAST_OPCODE`.
`[UNCONFIRMED — hypothesis]` The function's real symbol name is unknown (likely a
`ServerConnection::ResetPacketState`), so it is left as `FUN_` per Cardinal Rule 1 — the address and
semantics are what the hook needs.

Hooking TcpIn (`<addr in DB>`) remains useful for **scoping** (it tells you which connection is being
drained, and brackets the packet), but the payload read must happen at `<in Ghidra DB>`.

---

## FINDING 2 — `OClient` offsets DIFFER from desktop

`` `` Two `OClient` offsets are **not** the desktop values.
A Frida script reusing Project X's numbers would dereference garbage.

Read directly from disassembly (not from Ghidra's decompiler, which renders these as bogus
`__DT_RELA[...]` symbols):

```
00a33e3c: ldr x8,[x0, #0x8]          // ConnectionManager+0x08 = Client*
00a33e48: add x23,x8,#0x19, LSL #12  // Client + `<in Ghidra DB>`
00a33e4c: ldr w20,[x23, #0xb40]      // MAIN_STATE          = Client + `<in Ghidra DB>`
00a33ea0: cmp w20,#0x1e              // == 30 == LOGGED_IN

009f8228: ldr x0,[x8, #0x460]        // CONNECTION_MANAGER  = Client + `<in Ghidra DB>`
009f8240: mov w9,#0x9460
009f8248: movk w9,#0x1, LSL #16      // `<in Ghidra DB>` again, second independent encoding
009f824c: ldr x0,[x8, x9, LSL #0x0]
```

| Field | Desktop (Project X, 949-1) | **Mobile** | Status |
|-------|---------------------------|-----------|--------|
| `OClient::CONNECTION_MANAGER` | `<in Ghidra DB>` | **`<in Ghidra DB>`** | **DIFFERENT (+0x20)** `` |
| `OClient::MAIN_STATE` | `<in Ghidra DB>` | **`<in Ghidra DB>`** | **DIFFERENT (+0x18)** `` |
| `LOGGED_IN` state value | `30` | **`30`** (`0x1e`) | CONFIRMED-same `` |

The deltas differ (`+0x20` vs `+0x18`), so this is **not** a uniform shift — mobile's `Client` has
multiple insertions. **No other `OClient` offset may be assumed to port.** Note `<in Ghidra DB>` is desktop's
`PLAYER_VAR_DOMAIN`, so the desktop value is actively misleading here.

`CONNECTION_MANAGER = `<in Ghidra DB>` is proven by a closed loop: `Client + `<in Ghidra DB>` → `ConnectionManager`, and
`ConnectionManager + 0x08` → back to `Client`. `ProcessConnections` is called with exactly
`*(Client + `<in Ghidra DB>`)` and reads `*(param+8)` as the Client. Self-consistent.

Other `Client` members observed but **not** identified: `+`<in Ghidra DB>` (an object with an int state at `+0x28`
compared against `30`), `+`<in Ghidra DB>`, `+`<in Ghidra DB>`. `[UNCONFIRMED — hypothesis]`

---

## Offset confirmation table (the load-bearing output)

Every value below was confirmed against **mobile's own field accesses**, per Cardinal Rule 3 — desktop was
used only to generate the hypothesis.

### `OServerConnection` — all CONFIRMED-same

`` (all confirmed inside `TcpIn` unless noted)

| Field | Desktop | Mobile | Status | Mobile evidence |
|-------|---------|--------|--------|-----------------|
| `CLIENT_STREAM` | `0x08` | `0x08` | **CONFIRMED-same** | `ClientStream::Read(*(conn+8), *(conn+0x2d0), 1)` — passed as the `ClientStream*` |
| `CURRENT_OPCODE` | `0x2C` | `0x2C` | **CONFIRMED-same** | `iVar5 = *(int*)(conn+0x2c); if (iVar5 == -1)` idle check; `*(uint*)(conn+0x2c) = opcode` after decode |
| `RESOLVED_SIZE` | `0x30` | `0x30` | **CONFIRMED-same** | `*(uint*)(conn+0x30) = protEntry[1]`; sentinels `0xffffffff`/`<in Ghidra DB>` |
| `ISAAC_PTR` | `0x2B8` | `0x2B8` | **CONFIRMED-same** | `*(long*)(conn+0x2b8)` → passed to `Isaac::TakeNextValue`; also written with the **+50** Isaac in the login builder |
| `PACKET_BASE` | `0x2C0` | `0x2C0` | **CONFIRMED-same** | `(**(code**)(*handler+0x30))(handler, conn+0x2c0, …)` — handler dispatch |
| `BUF_DATA` | `0x2D0` | `0x2D0` | **CONFIRMED-same** | buffer passed to `ClientStream::Read`; filled from offset 0 |
| `BUF_POS` | `0x2D8` | `0x2D8` | **CONFIRMED-same** | `*(conn+0x2d8) = 0/1/2` as bytes are consumed |
| `ISAAC_OUT` (new) | — | **`0x40`** | **NEW — mobile-confirmed** | `` `ldr x8,[x20,#0x40]` → passed as `CreatePacket`'s isaac; also written with the **raw-key** Isaac in the login builder |

`ISAAC_OUT = 0x40` also holds on desktop (`local_48 = *(long *)(lVar6 + 0x40)` in desktop
`ProcessConnections`) — Project X simply has no constant for it.

### `OConnectionManager` — all CONFIRMED-same

``

| Field | Desktop | Mobile | Status | Mobile evidence |
|-------|---------|--------|--------|-----------------|
| `HANDLE_STATE` | `0x08` | `0x08` | **CONFIRMED-same** | `TcpIn` does `conn = *(long*)(X1 + 8)` |
| `GAME_CONNECTION` | `0x18` | `0x18` | **CONFIRMED-same** | game path (state `0x1e`): `*(long*)(mgr+0x18)`; `TcpIn(mgr, mgr+0x10)` |
| `LOGIN_CONNECTION` | `0x28` | `0x28` | **CONFIRMED-same** | login path (state `0x14`): `*(long*)(mgr+0x28)`; `TcpIn(mgr, mgr+0x20)` |
| `CLIENT` (new) | — | **`0x08`** | **NEW — mobile-confirmed** | `ldr x8,[x0,#0x8]` → Client; same on desktop |

`HANDLE_STATE = 0x08` is explained, not just observed: the symbol dump gives
`jag::ConnectionManager::TcpIn(jag::shared_ptr<jag::game::ServerConnection>&)`, and `jag::shared_ptr` is
`{refcounter@0x00, data@0x08}`. So `mgr+0x10`→data`+0x18` and `mgr+0x20`→data`+0x28` are the *same two
shared_ptrs*, fully self-consistent. `[VERIFIED — artifact]`

---

## Read/Write semantics — get this wrong and every capture is silently corrupt

### `jag::ClientStream::Read`

``

```
X0 = ClientStream* this
X1 = uint8_t*      buf     ← caller's destination buffer
X2 = size_t        len     ← REQUESTED count
X0 (ret) = size_t bytesCopied   ← ACTUAL count, <= len
```

**Hook on RETURN. The length is the RETURN VALUE, never `X2`.**

`Read` does *not* recv into the caller's buffer. It drains an internal **ring buffer**
(`rd +0x90`, `wr +0x98`, `avail +0xa0`) into `buf`, topping the ring up via the pump `<in Ghidra DB>` only
when short. It returns `min(len, avail)`. Logging `len` bytes at `onEnter` reads uninitialised tail bytes.

This matches Project X's production `RawLoginDump.rawLoginRead` exactly — it invokes the trampoline first,
then logs `copyOf(buf, read.toInt)`. `[VERIFIED — artifact]`

Each byte passes through `Read` **exactly once**, which is why this is the correct S→C choke point even
though the socket layer beneath it may use `MSG_PEEK` (`<in Ghidra DB>` computes flags as
`(*(char*)(sock+0x69) == 0) << 1` → `2` = `MSG_PEEK`, or `0`). Do **not** hook the socket layer.

Identification evidence (desktop `jag::ClientStream::Read`, same build 949-1):
same call-counter increment at entry (`<in Ghidra DB>` / desktop `_DAT_01677ab0`), same byte-counter at exit
(`<in Ghidra DB>` / desktop `<in Ghidra DB>`), the same highly distinctive **`/10` ring-occupancy heuristic**
(`uVar2/10 < uVar2 - uVar1`), identical field offsets, same 3-arg shape.

### `jag::ClientStream::Write`

``

```
X0 = ClientStream* this
X1 = uint8_t*      buf
X2 = size_t        len     ← the real length; data is complete at ENTRY
X0 (ret) = size_t bytesAccepted
```

**Hook on ENTER. The length is `X2`.** Bytes are already ISAAC-encrypted at this layer.

Two paths, selected by the bool at `this+0xe0`:

| `this+0xe0` | Behaviour | Return |
|---|---|---|
| `0` | direct `ClientSocket::Write` → `sendto(fd, buf, len, MSG_NOSIGNAL)` | actual sent; `ret != len` ⇒ `Close` + reset |
| `≠ 0` | buffered — appends to the write vector (`+0xc8` begin / `+0xd0` end / `+0xd8` cap) | `len` (or `0` if it doesn't fit) |

On the buffered path the wire I/O happens later in `Flush` (`<addr in DB>`). Buffered bytes do **not**
re-enter `Write`, so **hooking `Write` alone is complete for C→S and does not double-count against
`Flush`**. Check the return to catch short/failed sends.

Matches Project X's `RawLoginDump.rawLoginWrite` (logs at entry with `len`, then calls the trampoline).
`[VERIFIED — artifact]`

**Both are still required.** During login the bytes are consumed by the LoginManager state machine and are
never dispatched through `TcpIn`, so `Read`/`Write` are the only way to capture the RSA handshake.

---

## ISAAC

`jag::Isaac::Init` — ``

```
X0 = Isaac*         this
X1 = const int32_t* keys    ← pointer to EXACTLY 4 contiguous int32 (16 bytes). NO count arg.
```

It copies exactly four words (`randrsl[0..3] = keys[0..3]`), `memset(this+4, 0, 0x800)` for the rest,
mixes, inlines `Generate`, and sets `randcnt = 0x100`.

Object layout — **total size `0x810` (2064)**, `` via the `<in Ghidra DB>(0x810)`
pool allocation in the callers, and independently consistent with the field accesses:

```c
// jag::Isaac — total size 0x810
//
struct Isaac {
    /* 0x000 */ int32_t  randcnt;      // countdown; 0 ⇒ regenerate. Init leaves 0x100
    /* 0x004 */ int32_t  randrsl[256]; // results pool; keys land in [0..3]
    /* 0x404 */ int32_t  mm[256];      // internal state
    /* 0x804 */ int32_t  aa;
    /* 0x808 */ int32_t  bb;
    /* 0x80c */ int32_t  cc;
};
```

Located cross-architecture by ISA-independent constant anchoring: `MOVK Wd,#0xd92a,LSL#16` (pattern
`4? 25 bb 72`) has **exactly one** hit in `.text`. All eight golden-ratio mix constants match desktop
`Isaac::Init`: `<in Ghidra DB>` `<in Ghidra DB>` `<in Ghidra DB>` `<in Ghidra DB>` `<in Ghidra DB>` `<in Ghidra DB>`
`<in Ghidra DB>` `<in Ghidra DB>`.

### The `+50` question — answered

`` **`Init` performs no adjustment. The caller does.**

In the login block builder `<in Ghidra DB>`:

```c
uVar14 = <in Ghidra DB>(0x810);            // alloc Isaac
<in Ghidra DB>(uVar14, param_1 + 0x48);    // ctor with RAW keys (4 int32 at builder+0x48)
local_90  = ... *(undefined8 *)(param_1 + 0x48) + 0x32 ...   // keys[0],keys[1] + 50
lStack_88 = ... *(undefined8 *)(param_1 + 0x50) + 0x32 ...   // keys[2],keys[3] + 50
uVar13 = <in Ghidra DB>(0x810);
<in Ghidra DB>(uVar13, &local_90);         // ctor with +50 keys
*(undefined8 *)(conn + 0x40)  = uVar14;  // RAW-key Isaac  → OUTBOUND (c2s)
*(undefined8 *)(conn + 0x2b8) = uVar13;  // +50-key Isaac  → INBOUND  (s2c)
```

`0x32` = 50, applied to all four keys. `conn+0x2b8` is exactly the Isaac `TcpIn` reads — a closed loop
confirming **inbound/s2c uses keys+50**, which matches the RS protocol (the server encodes with keys+50).

**A hook on `Init` (or the ctor `<in Ghidra DB>`) therefore sees BOTH:** first call = raw keys (outbound),
second call = keys+50 (inbound). Read `X1` as 4×`int32` (16 bytes) at each call. Subtract 50 from the
second set to recover the originals, or just take the first.

`jag::Isaac::TakeNextValue` — `(X0=Isaac*)` → `X0`. Decrements `randcnt`, returns
`randrsl[randcnt]`; regenerates inline when `randcnt == 0`. `` Double-confirmed:
`TcpConnectionMessage::Init` calls it at exactly the spot desktop calls `jag::Isaac::TakeNextValue`.

**With `TcpIn` giving decoded opcodes directly, reimplementing ISAAC is not required** — Isaac is
documented here as a cross-check and a fallback.

---

## Outgoing (C→S)

`jag::game::TcpConnectionMessage::Init` — ``

```
X0 = msg*   X1 = protEntry*   W2 = resolvedSize   X3 = Isaac* (may be NULL)
opcode = *(int32_t*)protEntry
```

Identification: line-for-line identical to desktop `Init`, including the
`isaac ? (opcode + TakeNextValue(isaac)) : rawOpcode` first-byte branch. Sole caller is `CreatePacket`
`<in Ghidra DB>`, mirroring desktop's sole caller `<in Ghidra DB>`. Same template instantiation as desktop's:
both are reached from `ProcessConnections`' 50-tick keepalive using `conn+0x40`.

**Caveat — `Init` does not give you the payload.** It writes only the opcode byte; the payload is appended
by the caller *after* `Init` returns. Message layout ``:

```c
// jag::game::TcpConnectionMessage
/* 0x00 */ int32_t opcode;
/* 0x04 */ int32_t resolvedSize;
/* 0x18 */ uint8_t* data;      // buffer
/* 0x20 */ int64_t  position;  // write cursor
/* 0x30 */ void*    protEntry;
```

To capture C→S payloads: hook `Init` for `(opcode, size, msg*)`, then read `(msg+0x18, msg+0x20)` at flush
time — or simply use `ClientStream::Write` for post-ISAAC wire bytes. `TcpConnectionMessage` is a template
(`<ServerProt>`, `<ClientProt>`, `<LoginProt>` instantiations exist `[VERIFIED — artifact]`), so
`<addr in DB>` covers the `ClientProt` path only.

---

## Recommended mobile design

```
<in Ghidra DB>          <addr in DB>   S→C decoded packets. PRIMARY HOOK. onEnter, X0 = ServerConnection*
                                   skip if *(int*)(X0+0x2c) == -1
                                   opcode  = *(int*)(X0+0x2c)
                                   size    = *(int*)(X0+0x30)
                                   payload = *(void**)(X0+0x2d0), size bytes
                                   Fires exactly once per packet; connection is X0 — unambiguous.
TcpIn                 <addr in DB>   Optional: scoping/bracketing. conn = *(X1+8).
                                   Do NOT read the payload onLeave — opcode is already reset to -1.
ClientStream::Read    <addr in DB>   Raw S→C for login/RSA. onLeave, length = RETVAL (never X2).
ClientStream::Write   <addr in DB>   Raw C→S for login/RSA. onEnter, length = X2.
Isaac::Init           <addr in DB>   Optional: keys. X1 = 4×int32. 1st=raw(c2s), 2nd=+50(s2c).
```

Gate the raw dumps on `*(int*)(Client + `<in Ghidra DB>`) != 30` to stop at `LOGGED_IN`, mirroring
`RawLoginDump`, and reach the ConnectionManager via `*(Client + `<in Ghidra DB>`)` — **the mobile values, not
desktop's.**

Implemented by `tools/rs3-capture.js` + `tools/rs3-capture.py`; RVAs live in `tools/rva.json`.

**Do not target Project X's `capture/<session>/` file format** (`raw-c2s.bin` / `isaac-keys.txt` /
`DecodeCapture.kt`). That pipeline is dead: its only writer was the deprecated `LoginProxy`, nothing has
produced the format since May 2026, and its seven readers all sit unreferenced in `tools/archive/`.
`[VERIFIED — artifact]` This capture emits its own live decoded log instead.

## Cross-references

- Ground rules: [../re-methodology/cross-architecture-porting.md](../re-methodology/cross-architecture-porting.md)
- Desktop blueprint (sibling in this repo): `../../net/tcpin-isaac-decoding.md`,
  `client-plugin-engine/.../hooks/impl/ServerPacketCapture.kt`, `RawLoginDump.kt`, `game/nxt/Offsets.kt`
- Open items: [../OPEN-QUESTIONS.md](../OPEN-QUESTIONS.md)

## Flagged for the user — divergences from the Project X/Project X project

1. **`OClient::CONNECTION_MANAGER` and `OClient::MAIN_STATE` differ on mobile** (`<in Ghidra DB>`/`<in Ghidra DB>` vs
   `<in Ghidra DB>`/`<in Ghidra DB>`). Project X's `Offsets.kt` is correct for desktop; these must not be reused.
2. **`InitIncoming` cannot be hooked on mobile** — it is inlined. Project X's central capture design needs
   replacing with a TcpIn-based read.
3. Mobile TcpIn rejects opcodes `> 0xe5` (229). The Project X doc `tcpin-isaac-decoding.md` states max
   `0xd8` (216) — that doc is written for rev **946**, so this is a build difference, not an
   architecture one. `` Worth re-checking against desktop **949-1**.
4. Mobile's `ClientStream` calls `recvfrom`/`sendto`; desktop calls `recv`/`send`. Same semantics
   (`MSG_NOSIGNAL`/peek-flag logic identical), but **import-anchoring on `recv` finds only libcurl** on
   mobile. ``
