# `jag::input` — the client's own input layer (one level below SDL / Win32 / Cocoa)

Scope: the platform-independent keyboard/mouse/gamepad layer inside `rs2client`. This is the layer
that the Linux SDL2 event pump, the Windows `WndProc` and the macOS `NSEvent` handler all feed. It is
the correct injection point for synthetic input on **all three** desktop platforms.

Everything here was derived from the 949-1 binaries by disassembly. Byte-precise addresses live in
the Ghidra DB; this file documents the architecture and the semantics,
which are build-independent.

---

## 1. Why this layer, and the portability claim

SDL is **Linux-only**. The three desktop clients ship different windowing/input backends and share
everything below them:

| Platform | Input backend (import table) | Feeds |
|---|---|---|
| Linux | `libSDL2-2.0.so.0` — `SDL_PollEvent`, `SDL_StartTextInput`, `SDL_GetMouseState` | `jag::input::Input` |
| Windows | `USER32.dll` (`WndProc`), `IMM32.dll` (IME), `xinput9_1_0.dll` (pad) — **zero** SDL imports, zero `SDL_` strings | `jag::input::Input` |
| macOS | `Cocoa`/`AppKit` (`NSEvent`, `NSWindow`) via `objc_msgSend` — **zero** SDL imports, zero `SDL_` strings | `jag::input::Input` |

All three call the **same `jag::input::Input` virtual methods with the same argument shapes**. So
hooking or calling `jag::input::Input` gives one code path that works everywhere, and never touches
SDL. Hooking SDL would only ever work on Linux.

The **only** things that differ per platform are:

1. **Keycode value space** — platform-native, see §7. This is the one thing that is *not* portable.
2. **Vtable slot indices** — MSVC emits one destructor slot, the Itanium ABI emits two, so the
   Windows indices are shifted down by 8 bytes.
3. **Struct field offsets** — the head of `Input` (`vptr`, `globalHandler`, `mLock`) matches across
   platforms, the tail does not.
4. **Calling convention** for the non-virtual mouse entries (SysV `RDI`+`XMM0/1` vs MSVC
   `RCX`+`XMM1/2`).

---

## 2. Layer map

```
   ┌──────────────────────────── platform adapter (ONE per OS) ────────────────────────────┐
   │  Linux: jag::Client::Main  — SDL_PollEvent loop                                       │
   │  Windows: WndProc          — WM_KEYDOWN/UP, WM_CHAR, WM_*MOUSE*                       │
   │  macOS: NSEvent handler    — [NSEvent keyCode], [NSEvent characters], mouse events     │
   └───────────────────────────────────────┬───────────────────────────────────────────────┘
                                           │  synchronous call, no queue
                                           ▼
                        ┌──────────────  jag::input::Input  ──────────────┐
                        │  embedded in jag::Client (not heap-allocated)   │
                        │  5 virtuals + 4 non-virtual mouse entries       │
                        │  owns: globalHandler + map<string,InputHandler*>│
                        └───────────────────────┬────────────────────────┘
                                                │  for each handler, in map order,
                                                │  then globalHandler LAST
                                                ▼
                     ┌──────────────  jag::input::InputHandler  ──────────────┐
                     │  ~23 × jag::EventListeners<std::function<bool(...)>>   │
                     │  one slot per event kind, each with its own lock       │
                     └───────────────────────┬──────────────────────────────┘
                                             │  first listener returning true CONSUMES
                                             ▼
              jag::game::Mouse   jag::game::Keyboard   jag::game::Gamepad   jag::game::Console …
              (registered via `Xxx::Xxx(jag::input::InputHandler&)` constructors)

   side-channel, written by the entry points, read by everything:
              jag::input::InputState — mouseX / mouseY / 3 button bytes / map<int,bool> keyDown
```

### Reference-binary symbol corroboration

The unstripped `librs2client.so` (severely outdated — names only, never offsets) confirms the class
and method names used here:

```
jag::input::Input::OnKeyDown(int)
jag::input::Input::OnKeyUp(int)
jag::input::Input::OnMouseWheel(float,float,float,float)
jag::input::InputHandler::InputHandler(void)
jag::input::InputState::IsKeyDown(int)
jag::game::Mouse::Mouse(jag::input::InputHandler &)
jag::game::Gamepad::Gamepad(jag::input::InputHandler &)
jag::game::Keyboard::OnKeyDown(int) / OnKeyUp(int) / OnKeyChar(int)
eastl::rbtree<eastl::basic_string<char,…>, eastl::pair<… const, jag::input::InputHandler *>, …>
jag::EventListeners<std::function<bool (float,float)>>::CallListeners<
    {jag::input::InputHandler::OnLMouseDown(float,float)::lambda}>
jag::EventListeners<std::function<bool (uint,jag::input::GamepadAxis,short)>>
jag::EventListeners<std::function<bool (uint,jag::input::GamepadButton,bool)>>
jag::EventListeners<std::function<bool (uint,jag::input::GamepadTrigger,uchar)>>
```

The `rbtree<eastl::string, InputHandler*>` symbol is what independently confirms that `Input`'s
handler container is a **string-keyed map**, and the `pair<string const, InputHandler*>` layout is
what puts the handler pointer at node `+0x38` (rbtree node header `0x20` + `eastl::basic_string`
`0x18`).

---

## 3. The `jag::input::Input` API

### Virtuals (identical semantics on every platform)

| Itanium slot (Linux/macOS) | MSVC slot (Windows) | Signature | Notes |
|---|---|---|---|
| `+0x00`, `+0x08` | `+0x00` | `~Input` | Itanium emits both non-deleting and deleting dtors |
| `+0x10` | `+0x08` | `void OnKeyDown(int keycode)` | |
| `+0x18` | `+0x10` | `void OnKeyUp(int keycode)` | |
| `+0x20` | `+0x18` | `void OnKeyChar(int unicodeCodepoint)` | |

The vtable ends after `OnKeyChar` — there are exactly five virtual entries.

`OnKeyDown`/`OnKeyUp`/`OnKeyChar` are thin wrappers around the console-key special case; the real
dispatch bodies are separate non-virtual functions (referred to here as `*Inner`):

- `OnKeyDown(k)`: if `k == 0x1ca3` → console handling (see §6), **else** tail-call `OnKeyDownInner`.
  Note the console key does **not** reach the listeners.
- `OnKeyUp(k)`: always calls `OnKeyUpInner(k)` first, then if `k == 0x1ca3` clears `consoleKeyHeld`.
- `OnKeyChar(cp)`: if `consoleKeyHeld` is set, **drop the codepoint**; else `OnKeyCharInner(cp)`.

### Non-virtual mouse entry points

Called directly (not through the vtable) by the platform adapter:

| Function | Signature | Writes |
|---|---|---|
| `Input::OnMouseMotion` | `(Input*, float x, float y)` | `this->lastMouseX/Y`, `InputState.mouseX/Y` |
| `Input::OnLeftButtonDown` | `(Input*, float x, float y)` | `InputState.leftButtonDown = 1`, `mouseX/Y` |
| `Input::OnLeftButtonUp` | `(Input*, float x, float y)` | `InputState.leftButtonDown = 0`, `mouseX/Y` |
| `Input::OnScrollWheel` | `(Input*, float wheelX, float wheelY)` | nothing — see the warning below |

There is **no** `OnMiddleButton*` / `OnRightButton*` function. The platform adapter inlines those:
it writes the button byte in `InputState` itself and then calls
`EventListeners::CallListeners(packedXY, globalHandler + <slot>)` directly. To synthesise a middle or
right click you must reproduce that — see §8.

> ⚠️ `OnScrollWheel` takes **only the wheel deltas**. The `x`/`y` handed to wheel listeners are read
> out of `Input::lastMouseX/lastMouseY`, which **only `OnMouseMotion` ever writes**. A wheel event
> injected without a preceding motion carries a stale cursor position.

### `EventListeners::CallListeners`

Not a member of `Input` — it is the `std::function<bool(float,float)>` instantiation of
`jag::EventListeners<T>::CallListeners`. Signature: `(uint64 packedXY, EventListeners* slot)` where
the low dword of `packedXY` is `x` and the high dword is `y`. It locks the slot, walks
`mBegin..mEnd`, invokes each `std::function`, and stops at the first one returning `true`.

---

## 4. `Input` layout

```c
struct jag::input::Input {          // Linux offsets; see §7 for Windows/macOS
/* +0x00 */ void            *vptr;
/* +0x08 */ InputHandler    *globalHandler;   // dispatched LAST, after every named handler
/* +0x10 */ void            *unknown;
/* +0x18 */ pthread_mutex_t  mLock;           // RECURSIVE (__kind = 1)
/* +0x40 */ eastl::rbtree<eastl::string, InputHandler*> namedHandlers;
                                              // anchor +0x40, iteration begins at *(this+0x48),
                                              // ends when it equals this+0x40;
                                              // node: left+0x00 right+0x08 parent+0x10
                                              //       key(eastl::string)+0x20  handler+0x38
/* +0x70 */ eastl::rbtree<…>  unknown2;       // self-linked anchor, contents unidentified
/* +0x88 */ float             lastMouseX;
/* +0x8C */ float             lastMouseY;
/* +0x90 */ jag::Client      *client;
/* +0x98 */ bool              consoleKeyHeld;
};                                            // total 0xA0
```

`mLock` being **recursive** is load-bearing: re-entering `Input` from inside a listener on the same
thread cannot deadlock. It also means a hook that calls back into `Input::OnKeyDown` while already
inside a dispatch is safe.

The `Input` is **embedded in the `jag::Client`**, not heap-allocated. `Client::GetInput` (a Client
vtable slot) is just `return client + <fixed offset>`. Practical consequence: the `Input*` is
computable from the global `Client` pointer the moment the Client exists — there is no need to wait
for a real input event to capture it from a hook.

---

## 5. `InputHandler` slot map

`InputHandler` is essentially an array of `EventListeners`, each `0x40` bytes:

```c
struct jag::EventListeners {          // 0x40 bytes
/* +0x00 */ std::function<bool(Args...)> **mBegin;
/* +0x08 */ std::function<bool(Args...)> **mEnd;
/* +0x10 */ std::function<bool(Args...)> **mCapacityEnd;
/* +0x18 */ pthread_mutex_t              mLock;
};
```

Slot *n* lives at `InputHandler + 0x08 + n*0x40`. Verified slots:

| n | offset | event | listener signature |
|---|---|---|---|
| 0 | `+0x008` | LMouseDown | `bool(float x, float y)` |
| 1 | `+0x048` | LMouseUp | `bool(float x, float y)` |
| 2 | `+0x088` | MMouseDown | `bool(float x, float y)` |
| 3 | `+0x0C8` | MMouseUp | `bool(float x, float y)` |
| 4 | `+0x108` | RMouseDown | `bool(float x, float y)` |
| 5 | `+0x148` | RMouseUp | `bool(float x, float y)` |
| 6 | `+0x188` | MouseMove | `bool(float x, float y)` |
| 7 | `+0x1C8` | MouseWheel | `bool(float x, float y, float wheelX, float wheelY)` |
| 8 | `+0x208` | KeyDown | `bool(int keycode)` |
| 9 | `+0x248` | KeyUp | `bool(int keycode)` |
| 10 | `+0x288` | KeyChar | `bool(int unicodeCodepoint)` |
| 11–15 | `+0x2C8` … `+0x3C8` | **UNIDENTIFIED** | probably touch/gesture — the desktop adapters never dispatch them, and the reference binary has `bool(ulong touchId, float, float)` and `bool(GestureEvent_Swipe const&)` listener types. Not confirmed; do not rely on this. |
| 16 | `+0x408` | GamepadButton | `bool(uint padIndex, GamepadButton, bool pressed)` |
| 17 | `+0x448` | GamepadAxis | `bool(uint padIndex, GamepadAxis, short value)` |
| 18 | `+0x488` | GamepadTrigger | `bool(uint padIndex, GamepadTrigger, uchar value)` |
| 19–22 | `+0x4C8` … `+0x588` | **UNIDENTIFIED** | |
| — | `+0x5E8` | `eastl::rbtree` of per-frame updatables | the adapter calls `vtable+0x28` on `*(node+0x20)` for each entry once the OS event queue drains |

`InputHandler + 0x00` is 8 bytes that no dispatch path reads (likely a vptr — the reference binary
has `InputHandler::~InputHandler`).

Each listener is a **pointer to** a `std::function`. Dispatch is
`fn->_M_invoker(&fn->_M_functor, &arg0, &arg1, …)` (libstdc++ passes `_ArgTypes&&`, i.e. every
argument by reference, even `int` and `float`). A null `mEnd`-side pointer is skipped; a
`std::function` with a null `_M_manager` (`+0x10`) triggers `std::bad_function_call`.

---

## 6. Semantics you must respect when injecting

These are the behaviours that make a synthetic event indistinguishable from a real one. Every one is
a real difference in observable state, not a style preference.

1. **Dispatch is synchronous on the adapter's thread.** There is no queue between the OS and
   `jag::input::Input`. On Linux the adapter is the main loop: it drains `SDL_PollEvent`, dispatching
   each event inline, then runs the frame. Injected input must be delivered on **that same thread**
   to reproduce real ordering, and to be safe against the unlocked containers the consumers touch.

2. **First listener to return `true` consumes the event.** Injecting past a consuming listener is
   impossible by design, and a consumed event never reaches the later handlers or `globalHandler`.

3. **Handler dispatch order is: every `namedHandlers` entry in map (string) order, then
   `globalHandler`.** Not registration order.

4. **`InputState`'s key-down flag is set AFTER key-down dispatch and cleared BEFORE key-up
   dispatch.** So a listener that asks `IsKeyDown(k)` during `OnKeyDown(k)` sees `false`. Modifier
   state for a synthetic combo must be established by a *prior* `OnKeyDown` call — pressing shift and
   the shifted key in the same call sequence, with no intervening dispatch, will not read as
   "shift held" inside the second key's own dispatch.

5. **`OnKeyUpInner` inserts the key into the key-down map if absent**, so a key-up for a key that was
   never pressed is harmless but does create a map entry.

6. **The console key is a synthetic pseudo-keycode, `0x1ca3`**, and it is the one value that is
   identical on all three platforms. The adapter fires `OnKeyDown(0x1ca3)` *in addition to* the real
   keycode when the console key is pressed. `OnKeyDown(0x1ca3)` never reaches listeners; it opens the
   dev console (gated on Client state and on `IsKeyDown(LALT)`/`IsKeyDown(RALT)`) and sets
   `consoleKeyHeld`. While `consoleKeyHeld` is set, **every** `OnKeyChar` codepoint is dropped. Do not
   inject `0x1ca3`.

7. **Character input is a separate channel.** `OnKeyChar` receives Unicode codepoints produced by the
   OS text-input pipeline (UTF-8 decode on Linux, an ANSI→UTF-16 table on Windows, `NSString`
   `unichar` on macOS). Keycodes are *not* converted to characters anywhere below the adapter, so
   typing text requires driving `OnKeyChar` explicitly — `OnKeyDown('a')` alone types nothing.

8. **`OnScrollWheel` needs a preceding `OnMouseMotion`** (see §3).

9. **Middle/right button state bytes are written by the adapter, not by `Input`.** A synthetic middle
   or right click that only calls `CallListeners` leaves `InputState.middleButtonDown` /
   `rightButtonDown` stale.

---

## 7. Per-platform differences

### Keycode space — **platform-native, NOT a shared Jagex enum**

This is the single most important portability constraint, and it is easy to get wrong because the
Linux values look like a portable enum (they are not — they are just SDL's).

| Platform | Value passed to `Input::OnKeyDown` | Evidence |
|---|---|---|
| Linux | `SDL_Keycode` (`SDL_Event.key.keysym.sym`) — ASCII for printables, `<in Ghidra DB>` \| scancode` otherwise | adapter passes `keysym.sym` unmodified; game code compares against `<in Ghidra DB>`/E1/E2/E6` (LCTRL/LSHIFT/LALT/RALT) inline |
| Windows | Win32 **virtual-key code** (`wParam` of `WM_KEYDOWN`, unmodified) | `mov edx, ebx` where `ebx = wParam`, then `call [vtable+0x08]`. The binary contains **zero** occurrences of `<in Ghidra DB>` |
| macOS | macOS **virtual keycode** (`[NSEvent keyCode]`, `kVK_*`) | `objc_msgSend(event, @selector(keyCode))` → `movzx esi, r14w` → `call [vtable+0x10]` |

Platform-specific normalisations performed by the adapter (reproduce these or synthetic input will
diverge from real input):

- **Linux**: `keysym.scancode == 0x35` (`SDL_SCANCODE_GRAVE`) also fires `OnKeyDown(0x1ca3)` first.
- **Windows**: `wParam == Input->consoleKeyVk` (a *stored, configurable* VK field) fires `0x1ca3`
  first. `VK_F4` with the lParam ALT bit set (Alt+F4) is dropped entirely. `WM_CHAR` is repeated
  `lParam & 0xFFFF` times (the key-repeat count).
- **macOS**: `keyCode == 0x32` (`kVK_ANSI_Grave`) or `0x0A` (`kVK_ISO_Section`) fires `0x1ca3` first.
  `kVK_ANSI_KeypadEnter` (`0x4C`) is rewritten to `kVK_Return` (`0x24`) **before** dispatch.
  `kVK_Delete` (`0x33`, Backspace) additionally fires `OnKeyChar(8)`. Characters in the private-use
  range `0xF700–0xF8FF` (Cocoa's function-key encoding) are filtered out of `OnKeyChar`.

So an engine that wants one portable `keyPress("F1")` API needs **three keycode tables**, selected at
runtime. Only `0x1ca3` is shared, and you must never send it.

### Calling convention for the non-virtual mouse entries

| Platform | `this` | `x` | `y` |
|---|---|---|---|
| Linux / macOS (SysV) | `RDI` | `XMM0` | `XMM1` |
| Windows (MSVC x64) | `RCX` | `XMM1` | `XMM2` |

Windows shifts the float registers because `this` occupies argument slot 0.

### `std::function` and `EventListeners` internals

| | libstdc++ (Linux/macOS) | MSVC (Windows) |
|---|---|---|
| listener invoke | `fn->_M_invoker` at `fn+0x18`, empty check `fn+0x10` | virtual `_Do_call` at `(*fn)[2]`, i.e. `[[fn]+0x10]` |
| `EventListeners` | `mBegin+0x00 mEnd+0x08 cap+0x10 lock+0x18`, stride `0x40` | different — observed `mBegin` / `mEnd` / lock at handler-relative `+0xD8 / +0xE0 / +0xF0` for one slot; the slot stride is **not** `0x40` and must be re-derived |

So the `InputHandler` slot table in §5 is **Linux/macOS only**. On Windows the slot offsets must be
re-derived from that build's adapter.

### Windows middle/right buttons — the Linux recipe crashes

The §8 recipe does **not** port. MSVC stamps out one listener walker per slot with the slot and its
mutex baked in, so Windows has **no generic `CallListeners(packedXY, slot)`**. The function a
signature match pairs with the Linux `CallListeners_ff` is the *mouse-move* walker,
`(InputHandler*, float x, float y)`. Called with the Linux arguments, the packed floats become the
handler pointer and the client dies on the first mutex lock.

What Windows has instead:

| Action | Windows |
|---|---|
| right down / right up | `Input::OnRightButtonDown` / `OnRightButtonUp(input, x, y)`: each writes its button byte and `mouseX/Y` itself |
| middle up | `Input::OnMiddleButtonUp(input, x, y)` |
| middle down | **no function**: the WndProc open-codes it. Reproduce it: set the byte and `mouseX/Y`, `_Mtx_lock` the slot mutex, and invoke each listener's callable through its vtable as `(callable, &x, &y)` until one returns true, then `_Mtx_unlock` |

`_Mtx_lock`/`_Mtx_unlock` are the client's statically linked MSVC STL copies, not `msvcp140` imports,
so resolve them from the offset table and not from a DLL.

### `InputState` global block

The `(y, x)` ordering — **y at the lower address** — was independently confirmed on both the Linux
and Windows builds (two different compilers), so it is a real field order and not a decompiler
artefact. Both are `float`, never `int`. The three button bytes are adjacent on Linux; on Windows
they are not adjacent to the coordinate pair.

---

## 8. Injection recipe

Given `input = Client::GetInput` and `handler = input->globalHandler`, and running **on the game
thread**:

| Action | Calls |
|---|---|
| move | `OnMouseMotion(input, x, y)` |
| left down | `OnLeftButtonDown(input, x, y)` |
| left up | `OnLeftButtonUp(input, x, y)` |
| middle down | `InputState.middleButtonDown = 1`; `InputState.mouseX/Y = x/y`; `CallListeners_ff(pack(x,y), handler + 0x088)` |
| middle up | `InputState.middleButtonDown = 0`; `InputState.mouseX/Y = x/y`; `CallListeners_ff(pack(x,y), handler + 0x0C8)` |
| right down | `InputState.rightButtonDown = 1`; `InputState.mouseX/Y = x/y`; `CallListeners_ff(pack(x,y), handler + 0x108)` |
| right up | `InputState.rightButtonDown = 0`; `InputState.mouseX/Y = x/y`; `CallListeners_ff(pack(x,y), handler + 0x148)` |
| wheel | `OnMouseMotion(input, x, y)` first, then `OnScrollWheel(input, wheelX, wheelY)` |
| key down | `vtable[OnKeyDown](input, nativeKeycode)` |
| key up | `vtable[OnKeyUp](input, nativeKeycode)` |
| type a character | `vtable[OnKeyChar](input, codepoint)` — independently of any key event |

`pack(x, y)` = `(uint64)(bitcast<u32>(y) << 32) | bitcast<u32>(x)`.

Prefer the **virtuals** over the `*Inner` functions for keys: the virtuals are what the adapter
calls, so they reproduce the console-key and `consoleKeyHeld` behaviour exactly. Calling `*Inner`
directly skips that.

Note that `namedHandlers` is dispatched before `globalHandler`; if a named handler consumes the
event, a real event would also have been consumed, so dispatching only into `globalHandler` (as the
adapter does for middle/right clicks) is faithful only because the adapter itself does exactly that.

### What NOT to do

- **Do not hook or call SDL.** Linux-only, and the client's own layer is strictly better.
- **Do not synthesise OS-level input** (`XTestFakeKeyEvent`, `SendInput`, `CGEventPost`). It is
  observable, needs elevated permissions on macOS, and moves the real cursor.
- **Do not push into the `MainLogicManager` click ring.** That buffer is shared between the
  server-bound packet build and local input dispatch; writing to it side-effects the game (see
  `MouseEventBuffer.push`, permanently disabled).
- **Do not assume a `Input::InjectSyntheticRightClick` exists.** The function previously recorded
  under that name is a **touch** long-press handler whose `this` is a touch tracker, not an `Input`
  (§9).

---

## 9. Corrections to earlier project work

Recorded so the same mistakes are not re-derived:

1. **`Input::InjectSyntheticRightClick` is misnamed and is not an `Input` method.** Its `this` is a
   touch tracker (`+0x48` = `Input*`, `+0x430` active touch id, `+0x440` press timestamp ms,
   `+0x44d/e/f` state flags, vtable `<addr in DB>`). Since `Input` is only `0xA0` bytes, calling it
   with an `Input*` reads far outside the object. There is no native synthetic-right-click helper.
2. **`OnKeyDownInner` / `OnKeyUpInner` take exactly two parameters** (`Input*`, `int`). The prologue
   reads only `RDI` and `ESI`; `RDX`/`RCX` are never touched. A 4-parameter binding is wrong, and
   gating a helper on a captured 4th "parameter" gates on register garbage.
3. **The `InputState` mouse globals are `float`, in `(y, x)` order**, and the previously recorded
   addresses were outside the loaded image entirely — see the 949-4 offsets doc for the verified
   values. Reading them as `int` returns nonsense even at the right address.
4. **`Input::OnKeyDown`'s first parameter is the `Input`, not the `Client`.** The `Client` is reached
   through `Input+0x90`.
5. **`Input::DispatchObservers` is misnamed** — it is `jag::EventListeners<std::function<bool(float,
   float)>>::CallListeners` and never touches an `Input`.
6. **The `Input*` does not have to be captured from a hook.** It is `Client + <fixed offset>`.
