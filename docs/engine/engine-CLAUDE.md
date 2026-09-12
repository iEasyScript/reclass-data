# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Code Guidelines (Non-Negotiable)

### No fully-qualified-name inlines

Never reference symbols by their full package path inside code. Add an `import` at the top of the file and use the bare name.

```kotlin
// BAD
val v = com.projectx.game.math.Vector2f(1f, 2f)
val x = com.projectx.script.api.varps.getVarBit(123)

// GOOD
import com.projectx.game.math.Vector2f
import com.projectx.script.api.varps
val v = Vector2f(1f, 2f)
val x = varps.getVarBit(123)
```

This applies to function bodies, property getters, lambdas, parameter types, return types, KDoc references, and prose comments. If two symbols collide, use `import x as Y` aliasing — never inline FQNs.

### Self-documenting code, minimal comments

Default to writing no comments. Code should be readable on its own through good names. Only add a comment when:

- It explains a **non-obvious WHY** (a constraint, an invariant, a workaround for a specific bug, surprising behaviour).
- A function's role isn't clear from its signature and a single line of KDoc would help a reader navigating the file.

Do not write multi-paragraph KDoc blocks. Do not narrate what the code does ("Iterate the list and find the first matching..." — well-named code already says that). Do not write "this function returns X" — the signature does. Do not reference the current task, recent fix, ticket number, or who/why ("for the Y flow", "fixes #123") — those belong in the PR/commit message and rot with time.

If you find yourself writing a comment to explain a tricky block, first try renaming variables or extracting a function until the code is self-evident; only fall back to a comment when that fails.

## Project Overview

Project X is a reverse engineering tool for the Linux RuneScape NXT client. It injects into the running RS3 process via `gdb` + `dlopen`, using a native C++ bootstrap library that hooks the JVM and loads the Kotlin engine. There is no traditional `main` — the entry point is `Bootstrap.initialize(baseAddr: Long)` called from native code after injection.

## Build & Run Commands

```bash
# Build the engine (shadow JAR + native library)
./gradlew build

# Compile Kotlin only (fast check for errors)
./gradlew compileKotlin

# Build native bootstrap library only
./gradlew buildNativeBootstrap

# Build first-party scripts (outputs to ~/.projectx/scripts/)
./gradlew :client-plugin-engine:official-scripts:build

# Build community scripts (opt-in; not part of the default build)
./gradlew -PcommunityScripts :client-plugin-engine:community-scripts:build

# Inject into running RS3 client
./inject.sh
```

**Requirements:** Java 25 (Project Panama), CMake, Clang, SDL2, GDB. `JAVA_HOME` must be set.

## Architecture

### Injection & Bootstrap Flow
1. `inject.sh` finds `rs2client` PID, uses `gdb` to `dlopen` the native `.so`
2. `native-bootstrap/` (C++20): hooks into JVM, sets up ImGui/SDL2/EGL rendering, loads the engine JAR
3. `Bootstrap.kt` initializes NativeAccess, Client struct, HookManager, and ScriptExecutor

### Core Modules (`src/main/kotlin/com/projectx/`)

- **`game/`** — NXT client integration
  - `bootstrap/Bootstrap.kt` — injection entry point
  - `nxt/` — memory-mapped structs (Client, Player, NPC, etc.) via Project Panama `MemorySegment`
  - `hooks/` — game event interception (main loop, actions, vars, chat). `HookManager.kt` coordinates all hooks
  - `cs2/CS2Executor.kt` — interop with the game's CS2 scripting engine
  - `memory/NativeAccess.kt` — Java FFI layer (`java.lang.foreign`) for native function binding
- **`script/`** — coroutine-based scripting framework
  - `Script.kt` — base class, 40ms tick event loop, parallel execution support
  - `ScriptExecutor.kt` — lifecycle management, dynamic discovery via ClassGraph
  - `ScriptLoader.kt` — class scanning (JARs, class files, classpath)
  - `StateMachineScript.kt` — generic state machine pattern `StateMachineScript<T>`
  - Scripts auto-discovered from `~/.projectx/scripts/` via `@ScriptDescription` annotation
- **`pathfinder/`** — route finding with collision detection (`RouteFinder.kt`, `WorldCollision.kt`)
- **`traversal/`** — DSL for building movement/interaction sequences as linked `TraversalNode` chains. See `src/main/kotlin/com/projectx/traversal/README.md` for DSL docs
- **`ui/`** — ImGui-based overlay UI
- **`cache/`** — game cache parsing and SQLite storage

### Native Bootstrap (`native-bootstrap/`)
C++20 library producing `libprojectxbootstrap.so`. Uses funchook for function interception, ImGui + SDL2 + EGL for overlay rendering. CMake build system.

### Script Modules (`official-scripts/`, `community-scripts/`)
The concrete automation scripts live in two separate Gradle subprojects, **not** in `:client-plugin-engine`
itself — the engine only provides the framework and discovers script JARs at runtime.
- **`official-scripts/`** (`:client-plugin-engine:official-scripts`) — first-party scripts (trent + devin
  authorship, including the dungeoneering suite and the `ExampleModuleScript` demo). Built by
  default. The `com.projectx.script.impl.trent` / `.devin` packages live here.
- **`community-scripts/`** (`:client-plugin-engine:community-scripts`) — community-contributed scripts
  (`qb`, `bp`, `gibson`, `mel`, `pineapple`, `BugAbuser`, …). Optional and **excluded from the
  default build**; include it with `-PcommunityScripts` (or the `COMMUNITY_SCRIPTS` env var).
  Depends on `:client-plugin-engine:official-scripts` (a few community scripts reuse first-party ones).

Each module builds a plain JAR and copies it to `~/.projectx/scripts/` for auto-discovery by
`ScriptExecutor`.

### Key Patterns
- **Memory access:** Project Panama (`java.lang.foreign`) — `MemorySegment`, `Arena`, `Linker`, `FunctionDescriptor`
- **Scripts:** Kotlin coroutines with `ClientPulseDispatcher`, suspend functions for async game interaction
- **Script registration:** `@ScriptDescription(name, version, author, description, visible, category)` annotation
- **Remote debugging:** port 5005 for JVM hot-swap during script development

## Reference Data

- `developer-info/enums.txt` — reverse-engineered game enum mappings
- `developer-info/structs.txt` — reverse-engineered struct definitions
- `asm-refs/` — disassembly references
