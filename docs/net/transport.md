# Transport Layer: ClientStream, ServerConnection, ConnectionManager

## Overview

The NXT client's transport layer consists of three major components:

1. **ClientStream** (`jag::ClientStream`) -- Low-level TCP socket wrapper with ring-buffer reads and buffered writes
2. **ServerConnection** (`jag::game::ServerConnection`) -- Message framing, Isaac cipher integration, packet queuing, connection lifecycle
3. **ConnectionManager** (`jag::ConnectionManager`) -- High-level connection state machine, login orchestration, tick-based processing

Data flows: `Server <-> TCP Socket <-> ClientStream <-> ServerConnection <-> ConnectionManager <-> Game Logic`

---

## ClientStream

**Ghidra struct:** `ClientStream` (232 bytes, `/jag` category)

The ClientStream wraps a raw TCP socket and provides:
- A circular (ring) buffer for efficient reads
- An optional write buffer for batched sends
- DNS resolution and non-blocking connection support
- Ping measurement via ioctl timing

### Struct Layout

| Offset | Size | Type     | Name            | Description |
|--------|------|----------|-----------------|-------------|
| 0x00   | 4    | int      | state           | 0=initial, 1=connecting, 2=connected |
| 0x08   | 4    | int      | socketFd        | TCP socket file descriptor, -1 if closed |
| 0x0C   | 4    | int      | protocol        | Socket protocol (IPPROTO_TCP=6) |
| 0x10   | 24   | eastl::string | hostname   | Connected hostname (EASTL SSO string) |
| 0x30   | 24   | eastl::string | ipAddress  | Connected IP address string |
| 0x48   | 4    | int      | addressFamily   | AF_INET=0 or AF_INET6=1 |
| 0x4A   | 2    | ushort   | port            | Connected port (network byte order) |
| 0x4C   | 16   | byte[16] | ipAddrBytes     | Raw IP address bytes |
| 0x68   | 1    | bool     | hasSSL          | SSL/TLS enabled flag |
| 0x71   | 1    | bool     | usePeek         | If true, recv uses MSG_PEEK flag |
| 0x78   | 8    | void*    | ringBufStart    | Read ring buffer base pointer |
| 0x80   | 8    | void*    | ringBufEnd      | Read ring buffer wrap boundary |
| 0x88   | 8    | void*    | ringBufCapacity | Read ring buffer allocation end |
| 0x90   | 8    | void*    | ringBufReadPos  | Current consumer read position |
| 0x98   | 8    | void*    | ringBufWritePos | Current producer write position |
| 0xA0   | 8    | long     | availableBytes  | Bytes available in ring buffer |
| 0xA8   | 4    | int      | ping            | Last ping in ms, -1 = unknown |
| 0xB8   | 8    | long     | recvBufCapacity | Temporary recv buffer size |
| 0xC0   | 8    | void*    | recvBufPtr      | Temporary recv buffer pointer |
| 0xC8   | 8    | void*    | writeBufStart   | Write buffer start (buffered mode) |
| 0xD0   | 8    | void*    | writeBufCurrent | Write buffer current position |
| 0xD8   | 8    | void*    | writeBufEnd     | Write buffer capacity end |
| 0xE0   | 1    | bool     | bufferedMode    | true=buffer writes, false=send directly |
| 0xE4   | 4    | int      | lastErrno       | Last socket error (errno) |

### Methods

#### `ClientStream::ClientStream(hostname, readBufSize, writeBufSize, param5, param6, buffered)` -- `<addr in DB>`

Constructor. Initializes the ring buffer for reads (size `readBufSize`), the write buffer (size `writeBufSize`), and sets buffered mode. Calls `Connect` to establish the TCP connection. Registers with epoll/poll for async I/O monitoring.

Typical invocation from `OpenConnection`: `ClientStream(host, `<in Ghidra DB>`, 0x2800, `<in Ghidra DB>`, 0x2000, true)` -- 1MB read buffer, 10KB write buffer, buffered mode.

#### `ClientStream::Connect(hostname, errorOut, param4, param5)` -- `<addr in DB>`

Establishes a TCP connection. Supports two modes:
- **Synchronous:** Calls `ResolveHostname` then `ConnectSocket` directly
- **Asynchronous:** Dispatches to a thread pool for non-blocking resolution and connect

Returns true on success.

#### `ClientStream::ConnectSocket(addrInfo, errorOut, recvBufSize, sendBufSize)` -- `<addr in DB>`

Low-level socket creation. Performs:
1. `socket` -- creates TCP socket
2. `setsockopt(TCP_NODELAY, 1)` -- disables Nagle's algorithm
3. `setsockopt(SO_RCVBUF, recvBufSize)` -- sets receive buffer (reads `/proc/sys/net/core/rmem_max` for cap)
4. `setsockopt(SO_SNDBUF, sendBufSize)` -- sets send buffer (reads `/proc/sys/net/core/wmem_max` for cap)
5. `connect` -- connects to server
6. Stores connected address info (family, IP, port) in the struct

Iterates the addrinfo linked list on `EINPROGRESS` (errno 0x73).

#### `ClientStream::ResolveHostname(result, hostAndPort)` -- `<addr in DB>`

Parses `host:port` string, calls `getaddrinfo`. Stores addrinfo result for `ConnectSocket`.

#### `ClientStream::Read(buffer, length)` -- `<addr in DB>`

Reads up to `length` bytes into `buffer`. Algorithm:
1. If enough data in ring buffer, copy directly from ring buffer (consumer side)
2. If not enough, call `recv` from the socket to refill the producer side of the ring buffer
3. Copy from ring buffer to output
4. On `recv` failure (returns 0 or -1), closes the connection

Returns actual bytes read.

#### `ClientStream::Write(buffer, length)` -- `<addr in DB>`

Writes data to the socket. Two modes:
- **Unbuffered** (`bufferedMode=false`): Calls `send(fd, buffer, length, MSG_MORE)` directly. If send is incomplete, closes the connection.
- **Buffered** (`bufferedMode=true`): Appends to the write buffer vector (at +0xC8..+0xD8). Buffer auto-grows via `HeapInterface::Alloc` if needed.

Returns bytes written.

#### `ClientStream::Flush` -- `<addr in DB>`

Flushes the write buffer by calling `send`. Records timing statistics for bandwidth monitoring. Updates ping measurement via ioctl. Closes connection on send failure.

#### `ClientStream::GetAvailable` -- `<addr in DB>`

Returns bytes available to read. Combines:
1. `availableBytes` from the ring buffer
2. `ioctl(fd, FIONREAD)` to query kernel socket buffer

Closes connection on socket error.

#### `ClientStream::GetPing` -- `<addr in DB>`

Returns the last measured ping in milliseconds (-1 if unknown). Thread-safe (protected by mutex at `<addr in DB>`). Two paths:
- **Socket inactive** (fd==-1 or usePeek off): returns cached value at `this+0xA8`
- **Socket active**: creates a 5-second timing probe, measures round-trip via `<in Ghidra DB>`, stores result at `this+0xA8`

Called by the network diagnostics overlay to display `" Ping: %dms"`.

#### `ClientStream::Close` -- `<addr in DB>`

Closes the socket fd via `close`. Resets hostname string, port, and status. Returns true if `close` succeeded.

### Ring Buffer Design

The ring buffer uses 5 pointers:
```
ringBufStart  ->  [.....................]  <- ringBufEnd
                       ^         ^
                  ringBufReadPos  ringBufWritePos
```

- Data is written by `recv` at `ringBufWritePos`, which wraps to `ringBufStart` when reaching `ringBufEnd`
- Data is consumed by `Read` at `ringBufReadPos`, which similarly wraps
- `availableBytes` tracks the count without pointer arithmetic
- The buffer is allocated once in the constructor and never resized

---

## ServerConnection

**Ghidra struct:** `ServerConnection` (752 bytes, `/jag/game` category)

**Note:** The actual runtime object pointed to by `ConnectionManager.gameConnection` and `ConnectionManager.loginConnection` is a massive composite class with a vtable spanning ~680+ entries (from `<addr in DB>` to `<addr in DB>`). This vtable includes `ServerConnection`, `InventoryManager`, `PlayerVarDomain`, `LocationSection`, and many other subsystem methods. The `ServerConnection` struct in Ghidra covers only the fields relevant to the transport/connection layer portion of this object.

The ServerConnection sits between the ClientStream and the ConnectionManager. It provides:
- Opcode/size framing with Isaac cipher decryption
- A Packet buffer for reading server data
- A message queue for outgoing client messages (with pool-allocated nodes)
- Connection lifecycle management

### Struct Layout

| Offset | Size | Type     | Name               | Description |
|--------|------|----------|--------------------|-------------|
| 0x00   | 8    | void*    | sharedPtrControl   | shared_ptr control block for ClientStream |
| 0x08   | 8    | void*    | clientStream       | Pointer to ClientStream |
| 0x20   | 4    | int      | socketStatus       | Socket status tracking |
| 0x28   | 4    | int      | currentOpcode      | Current server opcode (-1 = none) |
| 0x2C   | 4    | int      | currentOpcode2     | Duplicate/pending opcode |
| 0x30   | 4    | int      | payloadSize        | Expected payload size (-1=var1byte, -2=var2byte) |
| 0x34   | 1    | bool     | opcodeDecoded      | True after opcode is Isaac-decrypted |
| 0x35   | 1    | bool     | payloadReady       | True after full payload read |
| 0x38   | 4    | int      | packetStalledCount | Counter for stalled reads (warns at 500) |
| 0x3C   | 1    | bool     | stalledWarning     | True when stalled count > 499 |
| 0x40   | 8    | Isaac*   | isaacInPtr         | Isaac cipher for incoming opcodes |
| 0x48   | 8    | void*    | messageQueueHead   | Outgoing message queue (doubly-linked list) |
| 0x50   | 8    | void*    | messageQueueTail   | Queue tail pointer |
| 0x58   | 8    | void*    | queueNodeFreelist  | Recycled queue node freelist |
| 0x88   | 8    | long     | pendingMessageCount| Messages in outgoing queue |
| 0x2B0  | 4    | int      | pendingByteCount   | Total bytes pending to send |
| 0x2B8  | 8    | Isaac*   | isaacOutPtr        | Isaac cipher for outgoing opcodes |
| 0x2C0  | 16   | Packet   | packetBuffer       | Packet buffer for reading server data |
| 0x2D0  | 8    | long     | packetReadPos      | Current read position in packet buffer |
| 0x2E0  | 4    | int      | lastOpcode         | Last decoded opcode (for error reporting) |
| 0x2E4  | 4    | int      | totalBytesSent     | Cumulative bytes sent |
| 0x2E8  | 4    | int      | totalBytesReceived | Cumulative bytes received |

### Methods

#### `ServerConnection::OpenConnection(host, port)` -- `<addr in DB>`

Opens a TCP connection:
1. Deletes old primary and secondary ClientStreams
2. Formats `host:port` string
3. Allocates new ClientStream via shared_ptr (readBuf=1MB, writeBuf=10KB, buffered=true)
4. If connect fails, calls `CloseConnection`

#### `ServerConnection::ReadBytes(count)` -- `<addr in DB>`

Reads `count` bytes from the ClientStream into the packet buffer at `+0x2C0`. Resets the packet read position (`+0x2D8`). Returns a pointer to the Packet at `+0x2C0`.

#### `ServerConnection::GetBytesAvailable(count)` -- `<addr in DB>`

Checks if at least `count` bytes are available. First checks ClientStream's ring buffer count, then queries socket via `ioctl(FIONREAD)`. Returns true if enough data.

#### `ServerConnection::IsConnected` -- `<addr in DB>`

Returns true if ClientStream exists and `clientStream->state == 2` (connected).

#### `ServerConnection::FlushClientMessages` -- `<addr in DB>`

Sends all queued outgoing messages:
1. Iterates the message queue (linked list at +0x48)
2. Calls `ClientStream::Write` for each message's payload
3. Calls `ClientStream::Flush` after all messages sent
4. Recycles queue nodes to freelist (+0x58)
5. Decrements pending byte count

Returns true on success. Returns false (0) if the ClientStream is null or disconnected.

#### `ServerConnection::MakeClientMessage<ClientProt>(prot, ...)` -- `<addr in DB>`

Creates a new outgoing client message:
1. Acquires a mutex-protected message pool
2. Allocates a `TcpConnectionMessage` (0x58 bytes) from the pool
3. Calls `WriteOpcodeWithIsaac` to write the encrypted opcode
4. Sets up shared_ptr reference counting
5. Returns the message as a shared_ptr pair

#### `ServerConnection::SendClientMessage(message)` -- `<addr in DB>`

Enqueues a message onto the outgoing queue:
1. Gets a queue node from freelist or allocates new one
2. Stores the message's shared_ptr (with refcount increment)
3. Links the node at the tail of the doubly-linked list
4. Increments `pendingMessageCount` and `pendingByteCount`

#### `ServerConnection::CloseConnection` -- `<addr in DB>`

Closes the connection:
1. Calls `FlushClientMessages` first
2. Records last opcode for error reporting
3. Calls `ClientStream::Close` on the stream
4. Releases the ClientStream shared_ptr
5. Calls `ClearMessageQueue` to release pending messages
6. Resets all packet state fields

#### `ServerConnection::ClearMessageQueue` -- `<addr in DB>`

Iterates and releases all messages in the outgoing queue. Decrements shared_ptr refcounts, returns nodes to freelist or frees them.

### Opcode Decoding (in TcpIn)

The opcode decoding flow in `TcpIn` is:

1. Read 1 byte from ClientStream
2. If Isaac cipher is available:
   - XOR byte with `Isaac::TakeNextValue` to get decrypted opcode
   - If opcode >= 0x80 (high bit set), read another byte and combine: `(opcode - 0x80) * 256 + (byte2 XOR Isaac::TakeNextValue)`
3. If no Isaac cipher (pre-login):
   - Use `Packet::gSmart1or2` for variable-length opcode decoding
4. Look up ServerProt entry at `g_serverProtTable[opcode]`
5. Read payload size from the ServerProt entry (or variable: -1=1byte, -2=2byte)
6. Read the full payload
7. Dispatch to the ServerProt handler

---

## ConnectionManager

**Ghidra struct:** `ConnectionManager` (832 bytes, `/jag` category)
**Client offset:** `client + `<in Ghidra DB>` (engine: `OClient.CONNECTION_MANAGER`)

The ConnectionManager orchestrates the entire connection lifecycle.

### Struct Layout

| Offset | Size | Type               | Name                    | Description |
|--------|------|--------------------|-------------------------|-------------|
| 0x00   | 8    | void*              | vtable                  | Virtual function table pointer |
| 0x08   | 8    | Client*            | clientPtr               | Pointer to jag::Client that owns this |
| 0x10   | 8    | void*              | gameConnectionCtrlBlock | shared_ptr control block for game ServerConnection |
| 0x18   | 8    | void*              | gameConnection          | shared_ptr object ptr: game ServerConnection (LOGGED_IN) |
| 0x20   | 8    | void*              | loginConnectionCtrlBlock| shared_ptr control block for login ServerConnection |
| 0x28   | 8    | void*              | loginConnection         | shared_ptr object ptr: login ServerConnection |
| 0x30   | 4    | int                | gameKeepaliveCounter    | Ticks since last keepalive (game conn); resets at >50 |
| 0x38   | 8    | long               | timeoutDeadline         | Absolute timestamp (ms) for connection timeout; set to currentTime+20000 |
| 0x40   | 1    | bool               | timeoutFlag             | Set to 1 when connection has timed out |
| 0x41   | 1    | bool               | disconnectFlag          | Set when a disconnect has been detected; triggers HandleDisconnect |
| 0x44   | 4    | int                | disconnectProcessed     | Set to 1 after HandleDisconnect runs, prevents re-entry |
| 0x48   | 1    | bool               | yieldFlag               | Set when TcpIn handler returns 1 (yield) |
| 0x49   | 1    | bool               | reconnectNeeded         | Set in ChangeMainState for non-reconnect transitions |
| 0x4C   | 4    | int                | loginKeepaliveCounter   | Ticks since last keepalive (login conn); resets at >50 |
| 0x50   | 4    | int                | reconnectDelay          | Ticks to wait before reconnect (100=game, 101=login) |

### Methods

#### `ConnectionManager::TcpIn(packetStream)` -- `<addr in DB>`

Main TCP packet processing loop. Reads up to 100 packets per tick:

```
for (i = 0; i < 100; i++) {
    1. Check connection is alive
    2. If no current opcode:
       a. Read 1-2 bytes from ClientStream
       b. Decrypt via Isaac XOR
       c. Look up ServerProt table
       d. Get payload size type
    3. Read variable-size header if needed (-1 = 1byte, -2 = 2byte)
    4. Wait until full payload available
    5. Read payload into packet buffer
    6. Allocate TcpConnectionMessage from pool
    7. Dispatch to ServerProt handler
    8. Handle return codes (0=success, 1=yield, error=disconnect)
}
```

#### `ConnectionManager::MainLogic(timestamp)` -- `<addr in DB>`

Main connection lifecycle tick. The state machine at `+0x2a4` of the connection context:

| State | Name              | Description |
|-------|-------------------|-------------|
| 0     | INIT              | Initial state, send login data, write to ClientStream, flush |
| 1     | AWAIT_RESPONSE    | Waiting for server response byte |
| 2     | READ_XTEA_KEYS    | Reading XTEA key exchange data |
| 3     | CONNECTED         | Steady-state packet reading loop (up to 500 iterations) |

Also handles:
- Connection timeout (30 second deadline)
- HTTP request dispatching and response processing
- Bandwidth tracking

#### `ConnectionManager::ProcessConnections(doRead)` -- `<addr in DB>`

Per-tick connection processing:
1. Checks main state (0x14=LOGIN_STAGE_1, 0x17=LOGIN_STAGE_2, 0x1e=LOGGED_IN)
2. Calls `TcpIn` for the appropriate connection (game or login)
3. Sends NO_TIMEOUT keepalive every 50 ticks
4. Calls `FlushClientMessages`
5. On failure, calls `HandleDisconnect`

#### `ConnectionManager::GetActiveConnection` -- `<addr in DB>`

Returns the currently active ServerConnection:
- During login (states 0x14/0x17): returns login connection at +0x20
- When logged in: returns game connection at +0x10
- Returns global null ptr (<addr in DB>) if no active connection

#### `ConnectionManager::HandleDisconnect` -- `<addr in DB>`

Handles connection failure:
- If logged in (state 0x1e): closes game connection, transitions to state 0x23 (RECONNECT), delay=100 ticks
- If in login (0x14/0x17): closes login connection, transitions to state 10 (LOGIN_ERROR), delay=101 ticks

#### `ConnectionManager::ChangeMainState(oldState, newState)` -- `<addr in DB>`

Virtual callback invoked by `Client::SetMainState` when the main game state changes. Handles connection cleanup during state transitions:
- **TO state 10 (LOGIN_ERROR):** closes both login and game connections
- **TO state 0x14 (LOGIN_STAGE_1):** closes game connection
- **TO state 0x1E (LOGGED_IN):** closes login connection; if coming from RECONNECT (0x23), clears game connection's secondary Isaac/crypto state
- **Other transitions:** sets reconnectNeeded flag at +0x49

This is part of the Client subsystem observer pattern: `Client` maintains a vector of subsystem pointers at `client+`<in Ghidra DB>`, and `SetMainState` calls each subsystem's `ChangeMainState` via vtable+0x10.

#### `ConnectionManager::WriteOpcodeWithIsaac(packet, opcode, size, isaacPtr)` -- `<addr in DB>`

Writes an encrypted opcode to a packet buffer. Encrypts opcode bytes with Isaac cipher output. Handles both 1-byte (opcode < 128) and 2-byte (opcode >= 128) encodings.

#### `ConnectionManager::GenerateXteaKeyAndBuildRsaBlock(...)` -- `<addr in DB>`

Generates XTEA session keys and builds the RSA-encrypted login block during the login handshake.

#### `ConnectionManager::LoginProtocolHandler(...)` -- `<addr in DB>`

Large (~18KB) login protocol state machine. Handles the multi-step login handshake including credential exchange, XTEA key setup, RSA block building, and world connection establishment.

---

## Connection State Machine

The main state values (from `Client::SetMainState`):

| State | Hex  | Name            | Description |
|-------|------|-----------------|-------------|
| 0     | 0x00 | INITIAL         | Initial state, not connected |
| 10    | 0x0A | LOGIN_ERROR     | Login failed, waiting to retry |
| 20    | 0x14 | LOGIN_STAGE_1   | First login stage (login server) |
| 23    | 0x17 | LOGIN_STAGE_2   | Second login stage (world transfer) |
| 30    | 0x1E | LOGGED_IN       | Connected and playing |
| 35    | 0x23 | RECONNECT       | Connection lost, attempting reconnect |

---

## Message Pool

Outgoing messages are allocated from a pooled allocator:

- **`TcpMessagePool::Allocate`** (`<addr in DB>`) -- Allocates 0x58-byte TcpConnectionMessage objects from a pool of sub-pools
- **`ConnectionManager::ResizeMessagePool`** (`<addr in DB>`) -- Grows the pool when needed
- **`TcpConnectionMessage::Init`** (`<addr in DB>`) -- Initializes a message with opcode, size, and buffer

The pool uses a vector of sub-pools, each with:
- A flat array of 0x58-byte message slots
- An index-to-slot mapping array
- A slot-to-index mapping array (for O(1) allocation/deallocation)
- A count of allocated vs available entries

---

## Data Flow: Sending a Client Message

```
1. Game logic calls MakeClientMessage<ClientProt>(prot)
2. MakeClientMessage:
   a. Acquires mutex on global message pool
   b. Allocates TcpConnectionMessage from pool
   c. Calls WriteOpcodeWithIsaac to encrypt opcode into message
   d. Returns shared_ptr<TcpConnectionMessage>
3. Game logic calls SendClientMessage(message)
4. SendClientMessage enqueues message at tail of linked list
5. ProcessConnections calls FlushClientMessages
6. FlushClientMessages:
   a. Iterates queue, writes each message via ClientStream::Write
   b. Calls ClientStream::Flush to send buffered data
   c. Returns nodes to freelist
```

## Data Flow: Receiving a Server Message

```
1. ProcessConnections calls TcpIn(serverConnection)
2. TcpIn (up to 100 iterations):
   a. ClientStream::GetAvailable checks for data
   b. ClientStream::Read reads 1-2 opcode bytes
   c. Isaac::TakeNextValue decrypts opcode
   d. ServerProt table lookup for payload size
   e. ClientStream::Read reads payload
   f. Allocate TcpConnectionMessage from pool
   g. Dispatch to ServerProt handler vtable function
   h. Handler returns 0=success, 1=yield
3. On success: reset opcode, continue loop
4. On yield: pause loop until next tick
5. On error: close connection
```

## Global Data

| Address     | Name                | Description |
|-------------|---------------------|-------------|
| <addr in DB>  | g_serverProtTable   | Array of ServerProt entries (ptr per opcode, max 0xd9) |
| <addr in DB>  | (null connection)   | Global null ServerConnection sentinel |
| <addr in DB>  | (client msg pool)   | Global TcpConnectionMessage pool for ClientProt |
| <addr in DB>  | (server msg pool)   | Global TcpConnectionMessage pool for ServerProt |
| <addr in DB>  | g_lastIoctlResult   | Last ioctl(FIONREAD) result |
| <addr in DB>  | g_totalBytesRead    | Cumulative bytes read by ClientStream::Read |
| <addr in DB>  | g_readCallCount     | Number of ClientStream::Read calls |
| <addr in DB>  | g_totalSendTime     | Cumulative send time in microseconds |
| <addr in DB>  | g_totalBytesSent    | Cumulative bytes sent |
| <addr in DB>  | g_sendCallCount     | Number of send calls |

---

## Function Summary Table

| Address    | Name | Prototype |
|------------|------|-----------|
| <addr in DB> | `jag::ClientStream::ClientStream` | `void (void*, char*, int, int, int, int, bool)` |
| <addr in DB> | `jag::ClientStream::Connect` | `bool (void*, char*, void*, int, int)` |
| <addr in DB> | `jag::ClientStream::ConnectSocket` | `bool (void*, void*, int*, int, int)` |
| <addr in DB> | `jag::ClientStream::ResolveHostname` | `bool (void*, char*)` |
| <addr in DB> | `jag::ClientStream::Read` | `ulong (void*, void*, ulong)` |
| <addr in DB> | `jag::ClientStream::Write` | `ulong (void*, void*, ulong)` |
| <addr in DB> | `jag::ClientStream::Flush` | `ulong (void*)` |
| <addr in DB> | `jag::ClientStream::GetAvailable` | `long (void*)` |
| <addr in DB> | `jag::ClientStream::GetPing` | `int (void*)` |
| <addr in DB> | `jag::ClientStream::Close` | `bool (void*)` |
| <addr in DB> | `jag::game::ServerConnection::OpenConnection` | `void (void*, char*, ushort)` |
| <addr in DB> | `jag::game::ServerConnection::ReadBytes` | `long (void*, ulong)` |
| <addr in DB> | `jag::game::ServerConnection::GetBytesAvailable` | `bool (void*, ulong)` |
| <addr in DB> | `jag::game::ServerConnection::IsConnected` | `bool (void*)` |
| <addr in DB> | `jag::game::ServerConnection::FlushClientMessages` | `bool (void*)` |
| <addr in DB> | `jag::game::ServerConnection::MakeClientMessage<ClientProt>` | `void* (void*, void*, void*, void*)` |
| <addr in DB> | `jag::game::ServerConnection::SendClientMessage<ClientProt>` | `void (long, long*)` |
| <addr in DB> | `jag::game::ServerConnection::CloseConnection` | `void (void*)` |
| <addr in DB> | `jag::game::ServerConnection::ClearMessageQueue` | `void (void*)` |
| <addr in DB> | `jag::ConnectionManager::TcpIn` | `void (long, long)` |
| <addr in DB> | `jag::ConnectionManager::MainLogic` | `void (void*, ulong)` |
| <addr in DB> | `jag::ConnectionManager::ProcessConnections` | `void (void*, bool)` |
| <addr in DB> | `jag::ConnectionManager::GetActiveConnection` | `void* (void*)` |
| <addr in DB> | `jag::ConnectionManager::HandleDisconnect` | `void (void*)` |
| <addr in DB> | `jag::ConnectionManager::ChangeMainState` | `void (void*, MainState, MainState)` |
| <addr in DB> | `jag::ConnectionManager::WriteOpcodeWithIsaac` | (see crypto.md) |
| <addr in DB> | `jag::ConnectionManager::WriteOpcodeWithIsaac2` | (see crypto.md) |
| <addr in DB> | `jag::ConnectionManager::GenerateXteaKeyAndBuildRsaBlock` | (see crypto.md) |
| <addr in DB> | `jag::ConnectionManager::LoginProtocolHandler` | `void (void*)` |
| <addr in DB> | `jag::TcpMessagePool::Allocate` | `long (void*)` |
| <addr in DB> | `jag::TcpConnectionMessage::Init` | `void (void*, void*, int, long)` |
