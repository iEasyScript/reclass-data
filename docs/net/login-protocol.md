# Login Protocol - Complete State Machine

## Overview

The NXT client login is managed by `jag::LoginManager`, which implements a state machine with ~35 states (the `LoginStep` enum). The constructor at `<addr in DB>` registers handler functions for each step in a dispatch table. The `MainLogic` function (called from `jag::Client::MainLogic`) looks up the current step in this table and invokes the corresponding handler.

### Key LoginManager Fields (offsets from `this`)

| Offset | Type    | Name              | Description |
|--------|---------|-------------------|-------------|
| 0x10   | int     | currentStep       | Current LoginStep enum value |
| 0x14   | int     | savedStep         | Step to resume after handshake |
| 0x18   | long    | clientPtr         | Pointer to Client object |
| 0x20   | int     | loginMode         | 1=lobby, 2=game |
| 0x30   | long    | serverConnection  | ServerConnection pointer |
| 0x38   | bool    | isReconnect       | True if reconnecting |
| 0x40   | long    | sessionKey        | 8-byte session key from server |
| 0x48   | int[4]  | xteaKey           | 4-int XTEA key for encryption |
| 0x68   | long    | isaacPtr          | Isaac cipher for handshake |
| 0x70   | string  | username          | Login username |
| 0x88   | string  | password          | Login password |
| 0xA0   | string  | accountHash       | Account hash string |
| 0xB9   | bool    | hasAccountHash    | Flag from Init step |
| 0xBC   | int     | socialToken       | Social network token int |
| 0xC0   | int     | worldId           | World ID for session ID |
| 0xC4   | int     | reconnectAttempts | Counter for retry logic |
| 0xCC   | int     | reconnectCount    | Times reconnect was tried |
| 0xD0   | long    | pendingDataLen    | Length of pending data to read |
| 0xD8   | long    | urlLength         | URL data length |
| 0xE0   | int     | disallowCode      | Disallow reason code |
| 0xE4   | int     | tickRate          | Server tick rate |
| 0xE8   | uint    | hopBlockTime      | Hop block duration |
| 0xEC   | bool    | connected         | Connection active flag |
| 0xF0   | long    | sessionNonce1     | Session nonce part 1 |
| 0xF8   | long    | sessionNonce2     | Session nonce part 2 |
| 0x100  | int     | loginAttemptType  | 1=legacy RSA, 2+=social/SSO, 4=mobile token |
| 0x108  | long    | socialLoginState  | Social login state ptr |
| 0x110  | long    | socialLoginCtx    | Social login context ptr |
| 0x118  | bool    | requireSocialAuth | Requires social network auth |
| 0x11C  | int     | totpFlag          | TOTP flag (-1 if not set) |
| 0x120  | long    | loginToken        | Login token from server |
| 0x128  | long    | payloadLength     | Expected payload length |
| 0x130  | long    | sessionNonce      | Session nonce from RSA exchange |
| 0x138  | long    | sessionId         | Session ID |
| 0x140  | bool    | isSocialLogin     | True if social/SSO login |
| 0x148  | string  | tokenString       | OAuth/SSO token string |
| 0x160  | long    | reasonLength      | Reason message length |
| 0x16C  | int     | gameLoginResult   | LoginResult for game login |
| 0x170  | int     | queueWaitTime     | Queue wait time (ticks) |
| 0x174  | ushort  | disallowExtra     | Extra disallow info |
| 0x178  | uint    | disallowCount     | Disallow retry count |
| 0x17C  | uint    | totpDuration      | TOTP validity duration |
| 0x184  | int     | serverResponse    | Raw response code from server |
| 0x188  | int     | thirdResult       | Third response result code |
| 0x18C  | bool    | hasRefreshToken   | Has OAuth refresh token |
| 0x18D  | bool    | hasSessionToken   | Has session token |
| 0x190  | byte[8] | padding           | - |
| 0x198  | long[3] | varConfigBuffer   | Server client var config data |
| 0x1B0  | long    | varConfigPos      | Current position in var config |
| 0x1B8  | int     | lobbyLoginResult  | LoginResult for lobby login |
| 0x1C8  | long    | svrClientVarLen   | Server client var data length |
| 0x1D0  | int     | tempBannedLen     | Temp banned data length (-2 = read size first) |

---

## LoginStep Enum (all step IDs)

```c
enum LoginStep {
    IDLE                                 = 0,    // No active login
    INIT                                 = 10,   // Initialize login
    WAITING_LOGIN_CREDENTIALS            = 12,   // Waiting for user to enter creds (UI)
    WAITING_SSO_KEY                      = 13,   // SSO/OAuth token handling
    WAITING_CONNECTION_OPENED            = 14,   // Opening TCP connection
    WAITING_SSO_KEY_RESPONSE             = 15,   // Connection established, send request
    WAITING_FIRST_RESPONSE               = 30,   // Waiting for first server response
    WAITING_SECOND_RESPONSE              = 40,   // Reading payload size
    DEAL_WITH_SECOND_RESPONSE            = 50,   // XTEA decrypt + validate nonce
    WAITING_THIRD_RESPONSE               = 60,   // Waiting for go-ahead byte
    DEAL_WITH_THIRD_RESPONSE             = 70,   // XTEA decrypt login token
    SEND_LOGIN_PACKET                    = 80,   // Build and send full login packet
    WAITING_DISALLOW_RESULT              = 90,   // Read 1-byte login result
    WAITING_REASON_LENGTH                = 92,   // Read reason string length
    WAITING_REASON_DATA                  = 94,   // Read reason string data
    DEAL_WITH_FIRST_RESPONSE             = 96,   // Dispatch on login result code
    WAITING_SEND_CONTINUE                = 110,  // Send "continue" ack to server
    WAITING_IN_QUEUE                     = 120,  // Read queue position
    WAITING_PLAYERS_PACKET_RECONNECT     = 130,  // Reconnect player data
    WAITING_THIRD_REASON_LENGTH          = 132,  // Read third reason length
    WAITING_THIRD_REASON_DATA            = 134,  // Read third reason data
    DEAL_WITH_THIRD_RESULT               = 136,  // Handle third result code
    WAITING_LOGIN_CREDENTIALS_LENGTH     = 140,  // Read credentials response length
    HANDLE_LOGIN_DATA                    = 150,  // Read full login data (success!)
    WAITING_DISALLOW_RESULT_2            = 190,  // Secondary disallow handling
    WAITING_TEMP_BANNED                  = 200,  // Read temp ban packet
    WAITING_TOTP_PASSCODE                = 210,  // Read TOTP duration
    WAITING_URL_LENGTH                   = 220,  // Read URL length
    WAITING_URL                          = 230,  // Read URL (Isaac-decrypted)
    WAITING_HOP_BLOCK_TIME               = 240,  // Read hop block duration
    WAITING_SERVER_CLIENT_VAR_LENGTH     = 250,  // Read server var data length
    WAITING_SERVER_CLIENT_VAR_CONFIG_DATA= 260,  // Read server var config raw data
    WAITING_SERVER_CLIENT_VAR            = 270,  // Process server client vars
    START_RSA_PACKET                     = 280,  // Build legacy RSA login packet
    CHECK_LOADED                         = 290,  // Check JS5 archives loaded
    WAITING_REASON_LENGTH_2              = 300,  // Read additional reason length
    WAITING_SOCIAL_TOKEN_LENGTH          = 310,  // Read social token data length
};
```

---

## LoginResult Enum (server response codes)

```c
enum LoginResult {
    OK_EXCHANGE_DATA       = 0,   // Handshake OK, exchange session data
    DELAY_AND_RETRY        = 1,   // Server busy, retry with delay (-> step 100)
    OK_LOGIN_SUCCESS       = 2,   // Login successful (-> read login data)
    TOTP_REQUIRED          = 15,  // TOTP/2FA is required (-> step 200)
    WAITING_IN_QUEUE       = 21,  // Placed in login queue (-> step 120)
    CONNECTION_FAILED      = 22,  // Connection failed or timed out
    RECONNECT_TRY_AGAIN    = 23,  // Reconnect: retry up to 3 times
    DISALLOWED_1D          = 29,  // Disallowed response with extra data
    TOTP_ENTER_CODE        = 42,  // TOTP: enter code (-> step 210)
    DISALLOWED_2D          = 45,  // Disallowed with extra data
    RECONNECT_FAILED_49    = 49,  // Reconnect specific failure
    TEMP_BANNED            = 52,  // Temporarily banned (-> step 220 URL)
    HOP_BLOCKED            = 53,  // World-hop blocked (-> step 240)
    SHOW_URL               = 63,  // Server wants client to show a URL (-> step 300)
    LOGIN_ERROR_66         = 66,  // Error code 0x42 (-> error UI)
};
```

---

## Complete Login Flow

### Phase 1: Initialization

```
INIT (10)
  |-- Destroy old Isaac ciphers
  |-- Generate session ID from worldId
  |-- Set hasAccountHash flag
  +-> WAITING_SSO_KEY (13)
```

### Phase 2: Authentication Setup

```
WAITING_SSO_KEY (13)
  |-- loginAttemptType==1 (legacy): skip to WAITING_CONNECTION_OPENED
  |-- Social/SSO login:
  |     |-- Check OAuth tokens (access_token, refresh_token)
  |     |-- If tokens exist: validate via REST API
  |     |     |-- POST shield/oauth/check_token (with Bearer auth)
  |     |     +-- POST game-session/v1/tokens (with accountId)
  |     +-- Store validated token
  +-> CHECK_LOADED (290) or WAITING_CONNECTION_OPENED (14)
```

### Phase 3: Check JS5 Archives Loaded

```
CHECK_LOADED (290)
  |-- Check JS5 archive loading status (<in Ghidra DB> or social state)
  |-- If not loaded yet: wait (return 1)
  |-- If load error:
  |     |-- -4: set CONNECTION_FAILED, clean up
  |     +-- Other: set error result, clean up
  |-- 0x57F: special flag for d64 update
  |-- Store token string at +0x148
  |-- Set savedStep = SEND_LOGIN_PACKET (0x50)
  +-> WAITING_CONNECTION_OPENED (14)
```

### Phase 4: Connection + Handshake

```
WAITING_CONNECTION_OPENED (14)
  |-- Pick server address and port from world info
  |-- isWebSocket? use WS port : use direct port
  |-- Open TCP connection to server
  +-> WAITING_SSO_KEY_RESPONSE (15)

WAITING_SSO_KEY_RESPONSE (15)
  |-- Wait for connection status == 1 (established)
  |-- Build handshake request (LoginProt opcode via <in Ghidra DB>)
  |-- Flush to server
  +-> WAITING_FIRST_RESPONSE (30)
        or CONNECTION_FAILED (22) if flush fails
```

### Phase 5: Server Handshake Response

```
WAITING_FIRST_RESPONSE (30)
  |-- Read 9 bytes from server
  |-- First byte = response code
  |-- If response == 0:
  |     |-- Read 8-byte session key -> +0x40
  |     |-- If savedStep != 0: goto savedStep
  |     +-- Else: CONNECTION_FAILED (0x42)
  +-- If response != 0: set LoginResult to code, close connection

WAITING_SECOND_RESPONSE (40)
  |-- Read 2 bytes = ushort payload length -> +0x128
  +-> DEAL_WITH_SECOND_RESPONSE (50)

DEAL_WITH_SECOND_RESPONSE (50)
  |-- Read +0x128 bytes from server
  |-- XTEA decrypt using key at +0x48
  |-- Read string (server challenge/nonce)
  |-- Validate nonce
  +-> WAITING_THIRD_RESPONSE (60) or CONNECTION_FAILED

WAITING_THIRD_RESPONSE (60)
  |-- Read 1 byte from server
  |-- If byte == 1:
  +-> DEAL_WITH_THIRD_RESPONSE (70)

DEAL_WITH_THIRD_RESPONSE (70)
  |-- Read 16 bytes from server
  |-- XTEA decrypt into two 8-byte values
  |-- First long: login token -> +0x120
  |-- Second long: session nonce -> +0x130
  |-- If token < 0: RECONNECT_TRY_AGAIN (23)
  +-> SEND_LOGIN_PACKET (80)
```

### Phase 6: Send Login Packet

```
SEND_LOGIN_PACKET (80)
  |-- Check step == 0x50
  +-- Call SendLoginPacketInner
```

#### Start RSA Packet (step 280 - legacy direct login path)

```
START_RSA_PACKET (280)
  |-- Check step == 0x118
  |-- Build packet:
  |     +-- ushort: client version (0x3B2 = 946)
  |     +-- int: sub-version (1)
  |     +-- [optional] byte: TOTP flag (if loginMode==2)
  |     +-- GenerateXteaKeyAndBuildRsaBlock
  |     +-- Credential type byte:
  |     |     0x01/0x03: SSO token (3 bytes: account hash as medium)
  |     |     0x02: anonymous (4 zero bytes)
  |     |     0x00: social token (int: social token value)
  |     +-- byte: TOTP flag from +0x11C
  |     +-- byte: world flag
  |     +-- int: world settings
  |     +-- 5x int: Isaac random values (from handshake Isaac)
  |     +-- long: session nonce (+0x138)
  |     +-- byte: another world flag
  |     +-- byte: random padding byte
  |     +-- RSA encrypt the block
  |     +-- Prepend RSA block to packet
  |     +-- Write size header (ushort)
  |-- Flush to server
  +-> WAITING_SECOND_RESPONSE (40)
        or CONNECTION_FAILED on flush failure
```

#### SendLoginPacketInner (main login path)

```
Direction: Client -> Server
LoginProt: Lobby login (if loginMode==1) or Game login (if loginMode==2)

Packet format (for game login, loginMode==2):
  [Header]
    ushort: size marker (filled in later)

  [Pre-RSA data (if loginAttemptType != 1)]
    int: client version (0x3B2 = 946)
    int: sub-version (1)
    byte: TOTP flag
    [RSA Block - via CreateLoginRSAPacket]:
      GenerateXteaKeyAndBuildRsaBlock
      Credential type byte (0x01/0x02/0x03/0x00)
      Credential data (token or hash)
      rsaEncrypt
    [RSA block bytes written to main packet]
    byte: hasSessionToken flag (token == -1)
    If hasSessionToken:
      password string (pStringNoConversion)
    Else:
      long: login token (+0x120)

  [Login type byte]
    byte: 0x02 (WebSocket) or 0x03 (direct socket)

  [World info]
    ushort: screen width
    ushort: screen height

  [Flags]
    byte: display mode flag
    byte[24]: hardware/machine info (0x18 bytes)

  [Strings]
    string: client info string (hostname)
    int: platform/client settings

  [Machine info block]
    byte: machine info length
    byte[N]: machine info data

  [JS5 archive checksums]
    byte: 0x01 (marks continued data)
    byte[N]: more metadata
    byte: arch CRC count
    int[N]: JS5 archive CRCs (one per archive)

  [Client strings]
    string: client token string
    int: client build number
    string: another string
    byte: platform flag
    byte: client type

  [Social auth flag]
    byte: hasSocialAuth (boolean)

  [XTEA encryption]
    tinyKeyEncrypt(packet, xteaKey, startPos, endPos)

  [Size finalization]
    Seek to size marker position
    ushort: total payload size

  [Send]
    SendClientMessage<ClientProt>
    FlushClientMessages

  [Post-send]
    Isaac::Init(sendCipher, xteaKey)
    Isaac::Init(recvCipher, xteaKey + delta)
    Store ciphers at ServerConnection+0x40 and +0x2B8

  +-> WAITING_DISALLOW_RESULT (90)
```

### Phase 7: Login Result Processing

```
WAITING_DISALLOW_RESULT (90)
  |-- Read 1 byte = LoginResult code -> +0x184
  |-- For certain providers: intercept to WAITING_REASON_LENGTH
  +-> DEAL_WITH_FIRST_RESPONSE (96)

WAITING_REASON_LENGTH (92)
  |-- Read 1 byte = string length -> +0x190 (400)
  +-> WAITING_REASON_DATA (94)

WAITING_REASON_DATA (94)
  |-- Read N bytes = reason string
  |-- Log: "Game World Login Result: %d (%s)"
  +-> DEAL_WITH_FIRST_RESPONSE (96)

DEAL_WITH_FIRST_RESPONSE (96)
  |-- Switch on LoginResult (+0x184):
  |
  |-- result == 0x15 (21, QUEUE):
  |     +-> WAITING_IN_QUEUE (120)
  |
  |-- result == 1 (DELAY_RETRY):
  |     |-- Set LoginResult=1 in lobby/game result
  |     +-> step 100 (delay, wait, retry)
  |
  |-- result == 0x34 (52, TEMP_BANNED):
  |     |-- Store disallow code 0x34
  |     +-> WAITING_URL_LENGTH (220)
  |
  |-- result == 2 (SUCCESS):
  |     |-- If loginMode != 2 (not game):
  |     |     +-> WAITING_LOGIN_CREDENTIALS_LENGTH (140)
  |     |-- If game login:
  |     |     |-- If mainState==0x23: SetMainState(0x24)
  |     |     |-- Clear render queues, reset buffers
  |     |     +-> WAITING_SERVER_CLIENT_VAR_LENGTH (250)
  |
  |-- result == 0xF (15, TOTP_REQUIRED):
  |     |-- Set tempBannedLen = -2
  |     +-> WAITING_TEMP_BANNED (200)
  |
  |-- result == 0x17 (23, RECONNECT_TRY_AGAIN):
  |     |-- If reconnectCount < 3:
  |     |     |-- Reset to step 10, increment counter
  |     |     +-> Close connection, retry
  |     |-- Else: fall through to error
  |
  |-- result == 0x2A (42, TOTP_CODE):
  |     |-- Set LoginResult=0x2A
  |     +-> WAITING_TOTP_PASSCODE (210)
  |
  |-- result == 0x35 (53, HOP_BLOCKED):
  |     +-> WAITING_HOP_BLOCK_TIME (240)
  |
  |-- result == 0x3F (63, SHOW_URL):
  |     +-> WAITING_REASON_LENGTH_2 (300)
  |
  |-- result == 0x40 or 0x41: special providers check
  |     +-> Close connection, set LoginResult
  |
  |-- Other: set LoginResult, close connection
  +-- End
```

### Phase 8: Successful Login Data

```
WAITING_LOGIN_CREDENTIALS_LENGTH (140)
  |-- Read 1 byte = data length -> +0xD0
  |-- Reset reconnectAttempts
  +-> HANDLE_LOGIN_DATA (150)

HANDLE_LOGIN_DATA (150)
  Direction: Server -> Client
  |-- Read +0xD0 bytes from server
  |-- Create LoginState object (0xF0 bytes)
  |
  |-- For lobby login (loginMode==1):
  |     byte: has TOTP update flag (if 1, read TOTP data)
  |     byte: membership type (+0x08)
  |     byte: membership days remaining (+0x0C)
  |     bool: email validated (+0x10)
  |     3 bytes: recovery delay as medium (+0x14, signed 24-bit)
  |     byte: staff moderator flag (+0x88)
  |     bool: unknown flag (+0x19)
  |     bool: unknown flag (+0x1A)
  |     long: membership timestamp (+0x30)
  |     byte: unknown (+days remainder?)
  |     uint: time delta from system clock
  |     -> Compute session time offset at +0x90
  |     byte: flags byte (bit 0: +0x28, bit 1: +0x29)
  |     uint: unknown (+0x40)
  |     uint: unknown (+0x44)
  |     ushort: player index (+0x1C)
  |     ushort: unknown (+0x20)
  |     ushort: unknown (+0x60)
  |     uint: unknown (+0x64)
  |     byte: unknown (+0x24)
  |     ushort: unknown (+0x38)
  |     ushort: unknown (+0x3C)
  |     bool: is members world (+0x18)
  |     string: display name (at +0x68)
  |     byte: unknown (+0x84)
  |     uint: unknown (+0x80)
  |     ushort: world ID (0xFFFF means -1)
  |     string: server info string
  |     ushort: screen width
  |     ushort: screen height
  |     long: session nonce 1 -> +0xF0
  |     long: session nonce 2 -> +0xF8
  |
  |-- For game login (loginMode==2):
  |     byte: has TOTP update flag
  |     byte: membership type (+0x08)
  |     byte: membership days (+0x0C)
  |     bool: email validated (+0x10)
  |     bool: unknown (+0x19)
  |     bool: unknown (+0x1A)
  |     bool: display name set flag (-> plVar16+1)
  |     ushort: unknown (+0x48)
  |     bool: is members (+0x28)
  |     3 bytes: recovery delay medium (+0x14)
  |     bool: HD flag (-> toggle HD in ConfigProvider)
  |     string: player display name
  |     ushort: unknown
  |     uint: time value
  |     -> Compute session time at +0x90
  |     long: session nonce 1 -> +0xF0
  |     long: session nonce 2 -> +0xF8
  |
  |-- Post-read common:
  |     Store LoginState in Client
  |     Reset stat table, clear inventory caches
  |     Set tick rate
  |     If session nonce changed: clear Js5 disk cache
  |     Set MainState to 0x1E (LOGGED_IN) or 0x14 (LOBBY)
  +-- Login complete!
```

### Phase 9: Special Result Handling

#### Queue Waiting
```
WAITING_IN_QUEUE (120)
  |-- Read 1 byte = queue position
  |-- Multiply by client tick rate -> wait time at +0x170
  |-- Set LoginResult = 0x15 (WAITING_IN_QUEUE)
  |-- Close connection
  +-- End (UI shows "You are in a queue")
```

#### TOTP Authentication
```
WAITING_TOTP_PASSCODE (210)
  |-- Read 2 bytes = ushort TOTP duration -> +0x17C
  +-> WAITING_DISALLOW_RESULT (90)
      (server checks the TOTP code and sends result)
```

#### Temp Ban / Hop Block
```
WAITING_TEMP_BANNED (200)
  |-- tempBannedLen == -2: read 2 bytes for actual length
  |-- Read N bytes = ban details packet
  |-- Set LoginResult = 0xF (TOTP_REQUIRED)
  |-- Set MainState to 0x1E
  |-- Process ban data
  +-- End

WAITING_HOP_BLOCK_TIME (240)
  |-- Read 4 bytes = uint hop block duration -> +0xE8
  |-- Set LoginResult = 0x35 (HOP_BLOCKED)
  |-- Close connection
  +-- End
```

#### URL Display
```
WAITING_URL_LENGTH (220) [also step for TEMP_BANNED initial]
  |-- Read 2 bytes = ushort URL data length -> +0xD8
  +-> WAITING_URL (230)

WAITING_URL (230)
  |-- Read +0xD8 bytes from server
  |-- Isaac-decrypt each byte (subtract Isaac random value)
  |-- CP1252 -> UTF8 convert the URL string
  |-- Store decoded URL
  |-- For lobby logins with world type != 0x1E:
  |     +-> WAITING_DISALLOW_RESULT (90) (continue protocol)
  |-- Otherwise: close connection
  +-- End
```

#### Server Client Vars
```
WAITING_SERVER_CLIENT_VAR_LENGTH (250)
  |-- Read 2 bytes = ushort length -> +0x1C8
  +-> WAITING_SERVER_CLIENT_VAR_CONFIG_DATA (260)

WAITING_SERVER_CLIENT_VAR_CONFIG_DATA (260)
  |-- Read +0x1C8 bytes = raw config data
  |-- Store buffer at +0x1A0/0x1A8/0x1B0
  +-> WAITING_SERVER_CLIENT_VAR (270)

WAITING_SERVER_CLIENT_VAR (270)
  |-- Set config progress = position + 2
  |-- For each 2-byte var ID in the buffer:
  |     |-- Read ushort var type ID
  |     |-- Look up VarType via ConfigProvider
  |     |-- Set the client var value
  |-- If first byte == 0x01 (has more):
  |     |-- Send "continue" ack to server
  |     +-> WAITING_PLAYERS_PACKET_RECONNECT (130)
  |-- Else (no more vars):
  |     +-> WAITING_SERVER_CLIENT_VAR_LENGTH (250)
```

#### Reconnect Player Data
```
WAITING_PLAYERS_PACKET_RECONNECT (130)
  |-- Read 1 byte = third result code -> +0x188
  |-- For certain providers with result != 2: intercept
  |     +-> WAITING_THIRD_REASON_LENGTH (132)
  |-- Otherwise:
  +-> DEAL_WITH_THIRD_RESULT (136)

WAITING_THIRD_REASON_LENGTH (132)
  |-- Read 1 byte = reason length -> +0x190
  +-> WAITING_THIRD_REASON_DATA (134)

WAITING_THIRD_REASON_DATA (134)
  |-- Read N bytes = reason string
  |-- Log: "Login Result: %d (%s)"
  +-> DEAL_WITH_THIRD_RESULT (136)

DEAL_WITH_THIRD_RESULT (136)
  |-- Check result code (+0x188):
  |-- 0x1D (29) or 0x2D (45): disallowed
  |     +-> WAITING_DISALLOW_RESULT_2 (190)
  |-- 2: success
  |     +-> WAITING_LOGIN_CREDENTIALS_LENGTH (140)
  |-- Other: close connection, set LoginResult
  +-- End
```

#### Send Continue
```
WAITING_SEND_CONTINUE (110)
  |-- Build "continue" packet (LoginProt opcode via <in Ghidra DB>)
  |-- Flush to server
  +-> WAITING_DISALLOW_RESULT (90)
        or CONNECTION_FAILED
```

---

## RSA Block Format

Built by `GenerateXteaKeyAndBuildRsaBlock` (<addr in DB>):

```
[RSA Block - encrypted with server's RSA public key]
  byte:    0x0A (magic marker)
  int[4]:  XTEA key (4 random ints, stored at LoginManager+0x48)
  long:    session ID
  ...additional handshake data...
```

RSA public key stored at globals:
- Modulus: `<in Ghidra DB>`
- Exponent: `<in Ghidra DB>`

## XTEA Encryption

Used to encrypt the login credentials section after the RSA block:

```
tinyKeyEncrypt(packet, xteaKey, startOffset, endOffset)
```

- Key: 4 ints at LoginManager+0x48 (generated in RSA block)
- Delta: 0x9E3779B9 (standard XTEA)
- 32 rounds per block

## Isaac Cipher

After successful login (step 80), two Isaac ciphers are initialized:

```
Send cipher: Isaac::Init(xteaKey[0..3])
Recv cipher: Isaac::Init(xteaKey[0..3] + <in Ghidra DB> delta)
```

The delta values at `<in Ghidra DB>` are added to each XTEA key int for the receive cipher, creating an asymmetric pair. These are stored at:
- `ServerConnection+0x40` = send cipher
- `ServerConnection+0x2B8` = receive cipher

---

## Complete State Transition Diagram

```
                  +---------+
                  |  IDLE   |
                  |  (0)    |
                  +----+----+
                       |
                  StartLogin
                       |
                  +----v----+
                  |  INIT   |
                  |  (10)   |
                  +----+----+
                       |
              +--------v--------+
              | WAITING_SSO_KEY |
              |      (13)       |
              +---+----+--------+
                  |    |
       legacy    |    |  social/SSO
                  |    |
                  |    +---> CHECK_LOADED (290) --+
                  |                               |
                  v                               v
          +-------+--------+          +-----------+---------+
          | WAITING_CONN   |<---------+                     |
          | OPENED (14)    |                                |
          +-------+--------+                                |
                  |                                         |
                  v                                         |
          +-------+--------+                                |
          | WAITING_SSO    |                                |
          | KEY_RESP (15)  |                                |
          +-------+--------+                                |
                  |                                         |
                  v                                         |
          +-------+--------+                                |
          | WAITING_FIRST  |                                |
          | RESPONSE (30)  |                                |
          +-------+--------+                                |
                  |                                         |
            result==0                                       |
                  |                                         |
                  v                        savedStep==0x50  |
          +-------+--------+              +--------+--------+
          | WAITING_SECOND |              | SEND_LOGIN      |
          | RESPONSE (40)  |              | PACKET (80)     |
          +-------+--------+              +--------+--------+
                  |                                |
                  v                                v
          +-------+--------+              +--------+--------+
          | DEAL_W_SECOND  |              | WAITING_DISALLOW|
          | RESPONSE (50)  |              | RESULT (90)     |
          +-------+--------+              +--------+--------+
                  |                                |
                  v                                v
          +-------+--------+              +--------+--------+
          | WAITING_THIRD  |              | DEAL_W_FIRST    |
          | RESPONSE (60)  |              | RESPONSE (96)   |
          +-------+--------+              +--------+--------+
                  |                                |
                  v                    +-----------+-----------+
          +-------+--------+          |           |           |
          | DEAL_W_THIRD   |     result==2   result==21  result==other
          | RESPONSE (70)  |          |           |           |
          +-------+--------+          v           v           v
                  |            +------+--+  +-----+---+  [Error/Close]
                  +----------->| LOGIN   |  | QUEUE   |
                               | DATA    |  | (120)   |
                               | (150)   |  +---------+
                               +---------+
                               SUCCESS!
```

---

## Function Address Reference

| Address    | Function Name |
|------------|--------------|
| <addr in DB> | jag::LoginManager::LoginManager (constructor) |
| <addr in DB> | jag::LoginManager::LoginStepInit |
| <addr in DB> | jag::LoginManager::LoginStepWaitingSSOKey |
| <addr in DB> | jag::LoginManager::LoginStepWaitingConnectionOpened |
| <addr in DB> | jag::LoginManager::LoginStepWaitingSSOKeyResponse |
| <addr in DB> | jag::LoginManager::LoginStepWaitingFirstResponse |
| <addr in DB> | jag::LoginManager::LoginStepWaitingSecondResponse |
| <addr in DB> | jag::LoginManager::LoginStepDealWithSecondResponse |
| <addr in DB> | jag::LoginManager::LoginStepWaitingThirdResponse |
| <addr in DB> | jag::LoginManager::LoginStepDealWithThirdResponse |
| <addr in DB> | jag::LoginManager::LoginStepSendLoginPacket |
| <addr in DB> | jag::LoginManager::SendLoginPacketInner |
| <addr in DB> | jag::LoginManager::LoginStepWaitingDisallowResult |
| <addr in DB> | jag::LoginManager::LoginStepWaitingReasonLength |
| <addr in DB> | jag::LoginManager::LoginStepDealWithFirstResponse |
| <addr in DB> | jag::LoginManager::LoginStepWaitingSendContinue |
| <addr in DB> | jag::LoginManager::LoginStepWaitingInQueue |
| <addr in DB> | jag::LoginManager::LoginStepWaitingPlayersPacketReconnect |
| <addr in DB> | jag::LoginManager::LoginStepWaitingThirdReasonLength |
| <addr in DB> | jag::LoginManager::LoginStepDealWithThirdResult |
| <addr in DB> | jag::LoginManager::LoginStepWaitingLoginCredentialsLength |
| <addr in DB> | jag::LoginManager::LoginStepHandleLoginData |
| <addr in DB> | jag::LoginManager::LoginStepWaitingDisallowResult2 |
| <addr in DB> | jag::LoginManager::LoginStepWaitingTempBanned |
| <addr in DB> | jag::LoginManager::LoginStepWaitingForTOTPPassCode |
| <addr in DB> | jag::LoginManager::LoginStepWaitingHopBlockTime |
| <addr in DB> | jag::LoginManager::LoginStepWaitingURLLength |
| <addr in DB> | jag::LoginManager::LoginStepWaitingURL |
| <addr in DB> | jag::LoginManager::LoginStepWaitingServerClientVarLength |
| <addr in DB> | jag::LoginManager::LoginStepWaitingServerClientVarConfigData |
| <addr in DB> | jag::LoginManager::LoginStepWaitingServerClientVar |
| <addr in DB> | jag::LoginManager::StartRSAPacket |
| <addr in DB> | jag::LoginManager::CreateLoginRSAPacket |
| <addr in DB> | jag::LoginManager::CheckLoaded |
| <addr in DB> | jag::LoginManager::LoginStepWaitingReasonLength2 |
| <addr in DB> | jag::LoginManager::LoginStepWaitingSocialNetworkTokenLength |
| <addr in DB> | jag::LoginManager::LoginStepWaitingSocialNetworkToken |
| <addr in DB> | jag::ConnectionManager::GenerateXteaKeyAndBuildRsaBlock |
| <addr in DB> | jag::Packet::rsaEncrypt |
| <addr in DB> | jag::Packet::tinyKeyEncrypt |
| <addr in DB> | jag::Isaac::Init |

---

## LoginProt Opcodes

The login protocol uses specific opcodes for different packet types, stored as global data references:

| Global Reference | Purpose | Used In |
|-----------------|---------|---------|
| <in Ghidra DB>    | Handshake request (initial connection) | LoginStepWaitingSSOKeyResponse |
| <in Ghidra DB>    | Legacy login packet (StartRSAPacket) | StartRSAPacket |
| <in Ghidra DB>    | Continue/ack packet | LoginStepWaitingSendContinue |
| <in Ghidra DB>    | Lobby login (loginMode==1, type 1) | SendLoginPacketInner |
| <in Ghidra DB>    | Game login (non-reconnect) | SendLoginPacketInner |
| <in Ghidra DB>    | Game reconnect login | SendLoginPacketInner |
| <in Ghidra DB>    | Social network token login | LoginStepWaitingSocialNetworkToken |

---

## SSO / OAuth Flow

The client supports OAuth-based login via Jagex accounts:

1. **Token globals:**
   - `<in Ghidra DB>` = Access token
   - `<in Ghidra DB>` = Refresh token
   - `<in Ghidra DB>` = Session ID
   - `<in Ghidra DB>` = Character/Account ID
   - `<in Ghidra DB>` = Token expiry timestamp
   - `<in Ghidra DB>` = HTTP request object
   - `<in Ghidra DB>` = HTTP request state

2. **Token validation:**
   - Endpoint: `shield/oauth/check_token` (POST, form-encoded with `token=<access_token>`)
   - Endpoint: `game-session/v1/tokens` (POST, JSON with `accountId`, Bearer auth)

3. **Environment variables (checked in constructor):**
   - `JX_DISPLAY_NAME` = Pre-populated display name
   - `JX_ACCESS_TOKEN` = OAuth access token
   - `JX_REFRESH_TOKEN` = OAuth refresh token
   - `JX_SESSION_ID` = Session ID
   - `JX_CHARACTER_ID` = Character/account ID

---

## Reconnect Flow

When the client loses connection:

1. `Reconnect` is called, which sets `isReconnect=true` and restarts from INIT
2. The login mode stays as 2 (game)
3. `loginAttemptType` remains unchanged
4. On RECONNECT_TRY_AGAIN (result 23): automatically retries up to 3 times
5. The reconnect login packet uses a different LoginProt opcode (<in Ghidra DB> instead of <in Ghidra DB>)
6. After successful reconnect, server client vars are re-exchanged via steps 250-270

---

## Client Version

The client version sent in login packets:
- `int: 0x3B2` (946 decimal)
- `int: 1` (sub-version)
