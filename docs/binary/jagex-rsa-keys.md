# Jagex RSA Public Keys (rs2client rev 946)

Extracted from: `data/client/rs2client` (ELF64, unpatched)
Init function: `<in Ghidra DB>` (`.init_array` constructor)
Source: ghidra-reverse-engineer agent via Ghidra MCP (port 8080)

---

## 1. Login RSA Key (1024-bit)

| Property | Value |
|----------|-------|
| Modulus global | `<in Ghidra DB>` |
| Exponent global | `<in Ghidra DB>` |
| String address | `<addr in DB>` |
| Format | Lowercase hex ASCII, null-terminated |
| Length | 256 hex characters (1024 bits) |
| Public exponent | `10001` (hex) = 65537 |
| Base | 16 (hex) |

### Modulus (hex)

```
9cbc5f910c473c629a26baf5f9a1d01d4b8aadc6480518d3fe8659e4b09cbe90e104147c47e7df58da3891358777ff6d3a4dbb8940b1d844592b40f45a975590028c0b480f82ac6a52b47ce63b8154e56aa8164a81063a95df25f07882ffdfeb1eb91c4a0d03dd0537c933065080b90436c1376cfa8c3fdebf2e747142579069
```

### Usage

Referenced by:
- `jag::LoginManager::StartRSAPacket` at `<addr in DB>`
- `jag::LoginManager::CreateLoginRSAPacket` at `<addr in DB>`
- `jag::LoginManager::LoginStepWaitingSocialNetworkToken` at `<addr in DB>`

Used for RSA encryption of the login block (ISAAC seeds, XTEA key, credentials).

---

## 2. JS5 Master Index RSA Key (4096-bit)

| Property | Value |
|----------|-------|
| Modulus global | `<in Ghidra DB>` |
| Exponent global | `<in Ghidra DB>` |
| String address | `<addr in DB>` |
| Format | Lowercase hex ASCII, null-terminated |
| Length | 1024 hex characters (4096 bits) |
| Public exponent | `10001` (hex) = 65537 |
| Base | 16 (hex) |

### Modulus (hex)

```
e9b6a139afb361a6438c46cdade9e7ae160dcda18e2a3c6eb549b870dceaf74c
39bbedfcbd6cbb1432f611c296d7fe53d4ab2eb8a73ca6ce6a58e4b003b1ec3e
1eabd2880ee7efed98f6a064bd48cf7b24de32418df839f09de4c80072af7f8b
cc0ad00e61e48b69ae53491c3103d86ee2ffca1256628df84c07aee33e6f8a76
ca12e8ff15111b6a6fb521e0e81f38faa9d2a49543189b0c46d767cbb3a83bf3
0c8e00cb4cf9f26691898f75af62b97783e34c9ac15750ab4b5eccf18b324c11
cdbfca3fe6719176452b25bedb1677f4db6b4b57b3b9d889b1ea2f3953290ab6
ae3be47b03ddbcc4f79bfbcbf35c7e3c995ad05bbbc39938515a2e2b1723871a
60179218af51c8d48a7ec6652363d54724cd685680f805596ca39bd620e3c1b6
f51819ba2fa4238429e914a0c3cb3414769ae20bf1d2bf17d43031d79ab0a2d4
094476f0f925b78d692c4be3b60bdc95dd836c18da12043380fdaa715cb0c1c4
b259365985243c61ceebf7a0747c1b8eab5b0687280173752d2447c51c33a76a
139555f552bb6a61ccbd6addbb39a7dd60c2abdd7bac061581d3b2697b06d969
3bf002d1a41dac815b5be745b75f56b514b8edd6b140bfe2f178b114feb49f53
9e0bdb9af65ef6ecc19a49f5b90faed0d9b76c247c02747236ad70ebd39257fa
eea76ad6a4d381a9d631149dd34a04814367adfc1e6d2e7c572d3feb5237d74b
```

### Usage

Referenced by:
- `jag::Js5WorkerThread::Js5WorkerThread` at `<addr in DB>` and `<addr in DB>`

Used for RSA verification of the JS5 master index (version table) Whirlpool hash signature.

---

## 3. Unknown 512-bit Key

| Property | Value |
|----------|-------|
| Modulus global | `<in Ghidra DB>` |
| Exponent global | `<in Ghidra DB>` |
| Exponent | `10001` (hex) = 65537 |
| Base | 16 (hex) |

### Modulus (hex)

```
ccd229d98f18b41132806b86674a4149a0fd48f534b2cf421587603087f72643c393cd54e3e55994bb6828e2693e5af6b95a56b9e5cf92fc7520ef28baa6b6b7
```

Not referenced outside the init function. Likely legacy/unused.

---

## 4. Decimal-format Key (Unknown purpose)

| Property | Value |
|----------|-------|
| Modulus global | `<in Ghidra DB>` |
| Exponent global | `<in Ghidra DB>` |
| Base | 10 (decimal) |

### Values (decimal)

- Exponent: `80782894952180643741752986186714059433953886149239752893425047584684715842049`
- Modulus: `7237300117305667488707183861728052766358166655052137727439795191253340127955075499635575104901523446809299097934591732635674173519120047404024393881551683`

Referenced by `<in Ghidra DB>` (LoginStepSendLoginPacket). Non-standard exponent suggests a different cryptographic purpose.
