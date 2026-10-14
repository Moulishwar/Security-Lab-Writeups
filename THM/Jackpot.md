# TryHackMe: Jackpot

**Category:** Black-box network protocol exploitation / reverse engineering
**Difficulty:** Medium

## Scenario

A branch ATM at "Earth's National Bank" (Terminal 004) was pulled off the network for forensic review after a string of unexplained cash-outs. Its maintenance interface, only meant to be reachable from the branch LAN, was left exposed with no meaningful authentication. The cash dispenser doesn't care about cards, PINs, or transactions, it only responds to something that speaks its protocol correctly. The goal: get the machine to empty every cassette with no card and no PIN.

## Recon

```
sudo nmap -sS -sV -sC <target>
```

Three ports were open:

| Port | Service | Role |
|---|---|---|
| 22 | OpenSSH | Not used in this path |
| 8080 | Python `BaseHTTPServer` | "Engineering Console" web UI, the front door |
| 9100 | nmap guessed `jetdirect?` | The ATM's actual command protocol, not a printer |

The port 8080 console displayed a live simulated ATM screen with a rotating 6-digit session code, the current cassette/vault state (denominations, counts), supervisor mode and fraud monitor status, and a download link for a field-service binary named `jackpot`.

## Binary analysis

```
file jackpot
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped
```

Stripping removes the symbol table, not string literals. Running `strings` against the binary surfaced:

```
ENBANK
[*] session nonce : %s
[*] activation code: %08u
usage: %s <6-digit session code from ATM screen>
```

This revealed the tool's job: take the 6-digit session code currently shown on the ATM screen and derive an 8-digit supervisor activation code from it. Crucially, this derivation is public and keyless, the algorithm ships entirely inside the client tool with no server-side secret, so anyone who downloads the tool can compute a valid activation code for any session they can observe.

```
chmod +x jackpot
./jackpot 197745
# [*] session nonce : 197745
# [*] activation code: 93161232
```

## Protocol reversing (port 9100)

Connecting directly with `nc` returned a JSON banner that documented the entire wire format, unusually generous for a black-box challenge, and even pointed at the exact next command to run:

```json
{
  "service": "Branch Engineering Gateway",
  "protocol": "XFS bridge",
  "request_format": "1 byte msg_type + 4 byte big-endian command id + 2 byte big-endian length + <length> bytes of data",
  "reply_format": "2 byte big-endian length + <length> bytes of JSON",
  "msg_types": {"GETINFO": "0x01", "EXECUTE": "0x02"},
  "hint": "query command 0x0304 (WFS_INF_CDM_CAPABILITIES) with msg_type GETINFO for the full command table"
}
```

A small Python client (`socket` + `struct`) was enough to speak this framing. Querying `0x0304` returned the full command table:

| Command | ID | Type |
|---|---|---|
| `WFS_INF_CDM_STATUS` | `0x301` | GETINFO |
| `WFS_INF_CDM_CASH_UNIT_INFO` | `0x303` | GETINFO |
| `WFS_INF_CDM_CAPABILITIES` | `0x304` | GETINFO |
| `WFS_CMD_CDM_DISPENSE` | `0x401` | EXECUTE |
| `WFS_CMD_CDM_ARM` | `0x4f0` | EXECUTE |
| `WFS_CMD_CDM_SET_MONITOR` | `0x4f1` | EXECUTE |
| `WFS_CMD_CDM_GET_FLAG` | `0x4ff` | EXECUTE |

The key discovery, found the hard way by iterating on the server's error messages: the server never parses JSON in *requests*. The banner only promises the reply is JSON, request payloads are always raw ASCII bytes. Sending JSON objects as request data produced confusing "anomalous"/"null" errors that looked like business-logic rejections but were really just parsing mismatches.

## Attack chain

1. **ARM** (`EXECUTE 0x4f0`): payload is the raw ASCII activation code (e.g. `93161232`). Enters supervisor mode with no card or PIN.
2. **SET_MONITOR** (`EXECUTE 0x4f1`): payload is the bare string `off`, no JSON, no label. Disables the fraud-detection watchdog.
3. **DISPENSE** (`EXECUTE 0x401`), looped: payload is the note count as raw ASCII digits (e.g. `40`). The vault holds 280 notes total, capped at 40 per call, so this takes 7 calls to fully drain.
4. **GET_FLAG** (`EXECUTE 0x4ff`): empty payload. `remaining_notes == 0` is treated as proof of a completed cashout, and the flag is released.

Session codes and the activation codes derived from them rotate quickly, so the sequence had to be re-armed with a freshly generated activation code more than once when the session drifted mid-exploit.

## Key takeaways

- Unauthenticated "engineering" protocols on nonstandard ports are a classic soft underbelly, here a raw TCP bridge controlling a physical cash dispenser with zero auth or encryption.
- A public, keyless derivation is not a secret. If the activation-code algorithm ships inside a client-side tool, anyone can compute valid codes offline for any session they can observe. This is security theater, not authentication.
- Stripping a binary removes symbols, not strings. Running `strings` on a stripped ELF is still worth doing first; usage text and format strings routinely survive and reveal intent.
- Don't assume every payload is JSON just because responses are. This protocol's banner only promised JSON *replies*, request payloads were raw ASCII. That mismatch cost real time until the actual wire format was confirmed against a primary source.
- "Proof of cashout" here was just an internal state check (`remaining_notes == 0`), not independent transaction verification, a good example of trusting client-driven state over real validation.

<details>
<summary>Flag</summary>

`THM{n0_card_n0_pin_just_the_wr0ng_v0ice_speaking_XFS}`

</details>
