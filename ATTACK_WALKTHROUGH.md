# IBOH Game 2 attack walkthrough

This documents the previously used techniques for the authorized IBOH::CTF Attack & Defense game. Use only the current game roster returned by the official Targets endpoint, and attack only listed teams whose status is `Ok`. The exploit scripts are single-target unless explicitly noted. They do not patch or persist changes on opponent services.

## 1. Prepare access

You need Python 3, the current Game 2 A&D API token, and the event WireGuard profile active. Keep the token out of scripts and shell history. For manual API calls, load it without echoing it:

```sh
read -r -s AD_API_TOKEN
export AD_API_TOKEN
```

Fetch the live roster each round; addresses can change after a reset:

```sh
curl -sS https://warzone.battleofhackers.com/api/Game/2/Ad/Targets \
  -H "Authorization: Bearer $AD_API_TOKEN" > /tmp/ad-targets.json

jq '.currentRound, (.challenges[] | {title, challengeId, tickSeconds,
  teams: [.teams[] | select(.lastCheckStatus == "Ok") | {teamName, ip, port}]})' \
  /tmp/ad-targets.json
```

Before running a single-target PoC, verify that the target route uses the WireGuard interface:

```sh
ip route get TARGET_IP
```

If it routes through the ordinary LAN interface or times out, stop and repair connectivity before trying exploits. Do not broaden the target list beyond the official response.

## 2. Web — Rusty Day (TCP 8080)

Saved PoC: [`web_rusty_day.py`](web_rusty_day.py).

```sh
python3 web_rusty_day.py TARGET_IP --port 8080
```

The preview API accepts a URL and fetches it server-side. The PoC asks the target's own web process for `http://127.0.0.1:8080/internal/read?path=/flag`. Because `127.0.0.1` is evaluated from the target container, the request reaches its loopback-only flag reader. The script URL-encodes the parameter, reads the preview response, and prints a matching `[REDACTED_FLAG]` value. It does not submit the flag.

The multi-target Web run used this same request only against healthy Rusty Day entries from the current roster. In the recorded batches, the per-target request returned the current flag and the official Submit API accepted it.

## 3. Crypto — “ok, noted.” (TCP 20561)

Saved PoC: [`crypto_ok_noted.py`](crypto_ok_noted.py).

```sh
python3 crypto_ok_noted.py TARGET_IP --port 20561
```

The exploit has two stages:

1. It uses the `legacy` service as a tag oracle on two related messages. The service's MAC construction permits a length-extension-style forgery, producing a notary token that the next service accepts.
2. It presents that token to `cosign`, parses the secp256k1 commitments, then exploits the verifier's degenerate-point handling. The implementation compares points using an x-coordinate-only equality condition. Crafted points with `x = 0` can therefore satisfy checks that should require full curve-point equality. This lets the PoC submit a false proof and controlled signing shares, after which it reads the flag from the service response.

The script retries a bounded number of fresh sessions when the random commitments do not fit the degenerate construction. It prints the captured flag but does not submit it. The older `/tmp/exploit_ok_noted_standalone.py` is not the recommended copy: it contains a stale token in a submission helper. Use the maintained single-target script above and submit with a current token.

## 4. Pwn — SupportConsole (TCP 9090)

Single-target PoC: [`pwn_supportconsole.py`](pwn_supportconsole.py). The roster-aware runner is [`exploit_supportconsole_roster.py`](exploit_supportconsole_roster.py).

Single target:

```sh
python3 pwn_supportconsole.py TARGET_IP --port 9090
```

The service reads a ticket reference into a stack buffer without enforcing its size. The saved return address is 88 bytes from the start of the input. The PoC selects menu option 1, waits for the ticket prompt, sends 88 filler bytes, then overwrites the saved return address with the challenge's fixed return gadget and the address of its flag-dump routine. The service prints the flag as `FLAG=...`.

The integrated runner discovers healthy Pwn targets from the official API, caps concurrency at four workers, collects flags, and submits the batch. It prompts for the token with a hidden input if `AD_API_TOKEN` is unset:

```sh
python3 exploit_supportconsole_roster.py --workers 4 --timeout 4
```

## 5. Reverse — reverse-my-connection-ad-reverse (TCP 7777)

Available helper: [`reverse_mac_oracle.py`](reverse_mac_oracle.py). This is **not a complete network PoC**.

The saved helper runs the supplied `sphostd` binary under GDB and calls its `crypto_mac` function on a 16-byte challenge nonce. The historical network driver used that result to authenticate a framed control-protocol response, changed the challenge session's command to read `/flag`, read the result, then restored and verified the original command setting.

The full `admin_reverse_round.py` driver lived in the challenge container's temporary filesystem and was not recovered. The saved files do not preserve its frame encoding or exact command sequence, so this walkthrough does not invent those missing steps. The MAC helper can be run independently as:

```sh
python3 reverse_mac_oracle.py \
  NONCE_AS_32_HEX_CHARS --binary PATH_TO_SPHOSTD
```

## 6. Submit captures

The single-target Web, Crypto, and Pwn PoCs print the captured flag; they do not submit it. Keep captures in a local file with restrictive permissions, then submit 1–100 flags per API request. Do not put a token or flags in this write-up.

```sh
chmod 600 /tmp/captured-flags.txt
python3 - <<'PY'
import getpass, json, urllib.request

with open('/tmp/captured-flags.txt', encoding='utf-8') as f:
    flags = list(dict.fromkeys(line.strip() for line in f if line.strip()))
if not flags or len(flags) > 100:
    raise SystemExit('expected 1–100 captured flags')
token = getpass.getpass('Current A&D API token: ')
body = json.dumps({'flags': flags}).encode()
req = urllib.request.Request(
    'https://warzone.battleofhackers.com/api/Game/2/Ad/Submit',
    data=body,
    headers={'Authorization': 'Bearer ' + token,
             'Content-Type': 'application/json'},
    method='POST',
)
with urllib.request.urlopen(req, timeout=15) as response:
    result = json.load(response)
print('Submission response received')
for item in result.get('results', []):
    print(item.get('status'))
PY
```

An `accepted` result means the platform recorded the flag as evidence. `duplicate`, `wrong`, `expired`, `self_attack`, and `not_started` do not count as a new accepted capture. Accepted evidence is later settled according to the event's epoch scoring rules.
