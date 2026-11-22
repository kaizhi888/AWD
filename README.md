# AWD — IBOH 2026 Attack & Defense field notes

This repository collects one participant's tools, exploit notes, and lessons from **International Battle of Hackers 2026, Event 2 (IBOH::CTF Attack & Defense)**. The techniques are specific to the event's challenge services and authorized game roster.

## Start here

- [flags-writeup.md](flags-writeup.md) — challenge-by-challenge analysis and reproduction steps.
- [ATTACK_WALKTHROUGH.md](ATTACK_WALKTHROUGH.md) — practical setup, exploit, and submission workflow.
- [EVENT_WORKFLOW.md](EVENT_WORKFLOW.md) — target discovery, round handling, submission statuses, and the scoring model shown in the toolkit.
- [ARTIFACTS.md](ARTIFACTS.md) — included challenge binary, checksums, and reproduction dependencies.

## Challenge coverage

| Challenge | Category | Saved material | Main idea |
|---|---|---|---|
| Rusty Day | Web | `web_rusty_day.py` | SSRF to a loopback-only flag reader |
| SupportConsole | Pwn | `pwn_supportconsole.py`, `exploit_supportconsole_roster.py`, `artifacts/SupportConsole` | Stack overwrite and ret-to-win |
| ok, noted. | Crypto | `crypto_ok_noted.py` | CBC-MAC length extension plus invalid elliptic-curve point validation |
| reverse-my-connection | Reverse | `reverse_mac_oracle.py`, `reverse_remote_driver.py` | MAC oracle and framed control protocol |
| On the House | Blockchain | Transaction sequence in `flags-writeup.md` | Exchange/reserve accounting mismatch |

## Setup

The saved Python PoCs use the Python 3 standard library. The Reverse MAC helper additionally needs GDB and the challenge's `sphostd` binary. The Blockchain sequence uses the challenge-provided `house.sh` helper and wallet inside the player's own challenge container, plus Foundry's `cast`, `curl`, and `jq`.

Use the official Game 2 Targets endpoint to obtain the current opponent addresses and check that the service is `Ok`; addresses can change after a reset. Choose a listed target for the matching service and run only that challenge's PoC. For example:

```sh
python3 web_rusty_day.py TARGET_IP --port 8080
python3 pwn_supportconsole.py TARGET_IP --port 9090
python3 crypto_ok_noted.py TARGET_IP --port 20561
```

The Reverse helper workflow and Blockchain transaction details are in the main write-up. Use these event-specific procedures only within an authorized IBOH game instance and against targets returned by its official API.

## Capturing and submitting

The single-target Web, Pwn, and Crypto PoCs print a captured flag; the Reverse driver writes it to a local file. Keep captures private and out of shell history, issue trackers, and this repository. Submit through the official API with the current personal token. `submit_flags.py` reads one flag per line, deduplicates them, and prints submission statuses without echoing flag values:

```sh
chmod 600 /path/to/captured-flags.txt
AD_API_TOKEN="$AD_API_TOKEN" python3 submit_flags.py /path/to/captured-flags.txt
```

The optional SupportConsole roster runner fetches the current official roster, attacks healthy entries for that challenge with at most four workers, and can submit the results. Use `--no-submit` to skip submission. It is included as a record of the contest workflow and should only be used within the event.
