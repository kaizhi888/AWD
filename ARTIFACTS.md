# Artifacts and reproduction environment

## Included attachment

| File | Origin | SHA-256 | Notes |
|---|---|---|---|
| `artifacts/SupportConsole` | SupportConsole attachment saved from the IBOH challenge card | `5da9fa20751efb18acfcaf3cd50d5fb0eb9b80f1afd739789cae45f02c25460a` | ELF 64-bit x86-64 executable; used to identify the fixed return gadget and flag routine in `pwn_supportconsole.py`. |

The overflow offset and addresses in the PoC are specific to this exact binary. Verify the hash before using it for local analysis. The challenge service itself runs in the authorized event environment.

## Referenced but unavailable locally

- The Reverse challenge's `sphostd` binary was used as a local GDB oracle in the earlier session, but it is not present in the current Desktop or temporary working directory. Obtain it from the original challenge attachment before running `reverse_mac_oracle.py`.
- The On the House `house.sh` helper, Solidity source, and exact registry response were available inside the running challenge container but were not saved. The write-up records the transaction sequence and labels it as unverified.

## Local material deliberately not copied

The local `Welcome.pcap` was not identified or linked to IBOH Game 2 in the saved notes, so it is excluded rather than publishing a capture of uncertain relevance.
