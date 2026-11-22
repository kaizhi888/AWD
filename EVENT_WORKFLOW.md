# IBOH Game 2 A&D workflow and scoring notes

This is a participant's reference to the Game 2 API and round model as it was shown in the event toolkit. Confirm the live toolkit before relying on historical values.

## Before a round

1. Join the event network with the per-user WireGuard profile. Keep the profile and private key out of Git, shell transcripts, and shared logs.
2. Load the current personal API token from a secret store into `AD_API_TOKEN`; do not paste it into a script or commit it.
3. After warmup, fetch `GET /api/Game/2/Ad/Targets`. The response lists challenges and opponent containers, with the current round, service port, and `lastCheckStatus`.
4. Select only the matching challenge and currently listed targets whose status is `Ok`. Refresh the roster each round; a reset or container restart can change an IP.
5. Run the matching single-target PoC. Keep captures in a local file with restrictive permissions, then use `submit_flags.py` to batch one to 100 distinct values.

Example target request:

```sh
curl -fsS https://warzone.battleofhackers.com/api/Game/2/Ad/Targets \
  -H "Authorization: Bearer $AD_API_TOKEN"
```

Example submission request (prefer the helper so the token and flag values are not echoed):

```sh
curl -X POST https://warzone.battleofhackers.com/api/Game/2/Ad/Submit \
  -H "Authorization: Bearer $AD_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"flags":["flag{captured_value}"]}'
```

The API reports each input as `accepted`, `duplicate`, `wrong`, `expired`, `self_attack`, or `not_started`. An accepted result records evidence; it does not award an immediate standalone point.

## Round and flag behavior

- Round 0 is warmup; target listing becomes available after warmup.
- Each service receives a new current flag each round. Read a current flag on every exploit request; do not cache it.
- The event documentation said old flags remain valid for a limited number of ticks (default five). Treat older captures as potentially expired.
- A service check status of `Ok`, `Mumble`, or `Offline` describes health. Prioritize `Ok` targets.
- The container's current flag path is supplied as `RSCTF_FLAG_FILE`; challenge defenders should use that environment variable rather than a cached or hard-coded path.

## Scoring model shown in the toolkit

For each service in an equal-budget epoch, the displayed model was:

- Attack coverage: `A = min(1, C + 0.25H)`, where `C` is accepted-capture coverage over the frozen opponent roster and `H` is a bounded capturer-count rarity term.
- Defense: `D = protected pairs / eligible pairs`. Distinct capturers remove their own protected pair; an unstolen pair is not evidence that an exploit was attempted.
- Service-level agreement: `R = checker credit / service ticks`. A clean pass earns full credit, recovery earns partial credit, and failed or missing checks earn none.
- Service score: `100 × R × (0.40A + 0.40D + 0.20√(A×D))`.
- Normalized service weights form the epoch score; finalized epochs determine official rank.

The platform's finalized score and history remain the source of truth. A raw accepted-submission count is not the same as an epoch score.

## Operational notes

- Check route selection with `ip route get TARGET_IP` before sending a PoC. If the target routes over the ordinary LAN instead of the event interface, fix VPN routing before proceeding.
- Keep parallelism bounded. The saved roster-aware SupportConsole runner caps its workers at four.
- Do not scan outside the official roster, attack the checker, or overload a service. Stop if a target is not a current in-scope game container.
- The scripts in this repository retrieve flags from the challenge service. The defender-side guidance in the toolkit says to patch services without breaking the health check, and to restart the service under its supervisor rather than killing PID 1.
