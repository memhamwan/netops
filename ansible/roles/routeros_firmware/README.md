# routeros_firmware — DRAFT, not yet executed

**Execution gate: no automation-driven router changes without Ryan's PR
review.** `playbooks/routeros_firmware.yml` refuses to run without
`-e confirm_execution=true`, and that flag must not be used until this role has
been reviewed. Nothing here has ever run against a device.

Upgrades RouterOS (and the RouterBOARD bootloader firmware) across the wireless
fleet, **one device at a time, deepest-chain-first**, and verifies each device
lands on the expected version before moving on.

## Why the ordering matters

The network is a set of linear chains: the SCO core feeds SCO→FTN and
SCO→HIL→MNO tails. Upgrading a device reboots it, and everything *behind* it
(further from the core) goes unreachable until it returns. If you upgraded a hub
first, its whole tail would go dark — and if that hub failed to come back, you'd
have lost management access to every device behind it.

So we upgrade **deepest first** (highest RoMON hop count), one device at a time:

- each reboot only drops the device itself — nothing you still need to reach
  sits behind it (deeper devices are already done);
- to reach the device being upgraded, all its ancestors (shallower, not yet
  touched) are still up;
- by the time a hub is upgraded, its whole tail is already done, so its reboot's
  blast radius is gear you no longer need to reach;
- the core (`r1.sco`, depth 0) reboots the entire fleet, so it goes **last**.

Ordering data lives in `ansible/firmware_topology.yml`, derived from RoMON.
**Refresh it before every campaign** (dishes get re-aimed, links change) — the
refresh procedure is documented in that file. Hosts with no topology entry are
*refused*, not guessed: the playbook fails fast listing them, so you never
upgrade a device whose blast radius you haven't mapped. Scope a run to the
mapped chain with `-l` (e.g. `-l sco:ftn:hil:mno`).

## How a single device is upgraded (roles/routeros_firmware)

1. Read current version, RouterBOARD firmware, and architecture.
2. RouterOS package, whichever mode applies:
   - **online** (default): set the channel, `check-for-updates`, download, reboot;
   - **offline** (`routeros_npk_source_dir` set): upload the `.npk`(s) for the
     pinned version + architecture, reboot to apply.
3. **RouterBOARD firmware**: `/system routerboard upgrade` + reboot, so the
   bootloader tracks the RouterOS version (skipped on CHR/x86; toggle with
   `routeros_upgrade_routerboard`).
4. **Verify**: assert the running version — and the RouterBOARD firmware — equal
   the expected version. A mismatch trips `any_errors_fatal` and halts the run.

Idempotent: a device already on the expected version and firmware is left
untouched (no reboot), so re-running to resume after a failure is safe.

## Specifying a version

- **Latest on a channel** — leave `routeros_target_version` empty; the channel's
  `latest-version` is the expected end state.
- **Pin an exact version** — `-e routeros_target_version=7.24.1`. Online, the run
  refuses to reboot unless the channel actually serves that version (so it never
  reboots toward an unreachable target), and the final check asserts every device
  ends on it.
- **Force a version the channel isn't serving** (a specific/older build, or
  catching a v6 box up to a chosen v7) — use the offline path:
  `-e routeros_npk_source_dir=~/routeros-npks`, with files laid out as
  `~/routeros-npks/<architecture-name>/routeros-<version>-*.npk`
  (architecture-name is read off each device: arm, arm64, mipsbe, mmips, tile…).

## Auth model

Runs over SSH as a human **operator** (group `full`), not the `ansible` service
account — the `netops-ansible` group deliberately lacks the `reboot` policy that
a firmware upgrade needs. `ansible_user` defaults to `$USER`, key-based, same as
`onboard_device.yml`.

## Known caveats for review

1. `check-for-updates` and the online download need the device to **resolve and
   reach `upgrade.mikrotik.com`** — so the device must have working DNS
   (`/ip dns print` must show `servers`) and an internet path. Several fleet
   devices have no DNS set (e.g. r2.sco), so online mode fails there with a
   clear message; fix DNS (routeros_baseline/site_services) or use the offline
   `.npk` mode.
2. **v6 → v7 is a major migration** (config semantics change). The role refuses
   it unless `-e routeros_allow_major_upgrade=true`, per device, after you've
   reviewed that device's config. `sec2.mno` (RoMON, 6.49.4) is the live example
   — and it isn't in inventory yet.
3. Reboot recovery is proven by SSH-port waits (from the controller) plus a CLI
   readiness probe, not a fixed sleep. Timeouts default generous for slow radio
   links (`routeros_*_timeout` in `defaults/main.yml`). OSPF reconvergence after
   a hub reboot can add a short delay before deeper (already-upgraded) devices
   are reachable again — deepest-first means we never depend on that mid-run.
4. Ordering is static data refreshed by hand from RoMON; a live-discovery
   variant is possible later but was kept out to keep the upgrade window
   deterministic and the ordering reviewable in a PR.
5. RouterOS wraps the *echoed* `:put` command line when it is wider than the
   detected terminal (~46 cols observed on mipsbe), leaking echo fragments into
   the command output — and when the queried value is **empty**, only those echo
   lines come back. So all reads drop echo lines (they contain `:put`, `/system`,
   or a `<` wrap marker) and take what remains, treating "nothing left" as an
   empty value. This is what lets the "could not reach servers" guard fire on a
   device with no DNS instead of mistaking an echo fragment for a version.
   (Dropping `:put` is not an option: the module returns empty without it.)
6. No automatic rollback. If a device comes back on the wrong version the run
   halts (`any_errors_fatal`) so you can intervene; RouterOS keeps the previous
   version for a manual `/system package downgrade` if needed.
