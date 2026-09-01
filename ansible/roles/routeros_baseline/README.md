# routeros_baseline — DRAFT, not yet executed

**Execution gate: no automation-driven router changes without Ryan's PR
review.** All three device playbooks (`bootstrap_ansible_user.yml`,
`onboard_device.yml`, `routeros_baseline.yml`) refuse to run without
`-e confirm_execution=true`, and that flag must not be used until this role
has been reviewed. Nothing in these plays has ever run against a device.

Replaces the `device-onboarding/*.sh` scripts plus accumulated hand-fixes.
Account *creation* lives in the two SSH-based plays —
`bootstrap_ansible_user.yml` (the `ansible` automation account) and
`onboard_device.yml` (`oxidized`, `oxidized-full`, `mktxp`) — while this role
runs over the RouterOS API (`api_modify`) and only corrects what exists:

- service groups + group membership (creation stays in the bootstrap/onboarding
  plays — this role can never mint a passwordless account)
- service lockdown: telnet/ftp/www/www-ssl/winbox off, ssh:222,
  strong-crypto, MAC-server none, bandwidth-server off; **api-ssl (8729,
  per-device cert) stays on** restricted to `api_allowed_sources`, plaintext
  api (8728) disabled (diff from old ioc-terraform role, which disabled the
  API outright)
- remote syslog (7.18+/pre-7.18 schema fallback) + topic rules
- NTP with `time.cloudflare.com` fallback (fleet drifts when LEB is dark)
- FQDN identity enforcement
- user audit (report-only — never deletes)

## Known open questions for review

1. `api_modify` path coverage varies by collection/ROS version — the first
   `--check --diff` run (post-review) is the real validation pass.
2. **api-ssl migration (implemented in these drafts; manual, ordered run):**
   1. `onboard_device.yml` fleet-wide — creates the per-device self-signed
      cert and enables api-ssl (8729) *alongside* plaintext 8728.
   2. Flip `mktxp_use_ssl: true` in `roles/netops_host/defaults/main.yml`
      and redeploy the backup host — the collector moves to 8729.
   3. `routeros_baseline.yml` — runs over 8729 and its final `api_lockdown`
      disables plaintext 8728 and pins api-ssl to `api_allowed_sources`.
   Out of order this breaks metrics (step 2 before 1) or strands devices on
   plaintext (step 3 before 2). Remaining open: certs are self-signed and
   clients don't validate (`validate_certs: false`, mktxp
   `ssl_certificate_verify = False`) — encryption defeats passive capture but
   not an active MITM; an internal CA is the follow-up.
3. RouterOS `/user ssh-keys` cannot be managed via API — key imports stay in
   the SSH-based bootstrap/onboarding plays (service accounts *and* operator
   keys from `files/operators/`).
4. romon and OSPF auth intentionally not touched yet (`ospf_auth` will be a
   separate audit-first role; romon secret not yet in sops).
5. Old role disabled neighbor discovery fleet-wide; kept out of this draft —
   decide whether to restrict to an interface list instead.
