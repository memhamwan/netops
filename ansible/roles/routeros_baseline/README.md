# routeros_baseline — DRAFT, not yet executed

**Execution gate: no automation-driven router changes without Ryan's PR
review.** Both playbooks refuse to run without `-e confirm_execution=true`,
and that flag must not be used until this role has been reviewed. Nothing in
this role has ever run against a device.

Replaces the three `device-onboarding/*.sh` scripts plus accumulated
hand-fixes with one idempotent role over the RouterOS API (`api_modify`):

- service groups + group membership (creation stays in bootstrap/onboarding —
  this role can never mint a passwordless account)
- service lockdown: telnet/ftp/www/www-ssl/api-ssl/winbox off, ssh:222,
  strong-crypto, MAC-server none, bandwidth-server off; **API stays on**
  restricted to `api_allowed_sources` (diff from old ioc-terraform role)
- remote syslog (7.18+/pre-7.18 schema fallback) + topic rules
- NTP with `time.cloudflare.com` fallback (fleet drifts when LEB is dark)
- FQDN identity enforcement
- user audit (report-only — never deletes)

## Known open questions for review

1. `api_modify` path coverage varies by collection/ROS version — the first
   `--check --diff` run (post-review) is the real validation pass.
2. Plaintext API on 8728 (also used by mktxp today): consider api-ssl + certs.
3. RouterOS `/user ssh-keys` cannot be managed via API — key imports stay in
   the SSH-based bootstrap play.
4. romon and OSPF auth intentionally not touched yet (`ospf_auth` will be a
   separate audit-first role; romon secret not yet in sops).
5. Old role disabled neighbor discovery fleet-wide; kept out of this draft —
   decide whether to restrict to an interface list instead.
