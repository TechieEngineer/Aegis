# Security policy

Aegis is an educational, local-only reference implementation. It is not an enterprise-certified or independently audited security gateway. Use only systems you own or have explicit permission to inspect. The default recon target is a fictional offline fixture; network audit targets are denied unless an operator adds exact approved names to `RECON_ALLOWED_HOSTS`. Never use actual credentials or sensitive data during testing.

## Reporting issues

Open a private GitHub security advisory (Security → Report a vulnerability, if enabled) or contact the repository maintainer privately. Describe expected behavior, impact, affected version and a minimal local reproduction. Do not include real secrets, credentials, other people's data, or live attack traffic. Allow time for remediation before public disclosure.

## Known limitations and deployment boundary

- Localhost HTTP only; Secure cookies and Web Crypto rely on localhost exceptions. For a remote deployment, use trusted HTTPS, change the configured origin, enforce TLS/HSTS on the outer proxy and reassess proxy/IP trust, firewalling and secrets management. The Compose port is deliberately bound to loopback.
- This is an API edge protecting its own routes, not a general upstream reverse-proxy WAF. Signature matching is illustrative and has false positives/negatives; it cannot replace parameterized SQL, contextual output encoding, authorization or a professionally maintained WAF. Credentials and opaque authorization/cookie headers are not logged; JSON strings are inspected and may trigger false positives.
- Redis persistence is disabled for the ephemeral vault, sessions and queue hints. A Redis restart destroys vault entries and sessions. `GETDEL` is atomic on a single primary, not proof of physical deletion; replicas, memory snapshots, backups, browser histories and recipient copies are outside that guarantee. The frontend code must be trusted, and link holders can consume secrets. A lost response or wrong key can burn an envelope irreversibly.
- Recon uses DNS resolution, pinned public IP, no redirects/proxy, verified TLS and two fixed web ports. Address filtering is defense in depth, not a complete egress boundary. Use external egress restrictions and independently verified authorization. Offline fixtures are clearly marked. No broad port ranges, crawling, exploit execution or target discovery are included.
- Audit logs are bounded and asynchronous; overload or database outage can drop events. Single deployment only; Redis/PostgreSQL cross-store operations are not distributed transactions. Postgres recovers queued jobs and stale leases. No multi-region HA, backup automation, external identity provider, account recovery, email verification or password reset.
- MFA confirmation prevents TOTP step reuse but no recovery codes or MFA reset UI are provided. Keep authenticator access safe. Refresh token reuse revokes the whole family, including legitimate simultaneous refreshes; the frontend serializes refreshes within a tab, not across tabs.
- Dependency versions and containers require ongoing updates. CI scanners can flag vulnerabilities; treat reports as blockers for any deployment, and review gosec findings manually. No independent penetration test or performance benchmark has been completed.
