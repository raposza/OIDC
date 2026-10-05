<!-- Copyright (c) 2026 bentzn -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security

## Reporting a vulnerability

Write to **info@raposza.com**. Say what you found, how to reproduce it, and
what you think it lets an attacker do. You will get an acknowledgement; if the
finding is valid you will be told what is being done about it and when the fix
lands.

Please do not open a public issue for a vulnerability before it is fixed.

There is no bug bounty.

## What is in scope

This repository: `oidc-core`, `oidc-server`, the web UI under
`oidc-server/src/main/resources/static/ui/`, and the three shell scripts.

**Not in scope: what this service is pointed at.** A participant, a validator
or any other relying party configured to trust this issuer is that project's
concern. Report anything you find there to its maintainers.

## Supported versions

Only the current tip of the default branch. There are no maintenance branches
and no backports. Published artefacts are never replaced - a released
coordinate on Maven Central is immutable - so a fix arrives as a new version.

## When this was last reviewed

**Reviewed 2026-10-05 for 0.5.0**, against the tree as it stands -
`docs/security-review.md` carries the result. No new finding. Six statements
there were stale and are corrected: four named 0.4.1, a version that was never
released and whose changes ship in 0.5.0, and the build's integrity and its
third-party versions had not moved with the build. The refusal of the old
`raposza.jwtmint.*` settings is added, and where it applies.

**Reviewed 2026-09-26 for 0.4.0**, against the tree as it then stood, and a
second time the same day - `docs/security-review.md` carries the result, the
statements each pass corrected and the three findings they fixed: an open
redirect at logout, guarded paths reachable by a different spelling, and a
signed-in UI session usable by a page on another site.

## The short statement of the model

**Raposza OIDC is a test identity provider and it is not hardened. It is not a
replacement for Keycloak and it is not trying to be.** What it promises is
PROTOCOL FIDELITY: a relying party configured against it moves to a real
OpenID Provider by changing settings and nothing else. Five consequences you
should read before running it:

* **It serves its own PRIVATE keys** at `/oauth2/jwks-private`. Anyone who can
  reach that path can sign a token this issuer's consumers accept. The admin
  credential closes it; with no password set it is open and the service says
  so at startup, in a WARN line.
* **It mints a token for any subject with any claims**, at `/mint`, with no
  authentication at all. That endpoint is deliberate and it stays - it is the
  reason the service exists - and it is why the service belongs on a machine
  and a network you control.
* **User passwords and client secrets are stored in clear text**, in
  `users.json` and `clients.json` beside the key set, and so are the standard
  claims a user may carry since 0.4.0 - name, e-mail, address, phone. The
  comparison is constant-time and that is the whole of what is done for them:
  no hashing, no lockout, no password policy, no MFA. They are a test system's
  users.
* **There is no rate limiting, no general revocation and no audit log.** A
  token this service issued is valid until it expires. The one exception is a
  reused authorization code, whose tokens UserInfo then refuses - a relying
  party's resource server that checks only the signature still accepts them.
* **It listens on every interface by default** and terminates no TLS. The
  issuer is required - `raposza.oidc.issuer`, and a service started without
  one refuses - and behind a proxy it is the external origin: RFC 8414 section
  3.3 compares issuers literally.

**What it does check, because a real provider does.** Once one client is
registered, an unknown `client_id`, an unregistered `redirect_uri` and a wrong
or unexpected `client_secret` are all refused, and the first two are refused
WITHOUT redirecting the error - OpenID Connect Core 1.0 section 3.1.2.6. Since
0.4.0 a logout's `post_logout_redirect_uri` is followed only when it is
registered for the client too, and since 0.5.0 a public client cannot use
`client_credentials`. While no client is registered none of this is checked,
and the service says so at startup. Since 0.5.0 a sign-in name and password
are read from the form's POST body only, never from an address, whatever is
registered. That is correctness, not hardening: it exists so that a component
which works here also works against a real provider.

`docs/security-review.md` is the full posture document: what executes, what is
downloaded and how its integrity is established, what listens and with what
authentication, what is written to disk, what key material is held, what
leaves the machine, and the limitations that follow.
