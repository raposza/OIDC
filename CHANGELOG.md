<!-- Copyright (c) 2026 bentzn -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

Version numbers here are this repository's own. `0.3.0` is the first release;
`0.1` and `0.2` were the two internal copies this replaces and were never
published under these coordinates.

## 0.3.0 - unreleased

The first release. Everything below describes what exists at 0.3.0 rather than
what changed, since there is no published predecessor.

### Added

* **`com.raposza.oidc:raposza-oidc-core`** - the JOSE half: `JwksMaterial`,
  `JwtMinter`, `MintAlg`, `MintKeys`, `MintSigner`, `TokenException`,
  `TokenShape`, `TokenSpec`. Nimbus and the JDK, no Spring and no web, so it
  can also be a dependency of a client that has neither.
* **`com.raposza.oidc:raposza-oidc-server`** - the HTTP half: the discovery
  document in both its forms, the public and private JWKS, the OpenID Connect
  browser flow with PKCE, `/oauth2/token` for `authorization_code`,
  `refresh_token` and `client_credentials`, `/oauth2/userinfo`, the mint, and
  an administrative surface. Published as a library jar and as a runnable
  Spring Boot jar under the classifier `app`.
* **A web UI at `/ui/`** - six pages over the service's own API: Overview,
  Keys, Users, Clients, Mint and Inspect. Hand-written HTML, CSS and plain
  JavaScript served from the jar; no Node, no build step, nothing from a CDN.
* **Inspect takes a foreign JWKS.** Paste the set a participant actually
  trusts and the page reports whether THAT set verifies the token, beside
  whether this service's own does. Every authentication failure in this project
  has been an issuer, an audience or a key that did not match, and a
  participant reports all three the same way.
* **A file-backed user store**, `users.json` beside the JWKS, seeded once from
  `raposza.jwtmint.users` and thereafter authoritative.
* **A writable key store.** Rotate, add and remove keys through the UI or
  `/api/ui/keys`; the set is written before it is swapped in, so a failed write
  leaves the running service untouched.
* **An admin credential** on the UI and on every write endpoint, and on the
  private JWKS - `raposza.jwtmint.admin.user` and `.admin.password`. With no
  password set those paths are OPEN and the service warns at startup;
  `raposza.jwtmint.standalone=true` refuses to start in that state.
* **A client registry**, `clients.json`, and the three checks a real OpenID
  Provider makes that this service did not: an unknown `client_id`, an
  unregistered `redirect_uri` - both refused WITHOUT redirecting the error,
  Core 1.0 section 3.1.2.6 - and a `client_secret` that is wrong, missing, or
  present on a public client. An EMPTY registry checks none of them, so it
  lands without changing any existing deployment.

### Notes

* **The Java package of the server module is `com.raposza.oidc`.** The JOSE
  classes in `raposza-oidc-core` keep `com.raposza.jwt`, because `raposza-auth`
  imports them and renaming there would fork the client code as well. The
  SETTINGS prefix stays `raposza.jwtmint` for the compatibility reason given
  above, and so does the default key directory `~/.raposza/jwtmint/keys`.
* **The extra endpoints are deliberate and permanent.**
  `/keys`, `/keys.txt`, the private JWKS and `/api/ui/*` are not part of any
  standard and are why this service exists. Nothing that speaks only OpenID
  Connect will ever call them, so a relying party built against this service
  moves to a real provider unchanged.
* **`/oauth2/token` behaves as the standard says and refuses what it does
  not implement.** A JSON body is 415 - RFC 6749 section 3.2 specifies form
  encoding - and a `grant_type` that is unknown or missing is
  `unsupported_grant_type` or `invalid_request`. An arbitrary token from a JSON
  body is `/mint`, which is unchanged.
* **It is not hardened and is not trying to be.** `SECURITY.md` carries the
  short statement; `docs/security-review.md` carries the posture in full.
