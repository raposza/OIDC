<!-- Copyright (c) 2026 bentzn -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Changelog

Version numbers here are this repository's own. `0.3.0` is the first release;
`0.1` and `0.2` were the two internal copies this replaces and were never
published under these coordinates.

## 0.4.0 - 2026-09-26

### Added

* **Users carry the standard claims** of OpenID Connect Core 1.0 section 5.1 -
  `name`, `email`, `address`, `phone_number` and the rest - set on the Users
  page or in `users.json`. A scope releases its claims at UserInfo, Core 5.4,
  and the discovery document now advertises `profile`, `email`, `address` and
  `phone` and every standard claim. A `users.json` from 0.3.0 is read
  unchanged.
* **The `claims` request parameter**, Core 5.5 - a claim asked for by name is
  released where it was asked for, at UserInfo or in the ID token.
  `essential` and `value` are accepted and not enforced.
  `claims_parameter_supported` is advertised.
* **Every ID token carries `acr` `"0"`**, and `acr_values_supported` advertises
  it: Core section 2's value for an authentication below ISO/IEC 29115 level
  1, which is what this service performs.
* **A reused authorization code revokes what it issued** as far as this
  service can, RFC 6749 section 4.1.2: UserInfo refuses the grant's access
  tokens and its refresh token is forgotten.
* **An unsigned request object is processed** - `request` by value with
  `alg: none`, Core 6.1. Its members supersede the query's, `client_id` and
  `response_type` must match, and discovery advertises
  `request_parameter_supported` and `request_object_signing_alg_values_supported`
  `["none"]`. A signed object is `invalid_request_object`; `request_uri` is
  still refused. 0.3.0 refused every request object.
* **The web UI and the sign-in page take their fonts, colours and logo from
  `com.raposza.design:raposza-design:0.4.0`**, served from its jar under
  `/raposza/`.

### Fixed

* **Logout no longer follows an unregistered `post_logout_redirect_uri`.** Once
  a client is registered, the URI must be one of that client's registered
  redirect URIs - the client named by `client_id` or by the `id_token_hint` -
  and anything else is refused with an error page, the session left as it was.
  0.3.0 followed any absolute http(s) URI: an open redirect on the issuer's
  address, and a logout a real provider would refuse.
* **The admin credential is checked on the path Spring dispatches on.** 0.3.0
  checked the raw request URI, so `/oauth2/jwks-private;x=1`,
  `/oauth2/%6Awks-private` and `/%61dmin/status` reached their handlers with
  no credential while the plain spellings were refused - the private key set
  served whole with the admin password set.
* **A signed-in UI session no longer authorises a write from another site.**
  A body-less POST is a request a browser sends cross-origin without asking
  first, and it carries the session cookie; 0.3.0 acted on it, so a page on
  any origin could rotate a key while an administrator was signed in. A write
  on the session now needs the `X-Raposza-UI` header, which the UI sends and
  a cross-origin page cannot send with credentials here.

### Changed

* **The sign-in page says "For test only - not production"**, in bold, in the
  design package's error colour.

* **`raposza.jwtmint.issuer` is required, and the service refuses to start
  without it.** 0.3.0 guessed a blank issuer from the machine's own addresses -
  the lowest site-local IPv4, sorted as strings - and on a workstation with a
  container network the guess was the pod network's own address, so every
  consumer rejected every token. The issuer is compared literally by every
  verifier, so it is now always set by whoever deploys the service. A
  standalone service still also requires an admin password.

### Notes

* **0.3.0 already had a sign-in session** - the `raposza_oidc_session` cookie,
  so a second authorization request from the same browser needs no login, and
  `prompt=none`, `id_token_hint` and `max_age` work as Core 3.1.2.1 defines
  them. Its entry above does not list it.

## 0.3.0 - 2026-09-19

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
