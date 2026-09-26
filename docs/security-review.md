<!-- Copyright (c) 2026 bentzn -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security posture

**This is a REVIEW, not an audit.** It was written by the people who wrote the
code, from a static reading of this tree on 2026-09-19. Nothing in it was
established by a third party, and no third party has signed anything about it.
When an external audit exists it will be published beside this document,
unedited.

**Reviewed 2026-09-26 for 0.4.0.** `SUITE.md` B8, against the tree as it
stands. Read in the same pass: `SECURITY.md`, this document, and `README.md`'s
endpoint list, "Behind a reverse proxy", "Users and their claims" and
"Settings". **SIX STATEMENTS WERE STALE AGAINST THE TREE and are corrected
below:** section 3's table had no session cookie at the authorization endpoint,
no `/raposza/` design files and nothing on logout's redirect; section 3's
standalone sentence predated the required issuer; section 5 had no sessions;
section 9 had no design package. The session shipped in 0.3.0 AFTER that
release's review was written, so 0.3.0's documents never described it. **ONE
FINDING WAS NEW AND IS FIXED IN 0.4.0:** `/oauth2/logout` followed any
absolute http(s) `post_logout_redirect_uri` - an open redirect on the issuer's
own address, and a relying party built here could rely on a logout URI a real
provider refuses. Section 3 has the check that replaced it. Users' standard
claims and unsigned request objects are new in 0.4.0; the claims are in
sections 3 to 6, the request object in section 3. Everything else was
confirmed against the source, not carried forward.

**A SECOND PASS THE SAME DAY, 2026-09-26, found TWO MORE, both measured on the
built 0.4.0 jar and both fixed in 0.4.0.** `AdminGuard` decided on the raw
request URI while Spring dispatched on the canonical path, so
`/oauth2/jwks-private;x=1`, `/oauth2/%6Awks-private` and `/%61dmin/status`
were served with no credential and the admin password set - the private key
set whole. And section 3 said `allowCredentials` false kept a page on another
origin off an administrator's session; it does not, because a body-less POST
is sent cross-origin without a preflight and carries the cookie, and one
rotated a key. Section 3 has both fixes. Two statements were also stale:
`GET /admin/reload` was missing from `README.md`'s endpoint list, and section 5
said no path but the admin UI returns a user's claims, beside the sentence
saying UserInfo and the ID token do.

**Reviewed 2026-09-19 for 0.3.0**, the first review: four statements were
falsified by the tree then - the key file names and count in section 4, the
atomic write in section 4, the password comparison in section 5, and the
omission of `/` from section 3's table - and L-10 was new.

It is organised as the questions a reviewer asks, in the order they get asked.
Read it with `SECURITY.md`, which carries the short statement of the model and
the reporting channel.

**What Raposza OIDC is, in one paragraph.** Two Java artefacts. `oidc-core` is
a JOSE library - key material, algorithms, a signer - with Nimbus and the JDK
and nothing else. `oidc-server` is a Spring Boot service that puts an OpenID
Connect and OAuth 2.0 surface over it, signs people in from a file of users,
mints arbitrary tokens on request, and serves a web UI over its own API. It
exists so that a relying party can be developed and tested against something
that speaks the real protocol, and then pointed at a real OpenID Provider
without changing anything but settings. It is not a production identity
provider and the sections below say exactly where that shows.

## 1 - What executes, and how the command line is built

`java` to run it, and `mvn` to build it. Nothing else.

**Nothing in this repository downloads a script and runs it.** There is no
`curl | sh`, no installer, no self-update, and no shelling out at runtime: the
service starts no child process and executes no external program. The three
shell scripts - `build.sh`, `test.sh`, `run-oidc.sh` - invoke `mvn` and `java`
and nothing else, and every argument after `--build` is passed through to the
JVM as a separate argument rather than through a shell string.

Configuration is Spring's: `application.yml` in the jar, overridden by command
line arguments, environment variables and any external configuration Spring is
told to read. Those are TRUSTED INPUT in the ordinary sense - they choose where
keys live and who may sign in - and they are your own files.

## 2 - What is downloaded, from where, and how integrity is established

At BUILD time, from Maven Central: Spring Boot 3.5.16 and its transitive
closure, Nimbus JOSE+JWT 9.40, springdoc-openapi 2.8.17, and the Maven plugins
named in `pom.xml`. Every version is pinned - Nimbus and springdoc explicitly
in `<properties>`, the rest by the `spring-boot-starter-parent` BOM. Integrity
is Maven's: the checksums Central serves beside each artefact, verified by the
resolver.

At RUN time, nothing. The service fetches no remote configuration, no remote
key set and no remote metadata. It has no outbound HTTP client at all.

Published artefacts of this project carry a `.md5`, a `.sha1` and a `.asc`
signature, which Central requires and which a consumer can check - section 10.

## 3 - What listens, on which interface, with what authentication

One HTTP port, **32002** by default, **on every interface**. The bind address
is deliberately not set, and `application.yml` says why in a comment: a Canton
or a scribe inside a virtual machine has to reach the JWKS, and a loopback
bind makes that fail in a way that looks like a key problem.
`--server.address=127.0.0.1` restricts it.

**No TLS.** The process holds no keystore and terminates nothing. The
standalone deployment puts nginx or equivalent in front of it - D-774 - and
`README.md` carries a worked example.

The surface, and what guards each part:

| path | authentication |
| --- | --- |
| `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | none, by design - RFC 8414 |
| `/oauth2/jwks`, `/jwks.json` | none, by design - the public key set |
| `/oauth2/authorize` | the user's own name and password, from `users.json` - or a live sign-in session, the HttpOnly cookie `raposza_oidc_session`, SameSite=Lax, `Secure` when the issuer is https, 12 hours from sign-in |
| the same, with `request` | an UNSIGNED request object, `alg: none`, is merged into the parameters before any check, Core 6.1; it carries the trust of the query it arrives in and no more. A signed one is refused - this service holds no client's keys - and `request_uri` is refused |
| `/oauth2/token`, and its aliases `/oauth/token` and `/token` | the client's, once a client is registered - see below |
| `/oauth2/userinfo` | the bearer token issued by this service |
| `/oauth2/logout` | none. It ends the browser's session, and follows `post_logout_redirect_uri` only when that URI is registered for the client - below |
| `/mint`, `/mint.txt` | **NONE. Any caller gets a token for any subject.** |
| `/keys`, `/keys.txt` | none - algorithm, kid and key size, no key material |
| `/oauth2/jwks-private`, `/jwks-private.json` | the admin credential |
| `/admin/*` | the admin credential |
| `/api/ui/*` except `/api/ui/login` | the admin credential |
| `/ui/`, `/swagger-ui.html`, `/v3/api-docs` | none - static pages and a schema |
| `/raposza/**` | none - the design package's fonts, tokens and logo, static files served from its jar |
| `/` | none - a plain-text index that names the ABSOLUTE PATH of the key directory and the issuer |

**The admin credential is held in clear in configuration** -
`raposza.jwtmint.admin.user` and `.admin.password` - **and compared with
`MessageDigest.isEqual`**, which is constant-time, so a wrong password cannot be
found one byte at a time. `AdminGuard` is a `OncePerRequestFilter` - there is no
Spring Security in the tree - and it accepts EITHER an HTTP Basic header or a
servlet session marked signed-in by `/api/ui/login`, which is how the web UI
stays signed in. WITH NO PASSWORD SET THE GUARDED PATHS ARE OPEN, and the
service logs a WARN naming them. Every start requires
`raposza.jwtmint.issuer` and refuses without it; a service started with
`raposza.jwtmint.standalone=true` refuses to start without a password as well. `/api/ui/login` is itself unguarded and unthrottled, which is
what L-3 means by no lockout.

**The guard decides on the path Spring dispatches on**, the servlet path the
container has already decoded and stripped of path parameters, and on the raw
URI as well: a request is guarded when either spelling is. Until the second
review of 2026-09-26 it read the raw URI alone, and a `;x=1` or a
percent-encoded letter reached a guarded handler with no credential.

**A session alone does not authorise a write.** A request authenticated by
the UI session that writes - any method but GET and HEAD, and `/admin/reload`
whatever its method - must also carry the header `X-Raposza-UI`, which the UI
sends on every call; without it the answer is 403. HTTP Basic needs no header.

**The client registry is EMPTY by default and then nothing is checked** - any
`client_id`, any `redirect_uri`, any or no `client_secret`. Registering the
first client turns all three checks on for every client; removing the last
reopens it. Both states are logged at startup. An unknown `client_id` and an
unregistered `redirect_uri` are refused WITHOUT redirecting the error, because
the URI in such a request is precisely the one that cannot be trusted to
receive it - OpenID Connect Core 1.0 section 3.1.2.6. `redirect_uri` is
compared as a whole string, section 3.1.2.1.

**The same registry governs logout, since 0.4.0.** A `post_logout_redirect_uri`
is followed only when it is registered for the client named by `client_id`, or
by the `azp` or single `aud` of the `id_token_hint`. Otherwise the request is
refused with an error page and the session is left as it was - the URI is the
one thing in the request that cannot be trusted. The URIs checked are the
client's redirect URIs; there is no second list, which is also Keycloak's
default. Before 0.4.0 any absolute http(s) URI was followed. With an empty
registry it still is, like every other check here.

**CORS is open on EVERY path.** `CorsConfig` maps `/**` with `allowedOrigins("*")`,
`allowedHeaders("*")` and the methods GET, POST and OPTIONS. That is what a
browser-side relying party on another port needs, and it is also a real
widening: any page in a browser that can reach this service can call `/mint`
and read the answer. DELETE is not in the list, so the UI's own delete
endpoints are not reachable cross-origin - which is an accident of the method
list rather than a decision.

**`allowCredentials` is not set, so it is false**, and that stops a page on
another origin READING what a guarded path answers on an administrator's
session. It does NOT stop the request: a body-less or form POST is sent
cross-origin without a preflight and the browser attaches the session cookie,
which is how a page on any origin rotated a key before the second review of
2026-09-26. What stops that is the `X-Raposza-UI` rule above: a custom header
forces a preflight, and a preflight for a credentialed request fails here
because the answer carries no `Access-Control-Allow-Credentials`. A
cross-origin caller that wants a guarded path has to present HTTP Basic
itself, which a page can only do when it already holds the credential.

**The CORS mapping is unconditional and does not consult the client registry.**
A registered client's `redirect_uri` list narrows the browser flow; it narrows
nothing here.

## 4 - What is written to disk, and with what permissions

FOUR files, all in the key directory - `raposza.jwtmint.dir-keys`, by default
`~/.raposza/jwtmint/keys`:

| file | contents |
| --- | --- |
| `jwks-private.json` | the full key set, **private members included** |
| `jwks-public.json` | the same set with the private members stripped |
| `users.json` | names, passwords and each user's standard claims, **in clear** |
| `clients.json` | client ids, secrets in clear, and redirect URIs |

**THE TWO HALVES ARE NOT WRITTEN THE SAME WAY, and an earlier draft of this
section said they were.**

`users.json` and `clients.json` are written to a sibling part-file and moved
into place with `Files.move`, then narrowed to `rw-------` by
`JwksMaterial.restrictToOwner`.

`jwks-private.json` and `jwks-public.json` are NOT. `MintKeys.write` calls
`Files.writeString` on each in turn - a truncate and rewrite in place - and
`restrictToOwner` runs on the private one only AFTER that write has returned.
Two consequences follow and both are real:

* a reader that opens `jwks-private.json` during the write sees a truncated
  document, and the private set is written BEFORE the public one, so the two
  disagree for the length of the second write. This is the reason
  `MintKeyStore` re-reads only on an explicit `/admin/reload` rather than
  watching the directory, and its javadoc gives that reason;
* on a first generation the private file exists with the process umask's
  permissions for the length of one `setPosixFilePermissions` call before it
  is narrowed.

Neither is reachable from the network - nothing serves a path into the key
directory - so both are recorded as L-10 rather than fixed. The store's own
reload rule already covers the first, and the second needs a create-with-mode
that `Files.writeString` does not offer.

`jwks-public.json` is deliberately left readable. On a file system without
POSIX permissions `restrictToOwner` is a no-op and the file is written anyway -
stated here because it is a silent difference, not a failure.

Nothing else is written. There is no database, no cache directory and no
temporary file outside the two part-files named above.

## 5 - What credential or key material is held, where, and for how long

**Signing keys.** Twelve by default, one per supported algorithm - HS256/384/512,
RS256/384/512, PS256/384/512, ES256/384/512 - generated on first start and then
read from `jwks-private.json` for ever. There is no automatic rotation and no
expiry; a key lives until someone rotates or deletes it through the UI or
`/api/ui/keys`. The full set, private members and all, is served at
`/oauth2/jwks-private` to anyone holding the admin credential, and to anyone at
all when no password is set.

**User passwords.** Plain text in `users.json`, compared with
`MessageDigest.isEqual` - constant-time, NOT `String.equals`, which is what an
earlier draft of this section said. Seeded once from `raposza.jwtmint.users`
when the file does not exist; after that the file always wins. No hashing, no
salt, no lockout, no expiry.

**User claims.** Since 0.4.0 a user may carry the standard claims of OpenID
Connect Core 1.0 section 5.1 - name, e-mail, address, phone and the rest - in
`users.json` beside the password, in clear. Only those names are accepted.
A scope releases its claims at UserInfo only, Core 5.4; the `claims` request
parameter, Core 5.5, releases a claim by name at UserInfo or in the ID token,
wherever it was asked for. A claim the user does not carry is never made up.
The admin UI returns every user's full set; UserInfo and the ID token release
only what a scope or the `claims` parameter asked for.

**Authentication strength.** Every ID token carries `acr` `"0"` since 0.4.0,
and `acr_values_supported` advertises that value alone: OpenID Connect Core
section 2 defines it as an authentication that did not meet ISO/IEC 29115
level 1 and SHOULD NOT authorize access to anything of monetary value. A name
and a clear-text password on a test system is exactly that, so the claim is a
statement of weakness, not of strength.

**Client secrets.** Plain text in `clients.json`, compared the same
constant-time way. Never returned by any endpoint, including the UI's own.

**Issued tokens.** Not stored as a database. There is no general revocation:
a token is valid until its `exp`, and the default lifetime is 24 hours. ONE
CASE IS REVOKED SINCE 0.4.0, the one RFC 6749 section 4.1.2 names: a code
exchanged a second time makes UserInfo refuse every access token of that grant
and forgets its refresh token. The memory of which access token belongs to
which grant is held for the token's lifetime, in `OidcFlow`, and lost on
restart. A participant that checks only the signature still accepts such a
token until it expires.

**Authorization codes, refresh tokens and sign-in sessions** live in memory,
in `OidcFlow` and `OidcSessions`, and are lost on restart. A code is
single-use; a session lasts 12 hours from sign-in and is ended by logout.

## 6 - What is logged, and whether a secret can reach a log line

INFO to the console, in the pattern `application.yml` sets. What is logged:
the issuer and where it came from; the key ids present after a load,
a rotate, an add or a remove; user names after a load or a change, with the
NAMES of the claims a changed user carries but never their values; a session
opened, with its user name; client ids after a load or a change; and the two
WARN lines that say the admin credential and the client registry are unset.

**No password, no client secret, no private key and no issued token is
logged**, and none of the objects that hold them has a `toString` that would
put one in an exception message. Key ids, user names and client ids are logged
by design - they are what makes a failed sign-in diagnosable.

An unhandled exception is rendered by `MintErrors` into an error body; it
carries the message, and the messages this code raises name inputs - an
algorithm, a kid, a client id - not secrets.

## 7 - What leaves the machine

**Nothing the service initiates.** It makes no outbound connection of any kind:
no telemetry, no update check, no remote JWKS fetch, no callback. Everything
that leaves is a response to a request that arrived.

What a response can carry is the whole point and is listed in section 3: public
keys to anyone, private keys and administrative detail behind the admin
credential, and a signed token to anyone who asks `/mint`.

## 8 - What privileges are needed

None beyond an ordinary user account. The service does not need root, writes
only under the key directory, binds one unprivileged port, and installs
nothing. `build.sh` and `test.sh` write only into `target/` and the local
Maven repository.

## 9 - What third-party code is present

Nothing is vendored. Everything is a declared Maven dependency, resolved from
Central:

| what | version | why |
| --- | --- | --- |
| Spring Boot (web starter) | 3.5.16 | the HTTP server and wiring |
| Nimbus JOSE+JWT | 9.40 | every JOSE operation in `oidc-core` |
| springdoc-openapi (webmvc-ui) | 2.8.17 | the OpenAPI document and Swagger UI |
| Jackson | via the Boot BOM | JSON, including the three stores |
| Raposza Design | 0.4.0 | the fonts, colour tokens and logo of the web UI and the sign-in page, served from its jar; it carries Inter (SIL Open Font License 1.1) and Hack (MIT with the Bitstream Vera License) |

`oidc-core` depends on Nimbus and the JDK and nothing else, deliberately: it is
also a dependency of `raposza-auth` in the Raposza tree, and a module that
dragged Spring in could not be.

**The web UI carries no JavaScript framework and loads nothing from a CDN.**
It is hand-written HTML, CSS and plain JavaScript served from the jar - D-774 -
so there is no npm tree under it and no third-party script in the page.

## 10 - How a release is built, and how a consumer verifies it

`mvn -Prelease deploy` from a clean tree. The build attaches a sources jar and
a javadoc jar to each module, GPG-signs every file, and uploads the bundle to
the Maven Central portal. `autoPublish` is FALSE: the bundle waits there and is
released by hand, because a coordinate on Central can never be replaced, only
superseded.

A consumer verifies an artefact the way Central intends: the `.sha1` and `.md5`
beside it, and the `.asc` signature against the public key published on a
keyserver. Nothing in this project asks anyone to trust a download from
anywhere else.

The version in the tree is a `-SNAPSHOT` at all times except at the moment of a
release.

## 11 - Known limitations

These are the things a reviewer would otherwise have to find. They are not
bugs; every one is a deliberate consequence of what this is for.

* **L-1 `/mint` has no authentication and will not get any.** Anyone who can
  reach the port can obtain a token for any subject, audience and claim set
  this issuer signs. It is the endpoint the product exists to provide.
* **L-2 The private key set is served over HTTP** to whoever holds the admin
  credential - and to everyone when no password is set. There is no
  configuration in which this service cannot hand out its signing keys.
* **L-3 User passwords, client secrets and user claims are stored in clear**,
  and passwords and secrets are compared in clear. No hashing, no policy, no
  lockout, no MFA, no throttling of attempts.
* **L-4 There is no general revocation and no audit trail.** A token cannot be
  withdrawn, and nothing records what was issued or to whom. The one
  exception, a reused code, reaches UserInfo only - section 5.
* **L-5 The admin credential is Basic over plain HTTP.** Without a TLS
  terminator in front, it is on the wire in base64 on every guarded request.
* **L-6 An empty client registry accepts any client.** That is the compatible
  default for existing deployments, and it is the state in which this service
  differs most from a real provider. Register a client to close it.
* **L-7 CORS is open on every path**, so any page in a browser that can reach
  the service can call `/mint` and read the token.
* **L-8 was the two standard-endpoint deviations, and they are gone.** The
  token endpoint refused nothing before: a JSON body was accepted where RFC
  6749 section 3.2 specifies form encoding, and an unknown `grant_type` fell
  through to the mint instead of answering `unsupported_grant_type`. Both are
  now refused by name - 415 and 400 - and the arbitrary-token path a JSON body
  used to reach is `/mint`, where it always was. Kept as L-8 rather than
  renumbered, because the ids are cited elsewhere.
* **L-9 The bind address is every interface by default.** Section 3 and
  `README.md` say what to set. The issuer is NOT resolved from the machine's
  addresses since 0.4.0: `raposza.jwtmint.issuer` is required and the service
  refuses to start without it. Until then a blank issuer was guessed, and on a
  workstation running a container network the guess advertised the pod
  network's own address.
* **L-10 The key files are rewritten in place, not moved into place**, so a
  concurrent reader can see a partial document and the two halves of the set
  disagree for the length of one write; and on a first generation the private
  file exists with the umask's permissions until `restrictToOwner` runs.
  Section 4 has the detail. Nothing serves a path into the key directory, so
  neither is reachable from the network.

## 12 - The trust boundary, stated plainly

The sections above answer what the service does. This one answers the question
a reviewer asks first and which the rest of this document had left implicit:
**who is being defended against, and who is not.**

**INSIDE the boundary - trusted completely, and no control here limits them.**

* Anyone who can reach the port. `/mint` hands them a token for any subject,
  any audience and any claim set, signed by the key every consumer of this
  issuer trusts. There is no configuration that changes this - L-1.
* Anyone who can read the key directory. The private set is a file on disk,
  narrowed to the owner but not encrypted and not held in a KMS.
* Anyone who can set the service's configuration. It chooses where the keys
  live, who may sign in, and what the issuer claims to be.
* The relying parties. Nothing here authenticates a participant, a validator or
  a scribe; they are given a key set and a token and are trusted to check them.

**OUTSIDE the boundary - what the controls in this tree actually stop.**

* A passer-by on the same network CHANGING the keys, the users or the clients,
  or reading the private set - the admin credential, section 3, and only when a
  password is set.
* A relying party built against this service being accidentally more permissive
  than one built against a real provider - the client registry, section 3. That
  is correctness rather than defence, and it is the reason the registry exists.
* A sign-in with a wrong password being found one byte at a time - the
  constant-time comparisons, section 5. There is no lockout behind it, so this
  is a narrow property and not a defence against guessing.
* A key file readable by another account on the same machine, after the window
  L-10 describes.

**WHAT THIS MEANS FOR A DEPLOYMENT.** The service belongs on a machine and a
network whose reach you control. Behind a proxy, the proxy is where a reachable
deployment is narrowed - `README.md` refuses `/oauth2/jwks-private` there and
says why. Nothing in this tree is a substitute for that, and no future version
of it will be: the property that makes this useful for testing is exactly the
property that makes it unsafe to expose.
