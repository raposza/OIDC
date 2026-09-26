<!-- Copyright (c) 2026 bentzn -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Raposza OIDC

A small OpenID Provider for development and test systems. It holds a JWKS,
serves an OpenID Connect and OAuth 2.0 surface against it, signs people in
from a user list, and mints arbitrary tokens on request.

**Passes the OpenID Foundation OP Basic conformance plan - 0 failures, 0 warnings.**

**IT IS NOT A PRODUCTION IDENTITY PROVIDER AND IS NOT A REPLACEMENT FOR ONE.**
It publishes its own private keys on request, mints a token for any subject
with any claims, and stores its users' passwords in clear. It speaks the same
protocol as a real provider so that a relying party configured against it moves
to Keycloak by changing settings and nothing else - and that is the whole of
what it promises.

`SECURITY.md` is the short statement of the model and the reporting channel;
`docs/security-review.md` is the posture in full.

## Using it

```xml
<dependency>
    <groupId>com.raposza.oidc</groupId>
    <artifactId>raposza-oidc-core</artifactId>
    <version>0.4.0</version>
</dependency>
```

`raposza-oidc-core` is the JOSE library - Nimbus and the JDK, no Spring and no
web. `raposza-oidc-server` is the service; take it as a dependency to embed it,
or take its `app` classifier, which is a runnable Spring Boot jar:

```
java -jar raposza-oidc-server-0.4.0-app.jar --raposza.jwtmint.issuer=http://127.0.0.1:32002
```

The issuer is the address consumers reach the service on. From 0.4.0 it is
REQUIRED and the service refuses to start without it; 0.3.0 guessed it from
the machine's own addresses when it was not given.

## What it serves

```
GET  /oauth2/jwks                          the public JWKS
GET  /jwks.json                            the same
GET  /oauth2/jwks-private                  the FULL set, private members and all
GET  /jwks-private.json                    the same
GET  /keys                                 algorithm, kid and key size per key
GET  /keys.txt                             the same, one line per key
GET  /.well-known/openid-configuration     the OpenID Provider configuration
GET  /.well-known/oauth-authorization-server   the same document, RFC 8414
GET  /oauth2/authorize                     sign in - the login page, then a code
POST /oauth2/token                         authorization_code, refresh_token,
                                           client_credentials; form or JSON.
                                           Also answers at /oauth/token, /token
GET  /oauth2/userinfo                      the signed-in user, and the claims the scope releases
GET  /oauth2/logout                        back to post_logout_redirect_uri, when it is
                                           registered for the client
POST /mint                                 a token from an explicit claims request
GET  /mint                                 the same through query parameters
GET  /mint.txt                             the same, the bare token as text
GET  /admin/status                         where the keys are and when they loaded
POST /admin/reload                         re-read the JWKS from disk
GET  /admin/reload                         the same
GET  /ui/                                  the web UI
     /api/ui/*                             what the UI calls; a script may too
GET  /swagger-ui.html                      every endpoint, with runnable examples
```

**The non-standard endpoints are deliberate and permanent.** `/mint`,
`/keys`, the private JWKS and `/api/ui/*` are why this service exists. Nothing
that speaks only OpenID Connect will call them, which is exactly why they cost
a consumer nothing on the day it is pointed at a real provider.

## The web UI

`/ui/` - six pages over the API above, and nothing it can ask for that a
script cannot.

| page | what it does |
| --- | --- |
| Overview | the issuer, where the keys, users and clients are, and every url a consumer is given |
| Keys | every key with its algorithm, type and thumbprint; rotate, add, delete, reload |
| Users | who can sign in, and their standard claims; add, change, delete |
| Clients | registered `client_id`s and their redirect URIs; register, replace, remove. NO SECRET is ever returned |
| Mint | a form over `/mint`, with the token decoded beside it |
| Inspect | paste a token: header, claims, expiry, whether THIS key set signed it - and, if you paste a JWKS, whether THAT one does |

Key, user and client management need the admin credential -
`raposza.jwtmint.admin.user` and `.admin.password`. With no password set they
are open, and the Overview page says so in as many words. A standalone
service refuses to start in that state.

**A signed-in browser session does not authorise a write on its own.** The
UI sends `X-Raposza-UI` with every call, and a write - any method but GET and
HEAD, and `/admin/reload` whatever its method - that arrives on the session
without it is refused with 403. A script uses HTTP Basic and needs no header.

**Inspect is the page that earns its place.** Every authentication failure
this project has had was an issuer that did not match, an audience that did
not match, or a key that was not the one that signed - and a participant
reports all three the same way, as a refusal with no detail. The JWKS field
answers the question directly: paste the set the participant actually trusts,
and the page says whether that set verifies the token.

## The client registry

**While no client is registered, nothing is checked**: any `client_id`, any
`redirect_uri`, any or no `client_secret` is accepted. That is the compatible
default and the service warns about it at startup. Registering the first
client turns on all three checks, for every client; removing the last reopens
it.

```
raposza.jwtmint.clients=wallet-ui||http://wallet.localhost:4000/cb,\
                        sv-app|s3cret|http://sv.localhost/cb
```

`id|secret|uris`, comma separated, URIs separated by spaces. **A blank secret
means a PUBLIC client**, which authenticates with `none` and is refused if it
presents a secret - because a component that sends one is configured for a
confidential client and would fail against a real provider. `redirect_uri` is
compared as a whole string, OpenID Connect Core 1.0 section 3.1.2.1: a
trailing slash is a different URI.

The setting seeds `clients.json` once; after that the file wins.

## Running it

```
./build.sh                 build and install both artefacts
./test.sh                  build, test, and prove the tests executed
./run-oidc.sh --build      build the runnable jar and start on 32002
```

## Behind a reverse proxy

TLS is terminated at the proxy; this process serves plain HTTP and holds no
keystore. **Pin the issuer to the external origin.** RFC 8414 section 3.3
compares the issuer in the discovery document and the `iss` of a token
literally, so an issuer that is not the origin the consumers reach has every
token rejected by every validator the moment a proxy is in front of it.

```
./run-oidc.sh --raposza.jwtmint.issuer=https://id.example.com
```

A worked nginx server block for that issuer:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name id.example.com;

    ssl_certificate     /etc/letsencrypt/live/id.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/id.example.com/privkey.pem;

    # The service is HTTP on the loopback of the same host. Start it with
    # --server.address=127.0.0.1 so nothing but nginx can reach it.
    location / {
        proxy_pass http://127.0.0.1:32002;
        proxy_http_version 1.1;

        # The issuer is PINNED in the service, so these are not what makes
        # the URLs right - they are what makes a redirect and a cookie right.
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
    }

    # THE PRIVATE KEY SET. This service will hand out its own signing keys to
    # anyone holding the admin credential, and to anyone at all when no
    # password is set. Refusing it at the proxy costs nothing and removes the
    # worst outcome of a misconfiguration.
    location = /oauth2/jwks-private { return 404; }
    location = /jwks-private.json   { return 404; }
}

server {
    listen 80;
    server_name id.example.com;
    return 301 https://$host$request_uri;
}
```

**That block does not authenticate anything.** It terminates TLS and hides one
path. `/mint` is still open to everyone who can reach the proxy, by design -
put the whole thing on a network you control.

## Users and their claims

A user is a name, a password and, since 0.4.0, the standard claims of OpenID
Connect Core 1.0 section 5.1 - set on the Users page or in `users.json`:

```
{ "alice": "a1",
  "bob": { "password": "b2",
           "claims": { "name": "Bob Doe", "email": "bob@example.com", "email_verified": true } } }
```

A scope releases its claims at UserInfo - `profile`, `email`, `address`,
`phone`, Core 5.4 - and the `claims` request parameter, Core 5.5, releases a
claim by name at UserInfo or in the ID token, wherever it asked. A claim the
user does not carry is never made up. A user with no claims is the
flat form, so a `users.json` from 0.3.0 is read unchanged. To run the OpenID
Foundation conformance suite's scope modules, give the user it signs in as a
claim from each of the four scopes, and for `profile` every one of its
fourteen claims: the suite checks that UserInfo carries them all.

## Settings

| key | meaning |
| --- | --- |
| `raposza.jwtmint.dir-keys` | the JWKS directory; blank is `~/.raposza/jwtmint/keys` |
| `raposza.jwtmint.issuer` | the issuer; REQUIRED from 0.4.0, and behind a proxy the external origin |
| `raposza.jwtmint.ttl-seconds` | default token lifetime, 86400 |
| `raposza.jwtmint.default-alg` | default signing algorithm, RS256 |
| `raposza.jwtmint.default-subject` | default `sub`, `raposza` |
| `raposza.jwtmint.users` | `name:password` pairs, comma separated; seeds `users.json` |
| `raposza.jwtmint.clients` | `id`, `secret`, `uris` separated by a vertical bar; entries comma separated; seeds `clients.json` |
| `raposza.jwtmint.admin.user` | the admin name, `admin` |
| `raposza.jwtmint.admin.password` | the admin password; **BLANK LEAVES THE WRITE ENDPOINTS AND THE PRIVATE JWKS OPEN** |
| `raposza.jwtmint.standalone` | true for a service on a network; refuses to start without a password |
| `server.port` | 32002 |
| `server.address` | unset, so it listens on EVERY interface |

The prefix is `raposza.jwtmint` rather than `raposza.oidc` deliberately: it is
the compatibility surface with every launcher and configuration file that
already names it.

## Licence

Apache-2.0. See `LICENSE` and `NOTICE`.
