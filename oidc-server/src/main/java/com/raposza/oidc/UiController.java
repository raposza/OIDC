// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.raposza.jwt.MintAlg;
import com.raposza.jwt.MintKeys;
import com.raposza.jwt.TokenException;

import com.nimbusds.jose.jwk.JWK;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Everything the web UI calls, and nothing else calls.
 *
 * <h2>The UI is a client of this API and has no other way in</h2>
 *
 * The pages are static HTML and JavaScript. They hold no key material, no
 * password and no state that outlives a reload; every answer on the screen came
 * from one of the calls below. That is what keeps the UI from becoming a second
 * source of truth about what this service is doing - `raposza_oidc.md`
 * section 8.
 *
 * <h2>Behind the admin credential, all of it bar the sign-in</h2>
 *
 * {@link AdminGuard} guards `/api/ui/*`. The one exception is `/api/ui/login`,
 * which cannot require what it exists to establish.
 *
 * <h2>What is deliberately NOT here</h2>
 *
 * Minting. The UI's Mint page posts to `/mint` like any other caller, so what
 * the page can ask for is exactly what a script can ask for and there is no
 * second code path to keep in step.
 *
 * Author Claude/bentzn
 */
@RestController
@Tag(name = "ui", description = "The web UI's own API. Not a stable interface -"
        + " it moves with the pages.")
public final class UiController {

    private final MintKeyStore store;

    private final OidcUsers users;

    private final OidcClients clients;

    private final MintSettings settings;

    private final IssuerResolver resolver;

    private final AdminGuard guard;


    public UiController(MintKeyStore store, OidcUsers users, OidcClients clients,
            MintSettings settings, IssuerResolver resolver, AdminGuard guard) {
        this.store = store;
        this.users = users;
        this.clients = clients;
        this.settings = settings;
        this.resolver = resolver;
        this.guard = guard;
    }


    @Operation(summary = "The web UI",
            description = "A redirect to the page itself. Spring serves a"
                    + " welcome `index.html` for `/` and for no other"
                    + " directory, so `/ui/` would otherwise be a 404 while"
                    + " `/ui/index.html` worked.")
    @GetMapping({"/ui", "/ui/"})
    public ResponseEntity<Void> page() {
        return ResponseEntity.status(HttpStatus.FOUND)
                .header("Location", "/ui/index.html").build();
    }


    @Operation(summary = "Sign in to the UI",
            description = "The only unguarded path under `/api/ui/`. A script"
                    + " does not need it - HTTP Basic works on every call here.")
    @PostMapping("/api/ui/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody Map<String, String> mapIn,
            HttpServletRequest req) {
        String strUser = mapIn == null ? null : mapIn.get("user");
        String strPassword = mapIn == null ? null : mapIn.get("password");

        if (!guard.flagCredential(strUser, strPassword)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(mapOne("error", "that is not the admin credential"));
        }

        // A NEW SESSION per sign-in, so a fixed cookie handed to the browser
        // beforehand cannot become a signed-in one.
        HttpSession sessionOld = req.getSession(false);
        if (sessionOld != null)
            sessionOld.invalidate();
        req.getSession(true).setAttribute(AdminGuard.STR_ATTR_SIGNED_IN, Boolean.TRUE);

        return ResponseEntity.ok(mapOne("signed_in", true));
    }


    @Operation(summary = "Sign out")
    @PostMapping("/api/ui/logout")
    public Map<String, Object> logout(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        if (session != null)
            session.invalidate();
        return mapOne("signed_in", false);
    }


    @Operation(summary = "What this service is and where it is",
            description = "The issuer, whether it is pinned, where the keys are,"
                    + " and every url a consumer is given.")
    @GetMapping("/api/ui/overview")
    public Map<String, Object> mapOverview() {
        MintKeys keys = store.keys();

        Map<String, Object> mapUrl = new LinkedHashMap<>();
        mapUrl.put("discovery_oidc", resolver.strUrl(IssuerResolver.STR_PATH_DISCOVERY_OIDC));
        mapUrl.put("discovery_oauth", resolver.strUrl(IssuerResolver.STR_PATH_DISCOVERY_OAUTH));
        mapUrl.put("jwks", resolver.strUrl(IssuerResolver.STR_PATH_JWKS));
        mapUrl.put("token", resolver.strUrl(IssuerResolver.STR_PATH_TOKEN));
        mapUrl.put("authorize", resolver.strUrl(IssuerResolver.STR_PATH_AUTHORIZE));
        mapUrl.put("userinfo", resolver.strUrl(IssuerResolver.STR_PATH_USERINFO));
        mapUrl.put("logout", resolver.strUrl(IssuerResolver.STR_PATH_LOGOUT));

        Map<String, Object> mapOut = new LinkedHashMap<>();
        mapOut.put("issuer", resolver.strIssuer());
        mapOut.put("issuer_pinned", resolver.flagPinned());
        mapOut.put("standalone", settings.flagStandalone());
        mapOut.put("admin_credential_set", settings.flagAdminSet());
        mapOut.put("dir_keys", String.valueOf(keys.dirKeys()));
        mapOut.put("file_users", String.valueOf(users.fileStore()));
        mapOut.put("keys_loaded", String.valueOf(keys.instLoaded()));
        mapOut.put("count_keys", keys.lstKid().size());
        mapOut.put("count_users", users.lstName().size());
        mapOut.put("file_clients", String.valueOf(clients.fileStore()));
        mapOut.put("count_clients", clients.lstId().size());
        mapOut.put("clients_strict", clients.flagStrict());
        mapOut.put("default_alg", settings.algDefault().name());
        mapOut.put("default_ttl_seconds", settings.nTtlSecondsDefault());
        mapOut.put("urls", mapUrl);
        return mapOut;
    }


    @Operation(summary = "Every key in the set",
            description = "EVERY key, not only the standard twelve `/keys`"
                    + " lists - a key added here appears here and nowhere else."
                    + " No key material is returned.")
    @GetMapping("/api/ui/keys")
    public List<Map<String, Object>> lstKeys() {
        MintKeys keys = store.keys();
        List<Map<String, Object>> lstOut = new ArrayList<>();

        for (JWK jwk : keys.lstJwk()) {
            String strKid = jwk.getKeyID();
            KeyRow row = KeyRow.of(strAlgOf(strKid), jwk);

            Map<String, Object> mapRow = new LinkedHashMap<>();
            mapRow.put("kid", row.kid());
            mapRow.put("alg", row.alg());
            mapRow.put("kty", row.kty());
            mapRow.put("detail", row.detail());
            mapRow.put("published", row.published());
            mapRow.put("standard", MintKeys.flagStandardKid(strKid));
            mapRow.put("thumbprint", strThumbprint(jwk));
            lstOut.add(mapRow);
        }
        return lstOut;
    }


    @Operation(summary = "Re-read the JWKS from disk")
    @PostMapping("/api/ui/keys/reload")
    public Map<String, Object> mapReload() {
        return mapKeys(store.reload(), "reloaded from disk");
    }


    @Operation(summary = "Replace one key's material, keeping its id",
            description = "**Every token already signed with it stops"
                    + " verifying**, and every participant holding the old"
                    + " public half has to re-read the JWKS.")
    @PostMapping("/api/ui/keys/{strKid}/rotate")
    public Map<String, Object> mapRotate(@PathVariable String strKid) {
        return mapKeys(store.rotate(strKid), "rotated " + strKid);
    }


    @Operation(summary = "Add a key under an id of your own",
            description = "`kid` and `alg`. The standard twelve are generated"
                    + " for you and cannot be added again; this is for a key a"
                    + " consumer expects under a name of its own.")
    @PostMapping("/api/ui/keys")
    public Map<String, Object> mapAdd(@RequestBody Map<String, String> mapIn) {
        String strKid = mapIn == null ? null : mapIn.get("kid");
        String strAlg = mapIn == null ? null : mapIn.get("alg");
        return mapKeys(store.add(strKid, strAlg), "added " + strKid);
    }


    @Operation(summary = "Remove a key that is not one of the standard set",
            description = "A standard key is REFUSED: the next load generates"
                    + " it again, so the removal would not hold.")
    @DeleteMapping("/api/ui/keys/{strKid}")
    public Map<String, Object> mapRemove(@PathVariable String strKid) {
        return mapKeys(store.remove(strKid), "removed " + strKid);
    }


    @Operation(summary = "Who can sign in", description = "Names only.")
    @GetMapping("/api/ui/users")
    public Map<String, Object> mapUsers() {
        Map<String, Object> mapOut = new LinkedHashMap<>();
        mapOut.put("file", String.valueOf(users.fileStore()));
        mapOut.put("names", users.lstName());
        return mapOut;
    }


    @Operation(summary = "Add a user or change its password",
            description = "`name` and `password`. The name is the `sub` of"
                    + " every token issued to that person.")
    @PostMapping("/api/ui/users")
    public Map<String, Object> mapPutUser(@RequestBody Map<String, String> mapIn) {
        String strName = mapIn == null ? null : mapIn.get("name");
        String strPassword = mapIn == null ? null : mapIn.get("password");

        boolean flagNew = users.flagPut(strName, strPassword);
        Map<String, Object> mapOut = new LinkedHashMap<>();
        mapOut.put("added", flagNew);
        mapOut.put("names", users.lstName());
        return mapOut;
    }


    @Operation(summary = "Remove a user")
    @DeleteMapping("/api/ui/users/{strName}")
    public Map<String, Object> mapRemoveUser(@PathVariable String strName) {
        boolean flagGone = users.flagRemove(strName);
        if (!flagGone)
            throw new TokenException("no user '" + strName + "'");

        Map<String, Object> mapOut = new LinkedHashMap<>();
        mapOut.put("removed", true);
        mapOut.put("names", users.lstName());
        return mapOut;
    }


    @Operation(summary = "The registered clients",
            description = "Ids and redirect URIs. NO SECRETS are returned."
                    + " While this list is EMPTY nothing is checked and any"
                    + " client_id, any redirect_uri and any secret are accepted"
                    + " - which a real OpenID Provider refuses.")
    @GetMapping("/api/ui/clients")
    public Map<String, Object> mapClients() {
        List<Map<String, Object>> lstRow = new ArrayList<>();
        for (String idClient : clients.lstId()) {
            OidcClient client = clients.client(idClient);
            Map<String, Object> mapRow = new LinkedHashMap<>();
            mapRow.put("client_id", idClient);
            mapRow.put("auth", client.flagPublic() ? "none (public)" : "client_secret");
            mapRow.put("redirect_uris", client.lstRedirect());
            lstRow.add(mapRow);
        }

        Map<String, Object> mapOut = new LinkedHashMap<>();
        mapOut.put("file", String.valueOf(clients.fileStore()));
        mapOut.put("strict", clients.flagStrict());
        mapOut.put("clients", lstRow);
        return mapOut;
    }


    @Operation(summary = "Register a client, or replace one",
            description = "`client_id`, `secret` - blank for a public client -"
                    + " and `redirect_uris`, whitespace separated. Registering"
                    + " the FIRST client turns the checks on for every client.")
    @PostMapping("/api/ui/clients")
    public Map<String, Object> mapPutClient(@RequestBody Map<String, String> mapIn) {
        String idClient = mapIn == null ? null : mapIn.get("client_id");
        String strSecret = mapIn == null ? null : mapIn.get("secret");
        String strUris = mapIn == null ? "" : String.valueOf(mapIn.get("redirect_uris"));

        List<String> lstUri = new ArrayList<>();
        for (String strUri : strUris.trim().split("\s+")) {
            if (!strUri.isEmpty())
                lstUri.add(strUri);
        }

        boolean flagNew = clients.flagPut(idClient, strSecret, lstUri);
        Map<String, Object> mapOut = new LinkedHashMap<>();
        mapOut.put("added", flagNew);
        mapOut.put("strict", clients.flagStrict());
        return mapOut;
    }


    @Operation(summary = "Remove a client",
            description = "Removing the LAST one reopens the service: with no"
                    + " client registered nothing is checked.")
    @DeleteMapping("/api/ui/clients/{idClient}")
    public Map<String, Object> mapRemoveClient(@PathVariable String idClient) {
        if (!clients.flagRemove(idClient))
            throw new TokenException("no client '" + idClient + "'");

        Map<String, Object> mapOut = new LinkedHashMap<>();
        mapOut.put("removed", true);
        mapOut.put("strict", clients.flagStrict());
        return mapOut;
    }


    @Operation(summary = "What a token says, and which key set signed it",
            description = "`token`, as pasted. An EXPIRED token is described"
                    + " rather than refused - minting one is something this"
                    + " service is asked to do.\n\n"
                    + "`jwks` is optional and is the question people actually"
                    + " have: what a participant accepts depends on the set its"
                    + " `auth-services` block names, which may be an older copy"
                    + " of this one, a different mint, or Keycloak. Paste that"
                    + " set and both answers come back - `verified` for this"
                    + " service's keys, `foreign_verified` for yours.")
    @PostMapping("/api/ui/inspect")
    public Map<String, Object> mapInspect(@RequestBody Map<String, String> mapIn) {
        return TokenInspect.mapOf(mapIn == null ? null : mapIn.get("token"),
                store.keys(), mapIn == null ? null : mapIn.get("jwks"));
    }


    private Map<String, Object> mapKeys(MintKeys keys, String strWhat) {
        Map<String, Object> mapOut = new LinkedHashMap<>();
        mapOut.put("done", strWhat);
        mapOut.put("kids", keys.lstKid());
        mapOut.put("loaded", String.valueOf(keys.instLoaded()));
        return mapOut;
    }


    private static String strAlgOf(String strKid) {
        for (MintAlg alg : MintAlg.values()) {
            if (alg.flagSigned() && alg.strKid().equals(strKid))
                return alg.name();
        }
        return "-";
    }


    private static String strThumbprint(JWK jwk) {
        try {
            return jwk.computeThumbprint().toString();
        }
        catch (Exception ex) {
            // A thumbprint is an aid to telling two keys apart, not something
            // any decision rests on. Its absence is not a failed request.
            return "-";
        }
    }


    private static Map<String, Object> mapOne(String strKey, Object objValue) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put(strKey, objValue);
        return map;
    }

}
