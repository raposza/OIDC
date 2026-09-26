// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The standard claims and the scopes that release them - OpenID Connect Core
 * 1.0 sections 5.1 and 5.4.
 *
 * <h2>Why a user carries them at all</h2>
 *
 * Until 0.4.0 a user was a name and a password, and `scopes_supported` named
 * `openid` and the ledger scope only, so the conformance suite skipped its five
 * scope modules. A relying party written against a real provider asks for
 * `profile` and `email` and reads `name` and `email` back; one written against
 * this service could not, and would meet those claims for the first time in
 * production. Fidelity is the product, so the claims exist - and they are
 * released exactly as Core 5.4 says: a claim only when its scope was asked for.
 *
 * <h2>Where they go</h2>
 *
 * A SCOPE releases its claims at UserInfo only - Core 5.4: with a response
 * type that issues an access token they are returned from UserInfo. 0.4.0's
 * first cut put them in the ID token as well, as Keycloak does by default, and
 * the conformance suite warned on `oidcc-scope-email` and
 * `oidcc-alternate-happy-flow` that it had not asked for them there - plan
 * `68llSh7PcLcKx`, 2026-09-26.
 *
 * The `claims` REQUEST PARAMETER - Core 5.5 - names claims per destination,
 * `userinfo` and `id_token`, and each is released where it was asked for.
 * That is how a relying party gets `name` in its ID token, and how
 * `oidcc-claims-essential` asks for `name` without the `profile` scope.
 *
 * <h2>Nothing is invented</h2>
 *
 * A claim is released only when the user HAS it. A user with no `email` asked
 * for `email` gets no `email` - never a made-up one. `preferred_username` is
 * the one exception, and it predates this class: it defaults to the name.
 *
 * Author Claude/bentzn
 */
public final class OidcClaims {

    public static final String STR_SCOPE_PROFILE = "profile";

    public static final String STR_SCOPE_EMAIL = "email";

    public static final String STR_SCOPE_ADDRESS = "address";

    public static final String STR_SCOPE_PHONE = "phone";

    /** Core 5.4, in the order the specification lists them. */
    private static final Map<String, List<String>> MAP_SCOPE_CLAIMS;

    /** Core 5.5: where a requested claim is to be returned. */
    public static final String STR_TARGET_USERINFO = "userinfo";

    public static final String STR_TARGET_ID_TOKEN = "id_token";

    private static final ObjectMapper mapper = new ObjectMapper();

    static {
        Map<String, List<String>> map = new LinkedHashMap<>();
        map.put(STR_SCOPE_PROFILE, List.of("name", "family_name", "given_name", "middle_name",
                "nickname", "preferred_username", "profile", "picture", "website", "gender",
                "birthdate", "zoneinfo", "locale", "updated_at"));
        map.put(STR_SCOPE_EMAIL, List.of("email", "email_verified"));
        map.put(STR_SCOPE_ADDRESS, List.of("address"));
        map.put(STR_SCOPE_PHONE, List.of("phone_number", "phone_number_verified"));
        MAP_SCOPE_CLAIMS = Collections.unmodifiableMap(map);
    }


    private OidcClaims() {
    }


    /**
     * @return the four scopes that release standard claims, Core 5.4
     */
    public static List<String> lstScope() {
        return List.copyOf(MAP_SCOPE_CLAIMS.keySet());
    }


    /**
     * @return every standard claim a user may carry - Core 5.1 without `sub`,
     *         which is the user's name and is never stored as a claim
     */
    public static Set<String> setClaim() {
        Set<String> set = new LinkedHashSet<>();
        for (List<String> lst : MAP_SCOPE_CLAIMS.values()) {
            set.addAll(lst);
        }
        return Collections.unmodifiableSet(set);
    }


    /**
     * The `claims` request parameter, Core 5.5.
     *
     * Only the NAMES are read. `essential` and `value` are accepted and not
     * enforced: a claim the user carries is released whether or not it was
     * essential, and one it does not carry is left out, which Core 5.5.1 allows
     * for an essential claim as much as a voluntary one.
     *
     * @param strClaims the parameter as sent, or null
     * @return target to the standard claim names asked for there; empty for
     *         none; never null
     * @throws IllegalArgumentException when it is not a JSON object whose
     *         `userinfo` and `id_token` members, where present, are objects
     */
    public static Map<String, Set<String>> mapRequested(String strClaims) {
        Map<String, Set<String>> mapOut = new LinkedHashMap<>();
        if (strClaims == null || strClaims.isBlank())
            return mapOut;

        JsonNode node;
        try {
            node = mapper.readTree(strClaims);
        }
        catch (java.io.IOException ex) {
            throw new IllegalArgumentException("claims is not JSON");
        }
        if (node == null || !node.isObject())
            throw new IllegalArgumentException("claims is not a JSON object");

        Set<String> setKnown = setClaim();
        for (String strTarget : List.of(STR_TARGET_USERINFO, STR_TARGET_ID_TOKEN)) {
            JsonNode nodeTarget = node.get(strTarget);
            if (nodeTarget == null || nodeTarget.isNull())
                continue;
            if (!nodeTarget.isObject())
                throw new IllegalArgumentException("claims." + strTarget + " is not a JSON object");
            Set<String> set = new LinkedHashSet<>();
            for (Iterator<String> it = nodeTarget.fieldNames(); it.hasNext();) {
                String strName = it.next();
                if (setKnown.contains(strName))
                    set.add(strName);
            }
            mapOut.put(strTarget, Collections.unmodifiableSet(set));
        }
        return mapOut;
    }


    /**
     * @param setName claim names asked for by name
     * @param mapUser the claims the user carries
     * @return those the user has, in the order asked
     */
    public static Map<String, Object> mapNamed(Set<String> setName, Map<String, Object> mapUser) {
        Map<String, Object> mapOut = new LinkedHashMap<>();
        if (setName == null || mapUser == null)
            return mapOut;
        for (String strName : setName) {
            if (mapUser.containsKey(strName))
                mapOut.put(strName, mapUser.get(strName));
        }
        return mapOut;
    }


    /**
     * @param strScope the space-separated scope a token was issued for, or null
     * @param mapUser the claims the user carries, possibly empty
     * @return the claims that scope releases and the user has, in the
     *         specification's order; empty when none
     */
    public static Map<String, Object> mapReleased(String strScope, Map<String, Object> mapUser) {
        Map<String, Object> mapOut = new LinkedHashMap<>();
        if (strScope == null || mapUser == null || mapUser.isEmpty())
            return mapOut;
        for (Map.Entry<String, List<String>> entScope : MAP_SCOPE_CLAIMS.entrySet()) {
            if (!OidcFlow.hasScope(strScope, entScope.getKey()))
                continue;
            for (String strClaim : entScope.getValue()) {
                if (mapUser.containsKey(strClaim))
                    mapOut.put(strClaim, mapUser.get(strClaim));
            }
        }
        return mapOut;
    }

}
