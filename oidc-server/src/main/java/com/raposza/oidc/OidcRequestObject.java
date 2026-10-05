// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The `request` parameter - OpenID Connect Core 1.0 section 6.1 - unsigned.
 *
 * <h2>Why it is processed rather than refused, since 0.4.0</h2>
 *
 * 0.3.0 refused every request object with `request_not_supported`, which Core
 * permits. The conformance suite then SKIPS its request-object module, because
 * a refusal leaves nothing to test, so the OP Basic plan could not be run
 * complete. Keycloak processes request objects, so a relying party that sends
 * one works there; it now works here too.
 *
 * <h2>Unsigned only</h2>
 *
 * `alg: none` is what discovery advertises and what is read. A SIGNED object
 * would need the client's own keys, which this service does not hold, and an
 * encrypted one its decryption key; both are answered `invalid_request_object`
 * by name rather than read past. An unsigned object carries exactly the trust
 * of the query string it arrives in, so accepting it grants nothing the query
 * did not already.
 *
 * <h2>What wins</h2>
 *
 * The object's parameters supersede the query's - Core 6.1 - so `state`,
 * `nonce`, `redirect_uri` and `scope` inside it are the ones used. `client_id`
 * and `response_type` must still be in the query, and when the object carries
 * them too they must be the same values. Only string, number and boolean
 * members become parameters; a structured member such as `claims` is not a
 * parameter this service reads and is left out.
 *
 * <h2>Never a name or a password - 0.5.0</h2>
 *
 * `username` and `password` are this service's sign-in form fields, not
 * request parameters, and an object carrying them was until 0.5.0 a way to sign
 * in with credentials in the address - which every proxy and access log on the
 * way writes down. They are dropped from the object;
 * {@link OidcController} refuses them in the query.
 *
 * Author Claude/bentzn
 */
final class OidcRequestObject {

    /** The parameter this class reads. */
    static final String STR_PARAM = "request";

    /** The sign-in form's fields, which an object never supplies. */
    static final Set<String> SET_CREDENTIAL = Set.of("username", "password");


    /**
     * @param mapParam the request's parameters, with the object merged in
     * @param strError why the object cannot be used, or null when it can -
     *        answered `invalid_request_object` once the redirect is trusted
     */
    record Merged(Map<String, String> mapParam, String strError) {
    }


    private OidcRequestObject() {
    }


    /**
     * @param mapQuery the parameters as they arrived
     * @return them unchanged when there is no `request`; otherwise with the
     *         object's members superseding them and `request` itself removed
     */
    static Merged merge(Map<String, String> mapQuery) {
        String strRequest = mapQuery.get(STR_PARAM);
        if (strRequest == null)
            return new Merged(mapQuery, null);

        Map<String, String> mapOut = new LinkedHashMap<>(mapQuery);
        mapOut.remove(STR_PARAM);

        JWT jwt;
        try {
            jwt = JWTParser.parse(strRequest.trim());
        }
        catch (ParseException ex) {
            return new Merged(mapOut, "the request object is not a JWT");
        }
        if (!(jwt instanceof PlainJWT))
            return new Merged(mapOut, "only an unsigned request object, alg none, is supported");

        Map<String, Object> mapClaim;
        try {
            mapClaim = jwt.getJWTClaimsSet().getClaims();
        }
        catch (ParseException ex) {
            return new Merged(mapOut, "the request object's claims cannot be read");
        }

        for (Map.Entry<String, Object> entClaim : mapClaim.entrySet()) {
            Object objValue = entClaim.getValue();
            if (!(objValue instanceof String || objValue instanceof Number || objValue instanceof Boolean))
                continue;
            String strKey = entClaim.getKey();
            if (SET_CREDENTIAL.contains(strKey))
                continue;
            String strValue = String.valueOf(objValue);
            String strQuery = mapQuery.get(strKey);
            if (("client_id".equals(strKey) || "response_type".equals(strKey))
                    && strQuery != null && !strQuery.equals(strValue)) {
                return new Merged(mapOut, strKey + " in the request object is not the one in the request");
            }
            mapOut.put(strKey, strValue);
        }
        return new Merged(mapOut, null);
    }

}
