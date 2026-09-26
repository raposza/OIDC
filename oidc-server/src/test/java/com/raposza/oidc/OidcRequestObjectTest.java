// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;

import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 * Core 6.1: an unsigned request object's members supersede the query, the
 * two values that must match do, and anything but `alg: none` is refused by
 * name.
 *
 * Author Claude/bentzn
 */
class OidcRequestObjectTest {

    private static String strObject(JWTClaimsSet claims) {
        return new PlainJWT(claims).serialize();
    }


    @Test
    void noRequestLeavesTheParametersAlone() {
        Map<String, String> mapQuery = Map.of("client_id", "c", "state", "s");
        OidcRequestObject.Merged merged = OidcRequestObject.merge(mapQuery);
        assertEquals(mapQuery, merged.mapParam());
        assertNull(merged.strError());
    }


    @Test
    void theObjectSupersedesTheQuery() {
        String strReq = strObject(new JWTClaimsSet.Builder().claim("state", "inside")
                .claim("nonce", "n1").claim("redirect_uri", "https://rp.example.com/cb")
                .claim("max_age", 10000L).claim("claims", Map.of("userinfo", Map.of())).build());
        OidcRequestObject.Merged merged = OidcRequestObject.merge(Map.of("client_id", "c",
                "response_type", "code", "state", "outside", "request", strReq));

        assertNull(merged.strError());
        assertEquals("inside", merged.mapParam().get("state"));
        assertEquals("n1", merged.mapParam().get("nonce"));
        assertEquals("https://rp.example.com/cb", merged.mapParam().get("redirect_uri"));
        assertEquals("10000", merged.mapParam().get("max_age"));
        assertFalse(merged.mapParam().containsKey("request"));
        assertFalse(merged.mapParam().containsKey("claims"));
    }


    @Test
    void aMismatchedClientOrASignedOrBrokenObjectIsRefused() {
        String strReq = strObject(new JWTClaimsSet.Builder().claim("client_id", "other").build());
        assertNotNull(OidcRequestObject.merge(Map.of("client_id", "c", "request", strReq)).strError());

        // a JWS header with alg RS256 - not something this service can verify
        String strSigned = "eyJhbGciOiJSUzI1NiJ9.eyJzdGF0ZSI6InMifQ.c2ln";
        assertNotNull(OidcRequestObject.merge(Map.of("client_id", "c", "request", strSigned)).strError());
        assertNotNull(OidcRequestObject.merge(Map.of("client_id", "c", "request", "junk")).strError());
    }

}
