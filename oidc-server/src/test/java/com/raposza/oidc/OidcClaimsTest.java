// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Core 5.4: a scope releases its own claims, only its own, and only those the
 * user has.
 *
 * Author Claude/bentzn
 */
class OidcClaimsTest {

    private static Map<String, Object> mapAlice() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("name", "Alice Doe");
        map.put("email", "alice@example.com");
        map.put("email_verified", Boolean.TRUE);
        map.put("address", Map.of("country", "PT"));
        map.put("phone_number", "+351 000 000 000");
        return map;
    }


    @Test
    void eachScopeReleasesItsOwnClaimsOnly() {
        assertEquals(Map.of("name", "Alice Doe"), OidcClaims.mapReleased("openid profile", mapAlice()));
        assertEquals(Map.of("email", "alice@example.com", "email_verified", Boolean.TRUE),
                OidcClaims.mapReleased("openid email", mapAlice()));
        assertEquals(Map.of("address", Map.of("country", "PT")),
                OidcClaims.mapReleased("address", mapAlice()));
        assertEquals(Map.of("phone_number", "+351 000 000 000"),
                OidcClaims.mapReleased("phone", mapAlice()));
        assertEquals(5, OidcClaims.mapReleased("openid profile email address phone", mapAlice()).size());
    }


    @Test
    void noScopeOrNoClaimReleasesNothing() {
        assertTrue(OidcClaims.mapReleased("openid daml_ledger_api", mapAlice()).isEmpty());
        assertTrue(OidcClaims.mapReleased(null, mapAlice()).isEmpty());
        assertTrue(OidcClaims.mapReleased("openid profile email", Map.of()).isEmpty());
    }


    @Test
    void theFourScopesAndTheirClaimsAreCore54() {
        assertEquals(List.of("profile", "email", "address", "phone"), OidcClaims.lstScope());
        assertTrue(OidcClaims.setClaim().containsAll(List.of("name", "given_name", "family_name",
                "email", "email_verified", "address", "phone_number", "phone_number_verified",
                "updated_at", "preferred_username")));
        assertFalse(OidcClaims.setClaim().contains("sub"));
    }

}
