// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * RP-initiated logout goes back only to a URI registered for the client -
 * the check a real provider makes and 0.3.0 did not. With an empty registry
 * nothing changes, like every other check the registry makes.
 *
 * Author Claude/bentzn
 */
class OidcLogoutTest {

    private static final String STR_ISSUER = "http://127.0.0.1:32002";

    private static final String STR_URI = "http://wallet.localhost:4000/cb";

    private static final String STR_ELSEWHERE = "https://elsewhere.example.com/";


    private static OidcController controller(Path dirKeys, String strClients) {
        MintSettings settings = new MintSettings(dirKeys.toString(), STR_ISSUER,
                3600L, "RS256", "raposza", "admin", "", false);
        MintKeyStore store = new MintKeyStore(settings);
        IssuerResolver resolver = new IssuerResolver(settings);
        OidcUsers users = new OidcUsers(settings, "alice:a1");
        OidcFlow flow = new OidcFlow(new MintService(store, settings), store, resolver, settings, users);
        return new OidcController(flow, users, new OidcClients(settings, strClients),
                new OidcSessions(), resolver);
    }


    @Test
    void anEmptyRegistryFollowsAnyUri(@TempDir Path dirKeys) {
        ResponseEntity<String> resp = controller(dirKeys, "")
                .logout(Map.of("post_logout_redirect_uri", STR_ELSEWHERE), null);
        assertEquals(HttpStatus.FOUND, resp.getStatusCode());
        assertEquals(STR_ELSEWHERE, resp.getHeaders().getFirst(HttpHeaders.LOCATION));
    }


    @Test
    void aRegisteredUriIsFollowed(@TempDir Path dirKeys) {
        ResponseEntity<String> resp = controller(dirKeys, "wallet-ui||" + STR_URI)
                .logout(Map.of("post_logout_redirect_uri", STR_URI, "client_id", "wallet-ui",
                        "state", "s1"), null);
        assertEquals(HttpStatus.FOUND, resp.getStatusCode());
        assertEquals(STR_URI + "?state=s1", resp.getHeaders().getFirst(HttpHeaders.LOCATION));
    }


    @Test
    void anUnregisteredUriIsRefusedAndNotFollowed(@TempDir Path dirKeys) {
        OidcController ctl = controller(dirKeys, "wallet-ui||" + STR_URI);
        ResponseEntity<String> resp = ctl.logout(Map.of("post_logout_redirect_uri", STR_ELSEWHERE,
                "client_id", "wallet-ui"), null);
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertNull(resp.getHeaders().getFirst(HttpHeaders.LOCATION));

        assertNotNull(ctl.strLogoutRefusal(Map.of("post_logout_redirect_uri", STR_URI)));
        assertNotNull(ctl.strLogoutRefusal(Map.of("post_logout_redirect_uri", STR_URI,
                "client_id", "nobody")));
    }


    @Test
    void noRedirectUriIsAPlainSignOut(@TempDir Path dirKeys) {
        ResponseEntity<String> resp = controller(dirKeys, "wallet-ui||" + STR_URI)
                .logout(Map.of(), null);
        assertEquals(HttpStatus.OK, resp.getStatusCode());
        assertEquals(List.of(), List.copyOf(resp.getHeaders().getOrEmpty(HttpHeaders.LOCATION)));
    }

}
