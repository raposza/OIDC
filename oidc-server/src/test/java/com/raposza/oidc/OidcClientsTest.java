// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The registry, and the three things it refuses that were accepted before it.
 *
 * The case that carries the design is the FIRST: an empty registry checks
 * nothing, so the day this lands no existing deployment changes behaviour.
 * Everything after it is what a real OpenID Provider does and this service did
 * not - `raposza_oidc.md`, and the operator's requirement of 2026-09-19 that a
 * component pointed at a real provider behave the same way.
 *
 * Author Claude/bentzn
 */
class OidcClientsTest {

    private static final String STR_URI = "http://wallet.localhost:4000/cb";


    private static MintSettings settings(Path dirKeys) {
        return new MintSettings(dirKeys.toString(), "https://id.example.com",
                86400, "RS256", "raposza", "admin", "", false);
    }


    private static OidcClients clients(Path dirKeys, String strSeed) {
        return new OidcClients(settings(dirKeys), strSeed);
    }


    @Test
    void anEmptyRegistryChecksNothing(@TempDir Path dirKeys) {
        OidcClients reg = clients(dirKeys, "");

        assertFalse(reg.flagStrict());
        assertTrue(reg.flagKnown("anything-at-all"));
        assertTrue(reg.flagRedirect("anything-at-all", "http://wherever.example/cb"));
        assertTrue(reg.flagSecret("anything-at-all", "any secret"));
        assertTrue(reg.flagSecret("anything-at-all", null));
        assertFalse(Files.isRegularFile(dirKeys.resolve(OidcClients.STR_FILE)));
    }


    @Test
    void oneClientMakesItStrictForEveryClient(@TempDir Path dirKeys) {
        OidcClients reg = clients(dirKeys, "wallet-ui||" + STR_URI);

        assertTrue(reg.flagStrict());
        assertTrue(reg.flagKnown("wallet-ui"));
        // THERE IS NO HALF-OPEN STATE. A registry that lets an unknown client
        // through is not a registry.
        assertFalse(reg.flagKnown("something-else"));
        assertFalse(reg.flagKnown(null));
    }


    @Test
    void anUnregisteredRedirectUriIsRefused(@TempDir Path dirKeys) {
        OidcClients reg = clients(dirKeys, "wallet-ui||" + STR_URI + " http://other.localhost/cb");

        assertTrue(reg.flagRedirect("wallet-ui", STR_URI));
        assertTrue(reg.flagRedirect("wallet-ui", "http://other.localhost/cb"));

        // WHOLE-STRING COMPARISON, Core 3.1.2.1. A trailing slash is a
        // different URI, and so is a different port.
        assertFalse(reg.flagRedirect("wallet-ui", STR_URI + "/"));
        assertFalse(reg.flagRedirect("wallet-ui", "http://wallet.localhost:4001/cb"));
        assertFalse(reg.flagRedirect("wallet-ui", null));
        assertFalse(reg.flagRedirect("nobody", STR_URI));
    }


    @Test
    void aConfidentialClientMustPresentItsSecret(@TempDir Path dirKeys) {
        OidcClients reg = clients(dirKeys, "sv-app|s3cret|" + STR_URI);

        assertTrue(reg.flagSecret("sv-app", "s3cret"));
        assertFalse(reg.flagSecret("sv-app", "wrong"));
        assertFalse(reg.flagSecret("sv-app", ""));
        assertFalse(reg.flagSecret("sv-app", null));
    }


    @Test
    void aPublicClientMustNotPresentOne(@TempDir Path dirKeys) {
        OidcClients reg = clients(dirKeys, "wallet-ui||" + STR_URI);

        assertTrue(reg.flagSecret("wallet-ui", null));
        assertTrue(reg.flagSecret("wallet-ui", ""));
        // REFUSED RATHER THAN IGNORED. A component sending a secret is
        // configured for a confidential client and would fail against a real
        // provider the moment it was pointed at one - which is the whole
        // failure this registry exists to stop.
        assertFalse(reg.flagSecret("wallet-ui", "s3cret"));
    }


    @Test
    void theSettingSeedsTheFileAndTheFileWinsAfterwards(@TempDir Path dirKeys) {
        clients(dirKeys, "wallet-ui||" + STR_URI).flagPut("sv-app", "s3cret",
                List.of("http://sv.localhost/cb"));

        OidcClients again = clients(dirKeys, "someone-else||http://nope.localhost/cb");

        assertEquals(List.of("wallet-ui", "sv-app"), again.lstId());
        assertFalse(again.flagKnown("someone-else"));
        assertTrue(again.flagSecret("sv-app", "s3cret"));
        assertTrue(again.flagRedirect("sv-app", "http://sv.localhost/cb"));
    }


    @Test
    void removingTheLastClientReopensTheService(@TempDir Path dirKeys) {
        OidcClients reg = clients(dirKeys, "wallet-ui||" + STR_URI);

        assertTrue(reg.flagRemove("wallet-ui"));
        assertFalse(reg.flagRemove("wallet-ui"));
        assertFalse(reg.flagStrict());
        assertTrue(reg.flagKnown("anything-at-all"));
    }


    @Test
    void aClientWithNoUsableRedirectUriIsRefused(@TempDir Path dirKeys) {
        OidcClients reg = clients(dirKeys, "wallet-ui||" + STR_URI);

        assertThrows(IllegalArgumentException.class,
                () -> reg.flagPut("x", "", List.of()));
        assertThrows(IllegalArgumentException.class,
                () -> reg.flagPut("x", "", List.of("not a uri")));
        assertThrows(IllegalArgumentException.class,
                () -> reg.flagPut("", "", List.of(STR_URI)));
    }


    /** 0.5.0, RFC 6749 section 4.4: client_credentials is for confidential clients only. */
    @Test
    void onlyAConfidentialClientMayUseClientCredentials(@TempDir Path dirKeys) {
        assertTrue(clients(dirKeys.resolve("open"), "").flagClientCredentials("anything-at-all"));

        OidcClients reg = clients(dirKeys.resolve("strict"),
                "wallet-ui||" + STR_URI + ",backend|s3cret|" + STR_URI);
        assertFalse(reg.flagClientCredentials("wallet-ui"));
        assertTrue(reg.flagClientCredentials("backend"));
        assertFalse(reg.flagClientCredentials("something-else"));
        assertFalse(reg.flagClientCredentials(null));
    }


    @Test
    void aSeedEntryThatIsNotThreeFieldsNamesItself(@TempDir Path dirKeys) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> clients(dirKeys, "wallet-ui|" + STR_URI));
        assertTrue(ex.getMessage().contains("wallet-ui"));
    }

}
