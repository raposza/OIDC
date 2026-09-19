// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

/**
 * The guard's decision, with no servlet in it.
 *
 * The two cases that carry the design are the LAST two: an unset password
 * leaves everything open, deliberately, and standalone refuses to start in that
 * state so the open case can never be a service on a network.
 *
 * Author Claude/bentzn
 */
class AdminGuardTest {

    private static final String STR_ISSUER = "https://id.example.com";


    private static AdminGuard guard(Path dirKeys, String strPassword, boolean flagStandalone) {
        return new AdminGuard(new MintSettings(dirKeys.toString(), STR_ISSUER,
                86400, "RS256", "raposza", "admin", strPassword, flagStandalone));
    }


    private static String strBasic(String strUser, String strPassword) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (strUser + ":" + strPassword).getBytes(StandardCharsets.UTF_8));
    }


    @Test
    void theWritePathsAndThePrivateKeysAreGuarded() {
        assertTrue(AdminGuard.flagGuarded("/admin/reload"));
        assertTrue(AdminGuard.flagGuarded("/admin/status"));
        assertTrue(AdminGuard.flagGuarded("/api/ui/keys"));
        assertTrue(AdminGuard.flagGuarded("/api/ui/users"));
        assertTrue(AdminGuard.flagGuarded(IssuerResolver.STR_PATH_JWKS_PRIVATE));
        assertTrue(AdminGuard.flagGuarded("/jwks-private.json"));
    }


    @Test
    void whatConsumersDependOnIsNotGuarded() {
        // BREAKING ANY OF THESE IS THE FAILURE THIS FILTER MUST NOT CAUSE.
        // loadtest.py takes its token from /mint.txt with no credential.
        assertFalse(AdminGuard.flagGuarded(IssuerResolver.STR_PATH_DISCOVERY_OIDC));
        assertFalse(AdminGuard.flagGuarded(IssuerResolver.STR_PATH_DISCOVERY_OAUTH));
        assertFalse(AdminGuard.flagGuarded(IssuerResolver.STR_PATH_JWKS));
        assertFalse(AdminGuard.flagGuarded(IssuerResolver.STR_PATH_TOKEN));
        assertFalse(AdminGuard.flagGuarded(IssuerResolver.STR_PATH_AUTHORIZE));
        assertFalse(AdminGuard.flagGuarded(IssuerResolver.STR_PATH_USERINFO));
        assertFalse(AdminGuard.flagGuarded(IssuerResolver.STR_PATH_LOGOUT));
        assertFalse(AdminGuard.flagGuarded("/mint"));
        assertFalse(AdminGuard.flagGuarded("/mint.txt"));
        assertFalse(AdminGuard.flagGuarded("/keys"));
        assertFalse(AdminGuard.flagGuarded("/"));
    }


    @Test
    void theSignInItselfCannotRequireWhatItEstablishes() {
        assertFalse(AdminGuard.flagGuarded(AdminGuard.STR_PATH_LOGIN));
    }


    @Test
    void basicAndTheSessionBothOpenIt(@TempDir Path dirKeys) {
        AdminGuard guard = guard(dirKeys, "s3cret", false);

        assertTrue(guard.flagAllowed("/api/ui/keys", strBasic("admin", "s3cret"), false));
        assertTrue(guard.flagAllowed("/api/ui/keys", null, true));
        assertFalse(guard.flagAllowed("/api/ui/keys", null, false));
    }


    @Test
    void aWrongOrMalformedCredentialIsRefusedRatherThanThrown(@TempDir Path dirKeys) {
        AdminGuard guard = guard(dirKeys, "s3cret", false);

        assertFalse(guard.flagAllowed("/api/ui/keys", strBasic("admin", "wrong"), false));
        assertFalse(guard.flagAllowed("/api/ui/keys", strBasic("root", "s3cret"), false));
        assertFalse(guard.flagAllowed("/api/ui/keys", "Basic not-base-64!!", false));
        assertFalse(guard.flagAllowed("/api/ui/keys", "Bearer something", false));
        assertFalse(guard.flagAllowed("/api/ui/keys", "Basic", false));
    }


    @Test
    void anUnguardedPathNeedsNothingEvenWithAPasswordSet(@TempDir Path dirKeys) {
        AdminGuard guard = guard(dirKeys, "s3cret", false);
        assertTrue(guard.flagAllowed("/mint.txt", null, false));
    }


    @Test
    void noPasswordLeavesEverythingOpen(@TempDir Path dirKeys) {
        AdminGuard guard = guard(dirKeys, "", false);

        assertTrue(guard.flagAllowed("/api/ui/keys", null, false));
        assertTrue(guard.flagAllowed("/admin/reload", null, false));
        assertTrue(guard.flagAllowed(IssuerResolver.STR_PATH_JWKS_PRIVATE, null, false));
    }


    @Test
    void standaloneWithNoPasswordRefusesToStart(@TempDir Path dirKeys) {
        // THIS IS WHAT MAKES THE OPEN CASE SAFE: it can only ever be a service
        // a window started on loopback, never one put on a network.
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> guard(dirKeys, "", true));
        assertTrue(ex.getMessage().contains("admin.password"));
    }


    @Test
    void standaloneWithNoIssuerRefusesToStart(@TempDir Path dirKeys) {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new MintSettings(dirKeys.toString(), "", 86400, "RS256",
                        "raposza", "admin", "s3cret", true));
        assertTrue(ex.getMessage().contains("issuer"));
    }

}
