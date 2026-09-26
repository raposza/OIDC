// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

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


    /** SINCE 0.4.0 THE ISSUER IS NEVER GUESSED - not even for a window's own child. */
    @Test
    void noIssuerRefusesToStartEvenWhenNotStandalone(@TempDir Path dirKeys) {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new MintSettings(dirKeys.toString(), "  ", 86400, "RS256",
                        "raposza", "admin", "", false));
        assertTrue(ex.getMessage().contains("raposza.jwtmint.issuer"));
    }


    /**
     * One request through the filter itself.
     *
     * @return the status, or 0 when the request was passed on
     */
    private static int nThrough(AdminGuard guard, String strMethod, String strUri,
            String strServletPath, String strAuth, boolean flagSession, boolean flagUi)
            throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest(strMethod, strUri);
        req.setServletPath(strServletPath);
        if (strAuth != null)
            req.addHeader("Authorization", strAuth);
        if (flagUi)
            req.addHeader(AdminGuard.STR_HEADER_UI, "1");
        if (flagSession) {
            MockHttpSession session = new MockHttpSession();
            session.setAttribute(AdminGuard.STR_ATTR_SIGNED_IN, Boolean.TRUE);
            req.setSession(session);
        }
        MockHttpServletResponse res = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        guard.doFilter(req, res, chain);
        return chain.getRequest() != null ? 0 : res.getStatus();
    }


    /** MEASURED 2026-09-26 on 0.4.0 before this fix: all three served with no credential. */
    @Test
    void aRawSpellingOfAGuardedPathIsDecidedOnTheCanonicalPath(@TempDir Path dirKeys)
            throws Exception {
        AdminGuard guard = guard(dirKeys, "s3cret", false);

        assertEquals(401, nThrough(guard, "GET", "/oauth2/jwks-private;x=1",
                IssuerResolver.STR_PATH_JWKS_PRIVATE, null, false, false));
        assertEquals(401, nThrough(guard, "GET", "/oauth2/%6Awks-private",
                IssuerResolver.STR_PATH_JWKS_PRIVATE, null, false, false));
        assertEquals(401, nThrough(guard, "GET", "/%61dmin/status", "/admin/status",
                null, false, false));
        assertEquals(0, nThrough(guard, "GET", "/%61dmin/status", "/admin/status",
                strBasic("admin", "s3cret"), false, false));
    }


    @Test
    void aGuardedRawUriStaysGuardedWhateverTheCanonicalPath(@TempDir Path dirKeys)
            throws Exception {
        AdminGuard guard = guard(dirKeys, "s3cret", false);
        assertEquals(401, nThrough(guard, "GET", "/admin/status", "/elsewhere",
                null, false, false));
    }


    /** MEASURED 2026-09-26 on 0.4.0 before this fix: a text/plain POST rotated a key. */
    @Test
    void aSessionWriteWithoutTheUiHeaderIsRefused(@TempDir Path dirKeys) throws Exception {
        AdminGuard guard = guard(dirKeys, "s3cret", false);

        assertEquals(403, nThrough(guard, "POST", "/api/ui/keys/rs256/rotate",
                "/api/ui/keys/rs256/rotate", null, true, false));
        assertEquals(403, nThrough(guard, "DELETE", "/api/ui/users/alice",
                "/api/ui/users/alice", null, true, false));
        assertEquals(403, nThrough(guard, "GET", AdminGuard.STR_PATH_RELOAD,
                AdminGuard.STR_PATH_RELOAD, null, true, false));
    }


    @Test
    void theUiHeaderOpensASessionWrite(@TempDir Path dirKeys) throws Exception {
        AdminGuard guard = guard(dirKeys, "s3cret", false);
        assertEquals(0, nThrough(guard, "POST", "/api/ui/keys/rs256/rotate",
                "/api/ui/keys/rs256/rotate", null, true, true));
    }


    @Test
    void aSessionReadNeedsNoHeader(@TempDir Path dirKeys) throws Exception {
        AdminGuard guard = guard(dirKeys, "s3cret", false);
        assertEquals(0, nThrough(guard, "GET", "/api/ui/users", "/api/ui/users",
                null, true, false));
    }


    /** A script is not a browser: Basic opens a write with no UI header. */
    @Test
    void basicOpensAWriteWithoutTheHeader(@TempDir Path dirKeys) throws Exception {
        AdminGuard guard = guard(dirKeys, "s3cret", false);
        assertEquals(0, nThrough(guard, "POST", AdminGuard.STR_PATH_RELOAD,
                AdminGuard.STR_PATH_RELOAD, strBasic("admin", "s3cret"), false, false));
    }


    @Test
    void noPasswordStillLeavesASessionlessWriteOpen(@TempDir Path dirKeys) throws Exception {
        AdminGuard guard = guard(dirKeys, "", false);
        assertEquals(0, nThrough(guard, "POST", "/api/ui/keys/rs256/rotate",
                "/api/ui/keys/rs256/rotate", null, false, false));
    }

}
