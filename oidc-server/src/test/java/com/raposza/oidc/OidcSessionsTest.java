// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The session the authorization endpoint keeps.
 *
 * Author Claude/bentzn
 */
class OidcSessionsTest {

    @Test
    void opensAndFinds() {
        OidcSessions sessions = new OidcSessions();
        String strHandle = sessions.strOpen("alice");
        OidcSessions.Session session = sessions.session(strHandle);
        assertNotNull(session);
        assertEquals("alice", session.strUser());
        assertEquals(1, sessions.cntLive());
    }


    @Test
    void unknownAndBlankAreNoSession() {
        OidcSessions sessions = new OidcSessions();
        assertNull(sessions.session(null));
        assertNull(sessions.session(""));
        assertNull(sessions.session("not-a-handle"));
    }


    @Test
    void closeEndsIt() {
        OidcSessions sessions = new OidcSessions();
        String strHandle = sessions.strOpen("alice");
        sessions.close(strHandle);
        assertNull(sessions.session(strHandle));
        assertEquals(0, sessions.cntLive());
    }


    @Test
    void handlesAreDistinct() {
        OidcSessions sessions = new OidcSessions();
        assertNotEquals(sessions.strOpen("alice"), sessions.strOpen("alice"));
        assertEquals(2, sessions.cntLive());
    }


    @Test
    void authInstantIsTheOneHeld() {
        OidcSessions sessions = new OidcSessions();
        String strHandle = sessions.strOpen("alice");
        Instant instFirst = sessions.session(strHandle).instAuth();
        assertEquals(instFirst, sessions.session(strHandle).instAuth());
    }


    /** A max_age older than the authentication forces a second sign-in. */
    @Test
    void staleByMaxAge() {
        OidcSessions.Session session = new OidcSessions.Session("alice",
                Instant.now().minusSeconds(120), Instant.now().plusSeconds(3600));
        assertTrue(OidcSessions.flagStale(session, "1"));
        assertFalse(OidcSessions.flagStale(session, "10000"));
        assertFalse(OidcSessions.flagStale(session, null));
        assertFalse(OidcSessions.flagStale(session, ""));
    }


    @Test
    void noSessionIsAlwaysStale() {
        assertTrue(OidcSessions.flagStale(null, null));
        assertTrue(OidcSessions.flagStale(null, "10000"));
    }


    @Test
    void anExpiredSessionIsGone() {
        OidcSessions.Session session = new OidcSessions.Session("alice",
                Instant.now().minusSeconds(10), Instant.now().minusSeconds(1));
        assertTrue(OidcSessions.flagStale(session, "5"));
    }


    @Test
    void maxAgeMustBeDigits() {
        assertTrue(OidcController.isDigits("0"));
        assertTrue(OidcController.isDigits("10000"));
        assertFalse(OidcController.isDigits("-1"));
        assertFalse(OidcController.isDigits("ten"));
        assertFalse(OidcController.isDigits(""));
        assertFalse(OidcController.isDigits(null));
    }

}
