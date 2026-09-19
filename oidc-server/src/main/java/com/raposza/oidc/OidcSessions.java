// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Who is signed in at the authorization endpoint, and since when.
 *
 * <h2>Why this exists, measured rather than argued</h2>
 *
 * Until 2026-09-19 every authorization request showed the login page and
 * `prompt=none` always answered `login_required`. The OpenID Foundation
 * conformance suite, OP Basic plan, failed three modules on that one fact:
 * `oidcc-prompt-none-logged-in` and `oidcc-id-token-hint` both expect a
 * silent success once the person has signed in, and `oidcc-max-age-10000`
 * expects the SAME `auth_time` in two id_tokens - which is impossible when
 * every request re-authenticates.
 *
 * <h2>What a session is here</h2>
 *
 * A handle in an HttpOnly cookie and, behind it, the user's name and the
 * instant they actually authenticated. Nothing else: no consent record, no
 * device binding, no idle timeout distinct from the absolute one. `auth_time`
 * is the instant of the ORIGINAL authentication and does not move until the
 * person signs in again, which is what makes `max_age` answerable.
 *
 * In memory, like the codes and refresh tokens in {@link OidcFlow}. A restart
 * signs everybody out, which on a test system is a feature.
 *
 * Author Claude/bentzn
 */
@Service
public class OidcSessions {

    /** The cookie the browser carries between authorization requests. */
    public static final String STR_COOKIE = "raposza_oidc_session";

    private static final Duration DUR_SESSION = Duration.ofHours(12);

    private static final int N_BYTES_HANDLE = 32;

    private static final Logger log = LoggerFactory.getLogger(OidcSessions.class);

    private final Map<String, Session> mapSession = new ConcurrentHashMap<>();

    private final SecureRandom random = new SecureRandom();


    /**
     * One signed-in browser.
     *
     * @param strUser who signed in
     * @param instAuth when they authenticated - the `auth_time` claim
     * @param instExpires when this session stops being honoured
     */
    public record Session(String strUser, Instant instAuth, Instant instExpires) {
    }


    /**
     * Records an authentication that has just succeeded.
     *
     * @param strUser the user that authenticated
     * @return the handle to put in the cookie
     */
    public String strOpen(String strUser) {
        purge();
        String strHandle = strHandle();
        Instant instNow = Instant.now();
        mapSession.put(strHandle, new Session(strUser, instNow, instNow.plus(DUR_SESSION)));
        log.info("session opened for {}", strUser);
        return strHandle;
    }


    /**
     * @param strHandle the cookie value, or null
     * @return the live session, or null when there is none, it is unknown or
     *         it has expired
     */
    public Session session(String strHandle) {
        if (strHandle == null || strHandle.isBlank())
            return null;
        Session session = mapSession.get(strHandle);
        if (session == null)
            return null;
        if (Instant.now().isAfter(session.instExpires())) {
            mapSession.remove(strHandle);
            return null;
        }
        return session;
    }


    /**
     * Whether an authentication is older than a `max_age` asks for - OpenID
     * Connect Core 1.0 section 3.1.2.1.
     *
     * @param session the session, or null
     * @param strMaxAge the `max_age` parameter, or null
     * @return true when the person has to authenticate again
     */
    public static boolean flagStale(Session session, String strMaxAge) {
        if (session == null)
            return true;
        if (strMaxAge == null || strMaxAge.isBlank())
            return false;
        try {
            long nMaxAge = Long.parseLong(strMaxAge.trim());
            if (nMaxAge < 0)
                return false;
            return Instant.now().isAfter(session.instAuth().plusSeconds(nMaxAge));
        }
        catch (NumberFormatException ex) {
            // A max_age that is not a number is not a reason to re-authenticate;
            // it is a malformed request, and the endpoint refuses it before it
            // gets here.
            return false;
        }
    }


    /**
     * @param strHandle the cookie value, or null
     */
    public void close(String strHandle) {
        if (strHandle != null && !strHandle.isBlank())
            mapSession.remove(strHandle);
    }


    /**
     * @return how many sessions are live, for the admin surface and the tests
     */
    public int cntLive() {
        purge();
        return mapSession.size();
    }


    private void purge() {
        Instant instNow = Instant.now();
        mapSession.entrySet().removeIf(entSession ->
                instNow.isAfter(entSession.getValue().instExpires()));
    }


    private String strHandle() {
        byte[] arrRaw = new byte[N_BYTES_HANDLE];
        random.nextBytes(arrRaw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(arrRaw);
    }

}
