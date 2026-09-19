// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * The one credential in front of everything that WRITES, and in front of the
 * private keys.
 *
 * <h2>What it guards, and what it deliberately does not</h2>
 *
 * Guarded: `/admin/*`, everything under `/api/ui/*` bar the sign-in itself, and
 * the two paths that publish the PRIVATE key set. Not guarded: discovery, the
 * public JWKS, `/token`, `/mint`, `/mint.txt` and the OpenID Connect browser
 * flow - consumers depend on all of those unauthenticated, `loadtest.py` among
 * them, and breaking them was never what this filter was for.
 *
 * <h2>It is not a security boundary and the document says so</h2>
 *
 * `/mint` stays open, so anyone who can reach this service can still obtain a
 * token for any subject signed by the key every participant trusts. The
 * credential stops a passer-by CHANGING the keys or the users. That is the
 * whole of its claim - `raposza_oidc.md` section 3, OD-4.
 *
 * <h2>No password configured means OFF, loudly</h2>
 *
 * The embedded case is a service on loopback that a window starts and stops,
 * and every existing caller of `/admin/reload` predates this filter. So an
 * unset password leaves the filter open and says so once at startup rather than
 * breaking them. The case that matters is covered from the other side:
 * `raposza.jwtmint.standalone` REFUSES TO START without a password -
 * {@link MintSettings} - so a service exposed on a network is always guarded.
 *
 * <h2>Two ways in, because there are two kinds of caller</h2>
 *
 * A browser signs in at `/api/ui/login` and carries a session; a script sends
 * HTTP Basic on every request. Both check the same pair.
 *
 * Author Claude/bentzn
 */
@Component
public final class AdminGuard extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AdminGuard.class);

    /** The session attribute set once a sign-in succeeded. */
    public static final String STR_ATTR_SIGNED_IN = "raposza.oidc.admin";

    /** The one path under `/api/ui/` that cannot require a credential. */
    public static final String STR_PATH_LOGIN = "/api/ui/login";

    private final MintSettings settings;


    public AdminGuard(MintSettings settings) {
        this.settings = settings;
        if (!settings.flagAdminSet()) {
            log.warn("NO ADMIN CREDENTIAL. /admin/*, /api/ui/* and the private"
                    + " JWKS are open to anyone who can reach this service."
                    + " Set raposza.jwtmint.admin.password to close them.");
        }
    }


    /**
     * Whether a path is one this filter protects.
     *
     * @param strPath the request path, with no query string
     * @return true when the path needs the credential
     */
    public static boolean flagGuarded(String strPath) {
        if (strPath == null)
            return false;
        if (STR_PATH_LOGIN.equals(strPath))
            return false;
        return strPath.startsWith("/admin/")
                || strPath.startsWith("/api/ui/")
                || strPath.equals(IssuerResolver.STR_PATH_JWKS_PRIVATE)
                || strPath.equals("/jwks-private.json");
    }


    /**
     * The whole decision, with no servlet in it.
     *
     * @param strPath the request path
     * @param strAuth the Authorization header, or null
     * @param flagSession whether the session carries a completed sign-in
     * @return true when the request may proceed
     */
    public boolean flagAllowed(String strPath, String strAuth, boolean flagSession) {
        if (!flagGuarded(strPath))
            return true;
        if (!settings.flagAdminSet())
            return true;
        if (flagSession)
            return true;
        return flagBasicValid(strAuth);
    }


    /**
     * @param strName what was typed as the admin name
     * @param strPassword what was typed as the admin password
     * @return true when both match, compared without a timing side channel
     */
    public boolean flagCredential(String strName, String strPassword) {
        if (!settings.flagAdminSet())
            return true;
        if (strName == null || strPassword == null)
            return false;
        return flagSame(settings.strAdminUser(), strName)
                && flagSame(settings.strAdminPassword(), strPassword);
    }


    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
            FilterChain chain) throws ServletException, IOException {
        HttpSession session = req.getSession(false);
        boolean flagSession = session != null
                && Boolean.TRUE.equals(session.getAttribute(STR_ATTR_SIGNED_IN));

        if (flagAllowed(req.getRequestURI(), req.getHeader("Authorization"), flagSession)) {
            chain.doFilter(req, res);
            return;
        }

        // BASIC IS ADVERTISED so curl -u works and a browser that reached an
        // API path directly is told how to answer.
        res.setHeader("WWW-Authenticate", "Basic realm=\"Raposza OIDC\"");
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        res.setContentType("application/json");
        res.getWriter().write("{\"error\":\"unauthorized\","
                + "\"error_description\":\"this path needs the admin credential\"}");
    }


    private boolean flagBasicValid(String strAuth) {
        if (strAuth == null || !strAuth.regionMatches(true, 0, "Basic ", 0, 6))
            return false;

        String strPair;
        try {
            strPair = new String(Base64.getDecoder().decode(strAuth.substring(6).trim()),
                    StandardCharsets.UTF_8);
        }
        catch (IllegalArgumentException ex) {
            // A header that is not base64 is a wrong credential, not a 500.
            return false;
        }

        int idxColon = strPair.indexOf(':');
        if (idxColon < 0)
            return false;
        return flagCredential(strPair.substring(0, idxColon), strPair.substring(idxColon + 1));
    }


    private static boolean flagSame(String strWant, String strGot) {
        return MessageDigest.isEqual(strWant.getBytes(StandardCharsets.UTF_8),
                strGot.getBytes(StandardCharsets.UTF_8));
    }

}
