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
 * `raposza.oidc.standalone` REFUSES TO START without a password -
 * {@link MintSettings} - so a service exposed on a network is always guarded.
 *
 * <h2>Two ways in, because there are two kinds of caller</h2>
 *
 * A browser signs in at `/api/ui/login` and carries a session; a script sends
 * HTTP Basic on every request. Both check the same pair.
 *
 * <h2>The path it decides on is the path Spring matches - 0.4.0</h2>
 *
 * Until 0.4.0 the decision was taken on the RAW request URI while Spring MVC
 * dispatched on the canonical one - decoded, path parameters removed. So
 * `/oauth2/jwks-private;x=1`, `/oauth2/%6Awks-private` and `/%61dmin/status`
 * reached their handlers with no credential while the plain spellings were
 * refused - measured 2026-09-26 with the admin password set, the private set
 * served whole. The decision is now taken on the servlet path, which the
 * container has already canonicalised for dispatch, and the raw URI is checked
 * as well: a request is guarded when EITHER spelling is.
 *
 * <h2>A session alone does not authorise a write that did not come from the UI - 0.4.0</h2>
 *
 * CORS here answers every origin with `*` and no credentials, which stops a
 * page on another origin READING a response - and does nothing about a request
 * the browser sends without asking first. A body-less `text/plain` POST is such
 * a request, the browser attaches the session cookie to it, and until 0.4.0 it
 * rotated a key: measured 2026-09-26. So a request authenticated by the SESSION
 * that writes - any method but GET and HEAD, and `/admin/reload` whatever its
 * method - must also carry {@link #STR_HEADER_UI}, which the UI sends on every
 * call. A custom header makes the browser ask first, and a cross-origin
 * preflight for a credentialed request fails here because the answer carries no
 * `Access-Control-Allow-Credentials`. HTTP Basic is not affected: a page cannot
 * send it without already holding the password.
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

    /** The header a session-authenticated write must carry; the UI sends it on every call. */
    public static final String STR_HEADER_UI = "X-Raposza-UI";

    /** The one GET that changes state: it re-reads the key set from disk. */
    public static final String STR_PATH_RELOAD = "/admin/reload";

    private final MintSettings settings;


    public AdminGuard(MintSettings settings) {
        this.settings = settings;
        if (!settings.flagAdminSet()) {
            log.warn("NO ADMIN CREDENTIAL. /admin/*, /api/ui/* and the private"
                    + " JWKS are open to anyone who can reach this service."
                    + " Set raposza.oidc.admin.password to close them.");
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
     * The whole decision for a read, with no servlet in it.
     *
     * @param strPath the request path
     * @param strAuth the Authorization header, or null
     * @param flagSession whether the session carries a completed sign-in
     * @return true when the request may proceed
     */
    public boolean flagAllowed(String strPath, String strAuth, boolean flagSession) {
        return flagAllowed(strPath, "GET", strAuth, flagSession, false);
    }


    /**
     * The whole decision, with no servlet in it.
     *
     * @param strPath the canonical request path
     * @param strMethod the HTTP method
     * @param strAuth the Authorization header, or null
     * @param flagSession whether the session carries a completed sign-in
     * @param flagUiHeader whether the request carries {@link #STR_HEADER_UI}
     * @return true when the request may proceed
     */
    public boolean flagAllowed(String strPath, String strMethod, String strAuth,
            boolean flagSession, boolean flagUiHeader) {
        if (!flagGuarded(strPath))
            return true;
        if (!settings.flagAdminSet())
            return true;
        if (flagBasicValid(strAuth))
            return true;
        if (!flagSession)
            return false;
        return flagUiHeader || !flagWrite(strPath, strMethod);
    }


    /**
     * @param strPath the canonical request path
     * @param strMethod the HTTP method
     * @return true when the request changes state
     */
    public static boolean flagWrite(String strPath, String strMethod) {
        if (STR_PATH_RELOAD.equals(strPath))
            return true;
        return !("GET".equalsIgnoreCase(strMethod) || "HEAD".equalsIgnoreCase(strMethod));
    }


    /**
     * The path the container dispatches on: decoded, normalised, path
     * parameters removed.
     *
     * @param req the request
     * @return the servlet path and the path info, joined
     */
    public static String strPathCanonical(HttpServletRequest req) {
        String strServlet = req.getServletPath();
        String strInfo = req.getPathInfo();
        return (strServlet == null ? "" : strServlet) + (strInfo == null ? "" : strInfo);
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

        // EITHER SPELLING GUARDS. The canonical path is what Spring dispatches
        // on; the raw one is kept so that nothing guarded before is let through
        // by a container that canonicalises differently.
        String strCanonical = strPathCanonical(req);
        String strPath = flagGuarded(strCanonical) ? strCanonical : req.getRequestURI();

        if (flagAllowed(strPath, req.getMethod(), req.getHeader("Authorization"), flagSession,
                req.getHeader(STR_HEADER_UI) != null)) {
            chain.doFilter(req, res);
            return;
        }

        res.setContentType("application/json");
        if (flagSession) {
            // SIGNED IN, BUT NOT FROM THE UI. 403 rather than 401, so the UI does
            // not answer it with its sign-in gate.
            res.setStatus(HttpServletResponse.SC_FORBIDDEN);
            res.getWriter().write("{\"error\":\"forbidden\",\"error_description\":\"a signed-in"
                    + " write must carry the " + STR_HEADER_UI + " header, or use HTTP Basic\"}");
            return;
        }

        // BASIC IS ADVERTISED so curl -u works and a browser that reached an
        // API path directly is told how to answer.
        res.setHeader("WWW-Authenticate", "Basic realm=\"Raposza OIDC\"");
        res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
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
