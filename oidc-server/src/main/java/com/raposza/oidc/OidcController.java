// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * The parts of an OpenID Provider a browser meets: the authorization endpoint
 * with its login page, UserInfo, and RP-initiated logout.
 *
 * <h2>The login is the production concept, without the hardening</h2>
 *
 * The application sends the browser here; the person types a name and a
 * password; the browser goes back to the application with a code, which the
 * application exchanges at the token endpoint. The application never sees the
 * password. That is how Keycloak does it, and it is why replacing this service
 * is a change of settings. What is left out is what makes a provider secure
 * rather than correct: no consent screen, no lockout, no multi-factor.
 *
 * <h2>There IS a session, since 2026-09-19</h2>
 *
 * {@link OidcSessions} holds who is signed in and when they authenticated, in
 * a cookie-addressed map. A second authorization request from the same browser
 * is answered SILENTLY - no login page - which is what every real provider
 * does and what `prompt=none`, `id_token_hint` and `max_age` are defined
 * against. `prompt=login` forces the page anyway; a `max_age` older than the
 * authentication forces it too; and `auth_time` stays the instant of the
 * ORIGINAL authentication, so two id_tokens from one session agree on it.
 *
 * The OpenID Foundation conformance suite failed three modules of the OP Basic
 * plan on the absence of this - `oidcc-prompt-none-logged-in`,
 * `oidcc-id-token-hint` and `oidcc-max-age-10000`, measured 2026-09-19.
 *
 * <h2>The request object is refused, not ignored</h2>
 *
 * Neither `request` nor `request_uri` is implemented. Core 6.1 and 6.2 name
 * the two error codes for exactly that, and they are returned. IGNORING the
 * parameter is the one thing a provider must not do: the `state` and `nonce`
 * the client put inside the object then never come back, which is how
 * `oidcc-unsigned-request-object-...` failed on both of them.
 *
 * Author Claude/bentzn
 */
@RestController
@Tag(name = "OpenID Connect", description = "Sign-in for browser applications:"
        + " the authorization code flow with PKCE, UserInfo and logout.")
public class OidcController {

    private static final String STR_NO_STORE = "no-store";

    private static final MediaType TYPE_HTML = MediaType.parseMediaType("text/html;charset=UTF-8");

    /** What the login form carries back to this endpoint, beside what was typed. */
    private static final Set<String> SET_PARAM_CARRIED = Set.of("response_type", "client_id",
            "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method",
            "audience", "response_mode");

    private final OidcFlow flow;

    private final OidcUsers users;

    private final OidcClients clients;

    private final OidcSessions sessions;

    private final IssuerResolver resolver;


    public OidcController(OidcFlow flow, OidcUsers users, OidcClients clients,
            OidcSessions sessions, IssuerResolver resolver) {
        this.flow = flow;
        this.users = users;
        this.clients = clients;
        this.sessions = sessions;
        this.resolver = resolver;
    }


    /**
     * The authorization endpoint, GET and POST alike - Core 3.1.2.1.
     *
     * A request from a browser that is not signed in answers the login page.
     * The page posts back here with the request's parameters and what was
     * typed; a match opens a session and redirects to the client with a code, a
     * mismatch shows the page again. A request from a browser that IS signed in
     * is answered with a code and no page at all, unless `prompt=login` or a
     * `max_age` says otherwise.
     *
     * @param mapParam the request's parameters, query or form
     * @param strSid the session cookie, or null
     * @return the login page, an error page, or a redirect to the client
     */
    @Operation(summary = "Authorization endpoint - sign in",
            description = "**Standard: OpenID Connect Core 1.0 section 3.1.2**, the"
                    + " authorization code flow, with **RFC 7636** PKCE (S256).\n\n"
                    + "Open it in a browser with `response_type=code`, `client_id`,"
                    + " `redirect_uri` and `scope=openid` to see the login page."
                    + " A second request from the same browser is answered without"
                    + " one; `prompt=login` and `max_age` override that.")
    @RequestMapping(value = IssuerResolver.STR_PATH_AUTHORIZE,
            method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<String> authorize(@RequestParam Map<String, String> mapParam,
            @CookieValue(name = OidcSessions.STR_COOKIE, required = false) String strSid) {
        String idClient = mapParam.get("client_id");
        String strRedirect = mapParam.get("redirect_uri");
        // NEVER REDIRECTED. Core 3.1.2.6 and RFC 6749 4.1.2.1: without a valid
        // redirect_uri the error cannot be sent anywhere trustworthy, so the
        // person is told here.
        if (isBlank(idClient))
            return page(HttpStatus.BAD_REQUEST, "Sign-in refused", "The request names no client_id.");
        if (!isRedirectUri(strRedirect)) {
            return page(HttpStatus.BAD_REQUEST, "Sign-in refused",
                    "redirect_uri is missing, or is not an absolute http or https URI without a fragment.");
        }

        // NEITHER OF THESE IS REDIRECTED EITHER, and for the same reason: an
        // unknown client and an unregistered redirect_uri are exactly the cases
        // where the URI in the request cannot be trusted to receive the error.
        // Core 3.1.2.6. While no client is registered both are skipped and the
        // service behaves as it did - OidcClients says why.
        if (!clients.flagKnown(idClient)) {
            return page(HttpStatus.BAD_REQUEST, "Sign-in refused",
                    "No client is registered under that client_id.");
        }
        if (!clients.flagRedirect(idClient, strRedirect)) {
            return page(HttpStatus.BAD_REQUEST, "Sign-in refused",
                    "That redirect_uri is not one of the URIs registered for that client.");
        }

        String strState = mapParam.get("state");

        // REFUSED RATHER THAN IGNORED - Core 6.1 and 6.2. A request object
        // carries its own state and nonce, so a provider that reads past it
        // answers with the wrong ones.
        if (mapParam.containsKey("request")) {
            return redirect(strRedirect, mapError("request_not_supported",
                    "this provider does not accept a request object", strState));
        }
        if (mapParam.containsKey("request_uri")) {
            return redirect(strRedirect, mapError("request_uri_not_supported",
                    "this provider does not accept a request_uri", strState));
        }

        if (!"code".equals(mapParam.get("response_type"))) {
            return redirect(strRedirect, mapError("unsupported_response_type",
                    "only response_type=code is supported", strState));
        }
        String strChallenge = mapParam.get("code_challenge");
        if (!isBlank(strChallenge) && !OidcFlow.STR_METHOD_S256.equals(mapParam.get("code_challenge_method"))) {
            return redirect(strRedirect, mapError("invalid_request",
                    "code_challenge_method must be S256", strState));
        }
        String strMaxAge = mapParam.get("max_age");
        if (!isBlank(strMaxAge) && !isDigits(strMaxAge)) {
            return redirect(strRedirect, mapError("invalid_request",
                    "max_age must be a non-negative number of seconds", strState));
        }

        // THE LOGIN PAGE POSTING BACK. This authenticates, so it satisfies
        // prompt=login and any max_age by construction.
        if (mapParam.containsKey("username")) {
            String strUser = mapParam.get("username");
            if (!users.isValid(strUser, mapParam.get("password")))
                return loginPage(mapParam, true);
            String strOpened = sessions.strOpen(strUser);
            return redirectWithCode(mapParam, idClient, strRedirect, strState, strChallenge,
                    strUser, Instant.now(), strCookie(strOpened, false));
        }

        String strPrompt = mapParam.get("prompt");
        boolean flagNone = hasPrompt(strPrompt, "none");
        boolean flagLogin = hasPrompt(strPrompt, "login");
        // Core 3.1.2.1: `none` may not be combined with any other value.
        if (flagNone && flagLogin) {
            return redirect(strRedirect, mapError("invalid_request",
                    "prompt=none cannot be combined with another prompt value", strState));
        }

        OidcSessions.Session session = sessions.session(strSid);
        if (OidcSessions.flagStale(session, strMaxAge))
            session = null;

        if (session != null && !flagLogin) {
            // Core 3.1.2.1: an id_token_hint names who the client believes is
            // signed in. A different person is not that request's answer.
            String strHint = flow.strSubjectOfHint(mapParam.get("id_token_hint"));
            if (strHint != null && !strHint.equals(session.strUser())) {
                return redirect(strRedirect, mapError("login_required",
                        "the id_token_hint names another user than the one signed in", strState));
            }
            return redirectWithCode(mapParam, idClient, strRedirect, strState, strChallenge,
                    session.strUser(), session.instAuth(), null);
        }

        if (flagNone) {
            return redirect(strRedirect, mapError("login_required",
                    "nobody is signed in at this provider", strState));
        }
        return loginPage(mapParam, false);
    }


    /**
     * @param strAuthorization the `Authorization` header
     * @param strBodyToken the access token in the form body, RFC 6750 section
     *        2.2 - accepted on POST because Core 5.3.1 describes it
     * @return the signed-in user's claims, or 401 with a Bearer challenge
     */
    @Operation(summary = "UserInfo endpoint",
            description = "**Standard: OpenID Connect Core 1.0 section 5.3**, GET and"
                    + " POST, with an access token this service issued. The token"
                    + " may be an `Authorization: Bearer` header or, on POST, an"
                    + " `access_token` form field - **RFC 6750** section 2.2.")
    @RequestMapping(value = IssuerResolver.STR_PATH_USERINFO,
            method = {RequestMethod.GET, RequestMethod.POST},
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> userinfo(
            @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String strAuthorization,
            @RequestParam(name = "access_token", required = false) String strBodyToken) {
        String strHeaderToken = strBearer(strAuthorization);
        String strToken = strHeaderToken != null ? strHeaderToken : blankToNull(strBodyToken);
        String strSub = strToken == null ? null : flow.strSubjectOf(strToken);
        if (strSub == null) {
            // RFC 6750 section 3: no token gets the bare challenge, a bad one
            // gets invalid_token.
            String strChallenge = "Bearer realm=\"" + resolver.strIssuer() + "\""
                    + (strToken == null ? "" : ", error=\"invalid_token\"");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(HttpHeaders.WWW_AUTHENTICATE, strChallenge).build();
        }
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("sub", strSub);
        map.put("preferred_username", strSub);
        return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, STR_NO_STORE).body(map);
    }


    /**
     * RP-initiated logout. It ends the session this browser carries and then
     * sends it back where the client asked.
     *
     * @param mapParam `post_logout_redirect_uri`, `state`, `id_token_hint`,
     *        `client_id`
     * @param strSid the session cookie, or null
     * @return a redirect to post_logout_redirect_uri, or a signed-out page
     */
    @Operation(summary = "End-session endpoint - sign out",
            description = "**Standard: OpenID Connect RP-Initiated Logout 1.0.**"
                    + " Ends the browser's session and redirects to"
                    + " `post_logout_redirect_uri` with `state`.")
    @RequestMapping(value = IssuerResolver.STR_PATH_LOGOUT,
            method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<String> logout(@RequestParam Map<String, String> mapParam,
            @CookieValue(name = OidcSessions.STR_COOKIE, required = false) String strSid) {
        sessions.close(strSid);
        String strClear = strCookie("", true);
        String strPost = mapParam.get("post_logout_redirect_uri");
        if (isRedirectUri(strPost)) {
            Map<String, String> mapQ = new LinkedHashMap<>();
            if (mapParam.get("state") != null)
                mapQ.put("state", mapParam.get("state"));
            return redirect(strPost, mapQ, strClear);
        }
        return ResponseEntity.ok().contentType(TYPE_HTML)
                .header(HttpHeaders.CACHE_CONTROL, STR_NO_STORE)
                .header(HttpHeaders.SET_COOKIE, strClear)
                .body(strHead("Signed out") + "<h1>Signed out</h1>\n<p>"
                        + "This browser is no longer signed in.</p>\n</body></html>\n");
    }


    /**
     * Issues a code for a user this request has established, and redirects.
     *
     * @param mapParam the request's parameters
     * @param idClient the client
     * @param strRedirect where the code goes
     * @param strState the state to echo, or null
     * @param strChallenge the PKCE challenge, or null
     * @param strUser the user the code speaks for
     * @param instAuth when that user authenticated - the `auth_time` claim
     * @param strCookie a Set-Cookie value, or null to send none
     * @return the 302
     */
    private ResponseEntity<String> redirectWithCode(Map<String, String> mapParam, String idClient,
            String strRedirect, String strState, String strChallenge, String strUser,
            Instant instAuth, String strCookie) {
        String strCode = flow.strIssueCode(strUser, idClient, strRedirect,
                mapParam.get("scope"), mapParam.get("audience"), strChallenge,
                mapParam.get("nonce"), instAuth);
        Map<String, String> mapQ = new LinkedHashMap<>();
        mapQ.put("code", strCode);
        if (strState != null)
            mapQ.put("state", strState);
        mapQ.put("iss", resolver.strIssuer());
        return redirect(strRedirect, mapQ, strCookie);
    }


    /**
     * @param strHandle the session handle, or an empty string to clear
     * @param flagClear true to expire it immediately
     * @return a Set-Cookie value; `Secure` only when the issuer is https, since
     *         a browser drops a Secure cookie set over plain http
     */
    private String strCookie(String strHandle, boolean flagClear) {
        StringBuilder sb = new StringBuilder(OidcSessions.STR_COOKIE);
        sb.append('=').append(strHandle);
        sb.append("; Path=/; HttpOnly; SameSite=Lax");
        if (resolver.strIssuer().regionMatches(true, 0, "https:", 0, 6))
            sb.append("; Secure");
        if (flagClear)
            sb.append("; Max-Age=0");
        return sb.toString();
    }


    private ResponseEntity<String> loginPage(Map<String, String> mapParam, boolean flagFailed) {
        StringBuilder sb = new StringBuilder();
        sb.append(strHead("Sign in"));
        sb.append("<h1>Sign in</h1>\n<p class=\"who\">to <b>").append(esc(mapParam.get("client_id")))
                .append("</b></p>\n");
        if (flagFailed)
            sb.append("<p class=\"err\">Invalid name or password.</p>\n");
        sb.append("<form method=\"post\" action=\"").append(IssuerResolver.STR_PATH_AUTHORIZE).append("\">\n");
        for (Map.Entry<String, String> entParam : mapParam.entrySet()) {
            if (!SET_PARAM_CARRIED.contains(entParam.getKey()))
                continue;
            sb.append("<input type=\"hidden\" name=\"").append(esc(entParam.getKey()))
                    .append("\" value=\"").append(esc(entParam.getValue())).append("\">\n");
        }
        String strUser = flagFailed ? mapParam.get("username") : "";
        sb.append("<label for=\"username\">Name</label>\n");
        sb.append("<input id=\"username\" name=\"username\" type=\"text\" autocomplete=\"username\""
                + " autofocus value=\"").append(esc(strUser)).append("\">\n");
        sb.append("<label for=\"password\">Password</label>\n");
        sb.append("<input id=\"password\" name=\"password\" type=\"password\""
                + " autocomplete=\"current-password\">\n");
        sb.append("<input type=\"submit\" value=\"Sign in\">\n</form>\n");
        sb.append("<p class=\"note\">Raposza OIDC - a test identity provider. Not for production.</p>\n");
        sb.append("</body></html>\n");
        return ResponseEntity.ok().contentType(TYPE_HTML)
                .header(HttpHeaders.CACHE_CONTROL, STR_NO_STORE).body(sb.toString());
    }


    private static ResponseEntity<String> page(HttpStatus status, String strTitle, String strText) {
        String strBody = strHead(strTitle) + "<h1>" + esc(strTitle) + "</h1>\n<p>" + esc(strText)
                + "</p>\n</body></html>\n";
        return ResponseEntity.status(status).contentType(TYPE_HTML)
                .header(HttpHeaders.CACHE_CONTROL, STR_NO_STORE).body(strBody);
    }


    private static String strHead(String strTitle) {
        return "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                + "<title>" + esc(strTitle) + " - Raposza OIDC</title>\n<style>"
                + "body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}"
                + "label,input{display:block;width:100%;box-sizing:border-box;margin:.35rem 0}"
                + "input{padding:.45rem}input[type=submit]{margin-top:1rem;cursor:pointer}"
                + ".err{color:#b00020}.who,.note{color:#555}.note{font-size:.8rem;margin-top:2rem}"
                + "</style></head><body>\n";
    }


    /**
     * @param strBase the client's URI, possibly carrying a query already
     * @param mapQ the parameters to add, form-encoded
     * @return a 302 to it
     */
    private static ResponseEntity<String> redirect(String strBase, Map<String, String> mapQ) {
        return redirect(strBase, mapQ, null);
    }


    /**
     * @param strBase the client's URI, possibly carrying a query already
     * @param mapQ the parameters to add, form-encoded
     * @param strCookie a Set-Cookie value, or null to send none
     * @return a 302 to it
     */
    private static ResponseEntity<String> redirect(String strBase, Map<String, String> mapQ,
            String strCookie) {
        StringBuilder sb = new StringBuilder(strBase);
        char chSep = strBase.indexOf('?') < 0 ? '?' : '&';
        for (Map.Entry<String, String> entQ : mapQ.entrySet()) {
            sb.append(chSep).append(enc(entQ.getKey())).append('=').append(enc(entQ.getValue()));
            chSep = '&';
        }
        ResponseEntity.BodyBuilder bld = ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.LOCATION, sb.toString())
                .header(HttpHeaders.CACHE_CONTROL, STR_NO_STORE);
        if (strCookie != null)
            bld = bld.header(HttpHeaders.SET_COOKIE, strCookie);
        return bld.build();
    }


    private Map<String, String> mapError(String strError, String strDescription, String strState) {
        Map<String, String> map = new LinkedHashMap<>();
        map.put("error", strError);
        map.put("error_description", strDescription);
        if (strState != null)
            map.put("state", strState);
        map.put("iss", resolver.strIssuer());
        return map;
    }


    /**
     * @param str a candidate redirect URI
     * @return true when it is absolute, http or https, has a host and no
     *         fragment - RFC 6749 section 3.1.2
     */
    static boolean isRedirectUri(String str) {
        if (isBlank(str))
            return false;
        try {
            URI uri = new URI(str);
            String strScheme = uri.getScheme();
            return uri.isAbsolute() && uri.getHost() != null && uri.getRawFragment() == null
                    && ("http".equalsIgnoreCase(strScheme) || "https".equalsIgnoreCase(strScheme));
        }
        catch (URISyntaxException ex) {
            return false;
        }
    }


    private static boolean hasPrompt(String strPrompt, String strWant) {
        return OidcFlow.hasScope(strPrompt, strWant);
    }


    static boolean isDigits(String str) {
        if (str == null || str.isBlank())
            return false;
        for (int idxChar = 0; idxChar < str.length(); idxChar++) {
            if (!Character.isDigit(str.charAt(idxChar)))
                return false;
        }
        return true;
    }


    private static String strBearer(String strAuthorization) {
        if (strAuthorization == null)
            return null;
        String strTrim = strAuthorization.trim();
        if (strTrim.length() <= 7 || !strTrim.regionMatches(true, 0, "Bearer ", 0, 7))
            return null;
        return strTrim.substring(7).trim();
    }


    private static String blankToNull(String str) {
        return str == null || str.isBlank() ? null : str.trim();
    }


    private static String enc(String str) {
        return URLEncoder.encode(str == null ? "" : str, StandardCharsets.UTF_8);
    }


    private static String esc(String str) {
        return HtmlUtils.htmlEscape(str == null ? "" : str);
    }


    private static boolean isBlank(String str) {
        return str == null || str.isBlank();
    }

}
