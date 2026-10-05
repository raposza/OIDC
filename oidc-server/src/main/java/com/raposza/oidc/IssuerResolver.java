// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;


/**
 * THE issuer - one value, resolved once, used by everything.
 *
 * <h2>Why this replaced a per-request derivation</h2>
 *
 * The mint used to answer the issuer question from whatever URL the request
 * happened to arrive on. That is correct for exactly one caller at a time and
 * wrong the moment there are two: a participant inside a virtual machine
 * fetches the discovery document at the routable address and records
 * `issuer=http://192.168.x.x:32002`, a curl on the host mints a token at
 * loopback and that token carries `iss=http://localhost:32002`, and the two do
 * not match. OpenID Connect Discovery 1.0 section 4.3 and RFC 8414 section 3.3
 * both require the `issuer` in the metadata and the `iss` in a token to be the
 * SAME string, compared literally.
 *
 * So one value is resolved at startup and every consumer reads it: the
 * discovery document's `issuer`, every endpoint URL that document advertises,
 * and the `iss` claim of every token minted.
 *
 * <h2>How it is resolved</h2>
 *
 * IT IS NOT RESOLVED. `raposza.oidc.issuer` is required and is the value,
 * with any trailing slash removed - {@link MintSettings} refuses to start
 * without it. Until 0.4.0 a blank setting was guessed from this machine's
 * addresses, and a guess is exactly the thing that cannot be compared
 * literally: the address a verifier reaches the service on is known to
 * whoever deploys it and to nothing on this machine.
 *
 * <h2>The paths</h2>
 *
 * The `/oauth2/` names are a PROJECT CONVENTION and form no part of any
 * protocol. A conforming client reads them out of the discovery document and
 * never builds them; they are constants here so that the document and the
 * service cannot disagree about what they are.
 *
 * Author Claude/bentzn
 */
@Component
public final class IssuerResolver {

    /** OpenID Connect Discovery 1.0 section 4. */
    public static final String STR_PATH_DISCOVERY_OIDC = "/.well-known/openid-configuration";

    /** RFC 8414 section 3 - the same document, at the OAuth location. */
    public static final String STR_PATH_DISCOVERY_OAUTH =
            "/.well-known/oauth-authorization-server";

    /** Project convention. A client takes this from `token_endpoint`. */
    public static final String STR_PATH_TOKEN = "/oauth2/token";

    /** Project convention. A client takes this from `jwks_uri`. */
    public static final String STR_PATH_JWKS = "/oauth2/jwks";

    /** Project convention. Advertised nowhere, because nothing standard has it. */
    public static final String STR_PATH_JWKS_PRIVATE = "/oauth2/jwks-private";

    /** Project convention. A client takes this from `authorization_endpoint`. */
    public static final String STR_PATH_AUTHORIZE = "/oauth2/authorize";

    /** Project convention. A client takes this from `userinfo_endpoint`. */
    public static final String STR_PATH_USERINFO = "/oauth2/userinfo";

    /** Project convention. A client takes this from `end_session_endpoint`. */
    public static final String STR_PATH_LOGOUT = "/oauth2/logout";

    private static final Logger log = LoggerFactory.getLogger(IssuerResolver.class);

    private final String strIssuer;


    /**
     * @param settings the configuration, which carries the issuer
     */
    public IssuerResolver(MintSettings settings) {
        if (settings.strIssuerFixed() == null)
            throw new IllegalStateException("raposza.oidc.issuer is not set");
        this.strIssuer = strNoTrailingSlash(settings.strIssuerFixed());
        log.info("issuer {} (raposza.oidc.issuer)", strIssuer);
    }


    /**
     * @return the one issuer, written into the discovery document and into
     *         every token
     */
    public String strIssuer() {
        return strIssuer;
    }


    /**
     * @return true, always since 0.4.0 - kept because the overview and the
     *         status page publish it
     */
    public boolean flagPinned() {
        return true;
    }


    /**
     * @param strPath a path beginning with a slash
     * @return the absolute URL a client is to be given for it
     */
    public String strUrl(String strPath) {
        return strIssuer + strPath;
    }


    /**
     * The URL THIS request arrived on, which is not the issuer.
     *
     * Used only by the plain-text index page, where the point is to echo back
     * the address the reader actually typed. Nothing that a verifier compares
     * may be built from it.
     *
     * @return the scheme, host, port and context path of the current request
     */
    static String strOfRequest() {
        return ServletUriComponentsBuilder.fromCurrentContextPath().build().toUriString();
    }


    /**
     * @param strUrl a URL
     * @return it without a trailing slash, because the issuer is compared as a
     *         literal string and one slash is one mismatch
     */
    private static String strNoTrailingSlash(String strUrl) {
        String strOut = strUrl.trim();
        while (strOut.endsWith("/")) {
            strOut = strOut.substring(0, strOut.length() - 1);
        }
        return strOut;
    }

}
