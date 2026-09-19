// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * One registered client: what it is called, what it knows, and where it may be
 * sent back to.
 *
 * <h2>Three fields, and that is the whole of it</h2>
 *
 * A registry is not what makes an identity provider a secure one. Password
 * policy, lockout, MFA, federation, revocation, admin roles, durable storage
 * and audit are - and this service has none of them and wants none of them,
 * D-711. What a registry makes it is CORRECT: without one, a `redirect_uri`
 * nobody registered works here and is refused by any real provider, and the
 * failure arrives at the moment somebody switches. That is the substitution
 * this whole product exists to make safe - `raposza_oidc.md`.
 *
 * <h2>A blank secret means a PUBLIC client</h2>
 *
 * A public client authenticates with `none` and must not be allowed to present
 * a secret; a confidential one must present the right one. A single blank-or-not
 * field carries that, so there is no third state to keep in step with the other
 * two.
 *
 * @param idClient the `client_id`
 * @param strSecret the shared secret, BLANK for a public client
 * @param lstRedirect every `redirect_uri` this client may be sent back to,
 *        compared as whole strings - OpenID Connect Core 1.0 section 3.1.2.1
 *
 * Author Claude/bentzn
 */
public record OidcClient(String idClient, String strSecret, List<String> lstRedirect) {

    public OidcClient {
        lstRedirect = lstRedirect == null
                ? List.of() : Collections.unmodifiableList(new ArrayList<>(lstRedirect));
        strSecret = strSecret == null ? "" : strSecret;
    }


    /**
     * @return true when this client has no secret and authenticates with `none`
     */
    public boolean flagPublic() {
        return strSecret.isBlank();
    }


    /**
     * @param strUri what the request asked to be sent back to
     * @return true when that is one of the registered URIs, compared whole
     */
    public boolean flagRedirect(String strUri) {
        // SIMPLE STRING COMPARISON, which Core 3.1.2.1 requires. Anything
        // cleverer - ignoring a trailing slash, matching a prefix - is the
        // difference between this and a real provider, and the difference is
        // the whole defect being fixed here.
        return strUri != null && lstRedirect.contains(strUri);
    }

}
