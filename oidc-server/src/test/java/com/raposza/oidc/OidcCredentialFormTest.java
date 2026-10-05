// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * 0.5.0: a name and a password are read from the sign-in form's POST body
 * only. In an address they land in every access log and proxy log on the way.
 *
 * Author Claude/bentzn
 */
class OidcCredentialFormTest {

    @Test
    void aPostWithNothingInItsAddressIsTheForm() {
        assertTrue(OidcController.flagCredentialFromForm("POST", null));
        assertTrue(OidcController.flagCredentialFromForm("POST", ""));
        assertTrue(OidcController.flagCredentialFromForm("post", "client_id=c&state=s"));
    }


    @Test
    void aGetIsNeverTheForm() {
        assertFalse(OidcController.flagCredentialFromForm("GET", null));
        assertFalse(OidcController.flagCredentialFromForm("GET", "username=alice&password=x"));
    }


    @Test
    void aPostCarryingEitherInItsAddressIsRefused() {
        assertFalse(OidcController.flagCredentialFromForm("POST", "client_id=c&password=x"));
        assertFalse(OidcController.flagCredentialFromForm("POST", "username"));
        // ENCODED NAMES ARE THE SAME NAMES - the container decodes them
        assertFalse(OidcController.flagCredentialFromForm("POST", "pass%77ord=x"));
        // and an address that cannot be decoded is not trusted either
        assertFalse(OidcController.flagCredentialFromForm("POST", "%zz=1"));
    }

}
