// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

/**
 * Raposza OIDC CARRIES ITS OWN fonts and style - the design package's rule of
 * 2026-09-24: a standalone web component never reaches for them over the
 * network. Spring Boot serves `META-INF/resources/` from every jar on the
 * classpath, so being on the classpath and not behind the admin guard is the
 * whole of it.
 *
 * Author Claude/bentzn
 * Generated 2026-09-24T08:30:00Z
 */
class DesignResourcesTest {

    @Test
    void theDesignFilesAreOnTheClasspath() {
        ClassLoader loader = DesignResourcesTest.class.getClassLoader();
        assertNotNull(loader.getResource("META-INF/resources/raposza/fonts.css"));
        assertNotNull(loader.getResource("META-INF/resources/raposza/tokens.css"));
        assertNotNull(loader.getResource("META-INF/resources/raposza/fonts/InterVariable.woff2"));
        assertNotNull(loader.getResource("META-INF/resources/raposza/fonts/hack-regular.woff2"));
    }


    @Test
    void theDesignPathsAreNotGuarded() {
        assertFalse(AdminGuard.flagGuarded("/raposza/fonts.css"));
        assertFalse(AdminGuard.flagGuarded("/raposza/fonts/InterVariable.woff2"));
    }

}
