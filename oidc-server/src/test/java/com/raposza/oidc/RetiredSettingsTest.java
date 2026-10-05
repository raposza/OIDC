// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

import java.util.List;
import java.util.Map;

/**
 * The old prefix refused in every form a start can carry it, and the new one
 * left alone.
 *
 * The environment under test has the JVM's own system properties and
 * environment REMOVED, so a variable set on the machine running the build
 * cannot decide the result.
 *
 * Author Claude/bentzn
 */
class RetiredSettingsTest {

    private static StandardEnvironment envWith(Map<String, Object> mapProps, Map<String, Object> mapEnv) {
        StandardEnvironment env = new StandardEnvironment();
        MutablePropertySources src = env.getPropertySources();
        src.remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        src.remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        src.addLast(new MapPropertySource("commandLineArgs", mapProps));
        src.addLast(new SystemEnvironmentPropertySource("env", mapEnv));
        return env;
    }


    @Test
    void anOldNameOnTheCommandLineIsRefusedAndTheNewOneNamed() {
        StandardEnvironment env = envWith(Map.of("raposza.jwtmint.issuer", "http://127.0.0.1:32002"), Map.of());

        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> RetiredSettings.refuse(env));
        assertTrue(ex.getMessage().contains("raposza.jwtmint.issuer  ->  raposza.oidc.issuer"), ex.getMessage());
    }


    @Test
    void anOldNameInTheEnvironmentIsRefusedInItsOwnForm() {
        StandardEnvironment env = envWith(Map.of(), Map.of("RAPOSZA_JWTMINT_ADMIN_PASSWORD", "x"));

        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> RetiredSettings.refuse(env));
        assertTrue(ex.getMessage().contains("RAPOSZA_JWTMINT_ADMIN_PASSWORD  ->  RAPOSZA_OIDC_ADMIN_PASSWORD"),
                ex.getMessage());
    }


    @Test
    void everyOldNameIsListedOnce() {
        StandardEnvironment env = envWith(Map.of("raposza.jwtmint.issuer", "a", "raposza.jwtmint.users", "b"),
                Map.of("RAPOSZA_JWTMINT_ISSUER", "a"));

        List<String> lstFound = RetiredSettings.lstRetired(env);
        assertEquals(3, lstFound.size(), lstFound.toString());
    }


    @Test
    void theNewNamesAndUnrelatedOnesPass() {
        StandardEnvironment env = envWith(
                Map.of("raposza.oidc.issuer", "http://127.0.0.1:32002", "raposza.oidc.dir-keys", "/k",
                        "server.port", "32002", "raposza.jwtmintish", "x"),
                Map.of("RAPOSZA_OIDC_ISSUER", "x", "HOME", "/home/x"));

        assertDoesNotThrow(() -> RetiredSettings.refuse(env));
    }
}
