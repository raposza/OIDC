// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.raposza.jwt.MintAlg;
import com.raposza.jwt.MintKeys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

/**
 * What the service was configured with, resolved once.
 *
 * The blank defaults are not missing values. A blank key directory means the
 * shared one under the home directory, and a blank issuer means "whatever
 * address this request arrived on" - which is the only answer that works for a
 * caller inside a virtual machine and a caller on the host at the same time.
 *
 * Author Claude/bentzn
 */
@Component
public final class MintSettings {

    private final Path dirKeys;

    private final String strIssuerFixed;

    private final long nTtlSecondsDefault;

    private final MintAlg algDefault;

    private final String strSubjectDefault;

    private final String strAdminUser;

    private final String strAdminPassword;

    private final boolean flagStandalone;


    /**
     * @param strDirKeys where the JWKS lives, blank for the default
     * @param strIssuer a fixed `iss`, blank to derive it per request
     * @param nTtlSeconds token lifetime when a request does not say
     * @param strAlg the algorithm when a request does not say
     * @param strSubject the `sub` when a request does not say
     * @param strAdminUserIn the admin name, default `admin`
     * @param strAdminPasswordIn the admin password; BLANK LEAVES THE WRITE
     *        PATHS OPEN - {@link AdminGuard} says why that is the default
     * @param flagStandaloneIn true for a service on a network rather than one a
     *        window starts; it REFUSES TO START without a pinned issuer and an
     *        admin password
     * @throws IllegalStateException when standalone is set and either is missing
     */
    public MintSettings(@Value("${raposza.jwtmint.dir-keys:}") String strDirKeys,
            @Value("${raposza.jwtmint.issuer:}") String strIssuer,
            @Value("${raposza.jwtmint.ttl-seconds:86400}") long nTtlSeconds,
            @Value("${raposza.jwtmint.default-alg:RS256}") String strAlg,
            @Value("${raposza.jwtmint.default-subject:raposza}") String strSubject,
            @Value("${raposza.jwtmint.admin.user:admin}") String strAdminUserIn,
            @Value("${raposza.jwtmint.admin.password:}") String strAdminPasswordIn,
            @Value("${raposza.jwtmint.standalone:false}") boolean flagStandaloneIn) {
        this.dirKeys = (strDirKeys == null || strDirKeys.isBlank())
                ? MintKeys.dirDefault()
                : Path.of(strDirKeys.trim()).toAbsolutePath().normalize();
        this.strIssuerFixed = (strIssuer == null || strIssuer.isBlank()) ? null : strIssuer.trim();
        this.nTtlSecondsDefault = nTtlSeconds;
        this.algDefault = MintAlg.of(strAlg);
        this.strSubjectDefault = (strSubject == null || strSubject.isBlank())
                ? "raposza" : strSubject.trim();
        this.strAdminUser = (strAdminUserIn == null || strAdminUserIn.isBlank())
                ? "admin" : strAdminUserIn.trim();
        this.strAdminPassword = strAdminPasswordIn == null ? "" : strAdminPasswordIn;
        this.flagStandalone = flagStandaloneIn;

        // STANDALONE REFUSES RATHER THAN WARNS, and both reasons are failures
        // that otherwise appear far from their cause.
        //
        // An unpinned issuer behind a proxy is the expensive one: the service
        // answers, the discovery document is served, tokens are minted, and
        // EVERY consumer rejects every one of them, because RFC 8414 section
        // 3.3 compares the issuer in the document and the `iss` of a token
        // literally and the service saw `http://host:32002` where the consumer
        // saw `https://id.example.com`. Nothing in that failure points here.
        //
        // The open write paths are the other: a service on a network with no
        // credential in front of its key management.
        if (flagStandalone) {
            if (strIssuerFixed == null) {
                throw new IllegalStateException("raposza.jwtmint.standalone is set"
                        + " and raposza.jwtmint.issuer is not. A standalone service"
                        + " sits behind a proxy, and an issuer resolved from the"
                        + " local address is not the one consumers reached - every"
                        + " token would be rejected. Set it to the external origin,"
                        + " for example https://id.example.com");
            }
            if (!flagAdminSet()) {
                throw new IllegalStateException("raposza.jwtmint.standalone is set"
                        + " and raposza.jwtmint.admin.password is not. That would"
                        + " leave key and user management open to anyone who can"
                        + " reach this service.");
            }
        }
    }


    public Path dirKeys() {
        return dirKeys;
    }


    /**
     * @return a configured issuer, or null when it is to be derived from the
     *         request
     */
    public String strIssuerFixed() {
        return strIssuerFixed;
    }


    public long nTtlSecondsDefault() {
        return nTtlSecondsDefault;
    }


    public MintAlg algDefault() {
        return algDefault;
    }


    public String strSubjectDefault() {
        return strSubjectDefault;
    }


    /**
     * @return the admin name, `admin` when nothing set one
     */
    public String strAdminUser() {
        return strAdminUser;
    }


    /**
     * @return the admin password, blank when there is none
     */
    public String strAdminPassword() {
        return strAdminPassword;
    }


    /**
     * @return whether a credential is configured at all; false leaves the write
     *         paths open
     */
    public boolean flagAdminSet() {
        return !strAdminPassword.isBlank();
    }


    /**
     * @return true for a service on a network rather than one a window starts
     */
    public boolean flagStandalone() {
        return flagStandalone;
    }

}
