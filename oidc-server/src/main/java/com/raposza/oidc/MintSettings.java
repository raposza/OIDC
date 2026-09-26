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
     * @param strIssuer the `iss` - REQUIRED; blank refuses to start
     * @param nTtlSeconds token lifetime when a request does not say
     * @param strAlg the algorithm when a request does not say
     * @param strSubject the `sub` when a request does not say
     * @param strAdminUserIn the admin name, default `admin`
     * @param strAdminPasswordIn the admin password; BLANK LEAVES THE WRITE
     *        PATHS OPEN - {@link AdminGuard} says why that is the default
     * @param flagStandaloneIn true for a service on a network rather than one a
     *        window starts; it REFUSES TO START without an admin password
     * @throws IllegalStateException when the issuer is missing, or standalone
     *         is set and the password is
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

        // NO ISSUER, NO START - the operator's decision of 2026-09-23. Until
        // 0.4.0 a blank issuer was GUESSED from the machine's own addresses,
        // and the guess was wrong in the one way that cannot be seen: the
        // service answers, the discovery document is served, tokens are
        // minted, and EVERY consumer rejects every one of them, because RFC
        // 8414 section 3.3 compares the issuer in the document and the `iss`
        // of a token literally. On a workstation with a container network the
        // guess advertised `http://10.244.0.0:32002`, the pod network's own
        // address. Nothing in that failure points here, so the service refuses
        // instead of guessing.
        if (strIssuerFixed == null) {
            throw new IllegalStateException("raposza.jwtmint.issuer is not set. It is"
                    + " the address consumers reach this service on, and it is written"
                    + " into every token and the discovery document, so it is not"
                    + " guessed. Set it, for example --raposza.jwtmint.issuer="
                    + "http://127.0.0.1:32002 on this machine, or"
                    + " --raposza.jwtmint.issuer=https://id.example.com behind a proxy");
        }

        // STANDALONE REFUSES RATHER THAN WARNS on the open write paths: a
        // service on a network with no credential in front of its key
        // management.
        if (flagStandalone) {
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
