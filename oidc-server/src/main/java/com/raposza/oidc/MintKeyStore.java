// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.raposza.jwt.MintAlg;
import com.raposza.jwt.MintKeys;
import com.raposza.jwt.TokenException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * The one key set the service mints from, and the one thing that can be swapped
 * while it runs.
 *
 * <h2>Why reload is explicit rather than a file watcher</h2>
 *
 * The keys change when somebody changes them: a hand-edited JWKS, a directory
 * restored from a backup, a key deleted to force a regeneration. A watcher
 * would pick up a half-written file - the private set is written before the
 * public one - and would then serve a set that never existed. An explicit
 * reload happens when the operator says the file is finished, which is the only
 * moment that is true.
 *
 * The reference is volatile and replaced whole. A request in flight keeps the
 * set it started with rather than seeing half of each.
 *
 * <h2>The three writes, added 2026-09-19 for the UI - D-774</h2>
 *
 * A change this service makes itself does not go through the window the watcher
 * note describes: the new set is built in memory, written to disk, and only
 * then swapped in. A failed write leaves the running set untouched, so a full
 * disk costs the change rather than the service.
 *
 * <h2>Removing a standard key is refused, and that is not a permission</h2>
 *
 * {@link MintKeys#ensure} REGENERATES any signing algorithm it does not find,
 * so deleting `rs256` would succeed, write a set without it, and hand back a
 * set that has it again at the next reload or restart. A caller would read that
 * as the delete silently failing. It is refused with the reason instead.
 *
 * Author Claude/bentzn
 */
@Component
public final class MintKeyStore {

    private static final Logger log = LoggerFactory.getLogger(MintKeyStore.class);

    private final MintSettings settings;

    private volatile MintKeys keys;


    public MintKeyStore(MintSettings settings) {
        this.settings = settings;
        this.keys = load();
    }


    /**
     * @return the set every request mints from
     */
    public MintKeys keys() {
        return keys;
    }


    /**
     * Re-reads the JWKS from disk, generating anything that is missing.
     *
     * @return the set now in use
     */
    public MintKeys reload() {
        MintKeys keysNew = load();
        this.keys = keysNew;
        return keysNew;
    }


    /**
     * Replaces one key's material with freshly generated material of the same
     * algorithm, keeping its id.
     *
     * Every token already issued under that id stops verifying, and every
     * participant holding the old public half has to re-read the JWKS. That is
     * what a rotation IS; it is said here because the button that calls this is
     * one click away from the button that adds a key.
     *
     * @param strKid the key to rotate
     * @return the set now in use
     * @throws TokenException when no key carries that id, or its algorithm
     *         cannot be told from the id
     */
    public synchronized MintKeys rotate(String strKid) {
        MintKeys keysNow = keys;
        keysNow.jwkOfKid(strKid);
        MintAlg alg = algOfKid(strKid);
        return swap(keysNow.withJwk(strKid.trim(), alg.generate(strKid.trim())),
                "rotated " + strKid);
    }


    /**
     * Adds a key under an id of the caller's choosing.
     *
     * @param strKid the new id, which must not be in use
     * @param strAlg the algorithm to generate
     * @return the set now in use
     * @throws TokenException when the id is in use or blank
     * @throws IllegalArgumentException when the algorithm is unknown
     */
    public synchronized MintKeys add(String strKid, String strAlg) {
        if (strKid == null || strKid.isBlank())
            throw new TokenException("no key id supplied");

        String strTrim = strKid.trim();
        MintKeys keysNow = keys;
        if (keysNow.lstKid().contains(strTrim))
            throw new TokenException("key '" + strTrim + "' already exists; rotate it instead");

        MintAlg alg = MintAlg.of(strAlg);
        if (!alg.flagSigned())
            throw new TokenException("NONE has no key to generate");
        return swap(keysNow.withJwk(strTrim, alg.generate(strTrim)),
                "added " + strTrim);
    }


    /**
     * Removes a key that is not one of the standard set.
     *
     * @param strKid the key to remove
     * @return the set now in use
     * @throws TokenException when the id is unknown, or names a standard key
     */
    public synchronized MintKeys remove(String strKid) {
        MintKeys keysNow = keys;
        keysNow.jwkOfKid(strKid);

        String strTrim = strKid.trim();
        if (MintKeys.flagStandardKid(strTrim)) {
            throw new TokenException("'" + strTrim + "' is a standard key and is"
                    + " regenerated on the next load, so removing it would not"
                    + " hold. Rotate it instead.");
        }
        return swap(keysNow.withoutJwk(strTrim), "removed " + strTrim);
    }


    private MintKeys swap(MintKeys keysNew, String strWhat) {
        // WRITTEN BEFORE SWAPPED. A write that throws leaves the running set
        // exactly as it was.
        keysNew.write();
        this.keys = keysNew;
        // KEY IDS ONLY, as everywhere else in this class.
        log.info("keys {} - {}", keysNew.lstKid(), strWhat);
        return keysNew;
    }


    private static MintAlg algOfKid(String strKid) {
        String strTrim = strKid == null ? "" : strKid.trim();
        for (MintAlg alg : MintAlg.values()) {
            if (alg.flagSigned() && alg.strKid().equals(strTrim))
                return alg;
        }
        throw new TokenException("the algorithm of '" + strTrim + "' cannot be told"
                + " from its id, so it cannot be rotated. Remove it and add one.");
    }


    private MintKeys load() {
        MintKeys keysNew = MintKeys.ensure(settings.dirKeys());
        // KEY IDS ONLY. Nothing about a key beyond its id may reach a log line,
        // and the ids are exactly what an operator needs to see to know which
        // set came up.
        log.info("keys {} from {}", keysNew.lstKid(), keysNew.dirKeys());
        return keysNew;
    }

}
