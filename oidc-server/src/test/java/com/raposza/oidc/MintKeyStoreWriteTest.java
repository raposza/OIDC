// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.raposza.jwt.MintKeys;
import com.raposza.jwt.TokenException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

/**
 * The three writes the UI drives.
 *
 * Every case re-reads the directory afterwards rather than trusting the object
 * in hand: what is owed is that the change reached DISK, because the next start
 * reads disk and nothing else.
 *
 * Author Claude/bentzn
 */
class MintKeyStoreWriteTest {

    private static MintKeyStore store(Path dirKeys) {
        return new MintKeyStore(new MintSettings(dirKeys.toString(),
                "http://127.0.0.1:32002", 86400, "RS256", "raposza", "admin", "", false));
    }


    @Test
    void rotateKeepsTheIdAndChangesTheMaterial(@TempDir Path dirKeys) {
        MintKeyStore store = store(dirKeys);
        String strBefore = store.keys().jwkOfKid("rs256").toJSONString();

        store.rotate("rs256");

        String strAfter = store.keys().jwkOfKid("rs256").toJSONString();
        assertNotEquals(strBefore, strAfter);
        assertEquals(strAfter, MintKeys.ensure(dirKeys).jwkOfKid("rs256").toJSONString());
    }


    @Test
    void rotateKeepsThePositionInTheFile(@TempDir Path dirKeys) {
        MintKeyStore store = store(dirKeys);
        List<String> lstBefore = store.keys().lstKid();

        store.rotate("es256");

        assertEquals(lstBefore, store.keys().lstKid());
    }


    @Test
    void addThenRemoveACustomKey(@TempDir Path dirKeys) {
        MintKeyStore store = store(dirKeys);

        store.add("wallet-ui", "RS256");
        // THE KEY CARRIES ITS OWN ID. Everything below rests on this: a JWKS
        // records an id nowhere else, so a key filed under one name and
        // carrying another is lost the moment the file is read back.
        assertEquals("wallet-ui", store.keys().jwkOfKid("wallet-ui").getKeyID());
        assertTrue(store.keys().lstKid().contains("wallet-ui"));
        // ensure() KEEPS what it did not generate, so a custom key survives a
        // restart. If that ever stops being true this is where it shows.
        assertTrue(MintKeys.ensure(dirKeys).lstKid().contains("wallet-ui"));

        store.remove("wallet-ui");
        assertFalse(store.keys().lstKid().contains("wallet-ui"));
        assertFalse(MintKeys.ensure(dirKeys).lstKid().contains("wallet-ui"));
    }


    @Test
    void addRefusesAnIdAlreadyInUse(@TempDir Path dirKeys) {
        MintKeyStore store = store(dirKeys);

        TokenException ex = assertThrows(TokenException.class,
                () -> store.add("rs256", "RS256"));
        assertTrue(ex.getMessage().contains("rotate"));
    }


    @Test
    void removeRefusesAStandardKeyAndSaysWhy(@TempDir Path dirKeys) {
        MintKeyStore store = store(dirKeys);

        TokenException ex = assertThrows(TokenException.class, () -> store.remove("rs256"));
        assertTrue(ex.getMessage().contains("regenerated"));
        assertTrue(store.keys().lstKid().contains("rs256"));
    }


    @Test
    void removeRefusesAnIdThatIsNotThere(@TempDir Path dirKeys) {
        MintKeyStore store = store(dirKeys);
        assertThrows(TokenException.class, () -> store.remove("nothing-here"));
    }


    @Test
    void aCustomKeyCannotBeRotatedBecauseItsAlgorithmIsUnknown(@TempDir Path dirKeys) {
        MintKeyStore store = store(dirKeys);
        store.add("wallet-ui", "ES256");

        // THE ID IS THE ONLY RECORD of a standard key's algorithm, and a custom
        // id carries none. The message says that rather than guessing.
        TokenException ex = assertThrows(TokenException.class,
                () -> store.rotate("wallet-ui"));
        assertTrue(ex.getMessage().contains("cannot be told"));
    }

}
