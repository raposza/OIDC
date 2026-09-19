// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.JWKSet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Author Claude/bentzn
 */
class MintKeysTest {

    /**
     * @return how many algorithms need a key
     */
    private static int cntKeyed() {
        int cnt = 0;
        for (MintAlg alg : MintAlg.values()) {
            if (alg.flagSigned())
                cnt++;
        }
        return cnt;
    }


    @Test
    void generatesOneKeyPerAlgorithmAndWritesBothFiles(@TempDir Path dirTmp) throws Exception {
        MintKeys keys = MintKeys.ensure(dirTmp);

        assertEquals(cntKeyed(), keys.lstJwk().size());
        assertTrue(Files.isRegularFile(keys.filePrivate()));
        assertTrue(Files.isRegularFile(keys.filePublic()));

        for (MintAlg alg : MintAlg.values()) {
            if (!alg.flagSigned())
                continue;
            assertTrue(keys.jwk(alg).isPrivate(), alg.name() + " must be a private key");
            assertEquals(alg.strKid(), keys.jwk(alg).getKeyID());
        }
    }


    @Test
    void publicSetDropsPrivateMembersAndEverySymmetricKey(@TempDir Path dirTmp) throws Exception {
        MintKeys keys = MintKeys.ensure(dirTmp);

        JWKSet setPublic = JWKSet.parse(keys.renderPublicJwks());
        int cntSymmetric = 0;
        for (MintAlg alg : MintAlg.values()) {
            if (alg.flagSigned() && alg.name().startsWith("HS"))
                cntSymmetric++;
        }
        assertEquals(cntKeyed() - cntSymmetric, setPublic.getKeys().size());
        for (int idx = 0; idx < setPublic.getKeys().size(); idx++) {
            assertFalse(setPublic.getKeys().get(idx).isPrivate(),
                    "the public set must carry no private member");
        }

        // and the private one keeps them
        JWKSet setPrivate = JWKSet.parse(keys.renderPrivateJwks());
        assertEquals(cntKeyed(), setPrivate.getKeys().size());
    }


    @Test
    void aSecondEnsureReusesTheKeysOnDisk(@TempDir Path dirTmp) {
        MintKeys keysFirst = MintKeys.ensure(dirTmp);
        String strFirst = keysFirst.renderPrivateJwks();

        MintKeys keysAgain = MintKeys.ensure(dirTmp);
        assertEquals(strFirst, keysAgain.renderPrivateJwks(),
                "a restart must not invalidate tokens already issued");
    }


    @Test
    void aMissingPublicFileIsRewrittenWithoutRegeneratingAnything(@TempDir Path dirTmp)
            throws Exception {
        MintKeys keysFirst = MintKeys.ensure(dirTmp);
        String strFirst = keysFirst.renderPrivateJwks();
        Files.delete(keysFirst.filePublic());

        MintKeys keysAgain = MintKeys.ensure(dirTmp);
        assertTrue(Files.isRegularFile(keysAgain.filePublic()));
        assertEquals(strFirst, keysAgain.renderPrivateJwks());
    }


    @Test
    void anUnknownKidNamesTheOnesThatExist(@TempDir Path dirTmp) {
        MintKeys keys = MintKeys.ensure(dirTmp);
        TokenException ex = assertThrows(TokenException.class, () -> keys.jwkOfKid("nope"));
        assertTrue(ex.getMessage().contains("rs256"));
    }


    @Test
    void noneHasNoKey(@TempDir Path dirTmp) {
        MintKeys keys = MintKeys.ensure(dirTmp);
        assertThrows(TokenException.class, () -> keys.jwk(MintAlg.NONE));
        assertThrows(TokenException.class, () -> MintAlg.NONE.generate());
    }


    @Test
    void unknownAlgorithmNamesTheKnownOnes() {
        TokenException ex = assertThrows(TokenException.class, () -> MintAlg.of("RS999"));
        assertTrue(ex.getMessage().contains("ES512"));
        assertEquals(MintAlg.HS512, MintAlg.of("hs512"));
    }

}
