// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

/**
 * Every algorithm the mint offers is signed here and verified with the matching
 * verifier. A mint that emits a token nothing can check is a mint that produces
 * a failure indistinguishable from a misconfigured participant.
 *
 * Author Claude/bentzn
 */
class MintSignerTest {

    private static JWTClaimsSet claims() {
        return new JWTClaimsSet.Builder()
                .subject("alice")
                .issuer("http://127.0.0.1:33301")
                .claim("scope", "daml_ledger_api")
                .build();
    }


    private static JWSVerifier verifier(JWK jwk) throws Exception {
        KeyType kty = jwk.getKeyType();
        if (KeyType.OCT.equals(kty))
            return new MACVerifier((OctetSequenceKey) jwk);
        if (KeyType.EC.equals(kty))
            return new ECDSAVerifier(((ECKey) jwk).toPublicJWK());
        return new RSASSAVerifier(((RSAKey) jwk).toPublicJWK());
    }


    @Test
    void everySignedAlgorithmVerifiesWithItsOwnKey(@TempDir Path dirTmp) throws Exception {
        MintKeys keys = MintKeys.ensure(dirTmp);

        for (MintAlg alg : MintAlg.values()) {
            if (!alg.flagSigned())
                continue;

            JWK jwk = keys.jwk(alg);
            String strToken = MintSigner.strSign(alg, jwk, claims());
            SignedJWT jwt = SignedJWT.parse(strToken);

            assertEquals(alg.name(), jwt.getHeader().getAlgorithm().getName());
            assertEquals(alg.strKid(), jwt.getHeader().getKeyID());
            assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
            assertTrue(jwt.verify(verifier(jwk)), alg.name() + " did not verify");
        }
    }


    @Test
    void noneProducesAnUnsignedTokenWithAnEmptyThirdSegment(@TempDir Path dirTmp)
            throws Exception {
        String strToken = MintSigner.strSign(MintAlg.NONE, null, claims());

        assertTrue(strToken.endsWith("."), "an unsigned token has no signature");
        assertEquals(3, strToken.split("\\.", -1).length);

        PlainJWT jwt = PlainJWT.parse(strToken);
        assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
        assertEquals("none", jwt.getHeader().getAlgorithm().getName());
    }


    @Test
    void aPublicKeyCannotSign(@TempDir Path dirTmp) throws Exception {
        MintKeys keys = MintKeys.ensure(dirTmp);
        JWK jwkPublic = keys.jwk(MintAlg.RS256).toPublicJWK();

        TokenException ex = org.junit.jupiter.api.Assertions.assertThrows(TokenException.class,
                () -> MintSigner.strSign(MintAlg.RS256, jwkPublic, claims()));
        assertTrue(ex.getMessage().contains("rs256"));
    }


    @Test
    void aKeyOfTheWrongTypeIsRefusedRatherThanUsed(@TempDir Path dirTmp) {
        MintKeys keys = MintKeys.ensure(dirTmp);

        // an EC key asked to sign RS256: the signer is chosen from the key, so
        // this is refused inside Nimbus rather than producing a token whose
        // header lies about how it was signed
        org.junit.jupiter.api.Assertions.assertThrows(RuntimeException.class,
                () -> MintSigner.strSign(MintAlg.RS256, keys.jwk(MintAlg.ES256), claims()));
    }

}
