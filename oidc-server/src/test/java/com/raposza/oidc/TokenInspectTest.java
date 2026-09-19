// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.raposza.jwt.MintAlg;
import com.raposza.jwt.MintKeys;
import com.raposza.jwt.MintSigner;

import com.nimbusds.jwt.JWTClaimsSet;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Date;
import java.util.Map;

/**
 * The three failures this page exists to tell apart: a wrong issuer, a wrong
 * audience, and a key that did not sign it.
 *
 * The one that needs a test rather than a reading is the LAST: a token signed
 * by a different set, which is the case that has cost this project whole
 * sessions and which every participant reports as an unexplained refusal.
 *
 * Author Claude/bentzn
 */
class TokenInspectTest {

    private static String strMint(MintKeys keys, MintAlg alg, JWTClaimsSet claims) {
        return MintSigner.strSign(alg, keys.jwk(alg), claims);
    }


    private static JWTClaimsSet claims(long nSecondsFromNow) {
        return new JWTClaimsSet.Builder()
                .issuer("https://id.example.com")
                .subject("alice")
                .audience("https://ledger.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + nSecondsFromNow * 1000L))
                .build();
    }


    @Test
    void aTokenFromThisSetVerifiesAndItsClaimsAreReported(@TempDir Path dirKeys) {
        MintKeys keys = MintKeys.ensure(dirKeys);
        Map<String, Object> map = TokenInspect.mapOf(
                strMint(keys, MintAlg.RS256, claims(3600)), keys);

        assertEquals(Boolean.TRUE, map.get("parsed"));
        assertEquals(Boolean.TRUE, map.get("verified"));
        assertEquals(Boolean.FALSE, map.get("expired"));
        assertEquals("https://id.example.com", map.get("issuer"));
        assertEquals("alice", map.get("subject"));
        assertEquals("rs256", map.get("kid"));
    }


    @Test
    void everySignedAlgorithmIsRecognised(@TempDir Path dirKeys) {
        MintKeys keys = MintKeys.ensure(dirKeys);

        for (MintAlg alg : MintAlg.values()) {
            if (!alg.flagSigned())
                continue;
            Map<String, Object> map = TokenInspect.mapOf(
                    strMint(keys, alg, claims(3600)), keys);
            assertEquals(Boolean.TRUE, map.get("verified"), alg.name());
        }
    }


    @Test
    void aTokenFromANOTHERSetDoesNotVerify(@TempDir Path dirMine, @TempDir Path dirTheirs) {
        MintKeys keysMine = MintKeys.ensure(dirMine);
        MintKeys keysTheirs = MintKeys.ensure(dirTheirs);

        Map<String, Object> map = TokenInspect.mapOf(
                strMint(keysTheirs, MintAlg.RS256, claims(3600)), keysMine);

        // THE ID MATCHES AND THE MATERIAL DOES NOT, which is exactly the shape
        // that reads as "the participant just refuses it".
        assertEquals(Boolean.TRUE, map.get("parsed"));
        assertEquals(Boolean.FALSE, map.get("verified"));
        assertTrue(String.valueOf(map.get("verified_detail")).contains("rs256"));
    }


    @Test
    void anExpiredTokenIsDescribedRatherThanRefused(@TempDir Path dirKeys) {
        MintKeys keys = MintKeys.ensure(dirKeys);
        Map<String, Object> map = TokenInspect.mapOf(
                strMint(keys, MintAlg.RS256, claims(-60)), keys);

        // MINTING AN EXPIRED TOKEN IS SOMETHING THIS SERVICE IS ASKED TO DO, so
        // the tool that looks at one must not treat it as an error.
        assertEquals(Boolean.TRUE, map.get("verified"));
        assertEquals(Boolean.TRUE, map.get("expired"));
    }


    @Test
    void aPASTEDjwksIsCheckedToo(@TempDir Path dirMine, @TempDir Path dirTheirs) {
        MintKeys keysMine = MintKeys.ensure(dirMine);
        MintKeys keysTheirs = MintKeys.ensure(dirTheirs);
        String strToken = strMint(keysMine, MintAlg.RS256, claims(3600));

        // OUR OWN PUBLIC SET, pasted back: both answers agree.
        Map<String, Object> mapSame = TokenInspect.mapOf(strToken, keysMine,
                keysMine.renderPublicJwks());
        assertEquals(Boolean.TRUE, mapSame.get("verified"));
        assertEquals(Boolean.TRUE, mapSame.get("foreign_verified"));

        // SOMEBODY ELSE'S, with the same kid in it: we signed it and they
        // cannot verify it. That is the case this field exists for - a
        // participant holding a stale copy of the JWKS.
        Map<String, Object> mapOther = TokenInspect.mapOf(strToken, keysMine,
                keysTheirs.renderPublicJwks());
        assertEquals(Boolean.TRUE, mapOther.get("verified"));
        assertEquals(Boolean.FALSE, mapOther.get("foreign_verified"));
    }


    @Test
    void aJwksThatIsNotOneSaysSoRatherThanFailing(@TempDir Path dirKeys) {
        MintKeys keys = MintKeys.ensure(dirKeys);
        String strToken = strMint(keys, MintAlg.RS256, claims(3600));

        Map<String, Object> map = TokenInspect.mapOf(strToken, keys, "not a jwks");
        assertEquals(Boolean.TRUE, map.get("verified"));
        assertEquals(Boolean.FALSE, map.get("foreign_verified"));
        assertTrue(String.valueOf(map.get("foreign_detail")).contains("not a JWKS"));
    }


    @Test
    void noJwksMeansNoForeignAnswerAtAll(@TempDir Path dirKeys) {
        MintKeys keys = MintKeys.ensure(dirKeys);
        Map<String, Object> map = TokenInspect.mapOf(
                strMint(keys, MintAlg.RS256, claims(3600)), keys, "   ");

        // ABSENT, not false. The page shows the line only when it was asked.
        assertFalse(map.containsKey("foreign_verified"));
    }


    @Test
    void nothingPastedAndRubbishPastedBothSayWhy(@TempDir Path dirKeys) {
        MintKeys keys = MintKeys.ensure(dirKeys);

        assertEquals(Boolean.FALSE, TokenInspect.mapOf("", keys).get("parsed"));
        assertEquals(Boolean.FALSE, TokenInspect.mapOf(null, keys).get("parsed"));

        Map<String, Object> map = TokenInspect.mapOf("not.a.token", keys);
        assertEquals(Boolean.FALSE, map.get("parsed"));
        assertFalse(String.valueOf(map.get("detail")).isBlank());
    }

}
