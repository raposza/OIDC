// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.raposza.jwt.MintKeys;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What a token actually says, and whether THIS key set signed it.
 *
 * <h2>Why this is the util that earns its place</h2>
 *
 * Every authentication failure this project has had was one of three things: an
 * issuer that did not match, an audience that did not match, or a key that was
 * not the one that signed. A participant reports all three the same way, as a
 * refusal with no detail, and finding out which one it was has cost whole
 * sessions. One answer that covers all three, against the live key set, is
 * worth more than the rest of the surface it sits behind.
 *
 * <h2>It reports, it does not judge</h2>
 *
 * An expired token is described as expired and is NOT called invalid: a
 * deliberately expired token is one of the things this service exists to mint,
 * and a tool that refuses to look at one is useless for the case it was built
 * for. `verified` answers exactly one question - did a key in this set produce
 * that signature.
 *
 * Author Claude/bentzn
 */
public final class TokenInspect {

    private TokenInspect() {
    }

    /**
     * @param strToken the compact serialization, as pasted
     * @param keys the set to check the signature against
     * @return header, claims, timing and verification, ready to serialize
     */
    public static Map<String, Object> mapOf(String strToken, MintKeys keys) {
        return mapOf(strToken, keys, null);
    }


    /**
     * The same, and against a JWKS the caller pasted as well.
     *
     * <h2>Why a foreign set is the question people actually have</h2>
     *
     * "This service signed it" is rarely what is being asked. What is being
     * asked is whether the PARTICIPANT will accept it - and the participant
     * verifies against whatever JWKS its `auth-services` block names, which may
     * be an older copy of this one, a different mint, or Keycloak. Pasting that
     * set answers it directly instead of by elimination.
     *
     * Both answers are reported. `verified` always means this service's set;
     * `foreign_verified` appears only when a set was pasted.
     *
     * @param strToken the compact serialization, as pasted
     * @param keys this service's set
     * @param strJwks a JWKS document, or null/blank for none
     * @return header, claims, timing and both verifications
     */
    public static Map<String, Object> mapOf(String strToken, MintKeys keys, String strJwks) {
        Map<String, Object> mapOut = new LinkedHashMap<>();
        if (strToken == null || strToken.isBlank()) {
            mapOut.put("parsed", false);
            mapOut.put("detail", "nothing was pasted");
            return mapOut;
        }

        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(strToken.trim());
        }
        catch (java.text.ParseException ex) {
            // A PLAIN JWT LANDS HERE TOO and that is worth saying, because an
            // alg=none token is something this service mints on request.
            mapOut.put("parsed", false);
            mapOut.put("detail", "not a signed JWT - " + ex.getMessage());
            return mapOut;
        }

        mapOut.put("parsed", true);
        mapOut.put("alg", String.valueOf(jwt.getHeader().getAlgorithm()));
        mapOut.put("kid", jwt.getHeader().getKeyID());
        mapOut.put("typ", String.valueOf(jwt.getHeader().getType()));

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        }
        catch (java.text.ParseException ex) {
            mapOut.put("detail", "the payload is not a claims set - " + ex.getMessage());
            return mapOut;
        }

        mapOut.put("claims", claims.getClaims());
        mapOut.put("issuer", claims.getIssuer());
        mapOut.put("subject", claims.getSubject());
        mapOut.put("audience", claims.getAudience());

        Date dateExp = claims.getExpirationTime();
        mapOut.put("expires", dateExp == null ? null : dateExp.toInstant().toString());
        mapOut.put("expired", dateExp != null && dateExp.toInstant().isBefore(Instant.now()));

        mapOut.putAll(mapVerify(jwt, keys.lstJwk(), keys.lstKid(), ""));

        if (strJwks != null && !strJwks.isBlank())
            mapOut.putAll(mapForeign(jwt, strJwks));
        return mapOut;
    }


    private static Map<String, Object> mapForeign(SignedJWT jwt, String strJwks) {
        Map<String, Object> mapOut = new LinkedHashMap<>();

        List<JWK> lstJwk;
        try {
            lstJwk = JWKSet.parse(strJwks.trim()).getKeys();
        }
        catch (java.text.ParseException ex) {
            mapOut.put("foreign_verified", false);
            mapOut.put("foreign_detail", "that is not a JWKS document - " + ex.getMessage());
            return mapOut;
        }

        if (lstJwk.isEmpty()) {
            mapOut.put("foreign_verified", false);
            mapOut.put("foreign_detail", "that JWKS holds no keys");
            return mapOut;
        }

        List<String> lstKid = new ArrayList<>();
        for (int idx = 0; idx < lstJwk.size(); idx++) {
            String strKid = lstJwk.get(idx).getKeyID();
            lstKid.add(strKid == null ? "(no kid)" : strKid);
        }

        Map<String, Object> mapHit = mapVerify(jwt, lstJwk, lstKid, "foreign_");
        mapOut.put("foreign_verified", mapHit.get("foreign_verified"));
        mapOut.put("foreign_detail", mapHit.get("foreign_verified_detail"));
        mapOut.put("foreign_kids", lstKid);
        return mapOut;
    }


    private static Map<String, Object> mapVerify(SignedJWT jwt, List<JWK> lstJwk,
            List<String> lstKid, String strPrefix) {
        Map<String, Object> mapOut = new LinkedHashMap<>();
        String strKid = jwt.getHeader().getKeyID();

        JWK jwk = null;
        for (int idx = 0; idx < lstJwk.size(); idx++) {
            String strHere = lstJwk.get(idx).getKeyID();
            if (strKid != null && strKid.equals(strHere)) {
                jwk = lstJwk.get(idx);
                break;
            }
        }

        // A SET WITH ONE KEY AND NO kid IS THE COMMON SHAPE of a hand-written
        // JWKS, and refusing to try it would answer "no" to a question the
        // caller can see the answer to.
        if (jwk == null && lstJwk.size() == 1 && lstJwk.get(0).getKeyID() == null)
            jwk = lstJwk.get(0);

        if (jwk == null) {
            mapOut.put(strPrefix + "verified", false);
            mapOut.put(strPrefix + "verified_detail", strKid == null || strKid.isBlank()
                    ? "the token names no kid, so no key here can be matched to it"
                    : "no key '" + strKid + "' in this set; it holds " + lstKid);
            return mapOut;
        }

        try {
            mapOut.put(strPrefix + "verified", jwt.verify(verifier(jwk)));
            mapOut.put(strPrefix + "verified_detail",
                    "checked against '" + jwk.getKeyID() + "'");
        }
        catch (Exception ex) {
            // A KEY OF THE WRONG TYPE FOR THE HEADER lands here - an RS256
            // token naming a kid that holds an EC key, which is exactly the
            // mismatch this service can be asked to produce.
            mapOut.put(strPrefix + "verified", false);
            mapOut.put(strPrefix + "verified_detail", "'" + jwk.getKeyID()
                    + "' cannot verify a " + jwt.getHeader().getAlgorithm()
                    + " signature - " + ex.getMessage());
        }
        return mapOut;
    }


    private static JWSVerifier verifier(JWK jwk) throws Exception {
        KeyType kty = jwk.getKeyType();
        if (KeyType.OCT.equals(kty))
            return new MACVerifier((OctetSequenceKey) jwk);
        if (KeyType.EC.equals(kty))
            return new ECDSAVerifier(((ECKey) jwk).toPublicJWK());
        return new RSASSAVerifier(((RSAKey) jwk).toPublicJWK());
    }

}
