// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.raposza.jwt.TokenException;

import com.nimbusds.jose.JOSEException;
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
import com.nimbusds.jwt.SignedJWT;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * The OpenID Connect authorization code flow, behind the login page and the
 * token endpoint.
 *
 * <h2>What a code is bound to</h2>
 *
 * A code is issued to one signed-in user, for one client, one `redirect_uri`
 * and, when the request carried one, one PKCE `code_challenge`. The exchange
 * must present the same client and the same `redirect_uri`, and the verifier
 * whose S256 hash is the challenge - OpenID Connect Core 1.0 section 3.1.3.2 and
 * RFC 7636 section 4.6. A code lives sixty seconds and is spent by the first
 * attempt to exchange it, successful or not, so a replay finds nothing.
 *
 * <h2>What comes back</h2>
 *
 * An RS256 access token whose `sub` is the user and whose `aud` is the
 * `audience` the authorization request asked for - the parameter the Splice
 * web UIs send - or the client when it asked for none. An ID token for the
 * client, carrying the nonce and `at_hash`, when the scope holds `openid`. A
 * refresh token, which renews the access token for as long as this process
 * runs. The user's standard claims, when the scope or the `claims` parameter
 * asks for them and the user has them - {@link OidcClaims}.
 *
 * <h2>A code used twice revokes what it issued - RFC 6749 section 4.1.2</h2>
 *
 * "If an authorization code is used more than once, the authorization server
 * MUST deny the request and SHOULD revoke (when possible) all tokens
 * previously issued based on that authorization code." The tokens are
 * stateless JWTs and nothing but this service can refuse one, so the
 * revocation is what THIS service can do: UserInfo refuses every access token
 * of that grant, and its refresh token is forgotten. A participant that checks
 * only the signature still accepts the token until it expires - L-4 of the
 * security review. The suite's `oidcc-codereuse-30seconds` measures exactly
 * the UserInfo half, and warned until 0.4.0.
 *
 * Everything is held in memory. A restart signs everybody out, which on a test
 * system is a feature.
 *
 * Author Claude/bentzn
 */
@Service
public class OidcFlow {

    public static final String STR_SCOPE_OPENID = "openid";

    /** OpenID Connect Core 1.0 section 5.4: what `preferred_username` belongs to. */
    public static final String STR_SCOPE_PROFILE = "profile";

    public static final String STR_METHOD_S256 = "S256";

    /** Core section 2: authentication below ISO/IEC 29115 level 1. */
    public static final String STR_ACR = "0";

    public static final String STR_GRANT_CODE = "authorization_code";

    public static final String STR_GRANT_REFRESH = "refresh_token";

    private static final Duration DUR_CODE = Duration.ofSeconds(60);

    /** The lifetime a login-issued token gets when the mint's own default writes no `exp`. */
    private static final long N_TTL_SECONDS_FLOOR = 3600L;

    /** RFC 7636 section 4.1: 43 to 128 unreserved characters. */
    private static final Pattern PAT_VERIFIER = Pattern.compile("[A-Za-z0-9._~-]{43,128}");

    private static final int N_BYTES_HANDLE = 32;

    private final SecureRandom random = new SecureRandom();

    private final Map<String, CodeGrant> mapCode = new ConcurrentHashMap<>();

    private final Map<String, Grant> mapRefresh = new ConcurrentHashMap<>();

    /** How long a spent code is remembered, so a second use can be told from a forgery. */
    private static final Duration DUR_SPENT = Duration.ofMinutes(10);

    /** A spent code to the grant it issued. */
    private final Map<String, Spent> mapSpent = new ConcurrentHashMap<>();

    /** An access token this flow issued to what it was issued for. */
    private final Map<String, Issued> mapIssued = new ConcurrentHashMap<>();

    /** Grants revoked by a reused code. */
    private final Set<String> setRevoked = ConcurrentHashMap.newKeySet();


    /**
     * @param idGrant the grant
     * @param instExpires when the memory of the code may go
     */
    record Spent(String idGrant, Instant instExpires) {
    }


    /**
     * @param idGrant the grant the token belongs to
     * @param setClaimUserInfo the claims the `claims` parameter asked UserInfo for
     * @param instExpires when the token expires, after which this entry goes
     */
    record Issued(String idGrant, Set<String> setClaimUserInfo, Instant instExpires) {
    }

    private final MintService minter;

    private final MintKeyStore store;

    private final IssuerResolver resolver;

    private final MintSettings settings;

    private final OidcUsers users;


    /**
     * What a sign-in grants: who, to which client, for what.
     *
     * @param strUser the signed-in user, the `sub`
     * @param idClient the client it was granted to
     * @param strScope the scope asked for, possibly null
     * @param strAudience the `audience` asked for, possibly null
     * @param instAuth when the user signed in
     * @param idGrant this grant's own id, what a revocation names
     * @param mapClaimsRequested the `claims` parameter, target to names
     */
    record Grant(String strUser, String idClient, String strScope, String strAudience,
            Instant instAuth, String idGrant, Map<String, Set<String>> mapClaimsRequested) {
    }


    /**
     * A code and what it is bound to.
     *
     * @param grant what the code stands for
     * @param strRedirect the `redirect_uri` of the authorization request
     * @param strChallenge the PKCE challenge, or null when none was sent
     * @param strNonce the nonce, or null when none was sent
     * @param instExpires when the code stops being accepted
     */
    record CodeGrant(Grant grant, String strRedirect, String strChallenge, String strNonce,
            Instant instExpires) {
    }


    public OidcFlow(MintService minter, MintKeyStore store, IssuerResolver resolver,
            MintSettings settings, OidcUsers users) {
        this.minter = minter;
        this.store = store;
        this.resolver = resolver;
        this.settings = settings;
        this.users = users;
    }


    /**
     * @param strUser the signed-in user
     * @param idClient the client the code is for
     * @param strRedirect the `redirect_uri` it will be delivered to
     * @param strScope the scope asked for
     * @param strAudience the `audience` asked for
     * @param strChallenge the S256 PKCE challenge, or null
     * @param strNonce the nonce, or null
     * @return the code, stamped as authenticated now
     */
    public String strIssueCode(String strUser, String idClient, String strRedirect,
            String strScope, String strAudience, String strChallenge, String strNonce) {
        return strIssueCode(strUser, idClient, strRedirect, strScope, strAudience, strChallenge,
                strNonce, Instant.now());
    }


    /**
     * @param strUser the signed-in user
     * @param idClient the client the code is for
     * @param strRedirect the `redirect_uri` it will be delivered to
     * @param strScope the scope asked for
     * @param strAudience the `audience` asked for
     * @param strChallenge the S256 PKCE challenge, or null
     * @param strNonce the nonce, or null
     * @param instAuth when the user actually authenticated
     * @return the code
     */
    public String strIssueCode(String strUser, String idClient, String strRedirect,
            String strScope, String strAudience, String strChallenge, String strNonce,
            Instant instAuth) {
        return strIssueCode(strUser, idClient, strRedirect, strScope, strAudience, strChallenge,
                strNonce, instAuth, Map.of());
    }


    /**
     * THE AUTHENTICATION INSTANT IS PASSED IN, not taken here, because a
     * second authorization request inside one session must carry the SAME
     * `auth_time` - Core 3.1.2.1 and the `oidcc-max-age-10000` module of the
     * conformance suite, which failed on this before 2026-09-19.
     *
     * @param strUser the signed-in user
     * @param idClient the client the code is for
     * @param strRedirect the `redirect_uri` it will be delivered to
     * @param strScope the scope asked for
     * @param strAudience the `audience` asked for
     * @param strChallenge the S256 PKCE challenge, or null
     * @param strNonce the nonce, or null
     * @param instAuth when the user actually authenticated
     * @param mapClaimsRequested the `claims` parameter, parsed -
     *        {@link OidcClaims#mapRequested}
     * @return the code
     */
    public String strIssueCode(String strUser, String idClient, String strRedirect,
            String strScope, String strAudience, String strChallenge, String strNonce,
            Instant instAuth, Map<String, Set<String>> mapClaimsRequested) {
        purge();
        String strCode = strHandle();
        Instant instNow = Instant.now();
        mapCode.put(strCode, new CodeGrant(
                new Grant(strUser, idClient, blankToNull(strScope), blankToNull(strAudience), instAuth,
                        strHandle(), mapClaimsRequested == null ? Map.of() : Map.copyOf(mapClaimsRequested)),
                strRedirect, blankToNull(strChallenge), blankToNull(strNonce), instNow.plus(DUR_CODE)));
        return strCode;
    }


    /**
     * The `authorization_code` grant.
     *
     * @param strCode the code
     * @param idClient the client presenting it
     * @param strRedirect the `redirect_uri` it presents
     * @param strVerifier the PKCE verifier, or null
     * @return the token response
     * @throws OidcException invalid_request or invalid_grant
     */
    public Map<String, Object> mapExchangeCode(String strCode, String idClient,
            String strRedirect, String strVerifier) {
        if (isBlank(strCode))
            throw new OidcException("invalid_request", "code is required");
        if (isBlank(idClient))
            throw new OidcException("invalid_request", "client_id is required");

        // REMOVED BEFORE IT IS CHECKED. The attempt spends the code whatever
        // its outcome, so a code that leaked into a log or a history cannot be
        // tried twice.
        CodeGrant code = mapCode.remove(strCode);
        if (code == null) {
            // A SECOND USE of a code that did issue tokens revokes them.
            Spent spent = mapSpent.remove(strCode);
            if (spent != null)
                revoke(spent.idGrant());
            throw new OidcException("invalid_grant", "the code is unknown, expired or already used");
        }
        if (Instant.now().isAfter(code.instExpires()))
            throw new OidcException("invalid_grant", "the code is unknown, expired or already used");
        if (!code.grant().idClient().equals(idClient))
            throw new OidcException("invalid_grant", "the code was issued to another client");
        if (!code.strRedirect().equals(strRedirect))
            throw new OidcException("invalid_grant",
                    "redirect_uri is not the one the authorization request carried");
        if (code.strChallenge() != null) {
            if (isBlank(strVerifier) || !PAT_VERIFIER.matcher(strVerifier).matches())
                throw new OidcException("invalid_grant", "code_verifier is missing or malformed");
            if (!code.strChallenge().equals(strS256(strVerifier)))
                throw new OidcException("invalid_grant", "code_verifier does not match the code_challenge");
        }

        Map<String, Object> map = mapTokens(code.grant());
        String strRefresh = strHandle();
        mapRefresh.put(strRefresh, code.grant());
        mapSpent.put(strCode, new Spent(code.grant().idGrant(), Instant.now().plus(DUR_SPENT)));
        map.put("refresh_token", strRefresh);
        if (hasScope(code.grant().strScope(), STR_SCOPE_OPENID))
            map.put("id_token", strIdToken(code.grant(), code.strNonce(), (String) map.get("access_token")));
        return map;
    }


    /**
     * The `refresh_token` grant. The refresh token is not rotated, and no new
     * ID token is issued: OpenID Connect Core 1.0 section 12.2 leaves both to
     * the provider.
     *
     * @param strRefresh the refresh token
     * @param idClient the client presenting it, or null when it did not say
     * @return the token response
     * @throws OidcException invalid_request or invalid_grant
     */
    public Map<String, Object> mapRefresh(String strRefresh, String idClient) {
        if (isBlank(strRefresh))
            throw new OidcException("invalid_request", "refresh_token is required");
        Grant grant = mapRefresh.get(strRefresh);
        if (grant != null && setRevoked.contains(grant.idGrant()))
            grant = null;
        if (grant == null)
            throw new OidcException("invalid_grant", "the refresh token is unknown");
        if (!isBlank(idClient) && !grant.idClient().equals(idClient))
            throw new OidcException("invalid_grant", "the refresh token was issued to another client");

        Map<String, Object> map = mapTokens(grant);
        map.put("refresh_token", strRefresh);
        return map;
    }


    /**
     * The subject of a token this service signed, for the UserInfo endpoint.
     *
     * @param strToken a compact JWS
     * @return its `sub` when it verifies against this service's keys, carries
     *         this issuer and has not expired; null otherwise
     */
    public String strSubjectOf(String strToken) {
        JWTClaimsSet claims = claimsOf(strToken, true);
        return claims == null ? null : claims.getSubject();
    }


    /**
     * The UserInfo response for an access token this service signed - Core
     * 5.3.2.
     *
     * `sub` always, and `preferred_username` always, as before 0.4.0: nothing
     * that read it unasked is broken by this release. Then every standard claim
     * the token's `scope` releases and the user carries - Core 5.4.
     *
     * @param strToken a compact JWS
     * @return the claims, or null when the token does not verify, carries
     *         another issuer or has expired
     */
    public Map<String, Object> mapUserInfo(String strToken) {
        JWTClaimsSet claims = claimsOf(strToken, true);
        if (claims == null || claims.getSubject() == null)
            return null;
        Issued issued = mapIssued.get(strToken);
        if (issued != null && setRevoked.contains(issued.idGrant()))
            return null;
        String strSub = claims.getSubject();
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("sub", strSub);
        map.put("preferred_username", strSub);
        String strScope;
        try {
            strScope = claims.getStringClaim("scope");
        }
        catch (ParseException ex) {
            strScope = null;
        }
        Map<String, Object> mapUser = users.mapClaims(strSub);
        map.putAll(OidcClaims.mapReleased(strScope, mapUser));
        if (issued != null)
            map.putAll(OidcClaims.mapNamed(issued.setClaimUserInfo(), mapUser));
        return map;
    }


    /**
     * The client an `id_token_hint` was issued to, for RP-initiated logout.
     * Expiry is not checked, for the reason {@link #strSubjectOfHint} gives.
     *
     * @param strToken a compact JWS, or null
     * @return its `azp`, else its only `aud`; null when it does not verify or
     *         names no single client
     */
    public String strClientOfHint(String strToken) {
        JWTClaimsSet claims = claimsOf(strToken, false);
        if (claims == null)
            return null;
        try {
            String strAzp = claims.getStringClaim("azp");
            if (!isBlank(strAzp))
                return strAzp;
        }
        catch (ParseException ex) {
            return null;
        }
        List<String> lstAud = claims.getAudience();
        return lstAud != null && lstAud.size() == 1 ? lstAud.get(0) : null;
    }


    /**
     * The subject of an `id_token_hint`. EXPIRY IS NOT CHECKED: Core 3.1.2.1
     * describes the hint as a previously issued ID token, and a client that
     * has one to hand is exactly the client whose token has run out.
     *
     * @param strToken a compact JWS, or null
     * @return its `sub`, or null when there is none to be had
     */
    public String strSubjectOfHint(String strToken) {
        JWTClaimsSet claims = claimsOf(strToken, false);
        return claims == null ? null : claims.getSubject();
    }


    private JWTClaimsSet claimsOf(String strToken, boolean flagCheckExpiry) {
        if (isBlank(strToken))
            return null;
        try {
            SignedJWT jwt = SignedJWT.parse(strToken);
            String strKid = jwt.getHeader().getKeyID();
            if (isBlank(strKid))
                return null;
            if (!jwt.verify(verifier(store.keys().jwkOfKid(strKid))))
                return null;
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (!resolver.strIssuer().equals(claims.getIssuer()))
                return null;
            Date dateExp = claims.getExpirationTime();
            if (flagCheckExpiry && dateExp != null && dateExp.toInstant().isBefore(Instant.now()))
                return null;
            return claims;
        }
        catch (ParseException | JOSEException | TokenException | ClassCastException ex) {
            return null;
        }
    }


    /**
     * @param strVerifier a PKCE verifier
     * @return BASE64URL(SHA256(ASCII(verifier))), RFC 7636 section 4.2
     */
    static String strS256(String strVerifier) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(arrSha256(strVerifier.getBytes(StandardCharsets.US_ASCII)));
    }


    /**
     * @param strAccess an access token
     * @return its `at_hash`: the left half of its SHA-256, base64url,
     *         OpenID Connect Core 1.0 section 3.1.3.6
     */
    static String strHalfHash(String strAccess) {
        byte[] arrHash = arrSha256(strAccess.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Arrays.copyOf(arrHash, arrHash.length / 2));
    }


    /**
     * @param strScope a space-separated scope, or null
     * @param strWant one scope value
     * @return true when strScope holds strWant
     */
    static boolean hasScope(String strScope, String strWant) {
        if (strScope == null)
            return false;
        for (String strPart : strScope.trim().split("\\s+")) {
            if (strPart.equals(strWant))
                return true;
        }
        return false;
    }


    private Map<String, Object> mapTokens(Grant grant) {
        long nTtl = nTtl();
        String strAud = grant.strAudience() == null ? grant.idClient() : grant.strAudience();
        Map<String, Object> mapClaim = new LinkedHashMap<>();
        mapClaim.put("azp", grant.idClient());
        MintResponse resp = minter.mint(new MintRequest("RS256", null, grant.strUser(), null,
                List.of(strAud), grant.strScope(), Long.valueOf(nTtl), null, null, null, null,
                null, null, null, mapClaim, null), resolver.strIssuer());

        Map<String, Object> map = new LinkedHashMap<>();
        map.put("access_token", resp.token());
        mapIssued.put(resp.token(), new Issued(grant.idGrant(),
                grant.mapClaimsRequested().getOrDefault(OidcClaims.STR_TARGET_USERINFO, Set.of()),
                Instant.now().plusSeconds(nTtl)));
        map.put("token_type", "Bearer");
        map.put("expires_in", Long.valueOf(nTtl));
        if (grant.strScope() != null)
            map.put("scope", grant.strScope());
        return map;
    }


    private String strIdToken(Grant grant, String strNonce, String strAccess) {
        Map<String, Object> mapClaim = new LinkedHashMap<>();
        mapClaim.put("azp", grant.idClient());
        mapClaim.put("auth_time", Long.valueOf(grant.instAuth().getEpochSecond()));
        mapClaim.put("at_hash", strHalfHash(strAccess));
        // THE HONEST acr - Core section 2: "0" is an authentication that did not
        // meet ISO/IEC 29115 level 1, which a name and a clear-text password on
        // a test system is. Returned always, as Keycloak returns its own; the
        // one value `acr_values_supported` advertises, so a relying party that
        // asks with acr_values gets an answer instead of silence - the suite's
        // `oidcc-ensure-request-with-acr-values-succeeds` warned on the silence.
        mapClaim.put("acr", STR_ACR);
        // Core 5.4: a scope-associated claim is returned only when its scope was
        // asked for. The conformance suite flagged this on `oidcc-server`.
        if (hasScope(grant.strScope(), STR_SCOPE_PROFILE))
            mapClaim.put("preferred_username", grant.strUser());
        // BY NAME ONLY, from the `claims` parameter's id_token member. A scope
        // releases its claims at UserInfo - OidcClaims says why.
        mapClaim.putAll(OidcClaims.mapNamed(
                grant.mapClaimsRequested().getOrDefault(OidcClaims.STR_TARGET_ID_TOKEN, Set.of()),
                users.mapClaims(grant.strUser())));
        if (strNonce != null)
            mapClaim.put("nonce", strNonce);
        return minter.mint(new MintRequest("RS256", null, grant.strUser(), null,
                List.of(grant.idClient()), null, Long.valueOf(nTtl()), null, null, null, null,
                null, null, null, mapClaim, null), resolver.strIssuer()).token();
    }


    /**
     * @return the mint's default lifetime, or an hour when that default is to
     *         write no `exp` - a signed-in user's token always carries one
     */
    private long nTtl() {
        long nTtl = settings.nTtlSecondsDefault();
        return nTtl > 0 ? nTtl : N_TTL_SECONDS_FLOOR;
    }


    /**
     * @param idGrant the grant a reused code issued
     */
    private void revoke(String idGrant) {
        setRevoked.add(idGrant);
        mapRefresh.values().removeIf(grant -> grant.idGrant().equals(idGrant));
    }


    private void purge() {
        Instant instNow = Instant.now();
        mapCode.values().removeIf(code -> instNow.isAfter(code.instExpires()));
        mapSpent.values().removeIf(spent -> instNow.isAfter(spent.instExpires()));
        mapIssued.values().removeIf(issued -> instNow.isAfter(issued.instExpires()));
    }


    private String strHandle() {
        byte[] arr = new byte[N_BYTES_HANDLE];
        random.nextBytes(arr);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(arr);
    }


    private static JWSVerifier verifier(JWK jwk) throws JOSEException {
        KeyType kty = jwk.getKeyType();
        if (KeyType.RSA.equals(kty))
            return new RSASSAVerifier(((RSAKey) jwk).toPublicJWK());
        if (KeyType.EC.equals(kty))
            return new ECDSAVerifier(((ECKey) jwk).toPublicJWK());
        if (KeyType.OCT.equals(kty))
            return new MACVerifier((OctetSequenceKey) jwk);
        throw new JOSEException("key type " + kty + " cannot verify");
    }


    private static byte[] arrSha256(byte[] arrIn) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(arrIn);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is missing from this JVM", ex);
        }
    }


    private static String blankToNull(String str) {
        return isBlank(str) ? null : str;
    }


    private static boolean isBlank(String str) {
        return str == null || str.isBlank();
    }

}
