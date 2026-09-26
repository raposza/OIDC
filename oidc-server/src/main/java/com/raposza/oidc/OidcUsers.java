// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.raposza.jwt.JwksMaterial;
import com.raposza.jwt.TokenException;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The people who can sign in.
 *
 * <h2>A test system's user store</h2>
 *
 * The concept is the production one: a person proves who they are to the
 * identity provider, and the application they are signing in to never sees the
 * password. The hardening is not: the passwords are stored as typed, and there
 * is no lockout and no policy. Keycloak, or whatever replaces this service,
 * keeps its own users; nothing outside this class reads these.
 *
 * The name is the `sub` of every token issued to that person.
 *
 * <h2>A FILE since 2026-09-19, and the setting SEEDS it - D-774</h2>
 *
 * Managing users from the UI means writing them, and a `@Value` string cannot
 * be written. So the store is `users.json` beside the JWKS. The setting
 * `raposza.jwtmint.users` is read exactly once, when that file does not yet
 * exist, and its contents become the file - so every `basenet.conf`, every
 * launcher and every Helm value that names users keeps working with no change,
 * and the first edit from the UI takes over from there.
 *
 * An EXISTING file wins over the setting, always. The alternative - the setting
 * overwriting the file at every start - would silently discard every user added
 * since, which is the failure this note exists to prevent.
 *
 * <h2>Jackson, and the reason it is not hand-rolled</h2>
 *
 * A map of two strings looks like forty lines of string scanning, and the first
 * draft of this class was exactly that. It is wrong: a password may carry a
 * quote or a backslash, and a writer that does not escape produces a file its
 * own reader cannot parse - a corruption that appears only for the person
 * unlucky enough to pick that password. Jackson is already on the classpath
 * through Boot and it escapes both directions. The alternative was to FORBID
 * those characters in a password, which is a policy this system has no business
 * having.
 *
 * <h2>Written then moved</h2>
 *
 * A reader that catches a half-written file sees a truncated document and
 * reports a parse error, which sends whoever is looking at the store rather
 * than at the interrupted write that caused it. The new content goes to a
 * `.part` beside it and is moved into place - the same rule the key files
 * follow.
 *
 * <h2>A user may carry the standard claims, since 0.4.0</h2>
 *
 * `name`, `email`, `address`, `phone_number` and the rest of Core 5.1 -
 * {@link OidcClaims}. The file keeps its old shape for a user who has none:
 *
 * <pre>
 * { "alice": "a1",
 *   "bob": { "password": "b2", "claims": { "name": "Bob", "email": "bob@example.com" } } }
 * </pre>
 *
 * so every `users.json` written before 0.4.0 is read unchanged, and a user is
 * written back in the flat form for as long as it carries no claim. Only the
 * standard claim names are accepted - an unknown one is refused by name, since
 * no scope would ever release it and it would sit in the file as a claim
 * nobody receives. `sub` is not a claim here: it is the name.
 *
 * Author Claude/bentzn
 */
@Component
public final class OidcUsers {

    private static final Logger log = LoggerFactory.getLogger(OidcUsers.class);

    /** The store, beside the JWKS. */
    public static final String STR_FILE = "users.json";

    private static final ObjectMapper mapper = new ObjectMapper();

    private final Path fileStore;

    private volatile Map<String, User> mapUser;


    /**
     * One person.
     *
     * @param strPassword as typed
     * @param mapClaim the standard claims, possibly empty, never null
     */
    private record User(String strPassword, Map<String, Object> mapClaim) {
    }


    /**
     * @param settings where the store lives
     * @param strUsers `name:password` pairs, comma separated - the SEED, used
     *        only when the store file does not exist; blank means nobody can
     *        sign in
     * @throws IllegalArgumentException when a seed pair has no name or no colon
     */
    public OidcUsers(MintSettings settings,
            @Value("${raposza.jwtmint.users:}") String strUsers) {
        this.fileStore = settings.dirKeys().resolve(STR_FILE);

        if (Files.isRegularFile(fileStore)) {
            this.mapUser = Collections.unmodifiableMap(mapRead(fileStore));
        }
        else {
            Map<String, User> mapSeed = mapParseSetting(strUsers);
            this.mapUser = Collections.unmodifiableMap(mapSeed);
            if (!mapSeed.isEmpty())
                write(mapSeed);
        }
        // NAMES ONLY. A password never reaches a log line, and neither does a claim.
        log.info("users {} from {}", mapUser.keySet(), fileStore);
    }


    /**
     * @return where the store is, whether or not it exists yet
     */
    public Path fileStore() {
        return fileStore;
    }


    /**
     * @return the names, in the order they were added
     */
    public List<String> lstName() {
        return new ArrayList<>(mapUser.keySet());
    }


    /**
     * @param strName what was typed as the name
     * @param strPassword what was typed as the password
     * @return true when that user exists and that is its password
     */
    public boolean isValid(String strName, String strPassword) {
        if (strName == null || strPassword == null)
            return false;
        User user = mapUser.get(strName);
        if (user == null)
            return false;
        return MessageDigest.isEqual(user.strPassword().getBytes(StandardCharsets.UTF_8),
                strPassword.getBytes(StandardCharsets.UTF_8));
    }


    /**
     * @param strName a user
     * @return the standard claims that user carries, empty for none or for an
     *         unknown name; never null
     */
    public Map<String, Object> mapClaims(String strName) {
        User user = strName == null ? null : mapUser.get(strName);
        if (user == null)
            return Map.of();
        return Collections.unmodifiableMap(new LinkedHashMap<>(user.mapClaim()));
    }


    /**
     * Adds a user, or changes an existing one's password. The claims an
     * existing user carries are kept.
     *
     * @param strName the name, which is the `sub` of its tokens
     * @param strPassword the password, stored as typed
     * @return true when the user was new, false when it was updated
     * @throws IllegalArgumentException when either is blank
     */
    public boolean flagPut(String strName, String strPassword) {
        return flagPut(strName, strPassword, null);
    }


    /**
     * Adds a user, or changes an existing one.
     *
     * A BLANK PASSWORD KEEPS THE ONE AN EXISTING USER HAS, so the claims can be
     * edited without retyping it. A new user still needs one.
     *
     * @param strName the name, which is the `sub` of its tokens
     * @param strPassword the password, stored as typed; blank keeps an
     *        existing user's
     * @param mapClaim the standard claims, replacing what the user had; null
     *        keeps them, an empty map removes them
     * @return true when the user was new, false when it was updated
     * @throws IllegalArgumentException when the name is blank, a new user has
     *         no password, or a claim is not a standard one
     */
    public synchronized boolean flagPut(String strName, String strPassword,
            Map<String, Object> mapClaim) {
        String strKey = strRequire(strName, "name");
        User userOld = mapUser.get(strKey);
        String strVal;
        if (userOld != null && (strPassword == null || strPassword.isBlank()))
            strVal = userOld.strPassword();
        else
            strVal = strRequire(strPassword, "password");

        Map<String, Object> mapKeep;
        if (mapClaim != null)
            mapKeep = mapChecked(mapClaim);
        else if (userOld != null)
            mapKeep = userOld.mapClaim();
        else
            mapKeep = Map.of();

        Map<String, User> mapNew = new LinkedHashMap<>(mapUser);
        boolean flagNew = mapNew.put(strKey, new User(strVal, mapKeep)) == null;
        write(mapNew);
        this.mapUser = Collections.unmodifiableMap(mapNew);
        log.info("user {} {}, claims {}", strKey, flagNew ? "added" : "updated", mapKeep.keySet());
        return flagNew;
    }


    /**
     * @param strName the user to remove
     * @return true when it was there
     */
    public synchronized boolean flagRemove(String strName) {
        if (strName == null || !mapUser.containsKey(strName))
            return false;

        Map<String, User> mapNew = new LinkedHashMap<>(mapUser);
        mapNew.remove(strName);
        write(mapNew);
        this.mapUser = Collections.unmodifiableMap(mapNew);
        log.info("user {} removed", strName);
        return true;
    }


    private static String strRequire(String strIn, String strWhat) {
        if (strIn == null || strIn.isBlank())
            throw new IllegalArgumentException("the " + strWhat + " is blank");
        return strIn.trim();
    }


    /**
     * @param mapIn claims as given
     * @return them, in a copy, when every name is a standard claim
     * @throws IllegalArgumentException naming the first that is not
     */
    private static Map<String, Object> mapChecked(Map<String, Object> mapIn) {
        Set<String> setAllowed = OidcClaims.setClaim();
        Map<String, Object> mapOut = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entClaim : mapIn.entrySet()) {
            if (!setAllowed.contains(entClaim.getKey())) {
                throw new IllegalArgumentException("'" + entClaim.getKey() + "' is not a standard"
                        + " claim - OpenID Connect Core 1.0 section 5.1 names " + setAllowed);
            }
            if (entClaim.getValue() != null)
                mapOut.put(entClaim.getKey(), entClaim.getValue());
        }
        return Collections.unmodifiableMap(mapOut);
    }


    private static Map<String, User> mapParseSetting(String strUsers) {
        Map<String, User> map = new LinkedHashMap<>();
        if (strUsers == null)
            return map;

        String[] arrPair = strUsers.split(",");
        for (int idxPair = 0; idxPair < arrPair.length; idxPair++) {
            String strTrim = arrPair[idxPair].trim();
            if (strTrim.isEmpty())
                continue;
            int idxColon = strTrim.indexOf(':');
            if (idxColon <= 0) {
                throw new IllegalArgumentException("raposza.jwtmint.users: '"
                        + strTrim.replaceAll(":.*", ":...") + "' is not name:password");
            }
            map.put(strTrim.substring(0, idxColon), new User(strTrim.substring(idxColon + 1), Map.of()));
        }
        return map;
    }


    private static Map<String, User> mapRead(Path fileIn) {
        Map<String, JsonNode> mapIn;
        try {
            mapIn = mapper.readValue(fileIn.toFile(),
                    new TypeReference<LinkedHashMap<String, JsonNode>>() { });
        }
        catch (IOException ex) {
            // THE MESSAGE NAMES THE FILE AND NOTHING ELSE. Jackson's own text
            // for a malformed document quotes the line it failed on, which
            // here is a password.
            throw new TokenException("could not read the user store " + fileIn
                    + " - it is not a JSON object of name to password");
        }

        Map<String, User> mapOut = new LinkedHashMap<>();
        if (mapIn == null)
            return mapOut;
        for (Map.Entry<String, JsonNode> entUser : mapIn.entrySet()) {
            JsonNode node = entUser.getValue();
            if (node != null && node.isTextual()) {
                mapOut.put(entUser.getKey(), new User(node.asText(), Map.of()));
                continue;
            }
            JsonNode nodePassword = node == null ? null : node.get("password");
            if (nodePassword == null || !nodePassword.isTextual()) {
                throw new TokenException("could not read the user store " + fileIn + " - the user '"
                        + entUser.getKey() + "' is neither a password nor an object with one");
            }
            Map<String, Object> mapClaim = Map.of();
            JsonNode nodeClaims = node.get("claims");
            if (nodeClaims != null && !nodeClaims.isNull()) {
                if (!nodeClaims.isObject()) {
                    throw new TokenException("could not read the user store " + fileIn
                            + " - the claims of '" + entUser.getKey() + "' are not an object");
                }
                try {
                    mapClaim = mapChecked(mapper.convertValue(nodeClaims,
                            new TypeReference<LinkedHashMap<String, Object>>() { }));
                }
                catch (IllegalArgumentException ex) {
                    throw new TokenException("could not read the user store " + fileIn
                            + " - user '" + entUser.getKey() + "': " + ex.getMessage());
                }
            }
            mapOut.put(entUser.getKey(), new User(nodePassword.asText(), mapClaim));
        }
        return mapOut;
    }


    private void write(Map<String, User> mapIn) {
        // THE FLAT FORM WHILE A USER HAS NO CLAIM, so a store written before
        // 0.4.0 and never given one comes back byte for byte as it was.
        Map<String, Object> mapOut = new LinkedHashMap<>();
        for (Map.Entry<String, User> entUser : mapIn.entrySet()) {
            User user = entUser.getValue();
            if (user.mapClaim().isEmpty()) {
                mapOut.put(entUser.getKey(), user.strPassword());
            }
            else {
                Map<String, Object> mapOne = new LinkedHashMap<>();
                mapOne.put("password", user.strPassword());
                mapOne.put("claims", user.mapClaim());
                mapOut.put(entUser.getKey(), mapOne);
            }
        }

        Path filePart = fileStore.resolveSibling(STR_FILE + ".part");
        try {
            Path dirParent = fileStore.getParent();
            if (dirParent != null && !Files.isDirectory(dirParent))
                Files.createDirectories(dirParent);
            mapper.writerWithDefaultPrettyPrinter().writeValue(filePart.toFile(), mapOut);
            Files.move(filePart, fileStore, StandardCopyOption.REPLACE_EXISTING);
            // THE FILE HOLDS PASSWORDS. Same treatment as the private JWKS.
            JwksMaterial.restrictToOwner(fileStore);
        }
        catch (IOException ex) {
            throw new TokenException("could not write " + fileStore, ex);
        }
    }

}
