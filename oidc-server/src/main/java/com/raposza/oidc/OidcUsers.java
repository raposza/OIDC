// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import com.raposza.jwt.JwksMaterial;
import com.raposza.jwt.TokenException;

import com.fasterxml.jackson.core.type.TypeReference;
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
 * Author Claude/bentzn
 */
@Component
public final class OidcUsers {

    private static final Logger log = LoggerFactory.getLogger(OidcUsers.class);

    /** The store, beside the JWKS. */
    public static final String STR_FILE = "users.json";

    private static final ObjectMapper mapper = new ObjectMapper();

    private final Path fileStore;

    private volatile Map<String, String> mapPassword;


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
            this.mapPassword = Collections.unmodifiableMap(mapRead(fileStore));
        }
        else {
            Map<String, String> mapSeed = mapParseSetting(strUsers);
            this.mapPassword = Collections.unmodifiableMap(mapSeed);
            if (!mapSeed.isEmpty())
                write(mapSeed);
        }
        // NAMES ONLY. A password never reaches a log line.
        log.info("users {} from {}", mapPassword.keySet(), fileStore);
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
        return new ArrayList<>(mapPassword.keySet());
    }


    /**
     * @param strName what was typed as the name
     * @param strPassword what was typed as the password
     * @return true when that user exists and that is its password
     */
    public boolean isValid(String strName, String strPassword) {
        if (strName == null || strPassword == null)
            return false;
        String strWant = mapPassword.get(strName);
        if (strWant == null)
            return false;
        return MessageDigest.isEqual(strWant.getBytes(StandardCharsets.UTF_8),
                strPassword.getBytes(StandardCharsets.UTF_8));
    }


    /**
     * Adds a user, or changes an existing one's password.
     *
     * @param strName the name, which is the `sub` of its tokens
     * @param strPassword the password, stored as typed
     * @return true when the user was new, false when it was updated
     * @throws IllegalArgumentException when either is blank
     */
    public synchronized boolean flagPut(String strName, String strPassword) {
        String strKey = strRequire(strName, "name");
        String strVal = strRequire(strPassword, "password");

        Map<String, String> mapNew = new LinkedHashMap<>(mapPassword);
        boolean flagNew = mapNew.put(strKey, strVal) == null;
        write(mapNew);
        this.mapPassword = Collections.unmodifiableMap(mapNew);
        log.info("user {} {}", strKey, flagNew ? "added" : "updated");
        return flagNew;
    }


    /**
     * @param strName the user to remove
     * @return true when it was there
     */
    public synchronized boolean flagRemove(String strName) {
        if (strName == null || !mapPassword.containsKey(strName))
            return false;

        Map<String, String> mapNew = new LinkedHashMap<>(mapPassword);
        mapNew.remove(strName);
        write(mapNew);
        this.mapPassword = Collections.unmodifiableMap(mapNew);
        log.info("user {} removed", strName);
        return true;
    }


    private static String strRequire(String strIn, String strWhat) {
        if (strIn == null || strIn.isBlank())
            throw new IllegalArgumentException("the " + strWhat + " is blank");
        return strIn.trim();
    }


    private static Map<String, String> mapParseSetting(String strUsers) {
        Map<String, String> map = new LinkedHashMap<>();
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
            map.put(strTrim.substring(0, idxColon), strTrim.substring(idxColon + 1));
        }
        return map;
    }


    private static Map<String, String> mapRead(Path fileIn) {
        try {
            Map<String, String> mapIn = mapper.readValue(fileIn.toFile(),
                    new TypeReference<LinkedHashMap<String, String>>() { });
            return mapIn == null ? new LinkedHashMap<>() : mapIn;
        }
        catch (IOException ex) {
            // THE MESSAGE NAMES THE FILE AND NOTHING ELSE. Jackson's own text
            // for a malformed document quotes the line it failed on, which
            // here is a password.
            throw new TokenException("could not read the user store " + fileIn
                    + " - it is not a flat JSON object of name to password");
        }
    }


    private void write(Map<String, String> mapOut) {
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
