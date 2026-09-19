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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The registered clients, and the three checks a real provider makes that this
 * service did not.
 *
 * <h2>What was wrong, and it was wrong in ONE direction</h2>
 *
 * Until 2026-09-19 any `client_id` was a client, any absolute http or https
 * `redirect_uri` was acceptable, and `client_secret` was accepted and never
 * read. None of that is an error a caller sees - it is PERMISSIVENESS, and
 * permissiveness is the one deviation that breaks the promise this product
 * exists to make: that a component pointed at this service and then at a real
 * provider behaves the same. Three things worked here that any real provider
 * refuses, and each would fail only at the moment of the switch.
 *
 * <h2>EMPTY MEANS OPEN, and that is what makes it adoptable</h2>
 *
 * With no clients configured this registry is not consulted at all and the
 * service behaves exactly as it did - so no existing deployment breaks on the
 * day this lands. Configure one client and the registry is STRICT for every
 * client: an unknown id is refused, an unregistered `redirect_uri` is refused,
 * and a secret is checked. There is no half-open state, because a registry that
 * lets an unknown client through is not a registry.
 *
 * This is the shape {@link AdminGuard} already uses, and for the same reason.
 *
 * <h2>The file, and the setting that seeds it</h2>
 *
 * `clients.json` beside the JWKS and the users. `raposza.jwtmint.clients` is
 * read once, when that file does not exist, and becomes the file:
 *
 * <pre>
 *   id|secret|uri uri , id2||uri
 * </pre>
 *
 * Pipe separates the three fields because a `redirect_uri` carries colons, and
 * spaces separate the URIs because a URI carries neither. A blank middle field
 * is a public client.
 *
 * <h2>It holds secrets, so it is written like the key file</h2>
 *
 * To a `.part` and moved into place, then restricted to the owner. And nothing
 * but the ids reaches a log line.
 *
 * Author Claude/bentzn
 */
@Component
public final class OidcClients {

    private static final Logger log = LoggerFactory.getLogger(OidcClients.class);

    /** The store, beside the JWKS and the users. */
    public static final String STR_FILE = "clients.json";

    private static final ObjectMapper mapper = new ObjectMapper();

    private final Path fileStore;

    private volatile Map<String, OidcClient> mapClient;


    /**
     * @param settings where the store lives
     * @param strClients `id|secret|uri uri` entries, comma separated - the
     *        SEED, used only when the store file does not exist
     * @throws IllegalArgumentException when an entry has no id
     */
    public OidcClients(MintSettings settings,
            @Value("${raposza.jwtmint.clients:}") String strClients) {
        this.fileStore = settings.dirKeys().resolve(STR_FILE);

        if (Files.isRegularFile(fileStore)) {
            this.mapClient = Collections.unmodifiableMap(mapRead(fileStore));
        }
        else {
            Map<String, OidcClient> mapSeed = mapParseSetting(strClients);
            this.mapClient = Collections.unmodifiableMap(mapSeed);
            if (!mapSeed.isEmpty())
                write(mapSeed);
        }

        if (mapClient.isEmpty()) {
            log.warn("NO CLIENTS REGISTERED. Any client_id is accepted, any"
                    + " redirect_uri is accepted and no client_secret is checked"
                    + " - which a real OpenID Provider refuses. Register a client"
                    + " to close all three.");
        }
        else {
            // IDS ONLY. A secret never reaches a log line.
            log.info("clients {} from {}", mapClient.keySet(), fileStore);
        }
    }


    /**
     * @return where the store is, whether or not it exists yet
     */
    public Path fileStore() {
        return fileStore;
    }


    /**
     * @return true when a registry exists and every check below applies
     */
    public boolean flagStrict() {
        return !mapClient.isEmpty();
    }


    /**
     * @return the ids, in the order they were added
     */
    public List<String> lstId() {
        return new ArrayList<>(mapClient.keySet());
    }


    /**
     * @param idClient the id to look up
     * @return that client, or null
     */
    public OidcClient client(String idClient) {
        return idClient == null ? null : mapClient.get(idClient);
    }


    /**
     * @param idClient what the request called itself
     * @return true when the request may proceed - always true while the
     *         registry is empty
     */
    public boolean flagKnown(String idClient) {
        return !flagStrict() || (idClient != null && mapClient.containsKey(idClient));
    }


    /**
     * @param idClient the client
     * @param strUri the `redirect_uri` the request asked for
     * @return true when that URI is registered for that client - always true
     *         while the registry is empty
     */
    public boolean flagRedirect(String idClient, String strUri) {
        if (!flagStrict())
            return true;
        OidcClient client = client(idClient);
        return client != null && client.flagRedirect(strUri);
    }


    /**
     * Whether the credential presented is the one this client must present.
     *
     * A PUBLIC client must present none: a secret offered for a client that has
     * none is refused rather than ignored, because a component sending one is
     * configured for a confidential client and will fail against a real
     * provider the moment it is pointed at one.
     *
     * @param idClient the client
     * @param strSecret what was presented, or null
     * @return true when it is right - always true while the registry is empty
     */
    public boolean flagSecret(String idClient, String strSecret) {
        if (!flagStrict())
            return true;

        OidcClient client = client(idClient);
        if (client == null)
            return false;

        boolean flagOffered = strSecret != null && !strSecret.isBlank();
        if (client.flagPublic())
            return !flagOffered;
        if (!flagOffered)
            return false;

        return MessageDigest.isEqual(client.strSecret().getBytes(StandardCharsets.UTF_8),
                strSecret.getBytes(StandardCharsets.UTF_8));
    }


    /**
     * Adds a client, or replaces one.
     *
     * @param idClient the id
     * @param strSecret its secret, blank for a public client
     * @param lstRedirect every URI it may be sent back to
     * @return true when the client was new
     * @throws IllegalArgumentException when the id is blank or no URI is given
     */
    public synchronized boolean flagPut(String idClient, String strSecret,
            List<String> lstRedirect) {
        if (idClient == null || idClient.isBlank())
            throw new IllegalArgumentException("the client id is blank");
        if (lstRedirect == null || lstRedirect.isEmpty()) {
            throw new IllegalArgumentException("a client with no redirect_uri could"
                    + " never be sent back to, so it cannot sign anybody in");
        }

        List<String> lstClean = new ArrayList<>();
        for (int idx = 0; idx < lstRedirect.size(); idx++) {
            String strUri = lstRedirect.get(idx) == null ? "" : lstRedirect.get(idx).trim();
            if (strUri.isEmpty())
                continue;
            if (!OidcController.isRedirectUri(strUri)) {
                throw new IllegalArgumentException("'" + strUri + "' is not an absolute"
                        + " http or https URI without a fragment");
            }
            lstClean.add(strUri);
        }
        if (lstClean.isEmpty())
            throw new IllegalArgumentException("no usable redirect_uri was given");

        Map<String, OidcClient> mapNew = new LinkedHashMap<>(mapClient);
        boolean flagNew = mapNew.put(idClient.trim(),
                new OidcClient(idClient.trim(),
                        strSecret == null ? "" : strSecret, lstClean)) == null;
        write(mapNew);
        this.mapClient = Collections.unmodifiableMap(mapNew);
        log.info("client {} {}", idClient.trim(), flagNew ? "added" : "updated");
        return flagNew;
    }


    /**
     * @param idClient the client to remove
     * @return true when it was there
     */
    public synchronized boolean flagRemove(String idClient) {
        if (idClient == null || !mapClient.containsKey(idClient))
            return false;

        Map<String, OidcClient> mapNew = new LinkedHashMap<>(mapClient);
        mapNew.remove(idClient);
        write(mapNew);
        this.mapClient = Collections.unmodifiableMap(mapNew);
        // REMOVING THE LAST ONE REOPENS THE SERVICE, which is a bigger change
        // than removing a client and is said as such.
        log.info("client {} removed{}", idClient,
                mapNew.isEmpty() ? " - THE REGISTRY IS EMPTY AND NOTHING IS CHECKED NOW" : "");
        return true;
    }


    private static Map<String, OidcClient> mapParseSetting(String strClients) {
        Map<String, OidcClient> map = new LinkedHashMap<>();
        if (strClients == null)
            return map;

        String[] arrEntry = strClients.split(",");
        for (int idxEntry = 0; idxEntry < arrEntry.length; idxEntry++) {
            String strTrim = arrEntry[idxEntry].trim();
            if (strTrim.isEmpty())
                continue;

            String[] arrField = strTrim.split("\\|", -1);
            if (arrField.length != 3 || arrField[0].trim().isEmpty()) {
                throw new IllegalArgumentException("raposza.jwtmint.clients: '"
                        + arrField[0] + "' is not id|secret|uri uri");
            }

            List<String> lstUri = new ArrayList<>();
            String[] arrUri = arrField[2].trim().split("\\s+");
            for (int idxUri = 0; idxUri < arrUri.length; idxUri++) {
                if (!arrUri[idxUri].isEmpty())
                    lstUri.add(arrUri[idxUri]);
            }

            String idClient = arrField[0].trim();
            map.put(idClient, new OidcClient(idClient, arrField[1], lstUri));
        }
        return map;
    }


    private static Map<String, OidcClient> mapRead(Path fileIn) {
        LinkedHashMap<String, LinkedHashMap<String, Object>> mapRaw;
        try {
            mapRaw = mapper.readValue(fileIn.toFile(),
                    new TypeReference<LinkedHashMap<String, LinkedHashMap<String, Object>>>() { });
        }
        catch (IOException ex) {
            // THE MESSAGE NAMES THE FILE AND NOTHING ELSE. Jackson's own text
            // for a malformed document quotes the line it failed on, which here
            // is a secret.
            throw new TokenException("could not read the client store " + fileIn
                    + " - it is not a JSON object of id to {secret, redirect_uris}");
        }

        Map<String, OidcClient> map = new LinkedHashMap<>();
        if (mapRaw == null)
            return map;

        for (Map.Entry<String, LinkedHashMap<String, Object>> entry
                : mapRaw.entrySet()) {
            Map<String, Object> mapOne = entry.getValue();
            Object objSecret = mapOne == null ? null : mapOne.get("secret");
            Object objUri = mapOne == null ? null : mapOne.get("redirect_uris");

            List<String> lstUri = new ArrayList<>();
            if (objUri instanceof List<?> lstRaw) {
                for (int idx = 0; idx < lstRaw.size(); idx++)
                    lstUri.add(String.valueOf(lstRaw.get(idx)));
            }
            map.put(entry.getKey(), new OidcClient(entry.getKey(),
                    objSecret == null ? "" : String.valueOf(objSecret), lstUri));
        }
        return map;
    }


    private void write(Map<String, OidcClient> mapOut) {
        Map<String, Map<String, Object>> mapRaw = new LinkedHashMap<>();
        for (Map.Entry<String, OidcClient> entry : mapOut.entrySet()) {
            Map<String, Object> mapOne = new LinkedHashMap<>();
            mapOne.put("secret", entry.getValue().strSecret());
            mapOne.put("redirect_uris", entry.getValue().lstRedirect());
            mapRaw.put(entry.getKey(), mapOne);
        }

        Path filePart = fileStore.resolveSibling(STR_FILE + ".part");
        try {
            Path dirParent = fileStore.getParent();
            if (dirParent != null && !Files.isDirectory(dirParent))
                Files.createDirectories(dirParent);
            mapper.writerWithDefaultPrettyPrinter().writeValue(filePart.toFile(), mapRaw);
            Files.move(filePart, fileStore, StandardCopyOption.REPLACE_EXISTING);
            // IT HOLDS SECRETS. Same treatment as the private JWKS.
            JwksMaterial.restrictToOwner(fileStore);
        }
        catch (IOException ex) {
            throw new TokenException("could not write " + fileStore, ex);
        }
    }

}
