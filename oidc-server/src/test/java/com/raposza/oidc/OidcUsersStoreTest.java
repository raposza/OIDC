// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The user store as a file: what seeds it, what wins, and what survives a
 * restart.
 *
 * The case that matters most is the THIRD one. A setting that overwrote the
 * file at every start would discard every user added since, silently, and the
 * only way to notice would be a sign-in that stopped working.
 *
 * Author Claude/bentzn
 */
class OidcUsersStoreTest {

    private static MintSettings settings(Path dirKeys) {
        return new MintSettings(dirKeys.toString(), "http://127.0.0.1:32002",
                86400, "RS256", "raposza", "admin", "", false);
    }


    @Test
    void theSettingSeedsTheFileWhenThereIsNone(@TempDir Path dirKeys) {
        OidcUsers users = new OidcUsers(settings(dirKeys), "alice:a1,bob:b2");

        assertEquals(List.of("alice", "bob"), users.lstName());
        assertTrue(Files.isRegularFile(dirKeys.resolve(OidcUsers.STR_FILE)));
        assertTrue(users.isValid("alice", "a1"));
        assertFalse(users.isValid("alice", "wrong"));
    }


    @Test
    void noSettingAndNoFileIsNobody(@TempDir Path dirKeys) {
        OidcUsers users = new OidcUsers(settings(dirKeys), "");

        assertEquals(List.of(), users.lstName());
        assertFalse(users.isValid("alice", "a1"));
        // NOTHING IS WRITTEN for an empty seed, so a later setting can still
        // seed it rather than meeting an empty file that wins.
        assertFalse(Files.isRegularFile(dirKeys.resolve(OidcUsers.STR_FILE)));
    }


    @Test
    void anExistingFileWinsOverTheSetting(@TempDir Path dirKeys) {
        new OidcUsers(settings(dirKeys), "alice:a1").flagPut("carol", "c3");

        OidcUsers users = new OidcUsers(settings(dirKeys), "dave:d4");

        assertEquals(List.of("alice", "carol"), users.lstName());
        assertFalse(users.isValid("dave", "d4"));
    }


    @Test
    void putAddsThenUpdatesAndBothSurviveAReload(@TempDir Path dirKeys) {
        OidcUsers users = new OidcUsers(settings(dirKeys), "");

        assertTrue(users.flagPut("alice", "a1"));
        assertFalse(users.flagPut("alice", "a2"));
        assertTrue(users.isValid("alice", "a2"));

        OidcUsers again = new OidcUsers(settings(dirKeys), "");
        assertTrue(again.isValid("alice", "a2"));
        assertFalse(again.isValid("alice", "a1"));
    }


    @Test
    void removeTakesItAwayAndKeepsTheRest(@TempDir Path dirKeys) {
        OidcUsers users = new OidcUsers(settings(dirKeys), "alice:a1,bob:b2");

        assertTrue(users.flagRemove("alice"));
        assertFalse(users.flagRemove("alice"));
        assertEquals(List.of("bob"), new OidcUsers(settings(dirKeys), "").lstName());
    }


    @Test
    void aPasswordMayCarryAQuoteAndABackslash(@TempDir Path dirKeys) {
        String strAwkward = "a\"b\\c";
        OidcUsers users = new OidcUsers(settings(dirKeys), "");
        users.flagPut("alice", strAwkward);

        // THE WHOLE POINT OF NOT HAND-ROLLING THE FILE. A writer that does not
        // escape produces a file its own reader cannot parse.
        assertTrue(new OidcUsers(settings(dirKeys), "").isValid("alice", strAwkward));
    }


    @Test
    void blankNameOrPasswordIsRefused(@TempDir Path dirKeys) {
        OidcUsers users = new OidcUsers(settings(dirKeys), "");

        assertThrows(IllegalArgumentException.class, () -> users.flagPut("", "a1"));
        assertThrows(IllegalArgumentException.class, () -> users.flagPut("alice", " "));
    }


    @Test
    void aSeedPairWithNoColonNamesItselfWithoutItsPassword(@TempDir Path dirKeys) {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new OidcUsers(settings(dirKeys), "alice"));
        assertTrue(ex.getMessage().contains("alice"));
    }

}
