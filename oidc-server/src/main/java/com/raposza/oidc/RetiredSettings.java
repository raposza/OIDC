// Copyright (c) 2026 bentzn
// SPDX-License-Identifier: Apache-2.0
package com.raposza.oidc;

import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Refuses a start that names a setting by its old prefix - 0.5.0.
 *
 * <h2>Why refused and not ignored</h2>
 *
 * The settings were `raposza.jwtmint.*` from 0.3.0 to 0.4.x and are
 * `raposza.oidc.*` from 0.5.0. Spring reads a property nobody binds as
 * nothing at all, so a launcher still passing `--raposza.jwtmint.issuer` would
 * start a service with no issuer, and `--raposza.jwtmint.admin.password` would
 * start one with its write endpoints open - silently. The operator's decision
 * of 2026-10-05: the old names are refused, and the refusal names the new one.
 *
 * <h2>Every source, once the configuration is read</h2>
 *
 * The command line, system properties, the environment - in its
 * `RAPOSZA_JWTMINT_*` form as well - and every configuration file. It runs on
 * the environment-prepared event, after Spring Boot has loaded the
 * configuration files, so a name in an `application.yml` beside the jar is
 * found too.
 *
 * Author Claude/bentzn
 */
public final class RetiredSettings implements ApplicationListener<ApplicationEnvironmentPreparedEvent> {

    /** The prefix until 0.4.x. */
    public static final String STR_PREFIX_OLD = "raposza.jwtmint.";

    /** The prefix from 0.5.0. */
    public static final String STR_PREFIX_NEW = "raposza.oidc.";

    /** The old prefix as an environment variable, Spring's relaxed form. */
    public static final String STR_ENV_OLD = "RAPOSZA_JWTMINT_";

    /** The new prefix as an environment variable. */
    public static final String STR_ENV_NEW = "RAPOSZA_OIDC_";


    @Override
    public void onApplicationEvent(ApplicationEnvironmentPreparedEvent event) {
        refuse(event.getEnvironment());
    }


    /**
     * @param env the prepared environment
     * @throws IllegalStateException naming every old name found and its new one
     */
    static void refuse(ConfigurableEnvironment env) {
        List<String> lstFound = lstRetired(env);
        if (lstFound.isEmpty())
            return;

        StringBuilder sb = new StringBuilder();
        sb.append("raposza.jwtmint.* was renamed raposza.oidc.* in 0.5.0 and the old names are refused:");
        for (String strName : lstFound) {
            sb.append("\n    ").append(strName).append("  ->  ").append(strRenamed(strName));
        }
        throw new IllegalStateException(sb.toString());
    }


    /**
     * @param env the environment
     * @return every property name carrying the old prefix, once each, in
     *         property-source order
     */
    static List<String> lstRetired(ConfigurableEnvironment env) {
        List<String> lstOut = new ArrayList<>();
        for (PropertySource<?> src : env.getPropertySources()) {
            if (!(src instanceof EnumerablePropertySource<?> srcNames))
                continue;
            for (String strName : srcNames.getPropertyNames()) {
                if (isRetired(strName) && !lstOut.contains(strName))
                    lstOut.add(strName);
            }
        }
        return lstOut;
    }


    /**
     * @param strName a property name as its source spells it
     * @return true when it carries the old prefix, in either form
     */
    static boolean isRetired(String strName) {
        return strName.startsWith(STR_PREFIX_OLD)
                || strName.toUpperCase(Locale.ROOT).startsWith(STR_ENV_OLD);
    }


    /**
     * @param strName an old name
     * @return the same setting under the new prefix, in the same form
     */
    static String strRenamed(String strName) {
        if (strName.startsWith(STR_PREFIX_OLD))
            return STR_PREFIX_NEW + strName.substring(STR_PREFIX_OLD.length());
        return STR_ENV_NEW + strName.substring(STR_ENV_OLD.length());
    }
}
