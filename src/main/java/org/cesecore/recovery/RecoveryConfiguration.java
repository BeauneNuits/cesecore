/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.recovery;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cesecore.config.ConfigurationHolder;
import org.cesecore.recovery.exception.DatabaseHomeNotSetException;
import org.cesecore.recovery.exception.RecoverySetupException;

/**
 * Small class to contain quick methods for retrieving backup related properties. It retrieves properties from backup.properties
 * 
 * @version $Id$
 * 
 */
public abstract class RecoveryConfiguration {

    /**
     * 
     * @return the backup directory from backup.properties.
     */
    public static final String getBackupDirectory() {
        String directory = ConfigurationHolder.getString("backup.directory");

        if (directory != null) {
            return appendSeparatorIfNeeded(directory);
        } else {
            return System.getProperty("java.io.tmpdir");
        }
    }

    public static final String getFilePrefix() {
        return ConfigurationHolder.getString("backup.prefix");
    }

    public static final String getDatabaseHome() {
        String result = ConfigurationHolder.getString("backup.database.home");
        if (result == null) {
            throw new DatabaseHomeNotSetException("Database home value has not been set, impossible to run backup sequence.");
        }
        return appendSeparatorIfNeeded(result);
    }

    /**
     * 
     * @return The database URL, defaults to 127.0.0.1
     */
    public static final String getDatabaseHost() {
        return ConfigurationHolder.getString("database.host");
    }

    public static final String getDatabaseUsername() {
        return ConfigurationHolder.getString("database.username");
    }

    public static final String getDatabasePassword() {
        return ConfigurationHolder.getString("database.password");
    }

    public static final String getDatabaseVendor() {
        return ConfigurationHolder.getString("database.vendor");
    }

    public static final String getDatabaseName() {
        return ConfigurationHolder.getString("database.name");
    }

    /**
     * 
     * @return a String array containing each word in the database dump command.
     */
    public static final String[] getDbDumpCommand() {
        String command = ConfigurationHolder.getExpandedString("backup.dbdump.command");
        if (command != null) {
            String[] result = command.trim().split(" ");
            for (int i = 0; i < result.length; i++) {
                result[i] = result[i].trim();
            }
            return result;
        } else {
            throw new RecoverySetupException("DB Dump command hasn't been configured in backup.properties. Can't perform backup.");
        }
    }

    /**
     * 
     * @return a List<String> containing the database restore command. Quotes will be treated as whole words.
     */
    public static final List<String> getDbRestoreCommand() {
        String configLine = ConfigurationHolder.getExpandedString("backup.dbrestorecommand");
        if (configLine != null) {
            try {
                List<String> resultList = patchQuotes(new ArrayList<String>(Arrays.asList(configLine.trim().split("\\s"))));
                return resultList;
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Configuration line: " + configLine + " was malformed, quotes did not match.", e);
            }
        } else {
            throw new RecoverySetupException("DB Restore command hasn't been configured in backup.properties. Can't perform recovery.");
        }
    }

    /**
     * Recursive utility method that takes a list of strings and patches together quoted words, then strips the quotes.
     * 
     * @param input
     */
    private static final List<String> patchQuotes(List<String> input) {
        for (int i = 0; i < input.size(); ++i) {
            String word = input.get(i);
            if (word.matches("^\".*") && !word.matches(".*\"$")) {
                // Match quotes
                if (i == input.size()) {
                    throw new IllegalArgumentException("Quotes could not be matched.");
                } else {
                    input.set(i, word + " " + input.get(i + 1));
                    input.remove(i + 1);
                    input = patchQuotes(input);
                }
            } else if (word.matches("^\".*") && word.matches(".*\"$")) {
                // Strip quotes if matched.
                input.set(i, word.substring(word.indexOf("\"") + 1, word.lastIndexOf("\"")));
            }
        }
        return input;
    }

    public static final String getDbPasswordEnvironmentVariable() {
        return ConfigurationHolder.getExpandedString("backup.dbdump.password.env");
    }

    public static final String getSourceFileKeyword() {
        return ConfigurationHolder.getExpandedString("backup.keyword.sourcefile");
    }

    public static final String getDatabaseSuperUserIdKeyword() {
        return ConfigurationHolder.getExpandedString("backup.keyword.databasesuperuserid");
    }

    public static final String getDatabaseSuperUserPasswordKeyword() {
        return ConfigurationHolder.getExpandedString("backup.keyword.databasesuperuserpassword");
    }

    /**
     * Simple utility method that ensures that all retrieved paths end with a separator
     * 
     * @param path with or without a separator.
     * @return a path with a separator.
     */
    private static final String appendSeparatorIfNeeded(String path) {
        if (path.length() > 0) {
            return (path.charAt(path.length() - 1) == File.separatorChar ? path : path.concat(File.separator));
        } else {
            return path;
        }
    }

}
