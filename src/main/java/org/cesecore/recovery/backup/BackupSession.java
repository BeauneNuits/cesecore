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
package org.cesecore.recovery.backup;

import java.security.PublicKey;
import java.text.SimpleDateFormat;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.recovery.exception.RecoveryCompressionException;
import org.cesecore.recovery.exception.ConfigurationRecoveryException;
import org.cesecore.recovery.exception.BackupDirectoryNotFoundException;
import org.cesecore.recovery.exception.RecoveryEncryptionFailedException;
import org.cesecore.recovery.exception.DatabaseDumpFailedException;

/**
 * Backups Database dump files and secure backup of CESeCore configuration artifacts. This interface is used to manage Backup.
 * 
 * @version $Id$
 */
public interface BackupSession {

    public static final String ZIP_FILENAME = "backup.zip";
    public static final String CONFIGURATION_FILENAME = "configuration.backup";
    public static final String DB_DUMP_FILENAME = "dbdump.sql";
    public static final String FILE_SUFFIX = ".backup";
    public static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyyMMdd_HH_mm_ss_SSS");
    
    /**
     * After Access Control, starts Backup.
     * 
     * @param token user performing the task.
     * @param ca the ca
     * @param cryptoToken used to check if the public key of the certificate matches the private key that we are trying to associate.
     * @throws AuthorizationDeniedException if user is not authorized to perform backup.
     * @throws BackupDirectoryNotFoundException if backup directory hasn't been set in configuration.
     * @throws RecoveryCompressionException if compression fails.
     * @throws ConfigurationRecoveryException if backup of the configuration fails.
     * @throws DatabaseDumpFailedException if an error occurs while dumping the database.
     * @throws RecoveryEncryptionFailedException if an error occurs while encrypting the compressed file.
     */
    void performBackup(final AuthenticationToken token, final PublicKey publicKey) throws AuthorizationDeniedException,
            BackupDirectoryNotFoundException, RecoveryCompressionException, ConfigurationRecoveryException, DatabaseDumpFailedException,
            RecoveryEncryptionFailedException;

}
