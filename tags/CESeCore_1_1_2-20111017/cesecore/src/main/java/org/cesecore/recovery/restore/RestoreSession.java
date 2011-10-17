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
package org.cesecore.recovery.restore;

import java.io.File;
import java.util.Properties;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.recovery.exception.RecoveryException;

/**
 * Restores Database dump files and secure backup of CESeCore configuration artefacts. This interface is used to manage Restore.
 * 
 * @version $Id$
 */
public interface RestoreSession {

    public final String DECRYPTED_FILE_NAME = "temp.zip";
    public final String UNZIPPED_DIRECTORY_NAME = "temp";

    /**
     * Perform recovery operation.
     * 
     * @param token an authentication token.
     * @param backupFile An encrypted file containing the backup.
     * @param The class of CryptoToken used in encryption.
     * @param tokenData An encoded crypto token containing the private key needed to decrypt the backup file.
     * @param tokenProperties Proprties of the encoded CryptoToken
     * @param tokenAlias Alias of the private key in the token.
     * @param tokenPin the PIN code to the crypto token.
     * @param superUserId User name for the database super user.
     * @param superUserPassword Password for the database super user.
     * @throws AuthorizationDeniedException the authorization denied exception
     * @throws RecoveryException this is the generic recovery exception. This exception might hold one of this exception.
     * 			RecoveryEncryptionFailedException If decryption of backupFile fails.
     *          RecoveryCompressionException if a failure occurs during backup file decompression.
     *          DatabaseDumpFailedException if an error is encountered while restoring the database.
     *          ConfigurationRecoveryException if an error is encountered while updating the configuration.
     */
    void performRecovery(final AuthenticationToken admin, File backupFile, Class<? extends CryptoToken> CryptoTokenClass, byte[] tokenData,
            Properties tokenProperties, String tokenAlias, String tokenPin, String superUserId, String superUserPassword)
            throws AuthorizationDeniedException, RecoveryException;

}
