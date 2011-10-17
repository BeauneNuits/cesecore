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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.zip.Adler32;
import java.util.zip.CheckedInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.recovery.RecoveryConfiguration;
import org.cesecore.recovery.backup.BackupSession;
import org.cesecore.recovery.exception.ConfigurationRecoveryException;
import org.cesecore.recovery.exception.DatabaseDumpFailedException;
import org.cesecore.recovery.exception.RecoveryCleanupException;
import org.cesecore.recovery.exception.RecoveryCompressionException;
import org.cesecore.recovery.exception.RecoveryEncryptionFailedException;
import org.cesecore.recovery.exception.RecoveryException;
import org.cesecore.util.CryptoProviderTools;

/**
 * This Class Restores conf files and Databases.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RestoreSessionRemote")
public class RestoreSessionBean implements RestoreSessionLocal, RestoreSessionRemote {

    private static final Logger log = Logger.getLogger(RestoreSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private static final String BACKUP_DIRECTORY = RecoveryConfiguration.getBackupDirectory();

    private static final String DB_BACKUP_KEYWORD = RecoveryConfiguration.getSourceFileKeyword();
    private static final String DB_SUPERUSER_ID_KEYWORD = RecoveryConfiguration.getDatabaseSuperUserIdKeyword();
    private static final String DB_SUPERUSER_PASSWORD_KEYWORD = RecoveryConfiguration.getDatabaseSuperUserPasswordKeyword();

    private static final int BUFFER_SIZE = 2048;

    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    @EJB
    private SecurityEventsAuditorSessionLocal securityEventsAuditorSession;

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void performRecovery(final AuthenticationToken admin, final File backupFile, final Class<? extends CryptoToken> cryptoTokenClass, final byte[] tokenData,
            final Properties tokenProperties, final String tokenAlias, final String tokenPin, final String superUserId, final String superUserPassword)
            throws AuthorizationDeniedException, RecoveryException {
        if (!accessSession.isAuthorized(admin, StandardRules.RESTORE.resource())) {
            throw new AuthorizationDeniedException(intres.getLocalizedMessage("restore.notauthorized", admin.toString()));
        }
        try {
            securityEventsAuditorSession.prepareReset();
        } catch (final AuditLogResetException e) {
            log.error(e.getMessage(), e);
            throw new RecoveryException(e.getMessage(), e);
        }
        final CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(cryptoTokenClass.getName(), tokenProperties, tokenData, 555);
        PrivateKey privateKey = null;
        try {
            try {
                cryptoToken.activate(tokenPin.toCharArray());
            } catch (final CryptoTokenAuthenticationFailedException e) {
                throw new RecoveryEncryptionFailedException("Could not activate crypto token, token PIN was incorrect.", e);
            }
            privateKey = cryptoToken.getPrivateKey(tokenAlias);
        } catch (final CryptoTokenOfflineException e) {
            throw new RecoveryEncryptionFailedException("Crypto provider was offline.", e);
        }
        EventStatus status = EventStatus.SUCCESS;
        try {
            RecoveryWorker.INSTANCE.performRecovery(backupFile, privateKey, cryptoToken.getEncProviderName(), superUserId, superUserPassword);
		} catch (final RecoveryException e) {
		    log.error(e.getMessage(), e);
		    status = EventStatus.FAILURE;
		    throw e;
		}
		catch (final DatabaseDumpFailedException e) {
		    log.error(e.getMessage(), e);
		    status = EventStatus.FAILURE;
		    throw new RecoveryException(e.getMessage(), e);
		}
		finally {
		    try {
                securityEventsAuditorSession.reset();
            } catch (final AuditLogResetException e) {
                log.error(e.getMessage(), e);
                throw new RecoveryException(e.getMessage(), e);
            }
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", "Restore operation performed");
            securityEventsLoggerSession.log(EventTypes.RESTORE, status, ModuleTypes.RECOVERY, ServiceTypes.CORE, admin.toString(), null, null, null, details);
        }
    }

    /**
     * Enum implemented singleton to provide thread safety.
     * 
     */
    private static enum RecoveryWorker {
        INSTANCE;

        private RecoveryWorker() {

        }

        /**
         * Performs recovery in a single atomic action.
         * 
         * @param cryptoText The encrypted backup file.
         * @param privateKey Private Key used to decrypt the file.
         * @param encProvider encryption provider to use for decryption
         * @param superUserId The super user ID to the database, needed to drop the old tables.
         * @param superUserPassword The super user password to the database, needed to drop the old tables.
         * @throws RecoveryEncryptionFailedException if decyption of the backup file fails.
         * @throws RecoveryCompressionException if decompression of the backup file fails.
         * @throws DatabaseDumpFailedException if restoration of the database fails.
         * @throws ConfigurationRecoveryException if restoration of the configuration fails.
         */
        public synchronized void performRecovery(final File cryptoText, final PrivateKey privateKey, final String encProvider, final String superUserId, final String superUserPassword)
                throws RecoveryEncryptionFailedException, RecoveryCompressionException, DatabaseDumpFailedException, ConfigurationRecoveryException {
            // Clean tmp dir
            final File tmpDir = new File(RecoveryConfiguration.getBackupDirectory());
            cleanUp(new File[] { new File(tmpDir, UNZIPPED_DIRECTORY_NAME), new File(tmpDir, DECRYPTED_FILE_NAME) });
            final File decryptedFile = decryptFile(cryptoText, privateKey, encProvider);
            final File unzippedDirectory = unzipBackupFile(decryptedFile);
            restoreDatabase(new File(unzippedDirectory, BackupSession.DB_DUMP_FILENAME), superUserId, superUserPassword);
            restoreConfiguration(new File(unzippedDirectory, BackupSession.CONFIGURATION_FILENAME));
            cleanUp(new File[] { decryptedFile, unzippedDirectory });
        }

        /**
         * Decrypt the backup file.
         * 
         * @param cryptoText The file to be decrypted.
         * @param privateKey Private Key used to decrypt the file.
         * @param encProvider encryption provider to use for decryption
         * 
         * @return a decrypted file.
         * @throws RecoveryEncryptionFailedException if decryption of backup file fails.
         */
        private File decryptFile(final File cryptoText, final PrivateKey privateKey, final String encProvider) throws RecoveryEncryptionFailedException {
            File result = null;

            CryptoProviderTools.installBCProviderIfNotAvailable();
            try {
                final BufferedInputStream instream = new BufferedInputStream(new FileInputStream(cryptoText));
                final byte[] data = new byte[(int) cryptoText.length()];
                try {

                    instream.read(data);
                } finally {
                    instream.close();
                }
                final CMSEnvelopedData envelopedData = new CMSEnvelopedData(data);
                final RecipientInformationStore recipients = envelopedData.getRecipientInfos();
                final RecipientInformation recipient = (RecipientInformation) recipients.getRecipients().iterator().next();
                final byte[] recipientData = recipient.getContent(privateKey, encProvider);
                result = new File(BACKUP_DIRECTORY + File.separator + DECRYPTED_FILE_NAME);
                final BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(result));
                try {
                    outputStream.write(recipientData);
                } finally {
                    outputStream.close();
                }
            } catch (final IOException e) {
                throw new RecoveryEncryptionFailedException("Decryption of backup file failed", e);
            } catch (final CMSException e) {
                throw new RecoveryEncryptionFailedException("Decryption of backup file failed", e);
            } catch (final NoSuchProviderException e) {
                throw new RecoveryEncryptionFailedException("BouncyCastle has not been installed as a crypto provider.", e);
            }

            if (result.exists() && result.isFile() && result.length() > 0) {

                return result;
            } else {
                throw new RecoveryEncryptionFailedException("Decrypted file was not created correctly for unknown reason.");
            }
        }

        /**
         * Clean all temporary files
         */
        private void cleanUp(final File... filesToDelete) {
            String unremovedFiles = "";
            for (final File file : filesToDelete) {
                if (file.exists()) {
                    if (file.isDirectory()) {
                        cleanUp(file.listFiles());
                    }
                    if (!file.delete()) {
                        unremovedFiles += file.getAbsolutePath() + ", ";
                    }
                }
            }
            if (!unremovedFiles.equals("")) {
                throw new RecoveryCleanupException("Could not delete temporary files " + unremovedFiles
                        + " this may be a breach of security specifications. Please ensure that this file is removed.");
            }
        }

        /**
         * Unzip the now decrypted backup file.
         * 
         * @return a directory containing the unzipped files.
         * @throws RecoveryCompressionException if errors are encountered during decompression operation.
         */
        private final File unzipBackupFile(final File zipFile) throws RecoveryCompressionException {
            final File tempdir = new File(BACKUP_DIRECTORY, UNZIPPED_DIRECTORY_NAME);
            if (!tempdir.exists()) {
                tempdir.mkdirs();
            }
            BufferedOutputStream outputStream = null;
            try {
                final ZipInputStream zipStream = new ZipInputStream(new BufferedInputStream(new CheckedInputStream(new FileInputStream(zipFile),
                        new Adler32())));
                try {
                    ZipEntry zipEntry;
                    while ((zipEntry = zipStream.getNextEntry()) != null) {
                        int count;
                        final byte data[] = new byte[BUFFER_SIZE];
                        outputStream = new BufferedOutputStream(new FileOutputStream(new File(tempdir, zipEntry.getName())), BUFFER_SIZE);
                        try {
                            while ((count = zipStream.read(data, 0, BUFFER_SIZE)) != -1) {
                                outputStream.write(data, 0, count);
                            }
                            outputStream.flush();
                        } finally {
                            outputStream.close();
                        }
                    }
                } finally {
                    zipStream.close();
                }
            } catch (final FileNotFoundException e) {
                throw new RecoveryCompressionException("Zip file " + zipFile.getAbsolutePath() + " was not found for unknown reason.", e);
            } catch (final IOException e) {
                throw new RecoveryCompressionException("IOException was encountered when closing zip stream.", e);
            }

            return tempdir;
        }

        /**
         * Restores the database according to the file found in the given directory.
         * 
         * @param sqlDump A text file containing an SQL dump.
         * @throws DatabaseDumpFailedException
         */
        private void restoreDatabase(final File sqlDump, final String superUserId, final String superUserPassword) throws DatabaseDumpFailedException {
            final List<String> command = RecoveryConfiguration.getDbRestoreCommand();
            // Make a string of the command to be able to log without exposing the passwords in the log
            // Expand keywords
            for (int i = 0; i < command.size(); ++i) {
                String subCommand = command.get(i);
                subCommand = subCommand.replace(DB_BACKUP_KEYWORD, sqlDump.getAbsolutePath());
                subCommand = subCommand.replace(DB_SUPERUSER_ID_KEYWORD, superUserId);
                subCommand = subCommand.replace(DB_SUPERUSER_PASSWORD_KEYWORD, superUserPassword);
                command.set(i, subCommand);
            }
            String logcommand = command.toString();
            logcommand = logcommand.replace(RecoveryConfiguration.getDatabasePassword(), "hidden");
            logcommand = logcommand.replace(RecoveryConfiguration.getDatabaseUsername(), "hidden");
            logcommand = logcommand.replace(superUserPassword, "hidden");
            if (log.isTraceEnabled()) {
                log.trace("Restore command: " + logcommand);
            }
            ProcessBuilder prb = new ProcessBuilder(command);
            prb = prb.redirectErrorStream(true);
            if (RecoveryConfiguration.getDbPasswordEnvironmentVariable() != null) {
                final Map<String, String> env = prb.environment();
                env.put(RecoveryConfiguration.getDbPasswordEnvironmentVariable(), superUserPassword);
            }
            try {
                String logLine;
                String dumpLog = "";
                final Process process = prb.start();
                final BufferedReader errorStream = new BufferedReader(new InputStreamReader(process.getInputStream()));
                try {
                    while ((logLine = errorStream.readLine()) != null) {
                        log.error(logLine);
                        dumpLog = dumpLog.concat(logLine);
                    }
                    final int returnValue = process.waitFor();
                    process.destroy();
                    if (dumpLog.length() > 0) {
                        throw new DatabaseDumpFailedException("Command: " + logcommand + "\n" + dumpLog);

                    } else if (returnValue != 0) {
                        throw new DatabaseDumpFailedException("Database restore failed with return value " + returnValue + ".\nCommand was "
                                + logcommand);
                    }
                } finally {
                    if(log.isDebugEnabled()) {
                        log.debug("closing error stream");
                    }
                    errorStream.close();
                }
            } catch (final InterruptedException e) {
                throw new DatabaseDumpFailedException("Database restoring process was interrupted during operation.", e);
            } catch (final IOException e) {
                throw new DatabaseDumpFailedException("IOException on restoring database", e);
            }
        }

        /**
         * Restores the configuration from the backup.
         * 
         * @throws ConfigurationRecoveryException if an error is encountered during configuration restoration.
         */
        private void restoreConfiguration(final File backupProperties) throws ConfigurationRecoveryException {
            final Properties properties = new Properties();
            try {
                final BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(backupProperties));
                try {
                    properties.load(inputStream);
                    ConfigurationHolder.instance().clear();
                    ConfigurationHolder.updateConfiguration(properties);
                } finally {
                    inputStream.close();
                }
            } catch (final FileNotFoundException e) {
                throw new ConfigurationRecoveryException("Configuration file not found.", e);
            } catch (final IOException e) {
                throw new ConfigurationRecoveryException(e);
            }
        }
    }
}
