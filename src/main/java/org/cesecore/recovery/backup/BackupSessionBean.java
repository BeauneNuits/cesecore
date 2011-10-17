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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.recovery.RecoveryConfiguration;
import org.cesecore.recovery.exception.BackupDirectoryNotFoundException;
import org.cesecore.recovery.exception.ConfigurationRecoveryException;
import org.cesecore.recovery.exception.DatabaseDumpFailedException;
import org.cesecore.recovery.exception.RecoveryCleanupException;
import org.cesecore.recovery.exception.RecoveryCompressionException;
import org.cesecore.recovery.exception.RecoveryEncryptionFailedException;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.Tuplet;


/**
 * This Class Backups configuration files, MySQL Database and PostgreSQL Database.
 *
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "BackupSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class BackupSessionBean implements BackupSessionLocal, BackupSessionRemote {



    private static final Logger log = Logger.getLogger(BackupSession.class);

    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    private static final String BACKUP_DIRECTORY = RecoveryConfiguration.getBackupDirectory();
    private static final String FILE_PREFIX = RecoveryConfiguration.getFilePrefix();

    private static final int BUFFER_SIZE = 2048;

    @EJB
    private AccessControlSessionLocal accessSession;

    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;

    @Override
    public void performBackup(final AuthenticationToken admin, final PublicKey publicKey) throws AuthorizationDeniedException,
            BackupDirectoryNotFoundException, RecoveryCompressionException, ConfigurationRecoveryException, DatabaseDumpFailedException, RecoveryEncryptionFailedException {
        if (!accessSession.isAuthorized(admin, StandardRules.BACKUP.resource())) {
            throw new AuthorizationDeniedException(INTRES.getLocalizedMessage("backup.notauthorized", admin.toString()));
        } else {
        	final Tuplet<File, String> result = BackupWorker.INSTANCE.performBackup(publicKey);
        	final File backupFile = result.getFirstElement();
        	final String hash = result.getSecondElement();
        	// Calculate SHA256 hash of backupfile to put in audit log
            final String msg = "Backup Performed at " + DATE_FORMAT.format(Calendar.getInstance().getTime());
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            details.put("file", backupFile.getAbsolutePath());
            details.put("sha256hash", hash);
            securityEventsLogger.log(EventTypes.BACKUP, EventStatus.SUCCESS, ModuleTypes.RECOVERY, ServiceTypes.CORE, admin.toString(),
                    null, null, null, details);
        }
    }

    /**
     * This enum-implemented singleton ensures that performing backups is thread safe.
     *
     */
    private enum BackupWorker {
        INSTANCE;

        private BackupWorker() {

        }

        /**
         * Performs a backup of database and configuration, then zips and encrypts the result. Should clean all temporary files after itself.
         *
         * @param publicKey Public key with which to encrypt the compressed file.
         * @return a File reference to the encrypted, compressed backup file.
         * @throws BackupDirectoryNotFoundException if the backup directory doesn't exist and can't be created.
         * @throws RecoveryCompressionException if an error occurs during compression.
         * @throws ConfigurationRecoveryException if an error occurs during configuration backup.
         * @throws DatabaseDumpFailedException if an error occurs while dumping the database.
         * @throws RecoveryEncryptionFailedException if an error occurs while encrypting the compressed file.
         */
        public synchronized Tuplet<File, String>  performBackup(PublicKey publicKey) throws BackupDirectoryNotFoundException, RecoveryCompressionException,
                ConfigurationRecoveryException, DatabaseDumpFailedException, RecoveryEncryptionFailedException {
            // Create backup directory:
            File backupDirectory = new File(BACKUP_DIRECTORY);
            if (!backupDirectory.exists()) {
                backupDirectory.mkdirs();
            }
            if (!backupDirectory.isDirectory() || !backupDirectory.exists()) {
                throw new BackupDirectoryNotFoundException("Directory " + BACKUP_DIRECTORY + " does not exist, can't perform backup.");
            }
            final List<File> files = new ArrayList<File>();
            Tuplet<File, String> result = null;
            try {
                File databaseDump = backupDatabase();
                File configurationBackup = createBackupFile();
                files.add(databaseDump);
                files.add(configurationBackup);
                File zipFile = zipBackupFiles(files, BACKUP_DIRECTORY + File.separator + ZIP_FILENAME);
                // Add zip file to files List, for removal below.
                files.add(zipFile);
                result = encrypt(zipFile, FILE_PREFIX, publicKey);
            } finally {
                // Ensure that all temp files have been removed after backup operation is complete.
                cleanUp(files.toArray(new File[files.size()]));
            }
            return result;
        }

        /**
         * Back up the database.
         *
         *
         * @return the dump, or null if an unexpected error occurs that is not thrown as an exception.
         * @throws DatabaseDumpFailedException if the database dump fails.
         */
        private File backupDatabase() throws DatabaseDumpFailedException {
            File dumpFile = new File(BACKUP_DIRECTORY + File.separator + DB_DUMP_FILENAME);
            List<String> dumpCommand = new ArrayList<String>(Arrays.asList(RecoveryConfiguration.getDbDumpCommand()));
            dumpCommand.add(dumpFile.getAbsolutePath());
            // Make a string of the command to be able to log without exposing the passwords in the log
            String logcommand = dumpCommand.toString();
            logcommand = logcommand.replace(RecoveryConfiguration.getDatabasePassword(), "hidden");
            logcommand = logcommand.replace(RecoveryConfiguration.getDatabaseUsername(), "hidden");
            final ProcessBuilder prb = new ProcessBuilder(dumpCommand);
            if (log.isTraceEnabled()) {
            	log.trace("Dump command: "+logcommand);
            }
            prb.redirectErrorStream(true);
            if (RecoveryConfiguration.getDbPasswordEnvironmentVariable() != null) {
                Map<String, String> env = prb.environment();
                env.put(RecoveryConfiguration.getDbPasswordEnvironmentVariable(), RecoveryConfiguration.getDatabasePassword());
            }
            try {
                String logLine;
                String dumpLog = "";
                final Process process = prb.start();
                final BufferedReader errorStream = new BufferedReader(new InputStreamReader(process.getInputStream()));
                try {
                    final BufferedWriter outputStream = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()));
                    try {
                        while ((logLine = errorStream.readLine()) != null) {
                            dumpLog = dumpLog.concat(logLine);
                        }
                        process.waitFor();
                        process.destroy();
                        if (dumpLog.length() > 0) {
                            throw new DatabaseDumpFailedException(dumpLog);
                        } else if (dumpFile.exists() && dumpFile.length() > 0 && dumpFile.isFile()) {
                            return dumpFile;
                        } else {
                            throw new DatabaseDumpFailedException("Failed to dump database of type: " + RecoveryConfiguration.getDatabaseVendor()
                                    + " for unknown reason.\nCommand was "+ logcommand);
                        }
                    } finally {
                        outputStream.close();
                    }
                } finally {
                    errorStream.close();
                }
            } catch (InterruptedException e) {
                throw new DatabaseDumpFailedException("Database dumping process was interrupted during operation.", e);
            } catch (IOException e) {
                throw new DatabaseDumpFailedException("IOException on dumping database", e);
            }
        }

        /**
         * Write backup file.
         *
         * TODO: Wouldn't this be soooo much more awesome if it produced an XML output instead? Yes, yes it would.
         *
         *
         * @throws ConfigurationRecoveryException
         */
        private File createBackupFile() throws ConfigurationRecoveryException {
            final File file = new File(BACKUP_DIRECTORY + File.separator + CONFIGURATION_FILENAME);
            if (!file.exists()) {
                try {
                    file.createNewFile();
                } catch (IOException e) {
                    log.error("Error creating Backup file", e);
                }
            }
            try {
                final BufferedWriter out = new BufferedWriter(new FileWriter(file));
                try {
                    Properties properties = ConfigurationHolder.getAsProperties();
                    properties.store(out, "Backup up properties.");
                } finally {
                    out.close();
                }
            } catch (IOException e) {
                log.error("Error writing in Backup file", e);
                throw new ConfigurationRecoveryException("IO error encountered when backing up configuration files", e);
            }

            if (file.exists() && file.isFile() && file.length() > 0) {
                return file;
            } else {
                throw new ConfigurationRecoveryException("Configuration backup was not properly produced.");
            }
        }

        /**
         * Clean all temporary files
         */
        private void cleanUp(File... filesToDelete) {
            String unremovedFiles = "";
            for (File file : filesToDelete) {
                if (!file.delete()) {
                    unremovedFiles += file.getAbsolutePath() + ", ";
                }
            }
            if (!unremovedFiles.equals("")) {
                throw new RecoveryCleanupException("Could not delete temporary files " + unremovedFiles
                        + " this may be a breach of security specifications. Please ensure that this file is removed.");
            }
        }

        /**
         * Compresses the backup files into a single Zip.
         *
         * @param inputFiles the input files
         * @param outputFileName the output file
         * @return the compressed file.
         * @throws RecoveryCompressionException if compression fails.
         */
        private File zipBackupFiles(List<File> inputFiles, String outputFileName) throws RecoveryCompressionException {
            final byte[] buffer = new byte[BUFFER_SIZE];
            final File zipFile = new File(outputFileName);
            try {
                final ZipOutputStream outputStream = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(zipFile)));
                try {
                    outputStream.setLevel(Deflater.DEFAULT_COMPRESSION);
                    BufferedInputStream inputFileStream;
                    for (File file : inputFiles) {
                        inputFileStream = new BufferedInputStream(new FileInputStream(file.getAbsolutePath()), BUFFER_SIZE);
                        try {
                            outputStream.putNextEntry(new ZipEntry(file.getName()));
                            int count;
                            while ((count = inputFileStream.read(buffer, 0, BUFFER_SIZE)) != -1) {
                                outputStream.write(buffer, 0, count);
                            }
                        } finally {
                            inputFileStream.close();
                        }
                    }
                } finally {
                    outputStream.close();
                }
            } catch (IOException e) {
                throw new RecoveryCompressionException("IOException was encountered while backing up files.", e);
            }
            if (zipFile.exists() && zipFile.isFile() && zipFile.length() > 0) {
                return zipFile;
            } else {
                throw new RecoveryCompressionException("Compressed backup file was not created correctly.");
            }
        }

        /**
         * Encrypt.
         *
         * @param plainFile the File to encrypt.
         * @param cipherFileName the backup file name
         * @return Tuplet with File and sha256 hash
         * @throws RecoveryEncryptionFailedException if encryption fails.
         */
        private Tuplet<File, String> encrypt(File plainFile, String cipherFileName, PublicKey publicKey) throws RecoveryEncryptionFailedException {
            final File result = new File(BACKUP_DIRECTORY + File.separator + cipherFileName + DATE_FORMAT.format(Calendar.getInstance().getTime()) + FILE_SUFFIX);
            String hash = null;
            CryptoProviderTools.installBCProviderIfNotAvailable();
            try {
            	final MessageDigest md = MessageDigest.getInstance("SHA256");
                final FileOutputStream outFile = new FileOutputStream(result);
                final DigestOutputStream out = new DigestOutputStream(outFile, md);
                try {
                    byte[] data = getBytesFromFile(plainFile);
                    CMSEnvelopedData ed;
                    CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
                    edGen.addKeyTransRecipient(publicKey, KeyTools.createSubjectKeyId(publicKey).getKeyIdentifier());
                    ed = edGen.generate(new CMSProcessableByteArray(data), CMSEnvelopedDataGenerator.CAMELLIA256_CBC, "BC");
                    out.write(ed.getEncoded());
                    hash = new String(Hex.encode(md.digest()));
                } finally {
                	out.close();
                    outFile.close();
                }
            } catch (NoSuchAlgorithmException e) {
                throw new RecoveryEncryptionFailedException("Could not be encrypted using CAMELLIA256_CBC", e);
            } catch (FileNotFoundException e) {
                throw new RecoveryEncryptionFailedException("Result file could not be created", e);
            } catch (NoSuchProviderException e) {
                throw new RecoveryEncryptionFailedException("BouncyCastle not found as crypto provider", e);
            } catch (CMSException e) {
                throw new RecoveryEncryptionFailedException("Error on CMS", e);
            } catch (IOException e) {
                throw new RecoveryEncryptionFailedException("IOException on encrypt", e);
            }

            if (result.exists() && result.isFile() && result.length() > 0) {
                return new Tuplet<File, String>(result, hash);
            } else {
                throw new RecoveryEncryptionFailedException("Crypto file was not produced.");
            }

        }

        /**
         * Gets the bytes from file.
         *
         * @param file the file
         * @return the bytes from file
         * @throws IOException Signals that an I/O exception has occurred.
         */
        private static byte[] getBytesFromFile(File file) throws IOException {
            InputStream is = new FileInputStream(file);
            // Get the size of the file
            long length = file.length();
            if (length > Integer.MAX_VALUE) {
                // File is too large
            }
            // Create the byte array to hold the data
            byte[] bytes = new byte[(int) length];
            // Read in the bytes
            int offset = 0;
            int numRead = 0;
            while (offset < bytes.length && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
                offset += numRead;
            }
            // Ensure all the bytes have been read in
            if (offset < bytes.length) {
                throw new IOException("Could not completely read file " + file.getName());
            }
            // Close the input stream and return bytes
            is.close();
            return bytes;
        }
    }

}
