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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditLogReportElem;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.SecurityEventsAuditorSession;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSession;
import org.cesecore.audit.log.SecurityEventsLoggerSessionRemote;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.ConfigurationBackupUtilitySessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.recovery.backup.BackupSession;
import org.cesecore.recovery.backup.BackupSessionRemote;
import org.cesecore.recovery.exception.BackupDirectoryNotFoundException;
import org.cesecore.recovery.exception.ConfigurationRecoveryException;
import org.cesecore.recovery.exception.DatabaseDumpFailedException;
import org.cesecore.recovery.exception.RecoveryCompressionException;
import org.cesecore.recovery.exception.RecoveryEncryptionFailedException;
import org.cesecore.recovery.exception.RecoverySetupException;
import org.cesecore.recovery.restore.RestoreSessionRemote;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the backup session bean.
 * 
 * @version $Id$
 */
public class BackupAndRestoreSessionTest extends RoleUsingTestCase {
    private static Logger log = Logger.getLogger(BackupAndRestoreSessionTest.class);
    
    private BackupSessionRemote backupSession = JndiHelper.getRemoteSession(BackupSessionRemote.class);
    private RestoreSessionRemote restoreSession = JndiHelper.getRemoteSession(RestoreSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    private CryptoTokenSessionRemote tokenSession = JndiHelper.getRemoteSession(CryptoTokenSessionRemote.class);
    private SecurityEventsLoggerSession securityEventsLogger = JndiHelper.getRemoteSession(SecurityEventsLoggerSessionRemote.class);
    private SecurityEventsAuditorSession securityEventsAuditor = JndiHelper.getRemoteSession(SecurityEventsAuditorSessionRemote.class);

    private ConfigurationBackupUtilitySessionRemote configurationBackupUtilitySession = JndiHelper
            .getRemoteSession(ConfigurationBackupUtilitySessionRemote.class);

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        // Set up base role that can edit roles
        setUpAuthTokenAndRole("BackupAndRestoreSessionTest");

        // Now we have a role that can edit roles, we can edit this role to include more privileges
        RoleData role = roleAccessSession.findRole("BackupAndRestoreSessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.BACKUP.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.RESTORE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.AUDITLOGSELECT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.AUDITLOGVERIFY.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.AUDITLOGLOG.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);
    }

    @After
    public void tearDown() throws Exception {
        tearDownRemoveRole();
    }

    private File makeBackup(final CryptoToken cryptoToken, final String alias) throws RecoveryCompressionException, ConfigurationRecoveryException, RecoveryEncryptionFailedException, CryptoTokenOfflineException, AuthorizationDeniedException, BackupDirectoryNotFoundException, DatabaseDumpFailedException, ParseException {
        // Check that super used id for the database has been set in backup.test.properties, otherwise these tests can't run.
        if (RecoveryTestConfiguration.getDatabaseSuperUserId() == null) {
            fail("Database superuser information hasn't been set in backup.test.properties.");
        }

        final File backupDirectory = new File(RecoveryConfiguration.getBackupDirectory());

        File backupFile = null;
        try {
            backupSession.performBackup(roleMgmgToken, cryptoToken.getPublicKey(alias));
            // Go through the backup directory, find the file latest produced.
            Date latestDate = null;
            for (File file : backupDirectory.listFiles()) {
                if (file.getName().matches(".*\\" + BackupSession.FILE_SUFFIX)) {
                    // Parse date from filename
                    Date date = BackupSession.DATE_FORMAT.parse(file.getName().substring(RecoveryConfiguration.getFilePrefix().length(),
                            file.getName().lastIndexOf(BackupSession.FILE_SUFFIX)));
                    if (latestDate == null) {
                        backupFile = file;
                        latestDate = date;
                    } else if (date.after(latestDate)) {
                        backupFile = file;
                        latestDate = date;
                    }
                }
            }
            assertNotNull(backupFile);
            backupFile.deleteOnExit();
        } catch (RecoverySetupException e) {
            fail("Backup/Recovery command haven't been set up in backup.properties. Please do so to continue testing.");
        }
        return backupFile;
    }
    
    @Test
    public void testBackup() throws Exception {
        final String alias = "backuptest";
        final String tokenpin = "userpin1";
        final Properties prop = new Properties();
        prop.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.toString(true));
        CryptoToken cryptoToken = tokenSession.createCryptoToken(roleMgmgToken, SoftCryptoToken.class.getName(), prop, null, 111);
        cryptoToken = tokenSession.generateKeyPair(roleMgmgToken, cryptoToken, tokenpin.toCharArray(), "512", alias);
        cryptoToken.activate(tokenpin.toCharArray());
        File backupFile = null;
        try {
        	backupFile = makeBackup(cryptoToken, alias);
        } finally {
        	if (backupFile != null) {
            	backupFile.delete();        		
        	}
        }
    }
    
    @Test
    public void testBackupAndRestore() throws Exception {
        final String testRoleName = "backupRole";
        // Check that the entry in RoleData which we're going to use to verify database backup doesn't exist.
        if (roleAccessSession.findRole(testRoleName) != null) {
            roleManagementSession.remove(roleMgmgToken, testRoleName);
        }

        // Verify logs first, so we know that we are entering with a clean, verifiable log
        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final AuditLogValidationReport report = securityEventsAuditor.verifyLogsIntegrity(roleMgmgToken, new Date(), logDeviceId);
            assertNotNull(report);
            final StringBuilder strBuilder = new StringBuilder();
            for (AuditLogReportElem error : report.errors()) {
                strBuilder.append(String.format("invalid sequence: %d %d\n", error.getFirst(), error.getSecond()));
                for (String reason: error.getReasons()) {
                    strBuilder.append(String.format("Reason: %s\n", reason));
                }
            }
            assertTrue("log device '"+logDeviceId+"', validation report: " + strBuilder.toString()+", warnings: "+report.warnings().size()+", errors: "+report.errors().size(), 
                    (report.warnings().size() == 1 || report.warnings().size() == 0) && 
                    report.errors().size() == 0);
        }
        
        // Then start backing up and restoring
        final String alias = "backuptest";
        final String tokenpin = "userpin1";
        final Properties prop = new Properties();
        prop.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.toString(true));
        CryptoToken cryptoToken = tokenSession.createCryptoToken(roleMgmgToken, SoftCryptoToken.class.getName(), prop, null, 111);
        cryptoToken = tokenSession.generateKeyPair(roleMgmgToken, cryptoToken, tokenpin.toCharArray(), "512", alias);
        cryptoToken.activate(tokenpin.toCharArray());

        File backupFile = makeBackup(cryptoToken, alias);
        try {
            // Log an event after the backup is taken and save the resulting AuditLogEntry for each AuditDevice
            securityEventsLogger.log(roleMgmgToken, EventTypes.AUTHENTICATION, EventStatus.FAILURE, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE);
            final Map<String,AuditLogEntry> missingMap = new HashMap<String,AuditLogEntry>();
            final long timeAfterLog = new Date().getTime();
            for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            	log.debug("Querying logDevice: "+logDeviceId);
            	List<? extends AuditLogEntry> listBackup = securityEventsAuditor.selectAuditLogs(roleMgmgToken, 1, 1, 
            	        QueryCriteria.create().add(Criteria.leq(AuditLogEntry.FIELD_TIMESTAMP, timeAfterLog)).add(Criteria.orderDesc(AuditLogEntry.FIELD_SEQUENCENUMBER)), logDeviceId);
                assertEquals("Should contain only 1 log", 1, listBackup.size());
                AuditLogEntry bkp = listBackup.get(0);
                assertTrue("EventType should be AUTHENTICATION for "+logDeviceId+": "+bkp.getSequenceNumber(), EventTypes.AUTHENTICATION.equals(bkp.getEventTypeValue()));
                assertTrue("ModuleType should be CERTIFICATEPROFILE for "+logDeviceId+": "+bkp.getSequenceNumber(), ModuleTypes.CERTIFICATEPROFILE.equals(bkp.getModuleTypeValue()));
                assertEquals("EventStatus should be FAILURE for "+logDeviceId+": "+bkp.getSequenceNumber(), EventStatus.FAILURE, bkp.getEventStatusValue());
                assertEquals("User should be roleMgmgToken for "+logDeviceId+": "+bkp.getSequenceNumber(), roleMgmgToken.toString(), bkp.getAuthToken());
                log.debug("Adding "+listBackup.get(0).getSequenceNumber()+" for logdevice "+logDeviceId);
                missingMap.put(logDeviceId, listBackup.get(0));
            }
            
            // Create some an entry in the RoleData table and then verify that it has been removed when the database has been restored.
            roleManagementSession.create(roleMgmgToken, testRoleName);
            // Pick a random value from CesecoreConfiguration and change it.
            final boolean originalValue = configurationBackupUtilitySession.isDevelopmentProviderInstallation();
            configurationBackupUtilitySession.setDevelopmentProviderInstallation(!originalValue);
            try {
                assertNotNull("Could not create verification data in table RoleData, test can not continue", roleAccessSession.findRole(testRoleName));
                assertFalse("Could not change configuration, test can't continue.",
                        originalValue == configurationBackupUtilitySession.isDevelopmentProviderInstallation());
                restoreSession.performRecovery(roleMgmgToken, backupFile, cryptoToken.getClass(), cryptoToken.getTokenData(), cryptoToken.getProperties(), alias, tokenpin,
                        RecoveryTestConfiguration.getDatabaseSuperUserId(), RecoveryTestConfiguration.getDatabaseSuperUserPassword());

                // Verify that that testRoleName doesn't exist anymore in RoleData;
                assertNull("Database restoration was not performed correctly", roleAccessSession.findRole(testRoleName));
                // Verify that the configuration is back.
                assertEquals("Configuration restoration not performed correctly.", originalValue,
                        configurationBackupUtilitySession.isDevelopmentProviderInstallation());
            } finally {
                // Clean up
                configurationBackupUtilitySession.setDevelopmentProviderInstallation(originalValue);
                if (roleAccessSession.findRole(testRoleName) != null) {
                    roleManagementSession.remove(roleMgmgToken, testRoleName);
                }
            }

            // We log again and verify that the sequence number in the log is held by a new entry and not the one logged before restore.
            securityEventsLogger.log(roleMgmgToken, EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE);
            for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
                final AuditLogEntry missingLog = missingMap.get(logDeviceId);
            	log.debug("Querying logDevice "+logDeviceId+" for sequence "+missingLog.getSequenceNumber());
                final List<? extends AuditLogEntry> listRecovery = securityEventsAuditor.selectAuditLogs(roleMgmgToken, 1, 1, 
                        QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_SEQUENCENUMBER, missingLog.getSequenceNumber())), logDeviceId);
                assertEquals("Should contain only 1 log for "+logDeviceId+": "+missingLog.getSequenceNumber(), 1, listRecovery.size());
                AuditLogEntry bkp = listRecovery.get(0);
                assertEquals("User should be roleMgmgToken for "+logDeviceId+": "+bkp.getSequenceNumber(), roleMgmgToken.toString(), bkp.getAuthToken());
                // the restore made the previous record with this sequence number disappear, and now we should have a new log row with the same sequence number
                assertTrue("Should be the same log sequencenumber for "+logDeviceId, missingLog.getSequenceNumber().equals(bkp.getSequenceNumber()));
                assertFalse("Event should not be AUTHENTICATION, CERTIFICATEPROFILE, FAILURE for "+logDeviceId+": "+bkp.getSequenceNumber(), 
                		EventTypes.AUTHENTICATION.equals(bkp.getEventTypeValue()) && 
                		ModuleTypes.AUTHENTICATION.equals(bkp.getModuleTypeValue()) && 
                				EventStatus.FAILURE.equals(bkp.getEventStatusValue()));

                // Validate log. It should still make a proper chain.
                final AuditLogValidationReport report = securityEventsAuditor.verifyLogsIntegrity(roleMgmgToken, new Date(), logDeviceId);
                assertNotNull(report);
                final StringBuilder strBuilder = new StringBuilder();
                for (AuditLogReportElem error : report.errors()) {
                	strBuilder.append(String.format("invalid sequence: %d %d\n", error.getFirst(), error.getSecond()));
                	for (String reason: error.getReasons()) {
                		strBuilder.append(String.format("Reason: %s\n", reason));
                	}
                }
                assertTrue("log device '"+logDeviceId+"', validation report: " + strBuilder.toString()+", warnings: "+report.warnings().size()+", errors: "+report.errors().size(), 
                		(report.warnings().size() == 1 || report.warnings().size() == 0) && 
                		report.errors().size() == 0);
            }

            
        } catch (RecoverySetupException e) {
        	log.debug("Backup/recovery error: ", e);
            fail("Backup/Recovery command haven't been set up in backup.properties. Please do so to continue testing.");
        }
    }

    @Test
    public void testFailRestore() throws Exception {
        final String alias = "backuptest";
        final String tokenpin = "userpin1";
        final Properties prop = new Properties();
        prop.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.toString(true));
        CryptoToken cryptoToken = tokenSession.createCryptoToken(roleMgmgToken, SoftCryptoToken.class.getName(), prop, null, 111);
        cryptoToken = tokenSession.generateKeyPair(roleMgmgToken, cryptoToken, tokenpin.toCharArray(), "512", alias);
        cryptoToken.activate(tokenpin.toCharArray());

        // Make a bad backup file that we wil lnot be able to decrypt
        File file = File.createTempFile("badbackup", "bup");
        file.deleteOnExit();
        FileOutputStream fos = new FileOutputStream(file);
        try {
        	fos.write("badbackupdata".getBytes());
        } finally {
            fos.close();        	
        }
        
        try {
        restoreSession.performRecovery(roleMgmgToken, file, cryptoToken.getClass(), cryptoToken.getTokenData(), cryptoToken.getProperties(), alias, tokenpin,
                RecoveryTestConfiguration.getDatabaseSuperUserId(), RecoveryTestConfiguration.getDatabaseSuperUserPassword());
        fail("Recovery should throw RecoveryEncryptionFailedException when trying to decrypt non encrypted data.");
        } catch (RecoveryEncryptionFailedException e) {
        	// NOPMD: this is what we expect
        }
    }
    
    @Test
    public void testAuthorization() throws Exception {

        KeyPair keys = KeyTools.genKeys("512", "RSA");
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test RecoverySessionNoAuth", 365, null, keys.getPrivate(),
                keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);

        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(principals, credentials);

        try {
            final String tokenpin = "userpin1";
            final String alias = "backuptest";
            Properties prop = new Properties();
            prop.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.toString(true));
            CryptoToken cryptoToken = tokenSession.createCryptoToken(roleMgmgToken, SoftCryptoToken.class.getName(), prop, null, 111);
            cryptoToken = tokenSession.generateKeyPair(roleMgmgToken, cryptoToken, tokenpin.toCharArray(), "512", alias);
            cryptoToken.activate(tokenpin.toCharArray());
            try {
                backupSession.performBackup(adminTokenNoAuth, cryptoToken.getPublicKey(alias));
                fail("should throw");
            } catch (AuthorizationDeniedException e) {
                // NOPMD
            }
            try {
                File backupFile = new File("/tmp/sqlDump.sql");
                restoreSession.performRecovery(adminTokenNoAuth, backupFile, SoftCryptoToken.class, cryptoToken.getTokenData(), cryptoToken.getProperties(), alias,
                        tokenpin, RecoveryTestConfiguration.getDatabaseSuperUserId(), RecoveryTestConfiguration.getDatabaseSuperUserPassword());
                fail("should throw");
            } catch (AuthorizationDeniedException e) {
                // NOPMD
            }
        } finally {
        }
    }

}
