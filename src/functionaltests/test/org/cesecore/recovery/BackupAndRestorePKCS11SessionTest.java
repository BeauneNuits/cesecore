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
import static org.junit.Assert.fail;

import java.io.File;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaSessionTest;
import org.cesecore.certificates.ca.catoken.CaTokenSessionRemote;
import org.cesecore.configuration.ConfigurationBackupUtilitySessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.recovery.backup.BackupSession;
import org.cesecore.recovery.backup.BackupSessionRemote;
import org.cesecore.recovery.exception.RecoverySetupException;
import org.cesecore.recovery.restore.RestoreSessionRemote;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the backup session bean using PKCS#11 HSM for private key protection.
 * 
 * @version $Id$
 */
public class BackupAndRestorePKCS11SessionTest extends RoleUsingTestCase {
    private BackupSessionRemote backupSession = JndiHelper.getRemoteSession(BackupSessionRemote.class);
    private RestoreSessionRemote restoreSession = JndiHelper.getRemoteSession(RestoreSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    private CaTokenSessionRemote caTokenSession = JndiHelper.getRemoteSession(CaTokenSessionRemote.class);
    private CaSessionRemote caSession = JndiHelper.getRemoteSession(CaSessionRemote.class);

    private ConfigurationBackupUtilitySessionRemote configurationBackupUtilitySession = JndiHelper
            .getRemoteSession(ConfigurationBackupUtilitySessionRemote.class);

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        // Set up base role that can edit roles
        setUpAuthTokenAndRole("BackupAndRestorePKCS11SessionTest");

        // Now we have a role that can edit roles, we can edit this role to include more privileges
        RoleData role = roleAccessSession.findRole("BackupAndRestorePKCS11SessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.BACKUP.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.RESTORE.resource(), AccessRuleState.RULE_ACCEPT, true));
        // To create a CA to get keys on the HSM on the server side
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAADD.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAREMOVE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);
    }

    @After
    public void tearDown() throws Exception {
        tearDownRemoveRole();
    }

    @Test
    public void testBackupAndRestore() throws Exception {
        // We know this is the key alias that will be generated
        final String alias = "dbProtKey";
        final String tokenpin = "userpin1";
        final String testRoleName = "backupRole";

        // Check that super used id for the database has been sett in backup.test.properties, otherwise these tests can't run.
        if (RecoveryTestConfiguration.getDatabaseSuperUserId() == null) {
            fail("Database superuser information hasn't been set in backup.test.properties.");
        }

        // Check that the entry in RoleData which we're going to use to verify database backup doesn't exist.
        if (roleAccessSession.findRole(testRoleName) != null) {
            roleManagementSession.remove(roleMgmgToken, testRoleName);
        }

        File backupDirectory = new File(RecoveryConfiguration.getBackupDirectory());

        // In order for the keys to be accessible by the server, they need to be generated on the server
        // Here we create a new CA for this purpose
    	final String cadn = "CN=BackupRestorePKCS11"; 
    	final CA ca = CaSessionTest.createTestX509CAOptionalGenKeys(cadn, tokenpin, false, true);
        try {
        	caSession.addCA(roleMgmgToken, ca);
        	// Generate keys, will audit log
        	caTokenSession.activateCAToken(roleMgmgToken, ca.getCAId(), tokenpin.toCharArray());
        	caTokenSession.generateKeyPair(roleMgmgToken, ca.getCAId(), tokenpin.toCharArray(), "1024", alias);
        	// Get the public key to encrypt the backup with
        	PublicKey pk = caTokenSession.getPublicKey(roleMgmgToken, ca.getCAId(), tokenpin.toCharArray(), alias);
    	
            backupSession.performBackup(roleMgmgToken, pk);

            File backupFile = null;
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

            // Create some an entry in the RoleData table and then verify that it has been removed when the database has been restored.
            roleManagementSession.create(roleMgmgToken, testRoleName);
            // Pick a random value from CesecoreConfiguration and change it.
            final boolean originalValue = configurationBackupUtilitySession.isDevelopmentProviderInstallation();
            configurationBackupUtilitySession.setDevelopmentProviderInstallation(!originalValue);
            try {
                assertNotNull("Could not create verification data in table RoleData, test can't continue", roleAccessSession.findRole(testRoleName));
                assertFalse("Could not change configuration, test can't continue.",
                        originalValue == configurationBackupUtilitySession.isDevelopmentProviderInstallation());
            	CryptoToken cryptoToken = ca.getCAToken().getCryptoToken();
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
        } catch (RecoverySetupException e) {
            fail("Backup/Recovery command haven't been set up in backup.properties. Please do so to continue testing.");
        } finally {
        	// Remove generated key pair
        	caTokenSession.deleteTokenEntry(roleMgmgToken, ca.getCAId(), tokenpin.toCharArray(), alias);
        	// remove generated CA
        	caSession.removeCA(roleMgmgToken, ca.getCAId());
        }
    }

}
