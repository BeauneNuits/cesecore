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
package org.cesecore.audit.log;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.fail;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.time.StopWatch;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.SecurityEventsBase;
import org.cesecore.audit.audit.AuditLogReportElem;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.SecurityEventsAuditorSession;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.ExampleClassEventTypes;
import org.cesecore.audit.impl.ExampleEnumEventTypes;
import org.cesecore.audit.impl.queued.entity.AuditLogData;
import org.cesecore.audit.impl.queued.entity.LogManagementData;
import org.cesecore.audit.impl.queued.management.LogManagementSession;
import org.cesecore.audit.impl.queued.management.LogManagementSessionRemote;
import org.cesecore.audit.log.management.LogManagementSessionBeanTest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Secure audit logs logger functional tests.
 * 
 * @version $Id$
 * 
 */
public class SecurityEventsLoggerSessionBeanTest extends SecurityEventsBase {

    private static final Logger log = Logger.getLogger(SecurityEventsLoggerSessionBeanTest.class);
    private final SecurityEventsLoggerSession securityEventsLogger = JndiHelper.getRemoteSession(SecurityEventsLoggerSessionRemote.class);
    private final SecurityEventsAuditorSession securityEventsAuditor = JndiHelper.getRemoteSession(SecurityEventsAuditorSessionRemote.class);
    private final TxFailureLoggerOperationSessionRemote txFailure = JndiHelper.getRemoteSession(TxFailureLoggerOperationSessionRemote.class);
    private final LogManagementSession logManagement = JndiHelper.getRemoteSession(LogManagementSessionRemote.class);

    @BeforeClass
    public static void setUpCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

    @Test
    public void test01SecureLogWithoutAdditionalDetails() throws AuditRecordStorageException, AuthorizationDeniedException {
        log.trace(">test01SecureLogWithoutAdditionalDetails");
        securityEventsLogger.log(roleMgmgToken, EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE);
        log.trace("<test01SecureLogWithoutAdditionalDetails");
    }

    @Test
    public void test02logAppCustomEventTypes() throws Exception {
        log.trace(">test02logAppCustomEventTypes");
        securityEventsLogger.log(roleMgmgToken, ExampleEnumEventTypes.NEW_EVENT_TYPE, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE);
        securityEventsLogger.log(roleMgmgToken, ExampleClassEventTypes.NEW_EVENT_TYPE_CLASS, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE);
        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> lastSignedLogs = securityEventsAuditor.selectAuditLogs(
                    roleMgmgToken,
                    1,
                    10,
                    QueryCriteria.create().add(Criteria.or(Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, ExampleEnumEventTypes.NEW_EVENT_TYPE.toString()), Criteria.eq(AuditLogEntry.FIELD_EVENTTYPE, ExampleClassEventTypes.NEW_EVENT_TYPE_CLASS.toString()))), logDeviceId);
            assertEquals(2, lastSignedLogs.size());
            for(AuditLogEntry ae: lastSignedLogs) {
                assertTrue(ae.getEventTypeValue().equals(ExampleEnumEventTypes.NEW_EVENT_TYPE) || 
                        ae.getEventTypeValue().equals(ExampleClassEventTypes.NEW_EVENT_TYPE_CLASS));
            }
        }

        log.trace("<test02logAppCustomEventTypes");
    }

    @Test
    public void test03SecurelogWithAdditionalDetails() throws AuditRecordStorageException, AuthorizationDeniedException {
        log.trace(">test03SecurelogWithAdditionalDetails");
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        final Map<String, String> innerDetails = new LinkedHashMap<String, String>();
        innerDetails.put("extra", "bar");
        details.put("foo", innerDetails);
        securityEventsLogger.log(roleMgmgToken, EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE, "0",
                "7FFFFFFFFFFFFFFF", "someentityname", details);
        log.trace("<test03SecurelogWithAdditionalDetails");
    }

    @Test
    public void test04SecureMultipleLog() throws Exception {
        log.trace(">test04SecureMultipleLog");
        final int THREADS = 50;
        final int WORKERS = 400;
        final int TIMEOUT_MS = 30000;
        final ThreadPoolExecutor workers = (ThreadPoolExecutor) Executors.newFixedThreadPool(THREADS);
        final StopWatch time = new StopWatch();

        time.start();
        for (int i = 0; i < WORKERS; i++) {
            workers.execute(new Runnable() { // NOPMD: this is a test, not a JEE application
                @Override
                public void run() {
                    try {
						securityEventsLogger.log(roleMgmgToken, EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE);
					} catch (AuthorizationDeniedException e) {
						fail("should be authorized");
					}
                }
            });
        }
        while (workers.getCompletedTaskCount() < WORKERS && time.getTime() < TIMEOUT_MS) {
            Thread.sleep(250);
        }
        time.stop();
        final int completedTaskCount = Long.valueOf(workers.getCompletedTaskCount()).intValue();
        log.info("securityEventsLogger.log: " + completedTaskCount + " completed in " + time.toString() + " using " + THREADS + " threads.");
        workers.shutdown();

        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final AuditLogValidationReport report = securityEventsAuditor.verifyLogsIntegrity(roleMgmgToken, new Date(), logDeviceId);
            assertNotNull(report);
            final StringBuilder strBuilder = new StringBuilder();
            for (final AuditLogReportElem error : report.errors()) {
                strBuilder.append(String.format("invalid sequence: %d %d\n", error.getFirst(), error.getSecond()));
                for (final String reason : error.getReasons()) {
                    strBuilder.append(String.format("Reason: %s\n", reason));
                }
            }
            assertTrue("validation report: " + strBuilder.toString(), (report.warnings().size() == 1 || report.warnings().size() == 0)
                    && report.errors().size() == 0);
        }
        log.trace("<test04SecureMultipleLog");
    }

    @Test
    public void test05ExportGeneratedLogs() throws Exception {
        log.trace(">test05ExportGeneratedLogs");
        final CryptoToken cryptoToken = createTokenWithKeyPair();
        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final String exportFilename = securityEventsAuditor.exportAuditLogs(roleMgmgToken, cryptoToken, new Date(), true, keyAlias,
                    keyPairSignAlgorithm, logDeviceId).getExportedFile();
            assertExportAndSignatureExists(exportFilename);
        }
        log.trace("<test05ExportGeneratedLogs");
    }

    @Test
    // (expected = Exception.class)
    public void test06TxFailure() throws Exception {
        log.trace(">test06TxFailure");
        try {
            txFailure.willLaunchExceptionAfterLog();
            fail("No exception was thrown..");
        } catch (final Exception e) {
            // Expected
        }
        for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditor.selectAuditLogs(roleMgmgToken, 1, 10,
                    QueryCriteria.create().add(Criteria.like(AuditLogEntry.FIELD_AUTHENTICATION_TOKEN, "TxFailureUser")), logDeviceId);
            assertEquals("List size is:" + list.size(), 1, list.size());
        }
        log.trace("<test06TxFailure");
    }

    @Test
    // This test is only for QueuedDevice
    public void test07QueuedDeviceValidateFrequency() throws Exception {
        log.trace(">test07QueuedDeviceValidateFrequency");
        final String logDeviceId = "QueuedDevice";

        final LogManagementData hmac = LogManagementSessionBeanTest.createHmacLogManagementData();
        /**
         * the reason why this is set to 8s has to do with glassfish default config restrictions
         * 
         * http://blogs.oracle.com/ievans/entry/minimum_timeout_interval_for_ejb
         * 
         */
        // Change frequency
        hmac.setFrequency(8000l);
        logManagement.changeLogManagement(roleMgmgToken, hmac);
        // check for logged event type LOG_MANAGEMENT_CHANGE
        final List<? extends AuditLogEntry> logManagementLogs = securityEventsAuditor.selectAuditLogs(
                roleMgmgToken,
                1,
                10,
                QueryCriteria.create().add(Criteria.like(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.LOG_MANAGEMENT_CHANGE.toString())).add(Criteria.orderDesc(AuditLogEntry.FIELD_TIMESTAMP)), logDeviceId);
        assertTrue("logManagementLogs size is:" + logManagementLogs.size(), logManagementLogs.size() >= 1);
        // We will wait ... this gives some time to the scheduler trigger times out
        Thread.sleep(8050l);

        // Since we set the audit log to sign in intervals of 8 secs ... this log will not contain signature.
        securityEventsLogger.log(roleMgmgToken, EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE);
        final List<? extends AuditLogEntry> lastSignedLogs = securityEventsAuditor.selectAuditLogs(
                roleMgmgToken,
                1,
                10,
                QueryCriteria.create().add(Criteria.like(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.AUTHENTICATION.toString())).add(Criteria.orderDesc(AuditLogEntry.FIELD_TIMESTAMP)), logDeviceId);
        assertTrue("lastSignedLogs size is:" + lastSignedLogs.size(), lastSignedLogs.size() >= 1);
        assertTrue("Unsigned log: signature field is not empty.", ((AuditLogData) lastSignedLogs.get(0)).getSignature() == null);

        final long notSignedSeqNumber = lastSignedLogs.get(0).getSequenceNumber();
        // We will wait ... this gives some time to the scheduler trigger times out
        Thread.sleep(8050l);
        // We will at least (database might not be clean) 2 logs with eventType = LOG_SIGN

        // Test signed logs frequency
        final List<? extends AuditLogEntry> listSignedLogs = securityEventsAuditor.selectAuditLogs(
                roleMgmgToken,
                1,
                10,
                QueryCriteria.create().add(Criteria.like(AuditLogEntry.FIELD_EVENTTYPE, EventTypes.LOG_SIGN.toString())).add(Criteria.orderAsc(AuditLogEntry.FIELD_TIMESTAMP)), logDeviceId);
        assertTrue("listSignedLogs size is:" + listSignedLogs.size(), listSignedLogs.size() >= 2);
        final long timestamp_diff = ((AuditLogData) listSignedLogs.get(1)).getTimeStamp() - ((AuditLogData) listSignedLogs.get(0)).getTimeStamp();
        // This kind of interval has to do with variable time that the bean needs to initialize and call the timeout method
        assertTrue("Difference between timestamps is " + timestamp_diff, timestamp_diff >= 7900l);
        // Validate signature fields
        assertTrue("Signed log: signature field is empty.", ((AuditLogData) listSignedLogs.get(0)).getSignature() != null);
        assertTrue("Signed log: signature field is empty.", ((AuditLogData) listSignedLogs.get(1)).getSignature() != null);

        // let's see if after all the timeouts the previous not signed log keeps it's not signed state
        final List<? extends AuditLogEntry> listNotSignedLogs = securityEventsAuditor.selectAuditLogs(roleMgmgToken, 1, 10,
                QueryCriteria.create().add(Criteria.eq(AuditLogEntry.FIELD_SEQUENCENUMBER, notSignedSeqNumber)), logDeviceId);
        assertTrue("Not signed log: signature field is not empty.", ((AuditLogData) listNotSignedLogs.get(0)).getSignature() == null);
        log.trace("<test07QueuedDeviceValidateFrequency");
    }

    @Test
    public void test08Authorization() throws Exception {
    	KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test SecurityEventsLoggerSessionTestNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);

        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(principals, credentials);

        try {
            securityEventsLogger.log(adminTokenNoAuth, EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE);
        	fail("should throw");
        } catch (AuthorizationDeniedException e) {
        	// NOPMD: ignore this is what we want
        }
    }

    @AfterClass
    public static void setDown() {
        CryptoProviderTools.removeBCProvider();
    }

    private void assertExportAndSignatureExists(final String exportFilename) {
        final File exportFile = new File(exportFilename);
        assertTrue("file does not exist, " + exportFile.getAbsolutePath(), exportFile.exists());
        assertTrue("file length is not > 0, " + exportFile.getAbsolutePath(), exportFile.length() > 0);
        assertTrue("file can not be deleted, " + exportFile.getAbsolutePath(), exportFile.delete());
        final File signatureFile = new File(String.format("%s.sig", FilenameUtils.removeExtension(exportFile.getAbsolutePath())));
        assertTrue("signatureFile does not exist, " + signatureFile.getAbsolutePath(), signatureFile.exists());
        assertTrue("signatureFile length is not > 0, " + signatureFile.getAbsolutePath(), signatureFile.length() > 0);
        assertTrue("signatureFile can not be deleted, " + signatureFile.getAbsolutePath(), signatureFile.delete());
    }
}
