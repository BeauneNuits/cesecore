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

import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.fail;
import static org.junit.Assert.assertEquals;

import java.io.File;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import org.apache.commons.io.FilenameUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.SecurityEventsBase;
import org.cesecore.audit.audit.SecurityEventsAuditorSession;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.queued.entity.AuditLogCryptoTokenConfigData;
import org.cesecore.audit.impl.queued.entity.DigSignLogManagementData;
import org.cesecore.audit.impl.queued.management.LogManagementSession;
import org.cesecore.audit.impl.queued.management.LogManagementSessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Compare performance between different log implementations.
 * @version $Id$
 */
public class LogPerformanceTest extends SecurityEventsBase {

    private static final Logger log = Logger.getLogger(LogPerformanceTest.class);
    private SecurityEventsLoggerSession securityEventsLogger = JndiHelper.getRemoteSession(SecurityEventsLoggerSessionRemote.class);
    private SecurityEventsAuditorSession securityEventsAuditor = JndiHelper.getRemoteSession(SecurityEventsAuditorSessionRemote.class);
    private LogManagementSession logManagement = JndiHelper.getRemoteSession(LogManagementSessionRemote.class);

    private static final int WORKERS = 2000;
    private static final int THREADS = 50;
    private static final int TIMEOUT_MS = 30000;

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
    	CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @AfterClass
    public static void rmCryptoProvider() {
    	CryptoProviderTools.removeBCProvider();
    }

    @Test
    public void testSecureLog() throws Exception {
    	log.trace(">testSecureLog");
    	// Use 1024 SHA512withRSA
        logManagement.changeLogManagement(roleMgmgToken, createDigSignLogManagementData());
    	// Export (delete) any old log first
        final CryptoToken cryptoToken = createTokenWithKeyPair();
    	for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
    		final String exportFilename = securityEventsAuditor.exportAuditLogs(roleMgmgToken, cryptoToken, new Date(), true, keyAlias, keyPairSignAlgorithm, logDeviceId).getExportedFile();
        	assertExportAndSignatureExists(exportFilename);
    	}
    	// Log some and measure time
        final ThreadPoolExecutor workers = (ThreadPoolExecutor) Executors.newFixedThreadPool(THREADS);
    	final long startTimeLog = System.currentTimeMillis();
        for (int i = 0; i < WORKERS; i++) {
            workers.execute(new Runnable() {
                @Override
                public void run() {
                    try {
                        securityEventsLogger.log(roleMgmgToken, EventTypes.AUTHENTICATION, EventStatus.SUCCESS, ModuleTypes.AUTHENTICATION, ServiceTypes.CORE);
                    } catch (Exception e) {
                    	fail("Logging should work");
                    }
                }
            });
        }
        while (workers.getCompletedTaskCount() < WORKERS && (System.currentTimeMillis()-startTimeLog)<TIMEOUT_MS) {
        	Thread.sleep(250);
        }
        final int completedTaskCount = Long.valueOf(workers.getCompletedTaskCount()).intValue();
    	log.info("securityEventsLogger.log: " + completedTaskCount + " completed in "+ (System.currentTimeMillis()-startTimeLog) + " ms using " + THREADS + " threads.");
        workers.shutdown();
    	for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
    		log.info("using device: " +logDeviceId);
        	// Validate
    		final QueryCriteria criteria = QueryCriteria.create().add(Criteria.orderDesc(AuditLogEntry.FIELD_TIMESTAMP));
    		final List<? extends AuditLogEntry> list = securityEventsAuditor.selectAuditLogs(roleMgmgToken, 1, completedTaskCount, criteria, logDeviceId);
            assertEquals(list.size(), completedTaskCount);
        	final long startTimeVerify = System.currentTimeMillis();
        	securityEventsAuditor.verifyLogsIntegrity(roleMgmgToken, new Date(), logDeviceId);
        	log.info("securityEventsLogger.verify:  " + (System.currentTimeMillis()-startTimeVerify));
        	// Export
        	final long startTimeExport = System.currentTimeMillis();
        	final String exportFilename = securityEventsAuditor.exportAuditLogs(roleMgmgToken, cryptoToken, new Date(), true, keyAlias, keyPairSignAlgorithm, logDeviceId).getExportedFile();
        	log.info("securityEventsLogger.export:  " + (System.currentTimeMillis()-startTimeExport));
        	assertExportAndSignatureExists(exportFilename);
    	}
    	log.trace("<testSecureLog");
    }
    
    private void assertExportAndSignatureExists(final String exportFilename) {
    	final File exportFile = new File(exportFilename);
        assertTrue("file does not exist, "+exportFile.getAbsolutePath(), exportFile.exists());
        assertTrue("file length is not > 0, "+exportFile.getAbsolutePath(), exportFile.length()>0);
        assertTrue("file can not be deleted, "+exportFile.getAbsolutePath(), exportFile.delete());
        final File signatureFile = new File(String.format("%s.sig", FilenameUtils.removeExtension(exportFile.getAbsolutePath())));
        assertTrue("signatureFile does not exist, "+signatureFile.getAbsolutePath(), signatureFile.exists());
        assertTrue("signatureFile length is not > 0, "+signatureFile.getAbsolutePath(), signatureFile.length()>0);
        assertTrue("signatureFile can not be deleted, "+signatureFile.getAbsolutePath(), signatureFile.delete());
    }

    private DigSignLogManagementData createDigSignLogManagementData() throws Exception {
    	final AuditLogCryptoTokenConfigData tokenConfig = new AuditLogCryptoTokenConfigData();
    	tokenConfig.setClassname(SoftCryptoToken.class.getName());
    	Properties props = new Properties();
    	props.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenPin);
    	final CryptoToken token = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), props, null, 1);
    	token.activate(tokenPin.toCharArray());
    	token.generateKeyPair("1024", keyAlias);
    	tokenConfig.setProperties(token.getProperties());
    	tokenConfig.setTokenData(token.getTokenData());
    	final DigSignLogManagementData digSign = new DigSignLogManagementData();
    	digSign.setAlgorithm("SHA512withRSA");
    	digSign.setKeyLabel(keyAlias);
    	digSign.setFrequency(0l);
    	digSign.setTokenConfig(tokenConfig);
    	token.deactivate();	// ??
    	return digSign;
    }
}
