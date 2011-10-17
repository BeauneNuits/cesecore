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
package org.cesecore.time;

import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.SecurityEventsBase;
import org.cesecore.audit.audit.SecurityEventsAuditorSession;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.time.providers.NtpClientParser;
import org.cesecore.time.providers.SimpleProvider;
import org.cesecore.time.providers.TrustedTimeProvider;
import org.cesecore.time.providers.TrustedTimeProviderException;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * TrustedTime functional Test
 * 
 * @version $Id$
 */
public class TrustedTimeSessionBeanTest extends SecurityEventsBase {
    private static final Logger log = Logger
            .getLogger(TrustedTimeSessionBeanTest.class);

    private CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = JndiHelper
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class);
    private TrustedTimeWatcherProxySessionRemote trustedTimeWatcherProxySession = JndiHelper
            .getRemoteSession(TrustedTimeWatcherProxySessionRemote.class);
    private SecurityEventsAuditorSession securityEventsAuditor = JndiHelper
            .getRemoteSession(SecurityEventsAuditorSessionRemote.class);
    private TrustedTimeSession trustedTime = JndiHelper
            .getRemoteSession(TrustedTimeSessionRemote.class);

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @AfterClass
    public static void rmCryptoProvider() {
        CryptoProviderTools.removeBCProvider();
    }

    @Test
    public void testGetTrustedTime() throws Exception {

        TrustedTimeProvider provider = cesecoreConfigurationProxySession
                .getTrustedTimeProvider();

        if (provider instanceof SimpleProvider) {
            testSimpleProvider();
        } else if (provider instanceof NtpClientParser) {
            testNtpProvider();
        } else {
            assertFalse("no TrustedTimeProvider was defined", false);
        }

    }

    private void testSimpleProvider() throws TrustedTimeProviderException {
        TrustedTime tt = trustedTime.getTrustedTime();
        assertNotNull("TrustedTime should not be null", tt);
        assertNull("NextUpdate should be null", tt.getNextUpdate());
        assertNull("Accuracy should be null", tt.getAccuracy());
        assertNull("Stratum should be null", tt.getStratum());
        log.info("Time: " + tt.getTime());
    }

    private void testNtpProvider() throws TrustedTimeProviderException {
        TrustedTime tt = trustedTime.getTrustedTime();
        assertNotNull("TrustedTime should not be null", tt);
        assertNotNull("NextUpdate should not be null", tt.getNextUpdate());
        assertNotNull("Accuracy should not be null", tt.getAccuracy());
        assertNotNull("Stratum should not be null", tt.getStratum());
        assertTrue("time.getAccuracy is " + tt.getAccuracy(),
                tt.getAccuracy() <= 2000);
        log.info("Accuracy: " + tt.getAccuracy());
        log.info("Stratum: " + tt.getStratum());
        log.info("Time: " + tt.getTime());
    }

    @Test
    public void testTrustedTimeLog() throws Exception {
        trustedTimeWatcherProxySession.getTrustedTimeForcedUpdate();
        for (final String logDeviceId : securityEventsAuditor
                .getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditor
                    .selectAuditLogs(roleMgmgToken, 1, 10,
                            QueryCriteria.create().add(Criteria.like("module", "TRUSTED_TIME")), logDeviceId);
            assertTrue("should return 1, returned " + list.size(),
                    list.size() == 1);
        }
        final CryptoToken cryptoToken = createTokenWithKeyPair();
        // for (final String logDeviceId :
        // securityEventsAuditor.getQuerySupportingLogDevices()) {
        // AuditLogExportReport report =
        // securityEventsAuditor.exportAuditLogs(roleMgmgToken, cryptoToken, new
        // Date(), true, keyAlias, keyPairSignAlgorithm, logDeviceId);
        // new File(report.getExportedFile()).delete();
        // String sig = report.getSignatureFile();
        // if(sig!=null) {
        // new File(sig).delete();
        // }
        // }
    }

    @Test
    public void testTrustedTimeScheduling() throws Exception {
        trustedTimeWatcherProxySession.setDummyProvider();
        trustedTimeWatcherProxySession.getTrustedTimeForcedUpdate();
        Thread.sleep(1100); // for the schedule to trigger ... dummy provider
                            // will set nextUpdate to 1000 ms
        for (final String logDeviceId : securityEventsAuditor
                .getQuerySupportingLogDevices()) {
            final List<? extends AuditLogEntry> list = securityEventsAuditor
                    .selectAuditLogs(roleMgmgToken, 1, 10,
                            QueryCriteria.create().add(Criteria.like("module", "TRUSTED_TIME")), logDeviceId);
            assertTrue("should return 1, returned " + list.size(),
                    list.size() > 0);
        }
        trustedTimeWatcherProxySession.unsetDummyProvider();
        trustedTimeWatcherProxySession.getTrustedTimeForcedUpdate();
        final CryptoToken cryptoToken = createTokenWithKeyPair();
        // for (final String logDeviceId :
        // securityEventsAuditor.getQuerySupportingLogDevices()) {
        // AuditLogExportReport report =
        // securityEventsAuditor.exportAuditLogs(roleMgmgToken, cryptoToken, new
        // Date(), true, keyAlias, keyPairSignAlgorithm, logDeviceId);
        // new File(report.getExportedFile()).delete();
        // String sig = report.getSignatureFile();
        // if(sig!=null) {
        // new File(sig).delete();
        // }
        // }
    }
}
