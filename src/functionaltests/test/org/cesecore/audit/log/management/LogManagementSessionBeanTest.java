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
package org.cesecore.audit.log.management;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.audit.SecurityEventsBase;
import org.cesecore.audit.audit.SecurityEventsAuditorSession;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionRemote;
import org.cesecore.audit.impl.queued.AuditLogSigningException;
import org.cesecore.audit.impl.queued.entity.AuditLogCryptoTokenConfigData;
import org.cesecore.audit.impl.queued.entity.DigSignLogManagementData;
import org.cesecore.audit.impl.queued.entity.HmacLogManagementData;
import org.cesecore.audit.impl.queued.entity.LogManagementData;
import org.cesecore.audit.impl.queued.management.LogManagementException;
import org.cesecore.audit.impl.queued.management.LogManagementSession;
import org.cesecore.audit.impl.queued.management.LogManagementSessionRemote;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests Audit Log configuration management.
 * 
 * @version $Id$
 */
public class LogManagementSessionBeanTest extends SecurityEventsBase {

    private static final Logger log = Logger.getLogger(LogManagementSessionBeanTest.class);
    private LogManagementSession logManagement = JndiHelper.getRemoteSession(LogManagementSessionRemote.class);
    private SecurityEventsAuditorSession securityEventsAuditor = JndiHelper.getRemoteSession(SecurityEventsAuditorSessionRemote.class);
    private static final String algorithm = "HmacSHA1";

    private static KeyPair keys;

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();

        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    public static HmacLogManagementData createHmacLogManagementData() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, InvalidAlgorithmParameterException,
            SignatureException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException, IOException {

        AuditLogCryptoTokenConfigData tokenConfig = new AuditLogCryptoTokenConfigData();
        tokenConfig.setClassname(SoftCryptoToken.class.getName());
        Properties props = new Properties();
        props.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenPin);

        CryptoToken token = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), props, null, 1);
        token.generateKey(algorithm, 256, keyAlias);

        tokenConfig.setProperties(props);

        byte[] tokenData = token.getTokenData();
        tokenConfig.setTokenData(tokenData);

        HmacLogManagementData hmac = new HmacLogManagementData();
        hmac.setAlgorithm(algorithm);
        hmac.setKeyLabel(keyAlias);
        hmac.setFrequency(0l);
        hmac.setTokenConfig(tokenConfig);

        token.deactivate();
        return hmac;
    }

    public static DigSignLogManagementData createDigSignLogManagementData() throws CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException,
            InvalidAlgorithmParameterException, SignatureException, CertificateException, NoSuchPaddingException, IllegalBlockSizeException,
            IOException {

        AuditLogCryptoTokenConfigData tokenConfig = new AuditLogCryptoTokenConfigData();
        tokenConfig.setClassname(SoftCryptoToken.class.getName());
        Properties props = new Properties();
        props.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenPin);

        CryptoToken token = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), props, null, 1);
        token.activate(tokenPin.toCharArray());
        token.generateKeyPair("1024", keyAlias);

        tokenConfig.setProperties(token.getProperties());

        byte[] tokenData = token.getTokenData();
        tokenConfig.setTokenData(tokenData);

        DigSignLogManagementData digSign = new DigSignLogManagementData();
        digSign.setAlgorithm("SHA512withRSA");
        digSign.setKeyLabel(keyAlias);
        digSign.setFrequency(0l);
        digSign.setTokenConfig(tokenConfig);

        token.deactivate();
        return digSign;
    }

    @Test
    public void test01SetSigninModeHMAC() throws Exception {
        HmacLogManagementData hmac = createHmacLogManagementData();
        logManagement.changeLogManagement(roleMgmgToken, hmac);
        LogManagementData current = logManagement.getCurrentConfiguration(roleMgmgToken);
        assertTrue(current.getAlgorithm().equals(hmac.getAlgorithm()));
        assertTrue(current.getFrequency() == hmac.getFrequency());
        assertTrue(current.getKeyLabel().equals(hmac.getKeyLabel()));
        assertNotNull(current.getRowProtection());
        assertNotNull(current.getTokenConfig());
        assertNotNull(current.getTokenConfig().getRowProtection());
    }

    @Test
    public void test02GetCurrentConfiguration() throws Exception {
        LogManagementData current = logManagement.getCurrentConfiguration(roleMgmgToken);
        assertTrue(current.getAlgorithm().equals(algorithm));
        assertTrue(current.getFrequency() == 0l);
        assertTrue(current.getKeyLabel().equals(keyAlias));
        assertNotNull(current.getRowProtection());
        assertNotNull(current.getTokenConfig());
        assertNotNull(current.getTokenConfig().getRowProtection());
        AuditLogCryptoTokenConfigData data = current.getTokenConfig();
        assertNotNull(data);
    }

    @Test
    public void test03ChangeFrequency() throws Exception {
        LogManagementData hmac = logManagement.getCurrentConfiguration(roleMgmgToken);
        hmac.setFrequency(50000l);
        logManagement.changeLogManagement(roleMgmgToken, hmac);
        LogManagementData current = logManagement.getCurrentConfiguration(roleMgmgToken);
        assertTrue(current.getAlgorithm().equals(hmac.getAlgorithm()));
        assertTrue(current.getFrequency() == hmac.getFrequency());
        assertTrue(current.getKeyLabel().equals(hmac.getKeyLabel()));
        assertNotNull(current.getRowProtection());
        assertNotNull(current.getTokenConfig());
        assertNotNull(current.getTokenConfig().getRowProtection());
        Thread.sleep(100);
    }

    @Test
    public void test04SetSigninModeDigSign() throws Exception {
        LogManagementData digSign = createDigSignLogManagementData();
        logManagement.changeLogManagement(roleMgmgToken, digSign);
        LogManagementData current = logManagement.getCurrentConfiguration(roleMgmgToken);
        assertTrue(current.getAlgorithm().equals(digSign.getAlgorithm()));
        assertTrue(current.getFrequency() == digSign.getFrequency());
        assertTrue(current.getKeyLabel().equals(digSign.getKeyLabel()));
        assertNotNull(current.getRowProtection());
        assertNotNull(current.getTokenConfig());
        assertNotNull(current.getTokenConfig().getRowProtection());
    }

    @Test
    public void test05Authorization() throws Exception {

        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test LogMgmtSessionNoAuth", 365, null, keys.getPrivate(),
                keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);

        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(principals, credentials);

        try {
            DigSignLogManagementData digSign = createDigSignLogManagementData();
            logManagement.changeLogManagement(adminTokenNoAuth, digSign);
            assertTrue("should throw", false);
        } catch (AuthorizationDeniedException e) {
            // NOPMD
        }

    }

    @Test
    public void testFaultyConfiguration() throws Exception {
        HmacLogManagementData hmac = null;
        try {
            logManagement.changeLogManagement(roleMgmgToken, hmac);
            fail("This should have failed: Trying to set a null mode");
        } catch (LogManagementException e1) {}
        hmac = createHmacLogManagementData();
        // test required fields
        try {
            hmac.setDetails(null);
            logManagement.changeLogManagement(roleMgmgToken, hmac);
            fail("This should have failed: Details can't be null");
        } catch (LogManagementException e1) {}
        try {
            hmac.setTokenConfig(null);
            logManagement.changeLogManagement(roleMgmgToken, hmac);
            fail("This should have failed: Configuration mode must have a token");
        } catch (LogManagementException e1) {}
        // test frequency
        try {
            hmac.setFrequency(-1l);
            logManagement.changeLogManagement(roleMgmgToken, hmac);
            fail("This should have failed: Frequency must be == 0 || > 100 ms");
        } catch (LogManagementException e1) {}
        try {
            hmac.setFrequency(50l);
            logManagement.changeLogManagement(roleMgmgToken, hmac);
            fail("This should have failed: Frequency must be == 0 || > 100 ms");
        } catch (LogManagementException e1) {}
    }

    //@After
    public void exportLogsAndDelete() throws Exception {
        try {
            CryptoToken cryptoToken = createTokenWithKeyPair();
            for (final String logDeviceId : securityEventsAuditor.getQuerySupportingLogDevices()) {
                String file = securityEventsAuditor.exportAuditLogs(roleMgmgToken, cryptoToken, new Date(), true, keyAlias, keyPairSignAlgorithm,
                        logDeviceId).getExportedFile();
                File f = new File(file);
                assertTrue("file does not exist, " + f.getAbsolutePath(), f.exists());
                f.deleteOnExit();
                // assertTrue("file exists, "+f.getAbsolutePath(), !f.exists());
            }
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        } catch (SQLException e) {
            log.error(e.getMessage(), e);
        } catch (AuditLogSigningException e) {
            log.error(e.getMessage(), e);
        }

    }

    @AfterClass
    public static void rmCryptoProvider() {
        CryptoProviderTools.removeBCProvider();
    }
}
