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
package org.cesecore.keys.key.management;    

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertNull;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.Tuplet;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @Version $Id$
 */ 
public class CertificateKeyAssociationAndRetrievalSessionTest {
    
    private final static String keyAlias = "foobar"; 
    private final static String tokenPin = "userpin";
    private static X509Certificate certificate;
    private static CryptoToken cryptoToken;
    private static AuthenticationToken adminToken;

    private final CertificateKeyAssociationSession ka = JndiHelper.getRemoteSession(CertificateKeyAssociationSessionRemote.class);
    private final CertificateKeyRetrievalSession kr = JndiHelper.getRemoteSession(CertificateKeyRetrievalSessionRemote.class);


    @BeforeClass
    public static void setUp() throws Exception {
        CryptoProviderTools.installBCProvider();

        final Properties props = new Properties();
        props.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenPin);
        cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), props, null, 1);
        cryptoToken.activate(tokenPin.toCharArray());
        cryptoToken.generateKeyPair("512", keyAlias);
        final PrivateKey privateKey = cryptoToken.getPrivateKey(keyAlias);
        final PublicKey publicKey = cryptoToken.getPublicKey(keyAlias);
        certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, privateKey, publicKey,
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        
        final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        final Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        adminToken = new X509CertificateAuthenticationToken(principals, credentials);
    }

    @Test
    public void testNoBindings() throws CryptoTokenOfflineException {
        final Key key = kr.getKey(cryptoToken, certificate);
        assertNull(key);
        
        final List<Certificate> certificates = kr.getCertificates(keyAlias);
        assertTrue(certificates.size() == 0);

        final String[] tags = {"tag1"};
        final List<Tuplet<Certificate, String>> associations = kr.getAssociations(Arrays.asList(tags));
        assertTrue(associations.size() == 0);
    }
    
    @Test
    public void testBindAndUnbindCertificate() throws CertificateKeyAssociationException, CryptoTokenOfflineException {
        final String[] tags = {"tag1", "tag2"};
        try {
            ka.bindCertificateToKey(adminToken, cryptoToken, certificate, Arrays.asList(tags), keyAlias);
            List<Certificate> certs = kr.getCertificates(keyAlias);
            assertTrue(certs.size() == 1);
            assertEquals(CertTools.getFingerprintAsString(certificate), CertTools.getFingerprintAsString(certs.iterator().next()));
            Key key = kr.getKey(cryptoToken, certificate);
            assertNotNull(key);
            assertEquals(cryptoToken.getKey(keyAlias), key);
        } finally {
        	ka.unBindCertificateFromKey(adminToken, certificate);
        	assertTrue(kr.getCertificates(keyAlias).size() == 0);
        	assertNull(kr.getKey(cryptoToken, certificate));
        }
        // Unbind a non existing binding will throw Exception
        try {
        	ka.unBindCertificateFromKey(adminToken, certificate);
        	assertTrue("Should throw", false);
        } catch (CertificateKeyAssociationException e) {
        	// NOPMD
        }
    }

    @AfterClass
    public static void rmCryptoProvider() {
        CryptoProviderTools.removeBCProvider();
    }
}
