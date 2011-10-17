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
package org.cesecore.audit.impl.queued.entity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.audit.impl.queued.AuditLogSigningException;
import org.cesecore.audit.impl.queued.entity.AuditLogCryptoTokenConfigData;
import org.cesecore.audit.impl.queued.entity.DigSignLogManagementData;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Digital signature secure audit log configuration entity unit test.
 * 
 * @version $Id$
 * 
 */
public class DigSignLogManagementDataTest {

    private static final Logger log = Logger.getLogger(DigSignLogManagementDataTest.class);

    private static final String keyAlias = "secretkey";
    private static final String tokenPin = "userpin";
    private static final String keyAlgorithm = "1024";
    private static final String signAlgorithm = "SHA512withRSA";

    private DigSignLogManagementData digSign;
    private AuditLogCryptoTokenConfigData tokenConfigData;

    @BeforeClass
    public static void setUpCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void createDigSignConfig() throws Exception {
        log.trace(">setUp()");

        tokenConfigData = new AuditLogCryptoTokenConfigData();
        tokenConfigData.setClassname(SoftCryptoToken.class.getName());
        Properties props = new Properties();
        props.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenPin);

        CryptoToken token = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), props, null, 1);
        token.activate(tokenPin.toCharArray());
        token.generateKeyPair(keyAlgorithm, keyAlias);

        tokenConfigData.setProperties(props);

        byte[] tokenData = token.getTokenData();
        tokenConfigData.setTokenData(tokenData);

        token.deactivate();

        digSign = new DigSignLogManagementData();
        digSign.setAlgorithm(signAlgorithm);
        digSign.setKeyLabel(keyAlias);
        digSign.setFrequency(0l);
        digSign.setTokenConfig(tokenConfigData);

        log.trace("<setUp()");
    }

    @Test
    public void test01LoadTokenConfigProps() throws CryptoTokenOfflineException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, AuditLogSigningException {

        String dataToBeSigned = "foobar";

        AuditLogCryptoTokenConfigData tokenConfig = digSign.getTokenConfig();
        CryptoToken token = CryptoTokenFactory.createCryptoToken(
                tokenConfig.getClassname(), tokenConfig.getProperties(), tokenConfig.getTokenData(), 1);

        Signature signature = Signature.getInstance(signAlgorithm, token.getEncProviderName());
        Signature validate = Signature.getInstance(signAlgorithm, token.getEncProviderName());

        PrivateKey pk = token.getPrivateKey(keyAlias);
        PublicKey pubk = token.getPublicKey(keyAlias);
        signature.initSign(pk);
        validate.initVerify(pubk);

        signature.update(dataToBeSigned.getBytes());
        validate.update(dataToBeSigned.getBytes());
        byte[] signedData = signature.sign(); 
        assertTrue(validate.verify(signedData));
    }

    @Test
    public void test02FrequencyEq0() {
        assertEquals(0l, digSign.getFrequency());
    }

    @Test
    public void test03Algorithm() {
        assertEquals(signAlgorithm, digSign.getAlgorithm());
    }

    @Test
    public void test04KeyLabel() {
        assertEquals(keyAlias, digSign.getKeyLabel());
    }

    @Test
    public void test05Clone() {
        DigSignLogManagementData digSign_new = (DigSignLogManagementData) digSign.metaClone();
        assertEquals(digSign.getFrequency(), digSign_new.getFrequency());
        assertEquals(digSign.getKeyLabel(), digSign_new.getKeyLabel());
        assertEquals(digSign.getAlgorithm(), digSign_new.getAlgorithm());
    }

}
