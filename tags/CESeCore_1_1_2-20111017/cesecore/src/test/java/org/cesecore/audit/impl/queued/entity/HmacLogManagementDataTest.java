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

import java.security.Key;
import java.util.Properties;

import javax.crypto.Mac;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.impl.queued.entity.AuditLogCryptoTokenConfigData;
import org.cesecore.audit.impl.queued.entity.HmacLogManagementData;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * HMAC secure audit log configuration entity unit test.
 * 
 * @version $Id$
 * 
 */
public class HmacLogManagementDataTest {

    private static final Logger log = Logger
            .getLogger(HmacLogManagementDataTest.class);

    private static final String keyAlias = "secretkey00001";
    private static final String tokenPin = "userpin";
    private static final String algorithm = "HmacSHA1";
    private static final String dataToBeSigned = "foobar";

    private HmacLogManagementData hmac;
    private AuditLogCryptoTokenConfigData tokenConfigData;
    private byte[] signed;

    @BeforeClass
    public static void setUpCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void createHmacConfig() throws Exception {
        log.trace(">setUp()");

        tokenConfigData = new AuditLogCryptoTokenConfigData();
        tokenConfigData.setClassname(SoftCryptoToken.class.getName());
        Properties props = new Properties();
        props.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, tokenPin);

        CryptoToken token = CryptoTokenFactory.createCryptoToken(
                SoftCryptoToken.class.getName(), props, null, 1);
        token.activate(tokenPin.toCharArray());
        token.generateKey("HmacSHA1", 256, keyAlias);

        tokenConfigData.setProperties(props);


        hmac = new HmacLogManagementData();
        hmac.setAlgorithm(algorithm);
        hmac.setKeyLabel(keyAlias);
        hmac.setFrequency(0l);
        hmac.setTokenConfig(tokenConfigData);

        byte[] tokenData = token.getTokenData();
        tokenConfigData.setTokenData(tokenData);

        Key hMacKey = token.getKey(keyAlias);

        Mac hMac = Mac.getInstance(hmac.getAlgorithm(),
                token.getEncProviderName());
        hMac.init(hMacKey);
        hMac.update(dataToBeSigned.getBytes());
        signed = hMac.doFinal();

        log.trace("<setUp()");
    }

    @Test
    public void test01LoadTokenConfigProps() throws Exception {

        AuditLogCryptoTokenConfigData tokenConfig = hmac.getTokenConfig();
        CryptoToken token = CryptoTokenFactory.createCryptoToken(
                tokenConfig.getClassname(), tokenConfig.getProperties(), tokenConfig.getTokenData(), 1);

        token.activate(((String) tokenConfig.getProperties().get(
                CryptoToken.AUTOACTIVATE_PIN_PROPERTY)).toCharArray());
        Key hMacKey = token.getKey(keyAlias);

        Mac hMac = Mac.getInstance(hmac.getAlgorithm(),
                token.getEncProviderName());
        hMac.init(hMacKey);
        hMac.update(dataToBeSigned.getBytes());
        byte[] signedData = hMac.doFinal();

        assertTrue(ArrayUtils.isEquals(signedData, signed));

    }

    @Test
    public void test02FrequencyEq0() {
        assertEquals(0l, hmac.getFrequency());
    }

    @Test
    public void test03Algorithm() {
        assertEquals(algorithm, hmac.getAlgorithm());
    }

    @Test
    public void test04KeyLabel() {
        assertEquals(keyAlias, hmac.getKeyLabel());
    }

    @Test
    public void test05Clone() {
        HmacLogManagementData hmac_new = (HmacLogManagementData) hmac.metaClone();
        assertEquals(hmac.getFrequency(), hmac_new.getFrequency());
        assertEquals(hmac.getKeyLabel(), hmac_new.getKeyLabel());
        assertEquals(hmac.getAlgorithm(), hmac_new.getAlgorithm());
    }

}
