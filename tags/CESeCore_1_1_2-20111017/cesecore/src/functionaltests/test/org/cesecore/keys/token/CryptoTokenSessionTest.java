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
package org.cesecore.keys.token;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the certificate profile entity bean.
 * 
 * @version $Id$
 */
public class CryptoTokenSessionTest extends RoleUsingTestCase {

    public static final String tokenpin = "userpin1";

    private CryptoTokenSessionRemote tokenSession = JndiHelper.getRemoteSession(CryptoTokenSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("CryptoTokenSessionTest");

    	// Now we have a role that can edit roles, we can edit this role to include more privileges
    	RoleData role = roleAccessSession.findRole("CryptoTokenSessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);
    }

    @After
    public void tearDown() throws Exception {
    	tearDownRemoveRole();
    }

    @Test
    public void test01CryptoTokenSession() throws Exception {
        CryptoToken token = createSoftToken(true, false);
    	// token should be not active
	    assertEquals(CryptoToken.STATUS_OFFLINE, token.getTokenStatus());
	    token.activate(tokenpin.toCharArray());
    	// token should be active
	    assertEquals(CryptoToken.STATUS_ACTIVE, token.getTokenStatus());
	    // Generate a key pair
	    token = tokenSession.generateKeyPair(roleMgmgToken, token, tokenpin.toCharArray(), "512", "rsatest00001");
	    // We must activate token again after passing through serialization for remote ejb
	    token.activate(tokenpin.toCharArray());
	    PrivateKey priv = token.getPrivateKey("rsatest00001");
	    PublicKey pub = token.getPublicKey("rsatest00001");
	    KeyTools.testKey(priv, pub, token.getSignProviderName());
	    assertEquals(512, KeyTools.getKeyLength(pub));
	    String keyhash = CertTools.getFingerprintAsString(pub.getEncoded());

	    token = tokenSession.generateKeyPair(roleMgmgToken, token, tokenpin.toCharArray(), "512", "rsatest00002");
	    // We must activate token again after passing through serialization for remote ejb
	    token.activate(tokenpin.toCharArray());
	    priv = token.getPrivateKey("rsatest00002");
	    pub = token.getPublicKey("rsatest00002");
	    KeyTools.testKey(priv, pub, token.getSignProviderName());
	    assertEquals(512, KeyTools.getKeyLength(pub));
	    String keyhash2 = CertTools.getFingerprintAsString(pub.getEncoded());
	    assertFalse(keyhash.equals(keyhash2));

	    token = tokenSession.deleteEntry(roleMgmgToken, token, tokenpin.toCharArray(), "rsatest00002");
	    // We must activate token again after passing through serialization for remote ejb
	    token.activate(tokenpin.toCharArray());
	    try {
		    priv = token.getPrivateKey("rsatest00002");
		    assertTrue("Should throw", false);
	    } catch (CryptoTokenOfflineException e) {
	    	// NOPMD
	    }
	    // This should still work though
	    priv = token.getPrivateKey("rsatest00001");

	    // generate key pair using Public key template, i.e. keyspec
	    token = tokenSession.generateKeyPair(roleMgmgToken, token, tokenpin.toCharArray(), pub, "rsatest00003");
	    token.activate(tokenpin.toCharArray());
	    priv = token.getPrivateKey("rsatest00003");
	    pub = token.getPublicKey("rsatest00003");
	    KeyTools.testKey(priv, pub, token.getSignProviderName());
	    assertEquals(512, KeyTools.getKeyLength(pub));
	    String keyhash3 = CertTools.getFingerprintAsString(pub.getEncoded());
	    assertFalse(keyhash2.equals(keyhash3));

	    // generate symm key
	    token = tokenSession.generateKey(roleMgmgToken, token, tokenpin.toCharArray(), "AES", 256, "symmkeytest001");
	    token.activate(tokenpin.toCharArray());
	    Key symkey = token.getKey("symmkeytest001");
	    // Encrypt something with the key, must be multiple of 16 bytes for AES (need to do padding on your own)
	    String input = "1234567812345678";
	    Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", token.getEncProviderName());
	    IvParameterSpec ivSpec = new IvParameterSpec("1234567812345678".getBytes());
	    cipher.init(Cipher.ENCRYPT_MODE, symkey, ivSpec);
	    byte[] cipherText = cipher.doFinal(input.getBytes());
	    // Decrypt
	    cipher.init(Cipher.DECRYPT_MODE, symkey, ivSpec);
	    byte[] plainText = cipher.doFinal(cipherText);
	    assertEquals(input, new String(plainText));
	}

    @Test
    public void test02KeyExtraction() throws Exception {
        // Create token allowing key extraction
        CryptoToken token = createSoftToken(true, true);
        token.activate(tokenpin.toCharArray());
        // Generate an extractable key pair
        token = tokenSession.generateKeyPair(roleMgmgToken, token, tokenpin.toCharArray(), "512", "extractkptest01");
        // We must activate token again after passing through serialization for remote ejb
        token.activate(tokenpin.toCharArray());
        PrivateKey priv = token.getPrivateKey("extractkptest01");
        PublicKey pub = token.getPublicKey("extractkptest01");
        KeyTools.testKey(priv, pub, token.getSignProviderName());
        assertEquals(512, KeyTools.getKeyLength(pub));
        // generate symm key
        token = tokenSession.generateKey(roleMgmgToken, token, tokenpin.toCharArray(), "DESede", 192, "symkeyextracttest01");
        token.activate(tokenpin.toCharArray());
        Key symkey = token.getKey("symkeyextracttest01");
        // extract private key
        byte[] extKey = token.extractKey( "DESede/ECB/PKCS5Padding", "symkeyextracttest01", "extractkptest01" );
        assertTrue( "Extracted key is null", extKey != null && extKey.length > 0 );


        // Create token not allowing key extraction
        token = createSoftToken(true, false);
        token.activate(tokenpin.toCharArray());
        // Generate an extractable key pair
        token = tokenSession.generateKeyPair(roleMgmgToken, token, tokenpin.toCharArray(), "512", "extractkptest02");
        // We must activate token again after passing through serialization for remote ejb
        token.activate(tokenpin.toCharArray());
        PrivateKey priv2 = token.getPrivateKey("extractkptest02");
        PublicKey pub2 = token.getPublicKey("extractkptest02");
        KeyTools.testKey(priv2, pub2, token.getSignProviderName());
        assertEquals(512, KeyTools.getKeyLength(pub));
        // generate symm key
        token = tokenSession.generateKey(roleMgmgToken, token, tokenpin.toCharArray(), "DESede", 192, "symkeyextracttest02");
        token.activate(tokenpin.toCharArray());
        Key symkey2 = token.getKey("symkeyextracttest02");

        byte[] extKey2 = null;
        try {
            extKey2 = token.extractKey("DESede/ECB/PKCS5Padding", "symkeyextracttest02", "extractkptest02");
            assertTrue("Should have thrown PrivateKeyNotExtractableException", false);
        }
        catch (PrivateKeyNotExtractableException e) {
            // NOPMD
        }
        assertTrue("Extracted key is not null", extKey2 == null || extKey2.length == 0);
    }


    public CryptoToken createSoftToken(boolean nodefaultpwd, boolean allowExtraction) {
        Properties prop = new Properties();
        if (nodefaultpwd) {
            prop.setProperty(SoftCryptoToken.NODEFAULTPWD, Boolean.toString(nodefaultpwd));
        }
        prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, Boolean.toString(allowExtraction));
        CryptoToken catoken = tokenSession.createCryptoToken(roleMgmgToken, SoftCryptoToken.class.getName(), prop, null, 111);
        return catoken;
    }

}
