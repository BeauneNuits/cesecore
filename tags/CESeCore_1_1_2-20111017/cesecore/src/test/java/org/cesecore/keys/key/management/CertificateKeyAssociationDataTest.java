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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * @version $Id$
 *
 */
public class CertificateKeyAssociationDataTest {

    private static final String keyAlias = "foobar";
    private static final String[] tag_array = {"tag1", "tag2"};
    private CertificateKeyAssociationData ckad;

    @BeforeClass
    public static void setUpCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void generateCertificate() throws Exception{
        final KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA); 
        final Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true); 

        final List<String> tags = Arrays.asList(tag_array);
        ckad = new CertificateKeyAssociationData(certificate, tags, keyAlias);
    }

    @Test
    public void testCertificateKeyAssociationFields(){
        assertNotNull(ckad.getFingerPrint());
        assertNotNull(ckad.getBase64Cert());
        assertNotNull(ckad.getKeyAlias());
        assertTrue(ArrayUtils.isEquals(((String[])ckad.getTagsList().toArray()), tag_array));
    }

    @AfterClass
    public static void removeCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

}
