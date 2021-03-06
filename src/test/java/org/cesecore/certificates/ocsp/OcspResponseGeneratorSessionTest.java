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
package org.cesecore.certificates.ocsp;

import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;

import org.bouncycastle.ocsp.OCSPException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ocsp.cache.TokenAndChainCache;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests for the OcspResponseGenerator that don't involve creating a CA.
 * 
 * @version $Id$
 * 
 */
public class OcspResponseGeneratorSessionTest {

    @Before
    public void setUp() throws Exception {

    }

    @Test
    public void testWithRandomBytes() throws AuthorizationDeniedException, OCSPException {
        final int MAX_REQUEST_SIZE = 100000;
        TestOcspResponseGeneratorSessionBean ocspResponseGeneratorSession = new TestOcspResponseGeneratorSessionBean();
        SecureRandom random = new SecureRandom();
        byte[] fakeRequest = new byte[MAX_REQUEST_SIZE + 1];
        random.nextBytes(fakeRequest);
        boolean caught = false;
        try {
            ocspResponseGeneratorSession.getOcspResponse(null, fakeRequest, null, null, null);
        } catch (MalformedRequestException e) {
            caught = true;
        }
        assertTrue("MalformedRequestException was not thrown for a request > 100000 bytes.", caught);
    }
 
    private class TestOcspResponseGeneratorSessionBean extends OcspResponseSessionBean {

        @Override
        protected void initiateIfNecessary() {
            // Do nothing.           
        }

        @Override
        protected TokenAndChainCache getTokenAndChainCache() {
            return null;
        }
        
    }

}
