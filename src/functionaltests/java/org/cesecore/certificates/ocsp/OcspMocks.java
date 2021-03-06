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

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * Class contains some mocks for use with OCSP functional tests.
 * 
 * @version $Id$
 * 
 */
public class OcspMocks {
    static class MockPublicKey implements PublicKey {
        private static final long serialVersionUID = -1984184005394205813L;

        public String getAlgorithm() {
            return null;
        }

        public byte[] getEncoded() {
            return null;
        }

        public String getFormat() {
            return null;
        }
    }

    static class MockRSAPublicKey extends MockPublicKey implements RSAPublicKey {

        private static final long serialVersionUID = -941094519775910654L;

        public BigInteger getPublicExponent() {
            return null;
        }

        public BigInteger getModulus() {
            return null;
        }
    }

    static class MockDSAPublicKey extends MockPublicKey implements DSAPublicKey {

        private static final long serialVersionUID = 7512987375200510856L;

        public BigInteger getY() {
            return null;
        }

        public DSAParams getParams() {
            return null;
        }
    }

    static class MockECDSAPublicKey extends MockPublicKey implements ECPublicKey {

        private static final long serialVersionUID = 335803923973058991L;

        public ECPoint getW() {
            return null;
        }

        public ECParameterSpec getParams() {
            return null;
        }
    }
}
