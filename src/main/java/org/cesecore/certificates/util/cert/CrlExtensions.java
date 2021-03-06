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
package org.cesecore.certificates.util.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509CRL;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.X509Extensions;

/**
 * A class for reading values from CRL extensions.
 *
 * Based on EJBCA version: CrlExtensions.java 8373 2009-11-30 14:07:00Z jeklund
 * 
 * @version $Id$
 */
public class CrlExtensions {
    private static Logger log = Logger.getLogger(CrlExtensions.class);

    /** Returns the CRL number if it exists as a CRL extension
     * 
     * @return the CRLnumber, or 0 if no CRL number extension was found or an error reading it occurred. Never return null.
     */
    public static BigInteger getCrlNumber(X509CRL crl) {
    	BigInteger ret = BigInteger.valueOf(0);
        try {
			DERObject obj = CrlExtensions.getExtensionValue(crl, X509Extensions.CRLNumber.getId());
			if (obj != null) {
				DERInteger crlnum = CRLNumber.getInstance(obj);
				if (crlnum != null) {
					ret = crlnum.getPositiveValue();
				}
			}
		} catch (IOException e) {
			log.error("Error reading CRL number extension: ", e);
		}
		return ret;
    }

    /** Returns the delta crl indicator number if it exists as a CRL extension
     * 
     * @return the BaseCRLNumber, or -1 if no delta crl indicator extension was found or an error reading it occurred. Never return null.
     */
    public static BigInteger getDeltaCRLIndicator(X509CRL crl) {
    	BigInteger ret = BigInteger.valueOf(-1);
        try {
			DERObject obj = CrlExtensions.getExtensionValue(crl, X509Extensions.DeltaCRLIndicator.getId());
			if (obj != null) {
	            DERInteger crlnum = CRLNumber.getInstance(obj);
	            if (crlnum != null) {
	                ret = crlnum.getPositiveValue();            	
	            }				
			}
		} catch (IOException e) {
			log.error("Error reading CRL number extension: ", e);
		}
		return ret;
    }

    /**
     * Return an Extension DERObject from a CRL
     */
    protected static DERObject getExtensionValue(X509CRL crl, String oid)
      throws IOException {
    	if (crl == null) {
    		return null;
    	}
        byte[] bytes = crl.getExtensionValue(oid);
        if (bytes == null) {
            return null;
        }
        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        return aIn.readObject();
    } //getExtensionValue


}
