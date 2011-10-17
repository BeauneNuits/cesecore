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

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Transient;

import org.cesecore.audit.impl.queued.AuditLogSigningException;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

/**
 * Digital Signature audit log configuration.
 *
 * @version $Id$
 */
@DiscriminatorValue("DIGSIGN")
public class DigSignLogManagementData extends LogManagementData {

    private static final long serialVersionUID = 4318188860513788785L;
    private static final String PUBLIC_KEY = "pubKey";
    private static final String PUBLIC_KEY_ALG = "pubKeyAlg";
    
    private PublicKey publicKey;

    @Transient
    public Certificate getCertificate() throws CertificateException{
        final Map<String, Object> details = getMapDetails();
        final String certificate64 = (String) details.get("certificate");
        if(certificate64!=null)
            return CertTools.getCertfromByteArray(Base64.decode(certificate64.getBytes()));
        return null;
    }

    @Transient
    public void setCertificate(final Certificate certificate) throws CertificateEncodingException{
        final Map<String, Object> details = getMapDetails();
        details.put("certificate", new String(Base64.encode(certificate.getEncoded())));
        setMapDetails(details);
    }

    @Transient
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
	@Override
	public byte[] sign(final CryptoToken token, final byte[] data) throws AuditLogSigningException {
		try {
		    
			final Signature signature = Signature.getInstance(this.getAlgorithm(), token.getEncProviderName());
            signature.initSign(token.getPrivateKey(this.getKeyLabel()));
            signature.update(data);
            final byte[] signedData = signature.sign();
			final Signature signValidate = Signature.getInstance(this.getAlgorithm(), token.getSignProviderName());
            final Certificate cert = getCertificate();
            if(cert!=null) {
                signValidate.initVerify(cert);
            }
            else {
                signValidate.initVerify(getPublicKey());
            }
            signValidate.update(data);
            final boolean verifies = signValidate.verify(signedData);
            if(!verifies) {
                throw new AuditLogSigningException("signature is not valid");
            }
            return signedData;
		} catch (final Exception e) {
		    throw new AuditLogSigningException(e.getMessage(), e);
		}
	}
	
	@Override
	protected void prePersistWork() throws Exception {
	    //instantiate public key
	    publicKey = getCryptoToken().getPublicKey(getKeyLabel());
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey.getEncoded());
	    final Map<String, Object> details = getMapDetails();
        details.put(PUBLIC_KEY, new String(Base64.encode(spec.getEncoded())));
        details.put(PUBLIC_KEY_ALG, publicKey.getAlgorithm());
        setMapDetails(details);
	}
	
	@Override
	protected void postLoadWork() throws Exception {
	  //instantiate public key
	    final Map<String, Object> details = getMapDetails();
        final String pubKey = (String) details.get(PUBLIC_KEY);
        final String pubKeyAlg = (String) details.get(PUBLIC_KEY_ALG);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(pubKey.getBytes()));
        KeyFactory kf = KeyFactory.getInstance(pubKeyAlg, getCryptoToken().getSignProviderName());
        publicKey = kf.generatePublic(keySpec);
	}

	@Override
	public LogManagementData metaClone() {
	    final DigSignLogManagementData digSign = new DigSignLogManagementData();
        digSign.setFrequency(this.getFrequency());
        digSign.setKeyLabel(this.getKeyLabel());
        digSign.setAlgorithm(this.getAlgorithm());
        digSign.setTokenConfig(this.getTokenConfig().clone());
        digSign.setRowProtection(this.getRowProtection());

		return digSign;
	}

}
