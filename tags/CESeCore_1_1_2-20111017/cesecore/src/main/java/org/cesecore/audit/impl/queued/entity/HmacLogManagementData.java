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

import java.security.Key;

import javax.crypto.Mac;
import javax.persistence.DiscriminatorValue;

import org.cesecore.audit.impl.queued.AuditLogSigningException;
import org.cesecore.keys.token.CryptoToken;

/**
 * 
 * HMAC type of configuration for audit log.
 * 
 * @version $Id$
 * 
 */
@DiscriminatorValue("HMAC")
public class HmacLogManagementData extends LogManagementData {

    private static final long serialVersionUID = 7037420915998090552L;
    

    @Override
    public byte[] sign(final CryptoToken token, final byte[] toBesigned) throws AuditLogSigningException {
        try {
            
            final Key hMacKey = token.getKey(getKeyLabel());

            final Mac hMac = Mac.getInstance(getAlgorithm(), token.getEncProviderName());
            hMac.init(hMacKey);
            hMac.update(toBesigned);
            final byte[] signedData = hMac.doFinal();

            return signedData;
        } catch (final Exception e) {
            throw new AuditLogSigningException(e.getMessage(), e);
        }
    }

    @Override
    public LogManagementData metaClone() {
        final HmacLogManagementData hmac = new HmacLogManagementData();
        hmac.setFrequency(this.getFrequency());
        hmac.setKeyLabel(this.getKeyLabel());
        hmac.setAlgorithm(this.getAlgorithm());
        hmac.setTokenConfig(this.getTokenConfig().clone());
        hmac.setRowProtection(this.getRowProtection());

        return hmac;
    }

    @Override
    protected void prePersistWork() throws Exception {}

    @Override
    protected void postLoadWork() throws Exception {}

}
