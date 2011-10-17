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

import java.security.cert.Certificate;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.keys.token.CryptoToken;

/**
 * Associate certificates with keys. This interface is used to manage a certificate store with related private keys on tokens.
 * 
 * See {@link https://wiki.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#Certificate_and_Key_Association}
 * 
 * @version $Id$
 * 
 */
public interface CertificateKeyAssociationSession {

    /**
     * Bind one Certificate with one Key.
     * 
     * @param adminUserForAudit
     *            user performing the task, only used for audit logging
     * @param cryptoToken
     *            used to check if the public key of the certificate matches the private key that we are trying to associate.
     * @param certificate
     *            Certificate to bind with the Key.
     * @param tags
     *            list of tags (keywords) used to describe the association.
     * @param keyLabel
     *            Label of the key to associate with the profile.
     */
    void bindCertificateToKey(final AuthenticationToken adminUserForAudit, CryptoToken cryptoToken, Certificate certificate, List<String> tags, String keyLabel)
            throws CertificateKeyAssociationException;

    /**
     * UnBind Certificate from the key
     * 
     * @param adminUserForAudit
     *            user performing the task, only used for audit logging
     * @param certificate
     *            certificate to be unbinded.
     * 
     */
    void unBindCertificateFromKey(final AuthenticationToken adminUserForAudit, Certificate certificate) throws CertificateKeyAssociationException;

}
