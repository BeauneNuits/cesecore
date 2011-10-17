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

import java.security.Key;
import java.security.cert.Certificate;
import java.util.List;

import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Tuplet;

/**
 * Retrieve certificates or keys. This interface is used to retrieve a certificate having the related private key alias.
 * 
 * See {@link https ://wiki.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#Certificate_and_Key_Association}
 * 
 * @version $Id$
 * 
 */
public interface CertificateKeyRetrievalSession {

    /**
     * Retrieve associations based on a list of tags.
     * 
     * @param tags
     *            used to search associations
     * 
     * @return list of tuplets containing the certificate and the associated keyAlias
     */
    List<Tuplet<Certificate, String>> getAssociations(List<String> tags);

    /**
     * Retrieve the certificate associated with a given Key.
     * 
     * @param keyAlias
     *            used to retrieve a list of certificates associated to this key
     * 
     * @return List of associated certificates, or empty list. Never null.
     */
    List<Certificate> getCertificates(String keyAlias);

    /**
     * Retrieve Key associated with a given certificate.
     * 
     * @param cryptoToken
     *            token where the key will be retrieved.
     * @param certificate
     *            certificate associated to the pretended key.
     * 
     * @return Associated key.
     * @throws CryptoTokenOfflineException
     *             if crypto token is not active or there is no key associated with given certificate
     */
    Key getKey(CryptoToken cryptoToken, Certificate certificate) throws CryptoTokenOfflineException;
}
