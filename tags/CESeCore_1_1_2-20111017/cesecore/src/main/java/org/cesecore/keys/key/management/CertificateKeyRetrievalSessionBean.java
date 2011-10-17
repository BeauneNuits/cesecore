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
import java.util.ArrayList;
import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.Tuplet;

/**
 * 
 * Class handling the retrieval of Certificate Key associations.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateKeyRetrievalSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CertificateKeyRetrievalSessionBean implements CertificateKeyRetrievalSessionLocal, CertificateKeyRetrievalSessionRemote {

    private static final Logger log = Logger.getLogger(CertificateKeyRetrievalSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager em;

    /**
     * Retrieve the certificate associated with a given Key.
     * 
     * @param token
     *            user performing the task.
     * @param keyAlias
     *            used to retrieve a list of certificates associated to this key
     * 
     * @return List of associated certificates, or empty list. Never null.
     */
    @Override
    public List<Certificate> getCertificates(final String keyAlias) {
        if (log.isTraceEnabled()) {
            log.trace(">getCertificates: " + keyAlias);
        }
        final List<CertificateKeyAssociationData> associations = CertificateKeyAssociationData.findByKeyAlias(em, keyAlias);
        final List<Certificate> certificates = new ArrayList<Certificate>();

        for (final CertificateKeyAssociationData association : associations) {
            certificates.add(association.getCertificate());
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCertificates: " + certificates.size());
        }
        return certificates;
    }

    /**
     * Retrieve Key associated with a given certificate.
     * 
     * @param token
     *            user performing the task.
     * @param cryptoToken
     *            token where the key will be retrieved.
     * @param certificate
     *            certificate associated to the pretended key.
     * 
     * @return Associated key.
     * @throws CryptoTokenOfflineException
     *             if crypto token is not active or there is no key associated
     *             with given certificate
     */
    @Override
    public Key getKey(final CryptoToken cryptoToken, final Certificate certificate)
            throws CryptoTokenOfflineException {
        if (log.isTraceEnabled()) {
            log.trace(">getKey: " + CertTools.getSubjectDN(certificate));
        }
        Key ret = null;
        final String certFingerprint = CertTools.getFingerprintAsString(certificate);
        final CertificateKeyAssociationData cka = CertificateKeyAssociationData.findByCertificate(em, certFingerprint);
        if (cka != null) {
        	final String alias = cka.getKeyAlias();
        	if (log.isDebugEnabled()) {
        		log.debug("Retrieving key with alias: " + alias);
        	}
        	ret = cryptoToken.getPrivateKey(alias);
        }
        return ret;
    }

    /**
     * Retrieve associations based on a list of tags.
     * 
     * @param token
     *            user performing the task
     * @param tags
     *            used to search associations
     * 
     * @return list of tuplets containing the certificate and the associated
     *         keyAlias
     */
    @Override
    public List<Tuplet<Certificate, String>> getAssociations(final List<String> tags) {
        if (log.isTraceEnabled()) {
            log.trace(">getAssociations " + StringUtils.join(tags, ","));
        }
        final List<CertificateKeyAssociationData> associations = CertificateKeyAssociationData.findByTags(em, tags);
        final List<Tuplet<Certificate, String>> result = new ArrayList<Tuplet<Certificate, String>>();

        for (final CertificateKeyAssociationData association : associations) {
            result.add(new Tuplet<Certificate, String>(association.getCertificate(), association.getKeyAlias()));
        }
        if (log.isTraceEnabled()) {
            log.trace("<getAssociations " + result.size());
        }
        return result;
    }

}
