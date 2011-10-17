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

import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;

/**
 * This class handles certificate key binding and unbinding.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateKeyAssociationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CertificateKeyAssociationSessionBean implements CertificateKeyAssociationSessionLocal, CertificateKeyAssociationSessionRemote {

    private static final Logger log = Logger.getLogger(CertificateKeyAssociationSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager em;

    @EJB
    private SecurityEventsLoggerSessionLocal securityLogger;

    @Override
    public void bindCertificateToKey(final AuthenticationToken adminUserForAudit, final CryptoToken cryptoToken, final Certificate certificate,
            final List<String> tags, final String keyLabel) throws CertificateKeyAssociationException {
        if (log.isTraceEnabled()) {
            log.trace(String.format(">bindCertificateToKey cert: %s, key:%s, tags:", CertTools.getSubjectDN(certificate), keyLabel,
                    StringUtils.join(tags, ",")));
        }
		Map<String, Object> details = new LinkedHashMap<String, Object>();
		details.put("fingerprint", CertTools.getFingerprintAsString(certificate));
		details.put("keylabel", keyLabel);
        try {

            final PrivateKey privateKey = cryptoToken.getPrivateKey(keyLabel);
            final PublicKey certificatePublicKey = certificate.getPublicKey();
            KeyTools.testKey(privateKey, certificatePublicKey, cryptoToken.getSignProviderName());

        } catch (final CryptoTokenOfflineException e) {
            securityLogger.log(EventTypes.CERTIFICATE_KEY_BIND, EventStatus.FAILURE, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE, adminUserForAudit.toString(), null, null, null, details);
            throw new CertificateKeyAssociationException(e.getMessage(), e);
        } catch (final InvalidKeyException e) {
            securityLogger.log(EventTypes.CERTIFICATE_KEY_BIND, EventStatus.FAILURE, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE, adminUserForAudit.toString(), null, null, null, details);
            throw new CertificateKeyAssociationException(e.getMessage(), e);
        } catch (final NoSuchProviderException e) {
            securityLogger.log(EventTypes.CERTIFICATE_KEY_BIND, EventStatus.FAILURE, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE, adminUserForAudit.toString(), null, null, null, details);
            throw new CertificateKeyAssociationException(e.getMessage(), e);
        }

        final CertificateKeyAssociationData cka = new CertificateKeyAssociationData(certificate, tags, keyLabel);
        em.persist(cka);
        securityLogger.log(EventTypes.CERTIFICATE_KEY_BIND, EventStatus.SUCCESS, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE, adminUserForAudit.toString(), null, null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<bindCertificateToKey");
        }
    }

    @Override
    public void unBindCertificateFromKey(final AuthenticationToken adminUserForAudit, final Certificate certificate) throws CertificateKeyAssociationException {
        if (log.isTraceEnabled()) {
            log.trace(">unBindCertificateToKey cert:" + CertTools.getSubjectDN(certificate));
        }
        final String certFingerprint = CertTools.getFingerprintAsString(certificate);
		Map<String, Object> details = new LinkedHashMap<String, Object>();
		details.put("fingerprint", certFingerprint);
		final CertificateKeyAssociationData cka = CertificateKeyAssociationData.findByCertificate(em, certFingerprint);
		if (cka == null) {
			securityLogger.log(EventTypes.CERTIFICATE_KEY_UNBIND, EventStatus.FAILURE, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE, adminUserForAudit.toString(), null, null, null, details);
			throw new CertificateKeyAssociationException("Unable to find certificate binding for fingerprint " + certFingerprint);
		} else {
			em.remove(cka);
			securityLogger.log(EventTypes.CERTIFICATE_KEY_UNBIND, EventStatus.SUCCESS, ModuleTypes.KEY_MANAGEMENT, ServiceTypes.CORE, adminUserForAudit.toString(), null, null, null, details);
		}
        if (log.isTraceEnabled()) {
            log.trace("<unBindCertificateToKey");
        }
    }

}
