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
package org.cesecore.certificates.ocsp.integrated;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.ocsp.OcspResponseSessionBean;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.cache.TokenAndChainCache;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.log.SaferAppenderListener;
import org.cesecore.util.log.SaferDailyRollingFileAppender;

/**
 * 
 * This class is based on OCSPUtil.java 11154 2011-01-12 09:56:23Z jeklund and OCSPServletBase.java 11143 2011-01-11 15:32:31Z jeklund
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "IntegratedOcspResponseGeneratorSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public final class IntegratedOcspResponseGeneratorSessionBean extends OcspResponseSessionBean implements
        IntegratedOcspResponseGeneratorSessionRemote, IntegratedOcspResponseGeneratorSessionLocal, SaferAppenderListener {

    private static final Logger log = Logger.getLogger(IntegratedOcspResponseGeneratorSessionBean.class);

    private static final String INTERNAL_ADMIN_PRINCIPAL = "Integrated OCSP cache update";

    private static volatile TokenAndChainCache cache;

    @Resource
    private SessionContext sessionContext;
    /* When the sessionContext is injected, the timerService should be looked up.
     * This is due to the Glassfish EJB verifier complaining. 
     */
    private TimerService timerService;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;

    @PostConstruct
    public void init() throws AuthorizationDeniedException {
        if (OcspConfiguration.getLogSafer() == true) {
            SaferDailyRollingFileAppender.addSubscriber(this);
            log.info("added us as subscriber" + SaferDailyRollingFileAppender.class.getCanonicalName());
        }

        timerService = sessionContext.getTimerService();

        if (cache == null) {
            cache = new TokenAndChainCache();
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void reloadTokenAndChainCache(AuthenticationToken authenticationToken) throws AuthorizationDeniedException {
    	// Cancel any waiting timers
    	cancelTimers();
    	try {
    		Map<Integer, CryptoTokenAndChain> newCache = new ConcurrentHashMap<Integer, CryptoTokenAndChain>();
    		for (Integer caId : caSession.getAvailableCAs()) {
    			CA ca = null;
    			try {
    				ca = caSession.getCA(authenticationToken, caId);
    			} catch (CADoesntExistsException e) {
    				// Should not be able to happen.
    				throw new Error("Could not find CA with id " + caId + " in spite of value just being collected from database.");
    			}

    			CertificateID certId = null;
    			try {
    				certId = new CertificateID(CertificateID.HASH_SHA1, (X509Certificate) ca.getCACertificate(), new BigInteger("1"));
    			} catch (OCSPException e) {
    				throw new OcspFailureException(e);
    			}

    			try {
    				newCache.put(TokenAndChainCache.keyFromCertificateID(certId), new CryptoTokenAndChain(ca.getCAToken().getCryptoToken(), ca
    						.getCertificateChain().toArray(new X509Certificate[ca.getCertificateChain().size()]), CAToken.SOFTPRIVATESIGNKEYALIAS));
    			} catch (IllegalCryptoTokenException e) {
    				throw new Error("Crypto token retrieved from CA was invalid. This is an erronous state.");
    			}
    		}
    		try {
    			X509Certificate latestCertificate = certificateStoreSession.findLatestX509CertificateBySubject(OcspConfiguration.getDefaultResponderId());

    			if (latestCertificate == null) {
    				log.warn("Could not find default responder in database.");
    				cache.updateCache(newCache, null);
    			} else {
    				cache.updateCache(newCache, new CertificateID(CertificateID.HASH_SHA1, latestCertificate, new BigInteger("1")));
    			}
    		} catch (OCSPException e) {
    			throw new OcspFailureException(e);
    		}
    	} finally {
    		// Schedule a new timer
    		addTimer(OcspConfiguration.getSignTrustValidTimeInSeconds(), cache.hashCode());
    	}
    }

    protected void initiateIfNecessary() {
        if (timerService.getTimers().size() == 0) {
            try {
                reloadTokenAndChainCache(new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(INTERNAL_ADMIN_PRINCIPAL)));
            } catch (AuthorizationDeniedException e) {
                throw new Error("Could not reload token and chain cache using internal admin.", e);
            }
        }
    }

    /**
     * When a timer expires, this method will update
     * 
     * According to JSR 220 FR (18.2.2), this method may not throw any exceptions.
     * 
     * @param timer The timer whose expiration caused this notification.
     * 
     */
    @Timeout
    /* Glassfish 2.1.1:
     * "Timeout method ....timeoutHandler(javax.ejb.Timer)must have TX attribute of TX_REQUIRES_NEW or TX_REQUIRED or TX_NOT_SUPPORTED"
     * JBoss 5.1.0.GA: We cannot mix timer updates with our EJBCA DataSource transactions. 
     */
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
    	if (log.isTraceEnabled()) {
    		log.trace(">timeoutHandler: "+timer.getInfo().toString()+", "+timer.getNextTimeout().toString());
    	}
        try {
        	// reloadTokenAndChainCache cancels old timers and adds a new timer
            reloadTokenAndChainCache(new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(INTERNAL_ADMIN_PRINCIPAL)));
        } catch (AuthorizationDeniedException e) {
            throw new Error("Could not authorize using internal admin.");
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<timeoutHandler");
    	}
    }

    /**
     * This method cancels all timers associated with this bean.
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    public void cancelTimers() {
        if (log.isTraceEnabled()) {
        	log.trace(">cancelTimers");
        }
        @SuppressWarnings("unchecked")
        Collection<Timer> timers = timerService.getTimers();
        for (Timer timer : timers) {
            timer.cancel();
        }
        if (log.isTraceEnabled()) {
        	log.trace("<cancelTimers, timers canceled: "+timers.size());
        }
    }

    /**
     * Adds a timer to the bean
     * 
     * @param id the id of the timer
     */
    // We don't want the appserver to persist/update the timer in the same transaction if they are stored in different non XA DataSources. This method
    // should not be run from within a transaction.
    public Timer addTimer(long interval, Integer id) {
        if (log.isTraceEnabled()) {
            log.trace(">addTimer: " + id+", interval: "+interval);
        }
        Timer ret = timerService.createTimer(interval, id);
        if (log.isTraceEnabled()) {
            log.trace("<addTimer: " + id+", interval: "+interval+", "+ret.getNextTimeout().toString());
        }
        return ret;
    }

    @Override
    protected TokenAndChainCache getTokenAndChainCache() {
        return cache;
    }

}
