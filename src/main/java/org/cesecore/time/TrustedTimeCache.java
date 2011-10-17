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
package org.cesecore.time;

import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.time.providers.TrustedTimeProvider;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * Simple singleton that holds the latest TrustedTime, an instance of the provider.
 * This class supports thread-safe atomic updates from the provider, but does not support any timeout.
 * 
 * @version $Id$
 */
public enum TrustedTimeCache {
	INSTANCE;

	private static final Logger log = Logger.getLogger(TrustedTimeCache.class);
	private TrustedTime trustedTime = null;
	private TrustedTimeProvider provider = null;
	private final ReentrantLock resourceLock = new ReentrantLock();

	protected TrustedTime getTrustedTime() {
		return trustedTime;
	}

	/**
	 * Perform an atomic update using the configured provider.
	 * 
	 * @param forceUpdate if true will force an update from the provider even if a time exists in the cache
	 * @return a list containing two TrustedTime objects: the value before the update and the value after
	 * @throws TrustedTimeProviderException if the there is a problem instantiating the configure provider
	 */
	public TrustedTime[] atomicUpdate(final boolean forceUpdate) throws TrustedTimeProviderException {
	    //using double-check idiom to increase performance by acquiring the lock only when we need to.
	    if(log.isTraceEnabled()) {
	        log.trace(String.format(">TrustedTimeCache: forcedUpdate: %s || TrustedTime: %s", forceUpdate, TrustedTimeCache.INSTANCE.getTrustedTime() != null));
	    }
	    if (!forceUpdate && TrustedTimeCache.INSTANCE.getTrustedTime() != null) {
            // False alarm.. another thread has already made the initial sync, so we don't need to.
            return null;
        }
        try {
    		resourceLock.lock();
    		if (!forceUpdate && TrustedTimeCache.INSTANCE.getTrustedTime() != null) {
                // False alarm.. another thread has already made the initial sync, so we don't need to.
                return null;
            }
    		if(log.isDebugEnabled()) {
                log.debug("TrustedTime will be updated");
            }
            final TrustedTime oldTrustedTime = trustedTime;
            trustedTime = getProvider().getTrustedTime();
            final TrustedTime[] ret = {oldTrustedTime, trustedTime};
            return ret;
        } finally {
            if(log.isTraceEnabled()) {
                log.trace("<TrustedTimeCache");
            }
    		resourceLock.unlock();
        }
	}
	
	/** @return the instance of the TrustedTime-provider (creates a new one if it does not exist) */
	private TrustedTimeProvider getProvider() throws TrustedTimeProviderException {
        if (provider == null) {
            try {
                final Class<?> providerClass = CesecoreConfiguration.getTrustedTimeProvider();
                provider = (TrustedTimeProvider) providerClass.newInstance();
            } catch (final Exception e) {
                throw new TrustedTimeProviderException("impossible to instantiate a provider class", e);
            }   
        }
        return provider;
	}
}
