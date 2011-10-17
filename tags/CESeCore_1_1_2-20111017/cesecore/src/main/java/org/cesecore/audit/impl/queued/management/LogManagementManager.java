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
package org.cesecore.audit.impl.queued.management;

import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.cesecore.audit.audit.LogServiceState;
import org.cesecore.audit.impl.queued.entity.AuditLogCryptoTokenConfigData;
import org.cesecore.audit.impl.queued.entity.LogManagementData;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Handles audit log configuration. It is important to use this class when you
 * need to get or update an audit log configuration. This class is also internal
 * to CESeCore and should not be available to the user.
 * 
 * @version $Id$
 */
public final class LogManagementManager {

    private static final Logger log = Logger.getLogger(LogManagementManager.class);

    private static LogManagementManager manager;
    private static LogManagementData currentConfig;

    /** state control variables */
    private final static Object instanceLock = new Object();
    private final static ReentrantReadWriteLock configurationLock = new ReentrantReadWriteLock();

    /**
     * Constructs a new instance.
     */
    private LogManagementManager() {
    }

    private static void getInstance(final EntityManager em) throws LogManagementException {
        if (manager == null) {
            synchronized (instanceLock) {
                if (manager == null) {
                    log.trace("creating new LogManagementManager instance");
                    manager = new LogManagementManager();
                    currentConfig = LogManagementData.getCurrentConfiguration(em);
                }
            }
        } else {
            log.trace("LogManagementManager instance running");
        }
    }

    /**
     * Gets the current audit log configuration.
     * 
     * @param em
     *            The EntityManager used to retrieve audit log configuration.
     * 
     * @return The current configuration.
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     */
    public static LogManagementData getCurrentConfiguration(final EntityManager em) throws LogManagementException {
        log.trace(">getCurrentConfig");
        if (!LogServiceState.INSTANCE.isDisabled()) {
            configurationLock.readLock().lock();
            try {
                getInstance(em);
            } finally {
                configurationLock.readLock().unlock();
            }
        } else {
            throw new LogManagementException("reset in progress");
        }
        log.trace("<getCurrentConfig");
        return currentConfig;
    }

    /**
     * Updates the current audit log configuration.
     * 
     * @param em
     *            The entity manager.
     * @param configuration
     *            The audit log configuration to take place.
     * 
     * @throws CryptoTokenOfflineException
     * @throws CryptoTokenAuthenticationFailedException
     */
    public static void updateConfiguration(final EntityManager em, final LogManagementData configuration) throws LogManagementException {
        log.trace(">updateConfiguration");
        if (!LogServiceState.INSTANCE.isDisabled()) {
            configurationLock.writeLock().lock();
            try {
                getInstance(em);
                if(currentConfig != null) {
                    CryptoToken token = currentConfig.getCryptoToken();
                    if(token != null) {
                        token.deactivate();
                    }
                }
                final AuditLogCryptoTokenConfigData tokenConfig = configuration.getTokenConfig();
                if (tokenConfig != null) {
                    tokenConfig.saveOrUpdate(em);
                    log.trace("new cryptoToken configuration in place");
                }
                configuration.save(em);
                currentConfig = configuration;
                if(log.isDebugEnabled()){
                    log.info("audit log configuration in place: "+ configuration.toString());
                }
            } finally {
                configurationLock.writeLock().unlock();
            }
        } else {
            throw new LogManagementException("reset in progress");
        }
        log.trace("<updateConfiguration");
    }

    public static void reset() {
        // trash the current instance
        manager = null;
    }

}
