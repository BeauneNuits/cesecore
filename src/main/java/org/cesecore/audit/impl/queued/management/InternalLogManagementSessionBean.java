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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.audit.LogServiceState;
import org.cesecore.audit.impl.queued.entity.LogManagementData;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * This class is an internal class and should not be used. It handles the
 * modification of the secure audit log configuration.
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalLogManagementSessionRemote")
public class InternalLogManagementSessionBean implements InternalLogManagementSessionLocal {

    private static final Logger log = Logger.getLogger(LogManagementSessionBean.class);
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager em;
    @EJB
    private SchedulerSessionLocal scheduler;

    /**
     * Gets the current secure logs configuration.
     * 
     * @return The current configuration.
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * 
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public LogManagementData getCurrentConfiguration() throws LogManagementException {
        if (LogServiceState.INSTANCE.isDisabled()) {
            throw new LogManagementException("Security audit logging is currently disabled.");
        }
        final LogManagementData config = LogManagementManager.getCurrentConfiguration(em);
        if(log.isDebugEnabled()) {
            log.debug("current audit log configuration: " + (config == null ? null : config.toString()));
        }
        // returns a special clone: contains only the essential info.
        return config == null ? null : config.metaClone();
    }

    /**
     * Updates the current configuration.
     * 
     * @param mode
     *            New configuration to be put in place.
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void changeLogManagement(final LogManagementData mode) throws LogManagementException {
        if (LogServiceState.INSTANCE.isDisabled()) {
            throw new LogManagementException("Security audit logging is currently disabled.");
        }
        //validate the possible configuration
        if(mode == null) {
            throw new LogManagementException("Configuration mode not supported");
        }
        mode.validate();
        LogManagementManager.updateConfiguration(em, mode);
        // check if we must create a schedule
        final long frequency = mode.getFrequency();
        if (frequency > 0) {
            scheduler.schedule(frequency, frequency);
        }
        else {
            scheduler.cancelTimers();
        }
    }

    
}

