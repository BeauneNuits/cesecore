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

import java.util.Date;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * 
 * This class handles the way to obtain reliable timestamps.
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "TrustedTimeSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class TrustedTimeSessionBean implements TrustedTimeSessionLocal, TrustedTimeSessionRemote {

    @EJB
    private TrustedTimeWatcherSessionLocal watcher;

    /**
     * Gets the current time without checking if it is synchronized.
     * 
     * @return current time
     */
    @Override
    public Date getTime() {
        return new Date();
    }

    /**
     * Gets the current time UTC synchronized.
     * 
     * @return synchronized current time with a specific accuracy.
     * @throws TrustedTimeProviderException 
     * @throws AuditRecordStorageException 
     */
    @Override
    public TrustedTime getTrustedTime() throws TrustedTimeProviderException, AuditRecordStorageException {
        return watcher.getTrustedTime(false);
    }
}
