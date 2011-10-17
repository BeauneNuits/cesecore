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

import javax.ejb.Local;

import org.cesecore.audit.impl.queued.entity.LogManagementData;

/**
 * Local Interface for the internal log management session bean
 * 
 * @version $Id$
 * 
 */
@Local
public interface InternalLogManagementSessionLocal {
    
    /**
     * Updates the current configuration.
     * 
     * @param mode
     *            New configuration to be put in place.
     * @throws LogManagementException
     */
    void changeLogManagement(final LogManagementData mode) throws LogManagementException;

    /**
     * Gets the current secure logs configuration.
     * 
     * @return The current configuration.
     * @throws LogManagementException
     * 
     */
    LogManagementData getCurrentConfiguration() throws LogManagementException;

}
