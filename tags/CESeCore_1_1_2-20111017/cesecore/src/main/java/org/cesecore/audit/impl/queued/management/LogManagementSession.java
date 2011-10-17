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

import org.cesecore.audit.impl.queued.entity.LogManagementData;
import org.cesecore.authentication.tokens.AuthenticationToken;

import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Allows management and configuration of the secure logging functionality.
 * 
 * See {@link https://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#Audit_Functions_Management} for more information.
 * 
 * @version $Id$
 * 
 */

public interface LogManagementSession {

    /**
     * Updates the current configuration.
     * 
     * @param mode
     *            New configuration to be put in place.
     * @throws AuthorizationDeniedException
     */
    void changeLogManagement(AuthenticationToken token, final LogManagementData mode) throws AuthorizationDeniedException,
            LogManagementException;

    /**
     * Gets the current secure logs configuration.
     * 
     * @return The current configuration.
     * @throws AuthorizationDeniedException
     * 
     */
    LogManagementData getCurrentConfiguration(AuthenticationToken token) throws AuthorizationDeniedException,
            LogManagementException;

}
