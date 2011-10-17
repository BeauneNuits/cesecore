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

import java.util.LinkedHashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.queued.entity.LogManagementData;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * This class implements the LogManagement interface. It handles the
 * modification of the secure audit log configuration.
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "LogManagementSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class LogManagementSessionBean implements LogManagementSessionLocal, LogManagementSessionRemote {

    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;
    @EJB
    private InternalLogManagementSessionLocal internalLogManagement;
    @EJB
    private AccessControlSessionLocal accessSession;

    /**
     * Gets the current secure logs configuration.
     * 
     * @return The current configuration.
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     * 
     */
    @Override
    public LogManagementData getCurrentConfiguration(final AuthenticationToken token) throws AuthorizationDeniedException,
            LogManagementException {
        checkAuthorization(token, StandardRules.AUDITLOGMANAGE.resource());
        return internalLogManagement.getCurrentConfiguration();
    }

    /**
     * Updates the current configuration.
     * 
     * @param mode
     *            New configuration to be put in place.
     * @throws AuthorizationDeniedException
     * @throws CryptoTokenAuthenticationFailedException
     * @throws CryptoTokenOfflineException
     */
    @Override
    public void changeLogManagement(final AuthenticationToken token, final LogManagementData mode) throws AuthorizationDeniedException,
            LogManagementException {
        checkAuthorization(token, StandardRules.AUDITLOGMANAGE.resource());
        try {
            internalLogManagement.changeLogManagement(mode);
            auditLog(mode, EventStatus.SUCCESS, token);
        } catch(final LogManagementException e) {
            auditLog(mode, EventStatus.FAILURE, token);
            throw e;
        }
    }
    
    private void auditLog(LogManagementData mode, EventStatus status, AuthenticationToken token) {
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        if(mode != null) {
            details.put("keyLabel", mode.getKeyLabel());
            details.put("algorithm", mode.getAlgorithm());
            details.put("frequency", mode.getFrequency());
            details.put("mode", mode.getSignMode());
        }
        securityEventsLogger.log(EventTypes.LOG_MANAGEMENT_CHANGE, status, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE,
                token.toString(), null, null, null, details);
    }


    private void checkAuthorization(final AuthenticationToken token, final String accessRule) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(token, accessRule)) {
            // TODO: Localized message
            final String msg = "not authorized for: " + token.toString();
            throw new AuthorizationDeniedException(msg);
        }
    }
    
}
