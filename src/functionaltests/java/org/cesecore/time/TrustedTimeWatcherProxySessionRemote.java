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

import javax.ejb.Remote;

import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * @version $Id$
 */
@Remote
public interface TrustedTimeWatcherProxySessionRemote {
    
    TrustedTime getTrustedTimeForcedUpdate() throws TrustedTimeProviderException, AuditRecordStorageException;

    void setDummyProvider() throws Exception;
    
    void unsetDummyProvider() throws Exception;
}
