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

import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * This interface provides a way to provide reliable timestamps. This means that
 * the source of the time is UTC synchronized.
 * 
 * @version $Id$
 * 
 */
public interface TrustedTimeSession {

    /**
     * Gets normal Time.
     * 
     * @return new Date
     */
    Date getTime();

    /**
     * Gets trusted time with a specific accuracy
     * 
     * @return new trusted date
     * @throws TrustedTimeProviderException 
     * @throws AuditRecordStorageException 
     */
    TrustedTime getTrustedTime() throws TrustedTimeProviderException, AuditRecordStorageException;

}
