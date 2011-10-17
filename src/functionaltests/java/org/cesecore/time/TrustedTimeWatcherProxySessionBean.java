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

import java.lang.reflect.Field;

import javax.ejb.EJB;
import javax.ejb.Stateless;

import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.time.providers.SimpleProvider;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * 
 * @version $Id: TrustedTimeWatcherProxySessionBean.java 897 2011-06-20
 *          11:17:25Z johane $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "TrustedTimeWatcherProxySessionRemote")
public class TrustedTimeWatcherProxySessionBean implements TrustedTimeWatcherProxySessionRemote {

    @EJB
    private TrustedTimeWatcherSessionLocal trustedTimeWatcherSession;

    public TrustedTime getTrustedTimeForcedUpdate() throws TrustedTimeProviderException, AuditRecordStorageException {
        return trustedTimeWatcherSession.getTrustedTime(true);
    }
    
    public void setDummyProvider() throws Exception {
        final TrustedTimeCache tc = TrustedTimeCache.INSTANCE;
        final Field ttField = tc.getClass().getDeclaredField("provider");
        ttField.setAccessible(true);
        ttField.set(tc, new DummyProvider());
    }
    
    public void unsetDummyProvider() throws Exception {
        final TrustedTimeCache tc = TrustedTimeCache.INSTANCE;
        final Field ttField = tc.getClass().getDeclaredField("provider");
        ttField.setAccessible(true);
        ttField.set(tc, new SimpleProvider());
    }

}
