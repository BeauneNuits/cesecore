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
package org.cesecore.configuration;

import javax.ejb.Remote;

import org.cesecore.time.providers.TrustedTimeProviderException;
import org.cesecore.time.providers.TrustedTimeProvider;

/**
 * Acts as a proxy for ConfigurationHolder tests
 * 
 * @version $Id$
 *
 */
@Remote
public interface CesecoreConfigurationProxySessionRemote {

    TrustedTimeProvider getTrustedTimeProvider() throws TrustedTimeProviderException;
    
    /**
     * Use this method to (from a test) set a configuration property.
     * 
     * @param key
     * @param value
     */
    void setConfigurationValue(String key, String value);
    
}                           
