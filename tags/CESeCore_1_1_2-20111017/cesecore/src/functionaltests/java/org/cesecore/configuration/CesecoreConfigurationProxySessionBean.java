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

import javax.ejb.Stateless;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.jndi.JndiConstants;

import org.cesecore.time.providers.TrustedTimeProvider;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CesecoreConfigurationProxySessionRemote")
public class CesecoreConfigurationProxySessionBean implements CesecoreConfigurationProxySessionRemote {

    @Override
    public TrustedTimeProvider getTrustedTimeProvider() throws TrustedTimeProviderException {
        TrustedTimeProvider provider = null;
        try {
            Class<?> providerClass = CesecoreConfiguration.getTrustedTimeProvider();
            provider = (TrustedTimeProvider) providerClass.newInstance();
        } catch (Exception e) {
            throw new TrustedTimeProviderException("impossible to instantiate a provider class", e);
        }
        return provider;
    }

    @Override
    public void setConfigurationValue(String key, String value) {
        ConfigurationHolder.updateConfiguration(key, value);
    }

}
