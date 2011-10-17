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
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.jndi.JndiConstants;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ConfigurationBackupUtilitySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ConfigurationBackupUtilitySessionBean implements ConfigurationBackupUtilitySessionRemote {

    @Override
    public boolean isDevelopmentProviderInstallation() {
        return CesecoreConfiguration.isDevelopmentProviderInstallation();
    }

    @Override
    public void setDevelopmentProviderInstallation(boolean value) {
        ConfigurationHolder.updateConfiguration("development.provider.installation", Boolean.toString(value));
    }
    
}
