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

/**
 * Remote interface for a Configuration backup testing utility. Gives access to properties from CESeCores configuration, so that they can be checked
 * from the functional tests.
 * 
 * @version $Id$
 * 
 */
@Remote
public interface ConfigurationBackupUtilitySessionRemote {

    boolean isDevelopmentProviderInstallation();
    
    void setDevelopmentProviderInstallation(boolean value);
}
