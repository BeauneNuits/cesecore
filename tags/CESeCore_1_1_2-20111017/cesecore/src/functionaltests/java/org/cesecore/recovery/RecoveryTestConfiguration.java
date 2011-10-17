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
package org.cesecore.recovery;

import org.cesecore.configuration.ConfigurationTestHolder;

/**
 * Provides configuration properties to Recovery Tests
 * 
 * @version $Id$
 * 
 */
public abstract class RecoveryTestConfiguration {

    public static final String getDatabaseSuperUserId() {
        return ConfigurationTestHolder.INSTANCE.getExpandedString("backup.database.superuser.username", null);
    }

    public static final String getDatabaseSuperUserPassword() {
        return ConfigurationTestHolder.INSTANCE.getExpandedString("backup.database.superuser.password", null);
    }
}
