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
package org.cesecore.recovery.exception;

/**
 * Thrown is backup of the configuration fails.
 * 
 * @version $Id$
 *
 */
public class ConfigurationRecoveryException extends RecoveryException {

    private static final long serialVersionUID = -2083919002977367584L;

    public ConfigurationRecoveryException() {
        super();
    }

    public ConfigurationRecoveryException(String message, Throwable cause) {
        super(message, cause);
    }

    public ConfigurationRecoveryException(String message) {
        super(message);
    }

    public ConfigurationRecoveryException(Throwable cause) {
        super(cause);
    }

}
