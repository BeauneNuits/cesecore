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
 * Thrown if encryption of the backup zip fails.
 * 
 * @version $Id$
 * 
 */
public class RecoveryEncryptionFailedException extends RecoveryException {

    public RecoveryEncryptionFailedException() {
        super();
    }

    public RecoveryEncryptionFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public RecoveryEncryptionFailedException(String message) {
        super(message);
    }

    public RecoveryEncryptionFailedException(Throwable cause) {
        super(cause);
    }

    private static final long serialVersionUID = 3174768691621253625L;

}
