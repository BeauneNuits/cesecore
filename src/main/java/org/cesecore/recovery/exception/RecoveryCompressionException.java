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
 * Thrown if an error is encountered while compressing backup. 
 * 
 * @version $Id$
 *
 */
public class RecoveryCompressionException extends RecoveryException {

    private static final long serialVersionUID = 9067855173210361366L;

    public RecoveryCompressionException() {
        super();
    }

    public RecoveryCompressionException(String message, Throwable cause) {
        super(message, cause);
    }

    public RecoveryCompressionException(String message) {
        super(message);
    }

    public RecoveryCompressionException(Throwable cause) {
        super(cause);
    }

}
