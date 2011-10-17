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
 * Thrown if an error is encountered during cleanup.
 * 
 * @version $Id$
 *
 */
public class RecoveryCleanupException extends RuntimeException {

    private static final long serialVersionUID = 45384882800854259L;

    public RecoveryCleanupException() {
        super();
    }

    public RecoveryCleanupException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public RecoveryCleanupException(String arg0) {
        super(arg0);
    }

    public RecoveryCleanupException(Throwable arg0) {
        super(arg0);
    }

}
