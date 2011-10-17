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
 * Thrown to indicate that setup of backup/recovery hasn't been performed.
 * 
 * @version $Id$
 *
 */
public class RecoverySetupException extends RuntimeException {

    private static final long serialVersionUID = -7295488624130449488L;

    public RecoverySetupException() {
    }

    /**
     * @param arg0
     */
    public RecoverySetupException(String arg0) {
        super(arg0);
    }

    /**
     * @param arg0
     */
    public RecoverySetupException(Throwable arg0) {
        super(arg0);
    }

    /**
     * @param arg0
     * @param arg1
     */
    public RecoverySetupException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

}
