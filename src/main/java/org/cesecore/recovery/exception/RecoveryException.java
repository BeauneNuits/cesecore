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
 * Thrown if an general error is encountered during recovery.
 * 
 * @version $Id$
 *
 */
public class RecoveryException extends Exception {

    public RecoveryException() {
        super();
    }

    public RecoveryException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public RecoveryException(String arg0) {
        super(arg0);
    }

    public RecoveryException(Throwable arg0) {
        super(arg0);
    }

}
