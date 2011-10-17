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
 * This exception is thrown as a result of the database failing to be dumped properly.
 * 
 * @version $Id$
 *
 */
public class DatabaseDumpFailedException extends Exception {

    private static final long serialVersionUID = 444370689426554587L;

    public DatabaseDumpFailedException() {
        super();
    }

    public DatabaseDumpFailedException(String message, Throwable cause) {
       super(message, cause);
    }

    public DatabaseDumpFailedException(String message) {
        super(message); 
    }

    public DatabaseDumpFailedException(Throwable cause) {
        super(cause);
    }

}
