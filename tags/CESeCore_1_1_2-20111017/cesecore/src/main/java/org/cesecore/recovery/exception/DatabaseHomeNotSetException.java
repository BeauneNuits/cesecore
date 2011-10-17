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
 * This exception is thrown if backup.database.home was not set in backup.properties
 * 
 * @version $Id$
 *
 */
public class DatabaseHomeNotSetException extends RuntimeException {

    private static final long serialVersionUID = 1504844078449279677L;

    /**
     * 
     */
    public DatabaseHomeNotSetException() {
      
    }

    /**
     * @param arg0
     */
    public DatabaseHomeNotSetException(String arg0) {
        super(arg0);
       
    }

    /**
     * @param arg0
     */
    public DatabaseHomeNotSetException(Throwable arg0) {
        super(arg0);
       
    }

    /**
     * @param arg0
     * @param arg1
     */
    public DatabaseHomeNotSetException(String arg0, Throwable arg1) {
        super(arg0, arg1);
        
    }

}
