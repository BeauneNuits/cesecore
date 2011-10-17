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
 * This exception is thrown to indicate that the backup directory hasn't been set properly.
 * 
 * @version $Id$
 *
 */
public class BackupDirectoryNotFoundException extends Exception {

    private static final long serialVersionUID = 6714332762019326823L;

    /**
     * 
     */
    public BackupDirectoryNotFoundException() {
        // TODO Auto-generated constructor stub
    }

    /**
     * @param arg0
     */
    public BackupDirectoryNotFoundException(String arg0) {
        super(arg0);
        // TODO Auto-generated constructor stub
    }

    /**
     * @param arg0
     */
    public BackupDirectoryNotFoundException(Throwable arg0) {
        super(arg0);
        // TODO Auto-generated constructor stub
    }

    /**
     * @param arg0
     * @param arg1
     */
    public BackupDirectoryNotFoundException(String arg0, Throwable arg1) {
        super(arg0, arg1);
        // TODO Auto-generated constructor stub
    }

}
