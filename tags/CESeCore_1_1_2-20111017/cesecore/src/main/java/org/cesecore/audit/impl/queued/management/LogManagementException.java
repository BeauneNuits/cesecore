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
package org.cesecore.audit.impl.queued.management;

/**
 *
 * @version $Id$
 */
public class LogManagementException extends Exception {

    private static final long serialVersionUID = -1027362393619348433L;

    /**
     * @see Exception#Exception()
     */
    public LogManagementException()
    {
        super();
    }

    /**
     * @see Exception#Exception(String)
     */
    public LogManagementException(String message)
    {
        super(message);
    }

    /**
     * @see Exception#Exception(String,Throwable)
     */
    public LogManagementException(String message, Throwable cause)
    {
        super(message, cause);
    }

    /**
     * @see Exception#Exception(Throwable)
     */
    public LogManagementException(Throwable cause)
    {
        super(cause);
    }
}
