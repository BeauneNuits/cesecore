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
 * This Exception means that the Frequency setted in the Audit Log configuration
 * does not satisfies the requirements. Frequency must be 0 or above 100 ms.
 * 
 * This exception will be thrown when applying a new configuration.
 * 
 * @version $Id$
 */
public class InvalidFrequencyException extends LogManagementException {

    private static final long serialVersionUID = 301478457608581707L;

    /**
     * @see LogManagementException#LogManagementException()
     */
    public InvalidFrequencyException() {
        super();
    }

    /**
     * @see LogManagementException#LogManagementException(String, Throwable)
     */
    public InvalidFrequencyException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * @see LogManagementException#LogManagementException(String)
     */
    public InvalidFrequencyException(final String message) {
        super(message);
    }

    /**
     * @see LogManagementException#LogManagementException(Throwable)
     */
    public InvalidFrequencyException(final Throwable cause) {
        super(cause);
    }

}
