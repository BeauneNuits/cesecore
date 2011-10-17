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
 * Audit log manager process exception.
 * 
 * @version $Id$
 * 
 */
public class AuditLogManagerProcessException extends Exception {

    private static final long serialVersionUID = 1636855335348752439L;

    public AuditLogManagerProcessException() {
        super();
    }

    public AuditLogManagerProcessException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public AuditLogManagerProcessException(String arg0) {
        super(arg0);
    }

    public AuditLogManagerProcessException(Throwable arg0) {
        super(arg0);
    }

    
}
