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
package org.cesecore.certificates.ocsp.standalone.exception;

/**  
 * @version $Id$
 *
 */
public class P11SlotException extends RuntimeException {
    
    private static final long serialVersionUID = 2402886545847244832L;

    public P11SlotException() {
        super();
    }

    public P11SlotException(String message, Throwable cause) {
        super(message, cause);
    }

    public P11SlotException(String message) {
        super(message);
    }

    public P11SlotException(Throwable cause) {
        super(cause);
    }

}
