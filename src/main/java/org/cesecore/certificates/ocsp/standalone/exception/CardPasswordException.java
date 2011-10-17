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
public class CardPasswordException extends RuntimeException {
    
    private static final long serialVersionUID = 709142644679727082L;
    
    public CardPasswordException() {
        super();
    }

    public CardPasswordException(String message, Throwable cause) {
        super(message, cause);
    }

    public CardPasswordException(String message) {
        super(message);
    }

    public CardPasswordException(Throwable cause) {
        super(cause);
    }


}
