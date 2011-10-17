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
package org.cesecore.authentication;

/**
 * This RunTimeException is thrown if an interceptor has intercepted method without it containing an AuthenticationToken as a parameter.
 * 
 * @version $Id$
 * 
 */
public class AuthenticationTokenNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 3261734175684520218L;

    public AuthenticationTokenNotFoundException() {
        super();
    }

    public AuthenticationTokenNotFoundException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    public AuthenticationTokenNotFoundException(String arg0) {
        super(arg0);
    }

    public AuthenticationTokenNotFoundException(Throwable arg0) {
        super(arg0);
    }

}
