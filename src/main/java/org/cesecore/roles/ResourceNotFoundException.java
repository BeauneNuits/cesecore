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
package org.cesecore.roles;

/**
 * @version $Id$
 *
 */
public class ResourceNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1829456673099998835L;

    public ResourceNotFoundException() {

    }

    public ResourceNotFoundException(String arg0) {
        super(arg0);
    }

    public ResourceNotFoundException(Throwable arg0) {
        super(arg0);
    }

    public ResourceNotFoundException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

}
