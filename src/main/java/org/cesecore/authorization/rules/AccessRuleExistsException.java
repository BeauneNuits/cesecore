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
package org.cesecore.authorization.rules;

/**
 * Thrown when creating an access rule that already exists.
 * 
 * @version $Id$
 *
 */
public class AccessRuleExistsException extends Exception{

    private static final long serialVersionUID = 1340738456351111597L;

    public AccessRuleExistsException() {
        super();
        // TODO Auto-generated constructor stub
    }

    public AccessRuleExistsException(String message, Throwable cause) {
        super(message, cause);
        // TODO Auto-generated constructor stub
    }

    public AccessRuleExistsException(String message) {
        super(message);
        // TODO Auto-generated constructor stub
    }

    public AccessRuleExistsException(Throwable cause) {
        super(cause);
        // TODO Auto-generated constructor stub
    }


}
