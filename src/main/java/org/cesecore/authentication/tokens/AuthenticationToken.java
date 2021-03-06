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
package org.cesecore.authentication.tokens;

import java.io.Serializable;
import java.security.Principal;
import java.util.Set;

import org.cesecore.authorization.user.AccessUserAspect;

/**
 * A token returned by the act of authentication. Ownership of such a token denotes that the caller has previously authenticated herself via the
 * Authentication session bean.
 * 
 * The Sets of Principals and credentials contained within this class will correspond to the subset of those found in the Subject class submitted for
 * authentication used for that process.
 * 
 * @version $Id$
 * 
 */
public abstract class AuthenticationToken implements Serializable {

    private static final long serialVersionUID = 1888731103952962350L;

    private final Set<? extends Principal> principals;
    private final Set<?> credentials;

    public AuthenticationToken(Set<? extends Principal> principals, Set<?> credentials) {
        this.principals = principals;
        this.credentials = credentials;
    }

    public Set<? extends Principal> getPrincipals() {
        return principals;
    }

    public Set<?> getCredentials() {
        return credentials;
    }

    /**
     * This method will take an <code>AccessUserAspectData</code> entity and return whether or not it matches to this AuthenticationToken. 
     * 
     * @param accessUser An <code>AccessUserAspectData</code> entity to match.
     * @return <code>true</code> if matching.
     */
    public abstract boolean matches(AccessUserAspect accessUser);
    
    @Override
    public abstract boolean equals(Object authenticationToken);
    
    @Override
    public abstract int hashCode();

    /**
     * Default way of returning the user information of the user(s) this authentication token belongs to.
     * This should never return sensitive information, since it is used in logging (CESeCore.FAU_GEN.1.2).
     * @return a comma-separated list of all principal names in this token
     */
    @Override
    public String toString() {
    	final StringBuilder sb = new StringBuilder();
    	final Set<? extends Principal> principals = getPrincipals();
    	if (principals != null) {
    		for (final Principal principal : principals) {
    			if (sb.length() > 0) {
        			sb.append(", ");
    			}
    			sb.append(principal.getName());
    		}
    	}
    	return sb.toString();
    }
}
