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

import java.security.Principal;
import java.security.SecureRandom;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;

/**
 * Common base class for tokens that are only valid in the JVM they are created and could
 * otherwise be spoofed. E.g. X509 client certificate validation AuthenticationToken could
 * otherwise be created and sent to a remote EJB interface.
 * 
 * Based on the work by Markus Kilås.  
 * 
 * @version $Id$
 */
public abstract class LocalJvmOnlyAuthenticationToken extends AuthenticationToken {

	private static final long serialVersionUID = 1L;

	/** A random token that is unique to this JVM (e.g. the application server JVM and a CLI JVM does not have the same token). */
	private static final byte[] RANDOM_TOKEN = createRandomToken();

    /** transient authToken should NOT be serialized. **/
    private transient byte[] authToken;

    /** @see org.cesecore.authentication.tokens.AuthenticationToken.AuthenticationToken(Set<? extends Principal>, Set<?>) */
	protected LocalJvmOnlyAuthenticationToken(Set<? extends Principal> principals, Set<?> credentials) {
		super(principals, credentials);
		authToken = RANDOM_TOKEN;
	}
	
	/** @return true if this */
	protected final boolean isCreatedInThisJvm() {
		return ArrayUtils.isEquals(authToken, RANDOM_TOKEN);
	}

	public void initRandomToken() {
		authToken = RANDOM_TOKEN;
	}

	private static byte[] createRandomToken() {
    	final byte[] token = new byte[32];
        new SecureRandom().nextBytes(token);
    	return token;
	}
}
