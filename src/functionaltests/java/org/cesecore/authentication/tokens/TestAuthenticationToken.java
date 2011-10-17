package org.cesecore.authentication.tokens;

import java.security.Principal;
import java.util.Set;

import org.cesecore.authorization.user.AccessUserAspect;

/**
 * Simple AuthenticationToken that always returns true for any match.
 * 
 * Should only be included in the server-side JVM when functional tests should be run.  
 * 
 * @version $Id$
 */
public class TestAuthenticationToken extends AuthenticationToken {

	private static final long serialVersionUID = 1L;
	
	public TestAuthenticationToken(Set<? extends Principal> principals, Set<?> credentials) {
		super(principals, credentials);
	}

	@Override
	public boolean matches(AccessUserAspect accessUser) {
		return true;
	}
	
    @Override
    public boolean equals(Object authenticationToken) {
        return true;
    }

    @Override
    public int hashCode() {
        return 0;
    }
}
