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
package org.cesecore.authorization.user;

import java.util.HashMap;
import java.util.Map;

/**
 * Match with constants. OBSERVE These constants is also used as a priority indicator for access rules. The higher values the higher priority.
 * 
 * @version $Id$
 * 
 */
public enum X500PrincipalAccessMatchValue {
    NONE(0), WITH_COUNTRY(1), WITH_DOMAINCOMPONENT(2), WITH_STATEORPROVINCE(3), WITH_LOCALITY(4), WITH_ORGANIZATION(5), WITH_ORGANIZATIONALUNIT(6), WITH_TITLE(7), WITH_COMMONNAME(
            8), WITH_UID(9), WITH_DNSERIALNUMBER(10), WITH_SERIALNUMBER(11), WITH_DNEMAILADDRESS(12), WITH_RFC822NAME(13), WITH_UPN(14), WITH_FULLDN(15);

    private X500PrincipalAccessMatchValue(int numericValue) {
        this.numericValue = numericValue;
    }

    public int getNumericValue() {
        return numericValue;
    }
    
    public static X500PrincipalAccessMatchValue matchFromDatabase(Integer numericValue) {
        return lookup.get(numericValue);
    }

    private static Map<Integer, X500PrincipalAccessMatchValue> lookup;
    private int numericValue;
    
    static {
        lookup = new HashMap<Integer, X500PrincipalAccessMatchValue>();
        for(X500PrincipalAccessMatchValue value : X500PrincipalAccessMatchValue.values()) {
            lookup.put(value.numericValue, value);
        }
    }
    
    
}
