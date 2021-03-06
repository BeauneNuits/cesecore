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

package org.cesecore.util;

import java.util.LinkedHashMap;
import java.util.Map;


/**
 * An implementation of HashMap that base64 encodes all String's that you 'put', it encodes them to form "B64:<base64 encoded string>". It only
 * encodes objects of type String.
 * 
 * Based on Base64PutHashMap.java 8373 2009-11-30 14:07:00Z jeklund from EJBCA
 * 
 * TODO: Look over this object, see if it can be implemented with generics.
 * 
 * @version $Id$
 */
public class Base64PutHashMap extends LinkedHashMap {

    private static final long serialVersionUID = 785586648964618032L;

    public Base64PutHashMap() {
        super();
    }

    public Base64PutHashMap(Map m) {
        super(m);
    }

    public Object put(Object key, Object value) {
        if (value == null) {
            return super.put(key, value);
        }
        if (value instanceof String) {
            String s = StringTools.putBase64String((String) value, true);
            return super.put(key, s);
        }
        return super.put(key, value);
    }

}
