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

/**
 * 
 * Utility class for validation, i.e for model field validation
 * 
 * @version $Id$
 * 
 */
public abstract class Validator {

    public enum Result {
        VALID, FAIL
    }

    public static Result notNull(final Object... obj) {
        for (final Object o : obj) {
            if (o == null) {
                return Result.FAIL;
            }
        }
        return Result.VALID;
    }

    public static <T extends Comparable<T>> Result inRange(final T lower, final T higher, final T... obj) {
        for (final T o : obj) {
            if (o.compareTo(lower) < 0 || o.compareTo(higher) > 0) {
                return Result.FAIL;
            }
        }
        return Result.VALID;
    }
    
    public static <T extends Comparable<T>> Result notLower(final T lower, final T... obj) {
        for (final T o : obj) {
            if (o.compareTo(lower) < 0) {
                return Result.FAIL;
            }
        }
        return Result.VALID;
    }
    
    public static <T extends Comparable<T>> Result isGreater(final T higher, final T... obj) {
        for (final T o : obj) {
            if (o.compareTo(higher) > 0) {
                return Result.FAIL;
            }
        }
        return Result.VALID;
    }
    
    public static <T extends Comparable<T>> Result isEqual(final T value, final T... obj) {
        for (final T o : obj) {
            if (o.compareTo(value) != 0) {
                return Result.FAIL;
            }
        }
        return Result.VALID;
    }

}
