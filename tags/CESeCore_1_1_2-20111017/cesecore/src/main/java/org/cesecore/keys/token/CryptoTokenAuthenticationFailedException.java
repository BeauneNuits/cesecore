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
package org.cesecore.keys.token;

import org.cesecore.CesecoreException;


/**
 * An exception thrown when authentication to HardCATokens fail.
 *
 * Based on EJBCA's: CATokenAuthenticationFailedException.java 8373 2009-11-30 14:07:00Z jeklund
 * 
 * @version $Id$
 */
public class CryptoTokenAuthenticationFailedException extends CesecoreException {
    
    private static final long serialVersionUID = -1444838755654213775L;


    /**
     * Creates a new instance of <code>CATokenAuthenticationFailedException</code> without detail message.
     */
    public CryptoTokenAuthenticationFailedException() {
        super();
    }
    
    
    /**
     * Constructs an instance of <code>CATokenAuthenticationFailedException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CryptoTokenAuthenticationFailedException(String msg) {
        super(msg);
    }
}
