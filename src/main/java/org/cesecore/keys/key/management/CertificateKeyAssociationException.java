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
package org.cesecore.keys.key.management;

/**
 * @version $Id:$
 */
public class CertificateKeyAssociationException extends Exception {

    private static final long serialVersionUID = 1L;

    /**
     * @see Exception#Exception()
     */
    public CertificateKeyAssociationException() {
        super();
    }

    /**
     * @see Exception#Exception(String)
     */
    public CertificateKeyAssociationException(String arg0) {
        super(arg0);
    }

    /**
     * @see Exception#Exception(String,Throwable)
     */
    public CertificateKeyAssociationException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

    /**
     * @see Exception#Exception(Throwable)
     */
    public CertificateKeyAssociationException(Throwable arg0) {
        super(arg0);
    }

}
