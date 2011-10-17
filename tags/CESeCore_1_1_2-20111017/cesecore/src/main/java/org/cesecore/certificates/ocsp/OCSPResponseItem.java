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

package org.cesecore.certificates.ocsp;

import java.io.Serializable;
import java.util.Date;

import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;

/**
 * Class used to encapsulate the data that goes into a OCSP response
 * 
 * Based on OCSPResponseItem.java 10328 2010-10-29 09:34:36Z anatom
 * 
 * @version $Id$
 */
public class OCSPResponseItem implements Serializable {

    /** Constants capturing the OCSP response status. 
     * These are the return codes defined in the RFC. 
     * The codes are just used for simple access to the OCSP return value. 
     */
    public static final int OCSP_GOOD = 0;
    public static final int OCSP_REVOKED = 1;
    public static final int OCSP_UNKNOWN = 2;

    
    private static final long serialVersionUID = 8520379864183774863L;
    
    private CertificateID certID;
    private CertificateStatus certStatus;
    /* RFC 2560 2.4: The time at which the status being indicated is known to be correct. */
    private Date thisUpdate;
    /*
     * RFC 2560 2.4: The time at or before which newer information will be available about the status of the certificate. If nextUpdate is not set,
     * the responder is indicating that newer revocation information is available all the time.
     */
    private Date nextUpdate = null;

    public OCSPResponseItem(CertificateID certID, CertificateStatus certStatus, long untilNextUpdate) {
        this.certID = certID;
        this.certStatus = certStatus;
        this.thisUpdate = new Date();
        if (untilNextUpdate > 0) {
            this.nextUpdate = new Date(this.thisUpdate.getTime() + untilNextUpdate);
        }
    }

    public CertificateID getCertID() {
        return certID;
    }

    public CertificateStatus getCertStatus() {
        return certStatus;
    }

    public Date getThisUpdate() {
        return thisUpdate;
    }

    public Date getNextUpdate() {
        return nextUpdate;
    }
}
