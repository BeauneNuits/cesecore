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
package org.cesecore.audit.impl.queued;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.cesecore.audit.impl.queued.entity.AuditLogData;

/**
 * Audit logs consumer process.
 * 
 * @version $Id$
 * 
 */
public final class AuditLogProcess implements Serializable, Comparable<AuditLogProcess> {

    private static final long serialVersionUID = 1L;

    private AuditLogData auditLogData;
    private CountDownLatch depsCount;
    private List<AuditLogProcess> waiting;

    public AuditLogProcess(final AuditLogData auditLogData) {
        this.auditLogData = auditLogData.clone();
        this.depsCount = new CountDownLatch(0);
        this.waiting = new ArrayList<AuditLogProcess>();
    }

    public AuditLogData getAuditLogData() {
        return auditLogData;
    }

    public void setAuditLogData(final AuditLogData auditLogData) {
        this.auditLogData = auditLogData;
    }

    public CountDownLatch getDepsCount() {
        return depsCount;
    }

    public void setDepsCount(final CountDownLatch depsCount) {
        this.depsCount = depsCount;
    }

    public List<AuditLogProcess> getWaiting() {
        return this.waiting;
    }

    public void addWaitingProcess(final AuditLogProcess process) {
        this.waiting.add(process);
    }

	@Override
	public int compareTo(AuditLogProcess o) {
	    return this.getAuditLogData().compareTo(o.getAuditLogData());
	}

    
}
