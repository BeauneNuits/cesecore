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

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.cesecore.audit.AuditLogDevice;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.queued.management.LogManagementManager;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.time.TrustedTime;
import org.cesecore.util.query.QueryCriteria;

/**
 * @version $Id$
 */
public class QueuedDevice implements AuditLogDevice {

	private Map<Class<?>, ?> ejbs;

	@Override
	public void setEjbs(final Map<Class<?>, ?> ejbs) {
		this.ejbs = ejbs;
	}
	
	@SuppressWarnings("unchecked")
	private <T> T getEjb(final Class<T> c) {
		return (T) ejbs.get(c);
	}

	@Override
	public AuditLogExportReport exportAuditLogs(final AuthenticationToken token, final CryptoToken cryptoToken, final Date timestamp, final boolean deleteAfterExport, final Map<String, Object> signatureDetails, final Properties properties, final Class<? extends AuditExporter> c) throws AuditLogExporterException {
		return getEjb(QueuedAuditorSessionLocal.class).exportAuditLogs(token, cryptoToken, timestamp, deleteAfterExport, signatureDetails, properties, c);
	}

	@Override
	public List<? extends AuditLogEntry> selectAuditLogs(final AuthenticationToken token, final int startIndex, final int max, final QueryCriteria criteria, final Properties properties) {
		return getEjb(QueuedAuditorSessionLocal.class).selectAuditLogs(token, startIndex, max, criteria, properties);
	}

	@Override
	public AuditLogValidationReport verifyLogsIntegrity(final AuthenticationToken token, final Date date, final Properties properties) throws AuditLogValidatorException {
		return getEjb(QueuedAuditorSessionLocal.class).verifyLogsIntegrity(token, date, properties);
	}

	@Override
	public void log(final TrustedTime trustedTime, final EventType eventType, final EventStatus eventStatus, final ModuleType module, final ServiceType service, final String authToken, final String customId, final String searchDetail1,
			final String searchDetail2, final Map<String, Object> additionalDetails, final Properties properties) throws AuditRecordStorageException {
		getEjb(QueuedLoggerSessionLocal.class).log(trustedTime, eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails, properties);
	}

	@Override
	public boolean isSupportingQueries() {
		return true;
	}

	@Override
	public void prepareReset() throws AuditLogResetException {
	    getEjb(QueuedAuditorSessionLocal.class).prepareReset();
	}

	@Override
	public void reset() throws AuditLogResetException {
	    LogManagementManager.reset();
        getEjb(QueuedAuditorSessionLocal.class).reset();
	}
}
