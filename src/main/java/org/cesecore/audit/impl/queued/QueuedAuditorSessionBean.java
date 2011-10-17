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

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TimeZone;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.persistence.EntityManager;
import javax.persistence.FlushModeType;
import javax.persistence.PersistenceContext;
import javax.sql.DataSource;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.audit.SigningFileOutputStream;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.queued.entity.AuditLogData;
import org.cesecore.audit.impl.queued.management.LogManagementException;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;

/**
 * This class handles secure logs auditing.
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class QueuedAuditorSessionBean implements QueuedAuditorSessionLocal {

    private static final Logger log = Logger.getLogger(QueuedAuditorSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager em;
    private static DataSource ds;
    @Resource
    private SessionContext sessionContext;
    // Myself needs to be injected in postConstruct
    private QueuedAuditorSessionLocal queuedAuditorSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;

    @PostConstruct
    public void postConstruct() throws NamingException {
        final Context context = new InitialContext();
        if(ds == null) {
            ds = (DataSource) context.lookup(CesecoreConfiguration.getDataSourceJndiName());
        }
        queuedAuditorSession = sessionContext.getBusinessObject(QueuedAuditorSessionLocal.class);
    }
    
    @Override
    public List<? extends AuditLogEntry> selectAuditLogs(final AuthenticationToken token, final int startIndex, final int max, final QueryCriteria criteria, final Properties properties) {
        return AuditLogData.search(em, startIndex, max, criteria);
    }

    @Override
    public void delete(AuthenticationToken token, Date timestamp) {
        // get last signed log before the specified timestamp
        final AuditLogData lastSigned = AuditLogData.getLastSignedAuditLog(em, timestamp);
        final boolean delete = lastSigned != null;
        if (delete) {
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("timestamp", FastDateFormat.getTimeInstance(FastDateFormat.FULL, TimeZone.getTimeZone("GMT")).format(timestamp));
            securityEventsLogger.log(EventTypes.LOG_DELETE, EventStatus.VOID, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE,
                    token.toString(), null, null, null, details);
            
            if (log.isDebugEnabled()) {
                log.debug("deleting exported logs");
            }

            // important to set flushmode to commit (commit only occurs on flush or explicit commit)
            em.setFlushMode(FlushModeType.COMMIT);
            // delete till the obtained log.
            AuditLogData.delete(em, QueryCriteria.create().add(Criteria.lsr(AuditLogEntry.FIELD_SEQUENCENUMBER, lastSigned.getSequenceNumber())));
            em.flush();
        }
    }
    
    @Override
    public AuditLogExportReport exportAuditLogs(final AuthenticationToken token, final CryptoToken cryptoToken, final Date timestamp,
            final boolean deleteAfterExport, final Map<String, Object> signatureDetails, final Properties properties, final Class<? extends AuditExporter> c) throws AuditLogExporterException {
        final AuditLogExportReport report = new AuditLogExportReport();
        Connection conn = null;
        EventStatus status = EventStatus.SUCCESS;
        try {
            conn = ds.getConnection();
            final File exportFile = AuditDevicesConfig.getExportFile(properties, timestamp);
        	report.setExportedFile(exportFile.getCanonicalPath());
            final SigningFileOutputStream fos = new SigningFileOutputStream(exportFile, cryptoToken, signatureDetails);
            final AuditLogDbExporter exporter = new AuditLogDbExporter(em, fos, conn);
            try {
            	// get logs count till the specified timestamp
            	if (log.isDebugEnabled()) {
            		log.debug("exporting logs to file: " + exportFile.getAbsolutePath());
            	}
            	exporter.export(timestamp, c, AuditDevicesConfig.getAuditLogExportFetchSize(properties));            	
            } finally {
            	try {
            		fos.flush();
            	} catch (final IOException e) {
            		log.error("Can not flush output stream: ", e);
            	}
            	fos.close(); 
            }
            // sign the exported file ... it will write the signature on the side
            fos.writeSignature();
        } catch (final Exception e) {
        	log.warn(e.getMessage(), e);
        	status = EventStatus.FAILURE;
            throw new AuditLogExporterException(e.getMessage(), e);
        } finally {
            if (conn != null) {
                try {
                    conn.close();
                } catch (final SQLException e) {
                    throw new AuditLogExporterException(e.getMessage(), e);
                }
            }
        }
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("deleted", deleteAfterExport);
        details.put("timestamp", FastDateFormat.getTimeInstance(FastDateFormat.FULL, TimeZone.getTimeZone("GMT")).format(timestamp));
        securityEventsLogger.log(EventTypes.LOG_EXPORT, status, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE,
                token.toString(), null, null, null, details);
        if(deleteAfterExport) {
            queuedAuditorSession.delete(token, timestamp);
        }
        return report;
    }

    @Override
    public AuditLogValidationReport verifyLogsIntegrity(final AuthenticationToken token, final Date timestamp, final Properties properties) throws AuditLogValidatorException {

        Connection conn = null;
        try {
            conn = ds.getConnection();
            em.setFlushMode(FlushModeType.COMMIT);
            
            final AuditLogValidator validator = new AuditLogDbValidator(em, conn);
            final AuditLogValidationReport report = validator.validate(timestamp, AuditDevicesConfig.getAuditLogValidationFetchSize(properties));
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("timestamp", FastDateFormat.getTimeInstance(FastDateFormat.FULL, TimeZone.getTimeZone("GMT")).format(timestamp));
            // Success or failure depending on if verification returns error or not
            EventStatus status = EventStatus.SUCCESS;
            if (report.errors().size() > 0) {
            	status = EventStatus.FAILURE;
                details.put("errors", report.errors().size());
            }
            securityEventsLogger.log(EventTypes.LOG_VERIFY, status, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE,
                    token.toString(), null, null, null, details);
            return report;
        } catch (final SQLException e) {
            throw new AuditLogValidatorException(e.getMessage(), e);
        } finally {
            em.flush();
            if (conn != null) {
                try {
                    conn.close();
                } catch (final SQLException e) {
                    throw new AuditLogValidatorException(e.getMessage(), e);
                }
            }
        }
    }

    /**
     * Prepares the secure audit log mechanism for reset.
     * This method will block till all audit log processes are completed. 
     * Should be used with caution because once called audit log will not be operational. 
     * Any attemp to log will result in an exception.
     */
    @Override
    public void prepareReset() throws AuditLogResetException {
        if (log.isTraceEnabled()) {
            log.trace(">prepareReset");
        }
        AuditLogProcessQueue.prepareReset();
        if (log.isTraceEnabled()) {
            log.trace("<prepareReset");
        }
    }

    /**
     * Resets all security audit events logger internal state.
     * Once this method finishes the audit log will be available again.
     * This method should be used with caution.
     * @throws LogManagementException 
     */
    @Override
    public void reset() throws AuditLogResetException {
        if (log.isTraceEnabled()) {
            log.trace(">reset");
        }
        AuditLogProcessQueue.reset();
        if (log.isTraceEnabled()) {
            log.trace("<reset");
        }
    }
}
