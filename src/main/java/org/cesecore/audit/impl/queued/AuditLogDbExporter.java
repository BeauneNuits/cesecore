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

import java.io.IOException;
import java.io.OutputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;

import javax.persistence.EntityManager;

import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.impl.queued.entity.AuditLogData;
import org.cesecore.audit.impl.queued.entity.LogManagementData;

/**
 * This class handles audit log database export.
 * 
 * @version $Id$
 * 
 */
public class AuditLogDbExporter {
    
    private static final String LOG_LABEL = "logs";
    private static final String CONFIG_LABEL = "configs";

    private final EntityManager em;
    private final OutputStream stream;
    private final Connection conn;

    public AuditLogDbExporter(final EntityManager em, final OutputStream stream, final Connection conn) {
        this.em = em;
        this.stream = stream;
        this.conn = conn;
    }

    /**
     * Exports audit logs and validates till the specified date. Validation
     * occurs simultaneously with export. The result is a file named
     * cesecore-<timestamp>.log unless properties are changed.
     * 
     * @param timestamp
     *            indicates until which date audit logs will be exported.
     * @throws AuditLogExporterException
     */
    public void export(final Date timestamp, final Class<? extends AuditExporter> c, final int fetchSize) throws AuditLogExporterException {
        AuditExporter auditExporter = null;
        long time = timestamp.getTime();
        try {
            auditExporter = c.newInstance();
            auditExporter.setOutputStream(stream);
            auditExporter.startObjectLabel(LOG_LABEL);
            exportAuditLogData(auditExporter, time, fetchSize);
            auditExporter.endObjectLabel();
            auditExporter.startObjectLabel(CONFIG_LABEL);
            exportLogManagementData(auditExporter, time, fetchSize);
            auditExporter.endObjectLabel();
        } catch (final Exception e) {
            throw new AuditLogExporterException(e.getMessage(), e);
        } finally {
            if (auditExporter != null) {
                try {
                    auditExporter.close();
                } catch (final IOException e) {
                    throw new AuditLogExporterException(e.getMessage(), e);
                }
            }

        }

    }

    public void exportAuditLogData(final AuditExporter auditExporter, final long timestamp, final int fetchSize)
            throws AuditLogExporterException {
        ResultSet rs = null;
        PreparedStatement stmt = null;
        final String query = AuditLogData.getJdbcAuditLogsBeforeTimestampQuery();
        try {
            stmt = conn.prepareStatement(query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY, ResultSet.FETCH_FORWARD);
            stmt.setLong(1, timestamp);
            stmt.setFetchSize(fetchSize);
            stmt.setPoolable(true);
            rs = stmt.executeQuery();
            final AuditLogDbValidator validator = new AuditLogDbValidator(em, conn);
            while (rs.next()) {
                long id = rs.getLong(AuditLogData.FIELD_ID);
                long timeStamp = rs.getLong(AuditLogData.FIELD_TIMESTAMP);
                long sequenceNumber = rs.getLong(AuditLogData.FIELD_SEQUENCENUMBER);
                long configId = rs.getLong(AuditLogData.FIELD_CONFIG);
                String authToken = rs.getString(AuditLogData.FIELD_AUTHENTICATION_TOKEN);
                String eventType = rs.getString(AuditLogData.FIELD_EVENTTYPE);
                String eventStatus = rs.getString(AuditLogData.FIELD_EVENTSTATUS);
                String moduleType = rs.getString(AuditLogData.FIELD_MODULE);
                String additionalDetails = rs.getString(AuditLogData.FIELD_ADDITIONAL_DETAILS);
                String signature = rs.getString(AuditLogData.FIELD_SIGNATURE);
                String serviceType = rs.getString(AuditLogData.FIELD_SERVICE);

                AuditLogData.toExport(auditExporter, id, timeStamp, eventType, eventStatus, authToken, serviceType, moduleType, additionalDetails,
                        signature, sequenceNumber, configId);
                validator.validate(id, timeStamp, eventType, eventStatus, authToken, serviceType, moduleType, additionalDetails, signature,
                        sequenceNumber, configId);
            }
        } catch (final Exception e) {
            throw new AuditLogExporterException(e.getMessage(), e);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (final SQLException e) {
                    throw new AuditLogExporterException(e.getMessage(), e);
                } finally {
                    if (stmt != null) {
                        try {
                            stmt.close();
                        } catch (final SQLException e) {
                            throw new AuditLogExporterException(e.getMessage(), e);
                        }
                    }
                }
            }
        }
    }

    public void exportLogManagementData(final AuditExporter auditExporter, final long timestamp, final int fetchSize)
            throws AuditLogExporterException {
        PreparedStatement stmt = null;
        ResultSet rs = null;
        try {
            final String configQuery = LogManagementData.JDBC_LOG_MANAGEMENT_IN_BY_ID;
            
            stmt = conn.prepareStatement(configQuery, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY, ResultSet.FETCH_FORWARD);
            stmt.setLong(1, timestamp);
            stmt.setFetchSize(fetchSize);
            stmt.setPoolable(true);
            rs = stmt.executeQuery();
            while (rs.next()) {
                long id = rs.getLong(LogManagementData.FIELD_ID);
                long time = rs.getLong(LogManagementData.FIELD_TIMESTAMP);
                String signMode = rs.getString(LogManagementData.FIELD_SIGNMODE);
                long frequency = rs.getLong(LogManagementData.FIELD_FREQUENCY);
                String details = rs.getString(LogManagementData.FIELD_DETAILS);
                LogManagementData.toExport(auditExporter, id, time, signMode, frequency, details);
            }
        } catch (final Exception e) {
            throw new AuditLogExporterException(e.getMessage(), e);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (final SQLException e) {
                    throw new AuditLogExporterException(e.getMessage(), e);
                } finally {
                    if (stmt != null) {
                        try {
                            stmt.close();
                        } catch (final SQLException e) {
                            throw new AuditLogExporterException(e.getMessage(), e);
                        }
                    }
                }
            }
        }
    }
}
