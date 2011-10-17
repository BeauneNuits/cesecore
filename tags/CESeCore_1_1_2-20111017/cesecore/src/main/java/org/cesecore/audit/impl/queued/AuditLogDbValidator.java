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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.impl.queued.entity.AuditLogData;
import org.cesecore.audit.impl.queued.entity.LogManagementData;

/**
 * 
 * Audit log Database validation implementation.
 *
 * @version $Id$
 *
 */
public class AuditLogDbValidator extends AuditLogValidator {
    private static final Logger log = Logger.getLogger(AuditLogDbValidator.class);

    private Connection conn = null;
    private EntityManager em;

    public AuditLogDbValidator(final EntityManager em, final Connection conn) {
        super();
        this.conn = conn;
        this.em = em;
    }

    protected LogManagementData getConfiguration(final Long id) {
        return LogManagementData.findById(em, id);
    }

    /**
     * Audit log validation till the specified timestamp. Any potential validation error will be stored in this instance report.
     *
     * @param timestamp
     *          Timestamp till which audit logs will be validated.
     *
     * @throws AuditLogValidatorException
     */
    public AuditLogValidationReport validate(final Date timestamp, final int fetchSize) throws AuditLogValidatorException {
        ResultSet rs = null;
        PreparedStatement stmt = null;
        try {
            final String query = AuditLogData.getJdbcAuditLogsBeforeTimestampQuery();
            stmt = conn.prepareStatement(query, ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY, ResultSet.FETCH_FORWARD);
            stmt.setLong(1, timestamp.getTime());
            stmt.setFetchSize(fetchSize);
            stmt.setPoolable(true);

            rs = stmt.executeQuery();
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
                validate(id, timeStamp, eventType, eventStatus, authToken, serviceType, moduleType, additionalDetails, signature,
                        sequenceNumber, configId);
            }

            return getReport();
        } catch (final SQLException e) {
            throw new AuditLogValidatorException(e.getMessage(), e);
        } finally {
            if (rs != null) {
                try {
                    rs.close();
                } catch (final SQLException e) {
                    throw new AuditLogValidatorException(e.getMessage(), e);
                } finally {
                    if (stmt != null) {
                        try {
                            stmt.close();
                        } catch (final SQLException e) {
                            throw new AuditLogValidatorException(e.getMessage(), e);
                        }
                    }
                }
            }
        }
    }

}
