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
package org.cesecore.audit.impl.integrityprotected;

import java.io.File;
import java.io.IOException;
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
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogReportElem;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.audit.SigningFileOutputStream;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.dbprotection.DatabaseProtectionError;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.QueryGenerator;

/**
 * This class handles secure logs auditing.
 * 
 * This was created to evaluate the performance of using database integrity protection
 * instead of custom code for log singing.
 * 
 * The index
 *  "CREATE UNIQUE INDEX auditrecorddata_idx1 ON AuditRecordData (nodeId,timeStamp,sequenceNumber);"
 * should be present for proper validation and export performance.
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class IntegrityProtectedAuditorSessionBean implements IntegrityProtectedAuditorSessionLocal {

	private static final Logger log = Logger.getLogger(IntegrityProtectedAuditorSessionBean.class);
	
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    @Resource
    private SessionContext sessionContext;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;
    // Myself needs to be injected in postConstruct
    private IntegrityProtectedAuditorSessionLocal integrityProtectedAuditorSession;

    @PostConstruct
    public void postConstruct() {
    	integrityProtectedAuditorSession = sessionContext.getBusinessObject(IntegrityProtectedAuditorSessionLocal.class);
    }

	@Override
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public AuditLogExportReport exportAuditLogs(final AuthenticationToken token, final CryptoToken cryptoToken, final Date timestamp, final boolean deleteAfterExport,
			final Map<String, Object> signatureDetails, final Properties properties, final Class<? extends AuditExporter> c) throws AuditLogExporterException {
        final AuditLogExportReport report = new AuditLogExportReport();
        try {
            final File exportFile = AuditDevicesConfig.getExportFile(properties, timestamp);
            final SigningFileOutputStream signingFileOutputStream = new SigningFileOutputStream(exportFile, cryptoToken, signatureDetails);
            final AuditExporter auditExporter = c.newInstance();
            auditExporter.setOutputStream(signingFileOutputStream);
            verifyAndOptionalExport(auditExporter, report, timestamp, AuditDevicesConfig.getAuditLogExportFetchSize(properties));
        	report.setExportedFile(exportFile.getCanonicalPath());
        	if (log.isDebugEnabled()) {
        		log.debug("Exported " + report.getExportCount() + " rows.");
        	}
        	logVerificationResult(report.errors().size(), timestamp, token);
            // Sign the exported file ... it will write the signature on the side
            final String signatureFilename = signingFileOutputStream.writeSignature();
            report.setSignatureFile(signatureFilename);
            // Log export success
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("deleteAfterExport", deleteAfterExport);
            details.put("timestamp", ValidityDate.formatAsISO8601(new Date(), ValidityDate.TIMEZONE_UTC));
            securityEventsLogger.log(EventTypes.LOG_EXPORT, EventStatus.SUCCESS, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, token.toString(), null, null, null, details);
        	// Delete the exported log entries if requested
            if (deleteAfterExport) {
                if (log.isDebugEnabled()) {
                    log.debug("deleting exported logs");
                }
        		final int deletedRowCount = integrityProtectedAuditorSession.deleteRows(token, timestamp, properties);
        		if (log.isDebugEnabled()) {
        			log.debug("Deleted " + deletedRowCount + " rows from audit log after export.");
        		}
            }
            auditExporter.close();
        } catch (final Exception e) {
        	throw new AuditLogExporterException(e.getMessage(), e);
        }
        return report;
	}
	
	/* Since we modify the database we need to run this in a transaction. */
	@Override
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public int deleteRows(final AuthenticationToken token, final Date timestamp, final Properties properties) {
        final Map<String, Object> detailsDelete = new LinkedHashMap<String, Object>();
        detailsDelete.put("timestamp", FastDateFormat.getInstance(ValidityDate.ISO8601_DATE_FORMAT, TimeZone.getTimeZone("GMT")).format(timestamp));
        securityEventsLogger.log(EventTypes.LOG_DELETE, EventStatus.VOID, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, token.toString(), null, null, null, detailsDelete);
        // Delete all the exported logs (from all nodes)
		final QueryCriteria queryCriteria = QueryCriteria.create().add(Criteria.leq("timeStamp", timestamp.getTime())).add(Criteria.orderAsc("sequenceNumber"));
        final QueryGenerator generator = QueryGenerator.generator(AuditRecordData.class, queryCriteria, "a");
		return buildConditionalQuery(entityManager, "DELETE FROM AuditRecordData a", generator, 0, 0).executeUpdate();
	}

	@Override
	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	public List<? extends AuditLogEntry> selectAuditLogs(final AuthenticationToken token, final int startIndex, final int max, final QueryCriteria criteria, final Properties properties) {
        final QueryGenerator generator = QueryGenerator.generator(AuditRecordData.class, criteria, "a");
        return internalSelectAuditLogs(startIndex, max, generator);
	}
	
	@Override
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public AuditLogValidationReport verifyLogsIntegrity(final AuthenticationToken token, final Date timestamp, final Properties properties) throws AuditLogValidatorException {
        final AuditLogValidationReport report = new AuditLogValidationReport();
        try {
            verifyAndOptionalExport(null, report, timestamp, AuditDevicesConfig.getAuditLogExportFetchSize(properties));
        	// Log the success or failure depending on if verification returns error or not
        	logVerificationResult(report.errors().size(), timestamp, token);
        } catch (final Exception e) {
        	throw new AuditLogValidatorException(e.getMessage(), e);
        }
        return report;
	}

	/**
	 * Read batches of logs from the database. If the database integrity check fails, the batch will be processed row by row.
	 * Results are added to the report.
	 * @param auditExporter can be null if no export should take place
	 * @param report is a AuditLogValidationReport or AuditLogExportReport
	 * @param timestamp process all entries up until this time (should be epoch GMT)
	 */
	private void verifyAndOptionalExport(final AuditExporter auditExporter, final AuditLogValidationReport report, final Date timestamp, final int fetchSize) throws IOException {
    	// Get a list of the nodes that have data in the database
    	for (final String nodeId : getNodeIds()) {
    		if (log.isDebugEnabled()) {
    			log.debug("exportAuditLogs for nodeId " + nodeId);
    		}
    		// Assuming timeStamp is in UTC
    		final QueryCriteria queryCriteria = QueryCriteria.create().add(Criteria.eq("nodeId", nodeId)).add(Criteria.leq("timeStamp", timestamp.getTime())).add(Criteria.orderAsc("sequenceNumber"));
            final QueryGenerator generator = QueryGenerator.generator(AuditRecordData.class, queryCriteria, "a");
    		int startIndex = 1;
    		final Holder<Long> lastSeqNumber = new Holder<Long>(Long.valueOf(-1L));
    		while (true) {
    			try {
        			final List<AuditRecordData> queryResult = verifyLogsIntegritySubset(startIndex, fetchSize, generator, report, lastSeqNumber, nodeId);
    				final int results = queryResult.size();
    				if (results == 0) {
    					break;	// No more data for this node
    				}
    				startIndex += results;
					if (auditExporter!=null) {
						for (final AuditRecordData auditRecordData : queryResult) {
							writeToExport(auditExporter, auditRecordData);
        					((AuditLogExportReport) report).incExportCount();
						}
					}
    			} catch (final DatabaseProtectionError e) {
    				// One of the FETCH_SIZE entries failed.. we have to go through line by line to find out witch one..
    				for (int i=0; i<fetchSize; i++) {
        				try {
                			final List<AuditRecordData> queryResult = verifyLogsIntegritySubset(startIndex, 1, generator, report, lastSeqNumber, nodeId);
            				final int results = queryResult.size();
            				if (results != 1) {
            					break;	// No more data for this node
            				}
        					if (auditExporter!=null) {
        						writeToExport(auditExporter, queryResult.get(0));
            					((AuditLogExportReport) report).incExportCount();
        					}
        				} catch (final DatabaseProtectionError e2) {
        					final AuditRecordData auditRecordData = (AuditRecordData) e2.getEntity();
        					// Add to report
        					report.warn(new AuditLogReportElem(lastSeqNumber.get().longValue(), auditRecordData.getSequenceNumber(), "log with sequence number after " + lastSeqNumber.get() + " on nodeId '" + nodeId + "' could not be verified"));
        					lastSeqNumber.set(auditRecordData.getSequenceNumber());
        					// We still export it
        					// TODO: It might make sense to make it configurable to export when verification fails..
        					if (auditExporter!=null) {
            					writeToExport(auditExporter, auditRecordData);
            					((AuditLogExportReport) report).incExportCount();
        					}
        				}
        				startIndex += 1;
    				}
    			}
    		}
    	}
	}

	/** We want to export exactly like it was stored in the database, to comply with requirements on logging systems where no altering of the original log data is allowed. */
    private void writeToExport(final AuditExporter auditExporter, final AuditRecordData auditRecordData) throws IOException {
        auditExporter.writeStartObject();
        auditExporter.writeField("pk", auditRecordData.getPk());
        auditExporter.writeField("nodeId", auditRecordData.getNodeId());
        auditExporter.writeField("sequenceNumber", auditRecordData.getSequenceNumber());
        auditExporter.writeField("timestamp", auditRecordData.getTimeStamp());
        auditExporter.writeField("eventType", auditRecordData.getEventTypeValue().toString());
        auditExporter.writeField("eventStatus", auditRecordData.getEventStatusValue().toString());
        auditExporter.writeField("authToken", auditRecordData.getAuthToken());
        auditExporter.writeField("service", auditRecordData.getServiceTypeValue().toString());
        auditExporter.writeField("module", auditRecordData.getModuleTypeValue().toString());
        auditExporter.writeField("customId", auditRecordData.getCustomId());
        auditExporter.writeField("searchDetail1", auditRecordData.getSearchDetail1());
        auditExporter.writeField("searchDetail2", auditRecordData.getSearchDetail2());
        auditExporter.writeField("additionalDetails", auditRecordData.getAdditionalDetails());
        auditExporter.writeField("rowProtection", auditRecordData.getRowProtection());
        auditExporter.writeEndObject();
    }
    
    /**
     * Fetch a batch of log rows from the database (implying database integrity check) and verifies
     * that all sequence numbers are present.
     * @param startIndex start batch from this position 
     * @param max entries per batch
     * @param queryCriteria where clause
     * @param report will be updated when a problem is found
     * @param lastSeqNumber will be updated to the last sequence number processed in this subset
     * @param nodeId identifier of which node that claims to have written this data
     * @return the log entries we fetched from the database so the caller may export these
     * @throws DatabaseProtectionError if the intregrity verification fails for one of the entries in the batch during fetch
     */
	private List<AuditRecordData> verifyLogsIntegritySubset(final int startIndex, final int max, final QueryGenerator generator, final AuditLogValidationReport report, final Holder<Long> lastSeqNumber, final String nodeId) throws DatabaseProtectionError {
		final List<AuditRecordData> queryResult = internalSelectAuditLogs(startIndex, max, generator);	// Might throw DatabaseProtectionError
		// Loop through results and verify that the sequence order is correct
		for (int i=0; i<queryResult.size(); i++) {
			final long currentSeqNumber = queryResult.get(i).getSequenceNumber().longValue();
			if (currentSeqNumber != lastSeqNumber.get().longValue() + 1) {
				if (log.isDebugEnabled()) {
					log.debug("Log verification failure for log on node '" + nodeId + "'. Missing entry. Last sequenceNumber was " + lastSeqNumber.get() + " and current is " + currentSeqNumber);
				}
				// Add to report
				report.warn(new AuditLogReportElem(lastSeqNumber.get(), Long.valueOf(currentSeqNumber), "missing log with sequence number " + (lastSeqNumber.get().longValue() + 1) + " on nodeId '" + nodeId+"'"));
			}
			lastSeqNumber.set(Long.valueOf(currentSeqNumber));
		}
		return queryResult;
	}
	
	/** Log the outcome of the verification to the secure audit log based on the supplied number of errors. */
	private void logVerificationResult(final int errors, final Date timestamp, final AuthenticationToken token) {
    	final Map<String, Object> details = new LinkedHashMap<String, Object>();
    	details.put("timestamp", FastDateFormat.getInstance(ValidityDate.ISO8601_DATE_FORMAT, TimeZone.getTimeZone("GMT")).format(timestamp));
    	EventStatus status = EventStatus.SUCCESS;
    	if (errors > 0) {
    		status = EventStatus.FAILURE;
    		details.put("errors", errors);
    	}
    	securityEventsLogger.log(EventTypes.LOG_VERIFY, status, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, token.toString(), null, null, null, details);
	}

	/**
	 * Select log entries using the supplied criteria.
	 * Optionally using startIndex and resultLimit (used if >0).
	 */
	@SuppressWarnings("unchecked")
	private List<AuditRecordData> internalSelectAuditLogs(final int startIndex, final int max, final QueryGenerator generator) {
        return buildConditionalQuery(entityManager, "SELECT a FROM AuditRecordData a", generator, startIndex, max).getResultList();
	}
	
	/** @return a unique list of node identifiers that have been writing audit log to the database. */
	@SuppressWarnings("unchecked")
	private List<String> getNodeIds() {
		return entityManager.createQuery("SELECT DISTINCT a.nodeId FROM AuditRecordData a").getResultList();
	}

	/**
	 * Build a JPA Query from the supplied queryStr and criteria.
	 * Optionally using startIndex and resultLimit (used if >0).
	 */
    private Query buildConditionalQuery(final EntityManager entityManager, final String queryStr, final QueryGenerator generator, final int startIndex, final int resultLimit) {
        Query query = null;
        if (generator == null) {
            query = entityManager.createQuery(queryStr);
        } else {
            final String str = queryStr + generator.generate();
            if (log.isDebugEnabled()) {
                log.debug("Running query: "+str+", resultLimit="+resultLimit+", startIndex="+startIndex);
            }
            query = entityManager.createQuery(str);
            for (final String key : generator.getParameterKeys()) {
                if (log.isDebugEnabled()) {
                    log.debug("Setting param "+key+", "+generator.getParameterValue(key));
                }
                query.setParameter(key, generator.getParameterValue(key));
            }
        }
        if (resultLimit > 0) {
            query.setMaxResults(resultLimit);
        }
        if (startIndex > 0) {
        	query.setFirstResult(startIndex-1);
        }
        return query;
    }
    
    /** Class used internally for holding an object that can updated by a method. */
    private class Holder<T> {
    	private T object;
    	Holder(final T object) { set(object); }
		public void set(final T object) { this.object = object; }
		public T get() { return object; }
    }
}
