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
package org.cesecore.audit.impl.queued.entity;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.FlushModeType;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypeHolder;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ModuleTypeHolder;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.enums.ServiceTypeHolder;
import org.cesecore.util.JsonSerializer;
import org.cesecore.util.QueryResultWrapper;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.QueryGenerator;
import org.codehaus.jackson.JsonGenerationException;
import org.hibernate.annotations.Index;

/**
 * 
 * This class represents the secure audit log.
 * 
 * @version $Id$
 * 
 */
@Entity
@Table(name = "AuditLogData")
@NamedQueries({
        @NamedQuery(name = "AuditLogData.LIST", query = "SELECT a FROM AuditLogData a"),
        @NamedQuery(name = "AuditLogData.COUNT", query = "SELECT COUNT(a) FROM AuditLogData a"),
        @NamedQuery(name = "AuditLogData.findByBetweenSequenceNumber", query = "SELECT a FROM AuditLogData a WHERE a.sequenceNumber BETWEEN :first AND :second ORDER BY a.sequenceNumber"),
        @NamedQuery(name = "AuditLogData.MAXSEQ", query = "SELECT MAX(a.sequenceNumber) FROM AuditLogData a"),
        @NamedQuery(name = "AuditLogData.LASTSIGNED", query = "SELECT a FROM AuditLogData a WHERE a.signature IS NOT NULL AND a.timeStamp <= :timeStamp ORDER BY a.sequenceNumber DESC"),
        @NamedQuery(name = "AuditLogData.LASTUNSIGNSEQ", query = "SELECT a FROM AuditLogData a where a.signature IS NULL AND a.sequenceNumber > :sequenceNumber ORDER BY a.sequenceNumber ASC") })
public class AuditLogData implements Serializable, Comparable<AuditLogData>,
        AuditLogEntry {

    private static final long serialVersionUID = 7661635422171398594L;
    private static final Logger log = Logger.getLogger(AuditLogData.class);

    public static final String FIELD_ID = "id";
    public static final String FIELD_SIGNATURE = "signature";
    public static final String FIELD_CONFIG = "config_id";

    private Long id;
    private Long timeStamp;
    private String eventType;
    private EventStatus eventStatus;
    private String authToken;
    private String service;
    private String module;
    private String additionalDetails;
    private String signature;
    private Long sequenceNumber;
    private LogManagementData config;

    /**
     * Gets id.
     * 
     * @return
     */
    public Long getId() {
        return id;
    }

    /**
     * Sets id.
     * 
     * @param id
     */
    public void setId(final Long id) {
        this.id = id;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.cesecore.audit.entity.AuditLog#getTimestamp()
     */
    @Index(name = "auditlogdata_timestamp_index")
    @Override
    public Long getTimeStamp() {
        return timeStamp;
    }

    /**
     * Sets Timestamp.
     * 
     * @param timestamp
     */
    public void setTimeStamp(final Long timeStamp) {
        this.timeStamp = timeStamp;
    }

    public String getEventType() {
        return eventType;
    }

    /**
     * Sets event type. @see EventTypes String should match the enumeration
     * names.
     * 
     * @param eventType
     */
    public void setEventType(final String eventType) {
        this.eventType = eventType;
    }

    /**
     * Sets event type. @see EventTypes
     * 
     * @param eventType
     */
    public void setEventType(final EventType eventType) {
        this.eventType = eventType.toString();
    }

    public EventStatus getEventStatus() {
        return eventStatus;
    }

    /**
     * Sets event status. @see EventStatusEnum
     * 
     * @param eventStatus
     */
    public void setEventStatus(final EventStatus eventStatus) {
        this.eventStatus = eventStatus;
    }

    @Override
    public String getAuthToken() {
        return authToken;
    }

    /**
     * Sets the user that triggered the creation of a log
     * 
     * @param userId
     *            user id. Normally obtained by the following example:
     *            authenticationToken.toString()
     */
    public void setAuthToken(final String authToken) {
        this.authToken = authToken;
    }

    public String getService() {
        return service;
    }

    /**
     * Sets service type. @see ServiceTypes
     * 
     * @param service
     */
    public void setService(final String service) {
        this.service = service;
    }

    /**
     * Sets service type. @see ServiceTypes
     * 
     * @param service
     */
    public void setService(final ServiceType service) {
        this.service = service.toString();
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.cesecore.audit.entity.AuditLog#getModule()
     */
    public String getModule() {
        return module;
    }

    /**
     * Sets module type. @see ModuleTypes
     * 
     * @param module
     *            Module type.
     */
    public void setModule(final String module) {
        this.module = module;
    }

    /**
     * Sets module type. @see ModuleTypes
     * 
     * @param module
     *            Module type.
     */
    public void setModule(final ModuleType module) {
        this.module = module.toString();
    }

    /**
     * Gets additional details in JSON format.
     * 
     * @return additional details.
     */
    public String getAdditionalDetails() {
        return additionalDetails;
    }

    /**
     * Sets additional details in JSON format.
     * 
     * @param additionalDetails
     */
    public void setAdditionalDetails(final String additionalDetails) {
        this.additionalDetails = additionalDetails;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.cesecore.audit.entity.AuditLog#getMapAdditionalDetails()
     */
    @Transient
    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> getMapAdditionalDetails() {
        Map<String, Object> result = null;
        try {
            result = (Map<String, Object>) JsonSerializer
                    .fromJSON(this.additionalDetails);
        } catch (final IOException e) {
            log.error(e.getMessage(), e);
        }
        return result;
    }

    /**
     * Sets additional details.
     * 
     * @param additionalDetails
     *            .
     */
    @Transient
    public void setMapAdditionalDetails(
            final Map<String, Object> additionalDetails) {
        try {
            this.additionalDetails = JsonSerializer.toJSON(additionalDetails);
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    /**
     * Gets log signature.
     * 
     * @return signature in b64.
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Sets log signature.
     * 
     * @param signature
     *            signature should be coded in b64.
     * 
     */
    public void setSignature(final String signature) {
        this.signature = signature;
    }

    @Index(name = "auditlogdata_sequencenumber_index")
    @Override
    public Long getSequenceNumber() {
        return sequenceNumber;
    }

    /**
     * Sets sequence number.
     * 
     * @param sequenceNumber
     *            This number MUST be unique.
     * 
     */
    public void setSequenceNumber(final Long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    /**
     * Gets the audit log configuration in place at time of creation.
     * 
     * @return configuration.
     */
    public LogManagementData getConfig() {
        return config;
    }

    /**
     * Association with configuration.
     * 
     * @param config
     *            Configuration to be associated. Normally the one that is
     *            currently in place.
     */
    public void setConfig(final LogManagementData config) {
        this.config = config;
    }

    public boolean willBeSigned() {
        return getEventType().equals(EventTypes.LOG_SIGN.toString())
                || getEventType().equals(
                        EventTypes.LOG_MANAGEMENT_CHANGE.toString())
                || getConfig().getFrequency() == 0;
    }

    /**
     * Persists audit log to database.
     * 
     */
    public void save(final EntityManager em) {
        em.persist(this);
    }

    /**
     * Gets the number of logs in database.
     * 
     * @param em
     *            EntityManager used to count the number of logs.
     * 
     * @return count
     */
    public static long count(final EntityManager em) {
        return ((Long) em.createNamedQuery("AuditLogData.COUNT")
                .getSingleResult()).longValue();
    }

    /**
     * Gets the number of logs in database based on a criteria. @see
     * QueryCriteria
     * 
     * @param em
     *            EntityManager.
     * @param criteria
     *            criteria clause.
     * 
     * @return count
     */
    public static long count(final EntityManager em,
            final QueryCriteria criteria) {
        final Query query = buildConditionalQuery(em,
                "SELECT COUNT(a.id) FROM AuditLogData a", criteria, 0);
        return (Long) query.getSingleResult();
    }

    /**
     * Retrieves all logs without pagination.
     * 
     * @param em
     *            EntityManager
     * 
     * @return list.
     */
    @SuppressWarnings("unchecked")
    public static List<AuditLogData> list(final EntityManager em) {
        return em.createNamedQuery("AuditLogData.LIST").getResultList();
    }

    @SuppressWarnings("unchecked")
    public static LinkedList<AuditLogData> findByBetweenSequenceNumber(
            final EntityManager em, final long first, final long second) {
        final Query query = em
                .createNamedQuery("AuditLogData.findByBetweenSequenceNumber");
        query.setParameter("first", first);
        query.setParameter("second", second);
        return new LinkedList<AuditLogData>(query.getResultList());
    }

    private static Query buildConditionalQuery(final EntityManager em,
            final String queryStr, final QueryCriteria criteria,
            final int resultLimit) {
        Query query = null;
        if (criteria != null) {
            QueryGenerator generator = QueryGenerator.generator(AuditLogData.class, criteria, "a");
            final String conditions = generator.generate();
            if (log.isTraceEnabled()) {
                log.trace("Conditions: " + conditions);
            }
            query = em.createQuery(queryStr + conditions);
            for (final String key : generator.getParameterKeys()) {
                final Object param = generator.getParameterValue(key);
                if (log.isTraceEnabled()) {
                    log.trace("Param: " + param.toString());
                }
                query.setParameter(key, param);
            }
            if (resultLimit > 0) {
                query.setMaxResults(resultLimit);
            }
        } else {
            query = em.createQuery(queryStr);
        }
        return query;
    }

    /**
     * Searchs logs with pagination.
     * 
     * @param em
     *            EntityManager
     * @param startIndex
     *            Indicates from which index logs will be retrieved.
     * @param max
     *            Number of elements to be retrieved in each iteration.
     * @param criteria
     *            Selection Criteria @see QueryCriteria
     * 
     * @return list.
     */
    @SuppressWarnings("unchecked")
    public static List<AuditLogData> search(final EntityManager em,
            final int startIndex, final int max, final QueryCriteria criteria) {
        final Query query = buildConditionalQuery(em,
                "SELECT a FROM AuditLogData a", criteria, max);
        query.setFirstResult(startIndex - 1);
        // query.setHint("org.hibernate.fetchSize", 1000);
        // query.setHint("org.hibernate.readOnly", true);
        // query.setHint("org.hibernate.cacheable", true);
        return query.getResultList();
    }

    /**
     * Deletes a log instance from database.
     * 
     * @param em
     */
    public void delete(final EntityManager em) {
        em.remove(this);
    }

    /**
     * Deletes a list of logs from database.
     * 
     * @param em
     * @param auditLogs
     *            List of logs to be deleted.
     */
    public static void delete(final EntityManager em,
            final List<AuditLogData> auditLogs) {
        em.setFlushMode(FlushModeType.COMMIT); // Is this really correct??
                                               // "Set the flush mode that applies to all objects contained in the persistence context."
        for (final AuditLogData log : auditLogs) {
            log.delete(em);
        }
        em.flush();
    }

    /**
     * Deletes logs from database based on criteria selection. @see
     * QueryCriteria
     * 
     * @param em
     * @param criteria
     *            criteria clause.
     */
    public static int delete(final EntityManager em,
            final QueryCriteria criteria) {
        final Query query = buildConditionalQuery(em,
                "DELETE FROM AuditLogData a", criteria, 0);
        return query.executeUpdate();
    }

    /**
     * Gets the maximum sequence number.
     * 
     * @param em
     * 
     * @return maximum number
     */
    public static Long getMaxSequenceNumber(final EntityManager em) {
        final Query query = em.createNamedQuery("AuditLogData.MAXSEQ");
        return QueryResultWrapper.getSingleResult(query, Long.valueOf(0L));
    }

    /**
     * Gets the last signed log from database.
     * 
     * @param em
     * 
     * @return last signed log.
     */
    public static AuditLogData getLastSignedAuditLog(final EntityManager em,
            final Date timeStamp) {
        final Query query = em.createNamedQuery("AuditLogData.LASTSIGNED");
        query.setMaxResults(1);
        query.setParameter("timeStamp", timeStamp.getTime());
        return QueryResultWrapper.getSingleResult(query);
    }

    /**
     * Gets the last unsigned sequence of logs from database.
     * 
     * @param em
     * 
     * @param log
     *            last signed log.
     * 
     * @return last unsigned sequence.
     */
    @SuppressWarnings("unchecked")
    public static List<AuditLogData> getLastUnsignedSequence(
            final EntityManager em, final AuditLogData log) {
        long seq = 0l;
        if (log != null) {
            seq = log.getSequenceNumber();
        }
        final Query query = em.createNamedQuery("AuditLogData.LASTUNSIGNSEQ");
        query.setParameter("sequenceNumber", seq);
        return query.getResultList();

    }

    /**
     * Retrieves the query used to get all audit logs till the specified
     * timestamp. Used for internal methods.
     * 
     * @return query string.
     */
    @Transient
    public static String getJdbcAuditLogsBeforeTimestampQuery() {
        return "select id, additionalDetails , config_id , eventStatus ,"
                + " eventType , module , sequenceNumber , service , signature , "
                + "timeStamp , authToken from AuditLogData where timeStamp <= ? order by sequenceNumber asc";
    }

    /**
     * JSON serialization.
     * 
     * @param generator
     * @param id
     * @param timeStamp
     * @param eventType
     * @param eventStatus
     * @param authToken
     * @param service
     * @param module
     * @param additionalDetails
     * @param signature
     * @param sequenceNumber
     * @param config
     * 
     * @throws JsonGenerationException
     * @throws IOException
     */
    public static void toExport(final AuditExporter auditExporter,
            final Long id, final Long timeStamp, final String eventType,
            final String eventStatus, final String authToken,
            final String service, final String module,
            final String additionalDetails, final String signature,
            final Long sequenceNumber, final Long config)
            throws JsonGenerationException, IOException {
        auditExporter.writeStartObject();
        auditExporter.writeField(FIELD_ID, id);
        auditExporter.writeField(FIELD_SEQUENCENUMBER, sequenceNumber);
        auditExporter.writeField(FIELD_TIMESTAMP, timeStamp);
        auditExporter.writeField(FIELD_EVENTTYPE, eventType);
        auditExporter.writeField(FIELD_EVENTSTATUS, eventStatus.toString());
        auditExporter.writeField(FIELD_AUTHENTICATION_TOKEN, authToken);
        auditExporter.writeField(FIELD_SERVICE, service);
        auditExporter.writeField(FIELD_MODULE, module);
        auditExporter.writeField(FIELD_ADDITIONAL_DETAILS, additionalDetails);
        auditExporter.writeField(FIELD_SIGNATURE, signature);
        auditExporter.writeField(FIELD_CONFIG, config);
        auditExporter.writeEndObject();
    }

    /**
     * AuditLogData to byte[]
     * 
     * @return array of bytes.
     * 
     * @throws IOException
     */
    @Transient
    public byte[] getBytes() throws IOException {
        return AuditLogData.getBytes(this.id, this.timeStamp, this.eventType,
                this.eventStatus.toString(), this.authToken, this.service,
                this.module, this.additionalDetails, this.signature,
                this.sequenceNumber, this.config != null ? this.config.getId()
                        : null);
    }

    /**
     * AuditLogData to byte[]
     * 
     * @param id
     * @param timestamp
     * @param eventType
     * @param eventStatus
     * @param userid
     * @param service
     * @param module
     * @param additionalDetails
     * @param signature
     * @param sequenceNumber
     * @param config
     * @return array of bytes.
     * 
     * @throws IOException
     */
    public static byte[] getBytes(final Long id, final Long timestamp,
            final String eventType, final String eventStatus,
            final String userid, final String service, final String module,
            final String additionalDetails, final String signature,
            final Long sequenceNumber, final Long config) throws IOException {

        final ByteArrayOutputStream bos = new ByteArrayOutputStream();
        final ObjectOutputStream oos = new ObjectOutputStream(bos);
        if (id != null)
            oos.writeLong(id);
        oos.writeLong(timestamp);
        oos.writeBytes(eventType);
        oos.writeBytes(eventStatus);
        oos.writeBytes(userid);
        oos.writeBytes(service);
        oos.writeBytes(module);
        if (additionalDetails != null)
            oos.writeBytes(additionalDetails);
        if (signature != null)
            oos.writeBytes(signature);
        oos.writeLong(sequenceNumber);
        if (config != null) {
            if (config.longValue() != 0) {
                oos.writeLong(config);
            }
        }
        oos.flush();
        oos.close();
        bos.close();
        final byte[] data = bos.toByteArray();
        return data;
    }

    @Override
    @Transient
    public int compareTo(final AuditLogData arg0) {
        return this.sequenceNumber.compareTo(arg0.getSequenceNumber());
    }

    public AuditLogData clone() {
        final AuditLogData auditLogData = new AuditLogData();
        auditLogData.setTimeStamp(this.getTimeStamp());
        auditLogData.setEventType(this.getEventType());
        auditLogData.setEventStatus(this.getEventStatus());
        auditLogData.setModule(this.getModule());
        auditLogData.setService(this.getService());
        auditLogData.setAuthToken(this.getAuthToken());
        auditLogData.setMapAdditionalDetails(this.getMapAdditionalDetails());
        auditLogData.setConfig(this.getConfig());
        auditLogData.setSequenceNumber(this.getSequenceNumber());
        auditLogData.setSignature(this.getSignature());
        return auditLogData;
    }

    @Override
    public String toString() {
        final StringBuilder buf = new StringBuilder();
        buf.append(this.getTimeStamp()).append(';').append(this.getEventType())
                .append(';').append(this.getEventStatus()).append(';')
                .append(this.getModule()).append(';').append(this.getService())
                .append(';').append(this.getAuthToken()).append(';')
                .append(this.getMapAdditionalDetails()).append(';')
                .append(this.getSequenceNumber()).append(';')
                .append(this.getSignature());
        return buf.toString();
    }

    @Transient
    @Override
    public String getCustomId() {
        return null;
    }

    @Transient
    @Override
    public EventType getEventTypeValue() {
        return new EventTypeHolder(getEventType());
    }

    @Transient
    @Override
    public EventStatus getEventStatusValue() {
        return getEventStatus();
    }

    @Override
    @Transient
    public ModuleType getModuleTypeValue() {
        return new ModuleTypeHolder(getModule());
    }

    @Transient
    @Override
    public String getNodeId() {
        return "global";
    }

    @Transient
    @Override
    public String getSearchDetail1() {
        return null;
    }

    @Transient
    @Override
    public String getSearchDetail2() {
        return null;
    }

    @Override
    @Transient
    public ServiceType getServiceTypeValue() {
        return new ServiceTypeHolder(getService());
    }
}
