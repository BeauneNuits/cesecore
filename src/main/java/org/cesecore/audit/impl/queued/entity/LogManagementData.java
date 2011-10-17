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

import java.io.IOException;
import java.io.Serializable;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.impl.queued.AuditLogSigningException;
import org.cesecore.audit.impl.queued.management.InvalidFrequencyException;
import org.cesecore.audit.impl.queued.management.LogManagementException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.JsonSerializer;
import org.cesecore.util.QueryResultWrapper;
import org.cesecore.util.Validator;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.hibernate.annotations.Cache;

/**
 * 
 * Abstract class to handle audit log configuration.
 * 
 * @version $Id$
 * 
 */
@Entity
@Table(name = "LogManagementData")
@NamedQueries({ @NamedQuery(name = "LogManagementData.CURRENT", query = "SELECT a FROM LogManagementData a WHERE a.id = (SELECT MAX(b.id) FROM LogManagementData b)") })
@Cache(region = "LogManagementData", usage = org.hibernate.annotations.CacheConcurrencyStrategy.READ_WRITE)
public abstract class LogManagementData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = -4783385097501386477L;
    private static final Logger log = Logger.getLogger(LogManagementData.class);
    
    public static final String TABLE_NAME = "LogManagementData";
    
    public static final String JDBC_LOG_MANAGEMENT_IN_BY_ID = "select id, timestamp, signMode, frequency, details "+
    "from LogManagementData where id in (select config_id from AuditLogData where timeStamp <= ?) order by id asc";
    
    public static final String FIELD_ID         = "id";
    public static final String FIELD_TIMESTAMP  = "timestamp";
    public static final String FIELD_SIGNMODE   = "signMode";
    public static final String FIELD_FREQUENCY  = "frequency";
    public static final String FIELD_DETAILS    = "details";

    private static final FastDateFormat ISO8601_DATE_FORMAT = FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ss");
    private static final long MIN_FREQUENCY = 100l; //milliseconds
    
    private Long id;
    private Long timestamp;
    private String signMode;
    private Long frequency;
    // FIXME: In a near FUTURE this should be nullable = false
    private String details;
    private List<AuditLogData> logs;
    private AuditLogCryptoTokenConfigData tokenConfig;
    private int rowVersion = 0;
    private String rowProtection;
    private CryptoToken cryptoToken;

    public Long getId() {
        return id;
    }

    public void setId(final Long id) {
        this.id = id;
    }

    public Long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(final Long timestamp) {
        this.timestamp = timestamp;
    }

    public String getSignMode() {
        return signMode;
    }

    public void setSignMode(final String signMode) {
        this.signMode = signMode;
    }

    public long getFrequency() {
        return frequency;
    }

    public void setFrequency(final Long frequency) {
        this.frequency = frequency;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(final String details) {
        this.details = details;
    }

    @Transient
    @SuppressWarnings("unchecked")
    protected Map<String, Object> getMapDetails() {
        Map<String, Object> result = new LinkedHashMap<String, Object>();
        try {
            if (this.details != null)
                result = (Map<String, Object>) JsonSerializer.fromJSON(this.details);
        } catch (final JsonParseException e) {
            log.error(e.getMessage(), e);
        } catch (final JsonMappingException e) {
            log.error(e.getMessage(), e);
        } catch (final IOException e) {
            log.error(e.getMessage(), e);
        }
        return result;
    }

    @Transient
    protected void setMapDetails(final Map<String, Object> details) {
        try {
            this.details = JsonSerializer.toJSON(details);
        } catch (final JsonGenerationException e) {
            log.error(e.getMessage(), e);
        } catch (final JsonMappingException e) {
            log.error(e.getMessage(), e);
        } catch (final IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    @Transient
    public String getKeyLabel() {
        final Map<String, Object> details = getMapDetails();
        return (String) details.get("label");
    }

    @Transient
    public void setKeyLabel(final String keyLabel) {
        final Map<String, Object> details = getMapDetails();
        details.put("label", keyLabel);
        setMapDetails(details);
    }

    @Transient
    public String getAlgorithm() {
        final Map<String, Object> details = getMapDetails();
        return (String) details.get("algorithm");
    }

    @Transient
    public void setAlgorithm(final String algorithm) {
        final Map<String, Object> details = getMapDetails();
        details.put("algorithm", algorithm);
        setMapDetails(details);
    }

    public List<AuditLogData> getLogs() {
        return logs;
    }

    public void setLogs(final List<AuditLogData> logs) {
        this.logs = logs;
    }

    /**
     * Gets the auditLogCryptoTokenConfig for this instance.
     * 
     * @return The auditLogCryptoTokenConfig.
     */
    public AuditLogCryptoTokenConfigData getTokenConfig() {
        return this.tokenConfig;
    }

    /**
     * Sets the auditLogCryptoTokenConfig for this instance.
     * 
     * @param auditLogCryptoTokenConfig
     *            The auditLogCryptoTokenConfig.
     */
    public void setTokenConfig(final AuditLogCryptoTokenConfigData tokenConfig) {
        this.tokenConfig = tokenConfig;
    }

    /**
     * Gets the rowVersion for this instance.
     * 
     * @return The rowVersion.
     */
    public int getRowVersion() {
        return this.rowVersion;
    }

    /**
     * Sets the rowVersion for this instance.
     * 
     * @param rowVersion
     *            The rowVersion.
     */
    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    /**
     * {@inheritDoc}
     * 
     * @see ProtectedData#getRowProtection()
     */
    public String getRowProtection() {
        return this.rowProtection;
    }

    /**
     * {@inheritDoc}
     * 
     * @see ProtectedData#setRowProtection(String)
     */
    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    public void save(final EntityManager em) {
        em.persist(this);
    }

    public static LogManagementData getCurrentConfiguration(final EntityManager em) {
        final Query query = em.createNamedQuery("LogManagementData.CURRENT").setHint("org.hibernate.cacheable", true);
        return QueryResultWrapper.getSingleResult(query);
    }

    public static LogManagementData findById(final EntityManager em, final Long id) {
        return em.find(LogManagementData.class, id);
    }
    
    @Transient
    public static void toExport(final AuditExporter auditExporter, final Long id, final Long timestamp, final String signMode, final Long frequency, final String details) throws JsonGenerationException, IOException {
        auditExporter.writeStartObject();
        auditExporter.writeField(FIELD_ID, id);
        auditExporter.writeField(FIELD_TIMESTAMP, timestamp);
        auditExporter.writeField(FIELD_SIGNMODE, signMode);
        auditExporter.writeField(FIELD_FREQUENCY, frequency);
        auditExporter.writeField(FIELD_DETAILS, details);
        auditExporter.writeEndObject();
    }

    /**
     * Will be used to validate the current instance. i.e if it as the proper set of attributes
     * In case anything is wrong this method will throw an exception
     * 
     * @throws LogManagementException
     */
    public void validate() throws LogManagementException {
        //test required fields
        if(Validator.notNull(getSignModeDescriptor(), frequency, tokenConfig, details)!=Validator.Result.VALID){
            throw new LogManagementException("missing required field");
        }
        //test frequency
        if(Validator.isEqual(0l, frequency)!=Validator.Result.VALID){
            if(Validator.inRange(0l, MIN_FREQUENCY, frequency)==Validator.Result.VALID) {
                throw new InvalidFrequencyException("Frequency is not in a valid interval");
            }
        }
    }
    
    public abstract LogManagementData metaClone();

    //
    // Start Database integrity protection methods
    //
    @Transient
    @Override
    protected String getTableName() {
        return TABLE_NAME;
    }

    @Transient
    private String getSignModeDescriptor() {
        final DiscriminatorValue dv = this.getClass().getAnnotation(DiscriminatorValue.class);
        return dv.value();
    }

    @Transient
    public CryptoToken getCryptoToken() {
        return cryptoToken;
    }
    
    protected void initCryptoToken() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        final String tokenClassname = getTokenConfig().getClassname();
        final Properties tokenProperties = getTokenConfig().getProperties();
        final byte[] tokenData = getTokenConfig().getTokenData();
        cryptoToken = CryptoTokenFactory.createCryptoToken(tokenClassname, tokenProperties, tokenData, 1);
        cryptoToken.activate(((String) tokenProperties.get(CryptoToken.AUTOACTIVATE_PIN_PROPERTY)).toCharArray());
    }

    public byte[] sign(final EntityManager em, final byte[] data) throws AuditLogSigningException {
        try {
            final CryptoToken token = getCryptoToken();
            if(token == null) {
                throw new AuditLogSigningException("crypto token was not initialized");
            }
            return sign(token, data);
        } catch (final Exception e) {
            throw new AuditLogSigningException(e.getMessage(), e);
        }
    }

    public abstract byte[] sign(final CryptoToken cryptoToken, final byte[] data) throws AuditLogSigningException;

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder(1200);
        // What is important to protect here is the data that we define, id,
        // name and certificate profile data
        // rowVersion is automatically updated by JPA, so it's not important, it
        // is only used for optimistic locking
        build.append(getSignModeDescriptor()).append(ISO8601_DATE_FORMAT.format(getTimestamp())).append(getFrequency()).append(getDetails())
                .append(getTokenConfig().getId());
        if (log.isDebugEnabled()) {
            // Some profiling
            if (build.length() > 1200) {
                log.debug("LogManagementData.getProtectString gives size: " + build.length());
            }
        }
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    /**
     * this method should have the @PrePersist ... however JPA enforces that
     * only one method can have this annotation
     * 
     * Since we have to do other stuff @see protectDataAndGenerateTimestamp()
     */
    @PreUpdate
    @Transient
    @Override
    protected void protectData() {
        super.protectData();
    }

    @Transient
    protected void protectDataAndGenerateTimestamp() {
        this.timestamp = new Date().getTime();
        protectData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return String.valueOf(getId());
    }

    protected abstract void prePersistWork() throws Exception;

    @PrePersist
    @Transient
    protected void prePersist() throws Exception {
        if(getTokenConfig() != null) {
            initCryptoToken();
        }
        prePersistWork();
        protectDataAndGenerateTimestamp();
    }
    
    protected abstract void postLoadWork() throws Exception;
    
    @PostLoad
    @Transient
    protected void postLoad() throws Exception {
        if(getTokenConfig() != null) {
            initCryptoToken();
        }
        postLoadWork();
        super.verifyData();
    }

    @Override
    public String toString() {
        return "LogManagementData [id=" + id + ", timestamp=" + timestamp + ", signMode=" + signMode + ", frequency=" + frequency + ", details="
                + details + ", tokenConfig=" + tokenConfig + ", rowVersion=" + rowVersion + ", rowProtection=" + rowProtection
                + ", cryptoToken=" + cryptoToken + "]";
    }
}
