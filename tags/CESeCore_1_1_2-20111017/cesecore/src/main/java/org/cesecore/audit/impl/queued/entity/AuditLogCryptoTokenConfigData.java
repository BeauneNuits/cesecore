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
import java.util.LinkedHashMap;
import java.util.Properties;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;
import org.cesecore.util.JsonSerializer;
import org.codehaus.jackson.JsonGenerationException;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.hibernate.annotations.Cache;

/**
 * 
 * Entity holding configuration parameters necessary to create a new crypto
 * token instance that will be used to sign secure logs.
 * 
 * @version $Id: AuditLogCryptoTokenConfigData.java 1114 2011-09-14 10:06:17Z
 *          filiper $
 * 
 */
@Entity
@Table(name = "AuditLogCryptoTokenConfigData")
@Cache(region = "AuditLogCryptoTokenConfigData", usage = org.hibernate.annotations.CacheConcurrencyStrategy.READ_WRITE)
public class AuditLogCryptoTokenConfigData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = -9106633699232309530L;

    private static final Logger log = Logger.getLogger(AuditLogCryptoTokenConfigData.class);
    private Long id;
    private String classname;
    private String tokenProperties;
    private String data;
    private int rowVersion = 0;
    private String rowProtection;

    /**
     * Gets the id for this configuration.
     * 
     * @return The id.
     */
    public Long getId() {
        return this.id;
    }

    /**
     * Sets the id for this configuration.
     * 
     * @param id
     *            The id.
     */
    private void setId(final Long id) {
        this.id = id;
    }

    /**
     * Gets the CryptoToken classname.
     * 
     * @return The CryptoToken classname.
     */
    public String getClassname() {
        return this.classname;
    }

    /**
     * Sets the CryptoToken classname.
     * 
     * @param classname
     *            The CryptoToken classname.
     */
    public void setClassname(final String classname) {
        this.classname = classname;
    }

    /**
     * Gets the CryptoToken roperties.
     * 
     * @return The CryptoToken Properties.
     */
    public String getTokenProperties() {
        return this.tokenProperties;
    }

    /**
     * Sets the CryptoToken roperties.
     * 
     * @param tokenProperties
     *            The CryptoToken Properties.
     */
    private void setTokenProperties(final String tokenProperties) {
        this.tokenProperties = tokenProperties;
    }

    /**
     * Gets the initial data for CryptoToken.
     * 
     * @return The initial data.
     */
    public String getData() {
        return this.data;
    }

    /**
     * Sets the initial data for CryptoToken.
     * 
     * @param data
     *            The data.
     */
    private void setData(final String data) {
        this.data = data;
    }

    /**
     * Gets the initial data for CryptoToken.
     * 
     * @return The initial data.
     */
    @Transient
    public byte[] getTokenData() {
        return getData() != null ? Base64.decode(getData().getBytes()) : new byte[0];
    }

    /**
     * Sets the initial data for CryptoToken.
     * 
     * @param tokenData
     *            The data.
     */
    @Transient
    public void setTokenData(final byte[] tokenData) {
        setData(new String(Base64.encode(tokenData)));
    }

    /**
     * Gets the properties for CryptoToken.
     * 
     * @return The properties.
     */
    @Transient
    @SuppressWarnings("unchecked")
    public Properties getProperties() {
        final Properties props = new Properties();
        try {
            if (getTokenProperties() != null) {
                final LinkedHashMap<String, String> propsMap = (LinkedHashMap<String, String>) JsonSerializer.fromJSON(getTokenProperties());
                for (final String key : propsMap.keySet()) {
                    props.setProperty(key, propsMap.get(key));
                }
            }
        } catch (final JsonParseException e) {
            log.error(e.getMessage(), e);
        } catch (final JsonMappingException e) {
            log.error(e.getMessage(), e);
        } catch (final IOException e) {
            log.error(e.getMessage(), e);
        }
        return props;
    }

    /**
     * Sets the properties for CryptoToken.
     * 
     * @param properties
     *            The properties.
     */
    @Transient
    @SuppressWarnings("unchecked")
    public void setProperties(final Properties properties) {
        try {
            // properties does not keep order when iterating over it
            LinkedHashMap<String, String> propsMap = new LinkedHashMap<String, String>();
            if (getTokenProperties() != null) {
                propsMap = (LinkedHashMap<String, String>) JsonSerializer.fromJSON(getTokenProperties());
            }
            for (final Object key : properties.keySet()) {
                propsMap.put((String) key, properties.getProperty((String) key));
            }
            setTokenProperties(JsonSerializer.toJSON(propsMap));
        } catch (final JsonGenerationException e) {
            log.error(e.getMessage(), e);
        } catch (final JsonMappingException e) {
            log.error(e.getMessage(), e);
        } catch (final IOException e) {
            log.error(e.getMessage(), e);
        }
    }

    /**
     * Clones this instance
     * 
     * @return new AuditLogCryptoTokenConfigData.
     */
    public AuditLogCryptoTokenConfigData clone() {
        final AuditLogCryptoTokenConfigData alctcd = new AuditLogCryptoTokenConfigData();
        alctcd.setId(this.id);
        alctcd.setClassname(this.classname);
        alctcd.setTokenProperties(this.tokenProperties);
        alctcd.setData(this.data);
        alctcd.setRowProtection(this.rowProtection);
        return alctcd;
    }

    /**
     * This method ensures the persistence or update of this instance
     * 
     * @param em
     *            EntityManager that will be used.
     */
    public void saveOrUpdate(final EntityManager em) {
        if (this.id != null) {
            em.merge(this);
        } else {
            em.persist(this);
        }
    }

    /**
     * Protection data methods
     */

    @Transient
    @Override
    protected String getProtectString(final int rowversion) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder(1200);
        build.append(getClassname()).append(getTokenProperties()).append(getData());
        if (log.isDebugEnabled()) {
            // Some profiling
            if (build.length() > 1200) {
                log.debug("AuditLogCryptoTokenConfigData.getProtectString gives size: " + build.length());
            }
        }
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return 1;
    }

    @PrePersist
    @PreUpdate
    @Transient
    @Override
    protected void protectData() {
        super.protectData();
    }

    @Override
    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    @Override
    public String getRowProtection() {
        return this.rowProtection;
    }

    @Transient
    @Override
    protected String getRowId() {
        return String.valueOf(getId());
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

    @PostLoad
    @Transient
    @Override
    protected void verifyData() {
        super.verifyData();
    }
}
