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
package org.cesecore.keys.key.management;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.List;

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

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.QueryResultWrapper;
import org.cesecore.util.query.Criteria;
import org.cesecore.util.query.QueryCriteria;
import org.cesecore.util.query.QueryGenerator;
import org.hibernate.annotations.Index;

/**
 * This entity bean represents a mapping between a Certificate and a cryptographic key.
 * 
 * @Version $Id$
 */
@Entity
@Table(name = "CertificateKeyAssociationData")
@NamedQueries({ @NamedQuery(name = "CertificateKeyAssociationData.BYKEY", query = "SELECT a FROM CertificateKeyAssociationData a WHERE a.keyAlias = :ka"),
        @NamedQuery(name = "CertificateKeyAssociationData.BYCERT", query = "SELECT a FROM CertificateKeyAssociationData a WHERE a.fingerPrint = :fp") })
public class CertificateKeyAssociationData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CertificateKeyAssociationData.class);
    private static final String TAG_SEPARATOR = ",";

    private String fingerPrint;
    private String base64Cert;
    private String tags;
    private String keyAlias;
    private int rowVersion = 0;
    private String rowProtection;

    /**
     * Constructs a new instance.
     */
    public CertificateKeyAssociationData() {
    }

    /**
     * Constructs a new instance.
     */
    public CertificateKeyAssociationData(final Certificate certificate, final List<String> tags, final String keyAlias) {
        try {
            setFingerPrint(CertTools.getFingerprintAsString(certificate));
            setBase64Cert(new String(Base64.encode(certificate.getEncoded())));
            setTagsList(tags);
            setKeyAlias(keyAlias);
        } catch (final CertificateEncodingException e) {
            final String msg = "Can't extract DER encoded certificate information.";
            log.error(msg, e);
            throw new RuntimeException(msg);
        }
    }

    /**
     * Gets the Certificate fingerPrint for this instance.
     * 
     * @return The fingerPrint.
     */
    public String getFingerPrint() {
        return this.fingerPrint;
    }

    /**
     * Sets the Certificate fingerPrint for this instance.
     * 
     * @param fingerPrint The fingerPrint.
     */
    public void setFingerPrint(final String fingerPrint) {
        this.fingerPrint = fingerPrint;
    }

    /**
     * Gets the Certificate encoded in base64Cert for this instance.
     * 
     * @return The base64Cert.
     */
    public String getBase64Cert() {
        return this.base64Cert;
    }

    /**
     * Sets the base64Cert for this instance.
     * 
     * @param base64Cert The base64Cert.
     */
    public void setBase64Cert(final String base64Cert) {
        this.base64Cert = base64Cert;
    }

    /**
     * Gets the tags for this instance.
     * 
     * @return The tags.
     */
    public String getTags() {
        return this.tags;
    }

    /**
     * Sets the tags for this instance.
     * 
     * @param tags The tags.
     */
    private void setTags(final String tags) {
        this.tags = tags;
    }

    @Transient
    public List<String> getTagsList() {
        return Arrays.asList(getTags().split(TAG_SEPARATOR));
    }

    private static String convertTags(final List<String> tagsList) {
        final StringBuilder sb = new StringBuilder();
        for (final String tag : tagsList) {
            sb.append(tag);
            sb.append(TAG_SEPARATOR);
        }
        return sb.toString();
    }

    @Transient
    public void setTagsList(final List<String> tagsList) {
        setTags(convertTags(tagsList));
    }

    /**
     * Gets the keyAlias for this instance.
     * 
     * @return The keyAlias.
     */
    @Index(name = "certificatekeyassoc_keyalias_index")
    public String getKeyAlias() {
        return this.keyAlias;
    }

    /**
     * Sets the keyAlias for this instance.
     * 
     * @param keyAlias The keyAlias.
     */
    public void setKeyAlias(final String keyAlias) {
        this.keyAlias = keyAlias;
    }

    // @Version @Column
    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    // @Column @Lob
    @Override
    public String getRowProtection() {
        return rowProtection;
    }

    @Override
    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    @Transient
    public Certificate getCertificate() {
        Certificate cert = null;
        try {
            cert = CertTools.getCertfromByteArray(Base64.decode(getBase64Cert().getBytes()));
        } catch (final CertificateException ce) {
            log.error("Can't decode certificate.", ce);
            return null;
        }
        return cert;
    }

    @SuppressWarnings("unchecked")
    public static List<CertificateKeyAssociationData> findByKeyAlias(final EntityManager em, final String keyAlias) {
        final Query query = em.createNamedQuery("CertificateKeyAssociationData.BYKEY");
        query.setParameter("ka", keyAlias);
        return query.getResultList();
    }

    public static CertificateKeyAssociationData findByCertificate(final EntityManager em, final String certificateFingerprint) {
        final Query query = em.createNamedQuery("CertificateKeyAssociationData.BYCERT");
        query.setParameter("fp", certificateFingerprint);
        return QueryResultWrapper.getSingleResult(query);
    }

    /**
     * Retrieves CertificateKeyAssociationData objects from persistence that match all tags in the supplied list parameter.
     * 
     * @param em An entity manager in EJB context.
     * @param tags A list of tags to match by.
     * @return All CertificateKeyAssociationData mappings that match the given tag list.
     */
    @SuppressWarnings("unchecked")
    public static List<CertificateKeyAssociationData> findByTags(final EntityManager em, final List<String> tags) {

        final QueryCriteria qc = QueryCriteria.create();
        for (final String tag : tags) {
            qc.add(Criteria.like("tags", tag));
        }
        final QueryGenerator generator = QueryGenerator.generator(CertificateKeyAssociationData.class, qc, "a");
        final Query query = em.createQuery("SELECT a FROM CertificateKeyAssociationData a" + generator.generate());
        for (final String entry : generator.getParameterKeys()) {
            query.setParameter(entry, generator.getParameterValue(entry));
        }
        return (List<CertificateKeyAssociationData>) query.getResultList();
    }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
        final ProtectionStringBuilder build = new ProtectionStringBuilder(1200);
        // What is important to protect here is the data that we define, id, name and certificate profile data
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getFingerPrint()).append(getBase64Cert()).append(getTags()).append(getKeyAlias());
        if (log.isDebugEnabled()) {
            // Some profiling
            if (build.length() > 1200) {
                log.debug("CertificatekeyAssociationData.getProtectString gives size: " + build.length());
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

    @PostLoad
    @Transient
    @Override
    protected void verifyData() {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return getFingerPrint();
    }
    //
    // End Database integrity protection methods
    //

}
