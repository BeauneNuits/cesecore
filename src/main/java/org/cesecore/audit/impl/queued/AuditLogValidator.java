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

import java.util.Arrays;
import java.util.Date;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.audit.AuditLogReportElem;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.impl.queued.entity.AuditLogData;
import org.cesecore.audit.impl.queued.entity.LogManagementData;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;

/**
 * Base class for audit log validation implementations.
 * 
 * @version $Id$
 * 
 */
public abstract class AuditLogValidator {

    private static final Logger log = Logger.getLogger(AuditLogValidator.class);

    private boolean first = true;
    private long startSequenceId = 0l;
    private long lastValidatedSequenceId = 0l;
    private byte[] sequence = new byte[0];
    
    private LogManagementData config = null;
    
    private AuditLogValidationReport report = null;
    private AuditLogReportElem currentReportElem;

    protected AuditLogValidator() {
        this.report = new AuditLogValidationReport();
    }

    /**
     * Validates secure logs from the first till one with the define timestamp.
     * 
     * @param timestamp
     *            Timestamp until which logs will be validated.
     * 
     * @return the validation report.
     */
    protected abstract AuditLogValidationReport validate(final Date timestamp, final int fetchSize) throws AuditLogValidatorException;

    /**
     * Get validation report.
     * 
     * @return the validation report.
     */
    protected AuditLogValidationReport getReport() {
        return report;
    }

    /**
     * Starts a new signature.
     * 
     * @param id
     *            first secure log id.
     */
    protected void startSignatureSequence(final Long id) {
        if (first) {
            this.startSequenceId = id;
            first = false;
            currentReportElem = new AuditLogReportElem();
            currentReportElem.setFirst(id);
        }
    }

    /**
     * Gets the current sequence signature.
     * 
     * @return signature.
     */
    protected byte[] getSignature() {
        return this.sequence;
    }

    /**
     * Concatenates the given signature with the current one.
     * 
     * @param data
     *            secure log signature.
     */
    protected void addToSignature(final byte[] data) {
        this.sequence = ArrayUtils.addAll(data, sequence);
    }

    /**
     * cleans the current signature sequence.
     * 
     */
    protected void cleanSignatureSequence() {
        if (!first) {
            first = true;
        }
        this.sequence = new byte[0];
    }

    /**
     * Gets the id of the first secure log of this sequence.
     * 
     * @return secure log id.
     */
    protected long getStartSequenceId() {
        return this.startSequenceId;
    }

    protected abstract LogManagementData getConfiguration(final Long configurationId);

    protected LogManagementData configuration(final Long configurationId) throws CryptoTokenOfflineException,
            CryptoTokenAuthenticationFailedException {
        if(this.config != null) {
            if(configurationId.equals(this.config.getId())) {
                return this.config;
            }
            if (log.isDebugEnabled()) {
                log.debug(String.format("different configuration || current %d needed %d", this.config.getId(), configurationId));
            }
            this.config.getCryptoToken().deactivate();
        }
        this.config = getConfiguration(configurationId);
        return this.config;
    }

    /**
     * Validates a specific ResultSet. It will store any potential validation
     * error in this instance report. This method takes care of unsigned audit
     * log sequences.
     * 
     * Given a ResultSet it will determine if it corresponds to a new log
     * sequence, if it finishes one sequence or even if it belongs to a sequence
     * being validated.
     * 
     * This method is void. It will store any potential validation error in this
     * instance report. Errors are indicated in the form of sequences X -> Y.
     * 
     * @param rs
     *            Database ResultSet rs
     * @throws AuditLogValidatorException
     */
    public void validate(Long id, Long timestamp, String eventType, String eventStatus, String userId, String service, String module, String details,
            String signature, Long sequenceNumber, Long configId) throws AuditLogValidatorException {
        try {
            startSignatureSequence(sequenceNumber);

            final byte[] data = AuditLogData.getBytes(null, timestamp, eventType, eventStatus, userId, service, module, details, signature,
                    sequenceNumber, configId);

            Long previousSequenceNumber = new Long(sequenceNumber - 1);
            if (this.lastValidatedSequenceId != previousSequenceNumber) {
                this.currentReportElem.setReason("missing log with sequence number " + previousSequenceNumber);
            }

            if (signature != null) {
                final byte[] auditLogSignedBytes = AuditLogData.getBytes(null, timestamp, eventType, eventStatus, userId, service, module, details,
                        null, sequenceNumber, configId);

                addToSignature(auditLogSignedBytes);
                final LogManagementData config = getConfiguration(configId);
                final CryptoToken cryptoToken = config.getCryptoToken();

                final byte[] sign = config.sign(cryptoToken, getSignature());
                final byte[] signatureToBeverified = Base64.decode(signature.getBytes());

                if (!Arrays.equals(sign, signatureToBeverified)) {
                    this.currentReportElem.setSecond(sequenceNumber);
                    if (getStartSequenceId() == sequenceNumber) {
                        this.currentReportElem.setReason("insufficient data to validate");
                        getReport().warn(this.currentReportElem);
                    } else {
                        this.currentReportElem.setReason("signature mismatch");
                        getReport().error(this.currentReportElem);
                    }
                }
                cleanSignatureSequence();
                startSignatureSequence(sequenceNumber);
            }
            addToSignature(data);

            this.lastValidatedSequenceId = sequenceNumber;
        } catch (final Exception e) {
            throw new AuditLogValidatorException(e.getMessage(), e);
        }
    }

}
