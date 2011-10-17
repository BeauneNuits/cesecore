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
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.impl.queued.entity.AuditLogData;
import org.cesecore.audit.impl.queued.entity.LogManagementData;
import org.cesecore.audit.impl.queued.management.AuditLogManagerProcessException;
import org.cesecore.audit.impl.queued.management.LogManagementManager;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.time.TrustedTime;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;

/**
 * Internal secure audit logs implementation.
 * 
 * @version $Id$
 */  
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class QueuedLoggerSessionBean implements QueuedLoggerSessionLocal {

    private static final Logger log = Logger.getLogger(QueuedLoggerSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager em;

    @PostConstruct
    public void postConstruct() {
        // Install BouncyCastle provider if not available
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    /**
     * {@inheritDoc}
     * @see InternalSecurityEventsLoggerSession#log(TrustedTime,EventType,EventStatus,ModuleType,ServiceType,String,Map<String,Object>)
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)    // Always persist audit log
    public void log(final TrustedTime trustedTime, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken,
    		final String customId, final String searchDetail1, final String searchDetail2, Map<String, Object> additionalDetails, Properties properties) throws AuditRecordStorageException {

        AuditLogData auditLogData = new AuditLogData();
        auditLogData.setEventType(eventType);
        auditLogData.setEventStatus(eventStatus);
        auditLogData.setModule(module);
        auditLogData.setService(service);
        auditLogData.setAuthToken(authToken);
        auditLogData.setMapAdditionalDetails(additionalDetails);

        LogManagementData config = null;
        try {
            config = LogManagementManager.getCurrentConfiguration(em);
        } catch (Exception e) {
            throw new AuditRecordStorageException(e.getMessage(), e);
        }
        if (config != null) {
            auditLogData.setConfig(config);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("configuration is not defined");
            }
        }

        AuditLogProcess process = null;
        AuditLogProcessQueue queue;
		try {
			queue = AuditLogProcessQueue.getInstance(em);
		} catch (AuditLogManagerProcessException e) {
			throw new AuditRecordStorageException(e.getMessage(), e);
		}
        try {
            process = queue.push(trustedTime, auditLogData);
            sign(queue, process);
            auditLogData = process.getAuditLogData();
            auditLogData.save(em);
            //removes process from queue
            queue.pull(process);
            if(log.isDebugEnabled()) {
                log.debug("Processed log:" + auditLogData.toString());
            } 
        } catch (Exception e) {
            if(process != null) {
                if(log.isDebugEnabled()) {
                    log.debug("Abort log: " + auditLogData.toString());
                }
                queue.abort(process, em);
            }
            throw new AuditRecordStorageException(e.getMessage(), e);
        }
    }

    private void sign(final AuditLogProcessQueue queue, final AuditLogProcess process) throws IOException, InterruptedException, AuditLogSigningException {

        final AuditLogData auditLogData = process.getAuditLogData();
        final LogManagementData config = auditLogData.getConfig();
        boolean sign = true;
        if (config != null) {
            final String type = auditLogData.getEventType();
            byte[] data = new byte[0];
            
            if (log.isTraceEnabled()) {
                log.trace(String.format("Log %d will be signed", auditLogData.getSequenceNumber()));
            }
            if (auditLogData.willBeSigned()) {
                // get previous logs to sign
                if(log.isDebugEnabled()){
                    log.debug("log eventType: " + type);
                }
                if (queue.hasProcessingDependencies(process)) {
                    process.getDepsCount().await();
                }
                data = queue.dependencyData(process);
            } else {
                //will not be signed
                sign = false;
                if(log.isTraceEnabled()){
                    log.trace(String.format("sign: false, eventType: %s, frequency: %d", auditLogData.getEventType(), config.getFrequency()));
                } 
            }
            if(sign) {
                data = ArrayUtils.addAll(auditLogData.getBytes(), data);
                final byte[] signature = config.sign(em, data);
                final String signatureb64 = new String(Base64.encode(signature));
                auditLogData.setSignature(signatureb64);
            }
        } else {
            sign = false;
        }

        if (log.isTraceEnabled() && !sign) {
            log.trace(String.format("Log %d not signed", auditLogData.getSequenceNumber()));
        }
    }
}
