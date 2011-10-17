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
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NavigableSet;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;

import javax.persistence.EntityManager;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.audit.LogServiceState;
import org.cesecore.audit.impl.queued.entity.AuditLogData;
import org.cesecore.audit.impl.queued.management.AuditLogManagerProcessException;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.time.TrustedTime;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * Audit logs blocking queue. This singleton class handles a FIFO queue of logs.
 * 
 * @version $Id$
 * 
 */
public final class AuditLogProcessQueue {

    private static final Logger logger = Logger.getLogger(AuditLogProcessQueue.class);
    /** queue with audit logs still being processed */
    private static LinkedList<AuditLogProcess> processing;
    /** queue with audit logs processed */
    private static NavigableSet<AuditLogData> logs;
    /** current audit log sequence number */
    private static Long lastSequenceNumber;

    /** instance */
    private static AuditLogProcessQueue queue;

    /** state control variables */
    private final static Object instanceLock = new Object();
    private final static Object pushLock = new Object();
    private final static Object pullLock = new Object();
    //private final static AtomicBoolean resetInProgress = new AtomicBoolean(false);
    private static CountDownLatch inProcess; 

    private AuditLogProcessQueue() {}
    
    /**
     * Handles the creation/retrieval of an AuditLogProcessQueue instance.
     * 
     * @param em EntityManager used retrieve usefull irformation from database to initiate this queue state.
     *
     * @return new AuditLogProcessQueue instance or an already instanciated instance.
     */
    public static AuditLogProcessQueue getInstance(final EntityManager em) throws AuditLogManagerProcessException {
        if(queue == null) {
            synchronized (instanceLock) {
                if(queue == null) {
                    processing = new LinkedList<AuditLogProcess>();
                    logs = new TreeSet<AuditLogData>();
                    final AuditLogData lastLog = AuditLogData.getLastSignedAuditLog(em, new Date());
                    final List<AuditLogData> unsignedSequence = AuditLogData.getLastUnsignedSequence(em, lastLog);
                    if(unsignedSequence.isEmpty()) {
                        if(lastLog != null) {
                            logs.add(lastLog.clone());
                            lastSequenceNumber = new Long(lastLog.getSequenceNumber());
                        } else {
                            lastSequenceNumber = new Long(0l);
                        }
                    }
                    else {
                        if(lastLog != null) {
                            logs.add(lastLog.clone());
                        }
                        logs.addAll(unsignedSequence);
                        lastSequenceNumber = unsignedSequence.get(unsignedSequence.size()-1).getSequenceNumber();
                    }
                    inProcess = new CountDownLatch(0);
                    queue = new AuditLogProcessQueue();
                }
            }
        }
        return queue;
    }
    
    /**
     * Push's an AuditLogData instance to the queue for processing.
     * 
     * @param trustedTime
     *          TrustedTime instance used to get a trusted time. The timestamp field in the AuditLogData instance 
     *          will be asigned with the obtained trusted time.
     * @param auditLogData
     *          AuditLogData instance to be processed.
     * @return  AuditLogProcess instance that represents a "process" in the queue.
     * 
     * @throws TrustedTimeProviderException
     * @throws AuditLogManagerProcessException
     */
    public AuditLogProcess push(final TrustedTime trustedTime, final AuditLogData auditLogData) throws TrustedTimeProviderException, AuditLogManagerProcessException {
        synchronized(pushLock) {
            lastSequenceNumber++;
            auditLogData.setSequenceNumber(lastSequenceNumber);
            auditLogData.setTimeStamp(Long.valueOf(trustedTime.getTime().getTime()));
            final AuditLogProcess process = new AuditLogProcess(auditLogData);
            processing.add(process);
            return process; 
        }
    }

    /**
     * Removes one process from the queue. This method should be called when the processed has finished.
     * 
     * @param process
     *          process instance to be removed.
     */
    public void pull(final AuditLogProcess process) {
        final AuditLogData auditLogData = process.getAuditLogData().clone();
        List<AuditLogProcess> consumersToBeNotified = null;
        synchronized(pushLock) {
            consumersToBeNotified = process.getWaiting();
            processing.remove(process);
        }
        synchronized(pullLock) {
            logs.add(auditLogData);
            if(logger.isTraceEnabled()){
                logger.trace(String.format("added to processed queue: %s", auditLogData.toString()));
            }
            for (final AuditLogProcess proc : consumersToBeNotified) {
                proc.getDepsCount().countDown();
            }
        }
        if(LogServiceState.INSTANCE.isDisabled()) { inProcess.countDown(); }
    }

    /**
     * Retrieves the list of already processed logs on which the provided process dependes on. 
     * This method should be used when the process provided is to be signed and you need to get 
     * the previous logs to properly calculate the signature.
     * 
     * @param process
     *
     * @return List of logs.
     */
    public List<AuditLogData> dependencies(final AuditLogProcess process) {
        final ArrayList<AuditLogData> deps = new ArrayList<AuditLogData>();
        synchronized(pullLock) {
            for(final Iterator<AuditLogData> it = logs.iterator(); it.hasNext(); ){
                final AuditLogData auditLogData = it.next();
                if (auditLogData.getSequenceNumber() < process.getAuditLogData().getSequenceNumber()) {
                    deps.add(auditLogData);
                    it.remove();
                }
                else { break; }
            }
        }
        return deps;
    }

    public byte[] dependencyData(final AuditLogProcess process) throws IOException {
        byte[] data = {};
        synchronized(pullLock) {
            for(final Iterator<AuditLogData> it = logs.iterator(); it.hasNext(); ){
                final AuditLogData auditLogData = it.next();
                if (auditLogData.getSequenceNumber() < process.getAuditLogData().getSequenceNumber()) {
                    data = ArrayUtils.addAll(auditLogData.getBytes(), data);
                    it.remove();
                }
                else { break; }
            }
        }
        return data;
    }

    /**
     * Checks if one process depends on other processes that are still being processed.
     * 
     * @param process
     *      Process that it will be checked for dependendencies.
     * @return true if has dependencies and false if otherwise.
     */
    public boolean hasProcessingDependencies(final AuditLogProcess process) {
        boolean hasDeps = false;
        int numberOfDeps = 0;
        synchronized(pushLock) {
            for(final AuditLogProcess proc: processing) {
                if (proc.getAuditLogData().getSequenceNumber() < process.getAuditLogData().getSequenceNumber()
                        && !proc.getWaiting().contains(process)) {
                    proc.addWaitingProcess(process);
                    numberOfDeps++;
                    hasDeps = true;
                } else {
                    if (process.getAuditLogData().getSequenceNumber() >= process.getAuditLogData().getSequenceNumber()) {
                        break;
                    }
                }
            }
            process.setDepsCount(new CountDownLatch(numberOfDeps));
        }
        return hasDeps;
    }

    /**
     * Aborts one audit log process and adjusts sequence numbers.
     * 
     * @param process
     * @param em
     */
    public void abort(final AuditLogProcess process, final EntityManager em) {
        synchronized(pushLock) {
            synchronized(pullLock) {
                //decrement last sequence number
                lastSequenceNumber--;
                final AuditLogData auditLogData = process.getAuditLogData();
                final Long abortSequenceNumber = auditLogData.getSequenceNumber();
                //remove log from processing
                if(processing.remove(process)) {
                    //decrement in process counter when reset is in progress
                    if(LogServiceState.INSTANCE.isDisabled()) {
                        inProcess.countDown();
                    }
                }
                final List<AuditLogProcess> consumersToBeNotified = process.getWaiting();
                for (final AuditLogProcess proc : consumersToBeNotified) {
                    //decrement sequence number in each dependent log
                    final Long seqNumber =  proc.getAuditLogData().getSequenceNumber();
                    auditLogData.setSequenceNumber(seqNumber-1);
                    proc.setAuditLogData(auditLogData);

                    proc.getDepsCount().countDown();
                }
                //decrement sequence number in already processed logs (not signed yet)
                for(final AuditLogData auditLog: logs){
                    final Long seqNumber = auditLog.getSequenceNumber();
                    if(seqNumber > abortSequenceNumber) {
                        auditLog.setSequenceNumber(seqNumber-1);
                        em.merge(auditLog);
                    }
                }
            }
        }
    }

    public static void prepareReset() throws AuditLogResetException {
        try { 
            synchronized (pushLock) {
                inProcess = new CountDownLatch(processing.size());
            }
            //let's wait for logs being processed at this moment
            inProcess.await();
        }
        catch (final InterruptedException e) {
            logger.error(e.getMessage(), e);
            throw new AuditLogResetException(e.getMessage(), e);
        }
    }

    public static void reset() {
        //since there are no logs being processed let's trash this instance.
        queue = null;
    }

}
