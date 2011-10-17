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
package org.cesecore.time;

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TimedObject;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.audit.log.InternalSecurityEventsLoggerSessionLocal;
import org.cesecore.time.providers.TrustedTimeProviderException;

/**
 * This is the trusted time watcher implementation.
 *
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class TrustedTimeWatcherSessionBean implements TrustedTimeWatcherSessionLocal, TimedObject  {
    private static final Logger log = Logger.getLogger(TrustedTimeWatcherSessionBean.class);
    private static final String ttSchedulerInfo = "TT_SCHEDULE";

    @Resource
    private TimerService timerService;

    @EJB
    private InternalSecurityEventsLoggerSessionLocal internal;

    /**
     * Schedules the next call to update the TrustedTime status.
     * 
     * @param nextUpdate
     */
    private void schedule(final long nextUpdate){
        if(log.isTraceEnabled()){
            log.trace(String.format(">schedule: nextUpdate %s", nextUpdate));
        }
        // we will have only one schedule job at the time... 
        cancelTimers();
        //schedule a new timer
        timerService.createTimer(nextUpdate, nextUpdate, ttSchedulerInfo);
        if(log.isTraceEnabled()){
            log.trace("<schedule");
        }
    }

     /**
     * Cancels all previous timers.
     */
    private void cancelTimers(){
        //cancel timers
        if(log.isTraceEnabled()){
            log.trace(">cancelTimers");
        }
        for(final Object objTimer : timerService.getTimers()){
            final Timer timer = (Timer)objTimer;
            if(timer.getInfo().equals(ttSchedulerInfo)) {
                timer.cancel();
            }
        }
        if(log.isTraceEnabled()){
            log.trace("<cancelTimers");
        }
    }

    /**
     * Updates the TrustedTime status.
     * 
     * @throws AuditRecordStorageException
     * @throws TrustedTimeProviderException 
     */
    private void update(final boolean forcedUpdate) throws AuditRecordStorageException, TrustedTimeProviderException {
        // Make the update atomically, but do logging and rescheduling based on the result outside the locked section
        final TrustedTime[] trustedTimes = TrustedTimeCache.INSTANCE.atomicUpdate(forcedUpdate);
        if (trustedTimes == null) {
            return; // Another thread has already made the initial sync, so we don't need to.
        }
        final TrustedTime oldTrustedTime = trustedTimes[0];
        final TrustedTime updatedTrustedTime = trustedTimes[1];
        if (log.isDebugEnabled()) {
            log.debug("TrustedTime is sync? "+updatedTrustedTime.isSync());
        }
        // Reschedule timeout for when the next update is available
        if (updatedTrustedTime.getNextUpdate() != null) {
            if (log.isDebugEnabled()) {
                log.debug("TrustedTime schedule next run in ~ "+updatedTrustedTime.getNextUpdate());
            }
            if (updatedTrustedTime.getPreviousUpdate() != null) {
                if (!updatedTrustedTime.getNextUpdate().equals(updatedTrustedTime.getPreviousUpdate())) {
                    schedule(updatedTrustedTime.getNextUpdate());
                }
            } else {
                schedule(updatedTrustedTime.getNextUpdate());
            }
        } else {
            if (oldTrustedTime != null) {
                if(oldTrustedTime.getNextUpdate() != null) {
                    cancelTimers();
                }
            }
        }
        // Calculate if synchronization state has changed (sync acquired or lost)
        boolean logStateChange = true;
        if (oldTrustedTime != null) {
            if (updatedTrustedTime.isSync() == oldTrustedTime.isSync()){
                logStateChange = false;
            }
        }
        // Log if synchronization state has changed (sync acquired or lost)
        if (logStateChange || forcedUpdate){
            EventType type = EventTypes.TIME_SYNC_ACQUIRE;
            EventStatus status = EventStatus.SUCCESS;
            if (!updatedTrustedTime.isSync()) {
                type = EventTypes.TIME_SYNC_LOST; 
                status = EventStatus.FAILURE;
            }
            final Map<String, Object> details = new HashMap<String, Object>();
            details.put("details", updatedTrustedTime.toString());
            internal.log(updatedTrustedTime, type, status, ModuleTypes.TRUSTED_TIME, ServiceTypes.CORE, "system", null, null, null, details);
        }
    }

    /**
     * {@inheritDoc}
     * @see TrustedTimeWatcherSession#getTrustedTime()
     */
    @Override
    public TrustedTime getTrustedTime(final boolean forceUpdate) throws TrustedTimeProviderException {
        if(log.isDebugEnabled()) {
            log.debug(String.format("TrustedTime %s will force update %s", TrustedTimeCache.INSTANCE.getTrustedTime() == null, forceUpdate));
        }
        update(forceUpdate);
        return TrustedTimeCache.INSTANCE.getTrustedTime();
    }

    @Override
    public void ejbTimeout(final Timer timer) {
        if(log.isTraceEnabled()){
            log.trace(">TrustedTimeWatcher.ejbTimeout");
        }
        try {
            update(true);
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
        }
        if(log.isTraceEnabled()){
            log.trace("<TrustedTimeWatcher.ejbTimeout");
        }
    }
}
