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
package org.cesecore.audit.impl.queued.management;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;

/**
 * This class handles secure audit scheduled signing.
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class SchedulerSessionBean implements SchedulerSessionLocal {
    
    private static final Logger log = Logger.getLogger(SchedulerSessionBean.class);

    private static final String scheduleLogInfo = "SCHEDULED_LOG";

    @Resource
    private TimerService timerService;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLogger;

    /**
     * Schedules a new job.
     * 
     * @param initialDuration
     *            Defines start time of the job in milliseconds.
     * @param intervalDuration
     *            Defines the time in milliseconds between intervals.
     */
    public void schedule(final long initialDuration, final long intervalDuration) {
        if (log.isTraceEnabled()) {
            log.trace(String.format(">schedule: initDuration %s intervalDuration %s", initialDuration, intervalDuration));
        }
        // we will have only one schedule job at the time...
        cancelTimers();
        // schedule a new timer
        final Timer timer = timerService.createTimer(initialDuration, intervalDuration, scheduleLogInfo);
        if (log.isDebugEnabled()) {
            log.debug(String.format("audit log timer (%d, %d) | remaining time: %d, next timeout: %s", initialDuration, intervalDuration,
                    timer.getTimeRemaining(), timer.getNextTimeout()));
        }

        if (log.isTraceEnabled()) {
            log.trace("<schedule");
        }
    }

    /**
     * Used to cancel all scheduled jobs.
     */
    public void cancelTimers() {
        // cancel timers
        if (log.isTraceEnabled()) {
            log.trace(">cancelTimers");
        }
        for (final Object objTimer : timerService.getTimers()) {
            final Timer timer = (Timer) objTimer;
            if (timer.getInfo().equals(scheduleLogInfo)) {
                timer.cancel();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<cancelTimers");
        }
    }

    /**
     * This Method will be triggered when a scheduled timeout occurs. This
     * method should not be invoked by the user. It's not available by the
     * interface
     * 
     * @param timer
     */
    @Timeout
    public void log(final Timer timer) {
        if (log.isTraceEnabled()) {
            log.trace(">shedule timedout");
        }
        
        if (log.isDebugEnabled()) {
            log.debug(String.format("audit log timeout | remaining time: %d, next timeout: %s",
                    timer.getTimeRemaining(), timer.getNextTimeout()));
        }
        
        // The user will be "system" this will indicate that the log was done
        // from an automated task.
        securityEventsLogger.log(EventTypes.LOG_SIGN, EventStatus.SUCCESS, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, "system", null, null, null, null);

        if (log.isTraceEnabled()) {
            log.trace("<shedule timedout");
        }
    }
}
