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


/**
 * Allows management and scheduling of secure log jobs.
 * 
 * @version $Id$
 * 
 */
public interface SchedulerSession {
    
    /**
     * Schedules a new job.
     * 
     * @param initialDuration Defines start time of the job in milliseconds. 
     * @param intervalDuration Defines the time in milliseconds between intervals.
     */
    void schedule(long initialDuration, long intervalDuration);
    
    /**
     * Used to cancel all scheduled jobs.
     */
    void cancelTimers();

}
