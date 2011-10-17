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

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.queued.entity.AuditLogData;
import org.junit.Before;
import org.junit.Test;

/**
 * Audit log entity unit test.
 * 
 * @version $Id$
 * 
 */
public class AuditLogDataTest{
	
	private static final Logger log = Logger.getLogger(AuditLogDataTest.class);
	
	private AuditLogData auditLogData;
	
	@Before
	public void setUp() throws Exception {
        log.trace(">setUp()");
        auditLogData = new AuditLogData();
        auditLogData.setModule(ModuleTypes.AUTHENTICATION);
        auditLogData.setService(ServiceTypes.CORE);
        auditLogData.setSignature("signature");
        auditLogData.setEventStatus(EventStatus.SUCCESS);
        auditLogData.setEventType(EventTypes.AUTHENTICATION);
        auditLogData.setAuthToken("user");
        log.trace("<setUp()");
    }

	@Test
	public void test01SetSimpleKeyValueDetails() {
		HashMap<String, Object> additionalDetails = new LinkedHashMap<String, Object>();
        additionalDetails.put("key", "value");
        
        auditLogData.setMapAdditionalDetails(additionalDetails);
        
        assertEquals(additionalDetails.get("key"), auditLogData.getMapAdditionalDetails().get("key"));
	}
	
	@Test
	public void test02SetNestedKeyValueDetails() {
		Map<String, Object> additionalDetails = new LinkedHashMap<String, Object>();
		Map<String, Object> asd = new LinkedHashMap<String, Object>();
		asd.put("nestedKey", "nestedValue");
		additionalDetails.put("key", asd);
		
		auditLogData.setMapAdditionalDetails(additionalDetails);
		
		assertEquals(
				((Map<String, Object>)additionalDetails.get("key")).get("nestedKey"), 
				((Map<String, Object>)auditLogData.getMapAdditionalDetails().get("key")).get("nestedKey"));
	}
	
}
