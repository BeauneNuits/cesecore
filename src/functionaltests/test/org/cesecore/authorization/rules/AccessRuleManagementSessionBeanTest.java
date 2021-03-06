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
package org.cesecore.authorization.rules;

import static org.junit.Assert.*;
import junit.framework.Assert;

import org.cesecore.jndi.JndiHelper;
import org.junit.Test;

/**
 * This testclass represents a sanity test of the AccessRuleManagementSessionBean.
 * 
 * @version $Id$
 * 
 */
public class AccessRuleManagementSessionBeanTest {

    AccessRuleManagementTestSessionRemote accessRuleManagementSession = JndiHelper.getRemoteSession(AccessRuleManagementTestSessionRemote.class);

    /**
     * Test all CRUD operations. Pure sanity test.
     * @throws AccessRuleExistsException 
     * 
     */
    @Test
    public void testCrud() throws AccessRuleExistsException {

        final String accessruleName = "/";
        final String roleName = "Hamlet";

        Assert.assertNotNull("AccessRuleManagementSession was not retrieved from JNDI context succesfully.", accessRuleManagementSession);

        int primaryKey = AccessRuleData.generatePrimaryKey(roleName, accessruleName);
        AccessRuleData accessRule = accessRuleManagementSession.createRule(accessruleName, roleName, AccessRuleState.RULE_ACCEPT, true);
        
        try {
            AccessRuleData retrievedRule = accessRuleManagementSession.find(primaryKey);
            assertNotNull("Access rule with primary key " + primaryKey + " was not collected succesfully from database.", retrievedRule);
            assertEquals("Two rules with the same primary key were not equal.", accessRule, retrievedRule);
        } finally {
            AccessRuleData retrievedRule = accessRuleManagementSession.find(primaryKey);
            if (retrievedRule != null) {
                accessRuleManagementSession.remove(retrievedRule);
            }
            retrievedRule = accessRuleManagementSession.find(primaryKey);
            assertNull("Access rule with primary key " + primaryKey + " was not removed succesfully from database.", retrievedRule);
        }

    }

}
