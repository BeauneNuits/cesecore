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
package org.cesecore.internal;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 * Based on EJBCA version: 
 *      InternalResourcesTest.java 8865 2010-04-09 15:14:51Z mikekushner
 * 
 * @version $Id$
 */
public class InternalResourcesTest {

	private static final String TEST_RESOURCE_LOCATION = "src/main/resources/intresources";
	
    @Test
    public void testGetLocalizedMessageString() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testmsg");
        assertEquals("Test ENG", res);
        assertEquals("Test ENG", intres.getLocalizedMessageCs("raadmin.testmsg").toString());
        // This message will only exist in the secondary language file
        res = intres.getLocalizedMessage("raadmin.testmsgsv");
        assertEquals("Test SV", res);
        assertEquals("Test SV", intres.getLocalizedMessageCs("raadmin.testmsgsv").toString());
    }

    @Test
    public void testNonExistingLocalizedMessageString() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.foo");
        assertEquals("raadmin.foo", res);
        assertEquals("raadmin.foo", intres.getLocalizedMessageCs("raadmin.foo").toString());
    }

    @Test
    public void testGetLocalizedMessageStringObject() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testparams", new Long(1), Integer.valueOf(3), "hi", Boolean.valueOf(true), "bye");
        assertEquals("Test 1 3 hi true bye message 1", res);
        assertEquals("Test 1 3 hi true bye message 1", intres.getLocalizedMessageCs("raadmin.testparams", new Long(1), Integer.valueOf(3), "hi", Boolean.valueOf(true), "bye").toString());
    }

    @Test
    public void testGetLocalizedMessageStringObjectWithNull() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testparams", null, Integer.valueOf(3), null, Boolean.valueOf(true), "bye");
        assertEquals("Test  3  true bye message ", res);
        assertEquals("Test  3  true bye message ", intres.getLocalizedMessageCs("raadmin.testparams", null, Integer.valueOf(3), null, Boolean.valueOf(true), "bye").toString());

        res = intres.getLocalizedMessage("raadmin.testparams");
        assertEquals("Test      message ", res);
        assertEquals("Test      message ", intres.getLocalizedMessageCs("raadmin.testparams").toString());
    }

    @Test
    public void testMessageStringWithExtraParameter() {
        InternalResources intres = new InternalResources(TEST_RESOURCE_LOCATION);
        String res = intres.getLocalizedMessage("raadmin.testmsgsv");
        assertEquals("Test SV", res);
        assertEquals("Test SV", intres.getLocalizedMessageCs("raadmin.testmsgsv").toString());
        res = intres.getLocalizedMessage("raadmin.testmsgsv", "foo $bar \\haaaar");
        assertEquals("Test SV", res);
        assertEquals("Test SV", intres.getLocalizedMessageCs("raadmin.testmsgsv", "foo $bar \\haaaar").toString());
    }
}
