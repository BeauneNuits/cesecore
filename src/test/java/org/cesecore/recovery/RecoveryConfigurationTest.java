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
package org.cesecore.recovery;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.cesecore.config.ConfigurationHolder;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the RecoveryConfiguration class
 * 
 * @version $Id$
 * 
 */
public class RecoveryConfigurationTest {

    @Before
    public void setUp() {
        ConfigurationHolder.instance().clear();
    }

    @Test
    public void testGetDbRestoreCommand() throws IOException {
        File f = File.createTempFile("cesecore", "test");
        try {
            FileWriter fw = new FileWriter(f);
            fw.write("backup.dbrestorecommand=foo bar \"lay low\" cow");
            fw.close();
            ConfigurationHolder.addConfigurationFile(f.getAbsolutePath());
            List<String> commandList = RecoveryConfiguration.getDbRestoreCommand();
            List<String> facit = Arrays.asList("foo", "bar", "lay low", "cow");
            for (int i = 0; i < commandList.size(); i++) {
                assertEquals(facit.get(i), commandList.get(i));
            }
        } finally {
            f.deleteOnExit();
        }
    }
    
    @Test
    public void testGetNullBackupDirectory() {
        assertNotNull(RecoveryConfiguration.getBackupDirectory());
    }

}
