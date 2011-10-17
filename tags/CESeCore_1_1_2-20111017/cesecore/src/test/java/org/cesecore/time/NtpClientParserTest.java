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

import org.cesecore.time.providers.NtpClientParser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

/** 
 *
 * Ntp Client parser implementation test.
 * 
 * @version $Id$
 *
 */
public class NtpClientParserTest {

    @Test
    public void testParsePositiveOffset() throws TrustedTimeUnavailableException {
        
        NtpClientParser parser = new NtpClientParser();
        
        List<String> lines= new ArrayList<String>();
        lines.add("     remote           refid      st t when poll reach   delay   offset  jitter");
        lines.add("==============================================================================");
        lines.add("*ntp.server. 10.0.0.1    3 u    4  128  377    0.336    0.369   1.718");
        lines.add(" europium.canoni .INIT.          16 u    - 1024    0    0.000    0.000   0.000");
        
        TrustedTime time = parser.parseOffset(lines);
        
        assertEquals("Source: ", "ntp.server.", time.getSource());
        assertEquals("Accuracy: ", 0.369, time.getAccuracy(), 0);
        assertEquals("Stratum: ", 3.0, time.getStratum(), 0);
        assertEquals("NextUpdate: ", new Long(125000), time.getNextUpdate());
    }

    @Test
    public void testParseNegativeOffset() throws TrustedTimeUnavailableException {
        
        NtpClientParser parser = new NtpClientParser();
        
        List<String> lines= new ArrayList<String>();
        lines.add("     remote           refid      st t when poll reach   delay   offset  jitter");
        lines.add("==============================================================================");
        lines.add("*ntp.server. 10.0.0.1    3 u    4  128  377    0.336    -0.369   1.718");
        lines.add(" europium.canoni .INIT.          16 u    - 1024    0    0.000    0.000   0.000");
        
        TrustedTime time = parser.parseOffset(lines);
        
        assertEquals("Source: ", "ntp.server.", time.getSource());
        assertEquals("Accuracy: ", -0.369, time.getAccuracy(), 0);
        assertEquals("Stratum: ", 3.0, time.getStratum(), 0);
        assertEquals("NextUpdate: ", new Long(125000), time.getNextUpdate());
    }
    
    @Test
    public void testParseWhenDash() throws TrustedTimeUnavailableException {
        
        NtpClientParser parser = new NtpClientParser();
        
        List<String> lines= new ArrayList<String>();
        lines.add("     remote           refid      st t when poll reach   delay   offset  jitter");
        lines.add("==============================================================================");
        lines.add("*ntp.server. 10.0.0.1    3 u    -  128  377    0.336    -0.369   1.718");
        lines.add(" europium.canoni .INIT.          16 u    - 1024    0    0.000    0.000   0.000");
        
        TrustedTime time = parser.parseOffset(lines);
        
        assertEquals("Source: ", "ntp.server.", time.getSource());
        assertEquals("Accuracy: ", -0.369, time.getAccuracy(), 0);
        assertEquals("Stratum: ", 3.0, time.getStratum(), 0);
        assertEquals("NextUpdate: ", new Long(129000), time.getNextUpdate());
    }

    @Test
    public void testPollInMinutes() throws TrustedTimeUnavailableException {
        
        NtpClientParser parser = new NtpClientParser();
        
        List<String> lines= new ArrayList<String>();
        lines.add("     remote           refid      st t when poll reach   delay   offset  jitter");
        lines.add("==============================================================================");
        lines.add("*time.euro.apple 17.72.133.55     2 u 1063  68m  377   52.558    0.995   0.382");
        
        TrustedTime time = parser.parseOffset(lines);
        
        assertEquals("Source: ", "time.euro.apple", time.getSource());
        assertEquals("Accuracy: ", 0.995, time.getAccuracy(), 0);
        assertEquals("Stratum: ", 2, time.getStratum(), 0);
        assertEquals("NextUpdate: ", new Long(3018000), time.getNextUpdate());
    }

    @Test
    public void testPollAndWhenInMinutes() throws TrustedTimeUnavailableException {
        
        NtpClientParser parser = new NtpClientParser();
        
        List<String> lines= new ArrayList<String>();
        lines.add("     remote           refid      st t when poll reach   delay   offset  jitter");
        lines.add("==============================================================================");
        lines.add("*time.euro.apple 17.72.133.55     2 u 42m  68m  377   52.558    0.995   0.382");
        
        TrustedTime time = parser.parseOffset(lines);
        
        assertEquals("Source: ", "time.euro.apple", time.getSource());
        assertEquals("Accuracy: ", 0.995, time.getAccuracy(), 0);
        assertEquals("Stratum: ", 2, time.getStratum(), 0);
        assertEquals("NextUpdate: ", new Long(1561000), time.getNextUpdate());
    }
    @Test
    public void testCommand() {
        final NtpClientParser ntp = new NtpClientParser();
        TrustedTime time = ntp.getTrustedTime();
        assertNotNull("TrustedTime should not be null", time);
        Double accuracy = time.getAccuracy();
        if( accuracy != null ) {
            assertTrue("time.getAccuracy: "+ time.getAccuracy(), time.getAccuracy() <= 2000 );
        }
        else {
            assertTrue("lacking NTP synchronization", false);
        }
    }
}
