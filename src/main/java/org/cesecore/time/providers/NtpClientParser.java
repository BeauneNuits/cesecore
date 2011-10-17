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
package org.cesecore.time.providers;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;

import org.cesecore.time.TrustedTimeUnavailableException;
import org.cesecore.time.TrustedTime;

/**
 * This parser reads the output from an NTP client call's output and obtains the offset of the selected peer (trusted time source)
 * 
 * @version $Id$
 * 
 */
public class NtpClientParser implements TrustedTimeProvider {

    private static final long serialVersionUID = -5636774650526211247L;
    private static final Logger log = Logger.getLogger(NtpClientParser.class);

    private String ntpClientCommand = CesecoreConfiguration.getTrustedTimeNtpCommand();
    private Pattern pattern = CesecoreConfiguration.getTrustedTimeNtpPattern();

    /**
     * Private constructor needed for singleton
     */
    public NtpClientParser() {
        super();
    }

    /**
     * Executes a call to an NTP client and parses the output in order to obtain the offset of the selected trusted time source.
     * 
     * @return Double containing the offset of the current selected trusted time source
     */
    public TrustedTime getTrustedTime() {

        Process proc = null;
        TrustedTime trustedTime = null;
        try {
            Runtime runtime = Runtime.getRuntime();
            proc = runtime.exec(this.ntpClientCommand);

            @SuppressWarnings("unchecked")
            List<String> lines = IOUtils.readLines(proc.getInputStream());

            trustedTime = parseOffset(lines);
        } catch (Exception e) {
            log.error("Error parsing NTP output", e);
            trustedTime = new TrustedTime();
        } finally {
            if (proc != null) {
                IOUtils.closeQuietly(proc.getInputStream());
                IOUtils.closeQuietly(proc.getErrorStream());
                IOUtils.closeQuietly(proc.getOutputStream());
            }
        }

        if (log.isDebugEnabled()) {
            log.debug(trustedTime.toString());
        }

        return trustedTime;
    }

    /**
     * Parses List of lines from the NTP client output and returns the offset of the current selected peer
     * 
     * @param lines - output from the NTP client call
     * 
     *            Explanation of output from "ntpq -p"
     * 
     *            remote refid st t when poll reach delay offset disp ==============================================================================
     *            clusternode1-pr 0.0.0.0 16 - - 1024 0 0.00 0.000 16000.0 *clusternode2-pr LOCAL(0) 4 u 528 1024 377 0.66 0.029 0.60
     * 
     * 
     *            The asterisk indicates the prefered update node (where first to try to get the time). remote is the address of the time server, with
     *            LOCAL(0) indicating the local clock. refid indicated the type of the time server. LOCAL or .LCL. means local, .DCFa. is a DCF77
     *            receiver, .PPS. is a hardware device generating a pulse every second. st is the Stratum, which indicates the accuracy to be
     *            expected. Stratum 0 are usually atomic clocks, Stratum 1 might be radio controlled clocks. when is the time to the next update. poll
     *            is the count that when has to reach before an update is attempted reach is an octal number that is left-shifted on each update. On a
     *            successful update an 1 is shifted in, 0 otherwise. delay is the RTT to the time server offset is the difference between the remote
     *            and the local clock
     * 
     * @return TrustedTime
     * @throws TrustedTimeUnavailableException
     */
    public TrustedTime parseOffset(List<String> lines) throws TrustedTimeUnavailableException {
        TrustedTime t = new TrustedTime();
        try {
            for (String line : lines) {
                // There is a * in one line when the client is synchronized with a time server
                // If not it means this client is not synchronized with a time server (?)
                if (line.trim().startsWith("*")) {
                    Matcher matcher = pattern.matcher(line.trim());
                    if (matcher.find()) {
                        String source = matcher.group(1);
                        String stratum = matcher.group(2);
                        String whenStr = matcher.group(3);
                        String whenInMinutes = matcher.group(4);
                        String pollStr = matcher.group(5);
                        String pollInMinutes = matcher.group(6);
                        String offsetStr = matcher.group(7);

                        if (log.isDebugEnabled()) {
                            log.debug(String.format("source %s stratum %s when %s poll %s %s offset %s", source, stratum, whenStr, pollStr,
                                    pollInMinutes, offsetStr));
                        }

                        Integer when = null;
                        try {
                            when = Integer.valueOf(whenStr);
                            if (whenInMinutes.equals("m")) {
                                when *= 60;
                            }
                        } catch (NumberFormatException e) {
                            // caught "-" which means poll is 0
                            when = 0;
                        }

                        Integer poll = Integer.valueOf(pollStr);
                        if (pollInMinutes.equals("m")) {
                            poll *= 60;
                        }

                        t.setNextUpdate(when, poll);
                        t.setSource(source);
                        t.setAccuracy(Double.valueOf(offsetStr));
                        t.setSync(true);
                        t.setStratum(Integer.valueOf(stratum));
                        return t;
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("ntp line not matched: " + line);
                        }
                        throw new TrustedTimeUnavailableException("Couldn't apply regexp over the ntp line.");
                    }
                }
            }
        } catch (NumberFormatException e) {
            throw new TrustedTimeUnavailableException("Error parsing NTP output", e);
        }

        // no offset, throw exception
        if (log.isDebugEnabled()) {
            for (String line : lines) {
                log.debug(line);
            }
        }
        throw new TrustedTimeUnavailableException("Couldn't get NTP offset value, no synchronized servers.");
    }
}
