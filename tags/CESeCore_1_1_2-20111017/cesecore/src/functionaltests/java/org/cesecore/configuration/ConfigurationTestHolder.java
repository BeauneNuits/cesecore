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
package org.cesecore.configuration;

import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolder;

/**
 * Mirrors {@link ConfigurationHolder} from CESeCore core. Provides the same service, but for test specific values.
 * 
 * @version $Id$
 * 
 */
public enum ConfigurationTestHolder {
    INSTANCE;

    private static final Logger log = Logger.getLogger(ConfigurationTestHolder.class);

    private CompositeConfiguration config = null;

    private ConfigurationTestHolder() {
        config = new CompositeConfiguration();
        init();
    }

    private void init() {
        final String[] CONFIG_FILES = { "/conf/backup.test.properties" };
        // Default values build into jar file, this is last prio used if no of the other sources override this
        for (int i = 0; i < CONFIG_FILES.length; i++) {
            try {
                addConfigurationResource(CONFIG_FILES[i]);
            } catch (final ConfigurationException e) {
                log.error("Could not start test confuguration", e);
            }
        }
    }

    /**
     * Add built in config file
     * 
     * @throws ConfigurationException
     */
    private void addConfigurationResource(final String resourcename) throws ConfigurationException {
        final URL url = ConfigurationHolder.class.getResource(resourcename);
        if (url != null) {
            final PropertiesConfiguration pc = new PropertiesConfiguration(url);
            config.addConfiguration(pc);
        }
    }

    /**
     * Return a the expanded version of a property. E.g. property1=foo property2=${property1}bar would return "foobar" for property2
     * 
     * @param defaultValue to use if no property of such a name is found
     */
    public String getExpandedString(final String property, final String defaultValue) {
        String ret = getString(property, defaultValue);
        if (ret != null) {
            while (ret.indexOf("${") != -1) {
                ret = interpolate(ret);
            }
        }
        return ret;
    }

    private String interpolate(final String orderString) {
        final Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");
        final Matcher m = PATTERN.matcher(orderString);
        final StringBuffer sb = new StringBuffer(orderString.length());
        m.reset();
        while (m.find()) {
            // when the pattern is ${identifier}, group 0 is 'identifier'
            final String key = m.group(1);
            final String value = getExpandedString(key, "");

            // if the pattern does exists, replace it by its value
            // otherwise keep the pattern ( it is group(0) )
            if (value != null) {
                m.appendReplacement(sb, value);
            } else {
                // I'm doing this to avoid the backreference problem as there will be a $
                // if I replace directly with the group 0 (which is also a pattern)
                m.appendReplacement(sb, "");
                final String unknown = m.group(0);
                sb.append(unknown);
            }
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * @param property the property to look for
     * @param defaultValue default value to use if property is not found
     * @return String configured for property, or default value, if defaultValue is null and property is not found null is returned.
     */
    public String getString(final String property, final String defaultValue) {
        // Commons configuration interprets ','-separated values as an array of Strings, but we need the whole String for example SubjectDNs.
        final String ret;
        final StringBuffer str = new StringBuffer();
        final String rets[] = config.getStringArray(property);
        for (int i = 0; i < rets.length; i++) {
            if (i != 0) {
                str.append(',');
            }
            str.append(rets[i]);
        }
        if (str.length() != 0) {
            ret = str.toString();
        } else {
            ret = defaultValue;
        }
        return ret;
    }

}
