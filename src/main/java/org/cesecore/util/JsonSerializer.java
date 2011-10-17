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
package org.cesecore.util;

import java.io.IOException;
import java.io.StringWriter;

import org.apache.log4j.Logger;
import org.codehaus.jackson.map.ObjectMapper;

/**
 * This is a helper classed that handles the serialization and deserialization from or JSON.
 * 
 * @version $Id$
 */
public abstract class JsonSerializer {
	
	private static final Logger log = Logger.getLogger(JsonSerializer.class);
	private static final ObjectMapper mapper = new ObjectMapper();
	
	/**
	 * Serializes an Object to JSON String.
	 * 
	 * @param value To be serialized.
	 * @return JSON string
	 * @throws IOException
	 */
	public static String toJSON(final Object value) throws IOException {
		if (log.isTraceEnabled()) {
			log.trace(">toJSON " + (value != null ? value.toString() : ""));
		}
		final StringWriter writer = new StringWriter();
		mapper.writeValue(writer, value);
		final String result = writer.toString();
		if (log.isTraceEnabled()) {
			log.trace("<toJSON " + result);
		}
		return result;
	}
	
	/**
	 * Deserializes an JSON String to object.
	 * 
	 * @param json
	 * @return The object
	 * @throws IOException
	 */
	public static Object fromJSON(final String json) throws IOException {
		if (log.isTraceEnabled()) {
			log.trace(">fromJSON " + json);
		}
		final Object result = mapper.readValue(json, Object.class);
		if (log.isTraceEnabled()) {
			log.trace("<fromJSON " + (result != null ? result.toString() : ""));
		}
		return result;
	}
}
