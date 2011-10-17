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
package org.cesecore.audit.impl;

import java.io.IOException;
import java.io.OutputStream;

import org.cesecore.audit.audit.AuditExporter;
import org.codehaus.jackson.JsonEncoding;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.map.MappingJsonFactory;

/**
 * Exports audit log using the Json implementation.
 * @version $Id$
 */
public class AuditExporterJson implements AuditExporter {

	JsonGenerator jsonGenerator;
	
	@Override
	public void setOutputStream(final OutputStream outputStream) throws IOException {
		jsonGenerator = new MappingJsonFactory().createJsonGenerator(outputStream, JsonEncoding.UTF8);
		jsonGenerator.writeStartObject();
	}
	
	@Override
	public void startObjectLabel(String label) throws IOException {
        jsonGenerator.writeArrayFieldStart(label);
	}
	
	@Override
	public void endObjectLabel() throws IOException {
	    jsonGenerator.writeEndArray();
//        jsonGenerator.flush();
    }
	
	@Override
	public void close() throws IOException {
	    jsonGenerator.writeEndObject();
		jsonGenerator.close();
	}

	@Override
	public void writeEndObject() throws IOException {
		jsonGenerator.writeEndObject();
		jsonGenerator.flush();
	}

	@Override
	public void writeField(String key, long value) throws IOException {
		jsonGenerator.writeNumberField(key, value);
	}

	@Override
	public void writeStartObject() throws IOException {
		jsonGenerator.writeStartObject();
	}

	@Override
	public void writeField(String key, String value) throws IOException {
		jsonGenerator.writeStringField(key, value);
	}
}
