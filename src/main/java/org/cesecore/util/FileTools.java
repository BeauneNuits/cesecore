/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.io.*;
import java.text.Collator;
import java.util.Arrays;
import java.util.Comparator;

import org.apache.log4j.Logger;


/**
 * Tools to handle some common file operations.
 *
 * Based on EJBCA version: FileTools.java 11099 2011-01-07 16:29:26Z anatom
 * @version $Id$
 */
public final class FileTools {
    private static final Logger log = Logger.getLogger(FileTools.class);

    /** Should not be created */
    private FileTools() {
    }

    /**
     * Reads binary bytes from a PEM-file. The PEM-file may contain other stuff, the first item
     * between beginKey and endKey is read. Example: <code>-----BEGIN CERTIFICATE REQUEST-----
     * base64 encoded PKCS10 certification request -----END CERTIFICATE REQUEST----- </code>
     *
     * @param inbuf input buffer containing PEM-formatted stuff.
     * @param beginKey begin line of PEM message
     * @param endKey end line of PEM message
     *
     * @return byte[] containing binary Base64 decoded bytes.
     *
     * @throws IOException if the PEM file does not contain the right keys.
     */
    public static byte[] getBytesFromPEM(final byte[] inbuf, final String beginKey, final String endKey)
        throws IOException {
        log.trace(">getBytesFromPEM");

        final ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
        final BufferedReader bufRdr = new BufferedReader(new InputStreamReader(instream));
        final ByteArrayOutputStream ostr = new ByteArrayOutputStream();
        final PrintStream opstr = new PrintStream(ostr);
        String temp;

        while (((temp = bufRdr.readLine()) != null) && !temp.equals(beginKey)) {
            continue;
        }

        if (temp == null) {
            throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
        }

        while (((temp = bufRdr.readLine()) != null) && !temp.equals(endKey)) {
        	// Skip empty lines
        	if (temp.trim().length() > 0) {
                opstr.print(temp);
        	}
        }

        if (temp == null) {
            throw new IOException("Error in input buffer, missing " + endKey + " boundary");
        }

        opstr.close();

        final byte[] bytes = Base64.decode(ostr.toByteArray());
        log.trace("<getBytesFromPEM");
        return bytes;
    } // getBytesfromPEM

    /**
     * Helpfunction to read a file to a byte array.
     *
     * @param file filename of file.
     *
     * @return byte[] containing the contents of the file.
     *
     * @throws IOException if the file does not exist or cannot be read.
     */
    public static byte[] readFiletoBuffer(final String file)
        throws IOException {
    	final InputStream in = new FileInputStream(file);
        return readInputStreamtoBuffer(in);
    } // readFiletoBuffer

    /**
     * Helpfunction to read an InputStream to a byte array.
     *
     * @return byte[] containing the contents of the file.
     *
     * @throws IOException if the file does not exist or cannot be read.
     */
    public static byte[] readInputStreamtoBuffer(final InputStream in)
        throws IOException {
    	final ByteArrayOutputStream os = new ByteArrayOutputStream();
        int len = 0;
        final byte[] buf = new byte[1024];

        while ((len = in.read(buf)) > 0) {
            os.write(buf, 0, len);
        }

        in.close();
        os.close();

        return os.toByteArray();
    } // readInputStreamtoBuffer

    /**
     * Sort the files by name with directories first.
     */
    public static void sortByName(final File[] files) {
    	if (files == null) {
    		return;
    	}
    	Arrays.sort(files, new FileComp());
    }
    
    private static class FileComp implements Comparator {
    	private final Collator c = Collator.getInstance();

    	public int compare(final Object o1, final Object o2) {
    		if(o1 == o2) {
    			return 0;
    		}
    		final File f1 = (File) o1;
    		final File f2 = (File) o2;
    		if(f1.isDirectory() && f2.isFile()) {
    			return -1;
    		}
    		if(f1.isFile() && f2.isDirectory()) {
    			return 1;
    		}
    		return c.compare(f1.getName(), f2.getName());
    	}
    }
} // FileTools
