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
package org.cesecore.certificates.certificate.request;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Testing various aspects of request messages
 *
 * Based on EJBCA version: RequestMessageTest.java 10353 2011-02-14 14:21:18Z johane
 * 
 * @version $Id$
 */
public class RequestMessageTest {

	 private static KeyPair keyPair;

	 @BeforeClass
	 public static void beforeClass() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		 CryptoProviderTools.installBCProviderIfNotAvailable();
		 keyPair = KeyTools.genKeys("512", null, "RSA");
	 }

	 @Test
	 public void test01Pkcs10RequestMessage() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		 
		 // Create a P10 with extensions, in this case altNames with a DNS name
		 ASN1EncodableVector altnameattr = new ASN1EncodableVector();
		 altnameattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
		 // AltNames
		 // String[] namearray = altnames.split(",");
		 GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foo1.bar.com");
		 ByteArrayOutputStream extOut = new ByteArrayOutputStream();
		 DEROutputStream derOut = new DEROutputStream(extOut);
		 try {
			 derOut.writeObject(san);
		 } catch (IOException e) {
			 throw new IllegalArgumentException("error encoding value: " + e);
		 }
		 // Extension request attribute is a set of X509Extensions
		 // ASN1EncodableVector x509extensions = new ASN1EncodableVector();
		 // An X509Extensions is a sequence of Extension which is a sequence of
		 // {oid, X509Extension}
		 // ASN1EncodableVector extvalue = new ASN1EncodableVector();
		 Vector<DERObjectIdentifier> oidvec = new Vector<DERObjectIdentifier>();
		 oidvec.add(X509Extensions.SubjectAlternativeName);
		 Vector<X509Extension> valuevec = new Vector<X509Extension>();
		 valuevec.add(new X509Extension(false, new DEROctetString(extOut.toByteArray())));
		 X509Extensions exts = new X509Extensions(oidvec, valuevec);
		 altnameattr.add(new DERSet(exts));
		 
		 // Add a challenge password as well
		 ASN1EncodableVector pwdattr = new ASN1EncodableVector();
		 pwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
		 ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
		 pwdvalues.add(new DERUTF8String("foo123"));
		 pwdattr.add(new DERSet(pwdvalues));
		 
		 // Complete the Attribute section of the request, the set (Attributes)
		 // contains one sequence (Attribute)
		 ASN1EncodableVector v = new ASN1EncodableVector();
		 v.add(new DERSequence(altnameattr));
		 v.add(new DERSequence(pwdattr));
		 DERSet attributes = new DERSet(v);

		 // Create the PKCS10
		 X509Name dn = new X509Name("CN=Test,OU=foo");
		 PKCS10CertificationRequest basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), attributes, keyPair.getPrivate());

		 PKCS10RequestMessage msg = new PKCS10RequestMessage(basicpkcs10);
		 String username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,OU=foo", msg.getRequestDN());
		 assertEquals("dNSName=foo1.bar.com", msg.getRequestAltNames());

		 // Same message by try decoding byte array
		 msg = new PKCS10RequestMessage(basicpkcs10.getEncoded());
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,OU=foo", msg.getRequestDN());
		 assertEquals("foo123", msg.getPassword());
		 
		 // Check public key
		 PublicKey pk = msg.getRequestPublicKey();
		 KeyTools.testKey(keyPair.getPrivate(), pk, "BC");
		 PKCS10RequestMessage msgempty = new PKCS10RequestMessage();
		 assertNull(msgempty.getRequestPublicKey());
		 
		 // Verify POP
		 assertTrue(msg.verify());
		 assertTrue(msg.verify(pk));
		 try {
			KeyPair otherkeys = KeyTools.genKeys("512", "RSA");
			assertFalse(msg.verify(otherkeys.getPublic()));
		} catch (InvalidAlgorithmParameterException e) {
			assertTrue("Should not throw", false);
		}
		 
		 // Try different DNs and DN oids
		 dn = new X509Name("C=SE, O=Foo, CN=Test Testsson");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("C=SE,O=Foo,CN=Test Testsson", msg.getRequestDN());
		 assertEquals(null, msg.getRequestAltNames());
		 assertEquals(null, msg.getPassword());

		 // oid for unstructuredName, will be handles specially by EJBCA
		 dn = new X509Name("CN=Test + 1.2.840.113549.1.9.2=AttrValue1");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,unstructuredName=AttrValue1", msg.getRequestDN());

		 dn = new X509Name("CN=Test + 1.2.840.113549.1.9.2=AttrValue1 AttrValue2");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,unstructuredName=AttrValue1 AttrValue2", msg.getRequestDN());

		 dn = new X509Name("CN=Test+1.2.840.113549.1.9.2=AttrValue1");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,unstructuredName=AttrValue1", msg.getRequestDN());

		 dn = new X509Name("CN=Test+1.2.840.113549.1.9.2=AttrValue1 AttrValue2");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test,unstructuredName=AttrValue1 AttrValue2", msg.getRequestDN());

		 // Completely unknown oid
		 dn = new X509Name("CN=Test + 1.2.840.113549.1.9.3=AttrValue1");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1", msg.getRequestDN());

		 dn = new X509Name("CN=Test + 1.2.840.113549.1.9.3=AttrValue1 AttrValue2");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2", msg.getRequestDN());

		 dn = new X509Name("CN=Test+1.2.840.113549.1.9.3=AttrValue1");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1", msg.getRequestDN());

		 dn = new X509Name("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
		 assertEquals("CN=Test+1.2.840.113549.1.9.3=AttrValue1 AttrValue2", msg.getRequestDN());

		 dn = new X509Name("1.2.840.113549.1.9.3=AttrValue1 AttrValue2+CN=Test");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("1.2.840.113549.1.9.3=AttrValue1 AttrValue2+CN=Test+O=abc");
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);

		 dn = new X509Name("1.2.840.113549.1.9.3=AttrValue1\\+\\= AttrValue2+CN=Test+O=abc");	// very strange, but should still be valid 
		 basicpkcs10 = new PKCS10CertificationRequest("SHA1WithRSA", dn, 
				 keyPair.getPublic(), new DERSet(), keyPair.getPrivate());

		 msg = new PKCS10RequestMessage(basicpkcs10);
		 username = msg.getUsername();
		 assertEquals("Test", username);
	 }
 }
