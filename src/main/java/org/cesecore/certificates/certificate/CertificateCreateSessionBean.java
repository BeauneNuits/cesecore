/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;

/**
 * Interface for creating certificates
 * 
 * Based on EJBCA version: RSASignSessionBean.java 11374 2011-02-19 08:12:26Z anatom
 * 
 * Only one method from this bean is used, and it's the private method for creating certificates, also this modified.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CertificateCreateSessionBean implements CertificateCreateSessionLocal, CertificateCreateSessionRemote {

    private static final Logger log = Logger.getLogger(CertificateCreateSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @Resource
    private SessionContext sessionContext;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    // Myself needs to be looked up in postConstruct
    private CertificateCreateSessionLocal certificateCreateSession;

    /** Default create for SessionBean without any creation Arguments. */
    @PostConstruct
    public void postConstruct() {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();
        // We lookup the reference to our-self in PostConstruct, since we cannot inject this.
        certificateCreateSession = sessionContext.getBusinessObject(CertificateCreateSessionLocal.class);
    }

    @Override
    public CertificateResponseMessage createCertificate(final AuthenticationToken admin, final EndEntityInformation userData, final RequestMessage req,
            final Class responseClass) throws AuthorizationDeniedException, CustomCertSerialNumberException, IllegalKeyException,
            CADoesntExistsException, CertificateCreateException, CesecoreException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(IRequestMessage)");
        }
        CertificateResponseMessage ret = null;
        try {
            CA ca;
            // First find the CA, this checks authorization and that the CA exists
            if ((userData == null) || (userData.getCAId() == 0)) {
                // If no CAid in the supplied userdata
                ca = getCAFromRequest(admin, req);
            } else {
                ca = caSession.getCA(admin, userData.getCAId());
            }

            final CAToken catoken = ca.getCAToken();

            // See if we need some key material to decrypt request
            if (req.requireKeyInfo()) {
                // You go figure...scep encrypts message with the public CA-cert
                req.setKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken()
                        .getEncProviderName());
            }
            // Verify the request
            final PublicKey reqpk;
            try {
                if (req.verify() == false) {
                    final String msg = intres.getLocalizedMessage("createcert.popverificationfailed");
                    // logSession.log(admin, ca.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), req.getUsername(), null,
                    // LogConstants.EVENT_ERROR_CREATECERTIFICATE, msg);
                    throw new SignRequestSignatureException(msg);
                }
                reqpk = req.getRequestPublicKey();
                if (reqpk == null) {
                    final String msg = intres.getLocalizedMessage("createcert.nokeyinrequest");
                    throw new InvalidKeyException(msg);
                }
            } catch (InvalidKeyException e) {
                // If we get an invalid key exception here, we shoudl throw an IllegalKeyException to the caller
                // The catch of InvalidKeyException in the end of this method, catches error from the CA crypto token
                throw new IllegalKeyException(e);
            }

            final Date notBefore = req.getRequestValidityNotBefore(); // Optionally requested validity
            final Date notAfter = req.getRequestValidityNotAfter(); // Optionally requested validity
            final X509Extensions exts = req.getRequestExtensions(); // Optionally requested extensions
            int keyusage = -1;
            if (exts != null) {
                if (log.isDebugEnabled()) {
                    log.debug("we have extensions, see if we can override KeyUsage by looking for a KeyUsage extension in request");
                }
                final X509Extension ext = exts.getExtension(X509Extensions.KeyUsage);
                if (ext != null) {
                    final ASN1OctetString os = ext.getValue();
                    final ByteArrayInputStream bIs = new ByteArrayInputStream(os.getOctets());
                    final ASN1InputStream dIs = new ASN1InputStream(bIs);
                    try {
                        final DERObject dob = dIs.readObject();
                        final DERBitString bs = DERBitString.getInstance(dob);
                        keyusage = bs.intValue();
                    } catch (IOException e) {
                        log.warn("Invalid KeyUsage extension in request, extensionbytes: " + new String(Base64.encode(exts.getEncoded())));
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("We have a key usage request extension: " + keyusage);
                    }
                }
            }
            String sequence = null;
            byte[] ki = req.getRequestKeyInfo();
            // CVC sequence is only 5 characters, don't fill with a lot of garbage here, it must be a readable string
            if ((ki != null) && (ki.length > 0) && (ki.length < 10) ) {
            	final String str = new String(ki);
            	// A cvc sequence must be ascii printable, otherwise it's some binary data
            	if (StringUtils.isAsciiPrintable(str)) {
                    sequence = new String(ki);            		
            	}
            }
            Certificate cert = createCertificate(admin, userData, ca, req.getRequestX509Name(), reqpk, keyusage, notBefore, notAfter, exts, sequence);

            // Create the response message with all nonces and checks etc
            ret = req.createResponseMessage(responseClass, req, ca.getCACertificate(), catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
                    catoken.getCryptoToken().getSignProviderName());

            ResponseStatus status = ResponseStatus.SUCCESS;
            FailInfo failInfo = null;
            String failText = null;
            if ((cert == null) && (status == ResponseStatus.SUCCESS)) {
                status = ResponseStatus.FAILURE;
                failInfo = FailInfo.BAD_REQUEST;
            } else {
                ret.setCertificate(cert);
            }
            ret.setStatus(status);
            if (failInfo != null) {
                ret.setFailInfo(failInfo);
                ret.setFailText(failText);
            }

            ret.create();
        } catch (IOException e) {
            throw new CertificateCreateException(e);
        } catch (InvalidKeyException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalCryptoTokenException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalCryptoTokenException(e);
        }

        if (log.isTraceEnabled()) {
            log.trace("<createCertificate(IRequestMessage)");
        }
        return ret;
    }

    /**
     * Help Method that extracts the CA specified in the request.
     * 
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     */
    private CA getCAFromRequest(final AuthenticationToken admin, final RequestMessage req) throws CADoesntExistsException,
    AuthorizationDeniedException {
    	CA ca = null;
    	// See if we can get issuerDN directly from request
    	if (req.getIssuerDN() != null) {
    		String dn = getCADnFromRequest(req, certificateStoreSession);
    		ca = caSession.getCA(admin, dn.hashCode());
    		if (log.isDebugEnabled()) {
    			log.debug("Using CA (from issuerDN) with id: " + ca.getCAId() + " and DN: " + ca.getSubjectDN());
    		}
    	} else {
    		throw new CADoesntExistsException(intres.getLocalizedMessage("createcert.canotfoundissuerusername", req.getIssuerDN(), req.getUsername()));
    	}

    	if (ca.getStatus() != CAConstants.CA_ACTIVE) {
    		final String msg = intres.getLocalizedMessage("createcert.canotactive", ca.getSubjectDN());
    		throw new EJBException(msg);
    	}
    	return ca;
    }

    /** Tries to get an issuerDN/serialNumber pair from the request, and see if we have that CA certificate in the certificate store. If we have
     * the CA dn, in CESeCore normalized for is returned. 
     * @param req the request message that might contain an issued DN
     * @return issuer DN or null if it does not exist in the 
     */
    public static final String getCADnFromRequest(final RequestMessage req, final CertificateStoreSession certificateStoreSession) {
    	String dn = req.getIssuerDN();
    	if (log.isDebugEnabled()) {
    		log.debug("Got an issuerDN: " + dn);
    	}
    	// If we have issuer and serialNo, we must find the CA certificate, to get the CAs subject name
    	// If we don't have a serialNumber, we take a chance that it was actually the subjectDN (for example a RootCA)
    	final BigInteger serno = req.getSerialNo();
    	if (serno != null) {
    		if (log.isDebugEnabled()) {
    			log.debug("Got a serialNumber: " + serno.toString(16));
    		}

    		final Certificate cert = certificateStoreSession.findCertificateByIssuerAndSerno(dn, serno);
    		if (cert != null) {
    			dn = CertTools.getSubjectDN(cert);
    		}
    	}
    	if (log.isDebugEnabled()) {
    		log.debug("Using DN: " + dn);
    	}
    	return dn;
    }

    @Override
    public Certificate createCertificate(final AuthenticationToken admin, final EndEntityInformation data, final CA ca,
            final X509Name requestX509Name, final PublicKey pk, final int keyusage, final Date notBefore, final Date notAfter,
            final X509Extensions extensions, final String sequence) throws CustomCertSerialNumberException, IllegalKeyException,
            AuthorizationDeniedException, CertificateCreateException, CesecoreException {
        if (log.isTraceEnabled()) {
            log.trace(">createCertificate(EndEntityInformation, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)");
        }
        
        // Since CA is passed as an argument to this method, there is no need to check authorization on that.
        
        // We need to check that admin have rights to create certificates
        if (!accessSession.isAuthorized(admin, StandardRules.CREATECERT.resource())) {
            final String msg = intres.getLocalizedMessage("createcert.notauthorized", admin.toString(), ca.getCAId());
            throw new AuthorizationDeniedException(msg);
        }

        // Audit log that we received the request
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("subjectdn", data.getDN());
        details.put("requestX509name", requestX509Name == null ? "null" : requestX509Name.toString());
        details.put("certprofile", data.getCertificateProfileId());
        details.put("keyusage", keyusage);
        details.put("notbefore", notBefore);
        details.put("notafter", notAfter);
        details.put("sequence", sequence);
        details.put("publickey", new String(Base64.encode(pk.getEncoded(), false)));
        logSession.log(EventTypes.CERT_REQUEST, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), Integer.valueOf(ca.getCAId()).toString(), null, data.getUsername(), details);

        try {
            // If the user is of type USER_INVALID, it cannot have any other type (in the mask)
            if (data.getType() == EndEntityConstants.USER_INVALID) {
                final String msg = intres.getLocalizedMessage("createcert.usertypeinvalid", data.getUsername());
                throw new CertificateCreateException(msg);
            }
            final Certificate cacert = ca.getCACertificate();
            final String caSubjectDN = CertTools.getSubjectDN(cacert);
            if (ca.isDoEnforceUniqueDistinguishedName()) {
                if (ca.isUseCertificateStorage()) {
                    final Set<String> users = certificateStoreSession.findUsernamesByIssuerDNAndSubjectDN(caSubjectDN, data.getCertificateDN());
                    if (users.size() > 0 && !users.contains(data.getUsername())) {
                        final String msg = intres.getLocalizedMessage("createcert.subjectdn_exists_for_another_user", "'" + data.getUsername() + "'",
                                listUsers(users));
                        log.info(msg);
                        throw new CesecoreException(ErrorCode.CERTIFICATE_WITH_THIS_SUBJECTDN_ALLREADY_EXISTS_FOR_ANOTHER_USER, msg);
                    }
                } else {
                    log.warn("CA configured to enforce unique SubjectDN, but not to store issued certificates. Check will be ignored. Please verify your configuration.");
                }
            }
            if (ca.isDoEnforceUniquePublicKeys()) {
                if (ca.isUseCertificateStorage()) {
                    final Set<String> users = certificateStoreSession.findUsernamesByIssuerDNAndSubjectKeyId(caSubjectDN, KeyTools
                            .createSubjectKeyId(pk).getKeyIdentifier());
                    if (users.size() > 0 && !users.contains(data.getUsername())) {
                        final String msg = intres.getLocalizedMessage("createcert.key_exists_for_another_user", "'" + data.getUsername() + "'",
                                listUsers(users));
                        log.info(msg);
                        throw new CesecoreException(ErrorCode.CERTIFICATE_FOR_THIS_KEY_ALLREADY_EXISTS_FOR_ANOTHER_USER, msg);
                    }
                } else {
                    log.warn("CA configured to enforce unique entity keys, but not to store issued certificates. Check will be ignored. Please verify your configuration.");
                }
            }
            // Retrieve the certificate profile this user should have, checking for authorization to the profile
            final int certProfileId = data.getCertificateProfileId();
            final CertificateProfile certProfile = getCertificateProfile(certProfileId, ca.getCAId());

            // Check that the request public key fulfills policy
            verifyKey(pk, certProfile);

            // Below we have a small loop if it would happen that we generate the same serial number twice
            // If using only 4 byte serial numbers this do happen once in a while
            Certificate cert = null;
            String cafingerprint = null;
            String serialNo = "unknown";
            final long updateTime = new Date().getTime();
            String tag = null;
            final boolean useCustomSN;
            {
                final ExtendedInformation ei = data.getExtendedinformation();
                useCustomSN = ei != null && ei.certificateSerialNumber() != null;
            }
            final int maxRetrys;
            if (useCustomSN) {
                if (ca.isUseCertificateStorage() && !certificateCreateSession.isUniqueCertificateSerialNumberIndex()) {
                    final String msg = intres.getLocalizedMessage("createcert.not_unique_certserialnumberindex");
                    log.error(msg);
                    throw new CustomCertSerialNumberException(new CesecoreException(msg));
                }
                if (!certProfile.getAllowCertSerialNumberOverride()) {
                    final String msg = intres
                            .getLocalizedMessage("createcert.certprof_not_allowing_cert_sn_override", Integer.valueOf(certProfileId));
                    log.info(msg);
                    throw new CesecoreException(msg);
                }
                maxRetrys = 1;
            } else {
                maxRetrys = 5;
            }
            Exception storeEx = null; // this will not be null if stored == false after the below passage
            for (int retrycounter = 0; retrycounter < maxRetrys; retrycounter++) {
                cert = ca.generateCertificate(data, requestX509Name, pk, keyusage, notBefore, notAfter, certProfile, extensions, sequence);
                serialNo = CertTools.getSerialNumberAsString(cert);
                cafingerprint = CertTools.getFingerprintAsString(cacert);
                // Store certificate in the database, if this CA is configured to do so.
                if (!ca.isUseCertificateStorage()) {
                    break; // We have our cert and we don't need to store it.. Move on..
                }
                try {
                    // Authorization was already checked by since this is a private method, the CA parameter should
                    // not be possible to get without authorization
                    certificateStoreSession.storeCertificateNoAuth(admin, cert, data.getUsername(), cafingerprint, CertificateConstants.CERT_ACTIVE,
                            certProfile.getType(), certProfileId, tag, updateTime);
                    storeEx = null;
                    break;
                } catch (Exception e) {
                    // If we have created a unique index on (issuerDN,serialNumber) on table CertificateData we can
                    // get a CreateException here if we would happen to generate a certificate with the same serialNumber
                    // as one already existing certificate.
                    if (retrycounter + 1 < maxRetrys) {
                        log.info("Can not store certificate with serNo (" + serialNo + "), will retry (retrycounter=" + retrycounter
                                + ") with a new certificate with new serialNo: " + e.getMessage());
                    }
                    storeEx = e;
                }
            }
            if (storeEx != null) {
                if (useCustomSN) {
                    final String msg = intres.getLocalizedMessage("createcert.cert_serial_number_allready_in_database", serialNo);
                    log.info(msg);
                    throw new CesecoreException(msg);
                }
                log.error("Can not store certificate in database in 5 tries, aborting: ", storeEx);
                throw storeEx;
            }

            // Finally we check if this certificate should not be issued as active, but revoked directly upon issuance
            int revreason = RevokedCertInfo.NOT_REVOKED;
            ExtendedInformation ei = data.getExtendedinformation();
            if (ei != null) {
            	revreason = ei.getIssuanceRevocationReason();
            	if (revreason != RevokedCertInfo.NOT_REVOKED) {
                    // If we don't store the certificate in the database, we wont support revocation/reactivation so issuing revoked certificates would be
                    // really strange.
                    if (ca.isUseCertificateStorage()) {
                        certificateStoreSession.setRevokeStatusNoAuth(admin, cert, new Date(), revreason, data.getDN());
                    } else {
                        log.warn("CA configured to revoke issued certificates directly, but not to store issued the certificates. Revocation will be ignored. Please verify your configuration.");
                    }
            	}
            }
            if (log.isDebugEnabled()) {
                log.debug("Generated certificate with SerialNumber '" + serialNo + "' for user '" + data.getUsername() + "', with revocation reason="
                        + revreason);
                log.debug(cert.toString());
            }

            // Audit log that we issued the certificate
            final Map<String, Object> issuedetails = new LinkedHashMap<String, Object>();
            issuedetails.put("subjectdn", data.getDN());
            issuedetails.put("certprofile", data.getCertificateProfileId());
            issuedetails.put("issuancerevocationreason", revreason);
            issuedetails.put("cert", new String(Base64.encode(cert.getEncoded(), false)));
            logSession.log(EventTypes.CERT_CREATION, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), Integer.valueOf(ca.getCAId()).toString(), serialNo, data.getUsername(),
            		issuedetails);

            if (log.isTraceEnabled()) {
                log.trace("<createCertificate(EndEntityInformation, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)");
            }
            return cert;
            // We need to catch and re-throw all of these exception just because we need to audit log all failures
        } catch (CryptoTokenOfflineException e) {
            final String msg = intres.getLocalizedMessage("error.catokenoffline", ca.getCAId());
            log.info(msg);
            auditFailure(admin, e, e.getMessage(), "<createCertificate(EndEntityInformation, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), data.getUsername());
            throw e;
        } catch (AuthorizationDeniedException e) {
            log.info(e.getMessage());
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), data.getUsername());
            throw e;
        } catch (CustomCertSerialNumberException e) {
            log.info(e.getMessage());
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), data.getUsername());
            throw e;
        } catch (IllegalKeyException e) {
            log.info(e.getMessage());
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), data.getUsername());
            throw e;
        } catch (CertificateCreateException e) {
            log.info(e.getMessage());
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), data.getUsername());
            // Rollback
            throw e;
        } catch (CesecoreException e) {
            log.info(e.getMessage());
            auditFailure(admin, e, null, "<createCertificate(EndEntityInformation, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), data.getUsername());
            throw e;
        } catch (Exception e) {
            log.error("Error creating certificate", e);
            auditFailure(admin, e, null, "<createCertificate(UserDataVO, CA, X509Name, pk, ku, notBefore, notAfter, extesions, sequence)", ca.getCAId(), data.getUsername());
            // Rollback
            throw new CertificateCreateException(e);
        }
    }

    private CertificateProfile getCertificateProfile(final int certProfileId, final int caid)
            throws AuthorizationDeniedException {
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certProfileId);
        // What if certProfile == null?
        if (certProfile == null) {
            final String msg = intres.getLocalizedMessage("createcert.errorcertprofilenotfound", Integer.valueOf(certProfileId));
            throw new AuthorizationDeniedException(msg);
        }
        if (log.isDebugEnabled()) {
            log.debug("Using certificate profile with id " + certProfileId);
        }

        // Check that CAid is among available CAs
        boolean caauthorized = false;
        for (final Integer nextInt : certProfile.getAvailableCAs()) {
            final int next = nextInt.intValue();
            if (next == caid || next == CertificateProfile.ANYCA) {
                caauthorized = true;
                break;
            }
        }
        if (!caauthorized) {
            final String msg = intres.getLocalizedMessage("createcert.errorcertprofilenotauthorized", Integer.valueOf(caid),
                    Integer.valueOf(certProfileId));
            throw new AuthorizationDeniedException(msg);
        }
        return certProfile;
    }

    /**
     * FIXME: Documentation
     * 
     * @param admin
     * @param e
     */
    private void auditFailure(final AuthenticationToken admin, final Exception e, final String extraDetails, final String tracelog, final int caid, final String username) {
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", e.getMessage());
        if (extraDetails != null) {
            details.put("details", extraDetails);
        }
        logSession.log(EventTypes.CERT_CREATION, EventStatus.FAILURE, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), Integer.valueOf(caid).toString(), null, username, details);
        if (log.isTraceEnabled()) {
            if (tracelog != null) {
                log.trace(tracelog);
            }
        }
    }

    /**
     * Checks that a public key sent in a request fulfills the policy in the CertificateProfile
     * 
     * @param pk PublicKey sent in request
     * @param certProfile CertificateProfile with the key policy (length restrictions)
     * @throws IllegalKeyException if the PublicKey does not fulfill policy in CertificateProfile
     */
    private void verifyKey(final PublicKey pk, final CertificateProfile certProfile) throws IllegalKeyException {
        // Verify key length that it is compliant with certificate profile
        final int keyLength = KeyTools.getKeyLength(pk);
        if (log.isDebugEnabled()) {
            log.debug("Keylength = " + keyLength);
        }
        if (keyLength == -1) {
            final String text = intres.getLocalizedMessage("createcert.unsupportedkeytype", pk.getClass().getName());
            // logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null,
            // LogConstants.EVENT_INFO_CREATECERTIFICATE, text);
            throw new IllegalKeyException(text);
        }
        if ((keyLength < (certProfile.getMinimumAvailableBitLength() - 1)) || (keyLength > (certProfile.getMaximumAvailableBitLength()))) {
            final String text = intres.getLocalizedMessage("createcert.illegalkeylength", Integer.valueOf(keyLength));
            // logSession.log(admin, data.getCAId(), LogConstants.MODULE_CA, new java.util.Date(), data.getUsername(), null,
            // LogConstants.EVENT_INFO_CREATECERTIFICATE, text);
            throw new IllegalKeyException(text);
        }
    }

    /**
     * Small function that makes a list of users, space separated. Used for logging. Only actually displays the first 10 records, then a notice how
     * many records were not displayed
     * 
     * @param users a set of usernames to create a string of
     * @return space separated list of usernames, i.e. "'user1' 'user2' 'user3'", max 10 users
     */
    private String listUsers(final Set<String> users) {
        final StringBuilder sb = new StringBuilder();
        int bar = 0; // limit number of displayed users
        for (final String user : users) {
            if (sb.length() > 0) {
                sb.append(' ');
            }
            if (bar++ > 9) {
                sb.append("and ").append(users.size() - bar + 1).append(" users not displayed");
                break;
            }
            sb.append('\'');
            sb.append(user);
            sb.append('\'');
        }
        return sb.toString();
    }

	// We want each storage of a certificate to run in a new transactions, so we can catch errors as they happen..
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	@Override
    public boolean isUniqueCertificateSerialNumberIndex() {
    	return UniqueSernoHelper.isUniqueCertificateSerialNumberIndex(certificateStoreSession);
    }
}
