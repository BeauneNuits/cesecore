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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Set;

import javax.ejb.CreateException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Interface for certificate store operations
 * Stores certificate in the local database using Certificate JPA Beans. 
 * 
 *
 * Based on EJBCA version: CertificateStoreSession.java 11010 2010-12-29 17:40:11Z jeklund
 * 
 * Removed all CertReqHistory stuff, which belongs in it's own session bean in EJBCA
 * Also removed authenticate method, strange place...
 * Also removed getDatabaseStatus, completely wrong place, move to own healthcheck session
 * Also removed setArchivedStatus, strange "use internally only" method
 * IMPORTANT: Also removed publishing to publishersession from setRevokeStatus
 * 
 * @version $Id$
 */
public interface CertificateStoreSession {

    /**
     * Stores a certificate.
     * 
     * @param incert The certificate to be stored.
     * @param cafp Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status the status from the CertificateConstants.CERT_ constants
     * @param type Type of certificate (CERTTYPE_ENDENTITY etc from CertificateConstants).
     * @param certificateProfileId the certificate profile id this cert was issued under
     * @param tag a custom string tagging this certificate for some purpose
     * @return true if storage was successful.
     * @throws CreateException if the certificate can not be stored in the database
     */
    boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username,
            String cafp, int status, int type, int certificateProfileId, String tag, long updateTime) throws CreateException, AuthorizationDeniedException;

    /**
     * Lists fingerprint (primary key) of ALL certificates in the database.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what
     * happens if there are millions of certificates in the DB!). Should only be
     * used for testing purposes.
     * 
     * @param issuerdn the dn of the certificates issuer.
     * @return Collection of fingerprints, i.e. Strings
     */
    Collection<String> listAllCertificates(String issuerdn);

    /**
     * Lists RevokedCertInfo of ALL revoked certificates (status =
     * CertificateConstants.CERT_REVOKED) in the database from a certain issuer.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what
     * happens if there are millions of certificates in the DB!). Should only be
     * used for testing purposes.
     * 
     * @param issuerdn the dn of the certificates issuer.
     * @param lastbasecrldate a date (Date.getTime()) of last base CRL or -1 for a complete CRL
     * @return Collection of RevokedCertInfo, reverse ordered by expireDate
     *         where last expireDate is first in array.
     */
    Collection<RevokedCertInfo> listRevokedCertInfo(String issuerdn, long lastbasecrldate);

    /**
     * Lists certificates for a given subject signed by the given issuer.
     * 
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @param issuerDN the dn of the certificates issuer.
     * @return Collection of Certificates (java.security.cert.Certificate) in no
     *         specified order or an empty Collection.
     */
    Collection<Certificate> findCertificatesBySubjectAndIssuer(String subjectDN, String issuerDN);

    /** @return set of users with certificates with specified subject DN issued by specified issuer. */
    Set<String> findUsernamesByIssuerDNAndSubjectDN(String issuerDN, String subjectDN);

    /** @return set of users with certificates with specified key issued by specified issuer. */
    Set<String> findUsernamesByIssuerDNAndSubjectKeyId(String issuerDN, byte[] subjectKeyId);

    /**
     * Lists certificates for a given subject.
     * 
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @return Collection of Certificates (java.security.cert.Certificate) in no
     *         specified order or an empty Collection.
     */
    Collection<Certificate> findCertificatesBySubject(String subjectDN);

    /**
     * Finds certificates  expiring within a specified time and that has
     * status "active" or "notifiedaboutexpiration".
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
     * @return Collection of Certificate, never null
     */
    Collection<Certificate> findCertificatesByExpireTimeWithLimit(Date expireTime);

    /**
     * Finds usernames of users having certificate(s) expiring within a
     * specified time and that has status "active" or "notifiedaboutexpiration".
     * 
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
     * @return Collection of String, never null
     */
    Collection<String> findUsernamesByExpireTimeWithLimit(Date expiretime);

    /**
     * Finds a certificate specified by issuer DN and serial number.
     * 
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno serial number of the desired certificate!
     * @return Certificate if found or null
     */
    Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno);

    /**
     * Find a certificate by its subject key ID
     * 
     * @param subjectKeyId subject key ID of the sought certificate
     * @return Certificates if found, or null.
     */
    Collection<Certificate> findCertificatesBySubjectKeyId(byte[] subjectKeyId);
    
    /**
     * The method retrieves all certificates from a specific issuer which are
     * identified by list of serial numbers. The collection will be empty if the
     * issuerDN is <tt>null</tt>/empty or the collection of serial numbers is
     * empty.
     * 
     * @param issuerDN the subjectDN of a CA certificate
     * @param sernos a collection of certificate serialnumbers
     * @return Collection a list of certificates; never <tt>null</tt>
     */
    Collection<Certificate> findCertificatesByIssuerAndSernos(String issuerDN, Collection<BigInteger> sernos);

    /**
     * Finds certificate(s) for a given serialnumber.
     * 
     * @param serno the serialnumber of the certificate(s) that will be retrieved
     * @return Certificate or null if none found.
     */
    Collection<Certificate> findCertificatesBySerno(BigInteger serno);

    /**
     * Find the latest published X509Certificate matching the given subject DN
     * 
     * @param subjectDN The subject DN to match.
     * @return the sought result, or null if none exists. 
     */
    X509Certificate findLatestX509CertificateBySubject(String subjectDN);
    
    /**
     * Finds username for a given certificate serial number.
     * 
     * @param serno the serialnumber of the certificate to find username for.
     * @return username or null if none found.
     */
    String findUsernameByCertSerno(BigInteger serno, String issuerdn);

    /**
     * Finds certificate(s) for a given username.
     * 
     * @param username the username of the certificate(s) that will be retrieved
     * @return Collection of Certificates ordered by expire date, with last
     *         expire date first, or null if none found.
     */
    Collection<Certificate> findCertificatesByUsername(String username);

    /**
     * Finds certificate(s) for a given username and status.
     * 
     * @param username the username of the certificate(s) that will be retrieved
     * @param status the status from the CertificateConstants.CERT_ constants
     * @return Collection of Certificates ordered by expire date, with last
     *         expire date first, or empty list if user can not be found
     */
    Collection<Certificate> findCertificatesByUsernameAndStatus(String username, int status);

    /**
     * Gets certificate info, which is basically all fields except the
     * certificate itself. Note: this method should not be used within a
     * transaction where the reading of this info might depend on something
     * stored earlier in the transaction. This is because this method uses
     * direct SQL.
     * 
     * @return CertificateInfo or null if certificate does not exist.
     */
    CertificateInfo getCertificateInfo(String fingerprint);

    /**
     * Finds a certificate based on fingerprint. 
     * You can get fingerprint by for example "String fingerprint = CertTools.getFingerprintAsString(certificate);"
     * @return Certificate or null if it can not be found.
     */
    Certificate findCertificateByFingerprint(String fingerprint);

    /**
     * Lists all active (status = 20) certificates of a specific type and if
     * given from a specific issuer.
     *
     * @param issuerDN get all certificates issued by a specific issuer.
     *                 If <tt>null</tt> or empty return certificates regardless of
     *                 the issuer.
     * @param type     CERTTYPE_* types from CertificateConstants
     * @throws IllegalArgumentException when admin is null or type is not one or more of of SecConst.CERTTYPE_SUBCA, SecConst.CERTTYPE_ENDENTITY, SecConst.CERTTYPE_ROOTCA
     * @return Collection Collection of Certificate, never <tt>null</tt>
     */
    Collection<Certificate> findCertificatesByType(int type, String issuerDN);

    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * @param admin      AuthenticationToken performing the operation
     * @param issuerdn   Issuer of certificate to be removed.
     * @param serno      the serno of certificate to revoke.
     * @param revokeDate when it was revoked
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate, the object could be taken from user data instead.
     * @return true if status was changed in the database, false if not, for example if the certificate was already revoked or a null value was passed as certificate
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     */
    boolean setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno, Date revokedDate,
            int reason, String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException;

    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * @param admin      AuthenticationToken performing the operation
     * @param issuerdn   Issuer of certificate to be removed.
     * @param certificate the certificate to revoke or activate.
     * @param revokeDate when it was revoked
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate, the object could be taken from user data instead.
     * @return true if status was changed in the database, false if not, for example if the certificate was already revoked or a null value was passed as certificate
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     */
    boolean setRevokeStatus(AuthenticationToken admin, Certificate certificate, Date revokedDate, int reason, String userDataDN)
        throws CertificateRevokeException, AuthorizationDeniedException;
    
    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * @param admin      AuthenticationToken performing the operation
     * @param issuerdn   Issuer of certificate to be removed.
     * @param serno      the serno of certificate to revoke.
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate, the object could be taken from user data instead.
     * @return true if status was changed in the database, false if not, for example if the certificate was already revoked or a null value was passed as certificate
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     */
    boolean setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno,
            int reason, String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException;

    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * @param admin      AuthenticationToken performing the operation
     * @param issuerdn   Issuer of certificate to be removed.
     * @param certificate the certificate to revoke or activate.
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate, the object could be taken from user data instead.
     * @return true if status was changed in the database, false if not, for example if the certificate was already revoked or a null value was passed as certificate
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     */
    boolean setRevokeStatus(AuthenticationToken admin, Certificate certificate, int reason, String userDataDN)
    	throws CertificateRevokeException, AuthorizationDeniedException;

    /**
     * Method revoking all certificates generated by the specified issuerdn. Sets revocationDate to current time. 
     * Should only be called by when a CA is about to be revoked.
     * 
     * @param admin    the administrator performing the event.
     * @param issuerdn the dn of CA about to be revoked
     * @param reason   the reason of revocation.
     */
    void revokeAllCertByCA(AuthenticationToken admin, String issuerdn, int reason) throws AuthorizationDeniedException;

    /**
     * Method that checks if a users all certificates have been revoked.
     * 
     * @param username the username to check for.
     * @return returns true if all certificates are revoked.
     */
    boolean checkIfAllRevoked(String username);

    /**
     * Checks if a certificate is revoked.
     * 
     * @param issuerDN the DN of the issuer.
     * @param serno the serialnumber of the certificate that will be checked
     * @return true if the certificate is revoked or can not be found in the
     *         database, false if it exists and is not revoked.
     */
    boolean isRevoked(String issuerDN, BigInteger serno);

    /**
     * Get certificate status fast.
     * @return CertificateStatus status of the certificate, never null, CertificateStatus.NOT_AVAILABLE if the certificate is not found.
     */
    CertificateStatus getStatus(String issuerDN, BigInteger serno);

    /**
     * Update the status of a cert in the database.
     * @param fingerprint
     * @param status one of CertificateConstants.CERT_...
     * @return true if the status was updated, false if not, for example if the certificate did not exist
     */
    boolean setStatus(AuthenticationToken admin, String fingerprint, int status) throws AuthorizationDeniedException;
}
