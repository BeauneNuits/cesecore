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
package org.cesecore.audit.enums;

/**
 * Contains all event types that CESeCore core needs to log to secure audit log. 
 *
 * When doing secure audit log it is necessary to identify the event being logged.
 *
 * @version $Id$
 */
public enum EventTypes implements EventType {

    ACCESS_CONTROL,
    AUTHENTICATION,
    CA_CREATION,
    CA_DELETION,
    CA_RENAMING,
    CA_EDITING,
    CA_KEYGEN,
    CA_KEYACTIVATE,
    CA_KEYDELETE,
    CA_TOKENACTIVATE,
    CA_TOKENDEACTIVATE,
    CERT_STORED,
    CERT_REVOKED,
    CERT_CHANGEDSTATUS,
    CERT_REQUEST,
    CERT_CREATION,
    CERTIFICATE_KEY_BIND,
    CERTIFICATE_KEY_UNBIND,
    CERTPROFILE_CREATION,
    CERTPROFILE_DELETION,
    CERTPROFILE_RENAMING,
    CERTPROFILE_EDITING,
    CRL_STORED,
    CRL_DELETED,
    CRL_CREATION,
    CRYPTOTOKEN_CREATE,
    CRYPTOTOKEN_DELETE_ENTRY,
    CRYPTOTOKEN_GEN_KEYPAIR,
    CRYPTOTOKEN_GEN_KEY,
    CRYPTOTOKEN_GEN_EXTRACT_KEYPAIR,
    LOG_DELETE,
    LOG_EXPORT,
    LOG_MANAGEMENT_CHANGE,
    LOG_SIGN,
    LOG_VERIFY,
    ROLE_CREATION,
    ROLE_DELETION,
    ROLE_RENAMING,
    ROLE_ACCESS_RULE_ADDITION,
    ROLE_ACCESS_RULE_DELETION,
    ROLE_ACCESS_USER_ADDITION,
    ROLE_ACCESS_USER_DELETION,
    BACKUP,
    RESTORE,
    TIME_SYNC_ACQUIRE,
    TIME_SYNC_LOST;

    @Override
    public boolean equals(EventType value) {
        if(value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }
}
