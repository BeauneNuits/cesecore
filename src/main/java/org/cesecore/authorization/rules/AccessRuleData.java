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
package org.cesecore.authorization.rules;

import java.io.Serializable;

import javax.persistence.Entity;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.cesecore.authorization.access.AccessTreeState;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * POJO that represents an access rule.
 * 
 * Adapted from AccessRule version $Id$ in EJBCA.
 * 
 * @version $Id$
 * 
 */
@Entity
@Table(name = "AccessRuleData")
public class AccessRuleData extends ProtectedData implements Serializable, Comparable<AccessRuleData> {

    private static final long serialVersionUID = -8052112002139185890L;

    private int primaryKey;
    private String accessRuleName;
    private AccessRuleState internalState;
    private Boolean recursiveBool;
    private Integer recursiveInt;
    private int rowVersion = 0;
    private String rowProtection;

    /**
     * Default constructor.
     */
    public AccessRuleData() {
        
    }
    
    /**
     * Creates a new instance of AccessRule
     * 
     * @param internalState
     *            The rule's state.
     * @param recursive
     *            True if the rule is recursive.
     */
    public AccessRuleData(int primaryKey, String accessruleName, AccessRuleState internalState, boolean isRecursive) {
        this.primaryKey = primaryKey;
        this.accessRuleName = accessruleName.trim();
        this.internalState = internalState;
        setRecursive(isRecursive);
    }
    
    /**
     * Creates a new instance of AccessRule
     * 
     * @param internalState
     *            The rule's state.
     * @param recursive
     *            True if the rule is recursive.
     */
    public AccessRuleData(String roleName, String accessruleName, AccessRuleState internalState, boolean isRecursive) {
        this.primaryKey = generatePrimaryKey(roleName, accessruleName);
        this.accessRuleName = accessruleName.trim();
        this.internalState = internalState;
        setRecursive(isRecursive);
    }

    // @Column
    public String getAccessRuleName() {
        return accessRuleName;
    }

    public void setAccessRuleName(String accessRuleName) {
        this.accessRuleName = accessRuleName.trim();
    }

    @Transient
    public AccessRuleState getInternalState() {
        return internalState;
    }

    public void setInternalState(AccessRuleState state) {
        this.internalState = state;

    }

    /*
     * Formerly known as PRIMKEY
     */
    // @Id @Column
    public int getPrimaryKey() {
        return primaryKey;
    }

    public void setPrimaryKey(int primaryKey) {
        this.primaryKey = primaryKey;
    }

    /** This is a "combined" value of recursiveBool and recursiveInt. Used because some databases lacks a boolean type
     * so booleanInt is a workaround to get boolean values on such databases (Ingres). 
     */ 
    @Transient
    public boolean getRecursive() {
        final Boolean isRecB = getRecursiveBool();
        if (isRecB != null) {
            return isRecB.booleanValue();
        }
        final Integer isRecI = getRecursiveInt();
        if (isRecI != null) {
            return isRecI.intValue() == 1;
        }
        throw new RuntimeException("Could not retreive AccessRulesData.recursive from database.");
    }

    public final void setRecursive(final boolean recursive) {
        setRecursiveBool(Boolean.valueOf(recursive));
        setRecursiveInt(recursive ? 1 : 0);
    }

    /**
     * Use getIsRecursive() instead of this method! Ingres: Transient Non-ingres: Mapped to "isRecursive"
     */
    public Boolean getRecursiveBool() {
        return recursiveBool;
    }

    /** Use setIsRecursive(boolean) instead of this method! */
    public void setRecursiveBool(final Boolean recursiveBool) {
        this.recursiveBool = recursiveBool;
    }

    /**
     * Use getIsRecursive() instead of this method! Ingres: Mapped to "isRecursive" Non-ingres: Transient
     */
    public Integer getRecursiveInt() {
        return recursiveInt;
    }

    /** Use setIsRecursive(boolean) instead of this method! */
    public void setRecursiveInt(final Integer isRecursiveInt) {
        this.recursiveInt = isRecursiveInt;
    }

    // @Version @Column
    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(final int rowVersion) {
        this.rowVersion = rowVersion;
    }

    // @Column @Lob
	@Override
    public String getRowProtection() {
        return rowProtection;
    }

	@Override
    public void setRowProtection(final String rowProtection) {
        this.rowProtection = rowProtection;
    }

    /*
     * Formerly known as "RULE".
     */
    // @Column
    public int getState() {
        return internalState.getDatabaseValue();
    }

    public void setState(int state) {
        this.internalState = AccessRuleState.matchDatabaseValue(state);
    }

    @Transient
    public AccessTreeState getTreeState() {
        AccessTreeState result = AccessTreeState.STATE_UNKNOWN;

        switch (internalState) {
        case RULE_ACCEPT:

            result = (getRecursive() ? AccessTreeState.STATE_ACCEPT_RECURSIVE : AccessTreeState.STATE_ACCEPT);
            break;
        case RULE_DECLINE:
            result = AccessTreeState.STATE_DECLINE;
            break;
        default:
            result = AccessTreeState.STATE_UNKNOWN;
        }

        return result;
    }

    /**
     * The current pk in AdminEntityData and AccessRulesData is a mix of integer pk and constraints and actually works fine. It's used like a
     * primitive int primary key in the db, but embeds logic for enforcing constraints, which would otherwise have to be programatically added to the
     * beans. If needed it can easily be replaced with an int pk and programmatic logic to handle constraints. From the database view the pk is just
     * an int.
     */
    public static int generatePrimaryKey(final String roleName, final String accessRuleName) {
        final int roleNameHash = roleName == null ? 0 : roleName.hashCode();
        final int accessRuleHash = accessRuleName == null ? 0 : (accessRuleName.trim()).hashCode();
        return roleNameHash ^ accessRuleHash;
    }

    @Override
    public int hashCode() {
        final int prime = 47811;
        int result = 1;
        result = prime * result + ((accessRuleName == null) ? 0 : accessRuleName.hashCode());
        result = prime * result + ((internalState == null) ? 0 : internalState.getDatabaseValue());
        result = prime * result + primaryKey;
        result = prime * result + ((recursiveBool == null) ? 0 : recursiveBool.hashCode());
        result = prime * result + ((recursiveInt == null) ? 0 : recursiveInt.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        AccessRuleData other = (AccessRuleData) obj;
        if (accessRuleName == null) {
            if (other.accessRuleName != null) {
                return false;
            }
        } else if (!accessRuleName.equals(other.accessRuleName)) {
            return false;
        }
        //Comparing DB values to defend against the enums being loaded by different class loaders.
        if (internalState != other.internalState) {
      //  if (internalState.getDatabaseValue() != other.internalState.getDatabaseValue()) {
            return false;
        }
        if (primaryKey != other.primaryKey) {
            return false;
        }
        // We must compare the "combined" value of recursiveBool and recursiveInt here, since only one of 
        // the values are used depending on different databases 
        if (getRecursive() != other.getRecursive()) {
        	return false;
        }
        return true;
    }

    @Override
    public String toString() {
    	final StringBuilder buf = new StringBuilder();
    	buf.append(getPrimaryKey()).append(getAccessRuleName()).append(getInternalState()).append(getRecursiveBool()).append(getRecursiveInt());
    	return buf.toString();
    }
	//
	// Start Database integrity protection methods
	//
	
	@Transient
	@Override
	protected String getProtectString(final int version) {
		ProtectionStringBuilder build = new ProtectionStringBuilder();
		// What is important to protect here is the data that we define
		// rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
		build.append(getPrimaryKey()).append(getAccessRuleName()).append(getInternalState()).append(getRecursive());
		return build.toString();
	}

	@Transient
	@Override
	protected int getProtectVersion() {
		return 1;
	}

	@PrePersist
	@PreUpdate
	@Transient
	@Override
	protected void protectData() {
		super.protectData();
	}
	
	@PostLoad
	@Transient
	@Override
	protected void verifyData() {
		super.verifyData();
	}

	@Override 
    @Transient
	protected String getRowId() {
		return String.valueOf(getPrimaryKey());
	}
	//
	// End Database integrity protection methods
	//

    @Override
    public int compareTo(AccessRuleData o) {   
        return accessRuleName.compareTo(o.accessRuleName);
    }

}
