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
package org.cesecore.roles.management;

import java.util.Collection;
import java.util.List;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;

/**
 * The Roles Management interface manages the list of roles and which access rules applies to defined roles. The roles interface also manages the list
 * of Subjects who are part of the roles. There are three distinct methods to this interface:
 * <ul>
 * <li>
 * managing the roles, which by default are only a name not associated with anything.</li>
 * <li>
 * managing access rules, which makes a role into something that defines what subject can do.</li>
 * <li>
 * managing subjects, which makes users part of the role thus giving them the access rights defined by the access rules of the role.</li>
 * </ul>
 * 
 * See {@link https://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#Roles_Management}
 * 
 * @version $Id$
 * 
 */
public interface RoleManagementSession {

    /**
     * Adds a role
     * 
     * @param roleName
     *            Name of the role
     * @throws RoleExistsException
     *             If role by that name already exists.
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    RoleData create(AuthenticationToken authenticationToken, String roleName) throws RoleExistsException, AuthorizationDeniedException;

    /**
     * Remove a role. If the role does not exist nothing is done and the method silently returns.
     * 
     * @param authenticationToken
     *            An authentication token.
     * @param roleName
     *            The name of the role to remove.
     * @throws RoleNotFoundException if role does not exist 
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    void remove(AuthenticationToken authenticationToken, String roleName) throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Removes a known role. Will also remove all associated access rules and user aspects.
     * If the role does not exist nothing is done and the method silently returns.
     * 
     * @param authenticationToken
     *            An authentication token.
     * @param role
     *            the role to remove.
     * @throws RoleNotFoundException if role does not exist 
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    void remove(AuthenticationToken authenticationToken, RoleData role) throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Renames a role.
     * 
     * @param role
     *            The role to change.
     * @param newName
     *            The new name of the role.
     * @throws RoleExistsException
     *             If the new role name already exists.
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    RoleData renameRole(AuthenticationToken authenticationToken, RoleData role, String newName) throws RoleExistsException, AuthorizationDeniedException;

    /**
     * Associates a list of access rules to a role. If the given role already exists, replace it.
     * 
     * @param role
     *            The role
     * @param accessRules
     *            A collection of access rules. These are all presumed to be persisted.
     * @throws AccessRuleNotFoundException
     *             if an access rule was submitted without being persisted first.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     * 
     * @return the merged {@link RoleData}
     */
    RoleData addAccessRulesToRole(AuthenticationToken authenticationToken, RoleData role, Collection<AccessRuleData> accessRules) throws RoleNotFoundException, AccessRuleNotFoundException, AuthorizationDeniedException;

    /**
     * Removes the given access rules from a role.
     * 
     * @param role
     *            The role.
     * @param accessRules
     *            A collection of access rules. If these rules haven't been removed from persistence, they will be here.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    RoleData removeAccessRulesFromRole(AuthenticationToken authenticationToken, RoleData role, Collection<AccessRuleData> accessRules) throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Removes the given access rules from a role.
     * 
     * @param role The role.
     * @param accessRules A collection of strings. These rules will be looked up and removed from persistence.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    RoleData removeAccessRulesFromRole(AuthenticationToken authenticationToken, RoleData role, List<String> accessRuleNames)
            throws RoleNotFoundException, AuthorizationDeniedException;
    
    /**
     * Gives the collection of subjects the given role. If the subject already exists, update it with the new value.
     * 
     * @param subjects
     *            A collection of subjects
     * @param role
     *            The role to give.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     *            
     *            TODO: Rename this method AddAccessUserAspectsToRole
     */
    RoleData addSubjectsToRole(AuthenticationToken authenticationToken, RoleData role, Collection<AccessUserAspectData> subjects) throws RoleNotFoundException, AuthorizationDeniedException;

    /**
     * Removes the role from the list of subjects.
     * 
     * @param subjects
     *            A collection of subjects.
     * @param role
     *            The role to remove.
     * @throws RoleNotFoundException if the role does not exist
     * @throws AuthorizationDeniedException is authenticationToken not authorized to edit roles
     */
    RoleData removeSubjectsFromRole(AuthenticationToken authenticationToken, RoleData role, Collection<AccessUserAspectData> subjects) throws RoleNotFoundException, AuthorizationDeniedException;

}
