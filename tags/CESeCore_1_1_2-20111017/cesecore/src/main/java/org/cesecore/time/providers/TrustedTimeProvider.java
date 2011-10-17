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
package org.cesecore.time.providers;

import java.io.Serializable;

import org.cesecore.time.TrustedTime;

/**
 * This interface should be implemented by any provider of trusted time.
 *
 * @version $Id$
 */
public interface TrustedTimeProvider extends Serializable {

    /**
     * This should return a TrustedTime instance fully assigned. i.e:
     * The Accuracy must be set;
     * The Stratum must be set;
     * The NextUpdate must be set (for watcher scheduling);
     * And Sync must indicate if this data is synchronized or not.
     *
     * @return TrustedTime instance.
     */
    public TrustedTime getTrustedTime();

}
