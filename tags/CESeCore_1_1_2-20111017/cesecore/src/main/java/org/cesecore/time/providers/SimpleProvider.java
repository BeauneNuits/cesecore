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

import org.cesecore.time.TrustedTime;

/**
 * This one basic implementation of a TrustedTimeProvider.
 * This implementation should only be used when the system running the CESeCore, 
 * doesn't have any means to validate is current clock. This will not give any guarantees
 * of synchronization since the time that will be provided is retrieved from the system clock.
 * Expect an NextUpdate, Accuracy, Stratum set to NULL and the Sync property always set to false;
 *
 * @version $Id$
 *
 */
public class SimpleProvider implements TrustedTimeProvider {

    private static final long serialVersionUID = 3780578519196822183L;

    @Override
	public TrustedTime getTrustedTime() {
		final TrustedTime tt = new TrustedTime();
		tt.setSync(false);
		return tt;
	}

}
