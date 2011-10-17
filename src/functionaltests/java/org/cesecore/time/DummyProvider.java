package org.cesecore.time;

import org.cesecore.time.providers.TrustedTimeProvider;

public class DummyProvider implements TrustedTimeProvider {

    private static final long serialVersionUID = -3611925743196629339L;

    @Override
    public TrustedTime getTrustedTime() {
        final TrustedTime tt = new TrustedTime();
        tt.setSync(false);
        tt.setNextUpdate(0, 0); // this will give us an update interval of 1000 ms
        return tt;
    }

}
