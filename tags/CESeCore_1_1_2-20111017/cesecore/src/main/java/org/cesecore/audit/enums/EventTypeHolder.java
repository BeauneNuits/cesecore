package org.cesecore.audit.enums;

public class EventTypeHolder implements EventType {
    private static final long serialVersionUID = 1955829966673283680L;

    private final String value;
    
    public EventTypeHolder(final String value) {
        this.value = value;
    }
    
    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(EventType value) {
        if(value == null) {
            return false;
        }
        return this.value.equals(value.toString());
    }

}
