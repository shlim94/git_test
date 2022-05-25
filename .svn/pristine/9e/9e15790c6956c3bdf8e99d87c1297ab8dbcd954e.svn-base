package com.wise.common.diagnos;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;

public interface WdcTask extends AutoCloseable {

    String getName();

    Map<String, Object> getAttributeMap();

    public Enumeration<String> getAttributeNames();

    void setAttribute(String key, Object value);

    Object getAttribute(String key);

    Object removeAttribute(String key);

    WdcTask getParentTask();

    WdcTask startSubtask(String name);

    void stop();

    Collection<WdcTask> getChildTasks();

    boolean isRunning();

    long getStartTimeMillis();

    long getCurrentDurationTimeMillis();

    long getDurationTimeMillis();

    default void close() {
        stop();
    }
}
