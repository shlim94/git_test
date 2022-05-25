package com.wise.common.diagnos;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

class NoopWdcTaskImpl implements WdcTask {

    private boolean stopped;

    NoopWdcTaskImpl() {
    }

    @Override
    public String getName() {
        return "<noop/>";
    }

    @Override
    public Map<String, Object> getAttributeMap() {
        return Collections.emptyMap();
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        List<String> emptyAttrNames = Collections.emptyList();
        return Collections.enumeration(emptyAttrNames);
    }

    @Override
    public void setAttribute(String key, Object value) {
    }

    @Override
    public Object getAttribute(String key) {
        return null;
    }

    @Override
    public Object removeAttribute(String key) {
        return null;
    }

    @Override
    public WdcTask getParentTask() {
        return null;
    }

    @Override
    public WdcTask startSubtask(String name) {
        WDC.setCurrentTask(this);
        return this;
    }

    @Override
    public void stop() {
        stopped = true;
    }

    @Override
    public Collection<WdcTask> getChildTasks() {
        return Collections.emptyList();
    }

    @Override
    public boolean isRunning() {
        return !stopped;
    }

    @Override
    public long getStartTimeMillis() {
        return 0L;
    }

    @Override
    public long getCurrentDurationTimeMillis() {
        return 0L;
    }

    @Override
    public long getDurationTimeMillis() {
        return 0L;
    }

}
