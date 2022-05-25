package com.wise.common.diagnos;

import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WdcTaskImpl implements WdcTask {

    private static final Logger log = LoggerFactory.getLogger(WdcTaskImpl.class);

    private final String name;
    private Map<String, Object> attributes;

    private final WdcTask parentTask;
    private List<WdcTask> childTasks;

    private long startTimeMillis;
    private long durationTimeMillis = -1L;
    private boolean stopped;

    protected WdcTaskImpl(final WdcTask parentTask, final String name) {
        this.parentTask = parentTask;
        this.name = name;
        this.startTimeMillis = System.currentTimeMillis();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Map<String, Object> getAttributeMap() {
        if (attributes == null) {
            return Collections.emptyMap();
        }

        return Collections.unmodifiableMap(attributes);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        if (attributes != null) {
            return Collections.enumeration(attributes.keySet());
        }
        else {
            List<String> emptyAttrNames = Collections.emptyList();
            return Collections.enumeration(emptyAttrNames);
        }
    }

    @Override
    public void setAttribute(String key, Object value) {
        if (attributes == null) {
            attributes = new LinkedHashMap<String, Object>();
        }

        attributes.put(key, value);
    }

    @Override
    public Object getAttribute(String key) {
        if (attributes == null) {
            return null;
        }

        return attributes.get(key);
    }

    @Override
    public Object removeAttribute(String key) {
        if (attributes != null) {
            return attributes.remove(key);
        }

        return null;
    }

    @Override
    public WdcTask getParentTask() {
        return parentTask;
    }

    @Override
    public WdcTask startSubtask(String name) {
        if (stopped) {
            throw new IllegalStateException("The task was already stopped.");
        }

        if (childTasks == null) {
            childTasks = new LinkedList<WdcTask>();
        }

        WdcTask childTask = createSubtask(this, name);
        childTasks.add(childTask);
        WDC.setCurrentTask(childTask);
        return childTask;
    }

    @Override
    public void stop() {
        if (stopped) {
            log.warn("Task '{}' was already stopped.", name);
            return;
        }

        stopped = true;
        durationTimeMillis = System.currentTimeMillis() - startTimeMillis;
        WDC.setCurrentTask(parentTask);
    }

    @Override
    public Collection<WdcTask> getChildTasks() {
        if (childTasks == null) {
            return Collections.emptyList();
        }

        return Collections.unmodifiableCollection(childTasks);
    }

    @Override
    public boolean isRunning() {
        return !stopped;
    }

    @Override
    public long getStartTimeMillis() {
        return startTimeMillis;
    }

    @Override
    public long getCurrentDurationTimeMillis() {
        return System.currentTimeMillis() - startTimeMillis;
    }

    @Override
    public long getDurationTimeMillis() {
        if (!stopped) {
            log.warn("Task '{}' was not stopped hence duration time unknown.", name);
        }
        return durationTimeMillis;
    }

    protected WdcTask createSubtask(final WdcTask parentTask, final String name) {
        return new WdcTaskImpl(parentTask, name);
    }
}
