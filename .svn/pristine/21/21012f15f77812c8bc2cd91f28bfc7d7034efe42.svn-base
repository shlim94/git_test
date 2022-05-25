package com.wise.common.diagnos;

public class WDC {

    private static WDC singleton = new WDC();

    public static final WdcTask NOOP_TASK = new NoopWdcTaskImpl();

    private static ThreadLocal<WdcTask> tlRootTask = new ThreadLocal<WdcTask>();
    private static ThreadLocal<WdcTask> tlCurrentTask = new ThreadLocal<WdcTask>();

    public static WdcTask start(String name) {
        return singleton.doStart(name);
    }

    public static boolean isStarted() {
        return singleton.doIsStarted();
    }

    public static WdcTask getRootTask() {
        return singleton.doGetRootTask();
    }

    public static long getCurrentDurationTimeMillis() {
        final WdcTask rootTask = getRootTask();
        return rootTask != null ? rootTask.getCurrentDurationTimeMillis() : -1;
    }

    public static WdcTask getCurrentTask() {
        return singleton.doGetCurrentTask();
    }

    public static void setCurrentTask(WdcTask currentTask) {
        singleton.doSetCurrentTask(currentTask);
    }

    public static void cleanUp() {
        singleton.doCleanUp();
    }

    protected WDC() {
    }

    protected WdcTask doStart(String name) {
        WdcTask rootTask = tlRootTask.get();

        if (rootTask != null) {
            throw new IllegalStateException("The root task was already started.");
        }

        rootTask = doCreateTask(name);
        tlRootTask.set(rootTask);
        return rootTask;
    }

    protected WdcTask doCreateTask(String name) {
        return new WdcTaskImpl(null, name);
    }

    protected boolean doIsStarted() {
        return (tlRootTask.get() != null);
    }

    protected WdcTask doGetRootTask() {
        WdcTask rootTask = tlRootTask.get();
        return (rootTask != null ? rootTask : NOOP_TASK);
    }

    protected WdcTask doGetCurrentTask() {
        WdcTask current = tlCurrentTask.get();

        if (current != null) {
            return current;
        }

        return getRootTask();
    }

    protected void doSetCurrentTask(WdcTask currentTask) {
        tlCurrentTask.set(currentTask);
    }

    protected void doCleanUp() {
        tlCurrentTask.remove();
        tlRootTask.remove();
    }
}
