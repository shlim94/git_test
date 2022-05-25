package com.wise.common.diagnos;

import java.util.BitSet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WdcTaskLogFormatUtils {

    private static final Logger log = LoggerFactory.getLogger(WdcTaskLogFormatUtils.class);

    public static String getTaskLog(WdcTask task) {
        return getTaskLog(task, -1);
    }

    public static String getTaskLog(WdcTask task, final int maxDepth) {
        StringBuilder sb = new StringBuilder(256);
        appendTaskLog(sb, task, 0, new BitSet(0), false, maxDepth, -1);
        return sb.toString();
    }

    public static String getTaskLog(WdcTask task, final int maxDepth,
            final long subtaskThresholdMillisec) {
        StringBuilder sb = new StringBuilder(256);
        appendTaskLog(sb, task, 0, new BitSet(0), false, maxDepth, subtaskThresholdMillisec);
        return sb.toString();
    }

    private static void appendTaskLog(final StringBuilder sb, final WdcTask task, final int depth,
            final BitSet bitset, final boolean lastChild, final int maxDepth,
            final long subtaskThresholdMillisec) {
        if (maxDepth > -1 && depth > maxDepth) {
            return;
        }

        final long durationTimeMillis = task.getDurationTimeMillis();

        if (depth > 0 && subtaskThresholdMillisec > -1) {
            if (durationTimeMillis < subtaskThresholdMillisec) {
                return;
            }
        }

        BitSet hidePipeAt = new BitSet(depth);
        hidePipeAt.or(bitset);
        for (int i = 0; i < depth; i++) {
            if (i > 0) {
                if (hidePipeAt.get(i)) {
                    sb.append(" ");
                }
                else {
                    sb.append("|");
                }
            }

            sb.append("  ");
        }
        if (depth > 0) {
            if (lastChild) {
                sb.append("`");
                hidePipeAt.set(depth);
            }
            else {
                sb.append("|");
            }
        }
        try {
            String msg = "- " + task.getName() + " (" + durationTimeMillis + "ms): "
                    + task.getAttributeMap();
            sb.append(msg).append('\n');
        }
        catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.warn("Exception during writing task", e);
            }
            else {
                log.warn("Exception during writing task : {}", e.toString());
            }
        }

        int count = 0;
        for (WdcTask childTask : task.getChildTasks()) {
            count++;
            if (count == task.getChildTasks().size()) {
                appendTaskLog(sb, childTask, depth + 1, hidePipeAt, true, maxDepth,
                        subtaskThresholdMillisec);
            }
            else {
                appendTaskLog(sb, childTask, depth + 1, hidePipeAt, false, maxDepth,
                        subtaskThresholdMillisec);
            }
        }
    }
}
