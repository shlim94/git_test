package com.wise.common.web.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.wise.common.diagnos.WDC;
import com.wise.common.diagnos.WdcTask;
import com.wise.common.diagnos.WdcTaskLogFormatUtils;

/**
 * WISE application diagnostics filter.
 */
public class WDCServletFilter implements Filter {

    private static Logger log = LoggerFactory.getLogger(WDCServletFilter.class);

    private static final long DEFAULT_THRESHOLD_MILLIS = 10L * 1000L;
    
    private boolean enabled;
    
    private long thresholdMillis;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.enabled = BooleanUtils.toBoolean(filterConfig.getInitParameter("enabled"));
        this.thresholdMillis = NumberUtils.toLong(filterConfig.getInitParameter("thresholdMillis"), DEFAULT_THRESHOLD_MILLIS);
    }

    @Override
    public void destroy() {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        WdcTask rootTask = null;

        try {
            if (enabled) {
                final String contextPath = request.getServletContext().getContextPath();
                rootTask = WDC.start(contextPath);
                rootTask.setAttribute("uri", ((HttpServletRequest) request).getRequestURI());
            }

            chain.doFilter(request, response);
        }
        finally {
            try {
                if (rootTask != null) {
                    rootTask.stop();
                    final long t = rootTask.getDurationTimeMillis();
                    if(t > thresholdMillis) {
                    	log.info(WdcTaskLogFormatUtils.getTaskLog(rootTask));
                    }
                }
            }
            finally {
                if (WDC.isStarted()) {
                    WDC.cleanUp();
                }
            }
        }
    }
}
