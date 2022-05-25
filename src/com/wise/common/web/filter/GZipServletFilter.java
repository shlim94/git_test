package com.wise.common.web.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Providing an <code>HttpServletResponse</code> wrapper for next servlet filter chain executions in order to provide
 * gzip compression automatically, based on filter-mapping configurations.
 */
public class GZipServletFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void destroy() {
    }

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest httpRequest = (HttpServletRequest) request;
        final HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (!acceptsGZipEncoding(httpRequest)) {
            chain.doFilter(request, response);
            return;
        }

        httpResponse.addHeader("Content-Encoding", "gzip");

        GZipServletResponseWrapper gzipResponse = null;

        try {
            gzipResponse = new GZipServletResponseWrapper(httpResponse);
            chain.doFilter(request, gzipResponse);
        } finally {
            if (gzipResponse != null) {
                gzipResponse.close();
            }
        }
    }

    private boolean acceptsGZipEncoding(final HttpServletRequest httpRequest) {
        String acceptEncoding = httpRequest.getHeader("Accept-Encoding");
        return acceptEncoding != null && acceptEncoding.indexOf("gzip") != -1;
    }
}
