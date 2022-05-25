package com.wise.common.web.filter;

import java.io.IOException;
import java.util.zip.GZIPOutputStream;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;

import org.apache.commons.io.IOUtils;

class GZipServletOutputStream extends ServletOutputStream {

    private final ServletOutputStream servletOut;
    private GZIPOutputStream gzipOut = null;

    public GZipServletOutputStream(final ServletOutputStream servletOut) throws IOException {
        super();
        this.servletOut = servletOut;
        this.gzipOut = new GZIPOutputStream(servletOut);
    }

    @Override
    public void close() throws IOException {
        if (gzipOut != null) {
            IOUtils.closeQuietly(gzipOut);
        }

        if (servletOut != null) {
            IOUtils.closeQuietly(servletOut);
        }
    }

    @Override
    public void flush() throws IOException {
        gzipOut.flush();
    }

    @Override
    public void write(byte b[]) throws IOException {
        gzipOut.write(b);
    }

    @Override
    public void write(byte b[], int off, int len) throws IOException {
        gzipOut.write(b, off, len);
    }

    @Override
    public void write(int b) throws IOException {
        gzipOut.write(b);
    }

    @Override
    public boolean isReady() {
        return servletOut.isReady();
    }

    @Override
    public void setWriteListener(WriteListener writeListener) {
        servletOut.setWriteListener(writeListener);
    }
}
