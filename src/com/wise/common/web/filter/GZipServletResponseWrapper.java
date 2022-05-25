package com.wise.common.web.filter;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.commons.io.IOUtils;

class GZipServletResponseWrapper extends HttpServletResponseWrapper {

    private GZipServletOutputStream gzipOut = null;
    private PrintWriter printWriter = null;

    public GZipServletResponseWrapper(HttpServletResponse response) throws IOException {
        super(response);
    }

    public void close() throws IOException {
        if (printWriter != null) {
            IOUtils.closeQuietly(printWriter);
        }

        if (gzipOut != null) {
            IOUtils.closeQuietly(gzipOut);
        }
    }

    @Override
    public void flushBuffer() throws IOException {
        if (printWriter != null) {
            printWriter.flush();
        }

        IOException ex1 = null;

        try {
            if (gzipOut != null) {
                gzipOut.flush();
            }
        }
        catch (IOException e) {
            ex1 = e;
        }

        IOException ex2 = null;

        try {
            super.flushBuffer();
        }
        catch (IOException e) {
            ex2 = e;
        }

        if (ex1 != null) {
            throw ex1;
        }

        if (ex2 != null) {
            throw ex2;
        }
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (printWriter != null) {
            throw new IllegalStateException(
                    "PrintWriter obtained already - cannot get OutputStream");
        }

        if (gzipOut == null) {
            gzipOut = new GZipServletOutputStream(getResponse().getOutputStream());
        }

        return gzipOut;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (printWriter == null && gzipOut != null) {
            throw new IllegalStateException(
                    "OutputStream obtained already - cannot get PrintWriter");
        }

        if (printWriter == null) {
            gzipOut = new GZipServletOutputStream(getResponse().getOutputStream());
            printWriter = new PrintWriter(
                    new OutputStreamWriter(gzipOut, getResponse().getCharacterEncoding()));
        }

        return printWriter;
    }

    @Override
    public void setContentLength(int len) {
        // ignore, since content length of zipped content
        // does not match content length of unzipped content.
    }
}
