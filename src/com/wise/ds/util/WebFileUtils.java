package com.wise.ds.util;

import java.io.File;
import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.FileUtils;

/**
 * File utilities under the web root folders and files which is located at
 * <code>request.getServletContext().getRealPath("/")</code>.
 */
public final class WebFileUtils {

    private WebFileUtils() {
    }

    /**
     * Get the subfolder, located under the web root folder, by the {@code folderNames}. If {@code create} is
     * {@code true} and the subfolder designated by the folderNames doesn't exist yet, then this will create the
     * subfolder automatically.
     * <P>
     * For example, if {@code folderNames} is <code>{ "folder1", "folder2" }</code>, then <code>folder1/folder2</code>
     * subfolder will be retrieved. If the subfolder doesn't exist yet and {@code create} is true, then it will be
     * created automatically.
     * </P>
     * 
     * @param request servlet request
     * @param create flag whether or not to create the subfolder if it doesn't exist yet
     * @param folderNames subfolder name(s)
     * @return the subfolder, located under the web root folder, by the subfolder names
     * @throws IOException if the subfolder cannot be created
     */
    public static File getWebFolder(final HttpServletRequest request, final boolean create,
            String... folderNames) throws IOException {
        final File webRootFolder = new File(request.getServletContext().getRealPath("/"));
        final File folder = FileUtils.getFile(webRootFolder, folderNames);

        if (create && !folder.isDirectory()) {
            FileUtils.forceMkdir(folder);
        }

        return folder;
    }
}
