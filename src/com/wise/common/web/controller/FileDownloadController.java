package com.wise.common.web.controller;

import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.imageio.ImageIO;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.wise.common.secure.SecureUtils;
import com.wise.common.util.UniqueIdentifierGenerator;


/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 * 
 *     수정일         수정자               수정내용
 *  --------------    ------------    ---------------------------
 *  2015.06.08        DOGFOOT              최초 생성
 * </pre>
 */

@Controller
@RequestMapping(value = "/file/down")
public class FileDownloadController {
	private Logger logger = Logger.getLogger(this.getClass());
	
	@RequestMapping(value = "/base64/png.do", method = RequestMethod.POST)
    public void base64ToPng(HttpServletRequest request, HttpServletResponse response) {
        String base64 = SecureUtils.getParameter(request, "base64");
        
        try {
            byte[] decoded = Base64.decode(base64);
            
            String pngName = SecureUtils.getParameter(request, "reportName");
            pngName = URLEncoder.encode(pngName,"UTF-8");
            
            response.setContentType("image/png");
            response.addHeader("Content-Disposition", "attachment;filename=" + pngName + ".png");
            response.getOutputStream().write(decoded);
            response.getOutputStream().close();
        } catch (IOException e) {
            logger.error(e);
        }
        
    }
	
	@RequestMapping(value = "/base64/png/zip.do", method = RequestMethod.POST)
    public void base64ToPngAsZip(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String base64Params = SecureUtils.unsecure(SecureUtils.getParameter(request, "base64"));
        String[] base64List = base64Params.split("::space::");
        List<String> pngNames = new ArrayList<String>();
        
        String path = request.getSession().getServletContext().getRealPath("WEB-INF/download");
        File targetDir = new File(path);
        
        if (!targetDir.exists()) {
            targetDir.mkdir();
        }
        
//        try {
            UniqueIdentifierGenerator uidGen = new UniqueIdentifierGenerator();
            
            for (String base64 : base64List) {
                
                String pngName = "image-" + uidGen.createId().hashCode() + ".png";
//                String pngName = "image-" + System.currentTimeMillis() + ".png";
                pngNames.add(pngName);

                byte[] imgByteArray = Base64.decode(base64);
                InputStream in = new ByteArrayInputStream(imgByteArray);
                BufferedImage bufferedImage = ImageIO.read(in);
//                ImageIO.write(bufferedImage, "png", new File(path + "/" + pngName));
                ImageIO.write(bufferedImage, "png", new File(targetDir, pngName));
            }
            
            File directory = new File(path);
            String zipName = "image-" + uidGen.createId().hashCode() + ".zip";
//            String zipName = "image-" + System.currentTimeMillis() + ".zip";
            
            if (pngNames.size() > 0) {
                byte[] zip = zipFiles(directory, pngNames);

                ServletOutputStream sos = response.getOutputStream();
                response.setContentType("application/zip");
                response.setHeader("Content-Disposition", "attachment; filename="+ zipName);

                sos.write(zip);
                sos.flush();
            }
            
//        } catch(Exception ex){
//            logger.error(ex);
//        }
	}
	
	/**
     * Compress the given directory with all its files.
     */
    private byte[] zipFiles(File directory, List<String> files) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(baos);
        byte bytes[] = new byte[2048];

        for (String fileName : files) {
            FileInputStream fis = new FileInputStream(directory.getPath() +  "/" + fileName);
            BufferedInputStream bis = new BufferedInputStream(fis);

            zos.putNextEntry(new ZipEntry(fileName));

            int bytesRead;
            while ((bytesRead = bis.read(bytes)) != -1) {
                zos.write(bytes, 0, bytesRead);
            }
            zos.closeEntry();
            bis.close();
            fis.close();
        }
        zos.flush();
        baos.flush();
        zos.close();
        baos.close();

        return baos.toByteArray();
    }
    
}