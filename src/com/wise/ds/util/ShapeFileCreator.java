package com.wise.ds.util;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base64;

import com.wise.context.config.Configurator;

public class ShapeFileCreator {

    public synchronized void create(String fileLocationPath, String shapeFileName, String shapeData, String attributeData) {
    	try {
    		this.createFile("shp", fileLocationPath, shapeFileName, shapeData);
            this.createFile("dbf", fileLocationPath, shapeFileName, attributeData);
    	} catch (IOException e) {
    		e.printStackTrace();
    	}
        // FileUtils.writeByteArrayToFile(new File(fileLocationPath, shapeFileName + ".dbf"), Base64.decode(attributeData.getBytes()));
    }

    public void createFile(String fileExtension, String fileLocationPath, String shapeFileName, String data) throws IOException {
        File dataFile = new File(fileLocationPath, shapeFileName + "." + fileExtension);
        if (!dataFile.exists()) {
//            String encoding = Configurator.getInstance().getConfig("encoding");
//            String shpStr = new String(Base64.decode(data.getBytes()), encoding);
            FileUtils.writeByteArrayToFile(dataFile, Base64.decode(data.getBytes()));
        }
    }
}
