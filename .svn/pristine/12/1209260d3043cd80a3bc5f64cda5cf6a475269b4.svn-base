package wise.querygen.repository;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class PropertiesLoader {
	public PropertiesLoader()
    {
		
    }
 
    /**
     * properties 파일 읽기
     */
	public Properties Read()
    {
        Properties  pp  = new Properties();
        try
        {
             pp.load(ClassLoader.getSystemResourceAsStream("mybatis.properties"));
        }
        catch (IOException ioe)
        {
             ioe.printStackTrace();
             System.exit(-1);
        }
       return pp;
    }
 
}
