package com.wise.ds.util;

import org.apache.spark.sql.SparkSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.wise.context.config.Configurator;

@Service
public class SparkLoad {
	private static final Logger logger = LoggerFactory.getLogger(SparkLoad.class);
//	private static SparkSession spark;
	public SparkSession sparkSession() {
		String os = System.getProperty("os.name").toLowerCase();
		if(os.indexOf("win")>-1) {
			System.setProperty("hadoop.home.dir", Configurator.getInstance().getApplicationContextRealLocation()+"WEB-INF\\hadoop");
		}
		
		SparkSession spark = new SparkSession
				.Builder()
				.appName("WiseIntelligence")
				.config("spark.ui.enabled", false)
				.config("spark.driver.allowMultipleContexts", true)
				.master("local[*]")
				.getOrCreate();
		spark.sparkContext().setLogLevel("ERROR");
		return spark;
		
		/*dogfoot spark session 유지  shlim 20210219*/
//		if(spark == null) {
//			 spark = SparkSession
//					.builder()
//					.appName("WiseIntelligence")
//					.config("spark.ui.enabled", false)
//					.config("spark.driver.allowMultipleContexts", true)
//					.config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
//					.config("spark.kryo.registrationRequired", "false")
//					.master("local[*]")
//					.getOrCreate();
//			spark.sparkContext().setLogLevel("ERROR");
//		}
//		
//		return spark;
	}
}
