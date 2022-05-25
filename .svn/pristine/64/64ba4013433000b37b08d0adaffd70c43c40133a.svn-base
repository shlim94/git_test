package com.wise.common.file;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.Date;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.google.common.util.concurrent.Striped;

import net.sf.json.JSONObject;

/**
 * 동시제어를 방지하기 위한 Locking 관련 클래스
 */
@Service
public class KeyedFileLockService {
	
	private static Logger log = LoggerFactory.getLogger(KeyedFileLockService.class);
	
	private static final Pattern DATE_FOLDER_NAME_PATTERN = Pattern.compile("^\\d{8}$");

    // private File dailyReportBaseDir;
    private final Striped<Lock> reportLocks;
    private final File reportBaseDir;
    
    public KeyedFileLockService() {
    	this(1024);
    }
    
    public KeyedFileLockService(final int stripes) {
		reportLocks = Striped.lazyWeakLock(stripes);
		
		this.reportBaseDir = new File("UploadFiles/");
	}

   /**
    2021-08-09 yyb csv 파일 생성
   */
   public void writeCsvData(final String queryKey, String relFilePath, final String[] headers, List<JSONObject> result) throws Exception {
		BufferedWriter writer = null;
		CSVPrinter csvPrinter = null;
        Lock lock = null;
        File file = null;
        File tempFile = null;
        try {
        	
        	// 생성할 파일 객체 생성
        	final File reportDir = new File(this.reportBaseDir, relFilePath);
        	file = new File(reportDir, queryKey + ".csv");
        	if (!file.getParentFile().isDirectory()) {
        		file.getParentFile().mkdirs();
        	}

        	// 파일이 존재하면 다른 스레드에서 생성한 것이므로 진행하지 않음
            if (!file.isFile()) {
            	
            	// 잠금처리
            	lock = reportLocks.get(queryKey);
                lock.lock();
                
                // 다른 스레드가 작업을 끝내고 리턴하는 경우도 있으므로 한번더 체크
                if (!file.isFile()) {
                	
                	// temp파일 생성후 내용 Write
                	tempFile = File.createTempFile(queryKey, ".csv.tmp", reportDir);
                	
                	// tempFile = new File(tempPath);
                	writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(tempFile), StandardCharsets.UTF_8));
                	/* DOGFOOT ktkang 고용정보원10 캐시파일 , 에러 수정 */
                	csvPrinter = new CSVPrinter(writer, CSVFormat.EXCEL.builder().setDelimiter('|').setHeader(headers).build());
	     			
	     			// 고운산 - 조회 루틴 변경  20210913
	     			for (JSONObject map : result) {
	     				 csvPrinter.printRecord(map.values());
	     			}
	     			
	     			// csvPrinter.printRecord(resultSet);
	     			csvPrinter.flush();
	     			
	     			if (csvPrinter != null) {
	            		IOUtils.closeQuietly(csvPrinter);
	            		csvPrinter = null;
	    			}
	            	
	            	if (writer != null) {
	            		IOUtils.closeQuietly(writer);
	            		writer = null;
	    			}
	     			
	            	// 다 쓰고나서 Rename 처리
		        	if (tempFile != null && tempFile.isFile()) {
		        		FileUtils.moveFile(tempFile, file);
		        	}
	     		}
            }
        }
	
        finally {
        	
        	IOUtils.closeQuietly(csvPrinter, writer);
        	
        	// NOTE: 반드시 finally에서 unlock 해야 함.
            if (lock != null) {
                lock.unlock();
            }
        }
    }
   
   @Scheduled(cron = "0 0 0-4,22-23 * * *")
   public void clearOldCacheFiles() {
	   log.info("Scheduler starts clearing old query result cache fiels...");
	   deleteOldCacheFiles(new File(this.reportBaseDir, "cache_csv"));
	   log.info("Scheduler ends clearing old query result cache files...");
	   
	   log.info("Scheduler starts clearing old list json temp files...");
	   deleteOldCacheFiles(new File(this.reportBaseDir, "list_json_temp"));
	   log.info("Scheduler ends clearing old list json temp files...");
   }
   
   private void deleteOldCacheFiles(final File baseDir) {
	   if(!baseDir.isDirectory()) {
		  log.info("Scheduler stops as the base dir doesn't exist at {}", baseDir);
		  return;
	   }
	   
	   final String curSubFolderName = DateFormatUtils.format(new Date(),  "yyyyMMdd");
	   final String[] oldSubFolderNames = baseDir.list(new FilenameFilter() {
		   @Override
		   public boolean accept(File dir, String name) {
			   final Matcher m = DATE_FOLDER_NAME_PATTERN.matcher(name);
			   return m.matches() && name.compareTo(curSubFolderName) < 0;
		   }
	   });
	   
	   if (oldSubFolderNames != null) {
		   for (String subFolderName : oldSubFolderNames) {
			   final File subFolder = new File(baseDir, subFolderName);
			   try {
				   FileUtils.deleteDirectory(subFolder);
				   log.info("Scheduler deleted old cache folder at {}", subFolder );
			   } catch (Exception e) {
				   log.error("Failed to delete old cache folder at {}", subFolder, e);
			   }
		   }
	   }
   }
}