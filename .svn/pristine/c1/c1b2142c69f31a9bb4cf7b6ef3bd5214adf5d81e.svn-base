package com.wise.common.file;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.util.Date;
import java.util.concurrent.locks.Lock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.time.DateFormatUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.util.concurrent.Striped;
import com.wise.comp.pivotmatrix.AvroSummaryMatrixUtils;
import com.wise.comp.pivotmatrix.SummaryMatrix;
import com.wise.comp.pivotmatrix.impl.SummaryMatrixUtils;

@Service
public class SummaryMatrixFileWriterService {

	private static final String EXTENSION_JSON = ".json";

	private static final String EXTENSION_JSON_TMP = ".json.tmp";

	private static final String EXTENSION_AVRO_PART2 = ".avro.p2";

    private static final String EXTENSION_AVRO_PART2_TMP = ".avro.p2.tmp";

	private static Logger log = LoggerFactory.getLogger(SummaryMatrixFileWriterService.class);
    
    private static final Pattern DATE_FOLDER_NAME_PATTERN = Pattern.compile("^\\d{8}$");

    private static final int ROW_COUNT_IN_PART1 = 600;

    private ObjectMapper objectMapper = new ObjectMapper();

    private final Striped<Lock> reportLocks;
    private final File reportBaseDir;

    public SummaryMatrixFileWriterService() {
        this(1024);
    }

    public SummaryMatrixFileWriterService(final int stripes) {
        reportLocks = Striped.lazyWeakLock(stripes);
        this.reportBaseDir = new File(new File("UploadFiles"), "summarymatrix");
        if (!this.reportBaseDir.isDirectory()) {
            this.reportBaseDir.mkdirs();
        }
    }

    public int getRowCountInPart1() {
    	return ROW_COUNT_IN_PART1;
    }

    public File getSummaryMatrixFile(final String cacheKey, String relDirPath) {
        final File folder = new File(this.reportBaseDir, relDirPath);
        return new File(folder, cacheKey + EXTENSION_JSON);
    }

    public File getSummaryMatrixFileForPart2(final String cacheKey, String relDirPath) {
        final File folder = new File(this.reportBaseDir, relDirPath);
        return new File(folder, cacheKey + EXTENSION_AVRO_PART2);
    }

    public void writeSummaryMatrix(final String cacheKey, String relDirPath,
            final SummaryMatrix matrix) throws Exception {
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;
        JsonGenerator gen = null;

        Lock lock = null;
        
        File folder = null;
        File file = null;
        File tempFile = null;

        try {
            // 생성할 파일 객체 생성
            folder = new File(this.reportBaseDir, relDirPath);

            if (!folder.isDirectory()) {
                folder.mkdirs();
            }

            file = new File(folder, cacheKey + EXTENSION_JSON);

            // 파일이 존재하면 다른 스레드에서 생성한 것이므로 진행하지 않음
            if (!file.isFile()) {

                // 잠금처리
                lock = reportLocks.get(cacheKey);
                lock.lock();

                // 다른 스레드가 작업을 끝내고 리턴하는 경우도 있으므로 한번더 체크
                if (!file.isFile()) {

                    // temp파일 생성후 내용 Write
                    tempFile = File.createTempFile(cacheKey, EXTENSION_JSON_TMP, folder);

                    fos = new FileOutputStream(tempFile);
                    bos = new BufferedOutputStream(fos);
                    gen = objectMapper.createGenerator(bos);

                    SummaryMatrixUtils.writeSummaryMatrixToJson(gen, null, matrix);

                    gen.flush();

                    IOUtils.closeQuietly(gen);
                    gen = null;
                    IOUtils.closeQuietly(bos);
                    bos = null;
                    IOUtils.closeQuietly(fos);
                    fos = null;

                    if (matrix.getRows() > ROW_COUNT_IN_PART1) {
                    	try {
                    		writeSummaryMatrixPart2(folder, cacheKey, matrix);
                    	} catch (Exception e2) {
                            log.error("Failed to write part2 summary matrix data to json file.", e2);
                            throw e2;
                        }
                    }

                    // 다 쓰고나서 Rename 처리
                    FileUtils.moveFile(tempFile, file);
                }

                lock.unlock();
                lock = null;
            }
        }
        catch (Exception e) {
            log.error("Failed to write main summary matrix data to json file.", e);
        }
        finally {
            IOUtils.closeQuietly(gen, bos, fos);

            if (lock != null) {
                lock.unlock();
            }
        }
    }
    
	private void writeSummaryMatrixPart2(final File folder, final String cacheKey, final SummaryMatrix matrix)
			throws Exception {
	    final File file = new File(folder, cacheKey + EXTENSION_AVRO_PART2);
	
	    if (file.isFile()) {
	    	return;
	    }
	
        File tempFile = File.createTempFile(cacheKey, EXTENSION_AVRO_PART2_TMP, folder);

        try (FileOutputStream fos = new FileOutputStream(tempFile);
        		BufferedOutputStream bos = new BufferedOutputStream(fos)) {
	        AvroSummaryMatrixUtils.serializeAvroSummaryCellRowsToAvroData(bos, matrix.getSummaryCells(), ROW_COUNT_IN_PART1);
        }

        FileUtils.moveFile(tempFile, file);
    }

    @Scheduled(cron = "0 0 0-4,22-23 * * *")
    public void clearOldCacheFiles() {
 	   log.info("Scheduler starts clearing old query result cache fiels...");
 	   
 	   final File baseDir = this.reportBaseDir;
 	   
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
 				   log.info("Scheduler deleted old summary matrix cache folder at {}", subFolder );
 			   } catch (Exception e) {
 				   log.error("Failed to delete old cache folder at {}", subFolder, e);
 			   }
 		   }
 	   }
 	   
 	   log.info("Scheduler ends clearing old query result cache files...");
    }
}
