package com.wise.ds.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import com.wise.context.config.Configurator;
import com.wise.ds.query.util.SqlStorage;
import com.wise.ds.repository.ReportMasterVO;
import com.wise.ds.repository.ReportScheduleVO;
import com.wise.ds.repository.ParamScheduleVO;
import com.wise.ds.repository.service.DataSetService;
import com.wise.ds.repository.service.ReportService;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * Class for routinely checking scheduled data requests and retrieving data. 
 *
 */
public class ScheduleThread implements Runnable {
	private ReportService reportService;
	private DataSetService dataSetServiceImpl;
	private int userNo;
	private String path;
	private JSONObject params;
	private static boolean running = false;

    public ScheduleThread(ReportService reportservice, SqlStorage sqlstorage, DataSetService datasetServiceImpl,int regUserNo, String path, JSONObject params) {
    	this.reportService = reportservice;
    	this.dataSetServiceImpl = datasetServiceImpl;
    	this.userNo = regUserNo;
    	this.path = path;
    	this.params = params;
	}

	public void run() {
		/*
		if (!(ScheduleThread.running)) {
			ScheduleThread.running = true;
	    	while(true){
	    		try {
	    			List<ReportScheduleVO> result = new ArrayList<ReportScheduleVO>();
	    			ReportScheduleVO param = new ReportScheduleVO();
	    			param.setREG_USER_NO(this.userNo);
	    			
	    			SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmm");
	    			SimpleDateFormat parseTimeStamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
	    			Calendar cal = Calendar.getInstance();
	    			String today = null;
	    			today = formatter.format(cal.getTime());
	    			Timestamp ts = Timestamp.valueOf(parseTimeStamp.format(cal.getTime()));

					result = reportService.selectReportScheduleList(param);

					for (ReportScheduleVO vo : result) {
						String regDate = vo.getSCH_DT();
						String formatDateString = regDate.substring(0,regDate.lastIndexOf(':'));
						formatDateString = formatDateString.replaceAll("-","").replaceAll(" ","").replaceAll(":", "");
						
						if (formatDateString.equals(today)) {
							Integer selectedSchId = vo.getSCH_ID();
							Integer selectedReportId = vo.getREPORT_ID();
							JSONArray sqlItem = new JSONArray();
							// DOGFOOT ktkang 개인보고서 추가  20200107
							String reportType = this.reportService.selectReportType(selectedReportId.toString()).getREPORT_TYPE();
							ReportMasterVO reportvo = this.reportService.selectReportBasicInformation(selectedReportId, reportType);
		                    JSONObject info = reportvo.getDataSourceAndParameterJson("");
		                    JSONObject reportMasterInfo = JSONObject.fromObject(info);
		                    JSONArray dataSetElements = reportMasterInfo.getJSONObject("datasetJson").getJSONArray("DATASET_ELEMENT");
		                    JSONObject ret = new JSONObject();
					        for (int i = 0; i < dataSetElements.size(); i++) {
					            JSONObject dataSetObj = (JSONObject) dataSetElements.get(i);
			                    int dataSrcId = dataSetObj.getInt("DATASRC_ID");
			                    String dataSetName = dataSetObj.getString("DATASET_NM");
					            String dataSrcType = dataSetObj.getString("DATASRC_TYPE");
					            String sql = dataSetObj.getString("DATASET_QUERY");
					            // DOGFOOT ktkang 수정  20200123 
//					            KERIS
					            sqlItem = this.dataSetServiceImpl.querySql(dataSrcId, dataSrcType, sql, this.params, 0, null);
//					            ORIGIN
					            //sqlItem = this.dataSetServiceImpl.querySql(dataSrcId, dataSrcType, sql, this.params, 0, false);
					            ret.put(dataSetName, sqlItem);
					        }
					        
					        String filePath = path + selectedSchId + "-" + selectedReportId.toString() + "-" + formatDateString;
					        
					        try {
					        	File dataFile = new File(filePath);
					        	FileWriter fw = new FileWriter(dataFile);
								fw.write(ret.toString());
								fw.close();
					        } catch (IOException e) {
					        	e.printStackTrace();
					        }
							ParamScheduleVO schParam = new ParamScheduleVO();

							schParam.setSCH_ID(selectedSchId);
							schParam.setEXEC_ST_DT(ts);
							schParam.setEXEC_DATA(filePath);
							this.dataSetServiceImpl.insertSchData(schParam);
						}

					}
	    			Thread.sleep(60000);
	    		}catch(Exception e) {
	    			e.printStackTrace();
	    		}
	    	}
		}
		*/
    }
}
