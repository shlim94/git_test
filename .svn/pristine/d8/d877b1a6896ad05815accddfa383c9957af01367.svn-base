package com.wise.ds.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.wise.context.config.Configurator;
import com.wise.ds.repository.service.ReportService;

@Component
public class Scheduler {
	private static final Logger logger = LoggerFactory.getLogger(Scheduler.class);
	
	@Autowired
	ReportService reportService;
	
	//boolean runFlag = false;
	
	//1시간마다
	@Scheduled(cron = "0 0 0/1 * * *")
	public void reportLogClean() {
		//if(runFlag) {
			int interval = reportService.getReportLogCleanHour();
			int resultCnt = reportService.updateReportLogDetailError(interval);
			logger.debug("보고서 로그 정제 결과 건수 = " + resultCnt);
		//}
	}
	
	//1분마다
	@Scheduled(cron = "0 0/1 * * * *")
	public void reportScheduler() {
		boolean schduleFlag = Configurator.getInstance().getConfigBooleanValue("wise.schedule", false);
		if(schduleFlag) {
			int resultCnt = reportService.executeReportScheduleMaster();
			logger.debug("보고서 스케쥴 실행 결과 건수 = " + resultCnt);
		}
	}
}
