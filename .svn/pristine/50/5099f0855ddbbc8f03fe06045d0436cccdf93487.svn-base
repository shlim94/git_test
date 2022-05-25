package com.wise.common.util;

import com.wise.common.diagnos.WDC;
import com.wise.common.exception.ServiceTimeoutException;

public final class ServiceTimeoutUtils {
	
	private static final long DEFAULT_SERVICE_TIME_OUT = 20L * 60L * 1000L; // 20minutes
	
	private ServiceTimeoutUtils() {
		
	}
	
	public static void checkServiceTimeout() throws ServiceTimeoutException {
		if (WDC.isStarted()) {
			final long curDuration = WDC.getCurrentDurationTimeMillis();
			
			if(curDuration > DEFAULT_SERVICE_TIME_OUT) {
				throw new ServiceTimeoutException("ReportController timed out: " + curDuration + "ms.");
			}
		}
	}
}
