package com.wise.common.file;

import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.stereotype.Service;

@Service
public class CacheFileWritingTaskExecutorService extends ThreadPoolTaskExecutor {

	private static final long serialVersionUID = 1L;

	private static final int DEFAULT_CORE_POOL_SIZE = 10;
	
	private static final int DEFAULT_MAX_POOL_SIZE = 80;
	
	private static final int DEFAULT_QUEUE_CAPACITY = 160;
	
	public CacheFileWritingTaskExecutorService() {
		super();
		
		setCorePoolSize(DEFAULT_CORE_POOL_SIZE);
		setMaxPoolSize(DEFAULT_MAX_POOL_SIZE);
		setQueueCapacity(DEFAULT_QUEUE_CAPACITY);
	}
}
