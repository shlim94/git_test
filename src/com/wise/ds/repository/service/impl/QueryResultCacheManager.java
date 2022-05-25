package com.wise.ds.repository.service.impl;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

import org.springframework.stereotype.Service;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Element;

@Service
public class QueryResultCacheManager {

    private CacheManager cacheManager;

    private Cache queryResultCache;
    private Cache summaryMatrixCache;
    
    final static private long MAX_CASHABLE_SIZE = 100 * 1024 * 1024;

    public QueryResultCacheManager() {
    }

    @PostConstruct
    public void init() {
        cacheManager = CacheManager.getInstance();
        queryResultCache = cacheManager.getCache("queryResultCache");
        summaryMatrixCache = cacheManager.getCache("summaryMatrixCache");
    }

    @PreDestroy
    public void destroy() {
        if (cacheManager != null) {
            cacheManager.shutdown();
        }
    }

    public Object getQueryResultCache(final String key) {
        final Element elem = queryResultCache != null ? queryResultCache.get(key) : null;
        return elem != null ? elem.getObjectValue() : null;
    }

    public void putQueryResultCache(final String key, final Object data, long fileLen) {
        if (queryResultCache != null && MAX_CASHABLE_SIZE >= fileLen) {
            final Element elem = new Element(key, data);
            queryResultCache.put(elem);
        }
    }

    public Object getSummaryMatrixCache(final String key) {
        final Element elem = summaryMatrixCache != null ? summaryMatrixCache.get(key) : null;
        return elem != null ? elem.getObjectValue() : null;
    }

    public void putSummaryMatrixCache(final String key, final Object data) {
        if (summaryMatrixCache != null) {
            final Element elem = new Element(key, data);
            summaryMatrixCache.put(elem);
        }
    }
}
