package com.wise.comp.model;

import java.util.List;

/**
 * 써머리 데이터를 포함하는 객체의 추상화 인터페이스.
 * 
 * @param <T>
 */
public interface SummaryContainer<T> {

    public String getKey();

    public T addSummaryValue(final SummaryValue summaryValue);

    public List<SummaryValue> getSummaryValues();

}
