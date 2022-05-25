package com.wise.ds.statics;

import cern.colt.list.DoubleArrayList;
import cern.jet.stat.Descriptive;

public class Descex {
	/**
	 * 변수 선언
	 */
	private double sum; // 합계
	private double mean; // 평균
	private double variance; // 분산
	private double max; // 최대값
	private double min; //최소값
	private double standardDeviation; // 표준편차
	private double skew; // 왜도
	private double kurtosis; // 첨도
	private double standardError; // 표준오차
	private double range; // 범위
	private int n; // N
    
	/**
	 * 기초통계량을 계산해주는 메서드
	 * @param ele : double형 ArrayList 데이터
	 */
	public Descex(DoubleArrayList ele) {
		n = ele.size();  //표본 크기 
		sum = Descriptive.sum(ele);  //합계
		mean = Descriptive.mean(ele);  //평균
		max = Descriptive.max(ele) ;  //최대값
		min = Descriptive.min(ele);  //최소값
		variance = Descriptive.sampleVariance(ele, mean);  //분산
		standardDeviation= Descriptive.standardDeviation(variance);  //표준편차 
		skew = Descriptive.sampleSkew(ele, mean, variance);  //왜도
		kurtosis = Descriptive.sampleKurtosis(ele, mean, variance);  //첨도 
		standardError = Descriptive.standardError(n, variance);  //표준오차 
		range = max-min;  //범위
	}
 
	public double getmean(){
		return mean;  //평균 반환
	}
	
	public double getsum(){
		return sum;  //합계 반환
	} 
	 
	public double getvariance(){
		return variance;  //분산 반환
	}
	  
	public double getmax(){
		return max;  //최대값 반환
	}
	  
	public double getmin(){
		return min;  //최소값 반환
	}
	  
	public double getstandardDeviation(){
		return standardDeviation;  //표준편차 반환
	}
	  
	public double getskew(){
		return skew;  //왜도 반환
	}
	  
	public double getkurtosis(){
		return kurtosis;  //첨도 반환
	}
	  
	public double getstandardError(){
		return standardError;  //표준오차 반환
	}
	  
	public double getrange(){
		return range;  //범위 반환
	}
	  
	public double getn(){
		return n;  //표본 크기 반환
	}
}
