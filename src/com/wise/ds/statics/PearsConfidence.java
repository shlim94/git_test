package com.wise.ds.statics;

import org.apache.commons.math3.stat.descriptive.moment.Mean;
import org.apache.commons.math3.stat.descriptive.moment.StandardDeviation;

public class PearsConfidence {
		
	public double getPearsConfidence(double[] sample1, double[] sample2) {
		// TODO Auto-generated constructor stub
		//sample1의 표준편차
		double sample1Sd = getSd(sample1);
		//sample2의 표준편차
		double sample2Sd = getSd(sample2);
		//자유도
		int d = sample1.length - 1;
		
		//sample1의 편차 
		double sample1De[] = getDe(sample1);
		//sample2의 편차
		double sample2De[] = getDe(sample2);
		//편차들의 곱의 합
		double sum = 0;
		for(int i=0; i<sample1De.length; i++) {
			for(int j=0; j<sample2De.length; j++) {
				sum += sample1De[i] * sample2De[j];
			}
		}
		
		return sum/(d*sample1Sd*sample2Sd);
	}
	
	public double getMean(double[] sample) {	//평균
		Mean m = new Mean();
		for(int i=0; i<sample.length; i++) {
			m.increment(sample[i]);
		}
		
		return m.getResult();
	}
	
	public double getSd(double[] sample) {		//표준편차
		StandardDeviation sd = new StandardDeviation();
		for(int i=0; i<sample.length; i++) {
			sd.increment(sample[i]);
		}
		
		return sd.getResult();
	}
	
	public double[] getDe(double[] sample) {	//편차
		double de[] = new double[sample.length];
		double mean = getMean(sample);
		
		for(int i=0; i<sample.length; i++) {
			de[i] = sample[i] - mean;
			de[i] = Math.round(de[i]*100)/100.0;
		}
		
		return de;
	}
}
