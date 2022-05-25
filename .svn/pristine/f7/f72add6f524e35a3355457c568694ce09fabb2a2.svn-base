package com.wise.ds.statics;

import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

import cern.colt.list.DoubleArrayList;
import cern.jet.stat.Descriptive;
import cern.jet.stat.Probability;


public class OneSampleTTest {
	/** 
     * 일표본 t-검정에 필요한 변수들
     * n:표본크기, df:자유도
     * alpha:유의수준, mu0:검정값
     * mean:표본평균, sd:표준편차, se:표준오차, t:t값, 
     * sig:유의확률 , md:평균차, LC:신뢰구간 하한, UC:신뢰구간 상한
     */
    int n, df;  
    double alpha, mu0;
    double mean, sd, se, t, sig, md, LC, UC;

    /**
     * 일표본 t-검정을 해주는 메서드
     * @param data : DoubleArrayList 데이터
     * @param mu0 : 검정값
     * @param alpha : 유의수준
     */
    public OneSampleTTest(DoubleArrayList data, double mu0, double alpha, double x[], String alt){
         this.mu0 = mu0;  //검정값
         this.alpha = alpha;  //유의수준
         n = data.size();  //표본크기 계산
         df = n-1;  //자유도 계산
         mean = Descriptive.mean(data);  //표본평균 계산
         double var = Descriptive.sampleVariance(data, mean);  //표본분산 계산
         sd = Math.sqrt(var);  //표준편차 계산
         se = Math.sqrt(var/n);  //표준오차 계산
         t = (mean-mu0)/se;  //t값 계산
         sig = 2*(1 - Probability.studentT(df, Math.abs(t)));  //유의확률 계산
         md = mean-mu0;  //평균차 계산
         double w = Probability.studentTInverse(alpha, df)*se;  //오차한계 계산
                
         ConfidenceInterval cd = new ConfidenceInterval();
         SummaryStatistics stats = new SummaryStatistics();
         for (double val : x) {
             stats.addValue(val);
         }
         double ci = cd.calcMeanCI(stats, alpha, alt);

         //System.out.println(String.format("Mean: %f", stats.getMean()));
              
         //LC = md - w;  //신뢰구간의 하한 계산
         //UC = md + w;  //신뢰구간의 상한 계산  
         LC = stats.getMean() - ci;
         UC = stats.getMean() + ci;    
    }

    /**
     * 호출되면 각각의 일표본 t-검정 결과값을 반환하는 맴버함수들(12개)
     */
    public double getn() { return n;}  //표본크기 반환
    public double getmean() { return mean;}  //표본평균 반환
    public double getsd() { return sd;}  // 표준편차 반환
    public double getse() { return se;}  // 표준오차 반환
    public double gett() { return t;}  //t값 반환
    public double getalpha() { return alpha;}  //유의수준 반환
    public double getmu0() { return mu0;}  //검정값 반환
    public double getdf() { return df;}  //자유도 반환
    public double getsig(){ return sig;}  //유의확률 반환
    public double getmd(){ return md;}  //평균차 반환
    public double getLC(){ return LC;}  //신뢰구간의 하한 반환
    public double getUC(){ return UC;}  //신뢰구간의 상한 반환
}
