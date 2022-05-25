package com.wise.ds.statics;

import cern.colt.list.DoubleArrayList;
import cern.jet.stat.Descriptive;
import cern.jet.stat.Probability;

public class IndependentTwoSampleTTest {
	/**
     *  이표본 t검증에 필요한 변수들
     *  alpha:유의수준
     *  mean1:평균, mean2:평균, md:평균차
     *  sd1:표준편차, sd2:표준편차, se1:표준오차, se2:표준오차
     *  var1:분산, var2:분산, sp:합동표본분산
     *  n1:표본크기, n2:표본크기, df:자유도
     *  F:F값, sigF:유의확률
     *  t:t값, sig:유의확률, dse:평균의 표준오차, LC:신뢰구간 하한, UC;신뢰구간 상한
     *  nt:t값, ndf:자유도, nsig:유의확률, ndse:평균차, 
     *  nLC:신뢰구간 하한, nUC: 신뢰구간 상한
     */
    double alpha; 
    double mean1, mean2, md; 
    double sd1, sd2, se1, se2, s, s2; 
    double var1, var2, sp, tValue;  
    int n1, n2, df; 
    double F, sigF;  //Levene의 등분산 검정에 이용되는 변수  
    double t, sig, dse, LC, UC;  //등분산 가정될 때 이용되는 변수
    double nt, ndf, nsig, ndse, nLC, nUC;  //등분산이 가정되지 않을 때 이용되는 변수
  
    public IndependentTwoSampleTTest(DoubleArrayList x, DoubleArrayList y, double alpha, String alt){
         this.alpha=alpha;  //유의수준
         n1 = x.size();  //집단1의 표본크기
         n2 = y.size();  //집단2의 표본크기    
         mean1 = Descriptive.mean(x);  //집단1의 평균 계산
         mean2 = Descriptive.mean(y);  //집단2의 평균 계산 
         md = mean1-mean2;  //평균차 계산
         var1 = Descriptive.sampleVariance(x, mean1);  //집단1의 분산 계산
         var2 = Descriptive.sampleVariance(y, mean2);  //집단2의 분산 계산
         sd1 = Math.sqrt(var1);  //집단2의 표준편차 계산
         sd2 = Math.sqrt(var2);  //집단2의 표준편차 계산
         se1 = Math.sqrt(var1/n1);  //집잔1의 표준오차 계산
         se2 = Math.sqrt(var2/n2);  //집단2의 표준오차 계산
         sp = ((n1-1)*var1+(n2-1)*var2)/(n1+n2-2);  //합동표본분산 계산
         if(alt == "two.sided") {
        	 tValue = 2.306;// tValue 구하는 함수 필요
         }else {
        	 tValue = 1.86;
         }
         s2 = sp * Math.sqrt((double)1/n1+(double)1/n2);
         //Levene 등분산 검정의 F값 계산(SpecialFunction클래스 LeveneF 메서드 이용)
         F = SpecialFunction.LeveneF(x,y);  
 
         //Levene 등분산 검정의 유의확률 계산
         sigF = 2*(1-Probability.studentT(n1+n2-2, Math.sqrt(F)));
 
         // 분산이 같은 경우 계산
         computeEqualVarianceCase();
 
         // 분산이 다른 경우 계산
         computeNotEqualVarianceCase();    
    }

    /**
     * 등분산이 가정될 때 
     */
    void computeEqualVarianceCase(){
         t = (mean1-mean2)/Math.sqrt(sp*(1./n1+1./n2));  //t값
         df = n1+n2-2;  //자유도
         sig = 2*(1 - Probability.studentT(df, Math.abs(t)));  //유의확률
         dse = Math.sqrt(sp*(1./n1+1./n2));  //차이의 표준오차
         //double w = Probability.studentTInverse(alpha, df)*dse;  //오차한계
         double w = dse*tValue; 
         
         LC = md - w;  //신뢰구간 하한
         UC = md + w;  //신뢰구간 상한
    }

    /**
     * 등분산이 가정되지 않을 때
     * 자유도가 정수가 아니므로 pecialFunction 클래스의 InverseT 메서드를 이용
     */
    void computeNotEqualVarianceCase(){
         nt = (mean1-mean2)/Math.sqrt(var1/n1+var2/n2);  //t값
         ndf = (var1/n1+var2/n2)*(var1/n1+var2/n2)/((var1/n1)*(var1/n1)/(n1-1)
                    +(var2/n2)*(var2/n2)/(n2-1));  //자유도
         nsig = 2*(1 - Probability.studentT(ndf, Math.abs(t)));  //유의확률
         ndse = Math.sqrt(var1/n1+var2/n2);  //차이의 표준오차
         
         double nw = ndse*tValue;
         nLC = md - nw;  //신뢰구간 하한
         nUC = md + nw;  //신뢰구간 상한
    }
 
   /**
    * 호출되면 각각의 이표본 t-검정 결과값을 반환하는 맴버함수들(23개)
    */
    public double getN1() { return n1;}  //표본크기(집단1)
    public double getN2() { return n2;}  //표본크기(집단2)
    public double getMean1() { return mean1;}  //표본평균(집단1)
    public double getMean2() { return mean2;}  //표본평균(집단2)
    public double getSd1() { return sd1;}  //표준편차(집단1)
    public double getSd2() { return sd2;}  //표준편차(집단2)
    public double getSe1() { return se1;}  //표준오차(집단1)
    public double getSe2() { return se2;}  //표준오차(집단2)   
    public double getF() { return F;}  //F값
    public double getsigF() { return sigF;}  //유의확률
    public double getmd() { return md;}  //평균차     
    public double gett() { return t;}  //t값 
    public double getdf() { return df;}  //자유도
    public double getsig(){ return sig;}  //유의확률
    public double getdse(){ return dse;}  //차이의 표준오차
    public double getLC(){ return LC;}  //신뢰구간 하한
    public double getUC(){ return UC;}  //신뢰구간 상한 
    public double getnt() { return nt;}  //t값
    public double getndf() { return ndf;}  //자유도
    public double getnsig(){ return nsig;}  //유의확률
    public double getndse(){ return ndse;}  //차이의 표준오차
    public double getnLC(){ return nLC;}  //신뢰구간 하한 
    public double getnUC(){ return nUC;}  //신뢰구간 상한	
}
