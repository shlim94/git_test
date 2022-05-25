package com.wise.ds.statics;

import cern.colt.list.DoubleArrayList;
import cern.jet.stat.Descriptive;
import cern.jet.stat.Probability;

public class SpecialFunction {
	 /**
     * Levene 등분산 검정의 F값 계산해주는 메서드
     * Levene's test ( Levene 1960) 
     * is used to test if k samples have equal variances 
     * http://www.itl.nist.gov/div898/handbook/eda/section3/eda35a.htm 참고
     * F값을 반환
     */   
    public static double LeveneF(DoubleArrayList a, DoubleArrayList b){
         double mean1 = Descriptive.mean(a);  //집단1의 평균 계산  
         double mean2 = Descriptive.mean(b);  //집단2의 평균 계산
         int n1 = a.size();  //집단1의 표본크기
         int n2 = b.size();  //집단2의 표본크기
   
         DoubleArrayList a1 = a.copy();  //a1에 a를 복사
         DoubleArrayList b1 = b.copy();  //b1에 b를 복사
 
         /**
          * a1, b1에 데이터의 절대치 저장
          */
         for(int i=0; i<a1.size(); i++) a1.set(i, Math.abs(a1.get(i)-mean1));
         for(int i=0; i<b1.size(); i++) b1.set(i, Math.abs(b1.get(i)-mean2));
   
         mean1 = Descriptive.mean(a1);  //집단1의 절대치의 평균  
         mean2 = Descriptive.mean(b1);  //집단2의 절대치의 평균
   
         double pm = (n1*mean1+n2*mean2)/(n1+n2);
         double ss1 = (n1-1)*Descriptive.sampleVariance(a1, mean1);
         double ss2 = (n2-1)*Descriptive.sampleVariance(b1, mean2);    
         double F = (n1+n2-2)*(n1*(mean1-pm)*(mean1-pm)
                         +n2*(mean2-pm)*(mean2-pm))/(ss1+ss2);  //F값 계산  
         return F;  //F값 반환
    }
 
    /** 
     * non integer case
     * Fisher and Cornish(1960)
     * 정규 밀도함수 아래서 y값과 같은 x값을 반환(구간은 음의 무한대에서 x값까지)
     * 즉, 역함수 값을 반환
     */  
    public static double InverseT(double df, double alpha) {     
         double zp = Probability.normalInverse(alpha);
         double a1 = (zp*zp+1)/4;
         double a2 = (zp*zp*(5*zp*zp+16)+3)/96;
         double a3 = (zp*zp*(zp*zp*(3*zp*zp+19)+17)-15)/384;
         double a4 = (zp*zp*(zp*zp*(zp*zp*(79*zp*zp+77)+1482)-1920)-945)/92160;   
         double tp = zp*(1+a1/df+a2/(df*df)+a3/(df*df*df)+a4/(df*df*df*df));   
         return tp;  
    }
}
