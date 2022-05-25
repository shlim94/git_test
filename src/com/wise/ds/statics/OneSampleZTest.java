package com.wise.ds.statics;

public class OneSampleZTest {
	
	private int n = 0;	//자유도
	private double dataSum = 0; //합계
	private double dataMean = 0; //평균
	private double dataDvSum = 0; //편차 제곱의 합
	private double sampleVariance = 0; //표본 분산
	private double m = 0; //모집단 평균
	private double sig = 0; //모집단 표준편차
	private double Zstatistic = 0; //Z 검정 통계량
	private double pValue = 0; //유의 확률
	private String lower = ""; //신뢰구간(하한)
	private String upper = ""; //신뢰구간(상한)
	
	public double CNDF(double x)
	{
		int neg = (x < 0d) ? 1 : 0;
	    if ( neg == 1) 
	        x *= -1d;

	    double k = (1d / ( 1d + 0.2316419 * x));
	    double y = (((( 1.330274429 * k - 1.821255978) * k + 1.781477937) *
	                   k - 0.356563782) * k + 0.319381530) * k;
	    y = 1.0 - 0.398942280401 * Math.exp(-0.5 * x * x) * y;

	    return (1d - neg) * y + neg * (1d - y);
	}
	
	public OneSampleZTest(double[] testdata, String alternative, double alphaLevel, double mutest, double stdev) {
		// TODO Auto-generated constructor stub
		//testdata = {35,32,33,28,29,30,31,29,28,30};
		//DataManager dm = new DataManager();
		
		//자유도
		this.n = testdata.length;
		
		//합계
		for(int i=0; i<testdata.length; i++) {
			this.dataSum += testdata[i];
		}
		
		//평균
		this.dataMean = dataSum/testdata.length;
		
		for(int i=0; i<testdata.length; i++) {
			double dv = dataMean - testdata[i];	//편차
			this.dataDvSum += Math.pow(dv, 2);	//편차 제곱의 합
		}
		
		this.sampleVariance = this.dataDvSum/(n-1); //표본 분산
		
		this.m = mutest;	//모집단 평균	
		this.sig = stdev;	//모집단 표준편차
		
		this.Zstatistic = (this.dataMean-this.m) / this.sig * Math.sqrt(this.n);	//Z 검정 통계량
			
		if(alternative.equals("two.sided")) {//양측 검정
			this.pValue = (1-CNDF(Zstatistic))*2;	//유의 확률
			
			this.lower = String.valueOf(this.dataMean - 1.96 * this.sig / Math.sqrt(this.n));	//신뢰구간(하한)
			this.upper = String.valueOf(this.dataMean + 1.96 * this.sig / Math.sqrt(this.n));	//신뢰구간(상한)
		}else if(alternative.equals("less")) {
			this.pValue = 1-(1-CNDF(Zstatistic));	//유의 확률
			
			this.lower = "-Inf";	//신뢰구간(하한)
			this.upper = String.valueOf(this.dataMean + 1.645 * this.sig / Math.sqrt(this.n));	//신뢰구간(상한)
		}else {
			this.pValue = (1-CNDF(Zstatistic));	//유의 확률
			
			this.lower = String.valueOf(this.dataMean - 1.645 * this.sig / Math.sqrt(this.n));	//신뢰구간(하한)
			this.upper = "Inf";	//신뢰구간(상한)
		}
	}

	public int getN() {
		return n;
	}

	public double getDataSum() {
		return dataSum;
	}

	public double getDataMean() {
		return dataMean;
	}

	public double getDataDvSum() {
		return dataDvSum;
	}

	public double getSampleVariance() {
		return sampleVariance;
	}

	public double getM() {
		return m;
	}

	public double getSig() {
		return sig;
	}

	public double getZstatistic() {
		return Zstatistic;
	}

	public double getpValue() {
		return pValue;
	}

	public String getLower() {
		return lower;
	}

	public String getUpper() {
		return upper;
	}
}
