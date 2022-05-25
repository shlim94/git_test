package com.wise.ds.statics;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.commons.math3.linear.RealMatrix;
import org.apache.commons.math3.stat.correlation.PearsonsCorrelation;
import org.apache.commons.math3.stat.correlation.SpearmansCorrelation;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.apache.commons.math3.stat.regression.OLSMultipleLinearRegression;
import org.apache.commons.math3.stat.regression.SimpleRegression;

import com.datumbox.common.dataobjects.AssociativeArray2D;
import com.datumbox.common.dataobjects.FlatDataCollection;
import com.datumbox.common.dataobjects.TransposeDataCollection;
import com.datumbox.common.dataobjects.TransposeDataCollection2D;
import com.datumbox.framework.statistics.descriptivestatistics.Descriptives;
import com.datumbox.framework.statistics.distributions.ContinuousDistributions;
import com.github.signaflo.timeseries.TimeSeries;
import com.github.signaflo.timeseries.model.arima.Arima;
import com.github.signaflo.timeseries.model.arima.ArimaOrder;

import javastat.regression.glm.LogisticRegression;
import javastat.util.DataManager;

public class Analysis {

	public static void main(String[] args) {

		/*DecimalFormat format = new DecimalFormat("###,###.########");
		format.setGroupingUsed(false);
		double db = 8.84326117802194E+20;
		System.out.println(format.format(db));*/

		TransposeDataCollection transposeDataCollection = new TransposeDataCollection();
		transposeDataCollection.put(0, new FlatDataCollection(Arrays.asList(new Object[] { 86, 79, 81, 70, 84 })));
		transposeDataCollection.put(1, new FlatDataCollection(Arrays.asList(new Object[] { 90, 76, 88, 82, 89 })));

		double aLevel = 0.05;
		AssociativeArray2D outputTable = new AssociativeArray2D();
		boolean expResult = false;
		boolean result = Analysis.oneWayEqualVars(transposeDataCollection, aLevel, outputTable);

		System.out.println("expResult::" + expResult + ", " + "result::" + result);
		System.out.println(outputTable.get2d("BG", "SSq"));
		System.out.println(outputTable.get2d("BG", "DF"));
		System.out.println(outputTable.get2d("BG", "MSq"));
		System.out.println(outputTable.get2d("BG", "F"));
		System.out.println(outputTable.get2d("BG", "p"));


		double[] x = new double[]{-6.0,-5.0,-4.0,-3.0,-2.0,-1.0,0.0,1.0,2.0,3.0,4.0,5.0,6.0};
        /*
         * These are Y values for values of x for a "standard" logistic equation
         */
        double[] y = new double[]{0.002472623, 0.006692851, 0.01798621, 0.047425873, 0.119202922, 0.268941421,
                0.5, 0.731058579, 0.880797078, 0.952574127, 0.98201379, 0.993307149, 0.997527377};

        //getLogisticRegression(x, y);

	}

	  /**
     * Performs One-Way ANOVA Test on the Transpose Data Table when variances are
     * considered equal. Pass an empty array on the $outputTable variable to get
     * statistics concerning the ANOVA.
     *
     * @param transposeDataCollection
     * @param aLevel
     * @param outputTable
     * @return
     */
    public static boolean oneWayEqualVars(TransposeDataCollection transposeDataCollection, double aLevel, AssociativeArray2D outputTable) {
        int n = 0;
        int k = transposeDataCollection.size();
        if(k<=1) {
            throw new IllegalArgumentException("The collection must contain observations from at least 2 groups.");
        }

        Map<Object, Integer> nj = new HashMap<>();
        double Ymean = 0.0; //Total Y mean for
        Map<Object, Double> Yjmean = new HashMap<>();

        for(Map.Entry<Object, FlatDataCollection> entry : transposeDataCollection.entrySet()) {
            Object j = entry.getKey();
            FlatDataCollection flatDataCollection = entry.getValue();

            int m = flatDataCollection.size();
            if(m==0) {
                throw new IllegalArgumentException("The number of observations in each group but be larger than 0.");
            }
            nj.put(j, m); //get the number of observation for this category
            n+=m;

            double sum = Descriptives.sum(flatDataCollection);

            Yjmean.put(j, sum/m);
            Ymean+=sum;
        }

        if(n-k<=0) {
            throw new IllegalArgumentException("The number of observations must be larger than the number of groups.");
        }

        Ymean/=n;

        double RSS=0.0;
        double BSS=0.0;
        for(Map.Entry<Object, FlatDataCollection> entry : transposeDataCollection.entrySet()) {
            Object j = entry.getKey();
            FlatDataCollection flatDataCollection = entry.getValue();

            Iterator<Double> it = flatDataCollection.iteratorDouble();
            while(it.hasNext()) {
                RSS+=Math.pow( it.next() - Yjmean.get(j), 2);
            }
            BSS+=nj.get(j) * Math.pow( Yjmean.get(j) - Ymean, 2);
        }

        double F = (BSS/(k-1))/(RSS/(n-k));

        double pvalue = ContinuousDistributions.FCdf(F, k-1, n-k);

        boolean rejectH0=false;

        double a=aLevel/2;
        if(pvalue<=a || pvalue>=(1-a)) {
            rejectH0=true;
        }

        //if we requested an outputTable
        if(outputTable!=null) {
            double TSS = RSS+BSS;

            outputTable.clear();
            outputTable.put2d("BG", "SSq", BSS);
            outputTable.put2d("BG", "DF", k-1);
            outputTable.put2d("BG", "MSq", BSS/(k-1));
            outputTable.put2d("BG", "F", F);
            outputTable.put2d("BG", "p", 1-pvalue);
            outputTable.put2d("WG", "SSq", RSS);
            outputTable.put2d("WG", "DF", n-k);
            outputTable.put2d("WG", "MSq", RSS/(n-k));
            outputTable.put2d("R", "SSq", TSS);
            outputTable.put2d("R", "DF", n-1);
        }

        return rejectH0;
    }
    /**
     * Wrapper function for oneWayEqualVars, without passing the optional
     * output table.
     *
     * @param transposeDataCollection
     * @param aLevel
     * @return
     */
    public static boolean oneWayEqualVars(TransposeDataCollection transposeDataCollection, double aLevel) {
        return oneWayEqualVars(transposeDataCollection, aLevel, null);
    }

    /**
     * Performs One-Way ANOVA Test on the Transpose Data Table when variances are
     * considered NOT equal. Pass an empty array on the $outputTable variable to
     * get statistics concerning the ANOVA.
     *
     * @param transposeDataCollection
     * @param aLevel
     * @param outputTable
     * @return
     */
    public static boolean oneWayNotEqualVars(TransposeDataCollection transposeDataCollection, double aLevel, AssociativeArray2D outputTable) {
        int n = 0;
        int k = transposeDataCollection.size();
        if(k<=1) {
            throw new IllegalArgumentException("The collection must contain observations from at least 2 groups.");
        }

        Map<Object, Integer> nj = new HashMap<>();
        double Ymean = 0.0; //Total Y mean for
        Map<Object, Double> Yjmean = new HashMap<>();
        Map<Object, Double> Yjvariance = new HashMap<>();
        for(Map.Entry<Object, FlatDataCollection> entry : transposeDataCollection.entrySet()) {
            Object j = entry.getKey();
            FlatDataCollection flatDataCollection = entry.getValue();

            int m = flatDataCollection.size();
            if(m==0) {
                throw new IllegalArgumentException("The number of observations in each group but be larger than 0.");
            }
            nj.put(j, m); //get the number of observation for this category
            n+=m;

            double sum = Descriptives.sum(flatDataCollection);

            Yjmean.put(j, sum/m);
            Ymean+=sum;

            Yjvariance.put(j, Descriptives.variance(flatDataCollection, true));
        }

        if(n-k<=0) {
            throw new IllegalArgumentException("The number of observations must be larger than the number of groups.");
        }

        Ymean/=n;

        double BSS = 0.0;
        Map<Object, Double> mj = new HashMap<>();
        double mjSum = 0.0;
        for(Map.Entry<Object, FlatDataCollection> entry : transposeDataCollection.entrySet()) {
            Object j = entry.getKey();
            //FlatDataCollection flatDataCollection = entry.getValue();

            BSS += nj.get(j)*Math.pow(Yjmean.get(j)-Ymean, 2);
            mj.put(j, (1.0- (double)nj.get(j)/n)*Yjvariance.get(j));
            mjSum+=mj.get(j);
        }

        double dfDenominator = 0.0;
        for(Map.Entry<Object, FlatDataCollection> entry : transposeDataCollection.entrySet()) {
            Object j = entry.getKey();
            //FlatDataCollection flatDataCollection = entry.getValue();
            dfDenominator+=Math.pow(mj.get(j)/mjSum, 2)/(nj.get(j)-1.0);
        }

        int df = (int)Math.round(1.0/dfDenominator);

        double Fstar = BSS/mjSum;

        double pvalue = ContinuousDistributions.FCdf(Fstar, k-1, df);

        boolean rejectH0=false;

        double a=aLevel/2;
        if(pvalue<=a || pvalue>=(1-a)) {
            rejectH0=true;
        }

        //if we requested an outputTable
        if(outputTable!=null) {

            outputTable.clear();
            outputTable.put2d("BG", "Fparts", BSS);
            outputTable.put2d("BG", "DF", k-1);
            outputTable.put2d("BG", "F", Fstar);
            outputTable.put2d("BG", "p", 1.0-pvalue);
            outputTable.put2d("WG", "Fparts", mjSum);
            outputTable.put2d("WG", "DF", df);
        }

        return rejectH0;
    }

    /**
     * Wrapper function for oneWayNotEqualVars, without passing the optional
     * output table.
     *
     * @param transposeDataCollection
     * @param aLevel
     * @return
     */
    public static boolean oneWayNotEqualVars(TransposeDataCollection transposeDataCollection, double aLevel) {
        return oneWayNotEqualVars(transposeDataCollection, aLevel, null);
    }

    /**
     * Performs Two-Way ANOVA Test on the TransposeDataCollection2D when variances are considered equal.
     *
     * @param twoFactorDataCollection
     * @param aLevel
     * @param outputTable
     * @return
     */
    public static boolean twoWayEqualCellsEqualVars(TransposeDataCollection2D twoFactorDataCollection, double aLevel, AssociativeArray2D outputTable) {
        //NOTE! This is correct ONLY when all the samples have the same size! Also we assume equal variances. We follow the method described at Ntzoufras' English anova.pdf but we degrees of freedom are calculated slighty differently. The outcome though is the same (the df are correct). We don't follow the notes in order to make it feasible to use the method for Unequal cells. In that case the analysis will not be correct!
        //To expand the test for Unequal Cells and Unequal Vars we must implement a different function described in the below papers:
        //http://www3.stat.sinica.edu.tw/statistica/oldpdf/a7n35.pdf
        //http://sites.stat.psu.edu/~jls/stat512/lectures/lec23.pdf

        Integer Itotal = twoFactorDataCollection.size();
        Integer Jtotal = null;
        for(Map.Entry<Object, TransposeDataCollection> entry : twoFactorDataCollection.entrySet()) {
            if(Jtotal!=null) {
                if(Jtotal!=entry.getValue().size()) {
                    throw new IllegalArgumentException("The cells must be of equal size.");
                }
            }
            else {
                Jtotal = entry.getValue().size();
                if(Jtotal==0) {
                    throw new IllegalArgumentException("The size of Jtotal must be larger than 0.");
                }
            }
        	/*if(Jtotal==null) {
        		Jtotal = entry.getValue().size();
                if(Jtotal==0) {
                    throw new IllegalArgumentException("The size of Jtotal must be larger than 0.");
                }
            }*/
        }

        int n=0;
        Map<Object, Integer> nidotdot = new HashMap<>();
        Map<Object, Integer> ndotjdot = new HashMap<>();
        Map<Object, Map<Object, Integer>> nijdot = new HashMap<>();

        double Ydotdotdot=0.0; //Total Y
        Map<Object, Double> Yidotdot = new HashMap<>();
        Map<Object, Double> Ydotjdot = new HashMap<>();
        Map<Object, Map<Object, Double>> Yijdot = new HashMap<>();

        //calculate sums
        for(Map.Entry<Object, TransposeDataCollection> entry1 : twoFactorDataCollection.entrySet()) {
            Object IfactorAlevel = entry1.getKey();
            TransposeDataCollection listOfBlevels = entry1.getValue();

            if(!Yidotdot.containsKey(IfactorAlevel)) {
                Yidotdot.put(IfactorAlevel, 0.0);
                nidotdot.put(IfactorAlevel, 0);
                Yijdot.put(IfactorAlevel, new HashMap<>());
                nijdot.put(IfactorAlevel, new HashMap<>());
            }

            for(Map.Entry<Object, FlatDataCollection> entry2 : listOfBlevels.entrySet()) {
                Object JfactorBlevel = entry2.getKey();
                FlatDataCollection flatDataCollection = entry2.getValue();

                if(!Ydotjdot.containsKey(JfactorBlevel)) {
                    Ydotjdot.put(JfactorBlevel, 0.0);
                    ndotjdot.put(JfactorBlevel, 0);
                }

                if(!Yijdot.get(IfactorAlevel).containsKey(JfactorBlevel)) {
                    Yijdot.get(IfactorAlevel).put(JfactorBlevel, 0.0);
                    nijdot.get(IfactorAlevel).put(JfactorBlevel, 0);
                }

                Iterator<Double> it = flatDataCollection.iteratorDouble();
                while(it.hasNext()) {
                    Double value = it.next();

                    Ydotdotdot+=value;
                    ++n;

                    Yidotdot.put(IfactorAlevel, Yidotdot.get(IfactorAlevel)+value);
                    nidotdot.put(IfactorAlevel, nidotdot.get(IfactorAlevel)+1);

                    Ydotjdot.put(JfactorBlevel, Ydotjdot.get(JfactorBlevel)+value);
                    ndotjdot.put(JfactorBlevel, ndotjdot.get(JfactorBlevel)+1);

                    Yijdot.get(IfactorAlevel).put(JfactorBlevel, Yijdot.get(IfactorAlevel).get(JfactorBlevel) + value);
                    nijdot.get(IfactorAlevel).put(JfactorBlevel, nijdot.get(IfactorAlevel).get(JfactorBlevel) + 1);
                }
            }
        }

        //calculate averages
        Ydotdotdot/=n;

        for(Map.Entry<Object, Double> entry : Yidotdot.entrySet()) {
            Object i = entry.getKey();
            Yidotdot.put(i, entry.getValue()/nidotdot.get(i));
        }
        for(Map.Entry<Object, Double> entry : Ydotjdot.entrySet()) {
            Object j = entry.getKey();
            Ydotjdot.put(j, entry.getValue()/ndotjdot.get(j));
        }
        for(Map.Entry<Object, Map<Object, Double>> entry1 : Yijdot.entrySet()) {
            Object i = entry1.getKey();
            Map<Object, Double> listOfYj = entry1.getValue();

            for(Map.Entry<Object, Double> entry2 : listOfYj.entrySet()) {
                Object j = entry2.getKey();
                Double value = entry2.getValue();
                Yijdot.get(i).put(j, value/nijdot.get(i).get(j));
            }
        }
        //nidotdot = null;
        //ndotjdot = null;
        //nijdot = null;


        //Caclulate ANOVA SSq
        double SSA=0;
        double SSB=0;
        double SSAB=0;
        double SST=0;

		for (Map.Entry<Object, TransposeDataCollection> entry1 : twoFactorDataCollection.entrySet()) {
			Object IfactorAlevel = entry1.getKey();
			TransposeDataCollection listOfBlevels = entry1.getValue();

			for (Map.Entry<Object, FlatDataCollection> entry2 : listOfBlevels.entrySet()) {
				Object JfactorBlevel = entry2.getKey();
				FlatDataCollection flatDataCollection = entry2.getValue();

				Iterator<Double> it = flatDataCollection.iteratorDouble();
				while (it.hasNext()) {
					Double value = it.next();

					SST += Math.pow(value - Ydotdotdot, 2);
					SSA += Math.pow(Yidotdot.get(IfactorAlevel) - Ydotdotdot, 2);
					SSB += Math.pow(Ydotjdot.get(JfactorBlevel) - Ydotdotdot, 2);
					SSAB += Math.pow(Yijdot.get(IfactorAlevel).get(JfactorBlevel) - Yidotdot.get(IfactorAlevel)
							- Ydotjdot.get(JfactorBlevel) + Ydotdotdot, 2);
				}
			}
		}

        //Yidotdot = null;
        //Ydotjdot = null;
        //Yijdot = null;

        double SSE=SST-SSA-SSB-SSAB;
        double SSR=SSA+SSB+SSAB;

        int dfA=(Itotal-1);
        double MSA=SSA/dfA;

        int dfB=(Jtotal-1);
        double MSB=SSB/dfB;

        int dfAB=(Itotal-1)*(Jtotal-1);
        double MSAB=SSAB/dfAB;

        int dfE=(n-Itotal*Jtotal);
        double MSE=SSE/dfE;

        int dfR=dfA+dfB+dfAB;
        double MSR=SSR/dfR;

        double FA=MSA/MSE;
        double Apvalue=65535;
        try {
        	Apvalue=ContinuousDistributions.FCdf(FA,dfA,dfE);
		} catch (Exception e) {

		}

        double FB=MSB/MSE;
        double Bpvalue=65535;
        try {
        	Bpvalue=ContinuousDistributions.FCdf(FB,dfB,dfE);
		} catch (Exception e) {

		}

        double FAB=MSAB/MSE;
        double ABpvalue=65535;
        try {
        	ABpvalue=ContinuousDistributions.FCdf(FAB,dfAB,dfE);
		} catch (Exception e) {

		}

        double FR=MSR/MSE;
        double Rpvalue=65535;
        try {
        	Rpvalue=ContinuousDistributions.FCdf(FR,dfR,dfE);
		} catch (Exception e) {

		}

        boolean rejectH0=false;

        double a=aLevel/2;
        if(Rpvalue<=a || Rpvalue>=(1-a)) {
            rejectH0=true;
        }


        //if we requested an outputTable
        if(outputTable!=null) {
            outputTable.clear();
            outputTable.put2d("Model", "SSq", SSR);
            outputTable.put2d("Model", "DF", dfR);
            outputTable.put2d("Model", "MSq", MSR);
            outputTable.put2d("Model", "F", FR == -0.0 ? 65535 : FR);
            outputTable.put2d("Model", "p", Rpvalue == 65535 ? 65535 : 1.0-Rpvalue);

            outputTable.put2d("AFactor", "SSq", SSA);
            outputTable.put2d("AFactor", "DF", dfA);
            outputTable.put2d("AFactor", "MSq", MSA);
            outputTable.put2d("AFactor", "F", FA == -0.0 ? 65535 : FA);
            outputTable.put2d("AFactor", "p", Apvalue == 65535 ? 65535 : 1.0-Apvalue);

            outputTable.put2d("BFactor", "SSq", SSB);
            outputTable.put2d("BFactor", "DF", dfB);
            outputTable.put2d("BFactor", "MSq", MSB);
            outputTable.put2d("BFactor", "F", FB == -0.0 ? 65535 : FB);
            outputTable.put2d("BFactor", "p", Bpvalue == 65535 ? 65535 : 1.0-Bpvalue);

            outputTable.put2d("A*BFactor", "SSq", SSAB);
            outputTable.put2d("A*BFactor", "DF", dfAB);
            outputTable.put2d("A*BFactor", "MSq", MSAB);
            outputTable.put2d("A*BFactor", "F", FAB == -0.0 ? 65535 : FAB);
            outputTable.put2d("A*BFactor", "p", ABpvalue == 65535 ? 65535 : 1.0-ABpvalue);

            outputTable.put2d("Error", "SSq", SSE);
            outputTable.put2d("Error", "DF", dfE);
            outputTable.put2d("Error", "MSq", MSE);

            outputTable.put2d("Total", "SSq", SST);
            outputTable.put2d("Total", "DF", n-1);
            outputTable.put2d("Total", "MSq", MSE+MSAB);
        }

        return rejectH0;
    }

    /**
     * Wrapper function for twoWayEqualCellsEqualVars, without passing the
     * optional output table.
     *
     * @param twoFactorDataCollection
     * @param aLevel
     * @return
     */
    public static boolean twoWayEqualCellsEqualVars(TransposeDataCollection2D twoFactorDataCollection, double aLevel) {
        return twoWayEqualCellsEqualVars(twoFactorDataCollection, aLevel, null);
    }

    /**
     * pearson's correlation
     * @param matrix
     * @return
     */
    public static void getPearsonsCorrelation(RealMatrix matrix, List<Map<String, Object>> list) {
	    PearsonsCorrelation correlation = new PearsonsCorrelation(matrix);
	    RealMatrix correlationMatrix = correlation.getCorrelationMatrix();
	    RealMatrix standardErrorMatrix = correlation.getCorrelationStandardErrors();

	    // Output the correlation analysis
	    for (int i=0; i<correlationMatrix.getRowDimension(); i++){
	        for (int j=0; j<correlationMatrix.getColumnDimension(); j++){
	            Map<String, Object> map = new HashMap<>();
	            map.put("correlationCoefficient", correlationMatrix.getEntry(i,j));
	            list.add(map);
	        }
	    }
    }

    public static double getPearsonsCorrelation(double[] x, double[] y) {
	    PearsonsCorrelation correlation = new PearsonsCorrelation();
	    return correlation.correlation(x, y);
    }

    /**
     * spearman's correlation
     * @param matrix
     * @return
     */
    public static void getSpearmansCorrelation(RealMatrix matrix, List<Map<String, Object>> list) {
	    SpearmansCorrelation correlation = new SpearmansCorrelation(matrix);
	    RealMatrix correlationMatrix = correlation.getCorrelationMatrix();
	    RealMatrix pValueMatrix = correlation.getRankCorrelation().getCorrelationPValues();
	    RealMatrix standardErrorMatrix = correlation.getRankCorrelation().getCorrelationStandardErrors();

	    // Output the correlation analysis
	    for (int i=0; i<correlationMatrix.getRowDimension(); i++){
	        for (int j=0; j<correlationMatrix.getColumnDimension(); j++){
	            Map<String, Object> map = new HashMap<>();
	            map.put("correlationCoefficient", correlationMatrix.getEntry(i,j));
	            map.put("pValue", pValueMatrix.getEntry(i,j));
	            map.put("standardError", standardErrorMatrix.getEntry(i,j));
	            list.add(map);
	        }
	    }
    }

    public static double getSpearmansCorrelation(double[] x, double[] y) {
    	SpearmansCorrelation correlation = new SpearmansCorrelation();
	    return correlation.correlation(x, y);
    }

    /**
     * simple regression
     * @param x
     * @param y
     * @return
     */
    public static SimpleRegression getSimpleRegression(double[] x, double[] y) {
    	SimpleRegression regression = new SimpleRegression();
        for (int i = 0; i < x.length; i++) {
            regression.addData(y[i], x[i]);
        }

        return regression;
    }

    /**
     * OLSMultiple regression
     * @param x
     * @param y
     * @return
     */
    public static OLSMultipleLinearRegression getOLSMultipleRegression(double[][] x, double[] y) {
    	OLSMultipleLinearRegression regression = new OLSMultipleLinearRegression();
    	regression.newSampleData(y, x);
    	/*double[] beta = regression.estimateRegressionParameters();
    	double[] residuals = regression.estimateResiduals();
    	double[][] parametersVariance = regression.estimateRegressionParametersVariance();
    	double regressandVariance = regression.estimateRegressandVariance();
    	double rSquared = regression.calculateRSquared();
    	double sigma = regression.estimateRegressionStandardError();*/

        return regression;
    }

    /**
     * logistic regression
     * @param x
     * @param y
     * @return
     */
	@SuppressWarnings({ "rawtypes", "unchecked", "unused" })
    public static Map<String, Object> getLogisticRegression(String[] stringBinaryResponse, double[][] nominalCovariate, Map<String, Object> resultMap) {
    	DataManager dm = new DataManager();

		LogisticRegression testclass1 = new LogisticRegression(stringBinaryResponse, nominalCovariate);

		double[] coefficients = testclass1.coefficients;
		double[][] confidenceInterval = testclass1.confidenceInterval;
		double[] testStatistic = testclass1.testStatistic;
		double[] pValue = testclass1.pValue;
		double[][] devianceTable = testclass1.devianceTable;
		double[] standardError = testclass1.coefficientSE;

		LogisticRegression testclass2 = new LogisticRegression();

		coefficients = testclass2.coefficients(stringBinaryResponse, nominalCovariate);
		confidenceInterval = testclass2.confidenceInterval(0.1, stringBinaryResponse, nominalCovariate);
		testStatistic = testclass2.testStatistic(stringBinaryResponse,nominalCovariate);
		pValue = testclass2.pValue(stringBinaryResponse, nominalCovariate);
		devianceTable = testclass2.devianceTable(stringBinaryResponse, nominalCovariate);

		/*Hashtable argument1 = new Hashtable();
		StatisticalAnalysis testclass3 = new LogisticRegression(argument1, stringBinaryResponse, nominalCovariate).statisticalAnalysis;

		coefficients = (double[]) testclass3.output.get(COEFFICIENTS);
		confidenceInterval = (double[][]) testclass3.output.get(CONFIDENCE_INTERVAL);
		testStatistic = (double[]) testclass3.output.get(TEST_STATISTIC);
		pValue = (double[]) testclass3.output.get(PVALUE);
		devianceTable = (double[][]) testclass3.output.get(DEVIANCE_TABLE);

		Hashtable argument2 = new Hashtable();
		LogisticRegression testclass4 = new LogisticRegression(argument2, null);
		coefficients = testclass4.coefficients(argument2, stringBinaryResponse, nominalCovariate);

		argument2.put(ALPHA, 0.1);
		confidenceInterval = testclass4.confidenceInterval(argument2, stringBinaryResponse, nominalCovariate);
		testStatistic = testclass4.testStatistic(argument2, stringBinaryResponse, nominalCovariate);
		pValue = testclass4.pValue(argument2, stringBinaryResponse, nominalCovariate);
		devianceTable = testclass4.devianceTable(argument2, stringBinaryResponse, nominalCovariate);*/

		resultMap.put("value", coefficients);
		resultMap.put("tStatic", testStatistic);
		resultMap.put("pValue", pValue);
		resultMap.put("standardError", standardError);
		resultMap.put("devianceTable", devianceTable);

		return resultMap;
    }

    /* DOGFOOT ktkang 기술통계 구하는 부분  20201021 */
    public List<String> descriptiveList(boolean groups) {
		List<String> descriptiveList = new LinkedList<String>();
		descriptiveList.add("평균");
		descriptiveList.add("중앙값");
		descriptiveList.add("표준편차");
		descriptiveList.add("표준오차");
		descriptiveList.add("분산");
		descriptiveList.add("첨도");
		descriptiveList.add("왜도");
		descriptiveList.add("범위");
		descriptiveList.add("최소값");
		descriptiveList.add("최대값");
		descriptiveList.add("합");
		descriptiveList.add("관측수");
		descriptiveList.add("결측값");
		descriptiveList.add("유효함");
		if(groups) {
			descriptiveList.add("최빈수");
		}

		return descriptiveList;
	}

	public Map<String, Object> descriptiveResult(DescriptiveStatistics summary, Object[] measureArr, boolean groups) {
		double variance = summary.getVariance(); //분산
		double mean = summary.getMean(); //평균
		double median = summary.getPercentile(50); //중앙값
		double min = summary.getMin(); //최소값
		double max = summary.getMax(); //최대값
		double standardDeviation = summary.getStandardDeviation(); //표준편차
		double standardError = standardDeviation / Math.sqrt(summary.getN());
		double skewness = summary.getSkewness(); //왜도
		double kurtosis = summary.getKurtosis(); //첨도
		int dataLength = measureArr.length; //관측수
		double range = max - min; //범위
		double sum = summary.getSum();

		Map<String, Object> descriptiveResult = new HashMap<String, Object>();
		descriptiveResult.put("평균", mean);
		descriptiveResult.put("중앙값", median);
		descriptiveResult.put("표준편차", standardDeviation);
		descriptiveResult.put("표준오차", standardError);
		descriptiveResult.put("분산", variance);
		if(Double.isNaN(kurtosis)) {
			descriptiveResult.put("첨도", "NAN");
		} else {
			descriptiveResult.put("첨도", kurtosis);
		}
		if(Double.isNaN(kurtosis)) {
			descriptiveResult.put("왜도", "NAN");
		} else {
			descriptiveResult.put("왜도", skewness);
		}
		descriptiveResult.put("범위", range);
		descriptiveResult.put("최소값", min);
		descriptiveResult.put("최대값", max);
		descriptiveResult.put("합", sum);
		descriptiveResult.put("관측수", dataLength);
		descriptiveResult.put("결측값", 0);
		descriptiveResult.put("유효함", dataLength);
		if(groups) {
			Set<Double> mode = mode(measureArr);
			if(mode.size() == measureArr.length) {
				descriptiveResult.put("최빈수", "없음");
			} else {
				descriptiveResult.put("최빈수", mode.toString());
			}
		}

		return descriptiveResult;
	}

	/* DOGFOOT ktkang 최빈수 구하는 부분  20201028 */
	public Set<Double> mode(Object[] num){
		if (num.length == 0) {
			return null;
		} else {
			TreeMap<Double, Integer> map = new TreeMap<>(); //Map Keys are array values and Map Values are how many times each key appears in the array
			for (int index = 0; index != num.length; ++index) {
				//double value = (double) num[index];
				double value = Double.parseDouble(String.valueOf(num[index]));
				if (!map.containsKey(value)) {
					map.put(value, 1); //first time, put one
				}
				else {
					map.put(value, map.get(value) + 1); //seen it again increment count
				}
			}
			Set<Double> modes = new TreeSet<>(); //result set of modes, min to max sorted
			int maxCount = 1;
			Iterator<Integer> modeApperance = map.values().iterator();
			while (modeApperance.hasNext()) {
				maxCount = Math.max(maxCount, modeApperance.next()); //go through all the value counts
			}
			for (int index = 0; index != num.length; ++index) {
				//if (map.get(num[index]) == maxCount) { //if this key's value is max
				if(map.get(Double.parseDouble(String.valueOf(num[index]))) == maxCount) {
					//modes.add((double) num[index]); //get it
					modes.add(Double.parseDouble(String.valueOf(num[index])));
					break;
				}
			}
			return modes;
		}
    }

	/* DOGFOOT 시계열 분석 arima order 설정 20201118 yhkim */
	public static ArimaOrder setArimaOrder(TimeSeries timeSeries, ArimaOrder order, int[][] pdq, Map<String, Object> params) {
		ArimaOrder tmpOrder = null;
		double aic = 0.;
		double tmpAic = 0.;
		TimeSeries s = Arima.model(timeSeries, order).fittedSeries();

		for(int[] arr : pdq) {
			tmpOrder = ArimaOrder.order(arr[0], arr[1], arr[2]);

			aic = Arima.model(s, order).aic();
			tmpAic = Arima.model(s, tmpOrder).aic();

			if(aic > tmpAic) {
				order = tmpOrder;
				params.put("pOrder", arr[0]);
				params.put("dOrder", arr[1]);
				params.put("qOrder", arr[2]);
			}
		}

		return order;
	}

}
