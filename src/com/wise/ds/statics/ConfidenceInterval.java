package com.wise.ds.statics;

import org.apache.commons.math3.distribution.TDistribution;
import org.apache.commons.math3.exception.MathIllegalArgumentException;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

/*********
 * 
 * @author wise1012
 *	신뢰수준 구하는 함수
 */
public class ConfidenceInterval {
	public double calcMeanCI(SummaryStatistics stats, double level, String alt) {
        try {
            // Create T Distribution with N-1 degrees of freedom
            TDistribution tDist = new TDistribution(stats.getN() - 1);
            // Calculate critical value
            double critVal = 0;
            
            if(alt == "two.sided") {
            	critVal = tDist.inverseCumulativeProbability(1.0 - (1 - level) / 2);
            }else {
            	critVal = tDist.inverseCumulativeProbability(1.0 - (1 - level));
            }
            //double critVal = tDist.inverseCumulativeProbability(1.0 - (1 - level));
            // Calculate confidence interval
            return critVal * stats.getStandardDeviation() / Math.sqrt(stats.getN());
        } catch (MathIllegalArgumentException e) {
            return Double.NaN;
        }
    }
}
