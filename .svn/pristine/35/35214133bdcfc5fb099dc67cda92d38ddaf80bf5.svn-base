package com.wise.ds.repository.controller;

import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.math3.distribution.ChiSquaredDistribution;
import org.apache.commons.math3.distribution.FDistribution;
import org.apache.commons.math3.distribution.TDistribution;
import org.apache.commons.math3.stat.descriptive.DescriptiveStatistics;
import org.apache.commons.math3.stat.inference.ChiSquareTest;
import org.apache.commons.math3.stat.regression.OLSMultipleLinearRegression;
import org.apache.commons.math3.stat.regression.RegressionResults;
import org.apache.commons.math3.stat.regression.SimpleRegression;
import org.json.simple.parser.JSONParser;
import org.rosuda.REngine.REXPMismatchException;
import org.rosuda.REngine.RList;
import org.rosuda.REngine.Rserve.RConnection;
import org.rosuda.REngine.Rserve.RserveException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.datumbox.common.dataobjects.AssociativeArray2D;
import com.datumbox.common.dataobjects.FlatDataCollection;
import com.datumbox.common.dataobjects.TransposeDataCollection;
import com.datumbox.common.dataobjects.TransposeDataCollection2D;
import com.datumbox.framework.statistics.distributions.ContinuousDistributions;
import com.github.rcaller.datatypes.DataFrame;
import com.github.rcaller.exception.ExecutionException;
import com.github.rcaller.rstuff.RCaller;
import com.github.rcaller.rstuff.RCallerOptions;
import com.github.rcaller.rstuff.RCode;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.wise.common.secure.SecureUtils;
import com.wise.ds.statics.Analysis;
import com.wise.ds.statics.Descex;
import com.wise.ds.statics.IndependentTwoSampleTTest;
import com.wise.ds.statics.OneSampleTTest;
import com.wise.ds.statics.OneSampleZTest;
import com.wise.ds.statics.PearsConfidence;

import cern.colt.list.DoubleArrayList;
import javastat.regression.lm.LinearRegression;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import smile.classification.LogisticRegression;
import smile.stat.hypothesis.ChiSqTest;
import smile.stat.hypothesis.FTest;
import smile.stat.hypothesis.TTest;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 *     수정일                 수정자             수정내용   
 *  ----------    --------    ---------------------------
 *  2020.09.21      DOGFOOT             최초 생성
 * </pre>
 */

@Controller
@RequestMapping(value = "/static")
public class AnalysisController extends Analysis{
	private static final Logger logger = LoggerFactory.getLogger(ReportController.class);
	DecimalFormat format = new DecimalFormat("###,###.########");
    
	/**
	 * 분산분석(일원)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params={"analysisType=onewayAnova", "analysis=0"})
	public Map<String, Object> onewayAnova(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String dimensions = String.valueOf(params.get("dimensions"));
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		/* DOGFOOT ktkang 통계 오류 수정  20210216 */
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> dimensionList = gson.fromJson(dimensions, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		double aLevel = 0.05;
		AssociativeArray2D outputTable = new AssociativeArray2D();
		int resultCode = 0;
		String errorMsg = "";
		
		boolean significanceResult = false;
		
		Map<String, Object> entryMap = globalDataList.get(0);
		Map<String, Object> measureMap = measureList.get(0);
		Map<String, Object> dimensionMap = dimensionList.get(0);
		TransposeDataCollection transposeDataCollection = new TransposeDataCollection();
		
		Object[] dimensionsArr = new Object[globalDataList.size()];
		Object[] measureArr = new Object[globalDataList.size()];
		
		/* DOGFOOT ktkang 데이터 가공 부분  20210121 */
		String[] dimensionsStr = new String[globalDataList.size()];
		double[] measureDou = new double[globalDataList.size()];
		
		String measureName = (String) measureMap.get("name");
		String measureSummary = (String) measureMap.get("nameBySummaryType");
		String dimensionName = (String) dimensionMap.get("name");
		
		int i = 0;
		for(LinkedHashMap<String, Object> data : globalDataList) {
			for (String key : entryMap.keySet()) {
			    if(measureMap.containsValue(key)) {
			    	if(measureArr[i] == null) {
			    		measureArr[i] = Double.parseDouble(String.valueOf(data.get(key)));	
			    		measureDou[i] = Double.parseDouble(String.valueOf(data.get(key)));	
			    	} else {
			    		dimensionsStr[i] = String.valueOf(data.get(key));
			    		dimensionsArr[i] = String.valueOf(data.get(key));
			    	}
			    } else {
			    	dimensionsStr[i] = String.valueOf(data.get(key));
			    	dimensionsArr[i] = String.valueOf(data.get(key));
			    }
			}
			i++;
		}
		
		List<Object> list = Arrays.asList(dimensionsArr);
		Set<Object> uniqueSet = new HashSet<Object>(list);
		List<Object> setList = new ArrayList<Object>(uniqueSet);
		setList.sort(null);
		
		for(Object set : setList) {
			String groupName = "";
			Collection<Object> groupList = new ArrayList<Object>();
			for(LinkedHashMap<String, Object> data : globalDataList) {
				if(data.containsKey(dimensionName) && data.containsValue(set)) {
					groupName = String.valueOf(data.get(dimensionName));
					groupList.add(Double.parseDouble(String.valueOf(data.get(measureSummary))));
				}
			}
			transposeDataCollection.put(groupName, new FlatDataCollection(groupList));
		}

		/* DOGFOOT ktkang 도수분포표 구하는 부분  20201021 */
		Map<Object, Integer> frequencyMap = new HashMap<Object, Integer>();
	    for (Object k : setList) {  
	    	frequencyMap.put(k, Collections.frequency(list, k));
	    }
	    List<Object> frequencyList = new ArrayList<Object>();
	    int cumFre = 0;
	    Map<Object, List<Object>> meaMap = new HashMap<Object, List<Object>>();
		Object[][] obArray = new Object[setList.size()][1];
		String[] setListArray = new String[setList.size()];
		
		for(int k=0; k < setList.size(); k++) {
			
			JSONObject frequency = new JSONObject();
			cumFre = cumFre + frequencyMap.get(setList.get(k));
			frequency.put(dimensionName, setList.get(k));
			frequency.put("도수", frequencyMap.get(setList.get(k)));
			frequency.put("상대도수", frequencyMap.get(setList.get(k)) / (double) dimensionsArr.length);
			frequency.put("누적도수", cumFre);
			
			frequencyList.add(frequency);
			
			List<Object> meaList = new ArrayList<Object>();
			for(int o = 0; o < globalDataList.size(); o++) {
				Object dim = String.valueOf(globalDataList.get(o).get(dimensionName));
				if(dim.equals(setList.get(k))) {
					meaList.add(globalDataList.get(o).get(measureSummary));
				}
			}
			Object[] ob = new Object[meaList.size()];
			setListArray[k] = (String) setList.get(k);
			ob = meaList.toArray();
			obArray[k] = ob;
			meaMap.put(setList.get(k), meaList);
		}
		
		try {
			significanceResult = oneWayEqualVars(transposeDataCollection, aLevel, outputTable);
		} catch (Exception e) {
			resultCode = 99;
			errorMsg = e.getMessage();
		}
		
		format.setGroupingUsed(false);
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201021 */
		DescriptiveStatistics summary = new DescriptiveStatistics();
	    
		for (int k = 0; k < measureArr.length; k++) {
			summary.addValue((double) measureArr[k]);
		}
		
		Map<String, Object> descriptiveResult = descriptiveResult(summary, measureArr, true);
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<String> descriptiveList = descriptiveList(true);
		for(int k=0; k < descriptiveList.size(); k++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(k));
			descriptive.put(measureName, descriptiveResult.get(descriptiveList.get(k)));
			
			descriptiveMap.add(descriptive);
		}
		
		List<Object> descriptiveDimMap = new ArrayList<Object>();
		List<String> descriptiveDimList = descriptiveList(false);
		for(int k=0; k < setList.size(); k++) {
			List<Object> measureDimList = meaMap.get(setList.get(k));
			Object[] measureDimArray = measureDimList.toArray();
			summary = new DescriptiveStatistics();
			for (int p = 0; p < measureDimArray.length; p++) {
				
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) measureDimArray[p]);
				summary.addValue(Double.parseDouble(String.valueOf(measureDimArray[p])));
			}
			Map<String, Object> descriptiveDimResult = descriptiveResult(summary, measureDimArray, false);
			for(int o=0; o < descriptiveDimList.size(); o++) {
				JSONObject descriptive = new JSONObject();
				descriptive.put(dimensionName, setList.get(k));
				descriptive.put("기술명", descriptiveDimList.get(o));
				descriptive.put(measureName, descriptiveDimResult.get(descriptiveDimList.get(o)));
				
				descriptiveDimMap.add(descriptive);
			}
		}
		
		/* DOGFOOT ktkang R 스크립트 부분  20210121 */
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		code.addStringArray("dim", dimensionsStr);
		code.addDoubleArray("mea", measureDou);
		/* DOGFOOT ktkang 일원분산분석 수정  20210126 */
		code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
		code.addRCode("df<-data.frame(dim, mea)");
		code.addRCode("m <- anova(lm(mea~dim,df))");
		
		caller.setRCode(code);
		caller.runAndReturnResult("m");
		
		System.out.println("바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값");
		System.out.println(caller.getParser().getXMLFileAsString());
		System.out.println("Available results from lm() object : ");
		System.out.println(caller.getParser().getNames());
		
		//Sum of Squares
		double[] RSumSq = caller.getParser().getAsDoubleArray("SumSq");
		//Degress Of Freedom
		double[] RDf = caller.getParser().getAsDoubleArray("Df");
		//Mean Square
		double[] RMeanSq = caller.getParser().getAsDoubleArray("MeanSq");
		//F Statics
		String[] RFStatics = caller.getParser().getAsStringArray("Fvalue");
		//PrF
		String[] RPrf = caller.getParser().getAsStringArray("PrF");
		
		/* DOGFOOT ktkang 분석 결과표 값 수정  20201104 */
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		for(int k=0; k < 3; k++) {
			JSONObject resultData = new JSONObject();
			/* DOGFOOT syjin 일원배치 분석결과표 R로 변환 20210126 */
			if(k == 0) {
				resultData.put("Source Of Variation", "Between groups");
				//resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "SSq")))));
				//resultData.put("Degress Of Freedom", String.valueOf(Integer.parseInt(String.valueOf(outputTable.get2d("BG", "DF")))));
				//resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "MSq")))));
				//resultData.put("F Statistics", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "F")))));
				//resultData.put("P value", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "p")))));
				resultData.put("Sum Of Squares", String.valueOf(RSumSq[0]));
				resultData.put("Degress Of Freedom", String.valueOf(RDf[0]));
				resultData.put("Mean Square", String.valueOf(RMeanSq[0]));
				resultData.put("F Statistics", RFStatics[0]);
				resultData.put("P value", RPrf[0]);
			} else if(k == 1) {
				//resultData.put("Source Of Variation", "Within groups");
				//resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("WG", "SSq")))));
				//resultData.put("Degress Of Freedom", String.valueOf(Integer.parseInt(String.valueOf(outputTable.get2d("WG", "DF")))));
				//resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("WG", "MSq")))));
				resultData.put("Sum Of Squares", String.valueOf(RSumSq[1]));
				resultData.put("Degress Of Freedom", RDf[1]);
				resultData.put("Mean Square", RMeanSq[1]);
			} else {
				double mean = Double.parseDouble(String.valueOf(outputTable.get2d("BG", "SSq"))) + Double.parseDouble(String.valueOf(outputTable.get2d("WG", "SSq")));
				mean = mean / Double.parseDouble(String.valueOf(outputTable.get2d("R", "DF")));
				resultData.put("Source Of Variation", "Sum & Mean");
				//resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("R", "SSq")))));
				//resultData.put("Degress Of Freedom", String.valueOf(Integer.parseInt(String.valueOf(outputTable.get2d("R", "DF")))));
				//resultData.put("Mean Square", Double.isNaN(mean) ? "NaN" : mean);
				resultData.put("Sum Of Squares", String.valueOf(RSumSq[0] + RSumSq[1]));
				resultData.put("Degress Of Freedom", String.valueOf(RDf[0] + RDf[1]));
				resultData.put("Mean Square", String.valueOf(RMeanSq[0] + RMeanSq[1]));
			}
			
			resultDataList.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("significanceResult", significanceResult);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("frequency", frequencyList);
		resultMap.put("descriptiveDim", descriptiveDimMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=onewayAnova", "analysis=1"})
	public Map<String, Object> onewayAnovaJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String dimensions = String.valueOf(params.get("dimensions"));
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		/* DOGFOOT ktkang 통계 오류 수정  20210216 */
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> dimensionList = gson.fromJson(dimensions, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		double aLevel = 0.05;
		AssociativeArray2D outputTable = new AssociativeArray2D();
		int resultCode = 0;
		String errorMsg = "";
		
		boolean significanceResult = false;
		
		Map<String, Object> entryMap = globalDataList.get(0);
		Map<String, Object> measureMap = measureList.get(0);
		Map<String, Object> dimensionMap = dimensionList.get(0);
		TransposeDataCollection transposeDataCollection = new TransposeDataCollection();
		
		Object[] dimensionsArr = new Object[globalDataList.size()];
		Object[] measureArr = new Object[globalDataList.size()];
		
		/* DOGFOOT ktkang 데이터 가공 부분  20210121 */
		String[] dimensionsStr = new String[globalDataList.size()];
		double[] measureDou = new double[globalDataList.size()];
		
		String measureName = (String) measureMap.get("name");
		String measureSummary = (String) measureMap.get("nameBySummaryType");
		String dimensionName = (String) dimensionMap.get("name");
		
		int i = 0;
		for(LinkedHashMap<String, Object> data : globalDataList) {
			for (String key : entryMap.keySet()) {
			    if(measureMap.containsValue(key)) {
			    	if(measureArr[i] == null) {
			    		measureArr[i] = Double.parseDouble(String.valueOf(data.get(key)));	
			    		measureDou[i] = Double.parseDouble(String.valueOf(data.get(key)));	
			    	} else {
			    		dimensionsStr[i] = String.valueOf(data.get(key));
			    		dimensionsArr[i] = String.valueOf(data.get(key));
			    	}
			    } else {
			    	dimensionsStr[i] = String.valueOf(data.get(key));
			    	dimensionsArr[i] = String.valueOf(data.get(key));
			    }
			}
			i++;
		}
		
		List<Object> list = Arrays.asList(dimensionsArr);
		Set<Object> uniqueSet = new HashSet<Object>(list);
		List<Object> setList = new ArrayList<Object>(uniqueSet);
		setList.sort(null);
		
		for(Object set : setList) {
			String groupName = "";
			Collection<Object> groupList = new ArrayList<Object>();
			for(LinkedHashMap<String, Object> data : globalDataList) {
				if(data.containsKey(dimensionName) && data.containsValue(set)) {
					groupName = String.valueOf(data.get(dimensionName));
					groupList.add(Double.parseDouble(String.valueOf(data.get(measureSummary))));
				}
			}
			transposeDataCollection.put(groupName, new FlatDataCollection(groupList));
		}

		/* DOGFOOT ktkang 도수분포표 구하는 부분  20201021 */
		Map<Object, Integer> frequencyMap = new HashMap<Object, Integer>();
	    for (Object k : setList) {  
	    	frequencyMap.put(k, Collections.frequency(list, k));
	    }
	    List<Object> frequencyList = new ArrayList<Object>();
	    int cumFre = 0;
	    Map<Object, List<Object>> meaMap = new HashMap<Object, List<Object>>();
		Object[][] obArray = new Object[setList.size()][1];
		String[] setListArray = new String[setList.size()];
		
		for(int k=0; k < setList.size(); k++) {
			
			JSONObject frequency = new JSONObject();
			cumFre = cumFre + frequencyMap.get(setList.get(k));
			frequency.put(dimensionName, setList.get(k));
			frequency.put("도수", frequencyMap.get(setList.get(k)));
			frequency.put("상대도수", frequencyMap.get(setList.get(k)) / (double) dimensionsArr.length);
			frequency.put("누적도수", cumFre);
			
			frequencyList.add(frequency);
			
			List<Object> meaList = new ArrayList<Object>();
			for(int o = 0; o < globalDataList.size(); o++) {
				Object dim = String.valueOf(globalDataList.get(o).get(dimensionName));
				if(dim.equals(setList.get(k))) {
					meaList.add(globalDataList.get(o).get(measureSummary));
				}
			}
			Object[] ob = new Object[meaList.size()];
			setListArray[k] = (String) setList.get(k);
			ob = meaList.toArray();
			obArray[k] = ob;
			meaMap.put(setList.get(k), meaList);
		}
		
		try {
			significanceResult = oneWayEqualVars(transposeDataCollection, aLevel, outputTable);
		} catch (Exception e) {
			resultCode = 99;
			errorMsg = e.getMessage();
		}
		
		format.setGroupingUsed(false);
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201021 */
		DescriptiveStatistics summary = new DescriptiveStatistics();
	    
		for (int k = 0; k < measureArr.length; k++) {
			summary.addValue((double) measureArr[k]);
		}
		
		Map<String, Object> descriptiveResult = descriptiveResult(summary, measureArr, true);
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<String> descriptiveList = descriptiveList(true);
		for(int k=0; k < descriptiveList.size(); k++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(k));
			descriptive.put(measureName, descriptiveResult.get(descriptiveList.get(k)));
			
			descriptiveMap.add(descriptive);
		}
		
		List<Object> descriptiveDimMap = new ArrayList<Object>();
		List<String> descriptiveDimList = descriptiveList(false);
		for(int k=0; k < setList.size(); k++) {
			List<Object> measureDimList = meaMap.get(setList.get(k));
			Object[] measureDimArray = measureDimList.toArray();
			summary = new DescriptiveStatistics();
			for (int p = 0; p < measureDimArray.length; p++) {
				
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) measureDimArray[p]);
				summary.addValue(Double.parseDouble(String.valueOf(measureDimArray[p])));
			}
			Map<String, Object> descriptiveDimResult = descriptiveResult(summary, measureDimArray, false);
			for(int o=0; o < descriptiveDimList.size(); o++) {
				JSONObject descriptive = new JSONObject();
				descriptive.put(dimensionName, setList.get(k));
				descriptive.put("기술명", descriptiveDimList.get(o));
				descriptive.put(measureName, descriptiveDimResult.get(descriptiveDimList.get(o)));
				
				descriptiveDimMap.add(descriptive);
			}
		}
		
		/* DOGFOOT ktkang 분석 결과표 값 수정  20201104 */
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		for(int k=0; k < 3; k++) {
			JSONObject resultData = new JSONObject();
			/* DOGFOOT syjin 일원배치 분석결과표 R로 변환 20210126 */
			if(k == 0) {
				resultData.put("Source Of Variation", "Between groups");
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf(Integer.parseInt(String.valueOf(outputTable.get2d("BG", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "MSq")))));
				resultData.put("F Statistics", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "F")))));
				resultData.put("P value", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "p")))));
			} else if(k == 1) {
				resultData.put("Source Of Variation", "Within groups");
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("WG", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf(Integer.parseInt(String.valueOf(outputTable.get2d("WG", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("WG", "MSq")))));
			} else {
				double mean = Double.parseDouble(String.valueOf(outputTable.get2d("BG", "SSq"))) + Double.parseDouble(String.valueOf(outputTable.get2d("WG", "SSq")));
				mean = mean / Double.parseDouble(String.valueOf(outputTable.get2d("R", "DF")));
				resultData.put("Source Of Variation", "Sum & Mean");
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("R", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf(Integer.parseInt(String.valueOf(outputTable.get2d("R", "DF")))));
				resultData.put("Mean Square", Double.isNaN(mean) ? "NaN" : mean);
			}
			
			resultDataList.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("significanceResult", significanceResult);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("frequency", frequencyList);
		resultMap.put("descriptiveDim", descriptiveDimMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	/**
	 * 분산분석(일원반복)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=onewayAnova2", "analysis=0"})
	public Map<String, Object> onewayAnova2(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String dimensions = String.valueOf(params.get("dimensions"));
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		/* DOGFOOT ktkang 통계 오류 수정  20210216 */
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> dimensionList = gson.fromJson(dimensions, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		double aLevel = 0.05;
		AssociativeArray2D outputTable = new AssociativeArray2D();
		AssociativeArray2D outputTable2 = new AssociativeArray2D();
		int resultCode = 0;
		String errorMsg = "";
		
		boolean significanceResult = false;
		
		Map<String, Object> entryMap = globalDataList.get(0);
		Map<String, Object> measureMap = measureList.get(0);
		TransposeDataCollection transposeDataCollection = new TransposeDataCollection();
		TransposeDataCollection transposeDataCollection2 = new TransposeDataCollection();

		Object[] dimensionsArr1 = new Object[globalDataList.size()];
		Object[] dimensionsArr2 = new Object[globalDataList.size()];
		Object[] measureArr = new Object[globalDataList.size()];

		String[] dimensionsStr1 = new String[globalDataList.size()];
		String[] dimensionsStr2 = new String[globalDataList.size()];
		double[] measureDou = new double[globalDataList.size()];
		
		String measureName = (String) measureMap.get("name");
		String measureSummary = (String) measureMap.get("nameBySummaryType");

		int i = 0; int j = 0;
		for(LinkedHashMap<String, Object> data : globalDataList) {
			for (String key : entryMap.keySet()) {
				if(measureSummary.equals(key)) {
					measureDou[i] = Double.parseDouble(String.valueOf(data.get(key)));
					measureArr[i] = Double.parseDouble(String.valueOf(data.get(key)));
					i++;
				} else {
					if(dimensionsArr1[j] == null) {
						dimensionsStr1[j] = String.valueOf(data.get(key));
						dimensionsArr1[j] = String.valueOf(data.get(key));
					} else {
						dimensionsStr2[j] = String.valueOf(data.get(key));
						dimensionsArr2[j] = String.valueOf(data.get(key));
						j++;
					}
				}
			}
		}

		List<Object> list = Arrays.asList(dimensionsArr1);
		Set<Object> uniqueSet = new HashSet<Object>(list);
		List<Object> setList = new ArrayList<Object>(uniqueSet);
		setList.sort(null);
		
		List<Object> itemList = Arrays.asList(dimensionsArr2);
		Set<Object> itemUniqueSet = new HashSet<Object>(itemList);
		List<Object> itemSetList = new ArrayList<Object>(itemUniqueSet);
		itemSetList.sort(null);
		/*Map<String, Object> itemCntMap = new HashMap<String, Object>();
		for(Object set : itemList) {
			if(itemCntMap.get(set) == null) {
				itemCntMap.put(String.valueOf(set), 1);
			} else {
				itemCntMap.put(String.valueOf(set), Integer.parseInt(String.valueOf(itemCntMap.get(set))) + 1);
			}
		}
		int itemCnt = 0;
		for(String key : itemCntMap.keySet()) {
			if(itemCnt == 0) itemCnt = Integer.parseInt(String.valueOf(itemCntMap.get(key)));
			if(itemCnt != Integer.parseInt(String.valueOf(itemCntMap.get(key)))) {
				throw new IllegalArgumentException("The cells must be of equal size.");
			}
		}*/
		
		i = 0;
		for(Object set : setList) {
			String groupName = "";
			Collection<Object> groupList = new ArrayList<Object>();
			for(LinkedHashMap<String, Object> data : globalDataList) {
				if(data.get(dimensionList.get(0).get("name")).equals(set)) {
					groupName = String.valueOf(set);
					groupList.add(Double.parseDouble(String.valueOf(data.get(measureSummary))));
				}
			}
			transposeDataCollection.put(groupName, new FlatDataCollection(groupList));
			i++;
		}
		
		for(Object set : itemSetList) {
			String groupName = "";
			Collection<Object> groupList = new ArrayList<Object>();
			for(LinkedHashMap<String, Object> data : globalDataList) {
				if(data.get(dimensionList.get(1).get("name")).equals(set)) {
					groupName = String.valueOf(set);
					groupList.add(Double.parseDouble(String.valueOf(data.get(measureSummary))));
				}
			}
			transposeDataCollection2.put(groupName, new FlatDataCollection(groupList));
		}

		try {
			significanceResult = oneWayEqualVars(transposeDataCollection, aLevel, outputTable);
			/* DOGFOOT syjin 분산분석_반복없는이원 R 불러오기 수정 20210219 */
			//if(significanceResult) 
				significanceResult = oneWayEqualVars(transposeDataCollection2, aLevel, outputTable2);
		} catch (Exception e) {
			resultCode = 99;
			errorMsg = e.getMessage();
		}
		
		format.setGroupingUsed(false);
		
		DescriptiveStatistics summary = new DescriptiveStatistics();
	    
		for (int k = 0; k < measureArr.length; k++) {
			summary.addValue((double) measureArr[k]);
		}
		
		Map<String, Object> descriptiveResult = descriptiveResult(summary, measureArr, true);
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<String> descriptiveList = descriptiveList(true);
		for(int k=0; k < descriptiveList.size(); k++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(k));
			descriptive.put(measureName, descriptiveResult.get(descriptiveList.get(k)));
			
			descriptiveMap.add(descriptive);
		}
		
		/* DOGFOOT ktkang 교차분석 표 구현  20201104 */
		List<Object> crossoverMap = new ArrayList<Object>();
		for(int k = 0; k < itemSetList.size(); k++) {
			JSONObject crossover = new JSONObject();
			crossover.put(dimensionList.get(1).get("name"), itemSetList.get(k));
			for(int o = 0; o < setList.size(); o++) {
				int p = 0;
				for(LinkedHashMap<String, Object> gdl : globalDataList) {
					if(gdl.get(dimensionList.get(0).get("name")).equals(setList.get(o)) && gdl.get(dimensionList.get(1).get("name")).equals(itemSetList.get(k))) {
						p++;
					}
				}
				crossover.put(setList.get(o), String.valueOf(p));
			}
			
			crossoverMap.add(crossover);
		}
		
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		/* DOGFOOT ktkang 이원분산분석 수정  20210126 */
		code.addStringArray("dim1", dimensionsStr1);
		code.addStringArray("dim2", dimensionsStr2);
		code.addDoubleArray("mea", measureDou);
		code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
		code.addRCode("df<-data.frame(dim1, dim2, mea)");
		code.addRCode("a<-anova(lm(mea~dim1*dim2,df))");
		
		caller.setRCode(code);
		caller.runAndReturnResult("a");
		
		System.out.println(caller.getParser().getXMLFileAsString());

		
		/* DOGFOOT syjin 반복없는 이원 배치 분석결과표 R 추가 20210127 */
		//Sum of Squares
		double[] RSumSq = caller.getParser().getAsDoubleArray("SumSq");
		//Degress Of Freedom
		double[] RDf = caller.getParser().getAsDoubleArray("Df");
		//Mean Square
		double[] RMeanSq = caller.getParser().getAsDoubleArray("MeanSq");
		//F Statics
		String[] RFStatics = caller.getParser().getAsStringArray("Fvalue");
		//PrF
		String[] RPrf = caller.getParser().getAsStringArray("PrF");
		
		
		int bgdf = (int) Double.parseDouble(String.valueOf(outputTable.get2d("BG", "DF")));
		int bsdf = (int) Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "DF")));
		int wgdf = setList.size() + itemSetList.size() - 1;
		int totaldf = setList.size() * itemSetList.size() - 1;
		
		double wgssq = Double.parseDouble(String.valueOf((double)outputTable.get2d("R", "SSq") - (double)outputTable.get2d("BG", "SSq") - (double)outputTable2.get2d("BG", "SSq")));
		double wgmsq = wgssq/wgdf;
		
		double bgf = Double.parseDouble(String.valueOf(outputTable.get2d("BG", "MSq"))) / wgmsq;
        double bgp = ContinuousDistributions.FCdf(bgf, bgdf, wgdf);
        double bsf = Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "MSq"))) / wgmsq;
        double bsp = ContinuousDistributions.FCdf(bsf, bsdf, wgdf);
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		/* DOGFOOT ktkang 분석 결과표 값 수정  20201104 */
		for(int k=0; k < 4; k++) {
			JSONObject resultData = new JSONObject();
			if(k == 0) {
				resultData.put("Source Of Variation", dimensionList.get(0).get("name"));
				//resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "SSq")))));
				//resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("BG", "DF")))));
				//resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "MSq")))));
				resultData.put("F Statistics", String.valueOf(bgf));
				resultData.put("P value", String.valueOf(1.0 - bgp));
				
				resultData.put("Source Of Variation", dimensionList.get(0).get("name"));
				resultData.put("Sum Of Squares", RSumSq[0]);
				resultData.put("Degress Of Freedom", RDf[0]);
				resultData.put("Mean Square", RMeanSq[0]);
				//resultData.put("F Statistics", RFStatics[0]);
				//resultData.put("P value", RPrf[0]);
				
				System.out.println("======1=====");
				System.out.println("변경전 : " + String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "SSq")))));
				System.out.println("변경후 : " + RSumSq[0]);
				System.out.println("변경전 : " + String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("BG", "DF")))));
				System.out.println("변경후 : " + RDf[0]);
				System.out.println("변경전 : " + String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "MSq")))));
				System.out.println("변경후 : " + RMeanSq[0]);
				System.out.println("변경전 : " + String.valueOf(bgf));
				System.out.println("변경후 : " + RFStatics[0]);
				System.out.println("변경전 : " + String.valueOf(1.0 - bgp));
				System.out.println("변경후 : " + RPrf[0]);
				
			} else if(k == 1) {
				resultData.put("Source Of Variation", dimensionList.get(1).get("name"));
				//resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "SSq")))));
				//resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "DF")))));
				//resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "MSq")))));
				resultData.put("F Statistics", String.valueOf(bsf));
				resultData.put("P value", String.valueOf(1.0 - bsp));
				
				//resultData.put("Source Of Variation", dimensionList.get(1).get("name"));
				resultData.put("Sum Of Squares", RSumSq[1]);
				resultData.put("Degress Of Freedom", RDf[1]);
				resultData.put("Mean Square", RMeanSq[1]);
				//resultData.put("F Statistics", RFStatics[1]);
				//resultData.put("P value", RPrf[1]);
				System.out.println("======2=====");
				System.out.println("변경전 : " + String.valueOf(Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "SSq")))));
				System.out.println("변경후 : " + RSumSq[1]);
				System.out.println("변경전 : " + String.valueOf((int)Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "DF")))));
				System.out.println("변경후 : " + RDf[1]);
				System.out.println("변경전 : " + String.valueOf(Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "MSq")))));
				System.out.println("변경후 : " + RMeanSq[1]);
				System.out.println("변경전 : " + String.valueOf(bsf));
				System.out.println("변경후 : " + RFStatics[1]);
				System.out.println("변경전 : " + String.valueOf(1.0 - bsp));
				System.out.println("변경후 : " + RPrf[1]);
			} else if(k == 2) {
				resultData.put("Source Of Variation", "Within groups");
				resultData.put("Sum Of Squares", String.valueOf(wgssq));
				resultData.put("Degress Of Freedom", String.valueOf((int)wgdf));
				resultData.put("Mean Square", String.valueOf(wgmsq));								
			} else {
				resultData.put("Source Of Variation", "");
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("R", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)totaldf));
				resultData.put("Mean Square", String.valueOf((double)outputTable.get2d("R", "SSq")/totaldf));
			}
			
			resultDataList.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("significanceResult", significanceResult);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("crossover", crossoverMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=onewayAnova2", "analysis=1"})
	public Map<String, Object> onewayAnova2Java(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String dimensions = String.valueOf(params.get("dimensions"));
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		/* DOGFOOT ktkang 통계 오류 수정  20210216 */
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> dimensionList = gson.fromJson(dimensions, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		double aLevel = 0.05;
		AssociativeArray2D outputTable = new AssociativeArray2D();
		AssociativeArray2D outputTable2 = new AssociativeArray2D();
		int resultCode = 0;
		String errorMsg = "";
		
		boolean significanceResult = false;
		
		Map<String, Object> entryMap = globalDataList.get(0);
		Map<String, Object> measureMap = measureList.get(0);
		TransposeDataCollection transposeDataCollection = new TransposeDataCollection();
		TransposeDataCollection transposeDataCollection2 = new TransposeDataCollection();

		Object[] dimensionsArr1 = new Object[globalDataList.size()];
		Object[] dimensionsArr2 = new Object[globalDataList.size()];
		Object[] measureArr = new Object[globalDataList.size()];

		String[] dimensionsStr1 = new String[globalDataList.size()];
		String[] dimensionsStr2 = new String[globalDataList.size()];
		double[] measureDou = new double[globalDataList.size()];
		
		String measureName = (String) measureMap.get("name");
		String measureSummary = (String) measureMap.get("nameBySummaryType");

		int i = 0; int j = 0;
		for(LinkedHashMap<String, Object> data : globalDataList) {
			for (String key : entryMap.keySet()) {
				if(measureSummary.equals(key)) {
					measureDou[i] = Double.parseDouble(String.valueOf(data.get(key)));
					measureArr[i] = Double.parseDouble(String.valueOf(data.get(key)));
					i++;
				} else {
					if(dimensionsArr1[j] == null) {
						dimensionsStr1[j] = String.valueOf(data.get(key));
						dimensionsArr1[j] = String.valueOf(data.get(key));
					} else {
						dimensionsStr2[j] = String.valueOf(data.get(key));
						dimensionsArr2[j] = String.valueOf(data.get(key));
						j++;
					}
				}
			}
		}

		List<Object> list = Arrays.asList(dimensionsArr1);
		Set<Object> uniqueSet = new HashSet<Object>(list);
		List<Object> setList = new ArrayList<Object>(uniqueSet);
		setList.sort(null);
		
		List<Object> itemList = Arrays.asList(dimensionsArr2);
		Set<Object> itemUniqueSet = new HashSet<Object>(itemList);
		List<Object> itemSetList = new ArrayList<Object>(itemUniqueSet);
		itemSetList.sort(null);
		/*Map<String, Object> itemCntMap = new HashMap<String, Object>();
		for(Object set : itemList) {
			if(itemCntMap.get(set) == null) {
				itemCntMap.put(String.valueOf(set), 1);
			} else {
				itemCntMap.put(String.valueOf(set), Integer.parseInt(String.valueOf(itemCntMap.get(set))) + 1);
			}
		}
		int itemCnt = 0;
		for(String key : itemCntMap.keySet()) {
			if(itemCnt == 0) itemCnt = Integer.parseInt(String.valueOf(itemCntMap.get(key)));
			if(itemCnt != Integer.parseInt(String.valueOf(itemCntMap.get(key)))) {
				throw new IllegalArgumentException("The cells must be of equal size.");
			}
		}*/
		
		i = 0;
		for(Object set : setList) {
			String groupName = "";
			Collection<Object> groupList = new ArrayList<Object>();
			for(LinkedHashMap<String, Object> data : globalDataList) {
				if(data.get(dimensionList.get(0).get("name")).equals(set)) {
					groupName = String.valueOf(set);
					groupList.add(Double.parseDouble(String.valueOf(data.get(measureSummary))));
				}
			}
			transposeDataCollection.put(groupName, new FlatDataCollection(groupList));
			i++;
		}
		
		for(Object set : itemSetList) {
			String groupName = "";
			Collection<Object> groupList = new ArrayList<Object>();
			for(LinkedHashMap<String, Object> data : globalDataList) {
				if(data.get(dimensionList.get(1).get("name")).equals(set)) {
					groupName = String.valueOf(set);
					groupList.add(Double.parseDouble(String.valueOf(data.get(measureSummary))));
				}
			}
			transposeDataCollection2.put(groupName, new FlatDataCollection(groupList));
		}

		try {
			significanceResult = oneWayEqualVars(transposeDataCollection, aLevel, outputTable);
			/* DOGFOOT syjin 분산분석_반복없는이원 JAVA 불러오기 수정 20210219 */
			//if(significanceResult) 
				significanceResult = oneWayEqualVars(transposeDataCollection2, aLevel, outputTable2); 
		} catch (Exception e) {
			resultCode = 99;
			errorMsg = e.getMessage();
		}
		
		format.setGroupingUsed(false);
		
		DescriptiveStatistics summary = new DescriptiveStatistics();
	    
		for (int k = 0; k < measureArr.length; k++) {
			summary.addValue((double) measureArr[k]);
		}
		
		Map<String, Object> descriptiveResult = descriptiveResult(summary, measureArr, true);
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<String> descriptiveList = descriptiveList(true);
		for(int k=0; k < descriptiveList.size(); k++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(k));
			descriptive.put(measureName, descriptiveResult.get(descriptiveList.get(k)));
			
			descriptiveMap.add(descriptive);
		}
		
		/* DOGFOOT ktkang 교차분석 표 구현  20201104 */
		List<Object> crossoverMap = new ArrayList<Object>();
		for(int k = 0; k < itemSetList.size(); k++) {
			JSONObject crossover = new JSONObject();
			crossover.put(dimensionList.get(1).get("name"), itemSetList.get(k));
			for(int o = 0; o < setList.size(); o++) {
				int p = 0;
				for(LinkedHashMap<String, Object> gdl : globalDataList) {
					if(gdl.get(dimensionList.get(0).get("name")).equals(setList.get(o)) && gdl.get(dimensionList.get(1).get("name")).equals(itemSetList.get(k))) {
						p++;
					}
				}
				crossover.put(setList.get(o), String.valueOf(p));
			}
			
			crossoverMap.add(crossover);
		}
		
		int bgdf = (int) Double.parseDouble(String.valueOf(outputTable.get2d("BG", "DF")));
		int bsdf = (int) Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "DF")));
		int wgdf = setList.size() + itemSetList.size() - 1;
		int totaldf = setList.size() * itemSetList.size() - 1;
		
		double wgssq = Double.parseDouble(String.valueOf((double)outputTable.get2d("R", "SSq") - (double)outputTable.get2d("BG", "SSq") - (double)outputTable2.get2d("BG", "SSq")));
		double wgmsq = wgssq/wgdf;
		
		double bgf = Double.parseDouble(String.valueOf(outputTable.get2d("BG", "MSq"))) / wgmsq;
        double bgp = ContinuousDistributions.FCdf(bgf, bgdf, wgdf);
        double bsf = Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "MSq"))) / wgmsq;
        double bsp = ContinuousDistributions.FCdf(bsf, bsdf, wgdf);
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		/* DOGFOOT ktkang 분석 결과표 값 수정  20201104 */
		for(int k=0; k < 4; k++) {
			JSONObject resultData = new JSONObject();
			/* DOGFOOT syjin 분산분석 반복없는 이원배치 분석결과표 java 배치 수정  20210316 */
			if(k == 0) {
				resultData.put("Source Of Variation", dimensionList.get(0).get("name"));
				resultData.put("F Statistics", String.valueOf(bgf));
				resultData.put("P value", String.valueOf(1.0 - bgp));
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("BG", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BG", "MSq")))));					
			} else if(k == 1) {
				resultData.put("Source Of Variation", dimensionList.get(1).get("name"));
				resultData.put("F Statistics", String.valueOf(bsf));
				resultData.put("P value", String.valueOf(1.0 - bsp));
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable2.get2d("BG", "MSq")))));
			} else if(k == 2) {
				resultData.put("Source Of Variation", "Within groups");
				resultData.put("Sum Of Squares", String.valueOf(wgssq));
				resultData.put("Degress Of Freedom", String.valueOf((int)wgdf));
				resultData.put("Mean Square", String.valueOf(wgmsq));								
			} else {
				resultData.put("Source Of Variation", "");
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("R", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)totaldf));
				resultData.put("Mean Square", String.valueOf((double)outputTable.get2d("R", "SSq")/totaldf));
			}
			
			resultDataList.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("significanceResult", significanceResult);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("crossover", crossoverMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	/**
	 * 분산분석(이원)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=twowayAnova", "analysis=0"})
	public Map<String, Object> twowayAnova(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String dimensions = String.valueOf(params.get("dimensions"));
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		/* DOGFOOT ktkang 통계 오류 수정  20210216 */
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> dimensionList = gson.fromJson(dimensions, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		double aLevel = 0.05;
		AssociativeArray2D outputTable = new AssociativeArray2D();
		int resultCode = 0;
		String errorMsg = "";
		
		boolean significanceResult = false;
		
		Map<String, Object> entryMap = globalDataList.get(0);
		Map<String, Object> measureMap = measureList.get(0);
		
		Object[] dimensionsArr1 = new Object[globalDataList.size()];
		Object[] dimensionsArr2 = new Object[globalDataList.size()];
		Object[] measureArr = new Object[globalDataList.size()];
		
		String[] dimensionsStr1 = new String[globalDataList.size()];
		String[] dimensionsStr2 = new String[globalDataList.size()];
		double[] measureDou = new double[globalDataList.size()];
		
		String measureName = (String) measureMap.get("name");
		String measureSummary = (String) measureMap.get("nameBySummaryType");
		
		int i = 0; int j = 0;
		for(LinkedHashMap<String, Object> data : globalDataList) {
			for (String key : entryMap.keySet()) {
			    if(measureSummary.equals(key)) {
			    	measureDou[i] = Double.parseDouble(String.valueOf(data.get(key)));
			    	measureArr[i] = Double.parseDouble(String.valueOf(data.get(key)));
			    	i++;
			    } else {
			    	if(dimensionsArr1[j] == null) {
			    		dimensionsStr1[j] = String.valueOf(data.get(key));
			    		dimensionsArr1[j] = String.valueOf(data.get(key));
			    	} else {
			    		dimensionsStr2[j] = String.valueOf(data.get(key));
			    		dimensionsArr2[j] = String.valueOf(data.get(key));
			    		j++;
			    	}
			    }
			}
		}
		
		TransposeDataCollection2D twoFactorDataCollection = new TransposeDataCollection2D();
		
		List<Object> list = Arrays.asList(dimensionsArr1);
		Set<Object> uniqueSet = new LinkedHashSet<Object>(list);
		List<Object> setList = new ArrayList<Object>(uniqueSet);
		
		List<Object> list2 = Arrays.asList(dimensionsArr2);
		Set<Object> uniqueSet2 = new LinkedHashSet<Object>(list2);
		List<Object> setList2 = new ArrayList<Object>(uniqueSet2);
		
		setList2.sort(null);
		Map<String, Object> itemCntMap = new HashMap<String, Object>();
		for(Object set : setList2) {
			if(itemCntMap.get(set) == null) {
				itemCntMap.put(String.valueOf(set), 1);
			} else {
				itemCntMap.put(String.valueOf(set), Integer.parseInt(String.valueOf(itemCntMap.get(set))) + 1);
			}
		}
		int itemCnt = 0;
		for(String key : itemCntMap.keySet()) {
			if(itemCnt == 0) itemCnt = Integer.parseInt(String.valueOf(itemCntMap.get(key)));
			if(itemCnt != Integer.parseInt(String.valueOf(itemCntMap.get(key)))) {
				throw new IllegalArgumentException("The cells must be of equal size.");
			}
		}
		
		double[][] groupArr = new double[list.size()][];
		String[][] groupNmArr = new String[list.size()][];
		
		int idx = 0;
		for(Object set : setList) {
			for(Object set2 : setList2) {
				int idx2 = 0; int cnt = 0; 
				for(int ii = 0;ii < dimensionsArr2.length;ii++) {
					if(set.equals(dimensionsArr1[ii]) && set2.equals(dimensionsArr2[ii])) cnt++;
				} 
				if(cnt == 0) continue;
				i = 0; j = 0;
				groupArr[idx] = new double[cnt];
				groupNmArr[idx] = new String[cnt];
				for(Object dim : dimensionsArr2) {
					j++; idx2++;
					if(set.equals(dimensionsArr1[idx2-1]) && dim.equals(set2)) {
						groupArr[idx][i] = Double.parseDouble(String.valueOf(measureArr[j-1]));
						groupNmArr[idx][i] = String.valueOf(dimensionsArr2[j-1]);
						
						i++;
						if(i == cnt) {
							idx++;
							break;
						}
					}
				}
			}
		}
		
		Map<String, Object> keyMap = new HashMap<String, Object>();
		
		Collection<Object> groupList = new ArrayList<Object>();
		TransposeDataCollection transposeDataCollection = new TransposeDataCollection();
		
		i = 0;
		for(String[] arr : groupNmArr) {
			if(arr == null) {
				twoFactorDataCollection.put(i, transposeDataCollection);
				break;
			}
			double[] dataArr = new double[arr.length];
			
			if(keyMap.containsKey(arr[0])) {
				twoFactorDataCollection.put(i, transposeDataCollection);
				
				transposeDataCollection = new TransposeDataCollection();
			}
			
			if(i == 0) {
				keyMap.put(arr[0], arr[0]);
			}

			j = 0;
			for(String str : arr) {
				dataArr[j] = groupArr[i][j];
				
				if((j+1) == arr.length) {
					for(double data : dataArr) {
						groupList.add(data);
					}
					transposeDataCollection.put(str, new FlatDataCollection(groupList));
					
					groupList = new ArrayList<Object>();
				}
				j++;
			}
			
			i++;
			
			if((i+1) == groupNmArr.length) {
				twoFactorDataCollection.put(i, transposeDataCollection);
			}
		}

		try {
			significanceResult = twoWayEqualCellsEqualVars(twoFactorDataCollection, aLevel, outputTable);
		} catch (Exception e) {
			resultCode = 99;
			errorMsg = e.getMessage();
			e.printStackTrace();
		}
		
		format.setGroupingUsed(false);
		
		/* DOGFOOT ktkang 기술통계표 구현  20201104 */
		DescriptiveStatistics summary = new DescriptiveStatistics();
	    
		for (int k = 0; k < measureArr.length; k++) {
			summary.addValue((double) measureArr[k]);
		}
		
		Map<String, Object> descriptiveResult = descriptiveResult(summary, measureArr, true);
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<String> descriptiveList = descriptiveList(true);
		for(int k=0; k < descriptiveList.size(); k++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(k));
			descriptive.put(measureName, descriptiveResult.get(descriptiveList.get(k)));
			
			descriptiveMap.add(descriptive);
		}
		
		/* DOGFOOT ktkang 교차분석표 구현  20201104 */
		List<Object> crossoverMap = new ArrayList<Object>();
		for(int k = 0; k < setList2.size(); k++) {
			JSONObject crossover = new JSONObject();
			crossover.put(dimensionList.get(1).get("name"), setList2.get(k));
			for(int o = 0; o < setList.size(); o++) {
				int p = 0;
				for(LinkedHashMap<String, Object> gdl : globalDataList) {
					if(gdl.get(dimensionList.get(0).get("name")).equals(setList.get(o)) && gdl.get(dimensionList.get(1).get("name")).equals(setList2.get(k))) {
						p++;
					}
				}
				crossover.put(setList.get(o), String.valueOf(p));
			}
			
			crossoverMap.add(crossover);
		}
		
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		RCaller caller2 = RCaller.create(code, options);
		
		code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
		/* DOGFOOT ktkang install.packages("lmerTest") 필요 이원반복분산분석 추가  20210127 */
		/* DOGFOOT syjin install.packages("lmerTest") 추가  20210127 */
		
		//code.addRCode("if(!c(\"nloptr\") %in% installed.packages()[,\"Package\"]){");	//패키지 설치 여부 확인
		//code.addRCode("install.packages(\"lmerTest\");}");			
		//code.addRCode("install.packages(\"nloptr\");}");	
		
		//code.addRCode("if(!c(\"lme4\") %in% installed.packages()[,\"Package\"]){");	//패키지 설치 여부 확인
		//code.addRCode("install.packages(\"lmerTest\");}");			
		//code.addRCode("install.packages(\"lme4\");}");	
		
		//code.addRCode("if(!c(\"lmerTest\") %in% installed.packages()[,\"Package\"]){");	//패키지 설치 여부 확인
		//code.addRCode("install.packages(\"lmerTest\");}");			
		//code.addRCode("install.packages(\"lmerTest\");}");
				
		code.addStringArray("dim1", dimensionsStr1);
		code.addStringArray("dim2", dimensionsStr2);
		code.addDoubleArray("mea", measureDou);
		
		code.addRCode("library(lmerTest)");
		code.addRCode("df<-data.frame(dim1, dim2, mea)");
		code.addRCode("fit <- lmer(mea ~ dim1*dim2 + (1|dim1), data=df)");
		code.addRCode("fit2 <- lmer(mea ~ dim1*dim2 + (1|dim2), data=df)");
		code.addRCode("a<-anova(fit)");
		code.addRCode("b<-anova(fit2)");
		
		code.addRCode("path <- .libPaths()");
		code.addRCode("result <- c(b, path)");
		
		caller.setRCode(code);
		caller2.setRCode(code);
		caller.runAndReturnResult("a");
		caller2.runAndReturnResult("result");
		
		System.out.println(caller.getParser().getXMLFileAsString());
		System.out.println(caller2.getParser().getXMLFileAsString());
		
		//Sum of Squares
		double[] RSumSq1 = caller.getParser().getAsDoubleArray("SumSq");
		//Degress Of Freedom
		double[] RDf1 = caller.getParser().getAsDoubleArray("NumDF");
		//Mean Square
		double[] RMeanSq1 = caller.getParser().getAsDoubleArray("MeanSq");
		//F Statics
		String[] RFStatics1 = caller.getParser().getAsStringArray("Fvalue");
		//PrF
		String[] RPrf1 = caller.getParser().getAsStringArray("PrF");
		
		//Sum of Squares
		double[] RSumSq2 = caller2.getParser().getAsDoubleArray("SumSq");
		//Degress Of Freedom
		double[] RDf2 = caller2.getParser().getAsDoubleArray("NumDF");
		//Mean Square
		double[] RMeanSq2 = caller2.getParser().getAsDoubleArray("MeanSq");
		//F Statics
		String[] RFStatics2 = caller2.getParser().getAsStringArray("Fvalue");
		//PrF
		String[] RPrf2 = caller2.getParser().getAsStringArray("PrF");
				
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		/* DOGFOOT ktkang 분석 결과표 값 수정  20201104 */
		double sum = 0;
		double degress = 0;
		for(int k=0; k < 5; k++) {
			JSONObject resultData = new JSONObject();
			/* DOGFOOT syjin 반복있는 이원배치 R 추가  20210127 */
			if(k == 0) {
				sum = Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "SSq")));
				degress = Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "DF")));
				resultData.put("Source Of Variation", dimensionList.get(0).get("name"));
				//resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "SSq")))));
				//resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "DF")))));
				//resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "MSq")))));
				//resultData.put("F Statistics", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "F")))));
				//resultData.put("P value", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "p")))));
				
				resultData.put("Sum Of Squares", RSumSq2[0]);
				resultData.put("Degress Of Freedom", RDf2[0]);
				resultData.put("Mean Square", RMeanSq2[0]);
				resultData.put("F Statistics", RFStatics2[0]);
				resultData.put("P value", RPrf2[0]);
			} else if(k == 1) {
				sum = sum + Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "SSq"))); 
				degress = degress + Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "DF")));
				resultData.put("Source Of Variation", dimensionList.get(1).get("name"));
				//resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "SSq")))));
				//resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "DF")))));
				//resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "MSq")))));
				//resultData.put("F Statistics", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "F")))));
				//resultData.put("P value", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "p")))));
				
				resultData.put("Sum Of Squares", RSumSq1[1]);
				resultData.put("Degress Of Freedom", RDf1[1]);
				resultData.put("Mean Square", RMeanSq1[1]);
				resultData.put("F Statistics", RFStatics1[1]);
				resultData.put("P value", RPrf1[1]);
			} else if(k == 2) {
				sum = sum + Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "SSq")));
				degress = degress + Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "DF")));
				resultData.put("Source Of Variation", "Interaction");
				//resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "SSq")))));
				//resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "DF")))));
				//resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "MSq")))));
				//resultData.put("F Statistics", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "F")))));
				//resultData.put("P value", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "p")))));
				
				resultData.put("Sum Of Squares", RSumSq1[2]);
				resultData.put("Degress Of Freedom", RDf1[2]);
				resultData.put("Mean Square", RMeanSq1[2]);
				resultData.put("F Statistics", RFStatics1[2]);
				resultData.put("P value", RPrf1[2]);
			} else if(k == 3) {
				sum = sum + Double.parseDouble(String.valueOf(outputTable.get2d("Error", "SSq")));
				degress = degress + Double.parseDouble(String.valueOf(outputTable.get2d("Error", "DF")));
				resultData.put("Source Of Variation", "Within groups");
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("Error", "DF"))) == 0. ? 0 : Double.parseDouble(String.valueOf(outputTable.get2d("Error", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("Error", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("Error", "MSq")))));
				//resultData.put("Mean Square", format.format(Double.parseDouble(String.valueOf(outputTable.get2d("Error", "MSq")))));
			} else {
				resultData.put("Source Of Variation", "");
				resultData.put("Sum Of Squares", String.valueOf(sum));
				resultData.put("Degress Of Freedom", String.valueOf((int)degress));
				resultData.put("Mean Square", String.valueOf(sum / degress));
				//resultData.put("Mean Square", format.format(mean));
			}
			
			resultDataList.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("significanceResult", significanceResult);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("crossover", crossoverMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=twowayAnova", "analysis=1"})
	public Map<String, Object> twowayAnovaJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String dimensions = String.valueOf(params.get("dimensions"));
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		/* DOGFOOT ktkang 통계 오류 수정  20210216 */
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> dimensionList = gson.fromJson(dimensions, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		double aLevel = 0.05;
		AssociativeArray2D outputTable = new AssociativeArray2D();
		int resultCode = 0;
		String errorMsg = "";
		
		boolean significanceResult = false;
		
		Map<String, Object> entryMap = globalDataList.get(0);
		Map<String, Object> measureMap = measureList.get(0);
		
		Object[] dimensionsArr1 = new Object[globalDataList.size()];
		Object[] dimensionsArr2 = new Object[globalDataList.size()];
		Object[] measureArr = new Object[globalDataList.size()];
		
		String[] dimensionsStr1 = new String[globalDataList.size()];
		String[] dimensionsStr2 = new String[globalDataList.size()];
		double[] measureDou = new double[globalDataList.size()];
		
		String measureName = (String) measureMap.get("name");
		String measureSummary = (String) measureMap.get("nameBySummaryType");
		
		int i = 0; int j = 0;
		for(LinkedHashMap<String, Object> data : globalDataList) {
			for (String key : entryMap.keySet()) {
			    if(measureSummary.equals(key)) {
			    	measureDou[i] = Double.parseDouble(String.valueOf(data.get(key)));
			    	measureArr[i] = Double.parseDouble(String.valueOf(data.get(key)));
			    	i++;
			    } else {
			    	if(dimensionsArr1[j] == null) {
			    		dimensionsStr1[j] = String.valueOf(data.get(key));
			    		dimensionsArr1[j] = String.valueOf(data.get(key));
			    	} else {
			    		dimensionsStr2[j] = String.valueOf(data.get(key));
			    		dimensionsArr2[j] = String.valueOf(data.get(key));
			    		j++;
			    	}
			    }
			}
		}
		
		TransposeDataCollection2D twoFactorDataCollection = new TransposeDataCollection2D();
		
		List<Object> list = Arrays.asList(dimensionsArr1);
		Set<Object> uniqueSet = new LinkedHashSet<Object>(list);
		List<Object> setList = new ArrayList<Object>(uniqueSet);
		
		List<Object> list2 = Arrays.asList(dimensionsArr2);
		Set<Object> uniqueSet2 = new LinkedHashSet<Object>(list2);
		List<Object> setList2 = new ArrayList<Object>(uniqueSet2);
		
		setList2.sort(null);
		Map<String, Object> itemCntMap = new HashMap<String, Object>();
		for(Object set : setList2) {
			if(itemCntMap.get(set) == null) {
				itemCntMap.put(String.valueOf(set), 1);
			} else {
				itemCntMap.put(String.valueOf(set), Integer.parseInt(String.valueOf(itemCntMap.get(set))) + 1);
			}
		}
		int itemCnt = 0;
		for(String key : itemCntMap.keySet()) {
			if(itemCnt == 0) itemCnt = Integer.parseInt(String.valueOf(itemCntMap.get(key)));
			if(itemCnt != Integer.parseInt(String.valueOf(itemCntMap.get(key)))) {
				throw new IllegalArgumentException("The cells must be of equal size.");
			}
		}
		
		double[][] groupArr = new double[list.size()][];
		String[][] groupNmArr = new String[list.size()][];
		
		int idx = 0;
		for(Object set : setList) {
			for(Object set2 : setList2) {
				int idx2 = 0; int cnt = 0; 
				for(int ii = 0;ii < dimensionsArr2.length;ii++) {
					if(set.equals(dimensionsArr1[ii]) && set2.equals(dimensionsArr2[ii])) cnt++;
				} 
				if(cnt == 0) continue;
				i = 0; j = 0;
				groupArr[idx] = new double[cnt];
				groupNmArr[idx] = new String[cnt];
				for(Object dim : dimensionsArr2) {
					j++; idx2++;
					if(set.equals(dimensionsArr1[idx2-1]) && dim.equals(set2)) {
						groupArr[idx][i] = Double.parseDouble(String.valueOf(measureArr[j-1]));
						groupNmArr[idx][i] = String.valueOf(dimensionsArr2[j-1]);
						
						i++;
						if(i == cnt) {
							idx++;
							break;
						}
					}
				}
			}
		}
		
		Map<String, Object> keyMap = new HashMap<String, Object>();
		
		Collection<Object> groupList = new ArrayList<Object>();
		TransposeDataCollection transposeDataCollection = new TransposeDataCollection();
		
		i = 0;
		for(String[] arr : groupNmArr) {
			if(arr == null) {
				twoFactorDataCollection.put(i, transposeDataCollection);
				break;
			}
			double[] dataArr = new double[arr.length];
			
			if(keyMap.containsKey(arr[0])) {
				twoFactorDataCollection.put(i, transposeDataCollection);
				
				transposeDataCollection = new TransposeDataCollection();
			}
			
			if(i == 0) {
				keyMap.put(arr[0], arr[0]);
			}

			j = 0;
			for(String str : arr) {
				dataArr[j] = groupArr[i][j];
				
				if((j+1) == arr.length) {
					for(double data : dataArr) {
						groupList.add(data);
					}
					transposeDataCollection.put(str, new FlatDataCollection(groupList));
					
					groupList = new ArrayList<Object>();
				}
				j++;
			}
			
			i++;
			
			if((i+1) == groupNmArr.length) {
				twoFactorDataCollection.put(i, transposeDataCollection);
			}
		}

		try {
			significanceResult = twoWayEqualCellsEqualVars(twoFactorDataCollection, aLevel, outputTable);
		} catch (Exception e) {
			resultCode = 99;
			errorMsg = e.getMessage();
			e.printStackTrace();
		}
		
		format.setGroupingUsed(false);
		
		/* DOGFOOT ktkang 기술통계표 구현  20201104 */
		DescriptiveStatistics summary = new DescriptiveStatistics();
	    
		for (int k = 0; k < measureArr.length; k++) {
			summary.addValue((double) measureArr[k]);
		}
		
		Map<String, Object> descriptiveResult = descriptiveResult(summary, measureArr, true);
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<String> descriptiveList = descriptiveList(true);
		for(int k=0; k < descriptiveList.size(); k++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(k));
			descriptive.put(measureName, descriptiveResult.get(descriptiveList.get(k)));
			
			descriptiveMap.add(descriptive);
		}
		
		/* DOGFOOT ktkang 교차분석표 구현  20201104 */
		List<Object> crossoverMap = new ArrayList<Object>();
		for(int k = 0; k < setList2.size(); k++) {
			JSONObject crossover = new JSONObject();
			crossover.put(dimensionList.get(1).get("name"), setList2.get(k));
			for(int o = 0; o < setList.size(); o++) {
				int p = 0;
				for(LinkedHashMap<String, Object> gdl : globalDataList) {
					if(gdl.get(dimensionList.get(0).get("name")).equals(setList.get(o)) && gdl.get(dimensionList.get(1).get("name")).equals(setList2.get(k))) {
						p++;
					}
				}
				crossover.put(setList.get(o), String.valueOf(p));
			}
			
			crossoverMap.add(crossover);
		}
					
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		/* DOGFOOT ktkang 분석 결과표 값 수정  20201104 */
		double sum = 0;
		double degress = 0;
		for(int k=0; k < 5; k++) {
			JSONObject resultData = new JSONObject();
			/* DOGFOOT syjin 반복있는 이원배치 R 추가  20210127 */
			if(k == 0) {
				sum = Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "SSq")));
				degress = Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "DF")));
				resultData.put("Source Of Variation", dimensionList.get(0).get("name"));
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "MSq")))));
				resultData.put("F Statistics", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "F")))));
				resultData.put("P value", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("AFactor", "p")))));
			} else if(k == 1) {
				sum = sum + Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "SSq"))); 
				degress = degress + Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "DF")));
				resultData.put("Source Of Variation", dimensionList.get(1).get("name"));
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "MSq")))));
				resultData.put("F Statistics", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "F")))));
				resultData.put("P value", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("BFactor", "p")))));
			} else if(k == 2) {
				sum = sum + Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "SSq")));
				degress = degress + Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "DF")));
				resultData.put("Source Of Variation", "Interaction");
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "MSq")))));
				resultData.put("F Statistics", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "F")))));
				resultData.put("P value", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("A*BFactor", "p")))));			
			} else if(k == 3) {
				sum = sum + Double.parseDouble(String.valueOf(outputTable.get2d("Error", "SSq")));
				degress = degress + Double.parseDouble(String.valueOf(outputTable.get2d("Error", "DF")));
				resultData.put("Source Of Variation", "Within groups");
				resultData.put("Sum Of Squares", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("Error", "DF"))) == 0. ? 0 : Double.parseDouble(String.valueOf(outputTable.get2d("Error", "SSq")))));
				resultData.put("Degress Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(outputTable.get2d("Error", "DF")))));
				resultData.put("Mean Square", String.valueOf(Double.parseDouble(String.valueOf(outputTable.get2d("Error", "MSq")))));
				//resultData.put("Mean Square", format.format(Double.parseDouble(String.valueOf(outputTable.get2d("Error", "MSq")))));
			} else {
				resultData.put("Source Of Variation", "");
				resultData.put("Sum Of Squares", String.valueOf(sum));
				resultData.put("Degress Of Freedom", String.valueOf((int)degress));
				resultData.put("Mean Square", String.valueOf(sum / degress));
				//resultData.put("Mean Square", format.format(mean));
			}
			
			resultDataList.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("significanceResult", significanceResult);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("crossover", crossoverMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	/**
	 * 상관분석(피어슨)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=pearsonsCorrelation", "analysis=0"})
	public Map<String, Object> pearsonsCorrelation(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}

		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		Object[][] obArray = new Object[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			Object[] ob = new Object[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		DataFrame df = DataFrame.create(obArray, setListArray);
		
		code.addDataFrame("x", df);
		code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
		code.addRCode("ols <- cor(x, method=\"pearson\")");
		caller.setRCode(code);
		caller.runAndReturnResult("ols");
		
		System.out.println(caller.getParser().getXMLFileAsString());
		System.out.println(caller.getParser().getNames());
		
		//ols
		//DOGFOOT syjin 상관분석 피어슨 R로 변환 수정 20210126
		double[] ROls = caller.getParser().getAsDoubleArray("ols");
		double[] ols = new double[result.size()];
		
		int length = setListArray.length;
		int loopCheck = 0;
		int index = 0;
				
		for(int k=0; k<ROls.length; k++) {
			if((k % (length+1)) != 0) {
				if(k % length != 0) {	
					if(k % length > loopCheck) {
						ols[index] = ROls[k];
						index++;
					}
				}else {
					if(k!=0) {
						loopCheck++;
					}
				}
				if(index == result.size()) {
					break;
				}
			}
		}
			
		for(int k=0; k < result.size(); k++) {
			JSONObject resultData = new JSONObject();
			String[] resultArr = result.get(k).split(",");
			resultData.put("변수", String.valueOf(resultArr[0]));
			resultData.put("구분", "상관 변수");
			resultData.put("값", String.valueOf(resultArr[1]));
			resultDataList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", "");
			resultData.put("구분", "피어슨 상관계수");
			//DOGFOOT syjin 상관분석 피어슨 R로 변환  20210125
			//resultData.put("값", String.valueOf(resultArr[2]));
			System.out.println("변경 전: " + String.valueOf(resultArr[2]));
			System.out.println("변경 후: " + ols[k]);
			resultData.put("값", ols[k]);
			
			resultDataList.add(resultData);
						
			resultData = new JSONObject();
			resultData.put("변수", "");
			resultData.put("구분", "N");
			
			resultData.put("값", String.valueOf(resultArr[3]));
			resultDataList.add(resultData);
		}
		
		List<Object> resultDataHeatMapList = new ArrayList<Object>();
		for(int k=0; k < result.size(); k++) {
			JSONObject resultData = new JSONObject();
			String[] resultArr = result.get(k).split(",");
			resultData.put("변수", String.valueOf(resultArr[0]));
			resultData.put("구분변수", String.valueOf(resultArr[1]));
			//DOGFOOT syjin 상관분석 피어슨 R로 변환  20210125
			//resultData.put("값", String.valueOf(resultArr[2]));
			System.out.println("변경 전: " + String.valueOf(resultArr[2]));
			System.out.println("변경 후: " + ols[k]);
			resultData.put("값", ols[k]);
			resultDataHeatMapList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", String.valueOf(resultArr[1]));
			resultData.put("구분변수", String.valueOf(resultArr[0]));
			//DOGFOOT syjin 상관분석 피어슨 R로 변환  20210125
			//resultData.put("값", String.valueOf(resultArr[2]));
			System.out.println("변경 전: " + String.valueOf(resultArr[2]));
			System.out.println("변경 후: " + ols[k]);
			resultData.put("값", ols[k]);
			resultDataHeatMapList.add(resultData);
		}
			
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("heatmapdata", resultDataHeatMapList);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=pearsonsCorrelation", "analysis=1"})
	public Map<String, Object> pearsonsCorrelationJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}

		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		Object[][] obArray = new Object[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			Object[] ob = new Object[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();	
		
		DataFrame df = DataFrame.create(obArray, setListArray);
		
		double[] ols = new double[result.size()];
		
		int length = setListArray.length;
		int loopCheck = 0;
		int index = 0;
							
		for(int k=0; k < result.size(); k++) {
			JSONObject resultData = new JSONObject();
			String[] resultArr = result.get(k).split(",");
			resultData.put("변수", String.valueOf(resultArr[0]));
			resultData.put("구분", "상관 변수");
			resultData.put("값", String.valueOf(resultArr[1]));
			resultDataList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", "");
			resultData.put("구분", "피어슨 상관계수");
			resultData.put("값", String.valueOf(resultArr[2]));
			
			resultDataList.add(resultData);
						
			resultData = new JSONObject();
			resultData.put("변수", "");
			resultData.put("구분", "N");
			
			resultData.put("값", String.valueOf(resultArr[3]));
			resultDataList.add(resultData);
		}
		
		List<Object> resultDataHeatMapList = new ArrayList<Object>();
		for(int k=0; k < result.size(); k++) {
			JSONObject resultData = new JSONObject();
			String[] resultArr = result.get(k).split(",");
			resultData.put("변수", String.valueOf(resultArr[0]));
			resultData.put("구분변수", String.valueOf(resultArr[1]));
			//DOGFOOT syjin 상관분석 피어슨 R로 변환  20210125
			resultData.put("값", String.valueOf(resultArr[2]));		
			resultDataHeatMapList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", String.valueOf(resultArr[1]));
			resultData.put("구분변수", String.valueOf(resultArr[0]));
			//DOGFOOT syjin 상관분석 피어슨 R로 변환  20210125
			resultData.put("값", String.valueOf(resultArr[2]));
			
			resultDataHeatMapList.add(resultData);
		}
			
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("heatmapdata", resultDataHeatMapList);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	
	
	/**
	 * 상관분석(스피어만)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=spearmansCorrelation", "analysis=0"})
	public Map<String, Object> spearmansCorrelation(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		String[] setListArray = new String[entryMap.size()];
		Object[][] obArray = new Object[entryMap.size()][];
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			
			Object[] ob = new Object[x.length];
			for(int j = 0; j < x.length; j++) {
				ob[j] = x[j];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}

		List<String> result = new ArrayList<String>();
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getSpearmansCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			p++;
		}
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		DataFrame df = DataFrame.create(obArray, setListArray);
		
		code.addDataFrame("x", df);
		code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
		code.addRCode("ols <- cor(x, method=\"spearman\")");
		caller.setRCode(code);
		caller.runAndReturnResult("ols");
		
		System.out.println(caller.getParser().getXMLFileAsString());
		System.out.println(caller.getParser().getNames());
		
		//ols
		//DOGFOOT syjin 상관분석 스피어만 R로 변환 수정 20210126
		double[] ROls = caller.getParser().getAsDoubleArray("ols");
		double[] ols = new double[result.size()];
		
		int length = setListArray.length;
		int loopCheck = 0;
		int index = 0;
				
		for(int k=0; k<ROls.length; k++) {
			if((k % (length+1)) != 0) {
				if(k % length != 0) {	
					if(k % length > loopCheck) {
						ols[index] = ROls[k];
						index++;
					}
				}else {
					if(k!=0) {
						loopCheck++;
					}
				}
				if(index == result.size()) {
					break;
				}
			}
		}
		for(int k=0; k < result.size(); k++) {
			JSONObject resultData = new JSONObject();
			String[] resultArr = result.get(k).split(",");
			resultData.put("변수", String.valueOf(resultArr[0]));
			resultData.put("구분", "상관 변수");
			resultData.put("값", String.valueOf(resultArr[1]));
			resultDataList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", "");
			resultData.put("구분", "스피어만 상관계수");
			//DOGFOOT syjin 상관분석 스피어만 R로 변환  20210125
			//resultData.put("값", String.valueOf(resultArr[2]));
			System.out.println("변경 전: " + String.valueOf(resultArr[2]));
			System.out.println("변경 후: " + ols[k]);
			resultData.put("값", ols[k]);
			resultDataList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", "");
			resultData.put("구분", "N");		
			resultData.put("값", String.valueOf(resultArr[3]));			
			resultDataList.add(resultData);
		}
		
		List<Object> resultDataHeatMapList = new ArrayList<Object>();
		for(int k=0; k < result.size(); k++) {
			JSONObject resultData = new JSONObject();
			String[] resultArr = result.get(k).split(",");
			resultData.put("변수", String.valueOf(resultArr[0]));
			resultData.put("구분변수", String.valueOf(resultArr[1]));
			//DOGFOOT syjin 상관분석 스피어만 R로 변환  20210125
			//resultData.put("값", String.valueOf(resultArr[2]));
			System.out.println("변경 전: " + String.valueOf(resultArr[2]));
			System.out.println("변경 후: " + ols[k]);
			resultData.put("값", ols[k]);
			resultDataHeatMapList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", String.valueOf(resultArr[1]));
			resultData.put("구분변수", String.valueOf(resultArr[0]));
			//DOGFOOT syjin 상관분석 스피어만 R로 변환  20210125
			//resultData.put("값", String.valueOf(resultArr[2]));
			System.out.println("변경 전: " + String.valueOf(resultArr[2]));
			System.out.println("변경 후: " + ols[k]);
			resultData.put("값", ols[k]);
			resultDataHeatMapList.add(resultData);
		}
			
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("heatmapdata", resultDataHeatMapList);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=spearmansCorrelation", "analysis=1"})
	public Map<String, Object> spearmansCorrelationJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		String[] setListArray = new String[entryMap.size()];
		Object[][] obArray = new Object[entryMap.size()][];
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			
			Object[] ob = new Object[x.length];
			for(int j = 0; j < x.length; j++) {
				ob[j] = x[j];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}

		List<String> result = new ArrayList<String>();
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getSpearmansCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			p++;
		}
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		
		
		//ols
		//DOGFOOT syjin 상관분석 스피어만 R로 변환 수정 20210126
		
		double[] ols = new double[result.size()];
						
		for(int k=0; k < result.size(); k++) {
			JSONObject resultData = new JSONObject();
			String[] resultArr = result.get(k).split(",");
			resultData.put("변수", String.valueOf(resultArr[0]));
			resultData.put("구분", "상관 변수");
			resultData.put("값", String.valueOf(resultArr[1]));
			resultDataList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", "");
			resultData.put("구분", "스피어만 상관계수");
			resultData.put("값", String.valueOf(resultArr[2]));
			
			resultDataList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", "");
			resultData.put("구분", "N");		
			resultData.put("값", String.valueOf(resultArr[3]));			
			resultDataList.add(resultData);
		}
		
		List<Object> resultDataHeatMapList = new ArrayList<Object>();
		for(int k=0; k < result.size(); k++) {
			JSONObject resultData = new JSONObject();
			String[] resultArr = result.get(k).split(",");
			resultData.put("변수", String.valueOf(resultArr[0]));
			resultData.put("구분변수", String.valueOf(resultArr[1]));
			resultData.put("값", String.valueOf(resultArr[2]));
			resultDataHeatMapList.add(resultData);
			
			resultData = new JSONObject();
			resultData.put("변수", String.valueOf(resultArr[1]));
			resultData.put("구분변수", String.valueOf(resultArr[0]));
			resultData.put("값", String.valueOf(resultArr[2]));
			resultDataHeatMapList.add(resultData);
		}
			
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("heatmapdata", resultDataHeatMapList);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	/**
	 * 회귀분석(단순)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=simpleRegression", "analysis=0"})
	public Map<String, Object> simpleRegression(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
					
		StringBuffer xBf = new StringBuffer();
		
		Gson gson = new Gson();
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());

		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		double[] y = new double[globalDataList.size()];
		double[][] y2 = new double[1][globalDataList.size()];
		double[] x = new double[globalDataList.size()];
		double[][] y3 = new double[globalDataList.size()][1];
		
		int i = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			int j = 0;
			for (String key : entryMap.keySet()) {
				if(j == 0) {
					x[i] = Double.parseDouble(String.valueOf(map.get(key)));
				} else {
					y[i] = Double.parseDouble(String.valueOf(map.get(key)));
					y2[0][i] = Double.parseDouble(String.valueOf(map.get(key)));
					y3[i][0] = Double.parseDouble(String.valueOf(map.get(key)));;
					j = 0;
				}
				j++;
			}
			i++;
		}
		//DOGFOOT syjin R코드 추가  20210115
		code.addDoubleArray("x", x);
		code.addDoubleArray("y", y);
			
		code.addRCode("m <- lm(x~y)");
		code.addRCode("result <- summary(m)");
		code.addRCode("an <- anova(m)");
		code.addRCode("residuals <- residuals(m)");
		code.addRCode("confint <- confint(m)");
		code.addRCode("deviance <- deviance(m)");
		
		code.addRCode("Regressionp <- function (modelobject) {");
		code.addRCode("if (class(modelobject) != \"lm\") stop(\"Not an object of class 'lm' \")");
		code.addRCode("f <- summary(modelobject)$fstatistic");
		code.addRCode("p <- pf(f[1],f[2],f[3],lower.tail=F)");
		code.addRCode("attributes(p) <- NULL");
		code.addRCode("return(p)}");
				
		code.addRCode("pValue <- Regressionp(m)");						
		code.addRCode("all <- c(result, pValue, an)");		
			
		caller.setRCode(code);

		caller.runAndReturnResult("all");
		
		System.out.println("바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값");
		System.out.println("바인딩된 값 : " + caller.getParser().getXMLFileAsString());
		System.out.println("Available results from lm() object : ");
		System.out.println(caller.getParser().getNames());
		
		//Standard Error
		double[] RSigma = caller.getParser().getAsDoubleArray("sigma");
		//R Squared
		double[] RSquared = caller.getParser().getAsDoubleArray("r_squared");
		//Adjusted R Squared
		double[] RAdjRsquared = caller.getParser().getAsDoubleArray("adj_r_squared");
		//F Statistic
		double[] RFstatistic = caller.getParser().getAsDoubleArray("fstatistic");
		//P Value
		double[] RPvalue = caller.getParser().getAsDoubleArray("obj");
		//Sum of Squares
		double[] RSumOfSq = caller.getParser().getAsDoubleArray("SumSq");
		//Degree Of Freedom
		int[] RDf = caller.getParser().getAsIntArray("Df");	
		//Mean Square
		double[] RMeanSq = caller.getParser().getAsDoubleArray("MeanSq");
		//Cofficients
		double[] RCofficients = caller.getParser().getAsDoubleArray("coefficients");
		
		// DOGFOOT ktkang 기술통계 구하는 부분  20201028 
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210126 */
				String str = String.valueOf(meaMap.get(meaList.get(k))[j]);
				Double db = Double.parseDouble(str);
				
				summary.addValue(db);
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		/* DOGFOOT syjin 회귀분석_단순 R 불러오기 수정 20210219 */
		double aLevel = Double.parseDouble(String.valueOf(staticOptions.get("alphaLevel"))) * 0.01;
		
		LinearRegression reg = new LinearRegression(aLevel, x, y2);
		SimpleRegression regression = getSimpleRegression(x, y);
		RegressionResults regressionResults = regression.regress();
		
		final OLSMultipleLinearRegression ols = new OLSMultipleLinearRegression();
	    ols.newSampleData(x, y3); // provide the data to the model
		
	    TDistribution distribution = new TDistribution(regression.getN() - 2);
	    double tvalue = distribution.inverseCumulativeProbability(1d - aLevel / 2d);
	    
	    /* DOGFOOT syjin 단순선형 분산분석 R로 변환 20210126 */
		//double[] coefficients = reg.coefficients; 
		//double[] stdErrors = regressionResults.getStdErrorOfEstimates();
		//double[] testStatistics = reg.testStatistic; 
		//double[] pValues = reg.pValue; 
		
	    double[] coefficients = {RCofficients[0], RCofficients[1]}; 
	  	double[] stdErrors = {RCofficients[2], RCofficients[3]}; 
	  	double[] testStatistics = {RCofficients[3], RCofficients[4]}; 
	  	double[] pValues = {RCofficients[5], RCofficients[6]}; 
	    
		double[] ss = new double[3];
		ss[0] = reg.SSR; ss[1] = reg.SSE; ss[2] = reg.SST;

		double[] degreeFreedoms = reg.degreeFreedom; 
		Map<String, Object> resultMap = new HashMap<String, Object>();
		List<Object> resultDataList = new ArrayList<Object>();
		List<Object> resultDataList2 = new ArrayList<Object>();
		List<Object> resultDataList3 = new ArrayList<Object>();
		
		JSONObject resultData = new JSONObject();
		resultData = new JSONObject();
		//DOGFOOT syjin 회귀분석 통계량 주석처리  20210115
		//resultData.put("Standard Error", String.valueOf(ols.estimateRegressionStandardError()));
		//resultData.put("R Squared", String.valueOf(reg.rSquare));
		//resultData.put("Adjusted R Squared", String.valueOf(regressionResults.getAdjustedRSquared()));
		//resultData.put("F Statistic", String.valueOf(reg.testFStatistic));
		//resultData.put("P Value", String.valueOf(reg.fPValue));
		//resultDataList.add(resultData);
		
		//DOGFOOT syjin 회귀분석 통계량 R로 변환  20210115
		resultData.put("Standard Error", RSigma[0]);
		resultData.put("R Squared", RSquared[0]);
		resultData.put("Adjusted R Squared", RAdjRsquared[0]);
		resultData.put("F Statistic", RFstatistic[0]);
		resultData.put("P Value", RPvalue[0]);
		resultDataList.add(resultData);
		
		for(i=0; i<2; i++) {
			resultData = new JSONObject();
			if(i == 0) {
				resultData.put("Name", "Constant");
			} else {
				resultData.put("Name", meaList.get(i).replace("sum_", ""));
			}
			resultData.put("Value", String.valueOf(coefficients[i]));
			resultData.put("Standard Error", String.valueOf(stdErrors[i]));
			resultData.put("T Statistic", String.valueOf(testStatistics[i]));
			resultData.put("P Value", String.valueOf(pValues[i]));
			if(i == 0) {
				resultData.put("신뢰구간(하한)", String.valueOf(coefficients[i] - (tvalue * stdErrors[i])));
				resultData.put("신뢰구간(상한)", String.valueOf(coefficients[i] + (tvalue * stdErrors[i])));
			} else {
				resultData.put("신뢰구간(하한)", String.valueOf(regression.getSlope() - regression.getSlopeConfidenceInterval()));
				resultData.put("신뢰구간(상한)", String.valueOf(regression.getSlope() + regression.getSlopeConfidenceInterval()));
			}
			
			resultDataList2.add(resultData);
		}
		
		//DOGFOOT syjin 회귀분석결과 주석처리  20210115
//		for(i=0; i<3; i++) {
//			resultData = new JSONObject();
//			if(i == 0) resultData.put("Source Of Variation", "Regression");
//			else resultData.put("Source Of Variation", "");
//			
//			resultData.put("Sum Of Squares", String.valueOf(ss[i]));
//			resultData.put("Degree Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(degreeFreedoms[i]))));
//			resultData.put("Mean Square", String.valueOf(ss[i]/(int)Double.parseDouble(String.valueOf(degreeFreedoms[i]))));
//			if(i == 0) {
//				resultData.put("F Statistics", String.valueOf(reg.testFStatistic));
//				resultData.put("P Value", String.valueOf(reg.fPValue));
//			} else {
//				resultData.put("F Statistics", "");
//				resultData.put("P Value", "");
//			}
//			
//			resultDataList3.add(resultData);
//		}
		
		//DOGFOOT syjin 회귀분석결과 R로 변환  20210115
		for(i=0; i<3; i++) {
			resultData = new JSONObject();
			if(i == 0) resultData.put("Source Of Variation", "Regression");
			else resultData.put("Source Of Variation", "");
			
			if(i<2) {
				resultData.put("Sum Of Squares", String.valueOf(RSumOfSq[i]));
				resultData.put("Degree Of Freedom", String.valueOf(RDf[i]));
				resultData.put("Mean Square", String.valueOf(RMeanSq[i]));
			}else {
				resultData.put("Sum Of Squares", String.valueOf(RSumOfSq[0]+RSumOfSq[1]));
				resultData.put("Degree Of Freedom", String.valueOf(RDf[0]+RDf[1]));
				resultData.put("Mean Square", String.valueOf(RMeanSq[0]+RMeanSq[1]));
			}
			if(i == 0) {
				resultData.put("F Statistics", String.valueOf(RFstatistic[i]));
				resultData.put("P Value", String.valueOf(RPvalue[i]));
			} else {
				resultData.put("F Statistics", "");
				resultData.put("P Value", "");
			}
			
			resultDataList3.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("data2", resultDataList2);
		resultMap.put("data3", resultDataList3);
		resultMap.put("descriptive", descriptiveMap);
		return resultMap;
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=simpleRegression", "analysis=1"})
	public Map<String, Object> simpleRegressionJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
							
		StringBuffer xBf = new StringBuffer();
		
		Gson gson = new Gson();
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());

		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		double[] y = new double[globalDataList.size()];
		double[][] y2 = new double[1][globalDataList.size()];
		double[] x = new double[globalDataList.size()];
		double[][] y3 = new double[globalDataList.size()][1];
		
		int i = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			int j = 0;
			for (String key : entryMap.keySet()) {
				if(j == 0) {
					x[i] = Double.parseDouble(String.valueOf(map.get(key)));
				} else {
					y[i] = Double.parseDouble(String.valueOf(map.get(key)));
					y2[0][i] = Double.parseDouble(String.valueOf(map.get(key)));
					y3[i][0] = Double.parseDouble(String.valueOf(map.get(key)));;
					j = 0;
				}
				j++;
			}
			i++;
		}
	
		// DOGFOOT ktkang 기술통계 구하는 부분  20201028 
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210126 */
				String str = String.valueOf(meaMap.get(meaList.get(k))[j]);
				Double db = Double.parseDouble(str);
				
				summary.addValue(db);
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		/* DOGFOOT syjin 회귀분석_단순 JAVA 불러오기 수정 20210219 */
		double aLevel = Double.parseDouble(String.valueOf(staticOptions.get("alphaLevel"))) * 0.01;
		
		LinearRegression reg = new LinearRegression(aLevel, x, y2);
		SimpleRegression regression = getSimpleRegression(x, y);
		RegressionResults regressionResults = regression.regress();
		
		final OLSMultipleLinearRegression ols = new OLSMultipleLinearRegression();
	    ols.newSampleData(x, y3); // provide the data to the model
		
	    TDistribution distribution = new TDistribution(regression.getN() - 2);
	    double tvalue = distribution.inverseCumulativeProbability(1d - aLevel / 2d);
	    
	    /* DOGFOOT syjin 단순선형 분산분석 R로 변환 20210126 */
		double[] coefficients = reg.coefficients; 
		double[] stdErrors = regressionResults.getStdErrorOfEstimates();
		double[] testStatistics = reg.testStatistic; 
		double[] pValues = reg.pValue; 
	    
		double[] ss = new double[3];
		ss[0] = reg.SSR; ss[1] = reg.SSE; ss[2] = reg.SST;

		double[] degreeFreedoms = reg.degreeFreedom; 
		Map<String, Object> resultMap = new HashMap<String, Object>();
		List<Object> resultDataList = new ArrayList<Object>();
		List<Object> resultDataList2 = new ArrayList<Object>();
		List<Object> resultDataList3 = new ArrayList<Object>();
		
		JSONObject resultData = new JSONObject();
		resultData = new JSONObject();

		resultData.put("Standard Error", String.valueOf(ols.estimateRegressionStandardError()));
		resultData.put("R Squared", String.valueOf(reg.rSquare));
		resultData.put("Adjusted R Squared", String.valueOf(regressionResults.getAdjustedRSquared()));
		resultData.put("F Statistic", String.valueOf(reg.testFStatistic));
		resultData.put("P Value", String.valueOf(reg.fPValue));
		resultDataList.add(resultData);
				
		for(i=0; i<2; i++) {
			resultData = new JSONObject();
			if(i == 0) {
				resultData.put("Name", "Constant");
			} else {
				resultData.put("Name", meaList.get(i).replace("sum_", ""));
			}
			resultData.put("Value", String.valueOf(coefficients[i]));
			resultData.put("Standard Error", String.valueOf(stdErrors[i]));
			resultData.put("T Statistic", String.valueOf(testStatistics[i]));
			resultData.put("P Value", String.valueOf(pValues[i]));
			if(i == 0) {
				resultData.put("신뢰구간(하한)", String.valueOf(coefficients[i] - (tvalue * stdErrors[i])));
				resultData.put("신뢰구간(상한)", String.valueOf(coefficients[i] + (tvalue * stdErrors[i])));
			} else {
				resultData.put("신뢰구간(하한)", String.valueOf(regression.getSlope() - regression.getSlopeConfidenceInterval()));
				resultData.put("신뢰구간(상한)", String.valueOf(regression.getSlope() + regression.getSlopeConfidenceInterval()));
			}
			
			resultDataList2.add(resultData);
		}
		
		//DOGFOOT syjin 회귀분석결과 주석처리  20210115
		for(i=0; i<3; i++) {
			resultData = new JSONObject();
			if(i == 0) resultData.put("Source Of Variation", "Regression");
			else resultData.put("Source Of Variation", "");
			
			resultData.put("Sum Of Squares", String.valueOf(ss[i]));
			resultData.put("Degree Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(degreeFreedoms[i]))));
			resultData.put("Mean Square", String.valueOf(ss[i]/(int)Double.parseDouble(String.valueOf(degreeFreedoms[i]))));
			if(i == 0) {
				resultData.put("F Statistics", String.valueOf(reg.testFStatistic));
				resultData.put("P Value", String.valueOf(reg.fPValue));
			} else {
				resultData.put("F Statistics", "");
				resultData.put("P Value", "");
			}
			
			resultDataList3.add(resultData);
		}
		
		
		resultMap.put("data", resultDataList);
		resultMap.put("data2", resultDataList2);
		resultMap.put("data3", resultDataList3);
		resultMap.put("descriptive", descriptiveMap);
		return resultMap;
	}
	
	/**
	 * 회귀분석(다중)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=multipleRegression", "analysis=0"})
	public Map<String, Object> multipleRegression(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		int resultCode = 0;
		String errorMsg = "";
		
		Gson gson = new Gson();
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList2 = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		//DOGFOOT syjin R코드 추가  20210119
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
				
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		LinkedHashMap<String, Object> entryMap2 = globalDataList2.get(0);
		double[] y = new double[globalDataList.size()];
		double[][] x = new double[globalDataList.size()][entryMap.size()-1];
		double[][] x2 = new double[entryMap.size()-1][globalDataList.size()];
				
		int i = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			for (String key : entryMap.keySet()) {
				y[i] = Double.parseDouble(String.valueOf(map.get(key)));
				
				if(i == globalDataList.size()-1) entryMap.remove(key);
				break;
			}
			i++;
		}
		
		int j = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			int k = 0;
			for(String key : entryMap.keySet()) {
				x[j][k] = Double.parseDouble(String.valueOf(map.get(key)));
				x2[k][j] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			j++;
		}
				
		StringBuffer xBf = new StringBuffer();
		
		for(i=0; i<x[0].length; i++) {
			if(i < 1) {
				xBf.append("x".concat(String.valueOf(i)));
			}else {
				xBf.append("+x".concat(String.valueOf(i)));
			}
			
			double[] d = new double[x.length];
			for(j=0; j<x.length; j++) {
				d[j] = x[j][i];
			}
			code.addDoubleArray("x" + i,d);
		}
		
		code.addDoubleArray("y", y);
			
		//code.addRCode("m <- lm(y~x0+x1)");
		code.addRCode("m <- lm(y~"+xBf+")");
		code.addRCode("result <- summary(m)");							
		code.addRCode("an <- anova(m)");
		
		code.addRCode("Regressionp <- function (modelobject) {");
		code.addRCode("if (class(modelobject) != \"lm\") stop(\"Not an object of class 'lm' \")");
		code.addRCode("f <- summary(modelobject)$fstatistic");
		code.addRCode("p <- pf(f[1],f[2],f[3],lower.tail=F)");
		code.addRCode("attributes(p) <- NULL");
		code.addRCode("return(p)}");
		
		code.addRCode("pValue <- Regressionp(m)");	
		
		code.addRCode("all <- c(result, pValue, an)");
		
		caller.setRCode(code);

		caller.runAndReturnResult("all");
		
		System.out.println("바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값");
		System.out.println("바인딩된 값 : " + caller.getParser().getXMLFileAsString());
		System.out.println("Available results from lm() object : ");
		System.out.println(caller.getParser().getNames());
		
		//Standard Error
		double[] RSigma = caller.getParser().getAsDoubleArray("sigma");
		//R Squared
		double[] RSquared = caller.getParser().getAsDoubleArray("r_squared");
		//Adjusted R Squared
		double[] RAdjRsquared = caller.getParser().getAsDoubleArray("adj_r_squared");
		//F Statistic
		double[] RFstatistic = caller.getParser().getAsDoubleArray("fstatistic");
		//P Value
		double[] RPvalue = caller.getParser().getAsDoubleArray("obj");
		//Sum of Squares
		double[] RSumOfSq = caller.getParser().getAsDoubleArray("SumSq");
		//Degree Of Freedom
		int[] RDf = caller.getParser().getAsIntArray("Df");	
		//Mean Square
		double[] RMeanSq = caller.getParser().getAsDoubleArray("MeanSq");
		//Cofficients
		double[] RCofficients = caller.getParser().getAsDoubleArray("coefficients");		
		
		format.setGroupingUsed(false);
		//DOGFOOT ktkang 기술통계 구하는 부분  20201028 
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap2.keySet()) {
			Object[] measureArr = new Object[globalDataList2.size()];
			for(int o = 0; o < globalDataList2.size(); o++) {
				measureArr[o] = globalDataList2.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int p = 0; p < meaMap.get(meaList.get(k)).length; p++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210126 */
				String str = String.valueOf(meaMap.get(meaList.get(k))[p]);
				Double db = Double.parseDouble(str);
				
				summary.addValue(db);
				
				//summary.addValue((double) meaMap.get(meaList.get(k))[p]);
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<String, Object>();
		List<Object> resultDataList = new ArrayList<Object>();
		List<Object> resultDataList2 = new ArrayList<Object>();
		List<Object> resultDataList3 = new ArrayList<Object>();
		
		LinearRegression reg = new LinearRegression();
		/* DOGFOOT syjin 회귀분석_다중 R 불러오기 수정 20210219 */
		double aLevel = Double.parseDouble(String.valueOf(staticOptions.get("alphaLevel"))) * 0.01;
		try {
			reg = new LinearRegression(aLevel, y, x2);
			
			OLSMultipleLinearRegression regression = getOLSMultipleRegression(x, y);
			
			/* DOGFOOT syjin 다중선형 분산분석 R로 변환 20210126 */
			//double[] coefficients = reg.coefficients; 
			//double[] stdErrors = regression.estimateRegressionParametersStandardErrors();
			//double[] testStatistics = reg.testStatistic; 
			//double[] pValues = reg.pValue; 
			//double[][] confidenceIntervals = reg.confidenceInterval;
			
			double[] coefficients = {RCofficients[0], RCofficients[1], RCofficients[2]}; 
			double[] stdErrors = {RCofficients[3], RCofficients[4], RCofficients[5]};
			double[] testStatistics = {RCofficients[6], RCofficients[7], RCofficients[8]};
			double[] pValues = {RCofficients[9], RCofficients[10], RCofficients[11]};
			double[][] confidenceIntervals = reg.confidenceInterval;
			
			double[] ss = new double[3];
			ss[0] = reg.SSR; ss[1] = reg.SSE; ss[2] = reg.SST;
			
			double[] degreeFreedoms = reg.degreeFreedom; 
			
			TDistribution distribution = new TDistribution(y.length - meaList.size() - 1);
		    double tvalue = distribution.inverseCumulativeProbability(1d - aLevel / 2d);
			
			JSONObject resultData = new JSONObject();
			
			resultData = new JSONObject();
			//DOGFOOT syjin 회귀분석 다중선형 통계량 주석처리  20210120
			//resultData.put("Standard Error", String.valueOf(regression.estimateRegressionStandardError()));
			//resultData.put("R Squared", String.valueOf(reg.rSquare));
			//resultData.put("Adjusted R Squared", String.valueOf(regression.calculateAdjustedRSquared()));
			//resultData.put("F Statistic", String.valueOf(reg.testFStatistic));
			//resultData.put("P Value", String.valueOf(reg.fPValue));
			//resultDataList.add(resultData);
			
			//DOGFOOT syjin 회귀분석 다중선형 통계량 R로 변환  20210120
			resultData.put("Standard Error", RSigma[0]);
			resultData.put("R Squared", RSquared[0]);
			resultData.put("Adjusted R Squared", RAdjRsquared[0]);
			resultData.put("F Statistic", RFstatistic[0]);
			resultData.put("P Value", RPvalue[0]);
			resultDataList.add(resultData);
			
			for(i=0; i<coefficients.length; i++) {
				resultData = new JSONObject();
				if(i == 0) {
					resultData.put("Name", "Constant");
				} else {
					resultData.put("Name", meaList.get(i).replace("sum_", ""));
				}
				resultData.put("Value", String.valueOf(coefficients[i]));
				resultData.put("Standard Error", String.valueOf(stdErrors[i]));
				resultData.put("T Statistic", String.valueOf(testStatistics[i]));
				resultData.put("P Value", String.valueOf(pValues[i]));
				for(j=0; j<2; j++) {
					if(j == 0) {
						resultData.put("신뢰구간(하한)", String.valueOf(coefficients[i] - (tvalue * stdErrors[i])));
					} else {
						resultData.put("신뢰구간(상한)", String.valueOf(coefficients[i] + (tvalue * stdErrors[i])));
					}
				}
				
				resultDataList2.add(resultData);
			}
			
			//DOGFOOT syjin 회귀분석결과 다중선형 주석처리  20210120
			for(i=0; i<3; i++) {
				resultData = new JSONObject();
				if(i == 0) resultData.put("Source Of Variation", "Regression");
				else resultData.put("Source Of Variation", "");
				
				resultData.put("Sum Of Squares", String.valueOf(ss[i]));
				resultData.put("Degree Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(degreeFreedoms[i]))));
				resultData.put("Mean Square", String.valueOf(ss[i]/(int)Double.parseDouble(String.valueOf(degreeFreedoms[i]))));
				if(i == 0) {
					resultData.put("F Statistics", String.valueOf(reg.testFStatistic));
					resultData.put("P Value", String.valueOf(reg.fPValue));
				} else {
					resultData.put("F Statistics", "");
					resultData.put("P Value", "");
				}
				
				resultDataList3.add(resultData);
			}
			
			//DOGFOOT syjin 회귀분석결과 다중선형 R로 변환  20210120
//			for(i=0; i<3; i++) {
//				resultData = new JSONObject();
//				if(i == 0) resultData.put("Source Of Variation", "Regression");
//				else resultData.put("Source Of Variation", "");
//				
//				if(i<2) {
//					resultData.put("Sum Of Squares", String.valueOf(RSumOfSq[i]));
//					resultData.put("Degree Of Freedom", String.valueOf(RDf[i]));
//					resultData.put("Mean Square", String.valueOf(RMeanSq[i]));
//				}else {
//					resultData.put("Sum Of Squares", String.valueOf(RSumOfSq[0]+RSumOfSq[1]));
//					resultData.put("Degree Of Freedom", String.valueOf(RDf[0]+RDf[1]));
//					resultData.put("Mean Square", String.valueOf(RMeanSq[0]+RMeanSq[1]));
//				}
//				if(i == 0) {
//					resultData.put("F Statistics", String.valueOf(RFstatistic[i]));
//					resultData.put("P Value", String.valueOf(RPvalue[i]));
//				} else {
//					resultData.put("F Statistics", "");
//					resultData.put("P Value", "");
//				}
//				
//				resultDataList3.add(resultData);
//			}
		} catch (JSci.maths.statistics.OutOfRangeException e) {
			resultCode = -1;
			e.printStackTrace();
		} catch (Exception e) {
			resultCode = 99;
			e.printStackTrace();
		}
		
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		resultMap.put("data", resultDataList);
		resultMap.put("data2", resultDataList2);
		resultMap.put("data3", resultDataList3);
		resultMap.put("descriptive", descriptiveMap);
		return resultMap;
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=multipleRegression", "analysis=1"})
	public Map<String, Object> multipleRegressionJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		int resultCode = 0;
		String errorMsg = "";
		
		Gson gson = new Gson();
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList2 = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
				
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		LinkedHashMap<String, Object> entryMap2 = globalDataList2.get(0);
		double[] y = new double[globalDataList.size()];
		double[][] x = new double[globalDataList.size()][entryMap.size()-1];
		double[][] x2 = new double[entryMap.size()-1][globalDataList.size()];
				
		int i = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			for (String key : entryMap.keySet()) {
				y[i] = Double.parseDouble(String.valueOf(map.get(key)));
				
				if(i == globalDataList.size()-1) entryMap.remove(key);
				break;
			}
			i++;
		}
		
		int j = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			int k = 0;
			for(String key : entryMap.keySet()) {
				x[j][k] = Double.parseDouble(String.valueOf(map.get(key)));
				x2[k][j] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			j++;
		}
				
		StringBuffer xBf = new StringBuffer();
		
		for(i=0; i<x[0].length; i++) {
			if(i < 1) {
				xBf.append("x".concat(String.valueOf(i)));
			}else {
				xBf.append("+x".concat(String.valueOf(i)));
			}
			
			double[] d = new double[x.length];
			for(j=0; j<x.length; j++) {
				d[j] = x[j][i];
			}			
		}
											
		format.setGroupingUsed(false);
		//DOGFOOT ktkang 기술통계 구하는 부분  20201028 
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap2.keySet()) {
			Object[] measureArr = new Object[globalDataList2.size()];
			for(int o = 0; o < globalDataList2.size(); o++) {
				measureArr[o] = globalDataList2.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int p = 0; p < meaMap.get(meaList.get(k)).length; p++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210126 */
				String str = String.valueOf(meaMap.get(meaList.get(k))[p]);
				Double db = Double.parseDouble(str);
				
				summary.addValue(db);
				
				//summary.addValue((double) meaMap.get(meaList.get(k))[p]);
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<String, Object>();
		List<Object> resultDataList = new ArrayList<Object>();
		List<Object> resultDataList2 = new ArrayList<Object>();
		List<Object> resultDataList3 = new ArrayList<Object>();
		
		LinearRegression reg = new LinearRegression();
		
		/* DOGFOOT syjin 회귀분석_다중 JAVA 불러오기 수정 20210219 */
		double aLevel = Double.parseDouble(String.valueOf(staticOptions.get("alphaLevel"))) * 0.01;
		
		try {
			reg = new LinearRegression(aLevel, y, x2);
			
			OLSMultipleLinearRegression regression = getOLSMultipleRegression(x, y);
			
			/* DOGFOOT syjin 다중선형 분산분석 R로 변환 20210126 */
			double[] coefficients = reg.coefficients; 
			double[] stdErrors = regression.estimateRegressionParametersStandardErrors();
			double[] testStatistics = reg.testStatistic; 
			double[] pValues = reg.pValue; 
			double[][] confidenceIntervals = reg.confidenceInterval;
					
			double[] ss = new double[3];
			ss[0] = reg.SSR; ss[1] = reg.SSE; ss[2] = reg.SST;
			
			double[] degreeFreedoms = reg.degreeFreedom; 
			
			TDistribution distribution = new TDistribution(y.length - meaList.size() - 1);
		    double tvalue = distribution.inverseCumulativeProbability(1d - aLevel / 2d);
			
			JSONObject resultData = new JSONObject();
			
			resultData = new JSONObject();

			resultData.put("Standard Error", String.valueOf(regression.estimateRegressionStandardError()));
			resultData.put("R Squared", String.valueOf(reg.rSquare));
			resultData.put("Adjusted R Squared", String.valueOf(regression.calculateAdjustedRSquared()));
			resultData.put("F Statistic", String.valueOf(reg.testFStatistic));
			resultData.put("P Value", String.valueOf(reg.fPValue));
			resultDataList.add(resultData);
						
			for(i=0; i<coefficients.length; i++) {
				resultData = new JSONObject();
				if(i == 0) {
					resultData.put("Name", "Constant");
				} else {
					resultData.put("Name", meaList.get(i).replace("sum_", ""));
				}
				resultData.put("Value", String.valueOf(coefficients[i]));
				resultData.put("Standard Error", String.valueOf(stdErrors[i]));
				resultData.put("T Statistic", String.valueOf(testStatistics[i]));
				resultData.put("P Value", String.valueOf(pValues[i]));
				for(j=0; j<2; j++) {
					if(j == 0) {
						resultData.put("신뢰구간(하한)", String.valueOf(coefficients[i] - (tvalue * stdErrors[i])));
					} else {
						resultData.put("신뢰구간(상한)", String.valueOf(coefficients[i] + (tvalue * stdErrors[i])));
					}
				}
				
				resultDataList2.add(resultData);
			}
			
			//DOGFOOT syjin 회귀분석결과 다중선형 주석처리  20210120
			for(i=0; i<3; i++) {
				resultData = new JSONObject();
				if(i == 0) resultData.put("Source Of Variation", "Regression");
				else resultData.put("Source Of Variation", "");
				
				resultData.put("Sum Of Squares", String.valueOf(ss[i]));
				resultData.put("Degree Of Freedom", String.valueOf((int)Double.parseDouble(String.valueOf(degreeFreedoms[i]))));
				resultData.put("Mean Square", String.valueOf(ss[i]/(int)Double.parseDouble(String.valueOf(degreeFreedoms[i]))));
				if(i == 0) {
					resultData.put("F Statistics", String.valueOf(reg.testFStatistic));
					resultData.put("P Value", String.valueOf(reg.fPValue));
				} else {
					resultData.put("F Statistics", "");
					resultData.put("P Value", "");
				}
				
				resultDataList3.add(resultData);
			}			
		} catch (JSci.maths.statistics.OutOfRangeException e) {
			resultCode = -1;
			e.printStackTrace();
		} catch (Exception e) {
			resultCode = 99;
			e.printStackTrace();
		}
		
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		resultMap.put("data", resultDataList);
		resultMap.put("data2", resultDataList2);
		resultMap.put("data3", resultDataList3);
		resultMap.put("descriptive", descriptiveMap);
		return resultMap;
	}
	
	/**
	 * 회귀분석(로지스틱)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=logisticRegression", "analysis=0"})
	public Map<String, Object> logisticRegression(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList2 = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measuresList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		//DOGFOOT syjin R코드 추가  20210119
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
				
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		LinkedHashMap<String, Object> entryMap2 =  globalDataList.get(1);
		int[] y = new int[globalDataList.size()];
		String[] y2 = new String[globalDataList.size()];
		double[][] x = new double[globalDataList.size()][entryMap.size()-1];
		double[][] x2 = new double[entryMap.size()-1][globalDataList.size()];
		
		int i = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			for (String key : entryMap.keySet()) {
				y[i] = (int)Double.parseDouble(String.valueOf(map.get(key)));
				y2[i] = String.valueOf((int)Double.parseDouble(String.valueOf(map.get(key))));
				
				if(i == globalDataList.size()-1) entryMap.remove(key);
				break;
			}
			i++;
		}
		
		int j = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			int k = 0;
			for(String key : entryMap.keySet()) {
				x[j][k] = Double.parseDouble(String.valueOf(map.get(key)));
				x2[k][j] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			j++;
		}
		
		StringBuffer xBf = new StringBuffer();
		
		for(i=0; i<x[0].length; i++) {
			if(i < 1) {
				xBf.append("x".concat(String.valueOf(i)));
			}else {
				xBf.append("+x".concat(String.valueOf(i)));
			}
			
			double[] d = new double[x.length];
			for(j=0; j<x.length; j++) {
				d[j] = x[j][i];
			}
			code.addDoubleArray("x" + i,d);
		}
		
		code.addIntArray("y", y);

		code.addInt("length", x[0].length+2);
		
		code.addRCode("m <- glm(y~"+xBf+", family = \"binomial\")");
		code.addRCode("result <- summary(m)");	
		//code.addRCode("coefi <- result$coefficients");
		//code.addRCode("value <- result$coefficients");
		
//		code.addRCode("for(i in c(2:length)){");
//		code.addRCode("for(j in c(1:4)){");
//		code.addRCode("switch(j,");   
//		code.addRCode("'1' =");
//		code.addRCode("if(i == 2){");
//		code.addRCode("value <- c();");
//		code.addRCode("value <- c(value, result$coefficients[i,j]);");
//		code.addRCode("}else{");
//		code.addRCode("value <- c(value, result$coefficients[i,j]);");
//		code.addRCode("},");
//		code.addRCode("'2' =");
//		code.addRCode("if(i == 2){");
//		code.addRCode("standardError <- c();");
//		code.addRCode("standardError <- c(standardError, result$coefficients[i,j]);");
//		code.addRCode("}else{");
//		code.addRCode("standardError <- c(standardError, result$coefficients[i,j])");
//		code.addRCode("},");
//		code.addRCode("'3' =");
//		code.addRCode("if(i == 2){");
//		code.addRCode("tStatic <- c();");
//		code.addRCode("tStatic <- c(tStatic, result$coefficients[i,j]);");
//		code.addRCode("}else{");
//		code.addRCode("tStatic <- c(tStatic, result$coefficients[i,j])");
//		code.addRCode("},");
//		code.addRCode("'4' =");
//		code.addRCode("if(i == 2){");
//		code.addRCode("pValue <- c();");
//		code.addRCode("pValue <- c(pValue, result$coefficients[i,j]);");
//		code.addRCode("}else{");
//		code.addRCode("pValue <- c(pValue, result$coefficients[i,j])");
//		code.addRCode("}");
//		code.addRCode(")");
//		code.addRCode("}");
//		code.addRCode("}");
		//code.addRCode("for(i in c(2:length)){ for(j in c(1:4)){ switch(j, '1' = if(i == 2){ value <- c(); value <- c(value, result$coefficients[i,j]); }else{ value <- c(value, result$coefficients[i,j]); }, '2' = if(i == 2){ standardError <- c(); standardError <- c(standardError, result$coefficients[i,j]); }else{ standardError <- c(standardError, result$coefficients[i,j]) }, '3' = if(i == 2){ tStatic <- c(); tStatic <- c(tStatic, result$coefficients[i,j]); }else{ tStatic <- c(tStatic, result$coefficients[i,j]) }, '4' = if(i == 2){ pValue <- c(); pValue <- c(pValue, result$coefficients[i,j]); }else{ pValue <- c(pValue, result$coefficients[i,j]) } ) } }");
		
		code.addRCode("logL <- logLik(m)");					//logL
		code.addRCode("ano <- anova(m, test=\"Chisq\")");
			
		code.addRCode("pValue <- m$coefficients[2]");	
		
		code.addRCode("if(!c(\"lmtest\") %in% installed.packages()[,\"Package\"]){");	//패키지 설치 여부 확인
		code.addRCode("install.packages(\"lmtest\", repos=\"http://cran.us.r-project.org\");}");	//chis 구하기 위한 lmtest 패키지 설치
		code.addRCode("library(lmtest)");					//lmtest 라이브러리 로드
		code.addRCode("chis <- lrtest(m)");					//lmtest 라이브러리 안에 lrtest 함수 호출
		
		code.addRCode("exp <- exp(result$coefficients)");
//		code.addRCode("all <- c(result, logL, ano, chis, pValue, exp, value, standardError, tStatic, pValue1)");
		code.addRCode("all <- c(result, logL, ano, chis, exp, length)");
		caller.setRCode(code);

		caller.runAndReturnResult("all");
		
		System.out.println("바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값 바인딩된 값");
		System.out.println("바인딩된 값 : " + caller.getParser().getXMLFileAsString());
		System.out.println("Available results from lm() object : ");
		System.out.println(caller.getParser().getNames());
		
		//Log-likelihood
		double[] RLogLike = caller.getParser().getAsDoubleArray("obj");
		//Chi-Squared
		String[] RChis = caller.getParser().getAsStringArray("Chisq");
		//P Value
		String[] RPvalue = caller.getParser().getAsStringArray("PrChisq");
		//로지스틱 회귀 계수
		double[] RCoeffi = caller.getParser().getAsDoubleArray("coefficients");
		//Exp(B)
		
		System.out.println("RLogLike");
		for(double k : RLogLike) {
			System.out.print(k + ",");
		}
		System.out.println("RChis");
		for(String k : RChis) {
			System.out.print(k + ",");
		}
		System.out.println("RPvalue");
		for(String k : RPvalue) {
			System.out.print(k + ",");
		}
		System.out.println("RCoeffi");
		for(double k : RCoeffi) {
			System.out.print(k + ",");
		}
		
		format.setGroupingUsed(false);
		/* DOGFOOT ktkang 기술통계 구하는 부분 수정  20201104 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (LinkedHashMap<String, Object> key : measuresList) {
			Object[] measureArr = new Object[globalDataList2.size()];
			for(int o = 0; o < globalDataList2.size(); o++) {
				measureArr[o] = globalDataList2.get(o).get(key.get("nameBySummaryType"));
			}
			meaList.add((String) key.get("nameBySummaryType"));
			meaMap.put((String) key.get("nameBySummaryType"), measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				String str = String.valueOf(meaMap.get(meaList.get(k))[j]);
				Double db = Double.parseDouble(str);
				
				summary.addValue(db);
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}

		
		Map<String, Object> resultMap = new HashMap<String, Object>();
		//LogisticRegression logit = new LogisticRegression(x, y);
		getLogisticRegression(y2, x2, resultMap);

		double chiSqured = 0.;
		double[][] chiSquered2D = (double[][]) resultMap.get("devianceTable"); 
		for(i = 0; i < chiSquered2D.length; i++) {
			for(j = 0; j < chiSquered2D[i].length; j++) {
				if(j == 1) {
					chiSqured = chiSqured + chiSquered2D[i][j];
				}
			}
		}
		
		ChiSquaredDistribution chisqDist = new ChiSquaredDistribution(chiSquered2D.length-1);
		double prob = chisqDist.cumulativeProbability(chiSqured);
		
		/* DOGFOOT syjin 로지스틱 로지스틱회귀계수 R로 변환 20210126 */
		//double[] valueArr2 = (double[]) resultMap.get("value");
		//double[] standardErrorArr2 = (double[]) resultMap.get("standardError");
		//double[] tStaticArr2 = (double[]) resultMap.get("tStatic");
		//double[] pValueArr2 = (double[]) resultMap.get("pValue");
		
		double[] valueArr = new double[x[0].length+1];
		double[] standardErrorArr = new double[x[0].length+1];
		double[] tStaticArr = new double[x[0].length+1];
		double[] pValueArr = new double[x[0].length+1];
		
		for(int k=0; k<=x[0].length; k++) {
			valueArr[k] = RCoeffi[k];
			standardErrorArr[k] = RCoeffi[k+x[0].length+1];
			tStaticArr[k] = RCoeffi[k+(x[0].length+1)*2];
			pValueArr[k] = RCoeffi[k+(x[0].length+1)*3];
		}
		
		List<Object> resultDataList = new ArrayList<Object>();
		List<Object> resultDataList2 = new ArrayList<Object>();
		/* DOGFOOT ktkang 분석 결과표 값 수정  20201104 */
		
		JSONObject resultData = new JSONObject();
		//DOGFOOT syjin 로지스틱 분석결과표 주석처리  20210120
		//resultData.put("Log-likelihood", String.valueOf(logit.loglikelihood()));
		//resultData.put("Chi-Squared", String.valueOf(chiSqured));
		//resultData.put("P Value", String.valueOf(1-prob));
		
		//DOGFOOT syjin 로지스틱 분석결과표 R로 변환  20210120
		resultData.put("Log-likelihood", String.valueOf(RLogLike[0]));
		resultData.put("Chi-Squared", String.valueOf(RChis[1]));
		resultData.put("P Value", String.valueOf(RPvalue[1]));
		resultDataList.add(resultData);
		
		for(i = 0; i < entryMap2.keySet().size(); i++) {
			resultData = new JSONObject();
			if(i == 0) {
				resultData.put("Name", "Constant");
				resultData.put("Value", String.valueOf(valueArr[i]));
				resultData.put("Standard Error", String.valueOf(standardErrorArr[i]));
				resultData.put("T Static", String.valueOf(tStaticArr[i]));
				resultData.put("P Value", String.valueOf(pValueArr[i]));
				resultData.put("Exp(B)", "");
			} else {
				resultData.put("Name", measuresList.get(i).get("name"));
				resultData.put("Value", String.valueOf(valueArr[i]));
				resultData.put("Standard Error", String.valueOf(standardErrorArr[i]));
				resultData.put("T Static", String.valueOf(tStaticArr[i]));
				resultData.put("P Value", String.valueOf(pValueArr[i]));
				resultData.put("Exp(B)", String.valueOf(Math.exp(valueArr[i])));
			}
			resultDataList2.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("data2", resultDataList2);
		resultMap.put("descriptive", descriptiveMap);
		
		return resultMap;
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=logisticRegression", "analysis=1"})
	public Map<String, Object> logisticRegressionJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList2 = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> measuresList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());

		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		LinkedHashMap<String, Object> entryMap2 =  globalDataList.get(1);
		int[] y = new int[globalDataList.size()];
		String[] y2 = new String[globalDataList.size()];
		double[][] x = new double[globalDataList.size()][entryMap.size()-1];
		double[][] x2 = new double[entryMap.size()-1][globalDataList.size()];
		
		int i = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			for (String key : entryMap.keySet()) {
				y[i] = (int)Double.parseDouble(String.valueOf(map.get(key)));
				y2[i] = String.valueOf((int)Double.parseDouble(String.valueOf(map.get(key))));
				
				if(i == globalDataList.size()-1) entryMap.remove(key);
				break;
			}
			i++;
		}
		
		int j = 0;
		for(LinkedHashMap<String, Object> map : globalDataList) {
			int k = 0;
			for(String key : entryMap.keySet()) {
				x[j][k] = Double.parseDouble(String.valueOf(map.get(key)));
				x2[k][j] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			j++;
		}
		
		format.setGroupingUsed(false);
		/* DOGFOOT ktkang 기술통계 구하는 부분 수정  20201104 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (LinkedHashMap<String, Object> key : measuresList) {
			Object[] measureArr = new Object[globalDataList2.size()];
			for(int o = 0; o < globalDataList2.size(); o++) {
				measureArr[o] = globalDataList2.get(o).get(key.get("nameBySummaryType"));
			}
			meaList.add((String) key.get("nameBySummaryType"));
			meaMap.put((String) key.get("nameBySummaryType"), measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				summary.addValue((double) meaMap.get(meaList.get(k))[j]);
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}

		
		Map<String, Object> resultMap = new HashMap<String, Object>();
		//LogisticRegression logit = LogisticRegression(x, y);
		//2021-03-18 syjin 로지스틱 단순, 다중 smile jar 버전 변경
		LogisticRegression logit = LogisticRegression.fit(x, y);
		getLogisticRegression(y2, x2, resultMap);

		double chiSqured = 0.;
		double[][] chiSquered2D = (double[][]) resultMap.get("devianceTable"); 
		for(i = 0; i < chiSquered2D.length; i++) {
			for(j = 0; j < chiSquered2D[i].length; j++) {
				if(j == 1) {
					chiSqured = chiSqured + chiSquered2D[i][j];
				}
			}
		}
		
		ChiSquaredDistribution chisqDist = new ChiSquaredDistribution(chiSquered2D.length-1);
		double prob = chisqDist.cumulativeProbability(chiSqured);
		
		double[] valueArr = (double[]) resultMap.get("value");
		double[] standardErrorArr = (double[]) resultMap.get("standardError");
		double[] tStaticArr = (double[]) resultMap.get("tStatic");
		double[] pValueArr = (double[]) resultMap.get("pValue");
		
		List<Object> resultDataList = new ArrayList<Object>();
		List<Object> resultDataList2 = new ArrayList<Object>();
		/* DOGFOOT ktkang 분석 결과표 값 수정  20201104 */
		
		JSONObject resultData = new JSONObject();
		resultData.put("Log-likelihood", String.valueOf(logit.loglikelihood()));
		resultData.put("Chi-Squared", String.valueOf(chiSqured));
		resultData.put("P Value", String.valueOf(1-prob));
		resultDataList.add(resultData);
		
		for(i = 0; i < entryMap2.keySet().size(); i++) {
			resultData = new JSONObject();
			if(i == 0) {
				resultData.put("Name", "Constant");
				resultData.put("Value", String.valueOf(valueArr[i]));
				resultData.put("Standard Error", String.valueOf(standardErrorArr[i]));
				resultData.put("T Static", String.valueOf(tStaticArr[i]));
				resultData.put("P Value", String.valueOf(pValueArr[i]));
				resultData.put("Exp(B)", "");
			} else {
				resultData.put("Name", measuresList.get(i).get("name"));
				resultData.put("Value", String.valueOf(valueArr[i]));
				resultData.put("Standard Error", String.valueOf(standardErrorArr[i]));
				resultData.put("T Static", String.valueOf(tStaticArr[i]));
				resultData.put("P Value", String.valueOf(pValueArr[i]));
				resultData.put("Exp(B)", String.valueOf(Math.exp(valueArr[i])));
			}
			resultDataList2.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("data2", resultDataList2);
		resultMap.put("descriptive", descriptiveMap);
		
		return resultMap;
	}
	
	/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
	/**
	 * 가설검정(T-test)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params={"analysisType=tTest", "analysis=0"})
	public Map<String, Object> tTest(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}

		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		double[][] obArray = new double[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			double[] ob = new double[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		String valueList = "";
		for(int k = 0; k < setListArray.length; k++) {
			if(valueList.equals("")) {
				valueList = setListArray[k];
			} else {
				valueList = valueList + "," + setListArray[k];
			}
		}
		
		String paired = "";
		if(staticOptions.has("paired")) {
			paired = staticOptions.getString("paired");
			if(paired.equals("twoSample")) {
				paired = "FALSE";
			} else if(paired.equals("pairedSample")) {
				paired = "TRUE";
			}
		}
		
		String alternative = "";
		if(staticOptions.has("alternative")) {
			alternative = staticOptions.getString("alternative");
			if(alternative.equals("twoSided")) {
				alternative = "two.sided";
			} else if(alternative.equals("lessSided")) {
				alternative = "less";
			} else if(alternative.equals("greaterSided")) {
				alternative = "greater";
			}
		}
		
		String varequal = "";
		if(staticOptions.has("varequal")) {
			varequal = staticOptions.getString("varequal");
			if(varequal.equals("true")) {
				varequal = "TRUE";
			} else if(varequal.equals("false")) {
				varequal = "FALSE";
			}
		}
		
		String alphaLevel = "";
		/* DOGFOOT ktkang T검정 오류 수정  20210216 */
		double alphaLevelF = 0.95;
		if(staticOptions.has("alphaLevel")) {
			alphaLevel = staticOptions.getString("alphaLevel");
			alphaLevelF = 1.0 - (Double.parseDouble(alphaLevel) * 0.01);
		}
		
		if(setListArray.length == 1) {
			String mutest = "";
			if(staticOptions.has("mutest")) {
				mutest = staticOptions.getString("mutest");
			}
			
			code.addDoubleArray("x", obArray[0]);
			code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
			code.addRCode("ols <- t.test(x, alternative = c(\"" + alternative + "\"), mu = " + mutest + ", var.equal = " + varequal + ", conf.level = " + alphaLevelF + ")");
			code.addRCode("conf <- ols$conf.int");
			code.addRCode("result <- c(ols, conf=conf)");
			
			caller.setRCode(code);
			caller.runAndReturnResult("result");
			
			System.out.println(caller.getParser().getXMLFileAsString());
			System.out.println(caller.getParser().getNames());
			
			
			JSONObject resultData = new JSONObject();

			double[] tEstimate = caller.getParser().getAsDoubleArray("estimate");
			String[] conf1 = caller.getParser().getAsStringArray("conf1");
			String[] conf2 = caller.getParser().getAsStringArray("conf2");
			
			resultData.put("변수", valueList);
			resultData.put("T", caller.getParser().getAsDoubleArray("statistic"));
			resultData.put("P-Value", caller.getParser().getAsDoubleArray("p_value"));
			resultData.put("자유도", caller.getParser().getAsDoubleArray("parameter"));
			/* DOGFOOT ktkang T검정 오류  수정  20210216 */
			if(tEstimate.length > 1) {
				resultData.put("평균차", tEstimate[0] - tEstimate[1]);
			} else {
				resultData.put("평균차", tEstimate[0] - Double.parseDouble(mutest));
			}
			
			resultData.put("신뢰구간(하한)", conf1[0]);
			resultData.put("신뢰구간(상한)", conf2[0]);
			resultDataList.add(resultData);
		} else {
			code.addDoubleArray("x", obArray[0]);
			code.addDoubleArray("y", obArray[1]);
			code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
			code.addRCode("ols <- t.test(x, y, alternative = c(\"" + alternative + "\"), paired = " + paired + ", var.equal = " + varequal + ", conf.level = " + alphaLevelF + ")");
			code.addRCode("conf <- ols$conf.int");
			code.addRCode("pears <- cor(x,y, method=\"pearson\")");
			code.addRCode("result <- c(ols, pears=pears, conf=conf)");
			
			caller.setRCode(code);
			caller.runAndReturnResult("result");
			
			System.out.println(caller.getParser().getXMLFileAsString());
			System.out.println(caller.getParser().getNames());
			
			
			JSONObject resultData = new JSONObject();

			double[] tEstimate = caller.getParser().getAsDoubleArray("estimate");
			String[] pearson = caller.getParser().getAsStringArray("pears");
			String[] conf1 = caller.getParser().getAsStringArray("conf1");
			String[] conf2 = caller.getParser().getAsStringArray("conf2");
			
			resultData.put("변수", valueList);
			resultData.put("T", caller.getParser().getAsDoubleArray("statistic"));
			resultData.put("P-Value", caller.getParser().getAsDoubleArray("p_value"));
			resultData.put("자유도", caller.getParser().getAsDoubleArray("parameter"));
			if(tEstimate.length > 1) {
				resultData.put("평균차", tEstimate[0] - tEstimate[1]);
			} else {
				resultData.put("평균차", tEstimate[0]);
			}
			
			//resultData.put("표준오차", caller.getParser().getAsDoubleArray("stderr"));
			//resultData.put("Pearson 상관계수", pearson[0]);
			resultData.put("신뢰구간(하한)", conf1[0]);
			resultData.put("신뢰구간(상한)", conf2[0]);
			resultDataList.add(resultData);
		}
		
		
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params={"analysisType=tTest", "analysis=1"})
	public Map<String, Object> tTestJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
			
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}

		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		double[][] obArray = new double[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			double[] ob = new double[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		String valueList = "";
		for(int k = 0; k < setListArray.length; k++) {
			if(valueList.equals("")) {
				valueList = setListArray[k];
			} else {
				valueList = valueList + "," + setListArray[k];
			}
		}
		
		String paired = "";
		if(staticOptions.has("paired")) {
			paired = staticOptions.getString("paired");
			if(paired.equals("twoSample")) {
				paired = "FALSE";
			} else if(paired.equals("pairedSample")) {
				paired = "TRUE";
			}
		}
		
		String alternative = "";
		if(staticOptions.has("alternative")) {
			alternative = staticOptions.getString("alternative");
			if(alternative.equals("twoSided")) {
				alternative = "two.sided";
			} else if(alternative.equals("lessSided")) {
				alternative = "less";
			} else if(alternative.equals("greaterSided")) {
				alternative = "greater";
			}
		}
		
		String varequal = "";
		if(staticOptions.has("varequal")) {
			varequal = staticOptions.getString("varequal");
			if(varequal.equals("true")) {
				varequal = "TRUE";
			} else if(varequal.equals("false")) {
				varequal = "FALSE";
			}
		}
		
		String alphaLevel = "";
		/* DOGFOOT ktkang T검정 오류 수정  20210216 */
		double alphaLevelF = 0.95;
		if(staticOptions.has("alphaLevel")) {
			alphaLevel = staticOptions.getString("alphaLevel");
			alphaLevelF = 1.0 - (Double.parseDouble(alphaLevel) * 0.01);
		}
		
		if(setListArray.length == 1) {
			String mutest = "";
			if(staticOptions.has("mutest")) {
				mutest = staticOptions.getString("mutest");
			}
			
			DoubleArrayList dataX = new DoubleArrayList(obArray[0]);
			OneSampleTTest one = new OneSampleTTest(dataX, Double.parseDouble(mutest), alphaLevelF, obArray[0], alternative);
					
			DecimalFormat de = new DecimalFormat("##.####");  // DecimalFormat 객체
			
			//two-sided test
			
			//TTest ttest = new TTest();
			//ttest.tTest(Double.parseDouble(mutest), obArray[0], alphaLevelF).;
			
			/*************smile**************/
			double t = TTest.test(obArray[0], Double.parseDouble(mutest)).t;
			//String method = TTest.test(obArray[0], Double.parseDouble(mutest)).method;
			double pValue = TTest.test(obArray[0], Double.parseDouble(mutest)).pvalue;
			double df = TTest.test(obArray[0], Double.parseDouble(mutest)).df;
			
			/////////////////////////////////////
			//code.addDoubleArray("x", obArray[0]);
			//code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
			//code.addRCode("ols <- t.test(x, alternative = c(\"" + alternative + "\"), mu = " + mutest + ", var.equal = " + varequal + ", conf.level = " + alphaLevelF + ")");
			//code.addRCode("conf <- ols$conf.int");
			//code.addRCode("result <- c(ols, conf=conf)");
			
			//caller.setRCode(code);
			//caller.runAndReturnResult("result");
			
			//System.out.println(caller.getParser().getXMLFileAsString());
			//System.out.println(caller.getParser().getNames());
			
			
			JSONObject resultData = new JSONObject();

			//double[] tEstimate = caller.getParser().getAsDoubleArray("estimate");
			//String[] conf1 = caller.getParser().getAsStringArray("conf1");
			//String[] conf2 = caller.getParser().getAsStringArray("conf2");
			
			resultData.put("변수", valueList);
			//resultData.put("T", caller.getParser().getAsDoubleArray("statistic"));
			resultData.put("T", t);
			//resultData.put("P-Value", caller.getParser().getAsDoubleArray("p_value"));
			if(alternative.equals("two.sided")) {
				resultData.put("P-Value", pValue);
			}else if(alternative.equals("less")){
				if(one.gett()>0) {
					resultData.put("P-Value", de.format(1-one.getsig()/2));
				}else {
					resultData.put("P-Value", de.format(one.getsig()/2));
				}
			}else {
				resultData.put("P-Value", de.format(1-one.getsig()/2));
				if(one.gett()>0) {
					resultData.put("P-Value", de.format(one.getsig()/2));
				}else {
					resultData.put("P-Value", de.format(1-one.getsig()/2));
				}
			}
			
			//resultData.put("자유도", caller.getParser().getAsDoubleArray("parameter"));
			resultData.put("자유도", df);
			/* DOGFOOT ktkang T검정 오류  수정  20210216 */
			//if(tEstimate.length > 1) {
				//resultData.put("평균차", tEstimate[0] - tEstimate[1]);
			//} else {
				//resultData.put("평균차", tEstimate[0]);
			//}
			
			resultData.put("평균차", de.format(one.getmd()));
			
			//resultData.put("신뢰구간(하한)", conf1[0]);
			//resultData.put("신뢰구간(상한)", conf2[0]);
			
			if(alternative.equals("two.sided")) {
				resultData.put("신뢰구간(하한)", de.format(one.getLC()));
				resultData.put("신뢰구간(상한)", de.format(one.getUC()));
			}else if(alternative.equals("less")) {
				resultData.put("신뢰구간(하한)", "-Inf");
				resultData.put("신뢰구간(상한)", de.format(one.getUC()));
			}else {
				resultData.put("신뢰구간(하한)", de.format(one.getLC()));
				resultData.put("신뢰구간(상한)", "Inf");
			}
			
			resultDataList.add(resultData);
		} else {
			JSONObject resultData = new JSONObject();
			
			if(paired.equals("FALSE")) {//독립
				DoubleArrayList dataX = new DoubleArrayList(obArray[0]);
				DoubleArrayList dataY = new DoubleArrayList(obArray[1]);
				IndependentTwoSampleTTest des = new IndependentTwoSampleTTest(dataX, dataY, alphaLevelF, alternative);
				
				DecimalFormat de = new DecimalFormat("##.####");  // DecimalFormat 객체
						
				resultData.put("변수", valueList);
				
				if(varequal.equals("TRUE")) {//분산이 같다고
					resultData.put("T", de.format(des.gett()));
					if(alternative.equals("two.sided")) {
						resultData.put("P-Value", de.format(des.getsig()));
					}else if(alternative.equals("less")){
						resultData.put("P-Value", de.format(des.getsig()/2));
					}else {
						resultData.put("P-Value", de.format(1-des.getsig()/2));
					}
					resultData.put("자유도", de.format(des.getdf()));
					resultData.put("평균차", de.format(des.getmd()));
					//resultData.put("표준오차", de.format(des.getdse()));
					//resultData.put("Pearson 상관계수", pearson[0]);
					if(alternative.equals("two.sided")) {
						resultData.put("신뢰구간(하한)", des.getLC());
						resultData.put("신뢰구간(상한)", des.getUC());
					}else if(alternative.equals("less")){
						resultData.put("신뢰구간(하한)", "-Inf");
						resultData.put("신뢰구간(상한)", de.format(des.getUC()));
					}else {
						resultData.put("신뢰구간(하한)", des.getLC());
						resultData.put("신뢰구간(상한)", "Inf");
					}			
				}else {
					resultData.put("T", de.format(des.getnt()));
					if(alternative.equals("two.sided")) {
						resultData.put("P-Value", de.format(des.getnsig()));
					}else if(alternative.equals("less")){
						if(des.getnt()>0) {
							resultData.put("P-Value", de.format(1-des.getsig()/2));
						}else {
							resultData.put("P-Value", de.format(des.getsig()/2));
						}
					}else {
						resultData.put("P-Value", de.format(1-des.getsig()/2));
						if(des.getnt()>0) {
							resultData.put("P-Value", de.format(des.getsig()/2));
						}else {
							resultData.put("P-Value", de.format(1-des.getsig()/2));
						}
					}
					resultData.put("자유도", de.format(des.getndf()));
					resultData.put("평균차", de.format(des.getmd()));
					//resultData.put("표준오차", de.format(des.getndse()));
					//resultData.put("Pearson 상관계수", pearson[0]);
					if(alternative.equals("two.sided")) {
						resultData.put("신뢰구간(하한)", des.getnLC());
						resultData.put("신뢰구간(상한)", des.getnUC());
					}else if(alternative.equals("less")){
						resultData.put("신뢰구간(하한)", "-Inf");
						resultData.put("신뢰구간(상한)", de.format(des.getnUC()));
					}else {
						resultData.put("신뢰구간(하한)", des.getnLC());
						resultData.put("신뢰구간(상한)", "Inf");
					}			
				}
				
				/**
			       * 이표본 t-검정 결과 출력
			       * DecimalFormat 클래스를 이용하여 소수 넷째짜리까지 출력 
			       */
			      //DecimalFormat de = new DecimalFormat("##.####");  // DecimalFormat 객체
//			      System.out.println("⊙   집단 통계량(집단1, 집단2)");
//			      System.out.println("     N : "+de.format(des.getN1())+",  "
//			                  +de.format(des.getN2()));
//			      System.out.println("평      균 : "+de.format(des.getMean1())+",  "
//			                  +de.format(des.getMean2()));
//			      System.out.println("표준편차 : "+de.format(des.getSd1())+",  " 
//			                  +de.format(des.getSd2()));
//			      System.out.println("표준오차 : "+de.format(des.getSe1())+",  " 
//			                  +de.format(des.getSe2()));
//			      System.out.println("\n\n⊙   독립표본 검정"); 
//			      System.out.println("\n▶ Levene의 등분산 검정");  
//			      System.out.println("F : "+de.format(des.getF()));
//			      System.out.println("유의확률 : "+de.format(des.getsigF()));  
//			      System.out.println("\n▶ 평균의 동질성에 대한 t-검정(등분산이 가정됨)");       
//			      System.out.println("t : "+de.format(des.gett()));
//			      System.out.println("자유도 : "+de.format(des.getdf()));
//			      System.out.println("유의확률 : "+de.format(des.getsig()));
//			      System.out.println("평균차 : "+de.format(des.getmd()));
//			      System.out.println("차이의 표준오차 : "+de.format(des.getdse()));
//			      System.out.println("신뢰구간 하한 : "+de.format(des.getLC()));
//			      System.out.println("신뢰구간 상한 : "+de.format(des.getUC()));  
//			      System.out.println("\n▶ 평균의 동질성에 대한 t-검정(등분산이 가정되지 않음)");
//			      System.out.println("t : "+de.format(des.getnt()));
//			      System.out.println("자유도  : "+de.format(des.getndf()));
//			      System.out.println("유의확률 : "+de.format(des.getnsig()));
//			      System.out.println("평균차 : "+de.format(des.getmd()));
//			      System.out.println("차이의 표준오차 : "+de.format(des.getndse()));
//			      System.out.println("신뢰구간 하한 : "+de.format(des.getnLC()));
//			      System.out.println("신뢰구간 상한 : "+de.format(des.getnUC()));
			      
			}else {//대응표본
				String mutest = "";
				if(staticOptions.has("mutest")) {
					mutest = staticOptions.getString("mutest");
				}
				
				double[] a = obArray[0];  
		        DoubleArrayList data_a = new DoubleArrayList(a);
		 
		        double[] b = obArray[1];  
		        DoubleArrayList data_b = new DoubleArrayList(b);
		  
		        DoubleArrayList data = new DoubleArrayList(); //신문-TV
		        
		        double[] ab = new double[a.length];
		        
		        for(int i =0;i<a.length;i++){
		        	data.add(a[i]-b[i]);    
		        	ab[i] = a[i]-b[i];
		        }
		           			
				OneSampleTTest one = new OneSampleTTest(data, Double.parseDouble(mutest), alphaLevelF, ab, alternative);
				Descex aa = new Descex(data_a);
				Descex bb = new Descex(data_b);
				
				DecimalFormat de = new DecimalFormat("##.####");  // DecimalFormat 객체
				
				resultData.put("변수", valueList);
				
				resultData.put("T", de.format(one.gett()));
				if(alternative.equals("two.sided")) {
					resultData.put("P-Value", de.format(one.getsig()));
				}else if(alternative.equals("less")){
					if(one.gett()>0) {
						resultData.put("P-Value", de.format(1-one.getsig()/2));
					}else {
						resultData.put("P-Value", de.format(one.getsig()/2));
					}
				}else {
					resultData.put("P-Value", de.format(1-one.getsig()/2));
					if(one.gett()>0) {
						resultData.put("P-Value", de.format(one.getsig()/2));
					}else {
						resultData.put("P-Value", de.format(1-one.getsig()/2));
					}
				}
				resultData.put("자유도", de.format(one.getdf()));
				resultData.put("평균차", de.format(one.getmd()));
				//resultData.put("표준오차", de.format(des.getdse()));
				if(alternative.equals("two.sided")) {
					resultData.put("신뢰구간(하한)", de.format(one.getLC()));
					resultData.put("신뢰구간(상한)", de.format(one.getUC()));
				}else if(alternative.equals("less")){
					resultData.put("신뢰구간(하한)", "-Inf");
					resultData.put("신뢰구간(상한)", de.format(one.getUC()));
				}else {
					resultData.put("신뢰구간(하한)", one.getLC());
					resultData.put("신뢰구간(상한)", "Inf");
				}	
			}
			

			resultDataList.add(resultData);
			
			

		}
		
		
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	
	}
	/* DOGFOOT syjin 가설검정 Z-test 추가  20210205 */
	/**
	 * 가설검정(Z-test)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=zTest", "analysis=0"})
	public Map<String, Object> zTest(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}
		
		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		double[][] obArray = new double[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			double[] ob = new double[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT syjin 기술통계 추가  20210210 */
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		String valueList = "";
		for(int k = 0; k < setListArray.length; k++) {
			if(valueList.equals("")) {
				valueList = setListArray[k];
			} else {
				valueList = valueList + "," + setListArray[k];
			}
		}
		
		/* DOGFOOT syjin Z검정 옵션 수정 */
		
		String alternative = "";
		if(staticOptions.has("alternative")) {
			alternative = staticOptions.getString("alternative");
			if(alternative.equals("twoSided")) {
				alternative = "two.sided";
			} else if(alternative.equals("lessSided")) {
				alternative = "less";
			} else if(alternative.equals("greaterSided")) {
				alternative = "greater";
			}
		}		
		
		String alphaLevel = "";
		/* DOGFOOT ktkang T검정 오류 수정  20210216 */
		double alphaLevelF = 0.95;
		if(staticOptions.has("alphaLevel")) {
			alphaLevel = staticOptions.getString("alphaLevel");
			alphaLevelF = 1.0 - (Double.parseDouble(alphaLevel) * 0.01);
		}
		
		if(setListArray.length == 1) {
			String mutest = "";
			if(staticOptions.has("mutest")) {
				mutest = staticOptions.getString("mutest");
			}
			
			/* DOGFOOT ktkang Z검정 옵션 추가  20210216 */
			String stdev = "";
			if(staticOptions.has("stdev")) {
				stdev = staticOptions.getString("stdev");
			}
			/* DOGFOOT syjin Z검정 옵션 수정  20210223 */
			code.addDoubleArray("x", obArray[0]);
			code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
			code.addRCode("library(TeachingDemos)");
			//code.addRCode("ols <- z.test(x, alternative = c(\"" + alternative + "\"), mu = " + mutest + ", conf.level = " + alphaLevelF + ")");
			code.addRCode("ols <- z.test(x, mu=" + mutest + ", sd=" + stdev + ", alternative = c(\"" + alternative + "\"), conf.level = " + alphaLevelF + ")");
			code.addRCode("conf <- ols$conf.int");
			code.addRCode("result <- c(ols, conf=conf)");
					
			caller.setRCode(code);
			caller.runAndReturnResult("result");
			
			System.out.println(caller.getParser().getXMLFileAsString());
			System.out.println(caller.getParser().getNames());
					
			JSONObject resultData = new JSONObject();

			double[] tEstimate = caller.getParser().getAsDoubleArray("estimate");
			String[] conf1 = caller.getParser().getAsStringArray("conf1");
			String[] conf2 = caller.getParser().getAsStringArray("conf2");
			
			resultData.put("변수", valueList);
			resultData.put("Z", caller.getParser().getAsStringArray("statistic"));
			resultData.put("P-Value", caller.getParser().getAsDoubleArray("p_value"));
			resultData.put("자유도", caller.getParser().getAsDoubleArray("parameter")[0]);
			resultData.put("평균차", tEstimate);
			resultData.put("신뢰구간(하한)", conf1[0]);
			resultData.put("신뢰구간(상한)", conf2[0]);
			resultDataList.add(resultData);
		}
//		else {
//			code.addDoubleArray("x", obArray[0]);
//			code.addDoubleArray("y", obArray[1]);
//			code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
//			code.addRCode("library(tadaatoolbox)");
//			//code.addRCode("ols <- z.test(x, y, alternative = c(\"" + alternative + "\"), conf.level = " + alphaLevelF + ")");
//			code.addRCode("ols <- z.test(x, y, alternative = c(\"" + alternative + "\"), paired=\"" + paired + "\", conf.level = " + alphaLevelF + ", sigma_x=sd(x), sigma_y=sd(y))");
//			code.addRCode("conf <- ols$conf.int");
//			code.addRCode("pears <- cor(x,y, method=\"pearson\")");
//			code.addRCode("result <- c(ols, pears=pears, conf=conf)");
//			
//			caller.setRCode(code);
//			caller.runAndReturnResult("result");
//			
//			System.out.println(caller.getParser().getXMLFileAsString());
//			System.out.println(caller.getParser().getNames());
//			
//			
//			JSONObject resultData = new JSONObject();
//
//			double[] tEstimate = caller.getParser().getAsDoubleArray("estimate");
//			String[] pearson = caller.getParser().getAsStringArray("pears");
//			String[] conf1 = caller.getParser().getAsStringArray("conf1");
//			String[] conf2 = caller.getParser().getAsStringArray("conf2");
//			
//			resultData.put("변수", valueList);
//			resultData.put("Z", caller.getParser().getAsDoubleArray("statistic"));
//			resultData.put("P-Value", caller.getParser().getAsDoubleArray("p_value"));
//			//resultData.put("자유도", caller.getParser().getAsDoubleArray("parameter"));
//			if(tEstimate.length > 1) {
//				resultData.put("평균차", tEstimate[0] - tEstimate[1]);
//			} else {
//				resultData.put("평균차", tEstimate[0]);
//			}
//			
//			//resultData.put("표준오차", caller.getParser().getAsDoubleArray("stderr"));
//			resultData.put("Pearson 상관계수", pearson[0]);
//			resultData.put("신뢰구간(하한)", conf1[0]);
//			resultData.put("신뢰구간(상한)", conf2[0]);
//			resultDataList.add(resultData);
//		}
		
		
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;	
	}
	
	/* DOGFOOT syjin Z검정 자바 추가  20210309 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=zTest", "analysis=1"})
	public Map<String, Object> zTestJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}
		
		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		double[][] obArray = new double[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			double[] ob = new double[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT syjin 기술통계 추가  20210210 */
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		String valueList = "";
		for(int k = 0; k < setListArray.length; k++) {
			if(valueList.equals("")) {
				valueList = setListArray[k];
			} else {
				valueList = valueList + "," + setListArray[k];
			}
		}
		
		/* DOGFOOT syjin Z검정 옵션 수정 */
		
		String alternative = "";
		if(staticOptions.has("alternative")) {
			alternative = staticOptions.getString("alternative");
			if(alternative.equals("twoSided")) {
				alternative = "two.sided";
			} else if(alternative.equals("lessSided")) {
				alternative = "less";
			} else if(alternative.equals("greaterSided")) {
				alternative = "greater";
			}
		}		
		
		String alphaLevel = "";
		/* DOGFOOT ktkang T검정 오류 수정  20210216 */
		double alphaLevelF = 0.95;
		if(staticOptions.has("alphaLevel")) {
			alphaLevel = staticOptions.getString("alphaLevel");
			alphaLevelF = 1.0 - (Double.parseDouble(alphaLevel) * 0.01);
		}
		
		/* DOGFOOT syjin Z검정 단일 표본 자바 추가  20210309 */
		if(setListArray.length == 1) {
			String mutest = "";
			if(staticOptions.has("mutest")) {
				mutest = staticOptions.getString("mutest");
			}
			
			/* DOGFOOT ktkang Z검정 옵션 추가  20210216 */
			String stdev = "";
			if(staticOptions.has("stdev")) {
				stdev = staticOptions.getString("stdev");
			}
			
			OneSampleZTest ztest = new OneSampleZTest(obArray[0], alternative, Double.parseDouble(alphaLevel), Double.parseDouble(mutest), Double.parseDouble(stdev));
								
			JSONObject resultData = new JSONObject();
			
			resultData.put("변수", valueList);
			resultData.put("Z", ztest.getZstatistic());
			resultData.put("P-Value", ztest.getpValue());
			resultData.put("자유도", ztest.getN());
			resultData.put("평균차", ztest.getDataMean());
			resultData.put("신뢰구간(하한)", ztest.getLower());
			resultData.put("신뢰구간(상한)", ztest.getUpper());
			resultDataList.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;	
	
	}
	/* DOGFOOT syjin 가설검정 chiTest 추가  20210210 */
	/**
	 * 카이제곱검정(chiTest)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=chiTest", "analysis=0"})
	public Map<String, Object> chiTest(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}
		
		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		double[][] obArray = new double[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			double[] ob = new double[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT syjin 기술통계 추가  20210210 */
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		String valueList = "";
		for(int k = 0; k < setListArray.length; k++) {
			if(valueList.equals("")) {
				valueList = setListArray[k];
			} else {
				valueList = valueList + "," + setListArray[k];
			}
		}
		
		/* DOGFOOT syjin 카이제곱 검정 옵션 수정 */
		
		if(staticOptions.getString("chisqType").equals("goodness")) {//적합도 검정
					
			code.addDoubleArray("ob", obArray[0]);
			
//			code.addRCode("for(i in 1:length(ob)){");
//			code.addRCode("if(i==1){");
//			code.addRCode("ex <- c();");
//			code.addRCode("ex <- c(ex, mean(ob));");
//			code.addRCode("}else{");
//			code.addRCode("ex <- c(ex, mean(ob));");
//			code.addRCode("}");
//			code.addRCode("}");
			
//			code.addRCode("sumEx <- sum(ex)");
//			code.addRCode("for(i in 0:length(ex)){");
//			code.addRCode("if(i==0){");
//			code.addRCode("pi <- c();");
//			code.addRCode("}else{");
//			code.addRCode("pi <- c(pi,ex[i]/sum(ex))");
//			code.addRCode("}");     
//			code.addRCode("}");
			
			code.addRCode("result <- chisq.test(ob)");
			//code.addRCode("result <- chisq.test(ob, ex)");
			code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
						
			caller.setRCode(code);
			caller.runAndReturnResult("result");
			
			System.out.println(caller.getParser().getXMLFileAsString());
			System.out.println(caller.getParser().getNames());
			
			
			JSONObject resultData = new JSONObject();

			//double[] tEstimate = caller.getParser().getAsDoubleArray("estimate");
			//String[] conf1 = caller.getParser().getAsStringArray("conf1");
			//String[] conf2 = caller.getParser().getAsStringArray("conf2");
			
			resultData.put("변수", valueList);
			resultData.put("chisq", caller.getParser().getAsDoubleArray("statistic"));
			resultData.put("P-Value", caller.getParser().getAsDoubleArray("p_value"));
			resultData.put("자유도", caller.getParser().getAsStringArray("parameter"));
			//resultData.put("평균차", tEstimate[0] - tEstimate[1]);
			//resultData.put("신뢰구간(하한)", conf1[0]);
			//resultData.put("신뢰구간(상한)", conf2[0]);
			resultDataList.add(resultData);
		} else { //if(staticOptions.getString("chisqType").equals("homogeneity")){	//동질성 검정	
			//dogfoot syjin 카이제곱 검정 수치변수 2개 이상일 때 데이터 형식 변경 20210322
			double val1[] = obArray[0];
			double val2[] = obArray[1];
			
			List<Double> valList1 = new ArrayList<Double>();
			List<Double> valList2 = new ArrayList<Double>();
			
			for(int i=0; i<val1.length; i++) {
				if(!valList1.contains(val1[i])) {
					valList1.add(val1[i]);
				}
			}
			Collections.sort(valList1);
			
			for(int i=0; i<val2.length; i++) {
				if(!valList2.contains(val2[i])) {
					valList2.add(val2[i]);
				}
			}
			Collections.sort(valList2);
			
			double[][] compArr = new double[valList1.size()][valList2.size()];
			
			for(double v1 : valList1) {
				for(double v2 : valList2) {
				
					for(int i=0; i<obArray[0].length; i++) {
						
						if(v1 == obArray[0][i]) {
							if(v2 == obArray[1][i]) {
								int l = (int)v1-1;
								int c = (int)v2-1;
								
								compArr[l][c]++;
							}
						}
						
					}
					
				}
			}
			
			String dataFrame = "";
			for(int i=0; i<compArr.length; i++) {
				code.addDoubleArray("x"+String.valueOf(i), compArr[i]);
				if( i==0 ) {
					dataFrame += "x" + String.valueOf(i);
				}else {
					dataFrame += ",x" + String.valueOf(i);
				}
			}
			
			code.addRCode("data <- data.frame("+dataFrame+")");
			code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
			code.addRCode("if(!c(\"BSDA\") %in% installed.packages()[,\"Package\"]){");	//패키지 설치 여부 확인
			code.addRCode("install.packages(\"BSDA\", repos=\"http://cran.us.r-project.org\");}");	
			code.addRCode("library(BSDA)");
			
			code.addRCode("ols <- chisq.test(data)");
			//code.addRCode("conf <- ols$conf.int");
			//code.addRCode("pears <- cor(x,y, method=\"pearson\")");
			//code.addRCode("result <- c(ols, pears=pears, conf=conf)");
			code.addRCode("result <- c(ols, data)");
			
			caller.setRCode(code);
			caller.runAndReturnResult("result");
			
			System.out.println(caller.getParser().getXMLFileAsString());
			System.out.println(caller.getParser().getNames());
			
			
			JSONObject resultData = new JSONObject();

			//double[] tEstimate = caller.getParser().getAsDoubleArray("estimate");
			//String[] pearson = caller.getParser().getAsStringArray("pears");
			//String[] conf1 = caller.getParser().getAsStringArray("conf1");
			//String[] conf2 = caller.getParser().getAsStringArray("conf2");
			
			resultData.put("변수", valueList);
			resultData.put("chisq", caller.getParser().getAsDoubleArray("statistic"));
			resultData.put("P-Value", caller.getParser().getAsDoubleArray("p_value"));
			double[] pValue1 = caller.getParser().getAsDoubleArray("statistic");
			
			resultData.put("자유도", caller.getParser().getAsStringArray("parameter"));
			//if(tEstimate.length > 1) {
				//resultData.put("평균차", tEstimate[0] - tEstimate[1]);
			//} else {
				//resultData.put("평균차", tEstimate[0]);
			//}
			
			//resultData.put("표준오차", caller.getParser().getAsDoubleArray("stderr"));
			//resultData.put("Pearson 상관계수", pearson[0]);
			//resultData.put("신뢰구간(하한)", conf1[0]);
			//resultData.put("신뢰구간(상한)", conf2[0]);
			resultDataList.add(resultData);
		}
		
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		
		return resultMap;	
	}

	/* DOGFOOT syjin 카이제곱 검정 JAVA 추가  20210315 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params= {"analysisType=chiTest", "analysis=1"})
	public Map<String, Object> chiTestJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {

			Gson gson = new Gson();
			String measures = String.valueOf(params.get("measures"));
			String globalDatas = String.valueOf(params.get("globalDatas"));
			JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
			List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
			List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
			
			LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
			int resultCode = 0;
			String errorMsg = "";
			
			Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
			List<String> measureNameList = new LinkedList<String>();
			int p = 0;
			for (String key : entryMap.keySet()) {
				int k = 0;
				double[] x = new double[globalDataList.size()];
				for(LinkedHashMap<String, Object> map : globalDataList) {
					/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
					//x[k] = (double) map.get(key);
					x[k] = Double.parseDouble(String.valueOf(map.get(key)));
					k++;
				}
				measureNameList.add(key.replace("sum_", ""));
				measureArrMap.put(key.replace("sum_", ""), x);
				p++;
			}
			
			List<String> result = new ArrayList<String>();
			String[] setListArray = new String[entryMap.size()];
			double[][] obArray = new double[entryMap.size()][];
			p = 0;
			for (String key : measureArrMap.keySet()) {
				double[] x = measureArrMap.get(key);
				for(int k = p+1; k < measureNameList.size(); k++) {
					double[] y = measureArrMap.get(measureNameList.get(k));
					double resultd = getPearsonsCorrelation(x,y);
					result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
				}
				double[] ob = new double[x.length];
				for(int k = 0; k < x.length; k++) {
					ob[k] = x[k];
				}
				setListArray[p] = key;
				obArray[p] = ob;
				p++;
			}
			
			/* DOGFOOT syjin 기술통계 추가  20210210 */
			/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
			Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
			List<String> meaList = new ArrayList<String>();
			for (String key : entryMap.keySet()) {
				Object[] measureArr = new Object[globalDataList.size()];
				for(int o = 0; o < globalDataList.size(); o++) {
					measureArr[o] = globalDataList.get(o).get(key);
				}
				meaList.add(key);
				meaMap.put(key, measureArr);
			}
			
			List<Object> descriptiveMap = new ArrayList<Object>();
			List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
			for(int k = 0; k < meaList.size(); k++) {
				DescriptiveStatistics summary = new DescriptiveStatistics();
				for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
					/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
					//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
					summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
				}
					
				Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
				descriptiveResultList.add(descriptiveResult);
			}
			
			List<String> descriptiveList = descriptiveList(true);
			for(int o=0; o < descriptiveList.size(); o++) {
				JSONObject descriptive = new JSONObject();
				descriptive.put("기술명", descriptiveList.get(o));
				for(int k = 0; k < meaList.size(); k++) {
					String measureName = meaList.get(k).replace("sum_", "");
					descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
				}
	
				descriptiveMap.add(descriptive);
			}
			
			Map<String, Object> resultMap = new HashMap<>();
			List<Object> resultDataList = new ArrayList<Object>();
				
			String valueList = "";
			for(int k = 0; k < setListArray.length; k++) {
				if(valueList.equals("")) {
					valueList = setListArray[k];
				} else {
					valueList = valueList + "," + setListArray[k];
				}
			}
			
			/* DOGFOOT syjin 카이제곱 검정 옵션 수정 */
			
			if(staticOptions.getString("chisqType").equals("goodness")) {//적합도 검정
			
			ChiSquareTest chis = new ChiSquareTest();
			
			double[] ob = obArray[0];
			double[] ex = new double[ob.length];
			long[] obLong = new long[ob.length];
			
			int sum = 0;
			
			for(int i=0; i<ob.length; i++) {
				sum += ob[i];
				obLong[i] = (long)ob[i];
			}
			
			for(int j=0; j<ex.length; j++) {
				ex[j] = sum/ex.length;
			}
			
			double chisq = chis.chiSquare(ex, obLong);
			double pValue = chis.chiSquareTest(ex, obLong);
																	
			JSONObject resultData = new JSONObject();
					
			resultData.put("변수", valueList);
			resultData.put("chisq", chisq);
			resultData.put("P-Value", pValue);
			resultData.put("자유도", obLong.length-1);
			
			resultDataList.add(resultData);
		} else {
			
			//dogfoot syjin 카이제곱 검정 수치변수 2개 이상일 때 데이터 형식 변경 20210322
			double val1[] = obArray[0];
			double val2[] = obArray[1];
			
			List<Double> valList1 = new ArrayList<Double>();
			List<Double> valList2 = new ArrayList<Double>();
			
			for(int i=0; i<val1.length; i++) {
				if(!valList1.contains(val1[i])) {
					valList1.add(val1[i]);
				}
			}
			Collections.sort(valList1);
			
			for(int i=0; i<val2.length; i++) {
				if(!valList2.contains(val2[i])) {
					valList2.add(val2[i]);
				}
			}
			Collections.sort(valList2);
			
			int[][] compArr = new int[valList1.size()][valList2.size()];
			
			for(double v1 : valList1) {
				for(double v2 : valList2) {
				
					for(int i=0; i<obArray[0].length; i++) {
						
						if(v1 == obArray[0][i]) {
							if(v2 == obArray[1][i]) {
								int l = (int)v1-1;
								int c = (int)v2-1;
								
								compArr[l][c]++;
							}
						}
						
					}
					
				}
			}
			
			
//			int table[][] = new int[obArray[0].length][obArray.length];
//			
//			for(int i=0; i<obArray[0].length; i++) {
//				for(int j=0; j<obArray.length; j++) {
//					table[i][j] = (int)obArray[j][i];
//				}
//			}
				
			JSONObject resultData = new JSONObject();
		
			resultData.put("변수", valueList);
			resultData.put("chisq", ChiSqTest.test(compArr).chisq);
			resultData.put("P-Value", ChiSqTest.test(compArr).pvalue);
			resultData.put("자유도", ChiSqTest.test(compArr).df);

			resultDataList.add(resultData);
		}
		
		
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;	
	}
	/* DOGFOOT syjin f 검정 fTest 추가  20210215 */

	/**
	 * f 검정(fTest)
	 * @param params
	 * @return
	 * @throws Exception
	 */
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params={"analysisType=fTest", "analysis=0"})
	public Map<String, Object> fTest(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}
		
		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		double[][] obArray = new double[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			double[] ob = new double[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT syjin 기술통계 추가  20210210 */
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		String valueList = "";
		for(int k = 0; k < setListArray.length; k++) {
			if(valueList.equals("")) {
				valueList = setListArray[k];
			} else {
				valueList = valueList + "," + setListArray[k];
			}
		}
		
		/* DOGFOOT syjin f검정 검정 옵션 수정 */		
		String alternative = "";
		if(staticOptions.has("alternative")) {
			alternative = staticOptions.getString("alternative");
			if(alternative.equals("twoSided")) {
				alternative = "two.sided";
			} else if(alternative.equals("lessSided")) {
				alternative = "less";
			} else if(alternative.equals("greaterSided")) {
				alternative = "greater";
			}
		}
		
//		String alphaLevel = "";
		/* DOGFOOT ktkang T검정 오류 수정  20210216 */
//		double alphaLevelF = 0.95;
//		if(staticOptions.has("alphaLevel")) {
//			alphaLevel = staticOptions.getString("alphaLevel");
//			alphaLevelF = 1.0 - (Double.parseDouble(alphaLevel) * 0.01);
//		}
				
		code.addDoubleArray("x", obArray[0]);
		code.addDoubleArray("y", obArray[1]);
		
		code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
		//code.addRCode("ols <- var.test(x, y, alternative = c(\"" + alternative + "\"), conf.level = " + alphaLevelF + ")");
		code.addRCode("ols <- var.test(x, y, alternative = c(\"" + alternative + "\"))");
		//code.addRCode("ols <- t.test(x, alternative = c(\"" + alternative + "\"), mu = " + mutest + ", paired = FALSE, var.equal = " + varequal + ", conf.level = " + alphaLevelF + ")");
		
		code.addRCode("conf <- ols$conf.int");
		code.addRCode("pears <- cor(x,y, method=\"pearson\")");
		code.addRCode("result <- c(ols, pears=pears, conf=conf)");
		
		caller.setRCode(code);
		caller.runAndReturnResult("result");
		
		System.out.println(caller.getParser().getXMLFileAsString());
		System.out.println(caller.getParser().getNames());
			
		JSONObject resultData = new JSONObject();

		double[] tEstimate = caller.getParser().getAsDoubleArray("estimate");
		String[] pearson = caller.getParser().getAsStringArray("pears");
		String[] conf1 = caller.getParser().getAsStringArray("conf1");
		String[] conf2 = caller.getParser().getAsStringArray("conf2");
		
		resultData.put("변수", valueList);
		resultData.put("f", caller.getParser().getAsDoubleArray("statistic"));
		resultData.put("P-Value", caller.getParser().getAsDoubleArray("p_value"));
		resultData.put("자유도", caller.getParser().getAsStringArray("parameter"));
		if(tEstimate.length > 1) {
			resultData.put("평균차", tEstimate[0] - tEstimate[1]);
		} else {
			resultData.put("평균차", tEstimate[0]);
		}
		
		//resultData.put("표준오차", caller.getParser().getAsDoubleArray("stderr"));
		resultData.put("Pearson 상관계수", pearson[0]);
		resultData.put("신뢰구간(하한)", conf1[0]);
		resultData.put("신뢰구간(상한)", conf2[0]);
		resultDataList.add(resultData);
		
		
		
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;	
	}
	
	@ResponseBody
	@RequestMapping(value="/analysis.do", params={"analysisType=fTest", "analysis=1"})
	public Map<String, Object> fTestJava(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {

		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//x[k] = (double) map.get(key);
				x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				k++;
			}
			measureNameList.add(key.replace("sum_", ""));
			measureArrMap.put(key.replace("sum_", ""), x);
			p++;
		}
		
		List<String> result = new ArrayList<String>();
		String[] setListArray = new String[entryMap.size()];
		double[][] obArray = new double[entryMap.size()][];
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getPearsonsCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			double[] ob = new double[x.length];
			for(int k = 0; k < x.length; k++) {
				ob[k] = x[k];
			}
			setListArray[p] = key;
			obArray[p] = ob;
			p++;
		}
		
		/* DOGFOOT syjin 기술통계 추가  20210210 */
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : entryMap.keySet()) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get(key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
	
		String valueList = "";
		for(int k = 0; k < setListArray.length; k++) {
			if(valueList.equals("")) {
				valueList = setListArray[k];
			} else {
				valueList = valueList + "," + setListArray[k];
			}
		}
		
		/* DOGFOOT syjin f검정 검정 옵션 수정 */		
		String alternative = "";
		if(staticOptions.has("alternative")) {
			alternative = staticOptions.getString("alternative");
			if(alternative.equals("twoSided")) {
				alternative = "two.sided";
			} else if(alternative.equals("lessSided")) {
				alternative = "less";
			} else if(alternative.equals("greaterSided")) {
				alternative = "greater";
			}
		}
		
		String alphaLevel = "";
		/* DOGFOOT ktkang T검정 오류 수정  20210216 */
		double alphaLevelF = 0.95;
		if(staticOptions.has("alphaLevel")) {
			alphaLevel = staticOptions.getString("alphaLevel");
			alphaLevelF = 1.0 - (Double.parseDouble(alphaLevel) * 0.01);
		}
		
		if(setListArray.length == 2) {
			
			FTest ftest = FTest.test(obArray[0], obArray[1]);
			FDistribution fd = new FDistribution(9,9);
			
			double fStatic = ftest.f;	//f검정 통계량
			double fPvalue = ftest.pvalue; //f 유의확률
			String fD = String.valueOf(ftest.df1) + "," + String.valueOf(ftest.df2);
			double fUpper = fd.inverseCumulativeProbability(1.0 - (1 - alphaLevelF) / 2);	//상한측 기각역
			double fLower = 1/fd.inverseCumulativeProbability(1.0 - (1 - alphaLevelF) / 2);	//하한측 기각역
			
			double fUpperOneSided = fd.inverseCumulativeProbability(1.0 - (1 - alphaLevelF));	//단측 상한측 기각역
			//신뢰구간 계산
			//f검정 통계량/상한측 기각역 ~ f검정 통계량*상한측 기각역
			String confLo = "0";		//신뢰구간 하한
			String confUp = "Inf";	
			if(alternative == "two.sided") {
				confLo = String.valueOf(fStatic/fUpper);		//신뢰구간 하한
				confUp = String.valueOf(fStatic*fUpper);		//신뢰구간 상한
			}else if(alternative == "less") {				
				confUp = String.valueOf(fStatic*fUpperOneSided);
				fPvalue = 1-(fPvalue/2);
			}else {
				confLo = String.valueOf(fStatic/fUpperOneSided);		//신뢰구간 하한
				fPvalue = fPvalue/2;
			}
						
			JSONObject resultData = new JSONObject();
			
			resultData.put("변수", valueList);
			resultData.put("f", fStatic);
			resultData.put("P-Value", fPvalue);
			resultData.put("자유도", fD);
			resultData.put("평균차", new PearsConfidence().getMean(obArray[0]) - new PearsConfidence().getMean(obArray[1]));
		
//			//resultData.put("표준오차", caller.getParser().getAsDoubleArray("stderr"));
			resultData.put("Pearson 상관계수", new PearsConfidence().getPearsConfidence(obArray[0], obArray[1]));
			resultData.put("신뢰구간(하한)", confLo);
			resultData.put("신뢰구간(상한)", confUp);
			resultDataList.add(resultData);
		}
		
		
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;	
	}
	
	/**
	 * 다변량 분석
	 * @param params
	 * @return
	 * @throws Exception
	 */
	@ResponseBody
	@RequestMapping(value="/analysis.do", params="analysisType=multivariate")
	public Map<String, Object> multivariate(
			@RequestParam Map<String, Object> params,
			Model model,
			HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		
		Gson gson = new Gson();
		String measures = String.valueOf(params.get("measures"));
		String dimensions = String.valueOf(params.get("dimensions"));
		String globalDatas = String.valueOf(params.get("globalDatas"));
		JSONObject staticOptions = SecureUtils.getJSONObjectParameter(request, "staticOptions");
		List<LinkedHashMap<String, Object>> measureList = gson.fromJson(measures, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> dimensionList = gson.fromJson(dimensions, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		List<LinkedHashMap<String, Object>> globalDataList = gson.fromJson(globalDatas, new TypeToken<List<LinkedHashMap<String, Object>>>() {}.getType());
		
		LinkedHashMap<String, Object> entryMap = globalDataList.get(0);
		int resultCode = 0;
		String errorMsg = "";
		
		Map<String, Object> resultMap = new HashMap<>();
		List<Object> resultDataList = new ArrayList<Object>();
		
		Map<String, double[]> measureArrMap = new LinkedHashMap<String, double[]>();
		List<String> measureNameList = new LinkedList<String>();
		List<String> dimensionNameList = new LinkedList<String>();
		for(LinkedHashMap<String, Object> measure : measureList) {
			measureNameList.add(measure.get("caption").toString());
		}
		
		for(LinkedHashMap<String, Object> dimension : dimensionList) {
			dimensionNameList.add(dimension.get("caption").toString());
		}
		
		String[] setListArray = new String[entryMap.size()];
		Object[][] obArray = new Object[entryMap.size()][];
		int p = 0;
		for (String key : entryMap.keySet()) {
			int k = 0;
			double[] x = new double[globalDataList.size()];
			String[] y = new String[globalDataList.size()];
			for(LinkedHashMap<String, Object> map : globalDataList) {
				if(dimensionNameList.contains(key)) {
					y[k] = String.valueOf(map.get(key));
				} else {
					x[k] = Double.parseDouble(String.valueOf(map.get(key)));
				}
				
				k++;
			}

			if(dimensionNameList.contains(key)) {
				Object[] ob = new Object[y.length];
				for(int j = 0; j < y.length; j++) {
					ob[j] = y[j];
				}
				obArray[p] = ob;
			} else {
				Object[] ob = new Object[x.length];
				for(int j = 0; j < x.length; j++) {
					ob[j] = x[j];
				}
				obArray[p] = ob;
			}

			setListArray[p] = key.replace("sum_", "");
			
			p++;
		}

		List<String> result = new ArrayList<String>();
		p = 0;
		for (String key : measureArrMap.keySet()) {
			double[] x = measureArrMap.get(key);
			for(int k = p+1; k < measureNameList.size(); k++) {
				double[] y = measureArrMap.get(measureNameList.get(k));
				double resultd = getSpearmansCorrelation(x,y);
				result.add(key + "," + measureNameList.get(k) + "," + resultd + "," + y.length);
			}
			p++;
		}
		
		/* DOGFOOT ktkang 기술통계 구하는 부분  20201028 */
		Map<String, Object[]> meaMap = new HashMap<String, Object[]>();
		List<String> meaList = new ArrayList<String>();
		for (String key : measureNameList) {
			Object[] measureArr = new Object[globalDataList.size()];
			for(int o = 0; o < globalDataList.size(); o++) {
				measureArr[o] = globalDataList.get(o).get("sum_" + key);
			}
			meaList.add(key);
			meaMap.put(key, measureArr);
		}
		
		List<Object> descriptiveMap = new ArrayList<Object>();
		List<Map<String, Object>> descriptiveResultList = new ArrayList<Map<String, Object>>();
		for(int k = 0; k < meaList.size(); k++) {
			DescriptiveStatistics summary = new DescriptiveStatistics();
			for (int j = 0; j < meaMap.get(meaList.get(k)).length; j++) {
				/* DOGFOOT syjin 측정값 오류(캐스팅) 수정  20210125 */
				//summary.addValue((double) meaMap.get(meaList.get(k))[j]);
				summary.addValue(Double.parseDouble(String.valueOf(meaMap.get(meaList.get(k))[j])));
			}
				
			Map<String, Object> descriptiveResult = descriptiveResult(summary, meaMap.get(meaList.get(k)), true);
			descriptiveResultList.add(descriptiveResult);
		}
		
		List<String> descriptiveList = descriptiveList(true);
		for(int o=0; o < descriptiveList.size(); o++) {
			JSONObject descriptive = new JSONObject();
			descriptive.put("기술명", descriptiveList.get(o));
			for(int k = 0; k < meaList.size(); k++) {
				String measureName = meaList.get(k).replace("sum_", "");
				descriptive.put(measureName, descriptiveResultList.get(k).get(descriptiveList.get(o)));
			}

			descriptiveMap.add(descriptive);
		}
		
		String method = "";
		if(staticOptions.has("method")) {
			method = staticOptions.getString("method");
		}
		
		String distance = "";
		if(staticOptions.has("distance")) {
			distance = staticOptions.getString("distance");
		}
		
		String cluster = "";
		if(staticOptions.has("cluster")) {
			cluster = staticOptions.getString("cluster");
		}
		
		RCode code = RCode.create();
		RCallerOptions options = RCallerOptions.create();
		RCaller caller = RCaller.create(code, options);
		
		try {
			DataFrame df = DataFrame.create(obArray, setListArray);

			code.addDataFrame("x", df);
			code.addRCode("Sys.setlocale(\"LC_ALL\", \"korean\")");
			code.addRCode("library(NbClust)"); 
			code.addRCode("x<-data.matrix(x)");
			code.addRCode("res <- NbClust(x, distance=\"" + distance + "\", min.nc=" + cluster + ", max.nc=15, method=\"" + method + "\", index=\"all\")");
			//		code.addRCode("res <- NbClust(data=x, distance=\"" + distance + "\", min.nc=" + cluster + ", max.nc=15, method=\"" + method + "\", index=\"all\")");
			code.addRCode("result <- t(res$Best.nc[1,])");
			caller.setRCode(code);
			caller.runAndReturnResult("result");
		} catch (ExecutionException e) {
			resultCode = 10;
		}
		
		System.out.println(caller.getParser().getXMLFileAsString());
		System.out.println(caller.getParser().getNames());
		
		int[] resultArr = caller.getParser().getAsIntArray("result");
		
		 int mode = 0;
	        int[] index = new int[resultArr.length];
	        int max = Integer.MIN_VALUE;
			for (int i = 0; i < resultArr.length; i++) {
	            index[resultArr[i]]++;         
	        }
	        for (int i=0; i< index.length; i++){
	            if(max<index[i]){
	                max = index[i];
	                mode = i;
	            }          
	        }   
	        
		JSONObject resultData = new JSONObject();
		resultData.put("Index명", "최적의 Cluster 개수");
		resultData.put("Cluster개수", String.valueOf(mode) + " 개");
		resultDataList.add(resultData);
		
		String[] indexString = {"KL","CH","Hartigan","CCC","Scott","Marriot","TrCovW","TraceW","Friedman","Rubin","Cindex","DB","Silhouette","Duda","PseudoT2","Beale","Ratkowsky","Ball","PtBiserial","Frey","McClain","Dunn","Hubert","SDindex","Dindex","SDbw"};
		for(int k=0; k < indexString.length; k++) {
			JSONObject resultData2 = new JSONObject();
			resultData2.put("Index명", String.valueOf(indexString[k]));
			resultData2.put("Cluster개수", String.valueOf(resultArr[k]) + " 개");
			resultDataList.add(resultData2);
		}
		
        
		resultMap.put("data", resultDataList);
		resultMap.put("descriptive", descriptiveMap);
		resultMap.put("resultCode", resultCode);
		resultMap.put("errorMsg", errorMsg);
		
		return resultMap;
	}
	
	
	@RequestMapping(value = "/rScript.do", method = RequestMethod.POST, produces ="text/plain; charset=utf8")
    public @ResponseBody String rScript(HttpServletRequest request, HttpServletResponse response, Model model) throws Exception {
		JSONParser parser = new JSONParser();
		String tempData = request.getParameter("data");
		String scriptStr = request.getParameter("script");
			
		/* dataSource : String Array 컬럼명, value
		 * sourceType : String String 컬럼명, 데이터 타입
		 * sourceMapping1 : String String 사용자 입력 컬럼명, 실제 컬렴명
		 * sourceMapping2 : String String 실제 컬럼명, 사용자 입력 컬럼명
		 */
		Map<String, Object> dataSource = new HashMap<String, Object>();
		Map<String, String> sourceType = new HashMap<String, String>();
		Map<String, String> sourceMapping1 = new HashMap<String, String>();
		Map<String, String> sourceMapping2 = new HashMap<String, String>();
		
		//데이터 가공
		JSONObject keyData = JSONArray.fromObject(tempData).getJSONObject(0);
		Iterator iter = keyData.keySet().iterator();
		int index = 0;
		while(iter.hasNext())
		{
			String key = (String)iter.next();
			Object v = keyData.get(key);
		 	if (v instanceof Integer || v instanceof Long || v instanceof Float || v instanceof Double) {
				 dataSource.put(key, new ArrayList<Double> ());
				 sourceType.put(key, "Number");
				 //한국어일 경우 영어로 바꿔 매핑
				 if(getIsKorean(key)) {
					 sourceMapping1.put(key, "wise_r_value_temp"+index);
					 sourceMapping2.put("wise_r_value_temp"+index, key);
				 }else {
					 sourceMapping1.put(key, key);
					 sourceMapping2.put(key, key);
				 }

				 index++;
		 	} else{
	        	 dataSource.put(key, new ArrayList<String> ());
	        	 sourceType.put(key, "String");
	        	 sourceMapping1.put(key, "wise_r_value_temp"+index);
				 sourceMapping2.put("wise_r_value_temp"+index, key);
				 index++;
	        }
			
		}
		
		JSONArray tempJsonArray = JSONArray.fromObject(tempData);
		
		for(int i = 0; i < tempJsonArray.size(); i++) {
			JSONObject object = tempJsonArray.getJSONObject(i);
			Iterator iter2 = object.keySet().iterator();
			try {
				while(iter2.hasNext())
				{
					String key = (String)iter2.next();
					if(sourceType.get(key).equals("Number")) {
						ArrayList<Double> tempArray = (ArrayList<Double>)dataSource.get(key);
						tempArray.add(Double.parseDouble(String.valueOf(object.get(key))));
						dataSource.replace(key, tempArray);
					}else {
						ArrayList<String> tempArray = (ArrayList<String>)dataSource.get(key);
						tempArray.add((String)object.get(key));
						dataSource.replace(key, tempArray);
					}
				}
			}catch(Exception e) {
				e.printStackTrace();
			}
		}
		
		RConnection connection = null;
		
		// resultMap : 결과값을 담아올 Map
		Map<String, Object> resultMap = new HashMap<String, Object>();
		int resultLength = 0;
		String aa = "";
		JSONObject result = new JSONObject();
		try {
			// R 연결
            connection = new RConnection();
            connection.setStringEncoding("utf8");
            
            // 데이터 미리 입력
            for (Map.Entry<String, Object> entry : dataSource.entrySet()) {
                 String key = entry.getKey();
                 if(sourceType.get(key).equals("Number")) {
 					ArrayList<Double> tempArray = (ArrayList<Double>)dataSource.get(key);
 					double[] target = new double[tempArray.size()];
					for (int i = 0; i < target.length; i++) {
					    target[i] = tempArray.get(i);
					}
 					connection.assign(sourceMapping1.get(key), target);
 				}else {
 					ArrayList<String> tempArray = (ArrayList<String>)dataSource.get(key);
 					connection.assign(sourceMapping1.get(key), tempArray.toArray(new String[tempArray.size()]));
 				}

            }

            //사용자 입력 R 스크립트 사용
            //사용자가 입력한 변수 이름 매핑
            for (Map.Entry<String, String> entry : sourceMapping1.entrySet()) {
            	String key   = entry.getKey();
            	String value =  entry.getValue();
            	
            	scriptStr = scriptStr.replaceAll(key, value);
		    }
            
//            System.out.println(scriptStr);
            //사용자 입력 스크립트 실행
            connection.eval(scriptStr);
            
//            System.out.println(connection.eval("as.character(exists(\"result\"))").asString().equals("TRUE"));
            //결과 캡처
            if(connection.eval("as.character(exists(\"result\"))").asString().equals("TRUE")) {
            	if(!(connection.eval("result").isString() && connection.eval("result").asString().equals("")))
                	connection.eval("result <- paste(capture.output(result, file=NULL, split = TRUE, type=\"output\"), collapse=\"\n\")");
                
                // 값 가져오는 곳 -> 보완 필요
//                System.out.println("스크립트 정상 실행");
                resultLength = connection.eval("length(result)").asInteger();
                if(resultLength > 1) {
                	RList resultList = connection.eval("lapply(result, as.character)").asList();
                    
                    int cols = resultList.size();
                    System.out.println(cols);
                    int rows = resultList.at(0).length();
//                    System.out.println(resultList.at(1).asDoubles()[10]);
                    
//                    System.out.println(resultList.names);
                   
                    for(int i = 0; i < cols; i++) {
                    	result.put(resultList.names.get(i), resultList.at(i).asStrings());
                    }
                } else {
                	result.put("value", connection.eval("as.character(result)").asString());
                }
            }else {
            	result.put("value", "");
            }
            // result 남은 값 제거
            // TODO : 변수 값도 제거해야함
            connection.eval("result <- ''");
            
            connection.close();
        } catch (RserveException e) {
            e.printStackTrace();
            return "RServer 오류";
        } catch (REXPMismatchException e) {
            e.printStackTrace();
            return "입력 스크립트 오류";
        } catch (Exception e){
        	e.printStackTrace();
        	return "알 수 없는 오류";
        } finally {
            connection.close();
        }
		

		if(resultLength > 1) {
			String[] resultStr = null;
			//결과 출력
			Iterator iter3 = result.keySet().iterator();
			
			while(iter3.hasNext()) {
				//결과값 key 반복
				String key = (String)iter3.next();
				//결과값 String 형태로 받아옴 ex)["1342", "321412", "32414"]
				System.out.println(result.get(key).getClass().getName());
				JSONArray tempList = (JSONArray) result.get(key);
				;
				//결과값 JSONArray 문자열 형태로 출력
				if(resultStr == null) resultStr = new String[tempList.size()];
				for(int i = 0; i < tempList.size(); i++) {
					if(resultStr[i] == null) {
						resultStr[i] = "{";
					}
					resultStr[i] += key + " : " + tempList.getString(i);
					if(iter3.hasNext()) {
						resultStr[i] += ", ";
					}else {
						resultStr[i] += "}";
					}
				}
				
				
			}
			
			String resultStr2 = "[";
			
			for(int i = 0; i< resultStr.length; i++) {
				resultStr2 += resultStr[i];
				if(i != resultStr.length - 1) {
					resultStr2 += ",\n";
				}else {
					resultStr2 += "]";
				}
			}
			
//			System.out.println(resultStr2);
			
			//사용자 입력 R 스크립트 사용
	        //사용자가 입력한 변수 이름 매핑
	        for (Map.Entry<String, String> entry : sourceMapping2.entrySet()) {

	        	String key = entry.getKey();
	        	String value = entry.getValue();
	        	
	        	resultStr2 = resultStr2.replaceAll(key, value);
		    }
	        
	        System.out.println(resultStr2);
	        return resultStr2;
		}else {
			String resultStr1 = (String)result.get("value");
			for (Map.Entry<String, String> entry : sourceMapping2.entrySet()) {

	        	String key = entry.getKey();
	        	String value = entry.getValue();
	        	
	        	resultStr1 = resultStr1.replaceAll(key, value);
		    }
			return resultStr1;
		}
	}
	
	//한국어 체크
	private static boolean getIsKorean(String word) {	
		return Pattern.matches(".*[ㄱ-ㅎㅏ-ㅣ가-힣]+.*", word);
	}
}
