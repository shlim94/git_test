package com.wise.ds.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
//import java.util.Base64.Encoder;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.annotation.Resource;
import javax.swing.text.BadLocationException;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.rtf.RTFEditorKit;

import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.sun.org.apache.xml.internal.security.utils.Base64;
import com.wise.ds.repository.CubeTableColumnVO;
import com.wise.ds.repository.CubeTableVO;
import com.wise.ds.repository.service.DataSetService;

@Service("Json2Xml")
public class Json2Xml {
	
	@Resource(name = "dataSetService")
    private DataSetService dataSetServiceImpl;
	
	final static private Logger logger = LoggerFactory.getLogger(Json2Xml.class);
//	@Value("${server.address}")
//    private String serverAddress;
//
//    @Value("${server.port}")
//    private String serverPort;
	
	public String getItemAttribute(JSONObject obj, String KeyName) {
		String returnString = "";
		try {
			returnString = obj.getString(KeyName);
		} catch (JSONException e) {
			e.printStackTrace();
		}
		return returnString;
	}

	public JSONArray toJsonArray(JSONObject obj, String key) {
		if (obj.has(key)) {
			Object json = obj.get(key);
			if (json.getClass() == JSONArray.class) {
				return obj.getJSONArray(key);
			} else if (json.getClass() == JSONObject.class) {
				return new JSONArray("[" + obj.getJSONObject(key).toString() + "]");
			} else {
				return null;
			}
		} else {
			return null;
		}
	}
	
	// 제대로 변환 안됨
	private static String convertToRTF(String htmlStr) throws IOException, BadLocationException { // ymbin : convert html to rtf

	    OutputStream os = new ByteArrayOutputStream();
	    HTMLEditorKit htmlEditorKit = new HTMLEditorKit();
	    RTFEditorKit rtfEditorKit = new RTFEditorKit();
	    String rtfStr = null;

	    htmlStr = htmlStr.replaceAll("<br.*?>","#NEW_LINE#");
	    htmlStr = htmlStr.replaceAll("</p>","#NEW_LINE#");
	    htmlStr = htmlStr.replaceAll("<p.*?>","");
	    InputStream is = new ByteArrayInputStream(htmlStr.getBytes());
        javax.swing.text.Document doc = htmlEditorKit.createDefaultDocument();
        htmlEditorKit.read(is, doc, 0);
        rtfEditorKit .write(os, doc, 0, doc.getLength());
        rtfStr = os.toString();
        rtfStr = rtfStr.replaceAll("#NEW_LINE#","\\\\par ");
	    return rtfStr;
	}
	
	//20200827 ajkim Json2Xml InteractivityOption 함수 처리 dogfoot
	private void addInteractivityOption(JSONObject obj, Element root) {
		if (obj.has("InteractivityOptions")) {
			String masterFilterMode = "";
			String drillDownMode = "";
			boolean ignoreMasterFilter = false;
			
			if(obj.getJSONObject("InteractivityOptions").has("MasterFilterMode"))
				if(!obj.getJSONObject("InteractivityOptions").getString("MasterFilterMode").equals("Off")) {
					masterFilterMode = obj.getJSONObject("InteractivityOptions").getString("MasterFilterMode");
				}
			if(obj.getJSONObject("InteractivityOptions").has("IsDrillDownEnabled"))
				if(obj.getJSONObject("InteractivityOptions").getBoolean("IsDrillDownEnabled")) {
					drillDownMode = "true";
				}
			if(obj.getJSONObject("InteractivityOptions").has("IgnoreMasterFilters"))
				if(obj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters") == true) {
					ignoreMasterFilter = obj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters");
				}
			if(!masterFilterMode.equals("") || !drillDownMode.equals("") || ignoreMasterFilter == true) {
				Element interactivityOptions = root.addElement("InteractivityOptions");
				if(!masterFilterMode.equals("")) {
					interactivityOptions.addAttribute("MasterFilterMode",masterFilterMode);
				}
				if(!drillDownMode.equals("")) {
					interactivityOptions.addAttribute("IsDrillDownEnabled",drillDownMode);
				}
				if(ignoreMasterFilter == true) {
					interactivityOptions.addAttribute("IgnoreMasterFilters","true");
				}
				if(obj.getJSONObject("InteractivityOptions").has("TargetDimensions"))
					if(!obj.getJSONObject("InteractivityOptions").getString("TargetDimensions").equals("")) {
						interactivityOptions.addAttribute("TargetDimensions",obj.getJSONObject("InteractivityOptions").getString("TargetDimensions"));
					}
			}
		}
	}

	public String sortLayoutXml(JSONObject layoutObj, String remoteAddr) throws IOException, BadLocationException {

		Document layoutXml = DocumentHelper.createDocument();
		Element dashBoard = layoutXml.addElement("Dashboard");
		dashBoard.addAttribute("CurrencyCulture", "ko-KR");

		Element Title = dashBoard.addElement("Title");
		Title.addAttribute("Text", layoutObj.getJSONObject("Title").getString("Text"));
		Title.addAttribute("Alignment", layoutObj.getJSONObject("Title").getString("Alignment"));

		JSONObject dataSources = layoutObj.getJSONObject("DataSources");
		JSONArray dataSourceArr = toJsonArray(dataSources, "DataSource");

		Element DataSources = dashBoard.addElement("DataSources");
		for (int dataidx = 0; dataidx < dataSourceArr.length(); dataidx++) {
			JSONObject dataSource = dataSourceArr.getJSONObject(dataidx);
			Element DataSource = DataSources.addElement("DataSource");
			DataSource.addAttribute("ComponentName", dataSource.getString("ComponentName"));
			DataSource.addAttribute("Name", dataSource.get("Name")+"");
			if (dataSource.has("CalculatedFields")) {
				Element CalculatedFields = DataSource.addElement("CalculatedFields");
				//2020.01.30 mksong CalculatedFields not Jsonobject 오류 수정 dogfoot
				if(!dataSource.get("CalculatedFields").equals("")) {
					JSONObject calcFields = dataSource.getJSONObject("CalculatedFields");
					if (calcFields.has("CalculatedField")) {
						JSONArray calcObjs = toJsonArray(calcFields, "CalculatedField");
						for (int calc = 0; calc < calcObjs.length(); calc++) {
							JSONObject calcObj = calcObjs.getJSONObject(calc);
							Element CalculatedField = CalculatedFields.addElement("CalculatedField");
							CalculatedField.addAttribute("Name", calcObj.getString("Name"));
							CalculatedField.addAttribute("Expression", calcObj.getString("Expression"));
							CalculatedField.addAttribute("DataType", calcObj.getString("DataType"));
						}
					}	
				}
			}
		}

		JSONObject itemObj = layoutObj.getJSONObject("Items");
		Element items = dashBoard.addElement("Items");
		Iterator<String> i = itemObj.keys();
		//20200608 ajkim memoText 추가 dogfoot
		while (i.hasNext()) {
			String KeyName = i.next().toString();
			switch (KeyName) {
			case "Chart":
				JSONArray chartItemArray = itemObj.getJSONArray("Chart");
				for(int eachChartItem = 0;eachChartItem < chartItemArray.length();eachChartItem++) {
					JSONObject chartObj = chartItemArray.getJSONObject(eachChartItem);
					JSONObject chartDataItem = chartObj.getJSONObject("DataItems");

					
					JSONObject chartPanes = chartObj.getJSONObject("Panes");

					Element Chartroot = items.addElement("Chart");
					Chartroot.addAttribute("ComponentName", chartObj.getString("ComponentName"));
					Chartroot.addAttribute("Name", chartObj.getString("Name"));
					Chartroot.addAttribute("MemoText", chartObj.getString("MemoText"));
					Chartroot.addAttribute("DataSource", chartObj.getString("DataSource"));
					
					if (chartObj.has("isAdhocItem")) {
						Chartroot.addAttribute("isAdhocItem", String.valueOf(chartObj.getBoolean("isAdhocItem")));
						Chartroot.addAttribute("adhocIndex", String.valueOf(chartObj.getInt("adhocIndex")));
					}
					
					addInteractivityOption(chartObj, Chartroot);
					
					if (chartObj.has("IsMasterFilterCrossDataSource")) {
						if (chartObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							Chartroot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					if (chartObj.has("Rotated")) {
						if(chartObj.getBoolean("Rotated") == true) {
							Chartroot.addAttribute("Rotated","true");
						}
					}
					if(chartObj.has("ShowCaption")) {
						if(chartObj.getBoolean("ShowCaption") == false)
							Chartroot.addAttribute("ShowCaption", "false");
					}
					if(chartObj.has("FilterString")) {
						Chartroot.addAttribute("FilterString", chartObj.getString("FilterString"));
					}
					//20210318 AJKIM 차원 하이라이트 기능 추가 dogfoot
					if(chartObj.has("PointHighlight")) {
//						Element PointHighlight = Chartroot.addElement("PointHighlight");
						JSONArray PointHighlightArr = chartObj.getJSONArray("PointHighlight");
						if (PointHighlightArr != null) {
							for (int PointIndex = 0; PointIndex < PointHighlightArr.length(); PointIndex++) {
								Element Point = Chartroot.addElement("PointHighlight");
								if(PointHighlightArr.getJSONObject(PointIndex).has("Name")) {
									Point.addAttribute("Name",  PointHighlightArr.getJSONObject(PointIndex).getString("Name"));
								}
								if(PointHighlightArr.getJSONObject(PointIndex).has("Color")) {
									Point.addAttribute("Color",  PointHighlightArr.getJSONObject(PointIndex).getString("Color"));
								}
	
							}
						}
					}
					Element DataItems = Chartroot.addElement("DataItems");
					JSONArray DataItemAttr = toJsonArray(chartDataItem, "Measure");
					if (DataItemAttr != null) {
						for (int Mea = 0; Mea < DataItemAttr.length(); Mea++) {
							Element Measure = DataItems.addElement("Measure");
							Measure.addAttribute("DataMember", DataItemAttr.getJSONObject(Mea).getString("DataMember"));
							String summaryType = "";
							if(DataItemAttr.getJSONObject(Mea).has("SummaryType")) {
								switch(DataItemAttr.getJSONObject(Mea).getString("SummaryType")) {
								case "countdistinct":
									summaryType = "CountDistinct";
									break;
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}
							
							Measure.addAttribute("SummaryType",  summaryType);
							if(DataItemAttr.getJSONObject(Mea).has("Name")) {
								Measure.addAttribute("Name",  DataItemAttr.getJSONObject(Mea).getString("Name"));
							}
							Measure.addAttribute("UniqueName", DataItemAttr.getJSONObject(Mea).getString("UniqueName"));
							/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 밑으로 CubeUniqueName 부분 전부  20200618 */
							if(DataItemAttr.getJSONObject(Mea).has("CubeUniqueName")) {
								Measure.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Mea).getString("CubeUniqueName"));
							}
							if (DataItemAttr.getJSONObject(Mea).has("NumericFormat")) {
								Element NumericFormat = Measure.addElement("NumericFormat");
								JSONObject ChartNumericFormat = DataItemAttr.getJSONObject(Mea)
										.getJSONObject("NumericFormat");
								if (ChartNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", ChartNumericFormat.getString("FormatType"));
								if (ChartNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", ChartNumericFormat.getString("Unit"));
								if (ChartNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", ChartNumericFormat.get("Precision") + "");
								/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
								if (ChartNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", ChartNumericFormat.getString("PrecisionOption") + "");
								if (ChartNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator", ChartNumericFormat.get("IncludeGroupSeparator").toString());
							}

						}
					}

					DataItemAttr = toJsonArray(chartDataItem, "Dimension");
					if (DataItemAttr != null) {
						for (int Dim = 0; Dim < DataItemAttr.length(); Dim++) {
							Element Dimension = DataItems.addElement("Dimension");
							Dimension.addAttribute("DataMember", DataItemAttr.getJSONObject(Dim).getString("DataMember"));
							if(DataItemAttr.getJSONObject(Dim).has("Name")) {
								Dimension.addAttribute("Name",  DataItemAttr.getJSONObject(Dim).getString("Name"));
							}
							if (DataItemAttr.getJSONObject(Dim).has("SortOrder")) {
								if(DataItemAttr.getJSONObject(Dim).getString("SortOrder").equalsIgnoreCase("Descending"))
									Dimension.addAttribute("SortOrder", "Descending");
							}
							if(DataItemAttr.getJSONObject(Dim).has("SortByMeasure")) {
								Dimension.addAttribute("SortByMeasure", DataItemAttr.getJSONObject(Dim).getString("SortByMeasure"));
							}
							//2020-01-14 LSH topN 차트 저장
							if(DataItemAttr.getJSONObject(Dim).has("TopNEnabled")) {
								String TopNEnabled = "true";
								Dimension.addAttribute("TopNEnabled",TopNEnabled);
								/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
								if(DataItemAttr.getJSONObject(Dim).has("TopNOrder")) {
									Dimension.addAttribute("TopNOrder", DataItemAttr.getJSONObject(Dim).get("TopNOrder")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNCount")) {
									Dimension.addAttribute("TopNCount", DataItemAttr.getJSONObject(Dim).get("TopNCount")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNMeasure")) {
									Dimension.addAttribute("TopNMeasure", DataItemAttr.getJSONObject(Dim).get("TopNMeasure")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNShowOthers")) {
									String TopNShowOthers = "true";
									Dimension.addAttribute("TopNShowOthers",TopNShowOthers);
								}
							}
							if (DataItemAttr.getJSONObject(Dim).has("ColoringMode")) {
								Dimension.addAttribute("ColoringMode",
										DataItemAttr.getJSONObject(Dim).getString("ColoringMode"));
							}
							Dimension.addAttribute("UniqueName", DataItemAttr.getJSONObject(Dim).getString("UniqueName"));
							if(DataItemAttr.getJSONObject(Dim).has("CubeUniqueName")) {
								Dimension.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Dim).getString("CubeUniqueName"));
							}
						}
					}
					if(chartObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = chartObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = Chartroot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					if (chartObj.has("Arguments")) {
						JSONObject chartArguments = chartObj.getJSONObject("Arguments");
						JSONArray ArgumentsArr = toJsonArray(chartArguments, "Argument");
						Element Arguments = Chartroot.addElement("Arguments");
						for (int arg = 0; arg < ArgumentsArr.length(); arg++) {
							Element ArgumentsAttr = Arguments.addElement("Argument");
							ArgumentsAttr.addAttribute("UniqueName",
									ArgumentsArr.getJSONObject(arg).getString("UniqueName"));
							if(ArgumentsArr.getJSONObject(arg).has("CubeUniqueName")) {
								ArgumentsAttr.addAttribute("CubeUniqueName",  ArgumentsArr.getJSONObject(arg).getString("CubeUniqueName"));
							}
						}
					}
					
					if(chartObj.has("ColoringOption")) {
						Element ColoringOptions = Chartroot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", chartObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", chartObj.getString("UseGlobalColors"));
						JSONArray colorArray = chartObj.getJSONArray("ColorSheme");
						Element ColorSheme = Chartroot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					
					if (chartObj.has("SeriesDimensions")) {
						JSONObject chartseriesDim = chartObj.getJSONObject("SeriesDimensions");
						JSONArray SeriesDimArr = toJsonArray(chartseriesDim, "SeriesDimension");
						Element SeriesDimensions = Chartroot.addElement("SeriesDimensions");
						for (int serdim = 0; serdim < SeriesDimArr.length(); serdim++) {
							Element SeriesDimensionAttr = SeriesDimensions.addElement("SeriesDimension");
							SeriesDimensionAttr.addAttribute("UniqueName",
									SeriesDimArr.getJSONObject(serdim).getString("UniqueName"));
							if(SeriesDimArr.getJSONObject(serdim).has("CubeUniqueName")) {
								SeriesDimensionAttr.addAttribute("CubeUniqueName",  SeriesDimArr.getJSONObject(serdim).getString("CubeUniqueName"));
							}
						}
					}
					/*dogfoot 차트 Y축 포멧 오류 수정 shlim 20210728*/
					if(chartObj.has("ChartYOption")) {
						JSONObject chartYoption = chartObj.getJSONObject("ChartYOption");
						Element AxisY = Chartroot.addElement("AxisY");
						if (chartYoption.has("Visible")) {
							if (chartYoption.getBoolean("Visible") != true)
								AxisY.addAttribute("Visible", "false");
						}
						if (chartYoption.has("Title")) {
							if (!chartYoption.getString("Title").equals("")) {
								AxisY.addAttribute("Title", chartYoption.getString("Title"));
							}
						}
						if (chartYoption.has("ShowZero")) {
							AxisY.addAttribute("ShowZero", chartYoption.getBoolean("ShowZero") ? "true" : "false");
						}
						if (chartYoption.has("FormatType")) {
							AxisY.addAttribute("FormatType", chartYoption.getString("FormatType"));
						}
						if (chartYoption.has("Unit")) {
							AxisY.addAttribute("Unit", chartYoption.getString("Unit"));
						}
						if (chartYoption.has("SuffixEnabled")) {
							AxisY.addAttribute("SuffixEnabled", chartYoption.getBoolean("SuffixEnabled") ? "true" : "false");
						}
						if (chartYoption.has("Precision")) {
							AxisY.addAttribute("Precision", chartYoption.getInt("Precision") + "");
						}
						/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
						if (chartYoption.has("PrecisionOption")) {
							AxisY.addAttribute("PrecisionOption", chartYoption.getString("PrecisionOption") + "");
						}
						
						if (chartYoption.has("Separator")) {
							AxisY.addAttribute("Separator", chartYoption.getBoolean("Separator") ? "true" : "false");
						}
						if (chartYoption.has("MeasureFormat")) {
							Element numFormat = AxisY.addElement("MeasureFormat");
							JSONObject measureFormat = chartYoption.getJSONObject("MeasureFormat");
							if (measureFormat.has("O")) {
								numFormat.addAttribute("O", measureFormat.getString("O"));
							}
							if (measureFormat.has("K")) {
								numFormat.addAttribute("K", measureFormat.getString("K"));
							}
							if (measureFormat.has("M")) {
								numFormat.addAttribute("M", measureFormat.getString("M"));
							}
							if (measureFormat.has("B")) {
								numFormat.addAttribute("B", measureFormat.getString("B"));
							}
							
						}
					}
					
					JSONArray PanesArr = toJsonArray(chartPanes, "Pane");
					Element Panes = Chartroot.addElement("Panes");
					Element AxisY = null;
					for (int pane = 0; pane < PanesArr.length(); pane++) {
						JSONObject PaneObj = PanesArr.getJSONObject(pane);
						Element Pane = Panes.addElement("Pane");
						Pane.addAttribute("Name", PaneObj.getString("Name"));
						if(chartObj.has("ChartYOption")) {
							JSONObject chartYoption = chartObj.getJSONObject("ChartYOption");
							AxisY = Pane.addElement("AxisY");
							if (chartYoption.has("Visible")) {
								if (chartYoption.getBoolean("Visible") != true)
									AxisY.addAttribute("Visible", "false");
							}
							if (chartYoption.has("Title")) {
								if (!chartYoption.getString("Title").equals("")) {
									AxisY.addAttribute("Title", chartYoption.getString("Title"));
								}
							}
							if (chartYoption.has("ShowZero")) {
								AxisY.addAttribute("ShowZero", chartYoption.getBoolean("ShowZero") ? "true" : "false");
							}
							if (chartYoption.has("FormatType") || chartYoption.has("Precision") || chartYoption.has("Unit") || chartYoption.has("Separator")) {
								Element numFormat = AxisY.addElement("NumericFormat");
								if (chartYoption.has("FormatType")) {
									numFormat.addAttribute("FormatType", chartYoption.getString("FormatType"));
								}
								if (chartYoption.has("Precision")) {
									numFormat.addAttribute("Precision", chartYoption.getInt("Precision") + "");
								}
								/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
								if (chartYoption.has("PrecisionOption")) {
									numFormat.addAttribute("PrecisionOption", chartYoption.getString("PrecisionOption") + "");
								}
								if (chartYoption.has("Unit")) {
									numFormat.addAttribute("Unit", chartYoption.getString("Unit"));
								}
								if (chartYoption.has("Separator")) {
									numFormat.addAttribute("IncludeGroupSeparator", chartYoption.getBoolean("Separator") ? "true" : "false");
								}
							}
						}
						
						Element Series = Pane.addElement("Series");
						JSONArray SeriesArr = toJsonArray(PaneObj, "Series");
						for (int series = 0; series < SeriesArr.length(); series++) {
							JSONObject SeriesItem = SeriesArr.getJSONObject(series);
							if (toJsonArray(SeriesItem, "Simple") != null) {
								JSONArray simpleArr = toJsonArray(SeriesItem, "Simple");
								for (int simple = 0; simple < simpleArr.length(); simple++) {
									JSONObject simpleItem = simpleArr.getJSONObject(simple);
									
									Element Simple = Series.addElement("Simple");
									if (simpleItem.has("IgnoreEmptyPoints")) {
										Simple.addAttribute("IgnoreEmptyPoints", simpleItem.getBoolean("IgnoreEmptyPoints") ? "true" : "false");
									}
									if (simpleItem.has("PlotOnSecondaryAxis")) {
										Simple.addAttribute("PlotOnSecondaryAxis", simpleItem.getBoolean("PlotOnSecondaryAxis") ? "true" : "false");
									}
									if (simpleItem.has("SeriesType")) {
										if (!simpleItem.getString("SeriesType").equalsIgnoreCase("bar"))
											Simple.addAttribute("SeriesType", simpleItem.getString("SeriesType"));
									}
									if (simpleItem.has("ShowPointMarkers")) {
										Simple.addAttribute("ShowPointMarkers", simpleItem.getBoolean("ShowPointMarkers") ? "true" : "false");
									}
									Element Value = Simple.addElement("Value");
									Value.addAttribute("UniqueName", simpleItem.getJSONObject("Value").getString("UniqueName"));
									JSONObject ploItem = simpleItem.getJSONObject("PointLabelOptions");
									if (ploItem != null) {
										Element plo = Simple.addElement("PointLabelOptions");
										if (ploItem.has("ContentType")) {
											plo.addAttribute("ContentType", ploItem.getString("ContentType"));
										}
										if (ploItem.has("Orientation")) {
											plo.addAttribute("Orientation", ploItem.getString("Orientation"));
										}
										if (ploItem.has("OverlappingMode")) {
											String overlappingmode = "";
											if(ploItem.getString("OverlappingMode").equals("Stack")) {
												overlappingmode = "Reposition";
											} else {
												overlappingmode = ploItem.getString("OverlappingMode");
											}
											plo.addAttribute("OverlappingMode", overlappingmode);
										}
										if (ploItem.has("Position") && !ploItem.getString("Position").equals("outside")) {
											plo.addAttribute("Position", ploItem.getString("Position"));
										}
										if (ploItem.has("ShowForZeroValues")) {
											plo.addAttribute("ShowForZeroValues", ploItem.getBoolean("ShowForZeroValues") ? "true" : "false");
										}
//										if (ploItem.has("FillBackground")) {
//											plo.addAttribute("FillBackground", ploItem.getBoolean("FillBackground") ? "true" : "false");
//										}
//										if (ploItem.has("ShowBorder")) {
//											plo.addAttribute("ShowBorder", ploItem.getBoolean("ShowBorder") ? "true" : "false");
//										}
									}
								}
							}
							if (toJsonArray(SeriesItem, "Weighted") != null) {
								JSONArray weightedArr = toJsonArray(SeriesItem, "Weighted");
								for (int weightedIndex = 0; weightedIndex < weightedArr.length(); weightedIndex++) {
									JSONObject weightedItem = weightedArr.getJSONObject(weightedIndex);
									Element Weighted = Series.addElement("Weighted");
									Element Value = Weighted.addElement("Value");
									Element Weight = Weighted.addElement("Weight");
									Value.addAttribute("UniqueName", weightedItem.getJSONObject("Value").getString("UniqueName"));
									Weight.addAttribute("UniqueName", weightedItem.getJSONObject("Weight").getString("UniqueName"));
									
									if (weightedItem.has("IgnoreEmptyPoints")) {
										Weighted.addAttribute("IgnoreEmptyPoints", weightedItem.getBoolean("IgnoreEmptyPoints") ? "true" : "false");
									}
									if (weightedItem.has("PlotOnSecondaryAxis")) {
										Weighted.addAttribute("PlotOnSecondaryAxis", weightedItem.getBoolean("PlotOnSecondaryAxis") ? "true" : "false");
									}
									if (weightedItem.has("SeriesType")) {
										if (!weightedItem.getString("SeriesType").equalsIgnoreCase("bar"))
											Weighted.addAttribute("SeriesType", weightedItem.getString("SeriesType"));
									}
									if (weightedItem.has("ShowPointMarkers")) {
										Weighted.addAttribute("ShowPointMarkers", weightedItem.getBoolean("ShowPointMarkers") ? "true" : "false");
									}
									Value.addAttribute("UniqueName", weightedItem.getJSONObject("Value").getString("UniqueName"));
									JSONObject ploItem = weightedItem.getJSONObject("PointLabelOptions");
									if (ploItem != null) {
										Element plo = Weighted.addElement("PointLabelOptions");
										if (ploItem.has("ContentType") && !(ploItem.getString("ContentType").equals(""))) {
											plo.addAttribute("ContentType", ploItem.getString("ContentType"));
										}
										if (ploItem.has("Orientation")) {
											plo.addAttribute("Orientation", ploItem.getString("Orientation"));
										}
										if (ploItem.has("OverlappingMode")) {
											plo.addAttribute("OverlappingMode", ploItem.getString("OverlappingMode"));
										}
										if (ploItem.has("Position")) {
											plo.addAttribute("Position", ploItem.getString("Position"));
										}
										if (ploItem.has("ShowForZeroValues")) {
											plo.addAttribute("ShowForZeroValues", ploItem.getBoolean("ShowForZeroValues") ? "true" : "false");
										}
//										if (ploItem.has("FillBackground")) {
//											plo.addAttribute("FillBackground", ploItem.getBoolean("FillBackground") ? "true" : "false");
//										}
//										if (ploItem.has("ShowBorder")) {
//											plo.addAttribute("ShowBorder", ploItem.getBoolean("ShowBorder") ? "true" : "false");
//										}
									}
								}
							}
						}
						if(chartObj.has("ChartXOption")) {
							JSONObject chartXoption = chartObj.getJSONObject("ChartXOption");
							Element chartX = Chartroot.addElement("AxisX");
							if(chartXoption.has("Visible")) {
								if(chartXoption.getBoolean("Visible") != true) {
									chartX.addAttribute("Visible", "false");
									chartX.addAttribute("TitleVisible", "false");
								}
							}
							if(chartXoption.has("Title")) {
								if(!chartXoption.getString("Title").equals("")) {
									chartX.addAttribute("Title", chartXoption.getString("Title"));
								}
							}
							if(chartXoption.has("Rotation")) {
								chartX.addAttribute("Rotation", chartXoption.getInt("Rotation") + "");
							}
						}
						if(chartObj.has("ChartLegend")) {
							JSONObject chartLegendObj = chartObj.getJSONObject("ChartLegend");
							Element chartLegend = Chartroot.addElement("ChartLegend");
							if(chartLegendObj.has("Visible")) {
								chartLegend.addAttribute("Visible", chartLegendObj.getBoolean("Visible") ? "true" : "false");
							}
							if(chartLegendObj.has("IsInsidePosition")) {
								chartLegend.addAttribute("IsInsidePosition", chartLegendObj.getBoolean("IsInsidePosition") ? "true" : "false");
							}
							if(chartLegendObj.has("InsidePosition")) {
								chartLegend.addAttribute("InsidePosition", chartLegendObj.getString("InsidePosition"));
							}
							if(chartLegendObj.has("OutsidePosition")) {
								chartLegend.addAttribute("OutsidePosition", chartLegendObj.getString("OutsidePosition"));
							}
						}
					}
				}
				break;
			case "BubbleChart":
				JSONArray bubbleChartItemArray = itemObj.getJSONArray("BubbleChart");
				for(int eachChartItem = 0;eachChartItem < bubbleChartItemArray.length();eachChartItem++) {
					JSONObject chartObj = bubbleChartItemArray.getJSONObject(eachChartItem);
					JSONObject chartDataItem = chartObj.getJSONObject("DataItems");

					
					JSONObject chartPanes = chartObj.getJSONObject("Panes");

					Element Chartroot = items.addElement("BubbleChart");
					Chartroot.addAttribute("ComponentName", chartObj.getString("ComponentName"));
					Chartroot.addAttribute("Name", chartObj.getString("Name"));
					Chartroot.addAttribute("MemoText", chartObj.getString("MemoText"));
					Chartroot.addAttribute("DataSource", chartObj.getString("DataSource"));

					addInteractivityOption(chartObj, Chartroot);
					
					if (chartObj.has("IsMasterFilterCrossDataSource")) {
						if (chartObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							Chartroot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					if (chartObj.has("Rotated")) {
						if(chartObj.getBoolean("Rotated") == true) {
							Chartroot.addAttribute("Rotated","true");
						}
					}
					if(chartObj.has("ShowCaption")) {
						if(chartObj.getBoolean("ShowCaption") == false)
							Chartroot.addAttribute("ShowCaption", "false");
					}
					if(chartObj.has("FilterString")) {
						Chartroot.addAttribute("FilterString", chartObj.getString("FilterString"));
					}
					Element DataItems = Chartroot.addElement("DataItems");
					JSONArray DataItemAttr = toJsonArray(chartDataItem, "Measure");
					if (DataItemAttr != null) {
						for (int Mea = 0; Mea < DataItemAttr.length(); Mea++) {
							Element Measure = DataItems.addElement("Measure");
							Measure.addAttribute("DataMember", DataItemAttr.getJSONObject(Mea).getString("DataMember"));
							String summaryType = "";
							if(DataItemAttr.getJSONObject(Mea).has("SummaryType")) {
								switch(DataItemAttr.getJSONObject(Mea).getString("SummaryType")) {
								case "countdistinct":
									summaryType = "CountDistinct";
									break;
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}
							
							Measure.addAttribute("SummaryType",  summaryType);
							if(DataItemAttr.getJSONObject(Mea).has("Name")) {
								Measure.addAttribute("Name",  DataItemAttr.getJSONObject(Mea).getString("Name"));
							}
							Measure.addAttribute("UniqueName", DataItemAttr.getJSONObject(Mea).getString("UniqueName"));
							if(DataItemAttr.getJSONObject(Mea).has("CubeUniqueName")) {
								Measure.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Mea).getString("CubeUniqueName"));
							}
							if (DataItemAttr.getJSONObject(Mea).has("NumericFormat")) {
								Element NumericFormat = Measure.addElement("NumericFormat");
								JSONObject ChartNumericFormat = DataItemAttr.getJSONObject(Mea)
										.getJSONObject("NumericFormat");
								if (ChartNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", ChartNumericFormat.getString("FormatType"));
								if (ChartNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", ChartNumericFormat.getString("Unit"));
								if (ChartNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", ChartNumericFormat.get("Precision") + "");
								/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
								if (ChartNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", ChartNumericFormat.getString("PrecisionOption") + "");
								if (ChartNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator", ChartNumericFormat.get("IncludeGroupSeparator").toString());
							}

						}
					}

					DataItemAttr = toJsonArray(chartDataItem, "Dimension");
					if (DataItemAttr != null) {
						for (int Dim = 0; Dim < DataItemAttr.length(); Dim++) {
							Element Dimension = DataItems.addElement("Dimension");
							Dimension.addAttribute("DataMember", DataItemAttr.getJSONObject(Dim).getString("DataMember"));
							if(DataItemAttr.getJSONObject(Dim).has("Name")) {
								Dimension.addAttribute("Name",  DataItemAttr.getJSONObject(Dim).getString("Name"));
							}
							if (DataItemAttr.getJSONObject(Dim).has("SortOrder")) {
								if(DataItemAttr.getJSONObject(Dim).getString("SortOrder").equalsIgnoreCase("Descending"))
									Dimension.addAttribute("SortOrder", "Descending");
							}
							if(DataItemAttr.getJSONObject(Dim).has("SortByMeasure")) {
								Dimension.addAttribute("SortByMeasure", DataItemAttr.getJSONObject(Dim).getString("SortByMeasure"));
							}
							//2020-01-14 LSH topN 차트 저장
							if(DataItemAttr.getJSONObject(Dim).has("TopNEnabled")) {
								String TopNEnabled = "true";
								Dimension.addAttribute("TopNEnabled",TopNEnabled);
								/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
								if(DataItemAttr.getJSONObject(Dim).has("TopNOrder")) {
									Dimension.addAttribute("TopNOrder", DataItemAttr.getJSONObject(Dim).get("TopNOrder")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNCount")) {
									Dimension.addAttribute("TopNCount", DataItemAttr.getJSONObject(Dim).get("TopNCount")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNMeasure")) {
									Dimension.addAttribute("TopNMeasure", DataItemAttr.getJSONObject(Dim).get("TopNMeasure")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNShowOthers")) {
									String TopNShowOthers = "true";
									Dimension.addAttribute("TopNShowOthers",TopNShowOthers);
								}
							}
							if (DataItemAttr.getJSONObject(Dim).has("ColoringMode")) {
								Dimension.addAttribute("ColoringMode",
										DataItemAttr.getJSONObject(Dim).getString("ColoringMode"));
							}
							Dimension.addAttribute("UniqueName", DataItemAttr.getJSONObject(Dim).getString("UniqueName"));
							if(DataItemAttr.getJSONObject(Dim).has("CubeUniqueName")) {
								Dimension.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Dim).getString("CubeUniqueName"));
							}
						}
					}
					if(chartObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = chartObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = Chartroot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					if (chartObj.has("Arguments")) {
						JSONObject chartArguments = chartObj.getJSONObject("Arguments");
						JSONArray ArgumentsArr = toJsonArray(chartArguments, "Argument");
						Element Arguments = Chartroot.addElement("Arguments");
						for (int arg = 0; arg < ArgumentsArr.length(); arg++) {
							Element ArgumentsAttr = Arguments.addElement("Argument");
							ArgumentsAttr.addAttribute("UniqueName",
									ArgumentsArr.getJSONObject(arg).getString("UniqueName"));
							if(ArgumentsArr.getJSONObject(arg).has("CubeUniqueName")) {
								ArgumentsAttr.addAttribute("CubeUniqueName",  ArgumentsArr.getJSONObject(arg).getString("CubeUniqueName"));
							}
						}
					}
					
					if(chartObj.has("ColoringOption")) {
						Element ColoringOptions = Chartroot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", chartObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", chartObj.getString("UseGlobalColors"));
						JSONArray colorArray = chartObj.getJSONArray("ColorSheme");
						Element ColorSheme = Chartroot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					
					if (chartObj.has("SeriesDimensions")) {
						JSONObject chartseriesDim = chartObj.getJSONObject("SeriesDimensions");
						JSONArray SeriesDimArr = toJsonArray(chartseriesDim, "SeriesDimension");
						Element SeriesDimensions = Chartroot.addElement("SeriesDimensions");
						for (int serdim = 0; serdim < SeriesDimArr.length(); serdim++) {
							Element SeriesDimensionAttr = SeriesDimensions.addElement("SeriesDimension");
							SeriesDimensionAttr.addAttribute("UniqueName",
									SeriesDimArr.getJSONObject(serdim).getString("UniqueName"));
							if(SeriesDimArr.getJSONObject(serdim).has("CubeUniqueName")) {
								SeriesDimensionAttr.addAttribute("CubeUniqueName",  SeriesDimArr.getJSONObject(serdim).getString("CubeUniqueName"));
							}
						}
					}
					
					JSONArray PanesArr = toJsonArray(chartPanes, "Pane");
					Element Panes = Chartroot.addElement("Panes");
					Element AxisY = null;
					for (int pane = 0; pane < PanesArr.length(); pane++) {
						JSONObject PaneObj = PanesArr.getJSONObject(pane);
						Element Pane = Panes.addElement("Pane");
						Pane.addAttribute("Name", PaneObj.getString("Name"));
						if(chartObj.has("ChartYOption")) {
							JSONObject chartYoption = chartObj.getJSONObject("ChartYOption");
							AxisY = Pane.addElement("AxisY");
							if (chartYoption.has("Visible")) {
								if (chartYoption.getBoolean("Visible") != true)
									AxisY.addAttribute("Visible", "false");
							}
							if (chartYoption.has("Title")) {
								if (!chartYoption.getString("Title").equals("")) {
									AxisY.addAttribute("Title", chartYoption.getString("Title"));
								}
							}
							if (chartYoption.has("ShowZero")) {
								AxisY.addAttribute("ShowZero", chartYoption.getBoolean("ShowZero") ? "true" : "false");
							}
							if (chartYoption.has("FormatType") || chartYoption.has("Precision") || chartYoption.has("Unit") || chartYoption.has("Separator")) {
								Element numFormat = AxisY.addElement("NumericFormat");
								if (chartYoption.has("FormatType")) {
									numFormat.addAttribute("FormatType", chartYoption.getString("FormatType"));
								}
								if (chartYoption.has("Precision")) {
									numFormat.addAttribute("Precision", chartYoption.getInt("Precision") + "");
								}
								/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
								if (chartYoption.has("PrecisionOption")) {
									numFormat.addAttribute("PrecisionOption", chartYoption.getString("PrecisionOption") + "");
								}
								if (chartYoption.has("Unit")) {
									numFormat.addAttribute("Unit", chartYoption.getString("Unit"));
								}
								if (chartYoption.has("Separator")) {
									numFormat.addAttribute("IncludeGroupSeparator", chartYoption.getBoolean("Separator") ? "true" : "false");
								}
							}
						}
						
						Element Series = Pane.addElement("Series");
						JSONArray SeriesArr = toJsonArray(PaneObj, "Series");
						for (int series = 0; series < SeriesArr.length(); series++) {
							JSONObject SeriesItem = SeriesArr.getJSONObject(series);
							if (toJsonArray(SeriesItem, "Simple") != null) {
								JSONArray simpleArr = toJsonArray(SeriesItem, "Simple");
								for (int simple = 0; simple < simpleArr.length(); simple++) {
									JSONObject simpleItem = simpleArr.getJSONObject(simple);
									
									Element Simple = Series.addElement("Simple");
									if (simpleItem.has("IgnoreEmptyPoints")) {
										Simple.addAttribute("IgnoreEmptyPoints", simpleItem.getBoolean("IgnoreEmptyPoints") ? "true" : "false");
									}
									if (simpleItem.has("PlotOnSecondaryAxis")) {
										Simple.addAttribute("PlotOnSecondaryAxis", simpleItem.getBoolean("PlotOnSecondaryAxis") ? "true" : "false");
									}
									if (simpleItem.has("SeriesType")) {
										if (!simpleItem.getString("SeriesType").equalsIgnoreCase("bar"))
											Simple.addAttribute("SeriesType", simpleItem.getString("SeriesType"));
									}
									if (simpleItem.has("ShowPointMarkers")) {
										Simple.addAttribute("ShowPointMarkers", simpleItem.getBoolean("ShowPointMarkers") ? "true" : "false");
									}
									Element Value = Simple.addElement("Value");
									Value.addAttribute("UniqueName", simpleItem.getJSONObject("Value").getString("UniqueName"));
									JSONObject ploItem = simpleItem.getJSONObject("PointLabelOptions");
									if (ploItem != null) {
										Element plo = Simple.addElement("PointLabelOptions");
										if (ploItem.has("ContentType") && !(ploItem.getString("ContentType").equals(""))) {
											plo.addAttribute("ContentType", ploItem.getString("ContentType"));
										}
										if (ploItem.has("Orientation")) {
											plo.addAttribute("Orientation", ploItem.getString("Orientation"));
										}
										if (ploItem.has("OverlappingMode")) {
											String overlappingmode = "";
											if(ploItem.getString("OverlappingMode").equals("Stack")) {
												overlappingmode = "Reposition";
											} else {
												overlappingmode = ploItem.getString("OverlappingMode");
											}
											plo.addAttribute("OverlappingMode", overlappingmode);
										}
										if (ploItem.has("Position") && !ploItem.getString("Position").equals("outside")) {
											plo.addAttribute("Position", ploItem.getString("Position"));
										}
										if (ploItem.has("ShowForZeroValues")) {
											plo.addAttribute("ShowForZeroValues", ploItem.getBoolean("ShowForZeroValues") ? "true" : "false");
										}
//										if (ploItem.has("FillBackground")) {
//											plo.addAttribute("FillBackground", ploItem.getBoolean("FillBackground") ? "true" : "false");
//										}
//										if (ploItem.has("ShowBorder")) {
//											plo.addAttribute("ShowBorder", ploItem.getBoolean("ShowBorder") ? "true" : "false");
//										}
									}
								}
							}
							if (toJsonArray(SeriesItem, "Weighted") != null) {
								JSONArray weightedArr = toJsonArray(SeriesItem, "Weighted");
								for (int weightedIndex = 0; weightedIndex < weightedArr.length(); weightedIndex++) {
									JSONObject weightedItem = weightedArr.getJSONObject(weightedIndex);
									Element Weighted = Series.addElement("Weighted");
									Element Value = Weighted.addElement("Value");
									Element Weight = Weighted.addElement("Weight");
									Value.addAttribute("UniqueName", weightedItem.getJSONObject("Value").getString("UniqueName"));
									Weight.addAttribute("UniqueName", weightedItem.getJSONObject("Weight").getString("UniqueName"));
									
									if (weightedItem.has("IgnoreEmptyPoints")) {
										Weighted.addAttribute("IgnoreEmptyPoints", weightedItem.getBoolean("IgnoreEmptyPoints") ? "true" : "false");
									}
									if (weightedItem.has("PlotOnSecondaryAxis")) {
										Weighted.addAttribute("PlotOnSecondaryAxis", weightedItem.getBoolean("PlotOnSecondaryAxis") ? "true" : "false");
									}
									if (weightedItem.has("SeriesType")) {
										if (!weightedItem.getString("SeriesType").equalsIgnoreCase("bar"))
											Weighted.addAttribute("SeriesType", weightedItem.getString("SeriesType"));
									}
									if (weightedItem.has("ShowPointMarkers")) {
										Weighted.addAttribute("ShowPointMarkers", weightedItem.getBoolean("ShowPointMarkers") ? "true" : "false");
									}
									Value.addAttribute("UniqueName", weightedItem.getJSONObject("Value").getString("UniqueName"));
									JSONObject ploItem = weightedItem.getJSONObject("PointLabelOptions");
									if (ploItem != null) {
										Element plo = Weighted.addElement("PointLabelOptions");
										if (ploItem.has("ContentType") && !(ploItem.getString("ContentType").equals(""))) {
											plo.addAttribute("ContentType", ploItem.getString("ContentType"));
										}
										if (ploItem.has("Orientation")) {
											plo.addAttribute("Orientation", ploItem.getString("Orientation"));
										}
										if (ploItem.has("OverlappingMode")) {
											plo.addAttribute("OverlappingMode", ploItem.getString("OverlappingMode"));
										}
										if (ploItem.has("Position")) {
											plo.addAttribute("Position", ploItem.getString("Position"));
										}
										if (ploItem.has("ShowForZeroValues")) {
											plo.addAttribute("ShowForZeroValues", ploItem.getBoolean("ShowForZeroValues") ? "true" : "false");
										}
//										if (ploItem.has("FillBackground")) {
//											plo.addAttribute("FillBackground", ploItem.getBoolean("FillBackground") ? "true" : "false");
//										}
//										if (ploItem.has("ShowBorder")) {
//											plo.addAttribute("ShowBorder", ploItem.getBoolean("ShowBorder") ? "true" : "false");
//										}
									}
								}
							}
						}
						if(chartObj.has("ChartXOption")) {
							JSONObject chartXoption = chartObj.getJSONObject("ChartXOption");
							Element chartX = Chartroot.addElement("AxisX");
							if(chartXoption.has("Visible")) {
								if(chartXoption.getBoolean("Visible") != true) {
									chartX.addAttribute("Visible", "false");
									chartX.addAttribute("TitleVisible", "false");
								}
							}
							if(chartXoption.has("Title")) {
								if(!chartXoption.getString("Title").equals("")) {
									chartX.addAttribute("Title", chartXoption.getString("Title"));
								}
							}
							if(chartXoption.has("Rotation")) {
								chartX.addAttribute("Rotation", chartXoption.getInt("Rotation") + "");
							}
						}
						if(chartObj.has("ChartLegend")) {
							JSONObject chartLegendObj = chartObj.getJSONObject("ChartLegend");
							Element chartLegend = Chartroot.addElement("ChartLegend");
							if(chartLegendObj.has("Visible")) {
								chartLegend.addAttribute("Visible", chartLegendObj.getBoolean("Visible") ? "true" : "false");
							}
							if(chartLegendObj.has("IsInsidePosition")) {
								chartLegend.addAttribute("IsInsidePosition", chartLegendObj.getBoolean("IsInsidePosition") ? "true" : "false");
							}
							if(chartLegendObj.has("InsidePosition")) {
								chartLegend.addAttribute("InsidePosition", chartLegendObj.getString("InsidePosition"));
							}
							if(chartLegendObj.has("OutsidePosition")) {
								chartLegend.addAttribute("OutsidePosition", chartLegendObj.getString("OutsidePosition"));
							}
						}
					}
				}
				break;
			case "Grid":
				JSONArray gridItemArray = itemObj.getJSONArray("Grid");
				for(int eachGridItem =0;eachGridItem<gridItemArray.length();eachGridItem++) {
					JSONObject GridObj = gridItemArray.getJSONObject(eachGridItem);

					Element Gridroot = items.addElement("Grid");
					Gridroot.addAttribute("ComponentName", GridObj.getString("ComponentName"));
					Gridroot.addAttribute("Name", GridObj.getString("Name"));
					Gridroot.addAttribute("MemoText", GridObj.getString("MemoText"));
					Gridroot.addAttribute("DataSource", GridObj.getString("DataSource"));
					if(GridObj.has("ShowCaption")) {
						if(GridObj.getBoolean("ShowCaption") == false)
							Gridroot.addAttribute("ShowCaption", "false");
					}
					if (GridObj.has("InteractivityOptions")) {
						String masterFilterMode = "";
						boolean ignoreMasterFilter = false;
						if(!GridObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode").equals("Off")) {
//							Element InteractivityOptions = Gridroot.addElement("InteractivityOptions");
//							InteractivityOptions.addAttribute("MasterFilterMode",
//									GridObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode"));
							masterFilterMode = GridObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode");
						}
						if(GridObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters") == true) {
//							InteractivityOptions.addAttribute("MasterFilterMode",
//									chartObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode"));
							ignoreMasterFilter = GridObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters");
						}
						
						if(!masterFilterMode.equals("") || ignoreMasterFilter == true) {
							Element InteractivityOptions = Gridroot.addElement("InteractivityOptions");
							if(!masterFilterMode.equals("")) {
								InteractivityOptions.addAttribute("MasterFilterMode",masterFilterMode);
							}
							if(ignoreMasterFilter == true) {
								InteractivityOptions.addAttribute("IgnoreMasterFilters","true");
							}
						}
					}
					if (GridObj.has("IsMasterFilterCrossDataSource")) {
						if (GridObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							Gridroot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					if(GridObj.has("FilterString")) {
						Gridroot.addAttribute("FilterString", GridObj.getString("FilterString"));
					}
					
					if(GridObj.has("SparklineArgument")) {
						Element sparkLineArgument = Gridroot.addElement("SparklineArgument");
						sparkLineArgument.addAttribute("DefaultId", GridObj.getJSONObject("SparklineArgument").getString("UniqueName"));
					}
					
					JSONObject gridDataItems = GridObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(gridDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(gridDataItems, "Measure");

					Element GridDataItems = Gridroot.addElement("DataItems");
					
					if(DimDataItems == null) {
						DimDataItems = new JSONArray();
					}
					if(MeaDataItems == null) {
						MeaDataItems = new JSONArray();
					}
					
					if(DimDataItems.length() > 0) {
						for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
							JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
							Element DimGridAttr = GridDataItems.addElement("Dimension");
							DimGridAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
							if(dimdata.has("Name")) {
								DimGridAttr.addAttribute("Name",  dimdata.getString("Name"));
							}
							/*dogfoot 통계분석 container Type 구분 shlim 20201103*/
							if(dimdata.has("ContainerType")) {
								DimGridAttr.addAttribute("ContainerType",  dimdata.getString("ContainerType"));
							}
							DimGridAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
							if(dimdata.has("CubeUniqueName")) {
								DimGridAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
							}
							if(dimdata.has("SortOrder")) {
								if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
									DimGridAttr.addAttribute("SortOrder", "Descending");
								}
							}
							if(dimdata.has("SortByMeasure")) {
								DimGridAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
							}
							//2020-01-14 LSH topN 그리드 저장
							if(dimdata.has("TopNEnabled")) {
								String TopNEnabled = "true";
								DimGridAttr.addAttribute("TopNEnabled",TopNEnabled);
								/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
								if(dimdata.has("TopNOrder")) {
									DimGridAttr.addAttribute("TopNOrder", dimdata.get("TopNOrder")+"");
								}
								if(dimdata.has("TopNCount")) {
									DimGridAttr.addAttribute("TopNCount", dimdata.get("TopNCount")+"");
								}
								if(dimdata.has("TopNMeasure")) {
									DimGridAttr.addAttribute("TopNMeasure", dimdata.get("TopNMeasure")+"");
								}
								if(dimdata.has("TopNShowOthers")) {
									String TopNShowOthers = "true";
									DimGridAttr.addAttribute("TopNShowOthers",TopNShowOthers);
								}
							}
							
						}
					}
					
					if(GridObj.has("ColoringOption")) {
						Element ColoringOptions = Gridroot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", GridObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", GridObj.getString("UseGlobalColors"));
						JSONArray colorArray = GridObj.getJSONArray("ColorSheme");
						Element ColorSheme = Gridroot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					
					if(GridObj.has("Palette")) {
						Gridroot.addAttribute("Palette", GridObj.getString("Palette"));
					}
					
					/*dogfoot 그리드 헤더 추가 기능 shlim 20210317*/
					if(GridObj.has("HeaderList")) {
						Gridroot.addAttribute("HeaderList", GridObj.getString("HeaderList"));
					}
					
					if(MeaDataItems.length() > 0) {
						for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
							JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
							Element MeaGridAttr = GridDataItems.addElement("Measure");
							MeaGridAttr.addAttribute("DataMember", meadata.getString("DataMember"));
							String summaryType = "";
							if(meadata.has("SummaryType")) {
								switch(meadata.getString("SummaryType")) {
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}
							if(meadata.has("Name")) {
								MeaGridAttr.addAttribute("Name",  meadata.getString("Name"));
							}
							/*dogfoot 통계 분석 추가 shlim 20201103*/
							if(meadata.has("ContainerType")) {
								MeaGridAttr.addAttribute("ContainerType",  meadata.getString("ContainerType"));
							}
							MeaGridAttr.addAttribute("SummaryType",  summaryType);
							if (meadata.has("NumericFormat")) {
								Element NumericFormat = MeaGridAttr.addElement("NumericFormat");
								JSONObject GridNumericFormat = meadata.getJSONObject("NumericFormat");
								if (GridNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", GridNumericFormat.getString("FormatType"));
								if (GridNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", GridNumericFormat.get("Precision") + "");
								/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
								if (GridNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", GridNumericFormat.getString("PrecisionOption") + "");
								if (GridNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", GridNumericFormat.getString("Unit"));
//								if (GridNumericFormat.has("SuffixEnabled")) {
//									NumericFormat.addAttribute("SuffixEnabled", GridNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
//								}
//								if (GridNumericFormat.has("Suffix")) {
//									Element Suffix = NumericFormat.addElement("Suffix");
//									JSONObject suffix = GridNumericFormat.getJSONObject("Suffix");
//									Suffix.addAttribute("O", suffix.getString("O"));
//									Suffix.addAttribute("K", suffix.getString("K"));
//									Suffix.addAttribute("M", suffix.getString("M"));
//									Suffix.addAttribute("B", suffix.getString("B"));
//								}
								if (GridNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator",
											GridNumericFormat.get("IncludeGroupSeparator").toString());
							}
							MeaGridAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
							if(meadata.has("CubeUniqueName")) {
								MeaGridAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
							}
//							if(meadata.has("SortOrder")) {
//								if(meadata.getString("SortOrder").equalsIgnoreCase("descending")) {
//									MeaGridAttr.addAttribute("SortOrder", "Descending");
//								}
//							}
						}
					}
					

					ArrayList<JSONObject> columnOrdering = new ArrayList<>();
					JSONObject GridColumnsObj = GridObj.getJSONObject("GridColumns");
					JSONArray DimColumnArr = toJsonArray(GridColumnsObj, "GridDimensionColumn");
					JSONArray MeaColumnArr = toJsonArray(GridColumnsObj, "GridMeasureColumn");
					JSONArray SparklineColumnArr = toJsonArray(GridColumnsObj, "GridSparklineColumn");
					JSONArray GridDeltaColumnArr = toJsonArray(GridColumnsObj, "GridDeltaColumn");
					
					int columnSize = DimDataItems.length() + MeaDataItems.length();

					Element GridColumns = Gridroot.addElement("GridColumns");
					
					if(DimColumnArr == null) {
						DimColumnArr = new JSONArray();
					}
					if(MeaColumnArr == null) {
						MeaColumnArr = new JSONArray();
					}
					/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 - null 검사 dogfoot*/
					if(SparklineColumnArr == null) {
						SparklineColumnArr = new JSONArray();
					}
					if(GridDeltaColumnArr == null) {
						GridDeltaColumnArr = new JSONArray();
					}
					if(GridObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = GridObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = Gridroot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					for (int idx = 0; idx < columnSize; idx++) {
						for (int dimIdx = 0; dimIdx < DimColumnArr.length(); dimIdx++) {
							if (idx == DimColumnArr.getJSONObject(dimIdx).getInt("wiseOrder")) {
								JSONObject dimObj = new JSONObject();
								dimObj.put("Dimension", DimColumnArr.getJSONObject(dimIdx).getJSONObject("Dimension"));
								columnOrdering.add(dimObj);
								break;
							}
						}
						for (int meaIdx = 0; meaIdx < MeaColumnArr.length(); meaIdx++) {
							if (idx == MeaColumnArr.getJSONObject(meaIdx).getInt("wiseOrder")) {
								JSONObject meaObj = new JSONObject();
								meaObj.put("Measure", MeaColumnArr.getJSONObject(meaIdx).getJSONObject("Measure"));
								meaObj.put("DisplayMode", MeaColumnArr.getJSONObject(meaIdx).getString("displayMode"));
								columnOrdering.add(meaObj);
								break;
							}
						}
						for (int sparkIdx = 0; sparkIdx < SparklineColumnArr.length(); sparkIdx++) {
							if (idx == SparklineColumnArr.getJSONObject(sparkIdx).getInt("wiseOrder")) {
								JSONObject sparklineObj = new JSONObject();
								sparklineObj.put("Sparkline", SparklineColumnArr.getJSONObject(sparkIdx).getJSONObject("SparklineValue"));
								if (SparklineColumnArr.getJSONObject(sparkIdx).has("SparklineOptions")){
									sparklineObj.put("SparklineOptions", SparklineColumnArr.getJSONObject(sparkIdx).getJSONObject("SparklineOptions"));	
								}
								columnOrdering.add(sparklineObj);
								break;
							}
						}
						
						for (int deltaIdx = 0; deltaIdx < GridDeltaColumnArr.length(); deltaIdx++) {
							if (idx == GridDeltaColumnArr.getJSONObject(deltaIdx).getInt("wiseOrder")) {
								JSONObject deltaObj = new JSONObject();
								JSONObject deltaDetailObj = new JSONObject();
								deltaDetailObj.put("ActualValue", GridDeltaColumnArr.getJSONObject(deltaIdx).getJSONObject("ActualValue"));
								deltaDetailObj.put("TargetValue", GridDeltaColumnArr.getJSONObject(deltaIdx).getJSONObject("TargetValue"));
								
								deltaObj.put("Delta", deltaDetailObj);
								
								if (GridDeltaColumnArr.getJSONObject(deltaIdx).has("DeltaOptions")){
									if (GridDeltaColumnArr.getJSONObject(deltaIdx).getJSONObject("DeltaOptions").has("AlwaysShowZeroLevel")){
										deltaObj.put("AlwaysShowZeroLevel", GridDeltaColumnArr.getJSONObject(deltaIdx).getJSONObject("DeltaOptions").getString("AlwaysShowZeroLevel"));
									}
									deltaObj.put("DeltaOptions", GridDeltaColumnArr.getJSONObject(deltaIdx).getJSONObject("DeltaOptions"));	
								}
								columnOrdering.add(deltaObj);
								break;
							}
						}
					}
					int columnIdx=0;
					for (JSONObject tempObj : columnOrdering) {
						Element GridColumn = null;
						if (tempObj.has("Dimension")) {
							GridColumn = GridColumns.addElement("GridDimensionColumn");
							Element Column = GridColumn.addElement("Dimension");
							Column.addAttribute("UniqueName",
									tempObj.getJSONObject("Dimension").getString("UniqueName"));
						} else if (tempObj.has("Measure")) {
							GridColumn = GridColumns.addElement("GridMeasureColumn");
							GridColumn.addAttribute("DisplayMode", tempObj.getString("DisplayMode"));
							Element Column = GridColumn.addElement("Measure");
							Column.addAttribute("UniqueName", tempObj.getJSONObject("Measure").getString("UniqueName"));
						} else if (tempObj.has("Sparkline")) {
							GridColumn = GridColumns.addElement("GridSparklineColumn");
							Element Column = GridColumn.addElement("SparklineValue");
							Column.addAttribute("UniqueName", tempObj.getJSONObject("Sparkline").getString("UniqueName"));
							if(tempObj.has("SparklineOptions")) {
								Element SparkOptions = GridColumn.addElement("SparklineOptions");
								if(tempObj.getJSONObject("SparklineOptions").has("HighlightMinMaxPoints")) {
									SparkOptions.addAttribute("HighlightMinMaxPoints", tempObj.getJSONObject("SparklineOptions").getString("HighlightMinMaxPoints"));
								}
								if(tempObj.getJSONObject("SparklineOptions").has("HighlightStartEndPoints")) {
									SparkOptions.addAttribute("HighlightStartEndPoints", tempObj.getJSONObject("SparklineOptions").getString("HighlightStartEndPoints"));
								}
							}
						}else if (tempObj.has("Delta")) {
							GridColumn = GridColumns.addElement("GridDeltaColumn");
							Element ActualValueColumn = GridColumn.addElement("ActualValue");
							Element TargetValueColumn = GridColumn.addElement("TargetValue");
							ActualValueColumn.addAttribute("UniqueName", tempObj.getJSONObject("Delta").getJSONObject("ActualValue").getString("UniqueName"));
							TargetValueColumn.addAttribute("UniqueName", tempObj.getJSONObject("Delta").getJSONObject("TargetValue").getString("UniqueName"));
							if(tempObj.has("AlwaysShowZeroLevel")) {
								GridColumn.addAttribute("AlwaysShowZeroLevel", tempObj.getString("AlwaysShowZeroLevel"));
							}
							
							if(tempObj.has("DeltaOptions")) {
								Element DeltaOptions = GridColumn.addElement("DeltaOptions");
								if(tempObj.getJSONObject("DeltaOptions").has("ResultIndicationMode")) {
									DeltaOptions.addAttribute("ResultIndicationMode", tempObj.getJSONObject("DeltaOptions").getString("ResultIndicationMode"));
								}
								if(tempObj.getJSONObject("DeltaOptions").has("ResultIndicationThreshold")) {
									DeltaOptions.addAttribute("ResultIndicationThreshold", tempObj.getJSONObject("DeltaOptions").getString("ResultIndicationThreshold"));
								}
								if(tempObj.getJSONObject("DeltaOptions").has("ResultIndicationThresholdType")) {
									DeltaOptions.addAttribute("ResultIndicationThresholdType", tempObj.getJSONObject("DeltaOptions").getString("ResultIndicationThresholdType"));
								}
								if(tempObj.getJSONObject("DeltaOptions").has("ValueType")) {
									DeltaOptions.addAttribute("ValueType", tempObj.getJSONObject("DeltaOptions").getString("ValueType"));
								}
							}
						}
						if(GridObj.has("GridOptions")) {
							JSONObject gridOption = GridObj.getJSONObject("GridOptions");
							if(gridOption.has("ColumnWidthMode")) {
								if(gridOption.getString("ColumnWidthMode").equalsIgnoreCase("Manual")) {
									if(GridObj.has("gridWidth")) {
										JSONArray gridWidthArr = GridObj.getJSONArray("gridWidth");
										GridColumn.addAttribute("Weight", gridWidthArr.getString(columnIdx).replace("%", ""));
										columnIdx++;
									}
								}
							}
						}
					}
					Element GridOptions = Gridroot.addElement("GridOptions");
					if(GridObj.has("GridOptions")) {
						JSONObject gridOption = GridObj.getJSONObject("GridOptions");
						if(gridOption.has("AllowGridCellMerge")) {
							if(gridOption.getBoolean("AllowGridCellMerge") == true) {
								GridOptions.addAttribute("AllowGridCellMerge","true");
							}
						}
						
						if(gridOption.has("ShowColumnHeaders")) {
							if(gridOption.getBoolean("ShowColumnHeaders") == false) {
								GridOptions.addAttribute("ShowColumnHeaders","false");
							}
						}
						
						if(gridOption.has("ColumnWidthMode")) {
							if(gridOption.getString("ColumnWidthMode").equalsIgnoreCase("Manual")) {
								GridOptions.addAttribute("ColumnWidthMode","Manual");
							}
							
						}
						if(gridOption.has("WordWrap")) {
							if(gridOption.getBoolean("WordWrap") == true) {
								GridOptions.addAttribute("WordWrap","true");
							}
							
						}
						if(gridOption.has("EnableBandedRows")) {
							if(gridOption.getBoolean("EnableBandedRows") == true) {
								GridOptions.addAttribute("EnableBandedRows","true");
							}
						}
						
						if(gridOption.has("ShowColumnLines")) {
							if(gridOption.getBoolean("ShowColumnLines") == false) {
								GridOptions.addAttribute("ShowVerticalLines","false");
							}
						}
						if(gridOption.has("ShowRowLines")) {
							if(gridOption.getBoolean("ShowRowLines") == false) {
								GridOptions.addAttribute("ShowHorizontalLines","false");
							}
						}
						/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
						if(gridOption.has("PagingEnabled")) {
							GridOptions.addAttribute("PagingEnabled", gridOption.getBoolean("PagingEnabled") ? "true" : "false");
						}
						if(gridOption.has("PagingDesc")) {
							GridOptions.addAttribute("PagingDesc", gridOption.getString("PagingDesc"));
						}
						if(gridOption.has("PagingDefault")) {
							/* DOGFOOT ktkang 그리드 페이징 저장 오류 수정  20200904 */
							GridOptions.addAttribute("PagingDefault", gridOption.getInt("PagingDefault") + "");
						}
						if(gridOption.has("PagingSizeEnabled")) {
							GridOptions.addAttribute("PagingSizeEnabled", gridOption.getBoolean("PagingSizeEnabled") ? "true" : "false");
						}
						if (gridOption.has("PagingSet")) {
							Element Suffix = GridOptions.addElement("PagingSet");
							JSONObject suffix = gridOption.getJSONObject("PagingSet");
							/* DOGFOOT ktkang 그리드 페이징 저장 오류 수정  20200904 */
							Suffix.addAttribute("Fir", suffix.getInt("Fir") + "");
							Suffix.addAttribute("Sec", suffix.getInt("Sec") + "");
							Suffix.addAttribute("Thi", suffix.getInt("Thi") + "");
						}
					}
				}
				break;
			case "Pie":
				JSONArray PieItemArray = itemObj.getJSONArray("Pie");
				for(int eachPieItem = 0; eachPieItem<PieItemArray.length();eachPieItem++) {
					JSONObject PieObj = PieItemArray.getJSONObject(eachPieItem);
					Element Pieroot = items.addElement("Pie");
					Pieroot.addAttribute("ComponentName", PieObj.getString("ComponentName"));
					Pieroot.addAttribute("Name", PieObj.getString("Name"));
					Pieroot.addAttribute("MemoText", PieObj.getString("MemoText"));
					Pieroot.addAttribute("DataSource", PieObj.getString("DataSource"));
					if(PieObj.has("PieType")) {
						if(!PieObj.getString("PieType").equalsIgnoreCase("Pie")) {
							Pieroot.addAttribute("PieType", "Donut");
						}
					}
					addInteractivityOption(PieObj, Pieroot);
					
					if (PieObj.has("IsMasterFilterCrossDataSource")) {
						if (PieObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							Pieroot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					
					if(PieObj.has("Legend")) {
						JSONObject LegendObject = PieObj.getJSONObject("Legend");
						Element FunnelLegend = Pieroot.addElement("Legend");
						FunnelLegend.addAttribute("Visible", LegendObject.getBoolean("Visible") == true? "true" : "false");
						FunnelLegend.addAttribute("Position", LegendObject.getString("Position"));
					}
					
					if(PieObj.has("LabelContentType")) {
						if(!PieObj.getString("LabelContentType").equalsIgnoreCase("ArgumentAndPercent")) {
							Pieroot.addAttribute("LabelContentType", PieObj.getString("LabelContentType"));
						}
					}
					if(PieObj.has("TooltipContentType")) {
						if(!PieObj.getString("TooltipContentType").equalsIgnoreCase("ArgumentValueAndPercent")) {
							Pieroot.addAttribute("TooltipContentType", PieObj.getString("TooltipContentType"));
						}
					}
					if(PieObj.has("ShowCaption")) {
						if(PieObj.getBoolean("ShowCaption") == false)
							Pieroot.addAttribute("ShowCaption", "false");
					}
					if(PieObj.has("LabelPosition")) {
						if(PieObj.getString("LabelPosition").equals("Inside")) {
							Pieroot.addAttribute("LabelPosition", "Inside");
						}
					}
					if(PieObj.has("FilterString")) {
						Pieroot.addAttribute("FilterString", PieObj.getString("FilterString"));
					}
					JSONObject pieDataItems = PieObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(pieDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(pieDataItems, "Measure");
					Element PieDataItems = Pieroot.addElement("DataItems");
					for(int dimDataIdx = 0; dimDataIdx<DimDataItems.length();dimDataIdx++) {
						JSONObject dimdata = DimDataItems.getJSONObject(dimDataIdx);
						Element DimPieAttr = PieDataItems.addElement("Dimension");
						DimPieAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						if(dimdata.has("Name")) {
							DimPieAttr.addAttribute("Name",  dimdata.getString("Name"));
						}
						DimPieAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimPieAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
						if(dimdata.has("SortOrder")) {
							if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
								DimPieAttr.addAttribute("SortOrder", "Descending");
							}
						}
						if(dimdata.has("SortByMeasure")) {
							DimPieAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
						}
						//2020-01-14 LSH topN 파이 저장
						if(dimdata.has("TopNEnabled")) {
							String TopNEnabled = "true";
							DimPieAttr.addAttribute("TopNEnabled",TopNEnabled);
							/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
							if(dimdata.has("TopNOrder")) {
								DimPieAttr.addAttribute("TopNOrder", dimdata.get("TopNOrder")+"");
							}
							if(dimdata.has("TopNCount")) {
								DimPieAttr.addAttribute("TopNCount", dimdata.get("TopNCount")+"");
							}
							if(dimdata.has("TopNMeasure")) {
								DimPieAttr.addAttribute("TopNMeasure", dimdata.get("TopNMeasure")+"");
							}
							if(dimdata.has("TopNShowOthers")) {
								String TopNShowOthers = "true";
								DimPieAttr.addAttribute("TopNShowOthers",TopNShowOthers);
							}
						}
					}
					
					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
						Element MeaPieAttr = PieDataItems.addElement("Measure");
						MeaPieAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							MeaPieAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						MeaPieAttr.addAttribute("SummaryType",  summaryType);
						MeaPieAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							MeaPieAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
						if (meadata.has("NumericFormat")) {
							Element NumericFormat = MeaPieAttr.addElement("NumericFormat");
							JSONObject PieNumericFormat = meadata.getJSONObject("NumericFormat");
							if (PieNumericFormat.has("FormatType"))
								NumericFormat.addAttribute("FormatType", PieNumericFormat.getString("FormatType"));
							if (PieNumericFormat.has("Precision"))
								NumericFormat.addAttribute("Precision", PieNumericFormat.get("Precision") + "");
							/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
							if (PieNumericFormat.has("PrecisionOption"))
								NumericFormat.addAttribute("PrecisionOption", PieNumericFormat.getString("PrecisionOption") + "");
							if (PieNumericFormat.has("Unit"))
								NumericFormat.addAttribute("Unit", PieNumericFormat.getString("Unit"));
//							if (PieNumericFormat.has("SuffixEnabled")) {
//								NumericFormat.addAttribute("SuffixEnabled", PieNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
//							}
//							if (PieNumericFormat.has("Suffix")) {
//								Element Suffix = NumericFormat.addElement("Suffix");
//								JSONObject suffix = PieNumericFormat.getJSONObject("Suffix");
//								Suffix.addAttribute("O", suffix.getString("O"));
//								Suffix.addAttribute("K", suffix.getString("K"));
//								Suffix.addAttribute("M", suffix.getString("M"));
//								Suffix.addAttribute("B", suffix.getString("B"));
//							}
							if (PieNumericFormat.has("IncludeGroupSeparator"))
								NumericFormat.addAttribute("IncludeGroupSeparator",
										PieNumericFormat.get("IncludeGroupSeparator").toString());
						}
//						if(meadata.has("SortOrder")) {
//							if(meadata.getString("SortOrder").equalsIgnoreCase("descending")) {
//								MeaPieAttr.addAttribute("SortOrder", "Descending");
//							}
//						}
					}
					if(PieObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = PieObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = Pieroot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					if (PieObj.has("Arguments")) {
						JSONObject PieArguments = PieObj.getJSONObject("Arguments");
						JSONArray ArgumentsArr = toJsonArray(PieArguments, "Argument");
						if(ArgumentsArr.length() >0) {
							Element Arguments = Pieroot.addElement("Arguments");
							for (int arg = 0; arg < ArgumentsArr.length(); arg++) {
								Element ArgumentsAttr = Arguments.addElement("Argument");
								ArgumentsAttr.addAttribute("UniqueName",ArgumentsArr.getJSONObject(arg).getString("UniqueName"));
								if(ArgumentsArr.getJSONObject(arg).has("CubeUniqueName")) {
									ArgumentsAttr.addAttribute("CubeUniqueName",  ArgumentsArr.getJSONObject(arg).getString("CubeUniqueName"));
								}
							}
						}
					}
					if(PieObj.has("ColoringOption")) {
						Element ColoringOptions = Pieroot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", PieObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", PieObj.getString("UseGlobalColors"));
						JSONArray colorArray = PieObj.getJSONArray("ColorSheme");
						Element ColorSheme = Pieroot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					
					if (PieObj.has("SeriesDimensions")) {
						JSONObject PieSeriesDim = PieObj.getJSONObject("SeriesDimensions");
						JSONArray SeriesDimArr = toJsonArray(PieSeriesDim, "SeriesDimension");
						if(SeriesDimArr.length() >0) {
							Element SeriesDimensions = Pieroot.addElement("SeriesDimensions");
							for (int serdim = 0; serdim < SeriesDimArr.length(); serdim++) {
								Element SeriesDimensionAttr = SeriesDimensions.addElement("SeriesDimension");
								SeriesDimensionAttr.addAttribute("UniqueName",SeriesDimArr.getJSONObject(serdim).getString("UniqueName"));
								if(SeriesDimArr.getJSONObject(serdim).has("CubeUniqueName")) {
									SeriesDimensionAttr.addAttribute("CubeUniqueName",  SeriesDimArr.getJSONObject(serdim).getString("CubeUniqueName"));
								}
							}
						}
					}
					
					
					JSONObject PieValuesMea = PieObj.getJSONObject("Values");
					JSONArray PieValArr = toJsonArray(PieValuesMea, "Value");
					Element ValuesMeasures = Pieroot.addElement("Values");
					for(int valmea = 0; valmea<PieValArr.length();valmea++) {
						Element ValueMeasureAttr = ValuesMeasures.addElement("Value");
						ValueMeasureAttr.addAttribute("UniqueName", PieValArr.getJSONObject(valmea).getString("UniqueName"));
					}
				}
				break;
			case "Pivot":
				JSONArray PivotItemArray = itemObj.getJSONArray("Pivot");
				for(int eachPivotItem =0;eachPivotItem<PivotItemArray.length();eachPivotItem++) {
					JSONObject PivotObj = PivotItemArray.getJSONObject(eachPivotItem);
					Element Pivotroot = items.addElement("Pivot");
					Pivotroot.addAttribute("ComponentName", PivotObj.getString("ComponentName"));
					Pivotroot.addAttribute("Name", PivotObj.getString("Name"));
					Pivotroot.addAttribute("MemoText", PivotObj.getString("MemoText"));
					Pivotroot.addAttribute("DataSource", PivotObj.getString("DataSource"));
					
					if (PivotObj.has("isAdhocItem")) {
						Pivotroot.addAttribute("isAdhocItem", String.valueOf(PivotObj.getBoolean("isAdhocItem")));
						Pivotroot.addAttribute("adhocIndex", String.valueOf(PivotObj.getInt("adhocIndex")));
					}
					
					if(PivotObj.has("ShowCaption")) {
						if(PivotObj.getBoolean("ShowCaption") == false)
							Pivotroot.addAttribute("ShowCaption", "false");
					}
					if (PivotObj.has("AutoExpandColumnGroups")) {
						Pivotroot.addElement("AutoExpandColumnGroups").addText(PivotObj.get("AutoExpandColumnGroups")+"");
					}
					if (PivotObj.has("AutoExpandRowGroups")) {
						Pivotroot.addElement("AutoExpandRowGroups").addText(PivotObj.get("AutoExpandRowGroups")+"");
					}
					if (PivotObj.has("InteractivityOptions")) {
						if(PivotObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters") == true) {
							Element InteractivityOptions = Pivotroot.addElement("InteractivityOptions");
							InteractivityOptions.addAttribute("IgnoreMasterFilters","true");
						}
					}
					if(PivotObj.has("FilterString")) {
						Pivotroot.addAttribute("FilterString", PivotObj.getString("FilterString"));
					}
					/*dogfoot 피벗그리드 행열 위치 변경 기능 shlim 202103*/
					if(PivotObj.has("DataFieldPosition")) {
						Pivotroot.addAttribute("DataFieldPosition", PivotObj.getString("DataFieldPosition"));
					}
					
					if(PivotObj.has("PagingOptions")) {
						Element pagingOptionsElement = Pivotroot.addElement("PagingOptions");
						JSONObject pagingOptions = PivotObj.getJSONObject("PagingOptions");
						pagingOptionsElement.addAttribute("PagingDesc", pagingOptions.get("PagingDesc") + "");
						pagingOptionsElement.addAttribute("PagingDefault", pagingOptions.get("PagingDefault") + "");
						pagingOptionsElement.addAttribute("PagingEnabled", pagingOptions.getBoolean("PagingEnabled") ? "true" : "false");
						pagingOptionsElement.addAttribute("PagingSizeEnabled", pagingOptions.getBoolean("PagingSizeEnabled") ? "true" : "false");
						Element pagingSetElement = pagingOptionsElement.addElement("PagingSet");
						JSONObject pagingSet = pagingOptions.getJSONObject("PagingSet");
						pagingSetElement.addAttribute("Fir", pagingSet.get("Fir")+"");
						pagingSetElement.addAttribute("Sec", pagingSet.get("Sec")+"");
						pagingSetElement.addAttribute("Thi", pagingSet.get("Thi")+"");
					}
					
					JSONObject pivotDataItems = PivotObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(pivotDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(pivotDataItems, "Measure");

					Element PivotDataItems = Pivotroot.addElement("DataItems");
					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
						Element DimPivotAttr = PivotDataItems.addElement("Dimension");
						DimPivotAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						if(dimdata.has("Name")) {
							DimPivotAttr.addAttribute("Name",  dimdata.getString("Name"));
						}
						DimPivotAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimPivotAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
						if(dimdata.has("SortOrder")) {
							if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
								DimPivotAttr.addAttribute("SortOrder", "Descending");
							}
						}
						if(dimdata.has("SortByMeasure")) {
							DimPivotAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
						}
						//2020-01-14 LSH topN 차트 저장
						if(dimdata.has("TopNEnabled")) {
							String TopNEnabled = "true";
							DimPivotAttr.addAttribute("TopNEnabled",TopNEnabled);
							/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
							if(dimdata.has("TopNOrder")) {
								DimPivotAttr.addAttribute("TopNOrder", dimdata.get("TopNOrder")+"");
							}
							if(dimdata.has("TopNCount")) {
								DimPivotAttr.addAttribute("TopNCount", dimdata.get("TopNCount")+"");
							}
							if(dimdata.has("TopNMeasure")) {
								DimPivotAttr.addAttribute("TopNMeasure", dimdata.get("TopNMeasure")+"");
							}
							if(dimdata.has("TopNShowOthers")) {
								String TopNShowOthers = "true";
								DimPivotAttr.addAttribute("TopNShowOthers",TopNShowOthers);
							}
						}
					}

					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
						Element MeaPivotAttr = PivotDataItems.addElement("Measure");
						MeaPivotAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							MeaPivotAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						MeaPivotAttr.addAttribute("SummaryType",  summaryType);
						MeaPivotAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							MeaPivotAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
						if (meadata.has("NumericFormat")) {
							Element NumericFormat = MeaPivotAttr.addElement("NumericFormat");
							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
							if (PivotNumericFormat.has("FormatType"))
								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
							if (PivotNumericFormat.has("Precision"))
								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
							/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
							if (PivotNumericFormat.has("PrecisionOption"))
								NumericFormat.addAttribute("PrecisionOption", PivotNumericFormat.getString("PrecisionOption") + "");
							if (PivotNumericFormat.has("Unit"))
								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
//							if (PivotNumericFormat.has("SuffixEnabled")) {
//								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
//							}
//							if (PivotNumericFormat.has("Suffix")) {
//								Element Suffix = NumericFormat.addElement("Suffix");
//								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
//								Suffix.addAttribute("O", suffix.getString("O"));
//								Suffix.addAttribute("K", suffix.getString("K"));
//								Suffix.addAttribute("M", suffix.getString("M"));
//								Suffix.addAttribute("B", suffix.getString("B"));
//							}
							if (PivotNumericFormat.has("IncludeGroupSeparator"))
								NumericFormat.addAttribute("IncludeGroupSeparator",
										PivotNumericFormat.get("IncludeGroupSeparator").toString());
						}
//						if(meadata.has("SortOrder")) {
//							if(meadata.getString("SortOrder").equalsIgnoreCase("descending")) {
//								MeaPivotAttr.addAttribute("SortOrder", "Descending");
//							}
//						}
					}
					if(PivotObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = PivotObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = Pivotroot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					JSONArray columns = toJsonArray(PivotObj.getJSONObject("Columns"), "Column");
					if(columns.length() >0) {
						Element ColumnRoot = Pivotroot.addElement("Columns");
						for(int columnIdx = 0; columnIdx<columns.length();columnIdx++) {
							JSONObject colItem = columns.getJSONObject(columnIdx);
							ColumnRoot.addElement("Column").addAttribute("UniqueName", colItem.getString("UniqueName"));
						}
					}
					
					
					JSONArray Rows = toJsonArray(PivotObj.getJSONObject("Rows"),"Row");
					if(Rows.length() >0) {
						Element RowRoot = Pivotroot.addElement("Rows");
						for(int rowIdx = 0; rowIdx<Rows.length();rowIdx++) {
							JSONObject rowItem = Rows.getJSONObject(rowIdx);
							RowRoot.addElement("Row").addAttribute("UniqueName", rowItem.getString("UniqueName"));
						}
					}
					
					JSONArray Values = toJsonArray(PivotObj.getJSONObject("Values"),"Value");
					if(Values.length() >0) {
						Element ValueRoot = Pivotroot.addElement("Values");
						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
							JSONObject valItem = Values.getJSONObject(valueIdx);
							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
						}
					}
					
				}
				break;
			case "Card":
				JSONArray cardItemArray = itemObj.getJSONArray("Card");
				for (int eachCardItem = 0; eachCardItem < cardItemArray.length(); eachCardItem++) {
					JSONObject cardObj = cardItemArray.getJSONObject(eachCardItem);
					Element cardRoot = items.addElement("Card");
					cardRoot.addAttribute("ComponentName", cardObj.getString("ComponentName"));
					cardRoot.addAttribute("Name", cardObj.getString("Name"));
					cardRoot.addAttribute("MemoText", cardObj.getString("MemoText"));
					cardRoot.addAttribute("DataSource", cardObj.getString("DataSource"));
					if(cardObj.has("ShowCaption")) {
						if(cardObj.getBoolean("ShowCaption") == false)
							cardRoot.addAttribute("ShowCaption", "false");
					}
					
					addInteractivityOption(cardObj, cardRoot);
					
					if (cardObj.has("IsMasterFilterCrossDataSource")) {
						if (cardObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							cardRoot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					JSONObject cardDataItems = cardObj.getJSONObject("DataItems");
					JSONArray dimDataItems = toJsonArray(cardDataItems, "Dimension");
					JSONArray meaDataItems = toJsonArray(cardDataItems, "Measure");
					Element cardDataElement = cardRoot.addElement("DataItems");
					for(int dimDataIdx = 0; dimDataIdx < dimDataItems.length(); dimDataIdx++) {
						JSONObject dimdata = dimDataItems.getJSONObject(dimDataIdx);
						Element dimCardAttr = cardDataElement.addElement("Dimension");
						dimCardAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						if(dimdata.has("Name")) {
							dimCardAttr.addAttribute("Name",  dimdata.getString("Name"));
						}
						dimCardAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							dimCardAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
						if(dimdata.has("SortOrder")) {
							if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
								dimCardAttr.addAttribute("SortOrder", "Descending");
							}
						}
						if(dimdata.has("SortByMeasure")) {
							dimCardAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
						}
					}
					
					for (int meaDataidx = 0; meaDataidx < meaDataItems.length(); meaDataidx++) {
						JSONObject meadata = meaDataItems.getJSONObject(meaDataidx);
						Element meaCardAttr = cardDataElement.addElement("Measure");
						meaCardAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							meaCardAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						meaCardAttr.addAttribute("SummaryType",  summaryType);
						meaCardAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							meaCardAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
						if (meadata.has("NumericFormat")) {
							JSONObject numericFormat = meadata.getJSONObject("NumericFormat");
							Element numericFormatElement = meaCardAttr.addElement("NumericFormat");
							if (numericFormat.has("FormatType"))
								numericFormatElement.addAttribute("FormatType", numericFormat.getString("FormatType"));
							if (numericFormat.has("Precision"))
								numericFormatElement.addAttribute("Precision", numericFormat.get("Precision") + "");
							/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
							if (numericFormat.has("PrecisionOption"))
								numericFormatElement.addAttribute("PrecisionOption", numericFormat.getString("PrecisionOption") + "");
							if (numericFormat.has("Unit"))
								numericFormatElement.addAttribute("Unit", numericFormat.getString("Unit"));
							if (numericFormat.has("IncludeGroupSeparator"))
								numericFormatElement.addAttribute("IncludeGroupSeparator", numericFormat.get("IncludeGroupSeparator").toString());
						}
					}
					if(cardObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = cardObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = cardRoot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					if (cardObj.has("SeriesDimensions")) {
						JSONObject cardSeriesDim = cardObj.getJSONObject("SeriesDimensions");
						JSONArray seriesDimArr = toJsonArray(cardSeriesDim, "SeriesDimension");
						if(seriesDimArr.length() >0) {
							Element SeriesDimensions = cardRoot.addElement("SeriesDimensions");
							for (int serdim = 0; serdim < seriesDimArr.length(); serdim++) {
								Element SeriesDimensionAttr = SeriesDimensions.addElement("SeriesDimension");
								SeriesDimensionAttr.addAttribute("UniqueName", seriesDimArr.getJSONObject(serdim).getString("UniqueName"));
								if(seriesDimArr.getJSONObject(serdim).has("CubeUniqueName")) {
									SeriesDimensionAttr.addAttribute("CubeUniqueName",  seriesDimArr.getJSONObject(serdim).getString("CubeUniqueName"));
								}
							}
						}
					}
					if (cardObj.has("Card")) {
						JSONObject cardOptions = cardObj.getJSONObject("Card");
						Element cardElement = cardRoot.addElement("Card");
						/* DOGFOOT hsshim 2020-01-22 카드 이름 저장 기능 작업 */
						if (cardOptions.has("Name")) {
							String cardName = cardOptions.getString("Name");
							if (cardName != null && cardName.length() > 0) {
								cardElement.addAttribute("Name", cardName);
							}
						}
						/* DOGFOOT hsshim 2020-01-22 끝 */
						if (cardOptions.has("ActualValue")) {
							JSONObject actualValue = cardOptions.getJSONObject("ActualValue");
							Element actualValueElement = cardElement.addElement("ActualValue");
							actualValueElement.addAttribute("UniqueName", actualValue.getString("UniqueName"));
						}
						if (cardOptions.has("TargetValue")) {
							JSONObject targetValue = cardOptions.getJSONObject("TargetValue");
							Element targetValueElement = cardElement.addElement("TargetValue");
							targetValueElement.addAttribute("UniqueName", targetValue.getString("UniqueName"));
						}
						/* DOGFOOT MKSONG 2020-07-29 카드 콘텐츠 배열 기능 추가 */
						if (cardOptions.has("ContentArrangementMode")) {
							String contentArrangementMode = cardOptions.getString("ContentArrangementMode");
							cardElement.addAttribute("ContentArrangementMode",contentArrangementMode);
							if (!contentArrangementMode.equals("Auto"))
								cardElement.addAttribute("ContentLineCount", cardOptions.get("ContentLineCount")+"");
						}
						if (cardOptions.has("CardDeltaOptions")) {
							JSONObject deltaFormat = cardOptions.getJSONObject("CardDeltaOptions");
							Element deltaFormatElement = cardElement.addElement("CardDeltaOptions");
							if (deltaFormat.has("ResultIndicationMode"))
								deltaFormatElement.addAttribute("ResultIndicationMode", deltaFormat.getString("ResultIndicationMode"));
							if (deltaFormat.has("ResultIndicationThresholdType"))
								deltaFormatElement.addAttribute("ResultIndicationThresholdType", deltaFormat.getString("ResultIndicationThresholdType"));
							if (deltaFormat.has("ResultIndicationThreshold"))
								deltaFormatElement.addAttribute("ResultIndicationThreshold", deltaFormat.get("ResultIndicationThreshold") + "");
						}
						if (cardOptions.has("AbsoluteVariationNumericFormat")) {
							JSONObject absoluteFormat = cardOptions.getJSONObject("AbsoluteVariationNumericFormat");
							Element absoluteFormatElement = cardElement.addElement("AbsoluteVariationNumericFormat");
							if (absoluteFormat.has("FormatType"))
								absoluteFormatElement.addAttribute("FormatType", absoluteFormat.getString("FormatType"));
							if (absoluteFormat.has("Precision"))
								absoluteFormatElement.addAttribute("Precision", absoluteFormat.get("Precision") + "");
							/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
							if (absoluteFormat.has("PrecisionOption"))
								absoluteFormatElement.addAttribute("PrecisionOption", absoluteFormat.getString("PrecisionOption") + "");
							if (absoluteFormat.has("Unit"))
								absoluteFormatElement.addAttribute("Unit", absoluteFormat.getString("Unit"));
							if (absoluteFormat.has("IncludeGroupSeparator"))
								absoluteFormatElement.addAttribute("IncludeGroupSeparator", absoluteFormat.get("IncludeGroupSeparator").toString());
						}
						if (cardOptions.has("PercentVariationNumericFormat")) {
							JSONObject percentFormat = cardOptions.getJSONObject("PercentVariationNumericFormat");
							Element percentFormatElement = cardElement.addElement("PercentVariationNumericFormat");
							if (percentFormat.has("FormatType"))
								percentFormatElement.addAttribute("FormatType", percentFormat.getString("FormatType"));
							if (percentFormat.has("Precision"))
								percentFormatElement.addAttribute("Precision", percentFormat.get("Precision") + "");
							/*dogfoot 포멧 반올림 설정 추가 shlim 20210720*/
							if (percentFormat.has("PrecisionOption"))
								percentFormatElement.addAttribute("PrecisionOption", percentFormat.getString("PrecisionOption") + "");
							if (percentFormat.has("Unit"))
								percentFormatElement.addAttribute("Unit", percentFormat.getString("Unit"));
							if (percentFormat.has("IncludeGroupSeparator"))
								percentFormatElement.addAttribute("IncludeGroupSeparator", percentFormat.get("IncludeGroupSeparator").toString());
						}
						if (cardOptions.has("PercentOfTargetNumericFormat")) {
							JSONObject percentTargetFormat = cardOptions.getJSONObject("PercentOfTargetNumericFormat");
							Element percentTargetFormatElement = cardElement.addElement("PercentOfTargetNumericFormat");
							if (percentTargetFormat.has("FormatType"))
								percentTargetFormatElement.addAttribute("FormatType", percentTargetFormat.getString("FormatType"));
							if (percentTargetFormat.has("Precision"))
								percentTargetFormatElement.addAttribute("Precision", percentTargetFormat.get("Precision") + "");
							if (percentTargetFormat.has("PrecisionOption"))
								percentTargetFormatElement.addAttribute("PrecisionOption", percentTargetFormat.getString("PrecisionOption") + "");
							if (percentTargetFormat.has("Unit"))
								percentTargetFormatElement.addAttribute("Unit", percentTargetFormat.getString("Unit"));
							if (percentTargetFormat.has("IncludeGroupSeparator"))
								percentTargetFormatElement.addAttribute("IncludeGroupSeparator", percentTargetFormat.get("IncludeGroupSeparator").toString());
						}
						if (cardOptions.has("SparklineOptions")) {
							JSONObject sparklineOptionsFormat = cardOptions.getJSONObject("SparklineOptions");
							Element sparklineOptionsFormatElement = cardElement.addElement("SparklineOptions");
							if (sparklineOptionsFormat.has("ViewType"))
								sparklineOptionsFormatElement.addAttribute("ViewType", sparklineOptionsFormat.getString("ViewType"));
							if (sparklineOptionsFormat.has("HighlightMinMaxPoints"))
								sparklineOptionsFormatElement.addAttribute("HighlightMinMaxPoints", sparklineOptionsFormat.getBoolean("HighlightMinMaxPoints") ? "true" : "false");
							if (sparklineOptionsFormat.has("HighlightStartEndPoints"))
								sparklineOptionsFormatElement.addAttribute("HighlightStartEndPoints", sparklineOptionsFormat.getBoolean("HighlightStartEndPoints") ? "true" : "false");
						}
						if (cardOptions.has("LayoutTemplate")) {
							JSONObject layoutTemplate = cardOptions.getJSONObject("LayoutTemplate");
							Element layoutTemplateElement = cardElement.addElement("LayoutTemplate");
							if (layoutTemplate.has("Type")) {
								layoutTemplateElement.addAttribute("Type", layoutTemplate.getString("Type"));
							}
							
							//2020.07.24 mksong 카드 최대폭, 최소폭 기능 dogfoot
							if (layoutTemplate.has("MaxWidth")) {
								layoutTemplateElement.addAttribute("MaxWidth", layoutTemplate.get("MaxWidth").toString());
							}
							
							if (layoutTemplate.has("MinWidth")) {
								layoutTemplateElement.addAttribute("MinWidth", layoutTemplate.get("MinWidth").toString());
							}
							//20200727 ajkim 카드 폰트 설정 추가 dogfoot
							if (layoutTemplate.has("TopValue")) {
								JSONObject topValue = layoutTemplate.getJSONObject("TopValue");
								Element topValueElement = layoutTemplateElement.addElement("TopValue");
								if (topValue.has("Visible"))
									topValueElement.addAttribute("Visible", topValue.getBoolean("Visible") ? "true" : "false");
								if (topValue.has("ValueType"))
									topValueElement.addAttribute("ValueType", topValue.getString("ValueType"));
								if (topValue.has("DimensionIndex"))
									topValueElement.addAttribute("DimensionIndex", topValue.get("DimensionIndex") + "");
								if (topValue.has("Font")) {
									Element fontElement = topValueElement.addElement("Font");
									JSONObject font = topValue.getJSONObject("Font");
									fontElement.addAttribute("Size", font.get("Size") + "");
									fontElement.addAttribute("Color", font.getString("Color"));
									fontElement.addAttribute("ColorVisible", font.getBoolean("ColorVisible")? "true" : "false");
									fontElement.addAttribute("Align", font.getString("Align"));
								}
							}
							if (layoutTemplate.has("MainValue")) {
								JSONObject mainValue = layoutTemplate.getJSONObject("MainValue");
								Element mainValueElement = layoutTemplateElement.addElement("MainValue");
								if (mainValue.has("Visible"))
									mainValueElement.addAttribute("Visible", mainValue.getBoolean("Visible") ? "true" : "false");
								if (mainValue.has("ValueType"))
									mainValueElement.addAttribute("ValueType", mainValue.getString("ValueType"));
								if (mainValue.has("DimensionIndex"))
									mainValueElement.addAttribute("DimensionIndex", mainValue.get("DimensionIndex") + "");
								if (mainValue.has("Font")) {
									Element fontElement = mainValueElement.addElement("Font");
									JSONObject font = mainValue.getJSONObject("Font");
									fontElement.addAttribute("Size", font.get("Size") + "");
									fontElement.addAttribute("Color", font.getString("Color"));
									fontElement.addAttribute("ColorVisible", font.getBoolean("ColorVisible")? "true" : "false");
									fontElement.addAttribute("Align", font.getString("Align"));
								}
							}
							if (layoutTemplate.has("SubValue")) {
								JSONObject subValue = layoutTemplate.getJSONObject("SubValue");
								Element subValueElement = layoutTemplateElement.addElement("SubValue");
								if (subValue.has("Visible"))
									subValueElement.addAttribute("Visible", subValue.getBoolean("Visible") ? "true" : "false");
								if (subValue.has("ValueType"))
									subValueElement.addAttribute("ValueType", subValue.getString("ValueType"));
								if (subValue.has("DimensionIndex"))
									subValueElement.addAttribute("DimensionIndex", subValue.get("DimensionIndex") + "");
								if (subValue.has("Font")) {
									Element fontElement = subValueElement.addElement("Font");
									JSONObject font = subValue.getJSONObject("Font");
									fontElement.addAttribute("Size", font.get("Size") + "");
									fontElement.addAttribute("Color", font.getString("Color"));
									fontElement.addAttribute("ColorVisible", font.getBoolean("ColorVisible")? "true" : "false");
									fontElement.addAttribute("Align", font.getString("Align"));
								}
							}
							if (layoutTemplate.has("BottomValue1")) {
								JSONObject bottomValueOne = layoutTemplate.getJSONObject("BottomValue1");
								Element bottomValueOneElement = layoutTemplateElement.addElement("BottomValue1");
								if (bottomValueOne.has("Visible"))
									bottomValueOneElement.addAttribute("Visible", bottomValueOne.getBoolean("Visible") ? "true" : "false");
								if (bottomValueOne.has("ValueType"))
									bottomValueOneElement.addAttribute("ValueType", bottomValueOne.getString("ValueType"));
								if (bottomValueOne.has("DimensionIndex"))
									bottomValueOneElement.addAttribute("DimensionIndex", bottomValueOne.get("DimensionIndex") + "");
								if (bottomValueOne.has("Font")) {
									Element fontElement = bottomValueOneElement.addElement("Font");
									JSONObject font = bottomValueOne.getJSONObject("Font");
									fontElement.addAttribute("Size", font.get("Size") + "");
									fontElement.addAttribute("Color", font.getString("Color"));
									fontElement.addAttribute("ColorVisible", font.getBoolean("ColorVisible")? "true" : "false");
									fontElement.addAttribute("Align", font.getString("Align"));
								}
							}
							if (layoutTemplate.has("BottomValue2")) {
								JSONObject bottomValueTwo = layoutTemplate.getJSONObject("BottomValue2");
								Element topValueElement = layoutTemplateElement.addElement("BottomValue2");
								if (bottomValueTwo.has("Visible"))
									topValueElement.addAttribute("Visible", bottomValueTwo.getBoolean("Visible") ? "true" : "false");
								if (bottomValueTwo.has("ValueType"))
									topValueElement.addAttribute("ValueType", bottomValueTwo.getString("ValueType"));
								if (bottomValueTwo.has("DimensionIndex"))
									topValueElement.addAttribute("DimensionIndex", bottomValueTwo.get("DimensionIndex") + "");
								if (bottomValueTwo.has("Font")) {
									Element fontElement = topValueElement.addElement("Font");
									JSONObject font = bottomValueTwo.getJSONObject("Font");
									fontElement.addAttribute("Size", font.get("Size") + "");
									fontElement.addAttribute("Color", font.getString("Color"));
									fontElement.addAttribute("ColorVisible", font.getBoolean("ColorVisible")? "true" : "false");
									fontElement.addAttribute("Align", font.getString("Align"));
								}
							}
							if (layoutTemplate.has("DeltaIndicator")) {
								JSONObject deltaIndicator = layoutTemplate.getJSONObject("DeltaIndicator");
								Element deltaIndicatorElement = layoutTemplateElement.addElement("DeltaIndicator");
								if (deltaIndicator.has("Visible"))
									deltaIndicatorElement.addAttribute("Visible", deltaIndicator.getBoolean("Visible") ? "true" : "false");
								if (deltaIndicator.has("Font")) {
									Element fontElement = deltaIndicatorElement.addElement("Font");
									JSONObject font = deltaIndicator.getJSONObject("Font");
									fontElement.addAttribute("Size", font.get("Size") + "");
									fontElement.addAttribute("Color", font.getString("Color"));
									fontElement.addAttribute("ColorVisible", font.getBoolean("ColorVisible")? "true" : "false");
									fontElement.addAttribute("Align", font.getString("Align"));
								}
							}
							if (layoutTemplate.has("Sparkline")) {
								JSONObject sparkline = layoutTemplate.getJSONObject("Sparkline");
								Element sparklineElement = layoutTemplateElement.addElement("Sparkline");
								if (sparkline.has("Visible"))
									sparklineElement.addAttribute("Visible", sparkline.getBoolean("Visible") ? "true" : "false");
							}
						}
					}
					if (cardObj.has("SparklineArgument")) {
						JSONObject sparklineArgument = cardObj.getJSONObject("SparklineArgument");
						Element sparklineArgumentElement = cardRoot.addElement("SparklineArgument");
						if (sparklineArgument.has("UniqueName")) {
							sparklineArgumentElement.addAttribute("UniqueName", sparklineArgument.getString("UniqueName"));
						}
					}
				}
				break;
			/* DOGFOOT hsshim 2020-02-03 게이지 저장 기능 작업 */
			case "Gauge":
				JSONArray gaugeItemArray = itemObj.getJSONArray("Gauge");
				for (int eachGaugeItem = 0; eachGaugeItem < gaugeItemArray.length(); eachGaugeItem++) {
					JSONObject gaugeObj = gaugeItemArray.getJSONObject(eachGaugeItem);
					Element gaugeRoot = items.addElement("Gauge");
					gaugeRoot.addAttribute("ComponentName", gaugeObj.getString("ComponentName"));
					gaugeRoot.addAttribute("Name", gaugeObj.getString("Name"));
					gaugeRoot.addAttribute("MemoText", gaugeObj.getString("MemoText"));
					gaugeRoot.addAttribute("DataSource", gaugeObj.getString("DataSource"));
					if (gaugeObj.has("ShowCaption")) {
						if (gaugeObj.getBoolean("ShowCaption") == false) {
							gaugeRoot.addAttribute("ShowCaption", "false");
						}
					}
					if (gaugeObj.has("ViewType")) {
						if (!(gaugeObj.getString("ViewType").equals("CircularFull"))) {
							gaugeRoot.addAttribute("ViewType", gaugeObj.getString("ViewType"));
						}
					}
					if (gaugeObj.has("ShowGaugeCaptions")) {
						if (gaugeObj.getBoolean("ShowGaugeCaptions") == false) {
							gaugeRoot.addAttribute("ShowGaugeCaptions", "false");
						}
					}
					
					addInteractivityOption(gaugeObj, gaugeRoot);
					
					if (gaugeObj.has("IsMasterFilterCrossDataSource")) {
						if (gaugeObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							gaugeRoot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					JSONObject gaugeDataItems = gaugeObj.getJSONObject("DataItems");
					JSONArray dimDataItems = toJsonArray(gaugeDataItems, "Dimension");
					JSONArray meaDataItems = toJsonArray(gaugeDataItems, "Measure");
					Element gaugeDataElement = gaugeRoot.addElement("DataItems");
					for(int dimDataIdx = 0; dimDataIdx < dimDataItems.length(); dimDataIdx++) {
						JSONObject dimdata = dimDataItems.getJSONObject(dimDataIdx);
						Element dimGaugeAttr = gaugeDataElement.addElement("Dimension");
						dimGaugeAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						if(dimdata.has("Name")) {
							dimGaugeAttr.addAttribute("Name",  dimdata.getString("Name"));
						}
						dimGaugeAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							dimGaugeAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
						if(dimdata.has("SortOrder")) {
							if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
								dimGaugeAttr.addAttribute("SortOrder", "Descending");
							}
						}
						if(dimdata.has("SortByMeasure")) {
							dimGaugeAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
						}
					}
					
					for (int meaDataidx = 0; meaDataidx < meaDataItems.length(); meaDataidx++) {
						JSONObject meadata = meaDataItems.getJSONObject(meaDataidx);
						Element meaGaugeAttr = gaugeDataElement.addElement("Measure");
						meaGaugeAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							meaGaugeAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						meaGaugeAttr.addAttribute("SummaryType",  summaryType);
						meaGaugeAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							meaGaugeAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
						if (meadata.has("NumericFormat")) {
							JSONObject numericFormat = meadata.getJSONObject("NumericFormat");
							Element numericFormatElement = meaGaugeAttr.addElement("NumericFormat");
							if (numericFormat.has("FormatType"))
								numericFormatElement.addAttribute("FormatType", numericFormat.getString("FormatType"));
							if (numericFormat.has("Precision"))
								numericFormatElement.addAttribute("Precision", numericFormat.get("Precision") + "");
							if (numericFormat.has("PrecisionOption"))
								numericFormatElement.addAttribute("PrecisionOption", numericFormat.getString("PrecisionOption") + "");
							if (numericFormat.has("Unit"))
								numericFormatElement.addAttribute("Unit", numericFormat.getString("Unit"));
							if (numericFormat.has("IncludeGroupSeparator"))
								numericFormatElement.addAttribute("IncludeGroupSeparator", numericFormat.get("IncludeGroupSeparator").toString());
						}
					}
					if(gaugeObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = gaugeObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = gaugeRoot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					if (gaugeObj.has("SeriesDimensions")) {
						JSONObject gaugeSeriesDim = gaugeObj.getJSONObject("SeriesDimensions");
						JSONArray seriesDimArr = toJsonArray(gaugeSeriesDim, "SeriesDimension");
						if(seriesDimArr.length() >0) {
							Element SeriesDimensions = gaugeRoot.addElement("SeriesDimensions");
							for (int serdim = 0; serdim < seriesDimArr.length(); serdim++) {
								Element SeriesDimensionAttr = SeriesDimensions.addElement("SeriesDimension");
								SeriesDimensionAttr.addAttribute("UniqueName", seriesDimArr.getJSONObject(serdim).getString("UniqueName"));
								if(seriesDimArr.getJSONObject(serdim).has("CubeUniqueName")) {
									SeriesDimensionAttr.addAttribute("CubeUniqueName",  seriesDimArr.getJSONObject(serdim).getString("CubeUniqueName"));
								}
							}
						}
					}
					if (gaugeObj.has("GaugeElement")) {
						JSONObject gaugeOptions = gaugeObj.getJSONObject("GaugeElement");
						Element gaugeElement = gaugeRoot.addElement("GaugeElement");
						if (gaugeOptions.has("ActualValue")) {
							JSONObject actualValue = gaugeOptions.getJSONObject("ActualValue");
							Element actualValueElement = gaugeElement.addElement("ActualValue");
							actualValueElement.addAttribute("UniqueName", actualValue.getString("UniqueName"));
						}
						if (gaugeOptions.has("TargetValue")) {
							JSONObject targetValue = gaugeOptions.getJSONObject("TargetValue");
							Element targetValueElement = gaugeElement.addElement("TargetValue");
							targetValueElement.addAttribute("UniqueName", targetValue.getString("UniqueName"));
						}
						if (gaugeOptions.has("DeltaOptions")) {
							JSONObject deltaFormat = gaugeOptions.getJSONObject("DeltaOptions");
							Element deltaFormatElement = gaugeElement.addElement("DeltaOptions");
							if (deltaFormat.has("ValueType")) {
								deltaFormatElement.addAttribute("ValueType", deltaFormat.getString("ValueType"));
							}
							if (deltaFormat.has("ResultIndicationMode")) {
								deltaFormatElement.addAttribute("ResultIndicationMode", deltaFormat.getString("ResultIndicationMode"));
							}
							if (deltaFormat.has("ResultIndicationThresholdType")) {
								deltaFormatElement.addAttribute("ResultIndicationThresholdType", deltaFormat.getString("ResultIndicationThresholdType"));
							}
							if (deltaFormat.has("ResultIndicationThreshold")) {
								deltaFormatElement.addAttribute("ResultIndicationThreshold", deltaFormat.get("ResultIndicationThreshold") + "");
							}
						}
						if (gaugeOptions.has("AbsoluteVariationNumericFormat")) {
							JSONObject absoluteFormat = gaugeOptions.getJSONObject("AbsoluteVariationNumericFormat");
							Element absoluteFormatElement = gaugeElement.addElement("AbsoluteVariationNumericFormat");
							if (absoluteFormat.has("FormatType"))
								absoluteFormatElement.addAttribute("FormatType", absoluteFormat.getString("FormatType"));
							if (absoluteFormat.has("Precision"))
								absoluteFormatElement.addAttribute("Precision", absoluteFormat.get("Precision") + "");
							if (absoluteFormat.has("PrecisionOption"))
								absoluteFormatElement.addAttribute("PrecisionOption", absoluteFormat.getString("PrecisionOption") + "");
							if (absoluteFormat.has("Unit"))
								absoluteFormatElement.addAttribute("Unit", absoluteFormat.getString("Unit"));
							if (absoluteFormat.has("IncludeGroupSeparator"))
								absoluteFormatElement.addAttribute("IncludeGroupSeparator", absoluteFormat.get("IncludeGroupSeparator").toString());
						}
						if (gaugeOptions.has("PercentVariationNumericFormat")) {
							JSONObject percentFormat = gaugeOptions.getJSONObject("PercentVariationNumericFormat");
							Element percentFormatElement = gaugeElement.addElement("PercentVariationNumericFormat");
							if (percentFormat.has("FormatType"))
								percentFormatElement.addAttribute("FormatType", percentFormat.getString("FormatType"));
							if (percentFormat.has("Precision"))
								percentFormatElement.addAttribute("Precision", percentFormat.get("Precision") + "");
							if (percentFormat.has("PrecisionOption"))
								percentFormatElement.addAttribute("PrecisionOption", percentFormat.getString("PrecisionOption") + "");
							if (percentFormat.has("Unit"))
								percentFormatElement.addAttribute("Unit", percentFormat.getString("Unit"));
							if (percentFormat.has("IncludeGroupSeparator"))
								percentFormatElement.addAttribute("IncludeGroupSeparator", percentFormat.get("IncludeGroupSeparator").toString());
						}
						if (gaugeOptions.has("PercentOfTargetNumericFormat")) {
							JSONObject percentTargetFormat = gaugeOptions.getJSONObject("PercentOfTargetNumericFormat");
							Element percentTargetFormatElement = gaugeElement.addElement("PercentOfTargetNumericFormat");
							if (percentTargetFormat.has("FormatType"))
								percentTargetFormatElement.addAttribute("FormatType", percentTargetFormat.getString("FormatType"));
							if (percentTargetFormat.has("Precision"))
								percentTargetFormatElement.addAttribute("Precision", percentTargetFormat.get("Precision") + "");
							if (percentTargetFormat.has("PrecisionOption"))
								percentTargetFormatElement.addAttribute("PrecisionOption", percentTargetFormat.getString("PrecisionOption") + "");
							if (percentTargetFormat.has("Unit"))
								percentTargetFormatElement.addAttribute("Unit", percentTargetFormat.getString("Unit"));
							if (percentTargetFormat.has("IncludeGroupSeparator"))
								percentTargetFormatElement.addAttribute("IncludeGroupSeparator", percentTargetFormat.get("IncludeGroupSeparator").toString());
						}
						if (gaugeOptions.has("ScaleLabelNumericFormat")) {
							JSONObject scaleLabelFormat = gaugeOptions.getJSONObject("ScaleLabelNumericFormat");
							Element scaleLabelFormatElement = gaugeElement.addElement("ScaleLabelNumericFormat");
							if (scaleLabelFormat.has("FormatType"))
								scaleLabelFormatElement.addAttribute("FormatType", scaleLabelFormat.getString("FormatType"));
							if (scaleLabelFormat.has("Precision"))
								scaleLabelFormatElement.addAttribute("Precision", scaleLabelFormat.get("Precision") + "");
							if (scaleLabelFormat.has("PrecisionOption"))
								scaleLabelFormatElement.addAttribute("PrecisionOption", scaleLabelFormat.getString("PrecisionOption") + "");
							if (scaleLabelFormat.has("Unit"))
								scaleLabelFormatElement.addAttribute("Unit", scaleLabelFormat.getString("Unit"));
							if (scaleLabelFormat.has("IncludeGroupSeparator"))
								scaleLabelFormatElement.addAttribute("IncludeGroupSeparator", scaleLabelFormat.get("IncludeGroupSeparator").toString());
						}
					}
				}
				break;
			/* DOGFOOT hsshim 2020-02-03 끝 */
			case "ChoroplethMap":
				JSONArray ChoroplethItemArray = itemObj.getJSONArray("ChoroplethMap");
				for(int eachMapItem =0;eachMapItem<ChoroplethItemArray.length();eachMapItem++) {
					JSONObject MapObj = ChoroplethItemArray.getJSONObject(eachMapItem);
					Element Maproot = items.addElement("ChoroplethMap");
					Maproot.addAttribute("ComponentName", MapObj.getString("ComponentName"));
					Maproot.addAttribute("Name", MapObj.getString("Name"));
					Maproot.addAttribute("MemoText", MapObj.getString("MemoText"));
					Maproot.addAttribute("DataSource", MapObj.getString("DataSource"));
					Maproot.addAttribute("ShapefileArea", MapObj.getString("ShapefileArea"));
					Maproot.addAttribute("Palette", MapObj.getString("Palette"));
					Maproot.addAttribute("ShpIndex", String.valueOf(MapObj.getInt("ShpIndex")));					
					//Maproot.addAttribute("PaletteCustomCheck", String.valueOf(MapObj.getBoolean("PaletteCustomCheck")));
					//Maproot.addAttribute("PaletteStartColor", MapObj.getString("PaletteStartColor"));
					//Maproot.addAttribute("PaletteLastColor", MapObj.getString("PaletteLastColor"));
					
					if(MapObj.getInt("TargetIndex") != -1) {
						Maproot.addAttribute("TargetIndex", String.valueOf(MapObj.getInt("TargetIndex")));
					}
					
					if(MapObj.has("LocationName")) {
						if(!MapObj.getString("LocationName").equals("")) {
							Maproot.addAttribute("LocationName", MapObj.getString("LocationName"));
						}					
					}
									
					//2021.06.25 syjin 코로플레스 색상편집 추가 dogfoot
					if(MapObj.has("EditPaletteOption")) {
						JSONObject EditPalette = MapObj.getJSONObject("EditPaletteOption");
						
						JSONArray PaletteRange = EditPalette.getJSONArray("paletteRangeArray");
						JSONArray Palette = EditPalette.getJSONArray("paletteArray");
						
						Element EditPaletteOption = Maproot.addElement("EditPaletteOption");
						
						EditPaletteOption.addAttribute("paletteBasic", EditPalette.getString("paletteBasic"));
						EditPaletteOption.addAttribute("customCheck", String.valueOf(EditPalette.getBoolean("customCheck")));
						EditPaletteOption.addAttribute("paletteStartColor", EditPalette.getString("paletteStartColor"));
						EditPaletteOption.addAttribute("paletteLastColor", EditPalette.getString("paletteLastColor"));
						EditPaletteOption.addAttribute("valueType", EditPalette.getString("valueType"));
						EditPaletteOption.addAttribute("labelCount", String.valueOf(EditPalette.getInt("labelCount")));
						
						Element paletteRangeArray = EditPaletteOption.addElement("paletteRangeArray");
						for(int pa=0; pa<PaletteRange.length(); pa++) {
							paletteRangeArray.addElement("Range").setText(PaletteRange.get(pa).toString());
						}
						
						Element paletteArray = EditPaletteOption.addElement("paletteArray");
						for(int pa=0; pa<Palette.length(); pa++) {
							paletteArray.addElement("Palette").setText(Palette.get(pa).toString());
						}
					}
					if(MapObj.has("FileMeta")) {
						JSONArray fileMeta = MapObj.getJSONArray("FileMeta");
						
						Element FileMeta = Maproot.addElement("FileMeta");					
						
						
						for(int fi=0; fi<fileMeta.length(); fi++) {
							JSONObject fileInfo = fileMeta.getJSONObject(fi);
							if(fileMeta.getJSONObject(fi).length() > 0) {
								fileInfo = fileInfo.getJSONObject("fileInfo");
								if(!fileInfo.getString("fileName").equals("")) {
									JSONArray fileProperties = fileInfo.getJSONArray("filePropertiesItems");
									
									Element FileInfo = FileMeta.addElement("FileInfo");
									FileInfo.addAttribute("fileName", fileInfo.getString("fileName"));
									FileInfo.addAttribute("fileProperties", fileInfo.getString("fileProperties"));
									
									for(int j=0; j<fileProperties.length(); j++) {
										FileInfo.addElement("filePropertiesItems").setText(fileProperties.get(j).toString());
									}
								}
							}
						}
						
					}
					//2021-06-29 syjin 코로플레스 레이블 옵션 기능 추가 dogfoot
					if(MapObj.has("LabelOption")) {
						JSONObject labelOption = MapObj.getJSONObject("LabelOption");
						Element LabelOption = Maproot.addElement("LabelOption");
						
						JSONObject suffix = labelOption.getJSONObject("Suffix");
						Element Suffix = LabelOption.addElement("Suffix");
						
						LabelOption.addAttribute("Visible", String.valueOf(labelOption.getBoolean("Visible")));
						LabelOption.addAttribute("FontSize", String.valueOf(labelOption.getInt("FontSize")));
						LabelOption.addAttribute("FormatType", labelOption.getString("FormatType"));
						LabelOption.addAttribute("Unit", labelOption.getString("Unit"));
						//dogfoot 지역 사용자 색상 지정 추가 20210707 syjin
						if(labelOption.has("ColorEnabled")) {
							LabelOption.addAttribute("ColorEnabled", String.valueOf(labelOption.getBoolean("ColorEnabled")));
						}
						if(labelOption.has("Color")) {
							LabelOption.addAttribute("Color", labelOption.getString("Color"));
						}
						LabelOption.addAttribute("PrefixEnabled", String.valueOf(labelOption.getBoolean("PrefixEnabled")));
						LabelOption.addAttribute("PrefixFormat", labelOption.getString("PrefixFormat"));
						LabelOption.addAttribute("SuffixEnabled", String.valueOf(labelOption.getBoolean("SuffixEnabled")));
					
						Suffix.addAttribute("O", suffix.getString("O"));
						Suffix.addAttribute("K", suffix.getString("K"));
						Suffix.addAttribute("M", suffix.getString("M"));
						Suffix.addAttribute("B", suffix.getString("B"));
						
						LabelOption.addAttribute("Precision", String.valueOf(labelOption.getInt("Precision")));
					}
					
					//2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가  dogfoot
					if(MapObj.has("TooltipContentType")) {
						if(!MapObj.getString("TooltipContentType").equalsIgnoreCase("ArgumentValueAndPercent")) {
							Maproot.addAttribute("TooltipContentType", MapObj.getString("TooltipContentType"));
						}
					}
					
					if(MapObj.has("LockNavigation")) {
						if(MapObj.getBoolean("LockNavigation")== true) {
							Maproot.addAttribute("LockNavigation", "true");
						}
					}
					
					if (MapObj.has("InteractivityOptions")) {
						String masterFilterMode = "";
						boolean ignoreMasterFilter = false;
						if(!MapObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode").equals("Off")) {
							masterFilterMode = MapObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode");
						}
						if(MapObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters") == true) {
							ignoreMasterFilter = MapObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters");
						}
						
						if(!masterFilterMode.equals("") || ignoreMasterFilter == true) {
							Element InteractivityOptions = Maproot.addElement("InteractivityOptions");
							if(!masterFilterMode.equals("")) {
								InteractivityOptions.addAttribute("MasterFilterMode",masterFilterMode);
							}
							if(ignoreMasterFilter == true) {
								InteractivityOptions.addAttribute("IgnoreMasterFilters","true");
							}
						}
					}
									
					//Maproot.addAttribute("AttributeName", MapObj.getString("AttributeName"));
					JSONArray AttributeNameArray = MapObj.getJSONArray("AttributeName");
					Element AttributeName = Maproot.addElement("AttributeName");
					
					for (int idx = 0; idx < AttributeNameArray.length(); idx++) {						
						String attributeName = "";
						if(!AttributeNameArray.isNull(idx)) {
							attributeName = AttributeNameArray.getString(idx);
						}
						
						Element Attr = AttributeName.addElement("Name");
						String name = "";
						if(idx == 0) {
							name = "state";
						}else if(idx == 1) {
							name = "city";
						}else {
							name = "dong";
						}
						if(!AttributeNameArray.isNull(idx)) {
							Attr.addAttribute(name, attributeName);	
						}
					}
									
					if(MapObj.has("ShowCaption")) {
						if(MapObj.getBoolean("ShowCaption") == false)
							Maproot.addAttribute("ShowCaption", "false");
					}
					
					logger.debug("dd : " + MapObj.has("CurrentLocation")); 
					if(MapObj.has("CurrentLocation")) {
						JSONObject currentLocation = MapObj.getJSONObject("CurrentLocation");
						Element CurrentLocation = Maproot.addElement("CurrentLocation");
																
						CurrentLocation.addAttribute("State", currentLocation.getString("State"));
						CurrentLocation.addAttribute("City", currentLocation.getString("City"));					
					}
					
					JSONObject mapDataItems = MapObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(mapDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(mapDataItems, "Measure");
					
					Element MapDataItems = Maproot.addElement("DataItems");
					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
						Element DimGridAttr = MapDataItems.addElement("Dimension");
						DimGridAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						DimGridAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimGridAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
					}
					
					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
						Element MeaMapAttr = MapDataItems.addElement("Measure");
						MeaMapAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							MeaMapAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						
						MeaMapAttr.addAttribute("SummaryType",  summaryType);
						MeaMapAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							MeaMapAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
					}
					
					// dogfoot 지도 범위, 지도 파일 변수 배열 처리 20210519 syjin dogfoot
					JSONArray CustomShapefileArray = MapObj.getJSONArray("CustomShapefile");
					Element CustomShapefile = Maproot.addElement("CustomShapefile");
					
					for (int idx = 0; idx < CustomShapefileArray.length(); idx++) {
						JSONObject shp = CustomShapefileArray.getJSONObject(idx);
						Element shpUrl = CustomShapefile.addElement("url");
						if(shp.has("Url")){
							shpUrl.addAttribute("Url", shp.getString("Url").replaceAll("geojson","shp"));
						}
					}
					
//					String url =  MapObj.getJSONObject("CustomShapefile").getString("Url");
//					url = url.replaceAll("geojson", "shp");
//					url = url.substring(url.indexOf("/ds"), url.length());
//					url = remoteAddr.substring(0, remoteAddr.indexOf("/ds"))+url;
					
					//String url2 =  MapObj.getJSONObject("CustomShapefile").getString("Url");
					//url2 = url2.replaceAll("geojson", "shp");
//					url2 = url2.substring(url2.indexOf("/ds"), url2.length());
					//url2 = remoteAddr+url2;
					
					//shapeFile.addAttribute("Url", url2);
					
					// dogfoot 지도 범위, 지도 파일 변수 배열 처리 20210519 syjin dogfoot
//					Element viewArea = Maproot.addElement("ViewArea");
//					JSONObject viewAreaJson = MapObj.getJSONObject("ViewArea");
//					viewArea.addAttribute("TopLatitude", viewAreaJson.getDouble("TopLatitude")+"");
//					viewArea.addAttribute("BottomLatitude", viewAreaJson.getDouble("BottomLatitude")+"");
//					viewArea.addAttribute("LeftLongitude", viewAreaJson.getDouble("LeftLongitude")+"");
//					viewArea.addAttribute("RightLongitude", viewAreaJson.getDouble("RightLongitude")+"");
//					viewArea.addAttribute("CenterPointLatitude", viewAreaJson.getDouble("CenterPointLatitude")+"");
//					viewArea.addAttribute("CenterPointLongitude", viewAreaJson.getDouble("CenterPointLongitude")+"");
					
					JSONObject ViewAreaObject = MapObj.getJSONObject("ViewArea");
					Element viewArea = Maproot.addElement("ViewArea");
					
					JSONArray AreaArray = ViewAreaObject.getJSONArray("area");
					
					for (int idx = 0; idx < AreaArray.length(); idx++) {
						JSONObject viewAreaJson = AreaArray.getJSONObject(idx);
						Element area = viewArea.addElement("area");
						if(viewAreaJson.has("TopLatitude")) {
							area.addAttribute("TopLatitude", viewAreaJson.getDouble("TopLatitude")+"");
							area.addAttribute("BottomLatitude", viewAreaJson.getDouble("BottomLatitude")+"");
							area.addAttribute("LeftLongitude", viewAreaJson.getDouble("LeftLongitude")+"");
							area.addAttribute("RightLongitude", viewAreaJson.getDouble("RightLongitude")+"");
							area.addAttribute("CenterPointLatitude", viewAreaJson.getDouble("CenterPointLatitude")+"");
							area.addAttribute("CenterPointLongitude", viewAreaJson.getDouble("CenterPointLongitude")+"");
						}
					}
					
					Element MapLegend = Maproot.addElement("MapLegend");
					if(MapObj.has("MapLegend")) {
						JSONObject mapLegend = MapObj.getJSONObject("MapLegend");
						if(mapLegend.has("Visible")) {
							if(mapLegend.getBoolean("Visible") == true) {
								MapLegend.addAttribute("Visible", "true");
							}
							else {
								MapLegend.addAttribute("Visible", "false");
							}
						}
						
					}
					
					//2020.11.27 mksong 코로플레스지도 레이블 표기 dogfoot
					Element MapLabel = Maproot.addElement("MapLabel");
					if(MapObj.has("MapLabel")) {
						JSONObject maplabel = MapObj.getJSONObject("MapLabel");
						if(maplabel.has("Visible")) {
							if(maplabel.getBoolean("Visible") == true) {
								MapLabel.addAttribute("Visible", "true");
							}
							else {
								MapLabel.addAttribute("Visible", "false");
							}
						}
					}
					
					Element WeightedLegend = Maproot.addElement("WeightedLegend");
									
					JSONArray AttributeDimensionArray = MapObj.getJSONArray("AttributeDimension");
					Element AttributeDimension = Maproot.addElement("AttributeDimension");
					
					for (int idx = 0; idx < AttributeDimensionArray.length(); idx++) {
						JSONObject attributeDimension = AttributeDimensionArray.getJSONObject(idx);
						Element Attr = AttributeDimension.addElement("Dimension");
						Attr.addAttribute("UniqueName", attributeDimension.getString("UniqueName"));
					}
					//AttributeDimension.addAttribute("UniqueName", MapObj.getJSONObject("AttributeDimension").getString("UniqueName"));
					
					
					Element Maps = Maproot.addElement("Maps");
					JSONArray valueMap = MapObj.getJSONObject("Maps").getJSONArray("ValueMap");
					for(int valMap=0;valMap<valueMap.length();valMap++) {
						JSONObject ValueObj = valueMap.getJSONObject(valMap);
						Element valueMaps = Maps.addElement("ValueMap");
						valueMaps.addElement("UniformScale");
						valueMaps.addElement("Value").addAttribute("UniqueName", ValueObj.getJSONObject("Value").getString("UniqueName"));
						if(ValueObj.has("CustomScale")) {
							JSONArray customScaleArray = ValueObj.getJSONObject("CustomScale").getJSONArray("RangeStop");
							Element customScale = valueMaps.addElement("CustomScale");
							for(int customScaleIndex = 0; customScaleIndex < customScaleArray.length(); customScaleIndex++) {
								customScale.addElement("RangeStop").setText(customScaleArray.get(customScaleIndex).toString());
							}
						}
						if(ValueObj.has("CustomPalette")) {
							JSONArray customPaletteArray = ValueObj.getJSONObject("CustomPalette").getJSONArray("Color");
							Element customPalette = valueMaps.addElement("CustomPalette");
							for(int customPaletteIndex = 0; customPaletteIndex < customPaletteArray.length(); customPaletteIndex++) {
								customPalette.addElement("Color").setText(customPaletteArray.get(customPaletteIndex).toString());
							}
						}
						/*dogfoot 지도 사용자지정 팔레트 저장 기능 shlim 20200616*/
						if(ValueObj.has("CustomColorSet")) {
							valueMaps.addElement("CustomColorSet").addAttribute("CustomColorSetCheck", ValueObj.getJSONObject("CustomColorSet").getString("CustomColorSetCheck"));
						}
					}
					
				}
				break;
			case "KakaoMap":
				JSONArray KakaoItemArray = itemObj.getJSONArray("KakaoMap");
				for(int eachMapItem =0;eachMapItem<KakaoItemArray.length();eachMapItem++) {
					JSONObject MapObj = KakaoItemArray.getJSONObject(eachMapItem);
					Element Maproot = items.addElement("KakaoMap");
					Maproot.addAttribute("ComponentName", MapObj.getString("ComponentName"));
					Maproot.addAttribute("Name", MapObj.getString("Name"));
					Maproot.addAttribute("MemoText", MapObj.getString("MemoText"));
					Maproot.addAttribute("DataSource", MapObj.getString("DataSource"));
					Maproot.addAttribute("ShapefileArea", MapObj.getString("ShapefileArea"));
					Maproot.addAttribute("Palette", MapObj.getString("Palette"));
					//2020.09.22 mksong dogfoot 카카오지도 포인트타입, 로케이션타입 추가
					Maproot.addAttribute("ShowPointType", MapObj.getString("ShowPointType"));
					Maproot.addAttribute("LocationType", MapObj.getString("LocationType"));
					//2020.10.27 syjin dogfoot 카카오지도 줌레벨, 중심좌표 추가
					Maproot.addAttribute("Lng", MapObj.getString("Lng"));
					Maproot.addAttribute("Lat", MapObj.getString("Lat"));
					Maproot.addAttribute("Level", MapObj.getString("Level"));
					//2020.10.22 syjin dogfoot 카카오지도 Interactivity 추가
					addInteractivityOption(MapObj, Maproot);
					if(MapObj.has("LockNavigation")) {
						if(MapObj.getBoolean("LockNavigation")== true) {
							Maproot.addAttribute("LockNavigation", "true");
						}
					}
					Maproot.addAttribute("AttributeName", MapObj.getString("AttributeName"));
					if(MapObj.has("ShowCaption")) {
						if(MapObj.getBoolean("ShowCaption") == false)
							Maproot.addAttribute("ShowCaption", "false");
					}
					
					
					JSONObject mapDataItems = MapObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(mapDataItems, "Dimension");
					JSONArray LatitudeDataItems = toJsonArray(mapDataItems, "Latitude");
					JSONArray LongitudeDataItems = toJsonArray(mapDataItems, "Longitude");
					JSONArray AddressDataItems = toJsonArray(mapDataItems, "Address");
					JSONArray MarkerDataItems = toJsonArray(mapDataItems, "MarkerDimension");
					JSONArray MeaDataItems = toJsonArray(mapDataItems, "Measure");
					
					Element MapDataItems = Maproot.addElement("DataItems");
					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
						Element DimGridAttr = MapDataItems.addElement("Dimension");
						DimGridAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						DimGridAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimGridAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
					}
					
					for (int latitudeDataItems = 0; latitudeDataItems < LatitudeDataItems.length(); latitudeDataItems++) {
						JSONObject dimdata = LatitudeDataItems.getJSONObject(latitudeDataItems);
						Element DimGridAttr = MapDataItems.addElement("Latitude");
						DimGridAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						DimGridAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimGridAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
					}
					
					for (int longitudeDataItems = 0; longitudeDataItems < LongitudeDataItems.length(); longitudeDataItems++) {
						JSONObject dimdata = LongitudeDataItems.getJSONObject(longitudeDataItems);
						Element DimGridAttr = MapDataItems.addElement("Longitude");
						DimGridAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						DimGridAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimGridAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
					}
					
					for (int addressDataItems = 0; addressDataItems < AddressDataItems.length(); addressDataItems++) {
						JSONObject dimdata = AddressDataItems.getJSONObject(addressDataItems);
						Element DimGridAttr = MapDataItems.addElement("Address");
						DimGridAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						DimGridAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						
						//2020.09.28 mksong 주소타입 지정 dogfoot
						if(dimdata.has("AddressType")) {
							DimGridAttr.addAttribute("AddressType", dimdata.getString("AddressType"));
						}
						
						if(dimdata.has("CubeUniqueName")) {
							DimGridAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
					}
					
					for (int markerDataItems = 0; markerDataItems < MarkerDataItems.length(); markerDataItems++) {
						JSONObject dimdata = MarkerDataItems.getJSONObject(markerDataItems);
						Element DimGridAttr = MapDataItems.addElement("MarkerDimension");
						DimGridAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						DimGridAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimGridAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
					}
						
					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
						Element MeaMapAttr = MapDataItems.addElement("Measure");
						MeaMapAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							MeaMapAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						
						MeaMapAttr.addAttribute("SummaryType",  summaryType);
						MeaMapAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							MeaMapAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
					}
					
					/*
					Element viewArea = Maproot.addElement("ViewArea");
					JSONObject viewAreaJson = MapObj.getJSONObject("ViewArea");
					viewArea.addAttribute("TopLatitude", viewAreaJson.getDouble("TopLatitude")+"");
					viewArea.addAttribute("BottomLatitude", viewAreaJson.getDouble("BottomLatitude")+"");
					viewArea.addAttribute("LeftLongitude", viewAreaJson.getDouble("LeftLongitude")+"");
					viewArea.addAttribute("RightLongitude", viewAreaJson.getDouble("RightLongitude")+"");
					viewArea.addAttribute("CenterPointLatitude", viewAreaJson.getDouble("CenterPointLatitude")+"");
					viewArea.addAttribute("CenterPointLongitude", viewAreaJson.getDouble("CenterPointLongitude")+"");
					*/
					
					Element MapLegend = Maproot.addElement("MapLegend");
					if(MapObj.has("MapLegend")) {
						JSONObject mapLegend = MapObj.getJSONObject("MapLegend");
						if(mapLegend.has("Visible")) {
							if(mapLegend.getBoolean("Visible") == true) {
								MapLegend.addAttribute("Visible", "true");
							}
							else {
								MapLegend.addAttribute("Visible", "false");
							}
						}
						
					}
					
					Element WeightedLegend = Maproot.addElement("WeightedLegend");
				
					//2020.09.22 mksong dogfoot 카카오지도 저장시 속성차원 오류 수정
					if(MapObj.has("AttributeDimension")) {
						if(MapObj.getJSONObject("AttributeDimension").has("UniqueName")) {
							Element AttributeDimension = Maproot.addElement("AttributeDimension");
							AttributeDimension.addAttribute("UniqueName", MapObj.getJSONObject("AttributeDimension").getString("UniqueName"));
						}
					}
					
					//DOGFOOT syjin 2020-12-03 카카오 지도 저장 오류 수정
					Element Maps = Maproot.addElement("Maps");
					JSONArray valueMap = MapObj.getJSONObject("Maps").getJSONArray("ValueMap");
					for(int valMap=0;valMap<valueMap.length();valMap++) {
						JSONObject ValueObj = valueMap.getJSONObject(valMap);
						Element valueMaps = Maps.addElement("ValueMap");
						valueMaps.addElement("UniformScale");
						valueMaps.addElement("Value").addAttribute("UniqueName", ValueObj.getJSONObject("Value").getString("UniqueName"));
						if(ValueObj.has("CustomScale")) {
							JSONArray customScaleArray = ValueObj.getJSONObject("CustomScale").getJSONArray("RangeStop");
							Element customScale = valueMaps.addElement("CustomScale");
							for(int customScaleIndex = 0; customScaleIndex < customScaleArray.length(); customScaleIndex++) {
								customScale.addElement("RangeStop").setText(customScaleArray.get(customScaleIndex).toString());
							}
						}
						if(ValueObj.has("CustomPalette")) {
							JSONArray customPaletteArray = ValueObj.getJSONObject("CustomPalette").getJSONArray("Color");
							Element customPalette = valueMaps.addElement("CustomPalette");
							for(int customPaletteIndex = 0; customPaletteIndex < customPaletteArray.length(); customPaletteIndex++) {
								customPalette.addElement("Color").setText(customPaletteArray.get(customPaletteIndex).toString());
							}
						}
						/*dogfoot 지도 사용자지정 팔레트 저장 기능 shlim 20200616*/
						if(ValueObj.has("CustomColorSet")) {
							valueMaps.addElement("CustomColorSet").addAttribute("CustomColorSetCheck", ValueObj.getJSONObject("CustomColorSet").getString("CustomColorSetCheck"));
						}
					}
					
				}
				break;
			case "KakaoMap2":
				JSONArray Kakao2ItemArray = itemObj.getJSONArray("KakaoMap2");
				for(int eachMapItem =0;eachMapItem<Kakao2ItemArray.length();eachMapItem++) {
					JSONObject MapObj = Kakao2ItemArray.getJSONObject(eachMapItem);
					Element Maproot = items.addElement("KakaoMap2");
					Maproot.addAttribute("ComponentName", MapObj.getString("ComponentName"));
					Maproot.addAttribute("Name", MapObj.getString("Name"));
					Maproot.addAttribute("MemoText", MapObj.getString("MemoText"));
					Maproot.addAttribute("DataSource", MapObj.getString("DataSource"));
					Maproot.addAttribute("ShapefileArea", MapObj.getString("ShapefileArea"));
					Maproot.addAttribute("Palette", MapObj.getString("Palette"));
					if(MapObj.has("LockNavigation")) {
						if(MapObj.getBoolean("LockNavigation")== true) {
							Maproot.addAttribute("LockNavigation", "true");
						}
					}
					Maproot.addAttribute("AttributeName", MapObj.getString("AttributeName"));
					if(MapObj.has("ShowCaption")) {
						if(MapObj.getBoolean("ShowCaption") == false)
							Maproot.addAttribute("ShowCaption", "false");
					}
					
					
					JSONObject mapDataItems = MapObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(mapDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(mapDataItems, "Measure");
					
					Element MapDataItems = Maproot.addElement("DataItems");
					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
						Element DimGridAttr = MapDataItems.addElement("Dimension");
						DimGridAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						DimGridAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimGridAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
					}
					
					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
						Element MeaMapAttr = MapDataItems.addElement("Measure");
						MeaMapAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							MeaMapAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						
						MeaMapAttr.addAttribute("SummaryType",  summaryType);
						MeaMapAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							MeaMapAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
					}
					
					/*
					Element viewArea = Maproot.addElement("ViewArea");
					JSONObject viewAreaJson = MapObj.getJSONObject("ViewArea");
					viewArea.addAttribute("TopLatitude", viewAreaJson.getDouble("TopLatitude")+"");
					viewArea.addAttribute("BottomLatitude", viewAreaJson.getDouble("BottomLatitude")+"");
					viewArea.addAttribute("LeftLongitude", viewAreaJson.getDouble("LeftLongitude")+"");
					viewArea.addAttribute("RightLongitude", viewAreaJson.getDouble("RightLongitude")+"");
					viewArea.addAttribute("CenterPointLatitude", viewAreaJson.getDouble("CenterPointLatitude")+"");
					viewArea.addAttribute("CenterPointLongitude", viewAreaJson.getDouble("CenterPointLongitude")+"");
					*/
					
					Element MapLegend = Maproot.addElement("MapLegend");
					if(MapObj.has("MapLegend")) {
						JSONObject mapLegend = MapObj.getJSONObject("MapLegend");
						if(mapLegend.has("Visible")) {
							if(mapLegend.getBoolean("Visible") == true) {
								MapLegend.addAttribute("Visible", "true");
							}
							else {
								MapLegend.addAttribute("Visible", "false");
							}
						}
						
					}
					
					Element WeightedLegend = Maproot.addElement("WeightedLegend");
					
					Element AttributeDimension = Maproot.addElement("AttributeDimension");
					AttributeDimension.addAttribute("UniqueName", MapObj.getJSONObject("AttributeDimension").getString("UniqueName"));
					
					
					Element Maps = Maproot.addElement("Maps");
					JSONArray valueMap = MapObj.getJSONObject("Maps").getJSONArray("ValueMap");
					for(int valMap=0;valMap<valueMap.length();valMap++) {
						JSONObject ValueObj = valueMap.getJSONObject(eachMapItem);
						Element valueMaps = Maps.addElement("ValueMap");
						valueMaps.addElement("UniformScale");
						valueMaps.addElement("Value").addAttribute("UniqueName", ValueObj.getJSONObject("Value").getString("UniqueName"));
						if(ValueObj.has("CustomScale")) {
							JSONArray customScaleArray = ValueObj.getJSONObject("CustomScale").getJSONArray("RangeStop");
							Element customScale = valueMaps.addElement("CustomScale");
							for(int customScaleIndex = 0; customScaleIndex < customScaleArray.length(); customScaleIndex++) {
								customScale.addElement("RangeStop").setText(customScaleArray.get(customScaleIndex).toString());
							}
						}
						if(ValueObj.has("CustomPalette")) {
							JSONArray customPaletteArray = ValueObj.getJSONObject("CustomPalette").getJSONArray("Color");
							Element customPalette = valueMaps.addElement("CustomPalette");
							for(int customPaletteIndex = 0; customPaletteIndex < customPaletteArray.length(); customPaletteIndex++) {
								customPalette.addElement("Color").setText(customPaletteArray.get(customPaletteIndex).toString());
							}
						}
						/*dogfoot 지도 사용자지정 팔레트 저장 기능 shlim 20200616*/
						if(ValueObj.has("CustomColorSet")) {
							valueMaps.addElement("CustomColorSet").addAttribute("CustomColorSetCheck", ValueObj.getJSONObject("CustomColorSet").getString("CustomColorSetCheck"));
						}
					}
					
				}
				break;								
			case "Treemap":
				JSONArray TreeMapArray = itemObj.getJSONArray("Treemap");
				for(int eachMapItem =0;eachMapItem<TreeMapArray.length();eachMapItem++) {
					JSONObject TreeMapObj = TreeMapArray.getJSONObject(eachMapItem);
					Element TreeMaproot = items.addElement("Treemap");
					TreeMaproot.addAttribute("ComponentName", TreeMapObj.getString("ComponentName"));
					TreeMaproot.addAttribute("Name", TreeMapObj.getString("Name"));
					TreeMaproot.addAttribute("MemoText", TreeMapObj.getString("MemoText"));
					TreeMaproot.addAttribute("DataSource", TreeMapObj.getString("DataSource"));
					/* DOGFOOT ktkang 캡션보기 저장 기능 없는 아이템들 모두 추가 이 밑으로 쭈욱  같은 주석 나올 때 까지 20200205 */
					if(TreeMapObj.has("ShowCaption")) {
						if(TreeMapObj.getBoolean("ShowCaption") == false) {
							TreeMaproot.addAttribute("ShowCaption", "false");
						}
					}
					
					if(TreeMapObj.has("ColoringOption")) {
						Element ColoringOptions = TreeMaproot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", TreeMapObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", TreeMapObj.getString("UseGlobalColors"));
						JSONArray colorArray = TreeMapObj.getJSONArray("ColorSheme");
						Element ColorSheme = TreeMaproot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					
					
					addInteractivityOption(TreeMapObj, TreeMaproot);
					
					JSONObject TreeMapDataItems = TreeMapObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(TreeMapDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(TreeMapDataItems, "Measure");
					
					Element TreeMapMapDataItems = TreeMaproot.addElement("DataItems");
					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
						Element DimTreemapAttr = TreeMapMapDataItems.addElement("Dimension");
						DimTreemapAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						if(dimdata.has("Name")) {
							DimTreemapAttr.addAttribute("Name",  dimdata.getString("Name"));
						}
						DimTreemapAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimTreemapAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
//						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
					}

					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
						Element MeaTreemapAttr = TreeMapMapDataItems.addElement("Measure");
						MeaTreemapAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							MeaTreemapAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						
						if (meadata.has("NumericFormat")) {
							Element NumericFormat = MeaTreemapAttr.addElement("NumericFormat");
							JSONObject TreemapNumericFormat = meadata.getJSONObject("NumericFormat");
							if (TreemapNumericFormat.has("FormatType"))
								NumericFormat.addAttribute("FormatType", TreemapNumericFormat.getString("FormatType"));
							if (TreemapNumericFormat.has("Precision"))
								NumericFormat.addAttribute("Precision", TreemapNumericFormat.get("Precision") + "");
							if (TreemapNumericFormat.has("PrecisionOption"))
								NumericFormat.addAttribute("PrecisionOption", TreemapNumericFormat.getString("PrecisionOption") + "");
							if (TreemapNumericFormat.has("Unit"))
								NumericFormat.addAttribute("Unit", TreemapNumericFormat.getString("Unit"));
						}
						MeaTreemapAttr.addAttribute("SummaryType",  summaryType);
						MeaTreemapAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							MeaTreemapAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
//						MeaGridAttr.addAttribute("DefaultId", meadata.getString("UniqueName"));
					}
					
					
					JSONArray Values = toJsonArray(TreeMapObj.getJSONObject("Values"), "Value");
					if(Values.length() >0) {
						Element ValueRoot = TreeMaproot.addElement("Values");
						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
							JSONObject valItem = Values.getJSONObject(valueIdx);
							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
//							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
						}
					}
					
					
					JSONArray Arguments = toJsonArray(TreeMapObj.getJSONObject("Arguments"),"Argument");
					if(Arguments.length() >0) {
						Element ArgumentRoot = TreeMaproot.addElement("Arguments");
						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
							JSONObject rowItem = Arguments.getJSONObject(argIdx);
							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
//							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
						}
					}
				}
				break;
			case "Funnelchart":
			case "Pyramidchart":
				JSONArray FunnelChartArray = itemObj.getJSONArray(KeyName);
				for(int eachMapItem =0;eachMapItem<FunnelChartArray.length();eachMapItem++) {
					JSONObject FunnelChartObj = FunnelChartArray.getJSONObject(eachMapItem);
					Element FunnelChartroot = items.addElement(KeyName);
					FunnelChartroot.addAttribute("ComponentName", FunnelChartObj.getString("ComponentName"));
					FunnelChartroot.addAttribute("Name", FunnelChartObj.getString("Name"));
					FunnelChartroot.addAttribute("MemoText", FunnelChartObj.getString("MemoText"));
					FunnelChartroot.addAttribute("DataSource", FunnelChartObj.getString("DataSource"));
					FunnelChartroot.addAttribute("LabelPosition", FunnelChartObj.getString("LabelPosition"));
					
					if(FunnelChartObj.has("Legend")) {
						JSONObject LegendObject = FunnelChartObj.getJSONObject("Legend");
						Element FunnelLegend = FunnelChartroot.addElement("Legend");
						FunnelLegend.addAttribute("Visible", LegendObject.getBoolean("Visible") == true? "true" : "false");
						FunnelLegend.addAttribute("Position", LegendObject.getString("Position"));
					}
					
					
					if(FunnelChartObj.has("LabelContentType")) {
						if(!FunnelChartObj.getString("LabelContentType").equalsIgnoreCase("ArgumentAndPercent")) {
							FunnelChartroot.addAttribute("LabelContentType", FunnelChartObj.getString("LabelContentType"));
						}
					}
					if(FunnelChartObj.has("TooltipContentType")) {
						if(!FunnelChartObj.getString("TooltipContentType").equalsIgnoreCase("ArgumentValueAndPercent")) {
							FunnelChartroot.addAttribute("TooltipContentType", FunnelChartObj.getString("TooltipContentType"));
						}
					}
					if(FunnelChartObj.has("ShowCaption")) {
						if(FunnelChartObj.getBoolean("ShowCaption") == false)
							FunnelChartroot.addAttribute("ShowCaption", "false");
					}
					
					addInteractivityOption(FunnelChartObj, FunnelChartroot);
					
					if(FunnelChartObj.has("ColoringOption")) {
						Element ColoringOptions = FunnelChartroot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", FunnelChartObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", FunnelChartObj.getString("UseGlobalColors"));
						JSONArray colorArray = FunnelChartObj.getJSONArray("ColorSheme");
						Element ColorSheme = FunnelChartroot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					
					JSONObject FunnelChartDataItems = FunnelChartObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(FunnelChartDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(FunnelChartDataItems, "Measure");
					
					Element FunnelChartMapDataItems = FunnelChartroot.addElement("DataItems");
					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
						Element DimFunnelChartAttr = FunnelChartMapDataItems.addElement("Dimension");
						DimFunnelChartAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						if(dimdata.has("Name")) {
							DimFunnelChartAttr.addAttribute("Name",  dimdata.getString("Name"));
						}
						DimFunnelChartAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimFunnelChartAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
//						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
					}

					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
						Element MeaFunnelChartAttr = FunnelChartMapDataItems.addElement("Measure");
						MeaFunnelChartAttr.addAttribute("DataMember", meadata.getString("DataMember"));
						if(meadata.has("Name")) {
							MeaFunnelChartAttr.addAttribute("Name",  meadata.getString("Name"));
						}
						String summaryType = "";
						if(meadata.has("SummaryType")) {
							switch(meadata.getString("SummaryType")) {
							case "count":
								summaryType = "Count";
								break;
							case "min":
								summaryType = "Min";
								break;
							case "max":
								summaryType = "Max";
								break;
							case "avg":
								summaryType = "Average";
								break;
							default:
								summaryType = "Sum";
								break;
							}
						}else {
							summaryType = "Sum";
						}
						
						if (meadata.has("NumericFormat")) {
							Element NumericFormat = MeaFunnelChartAttr.addElement("NumericFormat");
							JSONObject FunnelChartNumericFormat = meadata.getJSONObject("NumericFormat");
							if (FunnelChartNumericFormat.has("FormatType"))
								NumericFormat.addAttribute("FormatType", FunnelChartNumericFormat.getString("FormatType"));
							if (FunnelChartNumericFormat.has("Precision"))
								NumericFormat.addAttribute("Precision", FunnelChartNumericFormat.get("Precision") + "");
							if (FunnelChartNumericFormat.has("PrecisionOption"))
								NumericFormat.addAttribute("PrecisionOption", FunnelChartNumericFormat.getString("PrecisionOption") + "");
							if (FunnelChartNumericFormat.has("Unit"))
								NumericFormat.addAttribute("Unit", FunnelChartNumericFormat.getString("Unit"));
						}
						MeaFunnelChartAttr.addAttribute("SummaryType",  summaryType);
						MeaFunnelChartAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
						if(meadata.has("CubeUniqueName")) {
							MeaFunnelChartAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
						}
//						MeaGridAttr.addAttribute("DefaultId", meadata.getString("UniqueName"));
					}
					
					
					JSONArray Values = toJsonArray(FunnelChartObj.getJSONObject("Values"), "Value");
					if(Values.length() >0) {
						Element ValueRoot = FunnelChartroot.addElement("Values");
						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
							JSONObject valItem = Values.getJSONObject(valueIdx);
							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
//							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
						}
					}
					
					
					JSONArray Arguments = toJsonArray(FunnelChartObj.getJSONObject("Arguments"),"Argument");
					if(Arguments.length() >0) {
						Element ArgumentRoot = FunnelChartroot.addElement("Arguments");
						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
							JSONObject rowItem = Arguments.getJSONObject(argIdx);
							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
//							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
						}
					}
				}
				break;
			case "RangeBarChart":
			case "RangeAreaChart":
			/*dogfoot 타임라인 차트 추가 shlim 20200828*/
			case "TimeLineChart":
				JSONArray rangeBarChartItemArray = itemObj.getJSONArray(KeyName);
				for(int eachChartItem = 0;eachChartItem < rangeBarChartItemArray.length();eachChartItem++) {
					JSONObject rangeBarChartObj = rangeBarChartItemArray.getJSONObject(eachChartItem);
					JSONObject rangeBarChartDataItem = rangeBarChartObj.getJSONObject("DataItems");

					
					JSONObject chartPanes = rangeBarChartObj.getJSONObject("Panes");

					Element Chartroot = items.addElement(KeyName);
					Chartroot.addAttribute("ComponentName", rangeBarChartObj.getString("ComponentName"));
					Chartroot.addAttribute("Name", rangeBarChartObj.getString("Name"));
					Chartroot.addAttribute("MemoText", rangeBarChartObj.getString("MemoText"));
					Chartroot.addAttribute("DataSource", rangeBarChartObj.getString("DataSource"));
					
					
					addInteractivityOption(rangeBarChartObj, Chartroot);
					
					if (rangeBarChartObj.has("IsMasterFilterCrossDataSource")) {
						if (rangeBarChartObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							Chartroot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					if (rangeBarChartObj.has("Rotated")) {
						if(rangeBarChartObj.getBoolean("Rotated") == true) {
							Chartroot.addAttribute("Rotated","true");
						}
					}
					if(rangeBarChartObj.has("ShowCaption")) {
						if(rangeBarChartObj.getBoolean("ShowCaption") == false)
							Chartroot.addAttribute("ShowCaption", "false");
					}
					if(rangeBarChartObj.has("FilterString")) {
						Chartroot.addAttribute("FilterString", rangeBarChartObj.getString("FilterString"));
					}
					Element DataItems = Chartroot.addElement("DataItems");
					JSONArray DataItemAttr = toJsonArray(rangeBarChartDataItem, "Measure");
					if (DataItemAttr != null) {
						for (int Mea = 0; Mea < DataItemAttr.length(); Mea++) {
							Element Measure = DataItems.addElement("Measure");
							Measure.addAttribute("DataMember", DataItemAttr.getJSONObject(Mea).getString("DataMember"));
							String summaryType = "";
							if(DataItemAttr.getJSONObject(Mea).has("SummaryType")) {
								switch(DataItemAttr.getJSONObject(Mea).getString("SummaryType")) {
								case "countdistinct":
									summaryType = "CountDistinct";
									break;
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}
							
							Measure.addAttribute("SummaryType",  summaryType);
							if(DataItemAttr.getJSONObject(Mea).has("Name")) {
								Measure.addAttribute("Name",  DataItemAttr.getJSONObject(Mea).getString("Name"));
							}
							Measure.addAttribute("UniqueName", DataItemAttr.getJSONObject(Mea).getString("UniqueName"));
							/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 밑으로 CubeUniqueName 부분 전부  20200618 */
							if(DataItemAttr.getJSONObject(Mea).has("CubeUniqueName")) {
								Measure.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Mea).getString("CubeUniqueName"));
							}
							/*dogfoot shlim 바 ,영역 분포 차트  대상아이템 정보 추가 20200826*/
							if(DataItemAttr.getJSONObject(Mea).has("DeltaItem")) {
								Measure.addAttribute("DeltaItem",  DataItemAttr.getJSONObject(Mea).getString("DeltaItem"));
							}
							if (DataItemAttr.getJSONObject(Mea).has("NumericFormat")) {
								Element NumericFormat = Measure.addElement("NumericFormat");
								JSONObject ChartNumericFormat = DataItemAttr.getJSONObject(Mea)
										.getJSONObject("NumericFormat");
								if (ChartNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", ChartNumericFormat.getString("FormatType"));
								if (ChartNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", ChartNumericFormat.getString("Unit"));
								if (ChartNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", ChartNumericFormat.get("Precision") + "");
								if (ChartNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", ChartNumericFormat.getString("PrecisionOption") + "");
								if (ChartNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator", ChartNumericFormat.get("IncludeGroupSeparator").toString());
							}

						}
					}

					DataItemAttr = toJsonArray(rangeBarChartDataItem, "Dimension");
					if (DataItemAttr != null) {
						for (int Dim = 0; Dim < DataItemAttr.length(); Dim++) {
							Element Dimension = DataItems.addElement("Dimension");
							Dimension.addAttribute("DataMember", DataItemAttr.getJSONObject(Dim).getString("DataMember"));
							if(DataItemAttr.getJSONObject(Dim).has("Name")) {
								Dimension.addAttribute("Name",  DataItemAttr.getJSONObject(Dim).getString("Name"));
							}
							if (DataItemAttr.getJSONObject(Dim).has("SortOrder")) {
								if(DataItemAttr.getJSONObject(Dim).getString("SortOrder").equalsIgnoreCase("Descending"))
									Dimension.addAttribute("SortOrder", "Descending");
							}
							if(DataItemAttr.getJSONObject(Dim).has("SortByMeasure")) {
								Dimension.addAttribute("SortByMeasure", DataItemAttr.getJSONObject(Dim).getString("SortByMeasure"));
							}
							//2020-01-14 LSH topN 차트 저장
							if(DataItemAttr.getJSONObject(Dim).has("TopNEnabled")) {
								String TopNEnabled = "true";
								Dimension.addAttribute("TopNEnabled",TopNEnabled);
								/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
								if(DataItemAttr.getJSONObject(Dim).has("TopNOrder")) {
									Dimension.addAttribute("TopNOrder", DataItemAttr.getJSONObject(Dim).get("TopNOrder")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNCount")) {
									Dimension.addAttribute("TopNCount", DataItemAttr.getJSONObject(Dim).get("TopNCount")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNMeasure")) {
									Dimension.addAttribute("TopNMeasure", DataItemAttr.getJSONObject(Dim).get("TopNMeasure")+"");
								}
								if(DataItemAttr.getJSONObject(Dim).has("TopNShowOthers")) {
									String TopNShowOthers = "true";
									Dimension.addAttribute("TopNShowOthers",TopNShowOthers);
								}
							}
							if (DataItemAttr.getJSONObject(Dim).has("ColoringMode")) {
								Dimension.addAttribute("ColoringMode",
										DataItemAttr.getJSONObject(Dim).getString("ColoringMode"));
							}
							Dimension.addAttribute("UniqueName", DataItemAttr.getJSONObject(Dim).getString("UniqueName"));
							if(DataItemAttr.getJSONObject(Dim).has("CubeUniqueName")) {
								Dimension.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Dim).getString("CubeUniqueName"));
							}
						}
					}
					if(rangeBarChartObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = rangeBarChartObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = Chartroot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					if (rangeBarChartObj.has("Arguments")) {
						JSONObject chartArguments = rangeBarChartObj.getJSONObject("Arguments");
						JSONArray ArgumentsArr = toJsonArray(chartArguments, "Argument");
						Element Arguments = Chartroot.addElement("Arguments");
						for (int arg = 0; arg < ArgumentsArr.length(); arg++) {
							Element ArgumentsAttr = Arguments.addElement("Argument");
							ArgumentsAttr.addAttribute("UniqueName",
									ArgumentsArr.getJSONObject(arg).getString("UniqueName"));
							if(ArgumentsArr.getJSONObject(arg).has("CubeUniqueName")) {
								ArgumentsAttr.addAttribute("CubeUniqueName",  ArgumentsArr.getJSONObject(arg).getString("CubeUniqueName"));
							}
						}
					}
					
					if (rangeBarChartObj.has("StartDate")) {
						JSONObject chartStartDate = rangeBarChartObj.getJSONObject("StartDate");
						JSONArray StartDateArr = toJsonArray(chartStartDate, "StartDate");
						Element StartDate = Chartroot.addElement("StartDate");
						for (int arg = 0; arg < StartDateArr.length(); arg++) {
							Element StartDateAttr = StartDate.addElement("StartDate");
							StartDateAttr.addAttribute("UniqueName",
									StartDateArr.getJSONObject(arg).getString("UniqueName"));
							if(StartDateArr.getJSONObject(arg).has("CubeUniqueName")) {
								StartDateAttr.addAttribute("CubeUniqueName",  StartDateArr.getJSONObject(arg).getString("CubeUniqueName"));
							}
						}
					}
					
					if (rangeBarChartObj.has("EndDate")) {
						JSONObject chartEndDate = rangeBarChartObj.getJSONObject("EndDate");
						JSONArray EndDateArr = toJsonArray(chartEndDate, "EndDate");
						Element EndDate = Chartroot.addElement("EndDate");
						for (int arg = 0; arg < EndDateArr.length(); arg++) {
							Element EndDateAttr = EndDate.addElement("EndDate");
							EndDateAttr.addAttribute("UniqueName",
									EndDateArr.getJSONObject(arg).getString("UniqueName"));
							if(EndDateArr.getJSONObject(arg).has("CubeUniqueName")) {
								EndDateAttr.addAttribute("CubeUniqueName",  EndDateArr.getJSONObject(arg).getString("CubeUniqueName"));
							}
						}
					}
					

					
					if(rangeBarChartObj.has("ColoringOption")) {
						Element ColoringOptions = Chartroot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", rangeBarChartObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", rangeBarChartObj.getString("UseGlobalColors"));
						JSONArray colorArray = rangeBarChartObj.getJSONArray("ColorSheme");
						Element ColorSheme = Chartroot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					
					if (rangeBarChartObj.has("SeriesDimensions")) {
						JSONObject chartseriesDim = rangeBarChartObj.getJSONObject("SeriesDimensions");
						JSONArray SeriesDimArr = toJsonArray(chartseriesDim, "SeriesDimension");
						Element SeriesDimensions = Chartroot.addElement("SeriesDimensions");
						for (int serdim = 0; serdim < SeriesDimArr.length(); serdim++) {
							Element SeriesDimensionAttr = SeriesDimensions.addElement("SeriesDimension");
							SeriesDimensionAttr.addAttribute("UniqueName",
									SeriesDimArr.getJSONObject(serdim).getString("UniqueName"));
							if(SeriesDimArr.getJSONObject(serdim).has("CubeUniqueName")) {
								SeriesDimensionAttr.addAttribute("CubeUniqueName",  SeriesDimArr.getJSONObject(serdim).getString("CubeUniqueName"));
							}
						}
					}
					
					JSONArray PanesArr = toJsonArray(chartPanes, "Pane");
					Element Panes = Chartroot.addElement("Panes");
					Element AxisY = null;
					for (int pane = 0; pane < PanesArr.length(); pane++) {
						JSONObject PaneObj = PanesArr.getJSONObject(pane);
						Element Pane = Panes.addElement("Pane");
						Pane.addAttribute("Name", PaneObj.getString("Name"));
						if(rangeBarChartObj.has("ChartYOption")) {
							JSONObject chartYoption = rangeBarChartObj.getJSONObject("ChartYOption");
							AxisY = Pane.addElement("AxisY");
							if (chartYoption.has("Visible")) {
								if (chartYoption.getBoolean("Visible") != true)
									AxisY.addAttribute("Visible", "false");
							}
							if (chartYoption.has("Title")) {
								if (!chartYoption.getString("Title").equals("")) {
									AxisY.addAttribute("Title", chartYoption.getString("Title"));
								}
							}
							if (chartYoption.has("ShowZero")) {
								AxisY.addAttribute("ShowZero", chartYoption.getBoolean("ShowZero") ? "true" : "false");
							}
							if (chartYoption.has("FormatType") || chartYoption.has("Precision") || chartYoption.has("Unit") || chartYoption.has("Separator")) {
								Element numFormat = AxisY.addElement("NumericFormat");
								if (chartYoption.has("FormatType")) {
									numFormat.addAttribute("FormatType", chartYoption.getString("FormatType"));
								}
								if (chartYoption.has("Precision")) {
									numFormat.addAttribute("Precision", chartYoption.getInt("Precision") + "");
								}
								if (chartYoption.has("PrecisionOption")) {
									numFormat.addAttribute("PrecisionOption", chartYoption.getString("PrecisionOption") + "");
								}
								if (chartYoption.has("Unit")) {
									numFormat.addAttribute("Unit", chartYoption.getString("Unit"));
								}
								if (chartYoption.has("Separator")) {
									numFormat.addAttribute("IncludeGroupSeparator", chartYoption.getBoolean("Separator") ? "true" : "false");
								}
							}
						}
						
						Element Series = Pane.addElement("Series");
						JSONArray SeriesArr = toJsonArray(PaneObj, "Series");
						for (int series = 0; series < SeriesArr.length(); series++) {
							JSONObject SeriesItem = SeriesArr.getJSONObject(series);
							if (toJsonArray(SeriesItem, "Simple") != null) {
								JSONArray simpleArr = toJsonArray(SeriesItem, "Simple");
								for (int simple = 0; simple < simpleArr.length(); simple++) {
									JSONObject simpleItem = simpleArr.getJSONObject(simple);
									
									Element Simple = Series.addElement("Simple");
									if (simpleItem.has("IgnoreEmptyPoints")) {
										Simple.addAttribute("IgnoreEmptyPoints", simpleItem.getBoolean("IgnoreEmptyPoints") ? "true" : "false");
									}
									if (simpleItem.has("PlotOnSecondaryAxis")) {
										Simple.addAttribute("PlotOnSecondaryAxis", simpleItem.getBoolean("PlotOnSecondaryAxis") ? "true" : "false");
									}
									if (simpleItem.has("SeriesType")) {
										if (!simpleItem.getString("SeriesType").equalsIgnoreCase("bar"))
											Simple.addAttribute("SeriesType", simpleItem.getString("SeriesType"));
									}
									if (simpleItem.has("ShowPointMarkers")) {
										Simple.addAttribute("ShowPointMarkers", simpleItem.getBoolean("ShowPointMarkers") ? "true" : "false");
									}
									Element Value = Simple.addElement("Value");
									Value.addAttribute("UniqueName", simpleItem.getJSONObject("Value").getString("UniqueName"));
									/*dogfoot 영역 분포 차트 포인트 옵션 추가 shlim 20200828*/
									if(simpleItem.has("PointLabelOptions")) {
										JSONObject ploItem = simpleItem.getJSONObject("PointLabelOptions");
										if (ploItem != null) {
											Element plo = Simple.addElement("PointLabelOptions");
											if (ploItem.has("ContentType") && !(ploItem.getString("ContentType").equals(""))) {
												plo.addAttribute("ContentType", ploItem.getString("ContentType"));
											}
											if (ploItem.has("Orientation")) {
												plo.addAttribute("Orientation", ploItem.getString("Orientation"));
											}
											if (ploItem.has("OverlappingMode")) {
												plo.addAttribute("OverlappingMode", ploItem.getString("OverlappingMode"));
											}
											if (ploItem.has("Position")) {
												plo.addAttribute("Position", ploItem.getString("Position"));
											}
											if (ploItem.has("showForZeroValues")) {
												plo.addAttribute("ShowForZeroValues", ploItem.getBoolean("showForZeroValues") ? "true" : "false");
											}
											if (ploItem.has("FillBackground")) {
												plo.addAttribute("FillBackground", ploItem.getBoolean("FillBackground") ? "true" : "false");
											}
											if (ploItem.has("ShowBorder")) {
												plo.addAttribute("ShowBorder", ploItem.getBoolean("ShowBorder") ? "true" : "false");
											}
											if (ploItem.has("ShowCustomTextColor")) {
												plo.addAttribute("ShowCustomTextColor", ploItem.getBoolean("ShowCustomTextColor") ? "true" : "false");
											}
										}
									}
									
								}
							}
							if (toJsonArray(SeriesItem, "Weighted") != null) {
								JSONArray weightedArr = toJsonArray(SeriesItem, "Weighted");
								for (int weightedIndex = 0; weightedIndex < weightedArr.length(); weightedIndex++) {
									JSONObject weightedItem = weightedArr.getJSONObject(weightedIndex);
									Element Weighted = Series.addElement("Weighted");
									Element Value = Weighted.addElement("Value");
									Element Weight = Weighted.addElement("Weight");
									Value.addAttribute("UniqueName", weightedItem.getJSONObject("Value").getString("UniqueName"));
									Weight.addAttribute("UniqueName", weightedItem.getJSONObject("Weight").getString("UniqueName"));
									
									if (weightedItem.has("IgnoreEmptyPoints")) {
										Weighted.addAttribute("IgnoreEmptyPoints", weightedItem.getBoolean("IgnoreEmptyPoints") ? "true" : "false");
									}
									if (weightedItem.has("PlotOnSecondaryAxis")) {
										Weighted.addAttribute("PlotOnSecondaryAxis", weightedItem.getBoolean("PlotOnSecondaryAxis") ? "true" : "false");
									}
									if (weightedItem.has("SeriesType")) {
										if (!weightedItem.getString("SeriesType").equalsIgnoreCase("bar"))
											Weighted.addAttribute("SeriesType", weightedItem.getString("SeriesType"));
									}
									if (weightedItem.has("ShowPointMarkers")) {
										Weighted.addAttribute("ShowPointMarkers", weightedItem.getBoolean("ShowPointMarkers") ? "true" : "false");
									}
									Value.addAttribute("UniqueName", weightedItem.getJSONObject("Value").getString("UniqueName"));
									JSONObject ploItem = weightedItem.getJSONObject("PointLabelOptions");
									if (ploItem != null) {
										Element plo = Weighted.addElement("PointLabelOptions");
										if (ploItem.has("ContentType") && !(ploItem.getString("ContentType").equals(""))) {
											plo.addAttribute("ContentType", ploItem.getString("ContentType"));
										}
										if (ploItem.has("Orientation")) {
											plo.addAttribute("Orientation", ploItem.getString("Orientation"));
										}
										if (ploItem.has("OverlappingMode")) {
											plo.addAttribute("OverlappingMode", ploItem.getString("OverlappingMode"));
										}
										if (ploItem.has("Position")) {
											plo.addAttribute("Position", ploItem.getString("Position"));
										}
										if (ploItem.has("ShowForZeroValues")) {
											plo.addAttribute("ShowForZeroValues", ploItem.getBoolean("ShowForZeroValues") ? "true" : "false");
										}
										if (ploItem.has("FillBackground")) {
											plo.addAttribute("FillBackground", ploItem.getBoolean("FillBackground") ? "true" : "false");
										}
										if (ploItem.has("ShowBorder")) {
											plo.addAttribute("ShowBorder", ploItem.getBoolean("ShowBorder") ? "true" : "false");
										}
									}
								}
							}
						}
						if(rangeBarChartObj.has("ChartXOption")) {
							JSONObject chartXoption = rangeBarChartObj.getJSONObject("ChartXOption");
							Element chartX = Chartroot.addElement("AxisX");
							if(chartXoption.has("Visible")) {
								if(chartXoption.getBoolean("Visible") != true) {
									chartX.addAttribute("Visible", "false");
									chartX.addAttribute("TitleVisible", "false");
								}
							}
							if(chartXoption.has("Title")) {
								if(!chartXoption.getString("Title").equals("")) {
									chartX.addAttribute("Title", chartXoption.getString("Title"));
								}
							}
							if(chartXoption.has("Rotation")) {
								chartX.addAttribute("Rotation", chartXoption.getInt("Rotation") + "");
							}
						}
						if(rangeBarChartObj.has("ChartLegend")) {
							JSONObject chartLegendObj = rangeBarChartObj.getJSONObject("ChartLegend");
							Element chartLegend = Chartroot.addElement("ChartLegend");
							if(chartLegendObj.has("Visible")) {
								chartLegend.addAttribute("Visible", chartLegendObj.getBoolean("Visible") ? "true" : "false");
							}
							if(chartLegendObj.has("IsInsidePosition")) {
								chartLegend.addAttribute("IsInsidePosition", chartLegendObj.getBoolean("IsInsidePosition") ? "true" : "false");
							}
							if(chartLegendObj.has("InsidePosition")) {
								chartLegend.addAttribute("InsidePosition", chartLegendObj.getString("InsidePosition"));
							}
							if(chartLegendObj.has("OutsidePosition")) {
								chartLegend.addAttribute("OutsidePosition", chartLegendObj.getString("OutsidePosition"));
							}
						}
					}
				}
				break;
			case "Parallel":
			case "BubbleD3":
			case "RectangularAreaChart":
			case "Waterfallchart":
			case "Bipartitechart":
			case "Sankeychart":
			case "ForceDirect":
			case "ForceDirectExpand":
			case "HeatMap":
			case "HeatMap2":
			case "CoordinateDot":
            case "SynchronizedChart":
			case "WordCloud":
			case "HistogramChart":
			case "DivergingChart":
			case "ScatterPlot":
			case "ScatterPlot2":
			case "HistoryTimeline":
			case "ArcDiagram":
			case "RadialTidyTree":
			case "ScatterPlotMatrix":
			case "BoxPlot":
			case "CoordinateLine":
			case "LiquidFillGauge":
			case "SequencesSunburst":
			case "DependencyWheel":
			case "BubblePackChart":
			case "CalendarViewChart":
			case "CalendarView2Chart":
			case "CalendarView3Chart":
			case "CollapsibleTreeChart":
			case "DendrogramBarChart":
				JSONArray ParallelArray = itemObj.getJSONArray(KeyName);
				for(int eachMapItem =0;eachMapItem<ParallelArray.length();eachMapItem++) {
					JSONObject ParallelObj = ParallelArray.getJSONObject(eachMapItem);
					Element Parallelroot = items.addElement(KeyName);
					Parallelroot.addAttribute("ComponentName", ParallelObj.getString("ComponentName"));
					Parallelroot.addAttribute("Name", ParallelObj.getString("Name"));
					Parallelroot.addAttribute("MemoText", ParallelObj.getString("MemoText"));
					Parallelroot.addAttribute("DataSource", ParallelObj.getString("DataSource"));
					
					if(ParallelObj.has("ShowCaption")) {
						if(ParallelObj.getBoolean("ShowCaption") == false) {
							Parallelroot.addAttribute("ShowCaption", "false");
						}
					}
					
					if(ParallelObj.has("Legend")) {
						JSONObject LegendObject = ParallelObj.getJSONObject("Legend");
						Element ParalleLegend = Parallelroot.addElement("Legend");
						ParalleLegend.addAttribute("Visible", LegendObject.getBoolean("Visible") == true? "true" : "false");
						ParalleLegend.addAttribute("Position", LegendObject.getString("Position"));
					}
					
					if(ParallelObj.has("TextFormat")) {
						Parallelroot.addAttribute("TextFormat", ParallelObj.getString("TextFormat"));
					}
					if(ParallelObj.has("ZoomAble")) {
						Parallelroot.addAttribute("ZoomAble", ParallelObj.getString("ZoomAble"));
					}
					
					if(ParallelObj.has("Rotated")) {
						Parallelroot.addAttribute("Rotated", ParallelObj.getString("Rotated"));
					}
					
					addInteractivityOption(ParallelObj, Parallelroot);
					
					JSONObject ParallelDataItems = ParallelObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(ParallelDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(ParallelDataItems, "Measure");
					
					Element ParallelMapDataItems = Parallelroot.addElement("DataItems");
					/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 - null 검사 dogfoot*/
					if(DimDataItems != null) {
						for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
							JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
							Element DimParallelAttr = ParallelMapDataItems.addElement("Dimension");
							DimParallelAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
							if(dimdata.has("Name")) {
								DimParallelAttr.addAttribute("Name",  dimdata.getString("Name"));
							}
							DimParallelAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
							if(dimdata.has("CubeUniqueName")) {
								DimParallelAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
							}
							if(dimdata.has("SortOrder")) {
								if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
									DimParallelAttr.addAttribute("SortOrder", "Descending");
								}
							}
							
							if(dimdata.has("SortByMeasure")) {
								DimParallelAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
							}
	//						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
						}
					}
					
					if(MeaDataItems != null) {
						for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
							JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
							Element MeaParallelAttr = ParallelMapDataItems.addElement("Measure");
							MeaParallelAttr.addAttribute("DataMember", meadata.getString("DataMember"));
							if(meadata.has("Name")) {
								MeaParallelAttr.addAttribute("Name",  meadata.getString("Name"));
							}
							String summaryType = "";
							if(meadata.has("SummaryType")) {
								switch(meadata.getString("SummaryType")) {
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}
							MeaParallelAttr.addAttribute("SummaryType",  summaryType);
							MeaParallelAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
							if(meadata.has("CubeUniqueName")) {
								MeaParallelAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
							}
							if (meadata.has("NumericFormat")) {
								Element NumericFormat = MeaParallelAttr.addElement("NumericFormat");
								JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
								if (PivotNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
								if (PivotNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
								if (PivotNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", PivotNumericFormat.getString("PrecisionOption") + "");
								if (PivotNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
								/*dogfoot d3 차트 표기형식 저장 추가 shlim 20200828*/
								if (PivotNumericFormat.has("SuffixEnabled")) {
									NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
								}
								if (PivotNumericFormat.has("Suffix")) {
									Element Suffix = NumericFormat.addElement("Suffix");
									JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
									Suffix.addAttribute("O", suffix.getString("O"));
									Suffix.addAttribute("K", suffix.getString("K"));
									Suffix.addAttribute("M", suffix.getString("M"));
									Suffix.addAttribute("B", suffix.getString("B"));
								}
								if (PivotNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator",
											PivotNumericFormat.get("IncludeGroupSeparator").toString());
							}
//							MeaGridAttr.addAttribute("DefaultId", meadata.getString("UniqueName"));
						}
					}
					
					if(ParallelObj.has("Values")) {
						JSONArray Values = toJsonArray(ParallelObj.getJSONObject("Values"), "Value");
						if(Values.length() >0) {
							Element ValueRoot = Parallelroot.addElement("Values");
							for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
								JSONObject valItem = Values.getJSONObject(valueIdx);
								ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
	//							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
							}
						}
					}
					if(ParallelObj.has("SeriesDimensions")) {
						JSONArray SeriesDimensions = toJsonArray(ParallelObj.getJSONObject("SeriesDimensions"), "SeriesDimension");
						if(SeriesDimensions.length() >0) {
							Element SeriesRoot = Parallelroot.addElement("SeriesDimensions");
							for(int valueIdx = 0; valueIdx<SeriesDimensions.length();valueIdx++) {
								JSONObject valItem = SeriesDimensions.getJSONObject(valueIdx);
								System.out.println(valItem.getString("UniqueName"));
								SeriesRoot.addElement("SeriesDimension").addAttribute("UniqueName", valItem.getString("UniqueName"));
	//							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
							}
						}
					}
					
					if(ParallelObj.has("Arguments")) {
						JSONArray Arguments = toJsonArray(ParallelObj.getJSONObject("Arguments"),"Argument");
						if(Arguments.length() >0) {
							Element ArgumentRoot = Parallelroot.addElement("Arguments");
							for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
								JSONObject rowItem = Arguments.getJSONObject(argIdx);
								ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
//								ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
							}
						}
					}
					
					
					if(ParallelObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = ParallelObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = Parallelroot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					if(ParallelObj.has("ColoringOption")) {
						Element ColoringOptions = Parallelroot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", ParallelObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", ParallelObj.getString("UseGlobalColors"));
						JSONArray colorArray = ParallelObj.getJSONArray("ColorSheme");
						Element ColorSheme = Parallelroot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					/*dogfoot Y축 설정 추가 shlim 20200831*/
					Element AxisY = null;
					if(ParallelObj.has("ChartYOption")) {
						AxisY = Parallelroot.addElement("AxisY");
						JSONObject chartYoption = ParallelObj.getJSONObject("ChartYOption");
						if (chartYoption.has("Visible")) {
							if (chartYoption.getBoolean("Visible") != true) {
								AxisY.addAttribute("Visible", "false");
							}else {
								AxisY.addAttribute("Visible", "true");
							}
								
						}
						if (chartYoption.has("Title")) {
							if (!chartYoption.getString("Title").equals("")) {
								AxisY.addAttribute("Title", chartYoption.getString("Title"));
							}
						}
						if (chartYoption.has("ShowZero")) {
							AxisY.addAttribute("ShowZero", chartYoption.getBoolean("ShowZero") ? "true" : "false");
						}
						if (chartYoption.has("FormatType") || chartYoption.has("Precision") || chartYoption.has("Unit") || chartYoption.has("Separator")) {
							//Element numFormat = AxisY.addElement("MeasureFormat");
							
							if (chartYoption.has("MeasureFormat")) {
								Element MeasureFormat = AxisY.addElement("MeasureFormat");
								JSONObject measureformat = chartYoption.getJSONObject("MeasureFormat");
								MeasureFormat.addAttribute("O", measureformat.get("O") + "");
								MeasureFormat.addAttribute("K", measureformat.get("K") + "");
								MeasureFormat.addAttribute("M", measureformat.get("M") + "");
								MeasureFormat.addAttribute("B", measureformat.get("B") + "");
							}
							if (chartYoption.has("FormatType")) {
								AxisY.addAttribute("FormatType", chartYoption.getString("FormatType"));
							}
							if (chartYoption.has("Precision")) {
								AxisY.addAttribute("Precision", chartYoption.getInt("Precision") + "");
							}
							if (chartYoption.has("PrecisionOption")) {
								AxisY.addAttribute("PrecisionOption", chartYoption.getString("PrecisionOption") + "");
							}
							if (chartYoption.has("Unit")) {
								AxisY.addAttribute("Unit", chartYoption.getString("Unit"));
							}
							if (chartYoption.has("Separator")) {
								AxisY.addAttribute("Separator", chartYoption.getBoolean("Separator") ? "true" : "false");
							}
							if (chartYoption.has("SuffixEnabled")) {
								AxisY.addAttribute("SuffixEnabled", chartYoption.getBoolean("SuffixEnabled") ? "true" : "false");
							}
						}
					}
					
					Element AxisX = null;
					if(ParallelObj.has("ChartXOption")) {
						AxisX = Parallelroot.addElement("AxisX");
						JSONObject chartXoption = ParallelObj.getJSONObject("ChartXOption");
						if (chartXoption.has("Visible")) {
							if (chartXoption.getBoolean("Visible") != true) {
								AxisX.addAttribute("Visible", "false");
							}else {
								AxisX.addAttribute("Visible", "true");
							}
								
						}
						
						if (chartXoption.has("Overlapping")) {
							if (chartXoption.getBoolean("Overlapping") != true) {
								AxisX.addAttribute("Overlapping", "false");
							}else {
								AxisX.addAttribute("Overlapping", "true");
							}
								
						}
						if (chartXoption.has("Title")) {
							if (!chartXoption.getString("Title").equals("")) {
								AxisX.addAttribute("Title", chartXoption.getString("Title"));
							}
						}
						if (chartXoption.has("ShowZero")) {
							AxisX.addAttribute("ShowZero", chartXoption.getBoolean("ShowZero") ? "true" : "false");
						}
						if (chartXoption.has("FormatType") || chartXoption.has("Precision") || chartXoption.has("Unit") || chartXoption.has("Separator")) {
							//Element numFormat = AxisX.addElement("MeasureFormat");
							
							if (chartXoption.has("MeasureFormat")) {
								Element MeasureFormat = AxisX.addElement("MeasureFormat");
								JSONObject measureformat = chartXoption.getJSONObject("MeasureFormat");
								MeasureFormat.addAttribute("O", measureformat.get("O") + "");
								MeasureFormat.addAttribute("K", measureformat.get("K") + "");
								MeasureFormat.addAttribute("M", measureformat.get("M") + "");
								MeasureFormat.addAttribute("B", measureformat.get("B") + "");
							}
							if (chartXoption.has("FormatType")) {
								AxisX.addAttribute("FormatType", chartXoption.getString("FormatType"));
							}
							if (chartXoption.has("Precision")) {
								AxisX.addAttribute("Precision", chartXoption.getInt("Precision") + "");
							}
							if (chartXoption.has("PrecisionOption")) {
								AxisX.addAttribute("PrecisionOption", chartXoption.getString("PrecisionOption") + "");
							}
							if (chartXoption.has("Unit")) {
								AxisX.addAttribute("Unit", chartXoption.getString("Unit"));
							}
							if (chartXoption.has("Separator")) {
								AxisX.addAttribute("Separator", chartXoption.getBoolean("Separator") ? "true" : "false");
							}
							if (chartXoption.has("SuffixEnabled")) {
								AxisX.addAttribute("SuffixEnabled", chartXoption.getBoolean("SuffixEnabled") ? "true" : "false");
							}
						}
					}
					
					if(ParallelObj.has("ExpandOption")) {
						JSONObject chartLegendObj = ParallelObj.getJSONObject("ExpandOption");
						Element chartLegend = Parallelroot.addElement("ExpandOption");
						if(chartLegendObj.has("LabelOverlapping")) {
							chartLegend.addAttribute("LabelOverlapping", chartLegendObj.getBoolean("LabelOverlapping") ? "true" : "false");
						}
					}
					
					if(ParallelObj.has("ContentOption")) {
						JSONObject contentOptionObj = ParallelObj.getJSONObject("ContentOption");
						Element contentOption = Parallelroot.addElement("ContentOption");
						if(contentOptionObj.has("ContentAutoColumn")) {
							contentOption.addAttribute("ContentAutoColumn", contentOptionObj.getBoolean("ContentAutoColumn") ? "true" : "false");
						}
						if(contentOptionObj.has("ContentColumnCount")) {
							contentOption.addAttribute("ContentColumnCount", contentOptionObj.getInt("ContentColumnCount") + "");
						}
					}
					
					if(ParallelObj.has("ChartLegend")) {
						JSONObject chartLegendObj = ParallelObj.getJSONObject("ChartLegend");
						Element chartLegend = Parallelroot.addElement("ChartLegend");
						if(chartLegendObj.has("Visible")) {
							chartLegend.addAttribute("Visible", chartLegendObj.getBoolean("Visible") ? "true" : "false");
						}
						if(chartLegendObj.has("Position")) {
							chartLegend.addAttribute("Position", chartLegendObj.getString("Position"));
						}
					}
					
					//20200923 ajkim d3 레이아웃 옵션 추가 dogfoot
					if(ParallelObj.has("LayoutOption")) {
						JSONObject layoutOptionObj = ParallelObj.getJSONObject("LayoutOption");
						Element layoutOption = Parallelroot.addElement("LayoutOption");
						if(layoutOptionObj.has("AxisX")) {
							JSONObject xOptionObj = layoutOptionObj.getJSONObject("AxisX");
							Element xOption = layoutOption.addElement("AxisX");
							xOption.addAttribute("family", xOptionObj.getString("family"));
							if(xOptionObj.has("color"))
								xOption.addAttribute("color", xOptionObj.getString("color"));
							if(xOptionObj.has("size"))
								xOption.addAttribute("size", xOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("AxisY")) {
							JSONObject yOptionObj = layoutOptionObj.getJSONObject("AxisY");
							Element yOption = layoutOption.addElement("AxisY");
							yOption.addAttribute("family", yOptionObj.getString("family"));
							if(yOptionObj.has("color"))
								yOption.addAttribute("color", yOptionObj.getString("color"));
							if(yOptionObj.has("size"))
								yOption.addAttribute("size", yOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("Legend")) {
							JSONObject legendOptionObj = layoutOptionObj.getJSONObject("Legend");
							Element legendOption = layoutOption.addElement("Legend");
							legendOption.addAttribute("family", legendOptionObj.getString("family"));
							if(legendOptionObj.has("color"))
								legendOption.addAttribute("color", legendOptionObj.getString("color"));
							if(legendOptionObj.has("size"))
								legendOption.addAttribute("size", legendOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("Title")) {
							JSONObject titleOptionObj = layoutOptionObj.getJSONObject("Title");
							Element titleOption = layoutOption.addElement("Title");
							titleOption.addAttribute("family", titleOptionObj.getString("family"));
							if(titleOptionObj.has("color"))
								titleOption.addAttribute("color", titleOptionObj.getString("color"));
							if(titleOptionObj.has("size"))
								titleOption.addAttribute("size", titleOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("Label")) {
							JSONObject labelOptionObj = layoutOptionObj.getJSONObject("Label");
							Element labelOption = layoutOption.addElement("Label");
							labelOption.addAttribute("family", labelOptionObj.getString("family"));
							if(labelOptionObj.has("color"))
								labelOption.addAttribute("color", labelOptionObj.getString("color"));
							if(labelOptionObj.has("size"))
								labelOption.addAttribute("size", labelOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("Circle")) {
							JSONArray circleSizeArray = layoutOptionObj.getJSONArray("Circle");
							for(int arrayIndex = 0; arrayIndex < circleSizeArray.length(); arrayIndex++) {
								layoutOption.addElement("Circle").setText(circleSizeArray.get(arrayIndex).toString());
							}
						}
					}
					
					if(ParallelObj.has("Round")) {
						JSONObject chartRoundObj = ParallelObj.getJSONObject("Round");
						Element chartRound = Parallelroot.addElement("Round");
						if(chartRoundObj.has("Min")) {
							chartRound.addAttribute("Min", chartRoundObj.getDouble("Min") + "");
						}
						if(chartRoundObj.has("Max")) {
							chartRound.addAttribute("Max", chartRoundObj.getDouble("Max") + "");
						}
					}
				}
				break;
			// 임성현 주임 저장 불러오기
//			case "BubbleD3":
//				JSONArray BubbleD3Array = itemObj.getJSONArray("BubbleD3");
//				for(int eachMapItem =0;eachMapItem<BubbleD3Array.length();eachMapItem++) {
//					JSONObject BubbleD3Obj = BubbleD3Array.getJSONObject(eachMapItem);
//					Element BubbleD3root = items.addElement("BubbleD3");
//					BubbleD3root.addAttribute("ComponentName", BubbleD3Obj.getString("ComponentName"));
//					BubbleD3root.addAttribute("Name", BubbleD3Obj.getString("Name"));
//					BubbleD3root.addAttribute("MemoText", BubbleD3Obj.getString("MemoText"));
//					BubbleD3root.addAttribute("DataSource", BubbleD3Obj.getString("DataSource"));
//					
//					if(BubbleD3Obj.has("ShowCaption")) {
//						if(BubbleD3Obj.getBoolean("ShowCaption") == false) {
//							BubbleD3root.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject BubbleD3DataItems = BubbleD3Obj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(BubbleD3DataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(BubbleD3DataItems, "Measure");
//					
//					Element BubbleD3MapDataItems = BubbleD3root.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimBubbleD3Attr = BubbleD3MapDataItems.addElement("Dimension");
//						DimBubbleD3Attr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimBubbleD3Attr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimBubbleD3Attr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimBubbleD3Attr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaBubbleD3Attr = BubbleD3MapDataItems.addElement("Measure");
//						MeaBubbleD3Attr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaBubbleD3Attr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaBubbleD3Attr.addAttribute("SummaryType",  summaryType);
//						MeaBubbleD3Attr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaBubbleD3Attr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaBubbleD3Attr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					
//					JSONArray Values = toJsonArray(BubbleD3Obj.getJSONObject("Values"), "Value");
//					if(Values.length() >0) {
//						Element ValueRoot = BubbleD3root.addElement("Values");
//						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//							JSONObject valItem = Values.getJSONObject(valueIdx);
//							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//						}
//					}
//					
//					
//					JSONArray Arguments = toJsonArray(BubbleD3Obj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = BubbleD3root.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					
//					// 임성현 주임 팔레트 옵션 추가
//					if(BubbleD3Obj.has("ColoringOption")) {
//						Element ColoringOptions = BubbleD3root.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", BubbleD3Obj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", BubbleD3Obj.getString("UseGlobalColors"));
//						JSONArray colorArray = BubbleD3Obj.getJSONArray("ColorSheme");
//						Element ColorSheme = BubbleD3root.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
//							Element MeasureKey = Entry.addElement("MeasureKey");
//							Element Definition = MeasureKey.addElement("Definition");
//							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;
				// 임성현 주임 저장 추가
//			case "RectangularAreaChart":
//				JSONArray RectangularAreaChartArray = itemObj.getJSONArray("RectangularAreaChart");
//				for(int eachMapItem =0;eachMapItem<RectangularAreaChartArray.length();eachMapItem++) {
//					JSONObject RectangularAreaChartObj = RectangularAreaChartArray.getJSONObject(eachMapItem);
//					Element RectangularAreaChartroot = items.addElement("RectangularAreaChart");
//					RectangularAreaChartroot.addAttribute("ComponentName", RectangularAreaChartObj.getString("ComponentName"));
//					RectangularAreaChartroot.addAttribute("Name", RectangularAreaChartObj.getString("Name"));
//					RectangularAreaChartroot.addAttribute("MemoText", RectangularAreaChartObj.getString("MemoText"));
//					RectangularAreaChartroot.addAttribute("DataSource", RectangularAreaChartObj.getString("DataSource"));
//					
//					if(RectangularAreaChartObj.has("ShowCaption")) {
//						if(RectangularAreaChartObj.getBoolean("ShowCaption") == false) {
//							RectangularAreaChartroot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject RectangularAreaChartDataItems = RectangularAreaChartObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(RectangularAreaChartDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(RectangularAreaChartDataItems, "Measure");
//					
//					Element RectangularAreaChartMapDataItems = RectangularAreaChartroot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimRectangularAreaChartAttr = RectangularAreaChartMapDataItems.addElement("Dimension");
//						DimRectangularAreaChartAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimRectangularAreaChartAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimRectangularAreaChartAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimRectangularAreaChartAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaRectangularAreaChartAttr = RectangularAreaChartMapDataItems.addElement("Measure");
//						MeaRectangularAreaChartAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaRectangularAreaChartAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaRectangularAreaChartAttr.addAttribute("SummaryType",  summaryType);
//						MeaRectangularAreaChartAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaRectangularAreaChartAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaRectangularAreaChartAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					
//					JSONArray Values = toJsonArray(RectangularAreaChartObj.getJSONObject("Values"), "Value");
//					if(Values.length() >0) {
//						Element ValueRoot = RectangularAreaChartroot.addElement("Values");
//						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//							JSONObject valItem = Values.getJSONObject(valueIdx);
//							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//						}
//					}
//					
//					
//					JSONArray Arguments = toJsonArray(RectangularAreaChartObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = RectangularAreaChartroot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					
//					//팔레트 옵션 추가
//					if(RectangularAreaChartObj.has("ColoringOption")) {
//						Element ColoringOptions = RectangularAreaChartroot.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", RectangularAreaChartObj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", RectangularAreaChartObj.getString("UseGlobalColors"));
//						JSONArray colorArray = RectangularAreaChartObj.getJSONArray("ColorSheme");
//						Element ColorSheme = RectangularAreaChartroot.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
//							Element MeasureKey = Entry.addElement("MeasureKey");
//							Element Definition = MeasureKey.addElement("Definition");
//							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;
				// 임성현 주임 저장 추가
			
//				JSONArray WaterfallchartArray = itemObj.getJSONArray("Waterfallchart");
//				for(int eachMapItem =0;eachMapItem<WaterfallchartArray.length();eachMapItem++) {
//					JSONObject WaterfallchartObj = WaterfallchartArray.getJSONObject(eachMapItem);
//					Element Waterfallchartroot = items.addElement("Waterfallchart");
//					Waterfallchartroot.addAttribute("ComponentName", WaterfallchartObj.getString("ComponentName"));
//					Waterfallchartroot.addAttribute("Name", WaterfallchartObj.getString("Name"));
//					Waterfallchartroot.addAttribute("MemoText", WaterfallchartObj.getString("MemoText"));
//					Waterfallchartroot.addAttribute("DataSource", WaterfallchartObj.getString("DataSource"));
//					
//					if(WaterfallchartObj.has("ShowCaption")) {
//						if(WaterfallchartObj.getBoolean("ShowCaption") == false) {
//							Waterfallchartroot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject WaterfallchartDataItems = WaterfallchartObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(WaterfallchartDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(WaterfallchartDataItems, "Measure");
//					
//					Element WaterfallchartMapDataItems = Waterfallchartroot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimWaterfallchartAttr = WaterfallchartMapDataItems.addElement("Dimension");
//						DimWaterfallchartAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimWaterfallchartAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimWaterfallchartAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimWaterfallchartAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaWaterfallchartAttr = WaterfallchartMapDataItems.addElement("Measure");
//						MeaWaterfallchartAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaWaterfallchartAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaWaterfallchartAttr.addAttribute("SummaryType",  summaryType);
//						MeaWaterfallchartAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaWaterfallchartAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaWaterfallchartAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					
//					JSONArray Values = toJsonArray(WaterfallchartObj.getJSONObject("Values"), "Value");
//					if(Values.length() >0) {
//						Element ValueRoot = Waterfallchartroot.addElement("Values");
//						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//							JSONObject valItem = Values.getJSONObject(valueIdx);
//							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//						}
//					}
//					
//					
//					JSONArray Arguments = toJsonArray(WaterfallchartObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = Waterfallchartroot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					
//					//팔레트 옵션 추가
//					if(WaterfallchartObj.has("ColoringOption")) {
//						Element ColoringOptions = Waterfallchartroot.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", WaterfallchartObj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", WaterfallchartObj.getString("UseGlobalColors"));
//						JSONArray colorArray = WaterfallchartObj.getJSONArray("ColorSheme");
//						Element ColorSheme = Waterfallchartroot.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
//							Element MeasureKey = Entry.addElement("MeasureKey");
//							Element Definition = MeasureKey.addElement("Definition");
//							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;
//			case "Bipartitechart":
//				JSONArray BipartitechartArray = itemObj.getJSONArray("Bipartitechart");
//				for(int eachMapItem =0;eachMapItem<BipartitechartArray.length();eachMapItem++) {
//					JSONObject BipartitechartObj = BipartitechartArray.getJSONObject(eachMapItem);
//					Element Bipartitechartroot = items.addElement("Bipartitechart");
//					Bipartitechartroot.addAttribute("ComponentName", BipartitechartObj.getString("ComponentName"));
//					Bipartitechartroot.addAttribute("Name", BipartitechartObj.getString("Name"));
//					Bipartitechartroot.addAttribute("MemoText", BipartitechartObj.getString("MemoText"));
//					Bipartitechartroot.addAttribute("DataSource", BipartitechartObj.getString("DataSource"));
//					
//					if(BipartitechartObj.has("ShowCaption")) {
//						if(BipartitechartObj.getBoolean("ShowCaption") == false) {
//							Bipartitechartroot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject BipartitechartDataItems = BipartitechartObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(BipartitechartDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(BipartitechartDataItems, "Measure");
//					
//					Element BipartitechartMapDataItems = Bipartitechartroot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimBipartitechartAttr = BipartitechartMapDataItems.addElement("Dimension");
//						DimBipartitechartAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimBipartitechartAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimBipartitechartAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimBipartitechartAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaBipartitechartAttr = BipartitechartMapDataItems.addElement("Measure");
//						MeaBipartitechartAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaBipartitechartAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaBipartitechartAttr.addAttribute("SummaryType",  summaryType);
//						MeaBipartitechartAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaBipartitechartAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaBipartitechartAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					if(BipartitechartObj.has("Values")) {
//						JSONArray Values = toJsonArray(BipartitechartObj.getJSONObject("Values"), "Value");
//						if(Values.length() >0) {
//							Element ValueRoot = Bipartitechartroot.addElement("Values");
//							for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//								JSONObject valItem = Values.getJSONObject(valueIdx);
//								ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////								ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//							}
//						}
//					}
//					
//					JSONArray Arguments = toJsonArray(BipartitechartObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = Bipartitechartroot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					
//					//팔레트 옵션 추가
//					if(BipartitechartObj.has("ColoringOption")) {
//						Element ColoringOptions = Bipartitechartroot.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", BipartitechartObj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", BipartitechartObj.getString("UseGlobalColors"));
//						JSONArray colorArray = BipartitechartObj.getJSONArray("ColorSheme");
//						Element ColorSheme = Bipartitechartroot.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
////							Element MeasureKey = Entry.addElement("MeasureKey");
////							Element Definition = MeasureKey.addElement("Definition");
////							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;
//			case "Sankeychart":
//				JSONArray SankeychartArray = itemObj.getJSONArray("Sankeychart");
//				for(int eachMapItem =0;eachMapItem<SankeychartArray.length();eachMapItem++) {
//					JSONObject SankeychartObj = SankeychartArray.getJSONObject(eachMapItem);
//					Element Sankeychartroot = items.addElement("Sankeychart");
//					Sankeychartroot.addAttribute("ComponentName", SankeychartObj.getString("ComponentName"));
//					Sankeychartroot.addAttribute("Name", SankeychartObj.getString("Name"));
//					Sankeychartroot.addAttribute("MemoText", SankeychartObj.getString("MemoText"));
//					Sankeychartroot.addAttribute("DataSource", SankeychartObj.getString("DataSource"));
//					
//					if(SankeychartObj.has("ShowCaption")) {
//						if(SankeychartObj.getBoolean("ShowCaption") == false) {
//							Sankeychartroot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject SankeychartDataItems = SankeychartObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(SankeychartDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(SankeychartDataItems, "Measure");
//					
//					Element SankeychartMapDataItems = Sankeychartroot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimSankeychartAttr = SankeychartMapDataItems.addElement("Dimension");
//						DimSankeychartAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimSankeychartAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimSankeychartAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimSankeychartAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaSankeychartAttr = SankeychartMapDataItems.addElement("Measure");
//						MeaSankeychartAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaSankeychartAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaSankeychartAttr.addAttribute("SummaryType",  summaryType);
//						MeaSankeychartAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaSankeychartAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaSankeychartAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					if(SankeychartObj.has("Values")) {
//						JSONArray Values = toJsonArray(SankeychartObj.getJSONObject("Values"), "Value");
//						if(Values.length() >0) {
//							Element ValueRoot = Sankeychartroot.addElement("Values");
//							for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//								JSONObject valItem = Values.getJSONObject(valueIdx);
//								ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////								ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//							}
//						}	
//					}
//					
//					JSONArray Arguments = toJsonArray(SankeychartObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = Sankeychartroot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					
//					//팔레트 옵션 추가
//					if(SankeychartObj.has("ColoringOption")) {
//						Element ColoringOptions = Sankeychartroot.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", SankeychartObj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", SankeychartObj.getString("UseGlobalColors"));
//						JSONArray colorArray = SankeychartObj.getJSONArray("ColorSheme");
//						Element ColorSheme = Sankeychartroot.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
////							Element MeasureKey = Entry.addElement("MeasureKey");
////							Element Definition = MeasureKey.addElement("Definition");
////							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;
//			case "ForceDirect":
//				JSONArray ForceDirectArray = itemObj.getJSONArray("ForceDirect");
//				for(int eachMapItem =0;eachMapItem<ForceDirectArray.length();eachMapItem++) {
//					JSONObject ForceDirectObj = ForceDirectArray.getJSONObject(eachMapItem);
//					Element ForceDirectroot = items.addElement("ForceDirect");
//					ForceDirectroot.addAttribute("ComponentName", ForceDirectObj.getString("ComponentName"));
//					ForceDirectroot.addAttribute("Name", ForceDirectObj.getString("Name"));
//					ForceDirectroot.addAttribute("MemoText", ForceDirectObj.getString("MemoText"));
//					ForceDirectroot.addAttribute("DataSource", ForceDirectObj.getString("DataSource"));
//					
//					if(ForceDirectObj.has("ShowCaption")) {
//						if(ForceDirectObj.getBoolean("ShowCaption") == false) {
//							ForceDirectroot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject ForceDirectDataItems = ForceDirectObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(ForceDirectDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(ForceDirectDataItems, "Measure");
//					
//					Element ForceDirectMapDataItems = ForceDirectroot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimForceDirectAttr = ForceDirectMapDataItems.addElement("Dimension");
//						DimForceDirectAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimForceDirectAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimForceDirectAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimForceDirectAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaForceDirectAttr = ForceDirectMapDataItems.addElement("Measure");
//						MeaForceDirectAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaForceDirectAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaForceDirectAttr.addAttribute("SummaryType",  summaryType);
//						MeaForceDirectAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaForceDirectAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaForceDirectAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					if(ForceDirectObj.has("Values")) {
//						JSONArray Values = toJsonArray(ForceDirectObj.getJSONObject("Values"), "Value");
//						if(Values.length() >0) {
//							Element ValueRoot = ForceDirectroot.addElement("Values");
//							for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//								JSONObject valItem = Values.getJSONObject(valueIdx);
//								ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////								ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//							}
//						}	
//					}
//					
//					JSONArray Arguments = toJsonArray(ForceDirectObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = ForceDirectroot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					
//					//팔레트 옵션 추가
//					if(ForceDirectObj.has("ColoringOption")) {
//						Element ColoringOptions = ForceDirectroot.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", ForceDirectObj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", ForceDirectObj.getString("UseGlobalColors"));
//						JSONArray colorArray = ForceDirectObj.getJSONArray("ColorSheme");
//						Element ColorSheme = ForceDirectroot.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
////							Element MeasureKey = Entry.addElement("MeasureKey");
////							Element Definition = MeasureKey.addElement("Definition");
////							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;				
//			case "ForceDirectExpand":
//				JSONArray ForceDirectExpandArray = itemObj.getJSONArray("ForceDirectExpand");
//				for(int eachMapItem =0;eachMapItem<ForceDirectExpandArray.length();eachMapItem++) {
//					JSONObject ForceDirectExpandObj = ForceDirectExpandArray.getJSONObject(eachMapItem);
//					Element ForceDirectExpandroot = items.addElement("ForceDirectExpand");
//					ForceDirectExpandroot.addAttribute("ComponentName", ForceDirectExpandObj.getString("ComponentName"));
//					ForceDirectExpandroot.addAttribute("Name", ForceDirectExpandObj.getString("Name"));
//					ForceDirectExpandroot.addAttribute("MemoText", ForceDirectExpandObj.getString("MemoText"));
//					ForceDirectExpandroot.addAttribute("DataSource", ForceDirectExpandObj.getString("DataSource"));
//					
//					if(ForceDirectExpandObj.has("ShowCaption")) {
//						if(ForceDirectExpandObj.getBoolean("ShowCaption") == false) {
//							ForceDirectExpandroot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject ForceDirectExpandDataItems = ForceDirectExpandObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(ForceDirectExpandDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(ForceDirectExpandDataItems, "Measure");
//					
//					Element ForceDirectExpandMapDataItems = ForceDirectExpandroot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimForceDirectExpandAttr = ForceDirectExpandMapDataItems.addElement("Dimension");
//						DimForceDirectExpandAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimForceDirectExpandAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimForceDirectExpandAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimForceDirectExpandAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaForceDirectExpandAttr = ForceDirectExpandMapDataItems.addElement("Measure");
//						MeaForceDirectExpandAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaForceDirectExpandAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaForceDirectExpandAttr.addAttribute("SummaryType",  summaryType);
//						MeaForceDirectExpandAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaForceDirectExpandAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaForceDirectExpandAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					if(ForceDirectExpandObj.has("Values")) {
//						JSONArray Values = toJsonArray(ForceDirectExpandObj.getJSONObject("Values"), "Value");
//						if(Values.length() >0) {
//							Element ValueRoot = ForceDirectExpandroot.addElement("Values");
//							for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//								JSONObject valItem = Values.getJSONObject(valueIdx);
//								ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////								ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//							}
//						}	
//					}
//					
//					JSONArray Arguments = toJsonArray(ForceDirectExpandObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = ForceDirectExpandroot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					
//					//팔레트 옵션 추가
//					if(ForceDirectExpandObj.has("ColoringOption")) {
//						Element ColoringOptions = ForceDirectExpandroot.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", ForceDirectExpandObj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", ForceDirectExpandObj.getString("UseGlobalColors"));
//						JSONArray colorArray = ForceDirectExpandObj.getJSONArray("ColorSheme");
//						Element ColorSheme = ForceDirectExpandroot.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
////							Element MeasureKey = Entry.addElement("MeasureKey");
////							Element Definition = MeasureKey.addElement("Definition");
////							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;								
//			case "HeatMap":
//				JSONArray HeatMapArray = itemObj.getJSONArray("HeatMap");
//				for(int eachMapItem =0;eachMapItem<HeatMapArray.length();eachMapItem++) {
//					JSONObject HeatMapObj = HeatMapArray.getJSONObject(eachMapItem);
//					Element HeatMaproot = items.addElement("HeatMap");
//					HeatMaproot.addAttribute("ComponentName", HeatMapObj.getString("ComponentName"));
//					HeatMaproot.addAttribute("Name", HeatMapObj.getString("Name"));
//					HeatMaproot.addAttribute("MemoText", HeatMapObj.getString("MemoText"));
//					HeatMaproot.addAttribute("DataSource", HeatMapObj.getString("DataSource"));
//					
//					if(HeatMapObj.has("ShowCaption")) {
//						if(HeatMapObj.getBoolean("ShowCaption") == false) {
//							HeatMaproot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject HeatMapDataItems = HeatMapObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(HeatMapDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(HeatMapDataItems, "Measure");
//					
//					Element HeatMapMapDataItems = HeatMaproot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimHeatmapAttr = HeatMapMapDataItems.addElement("Dimension");
//						DimHeatmapAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimHeatmapAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimHeatmapAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimHeatmapAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaHeatmapAttr = HeatMapMapDataItems.addElement("Measure");
//						MeaHeatmapAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaHeatmapAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaHeatmapAttr.addAttribute("SummaryType",  summaryType);
//						MeaHeatmapAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaHeatmapAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaHeatmapAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					
//					JSONArray Values = toJsonArray(HeatMapObj.getJSONObject("Values"), "Value");
//					if(Values.length() >0) {
//						Element ValueRoot = HeatMaproot.addElement("Values");
//						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//							JSONObject valItem = Values.getJSONObject(valueIdx);
//							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//						}
//					}
//					
//					
//					JSONArray Arguments = toJsonArray(HeatMapObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = HeatMaproot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					
//					//팔레트 옵션 추가
//					if(HeatMapObj.has("ColoringOption")) {
//						Element ColoringOptions = HeatMaproot.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", HeatMapObj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", HeatMapObj.getString("UseGlobalColors"));
//						JSONArray colorArray = HeatMapObj.getJSONArray("ColorSheme");
//						Element ColorSheme = HeatMaproot.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
//							Element MeasureKey = Entry.addElement("MeasureKey");
//							Element Definition = MeasureKey.addElement("Definition");
//							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;
//			case "WordCloud":
//				JSONArray WordCloudArray = itemObj.getJSONArray("WordCloud");
//				for(int eachMapItem =0;eachMapItem<WordCloudArray.length();eachMapItem++) {
//					JSONObject WordCloudObj = WordCloudArray.getJSONObject(eachMapItem);
//					Element WordCloudroot = items.addElement("WordCloud");
//					WordCloudroot.addAttribute("ComponentName", WordCloudObj.getString("ComponentName"));
//					WordCloudroot.addAttribute("Name", WordCloudObj.getString("Name"));
//					WordCloudroot.addAttribute("MemoText", WordCloudObj.getString("MemoText"));
//					WordCloudroot.addAttribute("DataSource", WordCloudObj.getString("DataSource"));
//					
//					if(WordCloudObj.has("ShowCaption")) {
//						if(WordCloudObj.getBoolean("ShowCaption") == false) {
//							WordCloudroot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject WordCloudDataItems = WordCloudObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(WordCloudDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(WordCloudDataItems, "Measure");
//					
//					Element WordCloudMapDataItems = WordCloudroot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimWordCloudAttr = WordCloudMapDataItems.addElement("Dimension");
//						DimWordCloudAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimWordCloudAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimWordCloudAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimWordCloudAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaWordCloudAttr = WordCloudMapDataItems.addElement("Measure");
//						MeaWordCloudAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaWordCloudAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaWordCloudAttr.addAttribute("SummaryType",  summaryType);
//						MeaWordCloudAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaWordCloudAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaWordCloudAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					
//					JSONArray Values = toJsonArray(WordCloudObj.getJSONObject("Values"), "Value");
//					if(Values.length() >0) {
//						Element ValueRoot = WordCloudroot.addElement("Values");
//						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//							JSONObject valItem = Values.getJSONObject(valueIdx);
//							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//						}
//					}
//					
//					
//					JSONArray Arguments = toJsonArray(WordCloudObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = WordCloudroot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//				}
//				break;
//			case "HistogramChart":
//				JSONArray HistogramChartArray = itemObj.getJSONArray("HistogramChart");
//				for(int eachMapItem =0;eachMapItem<HistogramChartArray.length();eachMapItem++) {
//					JSONObject HistogramChartObj = HistogramChartArray.getJSONObject(eachMapItem);
//					Element HistogramChartroot = items.addElement("HistogramChart");
//					HistogramChartroot.addAttribute("ComponentName", HistogramChartObj.getString("ComponentName"));
//					HistogramChartroot.addAttribute("Name", HistogramChartObj.getString("Name"));
//					HistogramChartroot.addAttribute("MemoText", HistogramChartObj.getString("MemoText"));
//					HistogramChartroot.addAttribute("DataSource", HistogramChartObj.getString("DataSource"));
//					
//					if(HistogramChartObj.has("ShowCaption")) {
//						if(HistogramChartObj.getBoolean("ShowCaption") == false) {
//							HistogramChartroot.addAttribute("ShowCaption", "false");
//						}
//					}
//					
//					JSONObject HistogramChartDataItems = HistogramChartObj.getJSONObject("DataItems");
//					JSONArray DimDataItems = toJsonArray(HistogramChartDataItems, "Dimension");
//					JSONArray MeaDataItems = toJsonArray(HistogramChartDataItems, "Measure");
//					
//					Element HistogramChartMapDataItems = HistogramChartroot.addElement("DataItems");
//					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
//						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
//						Element DimHistogramChartAttr = HistogramChartMapDataItems.addElement("Dimension");
//						DimHistogramChartAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
//						if(dimdata.has("Name")) {
//							DimHistogramChartAttr.addAttribute("Name",  dimdata.getString("Name"));
//						}
//						DimHistogramChartAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
//						if(dimdata.has("CubeUniqueName")) {
//							DimHistogramChartAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
//						}
////						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
//					}
//
//					for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
//						JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
//						Element MeaHistogramChartAttr = HistogramChartMapDataItems.addElement("Measure");
//						MeaHistogramChartAttr.addAttribute("DataMember", meadata.getString("DataMember"));
//						if(meadata.has("Name")) {
//							MeaHistogramChartAttr.addAttribute("Name",  meadata.getString("Name"));
//						}
//						String summaryType = "";
//						if(meadata.has("SummaryType")) {
//							switch(meadata.getString("SummaryType")) {
//							case "count":
//								summaryType = "Count";
//								break;
//							case "min":
//								summaryType = "Min";
//								break;
//							case "max":
//								summaryType = "Max";
//								break;
//							case "avg":
//								summaryType = "Average";
//								break;
//							default:
//								summaryType = "Sum";
//								break;
//							}
//						}else {
//							summaryType = "Sum";
//						}
//						MeaHistogramChartAttr.addAttribute("SummaryType",  summaryType);
//						MeaHistogramChartAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
//						if(meadata.has("CubeUniqueName")) {
//							MeaHistogramChartAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
//						}
//						if (meadata.has("NumericFormat")) {
//							Element NumericFormat = MeaHistogramChartAttr.addElement("NumericFormat");
//							JSONObject PivotNumericFormat = meadata.getJSONObject("NumericFormat");
//							if (PivotNumericFormat.has("FormatType"))
//								NumericFormat.addAttribute("FormatType", PivotNumericFormat.getString("FormatType"));
//							if (PivotNumericFormat.has("Precision"))
//								NumericFormat.addAttribute("Precision", PivotNumericFormat.get("Precision") + "");
//							if (PivotNumericFormat.has("Unit"))
//								NumericFormat.addAttribute("Unit", PivotNumericFormat.getString("Unit"));
////							if (PivotNumericFormat.has("SuffixEnabled")) {
////								NumericFormat.addAttribute("SuffixEnabled", PivotNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
////							}
////							if (PivotNumericFormat.has("Suffix")) {
////								Element Suffix = NumericFormat.addElement("Suffix");
////								JSONObject suffix = PivotNumericFormat.getJSONObject("Suffix");
////								Suffix.addAttribute("O", suffix.getString("O"));
////								Suffix.addAttribute("K", suffix.getString("K"));
////								Suffix.addAttribute("M", suffix.getString("M"));
////								Suffix.addAttribute("B", suffix.getString("B"));
////							}
//							if (PivotNumericFormat.has("IncludeGroupSeparator"))
//								NumericFormat.addAttribute("IncludeGroupSeparator",
//										PivotNumericFormat.get("IncludeGroupSeparator").toString());
//						}
//					}
//					
//					
//					JSONArray Values = toJsonArray(HistogramChartObj.getJSONObject("Values"), "Value");
//					if(Values.length() >0) {
//						Element ValueRoot = HistogramChartroot.addElement("Values");
//						for(int valueIdx = 0; valueIdx<Values.length();valueIdx++) {
//							JSONObject valItem = Values.getJSONObject(valueIdx);
//							ValueRoot.addElement("Value").addAttribute("UniqueName", valItem.getString("UniqueName"));
////							ValueRoot.addElement("Value").addAttribute("DefaultId", valItem.getString("UniqueName"));
//						}
//					}
//					
//					
//					JSONArray Arguments = toJsonArray(HistogramChartObj.getJSONObject("Arguments"),"Argument");
//					if(Arguments.length() >0) {
//						Element ArgumentRoot = HistogramChartroot.addElement("Arguments");
//						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
//							JSONObject rowItem = Arguments.getJSONObject(argIdx);
//							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
////							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
//						}
//					}
//					//팔레트 옵션 추가
//					if(HistogramChartObj.has("ColoringOption")) {
//						Element ColoringOptions = HistogramChartroot.addElement("ColoringOptions");
//						ColoringOptions.addAttribute("MeasuresColoringMode", HistogramChartObj.getString("ColoringOption"));
//						ColoringOptions.addAttribute("UseGlobalColors", HistogramChartObj.getString("UseGlobalColors"));
//						JSONArray colorArray = HistogramChartObj.getJSONArray("ColorSheme");
//						Element ColorSheme = HistogramChartroot.addElement("ColorSheme");
//						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
//							JSONObject coloritems = colorArray.getJSONObject(coloritem);
//							Element Entry = ColorSheme.addElement("ColorSheme");
//							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
//							Entry.addAttribute("Color", coloritems.getString("Color"));
//							Element MeasureKey = Entry.addElement("MeasureKey");
//							Element Definition = MeasureKey.addElement("Definition");
//							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
//						}
//					}
//				}
//				break;
				// 임성현 주임 저장 추가
			case "Starchart":
				JSONArray starchartItemArray = itemObj.getJSONArray("Starchart");
				for(int eachChartItem = 0;eachChartItem < starchartItemArray.length();eachChartItem++) {
					JSONObject starchartObj = starchartItemArray.getJSONObject(eachChartItem);
					JSONObject starchartDataItem = starchartObj.getJSONObject("DataItems");
					JSONObject chartPanes = starchartObj.getJSONObject("Panes");

					Element starChartroot = items.addElement("Starchart");
					starChartroot.addAttribute("ComponentName", starchartObj.getString("ComponentName"));
					starChartroot.addAttribute("Name", starchartObj.getString("Name"));
					starChartroot.addAttribute("MemoText", starchartObj.getString("MemoText"));
					starChartroot.addAttribute("DataSource", starchartObj.getString("DataSource"));

					if(starchartObj.has("ShowCaption")) {
						if(starchartObj.getBoolean("ShowCaption") == false) {
							starChartroot.addAttribute("ShowCaption", "false");
						}
					}
					/* DOGFOOT ktkang 캡션보기 저장 기능 없는 아이템들 모두 추가 이 밑으로 쭈욱  같은 주석 나올 때 까지 20200205 */
					Element DataItems = starChartroot.addElement("DataItems");
					JSONArray DataItemAttr = toJsonArray(starchartDataItem, "Measure");
					if (DataItemAttr != null) {
						for (int Mea = 0; Mea < DataItemAttr.length(); Mea++) {
							Element Measure = DataItems.addElement("Measure");
							Measure.addAttribute("DataMember", DataItemAttr.getJSONObject(Mea).getString("DataMember"));
							if(DataItemAttr.getJSONObject(Mea).has("Name")) {
								Measure.addAttribute("Name",  DataItemAttr.getJSONObject(Mea).getString("Name"));
							}
							String summaryType = "";
							if(DataItemAttr.getJSONObject(Mea).has("SummaryType")) {
								switch(DataItemAttr.getJSONObject(Mea).getString("SummaryType")) {
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}

							Measure.addAttribute("SummaryType",  summaryType);
							Measure.addAttribute("UniqueName", DataItemAttr.getJSONObject(Mea).getString("UniqueName"));
							if(DataItemAttr.getJSONObject(Mea).has("CubeUniqueName")) {
								Measure.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Mea).getString("CubeUniqueName"));
							}
							if (DataItemAttr.getJSONObject(Mea).has("NumericFormat")) {
								Element NumericFormat = Measure.addElement("NumericFormat");
								JSONObject ChartNumericFormat = DataItemAttr.getJSONObject(Mea)
										.getJSONObject("NumericFormat");
								if (ChartNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", ChartNumericFormat.getString("FormatType"));
								if (ChartNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", ChartNumericFormat.get("Precision") + "");
								if (ChartNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", ChartNumericFormat.getString("PrecisionOption") + "");
								if (ChartNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", ChartNumericFormat.getString("Unit"));
								if (ChartNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator",
											ChartNumericFormat.get("IncludeGroupSeparator").toString());
							}

						}
					}

					DataItemAttr = toJsonArray(starchartDataItem, "Dimension");
					if (DataItemAttr != null) {
						for (int Dim = 0; Dim < DataItemAttr.length(); Dim++) {
							Element Dimension = DataItems.addElement("Dimension");
							Dimension.addAttribute("DataMember", DataItemAttr.getJSONObject(Dim).getString("DataMember"));
							if(DataItemAttr.getJSONObject(Dim).has("Name")) {
								Dimension.addAttribute("Name",  DataItemAttr.getJSONObject(Dim).getString("Name"));
							}
							if (DataItemAttr.getJSONObject(Dim).has("SortOrder")) {
								if(DataItemAttr.getJSONObject(Dim).getString("SortOrder").equalsIgnoreCase("Descending"))
									Dimension.addAttribute("SortOrder","Descending");
							}
							if (DataItemAttr.getJSONObject(Dim).has("ColoringMode")) {
								Dimension.addAttribute("ColoringMode",
										DataItemAttr.getJSONObject(Dim).getString("ColoringMode"));
							}
							if(DataItemAttr.getJSONObject(Dim).has("SortByMeasure")) {
								Dimension.addAttribute("SortByMeasure", DataItemAttr.getJSONObject(Dim).getString("SortByMeasure"));
							}
							Dimension.addAttribute("UniqueName", DataItemAttr.getJSONObject(Dim).getString("UniqueName"));
							if(DataItemAttr.getJSONObject(Dim).has("CubeUniqueName")) {
								Dimension.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Dim).getString("CubeUniqueName"));
							}
						}
					}

					if (starchartObj.has("Arguments")) {
						JSONObject starchartArguments = starchartObj.getJSONObject("Arguments");
						JSONArray ArgumentsArr = toJsonArray(starchartArguments, "Argument");
						Element Arguments = starChartroot.addElement("Arguments");
						for (int arg = 0; arg < ArgumentsArr.length(); arg++) {
							Element ArgumentsAttr = Arguments.addElement("Argument");
							ArgumentsAttr.addAttribute("UniqueName",
									ArgumentsArr.getJSONObject(arg).getString("UniqueName"));
							if(ArgumentsArr.getJSONObject(arg).has("CubeUniqueName")) {
								ArgumentsAttr.addAttribute("CubeUniqueName",  ArgumentsArr.getJSONObject(arg).getString("CubeUniqueName"));
							}
						}
					}


					if (starchartObj.has("SeriesDimensions")) {
						JSONObject starchartseriesDim = starchartObj.getJSONObject("SeriesDimensions");
						JSONArray SeriesDimArr = toJsonArray(starchartseriesDim, "SeriesDimension");
						Element SeriesDimensions = starChartroot.addElement("SeriesDimensions");
						for (int serdim = 0; serdim < SeriesDimArr.length(); serdim++) {
							Element SeriesDimensionAttr = SeriesDimensions.addElement("SeriesDimension");
							SeriesDimensionAttr.addAttribute("UniqueName",
									SeriesDimArr.getJSONObject(serdim).getString("UniqueName"));
							if(SeriesDimArr.getJSONObject(serdim).has("CubeUniqueName")) {
								SeriesDimensionAttr.addAttribute("CubeUniqueName",  SeriesDimArr.getJSONObject(serdim).getString("CubeUniqueName"));
							}
						}
					}

					JSONArray PanesArr = toJsonArray(chartPanes, "Pane");
					Element Panes = starChartroot.addElement("Panes");

					for (int pane = 0; pane < PanesArr.length(); pane++) {
						JSONObject PaneObj = PanesArr.getJSONObject(pane);
						Element Pane = Panes.addElement("Pane");
						Pane.addAttribute("Name", PaneObj.getString("Name"));
						if(starchartObj.has("ChartYOption")) {
							JSONObject chartYoption = starchartObj.getJSONObject("ChartYOption");
							Element AxisY = Pane.addElement("AxisY");
							if(chartYoption.has("Visible")) {
								if(chartYoption.getBoolean("Visible") != true)
									AxisY.addAttribute("Visible", "false");
							}
							AxisY.addAttribute("Title", chartYoption.getString("Title"));
						}
						Element Series = Pane.addElement("Series");

						JSONArray SeriesArr = toJsonArray(PaneObj, "Series");
						for (int series = 0; series < SeriesArr.length(); series++) {
							JSONObject SeriesItem = SeriesArr.getJSONObject(series);
							if (toJsonArray(SeriesItem, "Simple") != null) {
								JSONArray simpleArr = toJsonArray(SeriesItem, "Simple");
								for (int simple = 0; simple < simpleArr.length(); simple++) {
									JSONObject simpleItem = simpleArr.getJSONObject(simple);

									Element Simple = Series.addElement("Simple");
									if (simpleItem.has("SeriesType")) {
										if (!simpleItem.getString("SeriesType").equalsIgnoreCase("bar"))
											Simple.addAttribute("SeriesType", simpleItem.getString("SeriesType"));
									}
									Element Value = Simple.addElement("Value");
									Value.addAttribute("UniqueName", simpleItem.getJSONObject("Value").getString("UniqueName"));
								}
							}
						}
					}
				}
				break;
			case "ListBox":
				JSONArray listBoxItemArray = itemObj.getJSONArray("ListBox");
				for(int eachListBoxItem =0;eachListBoxItem<listBoxItemArray.length();eachListBoxItem++) {
					JSONObject ListBoxObj = listBoxItemArray.getJSONObject(eachListBoxItem);

					Element ListBoxRoot = items.addElement("ListBox");
					ListBoxRoot.addAttribute("ComponentName", ListBoxObj.getString("ComponentName"));
					ListBoxRoot.addAttribute("Name", ListBoxObj.getString("Name"));
					ListBoxRoot.addAttribute("MemoText", ListBoxObj.getString("MemoText"));
					ListBoxRoot.addAttribute("DataSource", ListBoxObj.getString("DataSource"));
					if(ListBoxObj.has("ShowCaption")) {
						if(ListBoxObj.getBoolean("ShowCaption") == false)
							ListBoxRoot.addAttribute("ShowCaption", "false");
					}
					if (ListBoxObj.has("InteractivityOptions")) {
						String masterFilterMode = "";
						boolean ignoreMasterFilter = false;
						if(!ListBoxObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode").equals("Off")) {
//							Element InteractivityOptions = ListBoxRoot.addElement("InteractivityOptions");
//							InteractivityOptions.addAttribute("MasterFilterMode",
//									ListBoxObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode"));
							masterFilterMode = ListBoxObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode");
						}
						if(ListBoxObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters") == true) {
//							InteractivityOptions.addAttribute("MasterFilterMode",
//									chartObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode"));
							ignoreMasterFilter = ListBoxObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters");
						}
						
						if(!masterFilterMode.equals("") || ignoreMasterFilter == true) {
							Element InteractivityOptions = ListBoxRoot.addElement("InteractivityOptions");
							if(!masterFilterMode.equals("")) {
								InteractivityOptions.addAttribute("MasterFilterMode",masterFilterMode);
							}
							if(ignoreMasterFilter == true) {
								InteractivityOptions.addAttribute("IgnoreMasterFilters","true");
							}
						}
					}
					if (ListBoxObj.has("IsMasterFilterCrossDataSource")) {
						if (ListBoxObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							ListBoxRoot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					
					if (ListBoxObj.has("ListBoxType")) {
						if (ListBoxObj.getString("ListBoxType").equals("Radio")) {
							ListBoxRoot.addAttribute("IsMasterFilterCrossDataSource", ListBoxObj.getString("ListBoxType"));
						}
					}
					
					if (ListBoxObj.has("ShowAllValue")) {
						if (ListBoxObj.getBoolean("ShowAllValue") == true) {
							ListBoxRoot.addAttribute("ShowAllValue", "true");
						}
					}
					
					if (ListBoxObj.has("EnableSearch")) {
						if (ListBoxObj.getBoolean("EnableSearch") == true) {
							ListBoxRoot.addAttribute("EnableSearch", "true");
						}
					}
					
					if(ListBoxObj.has("FilterString")) {
						ListBoxRoot.addAttribute("FilterString", ListBoxObj.getString("FilterString"));
					}
					
					JSONObject listBoxDataItems = ListBoxObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(listBoxDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(listBoxDataItems, "Measure");

					Element ListBoxDataItems = ListBoxRoot.addElement("DataItems");
					
					if(DimDataItems == null) {
						DimDataItems = new JSONArray();
					}
					if(MeaDataItems == null) {
						MeaDataItems = new JSONArray();
					}
					
					if(DimDataItems.length() > 0) {
						for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
							JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
							Element DimListBoxAttr = ListBoxDataItems.addElement("Dimension");
							DimListBoxAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
							if(dimdata.has("Name")) {
								DimListBoxAttr.addAttribute("Name",  dimdata.getString("Name"));
							}
							DimListBoxAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
							if(dimdata.has("CubeUniqueName")) {
								DimListBoxAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
							}
							if(dimdata.has("SortOrder")) {
								if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
									DimListBoxAttr.addAttribute("SortOrder", "Descending");
								}
							}
							if(dimdata.has("SortByMeasure")) {
								DimListBoxAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
							}
						}
					}
					
					if(MeaDataItems.length() > 0) {
						for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
							JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
							Element MeaListBoxAttr = ListBoxDataItems.addElement("Measure");
							MeaListBoxAttr.addAttribute("DataMember", meadata.getString("DataMember"));
							String summaryType = "";
							if(meadata.has("SummaryType")) {
								switch(meadata.getString("SummaryType")) {
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}
							if(meadata.has("Name")) {
								MeaListBoxAttr.addAttribute("Name",  meadata.getString("Name"));
							}
							MeaListBoxAttr.addAttribute("SummaryType",  summaryType);
							if (meadata.has("NumericFormat")) {
								Element NumericFormat = MeaListBoxAttr.addElement("NumericFormat");
								JSONObject GridNumericFormat = meadata.getJSONObject("NumericFormat");
								if (GridNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", GridNumericFormat.getString("FormatType"));
								if (GridNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", GridNumericFormat.get("Precision") + "");
								if (GridNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", GridNumericFormat.getString("PrecisionOption") + "");
								if (GridNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", GridNumericFormat.getString("Unit"));
//								if (GridNumericFormat.has("SuffixEnabled")) {
//									NumericFormat.addAttribute("SuffixEnabled", GridNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
//								}
//								if (GridNumericFormat.has("Suffix")) {
//									Element Suffix = NumericFormat.addElement("Suffix");
//									JSONObject suffix = GridNumericFormat.getJSONObject("Suffix");
//									Suffix.addAttribute("O", suffix.getString("O"));
//									Suffix.addAttribute("K", suffix.getString("K"));
//									Suffix.addAttribute("M", suffix.getString("M"));
//									Suffix.addAttribute("B", suffix.getString("B"));
//								}
								if (GridNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator",
											GridNumericFormat.get("IncludeGroupSeparator").toString());
							}
							MeaListBoxAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
							if(meadata.has("CubeUniqueName")) {
								MeaListBoxAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
							}
//							if(meadata.has("SortOrder")) {
//								if(meadata.getString("SortOrder").equalsIgnoreCase("descending")) {
//									MeaGridAttr.addAttribute("SortOrder", "Descending");
//								}
//							}
						}
					}
					

					ArrayList<JSONObject> columnOrdering = new ArrayList<>();
					JSONObject FilterDimensionsObj = ListBoxObj.getJSONObject("FilterDimensions");
					JSONArray FilterDimensionsArr = toJsonArray(FilterDimensionsObj,"Dimension");

					Element FilterDimensions = ListBoxRoot.addElement("FilterDimensions");
					
					if(FilterDimensionsArr == null) {
						FilterDimensionsArr = new JSONArray();
					}
					if(ListBoxObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = ListBoxObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = ListBoxRoot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					
					for (int filterDimIdx = 0; filterDimIdx < FilterDimensionsArr.length();filterDimIdx++) {
						JSONObject dimObj = new JSONObject();
						dimObj.put("Dimension", FilterDimensionsArr.getJSONObject(filterDimIdx));
						columnOrdering.add(dimObj);
					}
					
					for (int coumnIdx = 0; coumnIdx < columnOrdering.size(); coumnIdx++) {
						JSONObject tempObj = new JSONObject();
						tempObj = columnOrdering.get(coumnIdx);
						if (tempObj.has("Dimension")) {
							Element Column = FilterDimensions.addElement("Dimension");
							Column.addAttribute("UniqueName",
									tempObj.getJSONObject("Dimension").getString("UniqueName"));
						} 
					}
					
//					for (JSONObject tempObj : columnOrdering) {
//						if (tempObj.has("Dimension")) {
//							Element Column = FilterDimensions.addElement("Dimension");
//							Column.addAttribute("UniqueName",
//									tempObj.getJSONObject("Dimension").getString("UniqueName"));
//						} 
//					}
				}
				break;
			case "TreeView":
				JSONArray treeViewItemArray = itemObj.getJSONArray("TreeView");
				for(int eachTreeViewItem =0;eachTreeViewItem<treeViewItemArray.length();eachTreeViewItem++) {
					JSONObject TreeViewObj = treeViewItemArray.getJSONObject(eachTreeViewItem);

					Element TreeViewRoot = items.addElement("TreeView");
					TreeViewRoot.addAttribute("ComponentName", TreeViewObj.getString("ComponentName"));
					TreeViewRoot.addAttribute("Name", TreeViewObj.getString("Name"));
					TreeViewRoot.addAttribute("MemoText", TreeViewObj.getString("MemoText"));
					TreeViewRoot.addAttribute("DataSource", TreeViewObj.getString("DataSource"));
					if(TreeViewObj.has("ShowCaption")) {
						if(TreeViewObj.getBoolean("ShowCaption") == false)
							TreeViewRoot.addAttribute("ShowCaption", "false");
					}
					if (TreeViewObj.has("InteractivityOptions")) {
						String masterFilterMode = "";
						boolean ignoreMasterFilter = false;
						if(!TreeViewObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode").equals("Off")) {
//							Element InteractivityOptions = TreeViewRoot.addElement("InteractivityOptions");
//							InteractivityOptions.addAttribute("MasterFilterMode",
//									TreeViewObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode"));
							masterFilterMode = TreeViewObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode");
						}
						if(TreeViewObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters") == true) {
//							InteractivityOptions.addAttribute("MasterFilterMode",
//									chartObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode"));
							ignoreMasterFilter = TreeViewObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters");
						}
						
						if(!masterFilterMode.equals("") || ignoreMasterFilter == true) {
							Element InteractivityOptions = TreeViewRoot.addElement("InteractivityOptions");
							if(!masterFilterMode.equals("")) {
								InteractivityOptions.addAttribute("MasterFilterMode",masterFilterMode);
							}
							if(ignoreMasterFilter == true) {
								InteractivityOptions.addAttribute("IgnoreMasterFilters","true");
							}
						}
					}
					if (TreeViewObj.has("IsMasterFilterCrossDataSource")) {
						if (TreeViewObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							TreeViewRoot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					
					if (TreeViewObj.has("AutoExpand")) {
						if (TreeViewObj.getBoolean("AutoExpand") == true) {
							TreeViewRoot.addAttribute("AutoExpand", "true");
						}
					}
					
					if (TreeViewObj.has("EnableSearch")) {
						if (TreeViewObj.getBoolean("EnableSearch") == true) {
							TreeViewRoot.addAttribute("EnableSearch", "true");
						}
					}
					
					if(TreeViewObj.has("FilterString")) {
						TreeViewRoot.addAttribute("FilterString", TreeViewObj.getString("FilterString"));
					}
					
					JSONObject TreeViewDataItems = TreeViewObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(TreeViewDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(TreeViewDataItems, "Measure");

					Element treeViewDataItems = TreeViewRoot.addElement("DataItems");
					
					if(DimDataItems == null) {
						DimDataItems = new JSONArray();
					}
					if(MeaDataItems == null) {
						MeaDataItems = new JSONArray();
					}
					
					if(DimDataItems.length() > 0) {
						for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
							JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
							Element DimTreeViewAttr = treeViewDataItems.addElement("Dimension");
							DimTreeViewAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
							if(dimdata.has("Name")) {
								DimTreeViewAttr.addAttribute("Name",  dimdata.getString("Name"));
							}
							DimTreeViewAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
							if(dimdata.has("CubeUniqueName")) {
								DimTreeViewAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
							}
							if(dimdata.has("SortOrder")) {
								if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
									DimTreeViewAttr.addAttribute("SortOrder", "Descending");
								}
							}
							if(dimdata.has("SortByMeasure")) {
								DimTreeViewAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
							}
						}
					}
					
					if(MeaDataItems.length() > 0) {
						for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
							JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
							Element MeaTreeViewAttr = treeViewDataItems.addElement("Measure");
							MeaTreeViewAttr.addAttribute("DataMember", meadata.getString("DataMember"));
							String summaryType = "";
							if(meadata.has("SummaryType")) {
								switch(meadata.getString("SummaryType")) {
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}
							if(meadata.has("Name")) {
								MeaTreeViewAttr.addAttribute("Name",  meadata.getString("Name"));
							}
							MeaTreeViewAttr.addAttribute("SummaryType",  summaryType);
							if (meadata.has("NumericFormat")) {
								Element NumericFormat = MeaTreeViewAttr.addElement("NumericFormat");
								JSONObject GridNumericFormat = meadata.getJSONObject("NumericFormat");
								if (GridNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", GridNumericFormat.getString("FormatType"));
								if (GridNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", GridNumericFormat.get("Precision") + "");
								if (GridNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", GridNumericFormat.getString("PrecisionOption") + "");
								if (GridNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", GridNumericFormat.getString("Unit"));
//								if (GridNumericFormat.has("SuffixEnabled")) {
//									NumericFormat.addAttribute("SuffixEnabled", GridNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
//								}
//								if (GridNumericFormat.has("Suffix")) {
//									Element Suffix = NumericFormat.addElement("Suffix");
//									JSONObject suffix = GridNumericFormat.getJSONObject("Suffix");
//									Suffix.addAttribute("O", suffix.getString("O"));
//									Suffix.addAttribute("K", suffix.getString("K"));
//									Suffix.addAttribute("M", suffix.getString("M"));
//									Suffix.addAttribute("B", suffix.getString("B"));
//								}
								if (GridNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator",
											GridNumericFormat.get("IncludeGroupSeparator").toString());
							}
							MeaTreeViewAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
							if(meadata.has("CubeUniqueName")) {
								MeaTreeViewAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
							}
//							if(meadata.has("SortOrder")) {
//								if(meadata.getString("SortOrder").equalsIgnoreCase("descending")) {
//									MeaGridAttr.addAttribute("SortOrder", "Descending");
//								}
//							}
						}
					}
					

					ArrayList<JSONObject> columnOrdering = new ArrayList<>();
					JSONObject FilterDimensionsObj = TreeViewObj.getJSONObject("FilterDimensions");
					JSONArray FilterDimensionsArr = toJsonArray(FilterDimensionsObj,"Dimension");

					Element FilterDimensions = TreeViewRoot.addElement("FilterDimensions");
					
					if(FilterDimensionsArr == null) {
						FilterDimensionsArr = new JSONArray();
					}
					if(TreeViewObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = TreeViewObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = TreeViewRoot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					
					for (int filterDimIdx = 0; filterDimIdx < FilterDimensionsArr.length();filterDimIdx++) {
						JSONObject dimObj = new JSONObject();
						dimObj.put("Dimension", FilterDimensionsArr.getJSONObject(filterDimIdx));
						columnOrdering.add(dimObj);
					}
					
					for (int coumnIdx = 0; coumnIdx < columnOrdering.size(); coumnIdx++) {
						JSONObject tempObj = new JSONObject();
						tempObj = columnOrdering.get(coumnIdx);
						if (tempObj.has("Dimension")) {
							Element Column = FilterDimensions.addElement("Dimension");
							Column.addAttribute("UniqueName",
									tempObj.getJSONObject("Dimension").getString("UniqueName"));
						} 
					}
					
//					for (JSONObject tempObj : columnOrdering) {
//						if (tempObj.has("Dimension")) {
//							Element Column = FilterDimensions.addElement("Dimension");
//							Column.addAttribute("UniqueName",
//									tempObj.getJSONObject("Dimension").getString("UniqueName"));
//						} 
//					}
				}
				break;
			case "ComboBox":
				JSONArray comboBoxItemArray = itemObj.getJSONArray("ComboBox");
				for(int eachComboBoxItem =0;eachComboBoxItem<comboBoxItemArray.length();eachComboBoxItem++) {
					JSONObject ComboBoxObj = comboBoxItemArray.getJSONObject(eachComboBoxItem);

					Element ComboBoxRoot = items.addElement("ComboBox");
					ComboBoxRoot.addAttribute("ComponentName", ComboBoxObj.getString("ComponentName"));
					ComboBoxRoot.addAttribute("Name", ComboBoxObj.getString("Name"));
					ComboBoxRoot.addAttribute("MemoText", ComboBoxObj.getString("MemoText"));
					ComboBoxRoot.addAttribute("DataSource", ComboBoxObj.getString("DataSource"));
					if(ComboBoxObj.has("ShowCaption")) {
						if(ComboBoxObj.getBoolean("ShowCaption") == false)
							ComboBoxRoot.addAttribute("ShowCaption", "false");
					}
					if (ComboBoxObj.has("InteractivityOptions")) {
						String masterFilterMode = "";
						boolean ignoreMasterFilter = false;
						if(!ComboBoxObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode").equals("Off")) {
//							Element InteractivityOptions = ComboBoxRoot.addElement("InteractivityOptions");
//							InteractivityOptions.addAttribute("MasterFilterMode",
//									ComboBoxObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode"));
							masterFilterMode = ComboBoxObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode");
						}
						if(ComboBoxObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters") == true) {
//							InteractivityOptions.addAttribute("MasterFilterMode",
//									chartObj.getJSONObject("InteractivityOptions").getString("MasterFilterMode"));
							ignoreMasterFilter = ComboBoxObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters");
						}
						
						if(!masterFilterMode.equals("") || ignoreMasterFilter == true) {
							Element InteractivityOptions = ComboBoxRoot.addElement("InteractivityOptions");
							if(!masterFilterMode.equals("")) {
								InteractivityOptions.addAttribute("MasterFilterMode",masterFilterMode);
							}
							if(ignoreMasterFilter == true) {
								InteractivityOptions.addAttribute("IgnoreMasterFilters","true");
							}
						}
					}
					if (ComboBoxObj.has("IsMasterFilterCrossDataSource")) {
						if (ComboBoxObj.getBoolean("IsMasterFilterCrossDataSource") == true) {
							ComboBoxRoot.addAttribute("IsMasterFilterCrossDataSource", "true");
						}
					}
					
					if (ComboBoxObj.has("ComboBoxType")) {
						if (ComboBoxObj.getString("ComboBoxType").equals("Checked")) {
							ComboBoxRoot.addAttribute("IsMasterFilterCrossDataSource", ComboBoxObj.getString("ComboBoxType"));
						}
					}
					
					if (ComboBoxObj.has("ShowAllValue")) {
						if (ComboBoxObj.getBoolean("ShowAllValue") == false) {
							ComboBoxRoot.addAttribute("ShowAllValue", "false");
						}
					}
					
					if (ComboBoxObj.has("EnableSearch")) {
						if (ComboBoxObj.getBoolean("EnableSearch") == true) {
							ComboBoxRoot.addAttribute("EnableSearch", "true");
						}
					}
					
					if(ComboBoxObj.has("FilterString")) {
						ComboBoxRoot.addAttribute("FilterString", ComboBoxObj.getString("FilterString"));
					}
					
					JSONObject ComboBoxDataItems = ComboBoxObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(ComboBoxDataItems, "Dimension");
					JSONArray MeaDataItems = toJsonArray(ComboBoxDataItems, "Measure");

					Element comboBoxDataItems = ComboBoxRoot.addElement("DataItems");
					
					if(DimDataItems == null) {
						DimDataItems = new JSONArray();
					}
					if(MeaDataItems == null) {
						MeaDataItems = new JSONArray();
					}
					
					if(DimDataItems.length() > 0) {
						for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
							JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
							Element DimComboBoxAttr = comboBoxDataItems.addElement("Dimension");
							DimComboBoxAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
							if(dimdata.has("Name")) {
								DimComboBoxAttr.addAttribute("Name",  dimdata.getString("Name"));
							}
							DimComboBoxAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
							if(dimdata.has("CubeUniqueName")) {
								DimComboBoxAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
							}
							if(dimdata.has("SortOrder")) {
								if(dimdata.getString("SortOrder").equalsIgnoreCase("descending")) {
									DimComboBoxAttr.addAttribute("SortOrder", "Descending");
								}
							}
							if(dimdata.has("SortByMeasure")) {
								DimComboBoxAttr.addAttribute("SortByMeasure", dimdata.getString("SortByMeasure"));
							}
						}
					}
					
					if(MeaDataItems.length() > 0) {
						for (int meaDataidx = 0; meaDataidx < MeaDataItems.length(); meaDataidx++) {
							JSONObject meadata = MeaDataItems.getJSONObject(meaDataidx);
							Element MeaComboBoxAttr = comboBoxDataItems.addElement("Measure");
							MeaComboBoxAttr.addAttribute("DataMember", meadata.getString("DataMember"));
							String summaryType = "";
							if(meadata.has("SummaryType")) {
								switch(meadata.getString("SummaryType")) {
								case "count":
									summaryType = "Count";
									break;
								case "min":
									summaryType = "Min";
									break;
								case "max":
									summaryType = "Max";
									break;
								case "avg":
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum";
									break;
								}
							}else {
								summaryType = "Sum";
							}
							if(meadata.has("Name")) {
								MeaComboBoxAttr.addAttribute("Name",  meadata.getString("Name"));
							}
							MeaComboBoxAttr.addAttribute("SummaryType",  summaryType);
							if (meadata.has("NumericFormat")) {
								Element NumericFormat = MeaComboBoxAttr.addElement("NumericFormat");
								JSONObject GridNumericFormat = meadata.getJSONObject("NumericFormat");
								if (GridNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", GridNumericFormat.getString("FormatType"));
								if (GridNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", GridNumericFormat.get("Precision") + "");
								if (GridNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", GridNumericFormat.getString("PrecisionOption") + "");
								if (GridNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", GridNumericFormat.getString("Unit"));
//								if (GridNumericFormat.has("SuffixEnabled")) {
//									NumericFormat.addAttribute("SuffixEnabled", GridNumericFormat.getBoolean("SuffixEnabled") ? "true" : "false");
//								}
//								if (GridNumericFormat.has("Suffix")) {
//									Element Suffix = NumericFormat.addElement("Suffix");
//									JSONObject suffix = GridNumericFormat.getJSONObject("Suffix");
//									Suffix.addAttribute("O", suffix.getString("O"));
//									Suffix.addAttribute("K", suffix.getString("K"));
//									Suffix.addAttribute("M", suffix.getString("M"));
//									Suffix.addAttribute("B", suffix.getString("B"));
//								}
								if (GridNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator",
											GridNumericFormat.get("IncludeGroupSeparator").toString());
							}
							MeaComboBoxAttr.addAttribute("UniqueName", meadata.getString("UniqueName"));
							if(meadata.has("CubeUniqueName")) {
								MeaComboBoxAttr.addAttribute("CubeUniqueName",  meadata.getString("CubeUniqueName"));
							}
//							if(meadata.has("SortOrder")) {
//								if(meadata.getString("SortOrder").equalsIgnoreCase("descending")) {
//									MeaGridAttr.addAttribute("SortOrder", "Descending");
//								}
//							}
						}
					}
					

					ArrayList<JSONObject> columnOrdering = new ArrayList<>();
					JSONObject FilterDimensionsObj = ComboBoxObj.getJSONObject("FilterDimensions");
					JSONArray FilterDimensionsArr = toJsonArray(FilterDimensionsObj,"Dimension");

					Element FilterDimensions = ComboBoxRoot.addElement("FilterDimensions");
					
					if(FilterDimensionsArr == null) {
						FilterDimensionsArr = new JSONArray();
					}
					if(ComboBoxObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = ComboBoxObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								Element HiddenMeasures = ComboBoxRoot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
								}
							}
						}
					}
					
					for (int filterDimIdx = 0; filterDimIdx < FilterDimensionsArr.length();filterDimIdx++) {
						JSONObject dimObj = new JSONObject();
						dimObj.put("Dimension", FilterDimensionsArr.getJSONObject(filterDimIdx));
						columnOrdering.add(dimObj);
					}
					
					for (int coumnIdx = 0; coumnIdx < columnOrdering.size(); coumnIdx++) {
						JSONObject tempObj = new JSONObject();
						tempObj = columnOrdering.get(coumnIdx);
						if (tempObj.has("Dimension")) {
							Element Column = FilterDimensions.addElement("Dimension");
							Column.addAttribute("UniqueName",
									tempObj.getJSONObject("Dimension").getString("UniqueName"));
						} 
					}
					
//					for (JSONObject tempObj : columnOrdering) {
//						if (tempObj.has("Dimension")) {
//							Element Column = FilterDimensions.addElement("Dimension");
//							Column.addAttribute("UniqueName",
//									tempObj.getJSONObject("Dimension").getString("UniqueName"));
//						} 
//					}
				}
				break;
			case "Image": // ymbin, xml : <element="attribute">element</element>
				JSONArray imageItemArray = itemObj.getJSONArray("Image");
				for(int eachMapItem =0;eachMapItem<imageItemArray.length();eachMapItem++) {
					JSONObject imageObj = imageItemArray.getJSONObject(eachMapItem);
					// <Image> - ComponentName, Name, Url
					Element imageroot = items.addElement("Image");
					imageroot.addAttribute("ComponentName", imageObj.getString("ComponentName"));
					imageroot.addAttribute("Name", imageObj.getString("Name"));
					imageroot.addAttribute("MemoText", imageObj.getString("MemoText"));
					imageroot.addAttribute("Url", imageObj.getString("Url"));
					
					if(imageObj.has("ShowCaption")) {
						if(imageObj.getBoolean("ShowCaption") == false)
							imageroot.addAttribute("ShowCaption", "false");
					}
					if (imageObj.has("SizeMode")) {
						imageroot.addAttribute("SizeMode", imageObj.getString("SizeMode"));
					}
					if (imageObj.has("HorizontalAlignment")) {
						imageroot.addAttribute("HorizontalAlignment", imageObj.getString("HorizontalAlignment"));
					}
					if (imageObj.has("VerticalAlignment")) {
						imageroot.addAttribute("VerticalAlignment", imageObj.getString("VerticalAlignment"));
					}
					
				}
				break;
			case "TextBox": // ymbin
				JSONArray textBoxItemArray = itemObj.getJSONArray("TextBox");
				for(int eachTextBoxItem = 0;eachTextBoxItem < textBoxItemArray.length();eachTextBoxItem++) {
					JSONObject textBoxObj = textBoxItemArray.getJSONObject(eachTextBoxItem);
					JSONObject textBoxDataItem = textBoxObj.getJSONObject("DataItems");
					
					// <TextBox> - ComponentName, Name
					Element textBoxRoot = items.addElement("TextBox");
					textBoxRoot.addAttribute("ComponentName", textBoxObj.getString("ComponentName"));
					textBoxRoot.addAttribute("Name", textBoxObj.getString("Name"));
					textBoxRoot.addAttribute("MemoText", textBoxObj.getString("MemoText"));
					/* DOGFOOT ktkang 텍스트에서 측정값 하나도 안올리고 저장 할 때 Default 설정  20191223 */
					if(textBoxObj.has("DataSource")) {
						textBoxRoot.addAttribute("DataSource", textBoxObj.getString("DataSource"));
					} else {
						textBoxRoot.addAttribute("DataSource", "dataSource1");
					}

					// 캡션 보기
					if(textBoxObj.has("ShowCaption")) {
						if(textBoxObj.getBoolean("ShowCaption") == false)
							textBoxRoot.addAttribute("ShowCaption", "false");
					}
					
					// 필터 - 마스터 필터 무시 On/Off
					if (textBoxObj.has("InteractivityOptions")) {
						boolean ignoreMasterFilter = false;
						
						if(textBoxObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters") == true) {
							ignoreMasterFilter = textBoxObj.getJSONObject("InteractivityOptions").getBoolean("IgnoreMasterFilters");
						}
						
						if(ignoreMasterFilter == true) {
							Element InteractivityOptions = textBoxRoot.addElement("InteractivityOptions");
							if(ignoreMasterFilter == true) {
								InteractivityOptions.addAttribute("IgnoreMasterFilters","true");
							}
						}
					}
					
					// <DataItems> - 값, 차원, 측정
					Element DataItems = textBoxRoot.addElement("DataItems");
					JSONArray DataItemAttr = toJsonArray(textBoxDataItem, "Measure");
					
					// <Measure> - Summary Type, DefaultId
					DataItemAttr = toJsonArray(textBoxDataItem, "Measure");
					if (DataItemAttr != null) {
						for (int Mea = 0; Mea < DataItemAttr.length(); Mea++) {
							
							Element Measure = DataItems.addElement("Measure");
							// <Dimentsion>
							Measure.addAttribute("DataMember", DataItemAttr.getJSONObject(Mea).getString("DataMember"));
							
							// SummaryType="summaryType"
							String summaryType = "";
							if(DataItemAttr.getJSONObject(Mea).has("SummaryType")) {
								switch(DataItemAttr.getJSONObject(Mea).getString("SummaryType")) {
								case "countdistinct":
									summaryType = "CountDistinct"; // 고유카운트
									break;
								case "count":
									summaryType = "Count"; // 카운트
									break;
								case "min": // 최소값
									summaryType = "Min";
									break;
								case "max": // 최대값
									summaryType = "Max";
									break;
								case "avg": // 평균
									summaryType = "Average";
									break;
								default:
									summaryType = "Sum"; // 합계
									break;
								}
							}else {
								summaryType = "Sum";
							}
							Measure.addAttribute("SummaryType",  summaryType);
							Measure.addAttribute("UniqueName", DataItemAttr.getJSONObject(Mea).getString("UniqueName"));
							if(DataItemAttr.getJSONObject(Mea).has("CubeUniqueName")) {
								Measure.addAttribute("CubeUniqueName",  DataItemAttr.getJSONObject(Mea).getString("CubeUniqueName"));
							}
							if (DataItemAttr.getJSONObject(Mea).has("NumericFormat")) {
								Element NumericFormat = Measure.addElement("NumericFormat");
								JSONObject ChartNumericFormat = DataItemAttr.getJSONObject(Mea)
										.getJSONObject("NumericFormat");
								if (ChartNumericFormat.has("FormatType"))
									NumericFormat.addAttribute("FormatType", ChartNumericFormat.getString("FormatType"));
								if (ChartNumericFormat.has("Precision"))
									NumericFormat.addAttribute("Precision", ChartNumericFormat.get("Precision") + "");
								if (ChartNumericFormat.has("PrecisionOption"))
									NumericFormat.addAttribute("PrecisionOption", ChartNumericFormat.getString("PrecisionOption") + "");
								if (ChartNumericFormat.has("Unit"))
									NumericFormat.addAttribute("Unit", ChartNumericFormat.getString("Unit"));
								if (ChartNumericFormat.has("IncludeGroupSeparator"))
									NumericFormat.addAttribute("IncludeGroupSeparator",
											ChartNumericFormat.get("IncludeGroupSeparator").toString());
							}
							
							// Rename ??
							if(DataItemAttr.getJSONObject(Mea).has("Name")) {
								Measure.addAttribute("Name",  DataItemAttr.getJSONObject(Mea).getString("Name"));
							}
						}
					}
					
					if(textBoxObj.has("HiddenMeasures")) {
						JSONObject hiddenMeasure = textBoxObj.getJSONObject("HiddenMeasures");
						if(hiddenMeasure.has("Measure")) {
							JSONArray hiddenMeasureArray = hiddenMeasure.getJSONArray("Measure");
							if(hiddenMeasureArray.length() != 0) {
								// <
								Element HiddenMeasures = textBoxRoot.addElement("HiddenMeasures");
								for(int hm = 0; hm < hiddenMeasureArray.length();hm++) {
									Element hiddenItem = HiddenMeasures.addElement("Measure");
									hiddenItem.addAttribute("UniqueName", hiddenMeasureArray.getJSONObject(hm).getString("UniqueName"));
									if(hiddenMeasureArray.getJSONObject(hm).has("CubeUniqueName")) {
										hiddenItem.addAttribute("CubeUniqueName",  hiddenMeasureArray.getJSONObject(hm).getString("CubeUniqueName"));
									}
									/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 밑으로 CubeUniqueName 부분 끝  20200618 */
								}
							}
						}
					}
					
					JSONObject textBoxValuesMea = textBoxObj.getJSONObject("Values");
					JSONArray textBoxValArr = toJsonArray(textBoxValuesMea, "Value");
					Element ValuesMeasures = textBoxRoot.addElement("Values");
					for(int valmea = 0; valmea<textBoxValArr.length();valmea++) {
						Element ValueMeasureAttr = ValuesMeasures.addElement("Value");
						ValueMeasureAttr.addAttribute("UniqueName", textBoxValArr.getJSONObject(valmea).getString("UniqueName"));
					}
					
//					Element textBoxText = textBoxRoot.addElement("Text");
//					textBoxText.addText(textBoxObj.getString("Text"));
					
					// html 형식에서 rtf 형식으로 변환
//					String rtfText = textBoxObj.getString("Text");
//					rtfText = convertToRTF(rtfText);
//		        	textBoxText.addText(rtfText);
					
				}
				break;
			case "TabContainer":
			/* DOGFOOT ktkang 탭컨테이너 삭제하면 저장안되는 오류 수정  20201113 */
				if(itemObj.has("TabContainer")) {
					JSONArray tabContainers = itemObj.getJSONArray("TabContainer");
					for(int eachMapItem = 0;eachMapItem < tabContainers.length(); eachMapItem++) {
						JSONObject tabContainerObj = tabContainers.getJSONObject(eachMapItem);
						Element tabContainerElement = items.addElement("TabContainer");
						if (tabContainerObj.has("ComponentName")) {
							tabContainerElement.addAttribute("ComponentName", tabContainerObj.getString("ComponentName"));
						}
						if (tabContainerObj.has("Name")) {
							tabContainerElement.addAttribute("Name", tabContainerObj.getString("Name"));
						}
						if (tabContainerObj.has("Pages")) {
							JSONObject pages = tabContainerObj.getJSONObject("Pages");
							Element pagesElement = tabContainerElement.addElement("Pages");
							if(pages.has("Page")) {
								JSONArray pageList = pages.getJSONArray("Page");
								if(pageList.length() != 0) {
									for(int pageNum = 0; pageNum < pageList.length(); pageNum++) {
										JSONObject page = pageList.getJSONObject(pageNum);
										Element pageElement = pagesElement.addElement("Page");
										if (page.has("ComponentName")) {
											pageElement.addAttribute("ComponentName", page.getString("ComponentName"));
										}
										if (page.has("Name")) {
											pageElement.addAttribute("Name", page.getString("Name"));
										}
									}
								}
							}
						}
					}
				}
				break;
			case "Hierarchical":
				JSONArray HierarchicalArray = itemObj.getJSONArray("Hierarchical");
				for(int eachMapItem =0;eachMapItem<HierarchicalArray.length();eachMapItem++) {
					JSONObject HierarchicalObj = HierarchicalArray.getJSONObject(eachMapItem);
					Element Hierarchicalroot = items.addElement("Hierarchical");
					Hierarchicalroot.addAttribute("ComponentName", HierarchicalObj.getString("ComponentName"));
					Hierarchicalroot.addAttribute("Name", HierarchicalObj.getString("Name"));
					Hierarchicalroot.addAttribute("MemoText", HierarchicalObj.getString("MemoText"));
					Hierarchicalroot.addAttribute("DataSource", HierarchicalObj.getString("DataSource"));
					
					if(HierarchicalObj.has("ShowCaption")) {
						if(HierarchicalObj.getBoolean("ShowCaption") == false) {
							Hierarchicalroot.addAttribute("ShowCaption", "false");
						}
					}
					
					if(HierarchicalObj.has("ZoomAble")) {
						//JSONObject LegendObject = ParallelObj.getJSONObject("TextFormat");
						//ParalleLegend.addAttribute("TextFormat", LegendObject.getBoolean("Visible") == true? "true" : "false");
						Hierarchicalroot.addAttribute("ZoomAble", HierarchicalObj.getString("ZoomAble"));
					}
					
					JSONObject HierarchicalDataItems = HierarchicalObj.getJSONObject("DataItems");
					JSONArray DimDataItems = toJsonArray(HierarchicalDataItems, "Dimension");
					
					Element HierarchicalMapDataItems = Hierarchicalroot.addElement("DataItems");
					for (int dimDataidx = 0; dimDataidx < DimDataItems.length(); dimDataidx++) {
						JSONObject dimdata = DimDataItems.getJSONObject(dimDataidx);
						Element DimHierarchicalAttr = HierarchicalMapDataItems.addElement("Dimension");
						DimHierarchicalAttr.addAttribute("DataMember", dimdata.getString("DataMember"));
						if(dimdata.has("Name")) {
							DimHierarchicalAttr.addAttribute("Name",  dimdata.getString("Name"));
						}
						DimHierarchicalAttr.addAttribute("UniqueName", dimdata.getString("UniqueName"));
						if(dimdata.has("CubeUniqueName")) {
							DimHierarchicalAttr.addAttribute("CubeUniqueName",  dimdata.getString("CubeUniqueName"));
						}
//						DimGridAttr.addAttribute("DefaultId", dimdata.getString("UniqueName"));
					}

					JSONArray Arguments = toJsonArray(HierarchicalObj.getJSONObject("Arguments"),"Argument");
					if(Arguments.length() >0) {
						Element ArgumentRoot = Hierarchicalroot.addElement("Arguments");
						for(int argIdx = 0; argIdx<Arguments.length();argIdx++) {
							JSONObject rowItem = Arguments.getJSONObject(argIdx);
							ArgumentRoot.addElement("Argument").addAttribute("UniqueName", rowItem.getString("UniqueName"));
//							ArgumentRoot.addElement("Argument").addAttribute("DefaultId", rowItem.getString("UniqueName"));
						}
					}
					if(HierarchicalObj.has("ColoringOption")) {
						Element ColoringOptions = Hierarchicalroot.addElement("ColoringOptions");
						ColoringOptions.addAttribute("MeasuresColoringMode", HierarchicalObj.getString("ColoringOption"));
						ColoringOptions.addAttribute("UseGlobalColors", HierarchicalObj.getString("UseGlobalColors"));
						JSONArray colorArray = HierarchicalObj.getJSONArray("ColorSheme");
						Element ColorSheme = Hierarchicalroot.addElement("ColorSheme");
						for(int coloritem=0; coloritem<colorArray.length(); coloritem++) {
							JSONObject coloritems = colorArray.getJSONObject(coloritem);
							Element Entry = ColorSheme.addElement("ColorSheme");
							Entry.addAttribute("DataSource", coloritems.getString("DataSource"));
							Entry.addAttribute("Color", coloritems.getString("Color"));
							Element MeasureKey = Entry.addElement("MeasureKey");
							Element Definition = MeasureKey.addElement("Definition");
							Definition.addAttribute("DataMember", coloritems.getString("MeasureKey"));
						}
					}
					
					//20200923 ajkim d3 레이아웃 옵션 추가 dogfoot
					if(HierarchicalObj.has("LayoutOption")) {
						JSONObject layoutOptionObj = HierarchicalObj.getJSONObject("LayoutOption");
						Element layoutOption = Hierarchicalroot.addElement("LayoutOption");
						if(layoutOptionObj.has("AxisX")) {
							JSONObject xOptionObj = layoutOptionObj.getJSONObject("AxisX");
							Element xOption = layoutOption.addElement("AxisX");
							xOption.addAttribute("family", xOptionObj.getString("family"));
							if(xOptionObj.has("color"))
								xOption.addAttribute("color", xOptionObj.getString("color"));
							if(xOptionObj.has("size"))
								xOption.addAttribute("size", xOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("AxisY")) {
							JSONObject yOptionObj = layoutOptionObj.getJSONObject("AxisY");
							Element yOption = layoutOption.addElement("AxisY");
							yOption.addAttribute("family", yOptionObj.getString("family"));
							if(yOptionObj.has("color"))
								yOption.addAttribute("color", yOptionObj.getString("color"));
							if(yOptionObj.has("size"))
								yOption.addAttribute("size", yOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("Legend")) {
							JSONObject legendOptionObj = layoutOptionObj.getJSONObject("Legend");
							Element legendOption = layoutOption.addElement("Legend");
							legendOption.addAttribute("family", legendOptionObj.getString("family"));
							if(legendOptionObj.has("color"))
								legendOption.addAttribute("color", legendOptionObj.getString("color"));
							if(legendOptionObj.has("size"))
								legendOption.addAttribute("size", legendOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("Title")) {
							JSONObject titleOptionObj = layoutOptionObj.getJSONObject("Title");
							Element titleOption = layoutOption.addElement("Title");
							titleOption.addAttribute("family", titleOptionObj.getString("family"));
							if(titleOptionObj.has("color"))
								titleOption.addAttribute("color", titleOptionObj.getString("color"));
							if(titleOptionObj.has("size"))
								titleOption.addAttribute("size", titleOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("Label")) {
							JSONObject labelOptionObj = layoutOptionObj.getJSONObject("Label");
							Element labelOption = layoutOption.addElement("Label");
							labelOption.addAttribute("family", labelOptionObj.getString("family"));
							if(labelOptionObj.has("color"))
								labelOption.addAttribute("color", labelOptionObj.getString("color"));
							if(labelOptionObj.has("size"))
								labelOption.addAttribute("size", labelOptionObj.getInt("size") + "");
						}
						if(layoutOptionObj.has("Circle")) {
							JSONArray circleSizeArray = layoutOptionObj.getJSONArray("Circle");
							for(int arrayIndex = 0; arrayIndex < circleSizeArray.length(); arrayIndex++) {
								layoutOption.addElement("Circle").setText(circleSizeArray.get(arrayIndex).toString());
							}
						}
					}
				}
				break;
			// KERIS 수정 끝
			}
		}
		
		if (layoutObj.has("LayoutTree")) {
			JSONObject layoutTree = layoutObj.getJSONObject("LayoutTree");
			Element layoutTreeElement = dashBoard.addElement("LayoutTree");
			setLayoutTreeElement(layoutTreeElement, layoutTree);
		}
		
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(false);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(layoutXml);

		return " "+sw.toString();
	}

	public String sortParamXml(JSONObject paramObjects) throws IOException {
		Document paramXml = DocumentHelper.createDocument();
		
		Element paramRoot = paramXml.addElement("PARAM_XML");
		
		Iterator<String> paramKey = paramObjects.keys();
		while (paramKey.hasNext()) {
			String paramKeyName = paramKey.next().toString();
			if(paramObjects.get(paramKeyName) instanceof JSONObject){
				JSONObject paramItem = paramObjects.getJSONObject(paramKeyName);
				Element paramElement = paramRoot.addElement("PARAM");
				/* dogfoot WHATIF 분석 매개변수 저장 shlim 20201022 */	
				if(paramItem.has("CALC_PARAM_YN")) {
					paramElement.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
					paramElement.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
					String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
					paramElement.addElement("DEFAULT_VALUE").addText(defaultVal);
					paramElement.addElement("SET_VALUE").addText(defaultVal);
					paramElement.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
//					paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
//					paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
					paramElement.addElement("SLIDER_POINT").addText(paramItem.get("SLIDER_POINT") + "");
					paramElement.addElement("SLIDER_MIN").addText(paramItem.get("SLIDER_MIN") + "");
					paramElement.addElement("SLIDER_MAX").addText(paramItem.get("SLIDER_MAX") + "");
					
					paramElement.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
					paramElement.addElement("CALC_PARAM_YN").addText(paramItem.getString("CALC_PARAM_YN"));
					
				}else {
					paramElement.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
					paramElement.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
					paramElement.addElement("DATA_TYPE").addText(paramItem.getString("DATA_TYPE"));
					paramElement.addElement("PARAM_TYPE").addText(paramItem.getString("PARAM_TYPE"));
					paramElement.addElement("DATASRC_TYPE").addText(paramItem.getString("DATASRC_TYPE"));
					paramElement.addElement("DATASRC").addText(paramItem.getString("DATASRC"));
					paramElement.addElement("CAPTION_VALUE_ITEM").addText(paramItem.getString("CAPTION_VALUE_ITEM"));
					paramElement.addElement("KEY_VALUE_ITEM").addText(paramItem.getString("KEY_VALUE_ITEM"));
					paramElement.addElement("SORT_VALUE_ITEM").addText(paramItem.getString("SORT_VALUE_ITEM"));
					String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
					
					if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
						String[] defalutBetween = paramItem.getString("HIDDEN_VALUE").split(",");
						String reultDefault = "";
						/* DOGFOOT mksong BASE64 오류 수정  20200116 */
//						reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[0].getBytes()));
//						reultDefault += ",";
//						reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[1].getBytes()));
						
						reultDefault += new String(defalutBetween[0].getBytes());
						reultDefault += ",";
						reultDefault += new String(defalutBetween[1].getBytes());
						paramElement.addElement("DEFAULT_VALUE").addText(reultDefault);
					}
					else if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
						/*dogfoot 비정형 비트윈달력 기본값 설정 오류 shlim 20210319*/
						String reultDefault = paramItem.get("DEFAULT_VALUE").toString();
						reultDefault = reultDefault.replace("\"", "");
						reultDefault = reultDefault.replace("\\", "");
						reultDefault = reultDefault.replace("[", "");
						reultDefault = reultDefault.replace("]", "");
						paramElement.addElement("DEFAULT_VALUE").addText(reultDefault);
//						paramElement.addElement("DEFAULT_VALUE").addText(paramItem.get("DEFAULT_VALUE")+"");
					}
					else if(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
						//String defaultSQLVal = paramItem.getString("HIDDEN_VALUE");
						paramElement.addElement("DEFAULT_VALUE").addText(paramItem.get("DEFAULT_VALUE")+"");
					}
					else {
						if(defaultVal.equals("_ALL_VALUE_")) {
							defaultVal = "[All]";
						}
						else {
							paramElement.addElement("DEFAULT_VALUE").addText(defaultVal);
						}
					}
					
		
					paramElement.addElement("CAPTION_FORMAT").addText(paramItem.getString("CAPTION_FORMAT"));
					paramElement.addElement("KEY_FORMAT").addText(paramItem.getString("KEY_FORMAT"));
					paramElement.addElement("CAND_DEFAULT_TYPE").addText(paramItem.getString("CAND_DEFAULT_TYPE"));
					/*dogfoot 캘린더 기간 설정 shlim 20210427*/
					if(paramItem.has("CAND_MAX_GAP")) {
						paramElement.addElement("CAND_MAX_GAP").addText(paramItem.get("CAND_MAX_GAP")+"");
					}
					paramElement.addElement("CAND_PERIOD_BASE").addText(paramItem.getString("CAND_PERIOD_BASE"));
					paramElement.addElement("CAND_PERIOD_VALUE").addText(paramItem.get("CAND_PERIOD_VALUE") + "");
					paramElement.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
					paramElement.addElement("MULTI_SEL").addText(paramItem.getString("MULTI_SEL"));
					/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
					if(paramItem.has("ORDERBY_KEY")) {
						paramElement.addElement("ORDERBY_KEY").addText(paramItem.getString("ORDERBY_KEY"));
					}
					//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
					if(paramItem.has("CAPTION_WIDTH")){
						paramElement.addElement("CAPTION_WIDTH").addText(paramItem.get("CAPTION_WIDTH") + "");
					}
					if(paramItem.has("CAPTION_WIDTH_VISIBLE")){
						paramElement.addElement("CAPTION_WIDTH_VISIBLE").addText(paramItem.get("CAPTION_WIDTH_VISIBLE") + "");
					}
					paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
					paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
					paramElement.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
					paramElement.addElement("DS_ID").addText(paramItem.get("DS_ID") + "");
					paramElement.addElement("ALL_YN").addText(paramItem.getString("ALL_YN"));
					paramElement.addElement("WHERE_CLAUSE").addText(paramItem.getString("WHERE_CLAUSE"));
					//2020.01.17 mksong 타입 오류 수정 dogfoot
					if(paramItem.get("HIDDEN_VALUE") instanceof Integer) {
						paramElement.addElement("HIDDEN_VALUE").addText(paramItem.getInt("HIDDEN_VALUE")+"");	
					}else {
						paramElement.addElement("HIDDEN_VALUE").addText(paramItem.getString("HIDDEN_VALUE"));					
					}
					paramElement.addElement("DEFAULT_VALUE_USE_SQL_SCRIPT").addText(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT"));
					paramElement.addElement("SORT_TYPE").addText(paramItem.getString("SORT_TYPE"));
					paramElement.addElement("OPER").addText(paramItem.getString("OPER"));
					paramElement.addElement("BIND_YN").addText(paramItem.getString("BIND_YN"));
					paramElement.addElement("SEARCH_YN").addText(paramItem.getString("SEARCH_YN"));
					paramElement.addElement("EDIT_YN").addText(paramItem.getString("EDIT_YN"));
					/*dogfoot shlim 20210415*/
					if(paramItem.has("LINE_BREAK")){
						paramElement.addElement("LINE_BREAK").addText(paramItem.getString("LINE_BREAK"));
					}
					if(paramItem.has("INPUT_EDIT_YN")){
						paramElement.addElement("INPUT_EDIT_YN").addText(paramItem.getString("INPUT_EDIT_YN"));
					}
					paramElement.addElement("RANGE_YN").addText(paramItem.getString("RANGE_YN"));
					/*DOGFOOT cshan 20200113 - between 필터 저장시 오류 수정*/
					paramElement.addElement("RANGE_VALUE").addText(paramItem.get("RANGE_VALUE")+"");
					paramElement.addElement("DEFAULT_VALUE_MAINTAIN").addText(paramItem.getString("DEFAULT_VALUE_MAINTAIN"));
					paramElement.addElement("TYPE_CHANGE_YN").addText(paramItem.getString("TYPE_CHANGE_YN"));
				}
				
			}
		}
		
//		for (int paramItem = 0; paramItem < paramArray.length(); paramItem++) {
//			JSONObject paramJson = paramArray.getJSONObject(paramItem);
//
//			Element paramElement = paramRoot.addElement("PARAM");
//			paramElement.addElement("PARAM_NM").addText(paramJson.getString("PARAM_NM"));
//			paramElement.addElement("PARAM_CAPTION").addText(paramJson.getString("PARAM_CAPTION"));
//			paramElement.addElement("DATA_TYPE").addText(paramJson.getString("DATA_TYPE"));
//			paramElement.addElement("PARAM_TYPE").addText(paramJson.getString("PARAM_TYPE"));
//			paramElement.addElement("DATASRC_TYPE").addText(paramJson.getString("DATASRC_TYPE"));
//			paramElement.addElement("DATASRC").addText(paramJson.getString("DATASRC"));
//			paramElement.addElement("CAPTION_VALUE_ITEM").addText(paramJson.getString("CAPTION_VALUE_ITEM"));
//			paramElement.addElement("KEY_VALUE_ITEM").addText(paramJson.getString("KEY_VALUE_ITEM"));
//			paramElement.addElement("SORT_VALUE_ITEM").addText(paramJson.getString("SORT_VALUE_ITEM"));
//			paramElement.addElement("DEFAULT_VALUE").addText(paramJson.get("DEFAULT_VALUE") + "");
//
//			paramElement.addElement("CAPTION_FORMAT").addText(paramJson.getString("CAPTION_FORMAT"));
//			paramElement.addElement("KEY_FORMAT").addText(paramJson.getString("KEY_FORMAT"));
//			paramElement.addElement("CAND_DEFAULT_TYPE").addText(paramJson.getString("CAND_DEFAULT_TYPE"));
//			paramElement.addElement("CAND_PERIOD_BASE").addText(paramJson.getString("CAND_PERIOD_BASE"));
//			paramElement.addElement("CAND_PERIOD_VALUE").addText(paramJson.get("CAND_PERIOD_VALUE") + "");
//			paramElement.addElement("VISIBLE").addText(paramJson.getString("VISIBLE"));
//			paramElement.addElement("MULTI_SEL").addText(paramJson.getString("MULTI_SEL"));
//			paramElement.addElement("WIDTH").addText(paramJson.get("WIDTH") + "");
//			paramElement.addElement("ORDER").addText(paramJson.get("ORDER") + "");
//			paramElement.addElement("UNI_NM").addText(paramJson.getString("UNI_NM"));
//			paramElement.addElement("DS_ID").addText(paramJson.get("DS_ID") + "");
//			paramElement.addElement("ALL_YN").addText(paramJson.getString("ALL_YN"));
//			paramElement.addElement("WHERE_CLAUSE").addText(paramJson.getString("WHERE_CLAUSE"));
//			paramElement.addElement("HIDDEN_VALUE").addText(paramJson.getString("HIDDEN_VALUE"));
//			paramElement.addElement("DEFAULT_VALUE_USE_SQL_SCRIPT").addText(paramJson.getString("DEFAULT_VALUE_USE_SQL_SCRIPT"));
//			paramElement.addElement("SORT_TYPE").addText(paramJson.getString("SORT_TYPE"));
//			paramElement.addElement("OPER").addText(paramJson.getString("OPER"));
//			paramElement.addElement("BIND_YN").addText(paramJson.getString("BIND_YN"));
//			paramElement.addElement("SEARCH_YN").addText(paramJson.getString("SEARCH_YN"));
//			paramElement.addElement("EDIT_YN").addText(paramJson.getString("EDIT_YN"));
//			paramElement.addElement("RANGE_YN").addText(paramJson.getString("RANGE_YN"));
//			paramElement.addElement("RANGE_VALUE").addText(paramJson.getString("RANGE_VALUE"));
//			paramElement.addElement("DEFAULT_VALUE_MAINTAIN").addText(paramJson.getString("DEFAULT_VALUE_MAINTAIN"));
//			paramElement.addElement("TYPE_CHANGE_YN").addText(paramJson.getString("TYPE_CHANGE_YN"));
//		}
		
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(paramXml.getRootElement());
		return sw.toString().substring(1);
	}
	
	public String sortLinkReportXml(JSONObject paramObjects) throws IOException {
		Document paramXml = DocumentHelper.createDocument();
		
		Element paramRoot = paramXml.addElement("LINKDATA_XML");
		
		Iterator<String> paramKey = paramObjects.keys();
		while (paramKey.hasNext()) {
			String paramKeyName = paramKey.next().toString();
			if(paramObjects.get(paramKeyName) instanceof JSONObject){
				JSONObject paramItem = paramObjects.getJSONObject(paramKeyName);
				/* DOGFOOT mksong 연결보고서 저장 오류 수정 20200116 */
				if(paramItem.get("ARG_DATA") instanceof JSONObject) {
					JSONObject param = paramItem.getJSONObject("ARG_DATA");
					Element paramElement = paramRoot.addElement("ARG_DATA");
					paramElement.addElement("FK_COL_NM").addText(param.getString("FK_COL_NM"));
					paramElement.addElement("PK_COL_NM").addText(param.getString("PK_COL_NM"));
				}else {
					JSONArray paramArgs = paramItem.getJSONArray("ARG_DATA");
					for(int i = 0; i < paramArgs.length(); i++) {
						Element paramElement = paramRoot.addElement("ARG_DATA");
						paramElement.addElement("FK_COL_NM").addText(paramArgs.getJSONObject(i).getString("FK_COL_NM"));
						paramElement.addElement("PK_COL_NM").addText(paramArgs.getJSONObject(i).getString("PK_COL_NM"));
					}	
				}
//				paramElement.addElement("FK_COL_NM").addText(paramItem.getJSONObject("ARG_DATA").getString("FK_COL_NM"));
//				paramElement.addElement("PK_COL_NM").addText(paramItem.getJSONObject("ARG_DATA").getString("PK_COL_NM"));
			}else if(paramObjects.get(paramKeyName) instanceof JSONArray){
				JSONArray paramItem = paramObjects.getJSONArray(paramKeyName);
				for(int i = 0; i < paramItem.length(); i++) {
					Element paramElement = paramRoot.addElement("ARG_DATA");
					paramElement.addElement("FK_COL_NM").addText(paramItem.getJSONObject(i).getJSONObject("ARG_DATA").getString("FK_COL_NM"));
					paramElement.addElement("PK_COL_NM").addText(paramItem.getJSONObject(i).getJSONObject("ARG_DATA").getString("PK_COL_NM"));
				}
			}
		}
		
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(paramXml.getRootElement());
		return sw.toString().substring(1);
	}
	
	public String sortSubLinkReportXml(JSONObject paramObjects) throws IOException {
		Document paramXml = DocumentHelper.createDocument();
		
		Element paramRoot = paramXml.addElement("LINK_XML_PARAM");
		
		Iterator<String> paramKey = paramObjects.keys();
		while (paramKey.hasNext()) {
			String paramKeyName = paramKey.next().toString();
			if(paramObjects.get(paramKeyName) instanceof JSONObject){
				JSONObject paramItem = paramObjects.getJSONObject(paramKeyName);
				/* DOGFOOT mksong 서브연결보고서 저장 오류 수정 20200116 */
				if(paramItem.get("ARG_DATA") instanceof JSONObject) {
					JSONObject param = paramItem.getJSONObject("ARG_DATA");
					Element paramElement = paramRoot.addElement("ARG_DATA");
					paramElement.addElement("FK_COL_NM").addText(param.getString("FK_COL_NM"));
					paramElement.addElement("PK_COL_NM").addText(param.getString("PK_COL_NM"));
				}else {
					JSONArray paramArgs = paramItem.getJSONArray("ARG_DATA");
					for(int i = 0; i < paramArgs.length(); i++) {
						Element paramElement = paramRoot.addElement("ARG_DATA");
						paramElement.addElement("FK_COL_NM").addText(paramArgs.getJSONObject(i).getString("FK_COL_NM"));
						paramElement.addElement("PK_COL_NM").addText(paramArgs.getJSONObject(i).getString("PK_COL_NM"));
					}	
				}
			}
		}
		
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(paramXml.getRootElement());
		return sw.toString().substring(1);
	}
	
	public String sortSubLinkReportDataXml(JSONObject paramObjects) throws IOException {
		Document paramXml = DocumentHelper.createDocument();
		
		Element paramRoot = paramXml.addElement("LINK_XML_DATA");
		
		Iterator<String> paramKey = paramObjects.keys();
		while (paramKey.hasNext()) {
			String paramKeyName = paramKey.next().toString();
			if(paramObjects.get(paramKeyName) instanceof JSONObject){
				JSONObject paramItem = paramObjects.getJSONObject(paramKeyName);
				/* DOGFOOT mksong 연결보고서 저장 오류 수정 20200116 */
				if(paramItem.get("ARG_DATA") instanceof JSONObject) {
					JSONObject param = paramItem.getJSONObject("ARG_DATA");
					Element paramElement = paramRoot.addElement("ARG_DATA");
					paramElement.addElement("FK_COL_NM").addText(param.getString("FK_COL_NM"));
					paramElement.addElement("PK_COL_NM").addText(param.getString("PK_COL_NM"));
				}else {
					JSONArray params = paramItem.getJSONArray("ARG_DATA");
					for(int i = 0; i < params.length(); i++) {
						Element paramElement = paramRoot.addElement("ARG_DATA");
						paramElement.addElement("FK_COL_NM").addText(params.getJSONObject(i).getString("FK_COL_NM"));
						paramElement.addElement("PK_COL_NM").addText(params.getJSONObject(i).getString("PK_COL_NM"));
					}	
				}
			}
		}
		
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(paramXml.getRootElement());
		return sw.toString().substring(1);
	}
	
	public String sortDataSetXml(JSONObject DataSetObject, JSONObject paramObject, JSONObject dsFields, boolean sheetFlag) throws IOException {
		Document DataSetXml = DocumentHelper.createDocument();
		
		Element DataSetRoot = DataSetXml.addElement("DATASET_XML");
		Element DataSetElement = DataSetRoot.addElement("DATASET_ELEMENT");
//		JSONArray DataSetArray = toJsonArray(DataSetObject, "dataset_xml");
		/* DOGFOOT hsshim 2020-01-15 주제영역 저장 오류 수정 */
		String[] names = JSONObject.getNames(DataSetObject);
		Arrays.sort(names);
		for(String dataSetNames : names) {
			JSONObject JsonDataSetElement = DataSetObject.getJSONObject(dataSetNames);
			Element DataSet = DataSetElement.addElement("DATASET");
			String uuid = UUID.randomUUID().toString();
			DataSet.addElement("DATASET_SEQ").addText(uuid);
			String dataSetNm = JsonDataSetElement.get("DATASET_NM")+"";
			dataSetNm = dataSetNm.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
			DataSet.addElement("DATASET_NM").addText(dataSetNm);
			DataSet.addElement("DATASRC_ID").addText(JsonDataSetElement.get("DATASRC_ID")+"");
			DataSet.addElement("DATASRC_TYPE").addText(JsonDataSetElement.getString("DATASRC_TYPE"));
			DataSet.addElement("DATASET_TYPE").addText(JsonDataSetElement.getString("DATASET_TYPE"));
			/* dogfoot shlim ERD 조인타입 추가 20210201*/
			if(JsonDataSetElement.has("JOIN_TYPE")) {
				DataSet.addElement("JOIN_TYPE").addText(JsonDataSetElement.getString("JOIN_TYPE"));
			}
			//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
			if(JsonDataSetElement.has("IN_MEMORY")) {
				DataSet.addElement("IN_MEMORY").addText(JsonDataSetElement.getString("IN_MEMORY"));
			}
			
			// 2021-07-07 yyb 주제영역이 아닐때 데이터 집합의 항목을 저장한다.
			if (!JsonDataSetElement.getString("DATASRC_TYPE").equals("CUBE")) {
				if(dsFields.has(dataSetNames)){
					JSONArray dsFieldArr = dsFields.getJSONArray(dataSetNames);
					if (dsFieldArr != null) {
						Element dataSetFileds = DataSet.addElement("DATASET_FIELD");
						for (int fieldIdx = 0; fieldIdx < dsFieldArr.length(); fieldIdx++) {
							Element field = dataSetFileds.addElement("LIST");
							JSONObject dsFieldObj = dsFieldArr.getJSONObject(fieldIdx);
							Iterator<String> itemKey = dsFieldObj.keys();
							while (itemKey.hasNext()) {
								String keyName = itemKey.next().toString();
								field.addAttribute(keyName, dsFieldObj.get(keyName).toString());
							}
						}
					}
				}
			}

			if(JsonDataSetElement.getString("DATASET_TYPE").equals("DataSetCube")) {
				Element dataSetXml = DataSet.addElement("DATASET_XML");
//				JSONArray dataSetMeta = toJsonArray(JsonDataSetElement, "DATA_META");
				JSONObject selectELEMENT = JsonDataSetElement.getJSONObject("SEL_ELEMENT");
				logger.debug(JsonDataSetElement.toString());
				StringBuilder sb = new StringBuilder();
				sb.append("<DATA_SET>");
				sb.append(sortSelectElement(selectELEMENT));
//				sb.append("<WHERE_ELEMENT/>");
				JSONObject whereELEMENT = new JSONObject();
				if(!JsonDataSetElement.get("WHERE_ELEMENT").toString().equals("")) {
					whereELEMENT = JsonDataSetElement.getJSONObject("WHERE_ELEMENT");
					sb.append(sortWhereElement(whereELEMENT));
				}else {
					sb.append("<WHERE_ELEMENT/>");
				}
				if(!JsonDataSetElement.get("ORDER_ELEMENT").toString().equals("")) {
					JSONObject orderElement = JsonDataSetElement.getJSONObject("ORDER_ELEMENT");
					sb.append(sortOrderElement(orderElement));
				}else {
					sb.append("<ORDER_ELEMENT/>");
				}
				sb.append(sortParamXmltoDataSetXml(paramObject));
				sb.append("</DATA_SET>");
				dataSetXml.addText(sb.toString());
			}else if(JsonDataSetElement.getString("DATASET_TYPE").equals("DataSetDs")) {
				Element dataSetXml = DataSet.addElement("DATASET_XML");
				dataSetXml.setText(sortDataSetXMLForDataSetDS(JsonDataSetElement,paramObject,true));
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
			}else if(JsonDataSetElement.getString("DATASET_TYPE").equals("DataSetSQL") || JsonDataSetElement.getString("DATASET_TYPE").equals("CUBE")) {
				Element dataSetXml = DataSet.addElement("DATASET_XML");
				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				String queryBase64 = "";
				if(JsonDataSetElement.has("SQL_QUERY")) {
					queryBase64 = new String(java.util.Base64.getEncoder().encode(JsonDataSetElement.getString("SQL_QUERY").getBytes()));
				}
				StringBuilder sb = new StringBuilder();
				sb.append("<DATA_SET><SQL_QUERY>");
				sb.append(queryBase64);
				sb.append("</SQL_QUERY>");
				if (JsonDataSetElement.has("PARAM_ELEMENT")) {
					JSONArray paramArr = JsonDataSetElement.getJSONArray("PARAM_ELEMENT");
					sb.append(sortParamXmltoDataSetXml(paramObject,paramArr));
				}
				sb.append("<DATASET_NM>");
				sb.append(JsonDataSetElement.get("DATASET_NM")+"");
				sb.append("</DATASET_NM></DATA_SET>");
				dataSetXml.addText(sb.toString());
				
			}else if(JsonDataSetElement.getString("DATASET_TYPE").equals("DataSetSingleDs") || JsonDataSetElement.getString("DATASET_TYPE").equals("DataSetSingleDsView")) {
				Element dataSetXml = DataSet.addElement("DATASET_XML");
				dataSetXml.setText(sortDataSetXMLForDataSetSingle(JsonDataSetElement,new JSONObject(),true));
			}
			
			
//			DataSet.addElement("DATASET_QUERY").addText(JsonDataSetElement.getString("SQL_QUERY"));
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
			String strQuery = "";
			if(JsonDataSetElement.has("SQL_QUERY")) {
				strQuery = JsonDataSetElement.getString("SQL_QUERY");
			}
//			strQuery = strQuery.replaceAll("\"", "\\\"");
			DataSet.addElement("DATASET_QUERY").addText(strQuery);
			if(sheetFlag) DataSet.addElement("SHEET_ID").addText(JsonDataSetElement.getString("SHEET_ID"));
		}
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
//		outputFormat.setIndent(true);
//		outputFormat.setNewlines(true);
//		outputFormat.setNewLineAfterDeclaration(false);
//		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(DataSetXml.getRootElement());
		System.out.println("----------------------------------------------");
		System.out.println(sw.toString());
		System.out.println("----------------------------------------------");
//		return DataSetXml.asXML().toString();
		return sw.toString();
	}
	
	public String sortParamXmltoDataSetXml(JSONObject paramObjects,JSONArray dataSourceParam) throws IOException {

		Document paramXml = DocumentHelper.createDocument();

		Element paramRoot = paramXml.addElement("PARAM_ELEMENT");
		
		Iterator<String> paramKey = paramObjects.keys();
		
		while (paramKey.hasNext()) {
			String paramKeyName = paramKey.next().toString();
			if(paramObjects.get(paramKeyName) instanceof JSONObject){
				for(int paramIdx = 0; paramIdx<dataSourceParam.length();paramIdx++) {
					String dataSourceParamKey = dataSourceParam.get(paramIdx).toString();
					/* dogfoot WHATIF 분석 매개변수 저장 shlim 20201022 */
					if(!paramObjects.getJSONObject(paramKeyName).has("CALC_PARAM_YN")) {
						if(paramObjects.getJSONObject(paramKeyName).get("PARAM_TYPE").toString().contains("BETWEEN")) {
							dataSourceParamKey = dataSourceParamKey.replace("_fr", "");
						}
					}
					
					if(dataSourceParamKey.equals(paramKeyName)) {
						JSONObject paramItem = paramObjects.getJSONObject(paramKeyName);
						
						Element paramElement = paramRoot.addElement("PARAM");
						/* dogfoot WHATIF 분석 매개변수 저장 shlim 20201022 */
						if(paramItem.has("CALC_PARAM_YN")) {
							paramElement.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
							paramElement.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
							String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
							paramElement.addElement("DEFAULT_VALUE").addText(defaultVal);
							paramElement.addElement("SET_VALUE").addText(defaultVal);
							paramElement.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
//							paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
//							paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
							paramElement.addElement("SLIDER_POINT").addText(paramItem.get("SLIDER_POINT") + "");
							paramElement.addElement("SLIDER_MIN").addText(paramItem.get("SLIDER_MIN") + "");
							paramElement.addElement("SLIDER_MAX").addText(paramItem.get("SLIDER_MAX") + "");
							
							paramElement.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
							paramElement.addElement("CALC_PARAM_YN").addText(paramItem.getString("CALC_PARAM_YN"));
							
						}else {
							paramElement.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
							paramElement.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
							paramElement.addElement("DATA_TYPE").addText(paramItem.getString("DATA_TYPE"));
							paramElement.addElement("PARAM_TYPE").addText(paramItem.getString("PARAM_TYPE"));
							paramElement.addElement("DATASRC_TYPE").addText(paramItem.getString("DATASRC_TYPE"));
							paramElement.addElement("DATASRC").addText(paramItem.getString("DATASRC"));
							paramElement.addElement("CAPTION_VALUE_ITEM").addText(paramItem.getString("CAPTION_VALUE_ITEM"));
							paramElement.addElement("KEY_VALUE_ITEM").addText(paramItem.getString("KEY_VALUE_ITEM"));
							paramElement.addElement("SORT_VALUE_ITEM").addText(paramItem.getString("SORT_VALUE_ITEM"));
							String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
							
							if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
								String[] defalutBetween = paramItem.getString("HIDDEN_VALUE").split(",");
								String reultDefault = "";
								/* DOGFOOT mksong BASE64 오류 수정 20200116 */
	//							reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[0].getBytes()));
	//							reultDefault += ",";
	//							reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[1].getBytes()));
								reultDefault += new String(defalutBetween[0].getBytes());
								reultDefault += ",";
								reultDefault += new String(defalutBetween[1].getBytes());
								paramElement.addElement("DEFAULT_VALUE").addText(reultDefault);
							}
							else if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
								if(paramItem.getString("PARAM_TYPE").equalsIgnoreCase("BETWEEN_CAND")) {
									defaultVal = paramItem.get("DEFAULT_VALUE")+"";
								}else {
									JSONArray defaultArr = paramItem.getJSONArray("DEFAULT_VALUE");
									defaultVal = defaultArr.get(0)+","+defaultArr.get(1);
								}
								
								paramElement.addElement("DEFAULT_VALUE").addText(defaultVal);
							}
							else if(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
								String defaultSQLVal = paramItem.getString("HIDDEN_VALUE");
								/* DOGFOOT mksong BASE64 오류 수정 20200116 */
								paramElement.addElement("DEFAULT_VALUE").addText(new String(java.util.Base64.getEncoder().encode(defaultSQLVal.getBytes())));
							}
							else {
								if(defaultVal.equals("_ALL_VALUE_")) {
									defaultVal = "[All]";
								}else {
									paramElement.addElement("DEFAULT_VALUE").addText(defaultVal);
								}
								
							}
							paramElement.addElement("CAPTION_FORMAT").addText(paramItem.getString("CAPTION_FORMAT"));
							paramElement.addElement("KEY_FORMAT").addText(paramItem.getString("KEY_FORMAT"));
							paramElement.addElement("CAND_DEFAULT_TYPE").addText(paramItem.getString("CAND_DEFAULT_TYPE"));
							/*dogfoot 캘린더 기간 설정 shlim 20210427*/
							if(paramItem.has("CAND_MAX_GAP")) {
								paramElement.addElement("CAND_MAX_GAP").addText(paramItem.get("CAND_MAX_GAP")+"");
							}
							paramElement.addElement("CAND_PERIOD_BASE").addText(paramItem.getString("CAND_PERIOD_BASE"));
							paramElement.addElement("CAND_PERIOD_VALUE").addText(paramItem.get("CAND_PERIOD_VALUE") + "");
							paramElement.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
							paramElement.addElement("MULTI_SEL").addText(paramItem.getString("MULTI_SEL"));
							/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
							if(paramItem.has("ORDERBY_KEY")) {
								paramElement.addElement("ORDERBY_KEY").addText(paramItem.getString("ORDERBY_KEY"));
							}
							paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
							paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
							paramElement.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
							paramElement.addElement("DS_ID").addText(paramItem.get("DS_ID") + "");
							paramElement.addElement("ALL_YN").addText(paramItem.getString("ALL_YN"));
							paramElement.addElement("WHERE_CLAUSE").addText(paramItem.getString("WHERE_CLAUSE"));
							//2020.01.17 mksong 타입 오류 수정 dogfoot
							if(paramItem.get("HIDDEN_VALUE") instanceof Integer) {
								paramElement.addElement("HIDDEN_VALUE").addText(paramItem.getInt("HIDDEN_VALUE")+"");	
							}else {
								paramElement.addElement("HIDDEN_VALUE").addText(paramItem.getString("HIDDEN_VALUE"));					
							}
							paramElement.addElement("DEFAULT_VALUE_USE_SQL_SCRIPT").addText(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT"));
							paramElement.addElement("SORT_TYPE").addText(paramItem.getString("SORT_TYPE"));
							paramElement.addElement("OPER").addText(paramItem.getString("OPER"));
							paramElement.addElement("BIND_YN").addText(paramItem.getString("BIND_YN"));
							paramElement.addElement("SEARCH_YN").addText(paramItem.getString("SEARCH_YN"));
							paramElement.addElement("EDIT_YN").addText(paramItem.getString("EDIT_YN"));
							/*dogfoot shlim 20210415*/
							if(paramItem.has("LINE_BREAK")){
								paramElement.addElement("LINE_BREAK").addText(paramItem.getString("LINE_BREAK"));
							}
							if(paramItem.has("INPUT_EDIT_YN")){
								paramElement.addElement("INPUT_EDIT_YN").addText(paramItem.getString("INPUT_EDIT_YN"));
							}
							paramElement.addElement("RANGE_YN").addText(paramItem.getString("RANGE_YN"));
							/*DOGFOOT cshan 20200113 - between 필터 저장시 오류 수정*/
							paramElement.addElement("RANGE_VALUE").addText(paramItem.get("RANGE_VALUE")+"");
							paramElement.addElement("DEFAULT_VALUE_MAINTAIN").addText(paramItem.getString("DEFAULT_VALUE_MAINTAIN"));
							paramElement.addElement("TYPE_CHANGE_YN").addText(paramItem.getString("TYPE_CHANGE_YN"));
						}
					}
				}
			}
		}
		
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(paramXml.getRootElement());
		String returnStr = sw.toString().substring(1);
		return returnStr;
	}
	
	public String sortParamXmltoDataSetXml(JSONObject paramObjects) throws IOException {

		Document paramXml = DocumentHelper.createDocument();

		Element paramRoot = paramXml.addElement("PARAM_ELEMENT");
		
		Iterator<String> paramKey = paramObjects.keys();
		
		while (paramKey.hasNext()) {
			String paramKeyName = paramKey.next().toString();
			if(paramObjects.get(paramKeyName) instanceof JSONObject){
				JSONObject paramItem = paramObjects.getJSONObject(paramKeyName);
				Element paramElement = paramRoot.addElement("PARAM");
				/* dogfoot WHATIF 분석 매개변수 저장 shlim 20201022 */
				if(paramItem.has("CALC_PARAM_YN")) {
					paramElement.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
					paramElement.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
					String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
					paramElement.addElement("DEFAULT_VALUE").addText(defaultVal);
					paramElement.addElement("SET_VALUE").addText(defaultVal);
					paramElement.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
//					paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
//					paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
					paramElement.addElement("SLIDER_POINT").addText(paramItem.get("SLIDER_POINT") + "");
					paramElement.addElement("SLIDER_MIN").addText(paramItem.get("SLIDER_MIN") + "");
					paramElement.addElement("SLIDER_MAX").addText(paramItem.get("SLIDER_MAX") + "");
					
					paramElement.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
					paramElement.addElement("CALC_PARAM_YN").addText(paramItem.getString("CALC_PARAM_YN"));
					
				}else {
					paramElement.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
					paramElement.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
					paramElement.addElement("DATA_TYPE").addText(paramItem.getString("DATA_TYPE"));
					paramElement.addElement("PARAM_TYPE").addText(paramItem.getString("PARAM_TYPE"));
					paramElement.addElement("DATASRC_TYPE").addText(paramItem.getString("DATASRC_TYPE"));
					paramElement.addElement("DATASRC").addText(paramItem.getString("DATASRC"));
					paramElement.addElement("CAPTION_VALUE_ITEM").addText(paramItem.getString("CAPTION_VALUE_ITEM"));
					paramElement.addElement("KEY_VALUE_ITEM").addText(paramItem.getString("KEY_VALUE_ITEM"));
					paramElement.addElement("SORT_VALUE_ITEM").addText(paramItem.getString("SORT_VALUE_ITEM"));
					String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
					
					if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
						String[] defalutBetween = paramItem.getString("HIDDEN_VALUE").split(",");
						String reultDefault = "";
	//					reultDefault += Base64.encode(defalutBetween[0].getBytes());
	//					reultDefault += ",";
	//					reultDefault += Base64.encode(defalutBetween[1].getBytes());
						reultDefault += new String(defalutBetween[0].getBytes());
						reultDefault += ",";
						reultDefault += new String(defalutBetween[1].getBytes());
						paramElement.addElement("DEFAULT_VALUE").addText(reultDefault);
					}
					else if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
						JSONArray defaultArr = paramItem.getJSONArray("DEFAULT_VALUE");
						defaultVal = defaultArr.get(0)+","+defaultArr.get(1);
						paramElement.addElement("DEFAULT_VALUE").addText(defaultVal);
					}
					else if(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
						String defaultSQLVal = paramItem.getString("HIDDEN_VALUE");
						paramElement.addElement("DEFAULT_VALUE").addText(Base64.encode(defaultSQLVal.getBytes()));
					}
					else {
						if(defaultVal.equals("_ALL_VALUE_")) {
							defaultVal = "[All]";
						}else {
							paramElement.addElement("DEFAULT_VALUE").addText(defaultVal);
						}
						
					}
					paramElement.addElement("CAPTION_FORMAT").addText(paramItem.getString("CAPTION_FORMAT"));
					paramElement.addElement("KEY_FORMAT").addText(paramItem.getString("KEY_FORMAT"));
					paramElement.addElement("CAND_DEFAULT_TYPE").addText(paramItem.getString("CAND_DEFAULT_TYPE"));
					/*dogfoot 캘린더 기간 설정 shlim 20210427*/
					if(paramItem.has("CAND_MAX_GAP")) {
						paramElement.addElement("CAND_MAX_GAP").addText(paramItem.get("CAND_MAX_GAP")+"");
					}
					paramElement.addElement("CAND_PERIOD_BASE").addText(paramItem.getString("CAND_PERIOD_BASE"));
					paramElement.addElement("CAND_PERIOD_VALUE").addText(paramItem.get("CAND_PERIOD_VALUE") + "");
					paramElement.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
					paramElement.addElement("MULTI_SEL").addText(paramItem.getString("MULTI_SEL"));
					/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
					if(paramItem.has("ORDERBY_KEY")) {
						paramElement.addElement("ORDERBY_KEY").addText(paramItem.getString("ORDERBY_KEY"));
					}
					paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
					paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
					paramElement.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
					paramElement.addElement("DS_ID").addText(paramItem.get("DS_ID") + "");
					paramElement.addElement("ALL_YN").addText(paramItem.getString("ALL_YN"));
					paramElement.addElement("WHERE_CLAUSE").addText(paramItem.getString("WHERE_CLAUSE"));
					//2020.01.17 mksong 타입 오류 수정 dogfoot
					if(paramItem.get("HIDDEN_VALUE") instanceof Integer) {
						paramElement.addElement("HIDDEN_VALUE").addText(paramItem.getInt("HIDDEN_VALUE")+"");	
					}else {
						paramElement.addElement("HIDDEN_VALUE").addText(paramItem.getString("HIDDEN_VALUE"));					
					}
					paramElement.addElement("DEFAULT_VALUE_USE_SQL_SCRIPT").addText(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT"));
					paramElement.addElement("SORT_TYPE").addText(paramItem.getString("SORT_TYPE"));
					paramElement.addElement("OPER").addText(paramItem.getString("OPER"));
					paramElement.addElement("BIND_YN").addText(paramItem.getString("BIND_YN"));
					paramElement.addElement("SEARCH_YN").addText(paramItem.getString("SEARCH_YN"));
					paramElement.addElement("EDIT_YN").addText(paramItem.getString("EDIT_YN"));
					/*dogfoot shlim 20210415*/
					if(paramItem.has("LINE_BREAK")){
						paramElement.addElement("LINE_BREAK").addText(paramItem.getString("LINE_BREAK"));
					}
					if(paramItem.has("INPUT_EDIT_YN")){
						paramElement.addElement("INPUT_EDIT_YN").addText(paramItem.getString("INPUT_EDIT_YN"));
					}
					paramElement.addElement("RANGE_YN").addText(paramItem.getString("RANGE_YN"));
					/*DOGFOOT cshan 20200113 - between 필터 저장시 오류 수정*/
					paramElement.addElement("RANGE_VALUE").addText(paramItem.get("RANGE_VALUE")+"");
					paramElement.addElement("DEFAULT_VALUE_MAINTAIN").addText(paramItem.getString("DEFAULT_VALUE_MAINTAIN"));
					paramElement.addElement("TYPE_CHANGE_YN").addText(paramItem.getString("TYPE_CHANGE_YN"));
				}
			}
		}
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(paramXml.getRootElement());
		String returnStr = sw.toString().substring(1);
		return returnStr;
	}
	
	public String sortSelectElement(JSONObject selObject) throws IOException {
		JSONArray selObjArray = toJsonArray(selObject, "SELECT_CLAUSE");
		Document selectXml = DocumentHelper.createDocument();
		
		Element selectRoot = selectXml.addElement("SEL_ELEMENT");
		for (int i = 0; i < selObjArray.length(); i++) {
			JSONObject eachSelObj = selObjArray.getJSONObject(i);
			Element SelectClause = selectRoot.addElement("SELECT_CLAUSE");
			SelectClause.addElement("UNI_NM").addText(eachSelObj.getString("UNI_NM"));
			SelectClause.addElement("CAPTION").addText(eachSelObj.getString("CAPTION"));
			SelectClause.addElement("DATA_TYPE").addText(eachSelObj.getString("DATA_TYPE"));
			SelectClause.addElement("TYPE").addText(eachSelObj.getString("TYPE"));
			SelectClause.addElement("ORDER").addText(eachSelObj.get("ORDER")+"");
		}
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(selectXml.getRootElement());
		String returnStr = sw.toString().substring(1);
		return returnStr;
	}
	
	public String sortWhereElement(JSONObject whereObject) throws IOException {
		JSONArray whereObjArray = toJsonArray(whereObject, "WHERE_CLAUSE");
		Document whereXml = DocumentHelper.createDocument();
		Element whereRoot = whereXml.addElement("WHERE_ELEMENT");
		for (int i = 0; i < whereObjArray.length(); i++) {
			JSONObject eachWhereObj = whereObjArray.getJSONObject(i);
			Element WhereClause = whereRoot.addElement("WHERE_CLAUSE");
			WhereClause.addElement("UNI_NM").addText(eachWhereObj.getString("UNI_NM"));
			WhereClause.addElement("CAPTION").addText(eachWhereObj.getString("CAPTION"));
			WhereClause.addElement("OPER").addText(eachWhereObj.getString("OPER"));
			WhereClause.addElement("VALUES").addText(eachWhereObj.getString("VALUES"));
			WhereClause.addElement("VALUES_CAPTION").addText(eachWhereObj.getString("VALUES_CAPTION"));
			WhereClause.addElement("DATA_BIND_YN").addText(eachWhereObj.get("DATA_BIND_YN")+"");
			WhereClause.addElement("AGG").addText(eachWhereObj.getString("AGG"));
			WhereClause.addElement("DATA_TYPE").addText(eachWhereObj.getString("DATA_TYPE"));
			WhereClause.addElement("PARAM_YN").addText(eachWhereObj.get("PARAM_YN")+"");
			WhereClause.addElement("PARAM_NM").addText(eachWhereObj.getString("PARAM_NM"));
			WhereClause.addElement("TYPE").addText(eachWhereObj.getString("TYPE"));
			WhereClause.addElement("ORDER").addText(eachWhereObj.get("ORDER")+"");
		}
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(whereXml.getRootElement());
		String returnStr = sw.toString().substring(1);
		return returnStr;
	}
	
	public String sortOrderElement(JSONObject orderObject) throws IOException {
		JSONArray orderObjArray = toJsonArray(orderObject, "ORDER_CLAUSE");
		Document orderXml = DocumentHelper.createDocument();
		
		Element orderRoot = orderXml.addElement("ORDER_ELEMENT");
		for (int i = 0; i < orderObjArray.length(); i++) {
			JSONObject eachOrderObj = orderObjArray.getJSONObject(i);
			Element orderClause = orderRoot.addElement("ORDER_CLAUSE");
			orderClause.addElement("UNI_NM").addText(eachOrderObj.getString("UNI_NM"));
			orderClause.addElement("CAPTION").addText(eachOrderObj.getString("CAPTION"));
			orderClause.addElement("SORT_TYPE").addText(eachOrderObj.getString("SORT_TYPE"));
			orderClause.addElement("TYPE").addText(eachOrderObj.getString("TYPE"));
			orderClause.addElement("ORDER").addText(eachOrderObj.get("ORDER")+"");
		}
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(orderXml.getRootElement());
		String returnStr = sw.toString().substring(1);
		return returnStr;
	}
	/**
	 * Return an array of JSON objects representing either LayoutGroup or LayoutItem, sorted by "Index" attribute ascending.
	 * @param layoutTree JSONObject with either LayoutGroup or LayoutItem attributes, or both.
	 * @return Sorted ArrayList of layout items, in ascending order.
	 */
	public List<JSONObject> getSortedLayoutObjects(JSONObject layoutTree) {
		List<JSONObject> layoutObjects = new ArrayList<JSONObject>();
		if (layoutTree.has("LayoutGroup")) {
			JSONArray layoutGroups = layoutTree.getJSONArray("LayoutGroup");
			for (int i = 0; i < layoutGroups.length(); i++) {
				JSONObject group = layoutGroups.getJSONObject(i);
				group.put("Type", "LayoutGroup");
				layoutObjects.add(group);
			}
		}
		if (layoutTree.has("LayoutItem")) {
			JSONArray layoutItems = layoutTree.getJSONArray("LayoutItem");
			for (int i = 0; i < layoutItems.length(); i++) {
				JSONObject item = layoutItems.getJSONObject(i);
				item.put("Type", "LayoutItem");
				layoutObjects.add(item);
			}
		}
		if (layoutTree.has("LayoutTabContainer")) {
			JSONArray layoutTabContainers = layoutTree.getJSONArray("LayoutTabContainer");
			for (int i = 0; i < layoutTabContainers.length(); i++) {
				JSONObject tabContainer = layoutTabContainers.getJSONObject(i);
				tabContainer.put("Type", "LayoutTabContainer");
				layoutObjects.add(tabContainer);
			}
		}
		if (layoutTree.has("LayoutTabPage")) {
			JSONArray layoutTabPages = layoutTree.getJSONArray("LayoutTabPage");
			for (int i = 0; i < layoutTabPages.length(); i++) {
				JSONObject tab = layoutTabPages.getJSONObject(i);
				tab.put("Type", "LayoutTabPage");
				layoutObjects.add(tab);
			}
		}
		Collections.sort(layoutObjects, new Comparator<JSONObject>() {
			private static final String KEY = "Index";
			
			@Override
			public int compare(JSONObject a, JSONObject b) {
				Integer aVal = null;
				Integer bVal = null;
				try {
					aVal = a.getInt(KEY);
					bVal = b.getInt(KEY);
				} catch (JSONException e) {
					e.printStackTrace();
				}
				return aVal.compareTo(bVal);
			}
		});
		
		return layoutObjects;
	}
	
	public void setLayoutTreeElement(Element element, JSONObject layoutTree) throws IOException {
		List<JSONObject> orderedLayoutObjects = getSortedLayoutObjects(layoutTree);
		for (JSONObject layoutObject : orderedLayoutObjects) {
			String type = layoutObject.getString("Type");
			if (type.equals("LayoutGroup")) {
				Element layoutGroupElement = element.addElement("LayoutGroup");
				if (layoutObject.has("Orientation")) {
					layoutGroupElement.addAttribute("Orientation", layoutObject.getString("Orientation"));
				}
				if (layoutObject.has("Weight")) {
					double weightNum = layoutObject.getDouble("Weight");
					String weightString = weightNum == 100.0 ? "100" : weightNum + "";
					layoutGroupElement.addAttribute("Weight", weightString);
				}
				setLayoutTreeElement(layoutGroupElement, layoutObject);
			}
			else if (type.equals("LayoutTabContainer")) {
				Element layoutTabContainerElement = element.addElement("LayoutTabContainer");
				if (layoutObject.has("DashboardItem")) {
					layoutTabContainerElement.addAttribute("DashboardItem", layoutObject.getString("DashboardItem"));
				}
				if (layoutObject.has("Orientation")) {
					layoutTabContainerElement.addAttribute("Orientation", layoutObject.getString("Orientation"));
				}
				/*dogfoot 통계 분석 저장 shlim 20201102*/
				if (layoutObject.has("LayoutType")) {
					layoutTabContainerElement.addAttribute("LayoutType", layoutObject.getString("LayoutType"));
				}
				if (layoutObject.has("Weight")) {
					double weightNum = layoutObject.getDouble("Weight");
					String weightString = weightNum == 100.0 ? "100" : weightNum + "";
					layoutTabContainerElement.addAttribute("Weight", weightString);
				}
				setLayoutTreeElement(layoutTabContainerElement, layoutObject);
			}
			else if (type.equals("LayoutTabPage")) {
				Element layoutTabPageElement = element.addElement("LayoutTabPage");
				if (layoutObject.has("DashboardItem")) {
					layoutTabPageElement.addAttribute("DashboardItem", layoutObject.getString("DashboardItem"));
				}
				if (layoutObject.has("Orientation")) {
					layoutTabPageElement.addAttribute("Orientation", layoutObject.getString("Orientation"));
				}
				if (layoutObject.has("Weight")) {
					double weightNum = layoutObject.getDouble("Weight");
					String weightString = weightNum == 100.0 ? "100" : weightNum + "";
					layoutTabPageElement.addAttribute("Weight", weightString);
				}
				setLayoutTreeElement(layoutTabPageElement, layoutObject);
			}
			else if (type.equals("LayoutItem")) {
				Element layoutItemElement = element.addElement("LayoutItem");
				if (layoutObject.has("DashboardItem")) {
					layoutItemElement.addAttribute("DashboardItem", layoutObject.getString("DashboardItem"));
				}
				if (layoutObject.has("Weight")) {
					double weightNum = layoutObject.getDouble("Weight");
					String weightString = weightNum == 100.0 ? "100" : weightNum + "";
					layoutItemElement.addAttribute("Weight", weightString);
				}
			}
		}
	}
	
	public String UploadTableInfo(String fileName,String fileExt,String tableCaption, String Owner,net.sf.json.JSONArray colArr) throws IOException {
		Document TABLEIMPORTXML = DocumentHelper.createDocument();
		Element IMPORT_XML = TABLEIMPORTXML.addElement("IMPORT_XML");
		Element IMPORT_INFO_ELEMENT = IMPORT_XML.addElement("IMPORT_INFO_ELEMENT");
		IMPORT_INFO_ELEMENT.addElement("FILE_NM").addText(fileName);
		IMPORT_INFO_ELEMENT.addElement("FILE_EXT").addText(fileExt);
		IMPORT_INFO_ELEMENT.addElement("FILE_DELIMITED").addText("Delimited(,)");
		IMPORT_INFO_ELEMENT.addElement("FILE_ENCODING").addText("ANSI");
		IMPORT_INFO_ELEMENT.addElement("FILE_FIRSTROW_HD").addText("True");
		IMPORT_INFO_ELEMENT.addElement("IMPORT_TBL_NM").addText("");
		IMPORT_INFO_ELEMENT.addElement("TBL_COMMENT").addText(tableCaption);
		IMPORT_INFO_ELEMENT.addElement("OWNER").addText(Owner);
		IMPORT_INFO_ELEMENT.addElement("DATA_CLEAR_ADD").addText("N");
		Element COL_ELEMENT = IMPORT_XML.addElement("COL_ELEMENT");
		for(int i=0;i<colArr.size();i++) {
			net.sf.json.JSONObject obj = colArr.getJSONObject(i);
			Element COL = COL_ELEMENT.addElement("COL");
			COL.addElement("COL_NM").addText(obj.getString("colPhysicalNm"));
			COL.addElement("COL_CAPTION").addText(obj.getString("colNm"));
			COL.addElement("COL_DATA_TYPE").addText(obj.getString("colType"));
			COL.addElement("COL_LENGTH").addText(obj.getString("colSize"));
		}
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
		outputFormat.setIndent(true);
		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(TABLEIMPORTXML.getRootElement());
		String returnStr = sw.toString().substring(1);
		return returnStr;
	}

	public String sortDataSetXMLForDataSetDS(JSONObject obj, JSONObject paramFromParameterInformation, boolean isMultipleDataSource) throws IOException {
		// TODO Auto-generated method stub
		/*
		 * 저장 오류가 나서 다시 원복함
		JSONArray selObjArray = (JSONArray) toJsonArray(obj, "SelArea").get(0);
		JSONArray CondObjArray = (JSONArray)toJsonArray(obj, "CondArea");//from $('#ConditionArea').dxDataGrid
		
		JSONArray relObjArray = (JSONArray) toJsonArray(obj, "RelArea").get(0);
		*/
		JSONArray selObjArray = toJsonArray(obj, "SelArea");
		JSONArray CondObjArray = toJsonArray(obj, "CondArea");//from $('#ConditionArea').dxDataGrid
		JSONArray relObjArray = toJsonArray(obj, "RelArea");
		
		JSONArray etcObjArray = toJsonArray(obj, "EtcArea");
		
		Document DATASETXML = DocumentHelper.createDocument();
		Element DATA_SET = DATASETXML.addElement("DATA_SET");
		Element SEL_ELEMENET = DATA_SET.addElement("SEL_ELEMENT");
		for(int i=0;i<selObjArray.length();i++) {
			JSONObject selJsonObject = selObjArray.getJSONObject(i);
			Element SELECT_CLAUSE = SEL_ELEMENET.addElement("SELECT_CLAUSE");
			SELECT_CLAUSE.addElement("AGG").addText(selJsonObject.getString("AGG"));
			SELECT_CLAUSE.addElement("COL_NM").addText(selJsonObject.getString("COL_NM"));
			SELECT_CLAUSE.addElement("STRATIFIED_YN").addText("False");
			SELECT_CLAUSE.addElement("COL_CAPTION").addText(selJsonObject.getString("COL_CAPTION"));
			SELECT_CLAUSE.addElement("DATA_TYPE").addText(selJsonObject.getString("DATA_TYPE"));
			SELECT_CLAUSE.addElement("TBL_NM").addText(selJsonObject.getString("TBL_NM"));
			SELECT_CLAUSE.addElement("TBL_CAPTION").addText(selJsonObject.getString("TBL_NM"));
			SELECT_CLAUSE.addElement("TYPE").addText(selJsonObject.getString("TYPE").toUpperCase());
			SELECT_CLAUSE.addElement("COL_EXPRESS").addText(selJsonObject.getString("COL_EXPRESS"));
			SELECT_CLAUSE.addElement("ORDER").addText((i+1)+"");
			SELECT_CLAUSE.addElement("DATASET_SRC").addText(selJsonObject.get("DATASET_SRC").toString());
		}
		Element WHERE_ELEMENT = DATA_SET.addElement("WHERE_ELEMENT");
		for(int i=0;i<CondObjArray.length();i++) {
			JSONObject whereJsonObject = CondObjArray.getJSONObject(i);
			Element WHERE_CLAUSE = WHERE_ELEMENT.addElement("WHERE_CLAUSE");
			WHERE_CLAUSE.addElement("COND_ID").addText(whereJsonObject.getString("COND_ID"));
			WHERE_CLAUSE.addElement("COL_NM").addText(whereJsonObject.getString("COL_NM"));
			WHERE_CLAUSE.addElement("COL_CAPTION").addText(whereJsonObject.getString("COL_CAPTION"));
			WHERE_CLAUSE.addElement("TBL_CAPTION").addText(whereJsonObject.getString("TBL_NM"));
			WHERE_CLAUSE.addElement("OPER").addText(whereJsonObject.getString("OPER"));
			WHERE_CLAUSE.addElement("VALUES").addText(whereJsonObject.getString("VALUES"));
			WHERE_CLAUSE.addElement("VALUES_CAPTION").addText(whereJsonObject.getString("VALUES_CAPTION"));
			WHERE_CLAUSE.addElement("DATA_BIND_YN").addText((whereJsonObject.get("DATA_BIND_YN")+"").equalsIgnoreCase("true")?"True":"False");
			WHERE_CLAUSE.addElement("AGG").addText(whereJsonObject.getString("AGG"));
			WHERE_CLAUSE.addElement("TBL_NM").addText(whereJsonObject.getString("TBL_NM"));
			WHERE_CLAUSE.addElement("DATA_TYPE").addText(whereJsonObject.getString("DATA_TYPE"));
			WHERE_CLAUSE.addElement("PARAM_YN").addText((whereJsonObject.get("PARAM_YN")+"").equalsIgnoreCase("true")?"True":"False");
			WHERE_CLAUSE.addElement("PARAM_NM").addText(whereJsonObject.getString("PARAM_NM"));
			WHERE_CLAUSE.addElement("TYPE").addText(whereJsonObject.getString("TYPE"));
			WHERE_CLAUSE.addElement("COL_EXPRESS").addText(whereJsonObject.getString("COL_EXPRESS").toUpperCase());
			WHERE_CLAUSE.addElement("ORDER").addText((i+1)+"");
			WHERE_CLAUSE.addElement("DATASET_SRC").addText(whereJsonObject.get("DATASET_SRC").toString());
		}
		Element ORDER_ELEMENT = DATA_SET.addElement("ORDER_ELEMENT");
//		for(int i=0;i<paramObjArray.length();i++) {
//			
//		}
		Element REL_ELEMENT = DATA_SET.addElement("REL_ELEMENT");
		for(int i=0; i<relObjArray.length();i++) {
			JSONObject relJsonObject = relObjArray.getJSONObject(i);
			Element JOIN_CLAUSE = REL_ELEMENT.addElement("JOIN_CLAUSE");
			JOIN_CLAUSE.addElement("CONST_NM").addText(relJsonObject.getString("CONST_NM"));
			JOIN_CLAUSE.addElement("FK_TBL_NM").addText(relJsonObject.getString("FK_TBL_NM"));
			JOIN_CLAUSE.addElement("FK_COL_NM").addText(relJsonObject.getString("FK_COL_NM"));
			JOIN_CLAUSE.addElement("PK_TBL_NM").addText(relJsonObject.getString("PK_TBL_NM"));
			JOIN_CLAUSE.addElement("PK_COL_NM").addText(relJsonObject.getString("PK_COL_NM"));
			JOIN_CLAUSE.addElement("JOIN_TYPE").addText(relJsonObject.getString("JOIN_TYPE"));
			JOIN_CLAUSE.addElement("FK_DATASET_SRC").addText(relJsonObject.get("FK_DATASET_SRC").toString());
			JOIN_CLAUSE.addElement("PK_DATASET_SRC").addText(relJsonObject.get("PK_DATASET_SRC").toString());
		}
		
		
		Element PARAM_ELEMENT = DATA_SET.addElement("PARAM_ELEMENT");
		if(isMultipleDataSource == false) {
			JSONObject paramObject = obj.getJSONObject("ParamArea");//from parameterInformation
			Iterator<String> paramKey = paramObject.keys();
			
			while (paramKey.hasNext()) {
				String paramKeyName = paramKey.next().toString();
				if(paramObject.get(paramKeyName) instanceof JSONObject){
					JSONObject paramItem = paramObject.getJSONObject(paramKeyName);
					Element PARAM = PARAM_ELEMENT.addElement("PARAM");
					/* dogfoot WHATIF 분석 매개변수 저장 shlim 20201022 */
					if(paramItem.has("CALC_PARAM_YN")) {
						PARAM.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
						PARAM.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
						String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
						PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
						PARAM.addElement("SET_VALUE").addText(defaultVal);
						PARAM.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
//						paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
//						paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
						PARAM.addElement("SLIDER_POINT").addText(paramItem.get("SLIDER_POINT") + "");
						PARAM.addElement("SLIDER_MIN").addText(paramItem.get("SLIDER_MIN") + "");
						PARAM.addElement("SLIDER_MAX").addText(paramItem.get("SLIDER_MAX") + "");
						
						PARAM.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
						PARAM.addElement("CALC_PARAM_YN").addText(paramItem.getString("CALC_PARAM_YN"));
						
					}else {
						PARAM.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
						PARAM.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
						PARAM.addElement("DATA_TYPE").addText(paramItem.getString("DATA_TYPE"));
						PARAM.addElement("PARAM_TYPE").addText(paramItem.getString("PARAM_TYPE"));
						PARAM.addElement("DATASRC_TYPE").addText(paramItem.getString("DATASRC_TYPE"));
						PARAM.addElement("DATASRC").addText(paramItem.getString("DATASRC"));
						PARAM.addElement("CAPTION_VALUE_ITEM").addText(paramItem.getString("CAPTION_VALUE_ITEM"));
						PARAM.addElement("KEY_VALUE_ITEM").addText(paramItem.getString("KEY_VALUE_ITEM"));
						PARAM.addElement("SORT_VALUE_ITEM").addText(paramItem.getString("SORT_VALUE_ITEM"));
						String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
						
						if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
							String[] defalutBetween = paramItem.getString("HIDDEN_VALUE").split(",");
							String reultDefault = "";
							/* DOGFOOT mksong BASE64 오류 수정 20200116 */
	//						reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[0].getBytes()));
	//						reultDefault += ",";
	//						reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[1].getBytes()));
							
							reultDefault += new String(defalutBetween[0].getBytes());
							reultDefault += ",";
							reultDefault += new String(defalutBetween[1].getBytes());
							PARAM.addElement("DEFAULT_VALUE").addText(reultDefault);
						}
						else if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
							JSONArray defaultArr = paramItem.getJSONArray("DEFAULT_VALUE");
							defaultVal = defaultArr.get(0)+","+defaultArr.get(1);
							PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
						}
						else if(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
							String defaultSQLVal = paramItem.getString("HIDDEN_VALUE");
							/* DOGFOOT mksong BASE64 오류 수정 20200116 */
							PARAM.addElement("DEFAULT_VALUE").addText(new String(java.util.Base64.getEncoder().encode(defaultSQLVal.getBytes())));
						}
						else {
							if(defaultVal.equals("_ALL_VALUE_")) {
								defaultVal = "[All]";
							}else {
								PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
							}
							
						}
						PARAM.addElement("CAPTION_FORMAT").addText(paramItem.getString("CAPTION_FORMAT"));
						PARAM.addElement("KEY_FORMAT").addText(paramItem.getString("KEY_FORMAT"));
						PARAM.addElement("CAND_DEFAULT_TYPE").addText(paramItem.getString("CAND_DEFAULT_TYPE"));
						/*dogfoot 캘린더 기간 설정 shlim 20210427*/
						if(paramItem.has("CAND_MAX_GAP")) {
							PARAM.addElement("CAND_MAX_GAP").addText(paramItem.get("CAND_MAX_GAP")+"");
						}
						PARAM.addElement("CAND_PERIOD_BASE").addText(paramItem.getString("CAND_PERIOD_BASE"));
						PARAM.addElement("CAND_PERIOD_VALUE").addText(paramItem.get("CAND_PERIOD_VALUE") + "");
						PARAM.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
						PARAM.addElement("MULTI_SEL").addText(paramItem.getString("MULTI_SEL"));
						/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
						if(paramItem.has("ORDERBY_KEY")) {
							PARAM.addElement("ORDERBY_KEY").addText(paramItem.getString("ORDERBY_KEY"));
						}
						PARAM.addElement("ORDER").addText(paramItem.get("ORDER") + "");
						PARAM.addElement("DS_ID").addText(paramItem.get("DS_ID") + "");
						PARAM.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
						PARAM.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
						PARAM.addElement("ALL_YN").addText(paramItem.getString("ALL_YN"));
						PARAM.addElement("WHERE_CLAUSE").addText(paramItem.getString("WHERE_CLAUSE"));
						PARAM.addElement("HIDDEN_VALUE").addText(paramItem.getString("HIDDEN_VALUE"));
						PARAM.addElement("DEFAULT_VALUE_USE_SQL_SCRIPT").addText(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT"));
						PARAM.addElement("SORT_TYPE").addText(paramItem.getString("SORT_TYPE"));
						PARAM.addElement("OPER").addText(paramItem.getString("OPER"));
						PARAM.addElement("BIND_YN").addText(paramItem.getString("BIND_YN"));
						PARAM.addElement("SEARCH_YN").addText(paramItem.getString("SEARCH_YN"));
						PARAM.addElement("EDIT_YN").addText(paramItem.getString("EDIT_YN"));
						/*dogfoot shlim 20210415*/
						if(paramItem.has("LINE_BREAK")){
							PARAM.addElement("LINE_BREAK").addText(paramItem.getString("LINE_BREAK"));
						}
						if(paramItem.has("INPUT_EDIT_YN")){
							PARAM.addElement("INPUT_EDIT_YN").addText(paramItem.getString("INPUT_EDIT_YN"));
						}
						PARAM.addElement("RANGE_YN").addText(paramItem.getString("RANGE_YN"));
						/*DOGFOOT cshan 20200113 - between 필터 저장시 오류 수정*/
						PARAM.addElement("RANGE_VALUE").addText(paramItem.get("RANGE_VALUE")+"");
						PARAM.addElement("DEFAULT_VALUE_MAINTAIN").addText(paramItem.getString("DEFAULT_VALUE_MAINTAIN"));
						PARAM.addElement("TYPE_CHANGE_YN").addText(paramItem.getString("TYPE_CHANGE_YN"));
						PARAM.addElement("DATASET_SRC").addText(paramItem.get("DATASET_SRC").toString());
					}
				}
			}
		}else {
			JSONArray paramArray = new JSONArray();
			Object paramObject = obj.get("ParamArea");
			if(paramObject instanceof JSONObject) {
				paramArray = toJsonArray((JSONObject)paramObject, "PARAM");
			}else {
				paramArray = obj.getJSONArray("ParamArea");
			}
			
			if(paramArray != null) {
				
				for(int idx= 0; idx <paramArray.length();idx++) {
					Element PARAM = PARAM_ELEMENT.addElement("PARAM");
					JSONObject paramItem = paramArray.getJSONObject(idx);
					/* dogfoot WHATIF 분석 매개변수 저장 shlim 20201022 */
					if(paramItem.has("CALC_PARAM_YN")) {
						PARAM.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
						PARAM.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
						String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
						PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
						PARAM.addElement("SET_VALUE").addText(defaultVal);
						PARAM.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
//						paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
//						paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
						PARAM.addElement("SLIDER_POINT").addText(paramItem.get("SLIDER_POINT") + "");
						PARAM.addElement("SLIDER_MIN").addText(paramItem.get("SLIDER_MIN") + "");
						PARAM.addElement("SLIDER_MAX").addText(paramItem.get("SLIDER_MAX") + "");
						
						PARAM.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
						PARAM.addElement("CALC_PARAM_YN").addText(paramItem.getString("CALC_PARAM_YN"));
						
					}else {
						PARAM.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
						PARAM.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
						PARAM.addElement("DATA_TYPE").addText(paramItem.getString("DATA_TYPE"));
						PARAM.addElement("PARAM_TYPE").addText(paramItem.getString("PARAM_TYPE"));
						PARAM.addElement("DATASRC_TYPE").addText(paramItem.getString("DATASRC_TYPE"));
						PARAM.addElement("DATASRC").addText(paramItem.getString("DATASRC"));
						PARAM.addElement("CAPTION_VALUE_ITEM").addText(paramItem.getString("CAPTION_VALUE_ITEM"));
						PARAM.addElement("KEY_VALUE_ITEM").addText(paramItem.getString("KEY_VALUE_ITEM"));
						PARAM.addElement("SORT_VALUE_ITEM").addText(paramItem.getString("SORT_VALUE_ITEM"));
						String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
						
						if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
							String[] defalutBetween = paramItem.getString("HIDDEN_VALUE").split(",");
							String reultDefault = "";
							/* DOGFOOT mksong BASE64 오류 수정 20200116 */
//							reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[0].getBytes()));
//							reultDefault += ",";
//							reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[1].getBytes()));
							reultDefault += new String(defalutBetween[0].getBytes());
							reultDefault += ",";
							reultDefault += new String(defalutBetween[1].getBytes());
							PARAM.addElement("DEFAULT_VALUE").addText(reultDefault);
						}
						else if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
//							String[] defaultBetween = (paramItem.get("DEFAULT_VALUE")+"").split(",");
							JSONArray defaultArr = paramItem.getJSONArray("DEFAULT_VALUE");
							defaultVal = defaultArr.get(0)+","+defaultArr.get(1);
							PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
						}
						else if(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
							String defaultSQLVal = paramItem.getString("HIDDEN_VALUE");
							/* DOGFOOT mksong BASE64 오류 수정 20200116 */
							PARAM.addElement("DEFAULT_VALUE").addText(new String(java.util.Base64.getEncoder().encode(defaultSQLVal.getBytes())));
						}
						else {
							if(defaultVal.equals("_ALL_VALUE_")) {
								defaultVal = "[All]";
							}else {
								PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
							}
							
						}
						PARAM.addElement("CAPTION_FORMAT").addText(paramItem.getString("CAPTION_FORMAT"));
						PARAM.addElement("KEY_FORMAT").addText(paramItem.getString("KEY_FORMAT"));
						PARAM.addElement("CAND_DEFAULT_TYPE").addText(paramItem.getString("CAND_DEFAULT_TYPE"));
						/*dogfoot 캘린더 기간 설정 shlim 20210427*/
						if(paramItem.has("CAND_MAX_GAP")) {
							PARAM.addElement("CAND_MAX_GAP").addText(paramItem.get("CAND_MAX_GAP")+"");
						}
						PARAM.addElement("CAND_PERIOD_BASE").addText(paramItem.getString("CAND_PERIOD_BASE"));
						PARAM.addElement("CAND_PERIOD_VALUE").addText(paramItem.get("CAND_PERIOD_VALUE") + "");
						PARAM.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
						PARAM.addElement("MULTI_SEL").addText(paramItem.getString("MULTI_SEL"));
						/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
						if(paramItem.has("ORDERBY_KEY")) {
							PARAM.addElement("ORDERBY_KEY").addText(paramItem.getString("ORDERBY_KEY"));
						}
						PARAM.addElement("ORDER").addText(paramItem.get("ORDER") + "");
						PARAM.addElement("DS_ID").addText(paramItem.get("DS_ID") + "");
						PARAM.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
						PARAM.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
						PARAM.addElement("ALL_YN").addText(paramItem.getString("ALL_YN"));
						PARAM.addElement("WHERE_CLAUSE").addText(paramItem.getString("WHERE_CLAUSE"));
						PARAM.addElement("HIDDEN_VALUE").addText(paramItem.getString("HIDDEN_VALUE"));
						PARAM.addElement("DEFAULT_VALUE_USE_SQL_SCRIPT").addText(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT"));
						PARAM.addElement("SORT_TYPE").addText(paramItem.getString("SORT_TYPE"));
						PARAM.addElement("OPER").addText(paramItem.getString("OPER"));
						PARAM.addElement("BIND_YN").addText(paramItem.getString("BIND_YN"));
						PARAM.addElement("SEARCH_YN").addText(paramItem.getString("SEARCH_YN"));
						PARAM.addElement("EDIT_YN").addText(paramItem.getString("EDIT_YN"));
						/*dogfoot shlim 20210415*/
						if(paramItem.has("LINE_BREAK")){
							PARAM.addElement("LINE_BREAK").addText(paramItem.getString("LINE_BREAK"));
						}
						if(paramItem.has("INPUT_EDIT_YN")){
							PARAM.addElement("INPUT_EDIT_YN").addText(paramItem.getString("INPUT_EDIT_YN"));
						}
						PARAM.addElement("RANGE_YN").addText(paramItem.getString("RANGE_YN"));
						/*DOGFOOT cshan 20200113 - between 필터 저장시 오류 수정*/
						PARAM.addElement("RANGE_VALUE").addText(paramItem.get("RANGE_VALUE")+"");
						PARAM.addElement("DEFAULT_VALUE_MAINTAIN").addText(paramItem.getString("DEFAULT_VALUE_MAINTAIN"));
						PARAM.addElement("TYPE_CHANGE_YN").addText(paramItem.getString("TYPE_CHANGE_YN"));
						PARAM.addElement("DATASET_SRC").addText(paramItem.get("DATASET_SRC").toString());
					}
					
				}
			}
			
		}
		Element DATASRC_REL_ELEMENT = DATA_SET.addElement("DATASRC_REL_ELEMENT");
		
		Element ETC_ELEMENT = DATA_SET.addElement("ETC_ELEMENT");
		for(int i=0;i<etcObjArray.length();i++) {
			JSONObject etcJsonObject = etcObjArray.getJSONObject(i);
			ETC_ELEMENT.addElement("STRATIFIED").addText(etcJsonObject.get("STRATIFIED")+"");
			ETC_ELEMENT.addElement("DISTINCT").addText(etcJsonObject.get("DISTINCT")+"");
			ETC_ELEMENT.addElement("SEL_COND").addText(etcJsonObject.get("SEL_COND")+"");
			ETC_ELEMENT.addElement("SEL_NUMERIC").addText(etcJsonObject.get("SEL_NUMERIC")+"");
			ETC_ELEMENT.addElement("CHANGE_COND").addText(etcJsonObject.get("CHANGE_COND")+"");
		}
		
		
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
//		outputFormat.setIndent(true);
//		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
//		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(DATASETXML.getRootElement());
		String returnStr = sw.toString();
		return returnStr;
	}

	public String sortDataSetXMLForDataSetSingle(JSONObject obj, JSONObject jsonObject, boolean b) throws IOException {
		// TODO Auto-generated method stub
		JSONArray colObjArray = toJsonArray(obj, "SelArea");
		JSONArray etcObjArray = toJsonArray(obj, "EtcArea");
		
		Document DATASETXML = DocumentHelper.createDocument();
		Element DATA_SET = DATASETXML.addElement("DATA_SET");
		Element TBL_ELEMENT = DATA_SET.addElement("TBL_ELEMENT");
		
		String TBL_NM = "";
		if(colObjArray.length() !=0) {
			JSONObject tblObj = colObjArray.getJSONObject(0);
			TBL_NM = tblObj.getString("TBL_NM");
			TBL_ELEMENT.addText(TBL_NM);
		}
		
		Element COL_ELEMENT = DATA_SET.addElement("COL_ELEMENT");
		
		for(int i=0;i<colObjArray.length();i++) {
			JSONObject colJsonObject = colObjArray.getJSONObject(i);
			Element COLUMN = COL_ELEMENT.addElement("COLUMN");
			COLUMN.addElement("TBL_NM").addText(TBL_NM);
			COLUMN.addElement("COL_NM").addText(colJsonObject.getString("COL_NM"));
			COLUMN.addElement("STRATIFIED_YN").addText("False");
			COLUMN.addElement("COL_CAPTION").addText(colJsonObject.getString("COL_CAPTION"));
			/* DOGFOOT ktkang 단일테이블 오류 수정  20201012 */
			COLUMN.addElement("CAPTION").addText(colJsonObject.getString("COL_CAPTION"));
			COLUMN.addElement("DATA_TYPE").addText(colJsonObject.getString("DATA_TYPE"));
			COLUMN.addElement("TYPE").addText(colJsonObject.getString("TYPE").toUpperCase());
//			COLUMN.addElement("ORDER").addText((i+1)+"");
			if(colJsonObject.has("COL_ID")) {
				COLUMN.addElement("ORDER").addText(colJsonObject.get("COL_ID")+"");
			}else {
				COLUMN.addElement("ORDER").addText(colJsonObject.get("ORDER")+"");
			}
			
			if(Boolean.parseBoolean((colJsonObject.get("VISIBLE")+"")) == true) {
				COLUMN.addElement("VISIBLE").addText("True");
			}else {
				COLUMN.addElement("VISIBLE").addText("False");
			}
			COLUMN.addElement("AGG").addText(colJsonObject.getString("AGG"));
		}
		
		Element ETC_ELEMENT = DATA_SET.addElement("ETC_ELEMENT");
		for(int i=0;i<etcObjArray.length();i++) {
			JSONObject etcJsonObject = etcObjArray.getJSONObject(i);
			ETC_ELEMENT.addElement("STRATIFIED").addText(etcJsonObject.get("STRATIFIED")+"");
			ETC_ELEMENT.addElement("DISTINCT").addText(etcJsonObject.get("DISTINCT")+"");
			ETC_ELEMENT.addElement("SEL_COND").addText(etcJsonObject.get("SEL_COND")+"");
			ETC_ELEMENT.addElement("SEL_NUMERIC").addText(etcJsonObject.get("SEL_NUMERIC")+"");
			ETC_ELEMENT.addElement("CHANGE_COND").addText(etcJsonObject.get("CHANGE_COND")+"");
		}
		
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
//		outputFormat.setIndent(true);
//		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
//		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(DATASETXML.getRootElement());
		String returnStr = sw.toString();
		return returnStr;
	}

	public String sortDataSetXMLForDataSetCUBE(JSONObject obj, JSONObject jsonObject, boolean isMultipleDataSource, Map<String,List<CubeTableVO>> cubeTableInfo) throws IOException {
		// TODO Auto-generated method stub
		JSONArray selObjArray = toJsonArray(obj, "SelArea");
		JSONArray CondObjArray = toJsonArray(obj, "CondArea");//from $('#ConditionArea').dxDataGrid
		JSONArray orderObjArray = toJsonArray(obj, "orderArea");
		logger.debug(obj.toString());
		logger.debug(CondObjArray.toString());
			
		List<CubeTableVO> dimCubeTable = cubeTableInfo.get("dimensions");
		List<CubeTableVO> meaCubeTable = cubeTableInfo.get("measures");
		Document DATASETXML = DocumentHelper.createDocument();
		Element DATA_SET = DATASETXML.addElement("DATA_SET");
		Element SEL_ELEMENET = DATA_SET.addElement("SEL_ELEMENT");
		for(int i=0;i<selObjArray.length();i++) {
			JSONObject selJsonObject = selObjArray.getJSONObject(i);
			Element SELECT_CLAUSE = SEL_ELEMENET.addElement("SELECT_CLAUSE");
			if(selJsonObject.getString("TYPE").toUpperCase().equalsIgnoreCase("DIM")) {
				for(CubeTableVO dimVo : dimCubeTable) {
					List<CubeTableColumnVO> dimColumns = dimVo.getColumns();
					for(CubeTableColumnVO dimColVo : dimColumns) {
						if(dimColVo.getUniqueName().equals(selJsonObject.getString("UNI_NM"))) {
							SELECT_CLAUSE.addElement("AGG").addText(nullCheck(dimColVo.getExpression()));
							SELECT_CLAUSE.addElement("COL_NM").addText(nullCheck(dimColVo.getPhysicalColumnName()));
							SELECT_CLAUSE.addElement("STRATIFIED_YN").addText("False");
							SELECT_CLAUSE.addElement("COL_CAPTION").addText(nullCheck(dimColVo.getCaptionName()));
							SELECT_CLAUSE.addElement("CAPTION").addText(nullCheck(dimColVo.getCaptionName()));
							SELECT_CLAUSE.addElement("DATA_TYPE").addText(nullCheck(dimColVo.getDataType()));
							SELECT_CLAUSE.addElement("TBL_NM").addText(nullCheck(dimColVo.getTableName()));
							SELECT_CLAUSE.addElement("TBL_CAPTION").addText(nullCheck(dimColVo.getPhysicalTableName()));
							SELECT_CLAUSE.addElement("TYPE").addText("DIM");
							SELECT_CLAUSE.addElement("COL_EXPRESS").addText(nullCheck(dimColVo.getExpression()));
							SELECT_CLAUSE.addElement("physicalTableName").addText(nullCheck(dimColVo.getPhysicalTableName()));
							SELECT_CLAUSE.addElement("tableName").addText(nullCheck(dimColVo.getTableName()));
							SELECT_CLAUSE.addElement("UNI_NM").addText(nullCheck(dimColVo.getUniqueName()));
							SELECT_CLAUSE.addElement("ORDER").addText((i+1)+"");
 	 						break;
						}
					}
				}
			}else {
				for(CubeTableVO meaVo : meaCubeTable) {
					List<CubeTableColumnVO> meaColumns = meaVo.getColumns();
					for(CubeTableColumnVO meaColVo : meaColumns) {
						if(meaColVo.getUniqueName().equals(selJsonObject.getString("UNI_NM"))) {
							SELECT_CLAUSE.addElement("AGG").addText(meaColVo.getExpression());
							SELECT_CLAUSE.addElement("COL_NM").addText(meaColVo.getLogicalColumnName());
							SELECT_CLAUSE.addElement("STRATIFIED_YN").addText("False");
							SELECT_CLAUSE.addElement("COL_CAPTION").addText(meaColVo.getCaptionName());
							SELECT_CLAUSE.addElement("CAPTION").addText(meaColVo.getCaptionName());
							SELECT_CLAUSE.addElement("DATA_TYPE").addText(meaColVo.getDataType());
							SELECT_CLAUSE.addElement("TBL_NM").addText(meaColVo.getTableName());
							SELECT_CLAUSE.addElement("TBL_CAPTION").addText(meaColVo.getLogicalTableName());
							SELECT_CLAUSE.addElement("TYPE").addText("MEA");
							SELECT_CLAUSE.addElement("COL_EXPRESS").addText(meaColVo.getExpression());
							SELECT_CLAUSE.addElement("physicalTableName").addText(meaColVo.getLogicalColumnName());
							SELECT_CLAUSE.addElement("tableName").addText(meaColVo.getTableName());
							SELECT_CLAUSE.addElement("UNI_NM").addText(meaColVo.getUniqueName());
							SELECT_CLAUSE.addElement("ORDER").addText((i+1)+"");
							break;
						}
					}
				}
			}
			
//			SELECT_CLAUSE.addElement("AGG").addText(selJsonObject.getString("AGG"));
//			SELECT_CLAUSE.addElement("COL_NM").addText(selJsonObject.getString("COL_NM"));
//			SELECT_CLAUSE.addElement("STRATIFIED_YN").addText("False");
//			SELECT_CLAUSE.addElement("COL_CAPTION").addText(selJsonObject.getString("COL_CAPTION"));
//			SELECT_CLAUSE.addElement("CAPTION").addText(selJsonObject.getString("CAPTION"));
//			SELECT_CLAUSE.addElement("DATA_TYPE").addText(selJsonObject.getString("DATA_TYPE"));
//			SELECT_CLAUSE.addElement("TBL_NM").addText(selJsonObject.getString("TBL_NM"));
//			SELECT_CLAUSE.addElement("TBL_CAPTION").addText(selJsonObject.getString("TBL_NM"));
//			SELECT_CLAUSE.addElement("TYPE").addText(selJsonObject.getString("TYPE").toUpperCase());
//			SELECT_CLAUSE.addElement("COL_EXPRESS").addText(selJsonObject.getString("COL_EXPRESS"));
//			SELECT_CLAUSE.addElement("physicalTableName").addText(selJsonObject.getString("physicalTableName"));
//			SELECT_CLAUSE.addElement("tableName").addText(selJsonObject.getString("tableName"));
//			SELECT_CLAUSE.addElement("UNI_NM").addText(selJsonObject.getString("UNI_NM"));
//			SELECT_CLAUSE.addElement("ORDER").addText((i+1)+"");
		}
		Element WHERE_ELEMENT = DATA_SET.addElement("WHERE_ELEMENT");
		for(int i=0;i<CondObjArray.length();i++) {
			JSONObject whereJsonObject = CondObjArray.getJSONObject(i);
			Element WHERE_CLAUSE = WHERE_ELEMENT.addElement("WHERE_CLAUSE");
			if(whereJsonObject.has("whereUNI_NM")) {
				WHERE_CLAUSE.addElement("UNI_NM").addText(whereJsonObject.getString("whereUNI_NM"));
			}else {
				WHERE_CLAUSE.addElement("UNI_NM").addText("@"+whereJsonObject.getString("PARAM_CAPTION"));
			}
			WHERE_CLAUSE.addElement("CAPTION").addText(whereJsonObject.getString("PARAM_CAPTION"));
			WHERE_CLAUSE.addElement("OPER").addText(whereJsonObject.getString("OPER"));
			WHERE_CLAUSE.addElement("VALUES").addText(whereJsonObject.getString("VALUES"));
			WHERE_CLAUSE.addElement("VALUES_CAPTION").addText(whereJsonObject.getString("VALUES_CAPTION"));
			WHERE_CLAUSE.addElement("DATA_BIND_YN").addText(whereJsonObject.getString("BIND_YN"));
			WHERE_CLAUSE.addElement("AGG").addText(whereJsonObject.getString("AGG"));
			WHERE_CLAUSE.addElement("DATA_TYPE").addText(whereJsonObject.getString("DATA_TYPE"));
			WHERE_CLAUSE.addElement("PARAM_YN").addText(whereJsonObject.get("PARAM_YN")+"");
			WHERE_CLAUSE.addElement("PARAM_NM").addText(whereJsonObject.getString("PARAM_NM"));
			WHERE_CLAUSE.addElement("TYPE").addText(whereJsonObject.getString("TYPE"));
			WHERE_CLAUSE.addElement("ORDER").addText((i+1)+"");
			if(whereJsonObject.has("PARAM_ITEM_UNI_NM")) {
				WHERE_CLAUSE.addElement("PARAM_ITEM_UNI_NM").addText(whereJsonObject.getString("PARAM_ITEM_UNI_NM"));
			}
			else {
				WHERE_CLAUSE.addElement("PARAM_ITEM_UNI_NM").addText(whereJsonObject.getString("UNI_NM"));
			}
//			WHERE_CLAUSE.addElement("COND_ID").addText(whereJsonObject.getString("COND_ID"));
//			WHERE_CLAUSE.addElement("COL_NM").addText(whereJsonObject.getString("COL_NM"));
//			WHERE_CLAUSE.addElement("COL_CAPTION").addText(whereJsonObject.getString("COL_CAPTION"));
//			WHERE_CLAUSE.addElement("TBL_CAPTION").addText(whereJsonObject.getString("TBL_NM"));
//			WHERE_CLAUSE.addElement("OPER").addText(whereJsonObject.getString("OPER"));
//			WHERE_CLAUSE.addElement("VALUES").addText(whereJsonObject.getString("VALUES"));
//			WHERE_CLAUSE.addElement("VALUES_CAPTION").addText(whereJsonObject.getString("VALUES_CAPTION"));
//			WHERE_CLAUSE.addElement("DATA_BIND_YN").addText((whereJsonObject.get("DATA_BIND_YN")+"").equalsIgnoreCase("true")?"True":"False");
//			WHERE_CLAUSE.addElement("AGG").addText(whereJsonObject.getString("AGG"));
//			WHERE_CLAUSE.addElement("TBL_NM").addText(whereJsonObject.getString("TBL_NM"));
//			WHERE_CLAUSE.addElement("DATA_TYPE").addText(whereJsonObject.getString("DATA_TYPE"));
//			WHERE_CLAUSE.addElement("PARAM_YN").addText((whereJsonObject.get("PARAM_YN")+"").equalsIgnoreCase("true")?"True":"False");
//			WHERE_CLAUSE.addElement("PARAM_NM").addText(whereJsonObject.getString("PARAM_NM"));
//			WHERE_CLAUSE.addElement("TYPE").addText(whereJsonObject.getString("TYPE"));
//			WHERE_CLAUSE.addElement("COL_EXPRESS").addText(whereJsonObject.getString("COL_EXPRESS").toUpperCase());
//			WHERE_CLAUSE.addElement("ORDER").addText((i+1)+"");
		}
		Element ORDER_ELEMENT = DATA_SET.addElement("ORDER_ELEMENT");
		for(int i=0;i<orderObjArray.length();i++) {
			JSONObject orderJsonObject = orderObjArray.getJSONObject(i);
			Element ORDER_CLAUSE = ORDER_ELEMENT.addElement("ORDER_CLAUSE");
			ORDER_CLAUSE.addElement("UNI_NM").addText(orderJsonObject.getString("UNI_NM"));
			ORDER_CLAUSE.addElement("CAPTION").addText(orderJsonObject.getString("CAPTION"));
			ORDER_CLAUSE.addElement("SORT_TYPE").addText(orderJsonObject.getString("SORT_TYPE"));
			ORDER_CLAUSE.addElement("TYPE").addText(orderJsonObject.getString("TYPE"));
			ORDER_CLAUSE.addElement("ORDER").addText(i+"");
		}
		
		Element PARAM_ELEMENT = DATA_SET.addElement("PARAM_ELEMENT");
		if(isMultipleDataSource == false) {
			JSONObject paramObject = obj.getJSONObject("ParamArea");//from parameterInformation
			Iterator<String> paramKey = paramObject.keys();
			
			while (paramKey.hasNext()) {
				String paramKeyName = paramKey.next().toString();
				if(paramObject.get(paramKeyName) instanceof JSONObject){
					JSONObject paramItem = paramObject.getJSONObject(paramKeyName);
					Element PARAM = PARAM_ELEMENT.addElement("PARAM");
					/* dogfoot WHATIF 분석 매개변수 저장 shlim 20201022 */
					if(paramItem.has("CALC_PARAM_YN")) {
						PARAM.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
						PARAM.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
						String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
						PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
						PARAM.addElement("SET_VALUE").addText(defaultVal);
						PARAM.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
//						paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
//						paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
						PARAM.addElement("SLIDER_POINT").addText(paramItem.get("SLIDER_POINT") + "");
						PARAM.addElement("SLIDER_MIN").addText(paramItem.get("SLIDER_MIN") + "");
						PARAM.addElement("SLIDER_MAX").addText(paramItem.get("SLIDER_MAX") + "");
						
						PARAM.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
						PARAM.addElement("CALC_PARAM_YN").addText(paramItem.getString("CALC_PARAM_YN"));
						
					}else {
						PARAM.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
						PARAM.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
						PARAM.addElement("DATA_TYPE").addText(paramItem.getString("DATA_TYPE"));
						PARAM.addElement("PARAM_TYPE").addText(paramItem.getString("PARAM_TYPE"));
						PARAM.addElement("DATASRC_TYPE").addText(paramItem.getString("DATASRC_TYPE"));
						PARAM.addElement("DATASRC").addText(paramItem.getString("DATASRC"));
						PARAM.addElement("CAPTION_VALUE_ITEM").addText(paramItem.getString("CAPTION_VALUE_ITEM"));
						PARAM.addElement("KEY_VALUE_ITEM").addText(paramItem.getString("KEY_VALUE_ITEM"));
						PARAM.addElement("SORT_VALUE_ITEM").addText(paramItem.getString("SORT_VALUE_ITEM"));
						String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
						
						if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
							String[] defalutBetween = paramItem.getString("HIDDEN_VALUE").split(",");
							String reultDefault = "";
							/* DOGFOOT mksong BASE64 오류 수정 20200116 */
//							reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[0].getBytes()));
//							reultDefault += ",";
//							reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[1].getBytes()));
							reultDefault += new String(defalutBetween[0].getBytes());
							reultDefault += ",";
							reultDefault += new String(defalutBetween[1].getBytes());
							PARAM.addElement("DEFAULT_VALUE").addText(reultDefault);
						}
						else if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
							JSONArray defaultArr = paramItem.getJSONArray("DEFAULT_VALUE");
							defaultVal = defaultArr.get(0)+","+defaultArr.get(1);
							PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
						}
						else if(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
							String defaultSQLVal = paramItem.getString("HIDDEN_VALUE");
							/* DOGFOOT mksong BASE64 오류 수정 20200116 */
							PARAM.addElement("DEFAULT_VALUE").addText(new String(java.util.Base64.getEncoder().encode(defaultSQLVal.getBytes())));
						}
						else {
							if(defaultVal.equals("_ALL_VALUE_")) {
								defaultVal = "[All]";
							}else {
								PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
							}
							
						}
						PARAM.addElement("CAPTION_FORMAT").addText(paramItem.getString("CAPTION_FORMAT"));
						PARAM.addElement("KEY_FORMAT").addText(paramItem.getString("KEY_FORMAT"));
						PARAM.addElement("CAND_DEFAULT_TYPE").addText(paramItem.getString("CAND_DEFAULT_TYPE"));
						/*dogfoot 캘린더 기간 설정 shlim 20210427*/
						if(paramItem.has("CAND_MAX_GAP")) {
							PARAM.addElement("CAND_MAX_GAP").addText(paramItem.get("CAND_MAX_GAP")+"");
						}
						PARAM.addElement("CAND_PERIOD_BASE").addText(paramItem.getString("CAND_PERIOD_BASE"));
						PARAM.addElement("CAND_PERIOD_VALUE").addText(paramItem.get("CAND_PERIOD_VALUE") + "");
						PARAM.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
						PARAM.addElement("MULTI_SEL").addText(paramItem.getString("MULTI_SEL"));
						/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
						if(paramItem.has("ORDERBY_KEY")) {
							PARAM.addElement("ORDERBY_KEY").addText(paramItem.getString("ORDERBY_KEY"));
						}
						PARAM.addElement("ORDER").addText(paramItem.get("ORDER") + "");
						PARAM.addElement("DS_ID").addText(paramItem.get("DS_ID") + "");
						PARAM.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
						PARAM.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
						PARAM.addElement("ALL_YN").addText(paramItem.getString("ALL_YN"));
						PARAM.addElement("WHERE_CLAUSE").addText(paramItem.getString("WHERE_CLAUSE"));
						PARAM.addElement("HIDDEN_VALUE").addText(paramItem.getString("HIDDEN_VALUE"));
						PARAM.addElement("DEFAULT_VALUE_USE_SQL_SCRIPT").addText(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT"));
						PARAM.addElement("SORT_TYPE").addText(paramItem.getString("SORT_TYPE"));
						PARAM.addElement("OPER").addText(paramItem.getString("OPER"));
						PARAM.addElement("BIND_YN").addText(paramItem.getString("BIND_YN"));
						PARAM.addElement("SEARCH_YN").addText(paramItem.getString("SEARCH_YN"));
						PARAM.addElement("EDIT_YN").addText(paramItem.getString("EDIT_YN"));
						/*dogfoot shlim 20210415*/
						if(paramItem.has("LINE_BREAK")){
							PARAM.addElement("LINE_BREAK").addText(paramItem.getString("LINE_BREAK"));
						}
						if(paramItem.has("INPUT_EDIT_YN")){
							PARAM.addElement("INPUT_EDIT_YN").addText(paramItem.getString("INPUT_EDIT_YN"));
						}
						PARAM.addElement("RANGE_YN").addText(paramItem.getString("RANGE_YN"));
						/*DOGFOOT cshan 20200113 - between 필터 저장시 오류 수정*/
						PARAM.addElement("RANGE_VALUE").addText(paramItem.get("RANGE_VALUE")+"");
						PARAM.addElement("DEFAULT_VALUE_MAINTAIN").addText(paramItem.getString("DEFAULT_VALUE_MAINTAIN"));
						PARAM.addElement("TYPE_CHANGE_YN").addText(paramItem.getString("TYPE_CHANGE_YN"));
					}
					
				}
			}
		}else {
			JSONArray paramArray = new JSONArray();
			Object paramObject = obj.get("ParamArea");
			if(paramObject instanceof JSONObject) {
				paramArray = toJsonArray((JSONObject)paramObject, "PARAM");
			}else {
				paramArray = obj.getJSONArray("ParamArea");
			}
			
			if(paramArray != null) {
				
				for(int idx= 0; idx <paramArray.length();idx++) {
					Element PARAM = PARAM_ELEMENT.addElement("PARAM");
					JSONObject paramItem = paramArray.getJSONObject(idx);
					/* dogfoot WHATIF 분석 매개변수 저장 shlim 20201022 */
					if(paramItem.has("CALC_PARAM_YN")) {
						PARAM.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
						PARAM.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
						String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
						PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
						PARAM.addElement("SET_VALUE").addText(defaultVal);
						PARAM.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
//						paramElement.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
//						paramElement.addElement("ORDER").addText(paramItem.get("ORDER") + "");
						PARAM.addElement("SLIDER_POINT").addText(paramItem.get("SLIDER_POINT") + "");
						PARAM.addElement("SLIDER_MIN").addText(paramItem.get("SLIDER_MIN") + "");
						PARAM.addElement("SLIDER_MAX").addText(paramItem.get("SLIDER_MAX") + "");
						
						PARAM.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
						PARAM.addElement("CALC_PARAM_YN").addText(paramItem.getString("CALC_PARAM_YN"));
						
					}else {
						PARAM.addElement("PARAM_NM").addText(paramItem.getString("PARAM_NM"));
						PARAM.addElement("PARAM_CAPTION").addText(paramItem.getString("PARAM_CAPTION"));
						PARAM.addElement("DATA_TYPE").addText(paramItem.getString("DATA_TYPE"));
						PARAM.addElement("PARAM_TYPE").addText(paramItem.getString("PARAM_TYPE"));
						PARAM.addElement("DATASRC_TYPE").addText(paramItem.getString("DATASRC_TYPE"));
						PARAM.addElement("DATASRC").addText(paramItem.getString("DATASRC"));
						PARAM.addElement("CAPTION_VALUE_ITEM").addText(paramItem.getString("CAPTION_VALUE_ITEM"));
						PARAM.addElement("KEY_VALUE_ITEM").addText(paramItem.getString("KEY_VALUE_ITEM"));
						PARAM.addElement("SORT_VALUE_ITEM").addText(paramItem.getString("SORT_VALUE_ITEM"));
						String defaultVal = paramItem.get("DEFAULT_VALUE")+"";
						
						if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
							String[] defalutBetween = paramItem.getString("HIDDEN_VALUE").split(",");
							String reultDefault = "";
							/* DOGFOOT mksong BASE64 오류 수정 20200116 */
//							reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[0].getBytes()));
//							reultDefault += ",";
//							reultDefault += new String(java.util.Base64.getEncoder().encode(defalutBetween[1].getBytes()));
							reultDefault += new String(defalutBetween[0].getBytes());
							reultDefault += ",";
							reultDefault += new String(defalutBetween[1].getBytes());
							PARAM.addElement("DEFAULT_VALUE").addText(reultDefault);
						}
						else if(paramItem.getString("OPER").equalsIgnoreCase("BETWEEN") && paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("N")) {
							JSONArray defaultArr = paramItem.getJSONArray("DEFAULT_VALUE");
							defaultVal = defaultArr.get(0)+","+defaultArr.get(1);
							PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
						}
						else if(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT").equalsIgnoreCase("Y")) {
							String defaultSQLVal = paramItem.getString("HIDDEN_VALUE");
							/* DOGFOOT mksong BASE64 오류 수정 20200116 */
							PARAM.addElement("DEFAULT_VALUE").addText(new String(java.util.Base64.getEncoder().encode(defaultSQLVal.getBytes())));
						}
						else {
							if(defaultVal.equals("_ALL_VALUE_")) {
								defaultVal = "[All]";
							}else {
								PARAM.addElement("DEFAULT_VALUE").addText(defaultVal);
							}
							
						}
						PARAM.addElement("CAPTION_FORMAT").addText(paramItem.getString("CAPTION_FORMAT"));
						PARAM.addElement("KEY_FORMAT").addText(paramItem.getString("KEY_FORMAT"));
						PARAM.addElement("CAND_DEFAULT_TYPE").addText(paramItem.getString("CAND_DEFAULT_TYPE"));
						/*dogfoot 캘린더 기간 설정 shlim 20210427*/
						if(paramItem.has("CAND_MAX_GAP")) {
							PARAM.addElement("CAND_MAX_GAP").addText(paramItem.get("CAND_MAX_GAP")+"");
						}
						PARAM.addElement("CAND_PERIOD_BASE").addText(paramItem.getString("CAND_PERIOD_BASE"));
						PARAM.addElement("CAND_PERIOD_VALUE").addText(paramItem.get("CAND_PERIOD_VALUE") + "");
						PARAM.addElement("VISIBLE").addText(paramItem.getString("VISIBLE"));
						PARAM.addElement("MULTI_SEL").addText(paramItem.getString("MULTI_SEL"));
						/*dogfoot 필터 리스트 키설정 정렬 추가 shlim 20210329 */
						if(paramItem.has("ORDERBY_KEY")) {
							PARAM.addElement("ORDERBY_KEY").addText(paramItem.getString("ORDERBY_KEY"));
						}
						PARAM.addElement("ORDER").addText(paramItem.get("ORDER") + "");
						PARAM.addElement("DS_ID").addText(paramItem.get("DS_ID") + "");
						PARAM.addElement("WIDTH").addText(paramItem.get("WIDTH") + "");
						PARAM.addElement("UNI_NM").addText(paramItem.getString("UNI_NM"));
						PARAM.addElement("ALL_YN").addText(paramItem.getString("ALL_YN"));
						PARAM.addElement("WHERE_CLAUSE").addText(paramItem.getString("WHERE_CLAUSE"));
						PARAM.addElement("HIDDEN_VALUE").addText(paramItem.getString("HIDDEN_VALUE"));
						PARAM.addElement("DEFAULT_VALUE_USE_SQL_SCRIPT").addText(paramItem.getString("DEFAULT_VALUE_USE_SQL_SCRIPT"));
						PARAM.addElement("SORT_TYPE").addText(paramItem.getString("SORT_TYPE"));
						PARAM.addElement("OPER").addText(paramItem.getString("OPER"));
						PARAM.addElement("BIND_YN").addText(paramItem.getString("BIND_YN"));
						PARAM.addElement("SEARCH_YN").addText(paramItem.getString("SEARCH_YN"));
						PARAM.addElement("EDIT_YN").addText(paramItem.getString("EDIT_YN"));
						/*dogfoot shlim 20210415*/
						if(paramItem.has("LINE_BREAK")){
							PARAM.addElement("LINE_BREAK").addText(paramItem.getString("LINE_BREAK"));
						}
						if(paramItem.has("INPUT_EDIT_YN")){
							PARAM.addElement("INPUT_EDIT_YN").addText(paramItem.getString("INPUT_EDIT_YN"));
						}
						PARAM.addElement("RANGE_YN").addText(paramItem.getString("RANGE_YN"));
						/*DOGFOOT cshan 20200113 - between 필터 저장시 오류 수정*/
						PARAM.addElement("RANGE_VALUE").addText(paramItem.get("RANGE_VALUE")+"");
						PARAM.addElement("DEFAULT_VALUE_MAINTAIN").addText(paramItem.getString("DEFAULT_VALUE_MAINTAIN"));
						PARAM.addElement("TYPE_CHANGE_YN").addText(paramItem.getString("TYPE_CHANGE_YN"));
					}
					
				}
			}
			
		}
		StringWriter sw = new StringWriter();
		OutputFormat outputFormat = new OutputFormat();
//		outputFormat.setIndent(true);
//		outputFormat.setNewlines(true);
		outputFormat.setNewLineAfterDeclaration(false);
//		outputFormat.setOmitEncoding(true);
		XMLWriter writer = new XMLWriter(sw, outputFormat);
		writer.write(DATASETXML.getRootElement());
		String returnStr = sw.toString();
		return returnStr;
	}
	
	public String nullCheck(String input) {
		return input == null ? "" : input;
	}
}

class MapComparator implements Comparator<HashMap<String, String>> {
	 
    private final String key;
    
    public MapComparator(String key) {
        this.key = key;
    }
    
    @Override
    public int compare(HashMap<String, String> first, HashMap<String, String> second) {
        int result = first.get(key).compareTo(second.get(key));
        return result;
    }
}
