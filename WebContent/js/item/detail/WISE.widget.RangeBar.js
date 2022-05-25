WISE.libs.Dashboard.item.RangeBarChartGenerator = function() {
	var self = this;
	
	this.type = 'RANGE_BAR_CHART';
	
	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	this.fieldManager;
	this.initialized;
	
	this.dimensions = [];
	this.measures = [];
	
	this.isAdhocItem = false;
	this.adhocIndex;
	
	/* 
	 * LSH topN 변수
	 */	
	this.topN;
	this.topItem;
	this.topNT;
	this.OtherCnt;
	this.otherShow;
	this.TopNMember;
	this.topNEnabeled = false;
	this.topMesure;
    this.dimensionTopN = new Array();
    
	this.arguments = [];
	this.seriesDimensions = [];
	this.tooltipData = [];
	this.HiddenMeasures = [];
	
	// custom chart palette
	this.customPalette = [];
	this.isCustomPalette = false;
	
	// this.isSuffixEnabled = false;
	// enable interactivity options
	this.enableIO = false;
    
	this.HueActive =false;
    this.rotated = false;
    this.selectedChartType;
    
    this.linkItemidBasten = [];
    
	this.populated = false;
	this.hasCustomFields = {};

	this.chartData = [];
	
	// drill down information
	this.drillDownData;
	this.drillDownStack;
	this.drillDownArgumentOrder;
	this.drillDownSeriesOrder;
	this.drillDownIndex;
	this.drillDownSeries;
	this.reducibleMeasures;
    
    this.trackingData = [];
	this.selectedPoint;
	/*DOGFOOT cshan 20200113 - 한계이상의 열이 놓이면 범례가 안그려지는 문제를 경고창으로 경고*/
	this.errorCheck = false;
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
		
	var stylizedChartTypes = {
		bar: 'Bar',
		stackedbar: 'StackedBar',
		fullstackedbar: 'FullStackedBar',
		scatter: 'Scatter',
		line: 'Line',
		stackedline: 'StackedLine',
		fullstackedline: 'FullStackedLine',
		stepline: 'StepLine',
		spline: 'Spline',
		area: 'Area',
		stackedarea: 'StackedArea',
		fullstackedarea: 'FullStackedArea',
		steparea: 'StepArea',
		splinearea: 'SplineArea',
		stackedslinearea: 'StackedSplineArea',
		fullstackedsplinearea: 'FullStackedSplineArea',
		bubble: 'Bubble'	
	};	
    
    this.RangeBarChart = {};
    
	function filterData(name,leveldown) {
		return self.metadata.filter(function (item) {
			return item.parentID === name && item.leveling === leveldown;
		});
	 }
	// function filterDataRoot(name,leveldown) {
	// 	return self.metadata.filter(function (item) {
	// 		return item.SINGLE_ARGUMENT === name && item.leveling === leveldown;
	// 	});
	//  }
	function filterDataByLevel(leveldown) {
        return self.metadata.filter(function (item) {
            return item.leveling === leveldown;
        });
    }
	function filterDataByParentKey(parent) {		
		return WISE.util.Object.toArray(self.metadata[parent]);
	}

	/**
	 * @param _chart: meta object
	 */
	this.getDxItemConfig = function(_chart, _options) {
		var titleFontSetting = {
			size: 14,
			weight: 400
		}
		
		var labelFontSetting = {
			size: 12,
			weight: 400
		}
		
		var confMeasure = _chart['DataItems']['Measure'];
		// var chartTheme = this.CUSTOMIZED.get('dx').palette;
		var labelOverlappingOption;
//		if(typeof(_chart['DataItems']['Dimension']) != undefined) {
//	         var dimensionTopN = _chart['DataItems']['Dimension'];

//	         if(dimensionTopN.TopNEnabled) {
//	            $.each(dimensionTopN,function(i,e){
//	               if(dimensionTopN[i].TopNCount > 0) {
//	                  self.topN = dimensionTopN[i].TopNCount;
//	                  self.topItem = dimensionTopN[i].TopNMeasure;
//	               } else if(dimensionTopN.TopNCount > 0){
//	                  self.topN = dimensionTopN.TopNCount;
//	                  self.topItem = dimensionTopN.TopNMeasure;
//	               } else {
//	                  self.topN = 5;
//	                  self.topItem = dimensionTopN.TopNMeasure;
//	               }
//	            });
//	         }
//	    }
		if (_chart.SeriesType !== 'bubble') {
			var findPointLabelOption = _chart['Panes']['Pane']['Series']['Simple'];
			if (findPointLabelOption) {
				if(Array.isArray(findPointLabelOption) == false){
					findPointLabelOption = [];
					findPointLabelOption.push(_chart['Panes']['Pane']['Series']['Simple']);
				}

				$.each(WISE.util.Object.toArray(findPointLabelOption),function(i,e) {
					if (typeof (e.PointLabelOptions) != 'undefined') {
					$.each(Object.getOwnPropertyNames(e['PointLabelOptions']), function(j,ee) {
						if(ee == 'OverlappingMode')
							var overlappingMode = '';
							if(e.PointLabelOptions.OverlappingMode == undefined) {
								overlappingMode = '';
							} else if(e.PointLabelOptions.OverlappingMode == 'Reposition') {
								overlappingMode = 'Stack';
							} else {
								overlappingMode = e.PointLabelOptions.OverlappingMode;
							}
							labelOverlappingOption = overlappingMode;
						})
					}
				});
			}
			if (labelOverlappingOption) {
				labelOverlappingOption = labelOverlappingOption.toLowerCase();
			}
		}
		var colorList = typeof _chart.ColorSheme == 'undefined'? []: gDashboard.itemColorManager.generateColorMeta(_chart.ColorSheme.Entry);
		if(colorList.length === 0){
			colorList = gDashboard.itemColorManager.colorMeta;
		}
		var legendSettings = WISE.libs.Dashboard.item.ChartUtility.Legend.get(_chart.ChartLegend);
		legendSettings.font = gDashboard.fontManager.getDxItemLabelFont();
		
		var dxConfigs = {
            rotated: _chart['Rotated'],
            resolveLabelOverlapping : labelOverlappingOption,
            dataSource: [],
            dataPrepareSettings: {
            	sortingMethod : function (_val,_val2){
            		return;
            	}
            },
            palette: _chart['Palette'],
    		commonSeriesSettings: {
    			argumentField : "arg",
				type: "rangeBar"
			},
			customizeLabel: function(e) {
				return {
					border: {
						color: e.series.getColor()
					}
				};
			},
    		animation: {
    			enabled: _chart['Animation'] === 'none' ? false : true,
    			easing: _chart['Animation'] === 'none' ? 'easeOutCubic' : _chart['Animation']
    		},
    		legend: legendSettings,
    		argumentAxis:[],
    		series: [],
    		valueAxis: [],
    		panes:[],
    		pointSelectionMode: 'multiple',
		    tooltip: {
		    	enabled: true,
		    	position: 'outside',
		    	location: 'edge',
		    	font:gDashboard.fontManager.getDxItemLabelFont(),
		        customizeTooltip: function(_pointInfo) {
					var Number = WISE.util.Number,
						labelFormat = 'Number',
						labelUnit = 'O',
						labelPrecision = 0,
						labelPrecisionOption = '반올림',
						labelSeparator = true,
						labelSuffixEnabled = false,
						labelSuffix = {
							O: '',
							K: '천',
							M: '백만',
							B: '십억'
						};
		        	if(typeof(confMeasure.NumericFormat) == 'object') {
	        			labelFormat = confMeasure.NumericFormat.FormatType;
	        			labelPrecision = confMeasure.NumericFormat.Precision;
	        			labelPrecisionOption = confMeasure.NumericFormat.labelPrecisionOption;
						labelUnit = confMeasure.NumericFormat.Unit;
						labelSeparator = confMeasure.NumericFormat.IncludeGroupSeparator;
						labelSuffixEnabled = confMeasure.NumericFormat.SuffixEnabled;
						labelSuffix = confMeasure.NumericFormat.Suffix;
					/* 나중에 비정형일 때 포맷 변경해야하는 부분*/
					} else {
		        		if (_chart.DataItems.Measure.length == 1) {
		        			if(_chart.DataItems.Measure[0].NumericFormat != undefined){
								labelFormat = typeof _chart.DataItems.Measure[0].NumericFormat.FormatType == 'undefined' ? labelFormat : _chart.DataItems.Measure[0].NumericFormat.FormatType;
								labelUnit = typeof _chart.DataItems.Measure[0].NumericFormat.Unit == 'undefined'? labelUnit : _chart.DataItems.Measure[0].NumericFormat.Unit;
								labelPrecision = typeof _chart.DataItems.Measure[0].NumericFormat.Precision == 'undefined' ? labelPrecision : _chart.DataItems.Measure[0].NumericFormat.Precision;
								labelPrecisionOption = typeof _chart.DataItems.Measure[0].NumericFormat.PrecisionOption == 'undefined' ? labelPrecisionOption : _chart.DataItems.Measure[0].NumericFormat.PrecisionOption;
								labelSeparator = typeof _chart.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator == 'undefiend' ? labelSeparator : _chart.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator;
								labelSuffixEnabled = typeof _chart.DataItems.Measure[0].NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : _chart.DataItems.Measure[0].NumericFormat.SuffixEnabled;
								labelSuffix = typeof _chart.DataItems.Measure[0].NumericFormat.Suffix == 'undefined' ? labelSuffix : _chart.DataItems.Measure[0].NumericFormat.Suffix;
							}
		        		} else {
							$.each(_chart.DataItems.Measure, function(i,k) {
								if (_pointInfo.seriesName.indexOf(k.DataMember) != -1 && typeof k.NumericFormat != 'undefined') {
									labelFormat = typeof k.NumericFormat.FormatType == 'undefined' ? '' : k.NumericFormat.FormatType;
									labelUnit = typeof k.NumericFormat.Unit == 'undefined'? undefined : k.NumericFormat.Unit.substring(0,1);
									labelPrecision = typeof k.NumericFormat.Precision == 'undefined' ? 2 : k.NumericFormat.Precision;
									labelPrecisionOption = typeof k.NumericFormat.PrecisionOption == 'undefined' ? '반올림' : k.NumericFormat.PrecisionOption;
									labelSeparator = typeof k.NumericFormat.IncludeGroupSeparator == 'undefined' ? true : k.NumericFormat.IncludeGroupSeparator;
									labelSuffixEnabled = typeof k.NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : k.NumericFormat.SuffixEnabled;
									labelSuffix = typeof k.NumericFormat.Suffix == 'undefined' ? labelSuffix : k.NumericFormat.Suffix;
									return false;
								}
							});
		        		}
		        	}
					var text;
					// range series
					if(_pointInfo.rangeValue1Text !== undefined) {
						text = '<b>' + _pointInfo.argumentText + '</b>' + '<br/>' + 
							'<b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.rangeValue1, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled, labelPrecisionOption) + 
							' - ' + Number.unit(_pointInfo.rangeValue2, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled, labelPrecisionOption);
					}
					// bubble series
					else if (_pointInfo.sizeText !== undefined) {
						text = '<b>' + _pointInfo.argumentText + '</b>' + '<br/>' + 
							'<b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled, labelPrecisionOption) + 
							' - ' + Number.unit(_pointInfo.size, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled, labelPrecisionOption);
					}
					// simple series
					else {
						text = '<div>' + _pointInfo.argumentText + '</div>' + 
							'<div><b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled, labelPrecisionOption) + '</div>';
					}

					return { html: text };
	        	}
		    },
			onDrawn: function() {
				//gDashboard.itemGenerateManager.removeLoadingImg(self);
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 렌더링 표시 추가 */
				gProgressbar.finishListening();
				/* DOGFOOT ktkang KERIS portal에서 메인화면에 X축 잘리는 오류 수정  20200228 */
				if(gDashboard.portalView) {
					var evt = document.createEvent("HTMLEvents");
					evt.initEvent('resize', true, false);
					window.dispatchEvent(evt);
				}
			},
			onPointClick: function(_e) {
				if (self.IO && self.IO.MasterFilterMode !== 'Off') {
					// do nothing if single master filter and selected point is selected
					if (self.IO.MasterFilterMode === 'Single' && _e.target.isSelected()) {
						return;
					}
					var dimensions, dimensionNames;
					// select and deselect points
					if (self.IO.TargetDimensions === 'Series') {
						dimensions = self.seriesDimensions;
						dimensionNames = _e.target.series.name.split('-');
						if (_e.target.isSelected()) {
							_e.target.series.getAllPoints().forEach(function(point) {
	                    		point.clearSelection();
	                    	});
						} else {
							_e.target.series.getAllPoints().forEach(function(point) {
	                    		point.select();
	                    	});
						}
					} else {
						dimensions = self.arguments.slice().reverse();
						dimensionNames = _e.target.argument.split('<br/>');
						for(var i=0; i<dimensionNames.length;i++){
							dimensionNames[i] = dimensionNames[i].replace(/\n/g, "");//행바꿈제거
							dimensionNames[i] = dimensionNames[i].replace(/\r/g, "");//엔터제거
						}
						if (_e.target.isSelected()) {
							self.dxItem.getAllSeries().forEach(function(seriesItem) {
	                    		seriesItem.getPointsByArg(_e.target.originalArgument).forEach(function(point) {
	                    			point.clearSelection();
	                    		});
	                    	});
						} else {
							self.dxItem.getAllSeries().forEach(function(seriesItem) {
	                    		seriesItem.getPointsByArg(_e.target.originalArgument).forEach(function(point) {
	                    			point.select();
	                    		});
	                    	});
						}
					}
			
					switch(self.IO.MasterFilterMode){
			       		case 'Multiple':
			       			$.each(dimensions, function(_i, _ao) {
				       			var inArray = false;
				       			var selectedData = {};
				       			selectedData[_ao.name] = dimensionNames[_i];
				       			for (var index = 0; index < self.trackingData.length; index++) {
				       				if (self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
				       					self.trackingData.splice(index, 1);
				       					index--;
				       					inArray = true;
				       				}
				       			}
				       			if (!inArray) {
				       				self.trackingData.push(selectedData);
				       			}

				       		});
			       			/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
    						if(WISE.Constants.editmode === "viewer"){
    							gDashboard.itemGenerateManager.focusedItem = self;
    						}
				       		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
			           		gDashboard.filterData(self.itemid, self.trackingData);
			                break;
			       		case 'Single':
			       			if (self.selectedPoint && self.selectedPoint.isSelected()) {
			                    if (self.IO.TargetDimensions === 'Series') {
			                    	self.selectedPoint.series.getAllPoints().forEach(function(point) {
			                    		point.clearSelection();
			                    	});
			                    } else {
			                    	self.dxItem.getAllSeries().forEach(function(seriesItem) {
			                    		seriesItem.getPointsByArg(self.selectedPoint.originalArgument).forEach(function(point) {
			                    			point.clearSelection();
			                    		});
			                    	});
			                    }
			       			}
			       			self.selectedPoint = _e.target;
			       			self.trackingData = [];
			       			$.each(dimensions, function(_i, _ao) {
				       			var selectedData = {};
				       			selectedData[_ao.name] = dimensionNames[_i];
				       			self.trackingData.push(selectedData);

				       		});
			       			/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
    						if(WISE.Constants.editmode === "viewer"){
    							gDashboard.itemGenerateManager.focusedItem = self;
    						}
				       		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
			           		gDashboard.filterData(self.itemid, self.trackingData);
			                break;
					}
				}
				else if (self.IO.IsDrillDownEnabled) {
					switch (self.IO.TargetDimensions) {
						// argument drill-down
						case 'Argument':
							if (self.drillDownArgumentOrder.length - 1 > self.drillDownIndex) {
								self.drillDown(
									self.drillDownArgumentOrder[self.drillDownIndex],
									_e.target.originalArgument,
									self.drillDownArgumentOrder[self.drillDownIndex + 1]
								);
							}
							break;
						// series drill-down
						case 'Series':
							if (self.drillDownSeriesOrder.length - 1 > self.drillDownIndex) {
								self.drillDown(
									self.drillDownSeriesOrder[self.drillDownIndex],
									_e.target.series.name.split('-')[0],
									self.drillDownSeriesOrder[self.drillDownIndex + 1]
								);
							}
							break;
						default:
					}
				} else {
					self.handleSubLinkEvent(_e);
				}
			},
			/*DOGFOOT cshan 20200206 - 경고창이 불편하다는 문제가 많아 제거*/
			onIncidentOccurred:function(_e){
//				if(_e.target.id == "W2104" && self.errorCheck == false){
//					WISE.alert('범례의 크기가 화면을 초과하여, 표시를 해제하였습니다.');
//					self.errorCheck = true;
//				}
			}
		};
		
		// extend custom-configurations
		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
		var CustomConfigs = $.extend({}, Configurations);
		$.extend(CustomConfigs, dxConfigs);
		dxConfigs = CustomConfigs;
		
		// Axis-X setting
		var xTitle = '',xVisible = false,xRotation = 0;
		
		if(_chart['AxisX'] != undefined){
			xTitle = _chart['AxisX']['Title'];
			xVisible =  _chart['AxisX']['Visible'];
			xRotation = _chart['AxisX']['Rotation'];
		}
		var X = {
			title: {
				text: xTitle,
				font: gDashboard.fontManager.getDxItemAxisTitleFont()
			},
			position: 'bottom',
//			type: 'discrete',
			discreteAxisDivisionMode: "crossLabels",
			grid: {
				visible: false
			},
			label: {
				font: gDashboard.fontManager.getDxItemLabelFont(),
				displayMode: 'rotate',
				rotationAngle: xRotation,
				maxLabelCount:10,
				visible: xVisible
			},
//			hoverMode: 'allArgumentPoints',
			visible: true
		};
		dxConfigs.argumentAxis = X;
		return dxConfigs;
	};

	this.handleSubLinkEvent = function(_point) {
		var chartItemDim = self.meta.DataItems.Dimension;
		var linkReportMeta = gDashboard.structure.subLinkReport;
		var linkChartMatch = {};
		var linkJsonMatch = {};
		var target_id;
		var linkitemid;
		var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

		var chartTextDim = _point.target.argument.split('<br/>').reverse();



		$.each(linkReportMeta,function(_i,_ee){
			var linkParam = _ee.linkJson.LINK_XML_PARAM.ARG_DATA;
			var linkDataParam = _ee.linkJson2.LINK_XML_DATA.ARG_DATA;
			if((_ee.target_item +'_' + _ee.arg_id +'_item' == self.itemid || _ee.target_item + '_item' == self.itemid) && _ee.link_type == 'LD'){
				linkitemid = self.itemid + "_link";

				target_id = _ee.target_id;

				linkChartMatch = {};
				linkJsonMatch = {};
//				var num = 0;
//				var seen = [];
//				$.each(WISE.util.Object.toArray(linkDataParam), function(_j,_dataParam){
//					$.each(paramListValue, function(_i,_eee){
//						var paramName = _eee.orgParamName || _eee.paramName;
//						if(!Array.isArray(chartTextDim)) {
//							if(paramName == _dataParam.PK_COL_NM) {
//								if (seen.indexOf(chartItemDim.DataMember) === -1) {
//									linkChartMatch[chartItemDim.DataMember] = chartTextDim[num];
//									num++;
//									return false;
//								}
//							}
//						} else {
//							/* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
//							$.each(chartItemDim, function(_j, dim) {
//								if(paramName == _dataParam.PK_COL_NM) {
//									if (seen.indexOf(dim.DataMember) === -1) {
//										seen.push(dim.DataMember);
//										linkChartMatch[dim.DataMember] = chartTextDim[num];
//										num++;
//										return false;
//									}
//								}
//							});
//						}
//					});
//				});
//
//				if(typeof _ee.linkJson != 'undefined' && _ee.linkJson != "") {
//						// 2020.02.14 mksong 비트윈 파라미터 전달 수정 DOGFOOT
//					$.each(WISE.util.Object.toArray(_ee.linkJson.LINK_XML_PARAM.ARG_DATA),function(_j,_linkJson){
//						var isBetween = false;
//						$.each(paramListValue, function(_key,_paramValue){
//							if(_paramValue.orgParamName == _linkJson.FK_COL_NM){
//								if(_paramValue.parameterType.indexOf('BETWEEN') != -1){
//									isBetween = true;
//									if(isBetween){
//										/* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
//										linkJsonMatch[_linkJson.FK_COL_NM] = paramListValue[_linkJson.FK_COL_NM+'_fr'].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM+'_fr'].value;	
//									}
//								}
//							}
//						});
//						// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
//						if(!isBetween){
//							/* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
//							linkJsonMatch[_linkJson.FK_COL_NM] = paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value;	
//						}
//					});
//				}
//
//				if(typeof _ee.linkJson2 != 'undefined' && _ee.linkJson2 != "") {
//					$.each(_ee.linkJson2.LINK_XML_DATA.ARG_DATA,function(_j,_linkJson){
//						if(!Array.isArray(_ee.linkJson2.LINK_XML_DATA.ARG_DATA)) {
//							/* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
//							linkJsonMatch[_ee.linkJson2.LINK_XML_DATA.ARG_DATA.PK_COL_NM] = linkChartMatch[_ee.linkJson2.LINK_XML_DATA.ARG_DATA.FK_COL_NM] == '_EMPTY_VALUE_' ? '[All]' : linkChartMatch[_ee.linkJson2.LINK_XML_DATA.ARG_DATA.FK_COL_NM];
//						} else if(_linkJson.PK_COL_NM) {
//							/* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
//							linkJsonMatch[_linkJson.PK_COL_NM] = linkChartMatch[_linkJson.FK_COL_NM] == '_EMPTY_VALUE_' ? '[All]' : linkChartMatch[_linkJson.FK_COL_NM] || linkJsonMatch[_linkJson.PK_COL_NM];
//						}
//					});
//				}

				var num = 0;
				$.each(paramListValue, function(_i,_eee){
					if(!Array.isArray(chartItemDim)) {
						if(_eee.name == chartItemDim.DataMember) {
							linkChartMatch[chartItemDim.DataMember] = chartTextDim[num];
							num++;
						}
					} else {
						chartItemDim.sort(function(a, b) {
							return a.UniqueName < b.UniqueName ? -1 : a.UniqueName > b.UniqueName ? 1 : 0;
						});
						if(_eee.name == chartItemDim[num].DataMember) {
							linkChartMatch[chartItemDim[num].DataMember] = chartTextDim[num];
							num++;
						}
					}
				});

				if(typeof _ee.linkJson != 'undefined' && _ee.linkJson != "") {
					$.each(_ee.linkJson.LINK_XML_PARAM.ARG_DATA,function(_j,_linkJson){
						if(!Array.isArray(_ee.linkJson.LINK_XML_PARAM.ARG_DATA)) {
							linkJsonMatch[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.PK_COL_NM] = paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value;
						} else if(_linkJson.PK_COL_NM) {
							linkJsonMatch[_linkJson.PK_COL_NM] = paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value;
						}
					});
				}

				if(typeof _ee.linkJson2 != 'undefined' && _ee.linkJson2 != "") {
					$.each(_ee.linkJson2.LINK_XML_DATA.ARG_DATA,function(_j,_linkJson){
						if(!Array.isArray(_ee.linkJson2.LINK_XML_DATA.ARG_DATA)) {
							linkJsonMatch[_ee.linkJson2.LINK_XML_DATA.ARG_DATA.PK_COL_NM] = linkChartMatch[_ee.linkJson2.LINK_XML_DATA.ARG_DATA.FK_COL_NM] == '_EMPTY_VALUE_' ? '[All]' : _point.target.argument;
						} else if(_linkJson.PK_COL_NM) {
							linkJsonMatch[_linkJson.PK_COL_NM] = linkChartMatch[_linkJson.FK_COL_NM] == '_EMPTY_VALUE_' ? '[All]' : _point.target.argument;
						}
					});
				}
				
				var locationStr = "";
				$.each(linkJsonMatch,function(_key,_val){
					// 2020.02.13 mksong 연결보고서 VALUE값 암호화 DOGFOOT
					/* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
					locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(encodeURI(_val))+'&';
				});
				locationStr = (locationStr.substring(0,locationStr.length-1));
				if(locationStr.length > 1) {
					locationStr = "&" + locationStr;
				}
				// 2020.02.13 수정자 : mksong 유저 수정 DOGFOOT
				var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_ee.target_id+'/viewer.do?USER='+userJsonObject.userId+'&assign_name=bWVpcw==' + locationStr;
				window.open(urlString);
			}
		});
	}
	
	this.enableButtons = function(_data) {
		var disabled = $.type(_data) === 'array' && _data.length > 0 ? false : true;
		if (this.seriesTypeSelector) {
			this.seriesTypeSelector.option('disabled', disabled);
		}
	};
	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	};

	this.populate = function(_options) {
		var R = _options.rows; // arguments
		var C = _options.columns; // series dimensions
		var D = _options.datas; // values
//		var CH = this.meta['CHART_XML'];
		// 초기화
		this.measures = [];
		this.dimensions = [];
		
//		this.RangeBarChart['DataItems']['Dimension'] = [];
//		this.RangeBarChart['DataItems']['Measure'] = [];
		
		this.meta['Values'] = this.RangeBarChart['Values'] = {Value :D.length != 0 ? D:[]};
		this.meta['Rows'] = this.RangeBarChart['Rows'] = {Row:R.length != 0 ? R:[]};
		this.meta['Columns'] = this.RangeBarChart['Columns'] = {Column:C.length != 0 ? C:[]};
		
		this.Panes = {};
		this.arguments = [];
    	this.seriesDimensions = [];
    	
		this.Panes.Pane = {'Name':"창 1", 'Series':{'Simple':[]}};			
		var chartElement = gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML ? gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML : {};
		var CU = WISE.libs.Dashboard.item.ChartUtility;

		for (var i = 1; i <= this.RangeBarChart.Values.Value.length; i++) {
			var uniqueName = chartElement['SERIES' + i + '_UNI_NM'],
				seriesType = CU.Series.Simple.getChartName(chartElement['SERIES' + i + '_CHART_TYPE']),
				secondaryAxis = chartElement['SERIES' + i + '_AXISY2'],
				Value = {
					Value: {
						UniqueName: (typeof uniqueName !== 'undefined' && uniqueName.length > 0) ? uniqueName : self.RangeBarChart.Values.Value[i - 1].UNI_NM
					},
					SeriesType: typeof seriesType !== 'undefined' ? seriesType : 'Bar',
					PlotOnSecondaryAxis: typeof secondaryAxis !== 'undefined' ? secondaryAxis : false,
					IgnoreEmptyPoints: false,
					ShowPointMarkers: true,
//					PointLabelOptions: {
//						Orientation: '',
//						ContentType: 'Value',
//						OverlappingMode: 'Hide',
//						ShowForZeroValues: false,
//						Position: 'Outside',
//						FillBackground: false,
//						ShowBorder: false
//					}
				};
			self.Panes.Pane.Series.Simple.push(Value);
		}
		
		this.Arguments = {'Argument' : []};
		_.each(this.meta['Rows']['Row'],function(_a){
			var Value = {'UniqueName' : _a.UNI_NM};
			self.Arguments['Argument'].push(Value);
			self.arguments.push(Value);
		})
		this.SeriesDimensions = {'SeriesDimension' : []};
		_.each(this.meta['Columns']['Column'],function(_s){
			var Value = {'UniqueName' : _s.UNI_NM};
			self.SeriesDimensions['SeriesDimension'].push(Value);
			self.seriesDimensions.push(Value);
		})
		
		this.RangeBarChart['Panes'] = self.Panes;
		this.RangeBarChart['SeriesDimensions'] = this.SeriesDimensions;
		this.RangeBarChart['Arguments'] = this.Arguments;
		
		this.renderType = this.__getRenderType();
		self.populated = true;
		this.bindData(_.clone(this.filteredData));
	};
	/**
	 * Clear master filter selections and tracking on all items.
	 */
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if(gDashboard.reportType != 'AdHoc' || !(gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer')){
				if (self.dxItem) self.dxItem.clearSelection();
				self.trackingData = [];
				self.selectedPoint = undefined;	
			}
		}
	};

	/**
	 * Selects the first point of the first series in the chart. 
	 */
	this.selectFirstPoint = function() {
		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
		self.trackingData = [];
		var firstSeries = self.dxItem.getSeriesByPos(0),
			firstPoint = firstSeries.getPointByPos(0),
			dimensions,
			dimensionNames;
		self.selectedPoint = firstPoint;
		if (self.IO.TargetDimensions === 'Series') {
			dimensions = self.seriesDimensions;
			dimensionNames = firstSeries.name.split('-');
			$.each(firstSeries.getAllPoints(), function(i, point) {
				point.select();
			});
		} else {
			dimensions = self.arguments.slice().reverse();
			dimensionNames = firstPoint.argument.split('<br/>');
			$.each(self.dxItem.getAllSeries(), function(i, series) {
				series.getPointByPos(0).select();
			});
		}
		$.each(dimensions, function(i, dim) {
			var selectedData = {};
			selectedData[dim.name] = dimensionNames[i];
			self.trackingData.push(selectedData);
		});
		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
		gDashboard.filterData(self.itemid, self.trackingData);
	}
	
	this.__getRenderType = function() {
		if (this.arguments.length === 0 && this.seriesDimensions.length === 0) {
			return 'NO-DIMENSTIONS';
		} else if (this.arguments.length > 0 && this.seriesDimensions.length === 0) {
			return 'ARGUMENTS-ONLY';
		}  else {

            return undefined;
		}
	};
	
	this.__getRangeBarChartData = function(_seriesType) {
		//gDashboard.itemGenerateManager.loadingImgRender(self);
		//2020.02.07 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 dogfoot	
		this.calculatedFields = [];
		this.tempMeasureFields = [];
		/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
		this.tempDimensionFields = [];
		this.calculateCaption;
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[this.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(self.measures,function(_i,_measure){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_measure != undefined){
							if(field.Name == _measure.name){
								self.calculatedFields.push(_measure);
								self.calculateCaption = _measure.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.measures,function(_k, _measure){
											if(_tempDataField == _measure.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								self.measures.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
												captionBySummaryType: "sum_"+_tempDataField,
												currencyCulture: undefined,
												format: "fixedPoint",
												formatType: "Number",
												includeGroupSeparator: true,
												name: _tempDataField,
												nameBySummaryType: "sum("+_tempDataField+")",
												nameBySummaryType2: "sum_"+_tempDataField,
												precision: 0,
												precisionOption: '반올림',
												rawCaption: _tempDataField,
												suffix: {
													B: "십억",
													K: "천",
													M: "백만",
													O: ""
												},
												suffixEnabled: false,
												summaryType: "sum",
												type: "measure",
												unit: "Ones",
												tempdata: true
										}
										self.measures.push(dataMember);
										self.tempMeasureFields.push(self.measures.length-1);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
					/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
					$.each(self.dimensions,function(_i,_dimension){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_dimension != undefined){
							if(field.Name == _dimension.name){
								self.calculatedFields.push(_dimension);
								self.calculateCaption = _dimension.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.dimensions,function(_k, _dimension2){
											if(_tempDataField == _dimension2.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								self.dimensions.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
												captionBySummaryType: _tempDataField,
												currencyCulture: undefined,
												includeGroupSeparator: true,
												name: _tempDataField,
												precision: 0,
												precisionOption: '반올림',
												rawCaption: _tempDataField,
												suffixEnabled: false,
												type: "dimension",
												tempdata: true,
												nameBySummaryType: "min("+_tempDataField+")",
												nameBySummaryType2: "min_"+_tempDataField
										}
										self.dimensions.push(dataMember);
										self.tempDimensionFields.push(self.dimensions.length-1);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
					
					$.each(self.seriesDimensions,function(_i,_seriesDimension){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_seriesDimension != undefined){
							if(field.Name == _seriesDimension.name){
								self.calculatedFields.push(_seriesDimension);
								self.calculateCaption = _seriesDimension.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.seriesDimensions,function(_k, _seriesDimension2){
											if(_tempDataField == _seriesDimension2.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								self.seriesDimensions.splice(_i,1);
								if(tempDataField != undefined && tempDataField.length != 0){
									$.each(tempDataField, function(_index,_tempDataField){
										var dataMember = {
												UNI_NM: undefined,
												caption: self.calculateCaption,
												captionBySummaryType: _tempDataField,
												currencyCulture: undefined,
												includeGroupSeparator: true,
												name: _tempDataField,
												precision: 0,
												precisionOption: '반올림',
												rawCaption: _tempDataField,
												suffixEnabled: false,
												type: "dimension",
												tempdata: true,
												nameBySummaryType: "min("+_tempDataField+")",
												nameBySummaryType2: "min_"+_tempDataField
										}
										self.seriesDimensions.push(dataMember);
										self.tempDimensionFields.push(self.seriesDimensions.length-1);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
				});
			}
		}
		//2020.02.07 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 수정 끝 dogfoot
		
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		var dimensions = [];
		dimensions = dimensions.concat(_.clone(this.dimensions));
		dimensions = dimensions.concat(_.clone(this.seriesDimensions));
		var measures = [];
		measures = measures.concat(_.clone(this.measures));
		measures = measures.concat(_.clone(this.HiddenMeasures));
		
//		/* DOGFOOT ktkang 비정형 그리드만 보기에서 차트 안그리도록 수정  20200401 */
		var tempData;
		var tempDataConfig;
		var csvDataConfig;
//		//2020.01.30 mksong SQLLIKE 기능 추가 dogfoot
		//20200715 ajkim 레이아웃 G일 때 디자이너에서는 조회하게 변경 dogfoot
		if(gDashboard.reportType == 'AdHoc' && gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer') {
			tempDataConfig = [];
			//2020.03.19 mksong 오류 메세지 출력 dogfoot
			tempData = [];
			csvDataConfig = [];
			this.csvData = [];
		} else {
			tempDataConfig = SQLikeUtil.fromJson(dimensions, measures, []);
			if (self.IO.IgnoreMasterFilters) {
				tempDataConfig.From = [];
				tempDataConfig.Where = [];
			}
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			tempData = SQLikeUtil.doSqlLike(this.dataSourceId, tempDataConfig, self);
			
			//2020.05.04 AJKIM 데이터 항목 없을 때 이미지 추가 DOGFOOT
			if(gDashboard.itemGenerateManager.noDataCheck(tempData, self)) return {};
			
			function fieldCheck(_filterString){
				var dimension = self.dimensions.concat(self.seriesDimensions)
				if(_filterString === undefined || _filterString === [] || _filterString === ""  || !_filterString)
					return;
				var removedData = true;
				if($.type(_filterString[0]) === 'string'){
					removedData = true;
					$.each(dimension, function(_i, _dimension){
						if(_dimension.name === self.meta.FilterString[0])
							removedData = false;
					});
					if(removedData)
						_filterString.splice(0, 3);
				}else{
					var removeCount = 0;
					$.each(_filterString, function(_i, _filter){
						removedData = true;
						$.each(dimension, function(_j, _dimension){
							if(_filter === undefined) return false;
							if($.type(_filter) === 'string'){
								removedData = false;
								return false;
							}
							else if($.type(_filter[0]) === 'array'){
								fieldCheck(_filter);
								if(_filter.length === 0)
									_filterString.splice(_i - removeCount, 2);
								removedData = false;
								return false;
							}
							else if(_dimension.name === _filter[0]){
								removedData = false;
								return false;
							}
						});
						if(removedData){
							_filterString.splice(_i - removeCount, 2);
							removeCount += 2;
						}
					});
				}
			}
			
			fieldCheck(self.meta.FilterString);
			/*dogfoot 차트 아이템 0 값 표시 안하도록 수정 shlim 20200731*/
			tempData = $.map(tempData, function(item) {
            	$.each(measures,function(_j,_mea){
						item[_mea.nameBySummaryType] = item[_mea.nameBySummaryType] == 0 ? null : item[_mea.nameBySummaryType];				
				});  
				 return item;  
			});   
			//2020.03.26 ajkim 필터 적용 dogfoot
			if(self.meta.FilterString!=undefined && self.meta.FilterString.length > 0){
				var newDataSource = new DevExpress.data.DataSource({
						store: tempData,
						paginate: false
				});
				newDataSource.filter(self.meta.FilterString);
				newDataSource.load();
				tempData = newDataSource.items();
			}
			
//			var tempData = SQLikeUtil.fromJson(dimensions, measures, this.filteredData);
//			var tempData = SQLikeUtil.fromJsonforNoSummaryType(dimensions, measures, this.filteredData);
			
//			var tempData = gDashboard.itemGenerateManager.doQueryData(self);
			csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(dimensions, measures, []);
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			this.csvData = SQLikeUtil.doSqlLike(this.dataSourceId, csvDataConfig, self);
//			this.csvData = gDashboard.itemGenerateManager.doQueryCSVData(self);
			//2020.02.07 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 dogfoot
		}
		
		self.globalData = self.csvData;
		self.filteredData = tempData;
		
		//2020.02.04 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 수정 끝 dogfoot
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && self.calculatedFields.length > 0) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[self.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					$.each(self.calculatedFields,function(_i,_calculatedField){
						if(field.Name == _calculatedField.name){
							gDashboard.customFieldManager.addCustomFieldsToDataSourceForSummaryValue(field, tempData, _calculatedField, self.measures, dimensions);		
							gDashboard.customFieldManager.addCustomFieldsToDataSource(field, self.globalData);
						}
					});
				});
			}
		}
		
		// DOGFOOT hjkim 사용자정의함수를 먼저 적용하고 Top/Bottom을 처리하게 20200708
		//비정형 Top/Bottom값 설정이 차트에 적용되게
		var isTopBottom;
		if(self.isAdhocItem){
			$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i,_item){
				if(_item.isAdhocItem && _item.adhocIndex == self.adhocIndex && _item.type == 'PIVOT_GRID'){
					if(_item.topBottomSet){
						self.globalData = _item.globalData;
						tempData = self.globalData;
						isTopBottom = true;
					}
				}
			});
		}		
		
		var deleteCount = 0;
		/*dogfoot 차트 사용자정의데이터 설정시 기존값이 표시 안되는 오류 수정 shlim 20200616*/
//		$.each(self.tempMeasureFields, function(_temp){
//			self.measures.splice(_temp-deleteCount,1);
//			deleteCount++;
//		});
		$.each(self.tempMeasureFields, function(_i,_temp){
			self.measures.splice(_temp - deleteCount,self.measures.length);
			deleteCount++;
		});
		self.measures = self.measures.concat(self.calculatedFields);
		
		/* dogfoot 사용자 정의 데이터 오류 수정 shlim 20201022 */
		if(self.tempDimensionFields.length > 0){
			$.each(self.tempDimensionFields, function(_i,_temp){
				self.dimensions.splice(_temp - deleteCount,self.dimensions.length);
				deleteCount++;
			});
			self.dimensions = self.dimensions.concat(self.calculatedFields);
		}
		
		//2020.02.07 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 수정 끝 dogfoot
		
		/* DOGFOOT hsshim 200103
		 * 사용자 정의 데이터 집계 함수 추가
		 */
		gDashboard.customFieldManager.addSummaryFieldData(self, tempData);
        var queryData = tempData;
        self.initDrillDownData(queryData);

		/*format 맞추는 부분*/
		$.each(tempData,function(_i,_data){
			$.each(measures,function(_j,_mea){
				/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */
				if(_mea.type == 'measure' && _mea.format.key != undefined){
					switch(_mea.format.key){
						case'#,##0,':
							_data[_mea.nameBySummaryType] = Number($.number(Number(_data[_mea.nameBySummaryType]) / 1000, 0));
						break;
						case'#,##0,,':
							_data[_mea.nameBySummaryType] = Number($.number(Number(_data[_mea.nameBySummaryType]) / 1000000, 0));
							break;
						case'#0"."##,,':
							_data[_mea.nameBySummaryType] =  Number($.number(Number(_data[_mea.nameBySummaryType]) / 1000000, 2));
							break;
						default:
							_data[_mea.nameBySummaryType] = _data[_mea.nameBySummaryType];
							break;
					}
				
				}
				
			});
		});


		switch(this.renderType) {
		case 'NO-DIMENSTIONS':
			_.each(queryData, function(_data) {
				_data['arg'] = 'Grand Total';
			});
			break;
		case 'ARGUMENTS-ONLY':
			queryData = tempData;
			
			/* LSH topN
			 *  topN 계산을 위한 함수
			 * */
			if(self.topNEnabeled){
				var first=[];
				
				//데이터 Array 계산 형식에 맞게 변경 
				first.push({items:queryData});
				queryData = first;
				
				//차원이 여러개일때 topN기능이 걸린 차원의 위치를 찾기위한 싸이클
				for(var i = 0; i < self.dimensionTopN.length; i++){
					queryData = this.__getTopNData(queryData,dimensions,self.dimensionTopN[i].DataMember,self.dimensionTopN[i].TopNEnabled);
				}
				
				for(var i = 0; i < self.dimensionTopN.length; i++){
					queryData = this.__getTopNsortData(queryData,self.dimensions,self.dimensionTopN[i].DataMember);
				}
				
				var topNarray=[];
				
				$.each(queryData,function(_i,_e){
					$.each(_e.items,function(_j,_k){
						topNarray.push(_k); 
					}) 
				});

				queryData = topNarray;
				/*dogfoot 차트 아이템 0 값 표시 안하도록 수정 shlim 20200731*/
				queryData = $.map(queryData, function(item) {
	            	$.each(measures,function(_j,_mea){
							item[_mea.nameBySummaryType] = item[_mea.nameBySummaryType] == 0 ? null : item[_mea.nameBySummaryType];				
					});  
					 return item;  
				});
			}
//			queryData = self.csvData;
			_.each(queryData, function(_data) {
				var argBasket = [];
				_.each(self.arguments, function(_arg) {
//					argBasket.push(_data[_arg.name]);
					argBasket.push(_data[_arg.caption]);
//					_data
				});
				
				if(isTopBottom){
					$.each(self.measures, function(_k, _measure){
						_data[_measure.nameBySummaryType] = _data[_measure.caption];
					});
				}
				_data['arg'] = argBasket.reverse().join('<br/>');
			});
			break;
		}
		return queryData;
	};
	
	this.setRangeBarChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type, self.isAdhocItem);
		this.RangeBarChart.DataItems = this.fieldManager.DataItems;
		this.RangeBarChart.Panes = this.fieldManager.Panes;
		this.RangeBarChart.SeriesDimensions = this.fieldManager.SeriesDimensions;
		this.RangeBarChart.Arguments = this.fieldManager.Arguments;
		this.RangeBarChart.HiddenMeasures = this.fieldManager.HiddenMeasures;
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.seriesDimensions = this.fieldManager.seriesDimensions;
		
		// default settings 기본값 맞춤
		if (!(this.RangeBarChart.ComponentName)) {
			this.RangeBarChart.ComponentName = this.ComponentName;
		}
		if (!(this.RangeBarChart.DataSource)) {
			this.RangeBarChart.DataSource = this.dataSourceId;
		}else if(this.RangeBarChart.DataSource != this.dataSourceId){
			this.RangeBarChart.DataSource = this.dataSourceId;
		}
		if (!(this.RangeBarChart.Name)) {
			this.RangeBarChart.Name = this.Name;
		}
		if (!(this.RangeBarChart.MemoText)) {
			this.RangeBarChart.MemoText = this.memoText;
		}
		if (this.RangeBarChart.InteractivityOptions) {
			if (!(this.RangeBarChart.InteractivityOptions.MasterFilterMode)) {
				this.RangeBarChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.RangeBarChart.InteractivityOptions.TargetDimensions)) {
				this.RangeBarChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.RangeBarChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.RangeBarChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.RangeBarChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.RangeBarChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.RangeBarChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (!(this.RangeBarChart.IsMasterFilterCrossDataSource)) {
			this.RangeBarChart.IsMasterFilterCrossDataSource = false;
		}
		if (!(this.RangeBarChart.FilterString)) {
			this.RangeBarChart.FilterString = [];
		}else{
			this.RangeBarChart.FilterString = JSON.parse(JSON.stringify(this.RangeBarChart.FilterString).replace(/"@null"/gi,null));
		}
		if (!(this.RangeBarChart.ShowCaption)) {
			this.RangeBarChart.ShowCaption = true;
		}
		if (!(this.RangeBarChart.Rotated)) {
			this.RangeBarChart.Rotated = false;
		}
		if (!(this.ChaRangeBarChartisX)) {
			this.RangeBarChart.AxisX = {
				Visible: true,
				Title: '',
				Rotation: 0
			};
		}
		if (!(this.RangeBarChart.AxisY)) {
			this.RangeBarChart.AxisY = {
				FormatType: 'Number',
				Unit: 'Ones',
				ShowZero: true,
				Visible: true,
				SuffixEnabled: false,
				MeasureFormat: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: 0,
				precisionOption: '반올림',
				Separator: true
			};
		}
		if (!(this.RangeBarChart.ChartLegend)) {
			this.RangeBarChart.ChartLegend = {
				Visible: true,
				IsInsidePosition: false,
				InsidePosition: 'TopRightHorizontal',
				OutsidePosition: 'TopRightHorizontal'
			};
		}
		if (!(this.RangeBarChart.SeriesType)) {
			this.RangeBarChart.SeriesType = 'bar';
		}
		if (!(this.RangeBarChart.Palette)) {
			this.RangeBarChart.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		if (!(this.RangeBarChart.Animation)) {
			this.RangeBarChart.Animation = 'easeOutCubic';
		}	
			
		this.meta = this.RangeBarChart;
	};
	
	this.setRangeBarChartForOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setRangeBarChart();
		}
		else{
			this.RangeBarChart=this.meta;
		}
		// load CHART_XML
		var chartDataElement = {};
		var dataElement = {};
		var webChartDataElement = {};
		var page = window.location.pathname.split('/');
		if(gDashboard.reportType === 'DashAny'){
			var tempCDE, tempDE, tempWCDE;
			if (typeof gDashboard.structure.MapOption.DASHBOARD_XML !== 'undefined') {
				tempCDE =  WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.RANGE_BAR_CHART_DATA_ELEMENT);
				tempDE = WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DATA_ELEMENT);
				tempWCDE = gDashboard.structure.MapOption.DASHBOARD_XML.WEB ? WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.RANGE_BAR_CHART_DATA_ELEMENT) : [];
			} else {
				tempCDE = [];
				tempDE = [];
				tempWCDE = [];
			}
			$.each(tempCDE,function(_i,_e){
				var CtrlNM;
				if(WISE.Constants.editmode == 'viewer'){
					CtrlNM = _e.CTRL_NM +"_"+WISE.Constants.pid;	
				}else{
					CtrlNM = _e.CTRL_NM;
				}
				
				if(CtrlNM == self.ComponentName){
					chartDataElement = _e;
					return false;
				}
			});
			$.each(tempDE,function(_i,_e){
				var CtrlNM;
				if(WISE.Constants.editmode == 'viewer'){
					CtrlNM = _e.CTRL_NM +"_"+WISE.Constants.pid;	
				}else{
					CtrlNM = _e.CTRL_NM;
				}
				if(CtrlNM == self.ComponentName){
					dataElement = _e;
					return false;
				}
			});
			$.each(tempWCDE,function(_i,_e){
				var CtrlNM;
				if(WISE.Constants.editmode == 'viewer'){
					CtrlNM = _e.CTRL_NM +"_"+WISE.Constants.pid;	
				}else{
					CtrlNM = _e.CTRL_NM;
				}
				if(CtrlNM == self.ComponentName){
					webChartDataElement = _e;
					return false;
				}
			});
		}

		if(this.RangeBarChart.Panes == undefined) {
			this.RangeBarChart.Panes = this.meta.Panes;
		}
		else if(this.fieldManager.initialized) {
			var axisY = this.RangeBarChart.Panes.Pane.AxisY;
			this.RangeBarChart.Panes = this.fieldManager.Panes;
		    this.RangeBarChart.Panes.Pane.AxisY = axisY;	
		
			this.RangeBarChart.DataItems = this.meta.DataItems = this.fieldManager.DataItems;
			this.RangeBarChart.SeriesDimensions = this.meta.SeriesDimensions = this.fieldManager.SeriesDimensions;
			this.RangeBarChart.Arguments = this.meta.Arguments = this.fieldManager.Arguments;
			this.RangeBarChart.HiddenMeasures =  this.meta.HiddenMeasures = this.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
			this.seriesDimensions = this.fieldManager.seriesDimensions;
			/* DOGFOOT ktkang 그냥 오류나는 경우 있어서 수정  20200110 */
		} else if(typeof this.RangeBarChart.DataItems != 'undefined'){
			// set point label options from CHART_XML
			$.each(WISE.util.Object.toArray(this.RangeBarChart.DataItems.Measure), function(mIndex, measure) {
				var uniqueName = measure.UniqueName;
				var pointLabel = {};
				var found = false;
				if (typeof chartDataElement.PANE_ELEMENT !== 'undefined') {
					$.each(WISE.util.Object.toArray(chartDataElement.PANE_ELEMENT.SERIES_ELEMENT), function(sIndex, series) {
						if (series.UNI_NM === uniqueName) {
							pointLabel = {
								fillBackground: series.SERIES_BACK_COLOR_VISIBLE === 'Y',
								showBorder: series.SERIES_BORDER_VISIBLE === 'Y',
								showCustomTextColor: series.SERIES_FONT_COLOR_YN === 'Y',
								customTextColor: typeof series.SERIES_FONT_COLOR !== 'undefined' ? gDashboard.itemColorManager.getHexColor(series.SERIES_FONT_COLOR) : '#000000'
							};
							return false;
						}
					});
				}
				$.each(WISE.util.Object.toArray(self.RangeBarChart.Panes.Pane.Series.Simple), function(j, simple) {
					if (simple.Value.UniqueName === uniqueName) {
						if (simple.PointLabelOptions && typeof simple.PointLabelOptions.FillBackground === 'undefined') {
							simple.PointLabelOptions.FillBackground = pointLabel.fillBackground;
						}
						if (simple.PointLabelOptions && typeof simple.PointLabelOptions.ShowBorder === 'undefined') {
							simple.PointLabelOptions.ShowBorder = pointLabel.showBorder;
						}
						if (simple.PointLabelOptions && typeof simple.PointLabelOptions.ShowCustomTextColor === 'undefined') {
							simple.PointLabelOptions.ShowCustomTextColor = pointLabel.showCustomTextColor;
						}
						if (simple.PointLabelOptions && typeof simple.PointLabelOptions.CustomTextColor === 'undefined') {
							simple.PointLabelOptions.CustomTextColor = pointLabel.customTextColor;
						}
						found = true;
						return false;
					}
				});
				if (found) {
					return true;
				}
				$.each(WISE.util.Object.toArray(self.RangeBarChart.Panes.Pane.Series.Weighted), function(j, weighted) {
					if (weighted.Value.UniqueName === uniqueName) {
						if (weighted.PointLabelOptions && typeof weighted.PointLabelOptions.FillBackground === 'undefined') {
							weighted.PointLabelOptions.FillBackground = pointLabel.fillBackground;
						}
						if (weighted.PointLabelOptions && typeof weighted.PointLabelOptions.ShowBorder === 'undefined') {
							weighted.PointLabelOptions.ShowBorder = pointLabel.showBorder;
						}
						//2020.01.23 MKSONG 보고서 열기 오류 수정 DOGFOOT
						if (weighted.PointLabelOptions && typeof weighted.PointLabelOptions.ShowCustomTextColor === 'undefined') {
							weighted.PointLabelOptions.ShowCustomTextColor = pointLabel.showCustomTextColor;
						}
						if (weighted.PointLabelOptions && typeof weighted.PointLabelOptions.CustomTextColor === 'undefined') {
							weighted.PointLabelOptions.CustomTextColor = pointLabel.customTextColor;
						}
						//2020.01.23 MKSONG 보고서 열기 오류 수정  끝 DOGFOOT
						found = true;
						return false;
					}
				});
			});
			// initialize format options from CHART_XML
			$.each(WISE.util.Object.toArray(this.RangeBarChart.DataItems.Measure), function(_i, _mea) {
				$.each(WISE.util.Object.toArray(webChartDataElement.MEASURES), function(_k, _measure) {
					if (_mea.UniqueName === _measure.UNI_NM) {
						_mea.NumericFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
						_mea.NumericFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
						return false;
					}
				});
			});
		}
		if(this.RangeBarChart.HiddenMeasures != undefined) {
			this.RangeBarChart.HiddenMeasures.Measure = WISE.util.Object.toArray(this.RangeBarChart.HiddenMeasures.Measure);
			this.RangeBarChart.HiddenMeasures.Dimension = WISE.util.Object.toArray(this.RangeBarChart.HiddenMeasures.Dimension);
		}

		// default settings 기본값 맞춤
		if (!(this.RangeBarChart.ComponentName)) {
			this.RangeBarChart.ComponentName = this.ComponentName;
		}
		if (!(this.RangeBarChart.DataSource)) {
			this.RangeBarChart.DataSource = this.dataSourceId;
		}else if(this.RangeBarChart.DataSource = this.dataSourceId){
			this.RangeBarChart.DataSource = this.dataSourceId;
		}
		if (!(this.RangeBarChart.Name)) {
			this.RangeBarChart.Name = this.Name;
		}
		if (!(this.RangeBarChart.MemoText)) {
			this.RangeBarChart.MemoText = this.memoText;
		}
		if (this.RangeBarChart.InteractivityOptions) {
			if (!(this.RangeBarChart.InteractivityOptions.MasterFilterMode)) {
				this.RangeBarChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.RangeBarChart.InteractivityOptions.TargetDimensions)) {
				this.RangeBarChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.RangeBarChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.RangeBarChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.RangeBarChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.RangeBarChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.RangeBarChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (!(this.RangeBarChart.IsMasterFilterCrossDataSource)) {
			this.RangeBarChart.IsMasterFilterCrossDataSource = false;
		}
		if (!(this.RangeBarChart.FilterString)) {
			this.RangeBarChart.FilterString = [];
		}else{
			this.RangeBarChart.FilterString = JSON.parse(JSON.stringify(this.RangeBarChart.FilterString).replace(/"@null"/gi,null));
		}
		if (this.RangeBarChart.ShowCaption == undefined) {
			this.RangeBarChart.ShowCaption = true;
		}
		if (!(this.RangeBarChart.Rotated)) {
			this.RangeBarChart.Rotated = false;
		}
		var page = window.location.pathname.split('/');
		if (!(this.RangeBarChart.AxisX)) {
			this.RangeBarChart.AxisX = {
				Visible: true,
				Title: '',
				Rotation: 0
			};
			if(gDashboard.reportType === 'DashAny' && typeof chartDataElement.AXISX_OPTION !== 'undefined') {
				self.RangeBarChart.AxisX.Rotation = chartDataElement.AXISX_OPTION.AXISX_ANGLE;
			}
		}else{
			if(gDashboard.reportType === 'DashAny') {
				self.RangeBarChart.AxisX.Visible = this.RangeBarChart.AxisX.Visible;
				self.RangeBarChart.AxisX.Title = this.RangeBarChart.AxisX.Title;
				self.RangeBarChart.AxisX.Rotation = this.RangeBarChart.AxisX.Rotation;
				if (typeof chartDataElement.AXISX_OPTION !== 'undefined') {
					self.RangeBarChart.AxisX.Rotation = chartDataElement.AXISX_OPTION.AXISX_ANGLE;
				}
			}else{
				if(WISE.Constants.editmode != 'viewer'){
					if(gDashboard.structure.chartXml.AXISX_MAJOR_GRID_ENABLED != undefined){
						self.RangeBarChart.AxisX.Visible = gDashboard.structure.chartXml.AXISX_MAJOR_GRID_ENABLED != undefined ? gDashboard.structure.chartXml.AXISX_MAJOR_GRID_ENABLED : this.RangeBarChart.AxisX.Visible;
						gDashboard.structure.chartXml.AXISX_MAJOR_GRID_ENABLED = undefined;	
					}	
				}else{
					if(gDashboard.structure.ReportMasterInfo.chartJson != undefined){
						if(gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML.AXISX_MAJOR_GRID_ENABLED != undefined){
							self.RangeBarChart.AxisX.Visible = gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML.AXISX_MAJOR_GRID_ENABLED != undefined ? gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML.AXISX_MAJOR_GRID_ENABLED : this.RangeBarChart.AxisX.Visible;
							gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML.AXISX_MAJOR_GRID_ENABLED = undefined;	
						}
					}
				}
			}
		}
		if(!(this.RangeBarChart.AxisY)) {
			if (!(this.RangeBarChart.Panes.Pane.AxisY)) {
				this.RangeBarChart.AxisY = {
					FormatType: 'Number',
					Unit: 'Ones',
					ShowZero: true,
					Visible: true,
					SuffixEnabled: false,
					MeasureFormat: {
						O: '',
						K: '천',
						M: '백만',
						B: '십억'
					},
					Precision: 0,
					precisionOption: '반올림',
					Separator: true
				};
				if(gDashboard.reportType === 'DashAny' && typeof chartDataElement.PANE_ELEMENT !== 'undefined'){
					self.RangeBarChart.AxisY = {
						FormatType: 'Number',
						Unit: 'Ones',
						ShowZero: true,
						Visible: true,
						Title: "",
						SuffixEnabled: chartDataElement.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN === 'Y',
						MeasureFormat: {
							O: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_O !== 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_O : "",
							K: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_K !== 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_K : "천",
							M: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_M !== 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_M : "백만",
							B: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_B !== 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_B : "십억"
						},
						Precision: 0,
						precisionOption: '반올림',
						Separator: true
					};
				}
			} else {
				if(gDashboard.reportType == 'DashAny'){
					if(typeof chartDataElement.PANE_ELEMENT != 'undefined') {
						self.RangeBarChart.AxisY = {
							FormatType: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.FormatType != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.FormatType : 'Number',
							Unit: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Unit != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Unit : 'Ones',
							ShowZero: typeof self.RangeBarChart.Panes.Pane.AxisY.ShowZero != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.ShowZero : true,
							Visible: typeof self.RangeBarChart.Panes.Pane.AxisY.Visible != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.Visible : true,
							Title: typeof self.RangeBarChart.Panes.Pane.AxisY.Title != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.Title : '',
							SuffixEnabled: chartDataElement.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN === 'Y',
							MeasureFormat: {
								O: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_O != 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_O : "",
								K: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_K != 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_K : "천",
								M: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_M != 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_M : "백만",
								B: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_B != 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_B : "십억"
							},
							Precision: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Precision != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Precision : 0,
							PrecisionOption: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.PrecisionOption != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.PrecisionOption : '반올림',
							Separator: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.IncludeGroupSeparator != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.IncludeGroupSeparator : true
						};
					} else {
						self.RangeBarChart.AxisY = {
							FormatType: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.FormatType != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.FormatType : 'Number',
							Unit: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Unit != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Unit : 'Ones',
							ShowZero: typeof self.RangeBarChart.Panes.Pane.AxisY.ShowZero != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.ShowZero : true,
							Visible: typeof self.RangeBarChart.Panes.Pane.AxisY.Visible != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.Visible : true,
							Title: typeof self.RangeBarChart.Panes.Pane.AxisY.Title != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.Title : '',
							SuffixEnabled: false,
							MeasureFormat: {
								O: '',
								K: '천',
								M: '백만',
								B: '십억'
							},
							Precision: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Precision != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Precision : 0,
							PrecisionOption: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.PrecisionOption != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.PrecisionOption : '반올림',
							Separator: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.IncludeGroupSeparator != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.IncludeGroupSeparator : true
						};
					}
				}else{
					if(gDashboard.structure.chartXml.AXISY_MAJOR_GRID_ENABLED != undefined){
						self.RangeBarChart.AxisY.Visible = gDashboard.structure.chartXml.AXISY_MAJOR_GRID_ENABLED != undefined ? gDashboard.structure.chartXml.AXISY_MAJOR_GRID_ENABLED : this.RangeBarChart.AxisY.Visible;
						gDashboard.structure.chartXml.AXISY_MAJOR_GRID_ENABLED = undefined;	
					}
				}
			}
		}
		if (this.RangeBarChart.ChartLegend) {
			var chartLegend = {
				Visible: typeof this.RangeBarChart.ChartLegend.Visible !== 'undefined' ? this.RangeBarChart.ChartLegend.Visible : true,
				IsInsidePosition: typeof this.RangeBarChart.ChartLegend.IsInsidePosition !== 'undefined' ? this.RangeBarChart.ChartLegend.IsInsidePosition : false,
				InsidePosition: typeof this.RangeBarChart.ChartLegend.InsidePosition !== 'undefined' ? this.RangeBarChart.ChartLegend.InsidePosition : 'TopRightHorizontal',
				OutsidePosition: typeof this.RangeBarChart.ChartLegend.OutsidePosition !== 'undefined' ? this.RangeBarChart.ChartLegend.OutsidePosition : 'TopRightHorizontal'
			};
			this.RangeBarChart.ChartLegend = chartLegend;
		} else {
			this.RangeBarChart.ChartLegend = {
				Visible: true,
				IsInsidePosition: false,
				InsidePosition: 'TopRightHorizontal',
				OutsidePosition: 'TopRightHorizontal'
			};
		}
		if (!(this.RangeBarChart.Animation)) {
			if(typeof chartDataElement.ANIMATION !== 'undefined'){
				this.RangeBarChart.Animation = chartDataElement.ANIMATION;
			}else{
				this.RangeBarChart.Animation = 'easeOutCubic';
			}
		}
		if (!(this.RangeBarChart.SeriesType)) {
			this.RangeBarChart.SeriesType = 'bar';
		}
		if (!(this.RangeBarChart.Palette)) {
			this.RangeBarChart.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			if (typeof dataElement.PALETTE_NM !== 'undefined') {
				self.RangeBarChart.Palette = dataElement.PALETTE_NM;
			}
			if(typeof this.meta.ColorSheme != 'undefined'){
				var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
				this.RangeBarChart.Palette = [];
				var newPalette = [];
				$.each(colorList,function(_i,_list){
					self.RangeBarChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
					newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
				});
				self.customPalette = newPalette;
				self.isCustomPalette = true;
			}
		}
		this.meta = this.RangeBarChart;
	};
	
	this.setRangeBarChartForViewer = function() {
		this.RangeBarChart=this.meta;

		var chartDataElement = {};
		var dataElement = {};
		var webChartDataElement = {};
		if(gDashboard.reportType == 'AdHoc'){
			this.meta = this.RangeBarChart = {};
			this.meta.ComponentName  = this.RangeBarChart.ComponentName = this.ComponentName;
			this.meta.DataSource = this.RangeBarChart.DataSource = this.dataSourceId;
			this.meta.DataItems = this.RangeBarChart.DataItems = {};
			if(gDashboard.structure.ReportMasterInfo.reportJson != undefined){
				if(gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT != undefined){
					this.meta.Name = this.RangeBarChart.Name = gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT.CHART_TITLE == undefined ? "차트" : gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT.CHART_TITLE;
				}
				if(gDashboard.structure.ReportMasterInfo.reportJson.WEB != undefined){
					this.meta.MemoText = this.RangeBarChart.MemoText = this.memoText = gDashboard.structure.ReportMasterInfo.reportJson.WEB.MEMO_ELEMENT.CHART_MEMO == undefined ? "" : gDashboard.structure.ReportMasterInfo.reportJson.WEB.MEMO_ELEMENT.CHART_MEMO
				
				}else{
					this.meta.MemoText = this.RangeBarChart.MemoText = this.memoText = "";	
				}
			}
			var gridElement = gDashboard.structure.ReportMasterInfo.reportJson.GRID_ELEMENT ? WISE.util.Object.toArray(gDashboard.structure.ReportMasterInfo.reportJson.GRID_ELEMENT.GRID) : [];
			var chartElement = gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML ? gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML : {};
			var sortlist = gDashboard.structure.ReportMasterInfo.reportJson.DATASORT_ELEMENT ? WISE.util.Object.toArray(gDashboard.structure.ReportMasterInfo.reportJson.DATASORT_ELEMENT.DATA_SORT) : [];
			var CU = WISE.libs.Dashboard.item.ChartUtility;
			
			this.RangeBarChart.DataItems.Dimension = [];
			this.RangeBarChart.DataItems.Measure = [];
			$.each(gridElement,function(_i,_e){
				if(_e.TYPE == 11){
					var NumericFormat = _e.FORMAT_STRING;
					var dataItem = {'DataMember': {}, 'UniqueName': ""};
					dataItem.DataMember = _e.CAPTION;
					dataItem.Name = _e.CAPTION;
					dataItem.UniqueName = _e.UNI_NM;
					dataItem.UNI_NM = _e.UNI_NM;
					dataItem.NumericFormat = NumericFormat;
					dataItem['SortOrder'] = 'asc';
					$.each(sortlist,function(_k,_sort){
						if(_e.UNI_NM == _sort.BASE_FLD_NM || _e.UNI_NM == _sort.BASE_FIELD_NM){
							dataItem.SortOrder = _sort.SORT_MODE == 'ASC' ? 'ascending' : 'descending';
						}
					});
					self.RangeBarChart.DataItems.Measure.push(dataItem);
					self.measures.push(dataItem);
				}else if(_e.TYPE == 10){
					var dataItem = {'DataMember': {}, 'UniqueName': ""};
					dataItem.DataMember = _e.CAPTION;
					dataItem.Name =  _e.CAPTION;
					dataItem.UniqueName = _e.UNI_NM;
					dataItem.UNI_NM = _e.UNI_NM;
					dataItem.SortOrder = 'asc';
					$.each(sortlist,function(_k,_sort){
						if(_e.UNI_NM == _sort.SORT_FLD_NM || _e.UNI_NM == _sort.SORT_FIELD_NM){
							dataItem.SortByMeasure = _sort.BASE_FLD_NM == undefined ? _sort.BASE_FIELD_NM : _sort.BASE_FLD_NM;
							dataItem.SortOrder = _sort.SORT_MODE == 'ASC' ? 'ascending' : 'descending';
						}
					});
					
					self.RangeBarChart.DataItems.Dimension.push(dataItem);
					self.dimensions.push(dataItem);
				}
			});
			this.meta.Values = this.RangeBarChart.Values = {Value:gDashboard.structure.ReportMasterInfo.reportJson.DATA_ELEMENT ? WISE.util.Object.toArray(gDashboard.structure.ReportMasterInfo.reportJson.DATA_ELEMENT.DATA) : []};
			this.meta.Rows = this.RangeBarChart.Rows = {Row:gDashboard.structure.ReportMasterInfo.reportJson.ROW_ELEMENT ? WISE.util.Object.toArray(gDashboard.structure.ReportMasterInfo.reportJson.ROW_ELEMENT.ROW) : []};
			this.meta.Columns = this.RangeBarChart.Columns = {Column:gDashboard.structure.ReportMasterInfo.reportJson.COL_ELEMENT ? WISE.util.Object.toArray(gDashboard.structure.ReportMasterInfo.reportJson.COL_ELEMENT.COL) : []};
			
			this.Panes = {};
			this.arguments = [];
	    	this.seriesDimensions = [];
	    	
			this.Panes.Pane = {'Name':"창 1", 'Series':{'Simple':[]}};			
			for (var i = 1; i <= this.RangeBarChart.Values.Value.length; i++) {
				var uniqueName = chartElement['SERIES' + i + '_UNI_NM'],
					seriesType = CU.Series.Simple.getChartName(chartElement['SERIES' + i + '_CHART_TYPE']),
					secondaryAxis = chartElement['SERIES' + i + '_AXISY2'],
					Value = {
						Value: {
							UniqueName: (typeof uniqueName !== 'undefined' && uniqueName.length > 0) ? uniqueName : self.RangeBarChart.Values.Value[i - 1].UNI_NM
						},
						SeriesType: typeof seriesType !== 'undefined' ? seriesType : 'Bar',
						PlotOnSecondaryAxis: typeof secondaryAxis !== 'undefined' ? secondaryAxis : false,
						IgnoreEmptyPoints: false,
						ShowPointMarkers: true,
//						PointLabelOptions: {
//							Orientation: '',
//							ContentType: 'Value',
//							OverlappingMode: 'Hide',
//							ShowForZeroValues: false,
//							Position: 'Outside',
//							FillBackground: false,
//							ShowBorder: false,
//							ShowCustomTextColor: false,
//							CustomTextColor: '#000000'
//						}
					};
				self.Panes.Pane.Series.Simple.push(Value);
			}
			
			this.Arguments = {'Argument' : []};
			_.each(this.meta.Rows.Row,function(_a){
				var Value = {'UniqueName' : _a.UNI_NM};
				self.Arguments.Argument.push(Value);
			})
			this.SeriesDimensions = {'SeriesDimension' : []};
			_.each(this.meta.Columns.Column,function(_s){
				var Value = {'UniqueName' : _s.UNI_NM};
				self.SeriesDimensions.SeriesDimension.push(Value);
			})
			
			this.RangeBarChart.Panes = self.Panes;
			this.RangeBarChart.SeriesDimensions = this.SeriesDimensions;
			this.RangeBarChart.Arguments = this.Arguments;
		} else {
			/* DOGFOOT ktkang 뷰어에서 X축 기울기 오류 수정 20191218*/
			this.RangeBarChart.ComponentName = this.meta.ComponentName;
			this.RangeBarChart.DataSource = this.meta.dataSourceId != undefined ? this.meta.dataSourceId:this.meta.DataSource;
			this.RangeBarChart.Name = this.meta.Name;
			// load CHART_XML
			var tempCDE, tempDE, tempWCDE;
			var page = window.location.pathname.split('/');
			if (typeof gDashboard.structure.MapOption.DASHBOARD_XML !== 'undefined') {
				tempCDE =  WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.CHART_DATA_ELEMENT);
				tempDE = WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DATA_ELEMENT);
				tempWCDE = gDashboard.structure.MapOption.DASHBOARD_XML.WEB ? WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT) : [];
			} else {
				tempCDE = [];
				tempDE = [];
				tempWCDE = [];
			}
			$.each(tempCDE,function(_i,_e){
				var CtrlNM = _e.CTRL_NM +"_"+WISE.Constants.pid;
				if(CtrlNM == self.ComponentName){
					chartDataElement = _e;
					return false;
				}
			});
			$.each(tempDE,function(_i,_e){
				var CtrlNM = _e.CTRL_NM +"_"+WISE.Constants.pid;
				if(CtrlNM == self.ComponentName){
					dataElement = _e;
					return false;
				}
			});
			$.each(tempWCDE,function(_i,_e){
				var CtrlNM = _e.CTRL_NM +"_"+WISE.Constants.pid;
				if(CtrlNM == self.ComponentName){
					webChartDataElement = _e;
					return false;
				}
			});
			// initialize format options from CHART_XML
			$.each(WISE.util.Object.toArray(this.RangeBarChart.DataItems.Measure), function(_i, _mea) {
				$.each(WISE.util.Object.toArray(webChartDataElement.MEASURES), function(_k, _measure) {
					if (_mea.UniqueName === _measure.UNI_NM) {
						_mea.NumericFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
						_mea.NumericFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
						return false;
					}
				});
			});
			// set point label options from CHART_XML
			$.each(WISE.util.Object.toArray(this.RangeBarChart.DataItems.Measure), function(mIndex, measure) {
				var uniqueName = measure.UniqueName;
				var pointLabel = {};
				var found = false;
				if (typeof chartDataElement.PANE_ELEMENT !== 'undefined') {
					$.each(WISE.util.Object.toArray(chartDataElement.PANE_ELEMENT.SERIES_ELEMENT), function(sIndex, series) {
						if (series.UNI_NM === uniqueName) {
							pointLabel = {
								fillBackground: series.SERIES_BACK_COLOR_VISIBLE === 'Y',
								showBorder: series.SERIES_BORDER_VISIBLE === 'Y',
								showCustomTextColor: series.SERIES_FONT_COLOR_YN === 'Y',
								customTextColor: typeof series.SERIES_FONT_COLOR !== 'undefined' ? gDashboard.itemColorManager.getHexColor(series.SERIES_FONT_COLOR) : '#000000'
							};
							return false;
						}
					});
				}
				$.each(WISE.util.Object.toArray(self.RangeBarChart.Panes.Pane.Series.Simple), function(j, simple) {
					if (simple.Value.UniqueName === uniqueName) {
						if (simple.PointLabelOptions && typeof simple.PointLabelOptions.FillBackground === 'undefined') {
							simple.PointLabelOptions.FillBackground = pointLabel.fillBackground;
						}
						if (simple.PointLabelOptions && typeof simple.PointLabelOptions.ShowBorder === 'undefined') {
							simple.PointLabelOptions.ShowBorder = pointLabel.showBorder;
						}
						if (simple.PointLabelOptions && typeof simple.PointLabelOptions.ShowCustomTextColor === 'undefined') {
							simple.PointLabelOptions.ShowCustomTextColor = pointLabel.showCustomTextColor;
						}
						if (simple.PointLabelOptions && typeof simple.PointLabelOptions.CustomTextColor === 'undefined') {
							simple.PointLabelOptions.CustomTextColor = pointLabel.customTextColor;
						}
						found = true;
						return false;
					}
				});
				if (found) {
					return true;
				}
				$.each(WISE.util.Object.toArray(self.RangeBarChart.Panes.Pane.Series.Weighted), function(j, weighted) {
					if (weighted.Value.UniqueName === uniqueName) {
						if (weighted.PointLabelOptions && typeof weighted.PointLabelOptions.FillBackground === 'undefined') {
							weighted.PointLabelOptions.FillBackground = pointLabel.fillBackground;
						}
						if (weighted.PointLabelOptions && typeof weighted.PointLabelOptions.ShowBorder === 'undefined') {
							weighted.PointLabelOptions.ShowBorder = pointLabel.showBorder;
						}
						if (weighted.PointLabelOptions && typeof weighted.PointLabelOptions.ShowCustomTextColor === 'undefined') {
							weighted.PointLabelOptions.ShowCustomTextColor = pointLabel.showCustomTextColor;
						}
						if (weighted.PointLabelOptions && typeof weighted.PointLabelOptions.CustomTextColor === 'undefined') {
							weighted.PointLabelOptions.CustomTextColor = pointLabel.customTextColor;
						}
						found = true;
						return false;
					}
				});
			});
		}
		if (this.RangeBarChart.InteractivityOptions) {
			if (!(this.RangeBarChart.InteractivityOptions.MasterFilterMode)) {
				this.RangeBarChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.RangeBarChart.InteractivityOptions.TargetDimensions)) {
				this.RangeBarChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.RangeBarChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.RangeBarChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.RangeBarChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.RangeBarChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.RangeBarChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (!(this.RangeBarChart.IsMasterFilterCrossDataSource)) {
			this.RangeBarChart.IsMasterFilterCrossDataSource = false;
		}
		if (this.RangeBarChart.ShowCaption == undefined) {
			this.RangeBarChart.ShowCaption = true;
		}
		if (!(this.RangeBarChart.Rotated)) {
			this.RangeBarChart.Rotated = false;
		}
		var page = window.location.pathname.split('/');
		if (!(this.RangeBarChart.AxisX)) {
			this.RangeBarChart.AxisX = {
				Visible: true,
				Title: '',
				Rotation: 0
			};
			if(gDashboard.reportType === 'DashAny' && typeof chartDataElement.AXISX_OPTION !== 'undefined') {
				self.RangeBarChart.AxisX.Rotation = chartDataElement.AXISX_OPTION.AXISX_ANGLE;
			}
		}else{
			if(gDashboard.reportType === 'DashAny') {
				self.RangeBarChart.AxisX.Visible = this.RangeBarChart.AxisX.Visible;
				self.RangeBarChart.AxisX.Title = this.RangeBarChart.AxisX.Title;
				self.RangeBarChart.AxisX.Rotation = this.RangeBarChart.AxisX.Rotation;
				if (typeof chartDataElement.AXISX_OPTION !== 'undefined') {
					self.RangeBarChart.AxisX.Rotation = chartDataElement.AXISX_OPTION.AXISX_ANGLE;
				}
			}
		}
		if(!this.RangeBarChart.AxisY) {
			if (!(this.RangeBarChart.Panes.Pane.AxisY)) {
				this.RangeBarChart.AxisY = {
					FormatType: 'Number',
					Unit: 'Ones',
					ShowZero: true,
					Visible: true,
					SuffixEnabled: false,
					MeasureFormat: {
						O: '',
						K: '천',
						M: '백만',
						B: '십억'
					},
					Precision: 0,
					PrecisionOption: '반올림',
					Separator: true
				};
				if(gDashboard.reportType === 'DashAny' && typeof chartDataElement.PANE_ELEMENT !== 'undefined'){
					self.RangeBarChart.AxisY = {
						FormatType: 'Number',
						Unit: 'Ones',
						ShowZero: true,
						Visible: true,
						Title: "",
						SuffixEnabled: chartDataElement.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN === 'Y',
						MeasureFormat: {
							O: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_O !== 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_O : "",
							K: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_K !== 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_K : "천",
							M: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_M !== 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_M : "백만",
							B: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_B !== 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_B : "십억"
						},
						Precision: 0,
						PrecisionOption: '반올림',
						Separator: true
					};
				}
			} else {
				if(gDashboard.reportType == 'DashAny'){
					if(typeof chartDataElement.PANE_ELEMENT != 'undefined') {
						self.RangeBarChart.AxisY = {
							FormatType: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.FormatType != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.FormatType : 'Number',
							Unit: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Unit != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Unit : 'Ones',
							ShowZero: typeof self.RangeBarChart.Panes.Pane.AxisY.ShowZero != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.ShowZero : true,
							Visible: typeof self.RangeBarChart.Panes.Pane.AxisY.Visible != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.Visible : true,
							Title: typeof self.RangeBarChart.Panes.Pane.AxisY.Title != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.Title : '',
							SuffixEnabled: chartDataElement.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN === 'Y',
							MeasureFormat: {
								O: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_O != 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_O : "",
								K: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_K != 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_K : "천",
								M: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_M != 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_M : "백만",
								B: typeof chartDataElement.PANE_ELEMENT.AXISY_UNIT_B != 'undefined' ? chartDataElement.PANE_ELEMENT.AXISY_UNIT_B : "십억"
							},
							Precision: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Precision != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Precision : 0,
							PrecisionOption: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.PrecisionOption != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.PrecisionOption : '반올림',
							Separator: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.IncludeGroupSeparator != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.IncludeGroupSeparator : true
						};
					} else {
						self.RangeBarChart.AxisY = {
							FormatType: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.FormatType != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.FormatType : 'Number',
							Unit: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Unit != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Unit : 'Ones',
							ShowZero: typeof self.RangeBarChart.Panes.Pane.AxisY.ShowZero != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.ShowZero : true,
							Visible: typeof self.RangeBarChart.Panes.Pane.AxisY.Visible != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.Visible : true,
							Title: typeof self.RangeBarChart.Panes.Pane.AxisY.Title != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.Title : '',
							SuffixEnabled: false,
							MeasureFormat: {
								O: '',
								K: '천',
								M: '백만',
								B: '십억'
							},
							Precision: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Precision != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.Precision : 0,
							PrecisionOption: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.PrecisionOption != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.PrecisionOption : '반올림',
							Separator: typeof self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.IncludeGroupSeparator != 'undefined' ? self.RangeBarChart.Panes.Pane.AxisY.NumericFormat.IncludeGroupSeparator : true
						};
					}
				}
			}
		}
		if (!(this.RangeBarChart.FilterString)) {
			this.RangeBarChart.FilterString = [];
		}else{
			this.RangeBarChart.FilterString = JSON.parse(JSON.stringify(this.RangeBarChart.FilterString).replace(/"@null"/gi,null));
		}
		if (this.RangeBarChart.ChartLegend) {
			var chartLegend = {
				Visible: typeof this.RangeBarChart.ChartLegend.Visible !== 'undefined' ? this.RangeBarChart.ChartLegend.Visible : true,
				IsInsidePosition: typeof this.RangeBarChart.ChartLegend.IsInsidePosition !== 'undefined' ? this.RangeBarChart.ChartLegend.IsInsidePosition : false,
				InsidePosition: typeof this.RangeBarChart.ChartLegend.InsidePosition !== 'undefined' ? this.RangeBarChart.ChartLegend.InsidePosition : 'TopRightHorizontal',
				OutsidePosition: typeof this.RangeBarChart.ChartLegend.OutsidePosition !== 'undefined' ? this.RangeBarChart.ChartLegend.OutsidePosition : 'TopRightHorizontal'
			};
			this.RangeBarChart.ChartLegend = chartLegend;
		} else {
			this.RangeBarChart.ChartLegend = {
				Visible: true,
				IsInsidePosition: false,
				InsidePosition: 'TopRightHorizontal',
				OutsidePosition: 'TopRightHorizontal'
			}
		}
		if (!(this.RangeBarChart.SeriesType)) {
			this.RangeBarChart.SeriesType = 'bar';
		}
		if (!(this.RangeBarChart.Animation)) {
			if(typeof chartDataElement.ANIMATION !== 'undefined'){
				this.RangeBarChart.Animation = chartDataElement.ANIMATION;
			}else{
				this.RangeBarChart.Animation = 'easeOutCubic';
			}
		}
		if (!(this.RangeBarChart.Palette)) {
			this.RangeBarChart.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			if (typeof dataElement.PALETTE_NM !== 'undefined') {
				self.RangeBarChart.Palette = dataElement.PALETTE_NM;
			}
			if(typeof this.meta.ColorSheme != 'undefined'){
				var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
				this.RangeBarChart.Palette = [];
				var newPalette = [];
				$.each(colorList,function(_i,_list){
					self.RangeBarChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
					newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
				});
				self.customPalette = newPalette;
				self.isCustomPalette = true;
			}
		}
		this.meta = this.RangeBarChart;
	};
	
	/**
	 * Assign data to the ChartGenerator object.
	 * @param _data Data to bind to ChartGenerator
	 * @param _options Iff true, generate chart without initializing fields.
	 * @param _overwrite Iff true, overwrite global data instance with _data.
	 * 
	 */
	this.bindData = function(_data, _options, _overwrite) {
		//2020.01.30 mksong query sqlike에서 한번만 돌게 하기 위해 수정 dogfoot
//		if (_overwrite) {
//			this.globalData = _data;
//		}
//        if (!this.tracked) {
//			if(this.globalData == undefined){
//				this.globalData = _.clone(_data);	
//			}
//			this.filteredData = _.clone(_data);
//		}
//		if (this.meta && this.meta.FilterString && this.meta.FilterString.length > 0) {
//			var newDataSource = new DevExpress.data.DataSource({
//			    store: _data,
//			    paginate: false
//			});
//			newDataSource.filter(this.meta.FilterString);
//			newDataSource.load();
//			self.filteredData = newDataSource.items();
//		}
//		this.enableButtons(_data);
		/*DOGFOOT cshan 20200113 - 한계이상의 열이 놓이면 범례가 안그려지는 문제를 경고창으로 경고*/
		self.errorCheck = false;
//		$("#" + this.itemid).empty();
		
		//2020.01.30 mksong query sqlike에서 한번만 돌게 하기 위해 수정 dogfoot
//		if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
//			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
//			$("#" + this.itemid).children('svg').css('display','none');
//			$("#" + this.itemid).append(nodataHtml);
//		}
//		else {
			this.renderChart(_options);
//			$("#" + this.itemid).children('.nodata-layer').remove();
//			$("#" + this.itemid).children('svg').css('display','block');
			/*
			 * 밑의 refresh()를 하는 이유는 시리즈 오름/내림차순을 변경하면 색상만 변하고 차트 바의 크기가 바뀌지 않기 때문에 해준거임  
			 * 또한, 필터 편집으로 데이터를 없앤 후 필터 초기화하면 아무 작동도 안해서 보이고 숨기기로 처리 및 위치 재조정 때문
			 * */
			if(gDashboard.reportType != 'AdHoc' || !(gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer')){
				if(self.dxItem){
					switch (DevExpress.VERSION) {
						case '17.2.13':
							self.dxItem.render();
							break;
						default:
							self.dxItem.refresh();
					}
				}
			}
//		}
		//2020.01.30 mksong query sqlike에서 한번만 돌게 하기 위해 수정 끝 dogfoot
	};
	
	this.bindDataForRefresh = function(_tempData) {
		this.enableButtons(this.filteredData);
		
//		$("#" + this.itemid).empty();
		
		if (!this.filteredData || ($.type(this.filteredData) === 'array' && this.filteredData.length === 0)) {
			var nodataHtml = '<div class="nodata-layer"></div>';
			$("#" + this.itemid).empty().append(nodataHtml);
		}
		else {
			this.renderChart();
		}
	};
	
	/**
	 * Gather fields, configure data, initialize chart options, and draw the chart.
	 * @param _options Iff true, generate chart without initializing fields.
	 */
	this.renderChart = function(_options) {		
		var _functionDo;
		if(typeof _options == 'boolean'){
			_functionDo = _options;
		}
		
		if (this.seriesTypeSelector && _options === undefined) {
			this.seriesTypeSelector.option('value', '');
		}
		
		if (this.selectedChartType) {
			_options = !_options ? {} : _options;
			_options.seriesType = this.selectedChartType;
		}
		
		if(_functionDo){
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}else if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setRangeBarChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.RangeBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RangeBarChart);
		}
		else if(self.fieldManager) { // 레포트 열기
			if (!($.isEmptyObject(self.RangeBarChart))) {
				this.fieldManager.seriesType = stylizedChartTypes[self.RangeBarChart.SeriesType];
				this.fieldManager.previousPanes = self.RangeBarChart.Panes;
				gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type, self.isAdhocItem);
			}else{
				if(gDashboard.reportType != 'AdHoc' && self.isAdhocItem){
					self.fieldManager.initialized = false;	
				}
			}
			this.setRangeBarChartForOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.RangeBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RangeBarChart);
		}
		else if(self.meta && $.isEmptyObject(self.RangeBarChart)) {
			this.setRangeBarChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.RangeBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RangeBarChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setRangeBarChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.RangeBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RangeBarChart);
		}
		else if(self.populated == true && gDashboard.reportType == 'AdHoc'){
			gDashboard.itemGenerateManager.itemCustomize(self,self.RangeBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.RangeBarChart);
			self.populated = false;
		}
		
		/* DOGFOOT ktkang 측정값이 없을 때 로딩바 사라지지 않는 현상 수정  20200619 */
		if(this.measures.length == 0) {
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}
			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.hide();
				gDashboard.updateReportLog();
			}
		}
		
		var queriedData, seriesDimensionColumnNames;
		var dataSet = this.__getRangeBarChartData();
		
		//2020.01.30 mksong query sqlike에서 한번만 돌게 하기 위해 수정 dogfoot
		if ($.type(dataSet) === 'array') {
			queriedData = dataSet;
		}
		else {
			queriedData = dataSet.data;
			seriesDimensionColumnNames = dataSet.seriesDimensionColumnNames;
		}
		self.chartData = queriedData;
		// render empty chart if there is no data or measures
		
		//2020.01.30 mksong query sqlike에서 한번만 돌게 하기 위해 수정 dogfoot
		if (this.measures.length === 0) {
//		if (queriedData.length === 0 || this.measures.length === 0) {			
			self.dxItem = $('#' + this.itemid).dxChart(
				{
					dataSource: [], 
					series: [], 
					valueAxis: [], 
					commonAxisSettings: {
						grid: {
							visible: false
						}
					}
				}
			).dxChart('instance');
			return;
		}
		
		// initialize dxConfig 
		var dxConfigs = this.getDxItemConfig(this.meta);
		
		DevExpress.config({ defaultCurrency: 'KRW' });

		// initialize Y axis
		var yCount = 0;
		var y2Count = 0;
		$.each(this.P, function(_i, _pane) {
			var pane = {
				name: _i === 0 ? 'default' : _pane.Name.replace(/\s/g,'')
			};
			dxConfigs.panes.push(pane);
			var iAxisY = _pane.AxisY || {},
				iSecondaryAxisY = _pane.SecondaryAxisY || {},
				yName = '',
				yDataItem = '',
				y2Name = '',
				y2DataItem = '',
				yFormat,
				yUnit,
				yShowZero,
				yVisible,
				yLabelPrecision,
				yLabelPrecisionOption,
				ySeparator,
				ySuffix,
				ySuffixEnabled;
			// Y axis count
			$.each(WISE.util.Object.toArray(_pane.Series.Simple), function(_seriesI, _seriesPane) {
				if(_seriesPane.PlotOnSecondaryAxis) {
					y2Count++;
					y2DataItem = _seriesPane.Value.UniqueName;
				}
				else{
					yCount++;
					yDataItem = _seriesPane.Value.UniqueName;
				}
			});
			$.each(WISE.util.Object.toArray(_pane.Series.Weighted), function(_seriesI, _seriesPane) {
				if(_seriesPane.PlotOnSecondaryAxis) {
					y2Count++;
					y2DataItem = _seriesPane.Value.UniqueName;
				}
				else{
					yCount++;
					yDataItem = _seriesPane.Value.UniqueName;
				}
			});
			// Y axis default title
			/* DOGFOOT ktkang 차트 Y축 이름 다시 조회 시 초기화 오류 수정   20200228 */
			if(typeof self.RangeBarChart.AxisY.TitleRename == 'undefined' || !self.RangeBarChart.AxisY.TitleRename) {
				if (yCount === 1) {
					$.each(self.meta.DataItems.Measure,function(i, e) {
						if(e.UniqueName === yDataItem) {
							if (typeof e.Name !== 'undefined') {
								yName = e.Name;
							}
							else {
								yName = e.DataMember;
							}
							return false;
						}
					});
				} else {
					yName = '값';
				}
				// Secondary Y axis default title
				if (y2Count === 1) {
					$.each(self.meta.DataItems.Measure, function(i, e) {
						if (e.UniqueName === y2DataItem) {
							if (typeof e.Name !== 'undefined') {
								y2Name = e.Name;
							} else {
								y2Name = e.DataMember;
							}
							return false;
						}
					});
				} else {
					y2Name = '값';
				}
			}
			// Y axis custom title, visibility, precision
			/* DOGFOOT ktkang Y축 이름 저장 오류 수정  20200130 */
			if (self.RangeBarChart.AxisY) {
				if ((typeof self.RangeBarChart.AxisY.TitleRename == 'undefined' || self.RangeBarChart.AxisY.TitleRename) && typeof self.RangeBarChart.AxisY.Title != 'undefined') {
					yName = self.RangeBarChart.AxisY.Title;
					/* DOGFOOT ktkang 차트 Y축 이름 다시 조회 시 초기화 오류 수정   20200228 */
				} else {
					self.RangeBarChart.AxisY.Title = yName;
					self.RangeBarChart.AxisY.TitleRename = false;
				}
				yFormat = self.RangeBarChart.AxisY.FormatType;
				yUnit = self.RangeBarChart.AxisY.Unit;
				yShowZero = self.RangeBarChart.AxisY.ShowZero === undefined? true : self.RangeBarChart.AxisY.ShowZero;
				yVisible = self.RangeBarChart.AxisY.Visible;
				yLabelPrecision = self.RangeBarChart.AxisY.Precision;
				yLabelPrecisionOption = self.RangeBarChart.AxisY.PrecisionOption;
				ySeparator = self.RangeBarChart.AxisY.Separator;
				ySuffixEnabled = self.RangeBarChart.AxisY.SuffixEnabled;
				ySuffix = self.RangeBarChart.AxisY.MeasureFormat;
			}
			// generate Y axis settings
			var axisY = {
				pane: pane.name,
				name: pane.name + '-DEFAULT-Y',
				position: 'left',
				// dx 18.1 and lower
//                min: 0,
				// dx 18.2+
				visualRange: {
					startValue: yShowZero ? 0 : null,
					endValue: null
				},
				visualRangeUpdateMode: 'keep',
				grid: {
					visible: true
				},
				title: {
					text: yVisible ? yName : '',
					font: gDashboard.fontManager.getDxItemAxisTitleFont()
				},
				visible: true,
				maxValueMargin : 0.1,
				valueType: 'numeric',
				inverted: iAxisY.Reverse,
				label: {
					font: gDashboard.fontManager.getDxItemLabelFont(),
					customizeText: function(e){
						return WISE.util.Number.unit(e.value, yFormat, yUnit, self.RangeBarChart.SeriesType.indexOf("fullstacked") > -1? yLabelPrecision > 0? yLabelPrecision : 1 : yLabelPrecision, ySeparator, undefined, ySuffix, ySuffixEnabled, yLabelPrecisionOption);
					},
					visible: yVisible,
					overlappingBehavior: {
						mode: 'rotate'
					}
				},
				showZero: false
			};
			// generate secondary Y axis settings
			var secondAxisY = {
				pane: pane.name,
				name: pane.name + '-SECONDARY-Y',
                position: 'right',
				// dx 18.1 and lower
//                min: 0,
				// dx 18.2+
				visualRange: {
					startValue: yShowZero ? 0 : null,
					endValue: null
				},
				visualRangeUpdateMode: 'keep',
				grid: { 
					visible: true
				},
				title: {
					text: yVisible ? y2Name : '',
					font: gDashboard.fontManager.getDxItemAxisTitleFont()
				},
				visible: true,
				maxValueMargin : 0.1,
				valueType: 'numeric',
				inverted: iSecondaryAxisY.Reverse,
				label: {
					font: gDashboard.fontManager.getDxItemLabelFont(),
					customizeText: function(e){
						var _seriesType = "";
						$.each(self.RangeBarChart.Panes.Pane.Series.Simple, function(_i, _series){
							if(_series.PlotOnSecondaryAxis){
								_seriesType = _series.SeriesType;
								return false;
							}
						})
						//console.log('e :',e);
						return WISE.util.Number.unit(e.value, yFormat, yUnit, _seriesType? _seriesType.indexOf("FullStacked") > -1? yLabelPrecision > 0? yLabelPrecision : 1 : yLabelPrecision : yLabelPrecision, ySeparator, undefined, self.RangeBarChart.AxisY.MeasureFormat, self.RangeBarChart.AxisY.SuffixEnabled, yLabelPrecisionOption);
					},
					visible: yVisible,
					overlappingBehavior: {
						mode: 'rotate'
					}
				},
				showZero: iSecondaryAxisY.ShowZero,
			};
			// add Y axis settings to item config
			if (yCount > 0) {
				dxConfigs.valueAxis.push(axisY);
			}
			if (y2Count > 0) {
				dxConfigs.valueAxis.push(secondAxisY);
			}
			// create series
			var seriesList = [];
			$.each(_pane['Series'], function(_seriesType, _serieses) {
				var seriesCreator;
				switch(_seriesType) {
				case 'Simple':
					seriesCreator = new WISE.libs.Dashboard.item.RangeBarChart.SimpleSeries();
					seriesCreator.seriesType = (_options && _options.seriesType) ? _options.seriesType : undefined;
					break;
				case 'Range':
					self.includedRangeSeries = true;
					seriesCreator = new WISE.libs.Dashboard.item.RangeBarChart.RangeSeries();
					break;
				case 'Weighted':
					seriesCreator = new WISE.libs.Dashboard.item.RangeBarChart.BubbleSeries();
					break;
				}
				seriesCreator.renderType = self.renderType;
				seriesCreator.pane = pane;
				seriesCreator.measures = self.measures;
				seriesCreator.measureMeta = self.DI.Measure;
				seriesCreator.seriesDimensions = self.seriesDimensions;
				
				seriesCreator.serieses = _serieses;
				seriesCreator.axis = {
					'Y': axisY,
					'SY': secondAxisY
				};
				$.each(WISE.util.Object.toArray(seriesCreator.serieses),function(_i,_seriesItems){
					if(typeof _seriesItems.ShowPointMarkers == 'boolean'){
						_seriesItems['point'] = {visible:_seriesItems.ShowPointMarkers};
					}
					if(typeof _seriesItems.IgnoreEmptyPoints == 'boolean'){
						_seriesItems['ignoreEmptyPoints'] = _seriesItems.IgnoreEmptyPoints;
					}
				});
				if (self.renderType === 'SERIESDIMENSIONS-ONLY' || self.renderType === 'ARGUMENTS-AND-SERIESDIMENSIONS') {
					seriesCreator.seriesDimensionColumnNames = seriesDimensionColumnNames;
				}
				var seriesElement = seriesCreator.getSeriesList();
				if(seriesElement.length>0)
					self.RangeBarChart['SeriesType'] = seriesElement[0].type;
				$.each(seriesElement,function(_i,_e){
					if(_e.type == 'area' || _e.type == "splinearea" ||  _e.type == "steparea"){
						self.tooltipData = queriedData;
						$.each(self.tooltipData,function(_i,_data){
							$.each(_data,function(_key,_val){
								if(_key.indexOf(_e.name) >-1){
									_data['name'] = _e.name;
									return false;
								}

							})
							
						});
					}
				});
				seriesList = seriesList.concat(seriesElement);
			});
			// order series by data item order
			$.each(WISE.util.Object.toArray(self.RangeBarChart.DataItems.Measure), function(mIndex, measure) {
				$.each(seriesList, function(_j, series) {
					if (measure.UniqueName === series.wiseUniqueName) {
						if(series.label.font){
							var font = gDashboard.fontManager.getDxItemLabelFont();
							series.label.font.size = font.size;
							series.label.font.family = font.family;
						}else
							series.label.font = gDashboard.fontManager.getDxItemLabelFont();
						
						dxConfigs.series = dxConfigs.series.concat(series);
					}
				});
			});
		}); // end of LOOP of Panes
		
		dxConfigs.dataSource = queriedData;
	
        
        //2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		self.dxItem = $("#" + this.itemid).dxChart(dxConfigs).dxChart('instance');
		
		self.IO && self.IO.IsDrillDownEnabled && self.initDrillDownOperation();
		

		if(!self.functionBinddata){
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}

			if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();	
				gDashboard.updateReportLog();
			}	
			
			/* DOGFOOT ktkang 다른 아이템에 측정값이 없으면 오류 수정  20200708 */
			if(this.measures.length == 0) {
				if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
				}
				if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
					gProgressbar.hide();
					gDashboard.updateReportLog();
				}
			}
		}else{
			/*dogfoot 차트 단일마스터 필터 선택시 다른 아이템 무한로딩 오류 수정 shlim 20200618*/
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}
			gProgressbar.hide();
			gDashboard.updateReportLog();
			self.functionBinddata = false;
		}
		
	};
	
	/* LSH topN
	 *  topN정렬을 위한 함수
	 * */
	 this.__getTopNsortData = function(queryData,dimensions,nowDim){
		var topnData = [];
		var topNarray = [];
		var sumNm;
		$.each(self.measures,function(_index,_item){
			if(_item.name == self.topMember){
				sumNm = _item.nameBySummaryType;
			}
		})
		$.each(queryData,function(_index,_e){
			var TopNdataArray = DevExpress.data.query(_e.items)  
				.groupBy(nowDim)  
				.select(function(dataItem) {  
					var resultItem = null;  
					DevExpress.data.query(dataItem.items)  
					.sum(sumNm)  
					.done(function(result) {  
						resultItem = {  
							key : dataItem.key,
							value: result  
						}  
					});  
					return resultItem;  
				})
				.sortBy("value",true);

			// 넘어온 데이터 그룹화 
			var ExecSyx = DevExpress.data.query(_e.items);
			ExecSyx = ExecSyx.groupBy(nowDim);
			topNarray = ExecSyx.toArray();

			// 그룹화된 데이터 TopN 정렬
			TopNdataArray = TopNdataArray.toArray();
			$.each(TopNdataArray, function(i, e) {
				$.each(topNarray, function(j, k) {
					if(e.key != undefined && e.key == k.key){
						topnData.push(k);
					}
				})
			});
        });					
		
        return topnData;
	}
	 
	/* LSH topN
	 *  topN정렬을 위한 함수
	 * */
	this.__getTopNData = function(queryData,dimensions,nowDim,_topEnabled){
		//넘어온 차원의 topN 유무
		var topBol = false;
		if(_topEnabled){
			topBol = true;
			for(var i = 0; i < self.dimensionTopN.length; i++){
				if(self.dimensionTopN[i].TopNEnabled===true && self.dimensionTopN[i].DataMember == nowDim){
					if(self.dimensionTopN[i].TopNCount > 0){
						self.topN = self.dimensionTopN[i].TopNCount;
						self.TopNMember = self.dimensionTopN[i].DataMember;
					}else{
						self.topN = 5;
						self.TopNMember = self.dimensionTopN[i].DataMember;
					}
					self.topMesure = self.dimensionTopN[i].TopNMeasure;
					self.otherShow = self.dimensionTopN[i].TopNShowOthers;
				}
			}
		}
		
		//topN순위 기준 측정값 계산
		var sumNm;
		$.each(self.measures,function(_index,_item){
			if(_item.uniqueName == self.topMesure){
				sumNm = _item.nameBySummaryType;
			}
		})
		
		/*sumNm = self.measures[0].nameBySummaryType*/
		var topnData = [];
		var otherData =[];
		var topNarray = [];
		var topNresult = [];
		var TopNExecSyx;
		var sortTopNdata;
		var TopNotherData;
		/*dogfoot 차원그룹 TopN 확인 부분 변경 shlim 20201223*/
		var seriesTopNCehck= false;
		
		//시리즈 차원 존재유무 //없을 시 기능 동작 x
		if (self.seriesDimensions != undefined){
			$.each(self.seriesDimensions,function(_i,_srDim){
				if(_srDim.name == nowDim && self.TopNMember != nowDim){
					seriesTopNCehck = true;
				}
			})
		}
		
		//넘어온 차원이 차원그룹이고 차원그룹이 topN이 아닐경우 현재 함수를 넘김 
		if(seriesTopNCehck){
			topnData = queryData;
		}else{
			
			$.each(queryData,function(_index,_e){
				//넘어온 차원이 topN 일 경우
				if(topBol){
					
					//topN이 걸린 차원을 가지고 측정값을 이용하여 정렬 계산
					var TopNdataArray = DevExpress.data.query(_e.items)  
					.groupBy(nowDim)  
					.select(function(dataItem) {  
						var resultItem = null;  
						DevExpress.data.query(dataItem.items)  
						.sum(sumNm)  
						.done(function(result) {  
							resultItem = {  
								key : dataItem.key,
								value: result  
							}  
						});  
						return resultItem;  
					})
					.sortBy("value",true);
					
					var dsdsdsd = TopNdataArray.toArray();
					
					//지정된 topN 값이 데이터의 길이보다 클 경우
					if(self.topN > _e.items.length){
						self.topN = _e.items.length;
					}
					//topN순위 만큼 자르기
					sortTopNdata = TopNdataArray.slice(0,self.topN)
					.toArray();
					
					// 넘어온 데이터 그룹화 
					var ExecSyx = DevExpress.data.query(_e.items);
					ExecSyx = ExecSyx.groupBy(nowDim);
					topNarray = ExecSyx.toArray();
					
					// 그룹화된 데이터 TopN 정렬
					var topOtherArray = topNarray;
					$.each(sortTopNdata, function(i, e) {
						$.each(topNarray, function(j, k) {
							if(e.key != undefined && e.key == k.key){
								topnData.push(k);
							}
						})
					});
					
					// topN 에 기타값 설정시
					if(self.otherShow){
						//topN순위 아래의 데이터
						TopNotherData = TopNdataArray.slice(self.topN,_e.items.length)
						.toArray();
						
						//기타 순위 데이터 계산
						otherData = [];
						$.each(TopNotherData, function(i, e) {
							$.each(topNarray, function(j, k) {
								if(e.key != undefined && e.key == k.key){
									otherData.push(k);
								}
							})
						});
						
						//차원명을 기타로 통일
						var otherDuple=[];
						$.each(otherData,function(_i,_e){
							$.each(_e.items,function(_j,_k){
								_k[nowDim]= '기타';
								otherDuple.push(_k); 
							}) 
						})
						
						//계산을 위한 형식맞추기
						var first=[];
						first.push({items:otherDuple});
						otherDuple = first;
						
						//기타값을 더하여 시리즈에 맞게 계산
						self.OtherCnt = 0;
						for(var i = 0; i <= dimensions.length; i++){
							var otherDim ;
							if(dimensions[i] == undefined){
								otherDim = 'end';
							}else{
								otherDim = dimensions[i].name;
							}
							
							otherDuple = self.__getOtherData(otherDuple,dimensions,otherDim);
							self.OtherCnt++;
						}
						
						topnData.push({items:otherDuple});
					}

					var topNarray=[];
					$.each(topnData,function(_i,_e){
						$.each(_e.items,function(_j,_k){
							topNarray.push(_k); 
						}) 
					})
                    
                    topnData=[];
					topnData.push({items:topNarray});

				}else{
					// 넘어온 차원값이 topN 이 아닐경우 데이터 그룹화
					topnData.push(_e);
				}	
			})
		}
        return topnData;
	}
	
	/* LSH topN
	   기타 값 계산을 위한 함수
	*/
	this.__getOtherData = function(otherDuple,dimensions,nowDim){
		var topnOtherData = [];
		var topNOtherarray = [];
		
		var sumNm =[];
		
		//topN순위 기준 측정값 계산
		$.each(self.measures,function(_i,_e){
			sumNm.push(_e.nameBySummaryType);
		})
		
		//기타값 계산
		$.each(otherDuple,function(_index,_e){
			//더이상 계산할 차원이 없을때
			if(self.OtherCnt==dimensions.length){
				
				var otherVal = _e.items[0];
				$.each(sumNm,function(_i,_sumNm){
					var resultItem = null;  
					DevExpress.data.query(_e.items)  
					.sum(_sumNm)  
					.done(function(result) {  
						resultItem = {  
							key : _e.key,
							value: result  
						}  
					});  
					otherVal[_sumNm] = resultItem.value;
				})
				
				topnOtherData.push(otherVal);
			}else{
				//차원이 뒤에 더 존재할때 기타값 그룹화
				var ExecSyx = DevExpress.data.query(_e.items);
				ExecSyx = ExecSyx.groupBy(nowDim);
				topNOtherarray = ExecSyx.toArray();
				$.each(topNOtherarray, function(i, e) {
					topnOtherData.push(e);
				});
			}
		})
        return topnOtherData;
	}
	
	this.renderButtons = function() {
	
		gDashboard.itemGenerateManager.renderButtons(self, self.isAdhoc);
	};
	
	this.initDataItemOptionsWindow = function(_e) {
		$('#seriesOptions').dxPopup({
			title: '시리즈 옵션',
			height: 'auto',
			width: 440,
			visible: true,
			showCloseButton: false,
			onContentReady: function(){
				gDashboard.fontManager.setFontConfigForOption('seriesOptions')
			},
			contentTemplate: function(contentElement) {
				contentElement.css('padding', '0');
				var html = 	'<div class="modal-inner">' +
								'<div class="modal-body">' +
									'<div class="tab-title focus">' +
										'<ul class="tab-m">' +
//											'<li rel="tabP1-1" id="defaultSeriesOptions"><a href="#">일반옵션</a></li>' +
											'<li rel="tabP1-1" id="pointSeriesOptions"><a href="#">포인트레이블 옵션</a></li>' +
										'</ul>' +
									'</div>' +
									'<div class="row">' +
										'<div class="column" style="width:100%;">' +
											'<div id="tabP1" class="tab-component">' +
//												'<div class="tabP1-1 tab-content">' +
//													'<div class="modal-article">' +
//														'<div class="tbl data-form">' +
//															'<table>' +
//																'<caption>일반옵션</caption>' +
//																'<colgroup><col style="width:140px"><col style="width:auto"></colgroup>' +
//																'<tbody>' +
//																	'<tr><th class="left">보조 축의 구성</th><td class="ipt"><input class="check" id="chk0" type="checkbox" name="check-set"><label for="chk0"></label></td></tr>' +
//																	'<tr><th class="left">빈 포인트 무시</th><td class="ipt"><input class="check" id="chk1" type="checkbox" name="check-set"><label for="chk1"></label></td></tr>' +
//																	'<tr><th class="left">포인트 마커 표시</th><td class="ipt"><input class="check" id="chk2" type="checkbox" name="check-set"><label for="chk2"></label></td></tr>' +
//																'</tbody>' +
//															'</table>' +
//														'</div>' +
//													'</div>' +
//												'</div>' +
												'<div class="tabP1-1 tab-content">' +
													'<div class="modal-article">' +
														'<div class="tbl data-form">' +
														'<table>' +
															'<caption>포인트레이블 옵션</caption>' +
															'<colgroup><col style="width:180px"><col style="width:auto"></colgroup>' +
															'<tbody>' +
																'<tr><th class="left">표기형식</th><td class="ipt">' +
																	'<select id="slct0">' +
																		'<option value="">없음</option>' +
																		'<option value="Argument">인수</option>' +
																		'<option value="SeriesName">측정값 명</option>' +
																		'<option value="Value">값</option>' +
																		'<option value="Argument, SeriesName">인수 및 측정값 명</option>' +
																		'<option value="Argument, Value">인수 및 값</option>' +
																		'<option value="SeriesName, Value">측정값 명 및 값</option>' +
																		'<option value="Argument, SeriesName, Value">인수, 측정값 명 및 값</option>' +
																	'</select>' +
																'</td></tr>' +
																'<tr><th class="left">겹침모드</th><td class="ipt"><select id="slct1"><option value="Hide">기본</option><option value="None">없음</option><option value="Reposition">중복 레이블 위치 변경</option></select></td></tr>' +
																'<tr><th class="left">방향</th><td class="ipt"><select id="slct2"><option value="">기본</option><option value="RotateLeft">왼쪽으로 회전</option><option value="RotateRight">오른쪽으로 회전</option></select></td></tr>' +
//																'<tr><th class="left">포인트 마커 표시</th><td class="ipt"><input class="check" id="chk2" type="checkbox" name="check-set"><label for="chk2"></label></td></tr>' +
															'</tbody>' +
														'</table>' +
													'</div>' +
												'</div>' +
												'<div class="modal-article">' +
													'<div class="modal-tit">' +
														'<span>막대옵션</span>' +
													'</div>' +
													'<div class="tbl data-form">' +
														'<table>' +
															'<caption>포인트레이블 옵션</caption>' +
															'<colgroup><col style="width:180px"><col style="width:auto"></colgroup>' +
															'<tbody>' +
																'<tr><th class="left">0값에 대한 표시</th><td class="ipt"><input class="check" id="chk3" type="checkbox" name="check-set"><label for="chk3"></label></td></tr>' +
																'<tr><th class="left">위치</th><td class="ipt"><select id="slct3"><option value="Outside">외부</option><option value="Inside">내부</option></select></td></tr>' +
																'<tr><th class="left">바탕색 표시</th><td class="ipt"><input class="check" id="chk4" type="checkbox" name="check-set"><label for="chk4"></label></td></tr>' +
																'<tr><th class="left">테두리 표시</th><td class="ipt"><input class="check" id="chk5" type="checkbox" name="check-set"><label for="chk5"></label></td></tr>' +
																'<tr><th class="left">사용자 지정 글꼴 색상</th><td class="ipt"><input class="check" id="chk6" type="checkbox" name="check-set"><label for="chk6"></label><input type="color" id="labelTextColorPicker"></td></tr>' +
																// '<tr><th class="left">사용자 지정 글꼴 색상</th><td class="ipt"><input type="color" id="labelTextColorPicker"></input></td></tr>' +
															'</tbody>' +
														'</table>' +
													'</div>' +
												'</div>' +
											'</div>' +
										'</div>' +
									'</div>' +
								'</div>' +
							'</div>' +
							'<div class="modal-footer">' +
								'<div class="row center">' +
//									2019.12.16 mksong 뷰어 시리즈 옵션 버튼 이벤트  오류 수정 dogfoot
									'<a href="#" id="seriesOptionsOk" class="btn positive ok-hide">확인</a>' +
									'<a href="#" id="seriesOptionsCancel" class="btn neutral close">취소</a>' +
								'</div>' +
							'</div>';
				contentElement.append(html);
				/* DOGFOOT hsshim 1216
				 * "onContentReady" 부분을 "contentTemplate"로 이동
				 */
				// initialize menu controls
				tabUi();
				menuItemUi();
				/*dogfoot 비정형일때 일반옵션, 시리즈옵션 안보이도록 처리 shlim 20200619*/
				if(gDashboard.reportType == 'AdHoc'){
//					$('#defaultSeriesOptions').css('display','none');
//					$('#pointSeriesOptions').css('display','none');
				}
				/* DOGFOOT hsshim 1216
				 * "popup.element" 값을 "contentTemplate"로 변경
				 */
				contentElement.find('.dx-popup-title').css('border-bottom', '0');
				var id = $(_e).attr('id');
				var options = $(_e).data('dataItemOptions');
				// default selections
				/* DOGFOOT hsshim 1216
				 * "$(target)" 값을 "contentTemplate"로 변경
				 */
				contentElement.find('.tab-m li').removeClass('on');
				contentElement.find('#tabP1 .tab-content.on').removeClass('on');
				contentElement.find('.tab-m li[rel="tabP1-1"]').addClass('on');
				contentElement.find('#tabP1 .tab-content').hide();
				contentElement.find('#tabP1 .tabP1-1').addClass('on').show();
				// tab 1
//				contentElement.find('.lnb-link').removeClass('on');
//				contentElement.find('.lnb-link.' + options.seriesType.toLowerCase()).addClass('on');
				/* DOGFOOT hsshim 1216 끝 */
				// tab 2
				$('#chk0').prop('checked', options.plotOnSecondaryAxis);
				$('#chk1').prop('checked', options.ignoreEmptyPoints);
				$('#chk2').prop('checked', options.showPointMarkers);
				$('#chk4').prop('checked', options.pointLabelOptions.fillBackground);
				$('#chk5').prop('checked', options.pointLabelOptions.showBorder);
				$('#chk6').prop('checked', options.pointLabelOptions.showCustomTextColor);
				// tab 3
				$('#slct0').val(options.pointLabelOptions.contentType);
				var overlappingMode = '';
				if(options.pointLabelOptions.overlappingMode == 'Stack') {
					overlappingMode = 'Reposition';
				} else {
					overlappingMode = options.pointLabelOptions.overlappingMode;
				}
				$('#slct1').val(overlappingMode);
				$('#slct2').val(options.pointLabelOptions.orientation);
				$('#labelTextColorPicker').spectrum({
					showPaletteOnly: true,
					togglePaletteOnly: true,
					togglePaletteMoreText: 'more',
					togglePaletteLessText: 'less',
					color: options.pointLabelOptions.customTextColor,
					palette: [
						["#000","#444","#666","#999","#ccc","#eee","#f3f3f3","#fff"],
						["#f00","#f90","#ff0","#0f0","#0ff","#00f","#90f","#f0f"],
						["#f4cccc","#fce5cd","#fff2cc","#d9ead3","#d0e0e3","#cfe2f3","#d9d2e9","#ead1dc"],
						["#ea9999","#f9cb9c","#ffe599","#b6d7a8","#a2c4c9","#9fc5e8","#b4a7d6","#d5a6bd"],
						["#e06666","#f6b26b","#ffd966","#93c47d","#76a5af","#6fa8dc","#8e7cc3","#c27ba0"],
						["#c00","#e69138","#f1c232","#6aa84f","#45818e","#3d85c6","#674ea7","#a64d79"],
						["#900","#b45f06","#bf9000","#38761d","#134f5c","#0b5394","#351c75","#741b47"],
						["#600","#783f04","#7f6000","#274e13","#0c343d","#073763","#20124d","#4c1130"]
					]
				});

//				2019.12.16 mksong 뷰어 시리즈 옵션 버튼 이벤트  오류 수정 dogfoot
				$('#seriesOptionsCancel').off('click').on('click',function(){
					/* DOGFOOT hsshim 1216
					 * "popup.component" 값을 "$('#seriesOptions').dxPopup('instance')"로 변경
					 */
					$('#seriesOptions').dxPopup('instance').hide();
				});

				/* save data item settings */
//				2019.12.16 mksong 뷰어 시리즈 옵션 버튼 이벤트  오류 수정 dogfoot
				$('#seriesOptionsOk').off('click').on('click',function(){
					gProgressbar.show();
					// tab 1
					/* DOGFOOT hsshim 1216
					 * "$(target)" 값을 "contentTemplate"로 변경
					 */
					// 20200421 akim 변동측정값이 있을 땐 계열 유형과 동일하게 작동하게 수정 dogfoot
					if(gDashboard.reportType === 'AdHoc'){
						var deltaItems = gDashboard.itemGenerateManager.dxItemBasten[1].deltaItems?
								gDashboard.itemGenerateManager.dxItemBasten[1].deltaItems : gDashboard.itemGenerateManager.dxItemBasten[0].deltaItems;
					 	if(deltaItems.length > 0){
					 		
					 		var type = contentElement.find('.lnb-link.on').attr('seriestype');
					 	    var newStyle = type.toLowerCase();
					 	    
					 		$('.chart.seriesoption:visible').each(function(i, e) {
								$(e).data('dataItemOptions').seriesType = type;
							});

					 	    self.Chart.SeriesType = newStyle;
							self.fieldManager.seriesType = type;
							$.each(WISE.util.Object.toArray(self.Chart.Panes.Pane.Series.Simple), function(sIndex, series) {
								series.SeriesType = newStyle;
							});
							$.each(self.dxItem.series, function(index, _series) {
								_series.type = newStyle;
							});
							$.each(self.dxItem.option('series'), function(index, element) {
								self.dxItem.option('series[' + index + '].type', newStyle);
							});
							
							self.dxItem.option('valueAxis[0].visualRange', [0, null]);
							self.dxItem.refresh();
					     }else{
					    	 options.seriesType = contentElement.find('.lnb-link.on').attr('seriestype');
					     }
					} else{
						options.seriesType = contentElement.find('.lnb-link.on').attr('seriestype');
					}
					
					// // tab 2
					options.plotOnSecondaryAxis = $('#chk0').prop('checked');
					options.ignoreEmptyPoints = $('#chk1').prop('checked');
					options.showPointMarkers = $('#chk2').prop('checked');
					// // tab 3
					options.pointLabelOptions.contentType = $('#slct0 option:selected').attr('value');
					$('#' + id).closest('.wise-area-value').find('.chart.seriesoption').each(function(i, e) {
						if($(e).data('dataItemOptions').pointLabelOptions.overlappingMode == 'Reposition') {
							$(e).data('dataItemOptions').pointLabelOptions.overlappingMode = 'Stack';
						} else {
							$(e).data('dataItemOptions').pointLabelOptions.overlappingMode = $('#slct1 option:selected').attr('value');
						}
					});
					options.pointLabelOptions.overlappingMode = $('#slct1').val();
					options.pointLabelOptions.orientation = $('#slct2 option:selected').attr('value');
					options.pointLabelOptions.showForZeroValues = $('#chk3').prop('checked');
					options.pointLabelOptions.position = $('#slct3 option:selected').attr('value');
					options.pointLabelOptions.fillBackground = $('#chk4').prop('checked');
					options.pointLabelOptions.showBorder = $('#chk5').prop('checked');
					options.pointLabelOptions.showCustomTextColor = $('#chk6').prop('checked');
					options.pointLabelOptions.customTextColor = $('#labelTextColorPicker').spectrum('get').toHexString();

					/* DOGFOOT ktkang 차트 2개 이상 일 때 시리즈 옵션에서 계열 유형이 바로 안바뀌는 현상 수정  20200708 */
					if (gDashboard.itemGenerateManager.focusedItem.filteredData) {
						//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
						if(gDashboard.itemGenerateManager.focusedItem.isAdhocItem){
							//20200714 비정형일 경우 차트 찾아서 처리하도록 수정 dogfoot
							if(gDashboard.itemGenerateManager.dxItemBasten[0].type === "SIMPLE_CHART"){
								gDashboard.itemGenerateManager.dxItemBasten[0].functionBinddata = true;
						        gDashboard.itemGenerateManager.dxItemBasten[0].bindData(self.filteredData);
							}
                            else{
                            	gDashboard.itemGenerateManager.dxItemBasten[1].functionBinddata = true;
						        gDashboard.itemGenerateManager.dxItemBasten[1].bindData(self.filteredData);
                            }
						}else{
							gDashboard.itemGenerateManager.focusedItem.functionBinddata = true;
						    gDashboard.itemGenerateManager.focusedItem.bindData(self.filteredData);
						}
					}else{
						gProgressbar.hide();
					}
					
					//2020.05.13 tbchoi 선택된 차트 유형 필드 시리즈 아이콘에 반영되도록 코드 추가
//					_e.children[0].src = contentElement.find('.lnb-link.on').find('img')[0].src;

					$('#seriesOptions').dxPopup('instance').hide();
				});

				/**
				 * Enable and disable certain point options based on series type.
				 */ 
				/* DOGFOOT hsshim 1216
				 * a) "$(target)" 값을 "contentTemplate"로 변경
				 * b) function() 파라미터 제
				 */
				var enablePointOptions = function() {
					var selectedSeries = contentElement.find('.lnb-link.on');
					if (selectedSeries.hasClass('bar') || selectedSeries.hasClass('stackedbar') || selectedSeries.hasClass('fullstackedbar')) {
						$('#chk3').prop('disabled', false);
					} else {
						$('#chk3').prop('disabled', true);
					}
					if (selectedSeries.hasClass('bar') || selectedSeries.hasClass('bubble')) {
						$('#slct3').prop('disabled', false);
					} else {
						$('#slct3').prop('disabled', true);
					}
				};
				enablePointOptions();
				
				contentElement.find('.lnb-link').off('click').on('click', function(e) {
					contentElement.find('.lnb-link.on')[0].classList.remove('on');
					$(this).addClass('on');
					enablePointOptions();
				});
				/* DOGFOOT hsshim 1216 끝 */
			}
		});
		
	}
	
	/**
	 * generate UI for data and design functions
	 */ 
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
		
	}

	/**
	 * 데이터 아이템 설정
	 */
	/**
	 * Initialize data used for drill-down procedures.
	 */
	this.initDrillDownData = function(_data) {
		self.drillDownData = crossfilter(_data);
		self.drillDownStack = [];
		self.drillDownArgumentOrder = [];
		self.drillDownSeriesOrder = [];
		self.reducibleMeasures = [];
		self.drillDownIndex = 0;

	}

	/**
	 * Map & reduce drill-down data and apply it to the grid instance.
	 */
	this.setDrillDownData = function(_dimKey) {
		var transformedDataObj = self.transformDrillDownData();
		var reducedData = [];
		
		switch (self.IO.TargetDimensions) {
			case 'Argument':
				reducedData = _(transformedDataObj.data).groupBy(_dimKey).map(function(objs, key) {
					var result = {};
					result['arg'] = key;
					transformedDataObj.measures.forEach(function(measureKey) {
						result[measureKey] = _.sumBy(objs, measureKey);
					});
					return result;
				}).value();
				break;
			case 'Series':
				if (self.drillDownArgumentOrder.length === 0) {
					var result = { arg: 'Grand Total' };
					transformedDataObj.measures.forEach(function(measureKey) {
						result[measureKey] = _.sumBy(transformedDataObj.data, measureKey);
					});

					reducedData.push(result);
				} else {
					$.each(self.drillDownArgumentOrder, function(j, argKey) {
						reducedData = reducedData.concat(
							_(transformedDataObj.data).groupBy(argKey).map(function(objs, key) {
								var result = {};
								result['arg'] = key;
								transformedDataObj.measures.forEach(function(measureKey) {
									result[measureKey] = _.sumBy(objs, measureKey);
								});
								return result;
							}).value()
						);
					});
				}
				// create new series
				var newSeries = [];
				$.each(reducedData[0], function(key) {
					if (key !== 'arg') {
						var measureName = key.split('-')[key.split('-').length - 1];
						var noSummaryName = measureName.split('_')[measureName.split('_').length - 1];
						newSeries.push({
							axis: 'default-DEFAULT-Y',
							name: key.replace(new RegExp(measureName, 'i'), noSummaryName),
							pane: 'default',
							type: self.meta.SeriesType,
							valueField: key
						});
					}
				});
				self.dxItem.option('series', newSeries);
				break;
			default:
		}

		var newDataSource = new DevExpress.data.DataSource({
			store: reducedData,
			paginate: false
		});
		
		//2020.03.26 ajkim 드릴다운에 필터 적용 dogfoot
//		if (this.meta && this.meta.FilterString && this.meta.FilterString.length > 0) {
//			newDataSource.filter(this.meta.FilterString);
//			newDataSource.load();
//		}

		newDataSource.load();
		self.dxItem.option('dataSource', newDataSource.items());
	}

	/**
	 * Return an object that contains data and list of measures with argument/series transformations applied to each measure.
	 */
	this.transformDrillDownData = function(_data) {
		var result = {
			data: self.drillDownData.allFiltered(),
			measures: _.clone(self.reducibleMeasures)
		};

		switch (self.IO.TargetDimensions) {
			case 'Argument':
				if (self.drillDownSeriesOrder.length > 0) {
					result.measures = [];
					result.data = _.map(result.data, function(d, i) {
						var seriesValues = [];
						$.each(self.drillDownSeriesOrder, function(j, series) {
							if (typeof d[series] !== 'undefiend') {
								seriesValues.push(d[series]);
							}
						});
						var prefix = seriesValues.join('-') + '-';

						var item = {};
						for (attr in d) {
							if (self.reducibleMeasures.indexOf(attr) !== -1) {
								item[prefix + attr] = d[attr];
								if (result.measures.indexOf(prefix + attr) === -1) {
									result.measures.push(prefix + attr);
								}
							} else {
								item[attr] = d[attr];
							}
						}
						return item;
					});
				}
				break;
			case 'Series':
				result.measures = [];
				result.data = _.map(result.data, function(d, i) {
					var seriesValue = self.drillDownSeriesOrder[self.drillDownIndex];
					var prefix = typeof d[seriesValue] !== 'undefined'
						? d[seriesValue] + '-' 
						: '';

					var item = {};
					for (attr in d) {
						if (self.reducibleMeasures.indexOf(attr) !== -1) {
							item[prefix + attr] = d[attr];
							if (result.measures.indexOf(prefix + attr) === -1) {
								result.measures.push(prefix + attr);
							}
						} else {
							item[attr] = d[attr];
						}
					}
					return item;
				});
				break;
			default:
		}

		return result;
	}

	/**
	 * Returns data results after drill-down operation of key _dimKey and value _dimValue.
	 */
	this.drillDown = function(_dimKey, _dimValue, _nextDimKey) {
		var dimObj = self.drillDownData.dimension(_dimKey);
		if (dimObj != undefined) {
			dimObj.filterFunction(function(d) { return d === _dimValue; });
			self.drillDownStack.push({ name: _dimKey, dim: dimObj });
			self.drillDownIndex++;
			self.setDrillDownData(_nextDimKey);
		}
	}

	/**
	 * Returns data results after drill-up operation.
	 */
	this.drillUp = function() {
		if (self.drillDownStack.length > 0) {
			var dimObj = self.drillDownStack.pop();
			if (dimObj != undefined) {
				dimObj.dim.dispose();
				self.drillDownIndex--;
				self.setDrillDownData(dimObj.name);
			}	
		}
	}

	/**
	 * Returns true if current chart can be drilled down.
	 */
	this.isValidDrillDown = function() {
		if (self.measures.length === 0) {
			return false;
		}
		switch (self.IO.TargetDimensions) {
			case 'Argument':
				if (self.dimensions.length < 2) {
					return false;
				}
				return true;
			case 'Series':
				if (self.seriesDimensions.length < 2) {
					return false;
				}
				return true;
			default:
				return false;
		}
	}

	/**
	 * Begin drill-down operations by hiding all dimension columns following the first.
	 */
	this.initDrillDownOperation = function() {
		if (self.isValidDrillDown()) {
			// configure settings to "true"
			self.meta.InteractivityOptions.IsDrillDownEnabled = true;
			self.IO.IsDrillDownEnabled = true;
			self.drillDownArgumentOrder = [];
			self.drillDownSeriesOrder = [];
			self.reducibleMeasures = [];
			self.drillDownSeries = self.dxItem.option('series');
			// determine order of drill-down and measures to reduce
			for (var i = 0; i < self.dimensions.length; i++) {
				self.dimensions[i] && self.drillDownArgumentOrder.push(self.dimensions[i].name);
			}
			for (var j = 0; j < self.seriesDimensions.length; j++) {
				self.seriesDimensions[j] && self.drillDownSeriesOrder.push(self.seriesDimensions[j].name);
			}
			for (var k = 0; k < self.measures.length; k++) {
				self.measures[k] && self.reducibleMeasures.push(self.measures[k].nameBySummaryType);
			}
			
			switch (self.IO.TargetDimensions) {
				case 'Argument':
					self.setDrillDownData(self.drillDownArgumentOrder[0]);
					break;
				case 'Series':
					self.setDrillDownData(self.drillDownSeriesOrder[0]);
					break;
				default:
			}
		} else {
			WISE.alert('현재 상태에 드릴 다운이 가능하지 않습니다.');
			/*dogfoot 드릴 다운 오류 무한로딩 수정 shlim 20200616*/
			gProgressbar.hide();
		}
	}

	/**
	 * Stop drill-down operations by restoring data and columns to its' original state.
	 */
	this.terminateDrillDownOperation = function() {
		// configure settings to "false"
		self.meta.InteractivityOptions.IsDrillDownEnabled = false;
		self.IO.IsDrillDownEnabled = false;
		// reset data
		var resetData = self.drillDownData.all();
		self.initDrillDownData(resetData);
		self.dxItem.option({
			dataSource: self.chartData,
			series: self.drillDownSeries
		});
	}
	
	/**
	 * data and design functions
	 * 
	 * @param _f: clicked button's id 
	 */
	this.functionDo = function(_f) {
		
		switch(_f) {
		/* DATA OPTIONS */
		
			// edit filter builder
			case 'editFilter': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup2').dxPopup('instance');
				p.option({
					title: '필터 편집',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopup2');
					},
					contentTemplate: function() {
						var html = 	'<div id="filterContent"></div>' +
									'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        return html;
					},
					onContentReady: function() {
						var field = [];
						$.each(self.seriesDimensions, function(_i, series) {
							field.push({ dataField: series.name, dataType: 'string' });
						});
						$.each(self.dimensions, function(_i, dimension) {
							field.push({ dataField: dimension.name, dataType: 'string' });
						});

						$('#filterContent').append('<div id="' + self.itemid + '_editFilter">');
						$('#' + self.itemid + '_editFilter').dxFilterBuilder({
							fields: field,
							value: self.meta.FilterString
                        });
                                                
                        // confirm and cancel
						$('#ok-hide').on('click', function() {
//                            var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').getFilterExpression();
							var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').option('value');
                            var newDataSource = new DevExpress.data.DataSource({
                                store: self.filteredData,
                                paginate: false
                            });
                            newDataSource.filter(filter);
							newDataSource.load();
							self.filteredData = newDataSource.items();
							self.meta.FilterString = filter;
							
							gProgressbar.show();
							setTimeout(function () {
								//2020.03.27 ajkim 비정형 필터 편집시 차트도 필터스트링 넘기도록 수정 dogfoot
								if(gDashboard.reportType == 'AdHoc'){
									$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
										_item.meta.FilterString = filter;
										//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
										self.functionBinddata = true;
										_item.bindData(self.filteredData, true);
									});
								}
								
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.filteredData, true);
								if (self.IO.MasterFilterMode !== 'Off') {
									/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
									gDashboard.filterData(self.itemid, []);
								}
								if(self.meta.FilterString.length > 0){
									$('#editFilter').addClass('on');
								}else{
									$('#editFilter').removeClass('on');
								}
								p.hide();
							},10);
						});
						$('#close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			// clear filters
			case 'clearFilter': {
				if (!(self.dxItem)) {
					break;
				}
				self.meta.FilterString = [];
				$('#editFilter').removeClass('on');
				self.filteredData = self.globalData;
				//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
				self.functionBinddata = true;
				gProgressbar.show();
				setTimeout(function () {
					self.bindData(self.globalData, true);
					if (self.IO.MasterFilterMode !== 'Off') {
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, []);
					}
				},10);	
				
				break;
			}
			// toggle single master filter mode
			case 'singleMasterFilter': {
				if (!(self.dxItem)) {
					break;
				}
				// Both master filter and drill-down cannot be active at the same time. Turn drill-down off.
				if (self.IO.IsDrillDownEnabled) {
					self.terminateDrillDownOperation();
				}
				gProgressbar.show();
				setTimeout(function () {
					self.functionBinddata = true;
					self.trackingClearId = self.itemid + '_topicon_tracking_clear';
					// toggle off
					if (self.IO.MasterFilterMode === 'Single') {
						$('#' + self.trackingClearId).addClass('invisible');
						self.RangeBarChart.InteractivityOptions.MasterFilterMode = 'Off';
						self.IO.MasterFilterMode = 'Off';
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
						if(reTrackItem){
							gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
						}else{
							gDashboard.filterData(self.itemid, self.trackingData);	
						}
					// toggle on
					} else {
						$('#' + self.trackingClearId).removeClass('invisible');
						self.RangeBarChart.InteractivityOptions.MasterFilterMode = 'Single';
						self.IO.MasterFilterMode = 'Single';
						
						// Only one master filter can be on. Turn off master filters on other items.
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
							/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
							if(gDashboard.getLayoutType() == "Container"){
								var ContainerList = gDashboard.setContainerList(self);            	

								$.each(ContainerList,function(_l,_con){
									if (_con.DashboardItem == item.ComponentName) {
										if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
											$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
											item.IO.MasterFilterMode = 'Off';
											item.meta.InteractivityOptions.MasterFilterMode = 'Off';
											/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
											gDashboard.filterData(item.itemid, []);
										}
									}
								})

							}else{
								if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
									$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
									item.IO.MasterFilterMode = 'Off';
									item.meta.InteractivityOptions.MasterFilterMode = 'Off';
									/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
									gDashboard.filterData(item.itemid, []);
								}
							}
						});
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						self.selectFirstPoint();
					}
				},10);
				break;
			}
			// toggle multiple master filter mode
			case 'multipleMasterFilter': {
				if (!(self.dxItem)) {
					break;
				}
				gProgressbar.show();
				setTimeout(function () {
					self.functionBinddata = true;
					// Both master filter and drill-down cannot be active at the same time. Turn drill-down off.
					if (self.IO.IsDrillDownEnabled) {
						self.terminateDrillDownOperation();
					}
					if (self.IO.MasterFilterMode === 'Multiple') {
						$('#' + self.trackingClearId).addClass('invisible');
						self.RangeBarChart.InteractivityOptions.MasterFilterMode = 'Off';
						self.IO.MasterFilterMode = 'Off';
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
						if(reTrackItem){
							gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
						}else{
							gDashboard.filterData(self.itemid, self.trackingData);	
						}
					} else {
						$('#' + self.trackingClearId).removeClass('invisible');
						self.RangeBarChart.InteractivityOptions.MasterFilterMode = 'Multiple';
						self.IO.MasterFilterMode = 'Multiple';
						// Only one master filter can be on. Turn off master filters on other items.
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
							/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
							if(gDashboard.getLayoutType() == "Container"){
								var ContainerList = gDashboard.setContainerList(self);            	

								$.each(ContainerList,function(_l,_con){
									if (_con.DashboardItem == item.ComponentName) {
										if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
											$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
											item.IO.MasterFilterMode = 'Off';
											item.meta.InteractivityOptions.MasterFilterMode = 'Off';
											/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
											gDashboard.filterData(item.itemid, []);
										}
									}
								})

							}else{
								if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
									$('#' + item.itemid + '_topicon_tracking_clear').addClass('invisible');
									item.IO.MasterFilterMode = 'Off';
									item.meta.InteractivityOptions.MasterFilterMode = 'Off';
									/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
									gDashboard.filterData(item.itemid, []);
								}
							}
						});
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						self.selectFirstPoint();
					}
				},10);
				break;
			}
			// toggle drill down
			case 'drillDown': {
				if (!(self.dxItem)) {
					break;
				}
				gProgressbar.show();
				setTimeout(function () {
					self.functionBinddata = true;
					// Both master filter and drill-down cannot be active at the same time. Turn master filter off.
					if (self.IO.MasterFilterMode !== 'Off') {
						self.RangeBarChart.InteractivityOptions.MasterFilterMode = 'Off';
						self.IO.MasterFilterMode = 'Off';
						self.clearTrackingConditions();
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
						if(reTrackItem){
							gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
						}else{
							gDashboard.filterData(self.itemid, self.trackingData);	
						}
					}
					
					if ($('#drillDown').hasClass('on')) {
						$('#' + self.DrilldownClearId).removeClass('invisible');
						self.initDrillDownOperation();
					} else {
						$('#' + self.DrilldownClearId).addClass('invisible');
						self.terminateDrillDownOperation();
					}
					/*dogfoot 드릴 다운 오류 무한로딩 수정 shlim 20200616*/
					gProgressbar.hide();
				},10);
				break;
			}
			// toggle cross data source filtering
			case 'crossFilter': {
				if (!(self.dxItem)) {
					break;
				}
				self.IsMasterFilterCrossDataSource = $('#crossFilter').hasClass('on') ? true : false;
				self.RangeBarChart.IsMasterFilterCrossDataSource = self.IsMasterFilterCrossDataSource;
				gProgressbar.show();
				setTimeout(function () {
					self.functionBinddata = true;
					if (self.IsMasterFilterCrossDataSource) {
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, self.trackingData);
					}
					// If turning cross filter off, clear filter for items with different data sources.
					else {
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
							if (item.ComponentName !== self.ComponentName && item.dataSourceId !== self.dataSourceId) {
								item.tracked = false;
								item.bindData(item.globalData, true);
							}
						});
					}
				},10);
				break;
			}
			// toggle ignore master filter
			case 'ignoreMasterFilter': {								
				if (!(self.dxItem)) {
					break;
				}
				self.IO.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
				self.RangeBarChart.InteractivityOptions.IgnoreMasterFilters = self.IO.IgnoreMasterFilters;
				self.tracked = !self.IO.IgnoreMasterFilters;
				gProgressbar.show();
				setTimeout(function () {
					if (self.IO.IgnoreMasterFilters) {
						//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
						self.functionBinddata = true;
						self.bindData(self.globalData,true);
					} else {
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
							if (item.ComponentName !== self.ComponentName && item.IO && item.IO.MasterFilterMode !== 'Off') {
								self.doTrackingCondition(item.itemid, item);
								return false;
							}
						});
					}
				},10);
				break;
			}
			// change dimension target to arguments
			case 'targetArgument': {
				if (!(self.dxItem)) {
					break;
				}
				self.IO.TargetDimensions = 'Argument';
				self.RangeBarChart.InteractivityOptions.TargetDimensions = 'Argument';
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				if (self.IO.MasterFilterMode !== 'Off') {
					self.clearTrackingConditions();
					self.selectFirstPoint();
				}
				break;
			}
			// change dimension target to series
			case 'targetSeries': {
				if (!(self.dxItem)) {
					break;
				}
				self.IO.TargetDimensions = 'Series';
				self.RangeBarChart.InteractivityOptions.TargetDimensions = 'Series';
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				if (self.IO.MasterFilterMode !== 'Off') {
					self.clearTrackingConditions();
					self.selectFirstPoint();
				}
				break;
			}
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.RangeBarChart.ShowCaption = true;
				} else {
					titleBar.css('display', 'none');
					self.RangeBarChart.ShowCaption = false;
				}
				break;
			}
			// edit chart title
			case 'editName': {
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '이름 편집',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopup');
					},
					contentTemplate: function(contentElement) {
						// initialize title input box
						contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput"></div>');
                        var html = 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
						contentElement.append(html);
                        
                        $('#' + self.itemid + '_titleInput').dxTextBox({
							text: $('#' + self.itemid + '_title').text()
                        });
                                                
                        // confirm and cancel
						$('#ok-hide').on('click', function() {
                            var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
                            if(newName.trim() == '') {
                            	WISE.alert('아이템 이름에 빈 값을 넣을 수 없습니다.');
                            	$('#' + self.itemid + '_titleInput').dxTextBox('instance').option('value', self.Name);
                            } else {
                            	/* DOGFOOT ktkang 컨테이너 추가시 내부 아이템 이름 변경이 안되는 오류 수정  20191223 */
                            	
//                            	var goldenLayout = gDashboard.goldenLayoutManager;
//                            	goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);
                            	
                            	var ele = $('#' + self.itemid + '_title');
                            	ele.attr( 'title', newName)
                                ele.find( '.lm_title' ).html(newName);
                            	
                            	self.RangeBarChart.Name = newName;
                            	self.Name = newName;
                            	p.hide();
                            }
						});
						$('#close').on('click', function() {
							p.hide();
						});
					}
				});
				// show popup
				p.show();
				break;
			}
			// rotate
			case 'rotation': {
				if (!(self.dxItem)) {
					break;
				}
				
				if(self.RangeBarChart.AxisX.Rotation !== 0 && !self.RangeBarChart.Rotated){
					WISE.confirm(
						'회전시 X축 기울기가 적용되지<br>않습니다. 회전하시겠습니까?', 
						{
							buttons: {
								confirm: {
									id: 'confirm',
									className: 'green',
									text: '확인',
									action: function() {
										self.RangeBarChart.Rotated = !(self.RangeBarChart.Rotated);
										self.dxItem.option('rotated', self.RangeBarChart.Rotated);
										$AlertPopup.hide();
									}
								},
								cancel: {
									id: 'cancel',
									className: 'negative',
									text: '취소',
									action: function() { $AlertPopup.hide(); }
								}
							}
						}
					);
				}else{
					self.RangeBarChart.Rotated = !(self.RangeBarChart.Rotated);
					self.dxItem.option('rotated', self.RangeBarChart.Rotated);
				}
				break;
			}
			// edit X axis
			case 'editAxisX': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: 'X축 설정',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_xShow" style="margin: 10px 0px;"></div>');
                        contentElement.append('<div id="' + self.itemid + '_xInputs"></div>');
                        var html = 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        
						// show and hide X axis labels
						$('#' + self.itemid + '_xShow').dxCheckBox({
							value: self.RangeBarChart.AxisX.Visible != undefined ? self.RangeBarChart.AxisX.Visible : true ,
							text: 'X축 표시'
						});
						// edit X axis title and label orientation
						$('#' + self.itemid + '_xInputs').dxForm({
							formData: {
								'사용자 정의 텍스트': self.RangeBarChart.AxisX.Title,
								'기울기': self.RangeBarChart.AxisX.Rotation
							},
							items: [
								{
									dataField: '사용자 정의 텍스트',
									editorType: 'dxTextBox'
								}, 
								{
									dataField: '기울기',
									editorType: 'dxRadioGroup',
									editorOptions: {
										layout: 'horizontal',
										dataSource: [0, 45, 90]
									}
								}
							]
                        });
                                                
                        // confirm and cancel
						$('#ok-hide').on('click', function() {
							self.RangeBarChart.AxisX.Visible = $('#' + self.itemid + '_xShow').dxCheckBox('instance').option('value');
							self.RangeBarChart.AxisX.Title = $('#' + self.itemid + '_xInputs').dxForm('instance').getEditor('사용자 정의 텍스트').option('value');
							self.RangeBarChart.AxisX.Rotation = $('#' + self.itemid + '_xInputs').dxForm('instance').getEditor('기울기').option('value');
							if(self.RangeBarChart.AxisX.Rotation !== 0 && self.RangeBarChart.Rotated){
								WISE.confirm(
									'회전된 상태에선 기울기가 적용되지 않습니다. 적용하시겠습니까?', 
									{
										buttons: {
											confirm: {
												id: 'confirm',
												className: 'green',
												text: '확인',
												action: function() {
						                            self.dxItem.option('argumentAxis.label.visible', self.RangeBarChart.AxisX.Visible);
						                            self.dxItem.option('argumentAxis.title', { text: self.RangeBarChart.AxisX.Title });
						                            if (self.dxItem.option('argumentAxis.label.displayMode') != 'rotate') {
						                                self.dxItem.option('argumentAxis.label.displayMode', 'rotate');
						                            }
						                            self.dxItem.option('argumentAxis.label.rotationAngle', self.RangeBarChart.AxisX.Rotation);
													self.dxItem.refresh();
						                            p.hide();
													$AlertPopup.hide();
												}
											},
											cancel: {
												id: 'cancel',
												className: 'negative',
												text: '취소',
												action: function() { $AlertPopup.hide(); }
											}
										}
									}
								);
							}else{
	                            self.dxItem.option('argumentAxis.label.visible', self.RangeBarChart.AxisX.Visible);
	                            self.dxItem.option('argumentAxis.title', { text: self.RangeBarChart.AxisX.Title });
	                            if (self.dxItem.option('argumentAxis.label.displayMode') != 'rotate') {
	                                self.dxItem.option('argumentAxis.label.displayMode', 'rotate');
	                            }
	                            self.dxItem.option('argumentAxis.label.rotationAngle', self.RangeBarChart.AxisX.Rotation);
								self.dxItem.refresh();
	                            p.hide();
							}
						});
						$('#close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			// edit Y axis
			case 'editAxisY': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: 'Y축 설정',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						var example = 1234567890.123;
						var initialized = false;

						// initialize template
						var html = 	'<div id="' + self.itemid + '_yOptions"></div>' +
									'<textarea id="exampleText" style="width: 100%; height: 50px; text-align: center; font-size: 1.5em;" disabled></textarea>' +
									'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
						contentElement.append(html);

						// edit Y axis measures
						var optionsForm = $('#' + self.itemid + '_yOptions').dxForm({
							items: [
								{
									dataField: '포맷 형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Auto', 'General', 'Number', 'Currency', 'Scientific', 'Percent'],
										value: self.RangeBarChart.AxisY.FormatType,
										onValueChanged: function(e) {
											if (e.value === 'Auto' || e.value === 'General') {
												optionsForm.getEditor('단위').option('disabled', true);
												optionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
												optionsForm.getEditor('O').option('disabled', true);
												optionsForm.getEditor('K').option('disabled', true);
												optionsForm.getEditor('M').option('disabled', true);
												optionsForm.getEditor('B').option('disabled', true);
												optionsForm.getEditor('정도').option('disabled', true);
												optionsForm.getEditor('정도 옵션').option('disabled', true);
												optionsForm.getEditor('그룹 구분 포함').option('disabled', true);
											} else if (e.value === 'Scientific' || e.value === 'Percent') {
												optionsForm.getEditor('단위').option('disabled', true);
												optionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
												optionsForm.getEditor('O').option('disabled', true);
												optionsForm.getEditor('K').option('disabled', true);
												optionsForm.getEditor('M').option('disabled', true);
												optionsForm.getEditor('B').option('disabled', true);
												optionsForm.getEditor('정도').option('disabled', false);
												optionsForm.getEditor('정도 옵션').option('disabled', false);
												optionsForm.getEditor('그룹 구분 포함').option('disabled', true);
											} else {
												optionsForm.getEditor('단위').option('disabled', false);
												optionsForm.getEditor('사용자 지정 접미사').option('disabled', false);
												if (optionsForm.getEditor('사용자 지정 접미사').option('value')) {
													optionsForm.getEditor('O').option('disabled', false);
													optionsForm.getEditor('K').option('disabled', false);
													optionsForm.getEditor('M').option('disabled', false);
													optionsForm.getEditor('B').option('disabled', false);	
												}
												optionsForm.getEditor('정도').option('disabled', false);
												optionsForm.getEditor('정도 옵션').option('disabled', false);
												optionsForm.getEditor('그룹 구분 포함').option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '단위',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
										value: self.RangeBarChart.AxisY.Unit,
										onInitialized: function(e) {
											var formatType = self.RangeBarChart.AxisY.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '항상 제로 수준 표시',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.ShowZero
									}
								},
								{
									dataField: 'Y축 표시',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.Visible
									}
								},
								{
									dataField: '사용자 정의 텍스트',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.Title
									}
								},
								{
									dataField: '사용자 지정 접미사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.SuffixEnabled,
										onInitialized: function(e) {
											var formatType = self.RangeBarChart.AxisY.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
										onValueChanged: function(e) {
											if (e.value) {
												optionsForm.getEditor('O').option('disabled', false);
												optionsForm.getEditor('K').option('disabled', false);
												optionsForm.getEditor('M').option('disabled', false);
												optionsForm.getEditor('B').option('disabled', false);
											} else {
												optionsForm.getEditor('O').option('disabled', true);
												optionsForm.getEditor('K').option('disabled', true);
												optionsForm.getEditor('M').option('disabled', true);
												optionsForm.getEditor('B').option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'O',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.MeasureFormat.O,
										onInitialized: function(e) {
											var formatType = self.RangeBarChart.AxisY.FormatType;
											var suffixEnabled = self.RangeBarChart.AxisY.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: 'K',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.MeasureFormat.K,
										onInitialized: function(e) {
											var formatType = self.RangeBarChart.AxisY.FormatType;
											var suffixEnabled = self.RangeBarChart.AxisY.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: 'M',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.MeasureFormat.M,
										onInitialized: function(e) {
											var formatType = self.RangeBarChart.AxisY.FormatType;
											var suffixEnabled = self.RangeBarChart.AxisY.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: 'B',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.MeasureFormat.B,
										onInitialized: function(e) {
											var formatType = self.RangeBarChart.AxisY.FormatType;
											var suffixEnabled = self.RangeBarChart.AxisY.SuffixEnabled;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '정도',
									editorType: 'dxNumberBox',
									editorOptions: {
										step: 1,
										min: 0,
										max: 5,
										//20210712 AJKIM 소수점 방지 dogfoot
										format: "#",
										showSpinButtons: true,
										value: self.RangeBarChart.AxisY.Precision,
										onInitialized: function(e) {
											var formatType = self.RangeBarChart.AxisY.FormatType;
											if (formatType === 'Auto' || formatType === 'General') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
									}
								},
								{
									dataField: '정도 옵션',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['반올림', '올림', '버림'],
										value: typeof self.RangeBarChart.AxisY.PrecisionOption !== 'undefined' ?  self.RangeBarChart.AxisY.PrecisionOption : '반올림',
									}
								},
								{
									dataField: '그룹 구분 포함',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: self.RangeBarChart.AxisY.Separator,
										onInitialized: function(e) {
											var formatType = self.RangeBarChart.AxisY.FormatType;
											if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										},
									}
								}
							],
							onContentReady: function(form) {
								if (!initialized) {
									initialized = true;
									function updateExample(e) {
										var formData = e.component.option('formData');
										var type = formData['포맷 형식'];
										var	unit = formData['단위'];
										var precision = formData['정도'];
										var precisionOption = formData['정도 옵션'];
										var separator = formData['그룹 구분 포함'];
										var prefix = undefined;
										var suffix = {
											O: formData['O'],
											K: formData['K'],
											M: formData['M'],
											B: formData['B']	
										};
										var suffixEnabled = formData['사용자 지정 접미사'];
										$('#exampleText').val(WISE.util.Number.unit(example, type, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption));
									}
									updateExample(form);
									form.component.option('onFieldDataChanged', updateExample);
								}
							}
						}).dxForm('instance');

						// confirm and cancel
						$('#ok-hide').off('click').on('click', function() {
							var formData = optionsForm.option('formData');
							var formatType = formData['포맷 형식'];
							var	unit = formData['단위'];
							var showZero = formData['항상 제로 수준 표시'];
							var visible = formData['Y축 표시'];
							var title = formData['사용자 정의 텍스트'];
							var suffixEnabled = formData['사용자 지정 접미사'];
							var suffix = {
								O: formData['O'],
								K: formData['K'],
								M: formData['M'],
								B: formData['B']	
							};
							var precision = formData['정도'];
							var precisionOption = formData['정도 옵션'];
							var separator = formData['그룹 구분 포함'];
							self.RangeBarChart.AxisY.FormatType = formatType;
							self.RangeBarChart.AxisY.Unit = unit;
							self.RangeBarChart.AxisY.ShowZero = showZero;
							self.RangeBarChart.AxisY.Visible = visible;
                            self.RangeBarChart.AxisY.Title = title;
                            /* DOGFOOT ktkang Y축 이름 저장 오류 수정  20200130 */
                            self.RangeBarChart.AxisY.TitleRename = true;
							self.RangeBarChart.AxisY.SuffixEnabled = suffixEnabled;
							self.RangeBarChart.AxisY.MeasureFormat = suffix;
							self.RangeBarChart.AxisY.Precision = precision;
							self.RangeBarChart.AxisY.PrecisionOption = precisionOption;
							self.RangeBarChart.AxisY.Separator = separator;
							// self.dxItem.option('valueAxis[0].title.text', self.RangeBarChart.AxisY.Title);
							// for (var i = 0; i < self.dxItem.option('valueAxis').length; i++) {
							// 	self.dxItem.option('valueAxis[' + i + '].label.visible', self.RangeBarChart.AxisY.Visible);
							// 	// if Y axis is not visible, hide title
							// 	var title = self.dxItem.option('valueAxis[' + i + '].title.text');
							// 	self.dxItem.option('valueAxis[' + i + '].title.text', self.RangeBarChart.AxisY.Visible ? title : '');
							// 	self.dxItem.option('valueAxis[' + i + '].label.customizeText', function(e) {
							// 		return WISE.util.Number.unit(e.value, formatType, unit, precision, separator, undefined, suffix, suffixEnabled);
							// 	});
							// 	self.dxItem.option('valueAxis[' + i + '].label.showZero', self.RangeBarChart.AxisY.ShowZero);
							// }
							//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
							self.functionBinddata = true;
							self.bindData(self.globalData, true);
                            p.hide();
						});
						$('#close').off('click').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			// edit legend
			case 'editLegend': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
                    target: '#editLegend',
					contentTemplate: function(contentElement) {
						/* DOGFOOT hsshim 2020-02-06 비정형 범레 옵션 UI 수정 */
//						if (gDashboard.reportType === 'AdHoc') {
//							$(	'<div id="' + self.itemid + '_toggleLegend" style="width:130px;"></div>' +
//								'<div style="height: auto; width: 150px;">' +
//									'<ul class="add-item-body icon-radio-list" style="display:block;">'+ 
//										'<li >'+ 
//											'<a  href="#" class="select-position" data-position="outside" data-description="TopLeftHorizontal">' +
//												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHLeftTop.png" alt="">' +
//											'</a>' + 
//										'</li>' + 
//										'<li >'+ 
//											'<a  href="#" class="select-position" data-position="outside" data-description="BottomLeftHorizontal">' +
//												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHLeftBottom.png" alt="">' +
//											'</a>' + 
//										'</li>' + 
//										'<li >'+ 
//											'<a  href="#" class="select-position" data-position="outside" data-description="TopLeftVertical">' +
//												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVLeftTop.png" alt="">' +
//											'</a>' + 
//										'</li>' + 
//										'<li>' + 
//											'<a  href="#" class="select-position" data-position="outside" data-description="TopRightVertical">' +
//												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVRightTop.png" alt="">' +
//											'</a>' + 
//										'</li>' + 
//									'</ul>' + 
//								'</div>'							
//							).appendTo(contentElement);
//						} else {
							$(	'<div id="' + self.itemid + '_toggleLegend" style="width:130px;' + gDashboard.fontManager.getCustomFontStringForMenu(14) +'"></div>' +
								'<div style="height: auto; width: 150px;">' +
									'<ul class="add-item-body icon-radio-list" style="display:block;">'+ 
										'<li >'+ 
											'<a  href="#" class="select-position" data-position="inside" data-description="TopLeftHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideHLeftTop.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li>' + 
											'<a  href="#" class="select-position" data-position="inside" data-description="TopCenterHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideHCenterTop.png" alt="">' +
											'</a>' + 
										'</li>' +  
										'<li>' + 
											'<a  href="#" class="select-position" data-position="inside" data-description="TopRightHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideHRightTop.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li >'+ 
											'<a  href="#" class="select-position" data-position="inside" data-description="BottomLeftHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideHLeftBottom.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li>' + 
											'<a  href="#" class="select-position" data-position="inside" data-description="BottomCenterHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideHCenterBottom.png" alt="">' +
											'</a>' + 
										'</li>' +  
										'<li>' + 
											'<a  href="#" class="select-position" data-position="inside" data-description="BottomRightHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideHRightBottom.png" alt="">' +
											'</a>' + 
										'</li>' + 

										'<li >'+ 
											'<a  href="#" class="select-position" data-position="inside" data-description="TopLeftVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideVLeftTop.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li>' + 
											'<a  href="#" class="select-position" data-position="inside" data-description="TopCenterVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideVCenterTop.png" alt="">' +
											'</a>' + 
										'</li>' +  
										'<li>' + 
											'<a  href="#" class="select-position" data-position="inside" data-description="TopRightVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideVRightTop.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li >'+ 
											'<a  href="#" class="select-position" data-position="inside" data-description="BottomLeftVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideVLeftBottom.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li>' + 
											'<a  href="#" class="select-position" data-position="inside" data-description="BottomCenterVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideVCenterBottom.png" alt="">' +
											'</a>' + 
										'</li>' +  
										'<li>' + 
											'<a  href="#" class="select-position" data-position="inside" data-description="BottomRightVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_insideVRightBottom.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li >'+ 
											'<a  href="#" class="select-position" data-position="outside" data-description="TopLeftHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHLeftTop.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="TopCenterHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHCenterTop.png" alt="">' +
											'</a>' + 
										'</li>' +  
										'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="TopRightHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHRightTop.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li >'+ 
											'<a  href="#" class="select-position" data-position="outside" data-description="BottomLeftHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHLeftBottom.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="BottomCenterHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHCenterBottom.png" alt="">' +
											'</a>' + 
										'</li>' +  
										'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="BottomRightHorizontal">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideHRightBottom.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li >'+ 
											'<a  href="#" class="select-position" data-position="outside" data-description="TopLeftVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVLeftTop.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="TopRightVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVRightTop.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li >'+ 
											'<a  href="#" class="select-position" data-position="outside" data-description="BottomLeftVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVLeftBottom.png" alt="">' +
											'</a>' + 
										'</li>' + 
										'<li>' + 
											'<a  href="#" class="select-position" data-position="outside" data-description="BottomRightVertical">' +
												'<img src="' + WISE.Constants.context + '/resources/main/images/ico_outsideVRightBottom.png" alt="">' +
											'</a>' + 
										'</li>' + 
									'</ul>' + 
								'</div>'							
							).appendTo(contentElement);
//						}
						/* DOGFOOT hsshim 2020-02-06 끝 */
						// toggle legend visibility
						$('#' + self.itemid + '_toggleLegend').dxButton({
                            text: '범례 표시',
							onClick: function() {
								self.RangeBarChart.ChartLegend.Visible = !self.RangeBarChart.ChartLegend.Visible;
								self.dxItem.option('legend.visible', self.RangeBarChart.ChartLegend.Visible);
							}
                        });
                        
						$.each($('.select-position'), function(index, position) {
							if (self.RangeBarChart.ChartLegend.IsInsidePosition) {
								if (self.RangeBarChart.ChartLegend.InsidePosition === $(position).data('description')
								       && $(position).data('position') === 'inside') {
									$(position).addClass('on');
									return false;
								}
							} else {
								if (self.RangeBarChart.ChartLegend.OutsidePosition === $(position).data('description')
								    && $(position).data('position') === 'outside') {
									$(position).addClass('on');
									return false;
								}
							}
						});
						
						$('.select-position').off('click').on('click', function(e) {
                            $('.select-position.on').removeClass('on');
							$(this).addClass('on');
							var newPosition = $(this).data('position');
							var newDescription = $(this).data('description');
							if (newPosition === 'inside') {
								self.RangeBarChart.ChartLegend.IsInsidePosition = true;
								self.RangeBarChart.ChartLegend.InsidePosition = newDescription;
							} else {
								self.RangeBarChart.ChartLegend.IsInsidePosition = false;
								self.RangeBarChart.ChartLegend.OutsidePosition = newDescription;
							}
							var newLegend = self.CU.Legend.get(self.RangeBarChart.ChartLegend);
                            self.dxItem.option('legend', newLegend);
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			}
			// change chart type 
			case 'editStyle': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#editStyle',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopover');
					},
					contentTemplate: function(contentElement) {
						$(	"<div style=\"height: 400px; width: 370px;\">" +
							"	<div class=\"add-item noitem\"><span class=\"add-item-head on\">막대</span>" + 
							"		<ul class=\"add-item-body icon-radio-list\">" + 
							"			<li >" + 
							"				<a  href=\"#\" class=\"select-style\" seriestype=\"Bar\" title=\"막대\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_bar2.png\" alt=\"\"><span>막대</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a  href=\"#\" class=\"select-style\" seriestype=\"StackedBar\" title=\"스택 막대\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_bar3.png\" alt=\"\"><span>스택 막대</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a  href=\"#\" class=\"select-style\" seriestype=\"FullStackedBar\" title=\"풀스택 막대\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_bar4.png\" alt=\"\"><span>풀스택 막대</span></a>" + 
							"			</li>" + 
							"		</ul>" + 
							"	</div>" + 
							"	<div class=\"add-item noitem\"><span class=\"add-item-head on\">선</span>" + 
							"		<ul class=\"add-item-body icon-radio-list\">" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"Scatter\" title=\"점\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine1.png\" alt=\"\"><span>점</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"Line\" title=\"선\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine2.png\" alt=\"\"><span>선</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"StackedLine\" title=\"스택 선\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine3.png\" alt=\"\"><span>스택 선</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"FullStackedLine\" title=\"풀스택 선\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine4.png\" alt=\"\"><span>풀스택 선</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"StepLine\" title=\"계단\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine5.png\" alt=\"\"><span>계단</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"Spline\" title=\"곡선\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine6.png\" alt=\"\"><span>곡선</span></a>" + 
							"			</li>" + 
							"		</ul>" + 
							"	</div>" + 
							"	<div class=\"add-item noitem\"><span class=\"add-item-head on\">영역</span>" + 
							"		<ul class=\"add-item-body icon-radio-list\">" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"Area\" title=\"영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area1.png\" alt=\"\"><span>영역</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"StackedArea\" title=\"스택 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area2.png\" alt=\"\"><span>스택 영역</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"FullStackedArea\" title=\"풀스택 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area3.png\" alt=\"\"><span>풀스택 영역</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"StepArea\" title=\"계단 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area4.png\" alt=\"\"><span>계단 영역</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"SplineArea\" title=\"곡선 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area5.png\" alt=\"\"><span>곡선 영역</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"StackedSplineArea\" title=\"스택 곡선 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area6.png\" alt=\"\"><span>스택 곡선 영역</span></a>" + 
							"			</li>" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"FullStackedSplineArea\" title=\"풀스택 곡선 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area7.png\" alt=\"\"><span>풀스택 곡선 영역</span></a>" + 
							"			</li>" + 
							"		</ul>" + 
							"	</div>" +
							"	<div class=\"add-item noitem\"><span class=\"add-item-head on\">버블</span>" + 
							"		<ul class=\"add-item-body icon-radio-list\">" + 
							"			<li>" + 
							"				<a href=\"#\" class=\"select-style\" seriestype=\"Bubble\" title=\"버블\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_bubble1.png\" alt=\"\"><span>버블</span></a>" + 
							"			</li>" + 
							"		</ul>" + 
							"	</div>" +
							"</div>"							
						).appendTo(contentElement);
						
						$.each($('.select-style'), function(index, style) {
							if (self.RangeBarChart['SeriesType'] === $(style).attr('seriestype').toLowerCase()) {
								style.classList.add('on');
							}
						});
						
						$('.select-style').off('click').on('click', function() {
							var type = $(this).attr('seriestype');
                            $('.select-style.on').removeClass('on');
                            $(this).addClass('on');
							var newStyle = type.toLowerCase();
							$('.chart.seriesoption:visible').each(function(i, e) {
								$(e).data('dataItemOptions').seriesType = type;
							});
							if (newStyle === 'bubble' || self.RangeBarChart.SeriesType === 'bubble') {
								self.RangeBarChart.SeriesType = newStyle;
								self.fieldManager.seriesType = type;
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData);
							} else {
								self.RangeBarChart.SeriesType = newStyle;
								self.fieldManager.seriesType = type;
								$.each(WISE.util.Object.toArray(self.RangeBarChart.Panes.Pane.Series.Simple), function(sIndex, series) {
									series.SeriesType = newStyle;
								});
								$.each(self.dxItem.series, function(index, _series) {
									_series.type = newStyle;
								});
								$.each(self.dxItem.option('series'), function(index, element) {
									self.dxItem.option('series[' + index + '].type', newStyle);
								});
							}
							self.dxItem.option('valueAxis[0].visualRange', [0, null]);
							self.dxItem.refresh();
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			}
			// edit color scheme
			case 'editPalette': {
				if (!(self.dxItem)) {
					break;
				}
				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office'];
				//2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 DOGFOOT
				var paletteCollection2 = ['밝음', '발광체', '바다', '파스텔', '부드러움', '연한 파스텔', '나무', '포도', 
					'단색', '우주', '진보라', '안개숲', '연파랑', '기본값', '사무실 테마'];
				var paletteObject = {
						'Bright':'밝음',
						'Harmony Light':'발광체',
						'Ocean':'바다',
						'Pastel':'파스텔',
						'Soft':'부드러움',
						'Soft Pastel':'연한 파스텔',
						'Vintage':'나무',
						'Violet':'포도',
						'Carmine':'단색',
						'Dark Moon':'우주',
						'Dark Violet':'진보라',
						'Green Mist':'안개숲',
						'Soft Blue':'연파랑',
						'Material':'기본값',
						'Office':'사무실 테마',
						'Custom':'사용자 정의 테마',
					};
				var paletteObject2 = {
					'밝음':'Bright',
					'발광체':'Harmony Light',
					'바다':'Ocean',
					'파스텔':'Pastel',
					'부드러움':'Soft',
					'연한 파스텔':'Soft Pastel',
					'나무':'Vintage',
					'포도':'Violet',
					'단색':'Carmine',
					'우주':'Dark Moon',
					'진보라':'Dark Violet',
					'안개숲':'Green Mist',
					'연파랑':'Soft Blue',
					'기본값':'Material',
					'사무실 테마':'Office',
					'사용자 정의 테마':'Custom',
				};
				
				if (self.customPalette.length > 0) {
					paletteCollection.push('Custom');
					paletteCollection2.push('사용자 정의 테마');
				}
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chagePalette = self.RangeBarChart.Palette;
				p.option({
                    target: '#editPalette',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // create html layout
                        var html = 	'<div id="' + self.itemid + '_paletteBox"></div>' +
								 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="save-ok" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="save-cancel" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        var select = $('#' + self.itemid + '_paletteBox');
                        // palette select
                        var originalPalette = paletteCollection.indexOf(self.RangeBarChart.Palette) != -1
										? self.RangeBarChart.Palette
										: 'Custom';
						select.dxSelectBox({
                            width: 400,
                            items: paletteCollection2,
                            itemTemplate: function(data) {
                                var html = $('<div />');
                                $('<p />').text(data).css({
                                    display: 'inline-block',
                                    float: 'left'
                                }).appendTo(html);
                                var itemPalette = data === '사용자 정의 테마'
										? self.customPalette 
										: DevExpress.viz.getPalette(paletteObject2[data]).simpleSet;
                                for (var i = 5; i >= 0; i--) {
                                    $('<div />').css({
                                        backgroundColor: itemPalette[i],
                                        height: 30,
                                        width: 30,
                                        display: 'inline-block',
                                        float: 'right'
                                    }).appendTo(html);
                                }
                                return html;
                            },
							value: paletteObject[originalPalette],
							onValueChanged: function(e) {
								if (e.value == '사용자 정의 테마') {
                                    self.isCustomPalette = true;
                                    self.dxItem.option('palette', self.customPalette);
								} else {
                                    self.isCustomPalette = false;
                                    self.dxItem.option('palette', paletteObject2[e.value]);
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.RangeBarChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                            self.dxItem.option('palette', self.RangeBarChart.Palette);
                            chagePalette = self.RangeBarChart.Palette;
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.RangeBarChart.Palette = chagePalette;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
			// set custom colors
			case 'customPalette': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '색상 편집',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
                        var colorContainer = $('<div id="colorContainer"></div>');
						self.dxItem.option('series').forEach(function(item, index) {
							colorContainer.append('<p>' + self.dxItem.option('series[' + index + '].name') 
													+ '</p><div id="' + self.itemid + '_seriesColor' + index + '"></div>');
						});
                        colorContainer.dxScrollView({
                            height: 600,
                            width: '100%'
                        }).appendTo(contentElement);
						var html = 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
						contentElement.append(html);

                        self.dxItem.option('series').forEach(function(item, index) {
							$('#' + self.itemid + '_seriesColor' + index).dxColorBox({
								value: self.dxItem.getAllSeries()[index].getColor()
							});
                        });

                        // confirm and cancel
						$('#ok-hide').on('click', function() {
                            var newPalette = [];
                            self.dxItem.series.forEach(function(item, index) {
                                newPalette[index] = $('#' + self.itemid + '_seriesColor' + index).dxColorBox('instance').option('value');
                            });
                            self.RangeBarChart['Palette'] = newPalette;
                            self.dxItem.option('palette', newPalette);
                            self.customPalette = newPalette;
                            self.isCustomPalette = true;
                            p.hide();
						});
						$('#close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			// set animation style
			case 'editAnimation': {
				if (!(self.dxItem)) {
					break;
                }
                var mapping = {
                    '없음': 'none',
                    '입방': 'easeOutCubic',
                    '선형': 'linear',
                    'none': '없음',
                    'easeOutCubic': '입방',
                    'linear': '선형'
                };
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#editAnimation',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        contentElement.empty();
						contentElement.append('<div id="' + self.itemid + '_editAnimation">');
						$('#' + self.itemid + '_editAnimation').dxRadioGroup({
							dataSource: ['없음', '입방', '선형'],
                            value: mapping[self.RangeBarChart['Animation']],
                            width: 70,
							onValueChanged: function(e) {
								self.RangeBarChart['Animation'] = mapping[e.value];
								if (e.value === '없음') {
									self.dxItem.option('animation.enabled', false);
								} else {
									self.dxItem.option({
										animation: {
											enabled: true,
											easing: self.RangeBarChart['Animation']
										}
									});
                                }
                                self.dxItem.refresh();
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
            }
			default: break;
		}
	}
};

WISE.namespace('WISE.libs.Dashboard.item.RangeBarChart');
WISE.libs.Dashboard.item.RangeBarChart.Series = function() {
	this.DU = WISE.libs.Dashboard.item.DataUtility;
	this.CU =  WISE.libs.Dashboard.item.ChartUtility;
	this.CTN = WISE.libs.Dashboard.item.ChartUtility.Constants; 
};
WISE.libs.Dashboard.item.RangeBarChart.Series.prototype = {
	pane: undefined,
	serieses: undefined,
	seriesDimensionColumnNames: undefined,
	point: undefined,
	valueAxis: undefined,
	
	axis:{},
//	dimensions: [],
	measures: [],
//	seriesDimensions: [],
	
	getSeriesList: function() {
		switch(this.renderType) {
		case 'NO-DIMENSTIONS':
		case 'ARGUMENTS-ONLY':
			return this.getSeriesListByValues();
			break;
		}
	},
	getSeriesListByValues: function() {
		return [];
	},
	getSeriesListBySeriesDimensions: function() {
		return [];
	},
	getMeasureDataMember: function(uniqueName) {
		var dataMember;
		_.each(this.measures, function(_m) {
			if (_m.uniqueName === uniqueName) {
				dataMember = _m;
				return false;
			}
		});
		
		_.each(this.measures, function(_m) {
			if (_m.uniqueName === uniqueName) {
				dataMember = _m;
				return false;
			}
		});
		
		
		return dataMember;
	},
	
	setAxisY: function(_S, _dataMember, _series) {
		var axisY;
		if (_S['PlotOnSecondaryAxis']) {
			_series.axis = this.pane.name + '-SECONDARY-Y';
			axisY = this.axis.SY;
		}
		else {
			_series.axis = this.pane.name + '-DEFAULT-Y';
			axisY = this.axis.Y;
		}
		
		/*
		 * fullstackedbar
		 * fullstackedline
		 * fullstackedarea
		 * fullstackedsplinearea
		 */
		if (_series.type && _series.type.indexOf('full') === 0) {
			axisY.label.format = undefined;
		}
		
		return axisY;
	}
};

WISE.libs.Dashboard.item.RangeBarChart.SimpleSeries = WISE.util.Object.extend(WISE.libs.Dashboard.item.RangeBarChart.Series);
WISE.libs.Dashboard.item.RangeBarChart.SimpleSeries.prototype.seriesType = undefined;
WISE.libs.Dashboard.item.RangeBarChart.SimpleSeries.prototype.defineCommonOption = function(_S, _dataMember, _series) {
	switch (_series.type) {
	case 'bar':	
	case 'stackedbar':	
	case 'fullstackedbar':	
	case 'scatter':	
		break;
	default:
		if(typeof this.point != 'undefined'){
			_series.point = this.point;
		}
	}
};
WISE.libs.Dashboard.item.RangeBarChart.SimpleSeries.prototype.getSeriesListByValues = function() {
	var self = this;
	var seriesList = [];
	var labelList = {};
	var deltaseries = [];
	var deltaUninqeName;
	_.each(WISE.util.Object.toArray(this.serieses), function(_S,_i) {
		var uniqueName = _S['Value']['UniqueName'];
		var dataMember = self.getMeasureDataMember(uniqueName);
		var deltaMember;
		var format = {};
		$.each(WISE.util.Object.toArray(self.measureMeta), function(i, mm) {
			if (mm.UniqueName === uniqueName) {
				if(typeof mm.DeltaItem != 'undefined' && mm.DeltaItem != ""){
					deltaMember = self.getMeasureDataMember(mm.DeltaItem);
					deltaUninqeName = mm.DeltaItem;
				}
				if (typeof mm.NumericFormat !== 'undefined') {
					format = mm.NumericFormat;
				}
				return false;
			}
		});
		if(dataMember != undefined){
			var type = self.CU.Series.Simple.getSeriesType(self.seriesType || _S['SeriesType']);
			var series = {
				wiseUniqueName: uniqueName,
				pane: self.pane.name,
				type: type,
				valueField: dataMember.nameBySummaryType,
//				valueField: dataMember.caption,
				point: typeof _S.point != 'undefined'?_S['point'] :{visible:false},
				ignoreEmptyPoints: typeof _S.ignoreEmptyPoints != 'undefined'? _S['ignoreEmptyPoints'] : false,
				// barWidth:80
				barPadding: 80
			};
			// label
			var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember, format);
			if (series.type === 'fullstackedbar' || series.type === 'stackedbar') label.position = 'inside';
			
			if(label.font){
				var font = gDashboard.fontManager.getDxItemLabelFont();
				label.font.size = font.size;
				label.font.family = font.family;
				series.label = label;
			}else
				label.font = gDashboard.fontManager.getDxItemLabelFont();
		
			series.label = label;
			if(_S['PointLabelOptions']){
				labelList = label;
			}
			var axisY = self.setAxisY(_S, dataMember, series);
			deltaseries[uniqueName] = series; 
			self.defineCommonOption(_S, dataMember, series);
			if(_i != 0 && _i%2 == 1){
				deltaseries[deltaUninqeName].rangeValue1Field = deltaMember.nameBySummaryType;
				deltaseries[deltaUninqeName].rangeValue2Field = dataMember.nameBySummaryType;
				deltaseries[deltaUninqeName].name =  deltaMember.caption + '-' + dataMember.caption;
				deltaseries[deltaUninqeName].label = labelList;
				seriesList.push(deltaseries[deltaUninqeName]);
			}
			
		}
		
	});
	
	return seriesList;
};
WISE.libs.Dashboard.item.RangeBarChart.SimpleSeries.prototype.getSeriesListBySeriesDimensions = function() {
	var self = this;
	var seriesList = [];
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		_.each(self.seriesDimensionColumnNames, function(_SDNM) {
			var uniqueName = _S['Value']['UniqueName'];
			var dataMember = self.getMeasureDataMember(uniqueName);
			var format = {};
			$.each(WISE.util.Object.toArray(self.measureMeta), function(i, mm) {
				if (mm.UniqueName === uniqueName) {
					if (typeof mm.NumericFormat !== 'undefined') {
						format = mm.NumericFormat;
					}
					return false;
				}
			});
			
			if(dataMember != undefined){
				var type = self.CU.Series.Simple.getSeriesType(self.seriesType || _S['SeriesType']);
				var seriesName = _SDNM + '-' +  dataMember.nameBySummaryType;
				var seriesCaption = _SDNM + '-' +  dataMember.caption;
				var series = {
					wiseUniqueName: uniqueName,
					pane: self.pane.name,
					type: type,
					valueField: seriesName,
					point: typeof _S.point != 'undefined'?_S['point'] :{visible:false},
					ignoreEmptyPoints: typeof _S.ignoreEmptyPoints != 'undefined'? _S['ignoreEmptyPoints'] : false,
					name: ($.type(self.serieses) === 'array' && self.serieses.length > 1) ? seriesCaption : _SDNM 
				};
				
				// label
				var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember, format);
				if (series.type === 'fullstackedbar' || series.type === 'stackedbar') label.position = 'inside';
				series.label = label;
				var axisY = self.setAxisY(_S, dataMember, series);
				
				self.defineCommonOption(_S, dataMember, series);
				seriesList.push(series);
			}
			
		});
	});
	
	return seriesList;
};

WISE.libs.Dashboard.item.RangeBarChart.RangeSeries = WISE.util.Object.extend(WISE.libs.Dashboard.item.RangeBarChart.Series);
WISE.libs.Dashboard.item.RangeBarChart.RangeSeries.prototype.getSeriesListByValues = function() {
	var self = this;
	var seriesList = [];
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		var format = {};
		var uniqueName1, uniqueName2;
		var dataMember1, dataMember2;
		if (_S['Value1']) {
			uniqueName1 = _S['Value1']['UniqueName'];
			dataMember1 = self.getMeasureDataMember(uniqueName1);
		}
		if (_S['Value2']) {
			uniqueName2 = _S['Value2']['UniqueName'];
			dataMember2 = self.getMeasureDataMember(uniqueName2);
		}
		
		uniqueName1 = uniqueName1 ? uniqueName1 : uniqueName2;
		dataMember1 = dataMember1 ? dataMember1 : _.clone(dataMember2);
		
		uniqueName2 = uniqueName2 ? uniqueName2 : uniqueName1;
		dataMember2 = dataMember2 ? dataMember2 : _.clone(dataMember1);

		$.each(WISE.util.Object.toArray(self.measureMeta), function(i, mm) {
			if (mm.UniqueName === uniqueName1) {
				if (typeof mm.NumericFormat !== 'undefined') {
					format = mm.NumericFormat;
				}
				return false;
			}
		});
		
		var seriesName = (uniqueName1 === uniqueName2 ? dataMember1.caption : dataMember1.caption + (dataMember2 ? ' - ' + dataMember2.caption : ''));
		var series = {
			wiseUniqueName: uniqueName1,
			pane: self.pane.name,
			type: (_S['SeriesType'] || 'RangeBar').toLowerCase(),
			rangeValue1Field: dataMember1.nameBySummaryType,
			rangeValue2Field: dataMember2.nameBySummaryType,
			name: _S['Name'] || seriesName
		};
		
		// label
		var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember1, format);
		// label.position = 'outside';
		series.label = label;
		
		var axisY = self.setAxisY(_S, dataMember1, series);
		
		seriesList.push(series);
	});
	
	return seriesList;
};
WISE.libs.Dashboard.item.RangeBarChart.RangeSeries.prototype.getSeriesListBySeriesDimensions = function() {
	var self = this;
	var seriesList = [];
	
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		_.each(self.seriesDimensionColumnNames, function(_SDNM) {
			var format = {};
			var uniqueName1, uniqueName2;
			var dataMember1, dataMember2;
			if (_S['Value1']) {
				uniqueName1 = _S['Value1']['UniqueName'];
				dataMember1 = self.getMeasureDataMember(uniqueName1);
			}
			if (_S['Value2']) {
				uniqueName2 = _S['Value2']['UniqueName'];
				dataMember2 = self.getMeasureDataMember(uniqueName2);
			}
			
			uniqueName1 = uniqueName1 ? uniqueName1 : uniqueName2;
			dataMember1 = dataMember1 ? dataMember1 : _.clone(dataMember2);
			
			uniqueName2 = uniqueName2 ? uniqueName2 : uniqueName1;
			dataMember2 = dataMember2 ? dataMember2 : _.clone(dataMember1);

			$.each(WISE.util.Object.toArray(self.measureMeta), function(i, mm) {
			if (mm.UniqueName === uniqueName1) {
				if (typeof mm.NumericFormat !== 'undefined') {
					format = mm.NumericFormat;
				}
				return false;
			}
		});
			
			var series = {
				wiseUniqueName: uniqueName1,
				pane: self.pane.name,
				type: (_S['SeriesType'] || 'RangeBar').toLowerCase(),
				rangeValue1Field: _SDNM + '-' +  dataMember1.caption,
				rangeValue2Field: _SDNM + '-' +  dataMember2.caption,
				name: _S['Name'] ||_SDNM
			};
			
			// label
			var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember1, format);
			// label.position = 'outside';
			series.label = label;
			
			var axisY = self.setAxisY(_S, dataMember1, series);
			
			seriesList.push(series);
		});
	});
	
	return seriesList;
};

WISE.libs.Dashboard.item.RangeBarChart.BubbleSeries = WISE.util.Object.extend(WISE.libs.Dashboard.item.RangeBarChart.Series);
WISE.libs.Dashboard.item.RangeBarChart.BubbleSeries.prototype.getSeriesListByValues = function() {
	var self = this;
	var seriesList = [];
	
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		var format = {};
		var uniqueName1, uniqueName2;
		var dataMember1, dataMember2;
		if (_S['Value']) {
			uniqueName1 = _S['Value']['UniqueName'];
			dataMember1 = self.getMeasureDataMember(uniqueName1);
		}
		if (_S['Weight']) {
			uniqueName2 = _S['Weight']['UniqueName'];
			dataMember2 = self.getMeasureDataMember(uniqueName2);
		}
		
		uniqueName1 = uniqueName1 ? uniqueName1 : uniqueName2;
		dataMember1 = dataMember1 ? dataMember1 : _.clone(dataMember2);
		
		uniqueName2 = uniqueName2 ? uniqueName2 : uniqueName1;
		dataMember2 = dataMember2 ? dataMember2 : _.clone(dataMember1);

		$.each(WISE.util.Object.toArray(self.measureMeta), function(i, mm) {
			if (mm.UniqueName === uniqueName1) {
				if (typeof mm.NumericFormat !== 'undefined') {
					format = mm.NumericFormat;
				}
				return false;
			}
		});
		
		var seriesName = (uniqueName1 === uniqueName2 ? dataMember1.caption : dataMember1.caption + (dataMember2 ? ' - ' + dataMember2.caption : ''));
		var series = {
			wiseUniqueName: uniqueName1,
			pane: self.pane.name,
			type: 'bubble',
			valueField: dataMember1.nameBySummaryType,
			sizeField: dataMember2.nameBySummaryType,
			name: _S['Name'] || seriesName
		};
		
		// label
		var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember1, format);
		// label.position = _S.PointLabelOptions.Position.toLowerCase();
		series.label = label;
		
		var axisY = self.setAxisY(_S, dataMember1, series);
		
		seriesList.push(series);
	});
	
	return seriesList;
};
WISE.libs.Dashboard.item.RangeBarChart.BubbleSeries.prototype.getSeriesListBySeriesDimensions = function() {
	var self = this;
	var seriesList = [];
	
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		_.each(self.seriesDimensionColumnNames, function(_SDNM) {
			var format = {};
			var uniqueName1, uniqueName2;
			var dataMember1, dataMember2;
			if (_S['Value']) {
				uniqueName1 = _S['Value']['UniqueName'];
				dataMember1 = self.getMeasureDataMember(uniqueName1);
			}
			if (_S['Weight']) {
				uniqueName2 = _S['Weight']['UniqueName'];
				dataMember2 = self.getMeasureDataMember(uniqueName2);
			}
			
			uniqueName1 = uniqueName1 ? uniqueName1 : uniqueName2;
			dataMember1 = dataMember1 ? dataMember1 : _.clone(dataMember2);
			
			uniqueName2 = uniqueName2 ? uniqueName2 : uniqueName1;
			dataMember2 = dataMember2 ? dataMember2 : _.clone(dataMember1);

			$.each(WISE.util.Object.toArray(self.measureMeta), function(i, mm) {
				if (mm.UniqueName === uniqueName1) {
					if (typeof mm.NumericFormat !== 'undefined') {
						format = mm.NumericFormat;
					}
					return false;
				}
			});
			/* DOGFOOT hsshim 2020-01-28 버블차트 차원/시리즈 오류 수정 */
			var series = {
				wiseUniqueName: uniqueName1,
				pane: self.pane.name,
				type: 'bubble',
				valueField: _SDNM + '-' +  dataMember1.nameBySummaryType,
				sizeField: _SDNM + '-' +  dataMember2.nameBySummaryType,
				name: _S['Name'] || _SDNM
			};
			

			
			/* DOGFOOT hsshim 2020-01-28 끝 */
			
			// label
			var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember1, format);
			// label.position = 'inside';
			series.label = label;
			
			var axisY = self.setAxisY(_S, dataMember1, series);
			
			seriesList.push(series);
		});
	});
	
	return seriesList;
};

WISE.libs.Dashboard.RangeBarChartFieldManager = function() {
	var self = this;
	
	this.initialized = false;
	this.alreadyFindOutMeta = false;
	
	//검색 - searchDisable
	this.searchDisable = false;
	//검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	//검색

	this.previousPanes = {};
	
	this.meta;
	this.isChange = false; // 사용자가 필드를 변경했는지 여부 체크
	this.columnMeta = {}; // 쿼리된 모든 컬럼정보 저장
	this.isColumnChooser = false;
	
	this.dataItemNo=0;
	
	this.all = [];
	this.values = [];
	this.arguments = [];
	this.series = [];
	this.hide_column_list_dim = [];
	this.hide_column_list_mea = [];
	
	this.tables = [];
	
	this.Constants = {
		CUSTOMIZED: '계산된필드',
		DELTA: '변동측정필드',
		UNSELECTED_FIELD: 'UNSELECTED_FIELD'
	}
	
	this.init = function() {
		this.columnMeta = {};
		this.tables = [];
		this.all = [];
		this.values = [];
		this.arguments = [];
		this.series = [];
		this.hide_column_list_dim = [];
		this.hide_column_list_mea = [];
		this.meta = gDashboard.structure.ReportMasterInfo.dataSource;
		this.previousPanes = {};
	};
	
	this.setMetaTables = function(tables){
		this.meta.tables = tables;
	}
	
	this.setDataItemByField = function(_fieldlist){
		this.DataItems = {};
		self.DataItems['Dimension'] = [];
		self.DataItems['Measure'] = [];
//		var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
		
		for(var i = 0; i < _fieldlist.length; i++){
			var listType = $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'rangebarchartValueList' || $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'rangebarchart_hide_measure_list' ||
			$(_fieldlist[i]).attr('prev-container') === 'delta-drop'? true : false;
//			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
			if(!listType){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				if (self.seriesType === 'Bubble') {
					dataItem['ColoringMode'] = 'Hue';
				}
				/*
				 * LSH topN
				 * */
				if($(_fieldlist[i]).attr('TopNEnabled')=="true"){
					dataItem['TopNEnabled'] = ($(_fieldlist[i]).attr('TopNEnabled')==='true');
					dataItem['TopNCount'] = $(_fieldlist[i]).attr('TopNCount');
					dataItem['TopNMeasure'] = $(_fieldlist[i]).attr('TopNMeasure');
					if($(_fieldlist[i]).attr('TopNShowOthers')==='true'){
						dataItem['TopNShowOthers'] = true;
					}
                }
				self.DataItems['Dimension'].push(dataItem);
//			} else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
			}else{
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = NumericFormat;
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				if($(_fieldlist[i]).hasClass('delta-drop')){
					dataItem['DeltaItem'] = $(_fieldlist[i-1]).attr('dataitem');
				}
				if (self.seriesType === 'Bubble') {
					dataItem['ColoringMode'] = 'Hue';
				}
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};
	
	this.setPanesByField = function(_panes){
		this.Panes = {};
		self.Panes.Pane = { Name: "창 1", Series: {} };	
		this.panelabeloption = [];
		_.each(_panes,function(_p) {
				var overlappingMode = 'Hide';
				if(_p.options ==  undefined){
					var optionItem;
					$.each(self.DataItems.Measure, function(_i,_measure){
						if(_measure.UniqueName === _p.uniqueName){
							if(_measure.DeltaItem != undefined && _measure.DeltaItem != ''){
                                optionItem = _measure.DeltaItem;
							}
						}
					})
					var Value = {
						SeriesType: 'rangeBar',
						PlotOnSecondaryAxis: false,
						IgnoreEmptyPoints: false,
						ShowPointMarkers: false,
						PointLabelOptions: {
							Orientation:self.panelabeloption[optionItem].pointLabelOptions == undefined ? '' : self.panelabeloption[optionItem].pointLabelOptions.orientation,
							ContentType: self.panelabeloption[optionItem].pointLabelOptions == undefined ? '' :self.panelabeloption[optionItem].pointLabelOptions.contentType,
							OverlappingMode: overlappingMode,
							ShowForZeroValues: self.panelabeloption[optionItem].pointLabelOptions == undefined ? false : self.panelabeloption[optionItem].pointLabelOptions.showForZeroValues,
							Position: self.panelabeloption[optionItem].pointLabelOptions == undefined ? '' :self.panelabeloption[optionItem].pointLabelOptions.position,
							FillBackground: self.panelabeloption[optionItem].pointLabelOptions == undefined ? false : self.panelabeloption[optionItem].pointLabelOptions.fillBackground,
							ShowBorder: self.panelabeloption[optionItem].pointLabelOptions == undefined ? false : self.panelabeloption[optionItem].pointLabelOptions.showBorder,
							ShowCustomTextColor: self.panelabeloption[optionItem].pointLabelOptions == undefined ? false : self.panelabeloption[optionItem].pointLabelOptions.showCustomTextColor,
							CustomTextColor: self.panelabeloption[optionItem].pointLabelOptions == undefined ? '#000000' : self.panelabeloption[optionItem].pointLabelOptions.customTextColor
						}
					};
				}else{
					self.panelabeloption[_p.uniqueName] = _p.options;
					var Value = {
						SeriesType: 'rangeBar',
						PlotOnSecondaryAxis: false,
						IgnoreEmptyPoints: false,
						ShowPointMarkers:  false,
						PointLabelOptions: {
							Orientation:_p.options.pointLabelOptions == undefined ? '' : _p.options.pointLabelOptions.orientation,
							ContentType: _p.options.pointLabelOptions == undefined ? '' :_p.options.pointLabelOptions.contentType,
							OverlappingMode: overlappingMode,
							ShowForZeroValues: _p.options.pointLabelOptions == undefined ? false : _p.options.pointLabelOptions.showForZeroValues,
							Position: _p.options.pointLabelOptions == undefined ? '' :_p.options.pointLabelOptions.position,
							FillBackground: _p.options.pointLabelOptions == undefined ? false : _p.options.pointLabelOptions.fillBackground,
							ShowBorder: _p.options.pointLabelOptions == undefined ? false : _p.options.pointLabelOptions.showBorder,
							ShowCustomTextColor: _p.options.pointLabelOptions == undefined ? false : _p.options.pointLabelOptions.showCustomTextColor,
							CustomTextColor: _p.options.pointLabelOptions == undefined ? '#000000' : _p.options.pointLabelOptions.customTextColor
						}
					};
				}
		
				if (self.Panes.Pane.Series.Simple == null) {
					self.Panes.Pane.Series.Simple = [];					
				}
				if(!_p.ishidden) {
					Value.Value = { UniqueName: _p.uniqueName };
					self.Panes.Pane.Series.Simple.push(Value);
				}
				
		});
		return self.Panes;
	};
	
	this.setSeriesDimensionsByField = function(_series){
		this.SeriesDimensions = {'SeriesDimension' : []};
		_.each(_series,function(_s){
			var Value = {'UniqueName' : _s.uniqueName};
			self.SeriesDimensions['SeriesDimension'].push(Value);
		})
		return self.SeriesDimensions;
	};
	
	this.setArgumentsByField = function(_argument){
		this.Arguments = {'Argument' : []};
		_.each(_argument,function(_a){
			var Value = {'UniqueName' : _a.uniqueName};
			self.Arguments['Argument'].push(Value);
		})
		return self.Arguments;
	};
	
	this.setHiddenMeasuresByField = function(_hiddenMeasure){
		this.HiddenMeasures = {'Measure' : []};
		_.each(_hiddenMeasure,function(_a){
			/* DOGFOOT ktkang 대시보드 주제영역 정렬 기준 항목 오류 수정  20200707 */
			var Value = {'UniqueName' : _a.uniqueName, 'cubeUniqueName': _a.cubeUniqueName};
			self.HiddenMeasures['Measure'].push(Value);
		})
		return self.HiddenMeasures;
	};
	
};
