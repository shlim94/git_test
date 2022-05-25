/*
 * BUGS:
 *     - multiple series not working if series names are changed
 *     - drill down not working with series
 */
WISE.libs.Dashboard.item.StarChartGenerator = function() {
	var self = this;
	
	this.type = 'STAR_CHART';
	
	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	this.topN;
	this.topItem;
	this.fieldManager;
	this.initialized;
	
	this.dimensions = [];
	this.measures = [];
	
	this.arguments = [];
	this.seriesDimensions = [];
	this.tooltipData = [];
	this.measureFormat = [];
	this.queriedData = [];
	
	// custom chart palette
	this.customPalette = [];
	this.isCustomPalette = false;
	
	// enable interactivity options
	this.enableIO = false;
    
	this.HueActive =false;
    this.rotated = false;
    this.selectedChartType;
    
    this.linkItemidBasten = [];
    
	var rootval;
	this.drillDownIndex; // must be number type
    
	var isFirstLevel = true;
	var firstlevel = 0;
	var leveling = 0;
	
    this.filter;
    this.hasCustomFields = {};
    
//  var trackedDataArray = new Array();
    var filterArray = new Array();
    var selectedPoint;
    
    this.StarChart = [];
    
 // 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
    
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
	this.getDxItemConfig = function(_chart) {
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
//		if(typeof(confMeasure['NumericFormat']) == 'object')
//		{
//			labelFormat =  typeof confMeasure['NumericFormat']['FormatType'] == 'undefined'? '' : typeof confMeasure['NumericFormat']['FormatType'];
//			labelPrecision = confMeasure['NumericFormat']['Precision'];
//			labelUnit = confMeasure['NumericFormat']['Unit'].substring(0,1);
//		}
		var findPointLabelOption = _chart['Panes']['Pane']['Series']['Simple'];
		if (findPointLabelOption) {
			$.each(findPointLabelOption,function(i,e) {
				if (typeof (e['PointLabelOptions']) != 'undefined') {
				$.each(Object.getOwnPropertyNames(e['PointLabelOptions']), function(j,ee) {
					if(ee == 'OverlappingMode')
						labelOverlappingOption = e['PointLabelOptions']['OverlappingMode'];
					})
				}
			});
		}
		switch(labelOverlappingOption) {
			case 'Reposition':
				labelOverlappingOption = 'stack';
				break;
			default :
				labelOverlappingOption = 'hide';
				break;
		}
		var colorList = typeof _chart.ColorSheme == 'undefined'? []: gDashboard.itemColorManager.generateColorMeta(_chart.ColorSheme.Entry);
		if(colorList.length === 0){
			colorList = gDashboard.itemColorManager.colorMeta
		}
		// var Colorindex = 0;
		var legnedHorizontalAlignement = "Left";
		var legendVisible = true;
		if(_chart['Legend'] != undefined){
			legnedHorizontalAlignement = _chart['Legend']['HorizontalAlignment'].toLowerCase();
			legendVisible = _chart['Legend']['Visible'];
		}
		
		var dxConfigs = {
            rotated: _chart['Rotated'],
            resolveLabelOverlapping : _chart['LabelOverlap'],
            dataSource: [],
    		commonSeriesSettings: {
    			//argumentField: 'arg' /* arg is default value for argumentField */
    		},
    		// default animation settings
    		animation: {
    			enabled: _chart['Animation'] === 'none' ? false : true,
    			easing: _chart['Animation'] === 'none' ? 'easeOutCubic' : _chart['Animation']
    		},
    		legend: {
//    			horizontalAlignment: _chart['Legend']['HorizontalAlignment'].toLowerCase(),
    			horizontalAlignment: legnedHorizontalAlignement,
    			visible: legendVisible,
    			orientation: 'horizontal',
    			verticalAlignment: 'top',
    			font: gDashboard.fontManager.getDxItemLabelFont()
    		},
    		argumentAxis:[],
    		series: [],
    		valueAxis: [],
    		panes:[],
    		palette: _chart['Palette'],
    		pointSelectionMode: 'multiple',
    		useSpiderWeb: true,
    		firstPointOnStartAngle:true,
		    tooltip: {
		    	enabled: true,
		    	position: 'outside',
		    	location: 'edge',
		    	font: gDashboard.fontManager.getDxItemLabelFont(),
		        customizeTooltip: function(_pointInfo) {
		        	var Number = WISE.util.Number;
		        	var labelFormat = 'Number',
					labelUnit = 'O',
					labelPrecision = 0,
					labelSeparator = true,
					labelSuffixEnabled = false,
					labelSuffix = {
						O: '',
						K: '천',
						M: '백만',
						B: '십억'
					};
		        	if(typeof(confMeasure['NumericFormat']) == 'object') {
	        			labelFormat = confMeasure['NumericFormat']['FormatType'];
	        			labelPrecision = confMeasure['NumericFormat']['Precision'];
						labelUnit = typeof confMeasure['NumericFormat']['Unit'] =='undefined'? undefined : confMeasure['NumericFormat']['Unit'].substring(0,1);
						labelSeparator = confMeasure['NumericFormat']['IncludeGroupSeparator'];
					/* 나중에 비정형일 때 포맷 변경해야하는 부분*/
	        		} else if (self.isAdhocItem == true) {
						labelFormat = 'Number';
						labelUnit = 'O';
						labelPrecision = 0;
						labelSeparator = true;
					} else {
		        		if (_chart['DataItems']['Measure'].length == 1) {
		        			if(_chart['DataItems']['Measure'][0].NumericFormat != undefined){
								labelFormat = typeof _chart['DataItems']['Measure'][0].NumericFormat.FormatType == 'undefined' ? '' : _chart['DataItems']['Measure'][0].NumericFormat.FormatType;
								labelUnit = typeof _chart['DataItems']['Measure'][0].NumericFormat.Unit == 'undefined'? undefined : _chart['DataItems']['Measure'][0].NumericFormat.Unit.substring(0,1);
								labelPrecision = typeof _chart['DataItems']['Measure'][0].NumericFormat.Precision == 'undefined' ? 2 : _chart['DataItems']['Measure'][0].NumericFormat.Precision;
								labelSeparator = typeof _chart['DataItems']['Measure'][0].NumericFormat.IncludeGroupSeparator == 'undefined' ? true : _chart['DataItems']['Measure'][0].NumericFormat.IncludeGroupSeparator;
								labelSuffixEnabled = typeof _chart['DataItems']['Measure'][0].NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : _chart['DataItems']['Measure'][0].NumericFormat.SuffixEnabled;
								labelSuffix = typeof _chart['DataItems']['Measure'][0].NumericFormat.Suffix == 'undefined' ? labelSuffix : _chart['DataItems']['Measure'][0].NumericFormat.Suffix;
							}
		        		} else {
							$.each(_chart['DataItems']['Measure'], function(i,k) {
								if (_pointInfo.seriesName.indexOf(k.DataMember) != -1 && typeof k.NumericFormat != 'undefined') {
									labelFormat = typeof k.NumericFormat.FormatType == 'undefined' ? '' : k.NumericFormat.FormatType;
									labelUnit = typeof k.NumericFormat.Unit == 'undefined'? undefined : k.NumericFormat.Unit.substring(0,1);
									labelPrecision = typeof k.NumericFormat.Precision == 'undefined' ? 2 : k.NumericFormat.Precision;
									labelSeparator = typeof k.NumericFormat.IncludeGroupSeparator == 'undefined' ? true : k.NumericFormat.IncludeGroupSeparator;
									labelSuffixEnabled = typeof k.NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : k.NumericFormat.SuffixEnabled;
									labelSuffix = typeof k.NumericFormat.Suffix == 'undefined' ? labelSuffix : k.NumericFormat.Suffix;
									return false;
								}
							});
		        		}
		        	}
					var text;
					if(_pointInfo.rangeValue1Text !== undefined) {
						text = '<b>' + _pointInfo.argumentText + '</b>' + '<br/>' + 
							'<b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.rangeValue1, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + 
							' - ' + Number.unit(_pointInfo.rangeValue2, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
					}
					// bubble series
					else if (_pointInfo.sizeText !== undefined) {
						text = '<b>' + _pointInfo.argumentText + '</b>' + '<br/>' + 
							'<b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + 
							' - ' + Number.unit(_pointInfo.size, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
					}
					// simple series
					else {
						text = '<div>' + _pointInfo.argumentText + '</div>' + 
							'<div><b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + '</div>';
					}
					// range series
//					if(_pointInfo.rangeValue1Text !== undefined) {
//						text = '<b>' + _pointInfo.argumentText + '</b>' + '<br/>' + '<b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.rangeValue1) + ' - ' + Number.unit(_pointInfo.rangeValue2);
//					}
					// bubble series
//					else if (_pointInfo.sizeText !== undefined) {
//						text = '<b>' + _pointInfo.argumentText + '</b>' + '<br/>' + '<b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.value) + ' - ' + Number.unit(_pointInfo.size);
//					}
					// simple series
//					else {
//						switch (labelFormat) {
//							case 'Percent':
//								text = '<div>' + _pointInfo.argumentText + '</div>' + 
//									'<div><b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.value * 100, labelUnit, labelPrecision, labelSeparator) + '%</div>';
//								break;
//							case 'General':
//								text = '<div>' + _pointInfo.argumentText + '</div>' + 
//									'<div><b>' + _pointInfo.seriesName + '</b>: ' + _pointInfo.value + '</div>';
//								break;
//							case 'Number':
//								text = '<div>' + _pointInfo.argumentText + '</div>' + 
//									'<div><b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.value, labelUnit, labelPrecision, labelSeparator) + '</div>';
//								break;
//							default:
//								text = '<div>' + _pointInfo.argumentText + '</div>' + 
//									'<div><b>' + _pointInfo.seriesName + '</b>: ' + Number.unit(_pointInfo.value) + '</div>';
//								break;
//						}
//					}

					return { html: text };
	        	}
		    },
			onPointClick: function(_e) {
				if (self.IO && self.IO['MasterFilterMode'] !== 'Off') {
					
					var reversed = self.IO['TargetDimensions'] === 'Series' ? _.clone(self.seriesDimensions) : _.clone(self.arguments).reverse();
					var selectedSeries = self.IO['TargetDimensions'] === 'Series' ? _e.target.series['name'].split('-') : _e.target.argument.split(',');


			
					switch(self.IO['MasterFilterMode']){
			       		case 'Multiple':
			       			$.each(reversed, function(_i, _ao) {
				       			var inArray = false;
				       			var selectedData = {};
				       			selectedData[_ao.name] = selectedSeries[_i];
				       			for (var index = 0; index < filterArray.length; index++) {
				       				if (filterArray[index][_ao.name] === selectedData[_ao.name]) {
				       					filterArray.splice(index, 1);
				       					index--;
				       					inArray = true;
				       				}
				       			}
				       			if (!inArray) {
				       				filterArray.push(selectedData);
				       			}

				       		});
			       			/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
    						if(WISE.Constants.editmode === "viewer"){
    							gDashboard.itemGenerateManager.focusedItem = self;
    						}
			           		window[self.dashboardid].filterData(self.itemid, filterArray,self.dataSourceId);
			           		var clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
			           		if (clearTrackingImg.src.indexOf('cont_box_icon_filter_disable.png') > -1) {
			           			$(clearTrackingImg)
			           				.attr('src', WISE.Constants.context + '/images/cont_box_icon_filter.png')
			           				.on('mouseover', function() {
			           					$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_.png');
			           				})
			           				.on('mouseout', function() {
			           					$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter.png');
			           				});
			           		}
			                break;
			       		case 'Single':
			       			if (selectedPoint && selectedPoint.isSelected()) {
			                    if (self.IO['TargetDimensions'] === 'Series') {
			                    	selectedPoint.series.getAllPoints().forEach(function(point) {
			                    		point.clearSelection();
			                    	});
			                    } else {
			                    	self.dxItem.getAllSeries().forEach(function(seriesItem) {
			                    		seriesItem.getPointsByArg(selectedPoint['originalArgument']).forEach(function(point) {
			                    			point.clearSelection();
			                    		});
			                    	});
			                    }
			       			}
			       			selectedPoint = _e.target;
			       			filterArray = new Array();
			       			$.each(reversed, function(_i, _ao) {
				       			var selectedData = {};
				       			selectedData[_ao.name] = selectedSeries[_i];
				       			filterArray.push(selectedData);

				       		});
			       			/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
    						if(WISE.Constants.editmode === "viewer"){
    							gDashboard.itemGenerateManager.focusedItem = self;
    						}
			           		window[self.dashboardid].filterData(self.itemid, filterArray,self.dataSourceId);
			           		var clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
			           		if (clearTrackingImg.src.indexOf('cont_box_icon_filter_disable.png') > -1) {
			           			$(clearTrackingImg)
			           				.attr('src', WISE.Constants.context + '/images/cont_box_icon_filter.png')
			           				.on('mouseover', function() {
			           					$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_.png');
			           				})
			           				.on('mouseout', function() {
			           					$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter.png');
			           				});
			           		}	
			                break;
					}
	           		// select and deselect point
	                if(_e.target.isSelected()) {
	                    if (self.IO['TargetDimensions'] === 'Series') {
	                    	_e.target.series.getAllPoints().forEach(function(point) {
	                    		point.clearSelection();
	                    	});
	                    } else {
	                    	self.dxItem.getAllSeries().forEach(function(seriesItem) {
	                    		seriesItem.getPointsByArg(_e.target['originalArgument']).forEach(function(point) {
	                    			point.clearSelection();
	                    		});
	                    	});
	                    }
	                } else { 
	                    if (self.IO['TargetDimensions'] === 'Series') {
	                    	_e.target.series.getAllPoints().forEach(function(point) {
	                    		point.select();
	                    	});
	                    } else {
	                    	self.dxItem.getAllSeries().forEach(function(seriesItem) {
	                    		seriesItem.getPointsByArg(_e.target['originalArgument']).forEach(function(point) {
	                    			point.select();
	                    		});
	                    	});
	                    }			                
	                }
				}
				else if (self.IO['IsDrillDownEnabled']) {
					// argument drill-down
					if (self.IO['TargetDimensions'] === 'Argument') {
						firstlevel++;
						self.dashItemSource = _e.component;
						if(isFirstLevel == true){
							rootval = (_e.target.originalArgument);
						}
						isFirstLevel = false;
						if(leveling >= firstlevel){
							_e.component.option({dataSource : filterData(_e.target.originalArgument,firstlevel)});
						}
					} 
					// series drill-down
					else if (self.IO['TargetDimensions'] === 'Series') {
						var newData = filterDataByParentKey(_e.target.series.name);
						var newSeries = [];
						if (newData.length > 0) {
							$.each(newData[0], function(seriesName) {
								$.each(self.measures, function(measureIndex, measure) {
									var seriesNameSplit = seriesName.split('-');
									if (seriesNameSplit[seriesNameSplit.length - 1] === measure.captionBySummaryType) {
										var tempSeries = {
											axis: 'default-DEFAULT-Y',
											name: seriesNameSplit[0],
											pane: 'default',
											type: self.StarChart['SeriesType'],
											valueField: seriesName
										};
										newSeries.push(tempSeries);
									}
								});
							});
							self.dxItem.option({
								dataSource: newData,
								series: newSeries
							});
						}
					}
		   			var clearDrilldownImg = $("#" + self.DrilldownClearId).find('img')[0];
		       		if (clearDrilldownImg.src.indexOf('cont_box_icon_filter_disable.png') > -1) {
		       			$(clearDrilldownImg)
		   				.attr('src', WISE.Constants.context + '/images/cont_box_icon_filter.png')
		   				.on('mouseover', function() {
		   					$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_.png');
		   				})
		   				.on('mouseout', function() {
		   					$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter.png');
		   				});
		       		}
				}
			},
		};
		
		// extend custom-configurations
		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
		var CustomConfigs = $.extend({}, Configurations);
		$.extend(CustomConfigs, dxConfigs);
		dxConfigs = CustomConfigs;
		
		// legend
		var legend = _chart['ChartLegend'];
		dxConfigs.legend = this.CU.Legend.get(legend);
		dxConfigs.legend.font = gDashboard.fontManager.getDxItemLabelFont();
		// Axis-X setting
		var xTitle = '',xVisible = false,xRotation = 90;
		if(_chart['AxisX'] != undefined){
			xTitle = _chart['AxisX']['Title'];
			xVisible =  _chart['AxisX']['Visible'];
			xRotation = _chart['AxisX']['Rotation'];
		}
		var X = {
			title: {
				text: xTitle,
				font: gDashboard.fontManager.getDxItemLabelFont()
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
//		if (axisX) {
//			var title = axisX['Title'] || _.pluck(this.arguments, 'caption').join('-');
//			_.extend(X, {
//				title: {text : axisX['Visible'] == false ? '' : (axisX['TitleVisible'] ? title : ''),font:self.CUSTOMIZED.get('axisY.title.font')},
//				inverted: axisX['Reverse']
//			});
//		}
		dxConfigs.argumentAxis = X;
		return dxConfigs;
	};
	
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
	
	this.clearTrackingConditions = function() {
//		if (self.IO && self.IO['MasterFilterMode']) {
//			if (this.dxItem) this.dxItem.clearSelection();
//			
//			$('#' + self.itemid + '_tracking_data_container').html('');
//			
//			var clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
//       		$(clearTrackingImg)
//       			.attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png')
//       			.on('mouseover', function() {
//       				$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
//       			})
//       			.on('mouseout', function() {
//       				$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
//       			});
//		}
	};
	
	this.__getRenderType = function() {
		if (this.arguments.length === 0 && this.seriesDimensions.length === 0) {
			return 'NO-DIMENSTIONS';
		} else if (this.arguments.length > 0 && this.seriesDimensions.length === 0) {
			return 'ARGUMENTS-ONLY';
		} else if (this.arguments.length === 0 && this.seriesDimensions.length > 0) {
			return 'SERIESDIMENSIONS-ONLY';
		} else if (this.arguments.length > 0 && this.seriesDimensions.length > 0) {
			return 'ARGUMENTS-AND-SERIESDIMENSIONS';
		} else {

            return undefined;
		}
	};
	
	this.__getChartData = function(_seriesType) {
//		var tempData = gDashboard.itemGenerateManager.doQueryData(self);
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;		
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		// var CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
		var dimensions = [];
		dimensions = dimensions.concat(_.clone(this.seriesDimensions));
		dimensions = dimensions.concat(_.clone(this.dimensions));

		//2020.02.04 mksong SQLLIKE 기능 추가 dogfoot
		var tempDataConfig = SQLikeUtil.fromJson(dimensions, this.measures, []);
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		var tempData = SQLikeUtil.doSqlLike(this.dataSourceId, tempDataConfig, self);
//        var tempData = SQLikeUtil.fromJson(dimensions, this.measures, this.filteredData);
		//2020.05.04 AJKIM 데이터 항목 없을 때 이미지 추가 DOGFOOT
		if(gDashboard.itemGenerateManager.noDataCheck(tempData, self)) return;
		
        var queryData = tempData;
        //2020.02.04 mksong filteredData 추가 dogfoot
        this.filteredData = queryData;
        
		switch(this.renderType) {
		case 'NO-DIMENSTIONS':
			_.each(queryData, function(_data) {
				_data['arg'] = 'Grand Total';
			});
			break;
		case 'ARGUMENTS-ONLY':
			_.each(queryData, function(_data) {
				var argBasket = [];
				_.each(self.arguments, function(_arg) {
					argBasket.push(_data[_arg.caption]);
				});
				_data['arg'] = argBasket.reverse().join('<br/>');
			});
			break;
		case 'SERIESDIMENSIONS-ONLY':
			var seriesDimensionColumnNames = [];
			var dataSet = {};
            dataSet['arg'] = 'Grand Total';
            
            _.each(queryData, function(_d) {
                var column = [];
                _.each(self.seriesDimensions, function(_sd) {
                    column.push(_d[_sd.caption]);
                });
                
                _.each(self.measures, function(_m) {
                    var columnNamePrefix = column.join('-');
                    seriesDimensionColumnNames.push(columnNamePrefix);
                    dataSet[columnNamePrefix + '-' + _m.caption] = _d[_m.captionBySummaryType]
                });
            });
            
            seriesDimensionColumnNames = _.uniq(seriesDimensionColumnNames);
            queryData = {seriesDimensionColumnNames: seriesDimensionColumnNames, data: [dataSet]};
			break;
		case 'ARGUMENTS-AND-SERIESDIMENSIONS':
			var dataSet = [];
			var seriesDimensionColumnNames = [];
			
			// sorting data by arguments
			var orderBy = [];
			
			//2020.02.04 mksong SQLLIKE doSqlLike 스타차트 적용 dogfoot
//			orderBy = orderBy.concat(self.arguments);
//			orderBy = orderBy.concat(self.seriesDimensions);
//			queryData = SQLikeUtil.fromJson('*', [], queryData, {orderBy:orderBy});
			
			// pluck column names from series-dimensions
			// arguments로 order by 후 추출해야 한다
			_.each(queryData, function(_d) {
				var column = [];
				_.each(self.seriesDimensions, function(_sd) {
					column.push(_d[_sd.caption]);
				});
				seriesDimensionColumnNames.push(column.join('-'));
			});
			seriesDimensionColumnNames = _.uniq(seriesDimensionColumnNames);
			
			// re-arrange data
			_.each(queryData, function(_d) {
				var column = [];
				_.each(self.seriesDimensions, function(_sd) {
					column.push(_d[_sd.caption]);
				});
				
				var argName = [];
				_.each(self.arguments, function(_arg) {
					argName.push(_d[_arg.caption]);
				});
				
				var subDataSet = [];
				_.each(self.measures, function(_m) {
					var columnNamePrefix = column.join('-');
					
					var d = {};
					d['arg'] = argName.reverse().join('<br/>');
					d[columnNamePrefix + '-' + _m.caption] = _d[_m.nameBySummaryType];
					subDataSet.push(d);
				});

				var rowData = {};
				_.each(subDataSet, function(_dao) {
					$.each(_dao, function(_k, _do) {
						if (!rowData[_k]) {
							rowData[_k] = _dao[_k];
						}
					});
				});
				
				dataSet.push(rowData);
			});
			
			queryData = {seriesDimensionColumnNames: seriesDimensionColumnNames, data: dataSet};
			break;
		}
		// drill down
		var temp = [];
		var itemname = [];
		if(self.IO && self.IO['IsDrillDownEnabled']){
			leveling = 0;
			var sqlConfig = {};
			sqlConfig.groupBy = [];
			sqlConfig.Select = [];
			// argument drill-down
			if (self.arguments.length > 0 && self.IO['TargetDimensions'] === 'Argument') {
				$.each(self.arguments,function(j,e){
					var valuearr;
					var realvaluearr;
					sqlConfig.From = tempData;
					sqlConfig.Select.push(e['name']);
					sqlConfig.Select.push(e['name'],'|as|','arg');
					$.each(self.measures,function(i,measures){
						valuearr = 'sum_'+measures['nameBySummaryType'];
						realvaluearr = measures['nameBySummaryType'];
						sqlConfig.Select.push('|sum|',measures['nameBySummaryType']);
					})
					sqlConfig.groupBy.push(e['name']);
					if(self.renderType == 'ARGUMENTS-AND-SERIESDIMENSIONS'){
						$.each(self.seriesDimensions,function(rooti,roote){
							sqlConfig.groupBy.push(roote['name']);
						})
					}
					var result = (SQLike.q(sqlConfig));
					var tt ="";

					itemname.push(e['name']);
					$.each(result,function(i,ee){
						if(ee[e['name']].toString() != ee[itemname[leveling]].toString()){
							tt =ee[itemname[leveling++]];
						}
						else{
							if(itemname.length ==1){
								switch(self.renderType) {
								case 'NO-DIMENSIONS':
								case 'ARGUMENTS-ONLY':
								case 'SERIESDIMENSIONS-ONLY':
									tt = "";
									break;
								case 'ARGUMENTS-AND-SERIESDIMENSIONS':
									tt = rootkey[i];
									break;
								}
							}else{
								tt =(ee[itemname[leveling-1]]);
							}
						}
						
						var obj = {};
						obj[e['name']] = ee[e['name']];
						obj['arg'] = ee['arg'];
						obj[realvaluearr] = ee[valuearr];
						obj['parentID'] = tt;
						obj['leveling'] = leveling;
						
						temp.push(obj);
					});
				});
			}
			// series drill-down
			else if (self.seriesDimensions.length > 0 && self.IO['TargetDimensions'] === 'Series') {
				$.each(self.seriesDimensions,function(j,e){
					var valuearr;
					var valueName;
					var sqlConfig = {};
					sqlConfig.groupBy = [];
					sqlConfig.Select = [];
					sqlConfig.From = tempData;
					sqlConfig.Select.push(e['name']);
					$.each(self.measures,function(i,measures){
						if (j === 0) {
							//
						} else {
							var parentKey = self.seriesDimensions[j - 1]['name'];
							sqlConfig.Select.push(parentKey, '|as|', 'parentID');
						}
						valuearr = 'sum_'+measures['nameBySummaryType'];
						valueName = measures['captionBySummaryType'];
						sqlConfig.Select.push('|sum|',measures['nameBySummaryType']);
					})
					sqlConfig.groupBy.push(e['name']);
					var valResult = (SQLike.q(sqlConfig));
					$.each(valResult, function(index, value) {
						if (!(value.parentID)) {
							value.parentID = '';
						}
						if (!(temp[value.parentID])) {
							temp[value.parentID] = { arg: 'Grand Total' };
						}
						temp[value.parentID][value[e.name] + '-' + valueName] = value[valuearr];
					});
				});
			} 
			// throw error message if drill-down is invalid
			else {
//				throw new Error('Invalid parameters: cannot drill down on empty arguments or series.');
				return;
			}
			this.metadata = temp;
		}
		return queryData;
	};
	
	this.setStarChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.StarChart['DataItems'] = this.fieldManager.DataItems;
		this.StarChart['Panes'] = this.fieldManager.Panes;
		this.StarChart['SeriesDimensions'] = this.fieldManager.SeriesDimensions;
		this.StarChart['Arguments'] = this.fieldManager.Arguments;
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.seriesDimensions = this.fieldManager.seriesDimensions;
		
		if (!(this.StarChart['Initialized'])) {
			this.StarChart['ComponentName'] = this.ComponentName;
			this.StarChart['DataSource'] = this.dataSourceId;
			this.StarChart['Name'] = this.Name;
			this.StarChart['InteractivityOptions'] = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
			this.StarChart['IsMasterFilterCrossDataSource'] = false;
			this.StarChart['Filter'] = undefined;
			this.StarChart['ShowCaption'] = true;
			this.StarChart['Rotated'] = false;
			this.StarChart['AxisX'] = {
				Visible: true,
				Title: '',
				Rotation: 0
			};
			this.StarChart['AxisY'] = {
				Visible: true,
				MeasureFormat: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				}
			};
			this.StarChart['Legend'] = {
					Visible: true,
					HorizontalAlignment: 'Right',
					font: gDashboard.fontManager.getDxItemLabelFont()
			};
			this.StarChart['SeriesType'] = 'line';
//			this.StarChart['SeriesType'] = 'area';
			this.StarChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			this.StarChart['Animation'] = 'easeOutCubic';
			
			this.StarChart['Initialized'] = true;
			
		}
		if(this.StarChart['DataSource'] != this.dataSourceId){
			this.StarChart['DataSource'] = this.dataSourceId;
		}

		this.meta = this.StarChart;
	};
	
	this.setStarChartForOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setStarChart();
		}
		else{
			this.StarChart=this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.StarChart['Panes'] == undefined){
			this.StarChart['Panes'] = this.meta['Panes'];
			// var s = this.meta['Panes']['Pane']['Series']['Simple'];
		}
		else if(this.fieldManager != undefined){
			this.StarChart['Panes'] = this.fieldManager.Panes;
		
			this.StarChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.StarChart['SeriesDimensions'] = this.meta['SeriesDimensions'] = this.fieldManager.SeriesDimensions;
			this.StarChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
			this.seriesDimensions = this.fieldManager.seriesDimensions;
		}
		
		if (!(this.StarChart['Initialized'])) {
			this.StarChart['ComponentName'] = this.ComponentName;
			this.StarChart['DataSource'] = this.dataSourceId;
			this.StarChart['Name'] = this.Name;
			this.StarChart['InteractivityOptions'] = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
			this.StarChart['IsMasterFilterCrossDataSource'] = false;
			this.StarChart['Filter'] = undefined;
			/* DOGFOOT ktkang 스타차트 캡션 보기 오류 수정  20200205 */
			if(this.StarChart['ShowCaption'] == undefined){
				this.StarChart['ShowCaption'] = true;
			}
			this.StarChart['Rotated'] = false;
			this.StarChart['AxisX'] = {
				Visible: true,
				Title: '',
				Rotation: 0
			};
			this.StarChart['AxisY'] = {
				Visible: true,
				MeasureFormat: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				}
			};
			this.StarChart['Legend'] = {
					Visible: true,
					HorizontalAlignment: 'Right',
					font: gDashboard.fontManager.getDxItemLabelFont()
			};
			this.StarChart['SeriesType'] = 'line';
//			this.StarChart['SeriesType'] = 'area';
			this.StarChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			this.StarChart['Animation'] = 'easeOutCubic';
			
			this.StarChart['Initialized'] = true;
		}
		if(window[self.dashboardid] != undefined){
			var StarChartOption = typeof window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.STAR_DATA_ELEMENT);
			var page = window.location.pathname.split('/');
			$.each(StarChartOption,function(_i,_starchartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _starchartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _starchartOption.CTRL_NM;
					}
				if(self.StarChart.ComponentName == CtrlNM){
					self.StarChart['Palette'] = _starchartOption.PALETTE_NM;
					return false;
				}
			})
			if(typeof this.meta.ColorSheme != 'undefined'){
				var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
				this.StarChart.Palette = new Array();
				$.each(colorList,function(_i,_list){
					self.StarChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
				});
			}
		}
		this.meta = this.StarChart;
	};
	
	
	this.bindData = function(_data, _options) {
		//2020.02.04 mksong SQLLIKE doSqlLike 스타차트 적용 dogfoot
//        if (this.filter) {
//			this.filteredData = _.clone(_data);
//		}else if (!this.tracked) {
//			this.globalData = _.clone(_data);
//			this.filteredData = _.clone(_data);
//		}
		
		this.enableButtons(_data);
		
//		$("#" + this.itemid).empty();
		
		//2020.02.04 mksong SQLLIKE doSqlLike 스타차트 적용 dogfoot
//		if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
//			var nodataHtml = '<div class="nodata-layer"></div>';
//			$("#" + this.itemid).empty().append(nodataHtml);
//		}
//		else {
			this.renderChart(_data, _options);
//		}
		//2020.02.04 mksong SQLLIKE doSqlLike 스타차트 적용 수정 끝 dogfoot
	};
	
	this.renderChart = function(_data, _options) {
		
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
			self.setStarChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.StarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.StarChart);
		}
		else if(this.fieldManager != null /*&& gDashboard.isNewReport == false*/ && self.StarChart){ // 레포트 열기
			
			if (!(this.fieldManager.seriesType) && self.meta != undefined) {
				this.fieldManager.seriesType = self.meta.Panes.Pane.Series.Simple.SeriesType;
			}
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setStarChartForOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.StarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.StarChart);
		}
		else if(self.meta != undefined && self.StarChart.length == 0){
			this.setStarChartForOpen();
			gDashboard.itemGenerateManager.generateItem(self, self.StarChart);
		}
		
		

		
		var queriedData, seriesDimensionColumnNames;
		var dataSet = this.__getChartData();
		
		//2020.09.11 mksong 스타차트 배경이 회색으로 변하는 오류 수정 dogfoot
		$('#'+self.itemid).find('rect').attr('fill','none');
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		// render empty chart if there is no data
		if (dataSet.length === 0) {
			self.dxItem = $('#' + this.itemid).dxPolarChart(
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
			).dxPolarChart('instance');
			return;
		}
		
		var yFormat = this.measures[0].format;
		var yPrecision = this.measures[0].precision;
		var moreAxisCount = 0;
		var moreSecondAxis = 0;
		if ($.type(dataSet) === 'array') {
			queriedData = dataSet;
		}
		else {
			queriedData = dataSet.data;
			seriesDimensionColumnNames = dataSet.seriesDimensionColumnNames;
		}
		
		// initialize dxConfig 
		var dxConfigs = this.getDxItemConfig(this.meta);
		$.each(this.P, function(_i, _pane) {
			
			var pane = {
				name: _i === 0 ? 'default' : _pane['Name'].replace(/\s/g,'')
			};
			dxConfigs.panes.push(pane);
			DevExpress.config({ defaultCurrency: 'KRW' });
			var iAxisY = _pane['AxisY'] || {};
//			var iAxisY = typeof _pane.Series.Simple[0] == 'undefined'?  _pane.Series.Simple.Value :   _pane.Series.Simple[0].Value || {};
//			var iSecondaryAxisY =  typeof _pane.Series.Simple[1] == 'undefined'? {} :  _pane.Series.Simple[1].Value;
			var iSecondaryAxisY = _pane['SecondaryAxisY'] || {};
			var axisYName;
			iAxisY['UniqueName'] = typeof _pane.Series.Simple[0] == 'undefined'?  _pane.Series.Simple.Value.UniqueName :   _pane.Series.Simple[0].Value.UniqueName || {};
			if(typeof _pane.Series.Simple[0] != 'undefined'){
				$.each(self.meta.DataItems.Measure,function(i,e){
					if(e.UniqueName == iAxisY.UniqueName){
						if(typeof e.Name != 'undefined'){
							axisYName = e.Name;
						}
						else{
							axisYName = e.DataMember;
						}
						if(e.hasOwnProperty('NumericFormat')){
							if(e.NumericFormat.hasOwnProperty('FormatType')){
									switch(e.NumericFormat.FormatType){
									case "Number":
										if(e.NumericFormat.hasOwnProperty('Unit')){
											switch(e.NumericFormat.Unit){
												case "Ones":
													yFormat = 'fixedPoint';
													yPrecision = '2';
													break;
												default:
//													yFormat =  e.NumericFormat.Unit;
													yFormat = 'largeNumber';
													break;
											}
										}
										else{
											yFormat = 'largeNumber';
										}
										yPrecision = typeof e.NumericFormat.Precision == 'undefined'? '2': e.NumericFormat.Precision;
										break;
									default:
										yFormat = e.NumericFormat.FormatType;
										break;
									}
							}
							
							else{
								yFormat = 'LargeNumber';
								yPrecision = typeof e.NumericFormat.Precision == 'undefined'? '2': e.NumericFormat.Precision;
							}
						}
						else{
							yFormat = 'largeNumber';
							yPrecision = '2';
						}
					}
				});
				
			}
			else{
//				if(self.meta.DataItems.Measure.UniqueName == iAxisY.UniqueName){
//					if(_pane.hasOwnProperty('AxisY')){
//						if(_pane.AxisY.hasOwnProperty('Title')){
//							axisYName = _pane.AxisY.Title;
//						}
//					}
//					else{
//						if(typeof _pane.Series.Simple.Name !='undefined'){
//							axisYName = _pane.Series.Simple.Name;
//						}else{
//							if(typeof self.meta.DataItems.Measure.Name != 'undefined'){
//								axisYName = self.meta.DataItems.Measure.Name;
//							}else{
//								axisYName = self.meta.DataItems.Measure.DataMember;
//							}
//						}
//					}
//				}
				$.each(WISE.util.Object.toArray(self.meta.DataItems.Measure),function(_i,_mea){
					if(_mea.UniqueName ==  iAxisY.UniqueName){
						axisYName = _mea.DataMember;
					}
				});
			}
			if(typeof _pane.Series.Simple[0] != 'undefined'){
				$.each(_pane.Series.Simple,function(_seriesI,_seriesPane){
					if(_seriesPane.hasOwnProperty('PlotOnSecondaryAxis')){
						iSecondaryAxisY = _seriesPane.Value;
						moreSecondAxis++;
					}
					else{
						moreAxisCount++;
					}
				});
			}
			else{
				$.each(_pane.Series,function(_seriesI,_seriesPane){
					if(_seriesPane.hasOwnProperty('PlotOnSecondaryAxis')){
						iSecondaryAxisY = _seriesPane.Value;
						moreSecondAxis++;
					}
					else{
						moreAxisCount++;
					}
				});
			}
			
			if(moreAxisCount >= 2)
			{
				if(_pane.hasOwnProperty('AxisY'))
					axisYName = _pane.AxisY.Title;
				else
					axisYName = '값';
			}
			else if(_pane.hasOwnProperty('AxisY') ){
				axisYName = _pane.AxisY.Title;
			}
			var yVisible = true;
			if(self.StarChart['AxisY'] != undefined){
				yVisible = self.StarChart['AxisY']['Visible'];
			}
			var axisY = {
				pane: pane.name,
				name: pane.name + '-DEFAULT-Y',
                position: 'left',
                min: 0,
				
				grid: false,
//				title: {
//					text: self.StarChart['AxisY']['Title'] ? self.StarChart['AxisY']['Title'] : axisYName,
//					font: self.CUSTOMIZED.get('axisY.title.font')
//				},
				visible: yVisible,
				maxValueMargin : 0.1,
				valueType: 'numeric',
				inverted: iAxisY['Reverse'],
//				label: {
//					font: self.CUSTOMIZED.get('axisY.label.font'),
//					format:  yFormat == 'fixedPoint'? '' :yFormat,
//					precision : yFormat == 'fixedPoint'? '' :yPrecision,
//					visible: typeof iAxisY['Visible'] == 'undefined' ? true : (iAxisY['Visible'] === false ? false : true)
//				},
//				label: {format:  yFormat,precision:yPrecision,visible: typeof axisYName === 'undefined' ? false : true},
				label: {
					font: gDashboard.fontManager.getDxItemLabelFont(),
					customizeText: function(e){
						return WISE.util.Number.unit(e.value, undefined, 'O', yPrecision, true, undefined, undefined, false);
					},
					visible: true
				},
				showZero: false,
			};
			if (self.StarChart['AxisY']['Title'] === undefined) {
				self.StarChart['AxisY']['Title'] = axisYName;
			}
			dxConfigs.valueAxis.push(axisY);
//			var iSecondaryAxisY = _pane['SecondaryAxisY'] || {};
			
			
			$.each(self.meta.DataItems.Measure,function(i,e){

				if(e.UniqueName == iSecondaryAxisY.UniqueName){
					if(moreSecondAxis <2){
						if(_pane.hasOwnProperty('SecondaryAxisY')){
							axisYName = _pane.SecondaryAxisY.Title;
						}
						else{
							if(typeof e.Name != 'undefined'){
								axisYName = e.Name;
							}
							else{
								axisYName = e.DataMember;
							}
						}
					}
					else{
						if(_pane.hasOwnProperty('SecondaryAxisY')){
							axisYName = _pane.SecondaryAxisY.Title;
						}
						else{
							axisYName = "값";
						}
					}
					if(e.hasOwnProperty('NumericFormat')){
						if(e.NumericFormat.hasOwnProperty('FormatType')){
							switch(e.NumericFormat.FormatType){
							case "Number":
								if(e.NumericFormat.hasOwnProperty('Unit')){
									switch(e.NumericFormat.Unit){
									case "Ones":
										yFormat = 'fixedPoint'
										break;
									default:
										yFormat = e.NumericFormat.Unit;
										break;
									}
								}
								else{
									yFormat = 'largeNumber'
								}
								yPrecision = typeof e.NumericFormat.Precision == 'undefined'? '2': e.NumericFormat.Precision;
								break;
							default:
								yFormat = e.NumericFormat.FormatType;
								break;
							}
						}
					}
					else{
						yFormat = 'largeNumber';
						yPrecision = '0';
					}
				}
			});
			var secondAxisY = {
				pane: pane.name,
				name: pane.name + '-SECONDARY-Y',
                position: 'right',
                min: 0,
				grid: {visible: iSecondaryAxisY['ShowGridLines'] === true ? true : false},
				title: {font: gDashboard.fontManager.getDxItemLabelFont(),text:/*iSecondaryAxisY['Title']*/axisYName ,visible: iSecondaryAxisY['TitleVisible'] === false ? false : true},
//				label: {font: self.CUSTOMIZED.get('secondaxisY.label.font'),format: yFormat,precision:yPrecision,visible:iSecondaryAxisY['Visible'] === false ? false : true},
				label: {
					font: gDashboard.fontManager.getDxItemLabelFont(),
					format: function(val){
						return WISE.util.Number.unit(val, null, null, null, self.measureFormat);
					},
					visible: typeof iAxisY['Visible'] == 'undefined' ? true : (iAxisY['Visible'] === false ? false : true)
				},
				inverted: iSecondaryAxisY['Reverse'],
				valueType: 'numeric',
				visible: iSecondaryAxisY['Visible'] === false ? false : true,
				showZero: iSecondaryAxisY['AlwaysShowZeroLevel'] === false ? false : true,
				wiseShowTitle: iSecondaryAxisY['TitleVisible'] === false ? false : true
			};
			_.each(_pane['Series'], function(_serieses) {
				var checker = true;
				_.each(WISE.util.Object.toArray(_serieses), function(_series) {
					if (_series['PlotOnSecondaryAxis'] === true) {
						dxConfigs.valueAxis.push(secondAxisY);
						return checker = false;
					}
				});
				return checker;
			});
			
			$.each(_pane['Series'], function(_seriesType, _serieses) {
				var seriesCreator;
				// var seriesPoint = false;
				switch(_seriesType) {
				case 'Simple':
					seriesCreator = new WISE.libs.Dashboard.item.StarChart.SimpleSeries();
					seriesCreator.seriesType = (_options && _options.seriesType) ? _options.seriesType : undefined;
					break;
				case 'Range':
					self.includedRangeSeries = true;
					seriesCreator = new WISE.libs.Dashboard.item.StarChart.RangeSeries();
					break;
				case 'Weighted':
					seriesCreator = new WISE.libs.Dashboard.item.StarChart.BubbleSeries();
					break;
				}
				seriesCreator.renderType = self.renderType;
				seriesCreator.pane = pane;
//				seriesCreator.dimensions = self.dimensions;
				seriesCreator.measures = self.measures;
//				seriesCreator.seriesDimensions = self.seriesDimensions;
				
				seriesCreator.serieses = _serieses;
				seriesCreator.axis = {
					'Y': axisY,
					'SY': secondAxisY
				};
				$.each(WISE.util.Object.toArray(seriesCreator.serieses),function(_i,_seriesItems){
					if(typeof _seriesItems.ShowPointMarkers == 'boolean'){
						_seriesItems['point'] = {visible:_seriesItems.ShowPointMarkers};
					}
				});

				if (self.renderType === 'SERIESDIMENSIONS-ONLY' || self.renderType === 'ARGUMENTS-AND-SERIESDIMENSIONS') {
					seriesCreator.seriesDimensionColumnNames = seriesDimensionColumnNames;
				}
				// series point

//				if (self.IO && self.IO['MasterFilterMode']) {
//					seriesCreator.point = {visible:true};
//				} 
//				else {
//					seriesCreator.point = {visible: false};
//				}
				var seriesElement = seriesCreator.getSeriesList();
				self.StarChart['SeriesType'] = seriesElement[0].type;
				if (self.StarChart['AxisY']['Title']) {
					dxConfigs.valueAxis[0].title = { text: self.StarChart['AxisY']['Title'] };
				}
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
//						$.each(seriesElement,function(_index,_series){
//							$.each(self.tooltipData,function(_dataIndex,_data){
//								$.each(self.measures,function(_i,_mea){

//									if(_series.valueField === (_mea.nameBySummaryType)){
//										
//										if(_mea['format'] == "percent"){
//											_data[_series.name] = (_data[_series.valueField]*100).toFixed(_mea['precision'])+"%";
//										}
//										else if(_mea['format'] == "decimal"){
//											_data[_series.name] = _data[_series.valueField];
//										}
//										else{
//											_data[_series.name] = WISE.util.Number.unit(_data[_series.valueField],_mea['format'].substring(0,1),_mea['precision']);
//										}
//										
//									}
//								});
////								_data[_series.name] = _data[_series.valueField];
//							});
//						});
////						return false;
					}
					
				});
				dxConfigs.series = dxConfigs.series.concat(seriesElement);
//				var colorList = typeof self.meta.ColorSheme == 'undefined'? []: gDashboard.itemColorManager.generateColorMeta(self.meta.ColorSheme.Entry);
//				if(colorList.length === 0){
//					colorList = gDashboard.itemColorManager.colorMeta
//				}
//				var Colorindex = 0;
//				$.each(dxConfigs.series,function(_i,_e){
//					var returnColor; 
//					$.each(colorList,function(_i,_colorItem){
//		        		if(_e.name.indexOf(_colorItem.Value) > -1){
//		        			if(typeof _colorItem.Color != 'undefined'){
//		        				returnColor = (gDashboard.itemColorManager.getHexColor(_colorItem.Color));
//		        				return false;
//		        			}
//		        			else{
//		        				returnColor = gDashboard.itemColorManager.paletteColor[_colorItem.PaletteIndex];
//		        				return false;
//		        			}
//		        		}
//		        	
//		        	});
//					if(typeof returnColor !='undefined'){
//						_e['color'] = (returnColor);
//					}
//				});
			});
		}); // end of LOOP of Panes
		
//		if (this.includedRangeSeries) {
//			dxConfigs.resolveLabelOverlapping = 'none';
//		}
//		
//		var temp = function(_data,key,arc){
//			return _data.sort(function(a,b){
//				var x = a[key], y = b[key];
//				if(arc){
//					return ((x<y)? -1 : (x>y)? 1:0);
//				}else{
//					return ((x>y)? -1 : (x<y)? 1:0);
//				}
//			});
//		}
		

//		$.each(queriedData, function(i,_e){
//			if(_e.arg === "-")
//				{

//					delete queriedData[i];
//				}
////				queriedData.splice(i,1);
//		});
		
//		dxConfigs.dataSource = queriedData;
		$.each(this.measures,function(_i,_e){
			if(_e.uniqueName == self.topItem){
				self.topItem = _e.nameBySummaryType;
				return false;
			}
		});

		var ShowItems = queriedData;
		var dataSourceQueried;
		if (self.topN > 0) {
			ShowItems.sort(function(a, b) {
				return a[self.topItem] - b[self.topItem];
			});
			ShowItems = ShowItems.reverse();
			var dataSourceQueried;
			var queriedDataTop = [];
			for (var i = 0; i < self.topN; i++) {
				queriedDataTop[i] = ShowItems[i];
			}
			dataSourceQueried = queriedDataTop;
		} else {
			dataSourceQueried = ShowItems;
		}

		dxConfigs.dataSource = dataSourceQueried;
		// if(dxConfigs.series.length >=2)
// {
// dxConfigs.legend.horizontalAlignment = "right";
// dxConfigs.legend.verticalAlignment = "top";
//			dxConfigs.legend.position = "inside";
//			dxConfigs.legend.paddingLeftRight = dxConfigs.legend.paddingTopBottom =  1;
//			dxConfigs.legend.top = dxConfigs.legend.bottom = dxConfigs.legend.left = dxConfigs.legend.right = 2; 
//		}
		// var xGrid = false;
		$.each(dxConfigs.series,function(_i,_series){
//			dxConfigs.series[_i].type = self.StarChart['SeriesType'];
			if(_series.type == 'line' || _series.type == 'spline' || _series.type == "stackedline"){
				dxConfigs.argumentAxis.grid.visible = self.CUSTOMIZED.get('valueGrid.visible');
			}
		});
		
//		_.each(WISE.util.Object.toArray(this.meta.DataItems.Dimension),function(_dim){
//			if(typeof _dim.ColoringMode!= 'undefined'){
//				if(_dim.ColoringMode == 'Hue'){
//					self.HueActive = true;
////					dxConfigs.commonSeriesSettings = {
////						type:dxConfigs.series[0].type,
////						argumentField: "arg",
////			            valueField: dxConfigs.series[0].valueField,
////			            ignoreEmptyPoints: true
////					};
//					dxConfigs.commonSeriesSettings = dxConfigs.series[0];
//					dxConfigs.commonSeriesSettings.ignoreEmptyPoints = true;
////					_.each(dxConfigs.commonSeriesSettings,function(_com){
////						_com.ignoreEmptyPoints = true;
////					});
//					var Colorindex = 0;
//					dxConfigs.seriesTemplate={
//						nameField :"arg",
//						customizeSeries:function(_seri){
//							var returnColor =  gDashboard.itemColorManager.paletteColor[Colorindex];
//		    				if(Colorindex >= 19){
//		    					Colorindex = 0;
//		    				}else{
//		    					Colorindex++;
//		    				}
//		    				return {color : returnColor};
//						}
//					};
//					return false;
//				}
//			}
//		});
		if(self.IO != undefined){
			if (self.IO['IsDrillDownEnabled']) {
	            if (self.IO['TargetDimensions'] === 'Argument' && self.arguments.length > 0) {
	                dxConfigs.dataSource = filterDataByLevel(0);
	            }
	            else if (self.IO['TargetDimensions'] === 'Series' && self.seriesDimensions.length > 0) {
	                dxConfigs.dataSource = filterDataByParentKey('');
	                var newSeries = [];
	                $.each(dxConfigs.dataSource[0], function(seriesName, seriesValue) {
	                    $.each(self.measures, function(measureIndex, measure) {
	                        var seriesNameSplit = seriesName.split('-');
	                        if (seriesNameSplit[seriesNameSplit.length - 1] === measure.captionBySummaryType) {
	                            var tempSeries = {
	                                axis: 'default-DEFAULT-Y',
	                                name: seriesNameSplit[0],
	                                pane: 'default',
	                                type: self.StarChart['SeriesType'],
	                                valueField: seriesName
	                            };
	                            newSeries.push(tempSeries);
	                        }
	                    });
	                });
	                dxConfigs.series = newSeries;
	            }
	        }
		}
        
		self.dxItem = $("#" + this.itemid).dxPolarChart(dxConfigs).dxPolarChart('instance');
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
	};
	
	this.renderButtons = function() {
		gDashboard.itemGenerateManager.renderButtons(self);
//		this.seriesChangeType = this.CUSTOMIZED.get('series.change.type') || 'image';
//		
//		var buttonPanerlId = this.itemid + '_topicon';
//		var topIconPanel = $('#' + buttonPanerlId);
//		
//		// tracking data text area
//		var trackingDataContainerId = this.itemid + '_tracking_data_container';
//		var trackingDataContainerHtml = '<li><div id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></div></li>';
//		topIconPanel.append(trackingDataContainerHtml);
//		
//		var renderSimpleSeriesSelector = false;
//		$.each(this.P, function(_i, _pane) {
//			for( var key in _pane['Series'] ) {
//			
//				if ( key=='Range' || key=='Weighted' || key=='OpenHighLowClose')
//				{
//					if (WISE.util.Object.toArray(_pane['Series']['Range']).length > 0) {
//						renderSimpleSeriesSelector = false;
//						return false;
//					}
//					if (WISE.util.Object.toArray(_pane['Series']['Weighted']).length > 0) {
//						renderSimpleSeriesSelector = false;
//						return false;
//					}
//					if (WISE.util.Object.toArray(_pane['Series']['OpenHighLowClose']).length > 0) {
//						renderSimpleSeriesSelector = false;
//						return false;
//					}
//				}
//			}
//		});
//		
//		if (renderSimpleSeriesSelector) {
//			// change series type
//			var seriesTypeChangepanelId = this.itemid + '_topicon_chgseries';
//			var chgSeriesHtml = this.chgSeriesButton = $('<li><div id="' + seriesTypeChangepanelId + '" class="dx-lookup-hack" style="height: 26px !important;"></div></li>');
//			topIconPanel.append(chgSeriesHtml);
//			
//			var seriesList = [];
//			$.each(this.CUSTOMIZED.get('series.change.list'), function(_i0, _s0) {
//				$.each(self.CU.Series.Simple.SERIES_TYPE, function(_i1, _s1) {
//					if (_s0 === _s1.type) {
//						seriesList.push(_s1);
//					}
//				});
//			});
//
//			var width;
//	    	switch((self.seriesChangeType).toLowerCase()) {
//	    	case 'text':
//	    		width = 180;
////	    		width = 200;
//	    		break;
//	    	case 'image':
//	    		width = 80;
//	    		break;
//	    	case 'imagetext':
//	    		width = 200;
////	    		width = 220;
//	    		break;
//	    	}
//			
//			this.seriesTypeSelector = $("#" + seriesTypeChangepanelId).dxLookup({
//			    items: seriesList,
//			    grouped: false,
//			    displayExpr: "name",
//			    valueExpr: "type",
//			    showPopupTitle: false,
//			    searchEnabled: false,
//			    showCancelButton: false,
//			    width: width,
//			    noDataText: gMessage.get('WISE.message.page.common.nodata'),
//			    placeholder: gMessage.get('WISE.message.page.common.graph'),
//			    onValueChanged: function(_e) {
//			    	if (self.filteredData && _e.value !== '') {
//			    		var seriesType = self.CU.Series.Simple.getSeriesType(_e.value);
//			    		var series = self.dxItem.option('series');
//			    		_.each(series, function(_s) {
//			    			_s.type = seriesType;
//			    		});
//			    		
//			    		self.dxItem.option('series', series);
//			    		
//			    		self.selectedChartType = seriesType;
//			    	} else {
//			    		this.option('value', '');
//			    	}
//			    },
//			    itemTemplate: function(_data) {
//			    	var template;
//			    	
//			    	switch((self.seriesChangeType).toLowerCase()) {
//			    	case 'text':
//			    		template = '<div>' + _data.name + '</div>';
//			    		break;
//			    	case 'image':
//			    		template = '<div><img src="' + WISE.Constants.context + '/images/chart/' + _data.type + '.png" style="width:20px;height:20px;" alt="' + _data.name + '" title="' + _data.name + '" /></div>';
//			    		break;
//			    	case 'imagetext':
//			    		template = '<div><img src="' + WISE.Constants.context + '/images/chart/' + _data.type + '.png" style="width:20px;height:20px;vertical-align: middle;margin-right:5px;" />' + _data.name + '</div>';
//			    		break;
//			    	}
//			        return template;
//			    }
//			}).dxLookup('instance');
//		}
//		
//		// export data
//		if (WISE.Constants.browser !== 'IE9') {
//			var exportDataId = this.itemid + '_topicon_exp', imgDownText = gMessage.get('WISE.message.page.widget.download.image');
//			var exportHtml = '<li><a id="' + exportDataId + '" href="#"><img src="' + WISE.Constants.context + '/images/cont_box_icon_export.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_export_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_export.png\'" alt="' + imgDownText + '" title="' + imgDownText + '"></a></li>';
//			topIconPanel.append(exportHtml);
//			
//			$("#" + exportDataId).click(function() {
//				if ($.type(self.filteredData) === 'array' && self.filteredData.length > 0) {
//				/* DOGFOOT ktkang 중복 코드 수정  20200205 */
//					var svgCode = $('#' +self.itemid).dxPolarChart('instance').svg();
//					WISE.resources.dx.exports.image(svgCode);
//					var param = {
//							'pid': WISE.Constants.pid,
//							'userId':userJsonObject.userId,
//							'reportType':gDashboard.reportType
//					}
//					$.ajax({
//						type : 'post',
//						data : param,
//						cache : false,
//						url : WISE.Constants.context + '/report/exportLog.do',
//						complete: function() {
//							gProgressbar.hide();
//						}
//					});
//				}
//				else {
//					WISE.alert(gMessage.get('WISE.message.page.common.nodata'));
//				}
//			});
//			
//			// tracking conditions clear
//			if (self.IO && self.IO['MasterFilterMode']) {
//				self.trackingClearId = self.itemid + '_topicon_tracking_clear';
//				
//				var trackingClearHtml = '';
//				trackingClearHtml += '<li><a id="' + self.trackingClearId + '" href="#">';
//				trackingClearHtml += '<img src="' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png" ';
//				trackingClearHtml += 'onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png\'" '; 
//				trackingClearHtml += 'onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png\'" ';
//				trackingClearHtml += 'alt="Clear Filters" title="Clear Filters"></a></li>';
//				topIconPanel.append(trackingClearHtml);
//				
//				$("#" + self.trackingClearId).click(function(_e) {
//					var clearTrackingImg = $(this).find('img')[0];
//					if(clearTrackingImg.src.indexOf('cont_box_icon_filter_.png') > -1 ) {
//						filterArray = new Array();
//						window[self.dashboardid].filterData(self.itemid, [],self.dataSourceId);
//						self.clearTrackingConditions();
//						selectedPoint = null;
//					}
//				});
//			}
//			if(self.IO && self.IO['IsDrillDownEnabled'] !== null){
//				self.DrilldownClearId = self.itemid + '_topicon_drilldown_clear';
//				var DrillDownClearHtml = '';
//				DrillDownClearHtml += '<li><a id="' + self.DrilldownClearId + '" href="#">';
//				DrillDownClearHtml += '<img src="' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png" ';
//				DrillDownClearHtml += 'onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png\'" '; 
//				DrillDownClearHtml += 'onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_filter_disable.png\'" ';
//				DrillDownClearHtml += 'alt="Clear Filters" title="Clear Filters"></a></li>';
//				topIconPanel.append(DrillDownClearHtml);
//				
//				$("#" + self.DrilldownClearId).click(function(_e) {
//					var clearTrackingImg = $(this).find('img')[0];
//					if(clearTrackingImg.src.indexOf('cont_box_icon_filter_.png') > -1 ) {
//						isFirstLevel = true;
//						firstlevel = 0;
//
//						switch(self.IO['TargetDimensions']){
//							case 'Series':
//								var newData = filterDataByParentKey('');
//								var newSeries = [];
//								$.each(newData[0], function(seriesName, seriesValue) {
//									$.each(self.measures, function(measureIndex, measure) {
//										var seriesNameSplit = seriesName.split('-');
//										if (seriesNameSplit[seriesNameSplit.length - 1] === measure.captionBySummaryType) {
//											var tempSeries = {
//												axis: 'default-DEFAULT-Y',
//												name: seriesNameSplit[0],
//												pane: 'default',
//												type: self.StarChart['SeriesType'],
//												valueField: seriesName
//											};
//											newSeries.push(tempSeries);
//										}
//									});
//								});
//								self.dxItem.option({
//									dataSource: newData,
//									series: newSeries
//								});								
//								break;
//							case 'Argument':
//								self.dashItemSource.option({dataSource : filterData("",firstlevel)});
//								break;
//						}						
//						
//						var clearTrackingImg = $("#" + self.DrilldownClearId).find('img')[0];
//			       		$(clearTrackingImg)
//			       			.attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png')
//			       			.on('mouseover', function() {
//			       				$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
//			       			})
//			       			.on('mouseout', function() {
//			       				$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
//			       			});
//					}
//				});
//			}
//		} // end of if (WISE.Constants.browser === 'IE9')
		
		// zoom popup
		/*var zoomPopupId = this.itemid + '_zoom_pop';
		var zoomPopupEventId = zoomPopupId + '_event';
		var zoomHtml = '<li><a id="' + zoomPopupEventId + '" href="#"><img src="' + WISE.Constants.context + '/images/cont_box_icon_playzoom.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_playzoom_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_playzoom.png\'" alt="Zoom Popup" title="Zoom Popup"></a></li>';
		topIconPanel.append(zoomHtml);
		
		$("#" + zoomPopupEventId).click(function(_e) {
			var options = {
				autoPosition: true,
				autoResize: true,
				escClose: true,
				onShow: function() {
					self.child.generate(self.meta, {containerid: zoomPopupId});
					
					var serieseType = self.seriesTypeSelector.option('value');
					if (serieseType) {
						self.child.bindData(self.filteredData, {seriesType: serieseType});
					} else {
						self.child.bindData(self.filteredData);
					}
				}
			};
			
			if (self.filteredData) {
				$('<div id="' + zoomPopupId + '" style="width: 98%; height: 97%;"></div>').modal(options);
			} else {
				alert(gMessage.get('WISE.message.page.common.nodata'));
			}
		});*/
		
	};
	
	this.functionDo = function(_f) {		
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.StarChart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.StarChart['ShowCaption'] = false;
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
						contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput">');
                        var html = '<div class="modal-footer" style="padding-bottom:0px;">';
						html += '<div class="row center">';
						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
						html += '</div>';
						html += '</div>';
						html += '</div>';
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
                            	
                            	self.StarChart['Name'] = newName;
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
				var chagePalette = self.StarChart.Palette;
				var firstPalette = self.StarChart.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.StarChart.Palette) != -1
										? self.StarChart.Palette
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
                                    self.resize();
								} else {
                                    self.isCustomPalette = false;
                                    self.dxItem.option('palette', paletteObject2[e.value]);
                                    self.StarChart.Palette = paletteObject2[e.value];
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.StarChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                            
//                            self.StarChart.Palette = select.dxSelectBox('instance').option('value');
//                          chagePalette = select.dxSelectBox('instance').option('value');
//                          p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	self.dxItem.option('palette', firstPalette);
                        	chagePalette = firstPalette;
                        	self.StarChart.Palette = firstPalette;
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.StarChart.Palette = chagePalette;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
		default: break;
//			case 'editPalette': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
//					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office'];
//				if (self.customPalette.length > 0) {
//					paletteCollection.push('Custom');
//				}
//				// popup configs
//				var p = $('#editPopover').dxPopover('instance');
//				var chagePalette = self.StarChart.Palette;
//				p.option({
//                    target: '#editPalette',
//					contentTemplate: function(contentElement) {
//                        // create html layout
//                        var html = 	'<div id="' + self.itemid + '_paletteBox"></div>' +
//								 	'<div style="padding-bottom:20px;"></div>' +
//									'<div class="modal-footer" style="padding-bottom:0px;">' +
//										'<div class="row center">' +
//											'<a id="save-ok" href="#" class="btn positive ok-hide">확인</a>' +
//											'<a id="save-cancel" href="#" class="btn neutral close">취소</a>' +
//										'</div>' +
//									'</div>';
//                        contentElement.append(html);
//                        var select = $('#' + self.itemid + '_paletteBox');
//                        // palette select
//                        var originalPalette = paletteCollection.indexOf(self.StarChart.Palette) != -1
//										? self.StarChart.Palette
//										: 'Custom';
//						select.dxSelectBox({
//                            width: 400,
//                            items: paletteCollection,
//                            itemTemplate: function(data) {
//                                var html = $('<div />');
//                                $('<p />').text(data).css({
//                                    display: 'inline-block',
//                                    float: 'left'
//                                }).appendTo(html);
//                                var itemPalette = data === 'Custom'
//										? self.customPalette 
//										: DevExpress.viz.getPalette(data).simpleSet;
//                                for (var i = 5; i >= 0; i--) {
//                                    $('<div />').css({
//                                        backgroundColor: itemPalette[i],
//                                        height: 30,
//                                        width: 30,
//                                        display: 'inline-block',
//                                        float: 'right'
//                                    }).appendTo(html);
//                                }
//                                return html;
//                            },
//							value: originalPalette,
//							onValueChanged: function(e) {
//								if (e.value == 'Custom') {
//                                    self.isCustomPalette = true;
//                                    self.dxItem.option('palette', self.customPalette);
//								} else {
//                                    self.isCustomPalette = false;
//                                    self.dxItem.option('palette', e.value);
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save-ok').on('click', function() {
//                            self.StarChart.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            p.option('visible', false);
//                        });
//                        $('#save-cancel').on('click', function() {
//                            self.dxItem.option('palette', self.StarChart.Palette);
//                            chagePalette = self.StarChart.Palette;
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.StarChart.Palette = chagePalette;
//					}
//                });
//                p.option('visible', !(p.option('visible')));
//				break;
//			}
//			default: break;
		}
	}
	/**
	 * generate UI for data and design functions
	 */ 
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
//		if($('#data').length > 0){
//			$('#data').remove();
//		}
//		$('#menulist').removeClass('col-2');
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
//		}
//		
//		if($('#design').length > 0){
//			$('#design').remove();
//		}
//		
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');	
//		}
//		
//		
//		
//		$('#tab5primary').empty();
//		$('<li class="slide-ui-item"><a id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		menuItemSlideUi();
//		
//		
////		
////		$('<a href="#" id="captionVisible" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="editName" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="rotation" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_rotate.png" alt=""><span>회전</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="editAxisX" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_xAxisSettings.png" alt=""><span>X축 설정</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="editAxisY" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_yAxisSettings.png" alt=""><span>Y축 설정</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="editLegend" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_showColorLegend.png" alt=""><span>범레</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="editStyle" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_bar2.png" alt=""><span>계열 유형</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="editPalette" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="customPalette" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_editColor.png" alt=""><span>색상 편집</span></a>').appendTo($('#tab5primary'));
////		$('<a href="#" id="editAnimation" class="lnb-link slide-ui-item more functiondo" style="padding-right: 15px;"><img src="'+WISE.Constants.context+'/resources/main/images/ico_pointLabels.png" alt=""><span>애니메이션</span></a>').appendTo($('#tab5primary'));
////		
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
//		}
////		$(  "<h4 class=\"tit-level3\">필터링</h4>" + 
////			"<div class=\"panel-body\">" + 
////			"	<div class=\"design-menu rowColumn\">" + 
////			"		<ul class=\"desing-menu-list col-2\">" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"editFilter\" class=\"functiondo\">" +
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_basicFilter.png\" alt=\"\"><span>필터 편집</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"clearFilter\" class=\"functiondo\">" + 
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>초기화</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"		</ul>" + 
////			"	</div>" + 
////			"</div>" +
////			/* DOGFOOT hsshim 2020-02-06 범정부 요청: 
////			 * Interactivity -> 상호작용
////			 * Interactivity Options -> 상호작용 설정
////			 */ 
////			"<h4 class=\"tit-level3\">상호작용</h4>" + 
////			"<div class=\"panel-body\">" + 
////			"	<div class=\"design-menu rowColumn\">" + 
////			"		<ul class=\"desing-menu-list col-3\">" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"singleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_singleMasterFilter.png\" alt=\"\"><span>단일 마스터<br>필터</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"multipleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_multipleMasterFilter.png\" alt=\"\"><span>다중 마스터<br>필터</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"drillDown\" class=\"single-toggle-button functiondo\">" + 
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_drillDown.png\" alt=\"\"><span>드릴<br>다운</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"		</ul>" + 
////			"	</div>" + 
////			"</div>" + 
////			/* DOGFOOT hsshim 2020-02-06 범정부 요청: 
////			 * Interactivity -> 상호작용
////			 * Interactivity Options -> 상호작용 설정
////			 */ 
////			"<h4 class=\"tit-level3\">상호작용 설정</h4>" + 
////			"<div class=\"panel-body\">" + 
////			"	<div class=\"design-menu rowColumn\">" + 
////			"		<ul class=\"desing-menu-list col-2\">" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"crossFilter\" class=\"single-toggle-button functiondo\">" + 
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_crossDataSourceFiltering.png\" alt=\"\"><span>교차 데이터<br>소스 필터링</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"ignoreMasterFilter\" class=\"single-toggle-button functiondo\">" + 
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>마스터 필터<br>무시</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"		</ul>" + 
////			"	</div>" + 
////			"</div>" +
////			"<h4 class=\"tit-level3\">대상 차원</h4>" + 
////			"<div class=\"panel-body\">" + 
////			"	<div class=\"design-menu rowColumn\">" + 
////			"		<ul class=\"desing-menu-list col-2\">" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"targetArgument\" class=\"multi-toggle-button functiondo\">" + 
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_basicArguments.png\" alt=\"\"><span>차원</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"			<li>" + 
////			"				<a href=\"#\" id=\"targetSeries\" class=\"multi-toggle-button functiondo\">" + 
////			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_basicSeries.png\" alt=\"\"><span>차원 그룹</span>" + 
////			"				</a>" + 
////			"			</li>" + 
////			"		</ul>" + 
////			"	</div>" + 
////			"</div>"
////		).appendTo($('#tab4primary'));
////		
////		// initialize UI elements
//		tabUi();
//		designMenuUi();
//		compMoreMenuUi();
////        $('.single-toggle-button').on('click', function(e) {
////            e.preventDefault();
////            $(this).toggleClass('on');
////        });
////        $('.multi-toggle-button').on('click', function(e) {
////            e.preventDefault();
////            var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
////            if ($(this)[0] !== currentlyOn[0]) {
////                currentlyOn.removeClass('on');
////            }
////            $(this).toggleClass('on');
////        });
////
////		// toggle 'on' status according to chart options
////		if (self.IO) {
////			if (self.IO['MasterFilterMode'] === 'Single') {
////				$('#singleMasterFilter').addClass('on');
////			} else if (self.IO['MasterFilterMode'] === 'Multiple') {
////				$('#multipleMasterFilter').addClass('on');
////			}
////			if (self.IO['IsDrillDownEnabled']) {
////				$('#drillDown').addClass('on');
////			}
////			if (self['isMasterFilterCrossDataSource']) {
////				$('#crossFilter').addClass('on');
////			}
////			if (self.IO['IgnoreMasterFilters']) {
////				$('#ignoreMasterFilter').addClass('on');
////			}
////			if (self.IO['TargetDimensions'] === 'Argument') {
////				$('#targetArgument').addClass('on');
////			} else if (self.IO['TargetDimensions'] === 'Series') {
////				$('#targetSeries').addClass('on');
////			}
////        }
////		
//		$('<div id="editPopup">').dxPopup({
//            height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('#tab5primary');
//		// settings popover
//		$('<div id="editPopover">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//		}).appendTo('#tab5primary');
//		
//		$('<div id="editPopup2">').dxPopup({
//			height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('body');
//		// settings popover
//		$('<div id="editPopover2">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//        }).appendTo('#tab4primary');
//		
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);	
//		});
//		
	}
	
	/**
	 * data and design functions
	 * 
	 * @param _f: clicked button's id 
	 */
//	this.functionDo = function(_f) {
//		switch(_f) {
//		/* DATA OPTIONS */
//		
//			// edit filter builder
//			case 'editFilter': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var p = $('#editPopup2').dxPopup('instance');
//				p.option({
//					title: '필터 편집',
//					contentTemplate: function() {
//                        var html = "<div id='filterContent'></div>";
//                        html += '<div class="modal-footer" style="padding-bottom:0px;">';
//						html += '<div class="row center">';
//						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
//						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
//						html += '</div>';
//						html += '</div>';
//                        return html;
//					},
//					onContentReady: function() {
//						var field = [];
//						$.each(self.seriesDimensions, function(_i, series) {
//							field.push({ dataField: series['name'], dataType: 'string' });
//						});
//						$.each(self.dimensions, function(_i, dimension) {
//							field.push({ dataField: dimension['name'], dataType: 'string' });
//						});

//						$('#filterContent').append('<div id="' + self.itemid + '_editFilter">');
//						$('#' + self.itemid + '_editFilter').dxFilterBuilder({
//							fields: field,
//							value: self.StarChart['Filter'] == undefined ? [] : self.StarChart['Filter']
//                        });
//                                                
//                        // confirm and cancel
//						$('#ok-hide').on('click', function() {
//                            var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').getFilterExpression();
//                            var newDataSource = new DevExpress.data.DataSource({
//                                store: self.globalData,
//                                paginate: false
//                            });
//                            newDataSource.filter(filter);
//                            newDataSource.load();
//                            
//                            self.StarChart['Filter'] = filter;
//                            self.StarChart['Filter'] = self.StarChart['Filter'];
//                            self.bindData(newDataSource.items(),true);
//
//							p.hide();
//						});
//						$('#close').on('click', function() {
//							p.hide();
//						});
//					}
//				});
//				p.show();
//				break;
//			}
//			// clear filters
//			case 'clearFilter': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				if (self.StarChart['Filter']) {
//					self.StarChart['Filter'] = undefined;
//					self.bindData(self.globalData,true);
//				}
//				break;
//			}
//			// toggle single master filter mode
//			case 'singleMasterFilter': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				if (self.IO['MasterFilterMode'] === 'Single') {
//					self.StarChart['InteractivityOptions']['MasterFilterMode'] = 'Off';
//					self.IO['MasterFilterMode'] = 'Off';
//				} else {
//					self.StarChart['InteractivityOptions']['MasterFilterMode'] = 'Single';
//					self.IO['MasterFilterMode'] = 'Single';
//				}
//				window[self.dashboardid].filterData(self.itemid, [], self.dataSourceId, self.isMasterFilterCrossDataSource);
//				filterArray = new Array();
//				self.clearTrackingConditions();
//				selectedPoint = null;
//				break;
//			}
//			// toggle multiple master filter mode
//			case 'multipleMasterFilter': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				if (self.IO['MasterFilterMode'] === 'Multiple') {
//					self.StarChart['InteractivityOptions']['MasterFilterMode'] = 'Off';
//					self.IO['MasterFilterMode'] = 'Off';
//				} else {
//					self.StarChart['InteractivityOptions']['MasterFilterMode'] = 'Multiple';
//					self.IO['MasterFilterMode'] = 'Multiple';
//				}			
//				window[self.dashboardid].filterData(self.itemid, [], self.dataSourceId, self.isMasterFilterCrossDataSource);
//				filterArray = new Array();
//				self.clearTrackingConditions();
//				selectedPoint = null;
//				break;
//			}
//			// toggle drill down
//			case 'drillDown': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				if ($('#drillDown').hasClass('on')) {
//					// argument drill-down
//					if (self.IO['TargetDimensions'] === 'Argument' && self.arguments.length > 0) {
//						self.StarChart['InteractivityOptions']['IsDrillDownEnabled'] = true;
//						self.IO['IsDrillDownEnabled'] = true;
//                        var newData = self.__getChartData();
//                        newData = filterDataByLevel(0);
//						self.dxItem.option({dataSource: newData});

//					}
//					// series drill-down
//					else if (self.IO['TargetDimensions'] === 'Series' && self.seriesDimensions.length > 0) {
//						self.StarChart['InteractivityOptions']['IsDrillDownEnabled'] = true;
//						self.IO['IsDrillDownEnabled'] = true;
//						var newData = self.__getChartData();
//						newData = filterDataByParentKey('');
//						var newSeries = [];
//						$.each(newData[0], function(seriesName, seriesValue) {
//							$.each(self.measures, function(measureIndex, measure) {
//								var seriesNameSplit = seriesName.split('-');
//								if (seriesNameSplit[seriesNameSplit.length - 1] === measure.captionBySummaryType) {
//									var tempSeries = {
//										axis: 'default-DEFAULT-Y',
//										name: seriesNameSplit[0],
//										pane: 'default',
//										type: self.StarChart['SeriesType'],
//										valueField: seriesName
//									};
//									newSeries.push(tempSeries);
//								}
//							});
//						});
//						self.dxItem.option({
//							dataSource: newData,
//							series: newSeries
//						});
//					}
//					// invalid parameters: throw error
////					else {
////						throw new Error('Invalid parameters: cannot drill down on empty arguments or series.');
////						e.component.option('value', 'Off');
////					}
//				} else {
//					self.StarChart['InteractivityOptions']['IsDrillDownEnabled'] = false;
//					self.IO['IsDrillDownEnabled'] = false;
//					self.bindData(self.globalData,true);
//				}
//				break;
//			}
//			// toggle cross data source filtering
//			case 'crossFilter': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				self.isMasterFilterCrossDataSource = $('#crossFilter').hasClass('on') ? true : false;
//				self.StarChart['IsMasterFilterCrossDataSource'] = self.isMasterFilterCrossDataSource;
//				window[self.dashboardid].filterData(self.itemid, [], self.dataSourceId, self.isMasterFilterCrossDataSource);
//				filterArray = new Array();
//				self.clearTrackingConditions();
//				selectedPoint = null;
//				break;
//			}
//			// toggle ignore master filter
//			case 'ignoreMasterFilter': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				self.IO['IgnoreMasterFilters'] = $('#ignoreMasterFilter').hasClass('on') ? true : false;
//				self.StarChart['InteractivityOptions']['IgnoreMasterFilters'] = self.IO['IgnoreMasterFilters'];
//				self.tracked = !self.IO['IgnoreMasterFilters'];
//				self.bindData(self.globalData,true);
//				break;
//			}
//			// change dimension target to arguments
//			case 'targetArgument': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				self.IO['TargetDimensions'] = 'Argument';
//				self.StarChart['InteractivityOptions']['TargetDimensions'] = self.IO['TargetDimensions'];
//				window[self.dashboardid].filterData(self.itemid, [], self.dataSourceId, self.isMasterFilterCrossDataSource);
//				filterArray = new Array();
//				self.clearTrackingConditions();
//				selectedPoint = null;
//				break;
//			}
//			// change dimension target to series
//			case 'targetSeries': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				self.IO['TargetDimensions'] = 'Series';
//				self.StarChart['InteractivityOptions']['TargetDimensions'] = self.IO['TargetDimensions'];
//				window[self.dashboardid].filterData(self.itemid, [], self.dataSourceId, self.isMasterFilterCrossDataSource);
//				filterArray = new Array();
//				self.clearTrackingConditions();
//				selectedPoint = null;
//				break;
//			}
//			
//		/* DESIGN OPTIONS */
//		
//			// show and hide title bar
//			case 'captionVisible': {
//				var titleBar = $('#' + self.itemid + '_title');
//				if (titleBar.css('display') === 'none') {
//					titleBar.css('display', 'block');
//					self.StarChart['ShowCaption'] = true;
//				} else {
//					titleBar.css('display', 'none');
//					self.StarChart['ShowCaption'] = false;
//				}
//				break;
//			}
//			// edit chart title
//			case 'editName': {
//				var p = $('#editPopup').dxPopup('instance');
//				p.option({
//					title: '이름 편집',
//					contentTemplate: function(contentElement) {
//						// initialize title input box
//						contentElement.append('<p>대시 보드 항목 이름 </p><div id="' + self.itemid + '_titleInput">');
//                        var html = '<div class="modal-footer" style="padding-bottom:0px;">';
//						html += '<div class="row center">';
//						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
//						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
//						html += '</div>';
//						html += '</div>';
//						html += '</div>';
//						contentElement.append(html);
//                        
//                        $('#' + self.itemid + '_titleInput').dxTextBox({
//							text: $('#' + self.itemid + '_title').text()
//                        });
//                                                
//                        // confirm and cancel
//						$('#ok-hide').on('click', function() {
//                            var newName = $('#' + self.itemid + '_titleInput').dxTextBox('instance').option('text');
//                            var goldenLayout = gDashboard.goldenLayoutManager;
//                            goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);
//                            self.StarChart['Name'] = newName;
//                            self.Name = newName;
//							p.hide();
//						});
//						$('#close').on('click', function() {
//							p.hide();
//						});
//					}
//				});
//				// show popup
//				p.show();
//				break;
//			}
//			// rotate
//			case 'rotation': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				self.StarChart['Rotated'] = !(self.StarChart['Rotated']);
//				self.dxItem.option('rotated', self.StarChart['Rotated']);
//				break;
//			}
//			// edit X axis
//			case 'editAxisX': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var p = $('#editPopup').dxPopup('instance');
//				p.option({
//					title: 'X축 설정',
//					contentTemplate: function(contentElement) {
//						contentElement.append('<div id="' + self.itemid + '_xShow" style="margin: 10px 0px;"></div>');
//                        contentElement.append('<div id="' + self.itemid + '_xInputs"></div>');
//                        var html = '<div class="modal-footer" style="padding-bottom:0px;">';
//						html += '<div class="row center">';
//						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
//						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
//						html += '</div>';
//						html += '</div>';
//                        contentElement.append(html);
//                        
//						// show and hide X axis labels
//						$('#' + self.itemid + '_xShow').dxCheckBox({
//							value: self.StarChart['AxisX']['Visible'],
//							text: 'X축 표시'
//						});
//						// edit X axis title and label orientation
//						$('#' + self.itemid + '_xInputs').dxForm({
//							formData: {
//								'사용자 정의 텍스트': self.StarChart['AxisX']['Title'],
//								'기울기': self.StarChart['AxisX']['Rotation']
//							},
//							items: [
//								{
//									dataField: '사용자 정의 텍스트',
//									editorType: 'dxTextBox'
//								}, 
//								{
//									dataField: '기울기',
//									editorType: 'dxRadioGroup',
//									editorOptions: {
//										layout: 'horizontal',
//										dataSource: [0, 45, 90]
//									}
//								}
//							]
//                        });
//                                                
//                        // confirm and cancel
//						$('#ok-hide').on('click', function() {
//                            self.StarChart['AxisX']['Visible'] = $('#' + self.itemid + '_xShow').dxCheckBox('instance').option('value');
//                            self.dxItem.option('argumentAxis.label.visible', self.StarChart['AxisX']['Visible']);
//                            self.StarChart['AxisX']['Title'] = $('#' + self.itemid + '_xInputs').dxForm('instance').getEditor('사용자 정의 텍스트').option('value');
//                            self.dxItem.option('argumentAxis.title', { text: self.StarChart['AxisX']['Title'] });
//                            if (self.dxItem.option('argumentAxis.label.displayMode') != 'rotate') {
//                                self.dxItem.option('argumentAxis.label.displayMode', 'rotate');
//                            }
//                            self.StarChart['AxisX']['Rotation'] = $('#' + self.itemid + '_xInputs').dxForm('instance').getEditor('기울기').option('value');
//                            self.dxItem.option('argumentAxis.label.rotationAngle', self.StarChart['AxisX']['Rotation']);
//                           
//                            p.hide();
//						});
//						$('#close').on('click', function() {
//							p.hide();
//						});
//					}
//				});
//				p.show();
//				break;
//			}
//			// edit Y axis
//			case 'editAxisY': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var p = $('#editPopup').dxPopup('instance');
//				p.option({
//					title: 'Y축 설정',
//					contentTemplate: function(contentElement) {

//						contentElement.append('<div id="' + self.itemid + '_yShow"></div>');
//						contentElement.append('<div id="' + self.itemid + '_yInputs"></div>');
//						contentElement.append('<div id="' + self.itemid + '_yMeasures"></div>');
//                        var html = '<div class="modal-footer" style="padding-bottom:0px;">';
//						html += '<div class="row center">';
//						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
//						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
//						html += '</div>';
//						html += '</div>';
//                        contentElement.append(html);
//                        
//                        // show and hide Y labels
//						$('#' + self.itemid + '_yShow').dxCheckBox({
//							value: self.StarChart['AxisY']['Visible'],
//							text: 'Y축 표시'
//						});
//						// edit Y axis title
//						$('#' + self.itemid + '_yInputs').dxForm({
//							formData: {
//								'사용자 정의 텍스트': self.StarChart['AxisY']['Title']
//							},
//							items: [
//								{
//									dataField: '사용자 정의 텍스트',
//									editorType: 'dxTextBox'
//								}
//							]
//						});
//						// edit Y axis measures
//						$('#' + self.itemid + '_yMeasures').dxForm({
//							formData: self.StarChart['AxisY']['MeasureFormat'],
//							items: [
//								{
//									dataField: 'O',
//									editorType: 'dxTextBox'
//								},
//								{
//									dataField: 'K',
//									editorType: 'dxTextBox'
//								},
//								{
//									dataField: 'M',
//									editorType: 'dxTextBox'
//								},
//								{
//									dataField: 'B',
//									editorType: 'dxTextBox'
//								}
//							]
//                        });
//                                                
//                        // confirm and cancel
//						$('#ok-hide').on('click', function() {
//                            self.StarChart['AxisY']['Visible'] =  $('#' + self.itemid + '_yShow').dxCheckBox('instance').option('value');
//                            self.dxItem.option('valueAxis[0].label.visible', self.StarChart['AxisY']['Visible']);
//                            self.StarChart['AxisY']['Title'] = $('#' + self.itemid + '_yInputs').dxForm('instance').getEditor('사용자 정의 텍스트').option('value');
//                            self.dxItem.option('valueAxis[0].title', { text: self.StarChart['AxisY']['Title'] });
//                            var form = $('#' + self.itemid + '_yMeasures').dxForm('instance');
//                            self.measureFormat = {
//                                O: form.getEditor('O').option('value'),
//                                K: form.getEditor('K').option('value'),
//                                M: form.getEditor('M').option('value'),
//                                B: form.getEditor('B').option('value')	
//                            };
//                            self.StarChart['AxisY']['MeasureFormat'] = self.measureFormat;
//                            self.dxItem.option('valueAxis[0].label.customizeText', function(e) {
//                                return self.CU.Series.AxisY.getLabelFormat(e.value, self.measureFormat);
//                            });
//                            p.hide();
//						});
//						$('#close').on('click', function() {
//							p.hide();
//						});
//					}
//				});
//				p.show();
//				break;
//			}
//			// edit legend
//			case 'editLegend': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var p = $('#editPopover').dxPopover('instance');
//				p.option({
//                    target: '#editLegend',
//					contentTemplate: function(contentElement) {
//                        $(	"<div id=\"" + self.itemid + "_toggleLegend\" style=\"width:130px;\"></div>" +
//                            "<div style=\"height: auto; width: 150px;\">" +
//							"	<ul class=\"add-item-body icon-radio-list\" style=\"display:block;\">" + 
//							"		<li >" + 
//							"			<a  href=\"#\" class=\"select-position\" position=\"Left\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_outsideHLeftTop.png\" alt=\"\"><span>왼쪽</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a  href=\"#\" class=\"select-position\" position=\"Center\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_outsideHCenterTop.png\" alt=\"\"><span>가운데</span></a>" + 
//							"		</li>" +  
//							"		<li>" + 
//							"		    <a  href=\"#\" class=\"select-position\" position=\"Right\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_outsideHRightTop.png\" alt=\"\"><span>오른쪽</span></a>" + 
//							"		</li>" + 
//							"	</ul>" + 
//                            "</div>"							
//						).appendTo(contentElement);
//						// toggle legend visibility
//						$('#' + self.itemid + '_toggleLegend').dxButton({
//                            text: '범례 표시',
//							onClick: function() {
//								self.StarChart.Legend.Visible = !(self.StarChart.Legend.Visible);
//								self.dxItem.option('legend.visible', self.StarChart.Legend.Visible);
//							}
//                        });
//                        
//                        $.each($('.select-position'), function(index, position) {
//							if (self.StarChart.Legend.HorizontalAlignment === $(position).attr('position')) {
//								$(position).addClass('on');
//							}
//						});
//						
//						$('.select-position').off('click').on('click', function(e) {
//                            $('.select-position.on').removeClass('on');
//                            $(this).addClass('on');
//							var newPos = $(this).attr('position');
//							self.StarChart.Legend.HorizontalAlignment = newPos;
//                            self.dxItem.option('legend.horizontalAlignment', newPos.toLowerCase());
//						});
//					}
//				});
//				p.option('visible', !(p.option('visible')));
//				break;
//			}
//			// change chart type 
//			case 'editStyle': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var p = $('#editPopover').dxPopover('instance');
//				p.option({
//					target: '#editStyle',
//					contentTemplate: function(contentElement) {
//						$(	"<div style=\"height: 315px; width: 370px;\">" +
//							"<div class=\"add-item noitem\"><span class=\"add-item-head on\">막대</span>" + 
//							"	<ul class=\"add-item-body icon-radio-list\">" + 
//							"		<li >" + 
//							"			<a  href=\"#\" class=\"select-style\" seriestype=\"Bar\" title=\"막대\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_bar2.png\" alt=\"\"><span>막대</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a  href=\"#\" class=\"select-style\" seriestype=\"StackedBar\" title=\"스택 막대\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_bar3.png\" alt=\"\"><span>스택 막대</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a  href=\"#\" class=\"select-style\" seriestype=\"FullStackedBar\" title=\"풀스택 막대\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_bar4.png\" alt=\"\"><span>풀스택 막대</span></a>" + 
//							"		</li>" + 
//							"	</ul>" + 
//							"</div>" + 
//							"<div class=\"add-item noitem\"><span class=\"add-item-head on\">선</span>" + 
//							"	<ul class=\"add-item-body icon-radio-list\">" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"Scatter\" title=\"점\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine1.png\" alt=\"\"><span>점</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"Line\" title=\"선\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine2.png\" alt=\"\"><span>선</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"StackedLine\" title=\"스택 선\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine3.png\" alt=\"\"><span>스택 선</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"FullStackedLine\" title=\"풀스택 선\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine4.png\" alt=\"\"><span>풀스택 선</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"StepLine\" title=\"계단\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine5.png\" alt=\"\"><span>계단</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"Spline\" title=\"곡선\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_pointLine6.png\" alt=\"\"><span>곡선</span></a>" + 
//							"		</li>" + 
//							"	</ul>" + 
//							"</div>" + 
//							"<div class=\"add-item noitem\"><span class=\"add-item-head on\">영역</span>" + 
//							"	<ul class=\"add-item-body icon-radio-list\">" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"Area\" title=\"영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area1.png\" alt=\"\"><span>영역</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"StackedArea\" title=\"스택 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area2.png\" alt=\"\"><span>스택 영역</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"FullStackedArea\" title=\"풀스택 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area3.png\" alt=\"\"><span>풀스택 영역</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"StepArea\" title=\"계단 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area4.png\" alt=\"\"><span>계단 영역</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"SplineArea\" title=\"곡선 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area5.png\" alt=\"\"><span>곡선 영역</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"StackedSplineArea\" title=\"스택 곡선 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area6.png\" alt=\"\"><span>스택 곡선 영역</span></a>" + 
//							"		</li>" + 
//							"		<li>" + 
//							"			<a href=\"#\" class=\"select-style\" seriestype=\"FullStackedSplineArea\" title=\"풀스택 곡선 영역\"><img src=\"" + WISE.Constants.context + "/resources/main/images/ico_area7.png\" alt=\"\"><span>풀스택 곡선 영역</span></a>" + 
//							"		</li>" + 
//							"	</ul>" + 
//							"</div>" +
//							"</div>"							
//						).appendTo(contentElement);
//						
//						$.each($('.select-style'), function(index, style) {
//							if (self.StarChart['SeriesType'] === $(style).attr('seriestype').toLowerCase()) {
//								style.classList.add('on');
//							}
//						});
//						
//						$('.select-style').off('click').on('click', function(e) {
//                            $('.select-style.on').removeClass('on');
//                            $(this).addClass('on');
//							var selected = $(this);
//							var newStyle = $(this).attr('seriestype').toLowerCase();
//							self.StarChart['SeriesType'] = newStyle;
//							$.each(WISE.util.Object.toArray(self.StarChart.Panes.Pane.Series.Simple), function(sIndex, series) {
//								series.SeriesType = selected.attr('seriestype');
//							});
//							$.each(self.dxItem.option('series'), function(index, element) {
//								self.dxItem.option('series[' + index + '].type', newStyle);
//							});
//							self.fieldManager.seriesType = selected.attr('seriestype');
//						});
//					}
//				});
//				p.option('visible', !(p.option('visible')));
//				break;
//			}
//			// edit color scheme
//			case 'editPalette': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
//					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office', 'Custom'];
//				// popup configs
//				var p = $('#editPopover').dxPopover('instance');
//				p.option({
//                    target: '#editPalette',
//					contentTemplate: function(contentElement) {
//                        // create html layout
//                        $(  "<div id=\"" + self.itemid + "_paletteBox\"></div>" +
//                            "<div class=\"modal-footer\" style=\"padding-top:15px; width:370px;\">" + 
//                            "    <div class=\"row center\">" + 
//		                    "        <a id=\"save_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>" + 
//		                    "        <a id=\"save_cancel\" class=\"btn neutral close\" href=\"#\">취소</a>" + 
//		                    "    </div>" + 
//                            "</div>"
//                        ).appendTo(contentElement);
//                        var select = $('#' + self.itemid + '_paletteBox');
//                        // palette select
//                        var originalPalette = paletteCollection.includes(self.StarChart.Palette) 
//										? self.StarChart.Palette
//										: 'Custom';
//						select.dxSelectBox({
//                            width: 400,
//                            items: paletteCollection,
//                            itemTemplate: function(data) {
//                                var html = $('<div />');
//                                $('<p />').text(data).css({
//                                    display: 'inline-block',
//                                    float: 'left'
//                                }).appendTo(html);
//                                var itemPalette = data === 'Custom'
//										? self.customPalette 
//										: DevExpress.viz.getPalette(data).simpleSet;
//                                for (var i = 5; i >= 0; i--) {
//                                    $('<div />').css({
//                                        backgroundColor: itemPalette[i],
//                                        height: 30,
//                                        width: 30,
//                                        display: 'inline-block',
//                                        float: 'right'
//                                    }).appendTo(html);
//                                }
//                                return html;
//                            },
//							value: originalPalette,
//							onValueChanged: function(e) {
//								if (e.value == 'Custom') {
//                                    self.isCustomPalette = true;
//                                    self.dxItem.option('palette', self.customPalette);
//								} else {
//                                    self.isCustomPalette = false;
//                                    self.dxItem.option('palette', e.value);
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.StarChart.Palette = select.dxSelectBox('instance').option('value');
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.StarChart.Palette);
//                            p.option('visible', false);
//                        });
//					}
//                });
//                p.option('visible', !(p.option('visible')));
//				break;
//			}
//			// set custom colors
//			case 'customPalette': {
//				if (!(self.dxItem)) {
//					break;
//				}
//				var p = $('#editPopup').dxPopup('instance');
//				p.option({
//					title: '색상 편집',
//					contentTemplate: function(contentElement) {
//                        var colorContainer = $('<div id="colorContainer"></div>');
//						self.dxItem.option('series').forEach(function(item, index) {
//							colorContainer.append('<p>' + self.dxItem.option('series[' + index + '].name') 
//													+ '</p><div id="' + self.itemid + '_seriesColor' + index + '"></div>');
//                        });
//                        colorContainer.dxScrollView({
//                            height: 600,
//                            width: '100%'
//                        }).appendTo(contentElement);
//						var html = '<div class="modal-footer" style="padding-bottom:0px;">';
//						html += '<div class="row center">';
//						html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
//						html += '<a id="close" href="#" class="btn neutral close">취소</a>';
//						html += '</div>';
//						html += '</div>';
//						contentElement.append(html);
//
//                        self.dxItem.option('series').forEach(function(item, index) {
//							$('#' + self.itemid + '_seriesColor' + index).dxColorBox({
//								value: self.dxItem.getAllSeries()[index].getColor()
//							});
//                        });
//
//                        // confirm and cancel
//						$('#ok-hide').on('click', function() {
//                            var newPalette = [];
//                            self.dxItem.series.forEach(function(item, index) {
//                                newPalette[index] = $('#' + self.itemid + '_seriesColor' + index).dxColorBox('instance').option('value');
//                            });
//                            self.StarChart['Palette'] = newPalette;
//                            self.dxItem.option('palette', newPalette);
//                            self.customPalette = newPalette;
//                            self.isCustomPalette = true;
//                            p.hide();
//						});
//						$('#close').on('click', function() {
//							p.hide();
//						});
//					}
//				});
//				p.show();
//				break;
//			}
//			// set animation style
//			case 'editAnimation': {
//				if (!(self.dxItem)) {
//					break;
//                }
//                var mapping = {
//                    '없음': 'none',
//                    '입방': 'easeOutCubic',
//                    '선형': 'linear',
//                    'none': '없음',
//                    'easeOutCubic': '입방',
//                    'linear': '선형'
//                };
//				var p = $('#editPopover').dxPopover('instance');
//				p.option({
//					target: '#editAnimation',
//					contentTemplate: function(contentElement) {
//                        contentElement.empty();
//						contentElement.append('<div id="' + self.itemid + '_editAnimation">');
//						$('#' + self.itemid + '_editAnimation').dxRadioGroup({
//							dataSource: ['없음', '입방', '선형'],
//                            value: mapping[self.StarChart['Animation']],
//                            width: 70,
//							onValueChanged: function(e) {
//								self.StarChart['Animation'] = mapping[e.value];
//								if (e.value === 'none') {
//									self.dxItem.option('animation.enabled', false);
//								} else {
//									self.dxItem.option({
//										animation: {
//											enabled: true,
//											easing: self.StarChart['Animation']
//										}
//									});
//                                }
//                                self.bindData(self.globalData, true);
//							}
//						});
//					}
//				});
//				p.option('visible', !(p.option('visible')));
//				break;
//            }
//			default: break;
//		}
//	}
	
};

WISE.namespace('WISE.libs.Dashboard.item.StarChart');
WISE.libs.Dashboard.item.StarChart.Series = function() {
	this.DU = WISE.libs.Dashboard.item.DataUtility;
	this.CU =  WISE.libs.Dashboard.item.ChartUtility;
	this.CTN = WISE.libs.Dashboard.item.ChartUtility.Constants; 
};
WISE.libs.Dashboard.item.StarChart.Series.prototype = {
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
		case 'SERIESDIMENSIONS-ONLY':
		case 'ARGUMENTS-AND-SERIESDIMENSIONS':
			return this.getSeriesListBySeriesDimensions();
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
		
		axisY.title = axisY.wiseShowTitle ? ((axisY.title === '' || axisY.title === undefined) ? _dataMember.caption : axisY.title) : '';
		
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

WISE.libs.Dashboard.item.StarChart.SimpleSeries = WISE.util.Object.extend(WISE.libs.Dashboard.item.StarChart.Series);
WISE.libs.Dashboard.item.StarChart.SimpleSeries.prototype.seriesType = undefined;
WISE.libs.Dashboard.item.StarChart.SimpleSeries.prototype.defineCommonOption = function(_S, _dataMember, _series) {
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
WISE.libs.Dashboard.item.StarChart.SimpleSeries.prototype.getSeriesListByValues = function() {
	var self = this;
	var seriesList = [];
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		var uniqueName = _S['Value']['UniqueName'];
		var dataMember = self.getMeasureDataMember(uniqueName);
		var type = self.CU.Series.Simple.getSeriesType(self.seriesType || _S['SeriesType']);
		var series = {
			pane: self.pane.name,
			type: 'line',
			valueField: dataMember.nameBySummaryType,
			name: _S['Name'] || dataMember.caption,
			//point:typeof _S.point != 'undefined'?_S['point'] :{visible:false},
			point:{visible:true},
			barWidth:80
		};
		// label
		var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember);
		if (series.type === 'fullstackedbar' || series.type === 'stackedbar') label.position = 'inside';
		label.connector = {visible: true};
		label.backgroundColor = "rgba(255,255,255,0)";
		label.font = {
			color: "#000000",
		};
		series.label = label;
		var axisY = self.setAxisY(_S, dataMember, series);
		
		self.defineCommonOption(_S, dataMember, series);
		
		seriesList.push(series);
	});
	
	return seriesList;
};
WISE.libs.Dashboard.item.StarChart.SimpleSeries.prototype.getSeriesListBySeriesDimensions = function() {
	var self = this;
	var seriesList = [];
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		_.each(self.seriesDimensionColumnNames, function(_SDNM) {
			var uniqueName = _S['Value']['UniqueName'];
			var dataMember = self.getMeasureDataMember(uniqueName);
			
			var type = self.CU.Series.Simple.getSeriesType(self.seriesType || _S['SeriesType']);
			var seriesName = _SDNM + '-' +  dataMember.caption;
			var series = {
				pane: self.pane.name,
				type: type,
				valueField: seriesName,
				name: ($.type(self.serieses) === 'array' && self.serieses.length > 1) ? seriesName : _SDNM 
			};
			
			// label
			var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember);
			if (series.type === 'fullstackedbar' || series.type === 'stackedbar') label.position = 'inside';
			series.label = label;
			var axisY = self.setAxisY(_S, dataMember, series);
			
			self.defineCommonOption(_S, dataMember, series);
			seriesList.push(series);
		});
	});
	
	return seriesList;
};

WISE.libs.Dashboard.item.StarChart.RangeSeries = WISE.util.Object.extend(WISE.libs.Dashboard.item.StarChart.Series);
WISE.libs.Dashboard.item.StarChart.RangeSeries.prototype.getSeriesListByValues = function() {
	var self = this;
	var seriesList = [];
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
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
		
		var seriesName = (uniqueName1 === uniqueName2 ? dataMember1.caption : dataMember1.caption + (dataMember2 ? ' - ' + dataMember2.caption : ''));
		var series = {
			pane: self.pane.name,
			type: (_S['SeriesType'] || 'RangeBar').toLowerCase(),
			rangeValue1Field: dataMember1.nameBySummaryType,
			rangeValue2Field: dataMember2.nameBySummaryType,
			name: _S['Name'] || seriesName
		};
		
		// label
		var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember1);
		label.position = 'outside';
		series.label = label;
		
		var axisY = self.setAxisY(_S, dataMember1, series);
		
		seriesList.push(series);
	});
	
	return seriesList;
};
WISE.libs.Dashboard.item.StarChart.RangeSeries.prototype.getSeriesListBySeriesDimensions = function() {
	var self = this;
	var seriesList = [];
	
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		_.each(self.seriesDimensionColumnNames, function(_SDNM) {
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
			
			var series = {
				pane: self.pane.name,
				type: (_S['SeriesType'] || 'RangeBar').toLowerCase(),
				rangeValue1Field: _SDNM + '-' +  dataMember1.caption,
				rangeValue2Field: _SDNM + '-' +  dataMember2.caption,
				name: _S['Name'] ||_SDNM
			};
			
			// label
			var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember1);
			label.position = 'outside';
			series.label = label;
			
			var axisY = self.setAxisY(_S, dataMember1, series);
			
			seriesList.push(series);
		});
	});
	
	return seriesList;
};

WISE.libs.Dashboard.item.StarChart.BubbleSeries = WISE.util.Object.extend(WISE.libs.Dashboard.item.StarChart.Series);
WISE.libs.Dashboard.item.StarChart.BubbleSeries.prototype.getSeriesListByValues = function() {
	var self = this;
	var seriesList = [];
	
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
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
		
		var seriesName = (uniqueName1 === uniqueName2 ? dataMember1.caption : dataMember1.caption + (dataMember2 ? ' - ' + dataMember2.caption : ''));
		var series = {
			pane: self.pane.name,
			type: 'bubble',
			valueField: dataMember1.nameBySummaryType,
			sizeField: dataMember2.nameBySummaryType,
			name: _S['Name'] || seriesName
		};
		
		// label
		var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember1);
		label.position = 'inside';
		series.label = label;
		
		var axisY = self.setAxisY(_S, dataMember1, series);
		
		seriesList.push(series);
	});
	
	return seriesList;
};
WISE.libs.Dashboard.item.StarChart.BubbleSeries.prototype.getSeriesListBySeriesDimensions = function() {
	var self = this;
	var seriesList = [];
	
	_.each(WISE.util.Object.toArray(this.serieses), function(_S) {
		_.each(self.seriesDimensionColumnNames, function(_SDNM) {
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
			
			var series = {
				pane: self.pane.name,
				type: 'bubble',
				valueField: _SDNM + '-' +  dataMember1.caption,
				sizeField: _SDNM + '-' +  dataMember2.caption,
				name: _S['Name'] || _SDNM
			};
			
			// label
			var label = self.CU.Series.Label.get(_S['PointLabelOptions'], dataMember1);
			label.position = 'inside';
			series.label = label;
			
			var axisY = self.setAxisY(_S, dataMember1, series);
			
			seriesList.push(series);
		});
	});
	
	return seriesList;
};

WISE.libs.Dashboard.StarChartFieldManager = function() {
	var self = this;
	
	this.initilized = false;
	this.alreadyFindOutMeta = false;
	
	//검색 - searchDisable
	this.searchDisable = false;
	//검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	//검색
	
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
		
		this.initilized = true;
	};
	
	this.setMetaTables = function(tables){
		this.meta.tables = tables;
	}
	
	this.setDataItemByField = function(_fieldlist){
		this.DataItems = {};
		self.DataItems['Dimension'] = [];
		self.DataItems['Measure'] = [];
		//var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
		
		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText; 
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				self.DataItems['Dimension'].push(dataItem);
			} else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = $(_fieldlist[i]).data('formatOptions');
//				dataItem['NumericFormat'] = NumericFormat;
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};
	
	this.setPanesByField = function(_panes){
		this.Panes = {};
		self.Panes['Pane'] = {'Name':"창 1", 'Series':{'Simple':[]}};
		_.each(_panes,function(_p){
			if(self.seriesType != undefined){
				var Value = {'SeriesType':self.seriesType ,'Value': {'UniqueName' : _p.uniqueName}};	
			}else{
				var Value = {'SeriesType': 'line', 'Value': {'UniqueName' : _p.uniqueName}};
			}
			self.Panes['Pane']['Series']['Simple'].push(Value);
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
};