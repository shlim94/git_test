/*
 * BUGS:
 *     - multiple series not working if series names are changed
 *     - drill down not working with series
 */
WISE.libs.Dashboard.item.PieGenerator = function() {
	var self = this;
	
	this.type = 'PIE_CHART';
	
	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	this.IsMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	this.values = [];
	this.arguments = [];
	this.seriesDimensions = [];
	this.HiddenMeasures = [];
	this.fieldManager;
	this.Pie = [];
	this.initialized;
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	
	//2020-01-14 LSH topN
	this.topN;
	this.topItem;
	this.topNT;
	this.OtherCnt;
	this.otherShow;
	this.TopNMember;
	this.topNEnabeled = false;
	this.TopNOrder = false;
	this.topMesure;
    this.dimensionTopN = new Array();
    
	
//	var TopN = [];
	var confDimension;
	// custom label/tooltip format settings
	var pieLabelFormat = [];
	var pieTooltipFormat = [];
	
	// custom pie palette
	this.customPalette = [];
	this.isCustomPalette = false;
	
	this.panelManager;
	
	var rootval;
//	this.drillDownIndex; // must be number type
	
	var isFirstLevel = true;
	var drillDownIndex = 0;
	var leveling = 0;
	var ddParentStack = [];
	var ddCurrentID = '';
	
	this.trackingData = [];
	this.selectedPoint;
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	function filterData(name,leveldown) {
		return self.metadata.filter(function (item) {

			return item.parentID === name && item.leveling === leveldown;
		});
	 }
	function filterDataRoot(name,leveldown) {
		return self.metadata.filter(function (item) {
			return item.SINGLE_ARGUMENT === name && item.leveling === leveldown;
		});
	 }
	 function filterDataByLevel(leveldown) {
        return self.metadata.filter(function (item) {
            return item.leveling === leveldown;
        });
    }
	 
	 this.filterDataByLevel = function(leveldown) {
		 return self.metadata.filter(function (item) {
            return item.leveling === leveldown;
        });
	 }
	/**
	 * @param _pie: meta object
	 * @param _options: title,
	 */
	this.getDxItemConfig = function(_pie, _options) {
		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
		var pieType = _pie['PieType'] === 'Donut' ? 'doughnut' : 'pie';
		var argumentName = ((self.IO && self.IO['IsDrillDownEnabled']) || this.A.length === 1) ? this.arguments[0].name : this.CTN.arguments.name.MULTI_ARGUMENT;
		var confMeasure = WISE.util.Object.toArray(_pie['DataItems']['Measure']);
		var pieTheme = Configurations.palette;
		//20210122 AJKIM 파이차트 범례 추가 DOGFOOT
		var pieLegend = self.getLegend(self.Pie.Legend.Position);

//		var pieOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DATA_ELEMENT);
		var pieLabelPosition = _pie['LabelPosition'] == undefined? 'top':_pie['LabelPosition'];
//		if(pieOption != ''){
//			$.each(pieOption,function(_i,_e){
//				if(_e.CTRL_NM == _pie.ComponentName){
////					pieLabelPosition = _pie.xxxxxx;
//					return false;
//				}
//			})
//		}

		
		/*LSH 기존 topN 삭제*/
		/*if(typeof(_pie['DataItems']['Dimension']) != undefined) {
			var dimensionTopN = _pie['DataItems']['Dimension'];
			if(dimensionTopN != undefined){
				if(dimensionTopN.TopNEnabled == true) {
		            $.each(dimensionTopN,function(i,e){
		            	if(dimensionTopN[i].TopNCount > 0) {
		            		self.topN = dimensionTopN[i].TopNCount;
		            		self.topItem = dimensionTopN[i].TopNMeasure;
		            	} else if(dimensionTopN.TopNCount > 0){
		            		self.topN = dimensionTopN.TopNCount;
		            		self.topItem = dimensionTopN.TopNMeasure;
		            	} else {
		            		self.topN = 5;
		            		self.topItem = dimensionTopN.TopNMeasure;
		            	}
		            });
		        }
			}
	    }*/

		if (this.dimensions.length === 0 ) {
			argumentName = this.CTN.arguments.name.SINGLE_ARGUMENT;
		}
		var label = {
			visible: _pie['LabelContentType'] === 'None' ? false : true,
			position: pieLabelPosition.toLowerCase(),
			font:gDashboard.fontManager.getDxItemLabelFont(),
			connector:{
				visible:true,           
				width: 1
			}
		};
		// initialize label and tooltip format
		pieLabelFormat = {
			type: _pie['LabelContentType'],
			format: _pie['LabelMeasureFormat'], 
			prefixEnabled: _pie['LabelPrefixEnabled'],
			prefixFormat: _pie['LabelPrefixFormat'],
			suffixEnabled: _pie['LabelSuffixEnabled'],
			suffix: _pie['LabelSuffix'],
			precision: _pie['LabelPrecision'],
			precisionOption: _pie['LabelPrecisionOption'],
		};
		label.customizeText = function(_pointInfo) {
//			return _pointInfo.valueText;
			return self.PCU.Series.Label.getLabelFormat(_pointInfo, pieLabelFormat);
		}
		var tooltip = {
			enabled: _pie['TooltipContentType'] === 'None' ? false : true,
			font:gDashboard.fontManager.getDxItemLabelFont(),
		};
		pieTooltipFormat = {
			type: _pie['TooltipContentType'], 
			format: _pie['TooltipMeasureFormat'],
			prefixEnabled: _pie['TooltipPrefixEnabled'],
			prefixFormat: _pie['TooltipPrefixFormat'],
			suffixEnabled: _pie['TooltipSuffixEnabled'], 
			suffix: _pie['TooltipSuffix'],
			precision: _pie['TooltipPrecision'],
			precisionOption: _pie['TooltipPrecisionOption'],
		};
		tooltip.customizeTooltip = function(_pointInfo) {
//			return { text: self.PCU.Tooltip.getTooltipFormat(_pointInfo, pieTooltipFormat) };
			
var type = pieTooltipFormat.type;
			
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
				},
				prefixEnabled = false,
				prefixFormat = "";
			
			//20210625 AJKIM 툴팁에 툴팁 설정 적용되도록 변경 dogfoot
			if(pieTooltipFormat){
				labelFormat = 'Number';
				labelPrecision = pieTooltipFormat.precision;
				labelPrecisionOption = pieTooltipFormat.precisionOption;
				labelUnit = pieTooltipFormat.format
				labelSeparator = true
				labelSuffixEnabled = pieTooltipFormat.suffixEnabled;
				labelSuffix = pieTooltipFormat.suffix;
				prefixEnabled = pieTooltipFormat.prefixEnabled;
				prefixFormat = prefixEnabled? pieTooltipFormat.prefixFormat : ""
			}
//        	if(typeof(confMeasure.NumericFormat) == 'object') {
//    			labelFormat = confMeasure.NumericFormat.FormatType;
//    			labelPrecision = confMeasure.NumericFormat.Precision;
//    			labelPrecisionOption = confMeasure.NumericFormat.PrecisionOption;
//				labelUnit = confMeasure.NumericFormat.Unit;
//				labelSeparator = confMeasure.NumericFormat.IncludeGroupSeparator;
//				labelSuffixEnabled = confMeasure.NumericFormat.SuffixEnabled;
//				labelSuffix = confMeasure.NumericFormat.Suffix;
//			/* 나중에 비정형일 때 포맷 변경해야하는 부분*/
//			} else {
//        		if (_pie.DataItems.Measure.length == 1) {
//        			if(_pie.DataItems.Measure[0].NumericFormat != undefined){
//						labelFormat = typeof _pie.DataItems.Measure[0].NumericFormat.FormatType == 'undefined' ? labelFormat : _pie.DataItems.Measure[0].NumericFormat.FormatType;
//						labelUnit = typeof _pie.DataItems.Measure[0].NumericFormat.Unit == 'undefined'? labelUnit : _pie.DataItems.Measure[0].NumericFormat.Unit;
//						labelPrecision = typeof _pie.DataItems.Measure[0].NumericFormat.Precision == 'undefined' ? labelPrecision : _pie.DataItems.Measure[0].NumericFormat.Precision;
//						labelPrecisionOption = typeof _pie.DataItems.Measure[0].NumericFormat.PrecisionOption == 'undefined' ? labelPrecisionOption : _pie.DataItems.Measure[0].NumericFormat.PrecisionOption;
//						labelSeparator = typeof _pie.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator == 'undefined' ? labelSeparator : _pie.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator;
//						labelSuffixEnabled = typeof _pie.DataItems.Measure[0].NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : _pie.DataItems.Measure[0].NumericFormat.SuffixEnabled;
//						labelSuffix = typeof _pie.DataItems.Measure[0].NumericFormat.Suffix == 'undefined' ? labelSuffix : _pie.DataItems.Measure[0].NumericFormat.Suffix;
//					}
//        		} else {
//					$.each(WISE.util.Object.toArray(_pie.DataItems.Measure), function(i,k) {
//						if (_pointInfo.point.data.caption.indexOf(k.DataMember) != -1 && typeof k.NumericFormat != 'undefined') {
//							labelFormat = typeof k.NumericFormat.FormatType == 'undefined' ? '' : k.NumericFormat.FormatType;
//							labelUnit = typeof k.NumericFormat.Unit == 'undefined'? undefined : k.NumericFormat.Unit.substring(0,1);
//							labelPrecision = typeof k.NumericFormat.Precision == 'undefined' ? 2 : k.NumericFormat.Precision;
//							labelPrecisionOption = typeof k.NumericFormat.PrecisionOption == 'undefined' ? 2 : k.NumericFormat.PrecisionOption;
//							labelSeparator = typeof k.NumericFormat.IncludeGroupSeparator == 'undefined' ? true : k.NumericFormat.IncludeGroupSeparator;
//							labelSuffixEnabled = typeof k.NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : k.NumericFormat.SuffixEnabled;
//							labelSuffix = typeof k.NumericFormat.Suffix == 'undefined' ? labelSuffix : k.NumericFormat.Suffix;
//							return false;
//						}
//					});
//        		}
//        	}
			var text;
			// range series
			
			switch(type) {
			case 'None':
				return '';
			case 'Argument':
				return _pointInfo.argumentText;
			case 'Value': 
//				return WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled);
				return Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled, labelPrecisionOption);
			case 'Percent':
//				return (_pointInfo.percent*100).toFixed(precision) + '%';
				return (_pointInfo.percent*100).toFixed(labelPrecision) + '%';
			case 'ArgumentAndValue':
				text = '<b>' + _pointInfo.argumentText + '</b>: '
					+ Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled, labelPrecisionOption);
				break;
			case 'ValueAndPercent': 
				return WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, labelPrecisionOption)
					+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
			case 'ArgumentAndPercent':
				return  '<b>' + _pointInfo.argumentText + '</b>: (' 
					+ (_pointInfo.percent*100).toFixed(precision) + '%)';
			case 'ArgumentValueAndPercent':
				text  = '<b>' + _pointInfo.argumentText + '</b>: '
				+ Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled, labelPrecisionOption)
				+ ' (' + (_pointInfo.percent*100).toFixed(labelPrecision) + '%)';
				break;
//				return '<b>' + _pointInfo.argumentText + '</b>: '
//					+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled)
//					+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
			default:
//				return '<b>' + _pointInfo.argumentText + '</b>: '
//					+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled)
//					+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
				text  = '<b>' + _pointInfo.argumentText + '</b>: '
				+ Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled , labelPrecisionOption)
				+ ' (' + (_pointInfo.percent*100).toFixed(labelPrecision) + '%)';
				break;
			}
			return { html: text };
		};
		
		var colorList = typeof _pie.ColorSheme == 'undefined'? []: gDashboard.itemColorManager.generateColorMeta(_pie.ColorSheme.Entry);
		if(colorList.length === 0){
			colorList = gDashboard.itemColorManager.colorMeta
		}
		var Colorindex = 0;

		var sizeoption = false;
		if(self.panelManager.pieContainers.length != 1){
			sizeoption = true;																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																								
		}
		
		var dxConfigs = {
			series: [{
		        type: pieType,
		        label: label,
			}],
			size:{
				width: sizeoption ? undefined : $('#'+self.itemid).width(),
				height: sizeoption ? undefined : $('#'+self.itemid).height()
			},
			animation: {
    			enabled: _pie['Animation'] === 'none' ? false : true,
    			easing: _pie['Animation'] === 'none' ? 'easeOutCubic' : _pie['Animation']
			},
			customizeLabel: function(e) {
				return {
					backgroundColor: 'none',
					// border: {
					// 	visible: true,
					// 	color: e.series.getPointsByArg(e.argument)[0].getColor()
					// }
				};
			},
			pointSelectionMode: 'multiple',
	        tooltip: tooltip,
	        legend: pieLegend,
	        adaptiveLayout: {keepLabels: true},
	        redrawOnResize: true,
	        palette: _pie['Palette'],
	        customizePoint:function(_e){
//	        	var returnColor;
//	        	$.each(colorList,function(_i,_colorItem){
//	        		if(_colorItem.Value ==_e.argument){
//	        			if(typeof _colorItem.Color != 'undefined'){
//	        				returnColor = (gDashboard.itemColorManager.getHexColor(_colorItem.Color));
//	        				return false;
//	        			}
//	        			else{
//	        				returnColor = gDashboard.itemColorManager.paletteColor[_colorItem.PaletteIndex];
//	        				return false;
//	        			}
//	        		}
//	        	});
//	        	if(typeof returnColor != 'undefined'){
//	        		if(returnColor == gDashboard.itemColorManager.paletteColor[Colorindex]){
//	        			Colorindex++;
//	        		}
//	        		return {color:returnColor};
//	        	}
//	        	else{
//	        		 var palettelist = DevExpress.viz.getPalette(pieTheme);
//	        		 returnColor = palettelist.simpleSet[Colorindex];
//	        		 Colorindex++;
//	        		 return {color:returnColor};
//	        	}
	        },
			onDrawn: function() {
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 렌더링 표시 추가 */
				gProgressbar.finishListening();
			},
	        onPointClick: function(_e) {

	        	if (self.IO && self.IO['MasterFilterMode'] !== 'Off') {
					// do nothing if single master filter and selected point is selected
					if (self.IO.MasterFilterMode === 'Single' && _e.target.isSelected()) {
						return;
					}
					var dimensions, dimensionNames;
					// select and deselect points
					if (self.IO.TargetDimensions === 'Series') {
						dimensions = self.seriesDimensions;
						dimensionNames = _e.component.option('title.text').split('-');
						if (_e.target.isSelected()) {
							$.each(_e.target.series.getAllPoints(), function(i, point) {
	                    		point.clearSelection();
	                    	});
						} else {
							$.each(_e.target.series.getAllPoints(), function(i, point) {
	                    		point.select();
	                    	});
						}
					} else {
						dimensions = self.arguments.slice().reverse();
						dimensionNames = _e.target.argument.split(',');
						for(var i=0; i<dimensionNames.length;i++){
							dimensionNames[i] = dimensionNames[i].replace(/\n/g, "");//행바꿈제거
							dimensionNames[i] = dimensionNames[i].replace(/\r/g, "");//엔터제거
						}
						if (_e.target.isSelected()) {
							$.each(self.dxItem, function(i, pie) {
	                    		$.each(pie.getAllSeries(), function(j, seriesItem) {
		                    		$.each(seriesItem.getPointsByArg(_e.target['originalArgument']), function(k, point) {
		                    			point.clearSelection();
		                    		});
	                    		});
	                    	});
						} else {
							$.each(self.dxItem, function(i, pie) {
	                    		$.each(pie.getAllSeries(), function(j, seriesItem) {
		                    		$.each(seriesItem.getPointsByArg(_e.target['originalArgument']), function(k, point) {
		                    			point.select();
		                    		});
	                    		});
	                    	});
						}
					}
					
	        		switch(self.IO['MasterFilterMode']){
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
			                    if (self.IO['TargetDimensions'] === 'Series') {
			                    	$.each(self.selectedPoint.series.getAllPoints(), function(i, point) {
			                    		point.clearSelection();
			                    	});
			                    } else {
//			                    	self.selectedPoint.clearSelection();

			                    	$.each(self.dxItem, function(i, pie) {
			                    		$.each(pie.getSeriesByPos(0).getPointsByArg(self.selectedPoint['originalArgument']), function(j, point) {
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
//	        	else if(self.IO && self.IO['IsDrillDownEnabled']){
	        	else if (self.IO['IsDrillDownEnabled']) {
	        		// argument drill-down
					if (self.IO['TargetDimensions'] === 'Argument') {
						if(leveling > drillDownIndex){
							drillDownIndex++;
							if (isFirstLevel) {
								isFirstLevel = false;
							}
							ddParentStack.push(ddCurrentID);
							ddCurrentID = _e.target.originalArgument;
							_e.component.option({dataSource : filterData(ddCurrentID, drillDownIndex)});
						}
					} 
					// series drill-down
					else if (self.IO['TargetDimensions'] === 'Series') {
						// TODO
					}
	        	}
	        },
		};
		// extend custom-configurations
		var CustomConfigs = $.extend({}, Configurations);
		$.extend(CustomConfigs, dxConfigs);
		dxConfigs = CustomConfigs;
		// setting loading-indicator message
		dxConfigs.loadingIndicator.text = gMessage.get('WISE.message.page.common.loding');
		
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
	
	/**
	 * Clear master filter selections and tracking on all items.
	 */
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if (self.dxItem) {
				self.dxItem.forEach(function(pie) { 
					pie.clearSelection(); 
				});
			}
			self.trackingData = [];
			self.selectedPoint = undefined;
		}
	};

	
	/**
	 * Selects the first point of the first series in the chart. 
	 */
	this.selectFirstPoint = function() {
		var firstPie = self.dxItem[0],
			firstSeries = firstPie.getSeriesByPos(0),
			firstPoint = firstSeries.getPointByPos(0),
			dimensions,
			dimensionNames;
		self.selectedPoint = firstPoint;
		if (self.IO.TargetDimensions === 'Series') {
			dimensions = self.seriesDimensions;
			dimensionNames = firstPie.option('title.text').split('-');;
			$.each(firstSeries.getAllPoints(), function(i, point) {
				point.select();
			});
		} else {
			dimensions = self.arguments.slice().reverse();
			dimensionNames = firstPoint.argument.split(',');
			$.each(self.dxItem, function(i, pie) {
				pie.getSeriesByPos(0).getPointByPos(0).select();
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
	
	this.setPie = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.Pie.DataItems = this.fieldManager.DataItems;
		this.Pie.Values = this.fieldManager.Values;
		this.Pie.SeriesDimensions = this.fieldManager.SeriesDimensions;
		this.Pie.Arguments = this.fieldManager.Arguments;
		this.Pie.HiddenMeasures = this.fieldManager.HiddenMeasures;
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.seriesDimensions = this.fieldManager.seriesDimensions;
		
		if (!(this.Pie.Initialized)) {
			this.Pie.Name = this.Name;		
			this.Pie.ComponentName = this.ComponentName;
			this.Pie.DataSource = this.dataSourceId;
			this.Pie.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
			this.Pie.IsMasterFilterCrossDataSource = false;
			this.Pie.FilterString = [];
			this.Pie.ShowCaption = true;
			this.Pie.LabelContentType = 'ArgumentAndPercent';
			this.Pie.LabelMeasureFormat = 'O';
			this.Pie.LabelPrefixEnabled = false;
			this.Pie.LabelPrefixFormat = '';
			this.Pie.LabelSuffixEnabled = false;
			this.Pie.LabelSuffix = {
				O: '',
				K: 'K',
				M: 'M',
				B: 'B'
			};
			this.Pie.LabelPrecision = 0;
			this.Pie.LabelPrecisionOption = '반올림';
			this.Pie.LabelPosition = 'Columns';
			this.Pie.TooltipContentType = 'ArgumentValueAndPercent';
			this.Pie.TooltipMeasureFormat = 'O';
			this.Pie.TooltipPrefixEnabled = false;
			this.Pie.TooltipPrefixFormat = '';
			this.Pie.TooltipSuffixEnabled = false;
			this.Pie.TooltipSuffix = {
				O: '',
				K: 'K',
				M: 'M',
				B: 'B'
			};
			this.Pie.TooltipPrecision = 0;
			this.Pie.TooltipPrecisionOption = '반올림';
			this.Pie.PieType = 'Pie';
			this.Pie.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			this.Pie.Animation = 'easeOutCubic';
			
			this.Pie.Initialized = true;
		}
		
		//20210122 AJKIM 파이차트 범례 추가 DOGFOOT
		if(!this.Pie.Legend){
			this.Pie.Legend = {
					Visible : false,
					Position : "TopRightVertical"
			}
		}

		this.meta = this.Pie;
	};
	
	this.setPieForOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setPie();
		}
		else{
			this.Pie = this.meta;
			this.Pie.Initialized = true;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta.DataSource = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.Pie.DataItems = this.meta.DataItems = this.fieldManager.DataItems;
			this.Pie.Values = this.meta.Values = this.fieldManager.Values;
			this.Pie.SeriesDimensions = this.meta.SeriesDimensions = this.fieldManager.SeriesDimensions;
			this.Pie.Arguments = this.meta.Arguments = this.fieldManager.Arguments;
			this.Pie.HiddenMeasures = this.meta.HiddenMeasures = this.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
			this.seriesDimensions = this.fieldManager.seriesDimensions;
		}
		var page = window.location.pathname.split('/');
		/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
		var dashboardXml = gDashboard.structure.MapOption.DASHBOARD_XML || {};
		var pieDataElements = WISE.util.Object.toArray(dashboardXml);
		/* DOGFOOT hsshim 2020-02-06 끝 */
		var pieDataElement = {
			LABEL_OPTIONS: {
				CONTENT_TYPE: 'ArgumentAndPercent',
				MEASURE: 'O',
				PREFIX_ENABLED_YN: 'N',
				PREFIX_FORMAT: '',
				SUFFIX_ENABLED_YN: 'N',
				SUFFIX_O: '',
				SUFFIX_K: 'K',
				SUFFIX_M: 'M',
				SUFFIX_B: 'B',
				PRECISION: 0,
				PRECISION_OPTION: '반올림',
			},
			TOOLTIP_OPTIONS: {
				CONTENT_TYPE: 'ArgumentValueAndPercent',
				MEASURE: 'O',
				PREFIX_ENABLED_YN: 'N',
				PREFIX_FORMAT: '',
				SUFFIX_ENABLED_YN: 'N',
				SUFFIX_O: '',
				SUFFIX_K: 'K',
				SUFFIX_M: 'M',
				SUFFIX_B: 'B',
				PRECISION: 0,
				PRECISION_OPTION: '반올림',
			}
		};
		//20211122 [산림청] syjin 파이차트 데이터 레이블 불러오기 수정 dogfoot
		var pieElements = [];
		if(pieDataElements[0].PIE_DATA_ELEMENT.length > 1){
			pieElements = pieDataElements[0].PIE_DATA_ELEMENT;
		}else{
			pieElements = pieDataElements[0];
		}
		
		$.each(pieElements,function(_i,_e) {
			var CtrlNM;
//			if (page[page.length - 1] === 'viewer.do'){
//				CtrlNM = _e.CTRL_NM + "_" + WISE.Constants.pid;
//			}else{
				CtrlNM = _e.CTRL_NM;
//			}
			/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
			if(CtrlNM == self.ComponentName){
				pieDataElement = _e;
				return false;
			}
		});
		
		$.each(pieDataElements,function(_i,_e) {
			var CtrlNM;
			if (page[page.length - 1] === 'viewer.do'){
				CtrlNM = _e.CTRL_NM + "_" + WISE.Constants.pid;
			}else{
				CtrlNM = _e.CTRL_NM;
			}
			/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
			if(CtrlNM == self.ComponentName){
				pieDataElement = _e;
				return false;
			}
		});
		/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
		//2020.02.12 mksong self.CU가 undefined로 오류 나서 주석 dogfoot
		var dataElement = {};
		if(self.CU!=undefined && self.CU.Data!=undefined) {
			dataElement = self.CU.Data.getDataElement(dashboardXml, pieDataElement.CTRL_NM || self.ComponentName);
		}
		
		if (typeof this.Pie.Name === 'undefined') {
			this.Pie.Name = this.Name;	
		}
		if (typeof this.Pie.ComponentName === 'undefined') {
			this.Pie.ComponentName = this.ComponentName;
		}	
		if (typeof this.Pie.DataSource === 'undefined') {
			this.Pie.DataSource = this.dataSourceId;
		}else if(this.Pie.DataSource != this.dataSourceId){
			this.Pie.DataSource = this.dataSourceId;
		}
		if (this.Pie.InteractivityOptions) {
			if (typeof this.Pie.InteractivityOptions.MasterFilterMode === 'undefined') {
				this.Pie.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (typeof this.Pie.InteractivityOptions.TargetDimensions === 'undefined') {
				this.Pie.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (typeof this.Pie.InteractivityOptions.IsDrillDownEnabled === 'undefined') {
				this.Pie.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (typeof this.Pie.InteractivityOptions.IgnoreMasterFilters === 'undefined') {
				this.Pie.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Pie.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (typeof this.Pie.IsMasterFilterCrossDataSource === 'undefined') {
			this.Pie.IsMasterFilterCrossDataSource = false;
		}
		if (typeof this.Pie.FilterString === 'undefined') {
			this.Pie.FilterString = [];
		}else{
			this.Pie.FilterString = JSON.parse(JSON.stringify(this.Pie.FilterString).replace(/"@null"/gi,null));
		}
		if (typeof this.Pie.ShowCaption === 'undefined') {
			this.Pie.ShowCaption = true;
		}
		if (gDashboard.structure)
		if (typeof this.Pie.LabelContentType === 'undefined') {
			this.Pie.LabelContentType = pieDataElement.LABEL_OPTIONS
				? pieDataElement.LABEL_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.Pie.LabelMeasureFormat === 'undefined') {
			this.Pie.LabelMeasureFormat = pieDataElement.LABEL_OPTIONS 
				? pieDataElement.LABEL_OPTIONS.MEASURE 
				: 'O';
		}
		if (typeof this.Pie.LabelPrefixEnabled === 'undefined') {
			this.Pie.LabelPrefixEnabled = pieDataElement.LABEL_OPTIONS
				&& pieDataElement.LABEL_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Pie.LabelPrefixFormat === 'undefined') {
			this.Pie.LabelPrefixFormat = pieDataElement.LABEL_OPTIONS
				? pieDataElement.LABEL_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.Pie.LabelSuffixEnabled === 'undefined') {
			this.Pie.LabelSuffixEnabled = pieDataElement.LABEL_OPTIONS 
				&& pieDataElement.LABEL_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Pie.LabelSuffix === 'undefined') {
			this.Pie.LabelSuffix = pieDataElement.LABEL_OPTIONS 
				? {
					O: pieDataElement.LABEL_OPTIONS.SUFFIX_O,
					K: pieDataElement.LABEL_OPTIONS.SUFFIX_K,
					M: pieDataElement.LABEL_OPTIONS.SUFFIX_M,
					B: pieDataElement.LABEL_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.Pie.LabelPrecision === 'undefined') {
			this.Pie.LabelPrecision = pieDataElement.LABEL_OPTIONS 
				? pieDataElement.LABEL_OPTIONS.PRECISION 
				: 0;
		}
		if (typeof this.Pie.LabelPrecisionOption === 'undefined') {
			this.Pie.LabelPrecisionOption = pieDataElement.LABEL_OPTIONS 
			? pieDataElement.LABEL_OPTIONS.PRECISION_OPTION 
					: '반올림';
		}
		if (typeof this.Pie.LabelPosition === 'undefined') {
			this.Pie.LabelPosition = 'Columns';
		}
		if (typeof this.Pie.TooltipContentType === 'undefined') {
			this.Pie.TooltipContentType = pieDataElement.TOOLTIP_OPTIONS
				? pieDataElement.TOOLTIP_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.Pie.TooltipMeasureFormat === 'undefined') {
			this.Pie.TooltipMeasureFormat = pieDataElement.TOOLTIP_OPTIONS 
				? pieDataElement.TOOLTIP_OPTIONS.MEASURE 
				: 'O';
		}
		if (typeof this.Pie.TooltipPrefixEnabled === 'undefined') {
			this.Pie.TooltipPrefixEnabled = pieDataElement.TOOLTIP_OPTIONS
				&& pieDataElement.TOOLTIP_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Pie.TooltipPrefixFormat === 'undefined') {
			this.Pie.TooltipPrefixFormat = pieDataElement.TOOLTIP_OPTIONS
				? pieDataElement.TOOLTIP_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.Pie.TooltipSuffixEnabled === 'undefined') {
			this.Pie.TooltipSuffixEnabled = pieDataElement.TOOLTIP_OPTIONS
				&& pieDataElement.TOOLTIP_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Pie.TooltipSuffix === 'undefined') {
			this.Pie.TooltipSuffix = pieDataElement.TOOLTIP_OPTIONS 
				? {
					O: pieDataElement.TOOLTIP_OPTIONS.SUFFIX_O,
					K: pieDataElement.TOOLTIP_OPTIONS.SUFFIX_K,
					M: pieDataElement.TOOLTIP_OPTIONS.SUFFIX_M,
					B: pieDataElement.TOOLTIP_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.Pie.TooltipPrecision === 'undefined') {
			this.Pie.TooltipPrecision = pieDataElement.TOOLTIP_OPTIONS 
				? pieDataElement.TOOLTIP_OPTIONS.PRECISION
				: 0;
		}
		if (typeof this.Pie.TooltipPrecisionOption === 'undefined') {
			this.Pie.TooltipPrecisionOption = pieDataElement.TOOLTIP_OPTIONS 
			? pieDataElement.TOOLTIP_OPTIONS.PRECISION_OPTION
					: '반올림';
		}
		if (typeof this.Pie.Animation === 'undefined') {
			if(window[self.dashboardid].structure.MapOption.DASHBOARD_XML == undefined){
				this.Pie.Animation = 'easeOutCubic';
			}else if(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT == undefined){
				this.Pie.Animation = 'easeOutCubic';
			}else if(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.ANIMATION == undefined){
				this.Pie.Animation = 'easeOutCubic';
			}else{
				this.Pie.Animation = window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.ANIMATION;
			}
//			this.Pie.Animation = typeof window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.ANIMATION == undefined ? 'easeOutCubic' : window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.ANIMATION;
		}
		if (typeof this.Pie.PieType === 'undefined') {
			this.Pie.PieType = 'Pie';
		}
		// preset palette
		if (typeof this.Pie.Palette === 'undefined') {
			/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
			this.Pie.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			if (typeof dataElement.PALETTE_NM !== 'undefined') {
				self.Pie.Palette = dataElement.PALETTE_NM;
			}
			if(typeof this.meta.ColorSheme != 'undefined'){
				var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
				this.Pie.Palette = [];
				var newPalette = [];
				$.each(colorList,function(_i,_list){
					self.Pie.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
					newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
				});
				
				self.customPalette = newPalette;
				self.isCustomPalette = true;
			}
		}
		// custom palette
		
		if (typeof this.Pie.Animation === 'undefined') {
			this.Pie.Animation = 'easeOutCubic';
		}
		
		//20210122 AJKIM 파이차트 범례 추가 DOGFOOT
		if(!this.Pie.Legend){
			this.Pie.Legend = {
					Visible : false,
					Position : "TopRightVertical"
			}
		}
		
		//2020.10.07 MKSONG 불필요한 코드 제거 dogfoot
	};

	this.setPieForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setPie();
		}
		else{
			this.Pie = this.meta;
			this.Pie.Initialized = true;
		}
		// initialize format options from CHART_XML
		$.each(WISE.util.Object.toArray(self.Pie.DataItems.Measure), function(_i, _mea) {
			var dataItemNo = _mea.UniqueName;
			$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.PIE_DATA_ELEMENT), function(_j, _item) {
				if (self.itemid === _item.CTRL_NM+"_"+WISE.Constants.pid+"_item") {
					$.each(WISE.util.Object.toArray(_item.MEASURES), function(_k, _measure) {
						if (dataItemNo === _measure.UNI_NM) {
							_mea.NumericFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
							_mea.NumericFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
							return false;
						}
					});
					return false;
				}
			});
		});

		if(typeof this.meta.DataSource == 'undefined'){
			this.meta.DataSource = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.Pie.DataItems = this.meta.DataItems = this.fieldManager.DataItems;
			this.Pie.Values = this.meta.Values = this.fieldManager.Values;
			this.Pie.SeriesDimensions = this.meta.SeriesDimensions = this.fieldManager.SeriesDimensions;
			this.Pie.Arguments = this.meta.Arguments = this.fieldManager.Arguments;
			this.Pie.HiddenMeasures = this.meta.HiddenMeasures = this.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
			this.seriesDimensions = this.fieldManager.seriesDimensions;
		}
		var page = window.location.pathname.split('/');
		/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
		var dashboardXml = gDashboard.structure.MapOption.DASHBOARD_XML || {};
		//var pieDataElements = WISE.util.Object.toArray(dashboardXml.PIE_DATA_ELEMENT);
		/* DOGFOOT syjin 파이차트 뷰어 불러오기 수정 20211104 */
		var pieDataElements = WISE.util.Object.toArray(dashboardXml);
		/* DOGFOOT hsshim 2020-02-06 끝 */
		var pieDataElement = {
			LABEL_OPTIONS: {
				CONTENT_TYPE: 'ArgumentAndPercent',
				MEASURE: 'O',
				PREFIX_ENABLED_YN: 'N',
				PREFIX_FORMAT: '',
				SUFFIX_ENABLED_YN: 'N',
				SUFFIX_O: '',
				SUFFIX_K: 'K',
				SUFFIX_M: 'M',
				SUFFIX_B: 'B',
				PRECISION: 0,
				PRECISION_OPTION: 0,
			},
			TOOLTIP_OPTIONS: {
				CONTENT_TYPE: 'ArgumentValueAndPercent',
				MEASURE: 'O',
				PREFIX_ENABLED_YN: 'N',
				PREFIX_FORMAT: '',
				SUFFIX_ENABLED_YN: 'N',
				SUFFIX_O: '',
				SUFFIX_K: 'K',
				SUFFIX_M: 'M',
				SUFFIX_B: 'B',
				PRECISION: 0,
				PRECISION_OPTION: 0,
			}
		};

		/* DOGFOOT syjin 파이차트 뷰어 불러오기 수정 20211104 */
		var pieElements = [];
		if(pieDataElements[0].PIE_DATA_ELEMENT.length > 1){
			pieElements = pieDataElements[0].PIE_DATA_ELEMENT;
		}else{
			pieElements = pieDataElements[0];
		}
		
		$.each(pieElements,function(_i,_e) {
			var CtrlNM;

			CtrlNM = _e.CTRL_NM + "_" + WISE.Constants.pid;

			/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
			if(CtrlNM == self.ComponentName){
				pieDataElement = _e;
				return false;
			}
		});
		
		/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
		var dataElement = self.CU.Data.getDataElement(dashboardXml, pieDataElement.CTRL_NM || self.ComponentName);
		
		if (typeof this.Pie.Name === 'undefined') {
			this.Pie.Name = this.Name;	
		}
		if (typeof this.Pie.ComponentName === 'undefined') {
			this.Pie.ComponentName = this.ComponentName;
		}	
		if (typeof this.Pie.DataSource === 'undefined') {
			this.Pie.DataSource = this.dataSourceId;
		}else if(this.Pie.DataSource != this.dataSourceId){
			this.Pie.DataSource = this.dataSourceId;
		}
		if (this.Pie.InteractivityOptions) {
			if (typeof this.Pie.InteractivityOptions.MasterFilterMode === 'undefined') {
				this.Pie.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (typeof this.Pie.InteractivityOptions.TargetDimensions === 'undefined') {
				this.Pie.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (typeof this.Pie.InteractivityOptions.IsDrillDownEnabled === 'undefined') {
				this.Pie.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (typeof this.Pie.InteractivityOptions.IgnoreMasterFilters === 'undefined') {
				this.Pie.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Pie.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (typeof this.Pie.IsMasterFilterCrossDataSource === 'undefined') {
			this.Pie.IsMasterFilterCrossDataSource = false;
		}
		if (typeof this.Pie.FilterString === 'undefined') {
			this.Pie.FilterString = [];
		}else{
			this.Pie.FilterString = JSON.parse(JSON.stringify(this.Pie.FilterString).replace(/"@null"/gi,null));
		}
		if (typeof this.Pie.ShowCaption === 'undefined') {
			this.Pie.ShowCaption = true;
		}
		if (gDashboard.structure)
		if (typeof this.Pie.LabelContentType === 'undefined') {
			this.Pie.LabelContentType = pieDataElement.LABEL_OPTIONS
				? pieDataElement.LABEL_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.Pie.LabelMeasureFormat === 'undefined') {
			this.Pie.LabelMeasureFormat = pieDataElement.LABEL_OPTIONS 
				? pieDataElement.LABEL_OPTIONS.MEASURE 
				: 'O';
		}
		if (typeof this.Pie.LabelPrefixEnabled === 'undefined') {
			this.Pie.LabelPrefixEnabled = pieDataElement.LABEL_OPTIONS
				&& pieDataElement.LABEL_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Pie.LabelPrefixFormat === 'undefined') {
			this.Pie.LabelPrefixFormat = pieDataElement.LABEL_OPTIONS
				? pieDataElement.LABEL_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.Pie.LabelSuffixEnabled === 'undefined') {
			this.Pie.LabelSuffixEnabled = pieDataElement.LABEL_OPTIONS 
				&& pieDataElement.LABEL_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Pie.LabelSuffix === 'undefined') {
			this.Pie.LabelSuffix = pieDataElement.LABEL_OPTIONS 
				? {
					O: pieDataElement.LABEL_OPTIONS.SUFFIX_O,
					K: pieDataElement.LABEL_OPTIONS.SUFFIX_K,
					M: pieDataElement.LABEL_OPTIONS.SUFFIX_M,
					B: pieDataElement.LABEL_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.Pie.LabelPrecision === 'undefined') {
			this.Pie.LabelPrecision = pieDataElement.LABEL_OPTIONS 
				? pieDataElement.LABEL_OPTIONS.PRECISION 
				: 0;
		}
		if (typeof this.Pie.LabelPrecisionOption === 'undefined') {
			this.Pie.LabelPrecisionOption = pieDataElement.LABEL_OPTIONS 
			? pieDataElement.LABEL_OPTIONS.PRECISION_OPTION 
					: '반올림';
		}
		if (typeof this.Pie.LabelPosition === 'undefined') {
			this.Pie.LabelPosition = 'Columns';
		}
		if (typeof this.Pie.TooltipContentType === 'undefined') {
			this.Pie.TooltipContentType = pieDataElement.TOOLTIP_OPTIONS
				? pieDataElement.TOOLTIP_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.Pie.TooltipMeasureFormat === 'undefined') {
			this.Pie.TooltipMeasureFormat = pieDataElement.TOOLTIP_OPTIONS 
				? pieDataElement.TOOLTIP_OPTIONS.MEASURE 
				: 'O';
		}
		if (typeof this.Pie.TooltipPrefixEnabled === 'undefined') {
			this.Pie.TooltipPrefixEnabled = pieDataElement.TOOLTIP_OPTIONS
				&& pieDataElement.TOOLTIP_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Pie.TooltipPrefixFormat === 'undefined') {
			this.Pie.TooltipPrefixFormat = pieDataElement.TOOLTIP_OPTIONS
				? pieDataElement.TOOLTIP_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.Pie.TooltipSuffixEnabled === 'undefined') {
			this.Pie.TooltipSuffixEnabled = pieDataElement.TOOLTIP_OPTIONS
				&& pieDataElement.TOOLTIP_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.Pie.TooltipSuffix === 'undefined') {
			this.Pie.TooltipSuffix = pieDataElement.TOOLTIP_OPTIONS 
				? {
					O: pieDataElement.TOOLTIP_OPTIONS.SUFFIX_O,
					K: pieDataElement.TOOLTIP_OPTIONS.SUFFIX_K,
					M: pieDataElement.TOOLTIP_OPTIONS.SUFFIX_M,
					B: pieDataElement.TOOLTIP_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.Pie.TooltipPrecision === 'undefined') {
			this.Pie.TooltipPrecision = pieDataElement.TOOLTIP_OPTIONS 
				? pieDataElement.TOOLTIP_OPTIONS.PRECISION
				: 0;
		}
		if (typeof this.Pie.TooltipPrecisionOption === 'undefined') {
			this.Pie.TooltipPrecisionOption = pieDataElement.TOOLTIP_OPTIONS 
			? pieDataElement.TOOLTIP_OPTIONS.PRECISION_OPTION
					: '반올림';
		}
		if (typeof this.Pie.Animation === 'undefined') {
			if(window[self.dashboardid].structure.MapOption.DASHBOARD_XML == undefined){
				this.Pie.Animation = 'easeOutCubic';
			}else if(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT == undefined){
				this.Pie.Animation = 'easeOutCubic';
			}else if(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.ANIMATION == undefined){
				this.Pie.Animation = 'easeOutCubic';
			}else{
				this.Pie.Animation = window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.ANIMATION;
			}
//			this.Pie.Animation = typeof window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.ANIMATION == undefined ? 'easeOutCubic' : window[self.dashboardid].structure.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.ANIMATION;
		}
		if (typeof this.Pie.PieType === 'undefined') {
			this.Pie.PieType = 'Pie';
		}
		// preset palette
		if (typeof this.Pie.Palette === 'undefined') {
			/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
			this.Pie.Palette = dataElement.PALETTE_NM ? dataElement.PALETTE_NM : (userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette);
			
			if(typeof this.meta.ColorSheme != 'undefined'){
				var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
				this.Pie.Palette = [];
				var newPalette = [];
				$.each(colorList,function(_i,_list){
					self.Pie.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
					newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
				});
				
				self.customPalette = newPalette;
				self.isCustomPalette = true;
			}
		}
		// custom palette
		
		if (typeof this.Pie.Animation === 'undefined') {
			this.Pie.Animation = 'easeOutCubic';
		}
		
		//20210122 AJKIM 파이차트 범례 추가 DOGFOOT
		if(!this.Pie.Legend){
			this.Pie.Legend = {
					Visible : false,
					Position : "TopRightVertical"
			}
		}

		var page = window.location.pathname.split('/');
	};
	
	/** @Override */
	this.bindData = function(_data, _activePanelId, _overwrite) {
		//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//		if (_overwrite) {
//			this.globalData = _data;
//		}
//		if (!this.tracked) {
//			if(this.globalData == undefined){
//				this.globalData = _.clone(_data);	
//			}
//			this.filteredData = _.clone(_data);
//		}
		if (this.meta && this.meta.FilterString && this.meta.FilterString.length > 0) {
			var newDataSource = new DevExpress.data.DataSource({
			    store: _data,
			    paginate: false
			});
			newDataSource.filter(this.meta.FilterString);
			newDataSource.load();
			self.filteredData = newDataSource.items();
		}
		
		this.enableButtons(_data);
		
//		$("#" + this.itemid).empty();
		//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//		if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
//			var nodataHtml = '<div class="nodata-layer"></div>';
//			$("#" + this.itemid).empty().append(nodataHtml);
//		}
//		else {
//			if (this.dxItem) {
//				this.dxItem = undefined;
//				this.layoutManager.createItemLayer(this.itemid);
//			}
			
			this.renderChart(_data, _activePanelId);
		//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//		}


	};
	
	this.renderChart = function(_data, _activePanelId) {
		var _functionDo;
		if(typeof _activePanelId == 'boolean'){
			_functionDo = _activePanelId;
		}
		
		if (this.seriesTypeSelector && _options === undefined) {
			this.seriesTypeSelector.option('value', '');
		}
		
		if (this.selectedChartType) {
			_options = !_options ? {} : _options;
			_options.seriesType = this.selectedChartType;
		}
		
		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setPie();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Pie);
			gDashboard.itemGenerateManager.generateItem(self, self.Pie);
		}
		else if(this.fieldManager != null && gDashboard.isNewReport == false){ // 레포트 열기
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setPieForOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Pie);
			gDashboard.itemGenerateManager.generateItem(self, self.Pie);
		}else if(self.meta != undefined && self.Pie.length == 0){
			this.setPieForViewer();
			gDashboard.itemGenerateManager.generateItem(self, self.Pie);
		}
		
		
		
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var DELIM = ',';
		var CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
		
		this.panelManager.init();
		this.panelManager.rawData = this.filteredData;
		
		var dataSource = this.__getPieData();
		
		this.panelManager.makePanel(Object.keys(dataSource).length);
		this.panelManager.resize();
		
		// array for each pie chart item
		self.dxItem = [];
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		/* render pie chart */
		$.each(this.panelManager.pieContainers, function(_i, _e) {
			var dxConfig = self.__getPieConfig(dataSource, _e, _i);

			//20201127 AJKIM 데이터가 없는 경우 차트 그리지 않게 수정 dogfoot
            if(dxConfig && dxConfig.dataSource.length !== 0) {
                if (self.IO['IsDrillDownEnabled']) {
                    dxConfig.dataSource = filterDataByLevel(0);
                }
				// push pie chart item to dxItem array
				self.dxItem.push(_e.container.dxPieChart(dxConfig).dxPieChart('instance'));                
            } else {
				$(_e.container).remove();                
            }
		});
		
		self.clearTrackingConditions();
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(!self.functionBinddata){			
			if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}
			/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
			if(WISE.Constants.editmode == 'viewer' && gDashboard.tabQuery){
				if(gDashboard.itemGenerateManager.selectedItemList.length <= gDashboard.itemGenerateManager.viewedItemList.length){
					$('.progress_box').css('display', 'none');
				}
			}
			else if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();
				gDashboard.updateReportLog();
			}
			$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _d) {
				if(_d.type != 'IMAGE'){
					if(_d.dimensions.length == 0 && _d.measures.length == 0){
						gProgressbar.hide();
					}	
				}
			});
			
		}else{
			gProgressbar.hide();
			self.functionBinddata = false;
		}
//		gDashboard.itemGenerateManager.generateDxItem(self);
	};
	
	this.__getRenderType = function() {
		if (this.values.length > 0 && this.arguments.length === 0 && this.seriesDimensions.length === 0) {
			return 'VALUES-ONLY';
		} else if (this.values.length > 0 && this.arguments.length > 0 && this.seriesDimensions.length === 0) {
			if (this.values.length > 1) {
				return 'MULTI_VALUES-AND-ARGUMENTS';
			} else {
				return 'SINGLE_VALUES-AND-ARGUMENTS';
			}
		} else if (this.values.length > 0 && this.arguments.length === 0 && this.seriesDimensions.length > 0) {
			return 'VALUES-AND-SERIESDIMENSIONS';
		} else if (this.values.length > 0 && this.arguments.length > 0 && this.seriesDimensions.length > 0) {
			return 'VALUES-AND-ARGUMENTS-AND-SERIESDIMENSIONS';
		} else {
			return undefined;

		}
	};
	
	this.__getPieConfig = function(_dataSource, _pieContainerInfo, _valueIndex) {
		var CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
		var dxConfig = self.getDxItemConfig(self.meta);
		var Series = dxConfig.series[0];
		var Title = dxConfig.title;
		Title.font = gDashboard.fontManager.getDxItemTitleFont();
		var showPieTitle = self.meta['ShowPieCaptions'] === false ? false : true;
		var dataSourceQueried;

//	      if(self.topN > 0) {
//	         var queriedDataTop = [];
//	         for(var i = 0; i < self.topN; i++) {
//	            queriedDataTop[i] = _dataSource[i];
//	         }

//	         dataSourceQueried = queriedDataTop;
//	      } else {
//	         dataSourceQueried = _dataSource;
//	      }
//	      
//		_dataSource = dataSourceQueried;
		switch(this.renderType) {
		case 'VALUES-ONLY':
			dxConfig.dataSource = _dataSource;
			

			
			Series.argumentField = CTN.arguments.name.SINGLE_ARGUMENT;
			Series.valueField = CTN.arguments.name.SINGLE_ARGUMENT_VALUE;
			
			Title.text = '';
			break;
		case 'SINGLE_VALUES-AND-ARGUMENTS':
			var keyset = _.keys(_dataSource);
			dataSourceQueried = _dataSource[keyset[0]];
			 
//			dxConfig.dataSource = _dataSource[keyset[0]];
			dxConfig.dataSource =  dataSourceQueried;
			
			Series.argumentField = CTN.arguments.name.SINGLE_ARGUMENT;
			Series.valueField = CTN.arguments.name.SINGLE_ARGUMENT_VALUE;
			
			Title.text = _dataSource[keyset[0]][0].caption;
			break;
		case 'MULTI_VALUES-AND-ARGUMENTS':
//			dxConfig.dataSource = _dataSource[_pieContainerInfo.title];
			var keyset = _.keys(_dataSource);
			
			
			dataSourceQueried = _dataSource[self.values[_valueIndex].uniqueName];
			dxConfig.dataSource = dataSourceQueried;
			
			Series.seriesName = typeof _pieContainerInfo.title === 'undefined'? dxConfig.dataSource[0].name : _pieContainerInfo.title;
			Series.argumentField = CTN.arguments.name.SINGLE_ARGUMENT;
			Series.valueField = CTN.arguments.name.SINGLE_ARGUMENT_VALUE;
			
			// Title.text = showPieTitle || (self.IO && self.IO['MasterFilterMode'] && self.IO['TargetDimensions'] === 'Series') ? _pieContainerInfo.title : '';
//			Title.text = keyset[_valueIndex];
			Title.text = _dataSource[keyset[_valueIndex]][0].caption;
			break;
		case 'VALUES-AND-SERIESDIMENSIONS':
			
			dxConfig.dataSource = _dataSource[_pieContainerInfo.title];
			if(typeof dxConfig.dataSource == 'undefined'){
				return false;
			}

			
			Series.seriesName = typeof _pieContainerInfo.title === 'undefined'? dxConfig.dataSource[0].name : _pieContainerInfo.title;
			Series.argumentField = CTN.arguments.name.SINGLE_ARGUMENT;
			Series.valueField = CTN.arguments.name.SINGLE_ARGUMENT_VALUE;
			
			// Title.text = showPieTitle || (self.IO && self.IO['MasterFilterMode'] && self.IO['TargetDimensions'] === 'Series') ? _pieContainerInfo.title : '';
			Title.text = _pieContainerInfo.title;
			break;
		case 'VALUES-AND-ARGUMENTS-AND-SERIESDIMENSIONS':
//			dxConfig.dataSource = _dataSource[_pieContainerInfo.title];
			dxConfig.dataSource = _dataSource[_pieContainerInfo.uniqueName];


			
			Series.argumentField = CTN.arguments.name.SINGLE_ARGUMENT;
			Series.valueField = CTN.arguments.name.SINGLE_ARGUMENT_VALUE;
			
			// Title.text = showPieTitle || (self.IO && self.IO['MasterFilterMode'] && self.IO['TargetDimensions'] === 'Series') ? _pieContainerInfo.title : '';
			Title.text = _pieContainerInfo.title;
			break;
		}
		
		if (!dxConfig.dataSource || _.isEmpty(dxConfig.dataSource)) {
			dxConfig.dataSource = [];
		}

		return dxConfig;
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
			
				/*dogfoot 파이차트 TopN 차원그룹 오류 수정 shlim 20200629*/
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
						/*dogfoot 파이차트 TopN 차원그룹 오류 수정 shlim 20200629*/
						var ExecSyx = DevExpress.data.query(_e.items);
						ExecSyx = ExecSyx.groupBy(nowDim);
						topNarray = ExecSyx.toArray();
						$.each(topNarray, function(i, e) {
							topnData.push(e);
						});
					}	
				})
			
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
	
	//20210122 AJKIM 파이차트 범례 추가 DOGFOOT
	this.getLegend = function(legendOption){
		return {
			horizontalAlignment : legendOption.indexOf("Right") > -1? "right" : legendOption.indexOf("Left") > -1? "left" : "center",
			orientation : legendOption.indexOf("Vertical") > -1? "vertical" : "horizontal",
			verticalAlignment : legendOption.indexOf("Top") > -1? "top" : "bottom",
			visible :self.meta.Legend.Visible,
			font : gDashboard.fontManager.getDxItemLabelFont()
		}
	}
	
	this.__getPieData = function() {
		var dataBasket = [];
		var rootkey = [];
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		var CTN = WISE.libs.Dashboard.item.ChartUtility.Constants;
		var queryData;
		//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
		var queryDataConfig;
		var captionBySummaryType;
		var caption;
		
//		this.csvData = gDashboard.itemGenerateManager.doQueryCSVData(self);
		
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
					$.each(self.arguments,function(_i, _argument){
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						if(_argument != undefined){
							if(field.Name == _argument.name){
								self.calculatedFields.push(_argument);
								self.calculateCaption = _argument.name;
								var tempDataField = gDashboard.customFieldManager.trackingDatafields(field);
								if(tempDataField != undefined && tempDataField.length != 0){
									var tempList = [];
									$.each(tempDataField,function(_ii,_tempDataField){
										var duplicatedCheck = false;
										$.each(self.arguments,function(_k, _argument2){
											if(_tempDataField == _argument2.UNI_NM){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											tempList.push(_tempDataField);
										}
									});
									tempDataField = tempList;
								}
								self.arguments.splice(_i,1);
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
										self.arguments.push(dataMember);
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
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
				});
			}
		}
		
		this.measures = this.measures.concat(this.HiddenMeasures);
		var dimensions = self.arguments.concat(self.seriesDimensions);
		//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//		this.csvData = SQLikeUtil.fromJsonforNoSummaryType(dimensions, this.measures, this.filteredData);
		/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
		var csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(dimensions, this.measures, null, undefined, undefined, self.orderKey);
		if(self.IO.IgnoreMasterFilters){
			csvDataConfig.Where = [];
			csvDataConfig.From = [];
		}
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		this.csvData = SQLikeUtil.doSqlLike(this.dataSourceId, csvDataConfig, self);
		
		//2020.05.04 AJKIM 데이터 항목 없을 때 이미지 추가 DOGFOOT
		if (!this.csvData || ($.type(this.csvData) === 'array' && this.csvData.length === 0)) {
			$('#'+self.itemid + ' .nodata-layer').remove();
			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
			$("#" + self.itemid).children().css('display','none');
			$("#" + self.itemid).prepend(nodataHtml);
			if($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0){
				$("#" + self.itemid).height('100%');
				$("#" + self.itemid).width('100%');
			}
			$("#" + self.itemid).css('display', 'block');

			if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
				gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
			}
			/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
			if(WISE.Constants.editmode == 'viewer' && gDashboard.tabQuery){
				if(gDashboard.itemGenerateManager.selectedItemList.length <= gDashboard.itemGenerateManager.viewedItemList.length){
					$('.progress_box').css('display', 'none');
				}
			}
			else if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();	
				gDashboard.updateReportLog();
			}
			
			return {};
		}else{
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
		self.filteredData = this.csvData;
		
		//2020.05.11 ajkim 제거된 필드가 있으면 필터에서도 제거 dogfoot
		function fieldCheck(_filterString){
			if(_filterString === undefined || _filterString === [] || _filterString === "" || !_filterString)
				return;
			var removedData = true;
			if($.type(_filterString[0]) === 'string'){
				removedData = true;
				dimensions = self.dimensions.concat(self.seriesDimensions);
				$.each(dimensions, function(_i, _dimension){
					if(_dimension.name === self.meta.FilterString[0])
						removedData = false;
				});
				if(removedData)
					_filterString.splice(0, 3);
			}else{
				var removeCount = 0;
				$.each(_filterString, function(_i, _filter){
					removedData = true;
					dimensions = self.dimensions.concat(self.seriesDimensions);
				    $.each(dimensions, function(_j, _dimension){
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
		
		switch(this.renderType) {
		case 'VALUES-ONLY':
			//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//			queryData = SQLikeUtil.fromJson([], this.measures, this.filteredData);
			/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
			queryDataConfig = SQLikeUtil.fromJson([], this.measures, null, undefined, undefined, self.orderKey);
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			queryData = SQLikeUtil.doSqlLike(this.dataSourceId, queryDataConfig, self);
			//2020.03.26 ajkim 필터 적용 dogfoot
			gDashboard.itemGenerateManager.checkFilteredData(queryData, self);
			/* DOGFOOT hsshim 200103
			 * 사용자 정의 데이터 집계 함수 추가
			 */
			
			//2020.02.04 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 수정 끝 dogfoot
			if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && self.calculatedFields.length > 0) {
				var fieldList = gDashboard.customFieldManager.fieldInfo[self.dataSourceId];
				if (fieldList) {
					fieldList.forEach(function(field) {
						$.each(self.calculatedFields,function(_i,_calculatedField){
							if(field.Name == _calculatedField.name){
								/* DOGFOOT shlim 사용자 정의 데이터 정렬기준항목으로 생성 가능하도록 수정  20210121 */
								gDashboard.customFieldManager.addCustomFieldsToDataSourceForSummaryValue(field, queryData, _calculatedField, self.measures, dimensions,self.HiddenMeasures);		
								gDashboard.customFieldManager.addCustomFieldsToDataSource(field, queryData, self.calculatedFields);
							}
						});
					});
				}
			}
			
//			gDashboard.customFieldManager.addSummaryFieldData(self, queryData);
//			queryData = SQLikeUtil.fromJsonforNoSummaryType(dimensions, this.measures, this.filteredData);
			$.each(queryData, function(_i, _do) {
				$.each(self.values, function(_i0, _v0) {
					var d = {};
					d[CTN.arguments.name.SINGLE_ARGUMENT] = _v0.caption;
					d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _do[_v0.nameBySummaryType];
					dataBasket.push(d);
				});
			});
			break;
		case 'SINGLE_VALUES-AND-ARGUMENTS':
		case 'MULTI_VALUES-AND-ARGUMENTS':
			dataBasket = {};
			//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//			queryData = SQLikeUtil.fromJson(this.dimensions, this.measures, this.filteredData);
			/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
			queryDataConfig = SQLikeUtil.fromJson(this.dimensions, this.measures, this.filteredData, undefined, undefined, self.orderKey);
			if(self.IO.IgnoreMasterFilters){
				queryDataConfig.Where = [];
				queryDataConfig.From = [];
			}
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			queryData = SQLikeUtil.doSqlLike(this.dataSourceId, queryDataConfig, self);
			
			// 20201127 AJKIM 데이터 필터링 추가 dogfoot
			if (this.meta && this.meta.FilterString && this.meta.FilterString.length > 0) {
				var newDataSource = new DevExpress.data.DataSource({
					store: queryData,
					paginate: false
				});
				newDataSource.filter(this.meta.FilterString);
				newDataSource.load();
				queryData = newDataSource.items();
		    }
			//2020.03.26 ajkim 필터 적용 dogfoot
			gDashboard.itemGenerateManager.checkFilteredData(queryData, self);
			
			var dimensions = [];
			dimensions = dimensions.concat(_.clone(this.dimensions));
			
			/* LSH topN
			 *  topN 계산을 위한 함수
			 * */
			if(self.topNEnabeled){
				var first=[];
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
				})

				queryData = topNarray;
			}
			
			
			/* DOGFOOT hsshim 200103
			 * 사용자 정의 데이터 집계 함수 추가
			 */
			if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && self.calculatedFields.length > 0) {
				var fieldList = gDashboard.customFieldManager.fieldInfo[self.dataSourceId];
				if (fieldList) {
					fieldList.forEach(function(field) {
						$.each(self.calculatedFields,function(_i,_calculatedField){
							if(field.Name == _calculatedField.name){
								/* DOGFOOT shlim 사용자 정의 데이터 정렬기준항목으로 생성 가능하도록 수정  20210121 */
								gDashboard.customFieldManager.addCustomFieldsToDataSourceForSummaryValue(field, queryData, _calculatedField, self.measures, dimensions,self.HiddenMeasures);		
								gDashboard.customFieldManager.addCustomFieldsToDataSource(field, queryData, self.calculatedFields);
							}
						});
					});
				}
			}
			
//			gDashboard.customFieldManager.addSummaryFieldData(self, queryData);
//			queryData = SQLikeUtil.fromJsonforNoSummaryType(dimensions, this.measures, this.filteredData);
			$.each(self.values, function(_i0, _v0) {
//				dataBasket[_v0.captionBySummaryType] = [];
				dataBasket[_v0.uniqueName] = [];
				captionBySummaryType = _v0.captionBySummaryType;
				$.each(queryData, function(_i1, _d1) {
					var caption = [];
					$.each(self.arguments, function(_ii, _ao) {
						caption.push(_d1[_ao.name]);
					});
					var d = {};
					d[CTN.arguments.name.SINGLE_ARGUMENT] = caption.reverse().join(',');
					d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _d1[_v0.nameBySummaryType];
//					d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _d1[_v0.caption];
					d['name'] = _v0.name;
					d['uniqueName'] = _v0.uniqueName;
					d['caption'] = _v0.caption;
//					dataBasket[_v0.captionBySummaryType].push(d);
					dataBasket[_v0.uniqueName].push(d);
				});
			});
			break;
		case 'VALUES-AND-SERIESDIMENSIONS':
			dataBasket = {};
			//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//			queryData = SQLikeUtil.fromJson(this.seriesDimensions, this.measures, this.filteredData);
			/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
			queryDataConfig = SQLikeUtil.fromJson(this.seriesDimensions, this.measures, null, undefined, undefined, self.orderKey);
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			queryData = SQLikeUtil.doSqlLike(this.dataSourceId, queryDataConfig, self);
			// 20201127 AJKIM 데이터 필터링 추가 dogfoot
			if (this.meta && this.meta.FilterString && this.meta.FilterString.length > 0) {
				var newDataSource = new DevExpress.data.DataSource({
					store: queryData,
					paginate: false
				});
				newDataSource.filter(this.meta.FilterString);
				newDataSource.load();
				queryData = newDataSource.items();
		    }
			//2020.03.26 ajkim 필터 적용 dogfoot
			gDashboard.itemGenerateManager.checkFilteredData(queryData, self);
			
			var dimensions = [];
			dimensions = dimensions.concat(_.clone(this.seriesDimensions));
			dimensions = dimensions.concat(_.clone(this.dimensions));
			
			/* LSH topN
			 *  topN 계산을 위한 함수
			 * */
			if(self.topNEnabeled){
				var first=[];
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
				})

				queryData = topNarray;
			}
			
			/* DOGFOOT hsshim 200103
			 * 사용자 정의 데이터 집계 함수 추가
			 */
			if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && self.calculatedFields.length > 0) {
				var fieldList = gDashboard.customFieldManager.fieldInfo[self.dataSourceId];
				if (fieldList) {
					fieldList.forEach(function(field) {
						$.each(self.calculatedFields,function(_i,_calculatedField){
							if(field.Name == _calculatedField.name){
								/* DOGFOOT shlim 사용자 정의 데이터 정렬기준항목으로 생성 가능하도록 수정  20210121 */
								gDashboard.customFieldManager.addCustomFieldsToDataSourceForSummaryValue(field, queryData, _calculatedField, self.measures, dimensions,self.HiddenMeasures);		
								gDashboard.customFieldManager.addCustomFieldsToDataSource(field, queryData, self.calculatedFields);
							}
						});
					});
				}
			}
			
//			gDashboard.customFieldManager.addSummaryFieldData(self, queryData);
//			queryData = SQLikeUtil.fromJsonforNoSummaryType(dimensions, this.measures, this.filteredData);
			
			$.each(queryData, function(_i, _do) {
				var key = [], keyBasket = [];
				$.each(self.seriesDimensions, function(_i0, _v0) {
					keyBasket.push(_do[_v0.name]);
				});
				key = keyBasket.join('-');
				captionBySummaryType = key;

				dataBasket[key] = [];
				$.each(self.values, function(_i0, _v0) {
					var d = {};
					d[CTN.arguments.name.SINGLE_ARGUMENT] = _v0.caption
					d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _do[_v0.nameBySummaryType];
//					d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _do[_v0.caption];
					d['name'] = _v0.name;
					d['uniqueName'] = _v0.uniqueName;
					d['caption'] = _v0.name;
					dataBasket[key].push(d);
				});
			});
			break;
		case 'VALUES-AND-ARGUMENTS-AND-SERIESDIMENSIONS':
			var dimensions = [];
			dimensions = dimensions.concat(_.clone(this.dimensions));
			dimensions = dimensions.concat(_.clone(this.seriesDimensions));
			
			var measures = [];
			measures = measures.concat(_.clone(this.measures));
//			measures = measures.concat(_.clone(this.HiddenMeasures));
			
			//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//			queryData = SQLikeUtil.fromJson(dimensions, measures, this.filteredData);
			/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
			queryDataConfig = SQLikeUtil.fromJson(dimensions, measures, null, undefined, undefined, self.orderKey);
			queryData = SQLikeUtil.doSqlLike(this.dataSourceId, queryDataConfig, self);
			// 20201127 AJKIM 데이터 필터링 추가 dogfoot
			if (this.meta && this.meta.FilterString && this.meta.FilterString.length > 0) {
				var newDataSource = new DevExpress.data.DataSource({
					store: queryData,
					paginate: false
				});
				newDataSource.filter(this.meta.FilterString);
				newDataSource.load();
				queryData = newDataSource.items();
		    }
			//2020.03.26 ajkim 필터 적용 dogfoot
			gDashboard.itemGenerateManager.checkFilteredData(queryData, self);
			
			/* LSH topN
			 *  topN 계산을 위한 함수
			 * */
			if(self.topNEnabeled){
				var first=[];
				first.push({items:queryData});
				queryData = first;
				/*dogfoot 파이차트 TopN 차원그룹 오류 수정 shlim 20200629*/
		    	var seriesTopCnt = 0;
		    	$.each(self.seriesDimensions,function(_id,_top){
			    	if(_top.TopNEnabled){
                       seriesTopCnt++;
				    }
				});

				if(seriesTopCnt>0){
					for(var i = 0; i < self.seriesDimensions.length;i++){
						var chdddg = self.dimensionTopN.pop();
						self.dimensionTopN.unshift(chdddg);
					}
				}
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
				})

				queryData = topNarray;
			}
			/* DOGFOOT hsshim 200103
			 * 사용자 정의 데이터 집계 함수 추가
			 */
			if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && self.calculatedFields.length > 0) {
				var fieldList = gDashboard.customFieldManager.fieldInfo[self.dataSourceId];
				if (fieldList) {
					fieldList.forEach(function(field) {
						$.each(self.calculatedFields,function(_i,_calculatedField){
							if(field.Name == _calculatedField.name){
								/* DOGFOOT shlim 사용자 정의 데이터 정렬기준항목으로 생성 가능하도록 수정  20210121 */
								gDashboard.customFieldManager.addCustomFieldsToDataSourceForSummaryValue(field, queryData, _calculatedField, self.measures, dimensions,self.HiddenMeasures);		
								gDashboard.customFieldManager.addCustomFieldsToDataSource(field, queryData, self.calculatedFields);
							}
						});
					});
				}
			}
			
//			gDashboard.customFieldManager.addSummaryFieldData(self, queryData);
//			queryData = SQLikeUtil.fromJsonforNoSummaryType(dimensions, this.measures, this.filteredData);
			
			var tempDataSet = {};
			var comparekey="";
			$.each(queryData, function(_i, _do) {
				var key = [], keyBasket = [];
				$.each(self.seriesDimensions, function(_i0, _v0) {
					keyBasket.push(_do[_v0.name]);
				});
				key = keyBasket.join('-');
				if (!tempDataSet[key]) tempDataSet[key] = [];
				
				tempDataSet[key].push(_.clone(_do));
				
				if(_i === 0){
					rootkey.push(key);
					comparekey = key;
				}
				else if(comparekey.indexOf(key)==-1){
					rootkey.push(key);
					comparekey = key;
				}
			});
			var dataBasket = {};
			leveling++;

			$.each(self.values, function(_i0, _v0) {
				$.each(tempDataSet, function(_k, _d) {
//					var pieName = _k + '-' + _v0.captionBySummaryType;
					var pieName = _k + '-' + _v0.uniqueName;
					dataBasket[pieName] = [];
					$.each(_d, function(_ii, _d0) {
						var caption = [];
						$.each(self.arguments, function(_ii, _ao) {
							caption.push(_d0[_ao.name]);
						});
					
						var d = {};
						d[CTN.arguments.name.SINGLE_ARGUMENT] = caption.reverse().join(',');
						d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _d0[_v0.nameBySummaryType];
						d['caption'] = _v0.name;
//						d[CTN.arguments.name.SINGLE_ARGUMENT_VALUE] = _d0[_v0.caption];
						d.leveling = leveling;
						dataBasket[pieName].push(d);
					});
					
				});
			});
			break;
		}

		var temp = [];
		var itemname = [];
		if(self.IO && self.IO['IsDrillDownEnabled']){
			leveling = 0;
			var sqlConfig = {};
			var arg = CTN.arguments.name.SINGLE_ARGUMENT;
			sqlConfig.groupBy = [];
			sqlConfig.Select = [];
			$.each(self.dimensions,function(j,e){
				var valuearr;
				var valname = CTN.arguments.name.SINGLE_ARGUMENT_VALUE;
				sqlConfig.From = queryData;
				sqlConfig.Select.push(e['name']);
				sqlConfig.Select.push(e['name'],'|as|','arg');
				$.each(self.measures,function(i,measures){
					valuearr = 'sum_'+measures['nameBySummaryType'];
					sqlConfig.Select.push('|sum|',measures['nameBySummaryType']);
				})
				sqlConfig.groupBy.push(e['name']);
				// if(self.renderType == 'VALUES-AND-ARGUMENTS-AND-SERIESDIMENSIONS'){
				// 	$.each(self.seriesDimensions,function(rooti,roote){
				// 		sqlConfig.groupBy.push(roote['name']);
				// 	})
				// }
				var result = (SQLike.q(sqlConfig));
				var tt ="";

				itemname.push(e['name']);
				$.each(result,function(i,ee){
					
					if(ee[e['name']].toString() != ee[itemname[leveling]].toString()){
						tt =ee[itemname[leveling++]];
					}
					else{
						if(itemname.length ==1){
							// switch(self.renderType) {
							// case 'VALUES-ONLY':
							// case 'SINGLE_VALUES-AND-ARGUMENTS':
							// case 'MULTI_VALUES-AND-ARGUMENTS':
							// case 'VALUES-AND-SERIESDIMENSIONS':
								tt = "";
								// break;
							// case 'VALUES-AND-ARGUMENTS-AND-SERIESDIMENSIONS':
							// 	tt = rootkey[i];
							// 	break;
							// }
						}else{
							tt =(ee[itemname[leveling-1]]);
						}
					}
					var obj = {};
					obj[arg] = ee[e['name']];
					obj[valname] = ee[valuearr];
					obj['parentID'] = tt;
					obj['leveling'] = leveling;

					temp.push(obj);
				})

			})
			this.metadata = temp;
		}
		return dataBasket;
	};
	
	/** @Override */
	this.resize = function() {
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'viewer.do' || page[page.length - 1] ==='view.do') {
			
		}
		else{
			this.panelManager.resize();
		}
	}
	
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
		//2020.10.07 MKSONG 불필요한 코드 제거 dogfoot
	};
	
	this.drillUp = function(){
		if (!isFirstLevel) {
			switch(self.IO['TargetDimensions']) {
				case 'Series':
					break;
				case 'Argument':
					drillDownIndex--;
					if (drillDownIndex === 0) {
						isFirstLevel = true;
					}
					ddCurrentID = ddParentStack.pop();
					var levelDownDs = filterData(ddCurrentID, drillDownIndex); 
					self.dxItem[0].option('dataSource', levelDownDs);
					break;
			}
		}
	}
	
	
	
	/**
	 * generate UI for data and design functions
	 */ 
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
		//2020.10.07 MKSONG 불필요한 코드 제거 dogfoot
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
				contentTemplate: function(contentElement) {
					var field = [];
					$.each(self.seriesDimensions, function(_i, series) {
						field.push({ dataField: series.name, dataType: 'string' });
					});
					$.each(self.dimensions, function(_i, dimension) {
						field.push({ dataField: dimension.name, dataType: 'string' });
					});

					contentElement.append('<div id="' + self.itemid + '_editFilter">');
					 var html = '<div class="modal-footer" style="padding-bottom:0px;">' +
									'<div class="row center">' +
										'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
										'<a id="close" href="#" class="btn neutral close">취소</a>' +
									'</div>' +
								'</div>';
					contentElement.append(html);

					$('#' + self.itemid + '_editFilter').dxFilterBuilder({
						fields: field,
						value: self.meta.FilterString
					});
                                        
                    // confirm and cancel
                    contentElement.find('#ok-hide').on('click', function() {
//                        var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').getFilterExpression();
                    	var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').option('value');
                        var newDataSource = new DevExpress.data.DataSource({
                            store: self.filteredData,
                            paginate: false
                        });
                        newDataSource.filter(filter);
						newDataSource.load();
						self.filteredData = newDataSource.items();
                        self.meta.FilterString = filter;
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
                        gProgressbar.hide();
                    });
                    contentElement.find('#close').on('click', function() {
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
			setTimeout(function () {
				if(self.meta.FilterString.length > 0){
					self.meta.FilterString = [];
					$('#editFilter').removeClass('on');
					self.functionBinddata = true;
					gProgressbar.show();
					self.filteredData = self.globalData;
					self.bindData(self.globalData, true);
					if (self.IO.MasterFilterMode !== 'Off') {
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, []);
					}
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
				self.Pie.InteractivityOptions.IsDrillDownEnabled = false;
				self.IO.IsDrillDownEnabled = false;
				drillDownIndex = 0;
				ddParentStack = [];
				ddCurrentID = '';
				self.bindData(self.globalData, true);	
			}
			
			gProgressbar.show();
			setTimeout(function () {
				// toggle off
				if (self.IO.MasterFilterMode === 'Single') {
					$('#' + self.trackingClearId).addClass('invisible');
					self.Pie.InteractivityOptions.MasterFilterMode = 'Off';
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
					self.Pie.InteractivityOptions.MasterFilterMode = 'Single';
					self.IO.MasterFilterMode = 'Single';
					
					gDashboard.itemGenerateManager.viewedItemList=[];
					gDashboard.itemGenerateManager.viewedItemList[0] = self.ComponentName ;		
					
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
					gDashboard.filterData(self.itemid, self.trackingData);
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
			// Both master filter and drill-down cannot be active at the same time. Turn drill-down off.
			if (self.IO.IsDrillDownEnabled) {
				self.Pie.InteractivityOptions.IsDrillDownEnabled = false;
				self.IO.IsDrillDownEnabled = false;
				drillDownIndex = 0;
				ddParentStack = [];
				ddCurrentID = '';
				self.bindData(self.globalData, true);	
			}	
			
			gProgressbar.show();
			setTimeout(function () {
				if (self.IO.MasterFilterMode === 'Multiple') {
					$('#' + self.trackingClearId).addClass('invisible');
					self.Pie.InteractivityOptions.MasterFilterMode = 'Off';
					self.IO.MasterFilterMode = 'Off';
					self.clearTrackingConditions();
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
					var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
					if(reTrackItem){
						gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
					}else{
						gDashboard.filterData(self.itemid, self.trackingData);	
					}
				} else {
					$('#' + self.trackingClearId).removeClass('invisible');
					self.Pie.InteractivityOptions.MasterFilterMode = 'Multiple';
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
					gDashboard.filterData(self.itemid, self.trackingData);
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
			if (self.IO.MasterFilterMode !== 'Off') {
				self.Pie.InteractivityOptions.MasterFilterMode = 'Off';
				self.IO.MasterFilterMode = 'Off';
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				gDashboard.filterData(self.itemid, []);
			}
			if ($('#drillDown').hasClass('on')) {
				$('#' + self.DrilldownClearId).removeClass('invisible');
				// argument drill-down
				if (self.IO.TargetDimensions === 'Argument' && self.arguments.length > 0) {
					self.Pie.InteractivityOptions.IsDrillDownEnabled = true;
					self.IO.IsDrillDownEnabled = true;
                    var newData = self.__getPieData();
                    newData = filterDataByLevel(0);
					$.each(self.dxItem, function(index, pie) {
						pie.option({dataSource: newData});
					});
					gProgressbar.hide();
				}
				// series drill-down
				else if (self.IO.TargetDimensions === 'Series' && self.seriesDimensions.length > 0) {
					// TODO
				}
			} else {
				$('#' + self.DrilldownClearId).addClass('invisible');
				self.Pie.InteractivityOptions.IsDrillDownEnabled = false;
				self.IO.IsDrillDownEnabled = false;
				drillDownIndex = 0;
				ddParentStack = [];
				ddCurrentID = '';
				self.bindData(self.globalData,true);
			}
			break;
		}
		// toggle cross data source filtering
		case 'crossFilter': {
			if (!(self.dxItem)) {
				break;
			}
			self.IsMasterFilterCrossDataSource = $('#crossFilter').hasClass('on') ? true : false;
			self.Pie.IsMasterFilterCrossDataSource = self.IsMasterFilterCrossDataSource;
			self.clearTrackingConditions();
			/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
			gDashboard.filterData(self.itemid, self.trackingData);
			break;
		}
		// toggle ignore master filter
		case 'ignoreMasterFilter': {
			if (!(self.dxItem)) {
				break;
			}	
			self.IO.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
			self.Pie.InteractivityOptions.IgnoreMasterFilters = self.IO.IgnoreMasterFilters;
			self.tracked = !self.IO.IgnoreMasterFilters;

			gProgressbar.show();
			
			setTimeout(function () {	
				if (self.IO.IgnoreMasterFilters) {
					self.functionBinddata = true;
				}				
				self.bindData(self.globalData, true);
			},10);
			
			
			break;
		}
		// change dimension target to arguments
		case 'targetArgument': {
			if (!(self.dxItem)) {
				break;
			}
			self.IO.TargetDimensions = 'Argument';
			self.Pie.InteractivityOptions.TargetDimensions = 'Argument';
			self.clearTrackingConditions();
			/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
			gDashboard.filterData(self.itemid, self.trackingData);
			if (self.IO.MasterFilterMode !== 'Off') {
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
			self.Pie.InteractivityOptions.TargetDimensions = 'Series';
			self.clearTrackingConditions();
			/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
			gDashboard.filterData(self.itemid, self.trackingData);
			if (self.IO.MasterFilterMode !== 'Off') {
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
					self.Pie.ShowCaption = true;
				} else {
					titleBar.css('display', 'none');
					self.Pie.ShowCaption = false;
				}
				break;
			}
			// edit pie title
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
                        contentElement.find('#ok-hide').on('click', function() {
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
                            	
                                self.Pie.Name = newName;
                                self.Name = newName;
                                p.hide();
                            }
                            });
                        contentElement.find('#close').on('click', function() {
                            p.hide();
                        });
					}
				});
				// show popup
				p.show();
				break;
			}
			// edit label/tooltip value measure, precision and suffix
			case 'editLabel': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				var mapping = {
					'없음': 'None',
					'인수': 'Argument',
					'값': 'Value',
					'%': 'Percent',
					'인수 및 값': 'ArgumentAndValue',
					'값 및 %': 'ValueAndPercent',
					'인수 및 %': 'ArgumentAndPercent',
					'인수, 값 및 %': 'ArgumentValueAndPercent',
					None: '없음',
					Argument: '인수',
					Value: '값',
					Percent: '%',
					ArgumentAndValue: '인수 및 값',
					ValueAndPercent: '값 및 %',
					ArgumentAndPercent: '인수 및 %',
					ArgumentValueAndPercent: '인수, 값 및 %',
					Auto: 'A',
					Ones: 'O',
					Thousands: 'K',
					Millions: 'M',
					Billions: 'B',
					A: 'Auto',
					O: 'Ones',
					K: 'Thousands',
					M: 'Millions',
					B: 'Billions'
				};
				p.option({
					title: '라벨 데이터 편집',
					contentTemplate: function(contentElement) {
                        contentElement.append('<div id="' + self.itemid + '_labelForm">');
                        var html = 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        
						$('#' + self.itemid + '_labelForm').dxForm({
							dataSource: {
								표기형식: mapping[pieLabelFormat.type],
								단위: pieLabelFormat.format,
								'사용자 지정 접두사': pieLabelFormat.prefixEnabled,
								'접두사': pieLabelFormat.prefixFormat,
								'사용자 지정 접미사': pieLabelFormat.suffixEnabled,
								O: pieLabelFormat.suffix.O,
								K: pieLabelFormat.suffix.K,
								M: pieLabelFormat.suffix.M,
								B: pieLabelFormat.suffix.B,
								정도: pieLabelFormat.precision,
								'정도 옵션': pieLabelFormat.precisionOption,
							},
							items: [
								{
									dataField: '표기형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										dataSource: ['없음', '인수', '값', '%', '인수 및 값', 
											 '값 및 %', '인수 및 %', '인수, 값 및 %'],
										value: mapping[pieLabelFormat.type],
										onValueChanged: function(e) {
											if (e.value === '값' || e.value === '인수 및 값' || e.value === '값 및 %' || e.value === '인수, 값 및 %') {
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('단위').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접두사').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접미사').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도').option('disabled', false);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도 옵션').option('disabled', false);
											} else {
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('단위').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접두사').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접미사').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도').option('disabled', true);
												$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도 옵션').option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '단위',
									editorType: 'dxSelectBox',
									editorOptions: {
										dataSource: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
										value: mapping[pieLabelFormat.format],
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '사용자 지정 접두사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: pieLabelFormat.prefixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										},
										onValueChanged: function(e) {
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: '접두사',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieLabelFormat.prefixFormat,
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '사용자 지정 접미사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: pieLabelFormat.suffixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										},
										onValueChanged: function(e) {
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('disabled', !e.value);
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('disabled', !e.value);
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('disabled', !e.value);
											$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: 'O',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieLabelFormat.suffix.O,
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'K',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieLabelFormat.suffix.K,
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'M',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieLabelFormat.suffix.M,
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'B',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieLabelFormat.suffix.B,
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
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
										showSpinButtons: true,
										value: pieLabelFormat.precision,
										onInitialized: function(e) {
											var formatType = mapping[pieLabelFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '정도 옵션',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['반올림', '올림', '버림'],
										value: typeof pieLabelFormat.precisionOption !== 'undefined' ? pieLabelFormat.precisionOption : "반올림",
									}
								},
							]
                        });
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            // save label settings
                            pieLabelFormat.type = mapping[$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('표기형식').option('value')];
							self.Pie.LabelContentType = pieLabelFormat.type;
                            pieLabelFormat.format = mapping[$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('단위').option('value')];
							self.Pie.LabelMeasureFormat = pieLabelFormat.format;
							pieLabelFormat.prefixEnabled = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접두사').option('value');
							self.Pie.LabelPrefixEnabled = pieLabelFormat.prefixEnabled;
							pieLabelFormat.prefixFormat = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('value');
							self.Pie.LabelPrefixFormat = pieLabelFormat.prefixFormat;
							pieLabelFormat.suffixEnabled = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접미사').option('value');
                            self.Pie.LabelSuffixEnabled = pieLabelFormat.suffixEnabled;
							pieLabelFormat.suffix.O = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('value');
							pieLabelFormat.suffix.K = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('value');
							pieLabelFormat.suffix.M = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('value');
							pieLabelFormat.suffix.B = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('value');
							self.Pie.LabelSuffix = pieLabelFormat.suffix;
							pieLabelFormat.precision = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도').option('value');
                            self.Pie.LabelPrecision = pieLabelFormat.precision;
                            pieLabelFormat.precisionOption = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도 옵션').option('value');
                            self.Pie.LabelPrecisionOption = pieLabelFormat.precisionOption;
                            // create new custom label format
                            self.dxItem.forEach(function(item) {
								item.option('series[0].label.customizeText', function(pointInfo) {
									 return self.PCU.Series.Label.getLabelFormat(pointInfo, pieLabelFormat);
								});
                            });
                            p.hide();
						});
						contentElement.find('#close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			//20210122 AJKIM 파이 범례 추가
			case 'editLegend': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
                    target: '#editLegend',
					contentTemplate: function(contentElement) {
							$(	'<div id="' + self.itemid + '_toggleLegend" style="width:130px;"></div>' +
								'<div style="height: auto; width: 150px;">' +
									'<ul class="add-item-body icon-radio-list" style="display:block;">'+ 
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
								self.Pie.Legend.Visible = !self.Pie.Legend.Visible;
								self.dxItem.forEach(function(item) {
									item.option('legend.visible', self.Pie.Legend.Visible);
	                            });
							}
                        });
                        
						$.each($('.select-position'), function(index, position) {
							if (self.Pie.Legend.Position === $(position).data('description')) {
								$(position).addClass('on');
								return false;
							}
						});
						
						$('.select-position').off('click').on('click', function(e) {
                            $('.select-position.on').removeClass('on');
							$(this).addClass('on');
							var newDescription = $(this).data('description');
							self.Pie.Legend.Position = newDescription;
							var newLegend = self.getLegend(newDescription);
                            
                            self.dxItem.forEach(function(item) {
								item.option('legend', newLegend);
                            });
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			}
			// edit label location
			case 'labelLocation': {
				if (!(self.dxItem)) {
					break;
				}
				var mapping = {
					컬럼: 'columns',
					내부: 'inside',
					외부: 'outside',
					columns: 'Columns',
					inside: 'Inside',
					outside: 'Outside',
					Columns: '컬럼',
					Inside: '내부',
					Outside: '외부'
				};
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#labelLocation',
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_labelLocation">');
						$('#' + self.itemid + '_labelLocation').dxRadioGroup({
							width: '60px',
							dataSource: ['컬럼', '내부', '외부'],
							value: mapping[self.Pie.LabelPosition],
							onValueChanged: function(e) {
								self.dxItem.forEach(function(item) {
									var position = mapping[e.value];
									self.Pie.LabelPosition = mapping[position];
									item.option('series[0].label.position', position);
								});
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			}
			// edit tooltip value measure, precision and suffix
			case 'editTooltip': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				var mapping = {
					'없음': 'None',
					'인수': 'Argument',
					'값': 'Value',
					'%': 'Percent',
					'인수 및 값': 'ArgumentAndValue',
					'값 및 %': 'ValueAndPercent',
					'인수 및 %': 'ArgumentAndPercent',
					'인수, 값 및 %': 'ArgumentValueAndPercent',
					None: '없음',
					Argument: '인수',
					Value: '값',
					Percent: '%',
					ArgumentAndValue: '인수 및 값',
					ValueAndPercent: '값 및 %',
					ArgumentAndPercent: '인수 및 %',
					ArgumentValueAndPercent: '인수, 값 및 %',
					Auto: 'A',
					Ones: 'O',
					Thousands: 'K',
					Millions: 'M',
					Billions: 'B',
					A: 'Auto',
					O: 'Ones',
					K: 'Thousands',
					M: 'Millions',
					B: 'Billions'
				};
				p.option({
					title: '툴팁 편집',
					contentTemplate: function(contentElement) {
                        contentElement.append('<div id="' + self.itemid + '_tooltipForm">');
                        var html = 	'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
                        contentElement.append(html);
                        
						$('#' + self.itemid + '_tooltipForm').dxForm({
							dataSource: {
								'표기 형식': mapping[pieTooltipFormat.type],
								'단위': pieTooltipFormat.format,
								'사용자 지정 접두사': pieTooltipFormat.prefixEnabled,
								'접두사': pieTooltipFormat.prefixFormat,
								'사용자 지정 접미사': pieTooltipFormat.suffixEnabled,
								O: pieTooltipFormat.suffix.O,
								K: pieTooltipFormat.suffix.K,
								M: pieTooltipFormat.suffix.M,
								B: pieTooltipFormat.suffix.B,
								'정도': pieTooltipFormat.precision,
								'정도 옵션': pieTooltipFormat.precisionOption,
							},
							items: [
								{
									dataField: '표기 형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										dataSource: ['없음', '인수', '값', '%', '인수 및 값', 
											 '값 및 %', '인수 및 %', '인수, 값 및 %'],
										value: mapping[pieTooltipFormat.type],
										onValueChanged: function(e) {
											if (e.value === '값' || e.value === '인수 및 값' || e.value === '값 및 %' || e.value === '인수, 값 및 %') {
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('단위').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접두사').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접미사').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('disabled', false);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도').option('disabled', false);
											} else {
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('단위').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접두사').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접미사').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('disabled', true);
												$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도').option('disabled', true);
											}
										}
									}
								},
								{
										dataField: '단위',
										editorType: 'dxSelectBox',
										editorOptions: {
											dataSource: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
											layout: 'horizontal',
											value: mapping[pieTooltipFormat.format],
											onInitialized: function(e) {
												var formatType = mapping[pieTooltipFormat.type];
												if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
													e.component.option('disabled', false);
												} else {
													e.component.option('disabled', true);
												}
											}
										}
								},
								{
									dataField: '사용자 지정 접두사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: pieTooltipFormat.prefixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[pieTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										},
										onValueChanged: function(e) {
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: '접두사',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieTooltipFormat.prefixFormat,
										onInitialized: function(e) {
											var formatType = mapping[pieTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '사용자 지정 접미사',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: pieTooltipFormat.suffixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[pieTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										},
										onValueChanged: function(e) {
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('disabled', !e.value);
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('disabled', !e.value);
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('disabled', !e.value);
											$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('disabled', !e.value);
										}
									}
								},
								{
									dataField: 'O',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieTooltipFormat.suffix.O,
										onInitialized: function(e) {
											var formatType = mapping[pieTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'K',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieTooltipFormat.suffix.K,
										onInitialized: function(e) {
											var formatType = mapping[pieTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'M',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieTooltipFormat.suffix.M,
										onInitialized: function(e) {
											var formatType = mapping[pieTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: 'B',
									editorType: 'dxTextBox',
									editorOptions: {
										value: pieTooltipFormat.suffix.B,
										onInitialized: function(e) {
											var formatType = mapping[pieTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
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
										showSpinButtons: true,
										value: pieTooltipFormat.precision,
										onInitialized: function(e) {
											var formatType = mapping[pieTooltipFormat.type];
											if (formatType === '값' || formatType === '인수 및 값' || formatType === '값 및 %' || formatType === '인수, 값 및 %') {
												e.component.option('disabled', false);
											} else {
												e.component.option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '정도 옵션',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: ['반올림', '올림', '버림'],
										value: typeof pieTooltipFormat.precisionOption !== 'undefined' ? pieTooltipFormat.precisionOption : "반올림",
									}
								},
							]
                        });
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            // save tooltip settings
                            pieTooltipFormat.type = mapping[$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('표기 형식').option('value')];
							self.Pie.TooltipContentType = pieTooltipFormat.type;
                            pieTooltipFormat.format = mapping[$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('단위').option('value')];
							self.Pie.TooltipMeasureFormat = pieTooltipFormat.format;
							pieTooltipFormat.prefixEnabled = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접두사').option('value');
							self.Pie.TooltipPrefixEnabled = pieTooltipFormat.prefixEnabled;
							pieTooltipFormat.prefixFormat = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('value');
							self.Pie.TooltipPrefixFormat = pieTooltipFormat.prefixFormat;
							pieTooltipFormat.suffixEnabled = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접미사').option('value');
                            self.Pie.TooltipSuffixEnabled = pieTooltipFormat.suffixEnabled;
							pieTooltipFormat.suffix.O = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('value');
							pieTooltipFormat.suffix.K = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('value');
							pieTooltipFormat.suffix.M = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('value');
							pieTooltipFormat.suffix.B = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('value');
							self.Pie.TooltipSuffix = pieTooltipFormat.suffix;
							pieTooltipFormat.precision = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도').option('value');
                            self.Pie.TooltipPrecision = pieTooltipFormat.precision;
                            pieTooltipFormat.precisionOption = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도 옵션').option('value');
                            self.Pie.TooltipPrecisionOption = pieTooltipFormat.precisionOption;
                            // create new custom label format
                            self.dxItem.forEach(function(item) {
								item.option('tooltip.customizeTooltip', function(_pointInfo) {
									 return { text: self.PCU.Tooltip.getTooltipFormat(_pointInfo, pieTooltipFormat) };
								});
                            });
                            p.hide();
						});
						contentElement.find('#close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			// edit pie style
			case 'editStyle': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#editStyle',
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_labelStyle">');
						$('#' + self.itemid + '_labelStyle').dxRadioGroup({
							dataSource: ['pie', 'donut'],
							value: self.Pie.PieType == undefined ? 'pie' : self.Pie.PieType.toLowerCase(),
							onValueChanged: function(e) {
								self.Pie.PieType = e.value === 'pie' ? 'Pie' : 'Donut';
								self.dxItem.forEach(function(item) {
									item.option('series[0].type', e.value);
								});
							}
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
				}
				// popup configs
				var p = $('#editPopover').dxPopover('instance');
				var chagePalette = self.Pie.Palette;
				p.option({
                    target: '#editPalette',
                    onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // palette select
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
                        var originalPalette = paletteCollection.indexOf(self.Pie.Palette) != -1
										? self.Pie.Palette
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
                                var itemPalette = data === 'Custom'
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
                                    self.dxItem.forEach(function(item) {
						                item.option('palette', self.customPalette);
					                });
								} else {
                                    self.isCustomPalette = false;
                                    self.dxItem.forEach(function(item) {
						                item.option('palette', paletteObject2[e.value]);
					                });
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        contentElement.find('#save-ok').on('click', function() {
                            self.Pie.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            p.option('visible', false);
                        });
                        contentElement.find('#save-cancel').on('click', function() {
                            self.dxItem.forEach(function(item) {
                                item.option('palette', self.Pie.Palette);
                            });
                            chagePalette = self.Pie.Palette;
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.Pie.Palette = chagePalette;
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
						self.dxItem[0].getSeriesByPos(0).getAllPoints().forEach(function(item, index) {
							colorContainer.append('<p>Point ' + index
													+ '</p><div id="' + self.itemid + '_pointColor' + index + '">');
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
                        
						self.dxItem[0].getSeriesByPos(0).getAllPoints().forEach(function(item, index) {
							$('#' + self.itemid + '_pointColor' + index).dxColorBox({
								value: item.getColor()
							});
                        });

                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            var newPalette = [];

                            self.dxItem[0].getSeriesByPos(0).getAllPoints().forEach(function(item, index) {
                                newPalette[index] = $('#' + self.itemid + '_pointColor' + index).dxColorBox('instance').option('value');
                            });
                            self.Pie.Palette = newPalette;
                            self.dxItem.forEach(function(pie, pieIndex) {
                                self.dxItem[pieIndex].option('palette', newPalette);
                            });
                            self.customPalette = newPalette;
                            self.isCustomPalette = true;
                            p.hide();
						});
						contentElement.find('#close').on('click', function() {
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
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_editAnimation">');
						$('#' + self.itemid + '_editAnimation').dxRadioGroup({
							dataSource: ['없음', '입방', '선형'],
                            value: mapping[self.Pie.Animation],
                            width: 70,
							onValueChanged: function(e) {
								self.Pie.Animation = mapping[e.value];
								self.dxItem.forEach(function(item) {
									if (e.value === 'none') {
										item.option('animation.enabled', false);
									} else {
										item.option({
											animation: {
												enabled: true,
												easing: mapping[e.value]
											}
										});
                                    }
                                });
                                self.bindData(self.globalData, true);
                                gProgressbar.hide();
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

WISE.libs.Dashboard.item.PieGenerator.PanelManager = function() {
	var self = this;
	
	this.itemid; // pie chart item id, chartItem
	//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
	this.dataSourceId;
	this.valuePanel = {};
	this.pieContainerIdBucket = [];
	this.pieCount;
	
	this.dxConfig = {
		dataSource: []
	};
	this.rawData;
	this.values;
	this.arguments;
	this.seriesDimensions;
	
	//2020-01-14 LSH topN 시리즈 변수
	this.topN;
	this.topItem;
	this.topNT;
	this.OtherCnt;
	this.otherShow;
	this.TopNMember;
	this.topNEnabeled = false;
	this.topMesure;
    this.dimensionTopN = new Array();

	this.groupByData;
	this.itemPanelMinSize = 325;
	
	this.init = function() {
		$("#" + this.itemid).empty();
		this.valuePanel = {}; 
		this.pieContainerIdBucket = [];
//		gConsole.info('[WisePie] panelManager initialized');
	};
	
	this.resize = function() {
		if (typeof this.pieContainers !== 'undefined') {
			var size = self.__calcPiePanelSize(self.pieCount || this.pieContainers.length);
			$.each(this.pieContainers, function(_i, _e) {
				_e.container
					.css('width',size.w)
					.css('height',size.h)
					.css('display','inline-block');

				_e.container.dxPieChart('instance').render();
			});
		}
	};
	
	this.__createSingleContainerTo = function() {
		var ww = $('#'+this.itemid).width();
		var hh = $('#'+this.itemid).height();
		var size = {w:ww,h:hh};
		
		var valuePanelId = this.itemid + '_' + new Date().valueOf();
		var $valuePanel, $pieContainer;
		$pieContainer = $valuePanel = $('<div id="' + valuePanelId + '" class="dx-item-pie-panel active" style="width: ' + size.w + 'px; height: ' + size.h + 'px;"></div>');
		
		$pieContainer.dxPieChart(this.dxConfig);
		
		$('#'+this.itemid).append($pieContainer);
		
		var pieContainers = [{title:'SINGLE_VALUE_TITLE', container:$pieContainer}];
		this.valuePanel[valuePanelId] = {
			panel: $valuePanel
		};
		
		this.pieContainers = pieContainers;
		
		this.pieContainerIdBucket.push(valuePanelId);
	};
	this.__createMultiPieContainerTo = function(_valuePanelId, _pieValues, _pieSize, _valueColumns) {
		var $valuePanel = $('<div id="' + _valuePanelId + '" class="dx-item-pie-panel active"></div>');
		$('#'+this.itemid).append($valuePanel);
		
		var $ul = $('<ul class="ul-panel" />');
		$valuePanel.append($ul);
		
		if (!_valueColumns) {
			var pieContainers = [];
			for (var index = 0 ; index < _pieValues.length; index++) {
				var pieContainerId = _valuePanelId + '_' + index;
				var $pieContainer = $('<li id="' + pieContainerId + '" class="child-panel" style="width: ' + _pieSize.w + 'px; height: ' + _pieSize.h + 'px;"></li>');
				$ul.append($pieContainer);
				
				var pieTitle;
				switch(this.renderType) {
				case 'VALUES-AND-SERIESDIMENSIONS':
					var nameBasket = [];
					$.each(_pieValues[index],function(_k,_t) {
						nameBasket.push(_t);
					});
					pieTitle = nameBasket.join('-');
					break;
				default:
	//				pieTitle = _pieValues[index].captionBySummaryType;
					pieTitle = _pieValues[index].rawCaption;
				}
				pieContainers.push({title:pieTitle, container: $pieContainer});
				$pieContainer.dxPieChart(this.dxConfig);
				this.pieContainerIdBucket.push(pieContainerId);
			}
		} else {
			var pieContainers = [];
			for (var index = 0 ; index < _pieValues.length; index++) {
				for (var vIndex = 0; vIndex < _valueColumns.length; vIndex++) {
					var pieContainerId = _valuePanelId + '_' + (vIndex + _valueColumns.length * index);
					var $pieContainer = $('<li id="' + pieContainerId + '" class="child-panel" style="width: ' + _pieSize.w + 'px; height: ' + _pieSize.h + 'px;"></li>');
					$ul.append($pieContainer);
					
					var pieTitle;
					var nameBasket = [];
					$.each(_pieValues[index],function(_k,_t) {
						nameBasket.push(_t);
					});
//					pieTitle = nameBasket.join('-') + '-' + _valueColumns[vIndex].captionBySummaryType;
					pieTitle = nameBasket.join('-') + '-' + _valueColumns[vIndex].caption;
					
					pieContainers.push({title:pieTitle, container: $pieContainer, uniqueName: nameBasket.join('-') + '-' + _valueColumns[vIndex].uniqueName});
					$pieContainer.dxPieChart(this.dxConfig);
					this.pieContainerIdBucket.push(pieContainerId);
				}	
			}
			$.each(_valueColumns, function(valColIndex, _valueColumn) {
				self.valuePanel[self.itemid + '_' + _valueColumn.uniqueName] = {
					id: _valueColumn ? _valueColumn.nameBySummaryType : undefined,
					panel: $valuePanel,
					title: $.type(_valueColumn) === 'object' ? _valueColumn.caption : undefined
				};
			})
		}
		
		this.pieContainers = pieContainers;
		
//		if (this.renderType === 'VALUES-AND-ARGUMENTS-AND-SERIESDIMENSIONS') {
//			$valuePanel.removeClass('active').addClass('in-active');
//		}
	};
	this.__calcPiePanelSize = function(_pieCount) {
		var ww = $('#'+this.itemid).width();
		var hh = $('#'+this.itemid).height();
        var itemPanelHeightSize, itemPanelWidthSize;
        
        if (ww < self.itemPanelMinSize) {
            itemPanelWidthSize = ww - 4; // padding-height, bottom : 2px
        }
        else {
            var _i = 0, itemPanelWidthSizeCountTimes;
            for (_i = 0; _i < _pieCount; _i++) {
            	itemPanelWidthSizeCountTimes = self.itemPanelMinSize * (_i+1);
            	if (ww < itemPanelWidthSizeCountTimes) {
            		break;
            	}
            }
            
            var pieCountForRow = _pieCount < (_i+1) ? _pieCount : (_i+1);
            
            itemPanelWidthSize = parseInt(ww / pieCountForRow, 10);
            itemPanelWidthSize = itemPanelWidthSize - 15; // 15: scroll width
        }
        
        if (hh < self.itemPanelMinSize) {
        	itemPanelHeightSize = hh - 4;  // padding-right, left : 2px
        }
        else {
        	itemPanelHeightSize = itemPanelWidthSize;
        }
        
        if (itemPanelHeightSize > self.itemPanelMinSize) {
        	itemPanelHeightSize = hh - 4;  // padding-right, left : 2px
        }
        
        return {w: itemPanelWidthSize, h: itemPanelHeightSize};
	};
	this.__getSeriesDimensionGroupByData = function() {
		//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		var columns = _.map(this.seriesDimensions, 'name');
		var columnsOrder = _.map(this.seriesDimensions, 'sortOrder');
		
		/* 2020-01-14 LSH topN 시리즈 정렬 */
		for(var i = 0; i < this.seriesDimensions.length; i++){
			if(this.seriesDimensions[i].TopNEnabled){
				self.topNEnabeled = true;
			}
			/*dogfoot 파이차트 TopN 차원그룹 오류 수정 shlim 20200629*/
			self.dimensionTopN.push(this.seriesDimensions[i]);
		}
		
		var Order = [];
		var Select = [];
		/*Sort By 추가해야할 부분*/
		var measures = [];
		measures = measures.concat(self.values);
		measures = measures.concat(self.HiddenMeasures);
		
		/* LSH topN */
		if(self.topNEnabeled){
		/*dogfoot 파이차트 TopN 차원그룹 오류 수정 shlim 20200629*/
            
            if(typeof self.arguments != 'undefined' && self.arguments.length > 0){
				for(var i=0; i < self.arguments.length; i++){
					self.dimensionTopN.push(self.arguments[i]);
				}
			}
			//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
			/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
			var queryDataConfig = SQLikeUtil.fromJson(self.dimensionTopN, this.values, this.rawData, undefined, undefined, self.orderKey);
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			var queryData = SQLikeUtil.doSqlLike(this.dataSourceId, queryDataConfig, self);
//			var queryData = WISE.libs.Dashboard.Query.likeSql.fromJson(this.seriesDimensions, this.values, this.rawData);
			var first=[];
			first.push({items:queryData});
			queryData = first;

			

			//차원이 여러개일때 topN기능이 걸린 차원의 위치를 찾기위한 싸이클
			for(var i = 0; i < self.dimensionTopN.length; i++){
				queryData = this.__getTopNData(queryData,self.dimensionTopN,self.dimensionTopN[i].name,self.dimensionTopN[i].TopNEnabled);
			}
			
			for(var i = 0; i < self.dimensionTopN.length; i++){
				queryData = this.__getTopNsortData(queryData,self.dimensionTopN,self.dimensionTopN[i].name);
			}
			
			var topNarray=[];
			$.each(queryData,function(_i,_e){
				$.each(_e.items,function(_j,_k){
					topNarray.push(_k); 
				}) 
			})

			this.rawData = topNarray;
		}
		
		$.each(this.seriesDimensions,function(_i,_e){
			if(_e.sortByMeasure != undefined){
				$.each(measures,function(_j,_mea){
					if(_mea.name === _e.sortByMeasure){
						Select.push('|' + _mea.summaryType + '|');
						Select.push(_mea.name);
						/*dogfoot syjin 파이차트 차원 그룹 select 절 Alias 추가 20211228*/
						Select.push('|as|');
						Select.push(_mea.captionBySummaryType);
						Order.push(_mea.nameBySummaryType);
						Order.push('|' + _e.sortOrder + '|');
					}
				});
			}
		});
		
		for(var i=0;i<columns.length; i++){
			Order.push(columns[i]);
			Order.push('|' + columnsOrder[i] + '|');
		}
		
		Select = Select.concat(columns);
		/*dogfoot 파이차트 차원그룹 표기 오류 마스터필터 조건 추가 shlim 20200717*/
		var Where = gDashboard.itemGenerateManager.sqlConfigWhere;
		//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
		var tempByDataConfig = {
			'Select': Select,
			'From': this.rawData,
			'GroupBy': columns,
			'OrderBy':Order,
			'Where':Where
		}
//		//2020.02.04 mksong SQLLIKE doSqlLike 파이 적용 dogfoot
//		var tempByDataConfig = {
//			'Select': Select,
//			'From': this.rawData,
//			'GroupBy': columns,
//			'OrderBy':Order
//		}
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		var tempByData = SQLikeUtil.doSqlLike(this.dataSourceId, tempByDataConfig, self);
		
		var groupByData = SQLike.q({
			'Select': columns,
			'From': tempByData
		});
		/*dogfoot 파이차트 TopN 차원그룹 오류 수정 shlim 20200629*/
		if(self.topNEnabeled){
			groupByData = SQLike.q({
			'Select': columns,
			'From': this.rawData,
			'GroupBy': columns
	    	});
		}
		
		return groupByData;
	};
	
	this.makePanel = function(_options) {
		if(_options)
		    self.pieCount = _options
		    
		if (this.renderType === 'VALUES-ONLY') {
			this.__createSingleContainerTo();
		}
		else if (this.renderType === 'SINGLE_VALUES-AND-ARGUMENTS') {
			this.__createSingleContainerTo();
		}
		else if (this.renderType === 'MULTI_VALUES-AND-ARGUMENTS') {
			var size = this.__calcPiePanelSize(_options);
			this.__createMultiPieContainerTo(this.itemid, this.values, size);
		}
		else if (this.renderType === 'VALUES-AND-SERIESDIMENSIONS') {
			this.groupByData = this.__getSeriesDimensionGroupByData();
			var size = this.__calcPiePanelSize(_options);
			this.__createMultiPieContainerTo(this.itemid, this.groupByData, size);
		}
		else if (this.renderType === 'VALUES-AND-ARGUMENTS-AND-SERIESDIMENSIONS') {
			this.groupByData = this.__getSeriesDimensionGroupByData();
			var size = this.__calcPiePanelSize(_options);
			var itemID = this.itemid;
			self.__createMultiPieContainerTo(itemID, self.groupByData, size, this.values);
		}
		else {

			this.__createSingleContainerTo();
		}
	};
	
	this.activeValuePanel = function(_activePanelId) {
		$.each(this.valuePanel, function(_k, _vp) {
			_vp.panel.removeClass('active');
			_vp.panel.addClass('in-active');
		});
		
		var activePanelSeq = 0; // for zoop popup
		$.each(this.valuePanel, function(_k, _vp) {
				
			if (_k === _activePanelId) { 
				_vp.panel.removeClass('in-active');
				_vp.panel.addClass('active');
				
				if (_.keys(self.valuePanel).length > 1) {
					if (!self.initTitleNm) {
						self.initTitleNm = $('#' + self.itemid + '_title').text();
					}
					var title = self.initTitleNm + ' - ' + _vp.title;
					$('#' + self.itemid + '_title').text(title);
				}
				
				self.activePanelId = _activePanelId;
				self.activePanelSeq = activePanelSeq;
				
				return false;
			} else {
				activePanelSeq++;
			}
			
		});
	};
	
	/* LSH topN
	 *  topN정렬을 위한 함수
	 * */
	 this.__getTopNsortData = function(queryData,dimensions,nowDim){
		var topnData = [];
		var topNarray = [];
		var sumNm;
		//topN순위 기준 측정값 계산
		var sumNm;
		$.each(self.values,function(_index,_item){
			if(_item.uniqueName == self.topMesure){
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
	
	//2020-01-14 LSH topN
	this.__getTopNData = function(queryData,dimensions,nowDim,_topEnabled){
		
		//넘어온 차원의 topN 유무
		var topBol = false;
		if(_topEnabled){
			topBol = true;
			/*dogfoot 파이차트 TopN 차원그룹 오류 수정 shlim 20200629*/
			for(var i = 0; i < self.dimensionTopN.length; i++){
				if(self.dimensionTopN[i].TopNEnabled===true && self.dimensionTopN[i].name == nowDim){
					if(self.dimensionTopN[i].TopNCount > 0){
						self.topN = self.dimensionTopN[i].TopNCount;
						self.TopNMember = self.dimensionTopN[i].name;
					}else{
						self.topN = 5;
						self.TopNMember = self.dimensionTopN[i].name;
					}
					self.topMesure = self.dimensionTopN[i].TopNMeasure;
					self.otherShow = self.dimensionTopN[i].TopNShowOthers;
				}
			}
		}
		
		//topN순위 기준 측정값 계산
		var sumNm;
		$.each(self.values,function(_index,_item){
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
		
		//넘어온 차원이 차원그룹이고 차원그룹이 topN이 아닐경우 현재 함수를 넘김 
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
					

				}else{
					// 넘어온 차원값이 topN 이 아닐경우 데이터 그룹화
					var ExecSyx = DevExpress.data.query(_e.items);
					ExecSyx = ExecSyx.groupBy(nowDim);
					topNarray = ExecSyx.toArray();
					$.each(topNarray, function(i, e) {
						topnData.push(e);
					});	
				}
						
			})
		
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
};

WISE.libs.Dashboard.PieFieldManager = function() {
	var self = this;
	
	this.initialized = false;
	this.alreadyFindOutMeta = false;
	
	//검색 - searchDisable
	this.searchDisable = false;
	//검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	//검색
	
	this.dataItemNo=0;
	
	this.meta;
	this.isChange = false; // 사용자가 필드를 변경했는지 여부 체크
	this.columnMeta = {}; // 쿼리된 모든 컬럼정보 저장
	this.isColumnChooser = false;
	
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
		
		this.initialized = true;
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
//			var listType = $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'pieValueList' ? true : false;
			var listType = $(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'pieValueList' || 
			$(_fieldlist[i]).attr('prev-container').substr(0,$(_fieldlist[i]).attr('prev-container').lastIndexOf('t')+1) == 'pie_hide_measure_list' ? true : false;
//			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
			if(!listType){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
//				dataItem['DataMember'] = $(_fieldlist[i]).children().get(0).innerText; 
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['UNI_NM'] = $(_fieldlist[i]).attr('uni_nm');
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				// 2020-01-14 LSH topN 필드 설정 값 가져오기
				if($(_fieldlist[i]).attr('TopNEnabled')=="true"){
					dataItem['TopNEnabled'] = ($(_fieldlist[i]).attr('TopNEnabled')==='true');
					dataItem['TopNOrder'] = ($(_fieldlist[i]).attr('TopNOrder')==='true');
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
//				dataItem['DataMember'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['UNI_NM'] = $(_fieldlist[i]).attr('uni_nm');
				dataItem['NumericFormat'] = NumericFormat;
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};
	
	this.setValuesByField = function(_values){
		this.Values = {'Value' : []};
		_.each(_values,function(_v){
			var Value = {'UniqueName' : _v.uniqueName};
			self.Values['Value'].push(Value);
		});
		return self.Values;
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
