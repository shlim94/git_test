WISE.libs.Dashboard.item.PyramidChartGenerator = function() {
	var self = this;

	this.type = 'PYRAMID_CHART';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	this.trackingData = [];
	
	var dataMember;
	var Exprname;
	var FilterArray = [];

	this.PyramidChart = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	
	//팔레트 
	this.customPalette = [];
	this.isCustomPalette = false;
	
	var chartLabelFormat = [];
	var chartTooltipFormat = [];
	/**
	 * @param _item:
	 *            meta object
	 */
	var CheckCurrentFilter;
	this.getDxItemConfig = function(_item) {
		var confMeasure = _item['DataItems']['Measure'];

		var count = 0;

//		D = _item.FilterDimensions ? WISE.util.Object
//		.toArray(_item.DataItems.Dimension) : [];

		this.DU = WISE.libs.Dashboard.item.DataUtility;

		this.DI = _item.DataItems;
		this.V = WISE.util.Object.toArray((_item.Values && _item.Values.Value) || []);
		this.A = WISE.util.Object.toArray((_item.Arguments && _item.Arguments.Argument) || []);

		this.measures = [];
		$.each(this.V, function(_i0, _a0) {
			var uniqueName = _a0['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			self.measures.push(dataMember);
		});
		this.dimensions = [];
		$.each(this.A, function(_i0, _a0) {
			var uniqueName = _a0['UniqueName'];
			var dataMember = self.DU.getDataMember(uniqueName, self.DI);
			self.dimensions.push(dataMember);
		});
		
		var measureKey = this.measures[0];
		if(!self.currentMeasureName || self.currentMeasureName === "")
			self.currentMeasureName = measureKey.caption;
		
		// 필드 속성에서 format 적용하는 기능 주석
//		var Number = WISE.util.Number,
//		labelFormat = 'Number',
//		labelUnit = 'O',
//		labelPrecision = 0,
//		labelSeparator = true,
//		labelSuffixEnabled = false,
//		labelSuffix = {
//			O: '',
//			K: '천',
//			M: '백만',
//			B: '십억'
//		};
//    	if(typeof(confMeasure.NumericFormat) == 'object') {
//    		if(confMeasure.NumericFormat.FormatType)
//    			labelFormat = confMeasure.NumericFormat.FormatType;
//    		if(confMeasure.NumericFormat.Precision)
//    			labelPrecision = confMeasure.NumericFormat.Precision;
//    		if(confMeasure.NumericFormat.Unit)
//    			labelUnit = confMeasure.NumericFormat.Unit;
//    		if(typeof confMeasure.NumericFormat.IncludeGroupSeparator !== 'undefined')
//    			labelSeparator = confMeasure.NumericFormat.IncludeGroupSeparator;
//    		if(typeof confMeasure.NumericFormat.SuffixEnabled !== 'undefined')
//    			labelSuffixEnabled = confMeasure.NumericFormat.SuffixEnabled;
//    		if(confMeasure.NumericFormat.Suffix)
//    			labelSuffix = confMeasure.NumericFormat.Suffix;
//		/* 나중에 비정형일 때 포맷 변경해야하는 부분*/
//		} else {
//    		if (_item.DataItems.Measure.length == 1) {
//    			if(_item.DataItems.Measure[0].NumericFormat != undefined){
//					labelFormat = typeof _item.DataItems.Measure[0].NumericFormat.FormatType == 'undefined' ? labelFormat : _item.DataItems.Measure[0].NumericFormat.FormatType;
//					labelUnit = typeof _item.DataItems.Measure[0].NumericFormat.Unit == 'undefined'? labelUnit : _item.DataItems.Measure[0].NumericFormat.Unit;
//					labelPrecision = typeof _item.DataItems.Measure[0].NumericFormat.Precision == 'undefined' ? labelPrecision : _item.DataItems.Measure[0].NumericFormat.Precision;
//					labelSeparator = typeof _item.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator == 'undefined' ? labelSeparator : _item.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator;
//					labelSuffixEnabled = typeof _item.DataItems.Measure[0].NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : _item.DataItems.Measure[0].NumericFormat.SuffixEnabled;
//					labelSuffix = typeof _item.DataItems.Measure[0].NumericFormat.Suffix == 'undefined' ? labelSuffix : _item.DataItems.Measure[0].NumericFormat.Suffix;
//				}
//    		} else {
//				$.each(_item.DataItems.Measure, function(i,k) {
//					if (self.currentMeasureName===k.Name) {
//						labelFormat = typeof k.NumericFormat.FormatType == 'undefined' ? '' : k.NumericFormat.FormatType;
//						labelUnit = typeof k.NumericFormat.Unit == 'undefined'? undefined : k.NumericFormat.Unit.substring(0,1);
//						labelPrecision = typeof k.NumericFormat.Precision == 'undefined' ? 2 : k.NumericFormat.Precision;
//						labelSeparator = typeof k.NumericFormat.IncludeGroupSeparator == 'undefined' ? true : k.NumericFormat.IncludeGroupSeparator;
//						labelSuffixEnabled = typeof k.NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : k.NumericFormat.SuffixEnabled;
//						labelSuffix = typeof k.NumericFormat.Suffix == 'undefined' ? labelSuffix : k.NumericFormat.Suffix;
//						return false;
//					}
//				});
//    		}
//    	}
		
		chartLabelFormat = {
				type: _item['LabelContentType'],
				format: _item['LabelMeasureFormat'], 
				prefixEnabled: _item['LabelPrefixEnabled'],
				prefixFormat: _item['LabelPrefixFormat'],
				suffixEnabled: _item['LabelSuffixEnabled'],
				suffix: _item['LabelSuffix'],
				precision: _item['LabelPrecision'],
				precisionOption: _item['LabelPrecisionOption'],
			};
	    	
			chartTooltipFormat = {
				type: _item['TooltipContentType'], 
				format: _item['TooltipMeasureFormat'],
				prefixEnabled: _item['TooltipPrefixEnabled'],
				prefixFormat: _item['TooltipPrefixFormat'],
				suffixEnabled: _item['TooltipSuffixEnabled'], 
				suffix: _item['TooltipSuffix'],
				precision: _item['TooltipPrecision'],
				precisionOption: _item['TooltipPrecisionOption'],
			};
    	
    	var measureKey = this.measures[0];
    	var measureCheck = false;
    	$.each(this.measures, function(i, mea){
    		if(self.currentMeasureName === mea.caption){
    			measureCheck = true;
    			return false;
    		}
    	})
		if(!self.currentMeasureName || self.currentMeasureName === "" || !measureCheck)
			self.currentMeasureName = measureKey.caption;
		
		var dxConfigs = {
				dataStructure: 'plain',
				allowExpandAll: true,
				allowFiltering: true,
				allowSorting: true,
				allowSortingBySummary: true,
				argumentField: "name",
				valueField: "value",
				inverted: true,
				algorithm: "dynamicHeight",
				selectionMode: 'multiple',
				margin: {
		            top: 20,
		            bottom: 20,
		            left: 30,
		            right: 30
		        },
				tooltip: {
					enabled: _item['TooltipContentType'] === 'None' ? false : true,
					zIndex: 21,
					font:gDashboard.fontManager.getDxItemLabelFont(),
					customizeTooltip:function(_pointInfo){
//						var text = '<b>' + _pointInfo.item.argument + '</b>' + '<br/>' +"<b>" +self.currentMeasureName+"</b> : "
//						+ Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
//						ret = {html: text};
//						return ret;
						return {html: self.getTooltipFormat(_pointInfo)};
					}
				},
				label: {
		            visible: chartLabelFormat.type !== 'None',
		            position: self.PyramidChart.LabelPosition === "Inside"? 'inside' : self.PyramidChart.LabelPosition,
            		backgroundColor: "none",
		            font:{
		            	color : self.PyramidChart.LabelPosition === "Inside" || self.PyramidChart.LabelPosition === "inside"? "black": undefined,
		            },
    				customizeText: function(e) {
		            	return self.getLabelFormat(e);
//		            	return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>" +
//		                Number.unit(e.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) +
//		                    "</span><br/><span style='" + gDashboard.fontManager.getCustomFontStringForItem(12) + "'>" +
//		                    e.item.argument + "</span>";
		            }
		        },
		        legend: self.getLegend(_item.Legend.Position),
		        onItemClick: function(_e) {

		        	if (self.IO && self.IO['MasterFilterMode'] !== 'Off') {
						// do nothing if single master filter and selected point is selected
						if (self.IO.MasterFilterMode === 'Single' && _e.item.isSelected()) {
							return;
						}
						var dimensions, dimensionNames;
						// select and deselect points
						dimensions = self.arguments.slice();
						dimensionNames = _e.item.argument.split(',');
						for(var i=0; i<dimensionNames.length;i++){
							dimensionNames[i] = dimensionNames[i].replace(/\n/g, "");//행바꿈제거
							dimensionNames[i] = dimensionNames[i].replace(/\r/g, "");//엔터제거
						}
            			_e.item.select(!_e.item.isSelected());
						
		        		switch(self.IO['MasterFilterMode']){
				       		case 'Multiple':
				       			$.each(dimensions, function(_i, _ao) {
					       			var inArray = false;
					       			var selectedData = {};
					       			selectedData[_ao.name] = dimensionNames[0].split(' - ')[_i];
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
									self.selectedPoint.select(false);
				       			}
				       			self.selectedPoint = _e.item;
				       			self.trackingData = [];
				       			$.each(dimensions, function(_i, _ao) {
				       				var selectedData = {};
					       			selectedData[_ao.name] = dimensionNames[0].split(' - ')[_i];
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
		        	else if (self.IO['IsDrillDownEnabled']) {
		        		if(_e.item.argument.indexOf('-') != -1 && self.dimensions.length > 1){
		        			self.currentDimensionKey = self.dimensions[0].caption;
		        		}
		        		
		        		var data = _e.item.data;
		        		var dimensionValue = _e.item.data.name.split('-')[0].trim();
						var foundCurrentNode = false;
						var checkRightNeighbor = false;
						var isDrillDownValid = false;
						$.each(self.argumentOrder, function(i, _arg) {
							// if current cell's nearest right neighbor is a measure, abort drill-down process
							if (checkRightNeighbor && _arg.value !== 'number') {
								checkRightNeighbor = false;
								isDrillDownValid = true;
								self.nextDimensionKey = _arg.key;
							} 
							// found current cell's position
							else if (self.currentDimensionKey === _arg.key) {
								foundCurrentCell = true;
								checkRightNeighbor = true;
							}
						});
						// if current cell's right most neighbor is a dimension, then drill-down is valid
						if (isDrillDownValid) {
							self.drillDown(self.currentDimensionKey, dimensionValue, self.nextDimensionKey);
							self.currentDimensionKey = self.nextDimensionKey;
						}
		        	}
		        },
		        palette : _item['Palette']
		}
		
		if(self.currentMeasureName){
			dxConfigs.title = {text: self.currentMeasureName, margin: { bottom: 30 }, font: gDashboard.fontManager.getDxItemTitleFont()};
		}

		// extend custom-configurations
		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
		var CustomConfigs = $.extend({}, Configurations);
		$.extend(CustomConfigs, dxConfigs);
		dxConfigs = CustomConfigs;
		return dxConfigs;
	};
	
	this.getTooltipFormat = function(_pointInfo){
		var type = chartTooltipFormat.type,
		format = 'Number',
		unit = chartTooltipFormat.format,
		prefixEnabled = chartTooltipFormat.prefixEnabled,
		suffixEnabled = chartTooltipFormat.suffixEnabled,
		precision = chartTooltipFormat.precision,
		precisionOption = chartTooltipFormat.precisionOption,
		separator = true,
		prefix = '',
		suffix = chartTooltipFormat.suffix;
		if (prefixEnabled) {
			prefix = chartTooltipFormat.prefixFormat;
		}

		switch(type) {
			case 'None':
				return '';
			case 'Argument':
				return _pointInfo.item.argument;
			case 'Value': 
				return WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption);
			case 'Percent':
				return (_pointInfo.percent*100).toFixed(precision) + '%';
			case 'ArgumentAndValue': 
				return '<b>' + _pointInfo.item.argument + '</b>: '
					+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption);
			case 'ValueAndPercent': 
				return WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption)
					+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
			case 'ArgumentAndPercent':
				return  '<b>' + _pointInfo.item.argument + '</b>: (' 
					+ (_pointInfo.percent*100).toFixed(precision) + '%)';
			case 'ArgumentValueAndPercent':
				return '<b>' + _pointInfo.item.argument + '</b>: '
					+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption)
					+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
			default:
				return '<b>' + _pointInfo.item.argument + '</b>: '
					+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption)
					+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)';
		}
	}
	
	this.getLabelFormat = function(_pointInfo){
		var type = chartLabelFormat.type,
		format = 'Number',
		unit = chartLabelFormat.format,
		prefixEnabled = chartLabelFormat.prefixEnabled,
		suffixEnabled = chartLabelFormat.suffixEnabled,
		precision = chartLabelFormat.precision,
		precisionOption = chartLabelFormat.precisionOption,
		separator = true,
		prefix = '',
		suffix = chartLabelFormat.suffix;
		if (prefixEnabled) {
			prefix = chartLabelFormat.prefixFormat;
		}
	
		switch(type) {
			case 'None':
				if(self.dxItem.option('label.visible'))
					self.dxItem.option('label.visible', false);
				return ' ';
			case 'Argument':
				return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>" + _pointInfo.item.argument + "</span>";
			case 'Value':
				return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>" + 
				WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption) + "</span>";
				;
			case 'Percent':
				return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>" + (_pointInfo.percent*100).toFixed(precision) + '%</span>';
			case 'ArgumentAndValue':
				return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>"
				+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption) + "</span>"
				+ "<br/><span style='" + gDashboard.fontManager.getCustomFontStringForItem(12) + "'>" + _pointInfo.item.argument + "</span>";
			case 'ValueAndPercent':
				return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>" + 
				WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption)
					+ ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)</span>';
			case 'ArgumentAndPercent':
				return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>"  + (_pointInfo.percent*100).toFixed(precision) + '%</span></br>' +
				"<span style='" + gDashboard.fontManager.getCustomFontStringForItem(12) + "'>" + _pointInfo.item.argument + "</span>";
			case 'ArgumentValueAndPercent':
				return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>"
				+ WISE.util.Number.unit(_pointInfo.value, format, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption) + "</span>"
				+ "<br/><span style='" + gDashboard.fontManager.getCustomFontStringForItem(12) + "'>" + _pointInfo.item.argument + ' (' + (_pointInfo.percent*100).toFixed(precision) + '%)</span>';
					
			default:
				return "<span style='" + gDashboard.fontManager.getCustomFontStringForItem(17) + "'>"  + (_pointInfo.percent*100).toFixed(precision) + '%</span></br>' +
				"<span style='" + gDashboard.fontManager.getCustomFontStringForItem(12) + "'>" + _pointInfo.item.argument + "</span>";
		}
	}

	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if (self.dxItem) self.dxItem.clearSelection();
			self.trackingData = [];
			self.selectedPoint = undefined;	
		}
	};
	
	this.initDrillDownData = function(_data) {
		self.drillDownData = crossfilter(_data);
		self.drillDownStack = [];
	}

	/**
	 * Map & reduce drill-down data and apply it to the grid instance.
	 */
	this.setDrillDownData = function(_dimKey) {
		self.currentDimensionKey = _dimKey;
		
		var nonReducedData = self.drillDownData.allFiltered();
		var reducedData = _(nonReducedData).groupBy(_dimKey).map(function(objs, key) {
			var result = {};
			result[_dimKey] = key;
			self.reducibleMeasures.forEach(function(measureName) {
				result[measureName] = _.sumBy(objs, measureName);
			});
			return result;
		}).value();
		
		var reFormedData = self.reformDataSourceByValueArray(reducedData, _dimKey);
		
		var newDataSource = new DevExpress.data.DataSource({
			store: reFormedData,
			paginate: true
		});
		if(self.TreeMap && self.TreeMap.FilterString && self.TreeMap.FilterString.length > 0) {
			newDataSource.filter(self.PyramidChart.FilterString);
			newDataSource.load();
		}
		self.dxItem.option('dataSource', newDataSource);
	}

	/**
	 * Returns data results after drill-down operation of key _dimKey and value _dimValue.
	 */
	this.drillDown = function(_dimKey, _dimValue, _nextDimKey) {
		if (typeof _dimValue !== 'number') {
			var dimObj = self.drillDownData.dimension(_dimKey);
			if (dimObj != undefined) {
				dimObj.filterFunction(function(d) { return d === _dimValue; });
				self.drillDownStack.push({ name: _dimKey, dim: dimObj });
				self.setDrillDownData(_nextDimKey);
			}
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
				self.setDrillDownData(dimObj.name);
			}	
		}
	}

	/**
	 * Begin drill-down operations by hiding all dimension columns following the first.
	 */
	this.initDrillDownOperation = function() {
		// determine order of drill-down and measures to reduce
		self.argumentOrder = [];
		self.reducibleMeasures = [];
		$.each(self.filteredData[0], function(key, val) {
			var valType = typeof val;
			self.argumentOrder.push({ key: key, value: valType });
		});
		
		$.each(self.measures, function(_i, _measure){
			if(self.currentMeasureName == _measure.caption){
				self.reducibleMeasures.push(_measure.captionBySummaryType);
			}
		});
		
		self.setDrillDownData(self.dimensions[0].caption);
	}

	this.initDrillDownOperationForOpen = function() {
		self.argumentOrder = [];
		self.reducibleMeasures = [];
		$.each(self.filteredData[0], function(key, val) {
			var valType = typeof val;
			self.argumentOrder.push({ key: key, value: valType });
		});
		
		$.each(self.measures, function(_i, _measure){
			if(self.currentMeasureName == _measure.caption){
				self.reducibleMeasures.push(_measure.captionBySummaryType);
			}
		});
	};
	
	/**
	 * Stop drill-down operations by restoring data and columns to its' original state.
	 */
	this.terminateDrillDownOperation = function() {
		// configure settings to "false"
		self.PyramidChart.InteractivityOptions.IsDrillDownEnabled = false;
		self.IO.IsDrillDownEnabled = false;
		// reset data
		var resetData = self.drillDownData.all();
		self.initDrillDownData(resetData);
		var reformedData = self.reformDataSourceByData(resetData);
		var newDataSource = new DevExpress.data.DataSource({
			store: reformedData,
			paginate: true
		});
		if(self.PyramidChart && self.PyramidChart.FilterString && self.PyramidChart.FilterString.length > 0) {
			newDataSource.filter(self.PyramidChart.FilterString);
			newDataSource.load();
		}
		self.dxItem.option('dataSource', newDataSource);
	}

	/**
	 * Selects the first point of the first series in the chart. 
	 */
	this.selectFirstPoint = function() {
		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
		self.trackingData = [];
			var firstPoint = self.dxItem.getAllItems()[0],
			dimensions,
			dimensionNames;
		self.selectedPoint = firstPoint;
		dimensions = self.arguments.slice();
		dimensionNames = firstPoint.argument.split('<br/>');
		self.dxItem.clearSelection();
		firstPoint.select(true);
		$.each(dimensions, function(i, dim) {
			var selectedData = {};
			selectedData[dim.name] = dimensionNames[0].split(' - ')[i];
			self.trackingData.push(selectedData);
		});
		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
		gDashboard.filterData(self.itemid, self.trackingData);
	}
	
	this.reformDataSourceByData = function(_ValueArray){
		var Dimension = WISE.util.Object.toArray(this.meta.DataItems.Dimension);
		var measureKey = self.measures[0];
		$.each(self.measures, function(_i,_measure){
			if(_measure.name == self.currentMeasureName){
				mesureKey = _measure;
			}
		});
		
		var Measure =  WISE.util.Object.toArray(measureKey);
		
		var resultArr = new Array();
		$.each(_ValueArray,function(_i,_obj){
			var str = new Array();
			var object = new Object();
			$.each(Dimension,function(_i,_Dim){
				str.push(_obj[_Dim.DataMember]);
			});
			$.each(Measure,function(_i,_Mea){
				//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
				object['value'] = _obj[_Mea.captionBySummaryType];
			});
			
			object['name'] = str.join(' - ');
			resultArr.push(object);
		});
		
		return resultArr;
	}
	
	this.reformDataSourceByValueArray = function(_ValueArray, _dimKey){
		var Dimension = WISE.util.Object.toArray(this.meta.DataItems.Dimension);
		var measureKey = self.measures[0];
		$.each(self.measures, function(_i,_measure){
			if(_measure.caption == self.currentMeasureName){
				mesureKey = _measure;
			}
		});
		
		var Measure =  WISE.util.Object.toArray(measureKey);
		
		var resultArr = new Array();
		$.each(_ValueArray,function(_i,_obj){
			var str = new Array();
			var object = new Object();
			str.push(_obj[_dimKey]);
			$.each(Measure,function(_i,_Mea){
				//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
				object['value'] = _obj[_Mea.captionBySummaryType];
			});
			
			object['name'] = str.join(' - ');
			resultArr.push(object);
		});
		
		return resultArr;
	}

	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	};

	this.setPyramidChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.PyramidChart['ComponentName'] = this.ComponentName;
		this.PyramidChart['Name'] = this.Name;
		this.PyramidChart['DataSource'] = this.dataSourceId;

		this.PyramidChart['DataItems'] = this.fieldManager.DataItems;
		this.PyramidChart['Arguments'] = this.fieldManager.Arguments;
		this.PyramidChart['Values'] = this.fieldManager.Values;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.PyramidChart;
		//초기 팔레트값 설정
		if (!(this.PyramidChart['Palette'])) {
			this.PyramidChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		if(!this.PyramidChart['LabelPosition']){
			this.PyramidChart.LabelPosition = 'Columns';
		}
		
		if (this.PyramidChart.InteractivityOptions) {
			if (!(this.PyramidChart.InteractivityOptions.MasterFilterMode)) {
				this.PyramidChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.PyramidChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.PyramidChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.PyramidChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.PyramidChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.PyramidChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (!(this.PyramidChart.IsMasterFilterCrossDataSource)) {
			this.PyramidChart.IsMasterFilterCrossDataSource = false;
		}
		if (!(this.PyramidChart.FilterString)) {
			this.PyramidChart.FilterString = [];
		}else{
			this.PyramidChart.FilterString = JSON.parse(JSON.stringify(this.PyramidChart.FilterString).replace(/"@null"/gi,null));
		}
		
		if(!this.PyramidChart.Legend){
			this.PyramidChart.Legend = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.PyramidChart.LabelContentType){
			this.PyramidChart.LabelContentType = 'ArgumentAndPercent';
			this.PyramidChart.LabelMeasureFormat = 'O';
			this.PyramidChart.LabelPrefixEnabled = false;
			this.PyramidChart.LabelPrefixFormat = '';
			this.PyramidChart.LabelSuffixEnabled = false;
			this.PyramidChart.LabelSuffix = {
				O: '',
				K: 'K',
				M: 'M',
				B: 'B'
			};
			this.PyramidChart.LabelPrecision = 0;
			this.PyramidChart.LabelPrecisionOption = '반올림';
		}
		if(!this.PyramidChart.TooltipContentType){
			this.PyramidChart.TooltipContentType = 'ArgumentValueAndPercent';
			this.PyramidChart.TooltipMeasureFormat = 'O';
			this.PyramidChart.TooltipPrefixEnabled = false;
			this.PyramidChart.TooltipPrefixFormat = '';
			this.PyramidChart.TooltipSuffixEnabled = false;
			this.PyramidChart.TooltipSuffix = {
				O: '',
				K: 'K',
				M: 'M',
				B: 'B'
			};
			this.PyramidChart.TooltipPrecision = 0;
			this.PyramidChart.TooltipPrecisionOption = '반올림';
		}
	};

	this.setPyramidChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setPyramidChart();
		}
		else{
			this.PyramidChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.PyramidChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.PyramidChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.PyramidChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if(!this.PyramidChart['LabelPosition']){
			this.PyramidChart.LabelPosition = 'Columns';
		}
		if (!(this.PyramidChart['Palette'])) {
			this.PyramidChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			if(gDashboard != undefined){
				var PyramidChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.PYRAMID_CHART_DATA_ELEMENT);
				
				$.each(PyramidChartOption,function(_i,_PyramidChartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _PyramidChartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _PyramidChartOption.CTRL_NM;
					}
					if(self.PyramidChart.ComponentName == CtrlNM){
						self.PyramidChart['Palette'] = _PyramidChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.PyramidChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.PyramidChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		var dashboardXml = gDashboard.structure.MapOption.DASHBOARD_XML || {};
		var chartDataElements = WISE.util.Object.toArray(dashboardXml.PYRAMID_CHART_DATA_ELEMENT);
		var chartDataElement = {
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
					PRECISION_OPTION: '반올림'
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
					PRECISION_OPTION: '반올림'
				}
			};
		
		$.each(chartDataElements,function(_i,_e) {
			var CtrlNM;
			if (page[page.length - 1] === 'viewer.do'){
				CtrlNM = _e.CTRL_NM + "_" + WISE.Constants.pid;
			}else{
				CtrlNM = _e.CTRL_NM;
			}
			/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
			if(CtrlNM == self.ComponentName){
				chartDataElement = _e;
				return false;
			}
		});
		
		if(!this.PyramidChart['LabelPosition']){
			this.PyramidChart.LabelPosition = 'Columns';
		}
		
		if (typeof this.PyramidChart.LabelContentType === 'undefined') {
			this.PyramidChart.LabelContentType = chartDataElement.LABEL_OPTIONS
				? chartDataElement.LABEL_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.PyramidChart.LabelMeasureFormat === 'undefined') {
			this.PyramidChart.LabelMeasureFormat = chartDataElement.LABEL_OPTIONS 
				? chartDataElement.LABEL_OPTIONS.MEASURE 
				: 'O';
		}
		if (typeof this.PyramidChart.LabelPrefixEnabled === 'undefined') {
			this.PyramidChart.LabelPrefixEnabled = chartDataElement.LABEL_OPTIONS
				&& chartDataElement.LABEL_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.PyramidChart.LabelPrefixFormat === 'undefined') {
			this.PyramidChart.LabelPrefixFormat = chartDataElement.LABEL_OPTIONS
				? chartDataElement.LABEL_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.PyramidChart.LabelSuffixEnabled === 'undefined') {
			this.PyramidChart.LabelSuffixEnabled = chartDataElement.LABEL_OPTIONS 
				&& chartDataElement.LABEL_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.PyramidChart.LabelSuffix === 'undefined') {
			this.PyramidChart.LabelSuffix = chartDataElement.LABEL_OPTIONS 
				? {
					O: chartDataElement.LABEL_OPTIONS.SUFFIX_O,
					K: chartDataElement.LABEL_OPTIONS.SUFFIX_K,
					M: chartDataElement.LABEL_OPTIONS.SUFFIX_M,
					B: chartDataElement.LABEL_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.PyramidChart.LabelPrecision === 'undefined') {
			this.PyramidChart.LabelPrecision = chartDataElement.LABEL_OPTIONS 
				? chartDataElement.LABEL_OPTIONS.PRECISION 
				: 0;
		}
		if (typeof this.PyramidChart.LabelPrecisionOption === 'undefined') {
			this.PyramidChart.LabelPrecisionOption = chartDataElement.LABEL_OPTIONS 
				? chartDataElement.LABEL_OPTIONS.PRECISION_OPTION 
				: '반올림';
		}
		if (typeof this.PyramidChart.LabelPosition === 'undefined') {
			this.PyramidChart.LabelPosition = 'Columns';
		}
		if (typeof this.PyramidChart.TooltipContentType === 'undefined') {
			this.PyramidChart.TooltipContentType = chartDataElement.TOOLTIP_OPTIONS
				? chartDataElement.TOOLTIP_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.PyramidChart.TooltipMeasureFormat === 'undefined') {
			this.PyramidChart.TooltipMeasureFormat = chartDataElement.TOOLTIP_OPTIONS 
				? chartDataElement.TOOLTIP_OPTIONS.MEASURE 
				: 'O';
		}
		if (typeof this.PyramidChart.TooltipPrefixEnabled === 'undefined') {
			this.PyramidChart.TooltipPrefixEnabled = chartDataElement.TOOLTIP_OPTIONS
				&& chartDataElement.TOOLTIP_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.PyramidChart.TooltipPrefixFormat === 'undefined') {
			this.PyramidChart.TooltipPrefixFormat = chartDataElement.TOOLTIP_OPTIONS
				? chartDataElement.TOOLTIP_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.PyramidChart.TooltipSuffixEnabled === 'undefined') {
			this.PyramidChart.TooltipSuffixEnabled = chartDataElement.TOOLTIP_OPTIONS
				&& chartDataElement.TOOLTIP_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.PyramidChart.TooltipSuffix === 'undefined') {
			this.PyramidChart.TooltipSuffix = chartDataElement.TOOLTIP_OPTIONS 
				? {
					O: chartDataElement.TOOLTIP_OPTIONS.SUFFIX_O,
					K: chartDataElement.TOOLTIP_OPTIONS.SUFFIX_K,
					M: chartDataElement.TOOLTIP_OPTIONS.SUFFIX_M,
					B: chartDataElement.TOOLTIP_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.PyramidChart.TooltipPrecision === 'undefined') {
			this.PyramidChart.TooltipPrecision = chartDataElement.TOOLTIP_OPTIONS 
				? chartDataElement.TOOLTIP_OPTIONS.PRECISION
				: 0;
		}
		if (typeof this.PyramidChart.TooltipPrecisionOption === 'undefined') {
			this.PyramidChart.TooltipPrecisionOption = chartDataElement.TOOLTIP_OPTIONS 
				? chartDataElement.TOOLTIP_OPTIONS.PRECISION_OPTION
				: '반올림';
		}
		
		if (this.PyramidChart.InteractivityOptions) {
			if (!(this.PyramidChart.InteractivityOptions.MasterFilterMode)) {
				this.PyramidChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.PyramidChart.InteractivityOptions.TargetDimensions)) {
				this.PyramidChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.PyramidChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.PyramidChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.PyramidChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.PyramidChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.PyramidChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (!(this.PyramidChart.IsMasterFilterCrossDataSource)) {
			this.PyramidChart.IsMasterFilterCrossDataSource = false;
		}
		if (!(this.PyramidChart.FilterString)) {
			this.PyramidChart.FilterString = [];
		}else{
			this.PyramidChart.FilterString = JSON.parse(JSON.stringify(this.PyramidChart.FilterString).replace(/"@null"/gi,null));
		}
		
		if(!this.PyramidChart.Legend){
			this.PyramidChart.Legend = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
	}
	
	this.setPyramidChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setPyramidChart();
		}
		else{
			this.PyramidChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.PyramidChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.PyramidChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.PyramidChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		//팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.PyramidChart['Palette'])) {
			this.PyramidChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var PyramidChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.PYRAMID_CHART_DATA_ELEMENT);
				
				$.each(PyramidChartOption,function(_i,_PyramidChartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _PyramidChartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _PyramidChartOption.CTRL_NM;
//					}
					if(self.PyramidChart.ComponentName == CtrlNM){
						self.PyramidChart['Palette'] = _PyramidChartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.PyramidChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.PyramidChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		var dashboardXml = gDashboard.structure.MapOption.DASHBOARD_XML || {};
		var chartDataElements = WISE.util.Object.toArray(dashboardXml.PYRAMID_CHART_DATA_ELEMENT);
		var chartDataElement = {
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
				PRECISION_OPTION: '반올림'
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
				PRECISION_OPTION: '반올림'
			}
		};
		
		$.each(chartDataElements,function(_i,_e) {
			var CtrlNM;
			if (page[page.length - 1] === 'viewer.do'){
				CtrlNM = _e.CTRL_NM + "_" + WISE.Constants.pid;
			}else{
				CtrlNM = _e.CTRL_NM;
			}
			/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
			if(CtrlNM == self.ComponentName){
				chartDataElement = _e;
				return false;
			}
		});
		
		if(!this.PyramidChart['LabelPosition']){
			this.PyramidChart.LabelPosition = 'Columns';
		}
		
		if (typeof this.PyramidChart.LabelContentType === 'undefined') {
			this.PyramidChart.LabelContentType = chartDataElement.LABEL_OPTIONS
				? chartDataElement.LABEL_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.PyramidChart.LabelMeasureFormat === 'undefined') {
			this.PyramidChart.LabelMeasureFormat = chartDataElement.LABEL_OPTIONS 
				? chartDataElement.LABEL_OPTIONS.MEASURE 
				: 'O';
		}
		if (typeof this.PyramidChart.LabelPrefixEnabled === 'undefined') {
			this.PyramidChart.LabelPrefixEnabled = chartDataElement.LABEL_OPTIONS
				&& chartDataElement.LABEL_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.PyramidChart.LabelPrefixFormat === 'undefined') {
			this.PyramidChart.LabelPrefixFormat = chartDataElement.LABEL_OPTIONS
				? chartDataElement.LABEL_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.PyramidChart.LabelSuffixEnabled === 'undefined') {
			this.PyramidChart.LabelSuffixEnabled = chartDataElement.LABEL_OPTIONS 
				&& chartDataElement.LABEL_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.PyramidChart.LabelSuffix === 'undefined') {
			this.PyramidChart.LabelSuffix = chartDataElement.LABEL_OPTIONS 
				? {
					O: chartDataElement.LABEL_OPTIONS.SUFFIX_O,
					K: chartDataElement.LABEL_OPTIONS.SUFFIX_K,
					M: chartDataElement.LABEL_OPTIONS.SUFFIX_M,
					B: chartDataElement.LABEL_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.PyramidChart.LabelPrecision === 'undefined') {
			this.PyramidChart.LabelPrecision = chartDataElement.LABEL_OPTIONS 
				? chartDataElement.LABEL_OPTIONS.PRECISION 
				: 0;
		}
		if (typeof this.PyramidChart.LabelPrecisionOption === 'undefined') {
			this.PyramidChart.LabelPrecision = chartDataElement.LABEL_OPTIONS 
				? chartDataElement.LABEL_OPTIONS.PRECISION_OPTION 
				: '반올림';
		}
		if (typeof this.PyramidChart.LabelPosition === 'undefined') {
			this.PyramidChart.LabelPosition = 'Columns';
		}
		if (typeof this.PyramidChart.TooltipContentType === 'undefined') {
			this.PyramidChart.TooltipContentType = chartDataElement.TOOLTIP_OPTIONS
				? chartDataElement.TOOLTIP_OPTIONS.CONTENT_TYPE
				: 'ArgumentAndPercent';
		}
		if (typeof this.PyramidChart.TooltipMeasureFormat === 'undefined') {
			this.PyramidChart.TooltipMeasureFormat = chartDataElement.TOOLTIP_OPTIONS 
				? chartDataElement.TOOLTIP_OPTIONS.MEASURE 
				: 'O';
		}
		if (typeof this.PyramidChart.TooltipPrefixEnabled === 'undefined') {
			this.PyramidChart.TooltipPrefixEnabled = chartDataElement.TOOLTIP_OPTIONS
				&& chartDataElement.TOOLTIP_OPTIONS.PREFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.PyramidChart.TooltipPrefixFormat === 'undefined') {
			this.PyramidChart.TooltipPrefixFormat = chartDataElement.TOOLTIP_OPTIONS
				? chartDataElement.TOOLTIP_OPTIONS.PREFIX_FORMAT
				: '';
		}
		if (typeof this.PyramidChart.TooltipSuffixEnabled === 'undefined') {
			this.PyramidChart.TooltipSuffixEnabled = chartDataElement.TOOLTIP_OPTIONS
				&& chartDataElement.TOOLTIP_OPTIONS.SUFFIX_ENABLED_YN === 'Y';
		}
		if (typeof this.PyramidChart.TooltipSuffix === 'undefined') {
			this.PyramidChart.TooltipSuffix = chartDataElement.TOOLTIP_OPTIONS 
				? {
					O: chartDataElement.TOOLTIP_OPTIONS.SUFFIX_O,
					K: chartDataElement.TOOLTIP_OPTIONS.SUFFIX_K,
					M: chartDataElement.TOOLTIP_OPTIONS.SUFFIX_M,
					B: chartDataElement.TOOLTIP_OPTIONS.SUFFIX_B
				}
				: {
					O: '',
					K: 'K',
					M: 'M',
					B: 'B'
				};
		}
		if (typeof this.PyramidChart.TooltipPrecision === 'undefined') {
			this.PyramidChart.TooltipPrecision = chartDataElement.TOOLTIP_OPTIONS 
				? chartDataElement.TOOLTIP_OPTIONS.PRECISION
				: 0;
		}
		if (typeof this.PyramidChart.TooltipPrecisionOption === 'undefined') {
			this.PyramidChart.TooltipPrecisionOption = chartDataElement.TOOLTIP_OPTIONS 
				? chartDataElement.TOOLTIP_OPTIONS.PRECISION_OPTION
				: '반올림';
		}
		if (this.PyramidChart.InteractivityOptions) {
			if (!(this.PyramidChart.InteractivityOptions.MasterFilterMode)) {
				this.PyramidChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.PyramidChart.InteractivityOptions.TargetDimensions)) {
				this.PyramidChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.PyramidChart.InteractivityOptions.IsDrillDownEnabled)) {
				this.PyramidChart.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.PyramidChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.PyramidChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.PyramidChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (!(this.PyramidChart.IsMasterFilterCrossDataSource)) {
			this.PyramidChart.IsMasterFilterCrossDataSource = false;
		}
		if (!(this.PyramidChart.FilterString)) {
			this.PyramidChart.FilterString = [];
		}else{
			this.PyramidChart.FilterString = JSON.parse(JSON.stringify(this.PyramidChart.FilterString).replace(/"@null"/gi,null));
		}
		
		if(!this.PyramidChart.Legend){
			this.PyramidChart.Legend = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
	}

	/** @Override */
	this.bindData = function(_data) {
		//2020.02.07 mksong sqllike 적용 dogfoot
//		if (!this.tracked) {
//			this.globalData = _.clone(_data);
//			this.filteredData = _.clone(_data);
//		}
//		if ($.type(this.child) === 'object' && this.dxItem) {
//			this.dxItem = undefined;
//			this.layoutManager.createItemLayer(this.itemid);
//		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setPyramidChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.PyramidChart);
			gDashboard.itemGenerateManager.generateItem(self, self.PyramidChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setPyramidChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.PyramidChart);
			gDashboard.itemGenerateManager.generateItem(self, self.PyramidChart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.PyramidChart)) {
			this.setPyramidChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.PyramidChart);
			gDashboard.itemGenerateManager.generateItem(self, self.PyramidChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setPyramidChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.PyramidChart);
			gDashboard.itemGenerateManager.generateItem(self, self.PyramidChart);
		}

		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
			topIconPanel.append(trackingDataContainerHtml);
		}

		var dxConfig = this.getDxItemConfig(this.meta);

		var measureKey = this.measures[0];
		if(!self.currentMeasureName || self.currentMeasureName === "")
			self.currentMeasureName = measureKey.caption;
		
		this.dataSourceConfig = self.deleteDuplecateData([],measureKey);
		if(!this.dataSourceConfig)
			this.dataSourceConfig = [];
				
		if(this.dataSourceConfig.length === 1 && this.dataSourceConfig[0].name === "")
			this.dataSourceConfig[0].name = self.currentMeasureName;
		
		dxConfig.dataSource = this.dataSourceConfig;
		
		if($('#'+self.itemid).length != 0){
			self.dxItem = $('#'+self.itemid).dxFunnel(dxConfig).dxFunnel('instance');
			//차트 render
//			self.fPyramidChart(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,self.measures[0]));	
		}
		self.clearTrackingConditions();
		
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
		
//		gDashboard.itemGenerateManager.generateDxItem(self, _data);
		
		gDashboard.itemGenerateManager.renderButtons(self);

	};
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
	}
	
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
	};
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		//2020.02.07 mksong sqllike 적용 dogfoot
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		/**
		 * 데이터 중복 제거 코드
		 */
		var ValueArray = new Array();
		var FieldArray = new Array();
		var selectArray = new Array();
		
		var Dimension = WISE.util.Object.toArray(this.dimensions);
		var Measure =  WISE.util.Object.toArray(MeasureKey);
		
		$.each(Dimension,function(_i,_Dim){
			selectArray.push(_Dim.name);
			FieldArray.push(_Dim.name);
		});
		
		$.each(Measure,function(_i,_Mea){
			selectArray.push('|'+_Mea.summaryType+'|');
			selectArray.push(_Mea.name);
			//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
			selectArray.push('|as|');
			selectArray.push(_Mea.captionBySummaryType);
		});
		//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
		var sqlConfig ={};
		 /*dogfoot 데이터 집합이 같을 때만 where 절 추가 shlim 20200619*/
		if(typeof self.dataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
			if(self.dataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
			}else{
				sqlConfig.Where = [];
			}
		}else{
			sqlConfig.Where = [];
        }
		sqlConfig.Select = selectArray;
		sqlConfig.From = _data;
//		sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
		sqlConfig.GroupBy = FieldArray;

		if(self.IO) {
			if(self.IO.IgnoreMasterFilters){
				sqlConfig.Where = [];
				sqlConfig.From = [];
			}
		}
		
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		self.filteredData = SQLikeUtil.doSqlLike(this.dataSourceId, sqlConfig, self);
//		self.filteredData = gDashboard.itemGenerateManager.doQueryCSVData(self, {'measureKey' : MeasureKey, 'data' : data});
		self.csvData = self.filteredData;
		self.initDrillDownData(self.filteredData);
		
		//2020.05.04 AJKIM 데이터 항목 없을 때 이미지 추가 DOGFOOT
		if(gDashboard.itemGenerateManager.noDataCheck(self.csvData, self)) return;
		if((self.filteredData = gDashboard.itemGenerateManager.checkFilteredData(self.filteredData, self).items()).length === 0) return;
		
//		ValueArray.push(SQLike.q(sqlConfig));
		ValueArray.push(self.filteredData);
		
		var resultArr = new Array();
		var isZeroValueCheck = false;
		var zeroValueQuantity = 0;
		$.each(ValueArray,function(_i,_e){
			$.each(_e,function(_item,_obj){
				var str = new Array();
				var object = new Object();
				$.each(Dimension,function(_i,_Dim){
					str.push(_obj[_Dim.name]);
				});
				$.each(Measure,function(_i,_Mea){
					//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
					object['value'] = _obj[_Mea.captionBySummaryType];
					if(object['value'] == 0){
						zeroValueQuantity++;
					}
				});
				
				object['name'] = str.join(' - ')
				resultArr.push(object);
			});
			
			if(_e.length == zeroValueQuantity){
				isZeroValueCheck = true;
			}
		});
		
		if(isZeroValueCheck){
			$('#'+self.itemid + ' .nodata-layer').remove();
			$('#'+self.itemid + ' .zerodata-layer').remove();
			var nodataHtml = '<div class="zerodata-layer" style="z-index:99999999999"></div>';
			// DOGFOOT tbchoi 2020-02-28 없는 정보 호출 후 다시 차트를 그리면 Y축 표시가 차트 안쪽으로 밀리는 현상 수정
			$("#" + self.itemid).children('svg').css('visibility','hidden');
			$("#" + self.itemid).prepend(nodataHtml); 
		}else{
			$('#'+self.itemid + ' .nodata-layer').remove();
			$('#'+self.itemid + ' .zerodata-layer').remove();
			$("#" + self.itemid).children('svg').css('visibility','');
			$("#" + self.itemid).children().css('display','block');
		}
		
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
		
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _d) {
			if(_d.type != 'IMAGE'){
				if(_d.dimensions != undefined && _d.measures != undefined) {
					if(_d.dimensions.length == 0 && _d.measures.length == 0){
						gProgressbar.hide();
					}	
				}
			}
		});
		
		self.metadata = resultArr;
		
		return resultArr;
//		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
//		var dataSourceId = this.dataSourceId;		
//		/**
//		 * 데이터 중복 제거 코드
//		 */
//		var ValueArray = new Array();
//		var FieldArray = new Array();
//		var selectArray = new Array();
//
//		var Dimension = WISE.util.Object.toArray(this.meta.DataItems.Dimension);
//		var Measure =  WISE.util.Object.toArray(MeasureKey);
//
//		$.each(Dimension,function(_i,_Dim){
//			selectArray.push(_Dim.DataMember);
//			FieldArray.push(_Dim.DataMember);
//		});
//
//		$.each(Measure,function(_i,_Mea){
//			selectArray.push('|sum|');
//			selectArray.push(_Mea.name);
//			selectArray.push('|as|');
//			selectArray.push(_Mea.captionBySummaryType);			
//		})
//
//		var sqlConfig ={};
//		 /*dogfoot 데이터 집합이 같을 때만 where 절 추가 shlim 20200619*/
//		if(typeof self.dataSourceId != 'undefined' && typeof gDashboard.itemGenerateManager.sqlConfigCurruntId != 'undefined') {
//			if(self.dataSourceId ==  gDashboard.itemGenerateManager.sqlConfigCurruntId){
//				sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
//			}else{
//				sqlConfig.Where = [];
//			}
//		}else{
//			sqlConfig.Where = [];
//        }
//		sqlConfig.Select = selectArray;
//		sqlConfig.From = _data;
////		sqlConfig.Where = gDashboard.itemGenerateManager.sqlConfigWhere;
//		sqlConfig.GroupBy = FieldArray;
//		
//		sqlConfig.OrderBy = [];
//		$.each(Dimension, function(_i, _d) {
//			//2020.02.07 mksong sqllike 적용 dogfoot
//			sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
//		});
//		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
//		self.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, self.cubeQuery);
//		ValueArray.push(self.filteredData);
//
//		var resultArr = new Array();
//		$.each(ValueArray,function(_i,_e){
//			$.each(_e,function(_item,_obj){
//				var valArray = new Array();
//				var object = new Object();
//				$.each(Dimension,function(_i,_Dim){
//					valArray.push(_obj[_Dim.DataMember]);
//				});
//				if(Measure.length == 0){
//					valArray.push(1);	
//				}else{
//					$.each(Measure,function(_i,_Mea){
//						valArray.push(_obj[_Mea.captionBySummaryType]);
//					});	
//				}
//				resultArr.push(valArray);
//			})
//		});
//		return resultArr;
	};
	
//	this.resize = function() {
//		if($("#" + self.itemid).length != 0){
//			self.fPyramidChart(self.filteredData, self.measures, self.dimensions, self.deleteDuplecateData(self.filteredData,self.measures[0]));	
//		}
//		
//		gProgressbar.hide();
//	};
	this.resize = function(){
		if(self.dxItem){
			self.dxItem.render();
			
		}
	}

	this.renderChart = function(jsonData, measures, dimensions, dupleData) {

	};
	
	this.getLegend = function(legendOption){
		return {
			horizontalAlignment : legendOption.indexOf("Right") > -1? "right" : legendOption.indexOf("Left") > -1? "left" : "center",
			orientation : legendOption.indexOf("Vertical") > -1? "vertical" : "horizontal",
			verticalAlignment : legendOption.indexOf("Top") > -1? "top" : "bottom",
			visible :self.meta.Legend.Visible,
			font : gDashboard.fontManager.getDxItemLabelFont()
		}
	}
	
	this.functionDo = function(_f) {		
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.PyramidChart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.PyramidChart['ShowCaption'] = false;
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
                            	
                            	self.PyramidChart['Name'] = newName;
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
				var chagePalette = self.PyramidChart.Palette;
				var firstPalette = self.PyramidChart.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.PyramidChart.Palette) != -1
										? self.PyramidChart.Palette
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
                                    self.dxItem.option('palette', self.PyramidChart.Palette);
                                    
								} else {
                                    self.isCustomPalette = false;
                                    self.PyramidChart.Palette = paletteObject2[e.value];
                                    self.dxItem.option('palette', self.PyramidChart.Palette);
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.PyramidChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            self.dxItem.option('palette', self.PyramidChart.Palette);
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	self.PyramidChart.Palette = firstPalette;
                            chagePalette = firstPalette;
                            self.dxItem.option('palette', self.PyramidChart.Palette);
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.PyramidChart.Palette = chagePalette;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
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
                        self.dxItem.option('dataSource').forEach(function(item, index) {
							colorContainer.append('<p>' + item.name
													+ '</p><div id="' + self.itemid + '_itemsColor' + index + '"></div>');
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

						self.dxItem.option('dataSource').forEach(function(item, index) {
							$('#' + self.itemid + '_itemsColor' + index).dxColorBox({
								value: self.dxItem.getAllItems()[index].getColor()
							});
                        });

                        // confirm and cancel
						$('#ok-hide').on('click', function() {
                            var newPalette = [];
                            self.dxItem._items.forEach(function(item, index) {
                                newPalette[index] = $('#' + self.itemid + '_itemsColor' + index).dxColorBox('instance').option('value');
                            });
                            self.PyramidChart['Palette'] = newPalette;
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
					}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#labelLocation',
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_labelLocation">');
						$('#' + self.itemid + '_labelLocation').dxRadioGroup({
							width: '60px',
							dataSource: ['컬럼', '내부', '외부'],
							value: mapping[self.PyramidChart.LabelPosition],
							onValueChanged: function(e) {
								var position = mapping[e.value];
								self.PyramidChart.LabelPosition = mapping[position];
								self.dxItem.option('label.position', position);
								self.dxItem.option('label.font.color', position === 'inside'? "black": undefined);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			}
			case 'editLegend': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
                    target: '#editLegend',
					contentTemplate: function(contentElement) {
							$(	'<div id="' + self.itemid + '_toggleLegend" style="width:130px;' + gDashboard.fontManager.getCustomFontStringForMenu(14) +'"></div>' +
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
								self.PyramidChart.Legend.Visible = !self.PyramidChart.Legend.Visible;
								self.dxItem.option('legend.visible', self.PyramidChart.Legend.Visible);
							}
                        });
                        
						$.each($('.select-position'), function(index, position) {
							if (self.PyramidChart.Legend.Position === $(position).data('description')) {
								$(position).addClass('on');
								return false;
							}
						});
						
						$('.select-position').off('click').on('click', function(e) {
                            $('.select-position.on').removeClass('on');
							$(this).addClass('on');
							var newDescription = $(this).data('description');
							self.PyramidChart.Legend.Position = newDescription;
							var newLegend = self.getLegend(newDescription);
                            self.dxItem.option('legend', newLegend);
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			}
			case 'editFilter': {
				if (!(self.dxItem)) {
					break;
				}
				// 20201102 AJKIM 차원 없을 경우 필터 편집 막음 dogfoot
				if(self.dimensions.length === 0){
					WISE.alert("차원이 하나 이상 존재해야 합니다.");
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
						self.PyramidChart.InteractivityOptions.MasterFilterMode = 'Off';
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
						self.PyramidChart.InteractivityOptions.MasterFilterMode = 'Single';
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
						self.PyramidChart.InteractivityOptions.MasterFilterMode = 'Off';
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
						self.PyramidChart.InteractivityOptions.MasterFilterMode = 'Multiple';
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
			case 'ignoreMasterFilter': {
				if (!(self.dxItem)) {
					break;
				}	
				self.IO.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
				self.PyramidChart.InteractivityOptions.IgnoreMasterFilters = self.IO.IgnoreMasterFilters;
				self.tracked = !self.IO.IgnoreMasterFilters;

				gProgressbar.show();
				
				setTimeout(function () {	
					if (self.IO.IgnoreMasterFilters) {
						self.functionBinddata = true;
					}				
					self.bindData(self.filteredData, true);
				},10);
				
				
				break;
			}
			case 'crossFilter': {
				if (!(self.dxItem)) {
					break;
				}
				self.IsMasterFilterCrossDataSource = $('#crossFilter').hasClass('on') ? true : false;
				self.PyramidChart.IsMasterFilterCrossDataSource = self.IsMasterFilterCrossDataSource;
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
			case 'drillDown': {
				if (!(self.dxItem)) {
					break;
				}
				// Both master filter and drill-down cannot be active at the same time. Turn master filter off.
				if (self.IO.MasterFilterMode !== 'Off') {
					self.PyramidChart.InteractivityOptions.MasterFilterMode = 'Off';
					self.IO.MasterFilterMode = 'Off';
					self.clearTrackingConditions();
					var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
					if(reTrackItem){
						gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
					}else{
						gDashboard.filterData(self.itemid, self.trackingData);	
					}
				}
				if ($('#drillDown').hasClass('on')) {
						// configure settings to "true"
						self.PyramidChart.InteractivityOptions.IsDrillDownEnabled = true;
						self.IO.IsDrillDownEnabled = true;
						self.initDrillDownOperation();
					
					$('#' + self.DrilldownClearId).removeClass('invisible');
				} else {
					$('#' + self.DrilldownClearId).addClass('invisible');
					self.terminateDrillDownOperation();
				}
				break;
			}
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
								표기형식: mapping[chartLabelFormat.type],
								단위: chartLabelFormat.format,
								'사용자 지정 접두사': chartLabelFormat.prefixEnabled,
								'접두사': chartLabelFormat.prefixFormat,
								'사용자 지정 접미사': chartLabelFormat.suffixEnabled,
								O: chartLabelFormat.suffix.O,
								K: chartLabelFormat.suffix.K,
								M: chartLabelFormat.suffix.M,
								B: chartLabelFormat.suffix.B,
								정도: chartLabelFormat.precision,
								'정도 옵션': chartLabelFormat.precisionOption
							},
							items: [
								{
									dataField: '표기형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										dataSource: ['없음', '인수', '값', '%', '인수 및 값', 
											 '값 및 %', '인수 및 %', '인수, 값 및 %'],
										value: mapping[chartLabelFormat.type],
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
										value: mapping[chartLabelFormat.format],
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										value: chartLabelFormat.prefixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										value: chartLabelFormat.prefixFormat,
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										value: chartLabelFormat.suffixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										value: chartLabelFormat.suffix.O,
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										value: chartLabelFormat.suffix.K,
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										value: chartLabelFormat.suffix.M,
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										value: chartLabelFormat.suffix.B,
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										//20210712 AJKIM 소수점 방지 dogfoot
										format: "#",
										showSpinButtons: true,
										value: chartLabelFormat.precision,
										onInitialized: function(e) {
											var formatType = mapping[chartLabelFormat.type];
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
										value: typeof chartLabelFormat.precisionOption !== 'undefined' ? chartLabelFormat.precisionOption : '반올림',
									}
								}
							]
                        });
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            // save label settings
                            chartLabelFormat.type = mapping[$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('표기형식').option('value')];
							self.PyramidChart.LabelContentType = chartLabelFormat.type;
                            chartLabelFormat.format = mapping[$('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('단위').option('value')];
							self.PyramidChart.LabelMeasureFormat = chartLabelFormat.format;
							chartLabelFormat.prefixEnabled = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접두사').option('value');
							self.PyramidChart.LabelPrefixEnabled = chartLabelFormat.prefixEnabled;
							chartLabelFormat.prefixFormat = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('접두사').option('value');
							self.PyramidChart.LabelPrefixFormat = chartLabelFormat.prefixFormat;
							chartLabelFormat.suffixEnabled = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('사용자 지정 접미사').option('value');
                            self.PyramidChart.LabelSuffixEnabled = chartLabelFormat.suffixEnabled;
							chartLabelFormat.suffix.O = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('O').option('value');
							chartLabelFormat.suffix.K = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('K').option('value');
							chartLabelFormat.suffix.M = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('M').option('value');
							chartLabelFormat.suffix.B = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('B').option('value');
							self.PyramidChart.LabelSuffix = chartLabelFormat.suffix;
							chartLabelFormat.precision = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도').option('value');
                            self.PyramidChart.LabelPrecision = chartLabelFormat.precision;
                            chartLabelFormat.precisionOption = $('#' + self.itemid + '_labelForm').dxForm('instance').getEditor('정도 옵션').option('value');
                            self.PyramidChart.LabelPrecisionOption = chartLabelFormat.precisionOption;
                            // create new custom label format
                            if(chartLabelFormat.type === 'None')
                            	self.dxItem.option('label.visible', false);
                            else{
                            	self.dxItem.option('label.visible', true);
                            	self.dxItem.option('label.customizeText', function(pointInfo) {
   								 return self.getLabelFormat(pointInfo);
                            	});
                            }
                            p.hide();
						});
						contentElement.find('#close').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}case 'editTooltip': {
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
								'표기 형식': mapping[chartTooltipFormat.type],
								'단위': chartTooltipFormat.format,
								'사용자 지정 접두사': chartTooltipFormat.prefixEnabled,
								'접두사': chartTooltipFormat.prefixFormat,
								'사용자 지정 접미사': chartTooltipFormat.suffixEnabled,
								O: chartTooltipFormat.suffix.O,
								K: chartTooltipFormat.suffix.K,
								M: chartTooltipFormat.suffix.M,
								B: chartTooltipFormat.suffix.B,
								'정도': chartTooltipFormat.precision,
								'정도 옵션': chartTooltipFormat.precisionOption,
							},
							items: [
								{
									dataField: '표기 형식',
									editorType: 'dxSelectBox',
									editorOptions: {
										dataSource: ['없음', '인수', '값', '%', '인수 및 값', 
											 '값 및 %', '인수 및 %', '인수, 값 및 %'],
										value: mapping[chartTooltipFormat.type],
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
											value: mapping[chartTooltipFormat.format],
											onInitialized: function(e) {
												var formatType = mapping[chartTooltipFormat.type];
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
										value: chartTooltipFormat.prefixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[chartTooltipFormat.type];
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
										value: chartTooltipFormat.prefixFormat,
										onInitialized: function(e) {
											var formatType = mapping[chartTooltipFormat.type];
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
										value: chartTooltipFormat.suffixEnabled,
										onInitialized: function(e) {
											var formatType = mapping[chartTooltipFormat.type];
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
										value: chartTooltipFormat.suffix.O,
										onInitialized: function(e) {
											var formatType = mapping[chartTooltipFormat.type];
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
										value: chartTooltipFormat.suffix.K,
										onInitialized: function(e) {
											var formatType = mapping[chartTooltipFormat.type];
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
										value: chartTooltipFormat.suffix.M,
										onInitialized: function(e) {
											var formatType = mapping[chartTooltipFormat.type];
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
										value: chartTooltipFormat.suffix.B,
										onInitialized: function(e) {
											var formatType = mapping[chartTooltipFormat.type];
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
										//20210712 AJKIM 소수점 방지 dogfoot
										format: "#",
										showSpinButtons: true,
										value: chartTooltipFormat.precision,
										onInitialized: function(e) {
											var formatType = mapping[chartTooltipFormat.type];
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
										value: typeof chartTooltipFormat.precisionOption !== 'undefined' ? chartTooltipFormat.precisionOption : '반올림',
									}
								}
							]
                        });
                                                
                        // confirm and cancel
						contentElement.find('#ok-hide').on('click', function() {
                            // save tooltip settings
                            chartTooltipFormat.type = mapping[$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('표기 형식').option('value')];
							self.PyramidChart.TooltipContentType = chartTooltipFormat.type;
                            chartTooltipFormat.format = mapping[$('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('단위').option('value')];
							self.PyramidChart.TooltipMeasureFormat = chartTooltipFormat.format;
							chartTooltipFormat.prefixEnabled = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접두사').option('value');
							self.PyramidChart.TooltipPrefixEnabled = chartTooltipFormat.prefixEnabled;
							chartTooltipFormat.prefixFormat = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('접두사').option('value');
							self.PyramidChart.TooltipPrefixFormat = chartTooltipFormat.prefixFormat;
							chartTooltipFormat.suffixEnabled = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('사용자 지정 접미사').option('value');
                            self.PyramidChart.TooltipSuffixEnabled = chartTooltipFormat.suffixEnabled;
							chartTooltipFormat.suffix.O = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('O').option('value');
							chartTooltipFormat.suffix.K = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('K').option('value');
							chartTooltipFormat.suffix.M = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('M').option('value');
							chartTooltipFormat.suffix.B = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('B').option('value');
							self.PyramidChart.TooltipSuffix = chartTooltipFormat.suffix;
							chartTooltipFormat.precision = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도').option('value');
                            self.PyramidChart.TooltipPrecision = chartTooltipFormat.precision;
                            chartTooltipFormat.precisionOption = $('#' + self.itemid + '_tooltipForm').dxForm('instance').getEditor('정도 옵션').option('value');
                            self.PyramidChart.TooltipPrecisionOption = chartTooltipFormat.precisionOption;
                            // create new custom label format
                            self.dxItem.option('tooltip.customizeTooltip', function(_pointInfo) {
								return {html: self.getTooltipFormat(_pointInfo)};
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
			// toggle cross data source filtering
			default: break;
		}
	}

};


function checkingItem(_data) {
	return !_data.items.length;
};

WISE.libs.Dashboard.PyramidChartFieldManager = function() {
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
//	this.hide_column_list_dim = [];
//	this.hide_column_list_mea = [];

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
		var NumericFormat = {'ForMatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'PrecisionOption': '반올림', 'Unit': "Ones"};

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
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = NumericFormat;
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

	this.setArgumentsByField = function(_argument){
		this.Arguments = {'Argument' : []};
		_.each(_argument,function(_a){
			var Value = {'UniqueName' : _a.uniqueName};
			self.Arguments['Argument'].push(Value);
		});
		return self.Arguments;
	};
};
