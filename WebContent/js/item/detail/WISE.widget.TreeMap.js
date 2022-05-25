WISE.libs.Dashboard.item.TreeMapGenerator = function() {
	var self = this;

	this.type = 'TREEMAP';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	var dataMember;
	var Exprname;
	var FilterArray = [];
	this.TreeMap = [];
	this.fieldManager;
	this.currentMeasureName = "";
	this.panelManager;
	
	//2020-01-14 LSH topN
	this.topN;
	this.topItem;
	this.topNT;
	this.OtherCnt;
	this.otherShow;
	this.TopNMember;
	this.topNEnabeled = false;
	this.topMesure;
    this.dimensionTopN = new Array();

	this.customPalette = [];
	this.isCustomPalette = false;
	this.trackingData = [];
	this.selectedPoint;
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	this.drillDownData = [];
	this.drillDownStack = [];
	this.argumentOrder = [];
	this.currentDimensionKey = "";
	this.nextDimensionKey = "";
	
	var rootval;
//	this.drillDownIndex; // must be number type
	
	var isFirstLevel = true;
	var drillDownIndex = 0;
	var leveling = 0;
	var ddParentStack = [];
	var ddCurrentID = '';
	
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
	
	/**
	 * @param _item:
	 *            meta object
	 */
	var CheckCurrentFilter;
	this.getDxItemConfig = function(_item) {
		var confMeasure = _item['DataItems']['Measure'];
		this.dataSourceConfig = {};
		this.dataSourceConfig.fields = [];

		var count = 0;
		
//		D = _item.FilterDimensions ? WISE.util.Object
//				.toArray(_item.DataItems.Dimension) : [];

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
		var dxConfigs = {
			dataSource : this.dataSourceConfig,
			dataStructure: 'plain',
			allowExpandAll: true,
			allowFiltering: true,
			allowSorting: true,
			allowSortingBySummary: true,
			resolveLabelOverflow:'ellipsis',
			layoutAlgorithm:"squarified",
			selectionMode: 'multiple',
			colorizer:{
				palette: _item['Palette'],
			},
			redrawOnResize:true,
			size:{
				width : $('#'+self.itemid).width(),
				height : $('#'+self.itemid).height(),
			},
			tile:{
				label: {
					font: gDashboard.fontManager.getDxItemLabelFont(),
					textOverflow:"none",
					wordWrap: "breakWord"
				}
			},
			tooltip: {
				enabled: true,
				zIndex: 21,
				font: gDashboard.fontManager.getDxItemLabelFont(),
				customizeTooltip:function(_pointInfo){
//					var text = '<b>' + _pointInfo.node.data.name + '</b>' + '<br/>' +"<b>" +self.currentMeasureName+"</b> : " +WISE.util.Number.unit(_pointInfo.value,"Number",'O',0);
//					ret = {html: text};
//					return ret;
					
					var Number = WISE.util.Number,
					labelFormat = 'Number',
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
		        	if(typeof(confMeasure.NumericFormat) == 'object') {
	        			labelFormat = confMeasure.NumericFormat.FormatType;
	        			labelPrecision = confMeasure.NumericFormat.Precision;
						labelUnit = confMeasure.NumericFormat.Unit;
						labelSeparator = confMeasure.NumericFormat.IncludeGroupSeparator;
						labelSuffixEnabled = confMeasure.NumericFormat.SuffixEnabled;
						labelSuffix = confMeasure.NumericFormat.Suffix;
					/* 나중에 비정형일 때 포맷 변경해야하는 부분*/
					} else {
		        		if (_item.DataItems.Measure.length == 1) {
		        			if(_item.DataItems.Measure[0].NumericFormat != undefined){
								labelFormat = typeof _item.DataItems.Measure[0].NumericFormat.FormatType == 'undefined' ? labelFormat : _item.DataItems.Measure[0].NumericFormat.FormatType;
								labelUnit = typeof _item.DataItems.Measure[0].NumericFormat.Unit == 'undefined'? labelUnit : _item.DataItems.Measure[0].NumericFormat.Unit;
								labelPrecision = typeof _item.DataItems.Measure[0].NumericFormat.Precision == 'undefined' ? labelPrecision : _item.DataItems.Measure[0].NumericFormat.Precision;
								labelSeparator = typeof _item.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator == 'undefined' ? labelSeparator : _item.DataItems.Measure[0].NumericFormat.IncludeGroupSeparator;
								labelSuffixEnabled = typeof _item.DataItems.Measure[0].NumericFormat.SuffixEnabled == 'undefined' ? labelSuffixEnabled : _item.DataItems.Measure[0].NumericFormat.SuffixEnabled;
								labelSuffix = typeof _item.DataItems.Measure[0].NumericFormat.Suffix == 'undefined' ? labelSuffix : _item.DataItems.Measure[0].NumericFormat.Suffix;
							}
		        		} else {
							$.each(_item.DataItems.Measure, function(i,k) {
								if (self.currentMeasureName===k.DataMember) {
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
					text = '<div>' + _pointInfo.node.data.name + '</div>' + 
						'<div><b>' + self.currentMeasureName + '</b>: ' + Number.unit(_pointInfo.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + '</div>';
	
					return { html: text };
				}
			},
			onClick: function(_e) {
	        	if (self.IO && self.IO['MasterFilterMode'] !== 'Off') {
					// do nothing if single master filter and selected point is selected
					if (self.IO.MasterFilterMode === 'Single' && _e.node.isSelected()) {
						return;
					}
					var dimensions, dimensionNames = [];
					// select and deselect points
					if (self.IO.TargetDimensions === 'Series') {
						dimensions = self.seriesDimensions;
						dimensionNames = _e.node.data.name.split('-');
						if (_e.node.isSelected()) {
							self.dxItem.clearSelection();
						} else {
							_e.node.select(!_e.node.isSelected());
							//self.dxItem._selectNode(_e.node.index, true);
						}
					} else {
						dimensions = self.meta['DataItems']['Dimension'];
						dimensionNames = _e.node.data.name.split('-');
						console.log(_e.node.data);
						/*
						for(var i=0; i<dimensionNames.length;i++){
							dimensionNames[i] = dimensionNames[i].replace(/\n/g, "");//행바꿈제거
							dimensionNames[i] = dimensionNames[i].replace(/\r/g, "");//엔터제거
						}					
						*/
//						if(_e.node.isSelected()){
//							_e.node.select(!_e.node.isSelected());
//						}else{
							_e.node.select(!_e.node.isSelected());
//						}
						
					}
					
	        		switch(self.IO['MasterFilterMode']){
			       		case 'Multiple':
			       			$.each(dimensions, function(_i, _ao) {
				       			var inArray = false;
				       			var selectedData = {};
				       			selectedData[_ao.DataMember] = dimensionNames[_i].trim();
				       			for (var index = 0; index < self.trackingData.length; index++) {
				       				if (self.trackingData[index][_ao.DataMember] === selectedData[_ao.DataMember]) {
				       					/* DOGFOOT ktkang 트리맵 다중 마스터 필터 오류 수정  20200619 */
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
			                    	_e.node.select(false);			                    	
			                    } else {			                    	
			                    	self.selectedPoint.select(false);			                    	
			                    }
			       			}
			       			self.selectedPoint = _e.node;
			       			self.trackingData = [];
			       			$.each(WISE.util.Object.toArray(dimensions), function(_i, _ao) {
			       				var selectedData = {};
				       			selectedData[_ao.DataMember] = dimensionNames[_i].trim();
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
	        		if(_e.node.data.name.indexOf('-') != -1 && self.dimensions.length > 1){
	        			self.currentDimensionKey = self.dimensions[0].caption;
	        		}
	        		
	        		var data = _e.node.data;
	        		var dimensionValue = _e.node.data.name.split('-')[0].trim();
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
			}
		}

		// extend custom-configurations
		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
		var CustomConfigs = $.extend({}, Configurations);
		$.extend(CustomConfigs, dxConfigs);
		dxConfigs = CustomConfigs;
		return dxConfigs;
	};

	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	};
	
	this.setTreeMap = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.TreeMap['ComponentName'] = this.ComponentName;
		this.TreeMap['Name'] = this.Name;
		this.TreeMap['DataSource'] = this.dataSourceId;
		
		this.TreeMap['DataItems'] = this.fieldManager.DataItems;
		this.TreeMap['Arguments'] = this.fieldManager.Arguments;
		this.TreeMap['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		if (!(this.TreeMap['Palette'])) {
			this.TreeMap['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		
		this.TreeMap['InteractivityOptions'] = {
				MasterFilterMode: 'Off',
				IgnoreMasterFilters: false,
				IsDrillDownEnabled: false
		};
		this.TreeMap['FilterString'] = [];
		
		this.meta = this.TreeMap;
	};
	
	this.setTreeMapforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setTreeMap();
		}
		else{
			this.TreeMap=this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.TreeMap['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.TreeMap['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.TreeMap['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		if (!(this.TreeMap['Initialized'])) {
			this.TreeMap['Initialized'] = true;
		}
		
		if(!(this.TreeMap['Palette'])){
			var TreeMapOption = typeof window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.TREEMAP_DATA_ELEMENT);
			$.each(TreeMapOption,function(_i,_treemapOption){
				if(self.TreeMap.ComponentName == _treemapOption.CTRL_NM){
					self.TreeMap['Palette'] = _treemapOption.PALETTE_NM;
					return false;
				}
			})
			if(typeof this.meta.ColorSheme != 'undefined'){
				var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
				this.TreeMap.Palette = new Array();
				$.each(colorList,function(_i,_list){
					self.TreeMap.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
				});
			}
		}
		
		if (this.TreeMap.InteractivityOptions) {
			if (typeof this.TreeMap.InteractivityOptions.MasterFilterMode === 'undefined') {
				this.TreeMap.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (typeof this.TreeMap.InteractivityOptions.TargetDimensions === 'undefined') {
				this.TreeMap.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (typeof this.TreeMap.InteractivityOptions.IsDrillDownEnabled === 'undefined') {
				this.TreeMap.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (typeof this.TreeMap.InteractivityOptions.IgnoreMasterFilters === 'undefined') {
				this.TreeMap.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.TreeMap.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (!(this.TreeMap['FilterString'])) {
			this.TreeMap['FilterString'] = [];
		}else{
			this.TreeMap.FilterString = JSON.parse(JSON.stringify(this.TreeMap.FilterString).replace(/"@null"/gi,null));
		}
		if (typeof this.TreeMap.ShowCaption === 'undefined') {
			this.TreeMap.ShowCaption = true;
		}
		
		this.meta = this.TreeMap;
	}
	
	this.setTreeMapforViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setTreeMap();
		}
		else{
			this.TreeMap = this.meta;
			this.TreeMap.Initialized = true;
		}
		// initialize format options from CHART_XML
		$.each(WISE.util.Object.toArray(self.TreeMap.DataItems.Measure), function(_i, _mea) {
			var dataItemNo = _mea.UniqueName;
			/*dogfoot 트리맵 툴팁 오류 수정 shlim 20200715*/
			$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.TREEMAP_DATA_ELEMENT), function(_j, _item) {
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
			this.TreeMap['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.TreeMap['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.TreeMap['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		var page = window.location.pathname.split('/');
		/* DOGFOOT hsshim 2020-02-06 파이 팔레트 적용 안되는 오류 수정 */
		var dashboardXml = gDashboard.structure.MapOption.DASHBOARD_XML || {};
		
		if(!(this.TreeMap['Palette'])){
			var TreeMapOption = typeof window[self.dashboardid].structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(window[self.dashboardid].structure.MapOption.DASHBOARD_XML.TREEMAP_DATA_ELEMENT);
			$.each(TreeMapOption,function(_i,_treemapOption){
				if(self.TreeMap.ComponentName == _treemapOption.CTRL_NM){
					self.TreeMap['Palette'] = _treemapOption.PALETTE_NM;
					return false;
				}
			})
			if(typeof this.meta.ColorSheme != 'undefined'){
				var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
				this.TreeMap.Palette = new Array();
				$.each(colorList,function(_i,_list){
					self.TreeMap.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
				});
			}
		}
		
		if (typeof this.TreeMap.Name === 'undefined') {
			this.TreeMap.Name = this.Name;	
		}
		if (typeof this.TreeMap.ComponentName === 'undefined') {
			this.TreeMap.ComponentName = this.ComponentName;
		}	
		if (typeof this.TreeMap.DataSource === 'undefined') {
			this.TreeMap.DataSource = this.dataSourceId;
		}else if(this.TreeMap.DataSource != this.dataSourceId){
			this.TreeMap.DataSource = this.dataSourceId;
		}
		if (this.TreeMap.InteractivityOptions) {
			if (typeof this.TreeMap.InteractivityOptions.MasterFilterMode === 'undefined') {
				this.TreeMap.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (typeof this.TreeMap.InteractivityOptions.TargetDimensions === 'undefined') {
				this.TreeMap.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (typeof this.TreeMap.InteractivityOptions.IsDrillDownEnabled === 'undefined') {
				this.TreeMap.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (typeof this.TreeMap.InteractivityOptions.IgnoreMasterFilters === 'undefined') {
				this.TreeMap.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.TreeMap.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (typeof this.TreeMap.IsMasterFilterCrossDataSource === 'undefined') {
			this.TreeMap.IsMasterFilterCrossDataSource = false;
		}
		if (typeof this.TreeMap.FilterString === 'undefined') {
			this.TreeMap.FilterString = [];
		}else{
			this.TreeMap.FilterString = JSON.parse(JSON.stringify(this.TreeMap.FilterString).replace(/"@null"/gi,null));
		}
		if (typeof this.TreeMap.ShowCaption === 'undefined') {
			this.TreeMap.ShowCaption = true;
		}
		
		// preset palette
		
		var page = window.location.pathname.split('/');
	}
	
	/** @Override */
	this.bindData = function(_data,_options) {
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
			self.setTreeMap();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.TreeMap);
			gDashboard.itemGenerateManager.generateItem(self, self.TreeMap);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setTreeMapforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.TreeMap);
			gDashboard.itemGenerateManager.generateItem(self, self.TreeMap);
		}
		else if(this.fieldManager == null && this.meta != undefined){
			this.setTreeMapforViewer();
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}

		
		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" class="img tracking"><img src="'+WISE.Constants.context+'/resources/main/images/ico_sigma.png" alt="기준 측정값 변경"></li>';
			topIconPanel.append(trackingDataContainerHtml);
		}
		
		var dxConfig = this.getDxItemConfig(this.meta);
		
		this.calculatedFields = [];
		/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
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
												rawCaption: _tempDataField,
												suffixEnabled: false,
												type: "dimension",
												tempdata: true,
												nameBySummaryType: "min("+_tempDataField+")",
												nameBySummaryType2: "min_"+_tempDataField
										}
										self.dimensions.push(dataMember);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
				});
			}
		}
		
		var measureKey = this.measures[0];
		if(measureKey == undefined){
			self.currentMeasureName = "";
		}else{
			self.currentMeasureName = measureKey.name;
		}
		
		// self.currentMeasureName = measureKey.caption;
		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'viewer.do') {
			$('#' + self.itemid + '_title').text(self.meta.Name);
		}else{
			$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		}
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap("instance");
		if((this.fieldManager != null && gDashboard.isNewReport != true || WISE.Constants.editmode == 'viewer') && self.IO['IsDrillDownEnabled']){
			self.initDrillDownOperation();
		}
		
		
//		gDashboard.itemGenerateManager.generateDxItem(self, _data);
		
		gDashboard.itemGenerateManager.renderButtons(self);

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
	
	this.resize = function() {

	};
	
	this.functionDo = function(_f){
		switch(_f) {
			
		// edit filter builder
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
				contentTemplate: function(contentElement) {
					var field = [];
					$.each(self.dimensions, function(_i, _field) {
						field.push({ dataField: _field.caption, dataType: 'string' });
					});

                    contentElement.append('<div id="' + self.itemid + '_editFilter">');
                    var html = '<div class="modal-footer" style="padding-bottom:0px;">';
                    html += '<div class="row center">';
                    html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
                    html += '<a id="close" href="#" class="btn neutral close">취소</a>';
                    html += '</div>';
                    html += '</div>';
                    html += '</div>';
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
                            paginate: true
                        });
                        newDataSource.filter(filter);
                        newDataSource.load();
                        
                        //dogfoot 조건 없을 때 필터편집 팝업창 안닫히는 오류 수정 syjin 20210410
                        self.meta.FilterString = filter==null ? [] : filter;
                        
						self.filteredData = newDataSource.items();
						self.bindData(self.filteredData,true);
						if (self.IO.MasterFilterMode !== 'Off') {
							/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
							gDashboard.filterData(self.itemid, []);
						}
                        if(self.meta.FilterString.length > 0) {
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
			if (self.meta.FilterString) {
				self.meta.FilterString = null;
				$('#editFilter').removeClass('on');
				self.filteredData = self.globalData;
				//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
				self.functionBinddata = true;
				self.bindData(self.globalData,true);
				if (self.IO.MasterFilterMode !== 'Off') {
					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
					gDashboard.filterData(self.itemid, []);
				}
			}
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
					self.TreeMap.InteractivityOptions.MasterFilterMode = 'Off';
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
					self.TreeMap.InteractivityOptions.MasterFilterMode = 'Single';
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
			// Both master filter and drill-down cannot be active at the same time. Turn drill-down off.
			if (self.IO.IsDrillDownEnabled) {
				self.terminateDrillDownOperation();	
			}	
			if (self.IO.MasterFilterMode === 'Multiple') {
				$('#' + self.trackingClearId).addClass('invisible');
				self.TreeMap.InteractivityOptions.MasterFilterMode = 'Off';
				self.IO.MasterFilterMode = 'Off';
				self.clearTrackingConditions();
				var reTrackItem = gDashboard.itemGenerateManager.reTrackingCondtionFilterItem();
				if(reTrackItem){
					gDashboard.filterData(reTrackItem.itemid, reTrackItem.trackingData,reTrackItem.dataSourceId);
				}else{
					gDashboard.filterData(self.itemid, self.trackingData);	
				}
				
			} else {
				$('#' + self.trackingClearId).removeClass('invisible');
				self.TreeMap.InteractivityOptions.MasterFilterMode = 'Multiple';
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
				//self.tracked = !self.TreeMap.InteractivityOptions.MasterFilterMode == 'Off' ? false : true;			
				self.meta = self.TreeMap;
				//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
				self.functionBinddata = true;
				//self.bindData(self.globalData,true);
				self.clearTrackingConditions();
				gDashboard.filterData(self.itemid, self.trackingData);
				self.selectFirstPoint();				
			}
		
			break;
		}
		// toggle drill down
		case 'drillDown': {
			if (!(self.dxItem)) {
				break;
			}
			// Both master filter and drill-down cannot be active at the same time. Turn master filter off.
			if (self.IO.MasterFilterMode !== 'Off') {
				self.TreeMap.InteractivityOptions.MasterFilterMode = 'Off';
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
					self.TreeMap.InteractivityOptions.IsDrillDownEnabled = true;
					self.IO.IsDrillDownEnabled = true;
					self.initDrillDownOperation();
				
				$('#' + self.DrilldownClearId).removeClass('invisible');
			} else {
				$('#' + self.DrilldownClearId).addClass('invisible');
				self.terminateDrillDownOperation();
			}
			break;
		}
		// toggle cross data source filtering
		case 'crossFilter': {
			if (!(self.dxItem)) {
				break;
			}
			self.IsMasterFilterCrossDataSource = $('#crossFilter').hasClass('on') ? true : false;
			self.meta.IsMasterFilterCrossDataSource = self.IsMasterFilterCrossDataSource;
			if (self.IsMasterFilterCrossDataSource) {
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				gDashboard.filterData(self.itemid, self.trackingData);
			}
			// If turning cross filter off, clear filter for items with different data sources.
			else {
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
					if (item.ComponentName !== self.ComponentName && item.dataSourceId !== self.dataSourceId) {
						item.tracked = false;
						//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
						self.functionBinddata = true;
						item.bindData(item.globalData, true);
					}
				});
			}
			break;
		}
		// toggle ignore master filter
		case 'ignoreMasterFilter': {
			if (!(self.dxItem)) {
				break;
			}			
			self.IO.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
			self.TreeMap.InteractivityOptions.IgnoreMasterFilters = self.IO.IgnoreMasterFilters;
			self.meta = self.TreeMap;
			self.tracked = !self.TreeMap.InteractivityOptions.IgnoreMasterFilters;
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
			break;
		}
		
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.TreeMap['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.TreeMap['ShowCaption'] = false;
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
                            	
                            	self.TreeMap['Name'] = newName;
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
				var chagePalette = self.TreeMap.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.TreeMap.Palette) != -1
										? self.TreeMap.Palette
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
                                    self.dxItem.option('colorizer', {palette : self.customPalette});
								} else {
                                    self.isCustomPalette = false;
                                    self.dxItem.option('colorizer', {palette : paletteObject2[e.value]});
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.TreeMap.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                            self.dxItem.option('palette', self.TreeMap.Palette);
                            chagePalette = self.TreeMap.Palette;
                            p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.TreeMap.Palette = chagePalette;
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
						$.each(self.dxItem._nodes, function(index, item) {
							if(item.level === -1) return true;
							colorContainer.append('<p>' + item.label 
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

                        $.each(self.dxItem._nodes, function(index, item) {
                        	if(item.level === -1) return true;
							$('#' + self.itemid + '_seriesColor' + index).dxColorBox({
								value: item.color
							});
                        });

                        // confirm and cancel
						$('#ok-hide').on('click', function() {
                            var newPalette = [];
                            $.each(self.dxItem._nodes, function(index, item) {
                            	if(item.level === -1) return true;
                                newPalette[index - 1] = $('#' + self.itemid + '_seriesColor' + index).dxColorBox('instance').option('value');
                            });
                            self.TreeMap['Palette'] = newPalette;
                            self.dxItem.option('colorizer.palette', newPalette);
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
//				var chagePalette = self.TreeMap.Palette;
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
//                        var originalPalette = paletteCollection.indexOf(self.TreeMap.Palette) != -1
//										? self.TreeMap.Palette
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
//                                    var options = {palette : self.customPalette};
//                                    self.dxItem.option('colorizer', options);
//								} else {
//                                    self.isCustomPalette = false;
//                                    var options = {palette : e.value};
//                                    self.dxItem.option('colorizer', options);
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save-ok').on('click', function() {
//                            self.TreeMap.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            p.option('visible', false);
//                        });
//                        $('#save-cancel').on('click', function() {
//                        	var options = {palette : self.TreeMap.Palette};
//                            self.dxItem.option('colorizer', options);
//                            chagePalette = self.TreeMap.Palette;
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.TreeMap.Palette = chagePalette;
//					}
//                });
//                p.option('visible', !(p.option('visible')));
//				break;
//			}
			default: break;
		}
	}
	
	this.menuItemGenerate = function(){
		
		gDashboard.itemGenerateManager.menuItemGenerate(self);

//		if($('#data').length > 0){
//			$('#data').remove();
//		}
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
//		}
//		
//		if($('#design').length > 0){
//			$('#design').remove();
//		}
//		
////		if($('#designMenu').length == 0){
////			$('<li id="designMenu"><a href="#" class="lnb-link txt new"><span>'+ gMessage.get('WISE.message.page.widget.nav.design') +'</span></a></li>').insertBefore('#openReport');	
////		}
//		
////		$('#menulist').append($('<li id="design"><a href="#tab5primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.design') +'</a></li>'));
////		if($('#tab5primary').length == 0){
////			$('.cont_query').append('<ul id="tab5primary" class="lnb-lst-tab" style="margin-top:10px;"><span class="drag-line"></span></ul>');	
////		}
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');	
//		}
//		
//		$('#tab5primary').empty();
//		
//		$('<li class="slide-ui-item"><a id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		
//		menuItemSlideUi();
//		
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
//		}
//		
//		$(  "<h4 class=\"tit-level3\">필터링</h4>" + 
//			"<div class=\"panel-body\">" + 
//			"	<div class=\"design-menu rowColumn\">" + 
//			"		<ul class=\"desing-menu-list col-2\">" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"editFilter\" class=\"functiondo\">" +
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_basicFilter.png\" alt=\"\"><span>필터 편집</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"clearFilter\" class=\"functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>초기화</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"		</ul>" + 
//			"	</div>" + 
//			"</div>" +
//			"<h4 class=\"tit-level3\">상호작용</h4>" + 
//			"<div class=\"panel-body\">" + 
//			"	<div class=\"design-menu rowColumn\">" + 
//			"		<ul class=\"desing-menu-list col-3\">" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"singleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_singleMasterFilter.png\" alt=\"\"><span>단일 마스터<br>필터</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"multipleMasterFilter\" class=\"multi-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_multipleMasterFilter.png\" alt=\"\"><span>다중 마스터<br>필터</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"drillDown\" class=\"multi-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_drillDown.png\" alt=\"\"><span>드릴<br>다운</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"		</ul>" + 
//			"	</div>" + 
//			"</div>" + 
//			"<h4 class=\"tit-level3\">상호작용 설정</h4>" + 
//			"<div class=\"panel-body\">" + 
//			"	<div class=\"design-menu rowColumn\">" + 
//			"		<ul class=\"desing-menu-list col-2\">" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"crossFilter\" class=\"single-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_crossDataSourceFiltering.png\" alt=\"\"><span>교차 데이터<br>소스 필터링</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"			<li>" + 
//			"				<a href=\"#\" id=\"ignoreMasterFilter\" class=\"single-toggle-button functiondo\">" + 
//			"					<img src=\"" + WISE.Constants.context + "/resources/main/images/ico_ignoreMasterFilters.png\" alt=\"\"><span>마스터 필터<br>무시</span>" + 
//			"				</a>" + 
//			"			</li>" + 
//			"		</ul>" + 
//			"	</div>" + 
//			"</div>" 
//		).appendTo($('#tab4primary'));
//		
//		tabUi();
//		designMenuUi();
//		compMoreMenuUi();
//        $('.single-toggle-button').on('click', function(e) {
//            e.preventDefault();
//            $(this).toggleClass('on');
//        });
//        $('.multi-toggle-button').on('click', function(e) {
//            e.preventDefault();
//            var currentlyOn = $(this).parent().parent().find('.multi-toggle-button.on');
//            if ($(this)[0] !== currentlyOn[0]) {
//                currentlyOn.removeClass('on');
//            }
//            $(this).toggleClass('on');
//		});
//		if(self.meta && self.meta.FilterString && self.meta.FilterString.length > 0) {
//			$('#editFilter').addClass('on');
//		}
//        // toggle 'on' status according to grid options
//		if (self.TreeMap && self.TreeMap.InteractivityOptions) {
//			if (self.TreeMap.InteractivityOptions['MasterFilterMode'] === 'Single') {
//				$('#singleMasterFilter').addClass('on');
//			} else if (self.TreeMap.InteractivityOptions['MasterFilterMode'] === 'Multiple') {
//				$('#multipleMasterFilter').addClass('on');
//			}
//			if (self.TreeMap.InteractivityOptions['IsDrillDownEnabled']) {
//				$('#drillDown').addClass('on');
//			}
//			if (self['IsMasterFilterCrossDataSource']) {
//				$('#crossFilter').addClass('on');
//			}
//			if (self.TreeMap.InteractivityOptions['IgnoreMasterFilters']) {
//				$('#ignoreMasterFilter').addClass('on');
//			}
//        }
//        // settings popup
//		$('<div id="editPopup">').dxPopup({
//			height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//        }).appendTo('#tab5primary');
//		// settings popover
//		$('<div id="editPopover">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//		}).appendTo('#tab5primary');
//		// settings popup2
//		$('<div id="editPopup2">').dxPopup({
//			height: 'auto',
//			width: 500,
//			visible: false,
//			showCloseButton: false
//		}).appendTo('#tab4primary');
//		// settings popover2
//		$('<div id="editPopover2">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//		}).appendTo('#tab4primary');
//		
//		
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);
//		});
	}
	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO['MasterFilterMode']) {
			if(self.dxItem){
				this.dxItem.clearSelection();
				
				self.trackingData = [];
				self.selectedPoint = undefined;
				
			
				var clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
				$(clearTrackingImg)
					.attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png')
					.on('mouseover', function() {
						$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
					})
					.on('mouseout', function() {
						$(this).attr('src', WISE.Constants.context + '/images/cont_box_icon_filter_disable.png');
					});
			}
		}
	};
	
	this.selectFirstPoint = function() {
		var dimensions,
			dimensionNames = [];
			self.selectedPoint = self.dxItem.getRootNode().getChild(0);
		if (self.IO.TargetDimensions === 'Series') {
			dimensions = self.seriesDimensions;
			dimensionNames[0] = self.selectedPoint.data.name.split('-');	
			$.each(firstSeries.getAllPoints(), function(i, point) {
				point.select();
			});
		} else {
			dimensions = self.arguments;
			dimensionNames = self.selectedPoint.data.name.split('-');	
			self.selectedPoint.select(true);			
		}
		$.each(dimensions, function(i, dim) {
			var selectedData = {};
			selectedData[dim.name] = dimensionNames[i].trim();
			self.trackingData.push(selectedData);
		});
		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
		gDashboard.filterData(self.itemid, self.trackingData);
	}
	
	/**
	 * Initialize data used for drill-down procedures.
	 */
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
			newDataSource.filter(self.TreeMap.FilterString);
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
		self.TreeMap.InteractivityOptions.IsDrillDownEnabled = false;
		self.IO.IsDrillDownEnabled = false;
		// reset data
		var resetData = self.drillDownData.all();
		self.initDrillDownData(resetData);
		var reformedData = self.reformDataSourceByData(resetData);
		var newDataSource = new DevExpress.data.DataSource({
			store: reformedData,
			paginate: true
		});
		if(self.TreeMap && self.TreeMap.FilterString && self.TreeMap.FilterString.length > 0) {
			newDataSource.filter(self.TreeMap.FilterString);
			newDataSource.load();
		}
		self.dxItem.option('dataSource', newDataSource);
	}
	
	this.renderButtons = function(_itemid) {
//		/* DOGFOOT tbchoi 다운로드 버튼 기능 추가  20200221 */
//		var buttonPanelId = _itemid + '_topicon';
//		var topIconPanel = $('#' + buttonPanelId);
//		// export data
//		
//			var page = window.location.pathname.split('/');
//			if (page[page.length - 1] === 'viewer.do') {
//				if(topIconPanel.children().length != 0){
//					topIconPanel.empty();
//				}
//				$('#export_popover').dxPopover({
//					height: 'auto',
//					width: 195,
//					position: 'bottom',
//					visible: false,
//				});
//				
//				
//				var exportDataId = this.itemid + '_topicon_tree';
//				var exportHtml = '<li id="' + exportDataId + '" title="내보내기" class="img"><img src="' + WISE.Constants.context + '/resources/main/images/ico-download_new.png" alt="이미지 다운로드"></li>';
//				topIconPanel.append(exportHtml);
//				
//				$('#'+exportDataId).off('click').click(function(){
//					var p = $('#export_popover').dxPopover('instance');
//					p.option({
//						target: topIconPanel,
//						contentTemplate: function() {
//							var html = '';
//							html += '<div class="add-item noitem" style="padding:0px;">';
//							html += '	<span class="add-item-head on">다운로드</span>';
//							html += '	<ul class="add-item-body">';
//							html += '		<li id="typeImg" class="exportFunction" title="이미지 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_exportImages.png" alt="이미지 다운로드"><span>이미지 다운로드</span></a></li>';
//							html += '		<li id="typeCsv" class="exportFunction" title="CSV 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcexcell.png" alt="CSV 다운로드"><span>CSV 다운로드</span></a></li>';
//							html += '		<li id="typeTxt" class="exportFunction" title="TXT 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_txt.png" alt=""><span>TXT 다운로드</span></a></li>';
//							html += '	</ul>';
//							html += '</div>';
//	                        return html;
//						},
//						onContentReady: function() {
//							$('.exportFunction').each(function(){
//								$(this).click(function(){
//									var exportType = $(this).attr('id');
//									self.csvData = self.filteredData;
//									console.log(self);
//									if(exportType == 'typeImg'){
//										self.dxItem.exportTo(self.Name,'PNG');
//									}
//									else if(exportType == 'typeCsv'){
//										gDashboard.downloadManager.downloadCSV(self);
//									}else if(exportType == 'typeTxt'){
//										gDashboard.downloadManager.downloadTXT(self);
//									}
//									var param = {
//										'pid': WISE.Constants.pid,
//										'userId':userJsonObject.userId,
//										'reportType':gDashboard.reportType
//									}
//									$.ajax({
//										type : 'post',
//										data : param,
//										cache : false,
//										url : WISE.Constants.context + '/report/exportLog.do',
//										complete: function() {
//											gProgressbar.hide();
//										}
//									});
//									p.hide();
//								});
//							});
//							
//						}
//					});
//					p.show();
//				});
//		}else{
//			$('#export_popover').dxPopover({
//				height: 'auto',
//				width: 195,
//				position: 'bottom',
//				visible: false,
//			});
//			
//			topIconPanel.find('.export').remove(); // tbchoi 20200227 아이콘 중복 생성 에러 수정
//			var exportDataId = this.itemid + '_topicon_exp';
//			var exportHtml = '<li id="' + exportDataId + '" title="내보내기" class="img"><img src="' + WISE.Constants.context + '/resources/main/images/ico-download_new.png" alt="이미지 다운로드"></li>';
//            topIconPanel.find('.lm_maximise').before(exportHtml);
//			
//			$('#'+exportDataId).off('click').click(function(){
//				var p = $('#export_popover').dxPopover('instance');
//				p.option({
//					target: topIconPanel,
//					contentTemplate: function() {
//						var html = '';
//						html += '<div class="add-item noitem" style="padding:0px;">';
//						html += '	<span class="add-item-head on">다운로드</span>';
//						html += '	<ul class="add-item-body">';
//						html += '		<li id="typeImg" class="exportFunction" title="이미지 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_exportImages.png" alt="이미지 다운로드"><span>이미지 다운로드</span></a></li>';
//						html += '		<li id="typeCsv" class="exportFunction" title="CSV 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcexcell.png" alt="CSV 다운로드"><span>CSV 다운로드</span></a></li>';
//						html += '		<li id="typeTxt" class="exportFunction" title="TXT 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_txt.png" alt=""><span>TXT 다운로드</span></a></li>';
//						html += '	</ul>';
//						html += '</div>';
//                        return html;
//					},
//					onContentReady: function() {
//						$('.exportFunction').each(function(){
//							$(this).click(function(){
//								var exportType = $(this).attr('id');
//								self.csvData = self.filteredData;
//								console.log(self);
//								if(exportType == 'typeImg'){
//									self.dxItem.exportTo(self.Name,'PNG');
//								}
//								else if(exportType == 'typeCsv'){
//									gDashboard.downloadManager.downloadCSV(self);
//								}else if(exportType == 'typeTxt'){
//									gDashboard.downloadManager.downloadTXT(self);
//								}
//
//								var param = {
//									'pid': WISE.Constants.pid,
//									'userId':userJsonObject.userId,
//									'reportType':gDashboard.reportType
//								}
//								$.ajax({
//									type : 'post',
//									data : param,
//									cache : false,
//									url : WISE.Constants.context + '/report/exportLog.do',
//									complete: function() {
//										gProgressbar.hide();
//									}
//								});
//								p.hide();
//							});
//						});
//						
//					}
//				});
//				p.show();
//			});
//			
//		}
//		
//		if (self.IO && self.IO['MasterFilterMode'] && gDashboard.reportType !== 'AdHoc') {
//			self.trackingClearId = self.itemid + '_topicon_tracking_clear';
//			
//			//20200506 ajkim 마스터필터가 적용된 경우에만 마스터 필터 초기화 활성화 dogfoot
//			var trackingClearHtml;
//			if(self.IO['MasterFilterMode'] === 'Off')
//				trackingClearHtml = '<li id="' + self.trackingClearId + '" title="마스터 필터 초기화" class="nofilter invisible"></li>';
//			else
//				trackingClearHtml = '<li id="' + self.trackingClearId + '" title="마스터 필터 초기화" class="nofilter"></li>';
//			
//			//2020.01.22 MKSONG 아이콘 수정 DOGFOOT
//			
//			topIconPanel.find('.lm_maximise').before(trackingClearHtml);
//			
//			$("#" + self.trackingClearId).click(function() {
//				self.clearTrackingConditions();
//				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
//				gDashboard.filterData(self.itemid, self.trackingData);
//			});
//		}
//		
//		if(self.IO && self.IO['IsDrillDownEnabled'] && gDashboard.reportType !== 'AdHoc'){
//			self.DrilldownClearId = self.itemid + '_topicon_drilldown_clear';
//			//2020.01.22 MKSONG 아이콘 수정 DOGFOOT
//			var DrillDownClearHtml = '<li id="' + self.DrilldownClearId + '" title="드릴업" class="back"></li>';
//			topIconPanel.find('.lm_maximise').before(DrillDownClearHtml);
//			
//			$("#" + self.DrilldownClearId).click(function(_e) {
//				self.drillUp();
//			});
//		}
//			
//		$('#'+_itemid + '_tracking_data_container').empty();
//		if (this.measures && this.measures.length > 1) {
//			var valueListId = _itemid + '_topicon_vl';
//			var popoverid = _itemid + '_topicon_vl_popover';
//			
//			var listHtml = '<li id="' + valueListId + '" href="#" style="position:relative; left: -5px; top: -6px"><img src="' + WISE.Constants.context + '/images/cont_box_icon_layer.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer.png\'" alt="Select Panel" title="Select Panel"></li>';
//			$('#' + _itemid + '_tracking_data_container').append(listHtml);
//			if($('#'+this.itemid+'editTreemapPopover').length == 0 ){
//				$('<div id="'+this.itemid+'editTreemapPopover">').dxPopover({
//					height: 'auto',
//					width: 'auto',
//					position: 'bottom',
//					visible: false
//				}).appendTo('#wrapper');
//			}
//			var p = $('#'+this.itemid+'editTreemapPopover').dxPopover('instance');
//			
//			
//			var temphtml = "<div>";
//			temphtml += '<div class="add-item noitem">';
//			$.each(this.measures, function(_i, _vo) {
//				if(_vo.name !== self.currentMeasureName)
//				    temphtml += '<div class="select-style" data-key="' + (_vo.uniqueName) + '"><span data-key="' + (_vo.uniqueName) + '">' + _vo.caption + '</span></a></div>';
//				else
//				    temphtml += '<div class="select-style selected" data-key="' + (_vo.uniqueName) + '"><span data-key="' + (_vo.uniqueName) + '">' + _vo.caption + '</span></a></div>';
//			});
//			temphtml += '</div>';
//			temphtml += '</div>'; 
//			
//			p.option({
//				target: '#'+valueListId,
//				contentTemplate: function(contentElement) {
//					$(temphtml).appendTo(contentElement);
//					$('.select-style').on('click',function(_e){
//						p.hide();
//						var targetPanelId = _e.target.getAttribute('data-key');
//						var selectedMeasure;
//						$.each(self.measures,function(_i,_mea){
//							if(_mea.uniqueName == targetPanelId){
//								selectedMeasure = _mea;
//								return false;
//							}
//						});
//						var page = window.location.pathname.split('/');
//						if (page[page.length - 1] === 'viewer.do') {
//							$('#' + self.itemid + '_title').text(self.meta.Name);
//						}else{
//							$('#' + self.itemid + '_title > .lm_title').text(self.Name);
//						}
//						var dxConfig = self.getDxItemConfig(self.meta);
//						self.currentMeasureName = selectedMeasure.caption;
//						$('.select-style.selected').removeClass('selected');
//						$(_e.currentTarget).addClass('selected');
//						dxConfig.dataSource = self.deleteDuplecateData(self.filteredData,selectedMeasure);
//						self.dxItem = $("#" + self.itemid).dxTreeMap(dxConfig).dxTreeMap("instance");
//					});
//				},
////				visible:false
//			})
//			$('#' + _itemid + '_topicon').off('click').on('click',function(){
//				p.option('visible', !(p.option('visible')));
//			});		
//		}
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
		
		var Dimension = WISE.util.Object.toArray(this.meta.DataItems.Dimension);
		var Measure =  WISE.util.Object.toArray(MeasureKey);
		
		$.each(Dimension,function(_i,_Dim){
			selectArray.push(_Dim.DataMember);
			FieldArray.push(_Dim.DataMember);
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
					str.push(_obj[_Dim.DataMember]);
				});
				$.each(Measure,function(_i,_Mea){
					//2020.02.04 mksong SQLLIKE doSqlLike 트리맵 적용 dogfoot
					object['value'] = _obj[_Mea.captionBySummaryType];
					if(object['value'] == 0){
						zeroValueQuantity++;
					}
				});
				
//				object['name'] = str.join(' - ');
				//2020.05.26 MKSONG 연세대 트리맵 노드별 이름에 측정값 캡션 추가 DOGFOOT
				object['name'] = str.join(' - ') + " - " + Measure[0].caption;
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
	};
	
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
				object['value'] = _obj[_Mea.nameBySummaryType];
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
				object['value'] = _obj[_Mea.nameBySummaryType];
			});
			
			object['name'] = str.join(' - ');
			resultArr.push(object);
		});
		
		return resultArr;
	}
	
};

function checkingItem(_data) {
	return !_data.items.length;
};

WISE.libs.Dashboard.item.TreeMapGenerator.PanelManager = function() {
	var self = this;
	
	this.itemid; // TreeMap chart item id, chartItem
	this.dataSourceId;
	this.valuePanel = {};
	this.treeMapContainerIdBucket = [];	
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
		this.treeMapContainerIdBucket = [];
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
			for(var i = 0; i < self.seriesDimensions.length; i++){
				if(self.seriesDimensions[i].TopNEnabled===true && self.seriesDimensions[i].name == nowDim){
					if(self.seriesDimensions[i].TopNCount > 0){
						self.topN = self.seriesDimensions[i].TopNCount;
						self.TopNMember = self.seriesDimensions[i].name;
					}else{
						self.topN = 5;
						self.TopNMember = self.seriesDimensions[i].name;
					}
					self.topMesure = self.seriesDimensions[i].TopNMeasure;
					self.otherShow = self.seriesDimensions[i].TopNShowOthers;
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
		
		//시리즈 차원 존재유무 //없을 시 기능 동작 x
		if (self.seriesDimensions != undefined){
			if(self.seriesDimensions.length == 0){
				self.seriesDimensions.push({name:"false"});
			}
		}
		
		//넘어온 차원이 차원그룹이고 차원그룹이 topN이 아닐경우 현재 함수를 넘김 
		if(self.seriesDimensions[0].name != undefined && self.seriesDimensions[0].name == nowDim && self.TopNMember != nowDim){
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
};

WISE.libs.Dashboard.TreeMapFieldManager = function() {
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
//		var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
		
		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText; 
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['UNI_NM'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['UNI_NM'] = $(_fieldlist[i]).attr('UNI_NM')
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
