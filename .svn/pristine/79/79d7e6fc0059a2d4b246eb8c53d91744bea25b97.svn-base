WISE.libs.Dashboard.item.ScatterPlot2Generator = function() {
	var self = this;

	this.type = 'SCATTER_PLOT2';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	this.HiddenMeasures = [];
	
	var dataMember;
	var Exprname;
	var FilterArray = [];
	
	this.ScatterPlot2 = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	this.customPalette = [];
	this.isCustomPalette = false;
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [];
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	this.trackingData = [];
	this.tempTrackingData = [];
	
	/**
	 * @param _item:
	 *            meta object
	 */
	var CheckCurrentFilter;
	this.getDxItemConfig = function(_item) {

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
			size:{
				width : $('#'+self.itemid).width(),
				height : $('#'+self.itemid).height(),
			},
			tooltip: {
				enabled: true,
				zIndex: 21,
				customizeTooltip:function(_pointInfo){
					var text = '<b>' + _pointInfo.node.data.name + '</b>' + '<br/>' +"<b>" +self.currentMeasureName+"</b> : " +WISE.util.Number.unit(_pointInfo.value,'O',0);
					ret = {html: text};
					return ret;
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
	
	this.setScatterPlot2 = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.ScatterPlot2['ComponentName'] = this.ComponentName;
		this.ScatterPlot2['Name'] = this.Name;
		this.ScatterPlot2['DataSource'] = this.dataSourceId;
		
		this.ScatterPlot2['DataItems'] = this.fieldManager.DataItems;
		this.ScatterPlot2['Arguments'] = this.fieldManager.Arguments;
		this.ScatterPlot2['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.ScatterPlot2.HiddenMeasures = self.fieldManager.HiddenMeasures;
		
		this.meta = this.ScatterPlot2;
		
		if (!(this.ScatterPlot2['Palette'])) {
			this.ScatterPlot2['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ScatterPlot2.InteractivityOptions) {
			if (!(this.ScatterPlot2.InteractivityOptions.MasterFilterMode)) {
				this.ScatterPlot2.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ScatterPlot2.InteractivityOptions.TargetDimensions)) {
				this.ScatterPlot2.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ScatterPlot2.InteractivityOptions.IgnoreMasterFilters)) {
				this.ScatterPlot2.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ScatterPlot2.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ScatterPlot2['Legend'])) {
			this.ScatterPlot2['Legend'] = {
					Visible : true,
					Position : "RightOuter"
			}
		}
		
		if (!(this.ScatterPlot2.AxisY)) {
			this.ScatterPlot2.AxisY = {
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
				Separator: true
			};
		}
		
		if (!(this.ScatterPlot2.AxisX)) {
			this.ScatterPlot2.AxisX = {
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
				Separator: true
			};
		}
		
		if(!(this.ScatterPlot2.Round)){
			this.ScatterPlot2.Round = {
					Min: 5,
					Max: 20
			}
		}
		
		if(!this.ScatterPlot2.LayoutOption){
			this.ScatterPlot2.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						size: 12
					},
					AxisX : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		if(!this.ScatterPlot2['ZoomAble']){
			this.ScatterPlot2.ZoomAble = 'none'
		}
	};
	
	this.setScatterPlot2forOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setScatterPlot2();
		}
		else{
			this.ScatterPlot2 = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.ScatterPlot2['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.ScatterPlot2['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.ScatterPlot2['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.ScatterPlot2.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.ScatterPlot2['Palette'])) {
			this.ScatterPlot2['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var ScatterPlot2Option = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SCATTER_PLOT2_DATA_ELEMENT);
				
				$.each(ScatterPlot2Option,function(_i,_ScatterPlot2Option){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _ScatterPlot2Option.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _ScatterPlot2Option.CTRL_NM;
					}
					if(self.ScatterPlot2.ComponentName == CtrlNM){
						self.ScatterPlot2['Palette'] = _ScatterPlot2Option.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.ScatterPlot2.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.ScatterPlot2.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ScatterPlot2.InteractivityOptions) {
			if (!(this.ScatterPlot2.InteractivityOptions.MasterFilterMode)) {
				this.ScatterPlot2.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ScatterPlot2.InteractivityOptions.TargetDimensions)) {
				this.ScatterPlot2.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ScatterPlot2.InteractivityOptions.IgnoreMasterFilters)) {
				this.ScatterPlot2.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ScatterPlot2.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ScatterPlot2['Legend'])) {
			this.ScatterPlot2['Legend'] = {
					Visible : true,
					Position : "RightOuter"
			}
		}
		
		if (!(this.ScatterPlot2.AxisY)) {
			this.ScatterPlot2.AxisY = {
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
				Separator: true
			};
		}
		
		if (!(this.ScatterPlot2.AxisX)) {
			this.ScatterPlot2.AxisX = {
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
				Separator: true
			};
		}
		
		if(!(this.ScatterPlot2.Round)){
			this.ScatterPlot2.Round = {
					Min: 5,
					Max: 20
			}
		}
		
		if(!this.ScatterPlot2.LayoutOption){
			this.ScatterPlot2.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						size: 12
					},
					AxisX : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		if(!this.ScatterPlot2['ZoomAble']){
			this.ScatterPlot2.ZoomAble = 'none'
		}
	}
	
	this.setScatterPlot2ForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setScatterPlot2();
		}
		else{
			this.ScatterPlot2 = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.ScatterPlot2['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.ScatterPlot2['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.ScatterPlot2['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.ScatterPlot2.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.ScatterPlot2['Palette'])) {
			this.ScatterPlot2['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var ScatterPlot2Option = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SCATTER_PLOT2_DATA_ELEMENT);
				
				$.each(ScatterPlot2Option,function(_i,_ScatterPlot2Option){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _ScatterPlot2Option.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _ScatterPlot2Option.CTRL_NM;
//					}
					if(self.ScatterPlot2.ComponentName == CtrlNM){
						self.ScatterPlot2['Palette'] = _ScatterPlot2Option.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.ScatterPlot2.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.ScatterPlot2.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ScatterPlot2.InteractivityOptions) {
			if (!(this.ScatterPlot2.InteractivityOptions.MasterFilterMode)) {
				this.ScatterPlot2.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ScatterPlot2.InteractivityOptions.TargetDimensions)) {
				this.ScatterPlot2.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ScatterPlot2.InteractivityOptions.IgnoreMasterFilters)) {
				this.ScatterPlot2.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ScatterPlot2.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ScatterPlot2['Legend'])) {
			this.ScatterPlot2['Legend'] = {
					Visible : true,
					Position : "RightOuter"
			}
		}
		
		if (!(this.ScatterPlot2.AxisY)) {
			this.ScatterPlot2.AxisY = {
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
				Separator: true
			};
		}
		
		if (!(this.ScatterPlot2.AxisX)) {
			this.ScatterPlot2.AxisX = {
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
				Separator: true
			};
		}
		
		if(!(this.ScatterPlot2.Round)){
			this.ScatterPlot2.Round = {
					Min: 5,
					Max: 20
			}
		}
		
		if(!this.ScatterPlot2.LayoutOption){
			this.ScatterPlot2.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						size: 12
					},
					AxisX : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					AxisY: {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					}
			}
		}
		if(!this.ScatterPlot2['ZoomAble']){
			this.ScatterPlot2.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setScatterPlot2();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.ScatterPlot2);
			gDashboard.itemGenerateManager.generateItem(self, self.ScatterPlot2);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setScatterPlot2forOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.ScatterPlot2);
			gDashboard.itemGenerateManager.generateItem(self, self.ScatterPlot2);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.ScatterPlot2)) {
			this.setScatterPlot2ForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.ScatterPlot2);
			gDashboard.itemGenerateManager.generateItem(self, self.ScatterPlot2);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setScatterPlot2ForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.ScatterPlot2);
			gDashboard.itemGenerateManager.generateItem(self, self.ScatterPlot2);
		}

		self.tempTrackingData = [];
		
		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
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
//								self.dimensions.splice(_i,1);
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
										self.dimensions[_i]=dataMember;
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
		if(measureKey){
	    	var measureCheck = false;
	    	$.each(this.measures, function(i, mea){
	    		if(self.currentMeasureName === mea.caption){
	    			measureKey = mea;
	    			measureCheck = true;
	    			return false;
	    		}
	    	})
			if(!self.currentMeasureName || self.currentMeasureName === "" || !measureCheck)
				self.currentMeasureName = measureKey.caption;
		}

    	//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fScatterPlot2(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
//		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
//		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
//				"instance");
		gDashboard.itemGenerateManager.renderButtons(self);

		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
		}
		
//		gDashboard.itemGenerateManager.generateDxItem(self, _data);
	};
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
	}
	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if (self.dxItem){
				d3.selectAll('#' + self.itemid + ' .bubbles').style('stroke', 'none').attr("filter", "false");
			}
			self.trackingData = [];
			self.tempTrackingData = [];
			self.selectedPoint = undefined;	
		}
	};
	
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
	};
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		if(typeof self.resizeData != 'undefined'){
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fScatterPlot2(self.filteredData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('#' + self.itemid + ' .bubbles[filter="true"]').style('stroke', 'black').style('stroke-width', 2).style('stroke-opacity', 0.7).attr("filter", "true");
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		
//		self.fScatterPlot2(self.filteredData, self.measures, self.dimensions, 
//				self.deleteDuplecateData(self.filteredData));
//		d3.selectAll('.bubbles[filter="true"]').style('stroke', 'black').style('stroke-width', 2).style('stroke-opacity', 0.7).attr("filter", "true");
//		gProgressbar.hide();
//	};
	
	this.fScatterPlot2 = function(jsonData, measures, dimensions, dupleData) {
		
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		self.resizeData = dupleData;
		d3.select("#"+self.itemid).selectAll('svg').remove();
		d3.select("#"+self.itemid).selectAll('div').remove();
		// set the dimensions and margins of the graph
		var margin = {top: 60, right: 50, bottom: 60, left: 100};
		if(self.meta.Legend.Position === "LeftOuter" && self.meta.Legend.Visible){
			margin.left = 200;
		}else if(self.meta.Legend.Position === 'RightOuter' && self.meta.Legend.Visible){
			margin.right = 150;
		}else if(self.meta.Legend.Position.indexOf("Bottom") > -1 && self.meta.Legend.Visible){
			margin.bottom = 120;
		}else if(self.meta.Legend.Visible){
			margin.top = 100;
		}
		
		var	svgWidth = $("#"+self.itemid).width(),
			svgHeight = $("#"+self.itemid).height(),
		    width = svgWidth - margin.left - margin.right,
		    height = svgHeight - margin.top - margin.bottom;
		 var scaleK = 0;

				
		// append the svg object to the body of the page
		var svg = d3.select("#"+self.itemid)
		  .append("svg")
		    .attr("width", width + margin.left + margin.right)
		    .attr("height", height + margin.top + margin.bottom)
		  .append("g")
		    .attr("transform",
		          "translate(" + margin.left + "," + margin.top + ")");
        
        var zoomCnt = 0;
		function zoomable(){
			 var zoom = d3.zoom().on("zoom", function (d,zz) {
				 if(pressKey['z'] || pressKey['Z'])
						  d3.select('#'+self.itemid).select('g').attr("transform", function(){ 
								  if(zoomCnt==0){
										d3.event.transform.x = d3.event.sourceEvent.layerX
										d3.event.transform.y = d3.event.sourceEvent.layerY
										d3.event.transform.k =1;
								  }
								  if(d3.event.transform.k <= 1){
									zoomCnt++;
									d3.event.transform.x = 0
									d3.event.transform.y = 0
									d3.event.transform.k =1;
									zoomable();
									return "translate(" + margin.left + "," + margin.top + ")";
								  }
								  if(d3.event.transform.x ===0 && d3.event.transform.y ===0){
										d3.event.transform.x = d3.event.sourceEvent.layerX
										d3.event.transform.y = d3.event.sourceEvent.layerY
								   }
								   zoomCnt++
								return d3.event.transform;
							})
						})

			  d3.select('#'+self.itemid).select('svg').call(zoom)
		}
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}
        
		//Read the data
			  // ---------------------------//
			  // AXIS AND SCALE //
			  // ---------------------------//
	
			  // Add X axis
		var data = dupleData;
		var arrX = data.map(function(d){return d[self.dimensions[0].caption]});
		var maxX = d3.max(arrX);
		var minX = d3.min(arrX);
		
		minX -= (maxX - minX)/10;
		
		
		if(typeof arrX[0] === "string"){
			arrX = arrX.reduce(function(a, b){
				if(a.indexOf(b) < 0) a.push(b);
				return a;
			}, [])
			maxX = arrX.length - 1;
			minX = -1;
		}
		var tickSize = Math.round(width/150);
		
		if(tickSize >= 8)
			tickSize = 7;
		  var x = d3.scaleLinear()
		    .domain([minX, maxX])
		    .range([ 0, width ]);
		  svg.append("g").attr('class', 'scatter-x')
		    .attr("transform", "translate(0," + height + ")")
		    .call(d3.axisBottom(x).ticks(tickSize).tickFormat(function(d) { return formatX(d, typeof arrX[0]); }));

		  // Add X axis label:
		  svg.append("text")
		      .attr("text-anchor", "end")
		      .attr("x", width)
		      .attr("y", height+50 )
		      .text(typeof self.meta.AxisX.Title === 'undefined'? self.dimensions[0].caption : self.meta.AxisX.Title)
		      .attr("font-size", self.meta.LayoutOption.AxisX.size * 1 + 2)
		      .attr("font-family", self.meta.LayoutOption.AxisX.family)
	      	  .style("fill", self.meta.LayoutOption.AxisX.color);

		  
		  var arrY = data.map(function(d){return d[self.dimensions[1].caption]});
		  var maxY = d3.max(arrY);
		  var minY = d3.min(arrY);
		  minY -= (maxY - minY)/10;
		  
		  if(typeof arrY[0] === "string"){
			  	arrY = arrY.reduce(function(a, b){
					if(a.indexOf(b) < 0) a.push(b);
					return a;
				}, [])
				maxY = arrY.length - 1;
				minY = -1;
		  }
		  // Add Y axis
		  var y = d3.scaleLinear()
		    .domain([minY, maxY])
		    .range([ height, 0]);
		  svg.append("g").attr('class', 'scatter-y')
		    .call(d3.axisLeft(y).tickFormat(function(d) { return formatY(d, typeof arrY[0]); }));

		  // Add Y axis label:
		  svg.append("text")
		      .attr("text-anchor", "end")
		      .attr("x", 0)
		      .attr("y", -20 )
		      .text(typeof self.meta.AxisY.Title === 'undefined'? self.dimensions[1].caption : self.meta.AxisY.Title)
		      .attr("text-anchor", "start")
		      .attr("font-size", self.meta.LayoutOption.AxisY.size * 1 + 2)
		      .attr("font-family", self.meta.LayoutOption.AxisY.family)
	      	  .style("fill", self.meta.LayoutOption.AxisY.color)

		      var z;
		  // Add a scale for bubble size
		  if(self.measures.length > 0){
			  var arr = data.map(function(d){return d[self.measures[0].captionBySummaryType]});
			  var max = d3.max(arr);
			  var min = d3.min(arr);
			  
			  z = d3.scaleSqrt()
			    .domain([min, max])
			    .range([ self.meta.Round.Min, self.meta.Round.Max]);
		  }else{
			z = function(){
				return self.meta.Round.Min;
			}
		  }
		  
		  var dimNames = [];
		  
		  $.each(data, function(i, data){
			  if($.inArray(data['dimension'], dimNames) === -1) dimNames.push(data['dimension']);
		  })
		  
		  self.paletteData = dimNames;
		  
		  var palette = gDashboard.d3Manager.getPalette(self);
		  
		  // Add a scale for bubble color
		  var myColor = d3.scaleOrdinal()
		    .domain(dimNames)
		    .range(palette);


		  // ---------------------------//
		  // TOOLTIP //
		  // ---------------------------//

		  // -1- Create a tooltip div that is hidden by default:
		  var tooltip = d3.select("#"+self.itemid)
		    .append("div")
		      .style("opacity", 0)
		      .attr("class", "scatter-plot-tooltip")
		      .style("background-color", "black")
		      .style("border-radius", "5px")
		      .style("padding", "10px")
		      .style("color", "white")

		  // -2- Create 3 functions to show / update (when mouse move but
			// stay on same circle) / hide the tooltip
		  var showTooltip = function(d) {
			  
			  var tooltipHtml = d.dimension;
			  tooltipHtml += ('<br>' + self.dimensions[0].caption + ': ' + d[self.dimensions[0].caption]);
			  tooltipHtml += ('<br>' + self.dimensions[1].caption + ': ' + d[self.dimensions[1].caption]);
			
			  if(self.measures.length > 0){
				  tooltipHtml += ('<br>' + self.measures[0].caption + ': ' + d[self.measures[0].captionBySummaryType]);
			  }
			  //			  $.each(self.dimensions, function(i, dim){
//				  if(i == 0) tooltipHtml = d[dim.caption];
//				  else tooltipHtml += (' - ' + d[dim.caption]);
//			  });
		    tooltip
		      .transition()
		      .duration(200)
		    tooltip
		      .style("opacity", 1)
		      .html(tooltipHtml)
		      .style("left", (d3.mouse(this)[0] + margin.left) + "px")
		      .style("top", (d3.mouse(this)[1] + 100) + "px")
		  }
		  var moveTooltip = function(d) {
		    tooltip
		      .style("left", (d3.mouse(this)[0]+margin.left) + "px")
		      .style("top", (d3.mouse(this)[1]+100) + "px")
		  }
		  var hideTooltip = function(d) {
		    tooltip
		      .transition()
		      .duration(200)
		      .style("opacity", 0)
		  }


		  // ---------------------------//
		  // HIGHLIGHT GROUP //
		  // ---------------------------//

		  // What to do when one group is hovered
		  var highlight = function(d){
		    // reduce opacity of all groups
		    d3.selectAll('#' + self.itemid + " .bubbles").style("opacity", .05)
		    // expect the one that is hovered
		    d3.selectAll("._"+d.replace(/(\s*)/g, "").replace(/\//g, '\\/')).style("opacity", 0.8)
		  }

		  // And when it is not hovered anymore
		  var noHighlight = function(d){
		    d3.selectAll('#' + self.itemid + " .bubbles").style("opacity", 0.8)
		  }


		  // ---------------------------//
		  // CIRCLES //
		  // ---------------------------//

		  // Add dots
		  svg.append('g')
		    .selectAll("dot")
		    .data(data)
		    .enter()
		    .append("circle")
		      .attr("class", function(d) { return 'bubbles _' + d['dimension'].replace(/(\s*)/g, "") })
		      .attr("cx", function (d) { return typeof arrX[0] === 'string' ? x(arrX.indexOf(d[self.dimensions[0].caption])) : x(d[self.dimensions[0].caption]); } )
		      .attr("cy", function (d) { return typeof arrY[0] === 'string' ? y(arrY.indexOf(d[self.dimensions[1].caption])) : y(d[self.dimensions[1].caption]); } )
		      .attr("r", function (d) { return z(self.measures[0]? d[self.measures[0].captionBySummaryType] : '')} )
		      .style("fill", function (d) { return myColor( d['dimension']); } )
		      .style("opacity", 0.8)
		      .attr("filter", function(d){
		    	  for (var index = 0; index < self.tempTrackingData.length; index++) {
		    			var check = 0;
	       				$.each(self.dimensions.slice(2), function(i, dim){
	       					if(self.tempTrackingData[index][dim.caption] === d.dimension.split(" - ")[i])
	       						check++;
	       				})
	       				if(check === self.dimensions.length - 2){
	       					return "true";
	       				}
	       			}
		    	  return "false";
		      })
		    // -3- Trigger the functions for hover
		    .on("mouseover", showTooltip )
		    .on("mousemove", moveTooltip )
		    .on("mouseleave", hideTooltip ).attr("cursor", "pointer")
		    .on("click", function(d){
		    	switch(self.meta.InteractivityOptions.MasterFilterMode){
	    		case 'Single':
	    			self.trackingData = [];
	    			self.tempTrackingData = [];
	    			if(d3.select(this).attr("filter") === "true"){
	    				d3.selectAll('#' + self.itemid + ' .bubbles').style('stroke', 'none').attr("filter", "false");
			    	}else{
			    		//선택 모두 해제
			    		d3.selectAll('#' + self.itemid + ' .bubbles').style('stroke', 'none').attr("filter", "false");
						
			    		d3.selectAll('#' + self.itemid + ' .bubbles._'+d.dimension.replace(/(\s*)/g, "").replace(/\//g, '\\/')).style('stroke', 'black').style('stroke-width', 2).style('stroke-opacity', 0.7).attr("filter", "true");
			    		
//	       				var selectedData = {};
//		       			selectedData[self.dimensions[0].name] = d.data[0];
			    		var tempSelectedData = {};
		       			$.each(self.dimensions.slice(2), function(i, dim){
		       				var selectedData = {};
			    			selectedData[dim.caption] = d.dimension.split(" - ")[i]
			    			tempSelectedData[dim.caption] = d.dimension.split(" - ")[i]
			    			self.trackingData.push(selectedData);
		       			})
		       			
		       			self.tempTrackingData.push(tempSelectedData);
			    	}
	    			/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
		       		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
	           		gDashboard.filterData(self.itemid, self.trackingData);
	    		break;
		    	case 'Multiple':
			    	if(d3.select(this).attr("filter") === "true"){
			    		d3.selectAll('.bubbles._'+d.dimension.replace(/(\s*)/g, "").replace(/\//g, '\\/')).style('stroke', 'none').attr("filter", "false");
			    		for (var index = 0; index < self.tempTrackingData.length; index++) {
			    			var check = 0;
		       				$.each(self.dimensions.slice(2), function(i, dim){
		       					if(self.tempTrackingData[index][dim.caption] === d.dimension.split(" - ")[i])
		       						check++;
		       				})
		       				if(check === self.dimensions.length - 2){
		       					self.tempTrackingData.splice(index, 1);
		       					index--;
		       				}
		       			}
			    	}else{
			    		d3.selectAll('.bubbles._'+d.dimension.replace(/(\s*)/g, "").replace(/\//g, '\\/')).style('stroke', 'black').style('stroke-width', 2).style('stroke-opacity', 0.7).attr("filter", "true");
//			    		self.tempTrackingData.push(d.dimension.split(" - ")[i]);
			    		tempSelectedData = {}
			    		$.each(self.dimensions.slice(2), function(i, dim){
			    			tempSelectedData[dim.caption] = d.dimension.split(" - ")[i]
		       			})
		       			self.tempTrackingData.push(tempSelectedData);
			    	}
			    	
			    	self.trackingData = [];
			    	
			    	$.each(self.dimensions.slice(2), function(i, dim){
			    		var unique = self.tempTrackingData.map(function(val, index){
			    			return val[dim.caption];
			    		}).filter(function(val, index, arr){
			    			return arr.indexOf(val) === index;
			    		});
			    		
			    		for(var j = 0; j < unique.length; j++){
			    			var selectedData = {};
			    			selectedData[dim.caption] = unique[j]
			    			self.trackingData.push(selectedData);
			    		}
			    	})
			    	/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
		       		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
	           		gDashboard.filterData(self.itemid, self.trackingData);
		    	break;
	    	  }
		    })

		    $('#'+self.itemid).css("display", "block");
		    d3.selectAll('#'+ self.itemid +" .scatter-x text")
		    .attr("font-size", self.meta.LayoutOption.AxisX.size+'px')
		    .attr("font-family", self.meta.LayoutOption.AxisX.family)
		  	.style("fill", self.meta.LayoutOption.AxisX.color)

             function wrap() {
				var s = d3.select(this),
					textLength = s.node().getComputedTextLength(),
					text = s.text();
				while (textLength > (90) && text.length > 0) {
					text = text.slice(0, -1);
					s.text(text + '...');
					textLength = s.node().getComputedTextLength();
				}
			} 

		  	d3.selectAll('#'+ self.itemid +" .scatter-y text")
		    .attr("font-size", self.meta.LayoutOption.AxisY.size+'px')
		    .attr("font-family", self.meta.LayoutOption.AxisY.family)
		  	.style("fill", self.meta.LayoutOption.AxisY.color)
		  	.each(wrap).append('title').text(function(d){ return formatY(d, typeof arrY[0]); });

		    if(self.meta.Legend.Visible){
		    	// ---------------------------//
			    // LEGEND //
			    // ---------------------------//

//		    	if(self.measures.length > 0){
//		    		// Add legend: circles
//				    var valuesToShow = [min, (max+min) / 2, max]
//				    
//				    var xCircle = width + 30;
//				    var xLabel = width + 80;
//				    
//				    if(self.meta.Legend.Position.indexOf("LeftInner") > -1){
//				    	xCircle = 50;
//				    	xLabel = 100;
//				    }
//				    else if(self.meta.Legend.Position.indexOf("LeftOuter") > -1){
//				    	xCircle = -150;
//				    	xLabel = -100;
//				    }
//				    else if(self.meta.Legend.Position.indexOf("RightInner") > -1){
//				    	xCircle = width - 50;
//				    	xLabel = width;
//				    }
//				    svg
//				      .selectAll("legend")
//				      .data(valuesToShow)
//				      .enter()
//				      .append("circle")
//				        .attr("cx", xCircle)
//				        .attr("cy", function(d){ return height - 100 - z(d) } )
//				        .attr("r", function(d){ return z(d) })
//				        .style("fill", "none")
//				        .attr("stroke", "black")
//
//				    // Add legend: segments
//				    svg
//				      .selectAll("legend")
//				      .data(valuesToShow)
//				      .enter()
//				      .append("line")
//				        .attr('x1', function(d){ return xCircle + z(d) } )
//				        .attr('x2', xLabel)
//				        .attr('y1', function(d){ return height - 100 - z(d) } )
//				        .attr('y2', function(d){ return height - 100 - z(d) } )
//				        .attr('stroke', 'black')
//				        .style('stroke-dasharray', ('2,2'))
//
//				    // Add legend: labels
//				    svg
//				      .selectAll("legend")
//				      .data(valuesToShow)
//				      .enter()
//				      .append("text")
//				        .attr('x', xLabel)
//				        .attr('y', function(d){ return height - 100 - z(d) } )
//				        .text( function(d){ return d } )
//				        .style("font-size", 11)
//				        .attr('alignment-baseline', 'middle')
//
//				    // Legend title
//				    svg.append("text")
//				      .attr('x', xCircle)
//				      .attr("y", height - 100 +30)
//				      .text(self.measures[0].caption)
//				      .attr("text-anchor", "middle")
//		    	}
			   
			    // Add one dot in the legend for each name.
			    var size = 20
			    if(self.meta.Legend.Position.indexOf("Center") === -1){
			    	var xPos = width + 50;
			    	
			    	if(self.meta.Legend.Position.indexOf("RightInner") > -1){
				    	xPos = width - 50;
				    }
				    else if(self.meta.Legend.Position.indexOf("LeftInner") > -1){
				    	xPos = 30
				    }
				    else if(self.meta.Legend.Position.indexOf("LeftOuter") > -1){
				    	xPos = -150
				    }
			    	 
			    	var lastIndex = (svgHeight - 120) / (size + 5);
				    if(lastIndex < 1) lastIndex = 1;
				    var labelData = dimNames.slice(0, Math.floor(lastIndex));
				    
				    if(labelData.length !== dimNames.length)
				    	labelData[labelData.length - 1] = ' . . . ';
				    
				    svg.selectAll("myrect")
				      .data(labelData.length === dimNames.length? labelData : labelData.slice(0, labelData.length - 1))
				      .enter()
				      .append("circle")
				        .attr("cx", xPos)
				        .attr("cy", function(d,i){ return 10 + i*(size+5)})
				        .attr("r", 7)
				        .style("fill", function(d){ return myColor(d)})
				        .on("mouseover", highlight)
				        .on("mouseleave", noHighlight)

				    // Add labels beside legend dots
				    svg.selectAll("mylabels")
				      .data(labelData)
				      .enter()
				      .append("text")
				        .attr("x", xPos+ size*.8)
				        .attr("y", function(d,i){ return i * (size + 5) + (size/2)})
				        .style("fill", function(d){ return myColor(d)})
				        .text(function(d){ return d})
				        .attr("font-family",self.meta.LayoutOption.Legend.family)
				    	.attr("font-size", self.meta.LayoutOption.Legend.size+'px')
				        .attr("text-anchor", "left")
				        .style("alignment-baseline", "middle")
				        .on("mouseover", highlight)
				        .on("mouseleave", noHighlight)
			    }else {
			    	size = 100;
			    	var yPos = -70;
			    	if(self.meta.Legend.Position.indexOf("Bottom") > -1){
				    	yPos = height + 80;
				    }
			    	 
			    	var lastIndex = (svgWidth - 60) / (size + 5);
				    if(lastIndex < 1) lastIndex = 1;
				    var labelData = dimNames.slice(0, Math.floor(lastIndex));
				    
				    if(labelData.length !== dimNames.length)
				    	labelData[labelData.length - 1] = ' . . . ';
				    
				    svg.selectAll("myrect")
				      .data(labelData.length === dimNames.length? labelData : labelData.slice(0, labelData.length - 1))
				      .enter()
				      .append("circle")
				      .attr("cx",  function(d,i){ return 10 + i*(size+5)})
				      .attr("cy", yPos)
				      .attr("r", 7)
				      .style("fill", function(d){ return myColor(d)})
				      .on("mouseover", highlight)
				      .on("mouseleave", noHighlight)

				    // Add labels beside legend dots
				    svg.selectAll("mylabels")
				      .data(labelData)
				      .enter()
				      .append("text")
				      .attr("x", function(d,i){ return i * (size + 5) + 20})
				      .attr("y", yPos + .8)
				      .style("fill", function(d){ return myColor(d)})
				      .text(function(d){ return d})
				      .attr("font-family",self.meta.LayoutOption.Legend.family)
				      .attr("font-size", self.meta.LayoutOption.Legend.size+'px')
				      .attr("text-anchor", "left")
				      .style("alignment-baseline", "middle")
				      .on("mouseover", highlight)
				      .on("mouseleave", noHighlight)
			    }
		    }
		  
		function formatY(n, type) {
			var result =  Math.round(n);
			if(self.ScatterPlot2.AxisY){
				var NumericY = self.meta.AxisY
				if(!NumericY.Visible){
					return '';
				}else{
					if(type === "string"){
						if(n % 1 == 0  && n > -1) return arrY[n];
						else return '';
					}
				    return WISE.util.Number.unit(result, NumericY.FormatType, NumericY.Unit, NumericY.Precision, NumericY.Separator, undefined, NumericY.MeasureFormat, NumericY.SuffixEnabled);	
				}
		  	}
		}
		  
		function formatX(n, type) {
			var result =  Math.round(n);
			if(self.ScatterPlot2.AxisX){
				var NumericX = self.meta.AxisX
				if(!NumericX.Visible){
					return '';
				}else{
					if(type === "string"){
						if(n % 1 == 0  && n > -1) return arrX[n];
						else return '';
					}
				    return WISE.util.Number.unit(result, NumericX.FormatType, NumericX.Unit, NumericX.Precision, NumericX.Separator, undefined, NumericX.MeasureFormat, NumericX.SuffixEnabled);	
				}
		  	}
		}
		    
	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
};


WISE.libs.Dashboard.ScatterPlot2FieldManager = function() {
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
		var NumericFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
		
		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText; 
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
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
	
	this.setHiddenMeasuresByField = function(_hiddenMeasure){
	 	this.HiddenMeasures = {'Measure' : []};
	 	_.each(_hiddenMeasure,function(_a){
	 		var Value = {'UniqueName' : _a.uniqueName};
	 		self.HiddenMeasures['Measure'].push(Value);
	 	})
	 	return self.HiddenMeasures;
	 };
};
