WISE.libs.Dashboard.item.ScatterPlotMatrixGenerator = function() {
	var self = this;

	this.type = 'SCATTER_PLOT_MATRIX';

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
	
	this.ScatterPlotMatrix = [];
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
	
	this.setScatterPlotMatrix = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.ScatterPlotMatrix['ComponentName'] = this.ComponentName;
		this.ScatterPlotMatrix['Name'] = this.Name;
		this.ScatterPlotMatrix['DataSource'] = this.dataSourceId;
		
		this.ScatterPlotMatrix['DataItems'] = this.fieldManager.DataItems;
		this.ScatterPlotMatrix['Arguments'] = this.fieldManager.Arguments;
		this.ScatterPlotMatrix['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		this.ScatterPlotMatrix.HiddenMeasures = self.fieldManager.HiddenMeasures;
		
		this.meta = this.ScatterPlotMatrix;
		
		if (!(this.ScatterPlotMatrix['Palette'])) {
			this.ScatterPlotMatrix['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ScatterPlotMatrix.InteractivityOptions) {
			if (!(this.ScatterPlotMatrix.InteractivityOptions.MasterFilterMode)) {
				this.ScatterPlotMatrix.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ScatterPlotMatrix.InteractivityOptions.TargetDimensions)) {
				this.ScatterPlotMatrix.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ScatterPlotMatrix.InteractivityOptions.IgnoreMasterFilters)) {
				this.ScatterPlotMatrix.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ScatterPlotMatrix.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ScatterPlotMatrix['Legend'])) {
			this.ScatterPlotMatrix['Legend'] = {
					Visible : true,
					Position : "RightOuter"
			}
		}
		
		if (!(this.ScatterPlotMatrix.AxisY)) {
			this.ScatterPlotMatrix.AxisY = {
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
		
		if (!(this.ScatterPlotMatrix.AxisX)) {
			this.ScatterPlotMatrix.AxisX = {
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
				Separator: true,
				Overlapping: false
			};
		}
		
		if(!(this.ScatterPlotMatrix.Round)){
			this.ScatterPlotMatrix.Round = {
					Min: 4,
					Max: 20
			}
		}
		
		if(!this.ScatterPlotMatrix.LayoutOption){
			this.ScatterPlotMatrix.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#000000',
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
		if(!this.ScatterPlotMatrix['ZoomAble']){
			this.ScatterPlotMatrix.ZoomAble = 'none'
		}
	};
	
	this.setScatterPlotMatrixforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setScatterPlotMatrix();
		}
		else{
			this.ScatterPlotMatrix = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.ScatterPlotMatrix['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.ScatterPlotMatrix['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.ScatterPlotMatrix['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.ScatterPlotMatrix.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.ScatterPlotMatrix['Palette'])) {
			this.ScatterPlotMatrix['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var ScatterPlotMatrixOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SCATTER_PLOT_MATRIX_DATA_ELEMENT);
				
				$.each(ScatterPlotMatrixOption,function(_i,_ScatterPlotMatrixOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _ScatterPlotMatrixOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _ScatterPlotMatrixOption.CTRL_NM;
					}
					if(self.ScatterPlotMatrix.ComponentName == CtrlNM){
						self.ScatterPlotMatrix['Palette'] = _ScatterPlotMatrixOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.ScatterPlotMatrix.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.ScatterPlotMatrix.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ScatterPlotMatrix.InteractivityOptions) {
			if (!(this.ScatterPlotMatrix.InteractivityOptions.MasterFilterMode)) {
				this.ScatterPlotMatrix.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ScatterPlotMatrix.InteractivityOptions.TargetDimensions)) {
				this.ScatterPlotMatrix.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ScatterPlotMatrix.InteractivityOptions.IgnoreMasterFilters)) {
				this.ScatterPlotMatrix.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ScatterPlotMatrix.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ScatterPlotMatrix['Legend'])) {
			this.ScatterPlotMatrix['Legend'] = {
					Visible : true,
					Position : "RightOuter"
			}
		}
		
		if (!(this.ScatterPlotMatrix.AxisY)) {
			this.ScatterPlotMatrix.AxisY = {
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
		
		if (!(this.ScatterPlotMatrix.AxisX)) {
			this.ScatterPlotMatrix.AxisX = {
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
				Separator: true,
				Overlapping: false
			};
		}
		
		if(!(this.ScatterPlotMatrix.Round)){
			this.ScatterPlotMatrix.Round = {
					Min: 4,
					Max: 20
			}
		}
		
		if(!this.ScatterPlotMatrix.LayoutOption){
			this.ScatterPlotMatrix.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#000000',
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
		if(!this.ScatterPlotMatrix['ZoomAble']){
			this.ScatterPlotMatrix.ZoomAble = 'none'
		}
	}
	
	this.setScatterPlotMatrixForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setScatterPlotMatrix();
		}
		else{
			this.ScatterPlotMatrix = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.ScatterPlotMatrix['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.ScatterPlotMatrix['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.ScatterPlotMatrix['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.ScatterPlotMatrix.HiddenMeasures = self.fieldManager.HiddenMeasures;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.ScatterPlotMatrix['Palette'])) {
			this.ScatterPlotMatrix['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var ScatterPlotMatrixOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.SCATTER_PLOT_MATRIX_DATA_ELEMENT);
				
				$.each(ScatterPlotMatrixOption,function(_i,_ScatterPlotMatrixOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _ScatterPlotMatrixOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _ScatterPlotMatrixOption.CTRL_NM;
//					}
					if(self.ScatterPlotMatrix.ComponentName == CtrlNM){
						self.ScatterPlotMatrix['Palette'] = _ScatterPlotMatrixOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.ScatterPlotMatrix.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.ScatterPlotMatrix.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.ScatterPlotMatrix.InteractivityOptions) {
			if (!(this.ScatterPlotMatrix.InteractivityOptions.MasterFilterMode)) {
				this.ScatterPlotMatrix.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.ScatterPlotMatrix.InteractivityOptions.TargetDimensions)) {
				this.ScatterPlotMatrix.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.ScatterPlotMatrix.InteractivityOptions.IgnoreMasterFilters)) {
				this.ScatterPlotMatrix.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ScatterPlotMatrix.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.ScatterPlotMatrix['Legend'])) {
			this.ScatterPlotMatrix['Legend'] = {
					Visible : true,
					Position : "RightOuter"
			}
		}
		
		if (!(this.ScatterPlotMatrix.AxisY)) {
			this.ScatterPlotMatrix.AxisY = {
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
		
		if (!(this.ScatterPlotMatrix.AxisX)) {
			this.ScatterPlotMatrix.AxisX = {
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
				Separator: true,
				Overlapping: false
			};
		}
		
		if(!(this.ScatterPlotMatrix.Round)){
			this.ScatterPlotMatrix.Round = {
					Min: 4,
					Max: 20
			}
		}
		
		if(!this.ScatterPlotMatrix.LayoutOption){
			this.ScatterPlotMatrix.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						color: '#000000',
						size: 12
					},
					Label : {
						family: '맑은 고딕',
						color: '#000000',
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
		if(!this.ScatterPlotMatrix['ZoomAble']){
			this.ScatterPlotMatrix.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setScatterPlotMatrix();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.ScatterPlotMatrix);
			gDashboard.itemGenerateManager.generateItem(self, self.ScatterPlotMatrix);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setScatterPlotMatrixforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.ScatterPlotMatrix);
			gDashboard.itemGenerateManager.generateItem(self, self.ScatterPlotMatrix);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.ScatterPlotMatrix)) {
			this.setScatterPlotMatrixForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.ScatterPlotMatrix);
			gDashboard.itemGenerateManager.generateItem(self, self.ScatterPlotMatrix);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setScatterPlotMatrixForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.ScatterPlotMatrix);
			gDashboard.itemGenerateManager.generateItem(self, self.ScatterPlotMatrix);
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
		self.fScatterPlotMatrix(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,measureKey));
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
			gDashboard.updateReportLog();
		}
		
//		gDashboard.itemGenerateManager.generateDxItem(self, _data);
	};
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);
	}
	
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if (self.dxItem){
				d3.selectAll('#' + self.itemid + ' .legend text').style('text-decoration', 'none').attr("filter", "false");
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
			self.fScatterPlotMatrix(self.filteredData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('#' + self.itemid + ' .legend text[filter="true"]').style("text-decoration", 'underline').attr("filter", "true");
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		
//		self.fScatterPlotMatrix(self.filteredData, self.measures, self.dimensions, 
//				self.deleteDuplecateData(self.filteredData));
//		d3.selectAll('.bubbles[filter="true"]').style("text-decoration", 'underline').attr("filter", "true");
//		gProgressbar.hide();
//	};
	
	this.fScatterPlotMatrix = function(jsonData, measures, dimensions, dupleData) {
		
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;
		self.resizeData = dupleData;
		d3.select("#"+self.itemid).selectAll('svg').remove();
		d3.select("#"+self.itemid).selectAll('div').remove();
		
		var svgWidth = $('#'+self.itemid).width(),
		svgHeight = $('#'+self.itemid).height();

		var margin = {top : -10, left: 30, bottom : -30, right : -30};

		if(self.meta.Legend.Visible){
			if(self.meta.Legend.Position.indexOf("Bottom") > -1){
				margin.bottom = 10;
				margin.top = -25;
			}else if(self.meta.Legend.Position.indexOf("Left") > -1){
				margin.left = 80;
				margin.right = 30;
			}else if(self.meta.Legend.Position.indexOf("Right") > -1){
				margin.left = -20;
				margin.right = 130;
			}else if(self.meta.Legend.Position.indexOf("Top") > -1){
				margin.top = 10;
			}
		}
		
		var height = svgHeight - margin.top - margin.bottom;
		var width = svgWidth - margin.left - margin.right;
		
		if(width < 0) width = 0;
		if(height < 0) height = 0;
		var svgSize = width> height? height : width,
		
		
		padding = 20,
		size = (svgSize - padding * 4) / 4;
		var moveH = (svgWidth - (size * 4)) / 2 + margin.left;
		var moveV =  (svgHeight - (size * 4)) / 2 + margin.top;
		

		
		if(gDashboard.reportType == "StaticAnalysis"){
			/*dogfoot 산점도 매트릭스 추가 shlim 20201109*/     
			padding = 140 / self.dimensions.length
			if(padding < 20) padding =20
			size = (svgSize - padding * (self.dimensions.length)) / (self.dimensions.length);
			if(size > 310) size = 310
		    moveH = (svgWidth - (size * (self.dimensions.length))) / 2 + margin.left;
		    moveV =  (svgHeight - (size * (self.dimensions.length))) / 2 + margin.top;
		}
		
		if(size < 20) size = 20;
		var x = d3.scaleLinear()
		.range([padding / 2, size - padding / 2]);

		var y = d3.scaleLinear()
		.range([size - padding / 2, padding / 2]);

		var currentIndex = 0;
		var prevIndex = null;
		
		var xAxis = d3.axisBottom()
		.scale(x)
		.ticks(6).tickFormat(function(d, i) {
			if(!self.meta.AxisX.Visible) return '';
			if(prevIndex > 3 && i === 0)
				currentIndex ++;
			prevIndex = i;
			var currentDimension =self.dimensions[currentIndex].name;
			if(typeof dupleData[0][currentDimension] === "string"){
			    return tempJson[currentDimension][d];
			}
			
			return formatX(d);
		});

		var yAxis = d3.axisLeft()
		.scale(y)
		.ticks(6).tickFormat(function(d, i) {
			if(!self.meta.AxisY.Visible) return '';
			if(prevIndex > 3 && i === 0)
				currentIndex ++;
			prevIndex = i;
			var currentDimension =self.dimensions[currentIndex].name;
			if(typeof dupleData[0][currentDimension] === "string"){
			    return tempJson[currentDimension][d];
			}
			
			return formatY(d);
		});

		var color = d3.scaleOrdinal(gDashboard.d3Manager.getPalette(self));

		var domainByTrait = {},
		traits = d3.keys(dupleData[0]).filter(function(d) { return d !== "dimension"; }),
		traitsY = d3.keys(dupleData[0]).filter(function(d) { return d !== "dimension"; }).reverse(),
		n = traits.length;

		var tempJson = {};
		traits.forEach(function(trait) {
			domainByTrait[trait] = d3.extent(dupleData, function(d) {
				if(typeof d[trait] === "string"){
                    if(!tempJson[trait]){
                    	tempJson[trait] = [];
                    }

                    if(tempJson[trait].indexOf(d[trait]) === -1){
                    	tempJson[trait].push(d[trait]);
                    }

                    return tempJson[trait].indexOf(d[trait]);
				}
				return d[trait];
			});
		});

		xAxis.tickSize(size * n);
		yAxis.tickSize(-size * n);

		var brush = d3.brush()
		.on("start", brushstart)
		.on("brush", brushmove)
		.on("end", brushend)
		.extent([[0,0],[size,size]]);

		var svg;
		if(gDashboard.reportType == "StaticAnalysis"){
			svg = d3.select('#'+self.itemid).classed("scatter-matrix", true).append("svg")
			.attr("width", svgWidth)
			.attr("height", svgHeight)
			.append("g")
			.attr("transform", "translate(" +((svgWidth - (size * (self.dimensions.length))) / 2 + margin.left) + "," + ((svgHeight - (size * (self.dimensions.length))) / 2 + margin.top) + ")");
		}else{
			svg = d3.select('#'+self.itemid).classed("scatter-matrix", true).append("svg")
			.attr("width", svgWidth)
			.attr("height", svgHeight)
			.append("g")
			.attr("transform", "translate(" +((svgWidth - (size * 4)) / 2 + margin.left) + "," + ((svgHeight - (size * 4)) / 2 + margin.top) + ")");
		}
		
		
		
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
		currentIndex = 0; 
		prevIndex = null;
		/*dogfoot 통계 산점도 매트릭스 구분 shlim 20201109*/     
		var cell;
		if(gDashboard.reportType == "StaticAnalysis"){
			svg.selectAll(".x.axis")
			.data(traitsY)
			.enter().append("g")
			.attr("class", "x axis")
			.attr("transform", function(d, i) { return "translate(" + (n - i - 1) * size + ",0)"; })
			.each(function(d) { x.domain(domainByTrait[d]); d3.select(this).call(xAxis); });

			currentIndex = 0;
			prevIndex = null;
			svg.selectAll(".y.axis")
			.data(traits)
			.enter().append("g")
			.attr("class", "y axis")
			.attr("transform", function(d, i) { return "translate(0," + i * size + ")"; })
			.each(function(d) { y.domain(domainByTrait[d]); d3.select(this).call(yAxis); });
		
		
			cell = svg.selectAll(".cell")
			.data(cross(traitsY,traits))
			.enter().append("g")
			.attr("class", "cell")
			.attr("transform", function(d) { return "translate(" + (n - d.i - 1) * size + "," + d.j * size + ")"; })
			.each(plot);

		// Titles for the diagonal.
			

			svg.selectAll(".dimy")
			    .data(traits)
			    .enter().append("text")
			      .text(function(d){ return d })
			      .classed("day", true)
			      .attr("x", 0)
			      .attr("y", function(d, i) { return i * size })
			      .style("text-anchor", "end")
			      .attr("transform", "translate(-50," + size / 2 + ")")

			  
			  svg.selectAll(".dimx")
			    .data(traits)
			    .enter().append("text")
			      .text(function(d){ return d })
			      .classed("hour", true)
			      .attr("x", function(d, i) { return i * size })
//			      .attr("y", 0)
			      .attr("y", function(d, i) { return gDashboard.reportType == "StaticAnalysis" ? traits.length * (size+10) : 0})
			      .attr("transform", function(d, i) { return "translate(" + (n - i - 1) * size + ",0)"; })
			      .style("text-anchor", "middle")
			      .attr("transform", "translate(" + size / 2 + ", 0)")

		}else{
            
            svg.selectAll(".x.axis")
			.data(traits)
			.enter().append("g")
			.attr("class", "x axis")
			.attr("transform", function(d, i) { return "translate(" + (n - i - 1) * size + ",0)"; })
			.each(function(d) { x.domain(domainByTrait[d]); d3.select(this).call(xAxis); });

			currentIndex = 0;
			prevIndex = null;
			svg.selectAll(".y.axis")
			.data(traits)
			.enter().append("g")
			.attr("class", "y axis")
			.attr("transform", function(d, i) { return "translate(0," + i * size + ")"; })
			.each(function(d) { y.domain(domainByTrait[d]); d3.select(this).call(yAxis); });

			cell = svg.selectAll(".cell")
			.data(cross(traits, traits))
			.enter().append("g")
			.attr("class", "cell")
			.attr("transform", function(d) { return "translate(" + (n - d.i - 1) * size + "," + d.j * size + ")"; })
			.each(plot);

		// Titles for the diagonal.
			cell.filter(function(d) { return d.i === d.j; }).append("text")
			.attr("x", padding)
			.attr("y", padding)
			.attr("dy", ".71em")
			.text(function(d) { return d.x; });
		}
		

		cell.call(brush);

		function plot(p) {
			var cell = d3.select(this);

			x.domain(domainByTrait[p.x]);
			y.domain(domainByTrait[p.y]);

			cell.append("rect")
			.attr("class", "frame")
			.attr("x", padding / 2)
			.attr("y", padding / 2)
			.attr("width", size - padding)
			.attr("height", size - padding);

			cell.selectAll("circle")
			.data(dupleData)
			.enter().append("circle")
			.attr("cx", function(d) { return x(typeof d[p.x] === "string"? tempJson[p.x].indexOf(d[p.x]) : d[p.x]); })
			.attr("cy", function(d) { return y(typeof d[p.y] === "string"? tempJson[p.y].indexOf(d[p.y]) : d[p.y]); })
			.attr("r", self.meta.Round.Min)
			.style("fill", function(d) {
				var returnVal;
				if(gDashboard.reportType == "StaticAnalysis"){
					returnVal = color(p.x+"-"+p.y)
				}else{
					returnVal = color(d.dimension)
				}
				return returnVal; 
			});
			
		}
		
		if(self.meta.Legend.Visible){

			  var startp = svg.append("g").attr("class", "legendbox").attr("id", "mylegendbox");
			  // this is not nice, we should calculate the bounding box and use that
			  var legend_tabs = [0, 120, 200, 375, 450];
			  var legend = startp.selectAll(".legend")
			      .data(color.domain().slice())
			      .enter().append("g")
			      .attr("class", "legend")
			      var maxIndex = -1;
			  if(self.meta.Legend.Position.indexOf("Center") > -1){
				  legend.attr("transform", function(d, i) { return "translate(" +  ( svgWidth /color.domain().slice().length * i - moveH) + ", -45)"; });
			  }else{
				  legend.attr("transform", function(d, i) {
					  if(maxIndex === - 1 && 30 * (i + 2) - moveV - margin.top > svgHeight) maxIndex = i;
					  return "translate("+ (self.meta.Legend.Position.indexOf("Left") > -1?  -(moveH) : svgWidth - 180 - moveH + 75) + ", "+ ( 30 * i -moveV) +")";
				  });
			  }

			  legend.append("rect")
			  .attr("x", 0)
			  .attr("width", 10)
			  .attr("height", 10)
			  .style("fill", function(d, i){
				  if(i >= maxIndex && maxIndex !== -1) return d3.rgb(0, 0, 0, 0);
				  return color(d);
			  });

			  legend.append("text")
			  .attr("x", 22)
			  .attr("y", 5)
			  .attr("dy", ".35em")
			  .style("text-anchor", "begin")
			  .style("font-size" , self.meta.LayoutOption.Legend.size + 'px')
			  .style("font-family" , self.meta.LayoutOption.Legend.family)
			  .style("fill" , self.meta.LayoutOption.Legend.color)
			  .attr("cursor", "pointer")
			  .text(function(d, i) { 
				  if(i == maxIndex && maxIndex !== -1) return '. . .';
				  else if(i > maxIndex && maxIndex !== -1) return '';
				  return d;
			  })
			      .attr("filter", function(d){
			    	  for (var index = 0; index < self.tempTrackingData.length; index++) {
			    			var check = 0;
		       				$.each(self.dimensions.slice(4), function(i, dim){
		       					if(self.tempTrackingData[index][dim.caption] === d.split(" - ")[i])
		       						check++;
		       				})
		       				if(check === self.dimensions.length - 4){
		       					return "true";
		       				}
		       			}
			    	  return "false";
			      }) .on("click", function(d){
				    	switch(self.meta.InteractivityOptions.MasterFilterMode){
			    		case 'Single':
			    			self.trackingData = [];
			    			self.tempTrackingData = [];
			    			if(d3.select(this).attr("filter") === "true"){
			    				d3.selectAll('#' + self.itemid + ' .legend text').style('text-decoration', 'none').attr("filter", "false");
					    	}else{
					    		//선택 모두 해제
					    		d3.selectAll('#' + self.itemid + ' .legend text').style('text-decoration', 'none').attr("filter", "false");
								
					    		d3.select(this).style("text-decoration", 'underline').attr("filter", "true");
					    		
//			       				var selectedData = {};
//				       			selectedData[self.dimensions[0].name] = d.data[0];
					    		var tempSelectedData = {};
				       			$.each(self.dimensions.slice(4), function(i, dim){
				       				var selectedData = {};
					    			selectedData[dim.caption] = d.split(" - ")[i]
					    			tempSelectedData[dim.caption] = d.split(" - ")[i]
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
					    		d3.select(this).style("text-decoration", 'underline').style('text-decoration', 'none').attr("filter", "false");
					    		for (var index = 0; index < self.tempTrackingData.length; index++) {
					    			var check = 0;
				       				$.each(self.dimensions.slice(4), function(i, dim){
				       					if(self.tempTrackingData[index][dim.caption] === d.split(" - ")[i])
				       						check++;
				       				})
				       				if(check === self.dimensions.length - 4){
				       					self.tempTrackingData.splice(index, 1);
				       					index--;
				       				}
				       			}
					    	}else{
					    		d3.select(this).style("text-decoration", 'underline').attr("filter", "true");
//					    		self.tempTrackingData.push(d.dimension.split(" - ")[i]);
					    		tempSelectedData = {}
					    		$.each(self.dimensions.slice(4), function(i, dim){
					    			tempSelectedData[dim.caption] = d.split(" - ")[i]
				       			})
				       			self.tempTrackingData.push(tempSelectedData);
					    	}
					    	
					    	self.trackingData = [];
					    	
					    	$.each(self.dimensions.slice(4), function(i, dim){
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

			  d3.selectAll('#' + self.itemid + " .axis path")
			      .style("fill", "none")
			      .style("stroke", "#000")
			      .style("shape-rendering", "crispEdges")

			  d3.selectAll('#' + self.itemid + " .axis line")
			      .style("fill", "none")
			      .style("stroke", "#000")
			      .style("shape-rendering", "crispEdges")

			   var movesize = 0;
			  var movesizeV = 30;
			  movesizeV = self.meta.Legend.Position.indexOf("Bottom") > -1? svgHeight + 10: 25;
			  d3.selectAll('#' + self.itemid + " .legendbox").attr("transform", "translate(" + movesize  + ","+ movesizeV +")");
		  }
		
		// 다운로드 오류
		d3.selectAll('#'+self.itemid + ' .axis line').style("stroke", '#ddd');
		d3.selectAll('#'+self.itemid + ' .axis .frame').style("shape-rendering", 'crispEdges');
		
		d3.selectAll('#'+ self.itemid +" .x.axis text")
	    .attr("font-size", self.meta.LayoutOption.AxisX.size+'px')
	    .attr("font-family", self.meta.LayoutOption.AxisX.family)
	  	.style("fill", self.meta.LayoutOption.AxisX.color)

	  	d3.selectAll('#'+ self.itemid +" .y.axis text")
	    .attr("font-size", self.meta.LayoutOption.AxisY.size+'px')
	    .attr("font-family", self.meta.LayoutOption.AxisY.family)
	  	.style("fill", self.meta.LayoutOption.AxisY.color)
	  	
	  	d3.selectAll('#'+ self.itemid +" .cell text")
	    .attr("font-size", self.meta.LayoutOption.Label.size+'px')
	    .attr("font-family", self.meta.LayoutOption.Label.family)
	  	.style("fill", self.meta.LayoutOption.Label.color)
	  	
	  	 $('#'+self.itemid).css('display', 'block');
		
		if(!self.meta.AxisX.Overlapping){
			d3.selectAll('#'+ self.itemid +" .x.axis").each(function(){
		  		var prevX;
		  		d3.select(this).selectAll('.tick').each(function(){
		  			var currX = d3.select(this).attr("transform").substring(10, d3.select(this).attr("transform").indexOf(','))*1;
		  			if(typeof prevX === 'undefined'){
	            	    prevX = currX + d3.select(this).select('text').node().getComputedTextLength() / 2;
	                }else{
	                	var textSize = d3.select(this).select('text').node().getComputedTextLength();

	                	if(currX - textSize / 2 < prevX){
	                		d3.select(this).select('text').style('display', 'none');
	                	}else{
	                		prevX = currX + textSize / 2;
	                	}
	                }
		  		})
		  	})
		}
	  			
		var brushCell;

		// Clear the previously-active brush, if any.
		function brushstart(p) {
			if (brushCell !== this) {
				d3.select(brushCell).call(brush.move, null);
				brushCell = this;
				x.domain(domainByTrait[p.x]);
				y.domain(domainByTrait[p.y]);
			}
		}

		// Highlight the selected circles.
		function brushmove(p) {
			var e = d3.brushSelection(this);
			svg.selectAll("circle").classed("hidden", function(d) {
				return !e
				? false
						: (
								e[0][0] > x(+d[p.x]) || x(+d[p.x]) > e[1][0]
								|| e[0][1] > y(+d[p.y]) || y(+d[p.y]) > e[1][1]
						);
			});
		}

		// If the brush is empty, select all circles.
		function brushend() {
			var e = d3.brushSelection(this);
			if (e === null) svg.selectAll(".hidden").classed("hidden", false);
		}

		function cross(a, b) {
			var c = [], n = a.length, m = b.length, i, j;
			for (i = -1; ++i < n;) for (j = -1; ++j < m;) c.push({x: a[i], i: i, y: b[j], j: j});
			return c;
		}
		

		function formatY(n) {
			var NumericY = self.meta.AxisY
			if(Number.isInteger(n)){
				return WISE.util.Number.unit(n, NumericY.FormatType, NumericY.Unit, NumericY.Precision, NumericY.Separator, undefined, NumericY.MeasureFormat, NumericY.SuffixEnabled);	
			}else{
			    return WISE.util.Number.unit(n, NumericY.FormatType, NumericY.Unit, 2, NumericY.Separator, undefined, NumericY.MeasureFormat, NumericY.SuffixEnabled);		
			}
		}
		  
		function formatX(n) {
			var NumericX = self.meta.AxisX
			if(Number.isInteger(n)){
				return WISE.util.Number.unit(n, NumericX.FormatType, NumericX.Unit, NumericX.Precision, NumericX.Separator, undefined, NumericX.MeasureFormat, NumericX.SuffixEnabled);	
			}else{
				return WISE.util.Number.unit(n, NumericX.FormatType, NumericX.Unit, 2, NumericX.Separator, undefined, NumericX.MeasureFormat, NumericX.SuffixEnabled);		
			}
		}
	};

	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
};


WISE.libs.Dashboard.ScatterPlotMatrixFieldManager = function() {
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
