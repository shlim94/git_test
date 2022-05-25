WISE.libs.Dashboard.item.CoordinateDotGenerator = function() {
	var self = this;

	this.type = 'COORDINATE_DOT';

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
	
	this.CoordinateDot = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	this.customPalette = [];
	this.isCustomPalette = false;
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [""];
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
	
	this.setCoordinateDot = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.CoordinateDot['ComponentName'] = this.ComponentName;
		this.CoordinateDot['Name'] = this.Name;
		this.CoordinateDot['DataSource'] = this.dataSourceId;
		
		this.CoordinateDot['DataItems'] = this.fieldManager.DataItems;
		this.CoordinateDot['Arguments'] = this.fieldManager.Arguments;
		this.CoordinateDot['Values'] = this.fieldManager.Values;
	
		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;
		
		this.meta = this.CoordinateDot;
		
		if (!(this.CoordinateDot['Palette'])) {
			this.CoordinateDot['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.CoordinateDot.InteractivityOptions) {
			if (!(this.CoordinateDot.InteractivityOptions.MasterFilterMode)) {
				this.CoordinateDot.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.CoordinateDot.InteractivityOptions.TargetDimensions)) {
				this.CoordinateDot.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.CoordinateDot.InteractivityOptions.IgnoreMasterFilters)) {
				this.CoordinateDot.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.CoordinateDot.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.CoordinateDot.AxisY)) {
			this.CoordinateDot.AxisY = {
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
		
		if (!(this.CoordinateDot.AxisX)) {
			this.CoordinateDot.AxisX = {
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
				Precision: gDashboard.reportType === 'StaticAnalysis' ?2 : 0,
				Separator: true
			};
		}
		
		if (!(this.CoordinateDot['Legend'])) {
			this.CoordinateDot['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.CoordinateDot.LayoutOption){
			this.CoordinateDot.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
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
		
		if(!this.CoordinateDot['ZoomAble']){
			this.CoordinateDot.ZoomAble = 'none'
		}
		
	};
	
	this.setCoordinateDotforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setCoordinateDot();
		}
		else{
			this.CoordinateDot = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.CoordinateDot['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.CoordinateDot['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.CoordinateDot['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.CoordinateDot['Palette'])) {
			this.CoordinateDot['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var CoordinateDotOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.COORDINATE_DOT_DATA_ELEMENT);
				
				$.each(CoordinateDotOption,function(_i,_CoordinateDotOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _CoordinateDotOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _CoordinateDotOption.CTRL_NM;
					}
					if(self.CoordinateDot.ComponentName == CtrlNM){
						self.CoordinateDot['Palette'] = _CoordinateDotOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.CoordinateDot.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.CoordinateDot.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		if (!(this.CoordinateDot.AxisY)) {
			this.CoordinateDot.AxisY = {
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
		if (!(this.CoordinateDot.AxisX)) {
			this.CoordinateDot.AxisX = {
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
				Precision: gDashboard.reportType === 'StaticAnalysis' ?2 : 0,
				Separator: true
			};
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.CoordinateDot.InteractivityOptions) {
			if (!(this.CoordinateDot.InteractivityOptions.MasterFilterMode)) {
				this.CoordinateDot.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.CoordinateDot.InteractivityOptions.TargetDimensions)) {
				this.CoordinateDot.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.CoordinateDot.InteractivityOptions.IgnoreMasterFilters)) {
				this.CoordinateDot.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.CoordinateDot.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.CoordinateDot['Legend'])) {
			this.CoordinateDot['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.CoordinateDot.LayoutOption){
			this.CoordinateDot.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
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
		if(!this.CoordinateDot['ZoomAble']){
			this.CoordinateDot.ZoomAble = 'none'
		}
		
	}
	
	this.setCoordinateDotForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setCoordinateDot();
		}
		else{
			this.CoordinateDot = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.CoordinateDot['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.CoordinateDot['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.CoordinateDot['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 주임 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.CoordinateDot['Palette'])) {
			this.CoordinateDot['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var CoordinateDotOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.COORDINATE_DOT_DATA_ELEMENT);
				
				$.each(CoordinateDotOption,function(_i,_CoordinateDotOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _CoordinateDotOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _CoordinateDotOption.CTRL_NM;
//					}
					if(self.CoordinateDot.ComponentName == CtrlNM){
						self.CoordinateDot['Palette'] = _CoordinateDotOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.CoordinateDot.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.CoordinateDot.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		if (!(this.CoordinateDot.AxisY)) {
			this.CoordinateDot.AxisY = {
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
		if (!(this.CoordinateDot.AxisX)) {
			this.CoordinateDot.AxisX = {
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
				Precision: gDashboard.reportType === 'StaticAnalysis' ?2 : 0,
				Separator: true
			};
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.CoordinateDot.InteractivityOptions) {
			if (!(this.CoordinateDot.InteractivityOptions.MasterFilterMode)) {
				this.CoordinateDot.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.CoordinateDot.InteractivityOptions.TargetDimensions)) {
				this.CoordinateDot.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.CoordinateDot.InteractivityOptions.IgnoreMasterFilters)) {
				this.CoordinateDot.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.CoordinateDot.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if (!(this.CoordinateDot['Legend'])) {
			this.CoordinateDot['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		if(!this.CoordinateDot.LayoutOption){
			this.CoordinateDot.LayoutOption = {
					Legend : {
						family: '맑은 고딕',
						size: 12,
						color: '#000000'
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
		if(!this.CoordinateDot['ZoomAble']){
			this.CoordinateDot.ZoomAble = 'none'
		}
	}
	
	/** @Override */
	this.bindData = function(_data) {
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setCoordinateDot();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.CoordinateDot);
			gDashboard.itemGenerateManager.generateItem(self, self.CoordinateDot);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setCoordinateDotforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.CoordinateDot);
			gDashboard.itemGenerateManager.generateItem(self, self.CoordinateDot);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.CoordinateDot)) {
			this.setCoordinateDotForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.CoordinateDot);
			gDashboard.itemGenerateManager.generateItem(self, self.CoordinateDot);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setCoordinateDotForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.CoordinateDot);
			gDashboard.itemGenerateManager.generateItem(self, self.CoordinateDot);
		}

		
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
		
		self.trackingData = [];
		self.tempTrackingData = [];

		//2020.11.03 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('d3');
		self.fCoordinateDot(_data, this.measures, this.dimensions, self.deleteDuplecateData(_data,[]));
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		this.dxItem = $("#" + this.itemid).dxTreeMap(dxConfig).dxTreeMap(
				"instance");
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
				d3.selectAll('#' + self.itemid + ' .coordinate-legend').style('text-decoration', 'none').attr("filter", "false");
			}
			self.trackingData = [];
			self.tempTrackingData = [];
		}
	};
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
	};
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	
//	this.resize = function() {
//		if(self.filteredData){
//			self.fCoordinateDot(self.filteredData, self.measures, self.dimensions, 
//					self.deleteDuplecateData(self.filteredData,self.measures[0]));
//		}
//		
//		d3.selectAll('rect.box[filter="true"]').style('stroke-width', 2.5)
//		gProgressbar.hide();
//	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		var dupledatacheck
		if(typeof self.resizeData != 'undefined'){
		    dupledatacheck = self.resizeData;
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
		    self.fCoordinateDot(self.filteredData, self.measures, self.dimensions, 
		    		dupledatacheck);
	//		self.fParallelCoordinates2(self.filteredData, self.measures, self.dimensions, 
	//							self.deleteDuplecateData(self.filteredData,self.measures[0]));
			d3.selectAll('#' + self.itemid + ' .coordinate-legend[filter="true"]').style("text-decoration", 'underline').attr("filter", "true");
		}
		
		gProgressbar.hide();
	};
	
	this.fCoordinateDot = function(jsonData, measures, dimensions, dupleData) {
		if(gDashboard.itemGenerateManager.noDataCheck(dupleData, self)) return;

		self.paletteData = [];
		$.each(dupleData, function(i, data){
			if($.inArray(data['dimension'], self.paletteData) === -1) self.paletteData.push(data['dimension']);
		})

		$('#'+self.itemid+ ' svg').remove();

		var svgWidth = $('#'+self.itemid).width(), svgHeight = $('#'+self.itemid).height();

		var margin = {top: 10, right: 10, bottom: 10, left: 10};

		if(self.meta.Legend.Visible){
			if(self.meta.Legend.Position === "TopRightVertical"){
				margin.right = 150;
			}else if(self.meta.Legend.Position === 'TopLeftVertical'){
				margin.left = 150;
			}else if(self.meta.Legend.Position === 'TopCenterHorizontal'){
				margin.top = 50;
			}else{
				margin.bottom = 50;
			}
		}

		var width = svgWidth - margin.left - margin.right,
		height = svgHeight - margin.top - margin.bottom;

		var data = dupleData;
		self.resizeData = data;
		// append the svg object to the body of the page
		var svg = d3.select("#"+self.itemid)
		.append("svg")
		.attr("width", width + margin.left + margin.right)
		.attr("height", height + margin.top + margin.bottom)
		.append("g")
		.append("g")
		.attr("transform",
				"translate(" + (margin.left+width/2) + ","
				+ (margin.top-height/2) + ")");
		// group the data: I want to draw one line per group
		var sumstat = d3.nest() // nest function allows to group the calculation per level of a factor
		.key(function(d) { return d.dimension;})
		.entries(data);

		// Add X axis --> it is a date format
		var x = d3.scaleLinear()
		.domain([-d3.max(data, function(d) { return d[dimensions[0].caption]; }),d3.max(data, function(d) { return d[dimensions[0].caption]; })])
		.range([ -width/2, width/2 ]);
		svg.append("g").classed("axis-x", true)
		.attr("transform", "translate(0," + height + ")")
		.call(d3.axisBottom(x).ticks(5).tickFormat(function(d) { return tickFormat(d, self.meta.AxisX)}))
		.append("text") // and text1
//		.attr("transform", "rotate(-90)")
		.attr("y", -20)
		.attr("x", width/2)
		.attr("dy", ".71em")
		.style("text-anchor", "end")
		.text(self.meta.AxisX.Title? self.meta.AxisX.Title : self.dimensions[0].caption)
		.attr("font-size", self.meta.LayoutOption.AxisX.size * 1 + 2)
		.attr("font-family", self.meta.LayoutOption.AxisX.family)
		.style("fill", self.meta.LayoutOption.AxisX.color);;

		// Add Y axis
		var y = d3.scaleLinear()
		.domain([d3.max(data, function(d) { return d[dimensions[1].caption]; }), -d3.max(data, function(d) { return d[dimensions[1].caption]; })])
		.range([height/2, height*1.5]);
		svg.append("g").classed("axis-y", true)
		.call(d3.axisLeft(y).ticks().tickFormat(function(d) { return tickFormat(d, self.meta.AxisY)}))
		.append("text") // and text1
//		.attr("transform", "rotate(-90)")
		.attr("y", height/2)
		.attr("x", 5)
		.attr("dy", ".71em")
		.style("text-anchor", "start")
		.text(self.meta.AxisY.Title? self.meta.AxisY.Title : self.dimensions[1].caption)
		.attr("font-size", self.meta.LayoutOption.AxisY.size * 1 + 2)
		.attr("font-family", self.meta.LayoutOption.AxisY.family)
		.style("fill", self.meta.LayoutOption.AxisY.color);

		// color palette
		var res = sumstat.map(function(d){ return d.key }) // list of group names
		var color = d3.scaleOrdinal()
		.domain(res)
		.range(gDashboard.d3Manager.getPalette(self));

		svg.append('g')
		.selectAll("dot")
		.data(data)
		.enter()
		.append("circle")
		.attr("r", 5)
		.style("fill", function (d) {
			return color(d.dimension);
		})
		.attr("opacity", .8)
		.attr("cx", function (d) { return x(d[dimensions[0].caption]); } )
		.attr("cy", function (d) { return y(d[dimensions[1].caption]); } )

		var zoomCnt = 0;
		function zoomable(){
			var zoom = d3.zoom().on("zoom", function (d,zz) {
				if(pressKey['z'] || pressKey['Z']){
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
							return "translate(0, 0)";
						}
						if(d3.event.transform.x ===0 && d3.event.transform.y ===0){
							d3.event.transform.x = d3.event.sourceEvent.layerX
							d3.event.transform.y = d3.event.sourceEvent.layerY
						}
						zoomCnt++
						return d3.event.transform;
					})
				}else{
					// Move scrollbars.
					var wrapper = $('#'+self.itemid);
					if(pressKey['Shift'] && wrapper.css('overflow-x') != 'hidden')
						wrapper.scrollLeft(wrapper.scrollLeft() + d3.event.sourceEvent.deltaY);
					else if(wrapper.css('overflow-y') != 'hidden')
						wrapper.scrollTop(wrapper.scrollTop() + d3.event.sourceEvent.deltaY);
				}

			})

			d3.select('#'+self.itemid).select('svg').call(zoom)
		}

		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}

		function tickFormat(n, format) {
			if(format){
				return WISE.util.Number.unit(n, format.FormatType, format.Unit, format.Precision, format.Separator, undefined, format.MeasureFormat, format.SuffixEnabled);	
			}
		}


		if(self.meta.Legend.Visible){
			var size = 20
			var xPos = width/2 + 20;

			if(self.meta.Legend.Position.indexOf("Bottom") > -1){
				xPos = height+60;
			}
			else if(self.meta.Legend.Position === "TopLeftVertical"){
				xPos = -width/2 - 140
			}else if(self.meta.Legend.Position.indexOf("Right") === -1){
				xPos = 10;
			}

			var colors = {};
			var palette = gDashboard.d3Manager.getPalette(self);

			for(var i = 0; i < self.paletteData.length; i++){
				colors[self.paletteData[i]] = palette[i%palette.length];
			}
			$('#'+self.itemid).css("display", "block");
			if(self.meta.Legend.Position.indexOf("Center") > -1){
				var beforeLegend;
				var beforeTranslateX;
				var legendWidthArr = [];
				var endIndex = -1;
				// Add labels beside legend dots
				$('#'+self.itemid).css('display', 'block')
				d3.select("#"+self.itemid + ' svg g g').selectAll("mylabels")
				.data(self.paletteData)
				.enter()
				.append("text")
				.classed("coordinate-legend", true)
				.attr("y", xPos+ size*.8+ height/2 - 50)
				.style("fill",self.meta.LayoutOption.Legend.color)
				.text(function(d){return d})
				.style("font-family", self.meta.LayoutOption.Legend.family)
				.style("font-size", self.meta.LayoutOption.Legend.size+'px')
				.attr("text-anchor", "left")
				.style("alignment-baseline", "middle")
				.attr("x", function(d,i){
					var translateX, beforeLegendWidth;


					if(beforeLegend != undefined){

						beforeLegendWidth = d3.select(beforeLegend).node().getComputedTextLength() + 30;
						translateX = beforeTranslateX + beforeLegendWidth + 20/2;

						if(translateX + d3.select(this).node().getComputedTextLength() > $('#'+self.itemid).width() - 75){
							legendWidthArr.push(2000);
							if(endIndex === -1){
								endIndex = i;
								d3.select(this).text(". . .");
								return translateX - width/2;
							}

							return 2000;
						}

						if(endIndex != -1)
							return 2000;
					}else{
						beforeTranslateX = 20;
						translateX = 20;
					}

					beforeLegend = this;
					beforeTranslateX = translateX;
					legendWidthArr.push(translateX);
					return translateX - width/2; 
				}).attr("filter", function(d){ return filter(d, this)})
				.style("cursor", "pointer")
				.on("click", function(d){ onMouseClick(d, this)})

				d3.select("#"+self.itemid + ' svg g g').selectAll("myrect")
				.data(self.paletteData)
				.enter()
				.append("rect")
				.attr("x", function(d,i){return legendWidthArr[i] - 15 - width/2})
				.attr("y", xPos + size *.5 + height/2 - 50)
				.attr("width", 12)
				.attr("height", 12)
				.style("stroke", "none")
				.style("fill", function(d){ return colors[d]})


			}else{
				// Add labels beside legend dots
				var maxIndex = self.paletteData.length;
				d3.select("#"+self.itemid + ' svg g g').selectAll("mylabels")
				.data(self.paletteData)
				.enter()
				.append("text")
				.classed("coordinate-legend", true)
				.attr("x", xPos+ size*.8)
				.attr("y", function(d,i){ return height/2 + i * (size + 5) + (size/2)})
				.style("fill", self.meta.LayoutOption.Legend.color)
				.text(function(d, i){ 
					if(16 + (i + 1) * (size + 5) + (size/2) > height + 40){
						if(16 + i * (size + 5) + (size/2) > height + 40)
							return '';
						else{
							if(self.paletteData.length - 1 !== i){
								maxIndex = i;
								return '. . .';

							}
						}
					}
					return (self.paletteData.length === 1 && self.paletteData[0] === "") ? "값" :d}


				)
				.attr("filter", function(d){ return filter(d, this)})
				.attr("font-family", self.meta.LayoutOption.Legend.family)
				.attr("font-size", self.meta.LayoutOption.Legend.size+'px')
				.attr("text-anchor", "left")
				.style("alignment-baseline", "middle")
				.style("cursor", "pointer")
				.on("click", function(d){ onMouseClick(d, this)})

				d3.select("#"+self.itemid + ' svg g g').selectAll("myrect")
				.data(self.paletteData.slice(0, maxIndex))
				.enter()
				.append("rect")
				.attr("x", xPos)
				.attr("y", function(d,i){ return height/2 + 4 + i*(size+5)})
				.attr("width", 12)
				.attr("height", 12)
				.style("stroke", "none")
				.style("fill", function(d){ return colors[d]})
			}
		}

		d3.selectAll('#'+ self.itemid +" .axis-x text")
		.attr("font-size", self.meta.LayoutOption.AxisX.size+'px')
		.attr("font-family", self.meta.LayoutOption.AxisX.family)
		.style("fill", self.meta.LayoutOption.AxisX.color)

		d3.selectAll('#'+ self.itemid +" .axis-y text")
		.attr("font-size", self.meta.LayoutOption.AxisY.size+'px')
		.attr("font-family", self.meta.LayoutOption.AxisY.family)
		.style("fill", self.meta.LayoutOption.AxisY.color)

		function filter(d, _this){
			for (var index = 0; index < self.tempTrackingData.length; index++) {
				var check = 0;
				$.each(self.dimensions.slice(2), function(i, dim){
					if(self.tempTrackingData[index][dim.caption] === d.split(" - ")[i])
						check++;
				})
				if(check === self.dimensions.length - 2){
					return "true";
				}
			}
			return "false";
		}
		
		function onMouseClick(d, _this){
			switch(self.meta.InteractivityOptions.MasterFilterMode){
			case 'Single':
				self.trackingData = [];
				self.tempTrackingData = [];
				if(d3.select(_this).attr("filter") === "true"){
					d3.selectAll('#' + self.itemid + ' .coordinate-legend').style('text-decoration', 'none').attr("filter", "false");
				}else{
					//선택 모두 해제
					d3.selectAll('#' + self.itemid + ' .coordinate-legend').style('text-decoration', 'none').attr("filter", "false");

					d3.select(_this).style("text-decoration", 'underline').attr("filter", "true");

//					var selectedData = {};
//					selectedData[self.dimensions[0].name] = d.data[0];
					var tempSelectedData = {};
					$.each(self.dimensions.slice(2), function(i, dim){
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
				if(d3.select(_this).attr("filter") === "true"){
					d3.select(_this).style("text-decoration", 'underline').style('text-decoration', 'none').attr("filter", "false");
					for (var index = 0; index < self.tempTrackingData.length; index++) {
						var check = 0;
						$.each(self.dimensions.slice(2), function(i, dim){
							if(self.tempTrackingData[index][dim.caption] === d.split(" - ")[i])
								check++;
						})
						if(check === self.dimensions.length - 2){
							self.tempTrackingData.splice(index, 1);
							index--;
						}
					}
				}else{
					d3.select(_this).style("text-decoration", 'underline').attr("filter", "true");
//					self.tempTrackingData.push(d.dimension.split(" - ")[i]);
					tempSelectedData = {}
					$.each(self.dimensions.slice(2), function(i, dim){
						tempSelectedData[dim.caption] = d.split(" - ")[i]
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
		}

	};
	
	function checkingItem(_data) {
		return !_data.items.length;
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self, self.meta);
	}
};


WISE.libs.Dashboard.CoordinateDotFieldManager = function() {
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
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
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
