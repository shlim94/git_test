WISE.libs.Dashboard.item.DendrogramBarChartGenerator = function() {
	var self = this;

	this.type = 'DENDROGRAM_BAR_CHART';

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
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";

	this.DendrogramBarChart = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	//임성현 팔레트 
	this.customPalette = [];
	// 20200825 ajkim 팔레트 데이터 추가 dogfoot
	this.paletteData = [];
	this.isCustomPalette = false;
	
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
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

		var dxConfigs = {
				dataSource : this.dataSourceConfig,
				dataStructure: 'plain',
				allowExpandAll: true,
				allowFiltering: true,
				allowSorting: true,
				allowSortingBySummary: true,
				palette: _item['Palette'],
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

	this.setDendrogramBarChart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.DendrogramBarChart['ComponentName'] = this.ComponentName;
		this.DendrogramBarChart['Name'] = this.Name;
		this.DendrogramBarChart['DataSource'] = this.dataSourceId;

		this.DendrogramBarChart['DataItems'] = this.fieldManager.DataItems;
		this.DendrogramBarChart['Arguments'] = this.fieldManager.Arguments;
		this.DendrogramBarChart['Values'] = this.fieldManager.Values;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.DendrogramBarChart;
		
		// 임성현 초기 팔레트값 설정
		if (!(this.DendrogramBarChart['Palette'])) {
			this.DendrogramBarChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		
		if (!(this.DendrogramBarChart['Legend'])) {
			this.DendrogramBarChart['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.DendrogramBarChart.AxisY)) {
			this.DendrogramBarChart.AxisY = {
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
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DendrogramBarChart.InteractivityOptions) {
			if (!(this.DendrogramBarChart.InteractivityOptions.MasterFilterMode)) {
				this.DendrogramBarChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DendrogramBarChart.InteractivityOptions.TargetDimensions)) {
				this.DendrogramBarChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DendrogramBarChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.DendrogramBarChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DendrogramBarChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.DendrogramBarChart.LayoutOption){
			this.DendrogramBarChart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 12,
						family: '맑은 고딕'
					},
					AxisX: {
						color: '#000000',
						size: 10,
						family: '맑은 고딕'
					}
			}
		}
		
		if(!this.DendrogramBarChart['ZoomAble']){
			this.DendrogramBarChart.ZoomAble = 'none'
		}
		
	};

	this.setDendrogramBarChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setDendrogramBarChart();
		}
		else{
			this.DendrogramBarChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.DendrogramBarChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.DendrogramBarChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.DendrogramBarChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.DendrogramBarChart['Palette'])) {
			this.DendrogramBarChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var DendrogramBarChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DENDROGRAM_BAR_CHART_DATA_ELEMENT);
				
				$.each(DendrogramBarChartOption,function(_i,_dendrogrambarchartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _dendrogrambarchartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _dendrogrambarchartOption.CTRL_NM;
					}
					if(self.DendrogramBarChart.ComponentName == CtrlNM){
						self.DendrogramBarChart['Palette'] = _dendrogrambarchartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.DendrogramBarChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.DendrogramBarChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.DendrogramBarChart.AxisY)) {
			this.DendrogramBarChart.AxisY = {
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
		
		if(!this.DendrogramBarChart.LayoutOption){
			this.DendrogramBarChart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 12,
						family: '맑은 고딕'
					},
					AxisX: {
						color: '#000000',
						size: 10,
						family: '맑은 고딕'
					}
			}
		}
		if(!this.DendrogramBarChart['ZoomAble']){
			this.DendrogramBarChart.ZoomAble = 'none'
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DendrogramBarChart.InteractivityOptions) {
			if (!(this.DendrogramBarChart.InteractivityOptions.MasterFilterMode)) {
				this.DendrogramBarChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DendrogramBarChart.InteractivityOptions.TargetDimensions)) {
				this.DendrogramBarChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DendrogramBarChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.DendrogramBarChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DendrogramBarChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
	}
	
	//d3vCal 뷰어모드
	this.setDendrogramBarChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setDendrogramBarChart();
		}
		else{
			this.DendrogramBarChart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.DendrogramBarChart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.DendrogramBarChart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.DendrogramBarChart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.DendrogramBarChart['Palette'])) {
			this.DendrogramBarChart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var DendrogramBarChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.DENDROGRAM_BAR_CHART_DATA_ELEMENT);
				
				$.each(DendrogramBarChartOption,function(_i,_dendrogrambarchartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _dendrogrambarchartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _dendrogrambarchartOption.CTRL_NM;
//					}
					if(self.DendrogramBarChart.ComponentName == CtrlNM){
						self.DendrogramBarChart['Palette'] = _dendrogrambarchartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.DendrogramBarChart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.DendrogramBarChart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.DendrogramBarChart.AxisY)) {
			this.DendrogramBarChart.AxisY = {
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
		
		if(!this.DendrogramBarChart.LayoutOption){
			this.DendrogramBarChart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 12,
						family: '맑은 고딕'
					},
					AxisX: {
						color: '#000000',
						size: 10,
						family: '맑은 고딕'
					}
			}
		}
		if(!this.DendrogramBarChart['ZoomAble']){
			this.DendrogramBarChart.ZoomAble = 'none'
		}
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.DendrogramBarChart.InteractivityOptions) {
			if (!(this.DendrogramBarChart.InteractivityOptions.MasterFilterMode)) {
				this.DendrogramBarChart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.DendrogramBarChart.InteractivityOptions.TargetDimensions)) {
				this.DendrogramBarChart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.DendrogramBarChart.InteractivityOptions.IgnoreMasterFilters)) {
				this.DendrogramBarChart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.DendrogramBarChart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
	};

	/** @Override */
	this.bindData = function(_data) {
		//2020.02.07 mksong sqllike 적용 dogfoot
//		if (!this.tracked) {
//			this.globalData = _.clone(_data);
//			this.filteredData = _.clone(_data);
//		}
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

		if(this.fieldManager !=null && gDashboard.isNewReport == true){ // 신규 생성
			self.setDendrogramBarChart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.DendrogramBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.DendrogramBarChart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setDendrogramBarChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.DendrogramBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.DendrogramBarChart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.DendrogramBarChart)) {
			this.setDendrogramBarChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.DendrogramBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.DendrogramBarChart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setDendrogramBarChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.DendrogramBarChart);
			gDashboard.itemGenerateManager.generateItem(self, self.DendrogramBarChart);
		}

//		var buttonPanelId = this.itemid + '_topicon';
//		var topIconPanel = $('#' + buttonPanelId);
//		if($('#'+this.itemid + '_tracking_data_container').length == 0){
//			var trackingDataContainerId = this.itemid + '_tracking_data_container';
//			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
//			topIconPanel.append(trackingDataContainerHtml);
//		}

		var dxConfig = this.getDxItemConfig(this.meta);
		
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

		/*dogfoot d3차트 수정 shlim 20200618*/
		var measureKey = this.measures;		
		var dupledatacehck = self.deleteDuplecateData(_data,measureKey);
		self.currentMeasureName = WISE.util.Object.toArray(measureKey)[0].caption;
		
		//2020.11.03 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('d3');
		self.fDendrogramBarChart(dupledatacehck, this.measures, this.dimensions, dupledatacehck);
//		dxConfig.dataSource = self.deleteDuplecateData(_data,measureKey);
		$('#' + self.itemid + '_title > .lm_title').text(self.Name);
		
		//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
		$('#'+self.itemid).css('display','block');
		this.dxItem = $("#" + this.itemid).dxChart(dxConfig).dxChart("instance");
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
	};
						   
	/*this.menuItemGenerate = function(){
		if($('#data').length > 0){
			$('#data').remove();
		}

		$('#menulist').removeClass('col-2');
		$('#menulist').addClass('col-2');
		if($('#data').length == 0){
			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
		}

		if($('#design').length > 0){
			$('#design').remove();
		}

		if($('#tab5primary').length == 0){
//			$('.menu-comp').append('<div  class="slide-ui"><ul id="tab5primary" class="lnb-lst-tab" style="margin-top:10px;"></ul></div>');
			// 2020.01.16 mksong 영역 크기 조정 dogfoot
			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
		}
		
		
		$('#tab5primary').empty();
		$('#tab5primary').append('<span class="drag-line"></span>');

		$('#tab4primary').empty();
		if($('#tab4primary').length == 0){
			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
		}

		// initialize UI elements
		
		tabUi();
		designMenuUi();
		compMoreMenuUi();
	}*/
	
	this.menuItemGenerate = function(){
		gDashboard.itemGenerateManager.menuItemGenerate(self);

//		if($('#data').length > 0){
//			$('#data').remove();
//		}
//		$('#menulist').addClass('col-2');
//		if($('#data').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('#menulist').append($('<li id="data" rel="panelDataA-2" class="itemDelete" style="width:50%;"><a href="#tab4primary" data-toggle="tab">'+ gMessage.get('WISE.message.page.widget.nav.properties') +'</a></li>'));	
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
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');
//		}
//		
//		//임성현 주임 d3 속성 추가
//		$('#tab5primary').empty();
//		
//		$('<li class="slide-ui-item"><a id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a id="editPalette" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_globalColor.png" alt=""><span>팔레트</span></a></li>').appendTo($('#tab5primary'));
//		
//		menuItemSlideUi();
//		// 임성현 주임  d3 속성 추가
//		
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content itemDelete"></div>'));	
//		}
//		
//		$().appendTo($('#tab4primary'));
//		
//		// initialize UI elements
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
//
//		// toggle 'on' status according to chart options
//		if (self.IO) {
//			if (self.IO['MasterFilterMode'] === 'Single') {
//				$('#singleMasterFilter').addClass('on');
//			} else if (self.IO['MasterFilterMode'] === 'Multiple') {
//				$('#multipleMasterFilter').addClass('on');
//			}
//			if (self.IO['IsDrillDownEnabled']) {
//				$('#drillDown').addClass('on');
//			}
//			if (self['isMasterFilterCrossDataSource']) {
//				$('#crossFilter').addClass('on');
//			}
//			if (self.IO['IgnoreMasterFilters']) {
//				$('#ignoreMasterFilter').addClass('on');
//			}
//			if (self.IO['TargetDimensions'] === 'Argument') {
//				$('#targetArgument').addClass('on');
//			} else if (self.IO['TargetDimensions'] === 'Series') {
//				$('#targetSeries').addClass('on');
//			}
//        }
//		
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
//		//d3 option 임성현
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);	
//		});
		
	}

	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if(gDashboard.reportType != 'AdHoc' || !(gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer')){
				if (self.dxItem) {
					d3.selectAll('rect')
			    	.attr("stroke","none")
                    .attr("stroke-width","2")
					.attr("filter", 'false');

					d3.selectAll('circle')
			    	.attr("stroke","none")
                    .attr("stroke-width","2")
					.attr("filter", 'false');
				}
				self.trackingData = [];
				self.selectedPoint = undefined;	
			}
		}
	};
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);

//		$('#'+_itemid + '_tracking_data_container').empty();
//		if (this.measures && this.measures.length > 1) {
//			var valueListId = _itemid + '_topicon_vl';
//			var popoverid = _itemid + '_topicon_vl_popover';
//
//			var listHtml = '<li><a id="' + valueListId + '" href="#"><img src="' + WISE.Constants.context + '/images/cont_box_icon_layer.png" onMouseOver="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer_.png\'" onMouseOut="this.src=\'' + WISE.Constants.context + '/images/cont_box_icon_layer.png\'" alt="Select Panel" title="Select Panel"></a></li>';
//			$('#' + _itemid + '_tracking_data_container').append(listHtml);
//			var page = window.location.pathname.split('/');
//			if (page[page.length - 1] == 'viewer.do') {
//				if($('#'+this.itemid+'editDendrogramBarChartPopover').length == 0 ){
//					$('<div id="'+this.itemid+'editDendrogramBarChartPopover">').dxPopover({
//					DendrogramBarChart 'auto',
//						width: 'auto',
//						position: 'bottom',
//						visible: false
//					}).appendTo('#wrap');
//				}
//			}else{
//				if($('#'+this.itemid+'editDendrogramBarChartPopover').length == 0 ){
//					$('<div id="'+this.itemid+'editDendrogramBarChartPopover">').dxPopover({
//						height: 'auto',
//						width: 'auto',
//						position: 'bottom',
//						visible: false
//					}).appendTo('#wrapper');
//				}
//			}
//			
//			var p = $('#'+this.itemid+'editDendrogramBarChartPopover').dxPopover('instance');
//
//
//			var temphtml = "<div style='width:150px;'>";
//			temphtml += '<div class="add-item noitem">';
//			$.each(this.measures, function(_i, _vo) {
//				temphtml += '<div class="select-style" data-key="' + (_vo.uniqueName) + '"><span data-key="' + (_vo.uniqueName) + '">' + _vo.caption + '</span></a>';
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
//						$('#' + self.itemid + '_title > .lm_title').text(self.Name);
//						var dxConfig = self.getDxItemConfig(self.meta);
//						self.currentMeasureName = selectedMeasure.caption;
//						dxConfig.dataSource = self.deleteDuplecateData(self.filteredData,selectedMeasure);
//						self.fDendrogramBarChart(self.filteredData);
////						self.dxItem = $("#" + self.itemid).dxTreeMap(dxConfig).dxTreeMap(
////						"instance");
//					});
//				},
////				visible:false
//			})
//			$('#' + _itemid + '_topicon').off('click').on('click',function(){
//				p.option('visible', !(p.option('visible')));
//			});
//		}
	};
	
	this.deleteDuplecateData2 = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	this.deleteDuplecateData = function(_data,MeasureKey){
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var dataSourceId = this.dataSourceId;
		self.selectedMeasure = WISE.util.Object.toArray(MeasureKey);
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
			//2020.02.07 mksong sqllike 적용 dogfoot
			selectArray.push('|as|');
			selectArray.push(_Mea.captionBySummaryType);
		});

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
		
		sqlConfig.OrderBy = [];
		$.each(Dimension, function(_i, _d) {
			//2020.02.07 mksong sqllike 적용 dogfoot
			sqlConfig.OrderBy.push(_d.DataMember || _d.sortByMeasure);
		});
		
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
		self.filteredData = SQLikeUtil.doSqlLike(dataSourceId, sqlConfig, self);
		self.csvData = self.filteredData;
		self.paletteData = self.filteredData.map(function (val, index) {
			return val[self.dimensions[self.dimensions.length-1].name];
		}).filter(function (val, index, arr) {
			return arr.indexOf(val) === index;
		});
		ValueArray.push(self.filteredData);
		var returnArray = [];
        self.returnData=[];
        self.xAxisData = [];
		 var first=[];
		first.push({items:self.filteredData});
		var queryData = first;
		
		//차원이 여러개일때 topN기능이 걸린 차원의 위치를 찾기위한 싸이클
		for(var i = 0; i < self.dimensions.length ; i++){
			if(i == 0){
                queryData = this.__getTopNData(queryData,self.dimensions,self.dimensions[i].name,undefined,i);
			}else{
			    queryData = this.__getTopNData(queryData,self.dimensions,self.dimensions[i].name,self.dimensions[i-1].name,i);	
			}
		}
        
      
		var resultArr = self.returnData;
		
		return resultArr;
	};

	
	String.prototype.replaceAll = function(org, dest) {
	    return this.split(org).join(dest);
	}
	
	this.__getTopNData = function(queryData,dimensions,nowDim,preDim,lastDim){
		
		
		var sumNm = self.selectedMeasure[0].captionBySummaryType;

		
		var topnData = [];
		var otherData =[];
		var topNarray = [];
		var topNresult = [];
		var TopNExecSyx;
		var sortTopNdata;
		var TopNotherData;
		var predim = '';
		var colLen = 0;
		$.each(queryData,function(_index,_e){
			if(_e.id){
			    predim = _e.id	
			}
	        
			var ExecSyx = DevExpress.data.query(_e.items);
			var sumValArray = ExecSyx.groupBy(nowDim)
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
					}).toArray();
			ExecSyx = ExecSyx.groupBy(nowDim);
			topNarray = ExecSyx.toArray();
            $.each(topNarray, function(i, e) {
                if(predim === ""){
                	predim = "start";
                	var reval;
                	reval = sumValArray.reduce(function(accumulator, currentValue, currentIndex, array) {
                	  var objectCk = typeof accumulator === "object" ? accumulator.value : accumulator
					  return objectCk + currentValue.value;
					});
                	self.returnData.push({'id':'start','value':reval});
                    e['id'] = predim.concat(";",e.key);
                }else{
                	e['id'] = predim.concat(";",e.key);
                }
            	
				topnData.push(e);
				if(lastDim == (self.dimensions.length-1)){
					var colorz = gDashboard.d3Manager.getPalette(self);
					if(colLen>(colorz.length-1))colLen=0;
					
					if(self.paletteData.length>0){

						colLen =  self.paletteData.indexOf(e.key) === -1 ?  colLen : self.paletteData.indexOf(e.key) > colorz.length? colLen: self.paletteData.indexOf(e.key);
						self.returnData.push({'id':e['id'],'value':e['items'][0][sumNm],'color':colorz[colLen]});
						self.xAxisData.push({'id':e['id'],'value':e['items'][0][sumNm],'color':colorz[colLen]});
						colLen++;	
					}else{
						if(colLen>(colorz.length-1))colLen=0;
						self.returnData.push({'id':e['id'],'value':e['items'][0][sumNm],'color':colorz[colLen]});
						self.xAxisData.push({'id':e['id'],'value':e['items'][0][sumNm],'color':colorz[colLen]});
						colLen++;
					}
					
                    
				}else{
					var reval;
                    $.each(sumValArray,function(_j,_value){
                    	if(e.key === _value.key){
                            reval = _value.value
                    	}
                    	
                    });
					
				    self.returnData.push({'id':e['id'],'value':reval});
				}
				colLen++;
			});
		})
        return topnData;
	}
	
//	this.resize = function() {
//		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/
//		var dupledatacehck = self.deleteDuplecateData(self.filteredData,self.measures);
//		self.fDendrogramBarChart(dupledatacehck, self.measures, self.dimensions, dupledatacehck);
//		gProgressbar.hide();
//	};
	this.resize = function() {
		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/
		var dupledatacehck
		if(typeof self.resizeData != 'undefined'){
		    dupledatacehck = self.resizeData;
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
		    self.fDendrogramBarChart(dupledatacehck, self.measures, self.dimensions, dupledatacehck);
		    
		    d3.selectAll('rect[filter="true"]')
			.attr("stroke","#4D4D4D")
	        .attr("stroke-width","2")
			.attr("filter", 'true');
		    
		    d3.selectAll('circle[filter="true"]')
			.attr("stroke","#4D4D4D")
	        .attr("stroke-width","2")
			.attr("filter", 'true');
		}
		
		gProgressbar.hide();
	};
	
	
	this.fDendrogramBarChart = function(jsonData, measures, dimensions, dupleData) {
		
		var nodata = false;
		
		if (!dupleData || ($.type(dupleData) === 'array' && dupleData.length === 0)
				|| (dupleData.length == 1 && dupleData[0].value == 0 && dupleData[0].key == "")) {
			$('#'+self.itemid + ' .nodata-layer').remove();
			var nodataHtml = '<div class="nodata-layer" style="z-index:99999999999"></div>';
			$("#" + self.itemid).children().css('display','none');
			$("#" + self.itemid).prepend(nodataHtml);
			if($("#" + self.itemid).height() === 0 || $("#" + self.itemid).width() === 0){
				$("#" + self.itemid).height('100%');
				$("#" + self.itemid).width('100%');
			}
			$("#" + self.itemid).css('display', 'block');

			nodata = true;
		}else{
			self.resizeData = dupleData;
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}
		
		if(!jsonData || ($.type(jsonData) === 'array' && jsonData.length === 0)
				|| (dupleData.length == 1 && dupleData[0].value == 0 && dupleData[0].key == "")){
			
			if(nodata){
				if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
				}

				if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
					gProgressbar.hide();		
					gDashboard.updateReportLog();
				}
				return;
			}
		} else if(nodata){
			$('#'+self.itemid + ' .nodata-layer').remove();
			$("#" + self.itemid).children().css('display','block');
		}

		self.paletteData = self.filteredData.map(function (val, index) {
			return val[self.dimensions[self.dimensions.length-1].name];
		}).filter(function (val, index, arr) {
			return arr.indexOf(val) === index;
		});

		var colorz = gDashboard.d3Manager.getPalette(self);
		var myColor = d3.scaleOrdinal()
		    .domain(self.paletteData)
		    .range(colorz);
		
		d3.select("#" + self.itemid).selectAll("svg").remove();
		var width = +$('#'+self.itemid).width();
        var height = +$('#'+self.itemid).height();
		var NumberF = WISE.util.Number,
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
		var NumericFormat;
		$.each(WISE.util.Object.toArray(self.DI.Measure),function(_i,_val){
			if(self.selectedMeasure[0].uniqueName ===  _val.UniqueName){
				if(_val.NumericFormat){
					
				    NumericFormat = _val.NumericFormat;	
				}
			}
		});
		
		if(typeof NumericFormat != 'undefined'){
			labelFormat = NumericFormat.FormatType;
			labelUnit = NumericFormat.Unit;
			labelPrecision = NumericFormat.Precision;
			labelSeparator = NumericFormat.IncludeGroupSeparator;
			labelSuffixEnabled = NumericFormat.SuffixEnabled;
			labelSuffix =NumericFormat.Suffix;
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
									return "translate(20,0)";
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
		
		var svg = d3.select("#" + self.itemid).append("svg")
		  //.attr("viewBox", `-${width / 2} -${height / 2} ${width} ${height}`)
			  .attr("width", width)
	          .attr("height", height)
	          .style("align", 'center')
			  .style("display", "block")
			  .style("margin", "auto")
			  .style("cursor", "pointer"),
        g = svg.append("g").attr("transform", "translate(20,0)");// move right 20px.
		
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}
   
		// x-scale and x-axis
		var experienceName = ["", "Basic 1.0","Alright 2.0","Handy 3.0","Expert 4.0","Guru 5.0"];
		var formatSkillPoints = function (d) {
		    return experienceName[d % 6];
		}
		



		    var stratify = d3.stratify()            // This D3 API method gives cvs file flat data array dimensions.
		        .parentId(function(d) { return d.id.substring(0, d.id.lastIndexOf(";")); });

		    var tree = d3.cluster()                 // This D3 API method setup the Dendrogram datum position.
		        .size([height*0.9, width - width/2])    // Total width - bar chart width = Dendrogram chart width
		        .separation(function separate(a, b) {
		            return a.parent == b.parent            // 2 levels tree grouping for category
		            || a.parent.parent == b.parent
		            || a.parent == b.parent.parent ? 0.4 : 0.8;
		        });
		        
		    var root = stratify(dupleData);
		    tree(root);
            var values = [];
            $.each(self.xAxisData, function(_i, _o) {
			    values.push(_o.value)
			});
			values.push(0)
			var gxmin =(d3.min(values)/2);

	//  		var gxmin = d4.min(values);
			var gxmax = d3.max(values);
	//  		var gxmin = 50;
	//  		var gxmax = 90;
			var xScale     = d3.scaleLinear().domain([gxmin,gxmax]).range([0, width/3]);
			/*var xScale =  d3.scaleLinear()
					.domain([0,5])
					.range([0, width/3]);*/

			var xAxis = d3.axisTop()
					.scale(xScale)
					.ticks(5)
					//.tickFormat();
		
		// Setting up a way to handle the data
		
		
		

		
		    // Draw every datum a line connecting to its parent.
		    var link = g.selectAll(".link")
		            .data(root.descendants().slice(1))
		            .enter().append("path")
		            .attr("class", "link")
		            .attr("d", function(d) {
		                return "M" + d.y + "," + (d.x+20)
		                        + "C" + (d.parent.y + 50) + "," + (d.x+20)
		                        + " " + (d.parent.y + 50) + "," + (d.parent.x+20)
		                        + " " + d.parent.y + "," + (d.parent.x+20);
		            });
		
		    // Setup position for every datum; Applying different css classes to parents and leafs.
		    var node = g.selectAll(".node")
		            .data(root.descendants())
		            .enter().append("g")
		            .attr("class", function(d) { return "node" + (d.children ? " node--internal" : " node--leaf"); })
		            .attr("transform", function(d) { return "translate(" + d.y + "," + (d.x+20) + ")"; });
		
		    // Draw every datum a small circle.
		    node.append("circle")
		            .attr("r", function(d){
		            	return ((height - 100)/dupleData.length/4) < 4 ? 4 :((height - 100)/dupleData.length/4)
		            	})
		            .attr("filter", function(d){
						if(self.trackingData){
						  var filter = false;
						  for(var i = 0; i < self.trackingData.length; i++){
							  if(self.trackingData[i][self.dimensions[self.dimensions.length-1].name] === d.data.id.substring(d.data.id.lastIndexOf(";") + 1))
								  filter = true;
						  }
						  return filter? "true" : "false";
					  }else return "false"
					})
			 	    .on("click", function(d) {
				         mouseclick(d,this,"circle");
				    })
		            .on('mouseover',function(event,d,zzz){    	
		            	return handleMouseOverLink(event);	
		            })
		            .on('mouseout',function(event,d,zzz){
		            	return handleMouseOutLink(event);
		            });
		
		    // Setup G for every leaf datum.
		    var leafNodeG = g.selectAll(".node--leaf")
		            .append("g")
		            .attr("class", "node--leaf-g")
		            .attr("transform", "translate(" + 8 + "," + -(height - 100)/dupleData.length/2 + ")");
		    var colLen=0;
		    leafNodeG.append("rect")
		            .attr("class","shadow")
		            .style("fill", function (d) {
		            	return d.data.color;
		            })
		            .attr("width", 2)
		            .attr("height", function(d){
		            	return (height - 100)/dupleData.length
		            })
		            .attr("rx", 2)
		            .attr("ry", 2)
		            .attr("filter", function(d){
						if(self.trackingData){
						  var filter = false;
						  for(var i = 0; i < self.trackingData.length; i++){
							  if(self.trackingData[i][self.dimensions[self.dimensions.length-1].name] === d.data.id.substring(d.data.id.lastIndexOf(";") + 1))
								  filter = true;
						  }
						  return filter? "true" : "false";
					  }else return "false"
					})
			 	    .on("click", function(d) {
				         mouseclick(d,this,"rect");
				    })
		            .transition()
		                .duration(800)
		                .attr("width", function (d) {return xScale(d.data.value);});
		
		   leafNodeG.append("text")
		            .attr("dy", (height - 100)/dupleData.length/2 + 3)
		            .attr("x", function (d) {return xScale(d.data.value)+10;})
		            .style("fill", "black")
		            .style("text-anchor", "start")
		            .style("font-size",self.meta.LayoutOption.Label.size+'px')
		            .style("fill", self.meta.LayoutOption.Label.color)
		            .style("font-family", self.meta.LayoutOption.Label.family)
		            //.text(function (d) {
		            //    return d.data.id.substring(d.data.id.lastIndexOf(";") + 1);
		           // })
		            ;
		
		    // Write down text for every parent datum
		    var internalNode = g.selectAll(".node--internal");
		    internalNode.append("text")
		            .attr("y", -10)
		            .style("text-anchor", "middle")
                    .style("font-size",self.meta.LayoutOption.Label.size+'px')
		            .style("fill", self.meta.LayoutOption.Label.color)
		            .style("font-family", self.meta.LayoutOption.Label.family)
		            .text(function (d) {
		                return d.data.id.substring(d.data.id.lastIndexOf(";") + 1);
		            }).on('mouseover',function(event,d,zzz){
		            	return handleMouseOverLink(event);
		            })
		            .on('mouseout',function(event,d,zzz){
		            	return handleMouseOutLink(event);
		            });
		
		    // Attach axis on top of the first leaf datum.
		    var firstEndNode = g.select(".node--leaf");
		        firstEndNode.insert("g")
		                .attr("class","xAxis")
		                .attr("transform", "translate(" + 7 + "," + -(((height - 100)/dupleData.length/2)+5) + ")")
		                .style("font-family", gDashboard.fontManager.getDxItemLabelFont().family)
		                .call(xAxis.tickFormat(function(event,d,zz){
		                	return NumberF.unit(event, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
		                }))
		        
		        d3.selectAll('#'+self.itemid + ' .xAxis text')
		        .style("font-size",self.meta.LayoutOption.AxisX.size+'px')
	            .style("fill", self.meta.LayoutOption.AxisX.color)
	            .style("font-family", self.meta.LayoutOption.AxisX.family)
		
		        // tick mark for x-axis
		        firstEndNode.insert("g")
		                .attr("class", "grid")
		                .attr("transform", "translate(7," + (height*0.8) + ")")
		                .call(d3.axisBottom()
		                        .scale(xScale)
		                        .ticks(5)
		                        .tickSize(-height, 0, 0)
		                        .tickFormat("")
		                )
		                .style("display","none")
		                ;
		
		    // Emphasize the y-axis baseline.
		    svg.selectAll(".grid").select("line")
		            .style("stroke-dasharray","20,1")
		            .style("stroke","white");
		
		    // The moving ball
		    var ballG = svg.insert("g")
		            .attr("class","ballG")
		            .attr("transform", "translate(" + -2000 + "," + height/2 + ")")
		            
		    ballG.insert("rect")
		            .attr("class","shadow")
		            .style("fill","steelblue")
		            .style("width", '120px')
		            .style("height", '20px')
		            .attr("rx", 5)
		            .attr("ry", 5)
		    ballG.insert("text")
		            .style("text-anchor", "middle")
		            .attr("dy",13)
		            .attr("dx",60)
		            .text("0.0");
		
		    // Animation functions for mouse on and off events.
		    d3.selectAll(".node--leaf-g")
		            .on("mouseover", handleMouseOver)
		            .on("mouseout", handleMouseOut);
		    
            function handleMouseOverLink(d) {
		        var leafG = d3.select(this);
		        var textV = d.data.id.substring(d.data.id.lastIndexOf(";") + 1)
		        	
		        var ballGMovement = ballG.transition()
		                .duration(400)
		                .attr("transform", "translate(" + (d.y+50) + ","
		                        + (d.x) + ")")
		                .style('opacity',"1");
		        colLen=0;
		        ballGMovement.select("rect")
		                .style("fill",function(){return d.data.color ? d.data.color :"blue"})
		                .style('width', 120 + (textV+d.data.value).length*2 + 'px')
		                .attr("height", 20)
		                .attr("rx", 5)
		                .attr("ry", 5)
		
		        ballGMovement.select("text")
		                //.delay(300)
		                .attr("dy",13)
		                .attr("dx",(120 + (textV+d.data.value).length*2)/2)
		                .style("font-size","10px")
		                .text(textV + " : " +NumberF.unit(d.data.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled));
		    }

		    function handleMouseOutLink(d) {
		        var leafG = d3.select(this);
		        ballG.transition()
		                .duration(400)
		                .attr("transform", "translate(" + (d.y +50) + ","
		                        + (d.x) + ")")
		                .style('opacity',"0");
		    }

		    function handleMouseOver(d) {
		        var leafG = d3.select(this);

		        var textV = d.data.id.substring(d.data.id.lastIndexOf(";") + 1)
		
		        leafG.select("rect")
		                .attr("stroke","#4D4D4D")
		                .attr("stroke-width","2");
		        	
		        var ballGMovement = ballG.transition()
		                .duration(400)
		                .attr("transform", "translate(" + (d.y - 120 - (textV+d.data.value).length*2) + ","
		                        + (d.x + ((height - 100)/dupleData.length/2)) + ")")
		                .style('opacity',"1");

		        colLen=0;
		        ballGMovement.select("rect")
		                .style("fill", d.data.color)
		                .style('width', 120 + (textV+d.data.value).length*2 + 'px')
		                .attr("height", 20)
		                .attr("rx", 5)
		                .attr("ry", 5)
		
		        ballGMovement.select("text")
//		                .delay(300)
		                .style("font-size","10px")
		                .attr("dy",13)
		                .attr("dx",(120 + (textV+d.data.value).length*2)/2)
		                .text(function(){
		                return textV + " : " +NumberF.unit(d.data.value, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)
		                });
		    }
		    function handleMouseOut(d) {
		        var leafG = d3.select(this);
		        ballG.transition()
		                .duration(400)
		                .attr("transform", "translate(" + (d.y - 120) + ","
		                        + (d.x + ((height - 100)/dupleData.length/2)) + ")")
		                .style('opacity',"0");
		        leafG.select('rect[filter="false"]')
		                .attr("stroke-width","0");
		    }

		    function mouseclick(d,_this,_type){
				
				var selectKey =  WISE.util.Object.toArray(d.data.id.substring(d.data.id.lastIndexOf(";") + 1))
				var otherSelection;
                if(_type != undefined && _type=="circle"){
				    otherSelection = $(_this).parent().find('rect');
				}else{
					otherSelection = $(_this).parent().parent().find('circle')
				}

                 switch(self.IO.MasterFilterMode){
					case 'Multiple':
						if(d3.select(_this).attr("filter") === "true"){
							
							d3.select(_this)
							.attr("stroke","none")
		                    .attr("stroke-width","2")
							.attr("filter", 'false');

							otherSelection
							.attr("stroke","none")
		                    .attr("stroke-width","2")
							.attr("filter", 'false');
							
				    	}else{
				    		
				    		d3.select(_this)
							.attr("stroke","#4D4D4D")
		                    .attr("stroke-width","2")
							.attr("filter", 'true');
                            
                            otherSelection
                            .attr("stroke","#4D4D4D")
		                    .attr("stroke-width","2")
							.attr("filter", 'true');
				    	}
						var inArray = false;
						var selectedData = {};
						$.each(selectKey,function(_j,_selectkey){
							$.each(dimensions, function(_i, _ao) {
								$.each(self.filteredData, function(_index, _val) {		
									if(_val[_ao.name] === _selectkey.trim()){
										selectedData[_ao.name] = _selectkey.trim();
									}
								});
								for (var index = 0; index < self.trackingData.length; index++) {
							
									if (self.trackingData[index][_ao.name]!=undefined && self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
										self.trackingData.splice(index, 1);
										index--;
										inArray = true;
									}

								}
							});

						});
						
						if (!inArray) {
							self.trackingData.push(selectedData);
						}
						/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
						if(WISE.Constants.editmode === "viewer"){
							gDashboard.itemGenerateManager.focusedItem = self;
						}
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, self.trackingData);
						break;
					case 'Single':

						//self.selectedPoint = _e.target;
						self.trackingData = [];
						
						if(d3.select(_this).attr("filter") === "true"){
				    		d3.select(_this)
							.attr("stroke","none")
		                    .attr("stroke-width","2")
							.attr("filter", 'false');

							otherSelection
							.attr("stroke","none")
		                    .attr("stroke-width","2")
							.attr("filter", 'false');
				    		
				    	}else{
				    		d3.selectAll('rect')
					    	.attr("stroke","none")
		                    .attr("stroke-width","2")
							.attr("filter", 'false');

							d3.selectAll('circle')
					    	.attr("stroke","none")
		                    .attr("stroke-width","2")
							.attr("filter", 'false');
							
							d3.select(_this)
							.attr("stroke","#4D4D4D")
		                    .attr("stroke-width","2")
							.attr("filter", 'true');
                            
                            otherSelection
                            .attr("stroke","#4D4D4D")
		                    .attr("stroke-width","2")
							.attr("filter", 'true');

							var selectedData = {};
							$.each(selectKey,function(_j,_selectkey){
								$.each(dimensions, function(_i, _ao) {
									$.each(self.filteredData, function(_index, _val) {		
										if(_val[_ao.name] === _selectkey.trim()){
											self.trackingData = [];
											selectedData[_ao.name] = _selectkey.trim();
											self.trackingData.push(selectedData);
											/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
										}
									});
								});
							});
				    	}
						/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
						if(WISE.Constants.editmode === "viewer"){
							gDashboard.itemGenerateManager.focusedItem = self;
						}
						/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
						gDashboard.filterData(self.itemid, self.trackingData);
						break;
				}
		    }

		    
		
		function row(d) {
		    return {
		        id: d.id,
		        value: +d.value,
		        color: d.color
		    };
		}
		
		
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self,self.DendrogramBarChart);
	}
	
	this.functionDo2 = function(_f) {			
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.DendrogramBarChart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.DendrogramBarChart['ShowCaption'] = false;
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
                            	
                            	self.DendrogramBarChart['Name'] = newName;
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
				var chagePalette = self.DendrogramBarChart.Palette;
				var firstPalette = self.DendrogramBarChart.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.DendrogramBarChart.Palette) != -1
										? self.DendrogramBarChart.Palette
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
//                                    self.dxItem.option('palette', self.customPalette);
                                    self.resize();
								} else {
                                    self.isCustomPalette = false;
                                    /*self.dxItem.option('palette', e.value);*/
                                    self.DendrogramBarChart.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.DendrogramBarChart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.DendrogramBarChart.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.DendrogramBarChart.Palette = chagePalette;
					}
                });
                p.option('visible', !(p.option('visible')));
				break;
			}
//			case 'editPalette': {
//				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
//					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office', 'Custom'];
//				// popup configs
//				var p = $('#editPopover').dxPopover('instance');
//				var chagePalette = self.DendrogramBarChart.Palette;
//				var firstPalette = self.DendrogramBarChart.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.DendrogramBarChart.Palette) 
//										? self.DendrogramBarChart.Palette
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
//                                    /*self.dxItem.option('palette', self.customPalette);*/
//                                    self.resize();
//								} else {
//                                    self.isCustomPalette = false;
//                                    /*self.dxItem.option('palette', e.value);*/
//                                    self.DendrogramBarChart.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.DendrogramBarChart.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.DendrogramBarChart.Palette);
//                            chagePalette = firstPalette;
//                            self.DendrogramBarChart.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.DendrogramBarChart.Palette = chagePalette;
//					}
//                });
//                p.option('visible', !(p.option('visible')));
//				break;
//			}
			default: break;
		}
	}

};


function checkingItem(_data) {
	return !_data.items.length;
};

WISE.libs.Dashboard.DendrogramBarChartFieldManager = function() {
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
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				self.DataItems['Dimension'].push(dataItem);
			}  else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['Name'] = $(_fieldlist[i]).children().get(0).innerText;
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM')
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = $(_fieldlist[i]).data('formatOptions');
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
