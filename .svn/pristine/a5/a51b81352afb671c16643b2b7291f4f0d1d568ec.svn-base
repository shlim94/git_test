WISE.libs.Dashboard.item.CalendarView3ChartGenerator = function() {
	var self = this;

	this.type = 'CALENDAR_VIEW3_CHART';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
    this.yearOptionArray=[];
	var dataMember;
	var Exprname;
	var FilterArray = [];
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";

	this.CalendarView3Chart = [];
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

	this.setCalendarView3Chart = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.CalendarView3Chart['ComponentName'] = this.ComponentName;
		this.CalendarView3Chart['Name'] = this.Name;
		this.CalendarView3Chart['DataSource'] = this.dataSourceId;

		this.CalendarView3Chart['DataItems'] = this.fieldManager.DataItems;
		this.CalendarView3Chart['Arguments'] = this.fieldManager.Arguments;
		this.CalendarView3Chart['Values'] = this.fieldManager.Values;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.CalendarView3Chart;
		
		// 임성현 초기 팔레트값 설정
		if (!(this.CalendarView3Chart['Palette'])) {
			this.CalendarView3Chart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		
		if (!(this.CalendarView3Chart['Legend'])) {
			this.CalendarView3Chart['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.CalendarView3Chart.AxisY)) {
			this.CalendarView3Chart.AxisY = {
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
		
		if (!(this.CalendarView3Chart['TextFormat'])) {
			this.CalendarView3Chart['TextFormat'] = 'Argument, Value'
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.CalendarView3Chart.InteractivityOptions) {
			if (!(this.CalendarView3Chart.InteractivityOptions.MasterFilterMode)) {
				this.CalendarView3Chart.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.CalendarView3Chart.InteractivityOptions.TargetDimensions)) {
				this.CalendarView3Chart.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.CalendarView3Chart.InteractivityOptions.IgnoreMasterFilters)) {
				this.CalendarView3Chart.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.CalendarView3Chart.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.CalendarView3Chart.LayoutOption){
			this.CalendarView3Chart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.CalendarView3Chart['ZoomAble']){
			this.CalendarView3Chart.ZoomAble = 'none'
		}
	};

	this.setCalendarView3ChartforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setCalendarView3Chart();
		}
		else{
			this.CalendarView3Chart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.CalendarView3Chart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.CalendarView3Chart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.CalendarView3Chart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.CalendarView3Chart['Palette'])) {
			this.CalendarView3Chart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var CalendarView3ChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.CALENDAR_VIEW3_CHART_DATA_ELEMENT);
				
				$.each(CalendarView3ChartOption,function(_i,_chartOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _chartOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _chartOption.CTRL_NM;
					}
					if(self.CalendarView3Chart.ComponentName == CtrlNM){
						self.CalendarView3Chart['Palette'] = _chartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.CalendarView3Chart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.CalendarView3Chart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.CalendarView3Chart.AxisY)) {
			this.CalendarView3Chart.AxisY = {
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
		if (!(this.CalendarView3Chart['TextFormat'])) {
			this.CalendarView3Chart['TextFormat'] = 'Argument, Value'
		}
		if(!this.CalendarView3Chart.LayoutOption){
			this.CalendarView3Chart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.CalendarView3Chart['ZoomAble']){
			this.CalendarView3Chart.ZoomAble = 'none'
		}
	}
	
	//d3vCal 뷰어모드
	this.setCalendarView3ChartForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setCalendarView3Chart();
		}
		else{
			this.CalendarView3Chart = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.CalendarView3Chart['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.CalendarView3Chart['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.CalendarView3Chart['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.CalendarView3Chart['Palette'])) {
			this.CalendarView3Chart['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var CalendarView3ChartOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.CALENDAR_VIEW3_CHART_DATA_ELEMENT);
				
				$.each(CalendarView3ChartOption,function(_i,_chartOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _chartOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _chartOption.CTRL_NM;
//					}
					if(self.CalendarView3Chart.ComponentName == CtrlNM){
						self.CalendarView3Chart['Palette'] = _chartOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.CalendarView3Chart.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.CalendarView3Chart.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.CalendarView3Chart.AxisY)) {
			this.CalendarView3Chart.AxisY = {
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
		if (!(this.CalendarView3Chart['TextFormat'])) {
			this.CalendarView3Chart['TextFormat'] = 'Argument, Value'
		}
		if(!this.CalendarView3Chart.LayoutOption){
			this.CalendarView3Chart.LayoutOption = {
					Label: {
						color: '#000000',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.CalendarView3Chart['ZoomAble']){
			this.CalendarView3Chart.ZoomAble = 'none'
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
			self.setCalendarView3Chart();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.CalendarView3Chart);
			gDashboard.itemGenerateManager.generateItem(self, self.CalendarView3Chart);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setCalendarView3ChartforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.CalendarView3Chart);
			gDashboard.itemGenerateManager.generateItem(self, self.CalendarView3Chart);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.CalendarView3Chart)) {
			this.setCalendarView3ChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.CalendarView3Chart);
			gDashboard.itemGenerateManager.generateItem(self, self.CalendarView3Chart);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setCalendarView3ChartForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.CalendarView3Chart);
			gDashboard.itemGenerateManager.generateItem(self, self.CalendarView3Chart);
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
//		self.currentMeasureName = measureKey.caption;
		self.currentMeasureName = WISE.util.Object.toArray(measureKey)[0].caption;
		
		//2020.11.03 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('d3');
		self.fCalendarView3Chart(dupledatacehck, this.measures, this.dimensions, dupledatacehck);
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
//				if($('#'+this.itemid+'editCalendarView3ChartPopover').length == 0 ){
//					$('<div id="'+this.itemid+'editCalendarView3ChartPopover">').dxPopover({
//					CalendarView3Chart 'auto',
//						width: 'auto',
//						position: 'bottom',
//						visible: false
//					}).appendTo('#wrap');
//				}
//			}else{
//				if($('#'+this.itemid+'editCalendarView3ChartPopover').length == 0 ){
//					$('<div id="'+this.itemid+'editCalendarView3ChartPopover">').dxPopover({
//						height: 'auto',
//						width: 'auto',
//						position: 'bottom',
//						visible: false
//					}).appendTo('#wrapper');
//				}
//			}
//			
//			var p = $('#'+this.itemid+'editCalendarView3ChartPopover').dxPopover('instance');
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
//						self.fCalendarView3Chart(self.filteredData);
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
		//2020.02.07 mksong sqllike 적용 dogfoot
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var dataSourceId = this.dataSourceId;
		self.selectedMeasure = MeasureKey;
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
		ValueArray.push(self.filteredData);
		self.yearOptionData={};
		var returnArr = self.getNewDate(self.filteredData,Measure,Dimension)
		
		return returnArr;
	};

	this.getNewDate = function(_dateList,_measure,_dimension){
		var reDateList = [];
		self.minY=0;
		self.maxY =0;
		$.each(_dateList,function(_i,__dateVal){
			var _dateVal
			if(typeof _dimension != 'undefined'){
				$.each(_dimension,function(_index,_dim){
					if(typeof __dateVal[_dim.DataMember] != 'undefined'){
						_dateVal = __dateVal[_dim.DataMember];
					}else{
						_dateVal = "";
					}
				})
			}
	
			var replaceVal = _dateVal.replace(/(\s*)/g, "");
			
			if(replaceVal.indexOf('년') > -1){
				replaceVal = replaceVal.replace('년','');
			}
			if(replaceVal.indexOf('월') > -1){
				replaceVal = replaceVal.replace('월','');
			}
			if(replaceVal.indexOf('일') > -1){
				replaceVal = replaceVal.replace('일','');
			}
			
			var datacheck = self.checkDataTodate(replaceVal);
			if(datacheck){
                
                if(_i == 0){
					self.minY = Number(replaceVal.slice(0,4));
					self.maxY = Number(replaceVal.slice(0,4));
				}else{
                    self.minY = Number(replaceVal.slice(0,4)) < self.minY ? Number(replaceVal.slice(0,4)) : self.minY;
                    self.maxY = Number(replaceVal.slice(0,4)) > self.maxY ? Number(replaceVal.slice(0,4)) : self.maxY;
				}
                self.yearOptionData[replaceVal.slice(0,4)] = Number(replaceVal.slice(0,4));
                var dt
                var format = self.formatDate;
                dt = moment(replaceVal, format.toLocaleUpperCase());
				
				dateVal = dt.toDate();

				reDateList.push({'Date' : replaceVal , 'value': __dateVal[_measure[0].captionBySummaryType],'dim':_dateVal})
			
			}else{
				WISE.alert('날짜(yyyymmdd) 형식의 데이터를 넣어 주세요!');
				gProgressbar.hide();
			}
		})
		
		return reDateList
	}

	this.checkDataTodate = function(_data){
        var check = false;
		var re;
		if(!check){
			re = /[0-9]{4}(0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1])/; 
			check = re.test(_data);
			if(check)self.formatDate = 'yyyymmdd';
			self.scope = 'days'
		} 
        
        return check;

	}
	
	String.prototype.replaceAll = function(org, dest) {
	    return this.split(org).join(dest);
	}
	
	this.__getTopNData = function(queryData,dimensions,nowDim){
		
		
		var sumNm;
		$.each(self.measures,function(_index,_item){
			if(_item.name == self.topMember){
				sumNm = _item.captionBySummaryType;
			}
		})
		
		var topnData = [];
		var otherData =[];
		var topNarray = [];
		var topNresult = [];
		var TopNExecSyx;
		var sortTopNdata;
		var TopNotherData;
		
		
		
		$.each(queryData,function(_index,_e){
			var ExecSyx = DevExpress.data.query(_e.items);
			ExecSyx = ExecSyx.groupBy(nowDim);
			topNarray = ExecSyx.toArray();
            $.each(topNarray, function(i, e) {
				topnData.push(e);
			});
		})
        return topnData;
	}
	
//	this.resize = function() {
//		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/
//		var dupledatacehck = self.deleteDuplecateData(self.filteredData,self.measures);
//		self.fCalendarView3Chart(dupledatacehck, self.measures, self.dimensions, dupledatacehck);
//		gProgressbar.hide();
//	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/
		var dupledatacehck
		if(typeof self.resizeData != 'undefined'){
		    dupledatacehck = self.resizeData;
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
		    self.fCalendarView3Chart(dupledatacehck, self.measures, self.dimensions, dupledatacehck);
		}
		gProgressbar.hide();
	};
	
	
	this.fCalendarView3Chart = function(jsonData, measures, dimensions, dupleData) {
		
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


        
		
		d3.select("#" + self.itemid).selectAll("svg").remove();
		d3.select("#" + self.itemid).selectAll("div").remove();
		d3.select("#" + self.itemid).selectAll("input").remove();
		d3.selectAll(".tooltip"+ self.itemid).remove();
		$("#halfpage" + self.itemid).remove();
		$("#selectBox_" + self.itemid).remove();
		
		
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
		var selectmea = WISE.util.Object.toArray(self.selectedMeasure);
		var NumericFormat;
		$.each(WISE.util.Object.toArray(self.DI.Measure),function(_i,_val){
			if(selectmea[0].uniqueName ===  _val.UniqueName){
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
        var yearOption = Object.keys(self.yearOptionData);
       

        self.paletteData = ['시작 값','끝 값','1월','2월','3월','4월','5월','6월','7월','8월','9월','10월','11월','12월']
		//self.paletteData.push('시작 값')
		//self.paletteData.push('끝 값')

        var colorz;
		var colorRange
        if(typeof self.meta.Palette === "string"){
            colorz = gDashboard.d3Manager.getPalette(self);		
			colorRange = [colorz[0],colorz[1]];
        }else{
			colorz = gDashboard.d3Manager.getPalette(self);		
			colorRange = [self.meta.Palette[0], self.meta.Palette[1]]
        }

        if(self.meta.Palette)

		var monthArray=[],yearArray={},monthColorArray=[],yearColorArray=[];
        $.each(dupleData,function(_index,_val){
        	var calcdataY,calcdataM,startval,endval;
        	calcdataY = _val.Date.slice(0,4);
        	if(typeof yearArray[calcdataY] === 'undefined'){
        		yearArray[calcdataY]=[];
        	}
        	startval = parseInt(_val.Date.slice(6,8))-1
        	endval = parseInt(_val.Date.slice(6,8))
        	calcdataM = { 'block_id':_val.Date.slice(4,6),
        	              'start':startval,
        	              'end':endval,
        	              'value':_val.value,
        	              'year': calcdataY,
        	              'Date': _val.dim
        	             }
        	yearArray[calcdataY] = yearArray[calcdataY].concat(calcdataM);
        })

        $.each(yearArray,function(_index,_val){
        	var calcdata = _index;
        	var color_Max = d3.max(_val, function(d) { return d.value; });
		    var color_Min = d3.min(_val, function(d) { return d.value; });
        	if(typeof yearColorArray[calcdata] === 'undefined'){
        		monthColorArray=[];
        	}
        	var color = d3.scale.linear()
	        .domain([color_Min, color_Max])
	        //.range(d3v3.range(11).map(function(d) { return "q" + d + "-11"; }));
	        .range(colorRange);
	        
        	yearColorArray[calcdata] = color;
        })
        
        yearOption.unshift('전체')

		var w = $("#" + self.itemid).width() - 40;
        var h = $("#" + self.itemid).height()- 40;
		var circosR = w > h ? h : w
		

		function drawCircos(error, months) {
            d3.select("#" + self.itemid).selectAll("svg").remove();
			d3.select("#" + self.itemid).selectAll("div").remove();
			d3.select("#" + self.itemid).selectAll("input").remove();
			d3.selectAll(".tooltip"+ self.itemid).remove();

			var tooltip = d3.select("body")
			  .append("div").attr("id", "tooltip")
			  .attr("class", "tooltip"+ self.itemid)
			  .style("position", "absolute")
			  .style("z-index", "10")
			  .style("visibility", "hidden")
			  .style("display", "none")

			 var selectBox = d3.select("#" + self.itemid).append("div")
			.attr("id", "selectBox_" + self.itemid)
			.attr("class", "selectBox")
			.style('width','auto')
			.style('height','30px')
			.style('z-index','20');

			var circosHeatmap = new Circos({
		        container: '#'+ self.itemid,
		        width: circosR,
		        height: circosR
		    });
		    
            
            if(typeof self.meta.Palette === "string"){
                $.each(months,function(_j,_col){
		    	    _col.color = colorz[_j];
		        })
			}else{
				$.each(months,function(_j,_col){
		    	    _col.color = colorz[_j+2];
		        })
			}

		    circosHeatmap
		      .layout(
		        months,
		        {
		          innerRadius: circosR / 2 - (circosR/5),
		          outerRadius: circosR / 2 - (circosR/7),
		          ticks: {display: false},
		          labels: {
		            position: 'center',
		            display: true,
//		            size: (((circosR/6)-(circosR/8))/2),
		            size:  self.meta.LayoutOption.Label.size,
		            color: self.meta.LayoutOption.Label.color,
		            radialOffset: (((circosR/6)-(circosR/8))/2)
		          },
		          events: {
				  'mouseover.demo': function (d, i, nodes, event) {
					//console.log(d, i, nodes, event)
					mouseover(d, i, nodes, event)
					d3.select('.cs-layout').selectAll('g').style("cursor", "pointer")
				  },
				  'mouseout.demo': function (d, i, nodes, event) {
					//console.log(d, i, nodes, event)
					mouseout(d, i, nodes, event)
				  }
				}
		        }
		      )
			  
			  


              var rdiusval = 0.99
              var rdiLen;
              if(self.yearOptionArray.length === 0){
              	  rdiLen = 0.6 / yearOption.length
				  $.each(yearOption,function(_j,_y){
					 if(_y!='전체'){
                        circosHeatmap
						  .heatmap('_heatmap'+_j, yearArray[_y], {
							innerRadius: rdiusval-rdiLen,
							outerRadius: rdiusval,
							logScale: false,
							color: 'Spectral',
							events: {
							  'mouseover.demo': function (d, i, nodes, event) {
								//console.log(d, i, nodes, event)
								mouseover(d, i, nodes, event)
							  },
							  'mouseout.demo': function (d, i, nodes, event) {
								//console.log(d, i, nodes, event)
								mouseout(d, i, nodes, event)
							  }
							}
						  })

						 rdiusval = rdiusval-rdiLen;
					 }
				  })
              }else{
              	 rdiLen = 0.6 / self.yearOptionArray.length
              	 $.each(self.yearOptionArray,function(_j,_y){
					if(_y!='전체'){
                        circosHeatmap
						  .heatmap('_heatmap'+_j, yearArray[_y], {
							innerRadius: rdiusval-rdiLen,
							outerRadius: rdiusval,
							logScale: false,
							color: 'Spectral',
							events: {
							  'mouseover.demo': function (d, i, nodes, event) {
								//console.log(d, i, nodes, event)
								mouseover(d, i, nodes, event)
							  },
							  'mouseout.demo': function (d, i, nodes, event) {
								//console.log(d, i, nodes, event)
								mouseout(d, i, nodes, event)
							  }
							}
						  })

						 rdiusval = rdiusval-rdiLen;
					 }
				  })
              }
		      

		      circosHeatmap.render()
            

/*              d3.select('.cs-layout').selectAll('g')
			  .on('mouseover',function(d, i, nodes, event){
			          mouseoverMonth(d, i, nodes, event);
			      }
			  );*/

              //if(typeof self.meta.Palette === "string"){
                  circosHeatmap.svg.selectAll('.tile')
				  .attr("fill",function(d){
					return yearColorArray[d.year](d.value)
				  })
				  .style("cursor", "pointer")	
              //}

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
		      
		       function mouseover(d, i, nodes, event) {
		       	    var yearlenArray;
					if(self.yearOptionArray.length === 0){
						yearlenArray = yearOption
					}else{
						yearlenArray = self.yearOptionArray
					}

					var monthSumAr=[],monthSum
                    tooltip.style("visibility", "visible");
					var percent_data;
                    if(!d.value){
                    	$.each(yearlenArray,function(_j,_year){
							monthSum = [];
							if(_year!='전체'){
								
								switch(self.selectedMeasure[0].summaryType){
								    case 'sum' :
								        monthSum = d3.sum(yearArray[_year], function(_d) { 
											return d.id == _d.block_id ?_d.value :0; 
										});
								    break;
								    case 'avg' :
								        monthSum = d3.mean(yearArray[_year], function(_d) { 
											return d.id == _d.block_id ?_d.value :0; 
										});
								    break;
								    case 'count' :
								       monthSum = 0
								       $.each(yearArray[_year],function(_k,_d){
                                            if(d.id == _d.block_id)monthSum++
								       	});
								    break;
								    case 'min' :
								        monthSum = d3.min(yearArray[_year], function(_d) { 
											if(d.id == _d.block_id){
												return _d.value; 
											}
										});
								    break;
								    case 'max' :
								        monthSum = d3.max(yearArray[_year], function(_d) { 
											if(d.id == _d.block_id){
												return _d.value; 
											}	
										});
								    break;

								    	
								}
							    monthSumAr+= '<p>'+_year+ d.id+" : "+NumberF.unit(monthSum, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled)+'</p>';	
							}



						});

						percent_data = monthSumAr;
                    }else{
                    	percent_data = textFormat(d);
                    }

					

					tooltip.transition()        
								.duration(200)      
								.style("opacity", .9)
								.style("display",'block');
					tooltip.html(percent_data)  
								.style("left", (event.pageX)+30 + "px")     
								.style("top", (event.pageY) + "px"); 
				  }
				  function mouseout (d, i, nodes, event) {
					tooltip.transition()        
							.duration(500)      
							.style("opacity", 0)
							.style("display",'none'); 
					var $tooltip = $(".tooltip_+"+ self.itemid);
					//$tooltip.empty();
				  }


			   function textFormat(d){
				  var textValue=""
				  switch(self.meta.TextFormat){
					  case 'none': {
						  textValue ="";
						  break;
					  }
					  case 'Argument': {
						  textValue = d.Date;
						  break;
					  }
					  case 'Value': {
						  var val = d.value? d.value : 0
						  textValue = NumberF.unit(val, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);
						  break;
					  }
					  case 'Argument, Value': {
						  var val = d.value? d.value : 0
						  textValue = d.Date+'  :  '+ NumberF.unit(val, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled);	
						  break;
					  }
					  case 'Percent': {
						  var percent = d3.format(".1%");
// 						  perStr = d.slice(0,7);
						  var tv = d3v3.sum(yearArray[d.year], function(d) { 
						              return d.value; 	
							  });	
						  var rePer = d.Date ? percent(d.value / tv): percent(0)
					  	  textValue = d.Date +'  :  '+ rePer;
//						  textValue = d.value + '%';
						  break;
					  }
					  case 'Value, Percent': {
						  var percent = d3.format(".1%");
// 						  perStr = d.slice(0,7);
						  var tv = d3v3.sum(yearArray[d.year], function(d) { 
						              return d.value; 	
							  });	
						  var rePer = d.Date ? percent(d.value / tv): percent(0)
					  	  var percentText = rePer;
						  var val = d.value? d.value : 0;
						  textValue = NumberF.unit(val, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + '(' + percentText + ')';
						  break;
					  }
					  case 'Argument, Percent': {
						  var percent = d3.format(".1%");
// 						  perStr = d.slice(0,7);
						  var tv = d3v3.sum(yearArray[d.year], function(d) { 
						              return d.value; 	
							  });	
						  var rePer = d.Date ? percent(d.value / tv): percent(0)
					  	  var percentText = rePer;
						  var val = d.value? d.value : 0;
						  textValue = d.Date +'  :  '+ percentText;
						  break;
					  }
					  case 'Argument, Value, Percent': {
						  var percent = d3.format(".1%");
// 						  perStr = d.slice(0,7);
						  var tv = d3v3.sum(yearArray[d.year], function(d) { 
						              return d.value; 	
							  });	
						  var rePer = d.Date ? percent(d.value / tv): percent(0)
					  	  var percentText = rePer;
						  var val = d.value? d.value : 0;
						  var val = d.value? d.value : 0;
						  textValue = d.Date +'  :  '+NumberF.unit(val, labelFormat, labelUnit, labelPrecision, labelSeparator, undefined, labelSuffix, labelSuffixEnabled) + '(' + percentText + ')';
						  break;
					  }

				  }
				  return textValue
			  }
                

              

		      $("#selectBox_" + self.itemid).dxSelectBox({
				width: 120,
				items: yearOption,
				itemTemplate: function(data) {
					var html = $('<div />');
					$('<p />').text(data).css({
						display: 'inline-block',
						float: 'left'
					}).appendTo(html);

					return html;
				},
				value: self.yearOptionArray.length != 0 ? self.yearOptionArray[0] : yearOption[0],
				onValueChanged: function(e) {
					if(e.value ==='전체'){
                        self.yearOptionArray=yearOption;
					}else{
						self.yearOptionArray=[];
						self.yearOptionArray.push(e.value);
					}
                    
                    self.resize();
				}
            });

//            d3.select("#" + self.itemid).select("svg")
//            .attr("transform", "translate(" + (($("#" + self.itemid).width()-circosR)/2) + "," 
//	                                      + ((h-circosR)/2) + ")");
            $("#" + self.itemid).find('svg').parent().attr('id','svgParentid')
            
            
            d3.select('#svgParentid')
                .style("font-family", self.meta.LayoutOption.Label.family)
				.style("left",(($("#" + self.itemid).width()-circosR)/2)+"px")
				.style("top",((h-circosR)/2)+"px")
				
            selectBox.style("margin-left", "20px")
            .style("margin-top", "20px");
            
    		$('.circos-tooltip').remove();
		}


	
		d3.queue()
		  .defer(d3.json, '../resources/visual/months.json')
		  .await(drawCircos)


	      
		
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self,self.CalendarView3Chart);
	}
	
	this.functionDo2 = function(_f) {			
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.CalendarView3Chart['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.CalendarView3Chart['ShowCaption'] = false;
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
                            	
                            	self.CalendarView3Chart['Name'] = newName;
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
				var chagePalette = self.CalendarView3Chart.Palette;
				var firstPalette = self.CalendarView3Chart.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.CalendarView3Chart.Palette) != -1
										? self.CalendarView3Chart.Palette
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
                                    self.CalendarView3Chart.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.CalendarView3Chart.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.CalendarView3Chart.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.CalendarView3Chart.Palette = chagePalette;
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
//				var chagePalette = self.CalendarView3Chart.Palette;
//				var firstPalette = self.CalendarView3Chart.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.CalendarView3Chart.Palette) 
//										? self.CalendarView3Chart.Palette
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
//                                    self.CalendarView3Chart.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.CalendarView3Chart.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.CalendarView3Chart.Palette);
//                            chagePalette = firstPalette;
//                            self.CalendarView3Chart.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.CalendarView3Chart.Palette = chagePalette;
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

WISE.libs.Dashboard.CalendarView3ChartFieldManager = function() {
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
//				dataItem['NumericFormat'] = NumericFormat;
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
