WISE.libs.Dashboard.item.ParallelCoorGenerator = function() {
	var self = this;

	this.type = 'PARALLEL_COORDINATE';

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
	this.trackingData = [];
	this.Parallel = [];
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

	this.setParallel = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.Parallel['ComponentName'] = this.ComponentName;
		this.Parallel['Name'] = this.Name;
		this.Parallel['DataSource'] = this.dataSourceId;

		this.Parallel['DataItems'] = this.fieldManager.DataItems;
		this.Parallel['Arguments'] = this.fieldManager.Arguments;
		this.Parallel['Values'] = this.fieldManager.Values;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.Parallel;
		
		// 임성현 초기 팔레트값 설정
		if (!(this.Parallel['Palette'])) {
			this.Parallel['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		}
		
		if (!(this.Parallel['Legend'])) {
			this.Parallel['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.Parallel.AxisY)) {
			this.Parallel.AxisY = {
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
		if (this.Parallel.InteractivityOptions) {
			if (!(this.Parallel.InteractivityOptions.MasterFilterMode)) {
				this.Parallel.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Parallel.InteractivityOptions.TargetDimensions)) {
				this.Parallel.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.Parallel.InteractivityOptions.IgnoreMasterFilters)) {
				this.Parallel.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Parallel.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.Parallel.LayoutOption){
			this.Parallel.LayoutOption = {
					AxisY: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
					AxisX: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
					Legend: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
			}
		}
		
		if(!this.Parallel['ZoomAble']){
			this.Parallel.ZoomAble = 'none'
		}
		
	};

	this.setParallelforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setParallel();
		}
		else{
			this.Parallel = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.Parallel['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.Parallel['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.Parallel['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.Parallel['Palette'])) {
			this.Parallel['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var ParallelOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.PARALLEL_DATA_ELEMENT);
				
				$.each(ParallelOption,function(_i,_parallelOption){
					var CtrlNM;
					if (page[page.length - 1] === 'viewer.do'){
						CtrlNM = _parallelOption.CTRL_NM +"_"+WISE.Constants.pid;
					}else{
						CtrlNM = _parallelOption.CTRL_NM;
					}
					if(self.Parallel.ComponentName == CtrlNM){
						self.Parallel['Palette'] = _parallelOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.Parallel.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.Parallel.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.Parallel.AxisY)) {
			this.Parallel.AxisY = {
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
		
		if (!(this.Parallel['Legend'])) {
			this.Parallel['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.Parallel.InteractivityOptions) {
			if (!(this.Parallel.InteractivityOptions.MasterFilterMode)) {
				this.Parallel.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Parallel.InteractivityOptions.TargetDimensions)) {
				this.Parallel.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.Parallel.InteractivityOptions.IgnoreMasterFilters)) {
				this.Parallel.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Parallel.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.Parallel.LayoutOption){
			this.Parallel.LayoutOption = {
					AxisY: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
					AxisX: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
					Legend: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
			}
		}
		
		if(!this.Parallel.LayoutOption.AxisY.size){
			this.Parallel.LayoutOption.AxisY.size = 12;
			this.Parallel.LayoutOption.AxisX.size = 12;
			this.Parallel.LayoutOption.Legend.size = 12;
		}
		if(!this.Parallel['ZoomAble']){
			this.Parallel.ZoomAble = 'none'
		}
	}
	
	//d3 뷰어모드
	this.setParallelForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setParallel();
		}
		else{
			this.Parallel = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.Parallel['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.Parallel['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.Parallel['Values'] = this.meta['Values'] = this.fieldManager.Values;
			this.measures = this.fieldManager.measures;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		if (!(this.Parallel['Palette'])) {
			this.Parallel['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			
			if(gDashboard != undefined){
				var ParallelOption = typeof gDashboard.structure.MapOption.DASHBOARD_XML == 'undefined' ? '' : WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.PARALLEL_DATA_ELEMENT);
				
				$.each(ParallelOption,function(_i,_parallelOption){
					var CtrlNM;
//					if (page[page.length - 1] === 'viewer.do'){
//						CtrlNM = _parallelOption.CTRL_NM +"_"+WISE.Constants.pid;
//					}else{
						CtrlNM = _parallelOption.CTRL_NM;
//					}
					if(self.Parallel.ComponentName == CtrlNM){
						self.Parallel['Palette'] = _parallelOption.PALETTE_NM;
						return false;
					}
				})
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.Parallel.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.Parallel.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		
		if (!(this.Parallel['Legend'])) {
			this.Parallel['Legend'] = {
					Visible : true,
					Position : "TopRightVertical"
			}
		}
		
		/*dogfoot Y축 설정 추가 shlim 20200831*/
		if (!(this.Parallel.AxisY)) {
			this.Parallel.AxisY = {
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
		if (this.Parallel.InteractivityOptions) {
			if (!(this.Parallel.InteractivityOptions.MasterFilterMode)) {
				this.Parallel.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Parallel.InteractivityOptions.TargetDimensions)) {
				this.Parallel.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.Parallel.InteractivityOptions.IgnoreMasterFilters)) {
				this.Parallel.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Parallel.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.Parallel.LayoutOption){
			this.Parallel.LayoutOption = {
					AxisY: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
					AxisX: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
					Legend: {
						color : '#000000',
						family : '맑은 고딕',
						size: 12
					},
			}
		}
		
		if(!this.Parallel.LayoutOption.AxisY.size){
			this.Parallel.LayoutOption.AxisY.size = 12;
			this.Parallel.LayoutOption.AxisX.size = 12;
			this.Parallel.LayoutOption.Legend.size = 12;
		}
		if(!this.Parallel['ZoomAble']){
			this.Parallel.ZoomAble = 'none'
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
			self.setParallel();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Parallel);
			gDashboard.itemGenerateManager.generateItem(self, self.Parallel);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setParallelforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Parallel);
			gDashboard.itemGenerateManager.generateItem(self, self.Parallel);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.Parallel)) {
			this.setParallelForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Parallel);
			gDashboard.itemGenerateManager.generateItem(self, self.Parallel);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setParallelForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Parallel);
			gDashboard.itemGenerateManager.generateItem(self, self.Parallel);
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
		self.currentMeasureName = measureKey.caption;
		
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fParallelCoordinates2(dupledatacehck, this.measures, this.dimensions, dupledatacehck);
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
			if (self.dxItem){
				d3.selectAll(".foreground path").style("stroke-width", 1)
				.attr('filter', "false");
			}
			self.trackingData = [];
			self.selectedPoint = undefined;	
		}
	};
	this.renderButtons = function(_itemid) {
		gDashboard.itemGenerateManager.renderButtons(self);
	};
	
	this.deleteDuplecateData = function(_data,MeasureKey){
		return gDashboard.d3Manager.getDataSource(self, self.type, {'data' : _data, 'measerKey': MeasureKey});
	}
	this.deleteDuplecateData2 = function(_data,MeasureKey){
		//2020.02.07 mksong sqllike 적용 dogfoot
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		var dataSourceId = this.dataSourceId;
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

		var resultArr = new Array();
		$.each(ValueArray,function(_i,_e){
			$.each(_e,function(_item,_obj){
				var str = new Array();
				var object = new Object();
				$.each(Dimension,function(_i,_Dim){
					str.push(_obj[_Dim.DataMember]);
				});
				$.each(Measure,function(_i,_Mea){
					object['value'] = _obj[_Mea.summaryType + '_' + _Mea.caption];
				});

				object['name'] = str.join(' - ');
				resultArr.push(object);
			})
		});
		return resultArr;
	};
	
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		/*dogfoot 고급시각화차트 팔레트 바로 반영되도록 수정 shlim 20200729*/
		if(typeof self.resizeData != 'undefined'){
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fParallelCoordinates2(self.resizeData, self.measures, self.dimensions, self.resizeData);
			d3.selectAll('.foreground path[filter="true"]').style("stroke-width", 6).attr('filter', "true");
		}
		
		gProgressbar.hide();
	};
	
	
	this.fParallelCoordinates2 = function(jsonData, measures, dimensions, dupleData) {
		
		var nodata = false;
		
		if (!dupleData || ($.type(dupleData) === 'array' && dupleData.length === 0)
				|| (dupleData.length == 1 && dupleData[0].value == 0 && dupleData[0].name == "")) {
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
				|| (dupleData.length == 1 && dupleData[0].value == 0 && dupleData[0].name == "")){
			
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
		
		var species = [];
		$.each(dupleData, function(_i, _o) {
			species.push(_o.name)
		});

		var traits = [];
		$.each(measures, function(_i, _o) {
			traits.push(_o.captionBySummaryType)
		});
		
		var dimesionsName = [];
		$.each(dimensions, function(_i, _o) {
			dimesionsName.push(_o.name)
		});
		
		self.paletteData = self.filteredData.map(function (val, index) {
			return val[self.dimensions[0].name];
		}).filter(function (val, index, arr) {
			return arr.indexOf(val) === index;
		});
		
		/*var paletteName = "Material";
		var rgb = [];
		
		d3.json("../resources/d3/palette.json", function(error, root) {
			$.each(root[paletteName],function(_i,_val){
				rgb.push(_val.paletteval);	
			})
		});
		*/
		
//		var paletteName = self.Parallel.Palette;
//		var rgb = getPaletteValue(paletteName);
		var rgb = gDashboard.d3Manager.getPalette(self);
		var rgbLen = 0;
		
		d3.select("#" + self.itemid).selectAll("svg").remove();
		
		var m = [40, 80, 100, 80],
		w = $('#'+self.itemid).width() * 65 / 100,
		h = $('#'+self.itemid).height() * 65 / 100;
		
		var x = d3.scale.ordinal().domain(traits).rangePoints([0, w]),
		y = {};
		var zoomCnt=0
		

		var line = d3.line(),
		axis = d3.axisLeft(),
		background,
		foreground;
		var xLeng = ($('#'+self.itemid).width() - w) / 2;
		if(self.meta.Legend.Visible && self.meta.Legend.Position.indexOf("Left") > -1)
			xLeng += (w * 0.2);
		var hLeng = ($('#'+self.itemid).height() - h) / 2;
//		var zoom = d3.zoom().on("zoom", function (d,zz) {
//					  d3.select('#'+self.itemid).select('g').attr("transform", function(){ 
//					          if(zoomCnt==0){
//									d3.event.transform.x = d3.event.sourceEvent.layerX
//									d3.event.transform.y = d3.event.sourceEvent.layerY
//									d3.event.transform.k =1;
//							  }
//							  if(d3.event.transform.k <= 1){
//							  	zoomCnt++;
//							  	d3.event.transform.x = d3.event.sourceEvent.layerX
//								d3.event.transform.y = d3.event.sourceEvent.layerY
//								d3.event.transform.k =1;
//							  	return "translate(" + xLeng + "," + hLeng + ")";
//							  }
//					          if(d3.event.transform.x ===0 && d3.event.transform.y ===0){
//									d3.event.transform.x = d3.event.sourceEvent.layerX
//									d3.event.transform.y = d3.event.sourceEvent.layerY
//							   }
//							   zoomCnt++
//							return d3.event.transform;
//						})
//					})
					
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
									d3.event.transform.k = 1;
								    zoomable();
								    return "translate(" + xLeng + "," + hLeng + ")";
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
		var svg = d3.select("#" + self.itemid).append("svg:svg")
		.attr("width", $('#'+self.itemid).width())
		.attr("height", $('#'+self.itemid).height())
		//.call(zoom)
		.append("svg:g")
//		.attr('transform', 'translate(' + xMargin + ', ' + yMargin + ')');
//		.attr("transform", "translate(150," + m[0] + ")");
		.attr("transform", "translate(" + xLeng + "," + hLeng + ")");
		
		if(self.meta.ZoomAble != 'none'){
			zoomable();
		}

//		d3.csv("http://localhost:58080/olap/UploadFiles/excel/cars.csv", function(error, cars) {
		// Extract the list of dimensions and create a scale for each.

		traits.forEach(function(d) {
			// Coerce values to numbers.
			self.filteredData.forEach(function(p) { p[d] = +p[d]; });
			
			y[d] = d3.scaleLinear()
			.domain(d3.extent(self.filteredData, function(p) { return +p[d]; }))
			.range([h, 0]);
			
			
		});
		
		/*var legend = svg.selectAll("g.legend")
		.data(species)
		.enter().append("svg:g")
		.attr("class", "legend")
//		.attr("transform", function(d, i) { return "translate(1050," + (i * 20) + ")"; });
		.attr("transform", function(d, i) { return "translate("+ (w+(w/15)) +"," + (i * (h/species.length-9)) + ")"; });
		

		rgbLen = -1;
		legend.append("svg:rect")
		.attr("class", String)
		.attr("width", 10)
		.attr("height", 10)
		.style("fill", function(d, i) {
			rgbLen++;
			if(rgb[rgbLen] == undefined){
				rgbLen = 0;
			}
			return rgb[rgbLen]; 
		});

		legend.append("svg:text")
		.attr("x", 12)
		.attr("dy", ".31em")
		.attr("font-size",  function(d, i){
		  		var fontz = (w/h) *10;
		  		if(fontz>10){
		  			fontz = 10;
		  		}
		  		return fontz;
		 	 }	  	
		  )
		.text(function(d) { return d; });*/
		var NumberF = WISE.util.Number
		function dollarFormatter(n) {
			n = Math.round(n);
			var result = n;
			if(self.Parallel.AxisY){
				var NumericY = self.Parallel.AxisY
				if(!NumericY.Visible){
					return '';
				}else{
				    return NumberF.unit(result, NumericY.FormatType, NumericY.Unit, NumericY.Precision, NumericY.Separator, undefined, NumericY.MeasureFormat, NumericY.SuffixEnabled);	
				}
		  	}
		}
		if(self.meta.Legend.Visible){
			var legend;
			if(self.meta.Legend.Position.indexOf("Left") > -1){
				legend = svg.append("g")
			    .attr("class", "legend")
				//.attr("x", w - 65)
				//.attr("y", 50)
			    .attr("height", 100)
			    .attr("width", 100)
				.attr('transform', 'translate(-' + (w + w * 0.4) + ',10)')  
			}else{
				legend = svg.append("g")
			    .attr("class", "legend")
				//.attr("x", w - 65)
				//.attr("y", 50)
			    .attr("height", 100)
			    .attr("width", 100)
				.attr('transform', 'translate(10,10)')  
			}


			var rgbLen = -1;
			if(self.meta.Legend.Position.indexOf("Center") > -1){
				var _y = self.meta['Legend'].Position.indexOf("Bottom") > -1? h + 25 : -70;
				legend.selectAll('rect')
				  .data(species)
				  .enter()
				  .append("rect")
				  .attr("x", function(d, i){ 

					  	return i *  (w/species.length) - 9;
					  })
				  .attr("y", _y)
				  .attr("width", 10)
				  .attr("height", 10)
				  .style("fill", function(d, i) { 
					rgbLen++;
					if(rgb[rgbLen] == undefined){
						rgbLen = 0;
					}
					return rgb[rgbLen];
				  })

				legend.selectAll('text')
				  .data(species)
				  .enter()
				  .append("text")
				  .attr("x", function(d, i){ 

					  	return i *  (w/species.length);
					  })
				  .attr("y", _y + 9)
//				  .style("font-size",  function(d, i){
//				  		var fontz = gDashboard.fontManager.getFontSize((w/h) * 10, 'Item');
//				  		if(Number(fontz.split('px')[0])>15 + Number(gDashboard.fontManager.getFontSize(0, 'Item').split('px')[0])){
//				  			fontz = gDashboard.fontManager.getFontSize(15, 'Item');
//				  		}else if(Number(fontz.split('px')[0]) < 5)
//				  			fontz = 5;
//				  		return fontz;
//				 	 })
				  .style("font-family", gDashboard.fontManager.getFontFamily('Item'))
				  .text(function(d) {
					return d;
				  });
			}else{
				legend.selectAll('rect')
				  .data(species)
				  .enter()
				  .append("rect")
				  .attr("x", w+15)
				  .attr("y", function(d, i){ 

				  	return i *  (h/species.length) - 9;
				  })
				  .attr("width", 10)
				  .attr("height", 10)
				  .style("fill", function(d, i) { 
					rgbLen++;
					if(rgb[rgbLen] == undefined){
						rgbLen = 0;
					}
					return rgb[rgbLen];
				  })

				legend.selectAll('text')
				  .data(species)
				  .enter()
				  .append("text")
				  .attr("x", w+30)
				  .attr("y", function(d, i){ return i *  (h/species.length);})
//				  .style("font-size",  function(d, i){
//				  		var fontz = gDashboard.fontManager.getFontSize((w/h) * 10, 'Item');
//				  		if(Number(fontz.split('px')[0])>15 + Number(gDashboard.fontManager.getFontSize(0, 'Item').split('px')[0])){
//				  			fontz = gDashboard.fontManager.getFontSize(15, 'Item');
//				  		}else if(Number(fontz.split('px')[0]) < 5)
//				  			fontz = 5;
//				  		return fontz;
//				 	 })
				  .style("font-family", gDashboard.fontManager.getFontFamily('Item'))
				  .text(function(d) {
					return d;
				  });
			}
			
			d3.selectAll("#"+self.itemid + ' .legend text')
			.style("font-family", self.meta.LayoutOption.Legend.family)
			.style("fill", self.meta.LayoutOption.Legend.color)
			.style("font-size", self.meta.LayoutOption.Legend.size + 'px')
		 
		}
		
		// Add grey background lines for context.
		background = svg.append("svg:g")
		.attr("class", "background")
		.selectAll("path")
		.data(self.filteredData)
		.enter().append("path")
		.attr("d", path);
		// Add blue foreground lines for focus.

		foreground = svg.append("svg:g")
		.attr("class", "foreground")
		.selectAll("path")
		.data(self.filteredData)
		.enter().append("path")
//		.attr("font-size", function(d, i){
//			var fontz = gDashboard.fontManager.getFontSize((w/h) * 10, 'Item');
//	  		if(Number(fontz.split('px')[0])>15 + Number(gDashboard.fontManager.getFontSize(0, 'Item').split('px')[0])){
//	  			fontz = gDashboard.fontManager.getFontSize(15, 'Item');
//	  		}else if(Number(fontz.split('px')[0]) < 5)
//	  			fontz = 5;
//	  		return fontz;
//	 	 })
	 	 .on("click", function(d) {
			
	    	  switch(self.meta.InteractivityOptions.MasterFilterMode){
	    		case 'Single':
	    			self.trackingData = [];
	    			if(d3.select(this).attr("filter") === "true"){
	    				d3.selectAll(".foreground path").style("stroke-width", 1).attr('filter', "false");
			    	}else{
			    		//선택 모두 해제
		    			d3.selectAll(".foreground path").style("stroke-width", 1).attr('filter', "false");
						
			    		d3.select(this)
				    	.style("stroke-width", 6)
						.attr("filter", 'true');
			    		
	       				var selectedData = {};
		       			selectedData[self.dimensions[0].name] = d[self.dimensions[0].name];
		       			self.trackingData.push(selectedData);
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
			    		d3.select(this)
				    	.style("stroke-width", 1)
						.attr("filter", 'false');
			    		
			    	}else{
			    		d3.select(this)
				    	.style("stroke-width", 6)
						.attr("filter", 'true');
			    	}

			    	var inArray = false;
	       			var selectedData = {};
	       			selectedData[self.dimensions[0].name] = d[self.dimensions[0].name];
	       			for (var index = 0; index < self.trackingData.length; index++) {
	       				if (self.trackingData[index][self.dimensions[0].name] === selectedData[self.dimensions[0].name]) {
	       					self.trackingData.splice(index, 1);
	       					index--;
	       					inArray = true;
	       				}
	       			}
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
	    	  }
	 	 })
	 	.attr("filter", function(d){
	 		if(self.trackingData){
		    	  var filter = false;
		    	  for(var i = 0; i < self.trackingData.length; i++){
		    		  if(self.trackingData[i][self.dimensions[0].name] === d[self.dimensions[0].name])
		    			  filter = true;
		    	  }
		    	  return filter? "true" : "false";
		      }else return "false"
	 	})
		.attr("font-family", gDashboard.fontManager.getFontFamily('Item'))
		.style("stroke", function(d, i) {
			var colorNum;
			$.each(species, function(_i, _o) {
				if(d[dimesionsName[0]] == species[_i]){
					colorNum = _i;
				}
			});
//			return color(colorNum);
			return rgb[colorNum];
		})
		.attr("d", path);

		// Add a group element for each dimension.
		var g = svg.selectAll(".trait")
		.data(traits)
		.enter().append("svg:g")
		.attr("class", "trait")
		.attr("transform", function(d) { return "translate(" + x(d) + ")"; });

		// Add an axis and title.
		g.append("g")
		.attr("class", "axis")
//		.each(function(d) { d3.select(this).call(axis.scale(y[d])); })
		.each(function(d) { d3.select(this).call(axis.scale(y[d]).tickFormat(function(z){ return dollarFormatter(z)})); })
		.append("text")
//		.style("font-size", function(d, i){
//			var fontz = gDashboard.fontManager.getFontSize((w/h) * 10, 'Item');
//	  		if(Number(fontz.split('px')[0])>15 + Number(gDashboard.fontManager.getFontSize(0, 'Item').split('px')[0])){
//	  			fontz = gDashboard.fontManager.getFontSize(15, 'Item');
//	  		}else if(Number(fontz.split('px')[0]) < 5)
//	  			fontz = 5;
//	  		return fontz;
//	 	 })
		.style("font-family", self.meta.LayoutOption.AxisX.family)
		.style("fill", self.meta.LayoutOption.AxisX.color)
		.style("font-size", self.meta.LayoutOption.AxisX.size + 'px')
		.attr("label", "true")
		.style("text-anchor", "middle")
		.attr("y", -9)
		.text(function(d) { return d.replace('sum_',''); });
		// Add and store a brush for each axis.

		g.append("svg:g")
		.attr("class", "brush")
		.each(function(d) { 
			d3.select(this).call(y[d].brush = d3.brushY()
					.extent([[-10,0], [10,h]])
					.on("brush", brush)           
					.on("end", brush)
			)
		})
//		.selectAll("rect")
//		.attr("x", -8)
//		.attr("width", 16);
//		});
//		Returns the path for a given data point.
		function path(d) {
			return line(traits.map(function(p) { return [x(p), y[p](d[p])]; }));
		}
//		Handles a brush event, toggling the display of foreground lines.
		function brush() {  
			var actives = [];
			svg.selectAll(".brush")
			.filter(function(d) {
				y[d].brushSelectionValue = d3.brushSelection(this);
				return d3.brushSelection(this);
			})
			.each(function(d) {
				// Get extents of brush along each active selection axis (the Y axes)
				actives.push({
					dimension: d,
					extent: d3.brushSelection(this).map(y[d].invert)
				});
			});
			// Update foreground to only display selected values
			foreground.style("display", function(d) {
				return actives.every(function(active) {
					return active.extent[1] <= d[active.dimension] && d[active.dimension] <= active.extent[0];
				}) ? null : "none";
			})
		}

//		var fontz = gDashboard.fontManager.getFontSize((w/h) * 10, 'Item');
//  		if(Number(fontz.split('px')[0])>15 + Number(gDashboard.fontManager.getFontSize(0, 'Item').split('px')[0])){
//  			fontz = gDashboard.fontManager.getFontSize(15, 'Item');
//  		}else if(Number(fontz.split('px')[0]) < 5)
//  			fontz = 5;
//  		
  		svg.append("text")
		  .attr("transform", "rotate(-90)")
		  .attr("y",(0 - w/5.3))
		  .attr("x",0 - (h / 2))
		  .attr("dy", "1em")
//		  .style("font-size",  function(d, i){
//			  var fontz = gDashboard.fontManager.getFontSize((w/h) * 10, 'Item');
//		  		if(Number(fontz.split('px')[0])>10 + Number(gDashboard.fontManager.getFontSize(0, 'Item').split('px')[0])){
//		  			fontz = gDashboard.fontManager.getFontSize(15, 'Item');
//		  		}else if(Number(fontz.split('px')[0]) < 5)
//		  			fontz = 5;
//		  		return fontz;
//		 	 }	  	
//		  )
		  .style("font-size", self.meta.LayoutOption.AxisY.size + 'px')
		  .style("font-family", self.meta.LayoutOption.AxisY.family)
			.style("fill", self.meta.LayoutOption.AxisY.color)
		  .style("text-anchor", "middle")
		  .text(function(d){
		  	if(self.Parallel.AxisY.Title){
              return self.Parallel.AxisY.Title;
		  	}else{
		  	    return '';	
		  	}
		  	
		  }).style("font-family", self.meta.LayoutOption.AxisY.family)
			.style("fill", self.meta.LayoutOption.AxisY.color);
  		
//		$('#' + self.itemid + ' g text').css("font-size", fontz);
		
		d3.selectAll('#' + self.itemid + ' .axis text:not([label])').style("font-family", self.meta.LayoutOption.AxisY.family)
		.style("font-size", self.meta.LayoutOption.AxisY.size + 'px').style("fill", self.meta.LayoutOption.AxisY.color);
		
		/*var legend = svg.append("g")
		    .attr("class", "legend")
			//.attr("x", w - 65)
			//.attr("y", 50)
		    .attr("height", 100)
		    .attr("width", 100)
			.attr('transform', 'translate(10,10)')  

		var rgbLen = -1;
		 legend.selectAll('rect')
		  .data(species)
		  .enter()
		  .append("rect")
		  .attr("x", width+15)
		  .attr("y", function(d, i){ 

		  	return i *  (height/species.length) - 9;
		  })
		  .attr("width", 10)
		  .attr("height", 10)
		  .style("fill", function(d, i) { 
			rgbLen++;
			if(rgb[rgbLen] == undefined){
				rgbLen = 0;
			}
			return rgb[rgbLen];
		  })

		legend.selectAll('text')
		  .data(species)
		  .enter()
		  .append("text")
		  .attr("x", width+30)
		  .attr("y", function(d, i){ return i *  (height/species.length);})
		  .style("font-size",  function(d, i){
		  		var fontz = (width/height) *10;
		  		if(fontz>15){
		  			fontz = 15;
		  		}
		  		return fontz;
		 	 }	  	
		  )
		  .text(function(d) {
			return d.name;
		  });*/
	};
	
	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self,self.Parallel);
	}
	
	this.functionDo2 = function(_f) {			
		switch(_f) {
			
		/* DESIGN OPTIONS */
		
			// show and hide title bar
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.Parallel['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.Parallel['ShowCaption'] = false;
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
                            	
                            	self.Parallel['Name'] = newName;
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
				var chagePalette = self.Parallel.Palette;
				var firstPalette = self.Parallel.Palette;
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
                        var originalPalette = paletteCollection.indexOf(self.Parallel.Palette) != -1
										? self.Parallel.Palette
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
                                    self.Parallel.Palette = paletteObject2[e.value];
                                    self.resize();
                                    chagePalette = paletteObject2[e.value];
								}
							}
                        });
                        // confirm and cancel
                        $('#save-ok').on('click', function() {
                            self.Parallel.Palette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            chagePalette = paletteObject2[select.dxSelectBox('instance').option('value')];
                            //2020.02.19 MKSONG KERIS 팔레트 이름 한글로 변경 수정 끝 DOGFOOT
                            p.option('visible', false);
                        });
                        $('#save-cancel').on('click', function() {
                        	chagePalette = firstPalette;
                        	self.Parallel.Palette = firstPalette;
                        	self.resize();
                        	p.option('visible', false);
                        });
					},
					onHiding:function(){
						 self.Parallel.Palette = chagePalette;
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
//				var chagePalette = self.Parallel.Palette;
//				var firstPalette = self.Parallel.Palette;
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
//                        var originalPalette = paletteCollection.includes(self.Parallel.Palette) 
//										? self.Parallel.Palette
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
//                                    self.Parallel.Palette = e.value;
//                                    self.resize();
//                                    chagePalette = e.value;
//								}
//							}
//                        });
//                        // confirm and cancel
//                        $('#save_ok').on('click', function() {
//                            self.Parallel.Palette = select.dxSelectBox('instance').option('value');
//                            chagePalette = select.dxSelectBox('instance').option('value');
//                            self.resize();
//                            p.option('visible', false);
//                        });
//                        $('#save_cancel').on('click', function() {
//                            self.dxItem.option('palette', self.Parallel.Palette);
//                            chagePalette = firstPalette;
//                            self.Parallel.Palette = firstPalette;
//                            self.resize();
//                            p.option('visible', false);
//                        });
//					},
//					onHiding:function(){
//						 self.Parallel.Palette = chagePalette;
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

WISE.libs.Dashboard.ParallelFieldManager = function() {
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
