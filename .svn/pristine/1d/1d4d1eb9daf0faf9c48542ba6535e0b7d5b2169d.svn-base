WISE.libs.Dashboard.item.HierarchicalEdgeGenerator = function() {
	var self = this;

	this.type = 'HIERARCHICAL_EDGE';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.isMasterFilterCrossDataSource;
	this.dimensions = [];

	var dataMember;
	var Exprname;
	var FilterArray = [];
	this.trackingData = [];
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";

	this.Hierarchical = [];
	this.fieldManager;
	this.currentMeasureName = "";
	
	//임성현 팔레트 
	this.customPalette = [];
	this.isCustomPalette = false;
	
	this.d3Data;
	
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
		this.A = WISE.util.Object.toArray((_item.Arguments && _item.Arguments.Argument) || []);

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

	this.setHierarchical = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		this.Hierarchical['ComponentName'] = this.ComponentName;
		this.Hierarchical['Name'] = this.Name;
		this.Hierarchical['DataSource'] = this.dataSourceId;

		this.Hierarchical['DataItems'] = this.fieldManager.DataItems;
		this.Hierarchical['Arguments'] = this.fieldManager.Arguments;

		this.measures = this.fieldManager.measures;
		this.dimensions = this.fieldManager.dimensions;

		this.meta = this.Hierarchical;
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.Hierarchical.InteractivityOptions) {
			if (!(this.Hierarchical.InteractivityOptions.MasterFilterMode)) {
				this.Hierarchical.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Hierarchical.InteractivityOptions.TargetDimensions)) {
				this.Hierarchical.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.Hierarchical.InteractivityOptions.IsDrillDownEnabled)) {
				this.Hierarchical.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.Hierarchical.InteractivityOptions.IgnoreMasterFilters)) {
				this.Hierarchical.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Hierarchical.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.Hierarchical.LayoutOption){
			this.Hierarchical.LayoutOption = {
					Label: {
						color: '#4C4C4C',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.Hierarchical['ZoomAble']){
			this.Hierarchical.ZoomAble = 'none'
		}
	};

	this.setHierarchicalforOpen = function(){
		if(typeof this.meta == 'undefined'){
			this.setHierarchical();
		}
		else{
			this.Hierarchical = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.Hierarchical['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.Hierarchical['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 임성현 팔레트 불러오기
		var page = window.location.pathname.split('/');
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.Hierarchical.InteractivityOptions) {
			if (!(this.Hierarchical.InteractivityOptions.MasterFilterMode)) {
				this.Hierarchical.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Hierarchical.InteractivityOptions.TargetDimensions)) {
				this.Hierarchical.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.Hierarchical.InteractivityOptions.IgnoreMasterFilters)) {
				this.Hierarchical.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Hierarchical.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.Hierarchical.LayoutOption){
			this.Hierarchical.LayoutOption = {
					Label: {
						color: '#4C4C4C',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.Hierarchical['ZoomAble']){
			this.Hierarchical.ZoomAble = 'none'
		}
	}
	
	//d3 뷰어모드
	this.setHierarchicalForViewer = function(){
		if(typeof this.meta == 'undefined'){
			this.setHierarchical();
		}
		else{
			this.Hierarchical = this.meta;
		}
		if(typeof this.meta.DataSource == 'undefined'){
			this.meta['DataSource'] = 'dataSource1';
		}
		if(this.fieldManager != undefined){
			this.Hierarchical['DataItems'] = this.meta['DataItems'] = this.fieldManager.DataItems;
			this.Hierarchical['Arguments'] = this.meta['Arguments'] = this.fieldManager.Arguments;
			this.dimensions = this.fieldManager.dimensions;
		}
		
		// 20200901 ajkim 마스터 필터 추가 dogfoot
		if (this.Hierarchical.InteractivityOptions) {
			if (!(this.Hierarchical.InteractivityOptions.MasterFilterMode)) {
				this.Hierarchical.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Hierarchical.InteractivityOptions.TargetDimensions)) {
				this.Hierarchical.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.Hierarchical.InteractivityOptions.IgnoreMasterFilters)) {
				this.Hierarchical.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Hierarchical.InteractivityOptions = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IgnoreMasterFilters: false
			};
		}
		
		if(!this.Hierarchical.LayoutOption){
			this.Hierarchical.LayoutOption = {
					Label: {
						color: '#4C4C4C',
						size: 14,
						family: 'Noto Sans KR'
					}
			}
		}
		if(!this.Hierarchical['ZoomAble']){
			this.Hierarchical.ZoomAble = 'none'
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
			self.setHierarchical();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Hierarchical);
			gDashboard.itemGenerateManager.generateItem(self, self.Hierarchical);
		}else if(this.fieldManager !=null && gDashboard.isNewReport != true){
			gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
			this.setHierarchicalforOpen();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Hierarchical);
			gDashboard.itemGenerateManager.generateItem(self, self.Hierarchical);
		}
		//d3 뷰어모드 
		else if(self.meta && $.isEmptyObject(self.Hierarchical)) {
			this.setHierarchicalForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Hierarchical);
			gDashboard.itemGenerateManager.generateItem(self, self.Hierarchical);
		}else if(self.meta == undefined && gDashboard.reportType == 'AdHoc'){
			this.setHierarchicalForViewer();
			gDashboard.itemGenerateManager.itemCustomize(self,self.Hierarchical);
			gDashboard.itemGenerateManager.generateItem(self, self.Hierarchical);
		}

		var buttonPanelId = this.itemid + '_topicon';
		var topIconPanel = $('#' + buttonPanelId);
		if($('#'+this.itemid + '_tracking_data_container').length == 0){
			var trackingDataContainerId = this.itemid + '_tracking_data_container';
			var trackingDataContainerHtml = '<li id="' + trackingDataContainerId + '" style="font-size: 14px; padding-top: 3px;"></li>';
			topIconPanel.append(trackingDataContainerHtml);
		}

		var dxConfig = this.getDxItemConfig(this.meta);

		/*dogfoot d3차트 수정 shlim 20200618*/
		var dupledatacehck = self.deleteDuplecateData(_data);
		
		//2020.11.03 MKSONG 필요한 리소스 동적으로 Import DOGFOOT
		WISE.loadedSourceCheck('d3');
		self.fHierarchicalEdge2(dupledatacehck);
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
    		if (self.dxItem) d3.selectAll('text.node').style('stroke', 'none').style('font-weight', '').attr("filter", "false");;
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

		$.each(Dimension,function(_i,_Dim){
			selectArray.push(_Dim.DataMember);
			FieldArray.push(_Dim.DataMember);
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
		self.csvData = _.cloneDeep(self.filteredData);
		var newData = [];

		$.each(Dimension, function(_ii, dim) {
			newData.push({name: dim.Name, imports: []});
			$.each(self.filteredData, function(_i, data) {
				var duple = true;
				$.each(newData, function(_iii, newdata) {
					if(newdata.name == data[dim.Name]) {
						duple = false;
					}
					
					for(var key in data) {
						if(key == dim.Name && newdata.name == key) {
							if(data[key] && data[key] != "") {
								newdata.imports.push(data[key]);
							}
						}
					}
				});
				if(data[dim.Name] != "" && duple) {
					newData.push({name: data[dim.Name], imports: []});
				}
			});
		});
		
		$.each(Dimension, function(_ii, dim) {
			$.each(self.filteredData, function(_i, data) {
				$.each(newData, function(_ii, newdata) {
					if(data[dim.Name] == newdata.name) {
						for(var key in data) {
							if(data[key] && data[key] != "" && key != newdata.name) {
								newdata.imports.push(data[key]);
							}
						}
					}
				});
			});
		});
		
		self.filteredData = newData;
		return self.filteredData;
	};
	/*dogfoot d3 resize시 쿼리 안타도록 수정  shlim 20200909*/
	this.resize = function() {
		/* DOGFOOT ktkang 대시보드 주제영역 일때 리사이즈 에러 당분간 주석  20200718 */
		if(typeof self.resizeData != 'undefined'){
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
    		WISE.loadedSourceCheck('d3');
			self.fHierarchicalEdge2(self.resizeData);
			d3.selectAll('text.node[filter="true"]').style('font-weight', 600).style('stroke-opacity', 0.1).style('stroke', 'black').style('stroke-width', 5)
		}
		gProgressbar.hide();
	};
//	this.resize = function() {
//		/* DOGFOOT ktkang 대시보드 주제영역 일때 리사이즈 에러 당분간 주석  20200718 */
//		var dupledatacheck = self.deleteDuplecateData(self.csvData);
//		self.fHierarchicalEdge2(dupledatacheck);
//		d3.selectAll('text.node[filter="true"]').style('font-weight', 600).style('stroke-opacity', 0.1).style('stroke', 'black').style('stroke-width', 5)
//		gProgressbar.hide();
//	};
	
	
	this.fHierarchicalEdge2 = function(jsonData) {

		$('#'+self.itemid + ' .nodata-layer').remove();
		$("#" + self.itemid).children().css('display','block');

		d3.select("#" + self.itemid).selectAll("svg").remove();
		self.resizeData = jsonData;
		var m = [40, 80, 100, 80],
		w = $('#'+self.itemid).width() + 2,
		h = $('#'+self.itemid).height() * 80 / 100;

		var xLeng = ($('#'+self.itemid).width()) / 2;
		var hLeng = ($('#'+self.itemid).height()) / 2;

		var scaleK = 0;
	
		var svg = d3.select("#" + self.itemid).append("svg:svg")
		.attr("width", $('#'+self.itemid).width())
		.attr("height", $('#'+self.itemid).height())
		.append("svg:g")
		.attr("transform", "translate(" + xLeng + "," + hLeng + ")");

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
		var diameter = $('#'+self.itemid).height() > $('#'+self.itemid).width()? $('#'+self.itemid).width() : $('#'+self.itemid).height(),
		radius = diameter / 1.8,
		innerRadius = radius - 120;

		var cluster = d3.cluster()
		.size([360, innerRadius]);

		var line = d3.radialLine()
		.curve(d3.curveBundle.beta(0.5))
		.radius(function(d) { return d.y; })
		.angle(function(d) { return d.x / 180 * Math.PI; });

//		var svg = d3.select("body").append("svg")
//		.attr("width", diameter)
//		.attr("height", diameter)
//		.append("g")
//		.attr("transform", "translate(" + radius + "," + radius + ")");

		var link = svg.append("g").selectAll(".hierarchicalLink"),
		node = svg.append("g").selectAll(".node");

		var root = packageHierarchy(self.filteredData)
		cluster(root);
		
		link = link
		.data(packageImports(root.leaves()))
		.enter().append("path")
		.each(function(d) { 
			d.source = d[0], d.target = d[d.length - 1]; 
		})
		.attr("class", "hierarchicalLink")
		.attr("d", line);

		node = node
		.data(root.leaves())
		.enter().append("text")
		.attr("class", "node")
		.attr("dy", "0.31em")
		.style("font-size", self.meta.LayoutOption.Label.size+'px')
		.style("font-family", self.meta.LayoutOption.Label.family)
		.style("fill", self.meta.LayoutOption.Label.color)
		.attr("transform", function(d) { 
			return "rotate(" + (d.x - 90) + ")translate(" + (d.y + 8) + ",0)" + (d.x < 180 ? "" : "rotate(180)"); 
		})
		.attr("text-anchor", function(d) {
			return d.x < 180 ? "start" : "end"; 
		})
		.text(function(d) { 
				return d.data.name; 
		})
		.attr("filter", function(d){
			var selectKey = d.data.name.split('-');
			var inArray = false;
			var selectedData = {};
			$.each(selectKey,function(_j,_selectkey){
				$.each(self.dimensions, function(_i, _ao) {
					$.each(self.csvData, function(_index, _val) {		
						if(_val[_ao.name] === _selectkey.trim()){
							selectedData[_ao.name] = _selectkey.trim();
						}
					});
					for (var index = 0; index < self.trackingData.length; index++) {
						if (self.trackingData[index][_ao.name] && self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
							inArray = true;
						}
					}
				});

			});
			
			return inArray? "true" : "false";
		})
		.on("mouseover",function(d){ 
		    $(this).attr('cursor','pointer');
		    mouseovered(d);
		})
		.on("mouseout", mouseouted)
		.on("click", function(d){mouseclick(d.data, this)});;

		function mouseovered(d) {
			node
			.each(function(n) { n.target = n.source = false; });

			link
			.classed("hierarchicalLink--target", function(l) { if (l.target === d) return l.source.source = true; })
			.classed("hierarchicalLink--source", function(l) { if (l.source === d) return l.target.target = true; })
			.filter(function(l) { return l.target === d || l.source === d; })
			.raise();

			node
			.classed("node--target", function(n) { return n.target; })
			.classed("node--source", function(n) { return n.source; });
		}

		function mouseouted(d) {
			link
			.classed("hierarchicalLink--target", false)
			.classed("hierarchicalLink--source", false);

			node
			.classed("node--target", false)
			.classed("node--source", false);
		}

		function mouseclick(d, s){
			
			var selectKey = d.name.split('-');
             switch(self.IO.MasterFilterMode){
				case 'Multiple':
					var inArray = false;
					var selectedData = {};
					$.each(selectKey,function(_j,_selectkey){
						$.each(self.dimensions, function(_i, _ao) {
							$.each(self.csvData, function(_index, _val) {		
								if(_val[_ao.name] === _selectkey.trim()){
									selectedData[_ao.name] = _selectkey.trim();
								}
								if(_ao.name === _selectkey){
									inArray = true;
								}
							});
							for (var index = 0; index < self.trackingData.length; index++) {
								if (self.trackingData[index][_ao.name] && self.trackingData[index][_ao.name] === selectedData[_ao.name]) {
									self.trackingData.splice(index, 1);
									index--;
									inArray = true;
								}
							}
						});

					});
					
					if (!inArray) {
						d3.select(s).style('font-weight', 600).style('stroke-opacity', 0.1).style('stroke', 'black').style('stroke-width', 5).attr("filter", "ture");
						self.trackingData.push(selectedData);
					}else{
						d3.select(s).style('font-weight', '').style('stroke', 'none').attr("filter", "false");
					}
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
				case 'Single':

					self.trackingData = [];
					d3.selectAll('text.node').style('stroke', 'none').style('font-weight', '').attr("filter", "false");
					d3.select(s).style('font-weight', 600).style('stroke-opacity', 0.1).style('stroke', 'black').style('stroke-width', 5).attr("filter", "ture");
					var selectedData = {};
					$.each(selectKey,function(_j,_selectkey){
						$.each(self.dimensions, function(_i, _ao) {
							$.each(self.csvData, function(_index, _val) {		
								if(_val[_ao.name] === _selectkey.trim()){
									self.trackingData = [];

									selectedData[_ao.name] = _selectkey.trim();
									self.trackingData.push(selectedData);
								}
							});
						});
					});
					/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
					if(WISE.Constants.editmode === "viewer"){
						gDashboard.itemGenerateManager.focusedItem = self;
					}
					gDashboard.filterData(self.itemid, self.trackingData);
					break;
			}
	    }

		function packageHierarchy(classes) {
			  var map = {};

			  function find(name, data) {
			    var node = map[name], i;
			    if (!node) {
			      node = map[name] = data || {name: name, children: []};
			      if (name.length) {
			        node.parent = find(name.substring(0, i = name.lastIndexOf(".")));
			        node.parent.children.push(node);
			        node.key = name.substring(i + 1);
			      }
			    }
			    return node;
			  }

			  classes.forEach(function(d) {
				if( typeof d.name != 'undefined')
					find(d.name, d);
			  });

			  return d3.hierarchy(map[""]);
			}

			// Return a list of imports for the given array of nodes.
			function packageImports(nodes) {
			  var map = {},
			      imports = [];

			  // Compute a map from name to node.
			  nodes.forEach(function(d) {
			    map[d.data.name] = d;
			  });

			  // For each import, construct a link from the source to target node.
			  nodes.forEach(function(d) {
			    if (d.data.imports) 
					d.data.imports.forEach(function(i) {
						var input = map[d.data.name];
						var mapi = map[i];
						if( typeof mapi != 'undefined'){
							var path = input.path(mapi);
							imports.push(path);
						}
					});
			  });

			  return imports;
			}

	};

	this.functionDo = function(_f) {
		gDashboard.d3Manager.functionDo(_f, self,self.Hierarchical);
	}
	
	this.functionDo2 = function(_f) {		
		switch(_f) {

		/* DESIGN OPTIONS */

		// show and hide title bar
		case 'captionVisible': {
			var titleBar = $('#' + self.itemid + '_title');
			if (titleBar.css('display') === 'none') {
				titleBar.css('display', 'block');
				self.Hierarchical['ShowCaption'] = true;
			} else {
				titleBar.css('display', 'none');
				self.Hierarchical['ShowCaption'] = false;
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

//							var goldenLayout = gDashboard.goldenLayoutManager;
//							goldenLayout.changeTitle(self.itemid, newName, goldenLayout.canvasLayout.root.contentItems);

							var ele = $('#' + self.itemid + '_title');
							ele.attr( 'title', newName)
							ele.find( '.lm_title' ).html(newName);

							self.Hierarchical['Name'] = newName;
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
		default: break;
		}
	}

};


function checkingItem(_data) {
	return !_data.items.length;
};

WISE.libs.Dashboard.HierarchicalFieldManager = function() {
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
			}
		}
		return self.DataItems;
	};

//	this.setValuesByField = function(_values){
//		this.Values = {'Value' : []};
//		_.each(_values,function(_v){
//			var Value = {'UniqueName' : _v.uniqueName};
//			self.Values['Value'].push(Value);
//		});
//		return self.Values;
//	};

	this.setArgumentsByField = function(_argument){
		this.Arguments = {'Argument' : []};
		_.each(_argument,function(_a){
			var Value = {'UniqueName' : _a.uniqueName};
			self.Arguments['Argument'].push(Value);
		});
		return self.Arguments;
	};
};
