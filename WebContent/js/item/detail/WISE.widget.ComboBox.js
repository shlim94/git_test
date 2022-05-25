WISE.libs.Dashboard.item.ComboBoxGenerator = function() {
	var self = this;
	
	this.type = 'COMBOBOX';
	
	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	this.layoutManager;
	this.IsMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	var dataMember;
	this.ComboType;
	this.HiddenMeasures = [];
	this.filterDimensions = [];
	this.filterArray = [];
	this.trackingData = [];
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	/**
	 * @param _item: meta object
	 */
	var CheckCurrentFilter;
	this.getDxItemConfig = function(_item) {

		this.dataSourceConfig = {};
		this.dataSourceConfig.fields = [];
		this.IsMasterFilterCrossDataSource = _item.IsMasterFilterCrossDataSource ?  true : false;
		var D,V, HM;
		var count = 0;
		D = _item.DataItems;
		V = _item.FilterDimensions ? WISE.util.Object.toArray(_item.FilterDimensions.Dimension) : [];
		HM = _item.HiddenMeasures ? WISE.util.Object.toArray(_item.HiddenMeasures.Measure): [];
		var Exprname="";
		var DU = WISE.libs.Dashboard.item.DataUtility;
		self.dimensions = [];
		// values 
		$.each(V, function(_i, _o) {
			dataMember = DU.getDataMember(_o['UniqueName'], D);
			self.dimensions.push(dataMember)
			Exprname += dataMember.name+","; 
			var fieldOption = {
				id : _i,
				dataSource : 'data',
				caption: dataMember.caption,
				dataField: dataMember.name
				
			};
			self.dataSourceConfig.fields.push(fieldOption);
		});

        self.HiddenMeasures = [];
		$.each(HM, function(_i, _o){
			dataMember = DU.getDataMember(_o['UniqueName'], D);
			self.HiddenMeasures.push(dataMember);
		})
		
		var dxConfigs =	{
			valueExpr: "text",
			displayExpr : "text",
			layout: 'horizontal',
			FromDataSource : Exprname,
			dataSource: this.dataSourceConfig,
			searchEnabled: self.ComboBox.EnableSearch,
			searchMode : "contains",
			searchTimeout:undefined,
			searchValue:"",
			searchExpr: ["FromDataSource","text"],
//			showSelectionControls:_item.hasOwnProperty('ComboBoxType'),
			showSelectionControls:true,
			applyValueMode: "useButtons",
//			height: '67px',
			onValueChanged:function(_e){
				var textArray = [];
				var datasourceArray = [];
				self.trackingData = [];
				if(self.meta.ComboBoxType != undefined){
					if(_e.component.option("selectedItems").length != 0){
						$.each(_e.component.option("selectedItems"),function(_i, _selectedItem){
							textArray.push(_selectedItem.text.split(','));
						});
						datasourceArray = _e.component.option("selectedItems")[0].FromDataSource.split(',');
						for(var j=0;j < datasourceArray.length;j++){
							for(var i=0;i<textArray.length;i++){
								var dataJson = {};
								dataJson[datasourceArray[j]] = textArray[i][j];
								self.trackingData.push(dataJson);
							}	
						}
					}else{
						var dataJson = {};
						$.each(_e.component.option('dataSource').fields,function(_i, _field){
							dataJson[_field.caption] = "undefined";
							self.trackingData.push(dataJson);
						});
					}
				}else{
					if(_e.component.option("selectedItem") == null){
						var dataJson = {};
						$.each(_e.component.option('dataSource').fields,function(_i, _field){
							dataJson[_field.caption] = "undefined";
							self.trackingData.push(dataJson);
						});
					}else{
						if(_e.component.option("selectedItem").length != 0){
							//20211022 syjin 콤보박스 전체로 변경 dogfoot
							//if(_e.component.option("selectedItem").text != "(ALL)"){
							if(_e.component.option("selectedItem").text != "전체"){
								textArray = _e.component.option("selectedItem").text.split(',');
								datasourceArray = _e.component.option("selectedItem").FromDataSource.split(',');
								for(var i=0;i<textArray.length;i++){
									var dataJson = {};
									dataJson[datasourceArray[i]] = textArray[i];
									self.trackingData.push(dataJson);
								}
							}
						}
					}
					
				}
				
				/* DOGFOOT ktkang 로딩바 안사라지는 오류 수정  20200909 */
				if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
				}

				if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
					gProgressbar.setStopngoProgress(true);
					gProgressbar.hide();		
					gDashboard.updateReportLog();
				}
			},
			onContentReady: function(_e){
				//gDashboard.itemGenerateManager.removeLoadingImg(self);
			}
	    };
		
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
	
	/** @Override */
	this.bindData = function(_data, _functionDo, _overwrite) {
		//gDashboard.itemGenerateManager.loadingImgRender(self);
		
		//2020.02.07 mksong sqllike 적용 dogfoot
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		
		if(self.meta != undefined){
			this.ComboBox = self.meta;
			if(!(this.ComboBox.FilterString)){
				this.ComboBox.FilterString = [];
			}else{
				this.ComboBox.FilterString = JSON.parse(JSON.stringify(this.ComboBox.FilterString).replace(/"@null"/gi,null));
			}
		}
		if(_functionDo){
//			self.dimensions = [];
//			self.measures = [];
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}else if(this.fieldManager != undefined && this.ComboBox == undefined){
			this.setComboBox();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.ComboBox);
		}else if(this.fieldManager != null && this.ComboBox){
//			self.dimensions = [];
//			self.measures = [];
			this.setDataItems();
			self.queryState = false;
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}else if(this.ComboBox){
			self.setComboBoxForViewer();
		}
		
		if(this.fieldManager != undefined){
			gDashboard.itemGenerateManager.generateItem(self, self.ComboBox);
		}
		
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		} 
		
//		if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
//			var nodataHtml = '<div class="nodata-layer"></div>';
//			$("#" + this.itemid).empty().append(nodataHtml);
//		}
		else {
			var dxConfig = this.getDxItemConfig(this.meta);
			
			var sqlConfig = SQLikeUtil.fromJsonforNoSummaryType(self.dimensions, self.HiddenMeasures);
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			_data = SQLikeUtil.doSqlLike(this.dataSourceId, sqlConfig, self);
			
			if (!_data || ($.type(_data) === 'array' && _data.length === 0)) {
				//gDashboard.itemGenerateManager.removeLoadingImg(self);
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

				if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
					gProgressbar.setStopngoProgress(true);
					gProgressbar.hide();		
					gDashboard.updateReportLog();
				}
				
				return ;
			}else{
				$('#'+self.itemid + ' .nodata-layer').remove();
				$("#" + self.itemid).children().css('display','block');
			}
			
			if (_overwrite) {
				this.globalData = _data;
			}
			if (!this.tracked) {
				this.globalData = _.clone(_data);
				this.filteredData = _.clone(_data);
			}
			
			/**
			 * 데이터 중복 제거 코드
			 */
			var temparr = new Array();//value group
			var jsonarr = new Array();//json group
			var DataSourceArr = new Array();
			var keynumber = 0;
			var divideArray = new Array();
			var sectorArray = new Array();
			
			if(_data.length != 0){
				if((_data = gDashboard.itemGenerateManager.getFilteredDataForList(_data, self)).length === 0) return;
				$.each(self.dataSourceConfig.fields,function(_i,_arr){
					$.each(_data,function(_j,_el){
						if ($.inArray(_el[_arr.dataField], temparr) == -1) {
							DataSourceArr.push(_arr.dataField)
							temparr.push(_el[_arr.dataField]);
						}
					})
				})
				
				$.each(temparr, function(_i, _ee) {
					var tempObj = new Object();
					tempObj.id = ++keynumber;
					 
					tempObj.FromDataSource = DataSourceArr[_i];
					 $.each(dxConfig.dataSource.fields,function(_i,_fields){
						if(_fields.dataField === tempObj.FromDataSource)
						{
							tempObj.dsid = _fields.id;
						}
					});
					tempObj.text = _ee;
					tempObj.items = [];
					jsonarr.push(tempObj);
				});
				
				for(var _i = 0; _i<jsonarr.length-1; _i++)
				{
					var nextarr = (_i+1);
					if( jsonarr[_i].dsid != jsonarr[nextarr].dsid)
					{
						sectorArray.push(jsonarr[_i]);
						divideArray.push(sectorArray);
						sectorArray=new Array();
					}
					else{
						sectorArray.push(jsonarr[_i]);
					}
				}
				sectorArray.push(jsonarr[jsonarr.length-1]);
				divideArray.push(sectorArray);
				var newArr = new Array();
				var copyArr = new Array();
				var tempArr = new Array(); 
				$.each(divideArray,function(_i,_e){
					for(var j=0;j<_e.length;j++)
					{
						if(_e[j].dsid == 0){
							var inputobj = new Object();
							inputobj.FromDataSource = _e[j].FromDataSource;
							inputobj.text = _e[j].text;
							copyArr.push(inputobj);
						}
						else{
							var count = 0;
							for(var k = 0; k<copyArr.length;k++)
							{
								var inputobj = new Object();
								$.each(_data,function(_j,_el){
									if(_el[copyArr[k].FromDataSource] == copyArr[k].text && _el[_e[j].FromDataSource] == _e[j].text){
										inputobj.FromDataSource =copyArr[k].FromDataSource + "," + _e[j].FromDataSource;
										inputobj.text = copyArr[k].text + "," +_e[j].text;
										if ($.inArray(inputobj, tempArr) == -1) {
											tempArr.push(inputobj);
											count++;
										}
									}
								})
							}
						}
					}
					if(tempArr.length !=0){
						copyArr = tempArr.slice();
						tempArr = new Array();
					}
				});
				
				$('#'+self.itemid).css('display','block');
				//데이터 중복 제거 코드 END
				if(this.meta.ComboBoxType != undefined){
					dxConfig.dataSource.store = copyArr;
					this.dxItem = $("#" + this.itemid).dxTagBox(dxConfig).dxTagBox("instance");
				}
				else{
					if(self.ComboBox.ShowAllValue){
						var inputobj = new Object();
						inputobj.FromDataSource = copyArr[0].FromDataSource;
						inputobj.text = "전체";
						copyArr.unshift(inputobj);
						dxConfig.dataSource.store = copyArr;
					}else{
						dxConfig.dataSource.store = copyArr;
					}
					this.dxItem = $("#" + this.itemid).dxSelectBox(dxConfig).dxSelectBox("instance");
				}
			}
			
		}
		
		if(self.trackingData){
			gDashboard.filterData(self.itemid, self.trackingData);		
			$('.dx-list-item-content').attr('style', gDashboard.fontManager.getCustomFontStringForItem(14))
		}
		
		$(document).on("click",".dx-popup-done.dx-button.dx-button-normal",function(){ 
			gDashboard.filterData(self.itemid, self.trackingData);		
			$('.dx-list-item-content').attr('style', gDashboard.fontManager.getCustomFontStringForItem(14))
		});
		
		$('.lm_content .dx-texteditor-input').attr('style', gDashboard.fontManager.getCustomFontStringForItem(14))
		$('.lm_content .dx-texteditor-container').attr('style', gDashboard.fontManager.getCustomFontStringForItem(14))
		$('.lm_content .dx-texteditor-input, .lm_content .dx-button-normal').on('click', function(){
			setTimeout(function(){
				$('.dx-list-item-content').attr('style', gDashboard.fontManager.getCustomFontStringForItem(14))
			}, 10);
		});
		
		//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
			gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
		}
		if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
			gProgressbar.setStopngoProgress(true);
			gProgressbar.hide();
			gDashboard.updateReportLog();
		}
	};
	this.resize = function(){
		
	};
	
	this.setComboBox = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		
		this.ComboBox = {};
		this.ComboBox['ComponentName'] = this.ComponentName;
		this.ComboBox['DataItems'] = this.fieldManager.DataItems;
		this.ComboBox['DataSource'] = this.dataSourceId;
		this.ComboBox['FilterDimensions'] = this.fieldManager.FilterDimensions
		this.ComboBox['ShowCaption'] = true;
		this.ComboBox['EnableSearch'] = true;
		this.ComboBox['ComboBoxType'] = undefined;
		this.ComboBox['ShowAllValue'] = true;
		this.ComboBox['HiddenMeasures'] = this.fieldManager.HiddenMeasures;
		this.ComboBox['Name'] = this.Name;
		this.ComboBox['InteractivityOptions'] = {
			MasterFilterMode: 'Off',
			IgnoreMasterFilters: false
		};
		this.ComboBox['FilterString'] = [];
	};
	
	this.setComboBoxForViewer = function() {
		if(this.meta.EnableSearch == undefined){
			this.meta['EnableSearch'] = true;	
		}else{
			this.meta['EnableSearch'] = self.meta['EnableSearch'];
		}
		if(this.meta.ComboBoxType == undefined){
			this.meta['ComboBoxType'] = undefined;	
		}else{
			this.meta['ComboBoxType'] = self.meta['ComboBoxType'];
		}
		if(this.meta.ShowAllValue == undefined){
			this.meta['ShowAllValue'] = true;	
		}else{
			this.meta['ShowAllValue'] = self.meta['ShowAllValue'];
		}
		
		if(this.ComboBox['ShowCaption'] == undefined){
			this.ComboBox['ShowCaption'] = true;
		}
	}
	
	this.setDataItems = function(){
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		
		this.meta['DataItems'] = this.ComboBox['DataItems'] = this.fieldManager.DataItems;
		this.meta['FilterDimensions'] = this.ComboBox['FilterDimensions'] = this.fieldManager.FilterDimensions;
		this.meta['HiddenMeasures'] = this.fieldManager.HiddenMeasures;
		
		if(this.meta.EnableSearch == undefined){
			this.meta['EnableSearch'] = true;	
		}else{
			this.meta['EnableSearch'] = self.meta['EnableSearch'];
		}
		if(this.meta.ComboBoxType == undefined){
			this.meta['ComboBoxType'] = undefined;	
		}else{
			this.meta['ComboBoxType'] = self.meta['ComboBoxType'];
		}
		if(this.meta.ShowAllValue == undefined){
			this.meta['ShowAllValue'] = true;	
		}else{
			this.meta['ShowAllValue'] = self.meta['ShowAllValue'];
		}
		
		if(this.ComboBox['ShowCaption'] == undefined){
			this.ComboBox['ShowCaption'] = true;
		}
		if (this.ComboBox['InteractivityOptions']) {
			if (!(this.ComboBox.InteractivityOptions.IgnoreMasterFilters)) {
				this.ComboBox.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.ComboBox['InteractivityOptions'] = {
				IgnoreMasterFilters: false,
				MasterFilterMode: 'Off'
			};
		}
		if (!(this.ComboBox['FilterString'])) {
			this.ComboBox['FilterString'] = [];
		}else{
			this.ComboBox.FilterString = JSON.parse(JSON.stringify(this.ComboBox.FilterString).replace(/"@null"/gi,null));
		}
	};
	
	this.clearTrackingConditions = function() {
		if(typeof this.dxItem !== "undefined" ){
			this.dxItem.reset();
		}
	};
	
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
//		if($('#tab5primary').length == 0){
//			// 2020.01.16 mksong 영역 크기 조정 dogfoot
//			$('.menu-comp.custom-menu').append('<div class="slide-ui responsive itemDelete" style="width:60%;"><a href="#" class="slide-ui-prev">prev</a><a href="#" class="slide-ui-next">next</a><ul id="tab5primary" class="slide-ui-list lnb-lst-tab"></ul></div>');	
//		}
//		$('#tab5primary').empty();
////		$('#tab5primary').append('<span class="drag-line"></span>');
//		$('<li class="slide-ui-item"><a href="#" id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
////		$('<li class="slide-ui-item"><a href="#" id="comboBoxType" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_use_checkmixradio.png" alt=""><span>리스트 타입</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="showAllValue" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_show_all_value.png" alt=""><span>전체 보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="enableSearch" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_use_search.png" alt=""><span>데이터 검색</span></a></li>').appendTo($('#tab5primary'));
//
//		menuItemSlideUi();
//		
//		$('#tab4primary').empty();
//		if($('#tab4primary').length == 0){
//			$('#panelDataA').append($('<div id="tab4primary" class="panelDataA-2 tab-content"><div id ="data-menu" class="panel-body"></div></div>'));	
//		}
//		var dashboard_html = "<h4 class=\"tit-level3\">필터링</h4>" + 
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
//			/* DOGFOOT hsshim 2020-02-06 범정부 요청: 
//			 * Interactivity -> 상호작용
//			 * Interactivity Options -> 상호작용 설정
//			 */ 
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
//			"</div>";
//		$( dashboard_html).appendTo($('#tab4primary'));
//		
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
//        // toggle 'on' status according to pivot options
//		if (self.IO) {
//			if (self.IO['IgnoreMasterFilters']) {
//				$('#ignoreMasterFilter').addClass('on');
//			}
//        }
//
//		$('.functiondo').on('click',function(e){
//			self.functionDo(this.id);	
//		});
//		
//		$('<div id="editPopup">').dxPopup({
//			height: 'auto',
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
//		}).appendTo('#tab4primary');
//		// settings popover
//		$('<div id="editPopover2">').dxPopover({
//			height: 'auto',
//			width: 'auto',
//			position: 'bottom',
//			visible: false
//		}).appendTo('#tab4primary');
		
	};
	
	this.functionDo = function(_f){
		switch(_f){
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
						$.each(self.dataSourceConfig['fields'], function(_i, _field) {
//							if(_field.area == 'row' || _field.area == 'column')
								field.push({ dataField: _field['caption'], dataType: 'string' });
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
						$('#ok-hide').on('click', function() {
//	                        var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').getFilterExpression();
							var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').option('value');
	                        var newDataSource = new DevExpress.data.DataSource({
	                            store: self.globalData,
	                            paginate: false
	                        });
	                        newDataSource.filter(filter);
							newDataSource.load();
							self.filteredData = newDataSource.items();
							self.meta.FilterString = filter;
							self.bindData(self.filteredData, true);
							if(self.meta.FilterString != null){
								$('#editFilter').addClass('on');
							}else{
								$('#editFilter').removeClass('on');
							}
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
			case 'clearFilter': {
				if (self.meta.FilterString) {
					self.meta.FilterString = null;
					$('#editFilter').removeClass('on');
					self.filteredData = self.globalData;
					self.bindData(self.filteredData,true);
				}
				break;
			}
			case 'crossFilter': {
				if (!(self.dxItem)) {
					break;
				}
				self.IsMasterFilterCrossDataSource = $('#crossFilter').hasClass('on') ? true : false;
				self.meta['IsMasterFilterCrossDataSource'] = self.IsMasterFilterCrossDataSource;
				if (self.IsMasterFilterCrossDataSource) {
					gDashboard.filterData(self.itemid, self.trackingData, self.dataSourceId, self.IsMasterFilterCrossDataSource);
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
				break;
			}
			case 'ignoreMasterFilter': {
				if (!(self.dxItem)) {
					break;
				}			
				self.IO['IgnoreMasterFilters'] = $('#ignoreMasterFilter').hasClass('on') ? true : false;
				self.meta.InteractivityOptions['IgnoreMasterFilters'] = self.IO['IgnoreMasterFilters'];
				self.tracked = !self.IO['IgnoreMasterFilters'];
				if (self.IO['IgnoreMasterFilters']) {
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
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					self.meta['ShowCaption'] = true;
				} else {
					titleBar.css('display', 'none');
					self.meta['ShowCaption'] = false;
				}
				break;
			}
			// edit chart title
			case 'editName': {
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '이름 편집',
					width:500,
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
                            	
                                if (self.meta) {
                                    self.meta['Name'] = newName;
                                }
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
			case 'comboBoxType':
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#comboBoxType',
					width : 150,
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_comboBoxType">');
						$('#' + self.itemid + '_comboBoxType').dxRadioGroup({
							dataSource: ['체크', '레디오'],
							value: self.ComboBox.ComboBoxType == undefined ? '레디오' : '체크',
							onValueChanged: function(e) {
								self.ComboBox.ComboBoxType = e.value === '레디오' ? undefined : 'Checked';
								self.ComboType = self.ComboBox.ComboBoxType == 'Checked' ? 'single' : 'multiple';
								self.tracked = !self.ComboBox.ComboBoxType;
								self.meta = self.ComboBox;
//								self.dxItem.option('selectionMode', self.ComboType);
								self.bindData(self.globalData,true);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			case 'showAllValue':
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#showAllValue',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_showAllValue">');
						$('#' + self.itemid + '_showAllValue').dxRadioGroup({
							dataSource: ['On', 'Off'],
							value: self.ComboBox.ShowAllValue ? 'On' : 'Off',
							onValueChanged: function(e) {
								self.ComboBox.ShowAllValue = e.value === 'On' ? true : false;
								self.tracked = !self.ComboBox.ShowAllValue;
								self.meta = self.ComboBox;
								self.bindData(self.globalData,true);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			case 'enableSearch':
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#enableSearch',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_enableSearch">');
						$('#' + self.itemid + '_enableSearch').dxRadioGroup({
							dataSource: ['On', 'Off'],
							value: self.ComboBox.EnableSearch ? 'On' : 'Off',
							onValueChanged: function(e) {
								self.ComboBox.EnableSearch = e.value === 'On' ? true : undefined;
								self.tracked = !self.ComboBox.EnableSearch;
								self.meta = self.ComboBox;
								self.dxItem.option('searchEnabled', self.ComboBox.EnableSearch);
								self.bindData(self.globalData,true);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
		}
	};
};

WISE.libs.Dashboard.ComboBoxFieldManager = function() {
	var self = this;
	
	this.initialized = false;
	this.alreadyFindOutMeta = false;
	
	//검색 - searchDisable
	this.searchDisable = false;
	//검색 - 검색어 완전일치 = true, 부분일치 = false
	this.searchMatchCompletely = true;
	//검색
	
	this.meta;
	this.isChange = false; // 사용자가 필드를 변경했는지 여부 체크
	this.columnMeta = {}; // 쿼리된 모든 컬럼정보 저장
	this.isColumnChooser = false;
	
	this.dataItemNo=0;
	
	this.all = [];
	
	this.hide_column_list_dim = [];
	this.hide_column_list_mea = [];
//	this.hide_column_list = {'dimension': [],'measure': []};
	
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
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
				self.DataItems['Dimension'].push(dataItem);
			} else if($(_fieldlist[i]).attr('data-field-type') == 'measure'){
				var NumericFormat = $(_fieldlist[i]).data('formatOptions');
				
				var dataItem = {'DataMember': {}, 'UniqueName': ""};
				dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
				dataItem['Name'] = $(_fieldlist[i]).attr('caption');
				dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				if(WISE.Context.isCubeReport) {
					dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
				}
				dataItem['NumericFormat'] = NumericFormat;
				dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
				self.DataItems['Measure'].push(dataItem);
			}
		}
		return self.DataItems;
	};
	
};
