﻿﻿﻿WISE.libs.Dashboard.item.TreeViewGenerator = function() {
	var self = this;

	this.type = 'TREEVIEW';

	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	this.dataSource;
	// this.dataSources; // xml datasources json structure
	this.layoutManager;
	this.IsMasterFilterCrossDataSource;
	this.dimensions = [];
	this.measures = [];
	var dataMember;
	var Exprname;
	var FilterArray = [];
	this.HiddenMeasures = [];
	this.filterDimensions = [];
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
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
		});
		
		var checkAll;


		var dxConfigs = {
			dataSource : this.dataSourceConfig,
			dataStructure: 'plain',
			// displayExpr : Exprname,
			// keyExpr : Exprname,
			displayExpr : "text",
			keyExpr : "id",
			expandAllEnabled : self.TreeView.AutoExpand,
			expandedExpr : self.TreeView.AutoExpand == true ? 'FromDataSource' : '*',
			searchEnabled: self.TreeView.EnableSearch,
			searchMode : "contains",
			searchTimeout:undefined,
			searchValue:"",
			searchExpr: ["FromDataSource","text"],
			selectByClick : false,
			showCheckBoxesMode : 'selectAll',
			selectAllText : "(ALL)",
			parentIdExpr: 'parentId',
//			onContentReady : function(_e) {
//				_e.component.option("selectedItemKeys",[]);
//				_e.component.selectAll();
////				var checkBox = $('.dx-checkbox').first();
////				checkBox.on('dxclick',
////						function() {
////							checkAll = checkBox.dxCheckBox('instance')
////									.option('value');
////							
////							if (checkAll == true) {
////								
////								var TreeviewID = _e.element[0].id;
////								var TreeViewInstance = $(
////										("div[id=" + TreeviewID + "]"))
////										.dxTreeView("instance");
////								TreeViewInstance.selectAll();
////								FilterArray = [];
////							}
////						});
////				checkBox.click();
//			},
			onSelectionChanged : function(_e) {
				self.trackingData = [];
				// 리스트 형태의 Data를 어떻게  중복해서 array를 만들것인가
				// 멀티 Dimension 구현(공통사항으로 적용)
				var item = _e.component;
				var TreeViewItems = item.getDataSource()._items
				var filterjson = new Object();
				var checkDsid = new Array();
				var checkcurrentparent;

				for(var i = TreeViewItems.length;i>=0;i--){
						filterjson = new Object();
					if(TreeViewItems[i] && 'selected' in  TreeViewItems[i] && TreeViewItems[i].selected != false){
						checkDsid.push(TreeViewItems[i]);

						filterjson[self.dataSource[i].FromDataSource] = TreeViewItems[i].text;
						self.trackingData.push(filterjson);
						checkcurrentparent = TreeViewItems[i].parentId;
						if(TreeViewItems[i].dsid == self.dataSourceConfig.fields[(self.dataSourceConfig.fields.length)-1].id){
							$($(TreeViewItems).get().reverse()).each(function(_i,_ee){
								if(_ee.id == checkcurrentparent){
									filterjson = new Object();
									filterjson[self.dataSourceConfig.fields[_ee.dsid].dataField] = _ee.text;
									checkcurrentparent = _ee.parentId;
									self.trackingData.push(filterjson);
								}
							});
						}
					}
				}

//				$.each(TreeViewItems,function(_i,_temp){
//					if(('selected' in _temp) != false && _temp.selected != false ){
//					}
//				})
				/*dogfoot 트리보기 전체 해제 시 쿼리 오류 수정 undefined 를 왜 넣는건지..? shlim 20200618*/
//				if(self.trackingData.length === 0){
//					if(TreeViewItems.length > 0){
//						filterjson[TreeViewItems[TreeViewItems.length-1].FromDataSource] = 'undefined';
//						self.trackingData.push(filterjson);
//						filterjson = new Object();
//						filterjson[TreeViewItems[0].FromDataSource] = 'undefined';
//						self.trackingData.push(filterjson);
//					}
//				}
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				gDashboard.filterData(self.itemid, self.trackingData);
				
				/* DOGFOOT ktkang 로딩바 안사라지는 오류 수정  20200909 */
				if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
				}

				if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
					gProgressbar.setStopngoProgress(true);
					gProgressbar.hide();		
					gDashboard.updateReportLog();
				}
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
			this.TreeView = self.meta;
			if(!(this.TreeView.FilterString)){
				this.TreeView.FilterString = [];
			}else{
				this.TreeView.FilterString = JSON.parse(JSON.stringify(this.TreeView.FilterString).replace(/"@null"/gi,null));
			}
		}
		
		if(_functionDo){
//			self.dimensions = [];
//			self.measures = [];
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}else if(this.fieldManager != undefined && this.TreeView == undefined){
			this.setTreeView();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.TreeView);
		}else if(this.fieldManager != null && this.TreeView){
//			self.dimensions = [];
//			self.measures = [];
			this.setDataItems();
			self.queryState = false;
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}
		
		if(this.fieldManager != undefined){
			gDashboard.itemGenerateManager.generateItem(self, self.TreeView);
		}
		
		if ($.type(this.child) === 'object' && this.dxItem) {
			this.dxItem = undefined;
			this.layoutManager.createItemLayer(this.itemid);
		}

//		 if (!_data) {
//			 var nodataHtml = '<div class="nodata-layer"></div>';
//			 $("#" + this.itemid).empty().append(nodataHtml);
//		 }
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
			var temparr = new Array();// value group
			var jsonarr = new Array();// json group
			var divideArray = new Array();
			var sectorArray = new Array();
			var DataSourceArr = new Array();
			var keynumber = 0;
			if (_data.length != 0) {
				
				if((_data = gDashboard.itemGenerateManager.getFilteredDataForList(_data, self)).length === 0) return;
				$.each(dxConfig.dataSource.fields, function(_j, _arr) // 2
				{
					$.each(_data, function(_i, _el) {
						if ($.inArray(_el[_arr.dataField], temparr) == -1) {
							DataSourceArr.push(_arr.dataField)
							temparr.push(_el[_arr.dataField]);
						}
					});
				});


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
				$.each(divideArray,function(_i,_e){
					$.each(_e,function(_j,_ee){
						if(_ee.dsid == 0)
						{
							var inputobj = new Object();
							inputobj.id = _ee.id;
							inputobj.dsid = _ee.dsid;
							inputobj.FromDataSource = _ee.FromDataSource;
							inputobj.text = _ee.text;
							inputobj.selected = true;
							newArr.push(inputobj);
						}
						else{
							$.each(newArr,function(_k,_newarr){
								var testArr = new Array();
								$.each(_data,function(_j,_el){
									if(_el[_newarr.FromDataSource] == _newarr.text && _el[_ee.FromDataSource] == _ee.text){
										var text = _ee.text;
										if ($.inArray(text, testArr) == -1) {
											testArr.push(text);
											var inputobj = new Object();
											inputobj.parentId = _newarr.id;
											inputobj.dsid = _ee.dsid;
											inputobj.id = _newarr.id+"_"+_ee.id;
											inputobj.FromDataSource = _ee.FromDataSource;
											inputobj.text = _ee.text;
											inputobj.selected = true;
											
											newArr.push(inputobj);
										}
									}
								});
							});
						}
					})
				})
			}

			
			


			var dataSource = new DevExpress.data.DataSource(newArr);
			dxConfig.dataSource = dataSource;
			self.dataSource = _.cloneDeep(newArr);
			
			//2020.02.13 mksong 조회시 그려진 아이템 초기화 되도록 수정 dogfoot
			$('#'+self.itemid).css('display','block');
			
			// 데이터 중복 제거 코드 END
			// dxConfig.dataSource.store = _data;
			this.dxItem = $("#" + this.itemid).dxTreeView(dxConfig).dxTreeView(
					"instance");
//			this.dxItem.selectAll();
			
			$('.lm_content .dx-treeview-item').attr('style', gDashboard.fontManager.getCustomFontStringForItem(14));
			$('.lm_content .dx-checkbox-text').attr('style', gDashboard.fontManager.getCustomFontStringForItem(14));
			
			//gDashboard.itemGenerateManager.removeLoadingImg(self);
			//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
		}
	};
	
	this.setTreeView = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		
		this.TreeView = {};
		this.TreeView['ComponentName'] = this.ComponentName;
		this.TreeView['DataItems'] = this.fieldManager.DataItems;
		this.TreeView['DataSource'] = this.dataSourceId;
		this.TreeView['FilterDimensions'] = this.fieldManager.FilterDimensions
		this.TreeView['ShowCaption'] = true;
		this.TreeView['EnableSearch'] = true;
		this.TreeView['AutoExpand'] = undefined;
		this.TreeView['HiddenMeasures'] = this.fieldManager.HiddenMeasures;
		this.TreeView['Name'] = this.Name;
		this.TreeView['InteractivityOptions'] = {
			MasterFilterMode: 'Off',
			IgnoreMasterFilters: false
		};
		this.TreeView['FilterString'] = [];
	};
	
	this.setDataItems = function(){
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		
		this.meta['DataItems'] = this.TreeView['DataItems'] = this.fieldManager.DataItems;
		this.meta['FilterDimensions'] = this.TreeView['FilterDimensions'] = this.fieldManager.FilterDimensions;
		this.meta['HiddenMeasures'] = this.fieldManager.HiddenMeasures;
		
		if(this.meta.EnableSearch == undefined){
			this.meta['EnableSearch'] = true;	
		}else{
			this.meta['EnableSearch'] = self.meta['EnableSearch'];
		}
		if(this.meta.AutoExpand == undefined){
			this.meta['AutoExpand'] = true;	
		}else{
			this.meta['AutoExpand'] = self.meta['AutoExpand'];
		}
		
		if(this.TreeView['ShowCaption'] == undefined){
			this.TreeView['ShowCaption'] = true;
		}
		if (this.TreeView['InteractivityOptions']) {
			if (!(this.TreeView.InteractivityOptions.IgnoreMasterFilters)) {
				this.TreeView.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.TreeView['InteractivityOptions'] = {
				IgnoreMasterFilters: false
			};
		}
		if (!(this.TreeView['FilterString'])) {
			this.TreeView['FilterString'] = [];
		}else{
			this.TreeView.FilterString = JSON.parse(JSON.stringify(this.TreeView.FilterString).replace(/"@null"/gi,null));
		}
	};
	
	this.clearTrackingConditions = function() {
		if(typeof this.dxItem !== "undefined" ){
			this.dxItem.repaint();
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
//		$('<li class="slide-ui-item"><a href="#" id="autoExpand" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_auto_expand.png" alt=""><span>자동 확장</span></a></li>').appendTo($('#tab5primary'));
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
//		
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
			case 'autoExpand':
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#autoExpand',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_autoExpand">');
						$('#' + self.itemid + '_autoExpand').dxRadioGroup({
							dataSource: ['On', 'Off'],
							value: self.TreeView.AutoExpand ? 'On' : 'Off',
							onValueChanged: function(e) {
								self.TreeView.AutoExpand = e.value === 'On' ? true : false;
								self.tracked = !self.TreeView.AutoExpand;
								self.meta = self.TreeView;
								self.dxItem.option('expandAllEnabled', self.TreeView.AutoExpand);
								if(self.TreeView.AutoExpand == true){
									self.dxItem.expandAll();
								}else{
									self.dxItem.collapseAll();	
								}
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
							value: self.TreeView.EnableSearch ? 'On' : 'Off',
							onValueChanged: function(e) {
								self.TreeView.EnableSearch = e.value === 'On' ? true : undefined;
								self.tracked = !self.TreeView.EnableSearch;
								self.meta = self.TreeView;
								self.dxItem.option('searchEnabled', self.TreeView.EnableSearch);
								self.bindData(self.globalData,true);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
		}
	};
	
	this.resize = function() {

	};
};

function checkingItem(_data) {
	return !_data.items.length;
}

WISE.libs.Dashboard.TreeViewFieldManager = function() {
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
