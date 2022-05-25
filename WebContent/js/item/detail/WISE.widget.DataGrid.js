WISE.libs.Dashboard.item.DataGridGenerator = function() {
	var self = this;
	
	this.type = 'DATA_GRID';
	
	this.dashboardid;
	this.itemid;
	this.dxItem;
	this.dataSourceId;
	this.IsMasterFilterCrossDataSource;
	this.tracked;
	this.dimensions = [];
	this.columns = [];
	this.measures = [];
	this.HiddenMeasures = [];
	this.edgeChk;
	this.sparklineElements;
	this.sparklineColumn;
	this.fieldManager;
	
	/* LSH topN */
	this.topN;
	this.topItem;
	this.topNT;
	this.OtherCnt;
	this.otherShow;
	this.TopNMember;
	this.topNEnabeled = false;
	this.topNOrder = false;
	this.topMesure;
	this.topMember;
    this.dimensionTopN = new Array();
    this.repaintCount = 0;
	
	this.columnNamesForBarCellMaxValue = []; // dataMember object list
	this.columnNamesForBarCellMinValue = [];
	this.columnNamesForSparklineCell = []; // dataMember object list

	this.drillDownData = [];
	this.drillDownStack = [];
	this.rowOrder = [];
	
	this.childItem;
	/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
	this.contentReady = false;
	
	// custom Grid palette
	this.customPalette = [];
	this.isCustomPalette = false;
	
	this.storekey;
	this.trackingData = [];
	
	// 20200608 ajkim 텍스트 입력 기능 개발 dogfoot 
	this.memoText = "";
	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeQuery = "";
	this.showQuery = "";
	
	/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
	this.pagingSplit = false;
	this.onContentCnt = 0;
	
	this.sqlConfig;
	this.renderGrid;
	/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
	this.staticAnalysisType;
	/* DOGFOOT ktkang 다변량분석 추가  20210215 */
	/* DOGFOOT syjin 카이제곱 검정 추가  20210315 */
	this.staticOptions = {'alphaLevel' : 5, 'paired': '', 'alternative' : '', 'varequal' : '', 'mutest' : 0, 'method' : '', 'distance' : '', 'cluster' : 5, 'chisqType' : ''}; 
	/* dogfoot 그리드 헤더 추가 기능 shlim 20210319 */
	this.headerList = {};
	this.headerChange = false;
	/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
	this.pagingControl = function() {
		var orders = new DevExpress.data.CustomStore({
	        load: function (loadOptions) {
	            var deferred = $.Deferred();
	            if (loadOptions.sort) {
	            	_param.orderby = loadOptions.sort[0].selector;
	                if (loadOptions.sort[0].desc)
	                	_param.orderby += " desc";
	            }
	            _param.skip = loadOptions.skip || 0;
	            _param.take = loadOptions.take || 20;
	            $.ajax({
	            	method : 'POST',
	                url: "./getMassData.do",
	                dataType: "json",
	                data: _param,
	                success: function(result) {
	                	var array = new Array();
	                	col = result['col'].split(",");
	                	deferred.resolve(result.items, { totalCount: result.totalCount });
	                },
	                error: function() {
	                    deferred.reject("Data Loading Error");
	                },
	                complete:function(e){
	                	dataGrid.endCustomLoading();
	        		}
	            });
	            return deferred.promise();
	        }
	    });
		$("#grid").dxDataGrid({
	        dataSource: {
	            store: orders
	        },
	        remoteOperations: {
	            sorting: true,
	            paging: true
	        },
	        paging: {
	            pageSize: 20
	        },
	        pager: {
	            showPageSizeSelector: false,
	            showInfo: true
	        },
	    }).dxDataGrid("instance");
	    $('#loading').dxLoadPanel('instance').option('visible',false);
	}
	
	// 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot
	this.getAllFields = function(){
		var fields = gDashboard.datasetMaster.getState('FIELDS')[self.dataSourceId];
		var tempJson = {
				mea : [],
				dim : []
		}
		
		$.each(fields, function(i, field){
			if(i == 0) return true;
			var temp = {};
			temp.caption = field.CAPTION;
			temp.name = field.CAPTION;
			if(field.TYPE == "DIM"){
				temp.sortOrder = "asc";
				temp.type = "dimension";
				tempJson.dim.push(temp);
			}else{
				temp.captionBySummaryType = "sum_"+temp.caption;
				temp.nameBySummaryType = "sum_"+temp.caption;
				temp.nameBySummaryType2 = "sum_"+temp.caption;
				temp.summaryType ="sum";
				temp.type = "measure";
				tempJson.mea.push(temp);
			}
		})
		
		return tempJson;
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
//		$('<li class="slide-ui-item"><a href="#" id="captionVisible" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_captionView.png" alt=""><span>캡션보기</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="editName" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_namEdit.png" alt=""><span>이름 편집</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="setGridLines" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_defaultStatus.png" alt=""><span>그리드 라인</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="allowGridCellMerge" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_totals.png" alt=""><span>셀 병합</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="showColumnHeaders" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_grandTotals.png" alt=""><span>열 머리글</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="wordWrap" class="lnb-link more functiondo"><img src="'+WISE.Constants.context+'/resources/main/images/ico_layout.png" alt=""><span>자동 줄 바꿈</span></a></li>').appendTo($('#tab5primary'));
//		$('<li class="slide-ui-item"><a href="#" id="columnWidthMode" class="lnb-link more functiondo"><img id="columnWidthMode" src="'+WISE.Constants.context+'/resources/main/images/ico_rowTotalsPosition.png" alt=""><span>그리드 너비 조정</span></a></li>').appendTo($('#tab5primary'));
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
//		if (self.Grid && self.Grid.InteractivityOptions) {
//			if (self.Grid.InteractivityOptions['MasterFilterMode'] === 'Single') {
//				$('#singleMasterFilter').addClass('on');
//			} else if (self.Grid.InteractivityOptions['MasterFilterMode'] === 'Multiple') {
//				$('#multipleMasterFilter').addClass('on');
//			}
//			if (self.Grid.InteractivityOptions['IsDrillDownEnabled']) {
//				$('#drillDown').addClass('on');
//			}
//			if (self['IsMasterFilterCrossDataSource']) {
//				$('#crossFilter').addClass('on');
//			}
//			if (self.Grid.InteractivityOptions['IgnoreMasterFilters']) {
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
	
	this.functionDo = function(_f){
		switch(_f){
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
//                            var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').getFilterExpression();
							var filter = $('#' + self.itemid + '_editFilter').dxFilterBuilder('instance').option('value');
                            var newDataSource = new DevExpress.data.DataSource({
                                store: self.filteredData,
                                paginate: true
                            });
                            newDataSource.filter(filter);
                            newDataSource.load();
                            
							self.meta.FilterString = filter;
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
			case 'customPalette': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				
				function rgbToHex ( rgb){
			        var toHex = function( string ){ 
			                string = parseInt( string, 10 ).toString( 16 ); 
			                string = ( string.length === 1 ) ? "0" + string : string; 

			                return string; 
			        }; 

			        var r = toHex( rgb.r ); 
			        var g = toHex( rgb.g ); 
			        var b = toHex( rgb.b ); 

			        var hexType = "#" + r + g + b; 

			        return hexType; 
				} 
				
				p.option({
					title: '색상 편집',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
                        var colorContainer = $('<div id="colorContainer"></div>');
                        $.each(self.filteredData, function(index, data) {
                        	var name = "";
                        	$.each(self.dimensions, function(_i, _dim){
                        		if(name != "")
                        			name += (" - " + data[_dim.caption]);
                        		else
                        			name = data[_dim.caption];
                        	});
							colorContainer.append('<p>' + name
													+ '</p><div id="' + self.itemid + '_itemsColor' + index + '"></div>');
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

						 $.each(self.filteredData, function(index, data) {
							 var color;
							 var palette = self.Grid.Palette;
							 if(typeof palette === "string")
								 palette = getPaletteValue(palette)
							
							 color = palette[index % palette.length];
							 if(typeof color !== 'string')
								 color = rgbToHex(color);
							 $('#' + self.itemid + '_itemsColor' + index).dxColorBox({
								value: color
							 });
                        });

                        // confirm and cancel
						$('#ok-hide').on('click', function() {
                            var newPalette = [];
                            $.each(self.filteredData, function(index, item) {
                                newPalette[index] = $('#' + self.itemid + '_itemsColor' + index).dxColorBox('instance').option('value');
                            });
                            self.Grid['Palette'] = newPalette;
                            self.dxItem.refresh();
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
			/* dogfoot 그리드 헤더 추가 기능 shlim 20210319 */
			case 'addColumnHeader': {
				if (!(self.dxItem)) {
					break;
				}
				
				var tempHeaderList = {};
				$.each(self.headerList,function(_i,_hdl){
					tempHeaderList[_hdl.HEADER_CODE] = _hdl;
				})
				
				function getHeaderListArray (_getList,_chkLookup){
			        var tempHeaderListArray = [];
			        if(_chkLookup){
			        	tempHeaderListArray.push({
			        		HEADER_CODE:"NonHeader",
			        		HEADER_NAME:"헤더없음",
			        		HEADER_YN:"N",
			        		COLUMN_LIST:[],
			        	})
			        }
			        if(Object.keys(tempHeaderList).length > 0){
			        	$.each(tempHeaderList,function(_i,_items){
			        		tempHeaderListArray.push(_items);
			        	})
			        }
			        return tempHeaderListArray
				}
				
				function getHeaderId (tempHeaderList) {
					var highestNum = 0;
					var paramNames = _.map(tempHeaderList, function(val) {
						return val.HEADER_CODE;
					});
					/* dogfoot WHATIF 데이터셋 매개변수와 중복되지 않도록 처리 shlim 20201022 */
					paramNames = paramNames.concat(
						_.map(tempHeaderList, function(param) {
							return param.HEADER_CODE;
						})
					);
					for (var i = 0; i < paramNames.length; i++) {
						var match = /^HEADER_CODE(\d*)$/.exec(paramNames[i]);
						if (match) {
							var paramNum = parseInt(match[1]);
							if (paramNum > highestNum) {
								highestNum = paramNum;
							}
						}
					}

					return {"HEADER_CODE":"HEADER_CODE"+(highestNum + 1),"HEADER_NAME":"HEADER"+(highestNum + 1)}
				}
				
				function addHeader(){
					var newHeaderGroup = {
							HEADER_CODE: getHeaderId(tempHeaderList).HEADER_CODE,
			        		HEADER_NAME: getHeaderId(tempHeaderList).HEADER_NAME,
			        		HEADER_YN:"N",
			        		COLUMN_LIST:[],
					}
					tempHeaderList[newHeaderGroup.HEADER_CODE] = newHeaderGroup;
				}
				
				function updateDataListLookup(){
					$('#' + self.itemid + '_dataFieldList').dxDataGrid('instance').option("columns",
							[
								{
									dataField: "name",
									caption:"필드 명",
									alignment:"center",
								},
								{
									dataField: "UniqueName",
									caption:"UniqueName",
									alignment:"center",
									visible:false,
								},
								{
									dataField: "HEADER_CODE",
									caption:"적용 헤더 그룹",
									alignment:"center",
									lookup:{
										dataSource: getHeaderListArray(tempHeaderList,true),
										displayExpr:"HEADER_NAME",
										valueExpr:"HEADER_CODE",
									}
								},
							]
					);
					$('#' + self.itemid + '_HeaderList').dxDataGrid('instance').option("columns",
							[
								{
									dataField: "HEADER_NAME",
									caption:"헤더 그룹명",
									alignment:"center",
								},
								{
									dataField: "HEADER_YN",
									caption:"적용 여부",
									alignment:"center",
									lookup:{
										dataSource:[
											{
												caption:'Y',
												value:'Y'
											},
											{
												caption:'N',
												value:'N'
											}
										],
										displayExpr:"caption",
										valueExpr:"value",
									},
								},
								{
									dataField: "HEADER_UPPER",
									caption:"상위 헤더",
									alignment:"center",
									lookup:{
										dataSource: getHeaderListArray(tempHeaderList,true),
										displayExpr:"HEADER_NAME",
										valueExpr:"HEADER_CODE",
									}
								},
								{
									dataField: "HEADER_CODE",
									caption:"HEADER_CODE",
									alignment:"center",
									visible:false,
								}
							]
					);
				}
				
				if($('#headerFieldPopup').length === 0){
					$('body').append('<div id="headerFieldPopup"></div>');
				}
				
				var X = $('#headerFieldPopup').dxPopup({
					width:1000,
					visible:true,
					showCloseButton:false,
					title: '헤더 추가',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('customFieldPopup');
					},
					contentTemplate: function(contentElement) {
                        var headerContainer = $('<div id="headerContainer"></div>');
                        
                        var paramTemplate = "<div class=\"modal-body\" style='height:93%'>\r\n" + 
                    	"                      <div class=\"row\" style='height:100%'>\r\n" + 
                    	"                            <div class=\"column\" style='width:40%'>\r\n" + 
                    	"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
                    	"                                   <div class=\"modal-tit\">\r\n" + 
                    	"                                   <span>헤더 목록</span>\r\n" +
                    	"									<div id=\"removeHeaderParam\" style=\"float: right\"></div>\r\n"+
                    	"									<div id=\"addHeaderParam\" style=\"float: right\"></div>\r\n"+
                    	"                                   </div>\r\n" +
                    	"									<div id=\""+self.itemid+"_HeaderList\" />\r\n" + 
                    	"                                </div>\r\n" +
                    	"                            </div>\r\n" + 
                    	"                            <div class=\"column\" style=\"width:60%\">\r\n" +
                    	"                            	<div class=\"row horizen\">\r\n" + 
                    	" 		                            <div class=\"column\" style=\"padding-bottom:0px; height:100%\">\r\n" +
                    	'										<div class="modal-article" style="height:100%;">' +
                    	"											<div id=\"calcParam_area\" class=\"param_area modal-tit\">\r\n" + 
                    	"   		                                     <span>필드 목록</span>" + 
                    	"       	                	            </div>\r\n" +
                    	"											<div id=\""+self.itemid+"_dataFieldList\" style='height: calc(100% - 30px);padding-bottom:30px;overflow:auto;'></div>\r\n" +
                    	"       	                	        </div>\r\n" +
                    	" 									</div>" + //column 끝
                        " 								 </div>" + //row horizon 끝
                    	"                            </div>\r\n" +  //column 끝 
                    	"                        </div>\r\n" + //row 끝
                    	"                    </div>\r\n" + //modal-body 끝
                    	"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
                    	"                        <div class=\"row center\">\r\n" + 
                    	"                            <a id=\"ok-hide-header\" class='btn positive ok-hide'>확인</a>" +
                    	"							<a id=\"close-header\" class='btn neutral close'>취소</a>" +
                    	"                        </div>\r\n" + 
                    	"                    </div>\r\n" + 
                    	"                </div>";
                        
                        contentElement.append(paramTemplate);
                        
                        headerContainer.dxScrollView({
                            height: 580,
                            width: '100%'
                        }).appendTo(contentElement);
                        
                       $('#' + self.itemid + '_HeaderList').dxDataGrid({
                        	height:'100%',
                        	width:'100%',
							dataSource: getHeaderListArray(tempHeaderList),
							editing: {
					            mode: 'cell',
				                allowUpdating: true,
				                allowAdding: false,
				                allowDeleting:true,
					            texts: {
					                confirmDeleteMessage: ''
				                },
				                useIcons: true,
				            },
							columns: [
								{
									dataField: "HEADER_NAME",
									caption:"헤더 그룹명",
									alignment:"center",
								},
								{
									dataField: "HEADER_YN",
									caption:"적용 여부",
									alignment:"center",
									lookup:{
										dataSource:[
											{
												caption:'Y',
												value:'Y'
											},
											{
												caption:'N',
												value:'N'
											}
										],
										displayExpr:"caption",
										valueExpr:"value",
									},
								},
								{
									dataField: "HEADER_UPPER",
									caption:"상위 헤더",
									alignment:"center",
									lookup:{
										dataSource: getHeaderListArray(tempHeaderList,true),
										displayExpr:"HEADER_NAME",
										valueExpr:"HEADER_CODE",
									}
								},
								{
									dataField: "HEADER_CODE",
									caption:"HEADER_CODE",
									alignment:"center",
									visible:false,
								}
							],
							selection:{
								mode:'single'
							},
							onRowInserted:function(e){
							},
							onRowInserting:function(e){
							},
							onRowRemoving:function(e){
								delete tempHeaderList[e.data.HEADER_CODE];
								updateDataListLookup();
							},
							onRowUpdated: function(e) {
								updateDataListLookup();
				            },
				            onRowUpdating: function(e) {
				            },
				            onEditorPreparing: function(e) {
							},
							showScrollbar:'never',
							hoverStateEnabled: true,
							showColumnHeaders:true,
							scrolling: {
								useNative: false 
							},
							onRowPrepared: function(e) {  
							 }  
						}).dxDataGrid('instance');
                       
                       $('#' + self.itemid + '_dataFieldList').dxDataGrid({
//                    	   height:'100%',
                       		width:'100%',
							dataSource: self.columns,
							editing: {
					            mode: 'cell',
				                allowUpdating: true,
				                allowAdding: false,
				                allowDeleting:false,
					            texts: {
					                confirmDeleteMessage: ''
				                },
				                useIcons: false,
				            },
							columns: [
								{
									dataField: "name",
									caption:"필드 명",
									alignment:"center",
								},
								{
									dataField: "UniqueName",
									caption:"UniqueName",
									alignment:"center",
									visible:false,
								},
								{
									dataField: "HEADER_CODE",
									caption:"적용 헤더 그룹",
									alignment:"center",
									lookup:{
										dataSource: getHeaderListArray(tempHeaderList,true),
										displayExpr:"HEADER_NAME",
										valueExpr:"HEADER_CODE",
									}
								},
							],
							selection:{
								mode:'standard'
							},
							onRowInserted:function(e){
							},
							onRowInserting:function(e){
							},
							onRowRemoving:function(e){
								delete tempHeaderList[e.data.HEADER_CODE];
								updateDataListLookup();
							},
							onRowUpdated: function(e) {
				            },
				            onRowUpdating: function(e) {
				            },
				            onEditorPreparing: function(e) {
							},
							showScrollbar:'never',
							hoverStateEnabled: true,
							showColumnHeaders:true,
							scrolling: {
								useNative: false 
							},
							onRowPrepared: function(e) {  
							 }  
                       }).dxDataGrid('instance')
                       
                       $('#addHeaderParam').dxButton({
                    	   icon:"plus",
                    	   onClick:function(){
                    		   addHeader();
                    		   $('#' + self.itemid + '_HeaderList').dxDataGrid("instance").option('dataSource',getHeaderListArray(tempHeaderList))
                    		   updateDataListLookup();
                    	   }
                       })
                        // confirm and cancel
						$('#ok-hide-header').on('click', function() {
							var hDataList = $('#' + self.itemid + '_dataFieldList').dxDataGrid("instance").getDataSource()._store._array
                           
                           $.each(tempHeaderList,function(_i,_tmp){
                        	   _tmp.COLUMN_LIST = [];
                        	   $.each(hDataList,function(_j,_hdata){
                        		   if(_tmp.HEADER_CODE === _hdata.HEADER_CODE){
                        			   _tmp.COLUMN_LIST.push(_hdata);
                        		   }
                               })
                           });
                           
                           self.headerChange = true;
                           self.headerList = tempHeaderList;
                           X.hide();
						});
						$('#close-header').on('click', function() {
							X.hide();
						});
					}
				}).dxPopup("instance");
				X.show();
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
			// 20200819 ajkim 데이터그리드 바 색상 추가 dogfoot
			case 'editPalette': {
                if (!(self.dxItem)) {
					break;
				}
				var paletteCollection = ['Bright', 'Harmony Light', 'Ocean', 'Pastel', 'Soft', 'Soft Pastel', 'Vintage', 'Violet', 
					'Carmine', 'Dark Moon', 'Dark Violet', 'Green Mist', 'Soft Blue', 'Material', 'Office'];
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
				var firstPalette = self.Grid.Palette;
				p.option({
                    target: '#editPalette',
                    onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
                        // palette select
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
                        var originalPalette = paletteCollection.indexOf(self.Grid.Palette) != -1
										? self.Grid.Palette
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
                                    self.Grid.Palette = self.customPalette;
                                    self.dxItem.refresh();
								} else {
                                    self.isCustomPalette = false;
	                                self.Grid.Palette = paletteObject2[e.value];
                                    self.dxItem.refresh();
								}
							}
                        });
                        // confirm and cancel
                        contentElement.find('#save-ok').on('click', function() {
                            p.option('visible', false);
                        });
                        contentElement.find('#save-cancel').on('click', function() {
                            self.Grid.Palette = firstPalette;
                            self.dxItem.refresh();
                            p.option('visible', false);
                        });
					},
//					onHiding:function(){
//						 self.Grid.Palette = chagePalette;
//					}
                });
                p.option('visible', !(p.option('visible')));
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
					if (self.IO.MasterFilterMode === 'Single') {
						$('#' + self.trackingClearId).addClass('invisible');
						self.Grid.InteractivityOptions.MasterFilterMode = 'Off';
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
						self.Grid.InteractivityOptions.MasterFilterMode = 'Single';
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
						gDashboard.filterData(self.itemid, self.trackingData);
						
					}
					self.tracked = !self.Grid.InteractivityOptions.MasterFilterMode == 'Off' ? false : true;
					self.meta = self.Grid;
					
					if(self.dxItem != undefined){
						self.dxItem.option('selection.mode',  WISE.util.String.toLowerCase(self.IO.MasterFilterMode));
					}
					
					if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
						gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
					}
					/*필터 프로그레스바 오류 수정*/
					if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
						gProgressbar.setStopngoProgress(true);
						gProgressbar.hide();	
						gDashboard.updateReportLog();
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
					self.Grid.InteractivityOptions.MasterFilterMode = 'Off';
					self.IO.MasterFilterMode = 'Off';
				} else {
					$('#' + self.trackingClearId).removeClass('invisible');
					self.Grid.InteractivityOptions.MasterFilterMode = 'Multiple';
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
					self.clearTrackingConditions();
				}
				/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
				self.tracked = !self.Grid.InteractivityOptions.MasterFilterMode == 'Off' ? false : true;
				
				if(self.dxItem != undefined){
					self.dxItem.option('selection.mode',  WISE.util.String.toLowerCase(self.IO.MasterFilterMode));
				}
				//self.meta = self.Grid;
				//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
				self.functionBinddata = true;
				//self.bindData(self.globalData,true);
				
				break;
			}
			// toggle drill down
			case 'drillDown': {
				if (!(self.dxItem)) {
					break;
				}
				// Both master filter and drill-down cannot be active at the same time. Turn master filter off.
				if (self.IO.MasterFilterMode !== 'Off') {
					self.Grid.InteractivityOptions.MasterFilterMode = 'Off';
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
					$('#' + self.DrilldownClearId).removeClass('invisible');
					self.initDrillDownOperation();
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
				self.Grid.IsMasterFilterCrossDataSource = self.IsMasterFilterCrossDataSource;				
				self.clearTrackingConditions();					
				gDashboard.filterData(self.itemid, self.trackingData);				
				
				if(!self.IsMasterFilterCrossDataSource){					
					gDashboard.query();
				}
				
				break;
			}
			// toggle ignore master filter
			case 'ignoreMasterFilter': {
				if (!(self.dxItem)) {
					break;
				}			
				self.IO.IgnoreMasterFilters = $('#ignoreMasterFilter').hasClass('on') ? true : false;
				self.Grid.InteractivityOptions.IgnoreMasterFilters = self.IO.IgnoreMasterFilters;
				self.meta = self.Grid;
				self.tracked = !self.Grid.InteractivityOptions.IgnoreMasterFilters;
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
			
			case 'captionVisible': {
				var titleBar = $('#' + self.itemid + '_title');
				if (titleBar.css('display') === 'none') {
					titleBar.css('display', 'block');
					if(self.meta)
						self.meta.ShowCaption = true;
				} else {
					titleBar.css('display', 'none');
					if(self.meta)
						self.meta.ShowCaption = false;
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
//						 initialize title input box
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
                        contentElement.find('#ok-hide').on('click', function() {
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
                                    self.meta.Name = newName;
                                }
                                self.Name = newName;
                                p.hide();
                            }
                        });
                        contentElement.find('#close').on('click', function() {
                            p.hide();
                        });
					}
				});
				// show popup
				p.show();
				break;
			}
			case 'setGridLines':
				if (!(self.dxItem)) {
					break;
				}	
				var p = $('#editPopover').dxPopover('instance');
				var isChanged = false;
				p.option({
					target: '#setGridLines',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_showHorizontalLines">');
						contentElement.append('<div id="' + self.itemid + '_showVerticalLines">');
						contentElement.append('<div id="' + self.itemid + '_enableBandedRows">');

						$('#' + self.itemid + '_showHorizontalLines').dxCheckBox({
							width: 150,
							value: self.Grid.GridOptions.ShowRowLines ? true : false,
							text: '가로 줄 표시',
							onValueChanged: function(e) {
								self.Grid.GridOptions.ShowRowLines = e.value;
								self.meta = self.Grid;
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData,true);
							}
						});
						
						$('#' + self.itemid + '_showVerticalLines').dxCheckBox({
							width: 150,
							value: self.Grid.GridOptions.ShowColumnLines ? true : false,
							text: '세로 줄 표시',
							onValueChanged: function(e) {
								self.Grid.GridOptions.ShowColumnLines = e.value;
								self.meta = self.Grid;
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData,true);
							}
						});
						
						$('#' + self.itemid + '_enableBandedRows').dxCheckBox({
							width: 150,
							value: self.Grid.GridOptions.EnableBandedRows ? true : false,
							text: '줄 무늬 행',
							onValueChanged: function(e) {
								self.Grid.GridOptions.EnableBandedRows = e.value;
								self.meta = self.Grid;
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData,true);
							}
						});
					}
								
				});
				p.option('visible', !(p.option('visible')));
				break;
			case 'allowGridCellMerge':
				if (!(self.dxItem)) {
					break;
				}	
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#allowGridCellMerge',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_allowGridCellMerge">');
						$('#' + self.itemid + '_allowGridCellMerge').dxRadioGroup({
							dataSource: ['On', 'Off'],
							value: self.Grid.GridOptions.AllowGridCellMerge ? 'On' : 'Off',
							onValueChanged: function(e) {
								self.Grid.GridOptions.AllowGridCellMerge = e.value === 'On' ? true : false;
								self.tracked = !self.Grid.GridOptions.AllowGridCellMerge;
								self.meta = self.Grid;
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData,true);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			case 'showColumnHeaders':
				if (!(self.dxItem)) {
					break;
				}	
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#showColumnHeaders',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_showColumnHeaders">');
						$('#' + self.itemid + '_showColumnHeaders').dxRadioGroup({
							dataSource: ['On', 'Off'],
							value: self.Grid.GridOptions.ShowColumnHeaders ? 'On' : 'Off',
							onValueChanged: function(e) {
								self.Grid.GridOptions.ShowColumnHeaders = e.value === 'On' ? true : false;
								self.tracked = !self.Grid.GridOptions.ShowColumnHeaders;
								self.meta = self.Grid;
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData,true);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			case 'wordWrap':
				if (!(self.dxItem)) {
					break;
				}	
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#wordWrap',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_wordWrap">');
						$('#' + self.itemid + '_wordWrap').dxRadioGroup({
							dataSource: ['On', 'Off'],
							value: self.Grid.GridOptions.WordWrap ? 'On' : 'Off',
							onValueChanged: function(e) {
								self.Grid.GridOptions.WordWrap = e.value === 'On' ? true : undefined;
								self.tracked = !self.Grid.GridOptions.WordWrap;
								self.meta = self.Grid;
								self.dxItem.option('wordWrapEnabled', self.Grid.GridOptions.WordWrap);
								//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
								self.functionBinddata = true;
								self.bindData(self.globalData,true);
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			case 'columnWidthMode':
				if (!(self.dxItem)) {
					break;
				}	
				var p = $('#editPopover').dxPopover('instance');
				p.option({
					target: '#columnWidthMode',
					width: 150,
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForEditText('editPopover');
					},
					contentTemplate: function(contentElement) {
						contentElement.append('<div id="' + self.itemid + '_ColumnWidthMode">');
						$('#' + self.itemid + '_ColumnWidthMode').dxRadioGroup({
//							dataSource: ['내용에 자동 맞춤', '모눈에 맞춤', '수동'],
							dataSource: ['내용에 자동 맞춤', '수동'],
							value: self.Grid.GridOptions.ColumnWidthMode == 'AutoFitToContents' ? '내용에 자동 맞춤' : '수동',
							onValueChanged: function(e) {
								self.Grid.GridOptions.ColumnWidthMode = e.value === '내용에 자동 맞춤' ? 'AutoFitToContents' : 'Manual';
								self.tracked = !self.Grid.GridOptions.ColumnWidthMode;
								self.meta = self.Grid;
								if(self.Grid.GridOptions.ColumnWidthMode == 'AutoFitToContents') {
									self.dxItem.option('allowColumnResizing', false);
									self.dxItem.option('columnAutoWidth', true);
									//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoot
									self.functionBinddata = true;
									self.bindData(self.globalData);
								} else {
									self.dxItem.option('allowColumnResizing', true);
									self.dxItem.option('columnAutoWidth', false);
								}
							}
						});
					}
				});
				p.option('visible', !(p.option('visible')));
				break;
			/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
			case 'pagingSetting': {
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '페이징 설정',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					contentTemplate: function(contentElement) {
						var initialized = false;

						// initialize template
						var html = 	'<div id="' + self.itemid + '_yOptions"></div>' +
									'<div style="padding-bottom:20px;"></div>' +
									'<div class="modal-footer" style="padding-bottom:0px;">' +
										'<div class="row center">' +
											'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
											'<a id="close" href="#" class="btn neutral close">취소</a>' +
										'</div>' +
									'</div>';
						contentElement.append(html);

						// edit Y axis measures
						var pagingSet = [self.Grid.GridOptions.PagingSet.Fir,self.Grid.GridOptions.PagingSet.Sec,self.Grid.GridOptions.PagingSet.Thi];
						var optionsForm = $('#' + self.itemid + '_yOptions').dxForm({
							items: [
								{
									dataField: '페이징 사용 여부',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: self.Grid.GridOptions.PagingEnabled,
										onValueChanged: function(e) {
											if (e.value) {
												optionsForm.getEditor('페이징 설명').option('disabled', false);
												optionsForm.getEditor('페이징 기본값').option('disabled', false);
											} else {
												optionsForm.getEditor('페이징 설명').option('disabled', true);
												optionsForm.getEditor('페이징 기본값').option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '페이징 설명',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.Grid.GridOptions.PagingDesc,
										onInitialized: function(e) {
											var pagingEnabled = self.Grid.GridOptions.PagingEnabled;
											if (pagingEnabled != true) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '페이징 기본값',
									editorType: 'dxSelectBox',
									editorOptions: {
										items: pagingSet,
										value: self.Grid.GridOptions.PagingDefault,
										onInitialized: function(e) {
											var pagingEnabled = self.Grid.GridOptions.PagingEnabled;
											if (pagingEnabled != true) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '페이징 개수 사용 여부',
									editorType: 'dxCheckBox',
									editorOptions: {
										value: self.Grid.GridOptions.PagingSizeEnabled,
										onValueChanged: function(e) {
											if (e.value) {
												optionsForm.getEditor('첫번째 값').option('disabled', false);
												optionsForm.getEditor('두번째 값').option('disabled', false);
												optionsForm.getEditor('세번째 값').option('disabled', false);
											} else {
												optionsForm.getEditor('첫번째 값').option('disabled', true);
												optionsForm.getEditor('두번째 값').option('disabled', true);
												optionsForm.getEditor('세번째 값').option('disabled', true);
											}
										}
									}
								},
								{
									dataField: '첫번째 값',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.Grid.GridOptions.PagingSet.Fir,
										onInitialized: function(e) {
											var pagingEnabled = self.Grid.GridOptions.PagingSizeEnabled;
											if (pagingEnabled != true) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '두번째 값',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.Grid.GridOptions.PagingSet.Sec,
										onInitialized: function(e) {
											var pagingEnabled = self.Grid.GridOptions.PagingSizeEnabled;
											if (pagingEnabled != true) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								},
								{
									dataField: '세번째 값',
									editorType: 'dxTextBox',
									editorOptions: {
										value: self.Grid.GridOptions.PagingSet.Thi,
										onInitialized: function(e) {
											var pagingEnabled = self.Grid.GridOptions.PagingSizeEnabled;
											if (pagingEnabled != true) {
												e.component.option('disabled', true);
											} else {
												e.component.option('disabled', false);
											}
										}
									}
								}
							]
						}).dxForm('instance');

						// confirm and cancel
						$('#ok-hide').off('click').on('click', function() {
							var formData = optionsForm.option('formData');
							var pagingDesc = formData['페이징 설명'];
							var pagingEnabled = formData['페이징 사용 여부'];
							var pagingSizeEnabled = formData['페이징 개수 사용 여부'];
							var pagingSet = {
								Fir: formData['첫번째 값'],
								Sec: formData['두번째 값'],
								Thi: formData['세번째 값']	
							};
							var pagingDefault = formData['페이징 기본값'];
							
							self.Grid.GridOptions.PagingDesc = pagingDesc;
							self.Grid.GridOptions.PagingEnabled = pagingEnabled;
							self.Grid.GridOptions.PagingSizeEnabled = pagingSizeEnabled;
							self.Grid.GridOptions.PagingSet = pagingSet;
							/*20210323 페이징 기본값이 바뀌었을 때, pagingStart 0으로 초기화   syjin dogfoot */
							if(pagingDefault != self.Grid.GridOptions.PagingDefault){
								self.Grid.GridOptions.pagingDefaultChanged = true;
							}else{
								self.Grid.GridOptions.pagingDefaultChanged = false;
							}
							self.Grid.GridOptions.PagingDefault = pagingDefault;
							
							self.functionBinddata = true;
							self.bindData(self.globalData, true);
                            p.hide();
						});
						$('#close').off('click').on('click', function() {
							p.hide();
						});
					}
				});
				p.show();
				break;
			}
			case 'autoFitGrid':
				break;
			case 'manual':
				break;
			case 'gridOption':
				/*dogfoot shlim 20210420*/
				if (!(self.dxItem)) {
					break;
				}
				var p = $('#editPopup').dxPopup('instance');
				p.option({
					title: '그리드 속성',
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForOption('editPopup');
					},
					width: 1000,
					contentTemplate: function(contentElement) {
						var deltahtml = "<div class=\"modal-body\" style='height: 85%;'>\r\n" +
    					"                        <div class=\"row\" style='height:100%'>\r\n" +
	    											/*dogfoot shlim 20210420*/
    					"                            <div class=\"column\" style='width:100%;height:90%'>\r\n" +
    					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
    					"                                   <div class=\"modal-tit\">\r\n" +
    					"                                   </div>\r\n" +
    					"									<div id=\"" + self.itemid + "_optionField\" />\r\n" +
    					"                                </div>\r\n" +
    					"                            </div>\r\n" +
    					"                        </div>\r\n" + //row 끝
    					"                    </div>\r\n" + //modal-body 끝
    					"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
    					"                        <div class=\"row center\">\r\n" +
    					"                            <a id='"+self.itemid+"_gridoptionOK' class=\"btn positive ok-hide\" href='#'>확인</a>\r\n" +
    					"                            <a id='"+self.itemid+"_gridoptionCancel' class='btn neutral close' href='#'>취소</a>\r\n" +
    					"                        </div>\r\n" +
    					"                    </div>\r\n" +
    					"                </div>";

						contentElement.append(deltahtml);
						var fieldItems = new Array();

						self.optionFields = [];
						$.each(self.columns,function(_i,_fields){
							var colVisible = false;
							$.each($('#' + self.itemid).dxDataGrid('instance').getVisibleColumns(),function(_ii,_ee){
								if(_ee.caption == _fields.caption) {
									colVisible = true;
								}
							});
							if(_fields.dataType == 'string'){
								var obj = {
									'TYPE': '차원',
									'dataField':_fields.dataField,
									'FLD_NM':_fields.dataField,
									'CAPTION':_fields.caption,
									'GRID_VISIBLE': _fields.visible
								}
								self.optionFields.push(obj);
							}else if(_fields.dataType == 'number'){
								var obj = {
									'TYPE': '측정값',
									'dataField':_fields.dataField,
									'FLD_NM':_fields.dataField,
									'CAPTION':_fields.caption,
									'FORMAT' : _fields.format,
									'GRID_VISIBLE':_fields.visible
								}
								self.optionFields.push(obj);
							}
						});

						$('#' + self.itemid + '_optionField').dxDataGrid({
							columns:[
								{
									dataField: "TYPE",
									alignment:"center",
									allowEditing:false,
									width: 50
								},
								{
									caption: "필드명",
									alignment:"center",
									dataField: "FLD_NM",
									allowEditing:false,
									cellTemplate: function(container, options) {
										container.addClass("FLD_NM-cell");
										container.text(options.value);
										return container;
									}
								},
								{
									caption: "데이터 항목 명",
									alignment:"center",
									dataField: "CAPTION"
								},
								{
									caption: "그리드 표시 여부",
									alignment:"center",
									dataField : "GRID_VISIBLE",
									allowEditing:false,
									width: 130,
									cellTemplate: function(container, options) {
										container.addClass("GRID_VISIBLE-cell");
					                    $("<div />").dxCheckBox({
					                    	visible:true,
					                    	onValueChanged: function(_e){
					                    		$.each(self.optionFields,function(_i,_fields){
					                    			if(_fields.FLD_NM == $(_e.element).parent().parent().children('.FLD_NM-cell').text()){
					                    				_fields.GRID_VISIBLE = _e.value;
					                    			}
					                    		});
					                    	}
					                    }).appendTo(container);
									},
								}
							],
							wordWrapEnabled:false,
							dataSource:self.optionFields,
							keyExpr: "FLD_NM",
							onContentReady:function(){
								gDashboard.fontManager.setFontConfigForOption('editPopup');
								$.each(self.optionFields,function(_i,_fields){
									if(_fields.GRID_VISIBLE == true){
										var rowItem = $('#'+self.itemid + '_optionField').dxDataGrid('instance').getRowElement($('#'+self.itemid + '_optionField').dxDataGrid('instance').getRowIndexByKey(_fields.FLD_NM));
										$($(rowItem).find(".GRID_VISIBLE-cell").children()).dxCheckBox('instance').option('value',true);
									}
								});
							}
						});
						$('#'+self.itemid+'_gridoptionOK').dxButton({
							text:"확인",
							onClick:function(){
								if($('#'+self.itemid + '_optionField').dxDataGrid('hasEditData')){
									$('#'+self.itemid + '_optionField').dxDataGrid('saveEditData');
								}
								
								$.each(self.optionFields,function(_ii,_ff){
									$.each(self.columns,function(_i,_fields){
										if(_fields.caption == _ff.CAPTION) {
											_fields.visible = _ff.GRID_VISIBLE;
										}
									});
									
									$.each(self.dimensions,function(_i,_fields){
										if(_fields.caption == _ff.CAPTION) {
											_fields.visible = _ff.GRID_VISIBLE;
										}
									});
									
									$.each(self.measures,function(_i,_fields){
										if(_fields.caption == _ff.CAPTION) {
											_fields.visible = _ff.GRID_VISIBLE;
										}
									});
									
									$.each(self.DI.Dimension,function(_i,_fields){
										if(_fields.Name == _ff.CAPTION) {
											_fields.visible = _ff.GRID_VISIBLE;
										}
									});
									
									$.each(self.DI.Measure,function(_i,_fields){
										if(_fields.Name == _ff.CAPTION) {
											_fields.visible = _ff.GRID_VISIBLE;
										}
									});
								});

								self.dxItem.option('columns', self.columns);
								self.dxItem.refresh();
								
								p.hide();
							}
						});
						$('#'+self.itemid+'_gridoptionCancel').dxButton({
							text:"취소",
							onClick:function(){
								p.hide();
							}
						});
					}
				});
				p.show();
				break;
		}
	}
	
	this.captionVisble = function(){
		var d = self.dxItem;
	}
	
	this.generateColumns = function(_grid) {
		var GetDataMember = WISE.libs.Dashboard.item.DataUtility.getDataMember;
		
		var ColumnConfig = {
			weave: function(_oGridColumn, _dataItems) {
				var setDisplayMode = function(_oGridColumn) {
					//var mode = (_oGridColumn['DisplayMode'] || '').toLowerCase();
					var mode = '';
					if (_oGridColumn['SparklineValue']) {
						mode = 'sparkline';	
					}else{
						mode = _oGridColumn['displayMode']? _oGridColumn['displayMode']: _oGridColumn['DisplayMode'];
					}
					return mode;
				};

				var getConfig = function(dataMember){
					// setting display-mode of data-member
					dataMember.displayMode = setDisplayMode(_oGridColumn);
					
					
					if (dataMember.displayMode === 'sparkline') {
						var sparklineOptions = {
							ViewType: 'Line',
							HighlightStartEndPoints: dataMember.highlightstartendpoints,
							HighlightMinMaxPoints: dataMember.highlightminmaxpoints
						};						
						dataMember.sparkline = {
							sparklineElements: self.sparklineElements,
							sparklineOptions: sparklineOptions,
							showStartEndValues: _oGridColumn['ShowStartEndValues'] // dxSparkline에서 지원하지 않음
						};
					}

					var width;
					if (_grid['GridOptions'] && _grid['GridOptions']['ColumnWidthMode'] === 'Manual') {
						if(_oGridColumn['Weight'] == undefined){
							_oGridColumn['Weight'] = 100/(self.DI.Dimension.length+self.DI.Measure.length);
						}
						_oGridColumn['Weight'] = (_oGridColumn['Weight']+"").replace('%','');
						width = ((_oGridColumn['Weight'] || -1) / _oGridColumn.wiseMaxColumnWidth * 100) + '%'
					} else {
						width = -1;
					}
					
					// LSH topN
					var dMtopNval = new Array();
                    if(self.meta['DataItems']['Measure']){
                    	if(self.meta['DataItems']['Measure'].length == undefined){
					    	dMtopNval.push(self.meta['DataItems']['Measure']);
						}else{
							dMtopNval = self.meta['DataItems']['Measure'];
						}
						if(dataMember.TopNEnabled){
							   $.each(dMtopNval,function(_i,_val){
								if(_val.UniqueName == dataMember.TopNMeasure){
									dataMember['topMember'] = _val.DataMember;
								}
							});
						}
                    }
					
                    var sortOrder = 'asc';
                    if(typeof self.sqlConfig != 'undefined' && self.sqlConfig.OrderBy.indexOf('S_' + dataMember.caption) > -1) {
                    	sortOrder = 'none';
                    } else if(typeof dataMember.sortByMeasure != 'undefined' && dataMember.sortByMeasure != "") {
                    	sortOrder = 'none';
                    } else {
                    	sortOrder = dataMember.sortOrder;
                    }
					// LSH topN
					var config = {
							dataField: dataMember.type === 'measure' ? dataMember.nameBySummaryType : dataMember.name,
							alignment: 'left',
							dataType: 'string',
							format: '',
							caption: _oGridColumn['Name'] || dataMember.caption,
							name: dataMember.name,
							uniqueName : dataMember.uniqueName,
							UniqueName : dataMember.uniqueName,
							/*dogfoot 그리드 정렬기준 항목 오류 수정shlim 20200716*/
							sortOrder: sortOrder,
							/* goyong ktkang 정렬 오류 수정 */
//							sortOrder: '',
							sortByMeasure: dataMember.sortByMeasure,
							TopNEnabled: dataMember.TopNEnabled === true ? dataMember.TopNEnabled : false,
							TopNOrder: dataMember.TopNOrder === true ? dataMember.TopNOrder : false,
							TopNCount: dataMember.TopNCount,
							TopNMeasure: dataMember.TopNMeasure,
							TopNShowOthers: dataMember.TopNShowOthers === true ? dataMember.TopNShowOthers : false,
							topMember:dataMember.topMember,
							width: width < 0 ? undefined : width,
							CubeUniqueName: dataMember.CubeUniqueName,
							sortByMeasure: dataMember.sortByMeasure,
							/*dogfoot 통계 분석 추가 shlim 20201103*/
							ContainerType: dataMember.ContainerType,
							headerCellTemplate:function(header,info){
								/*dogfoot 데이터 그리드 헤더 길이 오류 수정 shlim 20210507*/
								$(header).append('<span id="header_length"></span>')
								$('#header_length').text(info.column.caption);
								
                                var headerwidth =$('#header_length').outerWidth() +15;

                                $('#header_length').remove();
								$('<div style="width:'+headerwidth+'px;">')
								    .html(info.column.caption)
								    .appendTo(header);
								
//								$('<div>')
//								    .html(info.column.caption)
//								    .appendTo(header);
							},
					};
					
					
					if (dataMember.type === 'measure') {
					/*20201111 AJKIM 통계 모두 왼쪽 정렬 DOGFOOT*/
						config.alignment = gDashboard.reportType === 'StaticAnalysis'? 'left' : 'right';
						config.dataType = 'number';
						config.summaryType = dataMember.summaryType;
						config.format = dataMember.format;
						config.precision = dataMember.precision;
						config.precisionOption = dataMember.precisionOption;
						config.calculateDisplayValue = function(_rowData) {
							/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
							if(self.isDownloadExpand) return _rowData[dataMember.nameBySummaryType];
							var value = _rowData[dataMember.nameBySummaryType];
							return WISE.util.Number.unit(value, dataMember.formatType, dataMember.unit, dataMember.precision, dataMember.includeGroupSeparator, 
								undefined, dataMember.suffix, dataMember.suffixEnabled , dataMember.precisionOption);
						};
						config.sortingMethod =  function (value1, value2) {
			                // Handling null values
			                if(!value1 && value2) return -1;
			                if(!value1 && !value2) return 0;
			                if(value1 && !value2) return 1;
			                // Determines whether two strings are equivalent in the current locale
			                
							if(value1.indexOf('-') == -1 && value2.indexOf('-') == -1){
								if(value1.length > value2.length){
									return 1;
								}else if(value1.length == value2. length){
									return value1.localeCompare(value2);
								}else{
									return -1;
								}
							}else if(value1.indexOf('-') == -1){
								return 1; 
							}else if(value2.indexOf('-') == -1){
								return -1;
							}else{
								if(value1.length > value2.length){
									return -1;
								}else if(value1.length == value2. length){
									return value1.localeCompare(value2);
								}else{
									return 1;
								}
							}
			            }
					}
					switch (dataMember.displayMode) {
					case 'bar':
						
						if(self.columnNamesForBarCellMaxValue.length > 0 ){
							$.each(self.columnNamesForBarCellMaxValue,function(_i,_d){
								if(_d.nameBySummaryType !== dataMember.nameBySummaryType){
									self.columnNamesForBarCellMaxValue.push(dataMember);
								}
							});
						}else{
							self.columnNamesForBarCellMaxValue.push(dataMember);
						}
						
						
						var opts = {
							columnConfig: config,
							dataMember: dataMember,
							item: self
						};
						self.DGU.Graph.bar(opts);
						break;
					case 'sparkline':						
						if(self.columnNamesForSparklineCell.length > 0 ){
							$.each(self.columnNamesForSparklineCell,function(_i,_d){
								if(_d.nameBySummaryType !== dataMember.nameBySummaryType){
									self.columnNamesForSparklineCell.push(dataMember);
								}
							});
						}else{
							self.columnNamesForSparklineCell.push(dataMember);
						}
						
						var opts = {
							columnConfig: config,
							dataMember: dataMember,
							dimensions: self.dimensions
						};
						self.DGU.Graph.sparkline(opts);
						break;
					}
					return config;
				}
				
				var columnObject = _oGridColumn['Dimension'] || _oGridColumn['Measure'] || _oGridColumn['SparklineValue'];
				var dataMember;
				if(columnObject.length > 0){
					_.each(columnObject,function(_columnObject){
						dataMember = GetDataMember(_columnObject, _dataItems, self.dimensions, self.measures);
						return getConfig(dataMember);
					});
				} else{
					dataMember = GetDataMember(columnObject, _dataItems, self.dimensions, self.measures);
					return getConfig(dataMember);
				}
				
			}
		};
		/* sort grid columns */
		var gridColumns = [];
		if(typeof _grid.GridColumns != 'undefined')
		$.each(_grid.GridColumns, function(_ix0, _cx0) {
			$.each(WISE.util.Object.toArray(_cx0), function(_ix1, _cx1) {
				gridColumns.push({"type": _ix0, "elements": _cx1, "order": _cx1.wiseOrder});
			});
		});
		
		if(typeof(_grid.HiddenMeasures) != 'undefined')
		{
			$.each(_grid.HiddenMeasures, function(_ix0, _cx0) {			
				gridColumns.push({"type": 'Hidden' + _ix0, "elements":{ 'Measure' : _cx0 }, "order": '99999999'});
			});
		}
		gridColumns.sort(function(_a, _b) {return _a.order - _b.order;});
		
		var maxColumnWidth;
		if (_grid['GridOptions'] && _grid['GridOptions']['ColumnWidthMode'] === 'Manual') {
			maxColumnWidth = 0;
			$.each(gridColumns, function(_i, _co) {
				maxColumnWidth += (parseFloat(_co.elements['Weight'],10) || 0);
			});
		}	
		
		/* set column config */
		var columns = [];
		$.each(gridColumns, function(_id0, _ed0) {
			
			switch (_ed0.type) {
			case 'GridDimensionColumn':
			case 'GridMeasureColumn':
			case 'GridSparklineColumn':
				
				$.each(WISE.util.Object.toArray(_ed0.elements), function(_id1, _ed1) {
					if (maxColumnWidth) _ed1.wiseMaxColumnWidth = maxColumnWidth;
					
					if ( _ed1['DisplayMode'] === 'Image') {
//						gConsole.info('컬럼[' + _ed1['Name']+'] 이미지모드는 지원하지 않습니다.');
						return true;
					}
					var config = ColumnConfig.weave(_ed1, _grid.DataItems);
					/*dogfoot 헤더 정보 필드에 저장 shlim 20210317*/
					if(Object.keys(self.headerList).length > 0){
						$.each(self.headerList,function(_ih,_hdl){
							$.each(_hdl.COLUMN_LIST,function(_icl,_hcl){
								if(_hcl.UniqueName===config.UniqueName){
									config.HEADER_CODE =_hcl.HEADER_CODE
									config.HEADER_UPPER =_hdl.HEADER_UPPER 
								}
							})
						})
					}
					columns.push(config);
				});
				
				break;
			/*case 'HiddenDimension' :
			case 'HiddenMeasure' :
				
				$.each(WISE.util.Object.toArray(_ed0.elements), function(_id1, _ed1) {
	
					var dataMember = GetDataMember(_ed1.Measure, _grid.DataItems, self.dimensions, self.measures);
					
					var config = {
							dataField: dataMember.type === 'measure' ? dataMember.nameBySummaryType : dataMember.name,
							alignment: 'left',
							dataType: 'string',
							format: '',
							caption: dataMember.caption,
							visible:false,
							sortOrder:'asc'
						};

					columns.push(config);
				});*/
				
			case 'GridDeltaColumn':
				var calcColumnWidth = function(_ed2) {
					var width;
					if (_grid['GridOptions'] && _grid['GridOptions']['ColumnWidthMode'] === 'Manual') {
						width = ((_ed2['Weight'] || -1) / _ed2.wiseMaxColumnWidth * 100) + '%'
					} else {
						width = -1;
					}
					return width;
				};
				
				$.each(WISE.util.Object.toArray(_ed0.elements), function(_id2, _ed2) {
					if (maxColumnWidth) _ed2.wiseMaxColumnWidth = maxColumnWidth;
					
					var displayMode = _ed2['DisplayMode'];
					var width = calcColumnWidth(_ed2);
					
					var actualUniqueName = _ed2['ActualValue'] && _ed2['ActualValue']['UniqueName'];
					var targetUniqueName = _ed2['TargetValue'] && _ed2['TargetValue']['UniqueName'];
					var actualDataMember = actualUniqueName && GetDataMember(actualUniqueName, _grid.DataItems, self.dimensions, self.measures);
					var targetDataMember = targetUniqueName && GetDataMember(targetUniqueName, _grid.DataItems, self.dimensions, self.measures);
					
					if(targetDataMember == undefined){
                    	return;
                    }
					
					if(_ed2.DeltaOptions.AlwaysShowZeroLevel == undefined && _ed2.AlwaysShowZeroLevel != undefined){
						_ed2.DeltaOptions.AlwaysShowZeroLevel = _ed2.AlwaysShowZeroLevel;
						_ed2.AlwaysShowZeroLevel = undefined;
					}
					
					var deltaOptions = _ed2.DeltaOptions;
					
					var columnCaption = [];
					if (actualDataMember) columnCaption.push(actualDataMember.rawCaption || actualDataMember.captionBySummaryType);
					if (targetDataMember) columnCaption.push(targetDataMember.rawCaption || targetDataMember.captionBySummaryType);
					
					var uid = columnCaption.join('_');
					var caption = columnCaption.join(' vs ');
					var config = {
						caption: _ed2['Name'] || caption,
						dataField: 'DELTA_CELL_COLOR_' + uid,
						dataType: 'number',
						actualUniqueName: actualDataMember.uniqueName,
						targetUniqueName: targetDataMember.uniqueName,
						width: width < 0 ? undefined : width,
						calculateCellValue: function (_data) {
							var av = actualDataMember && _data[actualDataMember.nameBySummaryType];
							var tv = targetDataMember && _data[targetDataMember.nameBySummaryType];
							var valueTextObject = self.DU.makeTextValueObjectOfDeltaOptions(av, [tv], deltaOptions);
							_data['DELTA_CELL_COLOR_' + uid] = valueTextObject.fc;
							
							return valueTextObject.vt;
						}
					};
					
					if ((displayMode || '').toLowerCase() === 'bar') {
						var opts = {
							columnConfig: config,
							actualDataMember: actualDataMember,
							targetDataMember: targetDataMember
						};
						self.DGU.Graph.bar(opts);
					}
					else {
						config.cellTemplate = function (_container, _options) {
			               	var fontColor = _options.data['DELTA_CELL_COLOR_' + uid]; 
			                $('<div style="color:' + fontColor + ';">' + _options.value + '</div>').appendTo(_container);
			            };
					}
					columns.push(config);
				});
				
				break;
			}
		});
		
		$.each(gridColumns, function(_id0, _ed0) {
			switch (_ed0.type) {
			case 'HiddenDimension' :
			//case 'HiddenMeasure' :
				$.each(WISE.util.Object.toArray(_ed0.elements), function(_id1, _ed1) {
	
					var dataMember = GetDataMember(_ed1.Measure, _grid.DataItems, self.dimensions, self.measures);
					
					$.each(columns , function(_id2, _ed2) {
						if(_ed2.dataField == (dataMember.type === 'measure' ? dataMember.nameBySummaryType : dataMember.name))
						{
							_ed2.visible = false;
						}
					});
					
					/*var config = {
							dataField: dataMember.type === 'measure' ? dataMember.nameBySummaryType : dataMember.name,
							alignment: 'left',
							dataType: 'string',
							format: '',
							caption: dataMember.caption,
							visible:false,
							sortOrder:'asc'
						};

					columns.push(config);*/
				});
				
			}
		});
		return columns;
	};
	
	/**
	 * @param _grid: meta object
	 */
	this.setTackingFlag = function(chk)
	{
		this.tracked = chk;
	}
	
	this.getDxItemConfigs = function(_grid) {
	/*20201111 AJKIM 그리드 셀 병합 /셀 헤더 오류 수정   DOGFOOT*/
		var showColumnHeaders = true, showColumnLines = true, showRowLines = true, AllowGridCellMerge = gDashboard.reportType === 'StaticAnalysis' && self.Name === '그룹별 기술통계'? true :false, WordWrap = false, EnableBandedRows = false;
		/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
		var pagingDesc = '';
		var pagingEnabled = (gDashboard.reportType === 'StaticAnalysis' && $("#dashboardTabPage1 #"+self.ComponentName).length > 0)? true : false;
		var pagingSizeEnabled = false;
		var pagingSet = [10, 20, 50];
		var pagingDefault = 20;
		var page = window.location.pathname.split('/');
		if (_grid['GridOptions']) {
			showColumnHeaders = _grid['GridOptions']['ShowColumnHeaders'];
			if(page[page.length - 1] === 'viewer.do'){
				showColumnLines = _grid['GridOptions']['ShowVerticalLines'];
				showRowLines = _grid['GridOptions']['ShowHorizontalLines'];
			}
			else{
				showColumnLines = _grid['GridOptions']['ShowColumnLines'];
				showRowLines = _grid['GridOptions']['ShowRowLines'];
			}
			AllowGridCellMerge = _grid['GridOptions']['AllowGridCellMerge'];
			WordWrap = _grid['GridOptions']['WordWrap'];
			EnableBandedRows = _grid['GridOptions']['EnableBandedRows'];
			/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
			pagingDesc = _grid['GridOptions']['PagingDesc'];
			pagingEnabled = _grid['GridOptions']['PagingEnabled'];
			pagingSizeEnabled = _grid['GridOptions']['PagingSizeEnabled'];
			pagingSet = [_grid['GridOptions']['PagingSet'].Fir, _grid['GridOptions']['PagingSet'].Sec, _grid['GridOptions']['PagingSet'].Thi];
			pagingDefault = _grid['GridOptions']['PagingDefault'];
			
			showColumnHeaders = (showColumnHeaders === undefined ? true : showColumnHeaders);
			showColumnLines = (showColumnLines === undefined ? true : showColumnLines);
			showRowLines = (showRowLines === undefined ? true : showRowLines);
			AllowGridCellMerge = (AllowGridCellMerge === undefined ? gDashboard.reportType === 'StaticAnalysis' && self.Name === '그룹별 기술통계'? true :false : AllowGridCellMerge);
			WordWrap = (WordWrap === undefined ? false : WordWrap);
			EnableBandedRows = (EnableBandedRows === undefined ? false : EnableBandedRows);
			/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
			pagingDesc = (pagingDesc === undefined ? '' : pagingDesc);
			//pagingEnabled = (pagingEnabled === undefined ? (gDashboard.reportType === 'StaticAnalysis' && $("#dashboardTabPage1 #"+self.ComponentName).length > 0)? true : false : pagingEnabled);
			/* DOGFOOT syjin 로지스틱 단순 분석결과표, 로지스틱회귀계페이징 처리 제거  20200903 */
			pagingEnabled = ((pagingEnabled === undefined) ||(_grid.Name==="분석결과표") || (_grid.Name==="로지스틱회귀계수")? (gDashboard.reportType === 'StaticAnalysis' && $("#dashboardTabPage1 #"+self.ComponentName).length > 0)? true : false : pagingEnabled);
			pagingSizeEnabled = (pagingSizeEnabled === undefined ? false : pagingSizeEnabled);
			pagingSet = (pagingSet === undefined ? [10, 20, 50] : pagingSet);
			pagingDefault = (pagingDefault === undefined ? 20 : pagingDefault);
		}
		/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
		var gridOptions = {
				ShowColumnHeaders: showColumnHeaders, 
				AllowGridCellMerge: AllowGridCellMerge, 
				WordWrap: WordWrap, 
				EnableBandedRows: EnableBandedRows, 
				ShowColumnLines: showColumnLines, 
				ShowRowLines: showRowLines
			};
		var selectionMode = this.IO ? (this.IO['MasterFilterMode'] ? WISE.util.String.toLowerCase(this.IO['MasterFilterMode']) : 'none') : 'none';
		var selectionMode2 = selectionMode;
		
		if (selectionMode2 === 'none')
			selectionMode2 = 'Single';
		
		//20200715 ajkim 뷰어에서 작동하도록 주석처리 dogfoot
//		if(page[page.length - 1] === 'viewer.do' && $(window).width()>=720){
//			selectionMode2 = 'none'
//		}
		
		//2020.02.12 mksong 데이터 그리드 서브연결보고서 추가 dogfoot
		var timeout;
		var lastCell;
		
		/* DOGFOOT ktkang KERIS 상세현황 탭에 데이터 그리드 문구 추가  20200308 */
		var datasetName;
		
		
		$.each(gDashboard.dataSourceManager.datasetInformation, function(_i, _e) {
			if(_i == _grid.DataSource) {
				datasetName = _e.DATASET_NM;
			}
       	});
		
		if(datasetName == undefined) return;
		
		var pagerText = '전체 {2}건';
		if(datasetName.indexOf('상세현황') > -1) {
			pagerText = '(※상세현황은 100건 이하로 조회되며, 다운로드 시 전체 데이터가 내려집니다) 전체 {2}건';
		}

        /* DOGFOOT 통계 분석 부분 추가 shlim 20201111 */
		if(self.globalData && gDashboard.reportType === "StaticAnalysis" && (self.Name === '그룹별 기술통계' || self.Name === '기술통계' || self.Name === '도수분포표' || self.Name === '교차분석' || self.Name === '분석결과표')){
            
            var index = 0;
            for(var i = 0; i < gDashboard.itemGenerateManager.dxItemBasten.length; i++){
                if(gDashboard.itemGenerateManager.dxItemBasten[i].ComponentName == self.ComponentName){
                    index = i;
                    break;
                }
            }
            var columns = new Array();
            var k = 0;
            $.each(self.globalData[0], function(key, value) {
                var tempColumns = new Object();
                tempColumns.dataField = key;
                tempColumns.UniqueName = 'DataItem' + index.toString();
                tempColumns.uniqueName = 'DataItem' + index.toString();
                tempColumns.caption = key;
                columns.push(tempColumns);
                k++;
            });
            self.columns = columns;
        }
		
		 var temColumns = [];
			
		$.each(self.columns,function(_i,_d){ 
//					if(_d.dataField != 'SALEDATE'){
			if(typeof self.orderKey != 'undefined' && self.orderKey.length > 0) {
				$.each(self.orderKey, function(_ordi, _ordkey) {
					if(_d.CubeUniqueName == _ordkey.logicalColumnName || _d.uniqueName == _ordkey.uniqueName) {
						_d.sortOrder = 'none';
					}
				});
			} else if(gDashboard.datasetMaster.state.datasets[self.dataSourceId].DATASET_TYPE == "DataSetSQL") {
				var dimensionOrder = true;
				$.each(gDashboard.datasetMaster.state.fields[self.dataSourceId], function(_ii, _ee) {
					if(_ee.CAPTION == 'S_' + _d.caption) {
						_d.sortOrder = 'none';
					}
				});
			}
			temColumns.push(_d);
			if(_d.name !== _d.caption && typeof _d.summaryType === 'undefined')
				_d.dataField = _d.caption;
//			}

		});

        var columnsHeader = [],headerTemp=[],headerAddChk=[];
			if(Object.keys(self.headerList).length > 0){
				var UpperIndexArr=[];
				function UpperIndexCalc(_hdl){
					if(!(typeof _hdl.HEADER_UPPER != "undefined" && _hdl.HEADER_UPPER !="NonHeader")){
						if(UpperIndexArr.indexOf(_hdl.HEADER_CODE) == -1){
							UpperIndexArr.push(_hdl.HEADER_CODE);
						}
					}else{
						if(UpperIndexArr.indexOf(_hdl.HEADER_UPPER) > -1){
							if(UpperIndexArr.indexOf(_hdl.HEADER_CODE) == -1){
								UpperIndexArr.splice(UpperIndexArr.indexOf(_hdl.HEADER_UPPER),-1,_hdl.HEADER_CODE);
							}
						}else{
							if(typeof self.headerList[_hdl.HEADER_UPPER] != "undefined"){
								UpperIndexCalc(self.headerList[_hdl.HEADER_UPPER]);
								UpperIndexArr.splice(UpperIndexArr.indexOf(_hdl.HEADER_UPPER),-1,_hdl.HEADER_CODE);
							}else{
								if(UpperIndexArr.indexOf(_hdl.HEADER_CODE) == -1){
									UpperIndexArr.push(_hdl.HEADER_CODE);
								}
							}
						}
					}
				}
				$.each(self.headerList, function(_ihl,_hdl){
					headerTemp[_hdl.HEADER_CODE] = {"caption":_hdl.HEADER_NAME,"columns":[]};
					UpperIndexCalc(_hdl);
				})
				
				$.each(temColumns,function(_it,_tdl){
					$.each(self.headerList,function(_ihl,_hdl){
						if(typeof _tdl.HEADER_CODE != "undefined" && _tdl.HEADER_CODE === _hdl.HEADER_CODE
								&& _hdl.HEADER_YN === "Y"){
							headerTemp[_hdl.HEADER_CODE].columns.push(_tdl)
						}
					})
				});
				
				$.each(UpperIndexArr,function(_upi,_upa){
					$.each(self.headerList,function(_ihl,_hdl){
						if(_upa === _hdl.HEADER_CODE){
							if(_hdl.HEADER_YN === "Y" && typeof _hdl.HEADER_UPPER !="undefined"){
								if(headerTemp.HEADER_UPPER != "NonHeader"){
									if(headerTemp[_hdl.HEADER_UPPER] != undefined){
										/*dogfoot shlim 20210504*/
                                        var columnFront ="" , columnAfter = "" ;
										$.each(headerTemp[_hdl.HEADER_CODE].columns,function(_index,_hcol){	
										    if(columnFront == "")
										    columnFront = temColumns.indexOf(_hcol)
										    else						
											columnFront = columnFront > temColumns.indexOf(_hcol) ? temColumns.indexOf(_hcol) : columnFront;
										});
										
										$.each(headerTemp[_hdl.HEADER_UPPER].columns,function(_index2,_hcol2){
											if(columnAfter == "")
											columnAfter = temColumns.indexOf(_hcol2)
											else
											columnAfter = columnAfter > temColumns.indexOf(_hcol2) ? temColumns.indexOf(_hcol2) : columnAfter;          	
                                        });
										
                                        if(columnFront < columnAfter){
                                            headerTemp[_hdl.HEADER_UPPER].columns.unshift(headerTemp[_hdl.HEADER_CODE]);
                                        }else{
                                        	headerTemp[_hdl.HEADER_UPPER].columns.push(headerTemp[_hdl.HEADER_CODE]);
                                        }
										
										delete headerTemp[_hdl.HEADER_CODE];
									}
								}
							}
						}
					})
				})
				
				$.each(temColumns,function(_it,_tdl){
					if(typeof _tdl.HEADER_CODE != "undefined" && typeof _tdl.HEADER_CODE != "NonHeader" && self.headerList[_tdl.HEADER_CODE].HEADER_YN ==="Y"){
						function getHeaderInfo(_headerInfo){

							if(typeof headerTemp[_headerInfo] != "undefined"){
								if(self.headerList[_headerInfo].HEADER_YN ==="Y"){
								    columnsHeader.push(headerTemp[_headerInfo]);
								    headerAddChk[_headerInfo] = headerTemp[_headerInfo];
							        delete headerTemp[_headerInfo];		
								}
							}else{
								if(typeof headerAddChk[_headerInfo] == "undefined"){
									if(typeof self.headerList[_headerInfo].HEADER_UPPER !="undefined" && self.headerList[_headerInfo].HEADER_UPPER != "NonHeader"){
	                                    getHeaderInfo(self.headerList[_headerInfo].HEADER_UPPER);
									}
								}
							}
						}

						getHeaderInfo(_tdl.HEADER_CODE);
						
					}else{
						columnsHeader.push(_tdl);
					}
				})
				
				temColumns = columnsHeader;
			}
        
		

		var dxConfigs = {
			grouping: {
	            contextMenuEnabled: true
	        },
	        groupPanel: {
	            visible: false   // or "auto"
	        },
	      //columns: self.columns,
			columns: temColumns,	
			sorting: {mode: 'multiple'},
			selection: {mode: selectionMode2, showCheckBoxesMode: 'none'},
//			selection: {mode: selectionMode, allowSelectAll: false, showCheckBoxesMode: 'always'},
			allowColumnReordering:false,
			showColumnHeaders: gridOptions.ShowColumnHeaders,
			showColumnLines: gridOptions.ShowColumnLines,
			showRowLines: gridOptions.ShowRowLines,
			wordWrapEnabled: gridOptions.WordWrap,
			rowAlternationEnabled: gridOptions.EnableBandedRows,
			/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
			remoteOperations: {
	            sorting: true,
	            paging: true
	        },
			paging: {
   				pageSize: pagingDefault,
				enabled: pagingEnabled
   			},
   			pager: {
   				showPageSizeSelector: pagingSizeEnabled,
   				allowedPageSizes: pagingSet,
   				showInfo: pagingEnabled,
   				/* DOGFOOT ktkang 페이징 문구 수정  20201112 */
   				infoText: pagerText,
			/* DOGFOOT syjin 그리드 조회 페이징 처리 보이게 구현  20200727 */
				visible:pagingEnabled
   			},
			noDataText: gMessage.get('WISE.message.page.common.nodata'), //gMessage.get('WISE.message.page.common.nodata'),
			scrolling: {
				useNative: self.CUSTOMIZED.get('useNativeScrolling','Config')
			},
//			scrolling: {
//				mode: "infinite",
//				rowRenderingMode: "infinite",
//				useNative: self.CUSTOMIZED.get('useNativeScrolling','Config')
//			},
			"export" : {
		        enabled: false,
		        fileName: _grid['Name'] + '_' + new Date().valueOf()
		        /*,proxyUrl: WISE.Constants.context + '/download/grid/excel.do'*/
		    },
		    /* DOGFOOT syjin 보고서 레이아웃 데이터그리드 설정  20200814 */
			onCellPrepared: function(options) {
			/*dogfoot 고용정보원 그리드 특정 셀 row 색상 변경 추가 shlim 20210408*/
//				if(typeof options.row != 'undefined'){
//					if(typeof options.row.key["min_LVL"] != 'undefined'){
//						switch(options.row.key["min_LVL"]){
//							case 0:
//
//							break;
//							case 1:
//								$(options.cellElement).css("background",'#eeeeee');
//							break;
//							case 2:
//								$(options.cellElement).css("background",'#555555');
//							break;
//							case 3:
//								$(options.cellElement).css("background",'#999999');
//							break;
//						}
//					}
//				}
				
				/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  202009021 */
				if(DevExpress.VERSION == '20.1.6') {
					if(userJsonObject.gridDataPaging === 'Y'){
						if(typeof options.component._options._optionManager._options != 'undefined' && options.component._options._optionManager._options.paging.enabled == true && self.pagingSplit) {
							/*20210203 Dev20 버전 페이징 오류 수정  shlim dogfoot */
							var pagingStart = typeof options.component._options._optionManager._options.paging.pageIndex === "undefined" ? 0 : options.component._options._optionManager._options.paging.pageIndex
							var pagingSize = typeof options.component._options._optionManager._options.paging.pageSize === "undefined" ? 20 : options.component._options._optionManager._options.paging.pageSize
//							var pagingStart = ($('.dx-page.dx-selection').text() * 1) - 1;
//							var pagingSize = $('.dx-page-size.dx-selection').text() * 1;
							if(pagingStart != 0) {
								pagingStart = pagingStart * pagingSize;
							}
							/*20210323 페이징 기본값이 바뀌었을 때, pagingStart 0으로 초기화   syjin dogfoot */
							if(self.Grid.GridOptions.pagingDefaultChanged){
								pagingStart = 0;
								self.Grid.GridOptions.pagingDefaultChanged = false;
							}
							var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
							/* DOGFOOT syjin 그리드 기술통계 클릭했을 때 해당 페이지 데이터만 가져오기 개선  20210226 */
							if(gDashboard.reportType != "StaticAnalysis"){
								SQLikeUtil.doSqlLikePaging(self, pagingSize, pagingStart);
							}
							self.pagingSplit = false;
						}
					}
				} else {
					if(userJsonObject.gridDataPaging === 'Y' && gDashboard.reportType != 'StaticAnalysis'){
						if(typeof options.component._options != 'undefined' && options.component._options.paging.enabled == true && self.pagingSplit) {
							/*20210122 페이징 도큐먼트 선택 중복 오류 수정  shlim dogfoot */
							var pagingStart = typeof options.component._options.paging.pageIndex === "undefined" ? 0 : options.component._options.paging.pageIndex
							var pagingSize = typeof options.component._options.paging.pageSize === "undefined" ? 20 : options.component._options.paging.pageSize
//							var pagingStart = ($("#"+self.itemid).find('.dx-page.dx-selection').text() * 1) - 1;
//							var pagingSize = $("#"+self.itemid).find('.dx-page-size.dx-selection').text() * 1;
							if(pagingStart != 0) {
								pagingStart = pagingStart * pagingSize;
							}
							var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
							/* DOGFOOT syjin 그리드 기술통계 클릭했을 때 해당 페이지 데이터만 가져오기 개선  20210226 */
							if(gDashboard.reportType != "StaticAnalysis"){
								SQLikeUtil.doSqlLikePaging(self, pagingSize, pagingStart);
							}
							self.pagingSplit = false;
						}
					}
				}
			},
			onColumnsChanging: function(e){
				//20200731 ajkim 그리드 바 측정값 라벨 추가, 열 너비 바뀔 때 이동 dogfoot
				$.each($(".gridBar"), function(_i, _el){
					var $bullet = $(_el)
					var $label = $($('.gridBarLabel')[_i]);
					$label.css("top", $bullet.position().top + $bullet.height()/2 - $label.height()/2);
	                $label.css("left", $bullet.position().left + $bullet.width() - $label.width());
	                if($label.width() > $bullet.width())
	                	$label.css('display', 'none');
	                else
	                	$label.css('display', 'inline-block');
				});
	        },
		    onSelectionChanged: function(_e) {
	        	if (self.IO.MasterFilterMode !== 'none' /*&& self.preventTrackingEvent === false*/) {
	        		switch(self.IO.MasterFilterMode){
	        			case 'Single':
	        				self.trackingData = [];
	        				var obj = new Object();
	    		           	$.each(_e.selectedRowsData, function(_i, _el) {
	    		           		var d = {};
	    		           		$.each(_el, function(_k, _eld) {
	    		           			var checker = true;
	    		           			$.each(self.measures, function(_ii, _m) {
	    		           				if (_k.indexOf('DELTA_CELL_COLOR') > -1 || _k === _m.captionBySummaryType) {
	    		           					checker = false;
	    		           					return false;
	    		           				}
	    		           			});
	    		           			if (checker && !!_eld) {
	    		           				var name = _k
	    		           				$.each(self.dimensions, function(i, dim){
	    		           					if(dim.caption === name){
	    		           						name = dim.name;
	    		           						return false;
	    		           					}
	    		           				})
	    		           				d[name] = _eld;
	    		           			}
	    		           			obj[_k] = _eld;
	    		           		});
	    		           		self.storekey = obj;
	    		           		self.trackingData.push(d);
	    		           	});

	    		           	if(self.trackingData.length > 0){
	    		           		
	    		           		/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
	    						if(WISE.Constants.editmode === "viewer"){
	    							gDashboard.itemGenerateManager.focusedItem = self;
	    						}
	    		           		/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
	    		           		gDashboard.filterData(self.itemid, self.trackingData);
	    		           		if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
	    							gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
	    						}
	    						/*필터 프로그레스바 오류 수정*/
	    						if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
	    							gProgressbar.setStopngoProgress(true);
	    							gProgressbar.hide();		
	    							gDashboard.updateReportLog();
	    						}
	    						
	    		           	}
	    		           	
	    		           	self.preventTrackingEvent === false;
	        				break;
	        			case 'Multiple':
	        				var imgSrc, overImgSrc, clearTrackingImg = $("#" + self.trackingClearId).find('img')[0];
	        				self.trackingData = [];
	    		        	if (_e.selectedRowsData.length === 0) {
	    		        		imgSrc = overImgSrc = 'cont_box_icon_filter_disable';
	    		        		self.trackingData = [];
	    		        	}
	    		        	else {
	    		        		imgSrc = 'cont_box_icon_filter';
	    		        		overImgSrc = 'cont_box_icon_filter_';
	    		           	}
	    		           			
	    		           	$(clearTrackingImg)
	    		           		.attr('src', WISE.Constants.context + '/images/' + imgSrc + '.png')
	    		           		.on('mouseover', function() {
	    		           			$(this).attr('src', WISE.Constants.context + '/images/' + overImgSrc + '.png');
	    		           		})
	    		           		.on('mouseout', function() {
	    		           			$(this).attr('src', WISE.Constants.context + '/images/' + imgSrc + '.png');
	    		           		});
	    		           	
	    		           	$.each(_e.selectedRowsData, function(_i, _el) {
	    		           		var temparr = {};
	    		           		$.each(_el,function(_n,_v){
	    		           			$.each(self.dimensions, function(_k, _d) {
	    		           				if(_d.caption === _n){
	    		           					temparr[_d.name] = _v;
	    		           				}
	    		           			});
	    		           		});
	    		           		self.trackingData.push(temparr);
	    		           	});
	    		           	/*dogfoot 뷰어 마스터필터 선택 시 포커스 아이템설정  shlim 20201118*/
    						if(WISE.Constants.editmode === "viewer"){
    							gDashboard.itemGenerateManager.focusedItem = self;
    						}
	    		           	/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
	    		           	gDashboard.filterData(self.itemid, self.trackingData);
	    		           	if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
    							gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
    						}
    						/*필터 프로그레스바 오류 수정*/
    						if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
    							gProgressbar.setStopngoProgress(true);
    							gProgressbar.hide();		
    							gDashboard.updateReportLog();
    						}
	    		           	self.preventTrackingEvent === false;
	    		           	break;
	        		}
		        	
	        	}
	        	
//	        	self.preventTrackingEvent === false; // 반드시 상위로직 보다 하위에 위치시켜야함 ????
	        },
	        //클래스를 줘도 클릭된 상태를 유지 못함. 즉, 아이템 클릭 시 row가 회색으로 변하는데 다른 아이템을 클릭하면 기존 Row의 clicked class는 풀림
	        onRowClick: function(_e) {
	        	self.preventTrackingEvent = false;
	        	_e.rowElement.hasClass("clicked") ? _e.rowElement.removeClass("clicked") : _e.rowElement.addClass("clicked");
	        },
	        onContentReady: function(_e) {
	        	/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
	        	if(self.onContentCnt == 1) {
	        		self.pagingSplit = true;
	        		self.onContentCnt = 0;
	        	} else {
	        		self.onContentCnt++;
	        	}
	        	$('#'+self.itemid).css('opacity','0');
	        	$('#'+self.itemid).css('display','block');
	        	/* DOGFOOT hsshim 2020-02-06 마스터 필터 렌더링 표시 추가 */
				//gProgressbar.finishListening();
	    		/**
	    		 * 만약 필터 모드가 single 인 상황에서 데이터 조회하자 마자 필터를 걸고 싶은경우. 주석 해제
	    		 */  
//	        	if(selectionMode =='Single'){
//	        		if(typeof self.storekey != 'undefined')
//        			{
//	        				_e.component.selectRows(self.storekey);
//        			}
//	        		else{
//	        			setTimeout(function() {
//	        				_e.component.selectRowsByIndexes(0);
//	        			}, 10);
//	        		}
//	        	}
				/* DOGFOOT ktkang 데이터그리드에서 데이터 없는 부분에 쓸데없는 테두리가 생성되는 부분 삭제  20200116 */
	        	$('.dx-row.dx-freespace-row.dx-column-lines').remove();
				/* DOGFOOT ktkang KERIS 데이터 그리드 헤더 가운데 정렬  20200205 */
//	        	if($('.dx-datagrid-action.dx-cell-focus-disabled').attr('role') == 'columnheader') {
//	        		$('.dx-datagrid-action.dx-cell-focus-disabled').css('text-align', 'center');
//	        	}
	        	/* DOGFOOT shlim KERIS 데이터 그리드 헤더 가운데 정렬  20200715 */
	        	/* DOGFOOT AJKIM 데이터 그리드 헤더 자동 정렬 옵션 추가  20200715 */
	        	if($('.dx-row.dx-column-lines.dx-header-row').attr('role') == 'row') {
	        		if(userJsonObject.gridAutoAlign === 'Y'){
	        			$.each($('#' + self.itemid + ' .dx-row.dx-column-lines.dx-header-row').find('td'), function(i, ele){
	        				if(typeof self.columns[i] != 'undefined'){
	        				    $(ele).css('text-align', self.columns[i].alignment);	
	        				}
			        	});
	        		}
	        		else{
		        		$('.dx-row.dx-column-lines.dx-header-row').find('td').css('text-align', 'center');
	        		}
	        	}
	        	/*20201111 AJKIM 통계 모두 왼쪽 정렬 DOGFOOT*/
				if (gridOptions.AllowGridCellMerge) {
					var ind = 1;
					var dimensionLength = gDashboard.reportType === 'StaticAnalysis'? self.columns.length - (self.columns.length -self.dimensions.length) : self.dimensions.length;
					for (ind; ind <= dimensionLength; ind++) {
//	        			var ind = 1;
						var firstInstance = null;
						_e.element.find('tr.dx-row.dx-data-row.dx-row-lines.dx-column-lines').each(function() {
//							var childrenCount = $(this).children('td').length - self.measures.length;
							var childrenCount = $(this).children('td').length - (self.columns.length -self.dimensions.length);
							var reduceCount = dimensionLength - childrenCount;
							var childIndex = ind - reduceCount;
							
							var dimensionTd = $(this).find('td:nth-child(' + childIndex + ')');
								
							if (ind > 1) {
								dimensionTd.addClass('dx-grid-hack-border-left');
							}
									
							if (firstInstance == null) {
								firstInstance = dimensionTd;
								firstInstance.attr('rowspan', 1);
							} else {
								var secondChild = true;
								if(childIndex > 1){
									secondChild = ($(dimensionTd).parent().find('td:nth-child(' + (childIndex-1) + ')') == $(firstInstance).parent().find('td:nth-child(' + (childIndex-1) + ')'));
								}
								if (dimensionTd.text() == firstInstance.text()&&secondChild) {
									
									dimensionTd.remove();
									firstInstance.attr('rowspan', parseInt(firstInstance.attr('rowspan')) + 1);
									
									if (!$(this).hasClass('dx-grid-row-hack')) {
										$(this).addClass('dx-grid-row-hack');
									}
								} else {
									firstInstance = dimensionTd;
									firstInstance.attr('rowspan', 1);
								}
							}
						}); // end of $.each
					} // end of loop
				} // end of gridOptions.AllowGridCellMerge
			/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
				if(gDashboard.reportType == 'DashAny' && gDashboard.downloadFull && self.contentReady) {
					gDashboard.downloadFull = false;
					gDashboard.downloadReady = true;
					self.contentReady = false;
					gProgressbar.hide();
				} else if(gDashboard.reportType == 'DashAny' && gDashboard.downloadFull) {
//					if(WISE.Constants.editmode == 'viewer') {
//						gDashboard.downloadFull = false;
//						gDashboard.downloadReady = true;
//						self.contentReady = false;
//						gProgressbar.hide();
//					} else {
						self.contentReady = true;
//					}
				}
				
				
				
				$(".dx-datagrid-text-content").children("div").css("width", "100%");
				/* DOGFOOT syjin 보고서 레이아웃 데이터 그리드 설정  20200814 */
				var setGrid = {
					header : function(layoutObject){
						$(".dx-datagrid-headers").css({
							"font-family": layoutObject.GRID_HEADER_FONT_SETTING,
				            "font-size": layoutObject.GRID_HEADER_FONTSIZE_SETTING+"px",
							"color" : layoutObject.GRID_HEADER_COLOR_SETTING,
						});												
//						$("#"+self.itemid).find(".dx-row.dx-column-lines.dx-header-row").css("height" , layoutObject.GRID_HEADER_HEIGHT_SETTING+"px");
						/* dogfoot 그리드 헤더 추가 기능 shlim 20210319 */
						$("#"+self.itemid).find(".dx-row.dx-column-lines.dx-header-row").css({
//							"height" : layoutObject.GRID_HEADER_HEIGHT_SETTING+"px",
							"border-bottom" : "1px solid #e7e7e7",
							"border-top" : "1px solid #e7e7e7"
						});
						/* goyong ktkang 고용정보원 디자인 수정  20210525 */
						$(".dx-datagrid-headers .dx-datagrid-table").css({
							"background-image" : "linear-gradient(to bottom, #f5f5f5, #f5f5f5)",
		 					"border-bottom" : "1px solid " + layoutObject.GRID_HEADER_BOCOLORB_SETTING,
							"border-top" : "1px solid " + layoutObject.GRID_HEADER_BOCOLORT_SETTING
						});		
						$("#"+self.itemid).find(".dx-row.dx-column-lines.dx-header-row").find('td').css('vertical-align','middle');
					},
					data : function(layoutObject){
						$(".dx-datagrid-rowsview").css({	//데이터 영역
							"font-family" : layoutObject.GRID_DATA_FONT_SETTING,
							"font-size" : layoutObject.GRID_DATA_FONTSIZE_SETTING+"px",
							"color" : layoutObject.GRID_DATA_COLOR_SETTING,
							"background-color" : layoutObject.GRID_DATA_BGCOLOR_SETTING,
							"border" : "solid 1px #ddd"
						});
						$(".dx-datagrid-rowsview td").css("height", layoutObject.GRID_DATA_HEIGHT_SETTING+"px");
						/* DOGFOOT shlim 보고서 레이아웃 그리드 가운데 정렬 설정 20200820 */
						//$("#"+self.itemid).find('td').css('vertical-align','middle');
					}
				}
				
//				$('.dx-scrollable-scrollbar.dx-widget.dx-scrollbar-horizontal.dx-scrollbar-hoverable').css('bottom', '-12px');
				
//				$('.dx-datagrid-rowsview .dx-row.dx-row-lines:first-child').css('line-height', '6px');
//				if(WISE.Constants.editmode != 'viewer'){
//				    gDashboard.goldenLayoutManager.render_config_layout();	
//				}else{
//					gDashboard.goldenLayoutManager[WISE.Constants.pid].render_config_layout();
//				}
//				
				/* dogfoot shlim 그리드 화면 표시 완료 될때 프로그레스바 사라지도록 수정 
					대용량 데이터 조회시 이전 데이터가 화면에 보여지는 오류 수정
				20210201*/
				/*dogfoot 데이터 그리드 기본 세팅 <-> 데이터 조회 후 로딩 동기화  shlim 20210329 */
				if(self.loadingChk==0){
					self.loadingChk++;
				}else{
					if(self.ComponentName && gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
						gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
					}
					/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
					if(WISE.Constants.editmode == 'viewer' && gDashboard.tabQuery){
						if(gDashboard.itemGenerateManager.selectedItemList.length <= gDashboard.itemGenerateManager.viewedItemList.length){
							$('.progress_box').css('display', 'none');
						}
					}
					else if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
						gProgressbar.setStopngoProgress(true);
						gProgressbar.hide();
						/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
//						console.log("-----------------------------------------------------------------------");
//						window.endBeforQueryTime = window.performance.now();
//						console.log("아이템 생성 ~ 로딩바 사라질때까지 걸린시간 : " + (window.endBeforQueryTime - window.startBeforQueryTime)+'ms');
//						console.log("총 소요시간 (전체) : " + (window.endBeforQueryTime - window.startGenTime)+'ms');
//						console.log("-----------------------------------------------------------------------");
						gDashboard.updateReportLog();
					}
					
					$.each(self.dxItem.getVisibleRows(), function(_i, _row) {
						var sum = false;
						$.each(_row.cells, function(_ii, _cell) {
//							var text = _cell.text.replaceAll(/" "/gi, '');
							/*dogfoot 데이터 그리드 오류 수정 shlim 20210721*/
							var text = _cell.text.replace(/ /gi, '');
							if(text == '합계' || text == '총계') {
								sum = true;
							}
							
							if(sum) {
								_cell.cellElement.css('background-color', '#fffad0');
							}
						});
					});
					$('#'+self.itemid).css('opacity','1');
				    $('#'+self.itemid).css('display','block');	
				    
				}
				
                
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _d) {
					if(_d.type != 'IMAGE'){
						if(_d.dimensions.length == 0 && _d.measures.length == 0){
							gProgressbar.hide();
						}	
					}
				});
				if(WISE.Constants.editmode === 'viewer'){
					/* dogfoot 보고서 레아이웃 오류 수정 shlim 20210319 */
					var reportLayoutCheck = typeof gDashboard.layoutConfig[WISE.Constants.pid] != 'undefined' && gDashboard.layoutConfig[WISE.Constants.pid] != "" && typeof gDashboard.layoutConfig[WISE.Constants.pid] != "object" ?  true: false;
					if(reportLayoutCheck){
						//보고서 불러오기 할 때
						if(typeof gDashboard.layoutConfig[WISE.Constants.pid]!='undefined' && gDashboard.layoutConfig[WISE.Constants.pid] !=""
							&& gDashboard.layoutConfig[WISE.Constants.pid] !="\"\"" && Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0){
							setGrid.header(gDashboard.layoutConfig[WISE.Constants.pid]);
							setGrid.data(gDashboard.layoutConfig[WISE.Constants.pid]);					
						}
					}else{
						//보고서 작성할 때
						if(typeof userJsonObject.layoutConfig != 'undefined' && userJsonObject.layoutConfig != ""){
							setGrid.header(userJsonObject.layoutConfig);
							setGrid.data(userJsonObject.layoutConfig);
						}
					}
				}else{
					var reportLayoutCheck = typeof gDashboard.layoutConfig != 'undefined' && gDashboard.layoutConfig != "" && Object.keys(gDashboard.layoutConfig).length > 0 ?  true: false;
					if(reportLayoutCheck){
						//보고서 불러오기 할 때
						if(typeof gDashboard.layoutConfig != 'undefined' && gDashboard.layoutConfig != ""){
							setGrid.header(gDashboard.layoutConfig);
							setGrid.data(gDashboard.layoutConfig);					
						}
					}else{
						//보고서 작성할 때
						if(typeof userJsonObject.layoutConfig != 'undefined' && userJsonObject.layoutConfig != ""){
							setGrid.header(userJsonObject.layoutConfig);
							setGrid.data(userJsonObject.layoutConfig);
						}
					}
				}
				
				$('.dx-datagrid .dx-row > td').css('font-size', '12px');
				$('.dx-datagrid .dx-row > td').css('padding' , '0px 10px');
				$('.dx-datagrid .dx-row > td').css('height' , 'auto');
				
				/*if(gDashboard.structure.layoutConfig!=undefined){
					$(".dx-datagrid-headers").css("background-image","url('')");
					$(".dx-datagrid-table").css("background-image","url('')");
	
					$(".dx-datagrid-headers").css("background-color", gDashboard.structure.layoutConfig.GRID_HEADER_BGCOLOR_SETTING);
					if(gDashboard.structure.layoutConfig.GRID_HEADER_BGCOLOR_SETTING=="#000000"){
						$(".dx-datagrid-headers").css("background-color","");
					}				
				}*/
				
				var ua = window.navigator.userAgent;
                // 2021-08-06 jhseo 다 그리고 block 처리
				if(self.itemid.indexOf("gridDashboardItem") === -1)
					$("#" + self.itemid).children().css('display','block');
				else
					$("#" + self.itemid).children().css('display','flex');
			    if(self.repaintCount < gDashboard.itemGenerateManager.viewedItemList.length) {
			    	self.repaintCount++;
			    	setTimeout(function () {
			    		self.dxItem.repaint();
			        }, 50);
			    }
			    $("#" + self.itemid).find(".dx-page-sizes").css("display","none");
			    var scrollXY = $('#'+self.itemid).find('.dx-scrollable-wrapper').height() - $('#'+self.itemid).find('.dx-datagrid-rowsview').find(".dx-datagrid-table").height();
                $('#'+self.itemid).find(".dx-scrollable-scrollbar").css("bottom",(scrollXY)+ "px"); 
			    
	        },
	        onCellClick:function(_e){
	        	/* DOGFOOT ktkang 데이터 그리드 뷰어에서 불러온 후 클릭 오류 수정  20200731 */ 
	        	if (typeof self.IO != 'undefined' && self.IO.IsDrillDownEnabled) {
					var cellKey = _e.column.dataField;
					var cellValue = _e.value;
					var foundCurrentCell = false;
					var checkRightNeighbor = false;
					var isDrillDownValid = false;
					var nextDimKey = undefined;
					$.each(self.rowOrder, function(i, col) {
						// if current cell's nearest right neighbor is a measure, abort drill-down process
						if (checkRightNeighbor && col.value !== 'number') {
							checkRightNeighbor = false;
							isDrillDownValid = true;
							nextDimKey = col.key;
						} 
						// found current cell's position
						else if (cellKey === col.key) {
							foundCurrentCell = true;
							checkRightNeighbor = true;
						}
					});
					// if current cell's right most neighbor is a dimension, then drill-down is valid
					if (isDrillDownValid) {
						self.drillDown(cellKey, cellValue, nextDimKey);
					}
				} else {
		        	if (!timeout)
		        		/* DOGFOOT 20201021 ajkim setTimeout 시간 변경 300 > 5*/{
				        timeout = setTimeout(function () {
				            lastCell = _e.cell;
				            timeout = null;
				        }, 5);
				    }else{
						var gridItemDim = self.meta['DataItems']['Dimension'];
						var linkReportMeta;
						if(WISE.Constants.editmode == 'viewer' && gDashboard.reportType == 'AdHoc'){
							linkReportMeta = gDashboard.structure.ReportMasterInfo.subLinkReport; 
						}else{
							linkReportMeta = gDashboard.structure.subLinkReport;
						}
						
						var linkGridMatch = {};
						var linkJsonMatch = {};
						
						var target_id;
						var linkitemid;
						var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
						
						var gridTextDim = _e.data;
						var selectedValue = {};
						
						$.each(linkReportMeta,function(_i,_ee){
							var linkParam = _ee.linkJson.LINK_XML_PARAM.ARG_DATA;
							var linkDataParam = _ee.linkJson2.LINK_XML_DATA.ARG_DATA;
							
							if((_ee.target_item +'_' + _ee.arg_id +'_item' == self.itemid || _ee.target_item + '_item' == self.itemid) && _ee.link_type == 'LD'){
								linkitemid = self.itemid + "_link";
	
								target_id = _ee.target_id;
								
								linkGridMatch = {};
								linkJsonMatch = {};
								
								$.each(linkDataParam, function(_j,_dataParam){
									$.each(paramListValue, function(_k,_eee){
										if(!Array.isArray(gridItemDim)) {
											if(_eee.paramName == _dataParam.PK_COL_NM) {
												selectedValue[_eee.paramName] = gridTextDim[_dataParam.FK_COL_NM];
												linkGridMatch[_dataParam.FK_COL_NM] = gridTextDim[_dataParam.FK_COL_NM];
											}
										} else {
											if(_eee.paramName == _dataParam.PK_COL_NM) {
												selectedValue[_eee.paramName] = gridTextDim[_dataParam.FK_COL_NM];
												linkGridMatch[_dataParam.FK_COL_NM] = gridTextDim[_dataParam.FK_COL_NM];
											}
										}
									});
								});
								
								if(typeof _ee.linkJson != 'undefined' && _ee.linkJson != "" && _ee.linkJson.LINK_XML_PARAM != undefined) {
									$.each(_ee.linkJson.LINK_XML_PARAM.ARG_DATA,function(_j,_linkJson){
										if(!Array.isArray(_ee.linkJson.LINK_XML_PARAM.ARG_DATA)) {
											linkJsonMatch[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.PK_COL_NM] = paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value;
										} else if(_linkJson.PK_COL_NM) {
											linkJsonMatch[_linkJson.PK_COL_NM] = paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value;
										}
									});
								}
	
								if(typeof _ee.linkJson2 != 'undefined' && _ee.linkJson2 != "") {
									$.each(_ee.linkJson2.LINK_XML_DATA.ARG_DATA,function(_j,_linkJson){
										if(!Array.isArray(_ee.linkJson2.LINK_XML_DATA.ARG_DATA)) {
											linkJsonMatch[_ee.linkJson2.LINK_XML_DATA.ARG_DATA.PK_COL_NM] = linkGridMatch[_ee.linkJson2.LINK_XML_DATA.ARG_DATA.FK_COL_NM] == '_EMPTY_VALUE_' ? '[All]' : selectedValue[_ee.linkJson2.LINK_XML_DATA.ARG_DATA.PK_COL_NM];
										} else if(_linkJson.PK_COL_NM) {
											linkJsonMatch[_linkJson.PK_COL_NM] = linkGridMatch[_linkJson.FK_COL_NM] == '_EMPTY_VALUE_' ? '[All]' : selectedValue[_linkJson.PK_COL_NM];
										}
									});
								}
	//							}
	
								var locationStr = "";
								$.each(linkJsonMatch,function(_key,_val){
									// 2020.02.13 mksong 연결보고서 VALUE값 암호화 DOGFOOT
									locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(encodeURIComponent(_val))+'&';
								});
								locationStr = (locationStr.substring(0,locationStr.length-1));
								if(locationStr.length > 1) {
									locationStr = "&" + locationStr;
								}
								var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_ee.target_id+'/viewer.do?USER='+userJsonObject.userId+'&assign_name=bWVpcw==' + locationStr;
								window.open(urlString);
							}
						});
					}
			    }
	        }
//	        onFileSaving:function(_e){
//	        	var blob = new Blob([_e.data], {type: "text/plain;charset=utf-8"});
//				saveAs(blob, _e.fileName+".cell");
//	        	_e.cancel=true;
//	        }
		};
		
		// extend custom-configurations
		var Configurations = _.clone(this.CUSTOMIZED.get('dx'));
		var CustomConfigs = $.extend({}, Configurations);
		$.extend(CustomConfigs, dxConfigs);
		dxConfigs = CustomConfigs;
		dxConfigs.columnAutoWidth = true;
		if (_grid['GridOptions'] && _grid['GridOptions']['ColumnWidthMode'] === 'AutoFitToContents') {
			dxConfigs.allowColumnResizing =false;
			dxConfigs.columnAutoWidth = true;
		} else if(_grid['GridOptions'] && _grid['GridOptions']['ColumnWidthMode'] === 'Manual'){
			dxConfigs.allowColumnResizing = true;
			dxConfigs.columnAutoWidth = false;
		} 
		
//		if (self.IO && self.IO['MasterFilterMode']) {
//			dxConfigs.pager = undefined;
//			dxConfigs.paging = {enabled: false};
//		}
//		else {
//			// 합계
//			var summaryEnabled = this.CUSTOMIZED.get('summaryEnabled');
//			if (summaryEnabled) {
//				dxConfigs.groupPanel = {
//					visible: true,
//					emptyPanelText: gMessage.get('WISE.message.page.widget.grid.groupPanel.emptyText')
//				};
//				
//				dxConfigs.summary = {
//					totalItems: []	
//				};
//				_.each(this.measures, function(_m) {
//					if (!_m.displayMode) {
//						dxConfigs.summary.totalItems.push({
//							column: _m.nameBySummaryType,
//							summaryType: _m.summaryType
//						});
//					}
//				});
//			}
//		}

		return dxConfigs;
	};
	this.customSelectChanged = function (){
		this.dxItem.selectRowsByIndexes(0);
	}

	/** @Override */
	this.clearTrackingConditions = function() {
		if (self.IO && self.IO.MasterFilterMode) {
			if(gDashboard.reportType != 'AdHoc' || !(gDashboard.structure.Layout == 'G' && WISE.Constants.editmode==='viewer')){
				if (self.dxItem) self.dxItem.clearSelection();
				self.trackingData = [];
				self.selectedPoint = undefined;	
			}
		}
	};
	
	this.setGrid = function(){
		this.fieldManager.init();
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		
		this.Grid = {};
		this.Grid['ComponentName'] = this.ComponentName;
		this.Grid['DataItems'] = this.fieldManager.DataItems;
		this.Grid['DataSource'] = this.dataSourceId;
		this.Grid['GridColumns'] = this.fieldManager.GridColumns
		this.Grid['ShowCaption'] = true;
		/* DOGFOOT ktkang KERIS 그리드 기본옵션으로 Merge 풀기  20200305 */
		/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
		this.Grid['GridOptions'] = {
				ColumnWidthMode : "AutoFitToContents", 
				EnableBandedRows : false, 
				AllowGridCellMerge : gDashboard.reportType === 'StaticAnalysis' && self.Name === '그룹별 기술통계'? true : false, 
				ShowColumnHeaders: true, 
				ShowColumnLines: true, 
				ShowRowLines: true, 
				WordWrap : false,
				PagingDesc : '',
				PagingSet : {
					Fir: '10',
					Sec: '20',
					Thi: '50'	
				},
				PagingDefault : '20'
			};
		/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
		if(userJsonObject.gridDataPaging === 'Y'){
			this.Grid['GridOptions'].PagingEnabled = true;
			this.Grid['GridOptions'].PagingSizeEnabled = true;
		} else {
			this.Grid['GridOptions'].PagingEnabled = (gDashboard.reportType === 'StaticAnalysis' && $("#dashboardTabPage1 #"+self.ComponentName).length > 0)? true : false;
			this.Grid['GridOptions'].PagingSizeEnabled = false;
		}
		
		this.Grid['HiddenMeasures'] = this.fieldManager.HiddenMeasures;
		this.Grid['Name'] = this.Name;
		this.Grid['SparklineArgument'] = this.fieldManager.SparklineArgument;
		this.Grid['InteractivityOptions'] = {
			MasterFilterMode: 'Off',
			IgnoreMasterFilters: false,
			IsDrillDownEnabled: false
		};
		this.Grid.Palette = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
		
		/*dogfoot 그리드 헤더 추가 기능 shlim 20210317*/
		if (typeof this.Grid["HeaderList"] != "undefined") {
			self.headerList = this.Grid["HeaderList"]
		}
		
		if (!(this.Grid.IsMasterFilterCrossDataSource)) {
			this.Grid['IsMasterFilterCrossDataSource'] = false;
		}
		
		
		this.Grid['FilterString'] = [];
	};
	
	this.setDataItems = function(){
		gDashboard.itemGenerateManager.getherFields(this.fieldManager, self.type);
		
		this.meta['DataItems'] = this.Grid['DataItems'] = this.fieldManager.DataItems;
		this.meta['GridColumns'] = this.Grid['GridColumns'] = this.fieldManager.GridColumns;
		this.meta['HiddenMeasures'] = this.fieldManager.HiddenMeasures;
		this.meta['SparklineArgument'] = this.fieldManager.SparklineArgument;
		if (!(this.Grid['DataSource'])) {
			this.meta['DataSource'] = this.Grid['DataSource'] = this.dataSourceId;
		}else if(this.Grid['DataSource'] != this.dataSourceId){
			this.meta['DataSource'] = this.Grid['DataSource'] = this.dataSourceId;
		}
		if(this.meta['GridOptions'] == ""){
			this.Grid['GridOptions'] = {
				ColumnWidthMode : "AutoFitToContents", 
				EnableBandedRows : false, 
				AllowGridCellMerge : gDashboard.reportType === 'StaticAnalysis' && self.Name === '그룹별 기술통계'? true :false, 
				ShowColumnHeaders: true, 
				ShowColumnLines: true, 
				ShowRowLines: true, 
				/* DOGFOOT ktkang 그리드 페이징 설정 기능 구현  20200903 */
				WordWrap : false,
				PagingDesc : '',
				PagingSet : {
					Fir: '10',
					Sec: '20',
					Thi: '50'	
				},
				PagingDefault : '20'
			};
			/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
			if(userJsonObject.gridDataPaging === 'Y'){
				this.Grid['GridOptions'].PagingEnabled = true;
				this.Grid['GridOptions'].PagingSizeEnabled = true;
			} else {
				this.Grid['GridOptions'].PagingEnabled = (gDashboard.reportType === 'StaticAnalysis' && $("#dashboardTabPage1 #"+self.ComponentName).length > 0)? true : false;
				this.Grid['GridOptions'].PagingSizeEnabled = false;
			}
		}
		else{
			var gridOption = self.meta['GridOptions'];
			
			self.Grid['GridOptions']['ColumnWidthMode']  = (gridOption['ColumnWidthMode'] === undefined ? "AutoFitToContents" : gridOption['ColumnWidthMode']);
			self.Grid['GridOptions']['EnableBandedRows'] = (gridOption['EnableBandedRows'] === undefined ? false : gridOption['EnableBandedRows']);
			self.Grid['GridOptions']['AllowGridCellMerge'] = (gridOption['AllowGridCellMerge'] === undefined ? gDashboard.reportType === 'StaticAnalysis' && self.Name === '그룹별 기술통계'? true : false :  gridOption['AllowGridCellMerge']);
			self.Grid['GridOptions']['ShowColumnHeaders'] = (gridOption['ShowColumnHeaders'] === undefined ? true : gridOption['ShowColumnHeaders']);
			self.Grid['GridOptions']['ShowColumnLines'] = ( gridOption['ShowVerticalLines'] === undefined ? true :  gridOption['ShowVerticalLines']);
			self.Grid['GridOptions']['ShowRowLines'] = (gridOption['ShowHorizontalLines'] === undefined ? true : gridOption['ShowHorizontalLines']);
			self.Grid['GridOptions']['WordWrap'] = (gridOption['WordWrap'] === undefined ? false : gridOption['WordWrap']);
			/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
			self.Grid['GridOptions']['PagingDesc'] = typeof gridOption['PagingDesc'] != 'undefined' ? gridOption['PagingDesc'] : "";
			if(userJsonObject.gridDataPaging === 'Y'){
				self.Grid['GridOptions']['PagingEnabled'] = (gridOption['PagingEnabled'] === undefined ? true : gridOption['PagingEnabled']);
				self.Grid['GridOptions']['PagingSizeEnabled'] = (gridOption['PagingSizeEnabled'] === undefined ? true : gridOption['PagingSizeEnabled']);
			} else {
				self.Grid['GridOptions']['PagingEnabled'] = (gridOption['PagingEnabled'] === undefined ? (gDashboard.reportType === 'StaticAnalysis' && $("#dashboardTabPage1 #"+self.ComponentName).length > 0)? true : false : gridOption['PagingEnabled']);
				self.Grid['GridOptions']['PagingSizeEnabled'] = (gridOption['PagingSizeEnabled'] === undefined ? false : gridOption['PagingSizeEnabled']);
			}
			
			self.Grid['GridOptions']['PagingSet'] = {
					Fir: typeof gridOption['PagingSet'].Fir != 'undefined' ? gridOption['PagingSet'].Fir : "10",
					Sec: typeof gridOption['PagingSet'].Sec != 'undefined' ? gridOption['PagingSet'].Sec : "20",
					Thi: typeof gridOption['PagingSet'].Thi != 'undefined' ? gridOption['PagingSet'].Thi : "50"
				}
			self.Grid['GridOptions']['PagingDefault'] = typeof gridOption['PagingDefault'] != 'undefined' ? gridOption['PagingDefault'] : "";
		}
		if(this.Grid['ShowCaption'] == undefined){
			this.Grid['ShowCaption'] = true;
		}
		if (this.Grid['InteractivityOptions']) {
			if (!(this.Grid.InteractivityOptions.MasterFilterMode)) {
				this.Grid.InteractivityOptions.MasterFilterMode = 'Off';
			}
			if (!(this.Grid.InteractivityOptions.TargetDimensions)) {
				this.Grid.InteractivityOptions.TargetDimensions = 'Argument';
			}
			if (!(this.Grid.InteractivityOptions.IsDrillDownEnabled)) {
				this.Grid.InteractivityOptions.IsDrillDownEnabled = false;
			}
			if (!(this.Grid.InteractivityOptions.IgnoreMasterFilters)) {
				this.Grid.InteractivityOptions.IgnoreMasterFilters = false;
			}
		} else {
			this.Grid['InteractivityOptions'] = {
				MasterFilterMode: 'Off',
				TargetDimensions: 'Argument',
				IsDrillDownEnabled: false,
				IgnoreMasterFilters: false
			};
		}
		if (!(this.Grid['FilterString'])) {
			this.Grid['FilterString'] = [];
		}else{
			this.Grid.FilterString = JSON.parse(JSON.stringify(this.Grid.FilterString).replace(/"@null"/gi,null));
		}
		
		if (!(this.Grid['Palette'])) {
			this.Grid['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
			if(gDashboard != undefined){
				if(typeof this.meta.ColorSheme != 'undefined'){
					var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
					this.Grid.Palette = new Array();
					var newPalette = [];
					$.each(colorList,function(_i,_list){
						self.Grid.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
						 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
					});
					
					self.customPalette = newPalette;
					self.isCustomPalette = true;
				}
			}
		}
		/*dogfoot 그리드 헤더 추가 기능 shlim 20210317*/
		if (typeof this.Grid["HeaderList"] != "undefined") {
			if(!self.headerChange){
				self.headerList = this.Grid["HeaderList"]
			}
		}
	};
	
	/** @Override */
	this.bindData = function(_data, _functionDo, _overwrite) {
		//2020.01.30 mksong query sqlike에서 한번만 돌게 하기 위해 수정 dogfoot
//		if (_overwrite) {
//			this.globalData = _data;
//		}
//		if (!this.tracked) {
//			if(this.globalData == undefined){
//				this.globalData = _.clone(_data);	
//			}
//			this.filteredData = _.clone(_data);
//		}
		/*dogfoot 데이터 그리드 기본 세팅 <-> 데이터 조회 후 로딩 동기화  shlim 20210329 */
		self.loadingChk = 0;
		/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
		if(this.dataSourceId == undefined && this.fieldManager.focusItemType !== 'dataGrid') {
			var datasourceid;
			
			/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
			$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
				if(item.fieldManager.focusItemType.indexOf('Anova') > -1 ||
				   item.fieldManager.focusItemType.indexOf('Correlation') > -1 ||
				   item.fieldManager.focusItemType.indexOf('Test') > -1 ||
				   item.fieldManager.focusItemType.indexOf('multivariate') > -1 ||
				   item.fieldManager.focusItemType.indexOf('Regression') > -1) {
					if(item.dataSourceId !== undefined) {
						datasourceid = item.dataSourceId;
						return false;
					}
				}
			});
			
			this.dataSourceId = datasourceid;
			
			$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
				if(item.fieldManager.focusItemType.indexOf('Anova') > -1 ||
				   item.fieldManager.focusItemType.indexOf('Correlation') > -1 ||
				   item.fieldManager.focusItemType.indexOf('Test') > -1 ||
				   item.fieldManager.focusItemType.indexOf('multivariate') > -1 ||
				   item.fieldManager.focusItemType.indexOf('Regression') > -1) {
					if(item.dataSourceId === undefined) {
						item.dataSourceId = datasourceid;
					}
				}
			});
		}
		
		if(self.meta != undefined){
			this.Grid = self.meta;
			if(!(this.Grid.FilterString)){
				this.Grid.FilterString = [];
			}else{
				this.Grid.FilterString = JSON.parse(JSON.stringify(this.Grid.FilterString).replace(/"@null"/gi,null));
			}
		}
		if(_functionDo){
//			self.dimensions = [];
//			self.measures = [];
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}else if(this.fieldManager != undefined && this.Grid == undefined){
			this.setGrid();
			gDashboard.itemGenerateManager.addParentItems(self);
			gDashboard.itemGenerateManager.itemCustomize(self,self.Grid);
		}else if(this.fieldManager != null && this.Grid){
			self.dimensions = [];
			self.measures = [];
			this.setDataItems();
			self.queryState = false;
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}/*else if(self.meta != undefined){
			this.setGrid();
			this.generate(self.meta);
		}*/
		// initialize format options from CHART_XML
		else {
			$.each(WISE.util.Object.toArray(this.Grid.DataItems.Measure), function(_i, _mea) {
				var dataItemNo = _mea.UniqueName;
				if (typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined') {
					$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.DATA_GRID_ELEMENT), function(_j, _item) {
						if (self.Grid.ComponentName.split('_')[0] === _item.CTRL_NM) {
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
				}
			});
			
			if (!(this.Grid['Palette'])) {
				this.Grid['Palette'] = userJsonObject.userPalette ? userJsonObject.userPalette : userJsonObject.defaultPalette;
				if(gDashboard != undefined){
					if(typeof this.meta.ColorSheme != 'undefined'){
						var colorList = WISE.util.Object.toArray(this.meta.ColorSheme.ColorSheme);
						this.Grid.Palette = new Array();
						var newPalette = [];
						$.each(colorList,function(_i,_list){
							self.Grid.Palette.push(gDashboard.itemColorManager.getHexColor(_list.Color)); 
							 newPalette[_i] = gDashboard.itemColorManager.getHexColor(_list.Color);
						});
						
						self.customPalette = newPalette;
						self.isCustomPalette = true;
					}
				}
			}
			
			/* 20201110 ajkim 그리드 옵션 뷰어에서 기본값 채워주기 dogfoot*/
			var gridOption = self.meta['GridOptions'];
			
			self.Grid['GridOptions']['ColumnWidthMode']  = (gridOption['ColumnWidthMode'] === undefined ? "AutoFitToContents" : gridOption['ColumnWidthMode']);
			self.Grid['GridOptions']['EnableBandedRows'] = (gridOption['EnableBandedRows'] === undefined ? false : gridOption['EnableBandedRows']);
			self.Grid['GridOptions']['AllowGridCellMerge'] = (gridOption['AllowGridCellMerge'] === undefined ? gDashboard.reportType === 'StaticAnalysis' && self.Name === '그룹별 기술통계'? true : false :  gridOption['AllowGridCellMerge']);
			self.Grid['GridOptions']['ShowColumnHeaders'] = (gridOption['ShowColumnHeaders'] === undefined ? true : gridOption['ShowColumnHeaders']);
			self.Grid['GridOptions']['ShowColumnLines'] = ( gridOption['ShowVerticalLines'] === undefined ? true :  gridOption['ShowVerticalLines']);
			self.Grid['GridOptions']['ShowRowLines'] = (gridOption['ShowHorizontalLines'] === undefined ? true : gridOption['ShowHorizontalLines']);
			self.Grid['GridOptions']['WordWrap'] = (gridOption['WordWrap'] === undefined ? false : gridOption['WordWrap']);
			/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
			self.Grid['GridOptions']['PagingDesc'] = typeof gridOption['PagingDesc'] != 'undefined' ? gridOption['PagingDesc'] : "";
			if(userJsonObject.gridDataPaging === 'Y'){
				self.Grid['GridOptions']['PagingEnabled'] = (gridOption['PagingEnabled'] === undefined ? true : gridOption['PagingEnabled']);
				self.Grid['GridOptions']['PagingSizeEnabled'] = (gridOption['PagingSizeEnabled'] === undefined ? true : gridOption['PagingSizeEnabled']);
			} else {
				self.Grid['GridOptions']['PagingEnabled'] = (gridOption['PagingEnabled'] === undefined ? (gDashboard.reportType === 'StaticAnalysis' && $("#dashboardTabPage1 #"+self.ComponentName).length > 0)? true : false : gridOption['PagingEnabled']);
				self.Grid['GridOptions']['PagingSizeEnabled'] = (gridOption['PagingSizeEnabled'] === undefined ? false : gridOption['PagingSizeEnabled']);
			}
			if(self.Grid['GridOptions']['PagingSet']){
				self.Grid['GridOptions']['PagingSet'] = {
						Fir: typeof gridOption['PagingSet'].Fir != 'undefined' ? gridOption['PagingSet'].Fir : "10",
						Sec: typeof gridOption['PagingSet'].Sec != 'undefined' ? gridOption['PagingSet'].Sec : "20",
						Thi: typeof gridOption['PagingSet'].Thi != 'undefined' ? gridOption['PagingSet'].Thi : "50"
					}
			}else{
				self.Grid['GridOptions']['PagingSet'] = { Fir: 10, Sec : 20, Thi : 50 };
			}
			
			self.Grid['GridOptions']['PagingDefault'] = typeof gridOption['PagingDefault'] != 'undefined' ? gridOption['PagingDefault'] : "";
			/*dogfoot 그리드 헤더 추가 기능 shlim 20210317*/
			if (typeof this.Grid["HeaderList"] != "undefined") {
				self.headerList = this.Grid["HeaderList"]
			}
			gDashboard.itemGenerateManager.generateItem(self, self.meta);
		}
		
		/* setting max value for bar chart
		if(self.csvData.length > 0){
			if (this.columnNamesForBarCellMaxValue.length > 0) {
				var SUFFIX_COL_NM = self.DGU.Constants['SUFFIX_COL_NM_FOR_BAR_CHART'];
				var SUFFIX_COL_NM_MIN = self.DGU.Constants['SUFFIX_COL_NM_MIN_FOR_BAR_CHART'];
				var SUFFIX_INTERVAL = self.DGU.Constants['SUFFIX_INTERVAL_FOR_BAR_CHART'];
				
				
				$.each(this.columnNamesForBarCellMaxValue, function(_i, _no) {
					var maxValueObject = _.max(queriedData, function(_d){ return _d[_no.nameBySummaryType]; });
					var minValueObject = _.min(queriedData, function(_d){ return _d[_no.nameBySummaryType]; });
	//				var temparr =  JSON.parse(JSON.stringify( queriedData ));
	//				temparr.sort(function(_a,_b){
	//					return _a[_no.nameBySummaryType] < _b[_no.nameBySummaryType] ? -1 : _a[_no.nameBySummaryType] > _b[_no.nameBySummaryType] ? 1:0;
	//				});
	
					if (!_.isEmpty(maxValueObject)) {
						$.each(queriedData, function(_i0, _no0) {
							_no0[_no.nameBySummaryType + SUFFIX_COL_NM] = maxValueObject[_no.nameBySummaryType];
							_no0[_no.nameBySummaryType + SUFFIX_COL_NM_MIN] = minValueObject[_no.nameBySummaryType];
							_no0[_no.nameBySummaryType + SUFFIX_INTERVAL] = (maxValueObject[_no.nameBySummaryType] - minValueObject[_no.nameBySummaryType])/100;
	//						_no0['seq'] = _i0;
						});
					}
	
				});
			}
		}
		 */
		
		if(this.fieldManager != undefined){
			gDashboard.itemGenerateManager.generateItem(self, self.Grid);
		}

		var dxConfigs = this.getDxItemConfigs(self.Grid);
		
		this.dxItem = $("#" + this.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
		
//		if (!this.child && !this.initialized) {
		if (!this.initialized) {
			gDashboard.itemGenerateManager.renderButtons(self);
			if($('#'+this.itemid+'_topicon').length != 0){
				this.initialized = true;	
			}else{
				this.initialized = false;
			}
		}
		
		/* DOGFOOT ktkang 데이터그리드 사용자정의데이터 오류 수정  20200705 */
		this.calculatedFields = [];
		this.tempMeasureFields = [];
		this.calculateCaption;
		this.udfGroups = [];
		if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo))) {
			var fieldList = gDashboard.customFieldManager.fieldInfo[this.dataSourceId];
			if (fieldList) {
				fieldList.forEach(function(field) {
					// 다운로드 사용자 데이터 오류 수정
					var selectors = [];
					$.each(self.columns, function(j, dim){
						if(field.Expression.indexOf("["+dim.name+"]") > -1){
							selectors.push(dim.name);
						}
					})
					// PivotGrid의 "[순매출액]*2"과 같은 표현식을 "_fields['순매출액']*2" 포맷으로 변경
					var convertedExpr = field.Expression.replace(/\[([^\[\]\'\"]+)\]/g, "_fields['$1']");
					self.udfGroups.push({name: field.Name, selectors: selectors, expression: convertedExpr});
					
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
												precisionOption: "반올림",
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
										self.tempMeasureFields.push(self.measures.length-1);
									});	
								}
							}
							//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 끝 dogfoot
						}
					});
					
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
												precisionOption: '반올림',
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
		
		var measures = [];
		measures = measures.concat(_.clone(this.measures));
		measures = measures.concat(_.clone(this.HiddenMeasures));
		
		/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
		var renderGrid = function(self, queriedData, totalCount){
			self.globalData = queriedData;
			self.filteredData = self.globalData;
			/* DOGFOOT ktkang 오타 수정  20200207 */
			self.csvData = self.filteredData;
			
			//2020.02.04 mksong SQLLIKE doSqlLike 사용자정의테스트 기능추가 수정 끝 dogfoot
			if(!($.isEmptyObject(gDashboard.customFieldManager.fieldInfo)) && self.calculatedFields.length > 0) {
				var fieldList = gDashboard.customFieldManager.fieldInfo[self.dataSourceId];
				if (fieldList) {
					fieldList.forEach(function(field) {
						$.each(self.calculatedFields,function(_i,_calculatedField){
							if(field.Name == _calculatedField.name){
								/* DOGFOOT shlim 사용자 정의 데이터 정렬기준항목으로 생성 가능하도록 수정  20210121 */
								gDashboard.customFieldManager.addCustomFieldsToDataSourceForSummaryValue(field, self.filteredData, _calculatedField, self.measures,self.dimensions,self.HiddenMeasures);		
//								gDashboard.customFieldManager.addCustomFieldsToDataSource(field, self.globalData);
							}
						});
					});
				}
			}			
			
			/* LSH topN */
			var dMtopNval = new Array();
			if(self.meta['DataItems']['Dimension']){
				dMtopNval = self.meta['DataItems']['Dimension'];
				
				if(dMtopNval.length == undefined){
					self.dimensionTopN.push(dMtopNval);
				}else{
					self.dimensionTopN = dMtopNval;
				}

				for(var i = 0; i < self.dimensionTopN.length; i++){
					if(self.dimensionTopN[i].TopNEnabled){
						self.topNEnabeled = true;
					}
				}
				for(var i = 0; i < self.dimensionTopN.length; i++){
					if(self.dimensionTopN[i].TopNOrder){
						self.TopNOrder = true;
					}
				}
			}
			/* LSH topN
			 *  topN 계산을 위한 함수
			 * */
			if(self.topNEnabeled){
				var first=[];
				
				//데이터 Array 계산 형식에 맞게 변경 
				first.push({items:queriedData});
				queriedData = first;
				self.preDimCheck=0;
				//차원이 여러개일때 topN기능이 걸린 차원의 위치를 찾기위한 싸이클
				for(var i = 0; i < self.dimensionTopN.length; i++){
					queriedData = self.__getTopNData(queriedData,self.dimensions,self.dimensionTopN[i].DataMember,self.dimensionTopN[i].TopNEnabled);
				}
	            
	            for(var i = 0; i < self.dimensionTopN.length; i++){
					queriedData = self.__getTopNsortData(queriedData,self.dimensions,self.dimensionTopN[i].DataMember);
				}
				

				var topNarray=[];
				$.each(queriedData,function(_i,_e){
					$.each(_e.items,function(_j,_k){
						topNarray.push(_k); 
					}) 
				})

				queriedData = topNarray;
			}
			
//			var csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(this.dimensions, this.measures, []);
//			this.csvData = SQLikeUtil.doSqlLike(this.dataSourceId, csvDataConfig);
			
			/* DOGFOOT hsshim 200103
			 * 사용자 정의 데이터 집계 함수 추가
			 */
			gDashboard.customFieldManager.addSummaryFieldData(self, queriedData);
			/* setting max value for bar chart */
			if (self.columnNamesForSparklineCell.length > 0) {
				//2020.02.07 mksong sqllike 적용 dogfoot
				var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
				/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
				gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
				var dimensions = self.dimensions.concat(self.sparklineElements);
				/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
				var sparklineDataConfig = SQLikeUtil.fromJson(dimensions, measures, _data, {orderBy: self.sparklineElements, exceptDimensionOrderBy: true}, self.type, self.orderKey);
				
				if(self.IO){
					if(self.IO.IgnoreMasterFilters){
						sparklineData.Where = [];
						sparklineData.From = [];
					}
				}
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				var sparklineData = SQLikeUtil.doSqlLike(self.dataSourceId, sparklineDataConfig, self);
				
				$.each(queriedData, function(_i0, _no0) {
					_no0['rawData'] = sparklineData;
				});
			}
			/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
			if(gDashboard.reportType == 'DashAny' && gDashboard.downloadFull && queriedData.length < 100) {
				self.contentReady = true;
			}
			
			//2020.05.11 ajkim 제거된 필드가 있으면 필터에서도 제거 dogfoot
			function fieldCheck(_filterString){
				if(_filterString === undefined || _filterString === [] || _filterString === "" || !_filterString)
					return;
				var removedData = true;
				if($.type(_filterString[0]) === 'string'){
					removedData = true;
					$.each(self.dimensions, function(_i, _dimension){
						if(_dimension.name === self.meta.FilterString[0])
							removedData = false;
					});
					if(removedData)
						_filterString.splice(0, 3);
				}else{
					var removeCount = 0;
					$.each(_filterString, function(_i, _filter){
						removedData = true;
						$.each(self.dimensions, function(_j, _dimension){
							if(_filter === undefined) return false;
							if($.type(_filter) === 'string'){
								removedData = false;
								return false;
							}
							else if($.type(_filter[0]) === 'array'){
								fieldCheck(_filter)
								if(_filter.length === 0)
									_filterString.splice(_i - removeCount, 2);
								removedData = false;
								return false;
							}
							else if(_dimension.name === _filter[0]){
								removedData = false;
								return false;
							}
						});
						if(removedData){
							_filterString.splice(_i - removeCount, 2);
							removeCount += 2;
						}
					});
				}
			}
			
			fieldCheck(self.meta.FilterString);			
			self.initDrillDownData(queriedData);
			if(self.columnNamesForBarCellMaxValue.length > 0){
				queriedData = self.initMaxValue(queriedData);
			}			
			
			// 스파크라인 관련코드 시작
			if(self.sparklineElements != undefined && self.sparklineElements.length != 0){
				var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
				/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
				gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
				
				var tempDimension = [];			
				$.each(self.DI.Dimension,function(_,_d){
					tempDimension.push({
						TopNCount: undefined,
						TopNEnabled: undefined,
						TopNOrder: undefined,
						TopNMeasure: undefined,
						TopNShowOthers: undefined,
						UNI_NM: undefined,
						caption: _d.Name,
						displayMode: undefined,
						name: _d.DataMember,
						rawCaption: _d.Name,
						sortOrder:(_d.SortOrder == 'descending' || _d.SortOrder == "Descending") ? "desc" : "asc",
						type: "dimension",
						uniqueName: _d.UniqueName
					})
				});
				/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
				var queriedDataConfig = SQLikeUtil.fromJson(tempDimension, measures, [], undefined, self.type, self.orderKey);				
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
				var rowData = SQLikeUtil.doSqlLike(self.dataSourceId, queriedDataConfig, self);				
				
				var newQueriedData = [];
				var keys = [];
				
				var TimeLine, Volumne;
				$.each(self.DI.Dimension,function(_,_d){
					if(_d.UniqueName ==  self.sparklineElements[0].uniqueName){
						TimeLine = _d.Name;
					}
				});
				
				$.each(self.measures,function(_,_d){
					$.each(WISE.util.Object.toArray(self.Grid.GridColumns.GridSparklineColumn), function(_i,_gridSparklineColumn){
						if(_d.uniqueName ==  _gridSparklineColumn.SparklineValue.UniqueName){
							Volumne = _d.nameBySummaryType;
						}	
					});
				});
				
				$.each(self.dimensions, function(_, _d) {
					keys.push(_d.name);
				});
				
				$.each(rowData, function(_, item1) {
					 $.each(queriedData, function(_, item2) {
						 if(item2.sparkLineData == undefined) item2.sparkLineData=[];					 
						 var tempFlag = 0;
						 $.each(keys, function(_, _key) {
							 if(item1[_key] == item2[_key]){
								 tempFlag++;
								 if(tempFlag == keys.length){
									 item2.sparkLineData.push({ "TimeLine": item1[TimeLine], "Volumne": item1[Volumne]}); 
									 tempFlag = 0;
								 }
							 }else{
							 	 //2020.10.21 MKSONG 데이터그리드 스파크라인 cs와 동기화 DOGFOOT
								 item2.sparkLineData.push({ "TimeLine": item1[TimeLine], "Volumne": 0}); 
								 tempFlag = 0;
							 }
						 });					 
			          });
				});				  
			}
			// 스파크라인 관련코드 끝
			/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
			var gridRealDatas;
			if(userJsonObject.gridDataPaging === 'Y' && gDashboard.reportType != "StaticAnalysis"){
				if(totalCount == undefined) totalCount = queriedData.length;
				gridRealDatas = new DevExpress.data.CustomStore({
					load: function (loadOptions) {
						var deferred = $.Deferred();
						deferred.resolve(queriedData, { totalCount: totalCount });
						return deferred.promise();
					}
				});
			} else {
				gridRealDatas = queriedData;
			}
			
			var newDataSource = new DevExpress.data.DataSource({
	            store: gridRealDatas,
	            paginate: true
	        });
	        if(self.Grid && self.Grid.FilterString && self.Grid.FilterString.length > 0) {
				newDataSource.filter(self.Grid.FilterString);
				newDataSource.load();
				$('#editFilter').addClass('on');
			}
//	        self.filterArrays = filter;
//	        self.bindData(newDataSource.items(),true);
			/* dogfoot shlim 그리드 화면 표시 완료 될때 프로그레스바 사라지도록 수정 20210201*/
	        //$('#'+self.itemid).css('display','block');
			self.dxItem.option('dataSource', newDataSource);
			
			var temColumns = [];
			
			$.each(self.dxItem.option('columns'),function(_i,_d){ 
//				if(_d.dataField != 'SALEDATE'){
					temColumns.push(_d);
					if(_d.name !== _d.caption && typeof _d.summaryType === 'undefined')
						_d.dataField = _d.caption;
//				}
				
			});
			
			/*dogfoot 그리드 헤더 추가 기능shlim 20210317*/
			var  columnsHeader = [],headerTemp=[],headerAddChk=[];
			if(Object.keys(self.headerList).length > 0){
				var UpperIndexArr=[];
				function UpperIndexCalc(_hdl){
					if(!(typeof _hdl.HEADER_UPPER != "undefined" && _hdl.HEADER_UPPER !="NonHeader")){
						if(UpperIndexArr.indexOf(_hdl.HEADER_CODE) == -1){
							UpperIndexArr.push(_hdl.HEADER_CODE);
						}
					}else{
						if(UpperIndexArr.indexOf(_hdl.HEADER_UPPER) > -1){
							if(UpperIndexArr.indexOf(_hdl.HEADER_CODE) == -1){
								UpperIndexArr.splice(UpperIndexArr.indexOf(_hdl.HEADER_UPPER),-1,_hdl.HEADER_CODE);
							}
						}else{
							if(typeof self.headerList[_hdl.HEADER_UPPER] != "undefined"){
								UpperIndexCalc(self.headerList[_hdl.HEADER_UPPER]);
								UpperIndexArr.splice(UpperIndexArr.indexOf(_hdl.HEADER_UPPER),-1,_hdl.HEADER_CODE);
							}else{
								if(UpperIndexArr.indexOf(_hdl.HEADER_CODE) == -1){
									UpperIndexArr.push(_hdl.HEADER_CODE);
								}
							}
						}
					}
				}
				$.each(self.headerList, function(_ihl,_hdl){
					headerTemp[_hdl.HEADER_CODE] = {"caption":_hdl.HEADER_NAME,"columns":[]};
					UpperIndexCalc(_hdl);
				})
				
				$.each(temColumns,function(_it,_tdl){
					$.each(self.headerList,function(_ihl,_hdl){
						if(typeof _tdl.HEADER_CODE != "undefined" && _tdl.HEADER_CODE === _hdl.HEADER_CODE
								&& _hdl.HEADER_YN === "Y"){
							headerTemp[_hdl.HEADER_CODE].columns.push(_tdl)
						}
					})
				});
				
				$.each(UpperIndexArr,function(_upi,_upa){
					$.each(self.headerList,function(_ihl,_hdl){
						if(_upa === _hdl.HEADER_CODE){
							if(_hdl.HEADER_YN === "Y" && typeof _hdl.HEADER_UPPER !="undefined"){
								if(headerTemp.HEADER_UPPER != "NonHeader"){
									if(headerTemp[_hdl.HEADER_UPPER] != undefined){
										headerTemp[_hdl.HEADER_UPPER].columns.push(headerTemp[_hdl.HEADER_CODE]);
										delete headerTemp[_hdl.HEADER_CODE];
									}
								}
							}
						}
					})
				})
//				$.each(temColumns,function(_it,_tdl){
//					if(typeof _tdl.HEADER_CODE != "undefined" && typeof _tdl.HEADER_CODE != "NonHeader" && self.headerList[_tdl.HEADER_CODE].HEADER_YN ==="Y"){
//						if(typeof headerTemp[_tdl.HEADER_CODE] != "undefined"){
//							columnsHeader.push(headerTemp[_tdl.HEADER_CODE]);
//							delete headerTemp[_tdl.HEADER_CODE];
//						}
//					}else{
//						columnsHeader.push(_tdl);
//					}
//				})
				
				$.each(temColumns,function(_it,_tdl){
					if(typeof _tdl.HEADER_CODE != "undefined" && typeof _tdl.HEADER_CODE != "NonHeader" && self.headerList[_tdl.HEADER_CODE].HEADER_YN ==="Y"){
						function getHeaderInfo(_headerInfo){

							if(typeof headerTemp[_headerInfo] != "undefined"){
								if(self.headerList[_headerInfo].HEADER_YN ==="Y"){
								    columnsHeader.push(headerTemp[_headerInfo]);
								    headerAddChk[_headerInfo] = headerTemp[_headerInfo];
							        delete headerTemp[_headerInfo];		
								}
							}else{
								if(typeof headerAddChk[_headerInfo] == "undefined"){
									if(typeof self.headerList[_headerInfo].HEADER_UPPER !="undefined" && self.headerList[_headerInfo].HEADER_UPPER != "NonHeader"){
	                                    getHeaderInfo(self.headerList[_headerInfo].HEADER_UPPER);
									}
								}
							}
						}

						getHeaderInfo(_tdl.HEADER_CODE);
						
					}else{
						columnsHeader.push(_tdl);
					}
				})
				
				temColumns = columnsHeader;
			}
			
			self.dxItem.option('columns',temColumns);
			
			/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
//			console.log("-----------------------------------------------------------------------");
//			window.endDrawItemTime[self.itemid] = window.performance.now();
//			console.log(self.Name +" DrawItemTime 걸린시간 : " + (window.endDrawItemTime[self.itemid] - window.startDrawItemTime[self.itemid])+'ms');
//			console.log("-----------------------------------------------------------------------");
			//2020.02.17 mksong 옵션 사용한 바인드일 때 프로그레스 하이드 되도록 수정 dogfoo
			/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
			if(!self.functionBinddata && self.ComponentName !== 'download_expand_grid'){
				/*dogfoot 데이터 그리드 기본 세팅 <-> 데이터 조회 후 로딩 동기화  shlim 20210329 */
				if(self.loadingChk==0){
					self.loadingChk++;
				}else{
					if(gDashboard.itemGenerateManager.viewedItemList.indexOf(self.ComponentName) < 0 ){
						gDashboard.itemGenerateManager.viewedItemList.push(self.ComponentName);
					}
					/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
					if(WISE.Constants.editmode == 'viewer' && gDashboard.tabQuery){
						if(gDashboard.itemGenerateManager.selectedItemList.length <= gDashboard.itemGenerateManager.viewedItemList.length){
							$('.progress_box').css('display', 'none');
						}
					}else{
						if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
							gProgressbar.setStopngoProgress(true);
							gProgressbar.hide();
							/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
//							console.log("-----------------------------------------------------------------------");
//							window.endBeforQueryTime = window.performance.now();
//							console.log("아이템 생성 ~ 로딩바 사라질때까지 걸린시간 : " + (window.endBeforQueryTime - window.startBeforQueryTime)+'ms');
//							console.log("총 소요시간 (전체) : " + (window.endBeforQueryTime - window.startGenTime)+'ms');
//							console.log("-----------------------------------------------------------------------");
							gDashboard.updateReportLog();
						}
					}
					//$('#'+self.itemid).css('display','block');	
				}
				
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _d) {
					if(_d.type != 'IMAGE'){
						if(_d.dimensions.length == 0 && _d.measures.length == 0){
							gProgressbar.hide();
						}	
					}
				});
			
			}else{
				gProgressbar.hide();
				self.functionBinddata = false;
			}
			console.log(self.itemid + '-ITEMVIEW END : '+ new Date());
			self.queryState = false;
			$('.lm_content .dx-datagrid').attr('style', gDashboard.fontManager.getCustomFontStringForItem(12));
			if(WISE.Constants.editmode == 'viewer') {
				if(gDashboard.itemGenerateManager.dxItemBasten.length > 1) {
					$('.lm_content .dx-datagrid').css('padding-bottom', '5px');
				} else {
					$('.lm_content .dx-datagrid').css('padding-bottom', '0px');
				}
			}
		}
		
		console.log(self.itemid + '-SQLIKE QUERY START : '+ new Date());
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		/*dogfoot 아이템 별 데이터 집합 파라메타 저장 shlim 20200619*/
		gDashboard.itemGenerateManager.itemDataSourceId = self.dataSourceId;
		/*dogfoot 데이터가 많을경우 ajax처리가 안됨(from구문에 쓰이지 않는거로 확인됨)  hjkim 20200806*/
		//var queriedDataConfig = SQLikeUtil.fromJson(self.dimensions, measures, self.filteredData);
		/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
		if(gDashboard.reportType !== 'DSViewer'){
			var queriedDataConfig = SQLikeUtil.fromJson(self.dimensions, measures, undefined,undefined,self.type,gDashboard.customFieldManager.fieldInfo[self.dataSourceId]);

			//2020.03.06 mksong 불필요한 변수 선언 삭제 dogfoot
			
			if(self.IO){
				if(self.IO.IgnoreMasterFilters){
					queriedDataConfig.Where = [];
					queriedDataConfig.From = [];
				}
			}
		}else{
			var fields = self.getAllFields();
			
			var queriedDataConfig = SQLikeUtil.fromJson(fields.dim, fields.mea, undefined,undefined,self.type,undefined);
		}
		
		/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
		if(self.isDownloadExpand){
			queriedDataConfig.Where = [];
			queriedDataConfig.From = [];
		}
		
		/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
		self.sqlConfig = queriedDataConfig;
		self.renderGrid = renderGrid;
		/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
		if(WISE.Constants.editmode != "viewer"){
			/* DOGFOOT ktkang 데이터 그리드 오류 수정  20201112 */
			if(gDashboard.reportType == 'StaticAnalysis') { //통계분석
				/* DOGFOOT ktkang 통계일때는 서버페이징 안타도록 수정  20210126 */
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
					if(item.Name === '데이터' && self.ComponentName === item.ComponentName) {
						SQLikeUtil.doSqlLikeAjax(self.dataSourceId, queriedDataConfig, self, renderGrid, self.cubeQuery);
						gDashboard.aysCheck = true;
                        return false;
					}
				});
				
				if(gDashboard.itemGenerateManager.dxItemBasten.length > 1 && self.ComponentName === gDashboard.itemGenerateManager.dxItemBasten[1].ComponentName && gDashboard.aysCheck){
					this.staticAnalysisType = this.fieldManager.focusItemType !== 'dataGrid' ? this.fieldManager.focusItemType : gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].ANALYSIS_TYPE;
					/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined' && typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT !== 'undefined') {
						this.staticOptions.alphaLevel = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].ALPHA_LEVEL;
						this.staticOptions.paired = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].PAIRED;
						this.staticOptions.alternative = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].ALTERNATIVE;
						this.staticOptions.varequal = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].VAREQUAL;
						this.staticOptions.mutest = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].MUTEST;
						/* DOGFOOT ktkang 다변량분석 추가  20210215 */
						this.staticOptions.method = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].METHOD;
						this.staticOptions.distance = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].DISTANCE;
						this.staticOptions.cluster = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].CLUSTER;
						/* DOGFOOT ktkang Z검정 옵션 추가  20210216 */
						this.staticOptions.stdev = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].STDEV;
						/* DOGFOOT syjin 카이제곱 검정 옵션 추가  20210315 */
						this.staticOptions.chisqType = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].CHISQTYPE;
					}
					if(gDashboard.analysisType === 'insertSimpleRegression' || gDashboard.analysisType === 'insertMultipleRegression') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
					} else if(gDashboard.analysisType === 'insertTtest') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
						this.staticOptions.mutest = typeof $("#mutest").dxNumberBox('instance') !== 'undefined' ? $("#mutest").dxNumberBox('instance').option('value') : self.staticOptions.mutest;
						
						if(typeof $("#paired").dxSelectBox('instance') !== 'undefined') {
							var paired = $("#paired").dxSelectBox('instance').option('value');
							if(paired == '일표본') {
								this.staticOptions.paired = 'oneSample';
							} else if(paired == '독립표본') {
								this.staticOptions.paired = 'twoSample';
							} else if(paired == '대응표본') {
								this.staticOptions.paired = 'pairedSample';
							}
						}
						
						if(typeof $("#alternative").dxSelectBox('instance') !== 'undefined') {
							var alternative = $("#alternative").dxSelectBox('instance').option('value');
							if(alternative == '양측검정') {
								this.staticOptions.alternative = 'twoSided';
							/* DOGFOOT syjin t검정 가설유형 옵션 오류 수정  20210312 */
							} else if(alternative == '좌측검정') {
								this.staticOptions.alternative = 'lessSided';
							} else if(alternative == '우측검정') {
								this.staticOptions.alternative = 'greaterSided';
							}
						}
						
						if(typeof $("#varequal").dxSelectBox('instance') !== 'undefined') {
							var paired = $("#varequal").dxSelectBox('instance').option('value');
							if(paired == '분산이 같다고 가정') {
								this.staticOptions.varequal = true;
							} else if(paired == '분산이 다르다고 가정') {
								this.staticOptions.varequal = false;
							}
						}
					} 
					
					/* DOGFOOT syjin 가설검정 Z-test 추가  20210209 */
					else if(gDashboard.analysisType === 'insertZtest') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
						this.staticOptions.mutest = typeof $("#mutest").dxNumberBox('instance') !== 'undefined' ? $("#mutest").dxNumberBox('instance').option('value') : self.staticOptions.mutest;
						this.staticOptions.stdev = typeof $("#stdev").dxNumberBox('instance') !== 'undefined' ? $("#stdev").dxNumberBox('instance').option('value') : self.staticOptions.stdev;
						/* DOGFOOT syjin Z검정 옵션 수정 */
						
						if(typeof $("#alternative").dxSelectBox('instance') !== 'undefined') {
							var alternative = $("#alternative").dxSelectBox('instance').option('value');
							if(alternative == '양측검정') {
								this.staticOptions.alternative = 'twoSided';
								/* DOGFOOT syjin z검정 가설유형 옵션 오류 수정  20210312 */
							} else if(alternative == '좌측검정') {
								this.staticOptions.alternative = 'lessSided';
							} else if(alternative == '우측검정') {
								this.staticOptions.alternative = 'greaterSided';
							}
						}												
					}
					
					/* DOGFOOT syjin 카이제곱 검정 chiTest 추가  20210209 */
					else if(gDashboard.analysisType === 'insertChitest') {
						/* DOGFOOT syjin 카이제곱 검정 옵션 수정 */
						if(typeof $("#chisqType").dxSelectBox('instance') !== 'undefined') {
							var chisqType = $("#chisqType").dxSelectBox('instance').option('value');
							if(chisqType == '적합도검정') {
								this.staticOptions.chisqType = 'goodness';
							} else if(chisqType == '동질성검정') {
								this.staticOptions.chisqType = 'homogeneity';
							} else if(chisqType == '독립성검정') {
								this.staticOptions.chisqType = 'independence';
							}
						}
					}
					/* DOGFOOT syjin f 검정 fTest 추가  20210215 */
					else if(gDashboard.analysisType === 'insertFtest') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
												
						if(typeof $("#alternative").dxSelectBox('instance') !== 'undefined') {
							var alternative = $("#alternative").dxSelectBox('instance').option('value');
							if(alternative == '양측검정') {
								this.staticOptions.alternative = 'twoSided';
							} else if(alternative == '좌측검정') {
								this.staticOptions.alternative = 'lessSided';
							} else if(alternative == '우측검정') {
								this.staticOptions.alternative = 'greaterSided';
							}
						}
												
					}
					/* DOGFOOT ktkang 다변량분석 추가  20210215 */
					else if(gDashboard.analysisType === 'insertMultivariate') {
						this.staticOptions.method = typeof $("#method").dxSelectBox('instance') !== 'undefined' ? $("#method").dxSelectBox('instance').option('value') : self.staticOptions.method;
						this.staticOptions.distance = typeof $("#distance").dxSelectBox('instance') !== 'undefined' ? $("#distance").dxSelectBox('instance').option('value') : self.staticOptions.distance;
						this.staticOptions.cluster = typeof $("#cluster").dxNumberBox('instance') !== 'undefined' ? $("#cluster").dxNumberBox('instance').option('value') : self.staticOptions.cluster;
					} 
					var params = {
							analysisType : self.staticAnalysisType === "multipleLogisticRegression" ? "logisticRegression":self.staticAnalysisType,
							measures : [],
							dimensions : [],
							globalDatas : [],
							staticOptions : $.toJSON(self.staticOptions),
							/* DOGFOOT syjin JAVA R 분기처리 방식 설정 추가 20210218 */
							analysis : menuConfigManager.getMenuConfig.Menu.ANALISYS.analUseType
					}
					
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
						if(typeof item.globalData != 'undefined' && item.globalData.length > 0) {
							params.globalDatas = JSON.stringify(item.globalData);
							return false;
						}
					});

					params.measures = JSON.stringify(self.measures);
					params.dimensions = JSON.stringify(self.dimensions);
					$.ajax({
						type : 'post',
						data : params,
						url : WISE.Constants.context + '/static/analysis.do',
						success : function(data) {
							if(data.resultCode == -1) {
								gProgressbar.hide();
								WISE.alert('분석범위에서 벗어났습니다.', 'error');
								return false;
							} else if(data.resultCode > 0) {
								gProgressbar.hide();
								WISE.alert('측정값이 잘못되었습니다.');
								return false;
							} else if(data.resultCode > 10) {
								gProgressbar.hide();
								WISE.alert('데이터가 R에서 Matrix로 변환 할 수 없는 형식입니다.');
								return false;
							}
							/*if(self.fieldManager.focusItemType.indexOf('Anova') > -1) {
								$('#significanceResult').html('  ->  ' + data.significanceResult);
							}*/
							$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
								if(i > 0) {
									if(item.Name == '분석결과표'){
										item.globalData = data.data;

										var columns = new Array();
										var k = 0;
										$.each(item.globalData[0], function(key, value) {
											var tempColumns = new Object();
											tempColumns.dataField = key;
											tempColumns.UniqueName = 'DataItem' + k.toString();
											tempColumns.uniqueName = 'DataItem' + k.toString();
											tempColumns.caption = key;
											columns.push(tempColumns); 
											k++;
										});

										item.columns = columns;

										item.renderGrid(item, item.globalData);
										var dxConfigs = item.getDxItemConfigs(item.Grid);
										$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
									} else if (item.Name == '예측 결과 시각화'){
										 var ValueArray = [],
	                                        xyDataArr = [],
	                                        x={},y={},xData,yData;
	                                     $.each(data.data2,function(_j,_val){
	                                         if(_val.Name === "Constant"){
	                                         	x[_val.Name]  = parseFloat(_val.Value);
	                                         	xData = parseFloat(_val.Value)
	                                         }else{
	                                         	y[_val.Name] = parseFloat(_val.Value)
	                                         	yData = parseFloat(_val.Value)
	                                         	xyDataArr.push([x,y])
	                                         }
	                                     })
										$.each(item.filteredData,function(_i,_data){
											var returnObj = new Object()
											var returnObj2 = new Object()
											,z;
											$.each(item.dimensions,function(_j,_dim){
                                         	
                                         	if(_j == 0){
													returnObj[_dim.name] = _data[_dim.name]
													z = _data[_dim.name]
													returnObj2[_dim.name] = _data[_dim.name]
												}else{
													returnObj[_dim.name] = (1/(1+(1/Math.exp(xData+yData*z))))
													returnObj['dimension'] = _dim.name
													returnObj2[_dim.name] = _data[_dim.name]
													returnObj2['dimension'] = _dim.name
													returnObj2['realdata'] = _dim.name
												}
                                             })

                                         
                                             ValueArray.push(returnObj);
                                             ValueArray.push(returnObj2)
										})

										
										if(item.dimensions.length > 2){
											d3.select("#"+item.itemid).selectAll('svg').remove();
											d3.select("#"+item.itemid).selectAll('div').remove();
										}else{
											item.fScatterPlot(_data, item.measures, item.dimensions, ValueArray);
										}
									} else if (item.Name == '분석후 시각화'){
										var ValueArray = [];
										ValueArray.push(data.heatmapdata);
                                        item.filteredData = data.heatmapdata;
                                        
										var Dimension = new Array(),
										Measure = new Array();
										var k = 0;
										$.each(data.heatmapdata[0], function(key, value) {
											var tempColumns = new Object();
											if(key == "값"){
                                                tempColumns.dataField = key;
												tempColumns.UniqueName = 'DataItem' + k.toString();
												tempColumns.uniqueName = 'DataItem' + k.toString();
												tempColumns.caption = key;
												tempColumns.DataMember = key;
												tempColumns.name = key;
												tempColumns.captionBySummaryType = key;
												tempColumns.nameBySummaryType = key;
												Measure.push(tempColumns); 
												item.currentMeasureName = key
											}else{
                                                tempColumns.dataField = key;
												tempColumns.UniqueName = 'DataItem' + k.toString();
												tempColumns.uniqueName = 'DataItem' + k.toString();
												tempColumns.caption = key;
												tempColumns.name = key;
												tempColumns.DataMember = key;

												Dimension.push(tempColumns); 
											}
											
											
											k++;
										});
										item.dimensions = Dimension;
										item.measures = Measure;
										/*dogfoot 통계 히트맵 변경  shlim 20201109*/
										item.selectedMeasure = Measure[0];
										var resultArr = new Array();
										$.each(ValueArray,function(_i,_e){
											$.each(_e,function(_item,_obj){
												var str = new Array();
												var object = new Object();
												$.each(Dimension,function(_i,_Dim){
													str.push(_obj[_Dim.DataMember]);
												});
												$.each(Measure,function(_i,_Mea){
													object['value'] = _obj[_Mea.caption];
												});
												
												object['name'] = str.join(' - ');
												resultArr.push(object);
											})
										});
										/*dogfoot 통계 히트맵 변경  shlim 20201109*/
										var dimx=[],dimy=[],dimX =[],dimY = []
										$.each(resultArr, function(_i, _o) {
											var splitName = _o.name.split('-');
											if(splitName[0])dimx.push(splitName[0].trim());
											if(splitName[1])dimy.push(splitName[1].trim());
										});

										
										
										dimx = dimx.reduce(function(a,b){if(a.indexOf(b)<0)a.push(b);return a;},[]);
										dimy = dimy.reduce(function(a,b){if(a.indexOf(b)<0)a.push(b);return a;},[]);
										
										$.each(dimx, function(_i, _o) {
											dimX.push({'dimension' : _o})
											dimY.push({'dimension' : _o})
										});

										result = {
											data : resultArr,
											dimX : dimX,
											dimY : dimY.reverse()
										};
										
										item.fHeatMap2(_data, Measure, Dimension, result);
									} else {
										if(gDashboard.analysisType === 'insertOnewayAnova') {
											if(item.Name == '기술통계'){
												item.globalData = data.descriptive;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
											else if(item.Name == '그룹별 기술통계'){
												item.globalData = data.descriptiveDim;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
											else if(item.Name == '도수분포표'){
												item.globalData = data.frequency;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
										} else if(gDashboard.analysisType === 'insertTwowayAnova' || gDashboard.analysisType === 'insertOnewayAnova2') {
											if(item.Name == '기술통계'){
												item.globalData = data.descriptive;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
											else if(item.Name == '교차분석'){
												item.globalData = data.crossover;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
										} else if(gDashboard.analysisType === 'insertSimpleRegression' || gDashboard.analysisType === 'insertMultipleRegression'){
											if(item.Name == '회귀분석 통계량'){
												item.globalData = data.data;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else if(item.Name == '분산분석'){
												item.globalData = data.data2;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else if(item.Name == '분석 결과'){
												item.globalData = data.data3;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else {
												if(item.Name == '기술통계'){
													item.globalData = data.descriptive;

													var columns = new Array();
													var k = 0;
													$.each(item.globalData[0], function(key, value) {
														var tempColumns = new Object();
														tempColumns.dataField = key;
														tempColumns.UniqueName = 'DataItem' + i.toString();
														tempColumns.uniqueName = 'DataItem' + i.toString();
														tempColumns.caption = key;
														columns.push(tempColumns); 
														k++;
													});

													item.columns = columns;

													item.renderGrid(item, item.globalData);
													var dxConfigs = item.getDxItemConfigs(item.Grid);
													$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
												}
											}
										} else if(gDashboard.analysisType === 'insertLogisticRegression' || gDashboard.analysisType === 'insertMultipleLogisticRegression'){
											if(item.Name == '분석결과표'){
												item.globalData = data.data;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else if(item.Name == '로지스틱회귀계수'){
												item.globalData = data.data2;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else {
												if(item.Name == '기술통계'){
													item.globalData = data.descriptive;

													var columns = new Array();
													var k = 0;
													$.each(item.globalData[0], function(key, value) {
														var tempColumns = new Object();
														tempColumns.dataField = key;
														tempColumns.UniqueName = 'DataItem' + i.toString();
														tempColumns.uniqueName = 'DataItem' + i.toString();
														tempColumns.caption = key;
														columns.push(tempColumns); 
														k++;
													});

													item.columns = columns;

													item.renderGrid(item, item.globalData);
													var dxConfigs = item.getDxItemConfigs(item.Grid);
													$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
												}
											}
										} else {
											if(item.Name == '기술통계'){
												item.globalData = data.descriptive;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
										}
									}
								}
							});

	//						var columns = new Array();
	//						var i = 0;
	//						$.each(self.globalData, function(key, value) {
	//						var tempColumns = new Object();
	//						tempColumns.dataField = key;
	//						tempColumns.UniqueName = 'DataItem' + i.toString();
	//						tempColumns.uniqueName = 'DataItem' + i.toString();
	//						tempColumns.caption = key;
	//						columns.push(tempColumns); 
	//						});

						},
						error : function(_e){
							gProgressbar.hide();
							/* DOGFOOT syjin f 검정 fTest 수치변수 2개 설정하도록 알림  20210216 */
							if(gDashboard.analysisType == 'insertFtest'){
							    if( $("#fTestNumericalList1").find("ul").length < 2){
							        WISE.alert('보고서 조회 오류<br>F검정은 수치변수가 2개 있어야 조회가 가능합니다.');
						        }else{
						        	WISE.alert('측정값이 잘못되었습니다.');	
						        }
							}else{
							    WISE.alert('측정값이 잘못되었습니다.');	
							}
						}
					});
					gDashboard.aysCheck = false;
				}
			} else {
				/* DOGFOOT syjin 그리드 클라이언트 페이징 설정 오류 수정  20210312 */
				if(userJsonObject.gridDataPaging === 'Y'){
					if(self.Grid.GridOptions.PagingEnabled){
                        SQLikeUtil.doSqlLikePaging(self, self.Grid.GridOptions.PagingDefault, 0);
					}else{
                        SQLikeUtil.doSqlLikeAjax(self.dataSourceId, queriedDataConfig, self, renderGrid, self.cubeQuery);
					}
				} else {
					SQLikeUtil.doSqlLikeAjax(self.dataSourceId, queriedDataConfig, self, renderGrid, self.cubeQuery);
				}
			}
		}else{
			if(typeof self.focusItemType != 'undefined'&& (self.focusItemType !== 'dataGrid' || typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT !== 'undefined')) { //통계분석
				if(self.ComponentName === gDashboard.itemGenerateManager.dxItemBasten[0].ComponentName) {
					if(userJsonObject.gridDataPaging === 'Y'){
						SQLikeUtil.doSqlLikePaging(self, self.Grid.GridOptions.PagingDefault, 0);
					} else {
						SQLikeUtil.doSqlLikeAjax(self.dataSourceId, queriedDataConfig, self, renderGrid, self.cubeQuery);
					}
				} else if(self.ComponentName === gDashboard.itemGenerateManager.dxItemBasten[1].ComponentName){
					this.staticAnalysisType = self.focusItemType !== 'dataGrid' ? self.focusItemType : gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].ANALYSIS_TYPE;
					/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined' && typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT !== 'undefined') {
						this.staticOptions.alphaLevel = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].ALPHA_LEVEL;
						this.staticOptions.paired = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].PAIRED;
						this.staticOptions.alternative = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].ALTERNATIVE;
						this.staticOptions.varequal = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].VAREQUAL;
						this.staticOptions.mutest = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].MUTEST;
						/* DOGFOOT ktkang 다변량분석 추가  20210215 */
						this.staticOptions.method = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].METHOD;
						this.staticOptions.distance = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].DISTANCE;
						this.staticOptions.cluster = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].CLUSTER;
						this.staticOptions.stdev = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].STDEV;
						this.staticOptions.chisqType = gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT[1].CHISQTYPE;
					}
					if(gDashboard.analysisType === 'insertSimpleRegression' || gDashboard.analysisType === 'insertMultipleRegression') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
					} else if(gDashboard.analysisType === 'insertTtest') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
						this.staticOptions.mutest = typeof $("#mutest").dxNumberBox('instance') !== 'undefined' ? $("#mutest").dxNumberBox('instance').option('value') : self.staticOptions.mutest;
						
						if(typeof $("#paired").dxSelectBox('instance') !== 'undefined') {
							var paired = $("#paired").dxSelectBox('instance').option('value');
							if(paired == '일표본') {
								this.staticOptions.paired = 'oneSample';
							} else if(paired == '독립표본') {
								this.staticOptions.paired = 'twoSample';
							} else if(paired == '대응표본') {
								this.staticOptions.paired = 'pairedSample';
							}
						}
						
						if(typeof $("#alternative").dxSelectBox('instance') !== 'undefined') {
							var alternative = $("#alternative").dxSelectBox('instance').option('value');
							if(alternative == '양측검정') {
								this.staticOptions.alternative = 'twoSided';
							} else if(paired == '좌측검정') {
								this.staticOptions.alternative = 'lessSided';
							} else if(paired == '우측검정') {
								this.staticOptions.alternative = 'greaterSided';
							}
						}
						
						if(typeof $("#varequal").dxSelectBox('instance') !== 'undefined') {
							var paired = $("#varequal").dxSelectBox('instance').option('value');
							if(paired == '분산이 같다고 가정') {
								this.staticOptions.varequal = true;
							} else if(paired == '분산이 다르다고 가정') {
								this.staticOptions.varequal = false;
							}
						}
					} 
					/* DOGFOOT ktkang 다변량분석 추가  20210215 */
					else if(gDashboard.analysisType === 'insertZtest') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
						this.staticOptions.mutest = typeof $("#mutest").dxNumberBox('instance') !== 'undefined' ? $("#mutest").dxNumberBox('instance').option('value') : self.staticOptions.mutest;
						this.staticOptions.stdev = typeof $("#stdev").dxNumberBox('instance') !== 'undefined' ? $("#stdev").dxNumberBox('instance').option('value') : self.staticOptions.stdev;
						
						if(typeof $("#alternative").dxSelectBox('instance') !== 'undefined') {
							var alternative = $("#alternative").dxSelectBox('instance').option('value');
							if(alternative == '양측검정') {
								this.staticOptions.alternative = 'twoSided';
							} else if(paired == '좌측검정') {
								this.staticOptions.alternative = 'lessSided';
							} else if(paired == '우측검정') {
								this.staticOptions.alternative = 'greaterSided';
							}
						}
					}
					/* DOGFOOT syjin 카이제곱 검정 chiTest 추가  20210209 */
					else if(gDashboard.analysisType === 'insertChitest') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
						this.staticOptions.mutest = typeof $("#mutest").dxNumberBox('instance') !== 'undefined' ? $("#mutest").dxNumberBox('instance').option('value') : self.staticOptions.mutest;
					}
					/* DOGFOOT syjin f 검정 fTest 추가  20210215 */
					else if(gDashboard.analysisType === 'insertFtest') {
						this.staticOptions.alphaLevel = typeof $("#alpha").dxNumberBox('instance') !== 'undefined' ? $("#alpha").dxNumberBox('instance').option('value') : self.staticOptions.alphaLevel;
						this.staticOptions.mutest = typeof $("#mutest").dxNumberBox('instance') !== 'undefined' ? $("#mutest").dxNumberBox('instance').option('value') : self.staticOptions.mutest;
						
						if(typeof $("#paired").dxSelectBox('instance') !== 'undefined') {
							var paired = $("#paired").dxSelectBox('instance').option('value');
							if(paired == '일표본') {
								this.staticOptions.paired = 'oneSample';
							} else if(paired == '독립표본') {
								this.staticOptions.paired = 'twoSample';
							} else if(paired == '대응표본') {
								this.staticOptions.paired = 'pairedSample';
							}
						}
						
						if(typeof $("#alternative").dxSelectBox('instance') !== 'undefined') {
							var alternative = $("#alternative").dxSelectBox('instance').option('value');
							if(alternative == '양측검정') {
								this.staticOptions.alternative = 'twoSided';
							} else if(paired == '좌측검정') {
								this.staticOptions.alternative = 'lessSided';
							} else if(paired == '우측검정') {
								this.staticOptions.alternative = 'greaterSided';
							}
						}
						
						if(typeof $("#varequal").dxSelectBox('instance') !== 'undefined') {
							var paired = $("#varequal").dxSelectBox('instance').option('value');
							if(paired == '분산이 같다고 가정') {
								this.staticOptions.varequal = true;
							} else if(paired == '분산이 다르다고 가정') {
								this.staticOptions.varequal = false;
							}
						}
					}
					else if(gDashboard.analysisType === 'insertMultivariate') {
						this.staticOptions.method = typeof $("#method").dxSelectBox('instance') !== 'undefined' ? $("#method").dxSelectBox('instance').option('value') : self.staticOptions.method;
						this.staticOptions.distance = typeof $("#distance").dxSelectBox('instance') !== 'undefined' ? $("#distance").dxSelectBox('instance').option('value') : self.staticOptions.distance;
						this.staticOptions.cluster = typeof $("#cluster").dxNumberBox('instance') !== 'undefined' ? $("#cluster").dxNumberBox('instance').option('value') : self.staticOptions.cluster;
					}
					var params = {
							analysisType : self.staticAnalysisType === "multipleLogisticRegression" ? "logisticRegression":self.staticAnalysisType,
							measures : [],
							dimensions : [],
							globalDatas : [],
							staticOptions : $.toJSON(self.staticOptions)
					}

					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
						if(typeof item.globalData != 'undefined' && item.globalData.length > 0) {
							params.globalDatas = JSON.stringify(item.globalData);
							return false;
						}
					});

					params.measures = JSON.stringify(self.measures);
					params.dimensions = JSON.stringify(self.dimensions);
					$.ajax({
						type : 'post',
						data : params,
						url : WISE.Constants.context + '/static/analysis.do',
						success : function(data) {
							if(data.resultCode > 0) {
								gProgressbar.hide();
								WISE.alert(data.errorMsg, 'error');
								return false;
							}
							$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
								if(i > 0) {
									if(item.Name == '분석결과표'){
										item.globalData = data.data;

										var columns = new Array();
										var k = 0;
										$.each(item.globalData[0], function(key, value) {
											var tempColumns = new Object();
											tempColumns.dataField = key;
											tempColumns.UniqueName = 'DataItem' + k.toString();
											tempColumns.uniqueName = 'DataItem' + k.toString();
											tempColumns.caption = key;
											columns.push(tempColumns); 
											k++;
										});

										item.columns = columns;

										item.renderGrid(item, item.globalData);
										var dxConfigs = item.getDxItemConfigs(item.Grid);
										$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
									} else if (item.Name == '예측 결과 시각화'){
										 var ValueArray = [],
	                                        xyDataArr = [],
	                                        x={},y={},xData,yData;
	                                     $.each(data.data2,function(_j,_val){
	                                         if(_val.Name === "Constant"){
	                                         	x[_val.Name]  = parseFloat(_val.Value);
	                                         	xData = parseFloat(_val.Value)
	                                         }else{
	                                         	y[_val.Name] = parseFloat(_val.Value)
	                                         	yData = parseFloat(_val.Value)
	                                         	xyDataArr.push([x,y])
	                                         }
	                                     })
										$.each(item.filteredData,function(_i,_data){
											var returnObj = new Object()
											var returnObj2 = new Object()
											,z;
											$.each(item.dimensions,function(_j,_dim){
                                      	
                                      	if(_j == 0){
													returnObj[_dim.name] = _data[_dim.name]
													z = _data[_dim.name]
													returnObj2[_dim.name] = _data[_dim.name]
												}else{
													returnObj[_dim.name] = (1/(1+(1/Math.exp(xData+yData*z))))
													returnObj['dimension'] = _dim.name
													returnObj2[_dim.name] = _data[_dim.name]
													returnObj2['dimension'] = _dim.name
													returnObj2['realdata'] = _dim.name
												}
                                          })

                                      
                                          ValueArray.push(returnObj);
                                          ValueArray.push(returnObj2)
										})

										
										if(item.dimensions.length > 2){
											d3.select("#"+item.itemid).selectAll('svg').remove();
											d3.select("#"+item.itemid).selectAll('div').remove();
										}else{
											item.fScatterPlot(_data, item.measures, item.dimensions, ValueArray);
										}
									} else if (item.Name == '분석후 시각화'){
										var ValueArray = [];
										ValueArray.push(data.heatmapdata);
                                        item.filteredData = data.heatmapdata;
                                        
										var Dimension = new Array(),
										Measure = new Array();
										var k = 0;
										$.each(data.heatmapdata[0], function(key, value) {
											var tempColumns = new Object();
											if(key == "값"){
                                                tempColumns.dataField = key;
												tempColumns.UniqueName = 'DataItem' + k.toString();
												tempColumns.uniqueName = 'DataItem' + k.toString();
												tempColumns.caption = key;
												tempColumns.DataMember = key;
												tempColumns.name = key;
												tempColumns.captionBySummaryType = key;
												tempColumns.nameBySummaryType = key;
												Measure.push(tempColumns); 
												item.currentMeasureName = key
											}else{
                                                tempColumns.dataField = key;
												tempColumns.UniqueName = 'DataItem' + k.toString();
												tempColumns.uniqueName = 'DataItem' + k.toString();
												tempColumns.caption = key;
												tempColumns.name = key;
												tempColumns.DataMember = key;

												Dimension.push(tempColumns); 
											}
											
											
											k++;
										});
										item.dimensions = Dimension;
										item.measures = Measure;
										/*dogfoot 통계 히트맵 변경  shlim 20201109*/
										item.selectedMeasure = Measure[0];
										var resultArr = new Array();
										$.each(ValueArray,function(_i,_e){
											$.each(_e,function(_item,_obj){
												var str = new Array();
												var object = new Object();
												$.each(Dimension,function(_i,_Dim){
													str.push(_obj[_Dim.DataMember]);
												});
												$.each(Measure,function(_i,_Mea){
													object['value'] = _obj[_Mea.caption];
												});
												
												object['name'] = str.join(' - ');
												resultArr.push(object);
											})
										});
										/*dogfoot 통계 히트맵 변경  shlim 20201109*/
										var dimx=[],dimy=[],dimX =[],dimY = []
										$.each(resultArr, function(_i, _o) {
											var splitName = _o.name.split('-');
											if(splitName[0])dimx.push(splitName[0].trim());
											if(splitName[1])dimy.push(splitName[1].trim());
										});

										
										
										dimx = dimx.reduce(function(a,b){if(a.indexOf(b)<0)a.push(b);return a;},[]);
										dimy = dimy.reduce(function(a,b){if(a.indexOf(b)<0)a.push(b);return a;},[]);
										
										$.each(dimx, function(_i, _o) {
											dimX.push({'dimension' : _o})
											dimY.push({'dimension' : _o})
										});

										result = {
											data : resultArr,
											dimX : dimX,
											dimY : dimY.reverse()
										};
										
										item.fHeatMap2(_data, Measure, Dimension, result);
									} else {
										if(gDashboard.analysisType === 'insertOnewayAnova') {
											if(item.Name == '기술통계'){
												item.globalData = data.descriptive;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
											else if(item.Name == '그룹별 기술통계'){
												item.globalData = data.descriptiveDim;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
											else if(item.Name == '도수분포표'){
												item.globalData = data.frequency;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
										} else if(gDashboard.analysisType === 'insertTwowayAnova' || gDashboard.analysisType === 'insertOnewayAnova2') {
											if(item.Name == '기술통계'){
												item.globalData = data.descriptive;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
											else if(item.Name == '교차분석'){
												item.globalData = data.crossover;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
										} else if(gDashboard.analysisType === 'insertSimpleRegression' || gDashboard.analysisType === 'insertMultipleRegression'){
											if(item.Name == '회귀분석 통계량'){
												item.globalData = data.data;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else if(item.Name == '분산분석'){
												item.globalData = data.data2;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else if(item.Name == '분석 결과'){
												item.globalData = data.data3;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else {
												if(item.Name == '기술통계'){
													item.globalData = data.descriptive;

													var columns = new Array();
													var k = 0;
													$.each(item.globalData[0], function(key, value) {
														var tempColumns = new Object();
														tempColumns.dataField = key;
														tempColumns.UniqueName = 'DataItem' + i.toString();
														tempColumns.uniqueName = 'DataItem' + i.toString();
														tempColumns.caption = key;
														columns.push(tempColumns); 
														k++;
													});

													item.columns = columns;

													item.renderGrid(item, item.globalData);
													var dxConfigs = item.getDxItemConfigs(item.Grid);
													$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
												}
											}
										} else if(gDashboard.analysisType === 'insertLogisticRegression' || gDashboard.analysisType === 'insertMultipleLogisticRegression'){
											if(item.Name == '분석결과표'){
												item.globalData = data.data;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else if(item.Name == '로지스틱회귀계수'){
												item.globalData = data.data2;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + k.toString();
													tempColumns.uniqueName = 'DataItem' + k.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											} else {
												if(item.Name == '기술통계'){
													item.globalData = data.descriptive;

													var columns = new Array();
													var k = 0;
													$.each(item.globalData[0], function(key, value) {
														var tempColumns = new Object();
														tempColumns.dataField = key;
														tempColumns.UniqueName = 'DataItem' + i.toString();
														tempColumns.uniqueName = 'DataItem' + i.toString();
														tempColumns.caption = key;
														columns.push(tempColumns); 
														k++;
													});

													item.columns = columns;

													item.renderGrid(item, item.globalData);
													var dxConfigs = item.getDxItemConfigs(item.Grid);
													$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
												}
											}
										} else {
											if(item.Name == '기술통계'){
												item.globalData = data.descriptive;

												var columns = new Array();
												var k = 0;
												$.each(item.globalData[0], function(key, value) {
													var tempColumns = new Object();
													tempColumns.dataField = key;
													tempColumns.UniqueName = 'DataItem' + i.toString();
													tempColumns.uniqueName = 'DataItem' + i.toString();
													tempColumns.caption = key;
													columns.push(tempColumns); 
													k++;
												});

												item.columns = columns;

												item.renderGrid(item, item.globalData);
												var dxConfigs = item.getDxItemConfigs(item.Grid);
												$("#" + item.itemid).dxDataGrid(dxConfigs).dxDataGrid("instance");
											}
										}
									}
								}
							});

	//						var columns = new Array();
	//						var i = 0;
	//						$.each(self.globalData, function(key, value) {
	//						var tempColumns = new Object();
	//						tempColumns.dataField = key;
	//						tempColumns.UniqueName = 'DataItem' + i.toString();
	//						tempColumns.uniqueName = 'DataItem' + i.toString();
	//						tempColumns.caption = key;
	//						columns.push(tempColumns); 
	//						});

						},
						error : function(_e){
							gProgressbar.hide();
							WISE.alert('측정값이 잘못되었습니다.');
						}
					});
					gDashboard.aysCheck = false;
				}
			} else {
				if(userJsonObject.gridDataPaging === 'Y'){
					SQLikeUtil.doSqlLikePaging(self, self.Grid.GridOptions.PagingDefault, 0);
				} else {
					SQLikeUtil.doSqlLikeAjax(self.dataSourceId, queriedDataConfig, self, renderGrid, self.cubeQuery);
				}
			}
		}

		/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
		var csvDataConfig = SQLikeUtil.fromJsonforNoSummaryType(self.dimensions, measures, self.filteredData, undefined, undefined, self.orderKey);
		
		//2020.03.06 mksong 비동기화 dogfoot
		var setCsvData = function(_self,data){
			_self.csvData = data;
		}
		/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
//		SQLikeUtil.doSqlLikeAjax(self.dataSourceId, csvDataConfig, self, setCsvData);
	};
	//2020.02.04 mksong SQLLIKE doSqlLike 비동기, 동기 구분 수정 끝 dogfoot
	
	/**
	 * Initialize data used for drill-down procedures.
	 */
	this.initDrillDownData = function(_data) {
		self.drillDownData = crossfilter(_data);
		self.drillDownStack = [];
	}
	
	this.initMaxValue = function(_data){			
		$.each(self.columnNamesForBarCellMaxValue, function(_i, _d){
			var maxValue = self.getMax(_data,_d.nameBySummaryType);			
			$.each(_data,function(_ii, _dd){
				_data[_ii][_d.nameBySummaryType+'_maxValue'] = maxValue;
			});
		});
		return _data;
	}
	
	this.getMax = function(arr, prop) {
	    var max;
	    for (var i=0 ; i<arr.length ; i++) {
	        if (max == null || parseInt(arr[i][prop]) > parseInt(max[prop]))
	            max = arr[i];
	    }
	    return max[prop];
	}

	/**
	 * Map & reduce drill-down data and apply it to the grid instance.
	 */
	this.setDrillDownData = function(_dimKey) {
		var nonReducedData = self.drillDownData.allFiltered();
		var reducedData = _(nonReducedData).groupBy(_dimKey).map(function(objs, key) {
			var result = {};
			result[_dimKey] = key;
			self.reducibleMeasures.forEach(function(measureName) {
				result[measureName] = _.sumBy(objs, measureName);
			});
			return result;
		}).value();
		var newDataSource = new DevExpress.data.DataSource({
			store: reducedData,
			paginate: true
		});
		if(self.Grid && self.Grid.FilterString && self.Grid.FilterString.length > 0) {
			newDataSource.filter(self.Grid.FilterString);
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
				self.setDrillDownColumns(_nextDimKey);
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
				self.setDrillDownColumns(dimObj.name);
				self.setDrillDownData(dimObj.name);
			}	
		}
	}

	/**
	 * Returns visible column results after drill-down/drill-up operation.
	 */
	this.setDrillDownColumns = function(_dimKey) {
		var newColumns = [];
		var addRest = false;
		for (var i = 0; i < self.columns.length; i++) {
			if (addRest || self.columns[i].dataField === _dimKey) {
				newColumns.push(_.clone(self.columns[i]));
			}
			if (!addRest && self.columns[i + 1] !== undefined && self.columns[i + 1].dataType === 'number') {
				addRest = true;
			}
		}
		self.dxItem.option('columns', newColumns);
	}

	/**
	 * Begin drill-down operations by hiding all dimension columns following the first.
	 */
	this.initDrillDownOperation = function() {
		// configure settings to "true"
		self.Grid.InteractivityOptions.IsDrillDownEnabled = true;
		self.IO.IsDrillDownEnabled = true;
		// determine order of drill-down and measures to reduce
		self.rowOrder = [];
		self.reducibleMeasures = [];
		$.each(self.dxItem.getDataSource().items()[0], function(key, val) {
			var valType = typeof val;
			if (valType === 'number') {
				self.reducibleMeasures.push(key);
			}
			self.rowOrder.push({ key: key, value: valType });
		});
		// show first dimension column, then hide all dimension columns until first measure column is reached
		var columns = self.dxItem.option('columns');
		if (columns[0] != undefined && columns[0].dataType !== 'number') {
			self.setDrillDownColumns(columns[0].dataField);
			self.setDrillDownData(columns[0].dataField);
		}
	}

	/**
	 * Stop drill-down operations by restoring data and columns to its' original state.
	 */
	this.terminateDrillDownOperation = function() {
		// configure settings to "false"
		self.Grid.InteractivityOptions.IsDrillDownEnabled = false;
		self.IO.IsDrillDownEnabled = false;
		// reset columns
		self.dxItem.option('columns', self.columns);
		// reset data
		var resetData = self.drillDownData.all();
		self.initDrillDownData(resetData);
		var newDataSource = new DevExpress.data.DataSource({
			store: resetData,
			paginate: true
		});
		if(self.Grid && self.Grid.FilterString && self.Grid.FilterString.length > 0) {
			newDataSource.filter(self.Grid.FilterString);
			newDataSource.load();
		}
		self.dxItem.option('dataSource', newDataSource);
	}

	
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
					self.topMember = self.dimensionTopN[i].topMember;
					self.otherShow = self.dimensionTopN[i].TopNShowOthers;
				}
			}
		}		
		
		//topN순위 기준 측정값 계산
		var sumNm;
		$.each(self.measures,function(_index,_item){
			if(_item.name == self.topMember){
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
		
		//넘어온 차원이 차원그룹이고 차원그룹이 topN이 아닐경우 현재 함수를 넘김 
		
			
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
	
	this.renderButtons = function(_itemid) {
		
		gDashboard.itemGenerateManager.renderButtons(self);
//		var buttonPanerlId = _itemid + '_topicon';
//		var topIconPanel = $('#' + buttonPanerlId);
//		var page = window.location.pathname.split('/');
//		// 2019.12.16 수정자 : mksong 뷰어 비정형 골든레이아웃 사용유무 구분 위한 수정 끝  dogfoot
//		if (page[page.length - 1] === 'viewer.do') {
//			if(topIconPanel.children().length != 0){
//				topIconPanel.empty();
//			}
//			$('#export_popover').dxPopover({
//				height: 'auto',
//				width: 195,
//				position: 'bottom',
//				visible: false,
//			});
//			var exportDataId = this.itemid + '_topicon_exp';
//			var exportHtml = '<li id="' + exportDataId + '" title="내보내기" class="img"><img src="' + WISE.Constants.context + '/resources/main/images/ico-download_new.png" alt="이미지 다운로드"></li>';
//			
//			topIconPanel.append(exportHtml);
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
//						html += '		<li id="typeXlsx" class="exportFunction" title="EXCEL 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xlsx.png" alt="XLSX 다운로드"><span>XLSX 다운로드</span></a></li>';
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
//								if(exportType == 'typeCsv'){
//									gDashboard.downloadManager.downloadCSV(self);
//								}else if(exportType == 'typeTxt'){
//									gDashboard.downloadManager.downloadTXT(self);
//								}else if(exportType == 'typeXlsx'){
//									$('#'+_itemid).dxDataGrid('instance').exportToExcel();
//								}
//								var param = {
//									'pid': WISE.Constants.pid,
//									'userId':userJsonObject.userId,
//									'reportType':gDashboard.reportType,
//									'itemid' : self.itemid,
//									'itemNm' : self.Name
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
//		}else{
//			$('#export_popover').dxPopover({
//				height: 'auto',
//				width: 195,
//				position: 'bottom',
//				visible: false,
//			});
//			var exportDataId = this.itemid + '_topicon_exp';
//			//2020.02.20 MKSONG 다운로드 아이콘 통일 DOGFOOT
//	//		var exportHtml = '<li id="' + exportDataId + '" title="내보내기" class="img"><img src="' + WISE.Constants.context + '/resources/main/images/ico-download_new.png" alt="이미지 다운로드"></li>';
//			var exportHtml = '<li id="' + exportDataId + '" title="내보내기" class="img"><img src="' + WISE.Constants.context + '/resources/main/images/ico-download_new.png" alt="이미지 다운로드"></li>';
//	
//	        topIconPanel.find('.lm_maximise').before(exportHtml);
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
//						html += '		<li id="typeXlsx" class="exportFunction" title="EXCEL 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xlsx.png" alt="XLSX 다운로드"><span>XLSX 다운로드</span></a></li>';
//						html += '		<li id="typeCsv" class="exportFunction" title="CSV 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcexcell.png" alt="CSV 다운로드"><span>CSV 다운로드</span></a></li>';
//						html += '		<li id="typeTxt" class="exportFunction" title="TXT 다운로드"><a href="#"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_txt.png" alt=""><span>TXT 다운로드</span></a></li>';
//						html += '	</ul>';
//						html += '</div>';
//	                    return html;
//					},
//					onContentReady: function() {
//						$('.exportFunction').each(function(){
//							$(this).click(function(){
//								var exportType = $(this).attr('id');
//								if(exportType == 'typeCsv'){
//									gDashboard.downloadManager.downloadCSV(self);
//								}else if(exportType == 'typeTxt'){
//									gDashboard.downloadManager.downloadTXT(self);
//								}else if(exportType == 'typeXlsx'){
//									$('#'+_itemid).dxDataGrid('instance').exportToExcel();
//								}
//								var param = {
//									'pid': WISE.Constants.pid,
//									'userId':userJsonObject.userId,
//									'reportType':gDashboard.reportType,
//									'itemid' : self.itemid,
//									'itemNm' : self.Name
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
//			// tracking conditions clear
//			if (self.IO && self.IO['MasterFilterMode']) {
//				self.trackingClearId = self.itemid + '_topicon_tracking_clear';
//				
//				//20200506 ajkim 마스터필터가 적용된 경우에만 마스터 필터 초기화 활성화 dogfoot
//				var trackingClearHtml;
//				if(self.IO['MasterFilterMode'] === 'Off')
//					trackingClearHtml = '<li id="' + self.trackingClearId + '" title="마스터 필터 초기화" class="nofilter invisible"></li>';
//				else
//					trackingClearHtml = '<li id="' + self.trackingClearId + '" title="마스터 필터 초기화" class="nofilter"></li>';
//				topIconPanel.find('.lm_maximise').before(trackingClearHtml);
//				
//				$("#" + self.trackingClearId).click(function(_e) {
//					/* DOGFOOT hsshim 2020-02-06 마스터 필터 기능 리팩토링 적용 (코드 정리) */
//					gDashboard.filterData(self.itemid, []);
//					self.clearTrackingConditions();
//				});
//			}
//
//			if(self.IO && typeof self.IO['IsDrillDownEnabled'] !== 'undefined'){
//				self.DrilldownClearId = self.itemid + '_topicon_drilldown_clear';
//				//2020.01.22 MKSONG 아이콘 수정 DOGFOOT
//				var DrillDownClearHtml = '<li id="' + self.DrilldownClearId + '" title="드릴업" class="back"></li>';
//				topIconPanel.find('.lm_maximise').before(DrillDownClearHtml);
//				
//				$("#" + self.DrilldownClearId).click(function(_e) {
//					self.drillUp();
//				});
//			}
//		}
	};
};

WISE.libs.Dashboard.DataGridFieldManager = function() {
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
	
	this.dimensionTopN = new Array();
	
	this.all = [];
	this.columns = [];
	this.sparkline = [];
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
		this.columns = [];
		this.sparkline = [];
		this.hide_column_list_dim = [];
		this.hide_column_list_mea = [];
//		this.hide_column_list = {'dimension': [],'measure':[]};
		this.meta = gDashboard.structure.ReportMasterInfo.dataSource;
		
		this.initialized = true;
	};
	
	this.setMetaTables = function(tables){
		this.meta.tables = tables;
	}
	
	this.deleteField = function(_uid) {
		this.columnMeta[_uid] = undefined;
		this.deleteFieldByType(_uid, 'all');
		this.deleteFieldByType(_uid, 'columns');
		this.deleteFieldByType(_uid, 'sparkline');
		this.deleteFieldByType(_uid, 'hide_column_list_dim');
		this.deleteFieldByType(_uid, 'hide_column_list_mea');
	};
	
	this.deleteFieldByType = function(_uid, _type) {
		var index = -1, basket = this[_type];
		$.each(basket, function(_i,_o) {
			if (_uid === _o.uid) {
				index = _i;
				return false;
			}
		});
		if (index > -1) basket.splice(index,1);
	};
	
	this.addColumnField = function(_fieldOption) {
		var o = this.columnMeta[_fieldOption.wiseUniqueName];


		if(_fieldOption.format == 'number'){
			o.format = _fieldOption.format;
			o.precision = _fieldOption.precision;
			o.precisionOption = _fieldOption.precisionOption;
			o.wiseFormat = _fieldOption.wiseFormat;	
		}
		this.columns.push(o);
	};
	
	this.addSparklineField = function(_fieldOption) {
		var o = this.columnMeta[_fieldOption.wiseUniqueName];


		this.sparkline.push(o);
	};
	
	this.addHideColumnListDimField = function(_fieldOption) {
		var o = this.columnMeta[_fieldOption.wiseUniqueName];


		o.format = _fieldOption.format;
		o.precision = _fieldOption.precision;
		o.precisionOption = _fieldOption.precisionOption;
		o.wiseFormat = _fieldOption.wiseFormat;
		this.hide_column_list_dim.push(o);
	};
	
	this.addHideColumnListMeaField = function(_fieldOption) {
		var o = this.columnMeta[_fieldOption.wiseUniqueName];


		o.format = _fieldOption.format;
		o.precision = _fieldOption.precision;
		o.precisionOption = _fieldOption.precisionOption;
		o.wiseFormat = _fieldOption.wiseFormat;
		this.hide_column_list_mea.push(o);
	};
	
	this.initAllFields = function() {


		$.each(this.columnMeta, function(_k, _o) {
			var checker = true;

			_.each(self.columns, function(_r) {
				if (_k === _r.uid) {
					checker = false;
					return false;
				}
			});
			
			_.each(self.sparkline, function(_r) {
				if (_k === _r.uid) {
					checker = false;
					return false;
				}
			});
			
			_.each(self.hide_column_list_dim, function(_r) {
				if (_k === _r.uid) {
					checker = false;
					return false;
				}
			});
			
			_.each(self.hide_column_list_mea, function(_r) {
				if (_k === _r.uid) {
					checker = false;
					return false;
				}
			});
			
			if (checker) {
				self.all.push(_o);
			}
			else {
				checker = true;
			}
		});
	};
	
	
	this.populate = function() {
		this.isChange = false;
		
		if (this.columns.length === 0) {
			WISE.alert('열 필드에 컬럼을 추가 해주십시오.');
		}
		else {
			if (WISE.Context.isCubeReport) {
				var selected = {
					dim: [],
					mea: []
				};
				
				// columns
				_.each(this.columns, function(_c) {
//					selected.dim.push(self.columnMeta[_c.uid]);
					var colUid = {uid : _c.uid};
					selected.dim.push(colUid);
				});
				
				// sparkline
				_.each(this.sparkline, function(_r) {
//					selected.dim.push(self.columnMeta[_r.uid]);
					var rowsUid = {uid : _r.uid};
					selected.dim.push(rowsUid);
				});
				
				// hide_column_list_dim
				_.each(this.hide_column_list_dim, function(_d) {
					var o = self.columnMeta[_d.uid];
					if ($.type(o.exp) === 'object') return true;
//					selected.mea.push(o);
					var dataUid = {uid : _d.uid};
					selected.hide_column_list_dim.push(dataUid);
				});
				
				// hide_column_list_mea
				_.each(this.hide_column_list_mea, function(_d) {
					var o = self.columnMeta[_d.uid];
					if ($.type(o.exp) === 'object') return true;
//					selected.mea.push(o);
					var dataUid = {uid : _d.uid};
					selected.hide_column_list_mea.push(dataUid);
				});
				
				gDashboard.queryHandler.queryByGeneratingSql = true;
				gDashboard.queryHandler.selected = selected;
				gDashboard.queryHandler.query();
			}
			else {
				var itemGenerateManager = gDashboard.itemGenerateManager;
				_.each(itemGenerateManager.dxItemBasten, function(_item) {
					_item.populate();
				});
			}
		}
	};
	
	this.setDataItemByField = function(_fieldlist, _optionList){
		this.DataItems = {};
		self.DataItems['Dimension'] = [];
		self.DataItems['Measure'] = [];
		
		for(var i = 0; i < _fieldlist.length; i++){
			if($(_fieldlist[i]).attr('dataType')){
				if($(_fieldlist[i]).attr('dataType') == 'dimension' || $(_fieldlist[i]).attr('dataType') == 'sparklineArgument'){
					var dataItem = {'DataMember': {}, 'UniqueName': ""};
					dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
					dataItem['Name'] = $(_fieldlist[i]).attr('caption');
//					dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
					/*dogfoot 정렬기준 항목 필드에 있을때만 SortByMeasure 추가 shlim 20201126*/
					var sortMeaId;
					$.each(_fieldlist,function(_j,_f){
						if($(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem') === _f.attr('dataitem'))
							sortMeaId = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
					})
					dataItem['SortByMeasure'] = sortMeaId;
					dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
					if(WISE.Context.isCubeReport) {
						dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
					}
					dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
					/* LSH topN */
					if($(_fieldlist[i]).attr('TopNEnabled')=="true"){
						dataItem['TopNEnabled'] = ($(_fieldlist[i]).attr('TopNEnabled')==='true');
						dataItem['TopNOrder'] = ($(_fieldlist[i]).attr('TopNOrder')==='true');
						dataItem['TopNCount'] = $(_fieldlist[i]).attr('TopNCount');
						dataItem['TopNMeasure'] = $(_fieldlist[i]).attr('TopNMeasure');
						dataItem['topMember'] = $(_fieldlist[i]).attr('topMember');
						if($(_fieldlist[i]).attr('TopNShowOthers')==='true'){
							dataItem['TopNShowOthers'] = true;
						}
					}
					/*dogfoot 통계 분석 추가 shlim 20201103*/
					var ctype = ""
						if(typeof $(_fieldlist[i]).attr('containerType') != 'undefined' && $(_fieldlist[i]).attr('containerType') != ""){
							ctype = $(_fieldlist[i]).attr('containerType')
						}
					dataItem['ContainerType'] = ctype;

					self.DataItems['Dimension'].push(dataItem);
				} else if($(_fieldlist[i]).attr('dataType') == 'measure' || $(_fieldlist[i]).attr('dataType') == 'sparkline' || $(_fieldlist[i]).attr('dataType') == 'delta'){
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
					dataItem['Highlightstartendpoints'] = $(_fieldlist[i]).attr('highlightstartendpoints');
					dataItem['Highlightminmaxpoints'] = $(_fieldlist[i]).attr('highlightminmaxpoints');
					dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
					/*dogfoot 통계 분석 추가 shlim 20201103*/
					var ctype = ""
						if(typeof $(_fieldlist[i]).attr('containerType') != 'undefined' && $(_fieldlist[i]).attr('containerType') != ""){
							ctype = $(_fieldlist[i]).attr('containerType')
						}
					dataItem['ContainerType'] = ctype;


					self.DataItems['Measure'].push(dataItem);
				}
			}else{
				if($(_fieldlist[i]).attr('data-field-type') == 'dimension'){
					var dataItem = {'DataMember': {}, 'UniqueName': ""};
					dataItem['DataMember'] = $(_fieldlist[i]).attr('UNI_NM');
					dataItem['Name'] = $(_fieldlist[i]).attr('caption');
//					dataItem['SortByMeasure'] = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
					/*dogfoot 정렬기준 항목 필드에 있을때만 SortByMeasure 추가 shlim 20201126*/
					var sortMeaId;
					$.each(_fieldlist,function(_j,_f){
						if($(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem') === _f.attr('dataitem'))
							sortMeaId = $(_fieldlist[i]).find('.measureList').find('.on').attr('dataitem');
					})
					dataItem['SortByMeasure'] = sortMeaId;
					dataItem['UniqueName'] = $(_fieldlist[i]).attr('dataitem');
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
					if(WISE.Context.isCubeReport) {
						dataItem['CubeUniqueName'] = $(_fieldlist[i]).attr('cubeuninm');
					}
					dataItem['SortOrder'] = $(_fieldlist[i]).attr('class').indexOf('arrayUp') > 0 ? 'ascending' : 'descending';
					/* LSH topN */
					if($(_fieldlist[i]).attr('TopNEnabled')=="true"){
						dataItem['TopNEnabled'] = ($(_fieldlist[i]).attr('TopNEnabled')==='true');
						dataItem['TopNOrder'] = ($(_fieldlist[i]).attr('TopNOrder')==='true');
						dataItem['TopNCount'] = $(_fieldlist[i]).attr('TopNCount');
						dataItem['TopNMeasure'] = $(_fieldlist[i]).attr('TopNMeasure');
						dataItem['topMember'] = $(_fieldlist[i]).attr('topMember');
						if($(_fieldlist[i]).attr('TopNShowOthers')==='true'){
							dataItem['TopNShowOthers'] = true;
						}
					}
					/*dogfoot 통계 분석 추가 shlim 20201103*/
					var ctype = ""
						if(typeof $(_fieldlist[i]).attr('containerType') != 'undefined' && $(_fieldlist[i]).attr('containerType') != ""){
							ctype = $(_fieldlist[i]).attr('containerType')
						}
					dataItem['ContainerType'] = ctype;

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
					dataItem['Highlightstartendpoints'] = $(_fieldlist[i]).attr('highlightstartendpoints');
					dataItem['Highlightminmaxpoints'] = $(_fieldlist[i]).attr('highlightminmaxpoints');
					dataItem['SummaryType'] = $(_fieldlist[i]).find('.on >.summaryType').attr('summarytype');
					/*dogfoot 통계 분석 추가 shlim 20201103*/
					var ctype = ""
					if(typeof $(_fieldlist[i]).attr('containerType') != 'undefined' && $(_fieldlist[i]).attr('containerType') != ""){
						ctype = $(_fieldlist[i]).attr('containerType')
					}
					dataItem['ContainerType'] = ctype;


					self.DataItems['Measure'].push(dataItem);
				}
			}

		}
		return self.DataItems;
	};
	
	this.setAllFields = function(_allFieldSet){
		this.all = _allFieldSet;
    	_.each(this.all, function(_uid) {
        	var o =self.columnMeta[_uid];
    		self.all.push(o);
        });    	
    	
    	return this;
	}
	
	this.getherFieldsByFieldSet = function(_fieldSet) {
		var rows = _fieldSet.rows;
    	var columns = _fieldSet.columns;
    	var datas = _fieldSet.datas;
    	
//    	var columnMetaSet = _.pluck(this.columnMeta, 'uid');
    	var columnMetaSet = _.map(this.columnMeta, 'uid');
    	var all = [].concat(rows).concat(columns).concat(datas);
    	all = _.difference(columnMetaSet, all);
    	
    	this.rows = [];
    	_.each(rows, function(_uid) {
    		var o = self.columnMeta[_uid];
    		self.rows.push(o);
    	});
    	
    	this.columns = [];
    	_.each(columns, function(_uid) {
    		var o =self.columnMeta[_uid];
    		self.columns.push(o);
    	});
    	
    	this.datas = [];
    	_.each(datas, function(_uid) {
    		var o =self.columnMeta[_uid];
    		self.datas.push(o);
    	});
    	
    	this.all = [];
    	_.each(all, function(_uid) {
        	var o =self.columnMeta[_uid];
    		self.all.push(o);
        });    	
    	
    	return this;
	};
	/*dogfoot 통계 분석 추가 shlim 20201103*/
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
	/*dogfoot 통계 오류 수정  shlim 20201109*/
	this.setHiddenMeasuresByField = function(_hiddenMeasure){
	 	this.HiddenMeasures = {'Measure' : []};
	 	_.each(_hiddenMeasure,function(_a){
	 		var Value = {'UniqueName' : _a.uniqueName};
	 		self.HiddenMeasures['Measure'].push(Value);
	 	})
	 	return self.HiddenMeasures;
	 };
	
};

