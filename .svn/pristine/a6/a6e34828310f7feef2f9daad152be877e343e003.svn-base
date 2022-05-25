function aa() {
/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
	if(gDashboard.reportType === 'DSViewer'){
		WISE.alert("현재 페이지에서 사용할 수 없는 기능입니다.");
		return;
	}
	/* 개발 cshan 1211
	 *  height 250 -> 160
	 *  */
	/*1212 cshan 디자인 적용 DOGFOOT*/
	/* DOGFOOT hsshim 2020-01-15 주제영역 적용 */
	$('#newDataset_popover').dxPopover({
		height: 'auto',
		width: 310 + (gDashboard.fontManager.getFontSizeNumber(0, 'Menu') * 20),
		position: 'left',
		visible: true,
	});
	var menuConfigJson = userJsonObject.menuconfig.Menu;
	var p = $('#newDataset_popover').dxPopover('instance');
	var selectTypeListHeight = 320;
	p.option({
		target:$('.db'),
		contentTemplate: function(contentElement) {
			contentElement.empty();
			contentElement.append('<div id="selectType"></div>');
			var selectTypeList = [];
			/* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
//			if(gDashboard.reportType != undefined){
				/*1212 cshan 디자인 적용 DOGFOOT*/
				if(typeof WISE.Context.isCubeReport == 'undefined' && !(gDashboard.reportType == 'Spread' || gDashboard.reportType == 'Excel')){
					selectTypeList = [
						{caption:'주제 영역 데이터',value:'CUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.CUBE},
						{caption:'신규 데이터 집합(주제 영역 기준)',value:'TypeCUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetCube},
						{caption:'신규 데이터 집합(데이터 원본 기준)',value:'TypeDS',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDs},
						/* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
						{caption:'신규 데이터 집합(이기종 조인)',value:'TypeDSJOIN',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDsJoin},
						{caption:'신규 데이터 집합(쿼리 직접 입력)',value:'TypeQuery',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_sqlInput.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSQL},
						{caption:'신규 데이터 집합(단일 테이블)',value:'TypeSingle',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_singleTable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSingleDs},
						{caption:'사용자 데이터 업로드',value:'TypeCustom',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exceltable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetUser},
						{caption:'기존 데이터 집합',value:'TypeExist',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exist.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetLoad},
					];
					/* 개발 cshan 1211
					 *  height 160 -> 200
					 *  */
				}else if(gDashboard.reportType == 'Spread' || gDashboard.reportType == 'Excel'){
					selectTypeList = [
//						{caption:'주제 영역 데이터',value:'CUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.CUBE},
						{caption:'신규 데이터 집합(주제 영역 기준)',value:'TypeCUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetCube},
						{caption:'신규 데이터 집합(데이터 원본 기준)',value:'TypeDS',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDs},
						{caption:'신규 데이터 집합(이기종 조인)',value:'TypeDSJOIN',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDsJoin},
						{caption:'신규 데이터 집합(쿼리 직접 입력)',value:'TypeQuery',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_sqlInput.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSQL},
						{caption:'신규 데이터 집합(단일 테이블)',value:'TypeSingle',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_singleTable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSingleDs},
						{caption:'사용자 데이터 업로드',value:'TypeCustom',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exceltable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetUser},
						{caption:'기존 데이터 집합',value:'TypeExist',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exist.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetLoad},
					];

				}
				else if((typeof WISE.Context.isCubeReport != 'undefined' && !WISE.Context.isCubeReport)){
					selectTypeList = [
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
						{caption:'신규 데이터 집합(주제 영역 기준)',value:'TypeCUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetCube},
						{caption:'신규 데이터 집합(데이터 원본 기준)',value:'TypeDS',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDs},
						{caption:'신규 데이터 집합(이기종 조인)',value:'TypeDSJOIN',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDsJoin},
						{caption:'신규 데이터 집합(쿼리 직접 입력)',value:'TypeQuery',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_sqlInput.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSQL},
						{caption:'신규 데이터 집합(단일 테이블)',value:'TypeSingle',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_singleTable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSingleDs},
						{caption:'사용자 데이터 업로드',value:'TypeCustom',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exceltable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetUser},
						{caption:'기존 데이터 집합',value:'TypeExist',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exist.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetLoad},
					];
				}else if(WISE.Context.isCubeReport){
					selectTypeList = [
						{caption:'주제 영역 데이터',value:'CUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.CUBE}
						];
				}
//			}else{//DashAny 기준
//				selectTypeList = [
//					{caption:'주제 영역 데이터',value:'CUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.CUBE},
//					{caption:'신규 데이터 집합(주제 영역 기준)',value:'TypeCUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetCube},
//					{caption:'신규 데이터 집합(데이터 원본 기준)',value:'TypeDS',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDs},
//					{caption:'신규 데이터 집합(쿼리 직접 입력)',value:'TypeQuery',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_sqlInput.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSQL},
//					{caption:'신규 데이터 집합(단일 테이블)',value:'TypeSingle',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_singleTable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSingleDs},
//					{caption:'사용자 데이터 업로드',value:'TypeCustom',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exceltable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetUser},
//					{caption:'기존 데이터 집합',value:'TypeExist',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exist.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetLoad},
//					];
//			}
			
			var _item = 0;
			var firstItem = 7;
			var splitIndex = [];
			$.each(selectTypeList, function(i, data) {
				if(data.visible && i < firstItem) firstItem = i;
				if(data.visible){
					if(i < selectTypeList.length % 6){
						splitIndex[0] = i+1;
					}else if(i <= 3 + selectTypeList.length % 6){
						splitIndex[1] = i+1;
					}
					_item++;
				}
			});
			
			$('#newDataset_popover').dxPopover('instance').option('height', 'auto');
			selectTypeListHeight = _item * 52 + 20;
			/* DOGFOOT ktkang KERIS 안쓰는 기능 제거  수정 끝 20200123 */
			
			if(_item !== 1){
				$('#selectType').dxList({
					dataSource:selectTypeList,
					displayExpr:'caption',
					keyExpr:'value',
					width:270 + (gDashboard.fontManager.getFontSizeNumber(0, 'Menu') * 20),
//					height:selectTypeListHeight,
					itemTemplate: function(data, index) {
			            var result = $("<div>");
			            $("<img>").attr("src", data.ImageSrc).css('width','32px').appendTo(result);
			            $("<span>").text(data.caption).css('padding-left','5px').attr('style', gDashboard.fontManager.getCustomFontStringForMenu(14)).appendTo(result);
			            return result;
					},
					onItemClick:function(_e){
						if(_e.itemData.value == 'TypeQuery'){
							var kk = new WISE.libs.Dashboard.DatasourceSelector();
							kk.render({ userId: userJsonObject.userId, userNo: userJsonObject.userNo, dsType: 'DS_SQL' });
						}else if(_e.itemData.value == 'TypeDS'){
							var kk = new WISE.libs.Dashboard.DatasourceSelector();
							kk.render({ userId: userJsonObject.userId, userNo: userJsonObject.userNo, dsType: 'DS', joinType: 'N' });
						/* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
						}else if(_e.itemData.value == 'TypeDSJOIN'){
							var kk = new WISE.libs.Dashboard.DatasourceSelector();
							kk.render({ userId: userJsonObject.userId, userNo: userJsonObject.userNo, dsType: 'DS', joinType: 'Y' });
						}else if(_e.itemData.value == 'TypeSingle'){
							var kk = new WISE.libs.SingleInput();
							kk.render();
						}else if(_e.itemData.value == 'TypeCUBE'){
							var kk = new WISE.libs.Dashboard.DatasourceSelector();
							kk.render({ userId: userJsonObject.userId, userNo: userJsonObject.userNo, dsType: 'CUBE' });
						}else if(_e.itemData.value == 'CUBE'){
							var kk = new WISE.libs.CubeData();
							kk.render();
						}else if(_e.itemData.value == 'TypeCustom'){
							gDashboard.dataSetCreate.openDataUpload();
						}else if(_e.itemData.value == 'TypeExist'){
							gDashboard.datasetMaster.openDataset();
						}
						p.hide();
					},
				})
				
				$.each(splitIndex, function(_i, _index){
					$('#selectType .dx-scrollview-content').children().eq(_index).css("border-top-color", "#6799FF");
				})
				$('#selectType .dx-scrollview-content').children().eq(firstItem).css("border-top", "none");
			}
			else {
				//2020.12.30 MKSONG 데이터 집합 추가 오류 수정 DOGFOOT
				switch(selectTypeList[firstItem].value){
				case 'TypeQuery':
					var kk = new WISE.libs.Dashboard.DatasourceSelector();
					kk.render({ userId: userJsonObject.userId, userNo: userJsonObject.userNo, dsType: 'DS_SQL' });
					break;
				case 'TypeDS': 
					var kk = new WISE.libs.Dashboard.DatasourceSelector();
					kk.render({ userId: userJsonObject.userId, userNo: userJsonObject.userNo, dsType: 'DS', joinType: 'N' });
					break;
				/* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
				case 'TypeDSJOIN': 
					var kk = new WISE.libs.Dashboard.DatasourceSelector();
					kk.render({ userId: userJsonObject.userId, userNo: userJsonObject.userNo, dsType: 'DS', joinType: 'Y' });
					break;
				case 'TypeSingle':
					var kk = new WISE.libs.SingleInput();
					kk.render();
					break;
				case 'CUBE':
					var kk = new WISE.libs.CubeData();
					kk.render();
					break;
				case 'TypeCustom':
					gDashboard.dataSetCreate.openDataUpload();
					break;
				case 'TypeExist':
					gDashboard.datasetMaster.openDataset();
					break;
				}
				p.hide();
			}
			
		},
	});
}

function bb() {
	var jj = gDashboard.dataSetCreate;
	jj.render();
}

function connectDataset() {
	var connectDatasetSpread = new WISE.libs.ConnectDataSetSpread();
	connectDatasetSpread.render();
}

WISE.libs.DataSet = function() {
	var self = this;

	this.lookUpItems = new Array();
	this.infoTreeList = new Array();
	this.paramTreeList = new Array();
	this.subjectInfoList = new Array();
	/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200212 */
	this.cubeRelationTable = new Array();
	/* DOGFOOT ktkang 필요없는 부분 삭제  20200221 */

	this.createDxItems = function() {
//		var treeViewIns;
		
//		treeViewIns = $("#allList").dxTreeView({ 
////			dataSource: self.infoTreeList[data['DATASET_NM']],
//			expanded: true,
//			parentIdExpr: "PARENT_ID",
//			keyExpr: "ORDER",
//			displayExpr: "CAPTION",
//			dataStructure: "plain",
//			onItemClick: function(e) {
//			},
//            onContentReady: function(_e) {
//            	if($(_e.element.get(0)).find('ul.dx-treeview-node-container').get(1)) {
//            		var dataSource, dataSourceId;
//            		var fieldList = $(_e.element.get(0)).find('ul.dx-treeview-node-container').get(1).children;
//            		for(var i =0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
//            			if(_e.component._dataSource._items[0].CAPTION == gDashboard.dataSourceManager.datasetInformation[_.keys(gDashboard.dataSourceManager.datasetInformation)[i]].DATASET_NM){
//            				dataSourceId = gDashboard.dataSourceManager.datasetInformation[_.keys(gDashboard.dataSourceManager.datasetInformation)[i]].mapid;
//            				if(gDashboard.dataSourceManager.datasetInformation[_.keys(gDashboard.dataSourceManager.datasetInformation)[i]].DATASET_TYPE == "DataSetCube"){
//            					dataSource = gDashboard.dataSourceManager.datasetInformation[_.keys(gDashboard.dataSourceManager.datasetInformation)[i]].SEL_ELEMENT.SELECT_CLAUSE;	
//            				} else{
//            					dataSource = gDashboard.dataSourceManager.datasetInformation[_.keys(gDashboard.dataSourceManager.datasetInformation)[i]].DATA_META;
//            				}
//            			}	
//            		}
//
//
//            		for(var i = 0; i < dataSource.length; i++){
//            			for(var j = 0; j < fieldList.length; j++){
//            				if(fieldList[j].innerText == dataSource[i].CAPTION){
//            					$(fieldList[j]).addClass('wise-column-chooser wise-area-field wise-area-box');
//            					$(fieldList[j]).attr('data-field-uname',dataSource[i].UNI_NM)
//            					.attr('data-source-id',dataSourceId)
//            					.attr('prev-container','allList');
////          					$(fieldList[j]).attr('data-table-uname',dataSource[i].UNI_NM.split(',').substr(0,dataSource[i].UNI_NM.split(',').length-1);
//            					if(dataSource[i].TYPE == 'DIM'){
//            						$(fieldList[j]).attr('data-field-type', 'dimension');	
//            					}else if(dataSource[i].TYPE == 'MEA'){
//            						$(fieldList[j]).attr('data-field-type', 'measure');	
//            					}
//
//            					$(fieldList[j]).draggable(gDashboard.dragNdropController.draggableOptions);
//            				}
//            			}
//            		}
//            	}
//            }
//		}).dxTreeView("instance");
		
//		if(gDashboard.reportType == "Spread" || gDashboard.reportType == "Excel"){			
//			$("#dataSetLookUp").dxList({		
//				selectionMode: "single",
//			    noDataText: gMessage.get('WISE.message.page.common.nodata'),
//			    onItemClick: function(e) {
//					/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 오류 수정 */
//			    	if(WISE.Constants.editmode != 'viewer'){
//		            	$('.drop-down.tree-menu > ul').empty();	
//		            }else{
//		            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
//		            }
//					if(e.itemData != '' && e.itemData != undefined){
//						/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 오류 수정 */
//						var dataSourceId = self.infoTreeList[e.itemData][0]['DATASOURCE'];
//						if(dataSourceId){	
//							var dd = gDashboard.dataSourceManager.datasetInformation[dataSourceId];
//            				if(dd.SHEET_ID){
//            					$("#dataSetLookUp").dxList('instance').option('selectedItemKeys',dd.DATASET_NM);
//								//gDashboard.spreadsheetManager.spreadJS.setActiveSheet(gDashboard.spreadsheetManager.getSheetNameFromID(Number(dd.SHEET_ID.substring(5))-1));
//            					gDashboard.spreadsheetManager.spreadJS.setActiveSheet(dd.SHEET_NM);
//            				}
//	            																
//						}
//						
//					}
//				}
//			}).dxList("instance");
//			
//			$("#dataSetLookUp").attr("style",'width:100% !important');
//			
//		}else{
			var $dataSetLookUp = $("#dataSetLookUp");
			
			if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
				$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
			}
			
			$dataSetLookUp.dxLookup({
				item:{},
				placeholder: "데이터 집합을 선택하세요",
				showPopupTitle: false,
				searchEnabled: false,
				showPopupTitle: false,
				showCancelButton: false,
				closeOnOutsideClick: true,
				onValueChanged: function(e) {
					/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 오류 수정 */
					if(WISE.Constants.editmode != 'viewer'){
		            	$('.drop-down.tree-menu > ul').empty();	
		            }else{
		            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
		            }
					if(e.value != '' && e.value != undefined){
						/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 오류 수정 */
						//console.log(self.infoTreeList[e.value]);
						var dataSourceId = self.infoTreeList[e.value][0]['DATASOURCE'];
						if(dataSourceId != undefined && typeof self.infoTreeList[e.value][0]['TYPE'] == 'undefined'){
							self.insertDataSet(self.infoTreeList[e.value], dataSourceId);	
						} else if(dataSourceId != undefined && self.infoTreeList[e.value][0]['FLD_TYPE'] == 'CUBE') {
							var n = new WISE.libs.CubeData();
							/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200212 */
							var $cubeFieldSearch = $("#cubeFieldSearch");
							if($("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch").length > 0 && WISE.Constants.editmode == "viewer"){
								$cubeFieldSearch = $("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch")
							}
							var searchText = $cubeFieldSearch.dxTextBox('instance').option('value');
							n.insertDataSet(self.infoTreeList[e.value], dataSourceId, searchText);
							/* DOGFOOT ktkang 주제영역 일 때 조회 전 기본 값 셋팅  20200214 */
							if(typeof gDashboard.dataSourceManager.datasetInformation[dataSourceId] == 'undefined' || gDashboard.dataSourceManager.datasetInformation[dataSourceId] == null) {
								gDashboard.dataSourceManager.datasetInformation[dataSourceId] = { 
										data: [],
										DATASRC_ID: self.infoTreeList[e.value][0]['DATASRC_ID'],
										DATASRC_TYPE: 'CUBE',
										DATASET_NM: e.value,
										DATASET_TYPE: "CUBE",
										mapid: dataSourceId
								};
							}
						}
					}
				}
			});
//		}
		
		
		
		
	};
	
	this.render = function() {
		var dataSetInfos;
		var treeViewIns;

		$("#data_popup").empty();
		
		self.createDxItems();

		var html = "				<div class=\"modal-inner\"  style='height: calc(100% - 85px);'>\r\n" + 
		"                    <div class=\"modal-body\" style='height:100%;'>\r\n" + 
		"	                    <div class=\"row\" style='height:100%;'>\r\n" +
		" 		                   <div class=\"column\" style=\"height:100%;\">\r\n" +
		"       	                 <div class=\"modal-article\" style='height:100%;'>\r\n" + 
		"           	                 <div class=\"modal-tit\">\r\n" + 
		"	            	                 <span>데이터집합 목록</span>\r\n" + 
		"               	             </div>\r\n" + 
		" 							  	 <div id=\"data_list\" class=\"data_list\" style=\"float:left; margin-right:20px;\"></div>" +
		"                          	 </div>\r\n" + 
		"                      	  </div>\r\n" + 
		"                    	</div>\r\n" + 
		"                  	 </div>\r\n" + 
		"                    <div class=\"modal-footer\" style=\"position: absolute; width:100%; bottom: 0; \">\r\n" + 
		"                        <div class=\"row center\">\r\n" + 
		"                            <a id=\"btn_subject_check\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
		"                            <a id=\"btn_subject_cancel\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                </div>";
		
		var dsType = "";
		
		$.each(userJsonObject.menuconfig.Menu.DATASET_MENU_TYPE, function(_type, _visible){
		    if(_visible && _type != "DataSetLoad" && _type != "CUBE" && _type != "DataSetUser"){
		    	if(dsType === "")
		    		dsType += _type;
		    	else
		    		dsType += ("," + _type);
		    	
		    	if(_type === 'DataSetSingleDs')
		    		dsType += ",DataSetSingleDsView"
		    }
		});
		
		var showFlag = true;		
		$("#data_popup").dxPopup({
			showCloseButton: false,
			showTitle: true,
			visible: true,
			title: "데이터 집합 불러오기",
			closeOnOutsideClick: false,
			contentTemplate: function() {
				return html;
			},
			width: '90vw',
            height: '90vh',
            maxWidth: 600,
            maxHeight: 850,
			onShown: function () {
				//두번호출안되게
				if(showFlag) {
					$.ajax({
						type : 'post',
						data:{
							'userId':userJsonObject.userId,
							'dsType': dsType
						},
						url : WISE.Constants.context + '/report/dataSetList.do',
						complete: function() {
							$('#progress_box').css({'display' : 'none'});
						},
						success : function(data) {
							var DATASET_ID;
							var DATASRC_TYPE;
							var DATASET_NAME;
	
							$('#progress_box').css({'display' : 'none'});
	
							data = jQuery.parseJSON(data);
	
							var dataSetFolders = data["dataSetFolders"];
	
							$("#data_list").dxTreeView({ 
								dataSource: dataSetFolders,
								dataStructure: "plain",
								parentIdExpr: "PARENT_FLD_ID",
								keyExpr: "FLD_ID",
								displayExpr: "FLD_NM",
								width: 500,
								height: 'calc(100% - 85px)',
								/* DOGFOOT hsshim 2020-02-03 데이터 집합 불러오기 UI에 탐색박스 추가 */
								searchEnabled: true,
								searchMode: 'contains',
								onInitialized:function(_e){
			            			$.each(_e.component.option('dataSource'),function(_i,_items){
			            				if(typeof _items['PARENT_FLD_ID'] == 'undefined') {
			            					_items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
			            				} else {
			            					_items['icon']= WISE.Constants.context + '/resources/main/images/ico_dataset.png';
			            				}
			            			});
			            		},
			            		onContentReady: function(){
			            			gDashboard.fontManager.setFontConfigForListPopup('data_list');
			        			},
								onItemClick: function(e) {
									DATASET_ID = e.itemData['DATASET_ID'];
									DATASET_NAME = e.itemData['FLD_NM'];
								}
							});
	
							$("#btn_subject_check").dxButton({
								text: "확인",
								type: "normal",
								onClick: function(e) {
									if(DATASET_ID != null){
	
										var sameName = 0;
										$.each(gDashboard.dataSetCreate.lookUpItems,function(_i,_data){
											if(DATASET_NAME == _data.DATASET_NM){
												sameName = 1;
											}
										});
										
										if(sameName == 1) {
											WISE.alert('현재 같은 이름의 데이터 집합명이 존재합니다.');
											return false;
										}
										/* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
										WISE.Context.isCubeReport = false;
										
										var confirmOk;
										//2020.02.12 mksong 뷰어 비정형 컬럼선택기 오류 수정 dogfoot
										if(gDashboard.dataSourceQuantity > 0 && gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode != 'viewer') {
											if(gDashboard.dataSourceQuantity > 0) {
												confirmOk = confirm('비정형모드에서는 데이터 집합이 1개만 사용됩니다. 기존 데이터집합을 삭제하고 추가하시겠습니까?');
												if(confirmOk){
													gDashboard.dataSourceQuantity = 0;
													gDashboard.dataSourceManager.datasetInformation = {};
													gDashboard.dataSetCreate.lookUpItems = [];
													gDashboard.dataSetCreate.infoTreeList = [];
													gDashboard.parameterFilterBar.parameterInformation = {};
													gDashboard.datasetMaster.state.params = [];
													/*dogfoot 비정형 필터 영역 초기화 shlim 20210319*/
													/*dogfoot shlim 20210415*/
													$('#report-filter-item').empty();
													$('.panelClear').click();
													var pivot = gDashboard.itemGenerateManager.dxItemBasten[0].type === 'PIVOT_GRID'? gDashboard.itemGenerateManager.dxItemBasten[0] : gDashboard.itemGenerateManager.dxItemBasten[1];
													pivot.deltaItems=[];
													gDashboard.itemGenerateManager.clearItemData();
													$('.wise-area-deltaval').css('display', 'none');
												} else {
													return false;
												}
											} else {
												confirmOk = true;
											}
										} else {
											confirmOk = true;
										}
										
										
										if(confirmOk){
											gProgressbar.show();
											var param = {
													'DATASET_ID' : DATASET_ID
											};
											$.ajax({
												method : 'POST',
												url: WISE.Constants.context + '/report/dataSetInfo.do',
												data: param,
												beforeSend:function(){
													gProgressbar.show();
												},
												complete: function(){
													gProgressbar.hide();
												},
												error: function(error) {
													WISE.alert('error'+ajax_error_message(error),'error');
												},
												success: function(data) {
													data = jQuery.parseJSON(data);
	
	//												gDashboard.structure.ReportMasterInfo.dataSource.type = data['DATASRC_TYPE'];
	//												gDashboard.structure.ReportMasterInfo.dataSource.sql = data['SQL_QUERY'];
	//												gDashboard.dataSourceManager.dataSource.dataset.type = data['DATASET_TYPE'];
	//												gDashboard.dataSourceManager.dataSource.id = data['DATASRC_ID'];
	
													if(data['DATASET_TYPE'] == 'DataSetCube' || data['DATASET_TYPE'] == 'DataSetDs'){
														var selectList = data['SEL_ELEMENT'];
														
														$.each(data['SEL_ELEMENT']['SELECT_CLAUSE'], function(_i, _o) {
															if(_o.TYPE == 'DIM') {
																_o.icon = '../images/icon_dimension.png';
															} else {
	//															_o.icon = '../images/icon_measure.png';
																_o.icon = '../images/spr_global.png';
															}
															_o.PARENT_ID = '0';
															if(data['DATASET_TYPE'] == 'DataSetDs'){
	//															_o.UNI_NM = _o.COL_NM;
																_o.UNI_NM = "["+_o.TBL_NM+"].["+_o.COL_NM+"]";
																_o.CAPTION = _o.COL_CAPTION;
															}
														});
														
														gDashboard.dataSourceQuantity++;
														for(var i = 0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
															if('dataSource'+gDashboard.dataSourceQuantity == _.keys(gDashboard.dataSourceManager.datasetInformation)[i]){
																gDashboard.dataSourceQuantity++;
															}
														}
														
														var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE': 'dataSource' + gDashboard.dataSourceQuantity}];
														data['mapid'] = 'dataSource'+gDashboard.dataSourceQuantity;
														gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity] = data;
														self.infoTreeList[data['DATASET_NM']] = dataSetInfoTree.concat(data['SEL_ELEMENT']['SELECT_CLAUSE']);
														
														gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName':'dataSource' + gDashboard.dataSourceQuantity,"Name":data['DATASET_NM']})
														
													}
													else if(data['DATASET_TYPE'] == 'DataSetSQL'){
														var params = data['PARAM_ELEMENT'];
														if(data['data'] != undefined){
															gDashboard.dataSourceQuantity++;
															for(var i = 0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
																if('dataSource'+self.dataSourceQuantity == _.keys(gDashboard.dataSourceManager.datasetInformation)[i]){
																	gDashboard.dataSourceQuantity++;
																}
															}
															
															var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE': 'dataSource' + gDashboard.dataSourceQuantity}];
	
															var i = 1;
															for(var key in data['data'][0]) {
																var type;
																var iconPath;
																var dataType;
																//switch($.type(data['data'][0][key])) {
																switch(data['data'][0][key]) {
																case 'decimal':
																	type = 'MEA';
																	iconPath = '../images/icon_measure.png';
																	dataType = 'decimal';
																	break;
																default:
																	type = 'DIM';
																	iconPath = '../images/icon_dimension.png';
																	dataType = 'varchar';
																}
																//Spread sheet 차원 측정값 가리기
																var VISIBLE = true;
																if(gDashboard.reportType == 'Spread'){
																	VISIBLE = false;
																}
	
																var infoTree = [{'CAPTION': key, 'ORDER': i, 'PARENT_ID': "0", 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType, 'VISIBLE':VISIBLE}];
	
																dataSetInfoTree = dataSetInfoTree.concat(infoTree);
																i++;
															}
															
															data['DATA_META'] = dataSetInfoTree;
															
															data['mapid'] = 'dataSource'+gDashboard.dataSourceQuantity;
															gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity] = data;
															self.infoTreeList[data['DATASET_NM']] = dataSetInfoTree;
															gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName':'dataSource' + gDashboard.dataSourceQuantity,"Name":data['DATASET_NM']});
														}else{
															WISE.alert('데이터 집합 쿼리의 반환 값이 없습니다.<br>데이터 집합을 확인하세요.');
															return false;
														}
														
													}
	
													if(data['DATASET_TYPE'] == 'DataSetDs'){
														gDashboard.structure.ReportMasterInfo.paramJson = data['PARAM_ELEMENT'];
													}else{
														gDashboard.structure.ReportMasterInfo.paramJson = data['PARAM_ELEMENT'];
													}
													
													$.each(gDashboard.structure.ReportMasterInfo.paramJson, function(i, param) {
														if (!gDashboard.dataSetCreate.paramTreeList[data.mapid]) {
															gDashboard.dataSetCreate.paramTreeList[data.mapid] = [];
														}
														gDashboard.dataSetCreate.paramTreeList[data.mapid].push(param.PARAM_NM);
													});
	
													$('.filter-item').empty();
//													gDashboard.parameterHandler.init();
//													gDashboard.parameterHandler.render();
//													gDashboard.parameterHandler.resize();
													$('.cont_query').empty();
													//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
													$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
													$('#btn_query').off();
					            					$('#btn_query').on('click', function() {
	//				            						if (!self.button.enabled) {return;}
														/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
					            						if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
					            							gDashboard.itemGenerateManager.selectedTabList = [];
					            							gDashboard.tabQuery = true;
					            						}
					            						
					            						gDashboard.queryByGeneratingSql = true;
					            						gDashboard.itemGenerateManager.clearTrackingConditionAll();
					            						/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
					            						gDashboard.itemGenerateManager.clearItemData();
					            						gDashboard.query();
					            						this.blur();
					            					});
					            					
					            					self.lookUpItems.push({
				            							DATASET_NM:data['DATASET_NM'],
				            							mapid:data['mapid']
					            					});
					            					
					            					var lookUpIns;
					            					var newLookUpItems=[];
					            					$.each(self.lookUpItems, function(_id, _ds) {
														if (typeof _ds === 'string') {
															newLookUpItems.push(_ds);
														} else {
															newLookUpItems.push(_ds.DATASET_NM);
														}
													});
					            									            					
//					            					if(gDashboard.reportType == 'Spread' || gDashboard.reportType == 'Excel'){
//														lookUpIns = $("#dataSetLookUp").dxList('instance');													
//														var selectedItems = $("#dataSetLookUp").dxList('instance')._selection.options.selectedItems[0]													
//														lookUpIns.option('dataSource', newLookUpItems);	
//														if(selectedItems){
//															$("#dataSetLookUp").dxList('instance').option('selectedItemKeys',selectedItems);
//														}													
//														
//					        						}else{
					            					var $dataSetLookUp = $("#dataSetLookUp");
					            					
					            					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
					            						$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
					            					}
														lookUpIns = $dataSetLookUp.dxLookup('instance');
														lookUpIns.option('items', newLookUpItems);
														lookUpIns.option('value', data['DATASET_NM']);
					        						//}
					            					
													$("#data_popup").dxPopup("instance").hide();
												}
											});
										}else{
											$("#data_popup").dxPopup("instance").hide();
											gProgressbar.hide();
										}
	
									}
								}
							});
	
							$("#btn_subject_cancel").dxButton({
								text: "취소",
								type: "normal",
								onClick: function(e) {
									$("#data_popup").dxPopup("instance").hide();
								}
							});
						},
						error: function(error) {
							WISE.alert('error'+ajax_error_message(error),'error');
						}
					});
				}
				showFlag = false;
			}
		});
	};
	
	/* DOGFOOT ktkang BMT 그룹핑 기능 구현  20201203 */
	/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
	this.cubeListInfo = function(dsViewId, idType, refresh, isDownloadExpand) {
		var param = {
				'dsviewid' : dsViewId,
				'dstype' : 'CUBE',
				'userId':userJsonObject.userId,
				'idType' : idType
		};
		$.ajax({
			/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 오류 수정 */
			/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//			async: false,
			method : 'POST',
			url: WISE.Constants.context + '/report/cubeListInfo.do',
			data: param,
			async: false,
			complete: function(){
				//$('#progress_box').css({'display' : 'none'});
			},
			success: function(data) {
				data = jQuery.parseJSON(data);
				
				if(!data['error'] && data['cubeTableInfoList'] != null) {
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
					WISE.Context.isCubeReport = true;
					var confirmOk;
					/* DOGFOOT ktkang 비정형 뷰어에서 디자이너로 넘어갈 때 오류 수정  20200709 */
					if(gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode != 'viewer') {
						if(gDashboard.dataSetCreate.lookUpItems.length > 0) {
							/*dogfoot 알림창 형식 변경 shlim 20200717*/
							var options = {
									buttons: {
										confirm: {
											id: 'confirm',
											className: 'blue',
											text: '확인',
											action: function() { 
												confirmOk = true;
												gDashboard.dataSourceQuantity = 0;
												gDashboard.dataSourceManager.datasetInformation = {};
												gDashboard.dataSetCreate.lookUpItems = [];
												gDashboard.dataSetCreate.infoTreeList = [];
												gDashboard.parameterFilterBar.parameterInformation = {};
												gDashboard.datasetMaster.state.params = [];
												/*dogfoot 비정형 주제영역 새로 추가시 항목 초기화 shlim 20200715*/
												$('#dataAdHocList1').empty();
												$('#rowAdHocList1').empty();
												$('#colAdHocList1').empty();
												$('#adhoc_hide_measure_list1').empty();
												/*dogfoot 비정형 필터 영역 초기화 shlim 20210319*/
												/*dogfoot shlim 20210415*/
												$('#report-filter-item').empty();
												gDashboard.dragNdropController.recovery($('#dataAdHocList1'));
												gDashboard.dragNdropController.recovery($('#rowAdHocList1'));
												gDashboard.dragNdropController.recovery($('#colAdHocList1'));
												gDashboard.dragNdropController.recovery($('#adhoc_hide_measure_list1'));
												/*dogfoot 비정형 주제영역 새로 추가시 차트도 초기화 shlim 20200715*/
												$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
													$('#'+_item.itemid).css('display','none');
												});
												gDashboard.itemGenerateManager.clearTrackingConditionAll();
												gDashboard.itemGenerateManager.clearItemData();

												self.addCubeDataList();

												$AlertPopup.hide();
											}
										},
										cancel: {
											id: 'cancel',
											className: 'negative',
											text: '취소',
											action: function() { 
												confirmOk = false
												$AlertPopup.hide();
											}
										}
									}
							};
							/* DOGFOOT ktkang 주제영역 뷰어에서 디자이너 이동 할 때 에러 수정  20201112 */
							if(userJsonObject.selectCubeId) {
								confirmOk = true;
							} else {
								WISE.confirm('비정형모드에서는 데이터 집합이 1개만 사용됩니다. 기존 데이터집합을 삭제하고 추가하시겠습니까?', options);
							}
						} else {
							confirmOk = true;
						}
					} else {
						/* DOGFOOT ktkang 같은 주제영역 중복 추가 불가하도록 수정  20200903 */
						if(gDashboard.dataSetCreate.lookUpItems.length > 0) {
							if(WISE.Constants.editmode !== "viewer"){
								var cubeName = '';
								$.each(data.cubeTableInfoList,function(_i,_e){
									cubeName = _i;
								});
								if(gDashboard.dataSetCreate.lookUpItems.indexOf(cubeName) > -1) {
									WISE.alert('같은 이름의 주제영역이 이미 추가되어 있습니다.', 'error');
									return false;
								} else {
									confirmOk = true;
								}	
							}else{
								confirmOk = true;
							}
						} else {
							confirmOk = true;
						}
					}
					/*dogfoot 알림창 형식 변경 shlim 20200717*/
					self.addCubeDataList = function(){
					
						gDashboard.dataSetCreate.createDxItems();
						/*dogfoot 상세데이터 보기 추가 shlim 20200715*/
						gDashboard.structure['drillThru'] = data.drillThru;
						/* DOGFOOT ktkang 주제영역 일 때 검색창 추가  20200130 */
						var $cubeFieldSearch = $("#cubeFieldSearch");
						if($("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch").length > 0 && WISE.Constants.editmode == "viewer"){
							$cubeFieldSearch = $("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch")
						}
						if(WISE.Constants.editmode != "viewer"){
							$cubeFieldSearch.remove();
						}
						/* DOGFOOT ktkang KERIS IE에서 UI 오류 수정  20200310 */
						var $dataSetLookUp = $("#dataSetLookUp");
    					
    					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
    						$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
    					}
    					
    					$dataSetLookUp.after('<div id="cubeFieldSearch" style="width:calc(100% - 15px);"></div>');
						gDashboard.dataSetCreate.lookUpItems = [];
						$.each(data.cubeTableInfoList,function(_i,_e){
							var cubeAllTree = [];
							gDashboard.dataSetCreate.lookUpItems.push(_i);
							/* DOGFOOT ktkang 비정형 주제영역  dataSourceQuantity 증가 오류 수정  20200708 */
							var dataSourceId = "";
							if(gDashboard.reportType == 'AdHoc') {
								dataSourceId = 'dataSource1';
							} else if(WISE.Constants.editmode == "viewer" && ((gDashboard.reportType == "DashAny" && userJsonObject.menuconfig.Menu.DASH_DATA_FIELD) || gDashboard.reportType == 'DSViewer')){
								dataSourceId = 'dataSource1';
								$.each(gDashboard.datasetMaster.state.datasets, function(_k, _dataset){
									if(_dataset.DATASET_NM == _i){
										dataSourceId = _k;
									}
								})
							} else {
								dataSourceId = 'dataSource' + ++gDashboard.dataSourceQuantity;
							}
							 
							var KeysortObject = new Object();
//							$.each(data.PARAM_ELEMENT,function(_i,_e){
//							$.each(_e,function(_key,_val){
//							for(var i=0;i<paramNameList.length;i++){
//							if(_key === paramNameList[i]){
//							KeysortObject[_key] = _val;
//							}
//							}
//							})
//							});
							
//							data['mapid'] = 'dataSource' + gDashboard.dataSourceQuantity;
//							gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity]= _e;

							/* DOGFOOT ktkang 측정값 먼저 보이도록 수정  20200221 */
							var i = 5000;
							var j = 7000;
							var fldArray = [];
							$.each(_e.measures ,function(_ii,_ee){
								/* DOGFOOT ktkang 비정형 뷰어에서 디자이너로 넘어갈 때 오류 수정  20200709 */
								var dataSetInfoTree = [{'CAPTION': _ee.logicalName, 'ORDER': _ii + _e.dimensions.length + 1, 'expanded': true, 'DATASOURCE' : dataSourceId, 'FLD_TYPE': 'CUBE', 'DATASRC_ID' : _ee.cubeId, 'TYPE' : 'measure'}];
								
								for(var key in _ee['columns']) {
									/* DOGFOOT ktkang IE에서 includes 함수 안됨   20200212 */
									if(_ee['columns'][key].folder != '' && fldArray.indexOf(_ee['columns'][key].folder) == -1){
										fldArray.push(_ee['columns'][key].folder);
										var type = 'FLD';
										var iconPath = '../images/icon_measure.png';

										var infoTree = [{'CUBE_UNI_NM': _ee['columns'][key].folder, 'CAPTION': _ee['columns'][key].folder, 'ORDER': j, 'PARENT_ID': String(_ii + _e.dimensions.length + 1), 'TYPE': type, 'MEAFLD': true}];

										dataSetInfoTree = dataSetInfoTree.concat(infoTree);
										i++;
										j++;
									}
								}
								
								for(var key in _ee['columns']) {
									if(_ee['columns'][key].visible == 1 && _ee['columns'][key].folder != ''){
										$.each(dataSetInfoTree ,function(_iii,_eee){
											/*dogfoot 주제영역 폴더 구분 집계함수 없을시  차원으로 변경 shlim 20201208*/
											if(_eee['CAPTION'] == _ee['columns'][key].folder && _ee['columns'][key].summaryType != '') {
												var type = 'MEA';
												var iconPath = '../images/icon_measure.png';
												var dataType = 'decimal';

												var infoTree = [{'CUBE_UNI_NM': _ee['columns'][key].uniqueName, 'CAPTION': _ee['columns'][key].captionName, 'ORDER': i, 'PARENT_ID': _eee['ORDER'], 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType, 'MEAFLD': _ee['columns'][key].folder, 'ORDINAL': _ee['columns'][key].ordinal}];

												dataSetInfoTree = dataSetInfoTree.concat(infoTree);
												i++;
												return false;
											}else if(_eee['CAPTION'] == _ee['columns'][key].folder && _ee['columns'][key].summaryType == ''){
												var type = 'DIM';
												var iconPath = '../images/icon_dimension.png';
												var dataType = 'varchar';
                                                
                                                var infoTree = [{'CUBE_UNI_NM': _ee['columns'][key].uniqueName, 'CAPTION': _ee['columns'][key].captionName, 'ORDER': i, 'PARENT_ID': _eee['ORDER'], 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType, 'MEAFLD': _ee['columns'][key].folder, 'ORDINAL': _ee['columns'][key].ordinal}];

												dataSetInfoTree = dataSetInfoTree.concat(infoTree);
												i++;
												return false;
											}
										});
										/* DOGFOOT ktkang 집계함수가 null 일 때 측정값을 차원으로 표기  20200130 */
									} else if(_ee['columns'][key].visible == 1 && _ee['columns'][key].folder == '' && _ee['columns'][key].summaryType != '') {
										var type = 'MEA';
										var iconPath = '../images/icon_measure.png';
										var dataType = 'decimal';

										var infoTree = [{'CUBE_UNI_NM': _ee['columns'][key].uniqueName, 'CAPTION': _ee['columns'][key].captionName, 'ORDER': i, 'PARENT_ID': String(_ii + _e.dimensions.length + 1), 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType, 'MEAFLD': false, 'ORDINAL': _ee['columns'][key].ordinal}];

										dataSetInfoTree = dataSetInfoTree.concat(infoTree);
										i++;
									} else if(_ee['columns'][key].visible == 1 && _ee['columns'][key].folder == '' && _ee['columns'][key].summaryType == '') {
										var type = 'DIM';
										var iconPath = '../images/icon_dimension.png';
										var dataType = 'varchar';

										var infoTree = [{'CUBE_UNI_NM': _ee['columns'][key].uniqueName, 'CAPTION': _ee['columns'][key].captionName, 'ORDER': i, 'PARENT_ID': String(_ii + _e.dimensions.length + 1), 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType, 'MEAFLD': false, 'ORDINAL': _ee['columns'][key].ordinal}];

										dataSetInfoTree = dataSetInfoTree.concat(infoTree);
										i++;
										/* DOGFOOT ktkang 집계함수가 null 일 때 측정값을 차원으로 표기 끝  20200130 */
									}
								}
								
								cubeAllTree = cubeAllTree.concat(dataSetInfoTree);
							});
							
							
							var i = 500;
							$.each(_e.dimensions ,function(_ii,_ee){
								/* DOGFOOT ktkang 비정형 뷰어에서 디자이너로 넘어갈 때 오류 수정  20200709 */
								var dataSetInfoTree = [{'CAPTION': _ee.logicalName, 'ORDER': _ii + 1, 'expanded': false, 'DATASOURCE' : dataSourceId, 'FLD_TYPE': 'CUBE', 'DATASRC_ID' : _ee.cubeId, 'TYPE' : 'dimension'}];

								for(var key in _ee['columns']) {
									if(_ee['columns'][key].visible == 1){
										var type = 'DIM';
										var iconPath = '../images/icon_dimension.png';
										var dataType = 'varchar';
										/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
//										var infoTree = [{'CUBE_UNI_NM': _ee['columns'][key].uniqueName, 'CAPTION': _ee['columns'][key].captionName, 'ORDER': i, 'PARENT_ID': String(_ii + 1), 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType}];
										var infoTree = [{'CUBE_UNI_NM': _ee['columns'][key].uniqueName, 'CAPTION': _ee['columns'][key].captionName, 'ORDER': i, 'PARENT_ID': String(_ii + 1), 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType, 'ORDER_BY':_ee['columns'][key].orderBy.trim(), 'ORDER_BY_KEY': _ee['columns'][key].physicalColumnId, 'ORDER_BY_NAME': _ee['columns'][key].physicalColumnName, 'ORDINAL': _ee['columns'][key].ordinal}];

										dataSetInfoTree = dataSetInfoTree.concat(infoTree);
										i++;
									}
								}
								
								cubeAllTree = cubeAllTree.concat(dataSetInfoTree);
							});
							
							
							
							gDashboard.dataSetCreate.infoTreeList[_i] = cubeAllTree;
							/* DOGFOOT ktkang 비정형 주제영역  dataSourceQuantity 증가 오류 수정  20200708 */
							gDashboard.dataSetCreate.paramTreeList[dataSourceId] = [];;
							gDashboard.dataSetCreate.subjectInfoList[dataSourceId] = {dataType: "CUBE"};
							data['DATA_META'] = cubeAllTree;
							/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 오류 수정 */
							var cubeDs = new WISE.libs.CubeData;
							
							/* DOGFOOT ktkang 주제영역 일 때 검색창 추가  20200130 */
							// 고용정보원 본사처리 - 15 begin
							var $cubeFieldSearch = $("#cubeFieldSearch");
							if($("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch").length > 0 && WISE.Constants.editmode == "viewer"){
								$cubeFieldSearch = $("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch")
							}
							$cubeFieldSearch.dxTextBox({
								visible:true,
								readOnly: false,
								/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200212 */
								placeholder: '검색어를 입력하세요.',
								showClearButton:true,
								onKeyUp: function(e) {
									/* DOGFOOT ktkang 주제영역 검색 기능 개선  20200308 */
									cubeDs.cubeSearchText(e.event.target.value, false);
									e.component.option('value',e.event.target.value);
								},
								onValueChanged: function(e){
									if(e.value == ""){
								        cubeDs.cubeSearchText("", false);		
									}
								}
							}).dxTextBox("instance");;
							// 고용정보원 본사처리 - 15 end
							/* DOGFOOT ktkang 비정형 주제영역  dataSourceQuantity 증가 오류 수정  20200708 */
							if(!isDownloadExpand)
								/*dogfoot 비정형 주제영역 사용자 정의 데이터 안나오는 오류 수정 shlim 20210402*/
								/*dogfoot shlim 20210414*/
								if(WISE.Constants.editmode != "viewer"){
									cubeDs.insertDataSet(data['DATA_META'], dataSourceId);
								}else{
									gDashboard.customFieldManager.setCustomFieldsForOpen(dataSourceId);
								}
								
								//
							
							/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200212 */
							/* DOGFOOT MKSONG cubeRelation추가 위해 수정  20200218 */
							$('#removeDataSource').css('display','none');
							/* DOGFOOT hjkim 주제영역을 교체할때 클릭이 안되어서 다시 생성하게 처리 20200704 */
							$("#cubeRelation").remove();
							/* DOGFOOT ktkang 고용정보원09  사용자 정보 변경 오류  수정  */
							if(WISE.Constants.editmode != 'viewer'){
								$('<a href="#" id="cubeRelation" alt="주제영역 연계 데이터 보기" title="주제영역 연계 데이터 보기"></a>').insertBefore('#removeDataSource');	
							} else {
								var dataSetLookUp = "#dataSetLookUp"
		    					
		    					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
		    						dataSetLookUp = "#dataArea_"+WISE.Constants.pid+" #dataSetLookUp"
		    					}
								$('<a href="#" id="cubeRelation" style="display:none;"></a>').insertBefore(dataSetLookUp);	
							}
							
							$("#cubeRelation").off();
							$("#cubeRelation").dxCheckBox({
								visible:true,
								readOnly: false,
								value: false,
								/* DOGFOOT ktkang KERIS 버튼 사이즈 수정  20200214 */
								width: 18,
								height: 18,
								hint: '주제영역 연계 데이터 보기',
								onOptionChanged: function(e){
									/* DOGFOOT MKSONG Element ID cubeRelation으로 변경  20200217 */
									var tabIndex = $("#cubeRelation").dxCheckBox('instance').option('tabIndex');
									if(tabIndex == 0) {
									} else {
										var $cubeFieldSearch = $("#cubeFieldSearch");
										if($("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch").length > 0 && WISE.Constants.editmode == "viewer"){
											$cubeFieldSearch = $("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch")
										}
										var searchText = $cubeFieldSearch.dxTextBox('instance').option('value');
										/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200219 */
//										cubeDs.insertDataSet(data['DATA_META'], 'dataSource'+gDashboard.dataSourceQuantity, searchText);
										cubeDs.cubeRalationTree();
										/* DOGFOOT ktkang 주제영역 검색 기능 개선  20200308 */
										cubeDs.cubeSearchText(searchText, true);
										var tabIndex = $("#cubeRelation").dxCheckBox('instance').option('tabIndex', 0);
									}
								},
								onValueChanged: function(e) {
									if(e.value) {
										WISE.Context.isCubeRelation = true;
									} else {
										WISE.Context.isCubeRelation = false;
									}
									/* DOGFOOT ktkang 주제영역 검색 기능 개선  20200305 */
									var $cubeFieldSearch = $("#cubeFieldSearch");
									if($("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch").length > 0 && WISE.Constants.editmode == "viewer"){
										$cubeFieldSearch = $("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch")
									}
									var searchText = $cubeFieldSearch.dxTextBox('instance').option('value');
									cubeDs.cubeRalationTree();
									/* DOGFOOT ktkang 주제영역 검색 기능 개선  20200308 */
									cubeDs.cubeSearchText(searchText, true);
								}
							});
							/* DOGFOOT ktkang KERIS 버튼 사이즈 수정  20200214 */
							$('.dx-checkbox-icon').css('width', '18px');
							$('.dx-checkbox-icon').css('height', '18px');
							$('.dx-checkbox-container').css('margin-top','1px');
							var $dataSetLookUp = $("#dataSetLookUp");
							
							if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
								$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
							}
							var lookUpIns = $dataSetLookUp.dxLookup('instance');
							lookUpIns.option('items', gDashboard.dataSetCreate.lookUpItems);
							/* DOGFOOT ktkang 주제영역 포커싱 주는 부분 그리는 시간때문에 조금 기다렸다가 포커싱을 줘야함  20200116 */
							/* DOGFOOT 20201021 ajkim setTimeout 시간 변경 300 > 10*/
							if(!isDownloadExpand)
								setTimeout(function(){
									if(data.focusCube != null) {
										lookUpIns.option('value', data.focusCube);
	//									$("#cubeRelation").dxCheckBox('instance').option('tabIndex', 1);
									} else {
										lookUpIns.option('value', _i);
									}
									/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
									/*dogfoot 통계 분석 추가 shlim 20201102*/
									if((gDashboard.reportType == 'DashAny' || gDashboard.reportType == 'StaticAnalysis') && gDashboard.isNewReport) {
										gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName': dataSourceId, "Name":_i});
										gDashboard.datasetMaster.migDatasetToState(dataSourceId);
										/*dogfoot 비정형 보고서 주제영역 새 보고서 에서 집합 생성시 dataset에 추가  shlim 20210219 */
									} else if(gDashboard.reportType == 'AdHoc' && gDashboard.isNewReport){
										gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName': dataSourceId, "Name":_i});
										gDashboard.datasetMaster.migDatasetToState(dataSourceId);
									} else {
									/* DOGFOOT ktkang 보고서 불러오기 후 관계 오류 수정  20200708 */
										$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
											if(_item.dataSourceId == dataSourceId) {
												gDashboard.dragNdropController.cubeRelationCheck(_item);
											}
										});	
									}
								},10);
							/* DOGFOOT ktkang 필요없는 소스 삭제  20200305 */
							
							/* DOGFOOT ktkang BMT 그룹핑 기능 구현  20201203 */
							if(typeof refresh != 'undefined' && refresh) {
								lookUpIns.option('value', '');
								lookUpIns.option('value', data.focusCube);
							}
						});
						
						$('.cont_query').empty();
						//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
						$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
						$('#btn_query').off();
						$('#btn_query').on('click', function() {
//							if (!self.button.enabled) {return;}
							gProgressbar.show();
                            setTimeout(function () {
                            	/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
                            	if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
            						gDashboard.itemGenerateManager.selectedTabList = [];
            						gDashboard.tabQuery = true;
            					}
                            	
								gDashboard.queryByGeneratingSql = true;
								gDashboard.itemGenerateManager.clearTrackingConditionAll();
								/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
								gDashboard.itemGenerateManager.clearItemData();
								gDashboard.query();
								this.blur();								        		
							}, 50);
						});
					}
					/*dogfoot 알림창 형식 변경 shlim 20200717*/
					if(confirmOk){
						self.addCubeDataList();
					}
				} else {
					gProgressbar.hide();
					WISE.alert('쿼리가 부적합 합니다.');
				}
			},error: function(_response) {
				gProgressbar.hide();
				WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
			}
		});
	};
	
	this.columnListInfo = function(dsViewId) {
		$.each(gDashboard.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT,function(_i,_dataset){
			if(_dataset.DATASET_TYPE == "DataSetCube"||_dataset.DATASET_TYPE == "DataSetDs"){
				gDashboard.dataSetCreate.openDataSetInfo(_dataset);
			}else{
				gDashboard.dataSetCreate.openDirectQueryTblColInfo(_dataset, gDashboard.structure.DataSources.DataSource[0].ComponentName);
			}
			$.ajax({
				type : 'post',
				async:false,
				url : WISE.Constants.context + '/report/subjectListForOpen.do',
				data:{
					'dataType': _dataset.DATASRC_TYPE,
					'dsid': _dataset.DATASRC_ID,
				},
				complete: function() {
					//$('#progress_box').css({'display' : 'none'});
				},
				success : function(data) {
					data = JSON.parse(data);
					gDashboard.dataSetCreate.subjectInfoList[_dataset.mapid] = data.subjectInfos[0];
					// gDashboard.dataSetCreate.paramTreeList[_dataset.mapid];
				}
			});
			gDashboard.dataSetCreate.paramTreeList[_dataset.mapid] = [];
			if(gDashboard.reportType == 'AdHoc'){
				$.each(gDashboard.dataSourceManager.datasetInformation,function(_i,_e){
					if(_e.PARAM_ELEMENT != undefined){
						$.each(WISE.util.Object.toArray(_e.PARAM_ELEMENT.PARAM),function(_j,_ee){
							gDashboard.dataSetCreate.paramTreeList[_dataset.mapid].push(_ee.PARAM_NM);
						})
						
					}
				});
				if (typeof gDashboard.dataSourceManager.datasetInformation.dataSource1.PARAM_ELEMENT !== 'undefined') {
					$.each(WISE.util.Object.toArray(gDashboard.dataSourceManager.datasetInformation.dataSource1.PARAM_ELEMENT.PARAM),function(_i,_e){
						gDashboard.dataSetCreate.paramTreeList[_dataset.mapid].push(_e.PARAM_NM);
					});
				}
			}else{
				if(_dataset.DATASET_TYPE != "DataSetSingleDs" && _dataset.DATASET_TYPE != "DataSetSingleDsView"){
					$.each(WISE.util.Object.toArray(_dataset.DATASET_JSON.DATA_SET.PARAM_ELEMENT.PARAM),function(_i,_e){
						gDashboard.dataSetCreate.paramTreeList[_dataset.mapid].push(_e.PARAM_NM);
					});
				}
			}
			/* DOGFOOT hsshim 2020-01-13 데이터 집합 트리 리스트 적용후 사용자 정의 데이터를 적용 */
			gDashboard.customFieldManager.setCustomFieldsForOpen(_dataset.mapid);
		});		
	};
	
	//2020.01.31 MKSONG dataSourceId 지정 DOGFOOT
	this.openDirectQueryTblColInfo = function(_dataSet,_dataSourceId){
		// gDashboard.parameterHandler.render();
		// gDashboard.parameterHandler.resize();
		var condition = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
		var param = {
				'DATASET_NM' : _dataSet.DATASET_NM,
		        'DATASET_TYPE' : _dataSet.DATASET_TYPE,
				'DATASRC_ID' : _dataSet.DATASRC_ID,
				'DATASRC_TYPE' : _dataSet.DATASRC_TYPE,
				'SQL_QUERY' : _dataSet.SQL_QUERY,
				/* DOGFOOT ktkang 콤마 삭제  20200212 */
				'params' : $.toJSON(condition)
		};

		$.ajax({
			method : 'POST',
			url: WISE.Constants.context + '/report/directSqlDataSetInfo.do',
			data: param,
			//2020.03.06 mksong 비동기화 dogfoot
			async:true,
			complete: function(){
//				$('#progress_box').css({'display' : 'none'});
			},
			success: function(data) {
				//2020.01.31 MKSONG dataSourceId 지정 DOGFOOT
				data = jQuery.parseJSON(data);
				
				var dataSetInfoTree;
				if(_dataSourceId){
					if(gDashboard.dataSourceQuantity < Number(_dataSourceId.substr(_dataSourceId.lastIndexOf('e')+1))){
						gDashboard.dataSourceQuantity = Number(_dataSourceId.substr(_dataSourceId.lastIndexOf('e')+1));
					}
					dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE' : _dataSourceId, 'DATASET_TYPE':_dataSet.DATASET_TYPE }];
				}else{
					gDashboard.dataSourceQuantity++;
					dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE' : 'dataSource' + gDashboard.dataSourceQuantity, 'DATASET_TYPE':_dataSet.DATASET_TYPE }];
				}
				
				if(gDashboard.dataSetCreate.lookUpItems == undefined){
					gDashboard.dataSetCreate.lookUpItems = new Array();	
				}
				if(data['data']){
					var i = 1;
					for(var key in data['data'][0]) {
						var type;
						var iconPath;
						var dataType;
						switch(data['data'][0][key]) {
						case 'decimal': 
							type = 'MEA';
							iconPath = '../images/icon_measure.png';
							dataType = 'decimal';
							break;
						default:
							type = 'DIM';
							iconPath = '../images/icon_dimension.png';
							dataType = 'varchar';
						}
						
						//Spread sheet 차원 측정값 가리기
						var VISIBLE = true;
						if(gDashboard.reportType == 'Spread' || gDashboard.reportType == 'Excel'){
							VISIBLE = false;
						}
	
						var infoTree = [{'CAPTION': key, 'ORDER': i, 'PARENT_ID': "0", 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType, 'UNI_NM':key, 'VISIBLE':VISIBLE}];
						if(_dataSet.DATASET_TYPE == "DataSetSingleDs" || _dataSet.DATASET_TYPE == 'DataSetSingleDsView'){
							infoTree[0].UNI_NM = '['+_dataSet.DATASET_JSON.DATA_SET.TBL_ELEMENT+']';
							$.each(_dataSet.DATASET_JSON.DATA_SET.COL_ELEMENT.COLUMN,function(_i,_col){
								if(_col.COL_NM === key){
									infoTree[0].ORDER = _col.ORDER;
									infoTree[0].VISIBLE = _col.VISIBLE;
									return false;
								}
							});
						}
						
	
						dataSetInfoTree = dataSetInfoTree.concat(infoTree);
						i++;
					}
				}
				gDashboard.dataSetCreate.infoTreeList[data['DATASET_NM']] = dataSetInfoTree;				
				gDashboard.dataSetCreate.lookUpItems.push({
					DATASET_NM:data['DATASET_NM'],
					mapid:'dataSource'+gDashboard.dataSourceQuantity
				});
				
				_dataSet['DATA_META'] = dataSetInfoTree;
				if(_dataSourceId){
					_dataSet['mapid'] = _dataSourceId;
					gDashboard.dataSourceManager.datasetInformation[_dataSourceId]= _dataSet;
				}else{
					_dataSet['mapid'] = 'dataSource' + gDashboard.dataSourceQuantity;
					gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity]= _dataSet;
				}
			
				
				var newLookUpItems=[];
				$.each(self.lookUpItems, function(_id, _ds) {
					newLookUpItems.push(_ds.DATASET_NM);
				});

				
				var lookUpIns;																	
				if(gDashboard.reportType == "Spread" || gDashboard.reportType == "Excel"){
//					lookUpIns = $("#dataSetLookUp").dxList('instance');
//					lookUpIns.option('dataSource', newLookUpItems);	
//					lookUpIns = $("#dataSetLookUp").dxLookup('instance');
					var $dataSetLookUp = $("#dataSetLookUp");
					
					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
						$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
					}
					lookUpIns = $dataSetLookUp.dxLookup('instance');
					lookUpIns.option('items', newLookUpItems);
					lookUpIns.option('value', data['DATASET_NM']);	
				}else{
					if(WISE.Constants.editmode != 'viewer'){
						lookUpIns = $("#dataSetLookUp").dxLookup('instance');
						lookUpIns.option('items', newLookUpItems);
						lookUpIns.option('value', data['DATASET_NM']);	
					}
					
					//2020.03.09 MKSONG 데이터 집합 1개일 경우 insertDataSet 안하는 오류 수정 DOGFOOT
					if(gDashboard.reportUtility.reportInfo.DataSources.DataSource.length == 1){
						if(self.infoTreeList[data['DATASET_NM']][0]['DATASOURCE'] != undefined && typeof self.infoTreeList[data['DATASET_NM']][0]['TYPE'] == 'undefined'){
							if(WISE.Constants.editmode != 'viewer'){
				            	$('.drop-down.tree-menu > ul').empty();	
				            }else{
				            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
				            }
							self.insertDataSet(self.infoTreeList[data['DATASET_NM']], self.infoTreeList[data['DATASET_NM']][0]['DATASOURCE']);	
						}
					}
				}				
				
				gDashboard.reportUtility.settingByDatasetMapid(_dataSet);
				
				$('.cont_query').empty();
				//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
				$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
				$('#btn_query').off();
				$('#btn_query').on('click', function() {
//					if (!self.button.enabled) {return;}
					/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
					if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
						gDashboard.itemGenerateManager.selectedTabList = [];
						gDashboard.tabQuery = true;
					}
					
					gDashboard.queryByGeneratingSql = true;
					gDashboard.itemGenerateManager.clearTrackingConditionAll();
					/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
					gDashboard.itemGenerateManager.clearItemData();
					gDashboard.query();
					this.blur();
				});
				
				/* DOGFOOT ktkang 아이템이 다 그려지기 전에 로딩바 사라지는 오류 수정  20201014 */
				if(gDashboard.itemGenerateManager.dxItemBasten.length == 0 || gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length)
					gProgressbar.hide();
				
			},error: function(_response) {
				gProgressbar.hide();
				WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
			}
		});
	};
	
	
	this.openDataSetInfo = function(_dataSet){
		var data =_dataSet;
		if(gDashboard.dataSetCreate.lookUpItems.length < 1) {
			gDashboard.dataSetCreate.createDxItemsForOpen();
		}
			
		//gDashboard.dataSourceQuantity++;
		
		if(data['DATASET_TYPE'] == 'DataSetCube' || data['DATASET_TYPE'] == 'DataSetDs'){
//			data = _dataSet.DATASET_JSON.DATA_SET;
			var selectList = data.DATASET_JSON.DATA_SET['SEL_ELEMENT'];

			
			var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE': 'dataSource' + gDashboard.dataSourceQuantity}];

			$.each(data.DATASET_JSON.DATA_SET['SEL_ELEMENT']['SELECT_CLAUSE'], function(_i, _o) {
				if(_o.TYPE == 'DIM') {
					_o.icon = '../images/icon_dimension.png';
				} else {
					_o.icon = '../images/icon_measure.png';
				}
				_o.PARENT_ID = '0';
				if(data['DATASET_TYPE'] == 'DataSetDs'){
//					_o.UNI_NM = _o.COL_NM;
					_o.UNI_NM = "["+_o.TBL_NM+"].["+_o.COL_NM+"]";
					_o.CAPTION = _o.COL_CAPTION;
				}
			});
			
//			for(var i = 0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
//				if('dataSource'+gDashboard.dataSourceQuantity == _.keys(gDashboard.dataSourceManager.datasetInformation)[i]){
//					gDashboard.dataSourceQuantity++;
//				}
//			}
			data['mapid'] = 'dataSource'+gDashboard.dataSourceQuantity;
			gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity] = data;
			self.infoTreeList[data['DATASET_NM']] = dataSetInfoTree.concat(data.DATASET_JSON.DATA_SET['SEL_ELEMENT']['SELECT_CLAUSE']);
//			gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName':'dataSource' + gDashboard.dataSourceQuantity,"Name":data['DATASET_NM']})
		}
		else if(data['DATASET_TYPE'] == 'DataSetSQL'){
			var params = data['PARAM_ELEMENT'];

			var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE': 'dataSource' + gDashboard.dataSourceQuantity}];

			var i = 1;
			for(var key in data['data'][0]) {
				var type;
				var iconPath;
				var dataType;
				switch(data['data'][0][key]) {
				case 'decimal': 
					type = 'MEA';
					iconPath = '../images/icon_measure.png';
					dataType = 'decimal';
					break;
				default:
					type = 'DIM';
					iconPath = '../images/icon_dimension.png';
					dataType = 'varchar';
				}

				var infoTree = [{'CAPTION': key, 'ORDER': i, 'PARENT_ID': "0", 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType}];

				dataSetInfoTree = dataSetInfoTree.concat(infoTree);
				i++;
			}
			
			data['DATA_META'] = dataSetInfoTree;
			
			gDashboard.dataSourceQuantity++;
			for(var i = 0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
				if('dataSource'+self.dataSourceQuantity == _.keys(gDashboard.dataSourceManager.datasetInformation)[i]){
					gDashboard.dataSourceQuantity++;
				}
			}
			data['mapid'] = 'dataSource'+gDashboard.dataSourceQuantity;
			gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity] = data;
			self.infoTreeList[data['DATASET_NM']] = dataSetInfoTree;
		}
		if(data['DATASET_TYPE'] == 'DataSetDs'){
//			gDashboard.structure.ReportMasterInfo.paramJson = data['PARAM_ELEMENT'];
		}else{
			gDashboard.structure.ReportMasterInfo.paramJson = data['PARAM_ELEMENT'];
		}
//		gDashboard.structure.ReportMasterInfo.paramJson = data['PARAM_ELEMENT'];
		// gDashboard.parameterHandler.init();
		// gDashboard.parameterHandler.render();
		// gDashboard.parameterHandler.resize();
		$('.cont_query').empty();
		//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
		$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
		$('#btn_query').off();
		$('#btn_query').on('click', function() {
//					if (!self.button.enabled) {return;}
			/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
			if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
				gDashboard.itemGenerateManager.selectedTabList = [];
				gDashboard.tabQuery = true;
			}
			
			gDashboard.queryByGeneratingSql = true;
			gDashboard.itemGenerateManager.clearTrackingConditionAll();
			/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
			gDashboard.itemGenerateManager.clearItemData();
			gDashboard.query();
			this.blur();
		});
		
		gDashboard.reportUtility.settingByDatasetMapid(_dataSet);
		
		self.lookUpItems.push({
			DATASET_NM:data['DATASET_NM'],
			mapid:data['mapid']
		});
		
		var newLookUpItems=[];
		$.each(self.lookUpItems, function(_id, _ds) {
			newLookUpItems.push(_ds.DATASET_NM);
		});

		var $dataSetLookUp = $("#dataSetLookUp");
		
		if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
			$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
		}
		
		var lookUpIns = $dataSetLookUp.dxLookup('instance');
		lookUpIns.option('items', newLookUpItems);
		lookUpIns.option('value', data['DATASET_NM']);
	};
	
	this.createDxItemsForOpen = function() {
		this.lookUpItems = new Array();
		this.infoTreeList = new Array();
		this.paramTreeList = new Array();
		this.subjectInfoList = new Array();
		
//		if(gDashboard.reportType == "Spread" || gDashboard.reportType == "Excel"){			
//			$("#dataSetLookUp").dxList({		
//				selectionMode: "single",
//			    noDataText: gMessage.get('WISE.message.page.common.nodata'),
//			    onItemClick: function(e) {
//					/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 오류 수정 */
//			    	if(WISE.Constants.editmode != 'viewer'){
//		            	$('.drop-down.tree-menu > ul').empty();	
//		            }else{
//		            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
//		            }
//					if(e.itemData != '' && e.itemData != undefined){
//						/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 오류 수정 */
//						var dataSourceId = self.infoTreeList[e.itemData][0]['DATASOURCE'];
//						if(dataSourceId){	
//							var dd = gDashboard.dataSourceManager.datasetInformation[dataSourceId];
//            				if(dd.SHEET_ID){
//            					$("#dataSetLookUp").dxList('instance').option('selectedItemKeys',dd.DATASET_NM);
//								//gDashboard.spreadsheetManager.spreadJS.setActiveSheet(gDashboard.spreadsheetManager.getSheetNameFromID(Number(dd.SHEET_ID.substring(5))-1));
//            					gDashboard.spreadsheetManager.spreadJS.setActiveSheet(dd.SHEET_NM);
//            				}	            																
//						}						
//					}
//				}
//			}).dxList("instance");			
//			$("#dataSetLookUp").attr("style",'width:100% !important');			
//		}else{
			var $dataSetLookUp = $("#dataSetLookUp");
			
			if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
				$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
			}
			$dataSetLookUp.dxLookup({
				item:{},
				placeholder: "데이터 집합을 선택하세요",
				showPopupTitle: false,
				searchEnabled: false,
				showPopupTitle: false,
				showCancelButton: false,
				closeOnOutsideClick: true,
				onValueChanged: function(e) {
					/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 리스트 겹치는 오류 수정 */
					if(e.value != "" && self.infoTreeList[e.value]){
						/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 리스트 겹치는 오류 수정 */
						if(self.infoTreeList[e.value][0] && self.infoTreeList[e.value][0]['DATASOURCE'] != undefined && typeof self.infoTreeList[e.value][0]['TYPE'] == 'undefined'){
							if(WISE.Constants.editmode != 'viewer'){
				            	$('.drop-down.tree-menu > ul').empty();	
				            }else{
				            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
				            }
							self.insertDataSet(self.infoTreeList[e.value], self.infoTreeList[e.value][0]['DATASOURCE']);	
						/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 리스트 겹치는 오류 수정 */
						} else if(self.infoTreeList[e.value][0] && self.infoTreeList[e.value][0]['DATASOURCE'] != undefined && self.infoTreeList[e.value][0]['TYPE'] == 'CUBE') {
							if(WISE.Constants.editmode != 'viewer'){
				            	$('.drop-down.tree-menu > ul').empty();	
				            }else{
				            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
				            }
							var n = new WISE.libs.CubeData();
							/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200212 */
							var $cubeFieldSearch = $("#cubeFieldSearch");
							if($("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch").length > 0 && WISE.Constants.editmode == "viewer"){
								$cubeFieldSearch = $("#dataArea_"+WISE.Constants.pid+" #cubeFieldSearch")
							}
							var searchText = $cubeFieldSearch.dxTextBox('instance').option('value');
							n.insertDataSet(self.infoTreeList[e.value], self.infoTreeList[e.value][0]['DATASOURCE'], searchText);
						}
						
						var valueTrees = gDashboard.datasetMaster.getState('FIELDS');
						var dsId = gDashboard.datasetMaster.utility.getMapIdByDatasetName(e.value);
                        if (dsId && valueTrees[dsId]) {
                            gDashboard.datasetMaster.setState({ selectedDataset: dsId });
                            gDashboard.datasetMaster.createDatasetFieldTree(valueTrees[dsId], dsId);	
                        }
					}else{
						/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
//						$('.drop-down.tree-menu > ul').empty();
					}
	
				}
			});
//		}
	};
	
	/*dogfoot 분석항목 폴더 그룹화 shlim 20210311*/
	this.insertDataSet = function(_dataSet,_dataSourceId){
		var html = '<li class="active" id="'+_dataSourceId+'">';
		var meaCount = 0, dimCount = 0,meaHtml="",dimHtml="", sortCount = 0, sortHtml = "";
		
		/* 20200330 ajkim 측정값이 앞쪽에 정렬되도록 수정 dogfoot */
		if(_dataSet.length <= 0) return;
//		_dataSet.sort(function(a,b){
//			return (a.ORDER <b.ORDER) ? -1 : (a.ORDER > b.ORDER) ? 1 : 0;
//		});
		
		/*dogfoot 폴더화 정렬 추가 shlim 20210408*/
//		if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
//    		_dataSet.sort(function(a,b){
//        		if(typeof a.DATASOURCE != "undefined"){
//        			return -1;
//                }
//                if(typeof b.DATASOURCE != "undefined"){
//        			return 1;
//                }
//    			return a.ORDINAL < b.ORDINAL ? -1 : a.ORDINAL < b.ORDINAL ? 1 : 0;
//    		})
//		}
		var customTF = true;
		$.each(_dataSet,function(_i,_data){
			if(_data.CUSTOM_DATA || _data.isCustomField) {
				customTF = false;
			}
		});
		
		if(customTF) {
			var customJson;
			var customJsonList = [];
			$.each(gDashboard.customFieldManager.fieldInfo[_dataSourceId],function(_ii,_ee){
				var customJson = {
						CAPTION: _ee.Name,
						DATA_TYPE: _ee.DataType,
						ORDER: gDashboard.customFieldManager.originalFieldInfo.length,
						PARENT_ID: 0,
						TYPE: (_ee.DataType === 'Decimal') ? 'MEA' : 'DIM',
						UNI_NM: _ee.Name,
						CUBE_UNI_NM: _ee.Name,
						icon: '',
						FLD_TYPE: '',
						isCustomField: true,
						CUSTOM_DATA: true
				};
				customJsonList.push(customJson);
			});

			_dataSet = _dataSet.concat(customJsonList);
		}
		
		$.each(_dataSet,function(_i,_data){
			// ingeter형식으로 들어오는 캡션명 문자열로 변경
			_data.CAPTION = _data.CAPTION + '';
			_data.UNI_NM = _data.UNI_NM + '';
			var iconField = (_data.TYPE == 'MEA')?"sigma":"block";
			var dataFieldType = (_data.TYPE == 'MEA')?"measure":"dimension";
			if(_i == 0){
		//		html += '<a href="#" class="ico arrow" dataset-caption="'+_data.CAPTION+'">'+_data.CAPTION+'</a>';
		//		html += '<ul class="dep dataset" style="display:block">';		
			}else{
				var _hideColumn = false;
				if(WISE.Constants.companyname == "고용정보원"){
					if(WISE.Constants.editmode == "viewer" && (_data.CAPTION.indexOf("H_") == 0
							|| _data.CAPTION.indexOf('S_') == 0)){
						_hideColumn = true;
					}
				}
				if(!_hideColumn){
					if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
						if(_data.TYPE == 'MEA'){
							if(meaCount == 0){
								meaHtml += '<li id="측정값" class="wise-fld-area active" >';
								meaHtml += '<a href="#" class="ico arrow" dataset-caption="측정값">측정값</a>';
								meaHtml += '<ul class="dep dataset" style="display:block">';
							}
							meaCount++;
							
							if(_data.VISIBLE == undefined || _data.VISIBLE == true){
								if(_data.UNI_NM != undefined){
									if(_data.CUSTOM_DATA){
										meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" CUSTOM_DATA="Y" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico custom '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
									}else{
										meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';		
									}	
								}else{
									meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
								}
							}
						}else if(_data.CAPTION.indexOf('S_') == 0 || _data.CAPTION.indexOf('H_') == 0) {
							if(sortCount == 0){
								sortHtml += '<li id="정렬항목" class="wise-fld-area" >';
								sortHtml += '<a href="#" class="ico arrow" dataset-caption="정렬항목">정렬항목</a>';
								sortHtml += '<ul class="dep dataset" style="display:none">';
							}
							sortCount++;
							
							if(_data.VISIBLE == undefined || _data.VISIBLE == true){
								if(_data.UNI_NM != undefined){
									if(_data.CUSTOM_DATA){
										sortHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" CUSTOM_DATA="Y" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico custom '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
									}else{
										sortHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';		
									}	
								}else{
									sortHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
								}
							}
						} else {
							if(dimCount == 0){
								dimHtml += '<li id="분석항목" class="wise-fld-area active" >';
								dimHtml += '<a href="#" class="ico arrow" dataset-caption="분석항목(행, 열)">분석항목(행, 열)</a>';
								dimHtml += '<ul class="dep dataset" style="display:block">';
							}
							dimCount++;
							
							if(_data.VISIBLE == undefined || _data.VISIBLE == true){
								if(_data.UNI_NM != undefined){
									if(_data.CUSTOM_DATA){
										dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" CUSTOM_DATA="Y" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico custom '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
									}else{
										dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';		
									}	
								}else{
									dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
								}
							}
						}
					}else{
						if(_data.VISIBLE == undefined || _data.VISIBLE == true){
							if(_data.UNI_NM != undefined){
								//2020.01.21 mksong title 추가 dogfoot
								/*dogfoot 사용자정의 데이터  구분자 추가 shlim 20200716*/
								if(_data.CUSTOM_DATA){
									/* dogfoot 사용자 정의 데이터 아이콘 변경 shlim 20201022 */
		                            html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" CUSTOM_DATA="Y" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico custom '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
								}else{
								    html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';		
								}	
							}else{
								//2020.01.21 mksong title 추가 dogfoot
								html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
							}
						}
					}
				}
				
			}
		});
		if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
			dimHtml += '</ul></li>';
			sortHtml += '</ul></li>';
			meaHtml += '</ul></li>';
			html += dimHtml;
			html += sortHtml;
			html += meaHtml;
		}
		
	//	html += '</ul>';
	//	html += '</li>';

		// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot
		if(WISE.Constants.editmode == 'viewer'){
			$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty().append(html); // 2021-07-07 yyb clear 되지 않는 경우 있어 empty() 추가
		}else{
			$('.drop-down.tree-menu > ul').append(html);
		}
		$('.dataset > li').not('.wise-fld-area').draggable(gDashboard.dragNdropController.draggableOptions);
		treeMenuUi();
	};
	
	
//	this.insertDataSet = function(_dataSet,_dataSourceId){
//		var html = '<li class="active" id="'+_dataSourceId+'">';
//		/* 20200330 ajkim 측정값이 앞쪽에 정렬되도록 수정 dogfoot */
//		if(_dataSet.length <= 0) return;
//		_dataSet.sort(function(a,b){
//			return (a.ORDER <b.ORDER) ? -1 : (a.ORDER > b.ORDER) ? 1 : 0;
//		});
//		$.each(_dataSet,function(_i,_data){
//			var iconField = (_data.TYPE == 'MEA')?"sigma":"block";
//			var dataFieldType = (_data.TYPE == 'MEA')?"measure":"dimension";
//			if(_i == 0){
//				html += '<a href="#" class="ico arrow" dataset-caption="'+_data.CAPTION+'">'+_data.CAPTION+'</a>';
//				html += '<ul class="dep dataset" style="display:block">';		
//			}else{
//				if(_data.VISIBLE == undefined || _data.VISIBLE == true){
//					if(_data.UNI_NM != undefined){
//						//2020.01.21 mksong title 추가 dogfoot
//						/*dogfoot 사용자정의 데이터  구분자 추가 shlim 20200716*/
//						if(_data.CUSTOM_DATA){
//							/* dogfoot 사용자 정의 데이터 아이콘 변경 shlim 20201022 */
//                            html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" CUSTOM_DATA="Y" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico custom '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
//						}else{
//						    html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';		
//						}	
//					}else{
//						//2020.01.21 mksong title 추가 dogfoot
//						html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
//					}
//				}
//			}
//		});
//		/*
//		if(_dataSet[0].DATASET_TYPE == 'DataSetSingleDs' || _dataSet[0].DATASET_TYPE == 'DataSetSingleDsView'){
//			$.each(_dataSet,function(_i,_data){
//				if(_i == 0){
//					html += '<a href="#" class="ico arrow">'+_data.CAPTION+'</a>';
//					html += '<ul class="dep dataset" style="display:block">';
//				}else{
//					if(_data.VISIBLE == undefined || _data.VISIBLE === true){
//						if(_data.TYPE == 'MEA'){
//							//2020.01.21 mksong title 추가 dogfoot
//							html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
//						}else{
//							//2020.01.21 mksong title 추가 dogfoot
//							html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
//						}
//					}
//				}
//			});
//		}else{
//			$.each(_dataSet,function(_i,_data){
//				if(_i == 0){
//					html += '<a href="#" class="ico arrow" dataset-caption="'+_data.CAPTION+'">'+_data.CAPTION+'</a>';
//					html += '<ul class="dep dataset" style="display:block">';		
//				}else{
//					if(_data.VISIBLE != undefined){
//						if(_data.VISIBLE == true){
//							if(_data.TYPE != 'MEA'){
//								if(_data.UNI_NM != undefined){
//									//2020.01.21 mksong title 추가 dogfoot
//									dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
//								}else{
//									//2020.01.21 mksong title 추가 dogfoot
//									dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
//								}
//							}
//						}
//					}else{
//						if(_data.TYPE != 'MEA'){
//							if(_data.UNI_NM != undefined){
//								//2020.01.21 mksong title 추가 dogfoot
//								dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
//							}else{
//								//2020.01.21 mksong title 추가 dogfoot
//								dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
//							}
//						}
//					}
//				}
//			});
//			
//			$.each(_dataSet,function(_i,_data){
//				if(_i != 0){
//					if(_data.VISIBLE != undefined){
//						if(_data.VISIBLE == true){
//							if(_data.TYPE == 'MEA'){
//								if(_data.UNI_NM != undefined){
//									//2020.01.21 mksong title 추가 dogfoot
//									meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
//								}else{
//									//2020.01.21 mksong title 추가 dogfoot
//									meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
//								}
//							}
//						}
//					}else{
//						if(_data.TYPE == 'MEA'){
//							if(_data.UNI_NM != undefined){
//								//2020.01.21 mksong title 추가 dogfoot
//								meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
//							}else{
//								//2020.01.21 mksong title 추가 dogfoot
//								meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
//							}
//						}
//					}
//				}
//			});
//		}
//		*/
//		
//		html += '</ul>';
//		html += '</li>';
//
//		// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot
//		if(WISE.Constants.editmode == 'viewer'){
//			$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').append(html);
//		}else{
//			$('.drop-down.tree-menu > ul').append(html);
//		}
//		$('.dataset > li').draggable(gDashboard.dragNdropController.draggableOptions);
//		treeMenuUi();
//	};
	
	this.openDataUpload = function(){
		//$("#sql_popup").empty();
		//$("#ds_popup").empty();
		
		self.createDxItems();
		var indexId,ds_id,uploadSubjects,uploadSubjectInfos;
		var html = "<div class=\"modal-inner\" style=\"height:calc(100% - 85px); width: 100%;\">\r\n" + 
		"                    <div class=\"modal-body\" style=\"height:100%\">\r\n" + 
		"                        <div class=\"row\" style='height:100%;'>\r\n" + 
		"                            <div class=\"column\" style=\"width:50%; height:100%\">\r\n" + 
		"                                <div class=\"modal-article\" style='height:100%;'>\r\n" + 
		"                                    <div class=\"modal-tit\">\r\n" + 
		"                                        <span>데이터원본 목록</span>\r\n" + 
		"                                    </div>\r\n" + 
		"                                    <div id=\"dataset_list\"/>\r\n" + 
		"                                </div>\r\n" + 
//		"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
		"                            </div>\r\n" + 
		"                            <div class=\"column\" style=\"width:50%; height:100%;\">\r\n" + 
		"                                <div class=\"modal-article\" style='height:100%;'>\r\n" + 
		"                                    <div class=\"modal-tit\">\r\n" + 
		"                                        <span>데이터원본 정보</span>\r\n" + 
		"                                    </div>\r\n" + 
		"                                    <div id=\"dataset_info\" >\r\n" + 
		"                                    </div>\r\n" + 
		"                                </div>\r\n" + 
		"                            </div>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                    <div class=\"modal-footer\">\r\n" + 
		"                        <div class=\"row center\">\r\n" + 
		"                            <a id=\"btn_subject_check2\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
		"                            <a id=\"btn_subject_cancel2\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                </div>";
		$.ajax({
			type : 'post',
			async : false,
			cache: false,
			url : WISE.Constants.context + '/report/uploadDsList.do',
			data:{
				'userId':userJsonObject.userId
			},
			complete: function() {
				//$('#progress_box').css({'display' : 'none'});
			},
			success : function(data) {
				//$('#progress_box').css({'display' : 'none'});

				data = jQuery.parseJSON(data);
				uploadSubjects = data["subjects"];
				uploadSubjectInfos = data["subjectInfos"];
			},
			error: function(error) {
				WISE.alert('error'+ajax_error_message(error),'error');
			}
		});
		if(uploadSubjects.length == 1){
//			uploadSubjects = data["subjects"];
//			uploadSubjectInfos = data["subjectInfos"];
			indexId = uploadSubjects[0]['ID'];
			ds_id = uploadSubjects[0]['DS_ID'];
			self.setUploadTable(ds_id,uploadSubjects[indexId]);
		}else{
			$('#sql_popup').dxPopup({
				showCloseButton: true,
				showTitle: true,
				title:"업로드 대상 데이터 원본 선택",
				visible: true,
				closeOnOutsideClick: false,
				contentTemplate: function() {
					return html;
				},
				width: '90vw',
	            height: '90vh',
	            maxWidth: 1300,
	            maxHeight: 830,
				onShown: function () {
					$.ajax({
						type : 'post',
						/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//						async : false,
						cache: false,
						url : WISE.Constants.context + '/report/uploadDsList.do',
						data:{
							'userId':userJsonObject.userId
						},
						complete: function() {
							//$('#progress_box').css({'display' : 'none'});
						},
						success : function(data) {
							//$('#progress_box').css({'display' : 'none'});

							data = jQuery.parseJSON(data);

							uploadSubjects = data["subjects"];
							uploadSubjectInfos = data["subjectInfos"];


							$("#dataset_list").dxDataGrid({
								dataSource: uploadSubjects,
								width: "100%",
								//height: "calc(100% - 50px)",
								height: "95%",
								showBorders: true,
								paging: {
									pageSize: 20
								},
								visible : true,
								columnAutoWidth: true,
								allowColumnResizing: true,
								columns: 
									[{dataField : '데이터원본 명', width : "40%"},  {dataField : 'DB 유형', width : "15%"},  
										{dataField : '서버 주소(명)', width : "25%"},  {dataField : '사용자 데이터', width : "20%"}]
								,
								selection:{
									mode:'single'
								},
								onContentReady: function(){
									gDashboard.fontManager.setFontConfigForListPopup('dataset_list')
								},
								onSelectionChanged: function (selectedItems) {

									indexId = selectedItems.selectedRowsData[0]['ID'];
									ds_id = selectedItems.selectedRowsData[0]['DS_ID'];
									
									var form = $("#dataset_info").dxForm('instance');
									form.option("formData", uploadSubjectInfos[indexId]);
								}
							});

							$("#dataset_info").dxForm({
								width: "100%",
								height: "100%",
								readOnly: true,
								formData: {},
								onContentReady: function(){
									gDashboard.fontManager.setFontConfigForListPopup('dataset_list')
								}
							});
							$("#btn_subject_cancel2").dxButton({
								text: "취소",
								type: "normal",
								onClick: function(e) {
									$("#sql_popup").dxPopup("instance").hide();
								}
							});
							$('#btn_subject_check2').dxButton({
								text: "확인",
								type: "normal",
								onClick: function(e) {
									if(ds_id != null){
										$("#sql_popup").dxPopup("instance").hide();
										self.setUploadTable(ds_id,uploadSubjects[indexId]);
									}
								}
							});
						},
						error: function(error) {
							WISE.alert('error'+ajax_error_message(error),'error');
						}
					});
				}
			})
		}
	};
	this.setUploadTable = function(ds_id,uploadSubjectsTarget){
		var selectedTableItem,globalDSData;
		$('#uploadTable_popup').remove();
		$('body').append('<div id="uploadTable_popup" class="data_popup"></div>');
		globalDSData = uploadSubjectsTarget;
		var html = "";
		html += '<div class="modal-inner" style="height:calc(100% - 85px); width: 100%;">';
		html += '	<div class="modal-body" style="height:100%;">';
		html += '		<div class="row" style="height:100%;">';
		html += '			<div class="column" style="width:40%; height:100%">';
		html += '				<div class="row horizen">';
		html += '					<div class="column" style="padding-bottom:0px;">';
		html += '						<div class="modal-article">';
		html += '							<div class="modal-tit">';
		html += '								<span>데이터 원본 정보</span>';
		html += '								<div id="ds_info"></div>';
		html += '							</div>';
		html += '						</div>';
		html += '					</div>';
		html += '				</div>';
		html += '			</div>';
		html += '			<div class="column" style="width:55%;height:100%">';
		html += '				<div class="row horizen">';
		html += '					<div class="column" style="padding-bottom:0px;height:100%;">';
		html += '						<div class="modal-article" style="height:100%;">';
		html += '							<div class="modal-tit" style="height:100%;">';
		html += '								<span>테이블 목록</span>';
		html += '								<div id="tblList"></div>';
		html += '							</div>';
		html += '						</div>';
		html += '					</div>';
		html += '				</div>';
		html += '			</div>';
		html += '		</div>';
		html += '	</div>';
		html += '	<div class="modal-footer" style="padding-top:15px;">';
		html += '		<div class="row center">';
		html += '			<a id="btn_table_OK" class="btn positive ok-hide" href="#" >확인</a>';
		html += '			<a id="btn_table_cancel" class="btn neutral close" href="#">취소</a>';
		html += '		</div>';
		html += '	</div>';
		html += '</div>';
		$.ajax({
			type : 'post',			
			/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//			async : false,
			cache: false,
			url : WISE.Constants.context + '/report/uploadTableList.do',
			data:{
				'userId':userJsonObject.userId,
				'DS_ID':ds_id
			},
			success:function(_data){
				$('#uploadTable_popup').dxPopup({
					contentTemplate: html,
					visible:true,
					title:'테이블 선택',
					width: '90vw',
		            height: '90vh',
		            maxWidth: 900,
		            maxHeight: 850,
		            onContentReady: function(){
						gDashboard.fontManager.setFontConfigForListPopup('dataset_list')
					},
					onShown:function(){
						_data = jQuery.parseJSON(_data);
						$('#tblList').dxDataGrid({
							columns: [
								{dataField : 'DATA_NM', caption:"테이블 논리명"},  
								{dataField : 'TBL_NM', caption:'테이블 물리명'},  
							],
							onContentReady: function(){
								gDashboard.fontManager.setFontConfigForListPopup('tblList')
							},
							width:470,
							height:'103%',
							selection:'single',
							dataSource:_data,
//							onSelectionChanged:function(_e){
//								if(selectedTableItem != undefined){
//									if(selectedTableItem == _e.selectedRowsData[0]){
//										selectedTableItem = [];
//									}
//								}else{
//									selectedTableItem = _e.selectedRowsData[0];
//								}
//							},
							onRowClick:function(_e){
								if(selectedTableItem != undefined){//같은 아이템 선택(선택 취소)
									if(selectedTableItem == _e.key){
										selectedTableItem = undefined;
										$('#tblList').dxDataGrid('clearSelection');
									}else{//다른 아이템 선택
										selectedTableItem = _e.key;
									}
								}else{//첫 선택
									selectedTableItem = _e.key;
								}
								
							}
						
						});
					}
				});
				$("#ds_info").dxForm({
					width: 300,
					height: 200,
					readOnly: true,
					formData: globalDSData,
					items: [{
						dataField: "데이터원본 명",
					},{
						dataField: "서버 주소(명)",
					},{
						dataField: "DB 명",
					},{
						dataField: "DB 유형",
					}]
				});
				$('#btn_table_cancel').dxButton({
					onClick:function(){
						$('#tblList').dxDataGrid('instance').option('dataSource',[]);
						$('#tblList').dxDataGrid('instance').clearSelection();
						$("#uploadTable_popup").dxPopup("instance").hide();
					}
				});
				$('#btn_table_OK').dxButton({
					onClick:function(){
						$("#uploadTable_popup").dxPopup("instance").hide();
						var html = "";
						html += '<div class="modal-inner" style="height:100%">';
						html += '	<div class="modal-body" style="height:calc(100% - 65px)">';
						html += '		<div class="row" style="height:100%">';
						html += '			<div class="column" style="width:100%">';
						html += '				<div class="row horizen">';
						html += '					<div class="column" style="padding-bottom:0px;">';
						html += '						<div class="modal-article">';
						html += '							<div class="modal-tit">';
						html += '								<span>데이터 집합 명</span>';
						html += '								<div>'
						/* DOGFOOT ktkang 사용자 업로드 UI 수정  20200923 */
						html += '									<div id="dataNm" style="float:left; margin-top:5px;"></div>';
						html += '									<div id="tableDeleteYN" style="float:right"></div>';
						html += '								</div>'
						html += '							</div>';
						html += '						</div>';
						html += '					</div>';
						html += '					<div class="column" style="padding-top:0px;-bottom:0px;border-top:0px solid;height:200px">';
						html += '						<div class="modal-article">';
						html += '							<div id="upload_area" class="param_area modal-tit">';
						html += '								<span>업로드 파일 선택</span>';
						html += '								<div>'
						html += '									<div id="chkEncode"></div>';
						html += '									<div id="fileUploader"></div>';
						html += '								</div>'
						html += '							</div>';
						html += '						</div>';
						html += '					</div>';
						html += '					<div class="column" style="padding-top:0px;padding-bottom:0px;border-top:0px solid; height: 45%;">';
						html += '						<div class="modal-article" style="height: 100%;">';
						html += '							<div id="param_area" class="param_area modal-tit" style="height: 100%;">';
						html += '								<span>컬럼 정보</span>';
						html += '								<div id="columnInfo"></div>';
						html += '							</div>';
						html += '						</div>';
						html += '					</div>';
						html += '				</div>';
						html += '			</div>';
						html += '		</div>';
						html += '	</div>';
						html += '	<div class="modal-footer" style="padding-top:15px; border:none !important;">';
						html += '		<div class="row center">';
						html += '			<a id="btn_Upload_OK" class="btn positive ok-hide" href="#" >확인</a>';
						html += '			<a id="btn_Upload_cancel" class="btn neutral close" href="#">취소</a>';
						html += '		</div>';
						html += '	</div>';
						html += '</div>';
						$('#ds_popup').dxPopup({
							contentTemplate: html,
							visible:true,
							title:'업로드 파일 선택',
							width: '90vw',
				            height: '90vh',
				            maxWidth: 700,
				            maxHeight: 900,
							onContentReady: function(){
								gDashboard.fontManager.setFontConfigForListPopup('ds_popup')
							},
							onShown: function(e){
								/*dogfoot 스프레드시트 데이터 연동시 알림창 뜨는 오류 shlim 20200717*/
								if(e.component.option('title') === '업로드 파일 선택'){
								    WISE.alert('업로드 알림<br>업로드 할 파일은 첫번째 시트만 업로드 되고 1행에 헤더가 있어야 하며 .xls .xlsx .csv 파일만 가능합니다.');	
								}
								var dataNm = "",appendTable="",targetTable="",tableDeleteYN="";

								if(selectedTableItem != undefined){
									dataNm = selectedTableItem.DATA_NM;
									targetTable = selectedTableItem.TBL_NM;
									appendTable = true;
								}
								$('#tblList').dxDataGrid('instance').clearSelection();
								$('#tblList').dxDataGrid('instance').option('dataSource',[]);
								$('#dataNm').dxTextBox({
									visible:true,
									value:dataNm,
									/* DOGFOOT ktkang 사용자 업로드 UI 수정  20200923 */
									width:'100%',
									readOnly:targetTable === "" ? false:true
								});
								if(appendTable != ""){
									$("#tableDeleteYN").dxCheckBox({
										visible:true,
										text:"데이터 삭제 후 추가",
									});
								}else{
									$("#tableDeleteYN").dxCheckBox({
										visible:false,
										text:"데이터 삭제 후 추가",
									});
								}
								
								$("#chkEncode").dxCheckBox({
									text:"UTF-8",
									onValueChanged: function(e){
										var uploader = $("#fileUploader").dxFileUploader("instance");  
										var url = WISE.Constants.context + '/report/Upload/data.do?ckutf='+e.value;  
										uploader.option("uploadUrl", url);
									},
								});
								var lookupData = [{
														caption: 'String',
														value: 'String'
													},{
														caption: 'Int',
														value: 'int'
													},{
														caption: 'Float',
														value: 'float'
													},{
														caption: 'Double',
														value: 'double'
													}];
								
								$('#columnInfo').dxDataGrid({
									columns:[
										{
												dataField: "colNm",
												caption:"컬럼명",
												allowEditing: false
										},
										{
												dataField: "colPhysicalNm",
												caption:"컬럼 물리명",
												allowEditing: false
										},
										/*{
												dataField: "colType",
												caption:"데이터유형",
												cellTemplate: function (container, options) {
													
														$("<div style='width:15px; height:15px;margin-right:5px'>")

													
												}
										},*/
										{
												dataField: "colType",
												caption:"데이터유형",
										},
										{
												dataField: "colSize",
												caption:"길이"
										},
									],
									height:'350px',
									dataSource:[],
									editing: {
										mode: 'cell',
										allowUpdating: true,
										texts: {
											confirmDeleteMessage: ''
										},
										useIcons: false,
									},
									onRowUpdating:function(e){
										console.log();
									}
								});
								$('#btn_Upload_cancel').dxButton({
									onClick:function(){
										$('#columnInfo').dxDataGrid('instance').option('dataSource',[]);
										$("#ds_popup").dxPopup("instance").hide();
										$('#fileUploader').dxFileUploader('instance').reset();
									}
								})
								/*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 shlim 20210120*/
								$('#fileUploader').dxFileUploader({
									multiple: false,
									selectButtonText:'선택하세요',
									labelText:'',
									uploadedMessage:"업로드 완료",

									allowedFileExtensions: ['.xls','.xlsx','.csv'],
									uploadUrl: WISE.Constants.context + '/report/Upload/data.do?ckutf=false',
									onUploadStarted:function(){
//										gProgressbar.show();
									},
									onUploadError:function(e){
										WISE.alert(e.request.status+ ", " + e.request.statusText,'error');
//										gProgressbar.hide();
									},
									onUploaded:function(_e){
										var data = JSON.parse(_e.request.responseText);
										gProgressbar.hide();
										$('#columnInfo').dxDataGrid('instance').option('dataSource',data);
										$('#btn_Upload_OK').dxButton({
											text:"업로드 시작",
											onClick:function(){
												if($('#dataNm').dxTextBox("instance").option("value") != ""){
													
//													var datasetInfo = $("#dataset_info").dxForm('instance').option('formData');
//													var datasetInfo = subjectInfos[indexId];
													var datasetInfo = uploadSubjectsTarget;
													var dataName = $('#dataNm').dxTextBox("instance").option("value");
													var sameDsName = false;
													$.each(gDashboard.datasetMaster.state.datasets, function(id, ds) {
														if (ds.DATASET_NM === dataName) {
															sameDsName = true;
														}
													});
													if(sameDsName) {
														WISE.alert('현재 같은 이름의 데이터 집합명이 존재합니다.');
													} else {
														$("#ds_popup").dxPopup("instance").hide();
														gProgressbar.show();
														if(appendTable != ""){
															if($('#tableDeleteYN').dxCheckBox('instance').option('value') == true){
																tableDeleteYN = "Y";
															}
														}
														var dataparam = {
															"DS_ID" : globalDSData.DS_ID,
															"ID" : globalDSData.USER_ID,
															"IP" : globalDSData.IP,
															"DB_TYPE" : globalDSData.DB_TYPE,
															"DB_NM" : globalDSData.DB_NM,
															"PORT" : globalDSData.PORT,
															"OWNER" : globalDSData.OWNER,
															"TBL_CAPTION":dataName,
															/*dogfoot 사용자업로드데이터 데이터 타입 변경기능 추가 shlim 20210120*/
															/*dogfoot 사용자업로드데이터 데이터 컬럼 21개 이상 일때 업로드 오류 수정 shlim 20210219*/
															"colList" : $.toJSON($('#columnInfo').dxDataGrid('instance').getDataSource()._store._array),
															"appendTable" : appendTable,
															'targetTable':Base64.encode(targetTable),
															'tableDeleteYN' : tableDeleteYN,
															'userId':userJsonObject.userId,
															'ckutf': $('#chkEncode').dxCheckBox('instance').option('value'),
														}
														/* DOGFOOT 20201021 ajkim setTimeout 제거*/
														$.ajax({
															type:"POST",
															url :  WISE.Constants.context + '/report/Upload/save.do',
															/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
															async : false,
															cache: false,
															data: (dataparam),
															beforeSend:function(){
																gProgressbar.show();
															},
															success: function(_data){
																gProgressbar.hide();
																_data = JSON.parse(_data);
																if(_data.code == 200){
																	
																	$('#fileUploader').dxFileUploader('instance').reset();
																	var options = {
																			buttons: {
																				confirm: {
																					id: 'confirm',
																					className: 'blue',
																					text: '확인',
																					action: function() {
																						$AlertPopup.hide();
																						gProgressbar.show();
																						self.openUploadTable(globalDSData.DS_ID,datasetInfo,dataName,_data.TableName,appendTable);
																						return false;
																					}
																				}
																			}
																	};
																
																	WISE.alert('사용자 데이터 업로드 정보 성공<br>대상테이블 논리명 : '+_data.dataName+'<br>대상테이블 물리명 : '+_data.TableName+'<br>테이블 총 레코드 건수 : '+_data.REC_count,'', options);
																	
																}else{
																	/* DOGFOOT ktkang 사용자 데이터 업로드 알림창 구현  20200904 */
																	alert("분석에 실패했습니다.관리자에게 문의하세요.");
																	gProgressbar.hide();
																}
															}
														});													}
												} else {
													WISE.alert('데이터집합명을 입력해주세요.');
												}
											}
										});
									}
								});
							}
						});

					}
				});
			},
			error: function(error) {
				WISE.alert('error'+ajax_error_message(error),'error');
			}
		});
	}
	this.openUploadTable = function(ds_id, dsInfo, datasetName, TableName,appendTable){
		gProgressbar.show();
		var uploaddsInfo = dsInfo;
		// var sql_areaText = $("#sql_area").dxTextArea('instance').option('value');
		
		var param = {
			'DATASET_NM' :  datasetName,
			'DATASET_TYPE' : 'DataSetSQL',
			'DATASRC_ID' : ds_id,
			'DATASRC_TYPE' : 'DS_SQL',
			'SQL_QUERY' : 'SELECT * FROM ' + TableName + ' ',
			'params' : {}
		};
		/* DOGFOOT hsshim 1220
		 * 조회 실페후 화면이 멈추는 형상 수정
		 */
//		$("#ds_popup").dxPopup("instance").hide();
		$.ajax({
			method : 'POST',
			url: WISE.Constants.context + '/report/directSqlDataSetInfo.do',
			data: param,
			complete: function(){
//				$('#progress_box').css({'display' : 'none'});
			},
			success: function(data) {
				data = jQuery.parseJSON(data);
				
				if(!data['error'] && data['data'].length != 0) {
					/* DOGFOOT hsshim 1220
					 * 조회 실페후 화면이 멈추는 형상 수정
					 */
					$("#ds_popup").dxPopup("instance").hide();
					/* DOGFOOT ktkang 사용자 데이터 업로드 오류 수정  20201111 */
					data.userUpload = "Y";
					var confirmOk;
					//2020.02.12 mksong 뷰어 비정형 컬럼선택기 오류 수정 dogfoot
					if(gDashboard.dataSourceQuantity > 0 && gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode != 'viewer') {
						if(gDashboard.dataSourceQuantity > 0) {
							confirmOk = confirm('비정형모드에서는 데이터 집합이 1개만 사용됩니다. 기존 데이터집합을 삭제하고 추가하시겠습니까?');
							if(confirmOk){
								gDashboard.dataSourceQuantity = 0;
								gDashboard.dataSourceManager.datasetInformation = {};
								gDashboard.dataSetCreate.lookUpItems = [];
								gDashboard.dataSetCreate.infoTreeList = [];
								gDashboard.parameterFilterBar.parameterInformation = {};
								gDashboard.datasetMaster.state.params = [];
								/*dogfoot 비정형 필터 영역 초기화 shlim 20210319*/
								/*dogfoot shlim 20210415*/
								$('#report-filter-item').empty();
								$('.panelClear').click();
								var pivot = gDashboard.itemGenerateManager.dxItemBasten[0].type === 'PIVOT_GRID'? gDashboard.itemGenerateManager.dxItemBasten[0] : gDashboard.itemGenerateManager.dxItemBasten[1];
								pivot.deltaItems=[];
								gDashboard.itemGenerateManager.clearItemData();
								$('.wise-area-deltaval').css('display', 'none');
							} else {
								return false;
							}
						} else {
							confirmOk = true;
						}
					} else {
						confirmOk = true;
					}
					
					if(confirmOk){
//						if(appendTable == ""){
//							gDashboard.dataSetCreate.lookUpItems.push(data['DATASET_NM']);
//							gDashboard.dataSourceQuantity++;
//						}
						
						gDashboard.dataSourceQuantity++;
						for(var i = 0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
							if('dataSource'+self.dataSourceQuantity == _.keys(gDashboard.dataSourceManager.datasetInformation)[i]){
								gDashboard.dataSourceQuantity++;
							}
						}

						data['mapid'] = 'dataSource' + gDashboard.dataSourceQuantity;
						gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity]= data;


						var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE' : 'dataSource' + gDashboard.dataSourceQuantity}];

						var i = 1;
						for(var key in data['data'][0]) {
							var type;
							var iconPath;
							var dataType;
							switch(data['data'][0][key]) {
							case 'decimal': 
								type = 'MEA';
								iconPath = '../images/icon_measure.png';
								dataType = 'decimal';
								break;
							default:
								type = 'DIM';
							iconPath = '../images/icon_dimension.png';
							dataType = 'varchar';
							}

							var infoTree = [{'CAPTION': key, 'ORDER': i, 'PARENT_ID': "0", 'TYPE': type,  'icon': iconPath, 'DATA_TYPE': dataType}];

							dataSetInfoTree = dataSetInfoTree.concat(infoTree);
							i++;
						}

						gDashboard.dataSetCreate.infoTreeList[data['DATASET_NM']] = dataSetInfoTree;
						gDashboard.dataSetCreate.paramTreeList['dataSource' + gDashboard.dataSourceQuantity] = [];
						gDashboard.dataSetCreate.subjectInfoList['dataSource' + gDashboard.dataSourceQuantity] = uploaddsInfo;
						data['DATA_META'] = dataSetInfoTree;
						if(WISE.Constants.editmode != 'viewer'){
			            	$('.drop-down.tree-menu > ul').empty();	
			            }else{
			            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
			            }
						self.insertDataSet(data['DATA_META'],'dataSource'+gDashboard.dataSourceQuantity);
						
//						if(appendTable == ""){
							gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName':'dataSource' + gDashboard.dataSourceQuantity,"Name":data['DATASET_NM']});
//						}
					
						$('.cont_query').empty();
						//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
						$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
						$('#btn_query').off();
						$('#btn_query').on('click', function() {
							/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
							if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
								gDashboard.itemGenerateManager.selectedTabList = [];
								gDashboard.tabQuery = true;
							}
							
							gDashboard.queryByGeneratingSql = true;
							gDashboard.itemGenerateManager.clearTrackingConditionAll();
							/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
							gDashboard.itemGenerateManager.clearItemData();
							gDashboard.query();
							this.blur();
						});
						
						gDashboard.dataSetCreate.lookUpItems.push({
							DATASET_NM:data['DATASET_NM'],
							mapid:data['mapid']
						});
    					
						var newLookUpItems=[];
						$.each(gDashboard.reportUtility.reportInfo.DataSources.DataSource, function(_id, _ds) {
							if (typeof _ds === 'string') {
								newLookUpItems.push(_ds);
							} else {
								newLookUpItems.push(_ds.Name);
							}
							if(gDashboard.reportType === 'AdHoc') return false;
						});
						
						var lookUpIns;
//						if(gDashboard.reportType == "Spread" || gDashboard.reportType == "Excel"){
//							lookUpIns = $("#dataSetLookUp").dxList('instance');
//							lookUpIns.option('dataSource', newLookUpItems);
//						} else {
							var $dataSetLookUp = $("#dataSetLookUp");
							
							if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
								$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
							}
							lookUpIns = $dataSetLookUp.dxLookup('instance');
							lookUpIns.option('items', newLookUpItems);
							lookUpIns.option('value', data['DATASET_NM']);
//						} 
						
						//2020.05.20 HJKIM refactoring state add DOGFOOT
						gDashboard.datasetMaster.migDatasetToState('dataSource'+gDashboard.dataSourceQuantity);
					}

					gProgressbar.hide();
				} 
				/* DOGFOOT hsshim 1220
				 * 데이터 없는 경우 행동 수정
				 */
				else if (!data['error'] && data['data'].length === 0) {
					gProgressbar.hide();
					WISE.alert('결과 데이터가 없습니다.');
				}
				else {
					gProgressbar.hide();
					WISE.alert('쿼리가 부적합 합니다.');
				}
			},error: function(_response) {
				gProgressbar.hide();
				WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
			}
		});
	}
}

WISE.libs.ConnectDataSetSpread = function() {
var self = this;
	
	this.init = function() {
		$('.viewer').on('click',function(e){
			self.render();
		});
	}

	this.render = function() {
		var html = "<div class=\"modal-inner\" style='height:100%;' >\r\n" + 
		"                    <div class=\"modal-body\" style='height:calc(100% - 50px);'>\r\n" + 
		"                        <div class=\"row\">\r\n" + 
		"                            <div class=\"column\" style=\"width:100%\">\r\n" + 
		"                                <div class=\"modal-article\">\r\n" +
		"                                    <div id=\"bindType_switch\"/>\r\n" +
		"                                    <div id=\"datasetCon_list\"/>\r\n" + 
		"                                </div>\r\n" + 
		"                            </div>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                    <div class=\"modal-footer\">\r\n" + 
		"                        <div class=\"row center\">\r\n" + 
		"                            <a id=\"btn_datasetcon_check\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
		"                            <a id=\"btn_datasetcon_cancel\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                </div>";
		$('#ds_popup').dxPopup({
			showCloseButton: true,
			showTitle: true,
			title:"데이터 집합과 Sheet 연동",
			visible: true,
			closeOnOutsideClick: false,
			contentTemplate: function() {
				return html;
			},
			width: '90vw',
            height: '90vh',
            maxWidth: 800,
            maxHeight: 600,
            onContentReady: function(){
				gDashboard.fontManager.setFontConfigForListPopup('ds_popup')
			},
			onShown: function () {
//				var lookup = $("dataSetLookUp").dxLookup('instance');
				
				var selectedItems = [] ;
				var tempDatasetInformation = gDashboard.dataSourceManager.datasetInformation;			
//				var lookup = gDashboard.dataSetCreate.lookUpItems;
				var gridData = [];
				var dataJson;
				$.each(tempDatasetInformation, function(_i, _o) {
					dataJson = new Object()
					dataJson.datasetName = _o.DATASET_NM;
					/*dogfoot 엑셀 스프레드시트 저장불러오기 오류 수정 shlim 20201123*/
					if(!_.isUndefined(tempDatasetInformation[_o.mapid].SHEET_ID) && tempDatasetInformation[_o.mapid].SHEET_ID != ""){
						dataJson.sheetNames = gDashboard.spreadsheetManager.getSheetNameFromID(Number(tempDatasetInformation[_o.mapid].SHEET_ID.substring(5))-1);
						//20200702 AJKIM SHEET_NM값 SHEET_ID로 대체
						//dataJson.sheetNames = tempDatasetInformation[_o.mapid].SHEET_ID;
					}
					dataJson.mapid = _o.mapid;
					/*dogfoot 테이블 바인드 바인드 위치 설정 shlim 20200727*/
					if(gDashboard.spreadsheetManager.bindingXY[tempDatasetInformation[_o.mapid].SHEET_ID]){
						dataJson.xy = gDashboard.spreadsheetManager.bindingXY[tempDatasetInformation[_o.mapid].SHEET_ID];
					}
					/*dogfoot 테이블 헤더 표시 여부 추가 shlim 20200805*/
					if(gDashboard.spreadsheetManager.showTableHeader[tempDatasetInformation[_o.mapid].SHEET_ID]){
						dataJson.showHeader = gDashboard.spreadsheetManager.showTableHeader[tempDatasetInformation[_o.mapid].SHEET_ID];
					}
					dataJson.spreadtable = gDashboard.queryHandler.spreadtable;
					gridData.push(dataJson);
				});
				
//				if(gDashboard.isNewReport){
//					$("#bindType_switch").dxSwitch({
//						value: gDashboard.queryHandler.spreadtable,
//						switchedOffText:"시트",
//						switchedOnText:"테이블",
//						width:'auto',
//						height:'auto',
//						onValueChanged:function(_e){
//							if(typeof gridData != 'undefined' && gridData.length != 0){
//								$.each(gridData,function(_i,_data){
//									_data.spreadtable = _e.value
//								})
//							}
//							$("#datasetCon_list").dxDataGrid('instance').columnOption('xy', 'allowEditing', _e.value);
//							$("#datasetCon_list").dxDataGrid('instance').refresh();
//						}
//					});
//			    }
				
				$("#datasetCon_list").dxDataGrid({
			        dataSource: gridData,
			        onEditorPreparing: function (e) {
			        	if(e.dataField == 'sheetNames'){
			        		e.editorOptions.showClearButton = true;
			        	}else{
			        		return false;
			        	}
			        },
			        showBorders: true,
			        editing: {
			            allowUpdating: true,
			            mode: "cell"
			        },
			        columns: [
			        	{
			                dataField: "datasetName",
			                caption: "데이터 집합 명",
			                width: 240
			            },
			            {
			                dataField: "sheetNames",
			                caption: "Sheet 명",
			                width: 240,
			                setCellValue: function(rowData, value) {
			                	if(value !== null){
				                    rowData.sheetNames = value.sheetNames;
			                	}else{
			                		 rowData.sheetNames = "";
			                	}
			                },
			                lookup: {
			                    dataSource: gDashboard.spreadsheetManager.sheetNameData(),
			                    displayExpr: "sheetNames"
			                }
			            },
			            /*dogfoot 테이블 바인드 바인드 위치 설정 shlim 20200727*/
			            {
			                dataField: "xy",
			                caption: "연동 셀 위치",
			                width: 110
			                ,allowEditing:gDashboard.queryHandler.spreadtable
//			                ,visible: gDashboard.queryHandler.spreadtable
			            }
			            ,{
			                dataField: "showHeader",
			                caption: "헤더 표시 여부",
			                width: 110
			                ,allowEditing:gDashboard.queryHandler.spreadtable
			                ,setCellValue: function(rowData, value) {
			                	if(value !== null){
				                    rowData.showHeader = value;
			                	}
			                },
			                lookup: {
			                    dataSource:['표시','표시안함']
			                }
//			                ,visible: gDashboard.queryHandler.spreadtable
			            }
			        ]
			    });
			}
		});
		
		$("#btn_datasetcon_check").dxButton({
			text: "확인",
			type: "normal",
			onClick: function(e) {
				//time code
				window.startTime = window.performance.now();
				$.each(gDashboard.dataSourceManager.datasetInformation, function(_id, _ds) {
					delete gDashboard.dataSourceManager.datasetInformation[_ds.mapid].SHEET_ID;
				});
				 
				var gridins = $("#datasetCon_list").dxDataGrid('instance');
				var gridRowData = gridins.getVisibleRows();
				gDashboard.spreadsheetManager.bindingColRow = [];
				$.each(gridRowData, function(_id, _ds) {
					if(_ds.data.sheetNames !== undefined && _ds.data.sheetNames !== "") {
						gDashboard.dataSourceManager.datasetInformation[_ds.data.mapid].SHEET_ID = "Sheet"+(Number(gDashboard.spreadsheetManager.getSheetId(_ds.data.sheetNames))+1);
						if(_ds.data.setColumn){
							gDashboard.spreadsheetManager.bindingColumn = Number(_ds.data.setColumn);
						}						
						/*dogfoot 테이블 바인드 바인드 위치 설정 shlim 20200727*/
						var sheetId = "Sheet"+(Number(gDashboard.spreadsheetManager.getSheetId(_ds.data.sheetNames))+1);
						//gDashboard.dataSourceManager.datasetInformation[_ds.data.mapid].SHEET_ID = sheetId;						
						if(_ds.data.spreadtable){
							if(typeof _ds.data.xy == 'undefined' || _ds.data.xy == ''){
								_ds.data.xy = 'A1'
							}
							gDashboard.queryHandler.spreadtable =_ds.data.spreadtable
							gDashboard.spreadsheetManager.setXYtoColumnRow(_ds.data.xy.toUpperCase(),sheetId);
							gDashboard.spreadsheetManager.setTableShowHeader(_ds.data.showHeader,sheetId);
						}else{
							gDashboard.queryHandler.spreadtable =_ds.data.spreadtable
							gDashboard.spreadsheetManager.setXYtoColumnRow('A1',sheetId);
						}
					}else{
						gDashboard.dataSourceManager.datasetInformation[_ds.data.mapid].SHEET_ID = undefined;
					}
				});
				
				gDashboard.queryHandler.query();
				$("#ds_popup").dxPopup("instance").hide();
				
			}
		});
		
		$("#btn_datasetcon_cancel").dxButton({
			text: "취소",
			type: "normal",
			onClick: function(e) {
				$("#ds_popup").dxPopup("instance").hide();
			}
		});
	}
}

WISE.libs.SingleInput = function(){
	var self = this;
	this.render = function(){
		$("#sql_popup").empty();
		$("#ds_popup").empty();
		$.ajax({
			url : './getSingleTBLList.do',
			/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//			async: false,
			data:{
				userNo:userJsonObject.userNo
			},beforeSend: function() {
				gProgressbar.show();
			},success: function(_data){
				_data = jQuery.parseJSON(_data);
				$("#ds_popup").empty();
				self.selectDSList('DataSetSingleDs',_data);
				gProgressbar.hide();
			},
			error: function(error) {
				WISE.alert('error'+ajax_error_message(error),'error');
			}
		});
	};
	
	this.selectDSList = function(_datasetType,_data){

		var html = "<div class=\"modal-inner\" style='height: calc(100% - 85px);'>\r\n" + 
		"                    <div class=\"modal-body\" style='height:100%'>\r\n" + 
		"                        <div class=\"row\" style='height:100%'>\r\n" + 
		"                            <div class=\"column\" style=\"width:50%; height: 100%;\">\r\n" + 
		"                                <div class=\"modal-article\" style='height:100%'>\r\n" +
		"                                <div id='switchDSType'></div>\r\n" + 
		"                                    <div class=\"modal-tit\">\r\n" + 
		"                                        <span>데이터원본 목록</span>\r\n" + 
		"                                    </div>\r\n" + 
		"									<div id='changeType'></div>"+
		"                                    <div id=\"dataset_list\"/>\r\n" + 
		"                                </div>\r\n" + 
		"                            </div>\r\n" + 
		"                            <div class=\"column\" style=\"width:50%; height: 100%;\">\r\n" + 
		"                                <div class=\"modal-article\">\r\n" + 
		"                                    <div class=\"modal-tit\">\r\n" + 
		"                                        <span>데이터원본 정보</span>\r\n" + 
		"                                    </div>\r\n" + 
		"                                    <div id=\"dataset_info\">\r\n" + 
		"                                    </div>\r\n" + 
		"                                </div>\r\n" + 
		"                            </div>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                    <div class=\"modal-footer\">\r\n" + 
		"                        <div class=\"row center\">\r\n" + 
		"                            <a id=\"btn_subject_check2\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
		"                            <a id=\"btn_subject_cancel2\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                </div>";
		$('#ds_popup').dxPopup({
			showCloseButton: true,
			showTitle: true,
			title:"데이터 원본 선택",
			visible: true,
			closeOnOutsideClick: false,
			contentTemplate: function() {
				return html;
			},
			width: '90vw',
            height: '90vh',
            maxWidth: 1300,
            maxHeight: 830,
            onContentReady: function(){
				gDashboard.fontManager.setFontConfigForListPopup('ds_popup')
			},
			onShown: function () {
				var selectDSType =[{
			        "text": "데이터 원본",
			        "value": "DS"
			    },{
			        "text": "데이터 원본 뷰",
			        "value": "DS_VIEW"
			    }];
				$('#switchDSType').dxRadioGroup({
					layout:"horizontal",
					dataSource:selectDSType,
					value:selectDSType[0],
					onValueChanged:function(_e){
						if(_e.value.value == 'DS'){
							$.ajax({
								url : './getSingleTBLList.do',
								/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//								async: false,
								data:{
									userNo:userJsonObject.userNo
								},
								beforeSend: function() {
									gProgressbar.show();
								},
								success: function(_data){
									_data = JSON.parse(_data);
									$("#dataset_list").dxDataGrid('instance').option('columns',[
										{caption : '데이터원본 명',dataField:'DS_NM', width : "45%"},  
										{caption : 'DB 유형',dataField:'DBMS_TYPE', width : "15%"},  
										{caption : '서버 주소(명)',dataField:'IP', width : "25%"},  
										{caption : '사용자 데이터',dataField:'USER_AREA_YN', width : "5%"}
									]);
									$("#dataset_list").dxDataGrid('instance').option('dataSource',_data);
									gProgressbar.hide();
								},
								error: function(error) {
									WISE.alert('error'+ajax_error_message(error),'error');
								}
							});
						}else{
							$.ajax({
								url : './getSingleViewTBLList.do',
								/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//								async: false,
								data:{
									userNo:userJsonObject.userNo
								},
								beforeSend: function() {
									gProgressbar.show();
								},
								success: function(_data){
									_data = JSON.parse(_data);
									$("#dataset_list").dxDataGrid('instance').option('columns',[
										{caption : '데이터원본 뷰 명',dataField:'DS_VIEW_NM', width : "23%"},
										{caption : '데이터원본 명',dataField:'DS_NM', width : "23%"},  
										{caption : 'DB 유형',dataField:'DBMS_TYPE', width : "15%"},  
										{caption : '서버 주소(명)',dataField:'IP', width : "24%"},  
										{caption : '사용자 데이터',dataField:'USER_AREA_YN', width : "5%"}
									]);
									$("#dataset_list").dxDataGrid('instance').option('dataSource',_data);
									gProgressbar.hide();
								},
								error: function(error) {
									WISE.alert('error'+ajax_error_message(error),'error');
								}
							});
						}
					}
				});
				
				$("#dataset_list").dxDataGrid({
					dataSource: _data,
					width: "100%",
					//height: "calc(100% - 80px)",
					height: "91%",
					showBorders: true,
					paging: {pageSize: 20},
					visible : true,
					columnAutoWidth: true,
					allowColumnResizing: true,
					columns: [
						{caption : '데이터원본 명',dataField:'DS_NM', width : "40%"},  
						{caption : 'DB 유형',dataField:'DBMS_TYPE', width : "15%"},  
						{caption : '서버 주소(명)',dataField:'IP', width : "25%"},  
						{caption : '사용자 데이터',dataField:'USER_AREA_YN', width : "20%"}
					],selection:{
						mode:'single'
					},onSelectionChanged: function (selectedItems) {
						var form = $("#dataset_info").dxForm('instance');
						form.option("formData", selectedItems.selectedRowsData[0]);
					},
					onContentReady: function(){
						gDashboard.fontManager.setFontConfigForListPopup('dataset_list')
					},
				});
				
				$("#dataset_info").dxForm({
					width: "100%",
					height: 550,
					readOnly: true,
					formData: {},
					onContentReady: function(){
						gDashboard.fontManager.setFontConfigForListPopup('dataset_list')
					},
					items: [{
						label: {text: "데이터 원본 명",},
						dataField:'DS_NM',
						editorOptions: {readOnly: true}
					},{
						label: {text: "서버 주소(명)",},
						dataField:'IP',
						editorOptions: {readOnly: true}
					},{
						label: {text: "DB 명",},
						dataField:'DB_NM',
						editorOptions: {readOnly: true}
					},{
						label: {text: "DB 유형",},
						dataField:'DBMS_TYPE',
						editorOptions: {readOnly: true}
					},{
						label: {text: "Port",},
						dataField: "PORT",
						editorOptions: {readOnly: true}
					},{
						label: {text: "소유자",},
						dataField: "OWNER_NM",
						editorOptions: {readOnly: true}
					},{
						label: {text: "접속 ID",},
						dataField: "USER_ID",
						editorOptions: {readOnly: true}
					},{
						label: {text: "설명",},
						dataField: "DS_DESC",
						editorType: "dxTextArea",
						editorOptions: {height: 130}
					}]
				});
				
				$("#btn_subject_check2").dxButton({
					text: "확인",
					type: "normal",
					onClick:function(){
						var dsTypeValue = $('#switchDSType').dxRadioGroup('instance').option('value').value;
						if(dsTypeValue == 'DS'){
							var selectDS = $("#dataset_list").dxDataGrid('instance').getSelectedRowsData();
							selectDS[0].dataType = "단일테이블";
//							$('#dataSetFormInfo').dxForm('instance').option('formData',selectDS[0]);
							dsInfo = selectDS[0];
							dsInfo.dataSrc_Type = "DS";
							dsInfo.dataSet_Type = "DataSetSingleDs";
							
							$("#ds_popup").dxPopup("instance").hide();
							/* DOGFOOT 20201022 ajkim setTimeout 제거*/
							self.getTBLList(selectDS[0].DS_ID,"DS_SINGLE")
						}else{
							var selectDS = $("#dataset_list").dxDataGrid('instance').getSelectedRowsData();
							selectDS[0].dataType = "단일테이블";
//							$('#dataSetFormInfo').dxForm('instance').option('formData',selectDS[0]);
							dsInfo = selectDS[0];
							dsInfo.dataSrc_Type = "DS_VIEW";
							dsInfo.dataSet_Type = "DataSetSingleDsView";
							
							$("#ds_popup").dxPopup("instance").hide();
							/* DOGFOOT 20201022 ajkim setTimeout 제거*/
							self.getTBLList(selectDS[0].DS_VIEW_ID,"DS_VIEW_SINGLE")
						}
					}
				});
				
				$("#btn_subject_cancel2").dxButton({
					text: "취소",
					type: "normal",
					onClick: function(e) {
						$("#ds_popup").dxPopup("instance").hide();
					}
				});
			}
		});
	};
	
	this.getTBLList = function(ds_id,ds_type){
		if(ds_type == 'DS_SINGLE'){
			$.ajax({
				type : 'post',
				/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//				async: false,
				url : WISE.Constants.context + '/report/getTableList.do',
				data:{
					'dsid': ds_id,
					'dstype' : 'DS'
				},
				complete: function() {
					gProgressbar.hide();
				},
				success : function(data) {
					tableList = data.data;
					var html = "<div class=\"modal-inner\">\r\n" + 
					"                    <div class=\"modal-body\">\r\n" + 
					"                        <div class=\"row\">\r\n" + 
					"                            <div class=\"column\" style=\"width:100%; height: 672px;\">\r\n" + 
					"                                <div class=\"modal-article\">\r\n" + 
					"                                    <div class=\"modal-tit\">\r\n" + 
					"                                        <span>대상 테이블 목록</span>\r\n" + 
					"                                    </div>\r\n" + 
					"                                    <div id=\"Table_list\"/>\r\n" + 
					"                                </div>\r\n" + 
					"                            </div>\r\n" + 
					"                        </div>\r\n" + 
					"                    </div>\r\n" + 
					"                    <div class=\"modal-footer\">\r\n" + 
					"                        <div class=\"row center\">\r\n" + 
					"                            <a id=\"btn_table_check2\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
					"                            <a id=\"btn_table_cancel2\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
					"                        </div>\r\n" + 
					"                    </div>\r\n" + 
					"                </div>";
					$.each(tableList,function(_i,_table){
						if(_table.TBL_CAPTION == ""){
							_table.TBL_CAPTION = _table.TBL_NM;
						}
					});
					$('#TBLList_popup').dxPopup({
						showCloseButton: true,
						showTitle: true,
						title:"데이터 원본 선택",
						visible: true,
						closeOnOutsideClick: false,
						contentTemplate: function() {
							return html;
						},
						width: '90vw',
			            height: '90vh',
			            maxWidth: 1300,
			            maxHeight: 830,
			            onContentReady: function() {
			            	gDashboard.fontManager.setFontConfigForListPopup('TBLList_popup');
			            },
						onShown: function () {
							$('#Table_list').dxDataGrid({
								height:'580px',
								dataSource:tableList,
								selection:{
									mode:'single'
								},
								/* DOGFOOT ajkim 테이블 검색기능 추가 20201109*/
								filterRow: { visible: true },
								/* DOGFOOT ktkang 단일테이블 테이블 캡션 수정  20200716  */
								columns:[
									{
										caption:'테이블 물리명',
										dataField:'TBL_NM',
										allowEditing:false,
									},{
										caption:'테이블 논리명',
										dataField:'TBL_CAPTION',
										allowEditing:false,
									}],
								onContentReady: function() {
					            	gDashboard.fontManager.setFontConfigForListPopup('Table_list');
					            },
								pager: {
						            showPageSizeSelector: true,
						            allowedPageSizes: [10, 25, 50, 100]
						        }
							});
							$('#btn_table_check2').dxButton({
								onClick:function(){
									var selectedTable = $("#Table_list").dxDataGrid('instance').getSelectedRowsData();
									var selectedTBL_NM = selectedTable[0].TBL_NM;
									if(selectedTBL_NM.indexOf("(")!=-1){
										selectedTBL_NM = selectedTBL_NM.substring(selectedTBL_NM.indexOf("(")+1,selectedTBL_NM.indexOf(")"));
									}
									dsInfo.TBL_NM = selectedTBL_NM;
									var items = [
										{label: {text: "데이터 원본 유형",},dataField: "dataType"},
										{label: {text: "테이블 명",},dataField : "TBL_NM"},
										{label: {text: "데이터 원본 명",},dataField: "DB_NM"},
										{label: {text: "서버 주소(명)",},dataField: "IP"},
										{label: {text: "DB 명"},dataField: "DB_NM"},
										{label: {text: "DB 유형",},dataField : "DBMS_TYPE"},
									];
									$.ajax({
										type : 'post',
										/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//										async: false,
										url : WISE.Constants.context + '/report/getColumnList.do',
										data:{
											'dsid': ds_id,
											'dstype' : "DS",
											'tableNm' : selectedTBL_NM
										},
										success : function(_data) {
											_data = _data.data;
											$.each(_data,function(_i,_dataItem){
												if(_dataItem.COL_CAPTION == ""){
													_dataItem.COL_CAPTION = _dataItem.COL_NM;
												}
												/* DOGFOOT ktkang tibero 컬럼 타입 추가  20200618 */
												if(_dataItem.DATA_TYPE.toLowerCase() == 'int' || _dataItem.DATA_TYPE.toLowerCase() == 'decimal' || 
														_dataItem.DATA_TYPE.toLowerCase() == 'bigint' || _dataItem.DATA_TYPE.toLowerCase() == 'number' ||
														/* DOGFOOT ktkang 단일테이블 NETEZZA 추가  20200910 */
														_dataItem.DATA_TYPE.toLowerCase() == 'float' || _dataItem.DATA_TYPE.toLowerCase() == 'double' || 
														_dataItem.DATA_TYPE.toLowerCase() == 'numeric'){
													_dataItem.TYPE = 'MEA'
												}else{
													_dataItem.TYPE = 'DIM'
												}
												_dataItem.AGG = "";
												_dataItem.VISIBLE = true;
											});

											$('#TBLList_popup').dxPopup('instance').hide();
											var html = "		<div class=\"modal-inner\">\r\n" + 
											"                    <div class=\"modal-body\">\r\n" + 
											"                        <div class=\"row\">\r\n" + 
											"                            <div class=\"column\" style=\"width:25%\">\r\n" + 
											"                                <div class=\"modal-article\">\r\n" + 
											"                                   <div class=\"modal-tit\">\r\n" + 
											"                                   <span>데이터 원본 정보</span>\r\n" + 
											"                                   </div>\r\n" + 
											"                                   <div id=\"ds_info\" />\r\n" + 
											"                                </div>\r\n" +
											//2020.03.30 ajkim 단일테이블에서 데이터 항목 가리기 dogfoot
//											"                                <div class=\"modal-article\" style=\"margin-top:30px;\">\r\n" + 
//											"                                   <div class=\"modal-tit\">\r\n" + 
//											"                                   <span>데이터 항목</span>\r\n" + 
//											"                                   </div>\r\n" + 
//											"									<div id=\"dataSetTableInfo\" style=\"width: 300px; height: 400px;\" />\r\n" + 
//											"                                </div>\r\n" +
											// 2020.01.07 mksong 리사이즈 버튼 주석 dogfoot
//											"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
											"                            </div>\r\n" + 
											"                            <div class=\"column\" style=\"width:75%\">\r\n" +
											"                            	<div class=\"row horizen\">\r\n" + 
											" 		                            <div class=\"column\" style=\"height: 600px;\">\r\n" +
											"		                                <div class=\"modal-article\">\r\n" + 
											"       	                           		<div class=\"modal-tit\">\r\n" +
											//20210122 AJKIM 계산된 컬럼 추가 DOGFOOT
											'												<div class="left-item"><a id="add_calculated_field" class="btn crud neutral" style="float:right; margin-right: 10px;">계산된 컬럼 추가</a><div id="add_calculated_field"></div></div>'+
											'												<div class="left-item"><a id="add_group_field" class="btn crud neutral" style="display: none; float:right; margin-right: 10px;">그룹 컬럼 추가</a><div id="add_calculated_field"></div></div>'+

											'												<div class="right-item"><a id="ds_query_button" class="btn crud neutral" style="float:right;">쿼리보기</a><div id="ds_query_popup"></div></div>'+
//											"           	                            	<span>쿼리</span>\r\n" + 
											'												<div class="right-item">' +
											'													<a id="ds_name_change_button" class="gui edit minPop-btn" href="#">데이터 집합 명 변경</a>'+
									        '													<div class="mini-box">'+
									        '														<div><em class="primary">데이터 집합 명 변경</em></div>'+
									        '														<div id="ds_name_change_text"></div>'+
									        '														<div class="row center">' +
									        '															<div class="column">' +
									        '																<a id="btn_ds_name_change_popup_ok" class="btn crud positive" href="#">변경</a>' +
									        '																<a id="btn_ds_name_change_popup_cancel" class="btn crud neutral" href="#">취소</a>' +
									        '															</div>' +
									        '														</div>' +
									        '													</div>' +
											'												</div>' +
											'												<p id="ds_name_text" style="float:right;height:30px;"></p>' +
											'											</div>' +
											'											<div id="ds_name_change"></div></div>'
//											'											<div id="sql_area" class="sql_area" style="float:right;">'+
											+'<div class="column">'
											+'<h4 class="tit-level3 pre" style="padding: 10px 9px 9px 20px">표시 항목</h4>'
											+'<div class="panel-inner componet-res scrollbar">'
											+'<div id="ExpressArea" class="tbl data-form preferences-tbl"></div>'
											+'</div>'
											+'</div>'
											+"                           		   	</div>\r\n" +
//											"                                       <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" +
											"                              		</div>\r\n" + //column끝
//											" 		                            <div class=\"column\" style=\"padding-bottom:0px; height: 345px;\">\r\n" +
//											'										<div class="modal-article">' +
//											"											<div id=\"param_area\" class=\"param_area modal-tit\">\r\n" + 
//											"   		                                     <span>매개변수<em class=\"red\">*매개변수는 영문만 가능합니다.</em></span>" + 
//											'												 <div class="right-item">' +
//											'												 	<a id=\"param_create_btn\" class="btn crud positive" href="#">생성</a>' +
//											'												 	<a id=\"param_edit_btn\" class="btn crud neutral" href="#">편집</a>' +
//											'												 	<a id=\"param_delete_btn\" class="btn crud negative" href="#">삭제</a>' +
//											'												 </div>' +
//											"       	                	            </div>\r\n" +
//											"											<div id=\"param_grid\" class=\"active\"></div>\r\n" +
//											"       	                	        </div>\r\n" +
//											" 									</div>" + //column 끝
										    " 								 </div>" + //row horizon 끝
											"                            </div>\r\n" +  //column 끝 
											"                        </div>\r\n" + //row 끝
											"                    </div>\r\n" + //modal-body 끝
											"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
											"                        <div class=\"row center\">\r\n" + 
											"                            <a id=\"btn_datadesign_check\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
											"                            <a id=\"btn_datadesign_cancel\" class=\"btn neutral close\" href=\"#\">취소</a>\r\n" + 
											"                        </div>\r\n" + 
											"                    </div>\r\n" + 
											"                </div>";
											
											$('#columnType_popup').dxPopup({
												showCloseButton: true,
												showTitle: true,
												title: "데이터 집합 디자이너",
												visible: true,
												closeOnOutsideClick: false,
												contentTemplate: function() {
													return html;
												},
												onContentReady: function() {
									            	gDashboard.fontManager.setFontConfigForListPopup('columnType_popup');
									            },
												width: '100vw',
									            height: '90vh',
									            maxWidth: 1500,
									            maxHeight: 800,
												onShown: function () {
													miniPop();
													var tableList;
													var colList;
													var listId = 1;
													
													$("#ds_info").dxForm({
														width: 300,
														height: 200,
														readOnly: true,
														formData: dsInfo,
														items: [{
															label: {
																text: "데이터 원본 유형",
											                },
															dataField: "dataType",
														},{
															label: {
																text: "테이블 명",
											                },
															dataField: "TBL_NM",
														},{
															label: {
																text: "데이터 원본 명",
											                },
															dataField: "DS_NM",
														},{
															label: {
																text: "서버 주소(명)",
											                },
															dataField: "IP",
														},{
															label: {
																text: "DB 명",
											                },
															dataField: "DB_NM",
														},{
															label: {
																text: "DB 유형",
											                },
															dataField : "DBMS_TYPE",
														}]
													});
													
													/* DOGFOOT ktkang 단일테이블 데이터 집합 명 수정  20200716  */
													$('#ds_name_text').text(selectedTBL_NM + (gDashboard.dataSourceQuantity+1));
													
													$("#ds_name_change_text").dxTextArea({
														width: 350,
														height: 35,
														value: $('#ds_name_text').text()
													});
													
													$("#btn_ds_name_change_popup_ok").dxButton({
														text: "확인",
														type: "normal",
														onClick: function(e) {
															if($('#ds_name_change_text').dxTextArea('instance').option('value')==='') {
																WISE.alert('데이터집합명을 입력해주세요.');
															} else {
																$("#ds_name_change_button").removeClass('on');
																$('#ds_name_text').text($('#ds_name_change_text').dxTextArea('instance').option('value'));
															}
														}
													});
													
													$("#btn_ds_name_change_popup_cancel").dxButton({
														text: "취소",
														type: "normal",
														onClick: function(e) {
															$("#ds_name_change_button").removeClass('on');
														}
													});													
													
													$('#dataSetTableInfo').dxTreeView({
														dataSource: [],
														height:100,
														noDataText:"",
													});
													
													$('#ExpressArea').dxDataGrid({
														allowColumnResizing: true,
														height:500,
														selection: {
															mode: 'single'
														},
														onContentReady: function() {
											            	gDashboard.fontManager.setFontConfigForListPopup('ExpressArea');
											            },
														columns:[
															{
																caption:'컬럼 물리명',
																dataField:'COL_NM',
																allowEditing:false,
																calculateCellValue: function(rowData){
																	if(rowData.DATA_TYPE == 'cal' || rowData.DATA_TYPE == 'grp')
                                                                        return rowData.COL_CAPTION;
																	else
																	    return rowData.COL_NM;
																}
															},{
																caption:'컬럼 논리명',
																dataField:'COL_CAPTION',
															},{
																width:'100px',
																caption:'항목 유형',
																dataField:'DATA_TYPE',
																allowEditing:false,
																customizeText: function(cellInfo){
																	if(cellInfo.value == 'cal')
																	    return "계산된 컬럼";
																	else if(cellInfo.value == 'grp')
																	    return "그룹 컬럼";
																	else
																	    return "";
																}
															},{
																width:'100px',
																caption:'데이터 유형',
																dataField:'DATA_TYPE',
																allowEditing:false,
																customizeText: function(cellInfo){
																	if(cellInfo.value == 'cal' || cellInfo.value == 'grp')
																	    return 'varchar';
																	else
																	    return cellInfo.value;
																}
															},{
																width:'120px',
																caption:'유형',
																dataField:'TYPE',
																visible: false,
																lookup:{
																	dataSource: [{
																		caption:'측정값',
																		value:'MEA'
																	},{
																		caption:'차원',
																		value:'DIM'
																	}],
																	displayExpr: "caption",
												                    valueExpr: "value",
																}
															},{
																width:'150px',
																caption:'집계',
																dataField:'AGG',
																visible: false,
																lookup:{
																	dataSource: [{
																		caption:'',
																		value : ''
																	},{
																		caption: 'Sum',
																		value : 'Sum'
																	},{
																		caption: 'Avg',
																		value : 'Avg'
																	},{
																		caption: 'Count',
																		value : 'Count'
																	},{
																		caption: 'Distinct Count',
																		value : 'Distinct Count'
																	},{
																		caption: 'Max',
																		value : 'Max'
																	},{
																		caption: 'Min',
																		value : 'Min'
																	}],
																	displayExpr: "caption",
												                    valueExpr: "value"
																}
															},{
																caption:'표시',
																dataField:'VISIBLE',
																alignment:"center",
																dataType:'boolean',
																width:'80px'
															},{
																caption:'순서',
																dataField:'COL_ID',
																width:'80px',
																dataType: 'number',
												                setCellValue: function(newData, value, currentRowData) {
																	if(value<0) newData.COL_ID = 0;
																	else newData.COL_ID = value;
												                }
															},
															
														],
														noDataText:"",
														dataSource:_data,
														editing: {
												            mode: "cell",
												            allowUpdating: true,
												            texts: {
												                confirmDeleteMessage: ""
												            }
														},onRowUpdated:function(_e){

//															if(_e.key.TYPE != undefined){
//																if(_e.key.TYPE === 'MEA'){
//																	_e.key.AGG = 'Sum';
//																}else{
//																	_e.key.AGG = '';
//																}	
//															}
														},
														onSelectionChanged: function(_e){
															if(_e.selectedRowsData[0].TYPE == "DIM"&& _e.selectedRowsData[0].DATA_TYPE !== 'grp' && _e.selectedRowsData[0].DATA_TYPE !== 'cal')
																$("#add_group_field").css("display", "inline-block")
															else
																$("#add_group_field").css("display", "none")
														}
													});

													//20200122 AJKIM 계산된 컬럼 추가 DOGFOOT
													$("#add_calculated_field").dxButton({
														height: 30,
														type: "normal",
														onClick: function(e) {
															gDashboard.customFieldManager.createCustomField(_data, dsInfo, 'dscal')
////															var html = '<div id="cal_panel" class="cal_panel" style="height: calc(100% - 85px);"></div>';
//															var html = "<div class=\"modal-body\" style='height:80%'>\r\n" + 
//															"                        <div class=\"row\" style='height:100%'>\r\n" + 
//															"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" + 
//															"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
//															"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
//															"                                   	<span>컬렴명</span>\r\n" + 
//															"                                   </div>\r\n" +
//															"									<div style='text-align: right;'>\r\n"+
//															"										<div id=\"field_name\"></div>\r\n" +
//															"									</div>\r\n"+
//															"                                </div>\r\n" +
//															"                                <div class=\"modal-article\" style=\"margin-top: 5px;height:80%;\">\r\n" + 
//															"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
//															"                                   	<span>계산식</span>\r\n" + 
//															"                                   </div>\r\n" + 
//															/* DOGFOOT ktkang 저장 버튼 위치 수정  20200619 */
//															"								 <div id=\"field_cal\" style=\"height:70%;\"></div>\r\n" +
//															"                                </div>\r\n" +
//															"                            </div>\r\n" + 
//															"                        </div>\r\n" + // row 끝
//															"                    </div>\r\n"; // modal-body 끝
//															html += "<div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
//															"	<div class=\"row center\">\r\n" + 
//															"		<a id=\"btn_tabpanel_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
//															"		<a id=\"btn_tabpanel_cancel\" class=\"btn neutral ok-hide\" href=\"#\" >취소</a>\r\n" + 
//															"	</div>\r\n" + 
//															"</div>\r\n";
//															$('#ds_name_change').dxPopup({
//																showCloseButton: true,
//																showTitle: true,
//																visible: true,
//																title: "계산된 컬럼 추가",
//																closeOnOutsideClick: false,
//																contentTemplate: function() {
//																	return html;
//																},
//																width: '90vw',
//																height: '90vh',
//																maxWidth: 700,
//																maxHeight: 500,
//																onShown: function () {
//																	$('#field_name').dxTextBox();
//																	$('#field_cal').dxTextArea();
//																}, onContentReady : function() {
//																	$("#btn_tabpanel_ok").dxButton({
//																		text: "확인",
//																		type: "normal",
//																		onClick: function(e) {
//																			var temp = {
//																					TBL_NM: _data[0].TBL_NM,
//																					COL_NM: $('#field_cal').dxTextArea('option').value,
//																					COL_CAPTION: $('#field_name').dxTextBox('option').value,
//																					DATA_TYPE: "cal",
//									                                                AGG: "",
//									                                                PK_YN: "",
//									                                                TYPE: "DIM",
//									                                                VISIBLE: true,
//									                                                COL_ID: "0"
//																				};
//																			
//																			var param = {
//																					'dsid' : dsInfo.DS_ID,
//																					'dstype' : 'DS_SQL',
//																					'sql' : "SELECT  TOP 1 "+ temp.COL_NM +" AS ["+ temp.DATA_CAPTION +"] FROM " + dsInfo.TBL_NM,
//																					'params' :{}
//																			};
//																			
//																			gProgressbar.show();
//																			
//																			$.ajax({
//																				type : 'post',
//																				data: param,
//																				url : WISE.Constants.context + '/report/directSql.do',
//																				success : function(data) {
//																					var result = data.data;
//																					
//																					if(result){
//																						_data.push(temp)
//																						
//											                                            $('#ExpressArea').dxDataGrid('instance').refresh()
//																						$("#ds_name_change").dxPopup("instance").hide();
//																					}
//																					
//																				},error: function(_response) {
//																					gProgressbar.hide();
//																					WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
//																				}
//																			});
//																			gProgressbar.hide();
//																			
////																			$("#ds_name_change").dxPopup("instance").hide();
////																			
////																			_data.push({
////																				TBL_NM: _data[0].TBL_NM,
////																				COL_NM: $('#field_cal').dxTextArea('option').value,
////																				COL_CAPTION: $('#field_name').dxTextBox('option').value,
////																				DATA_TYPE: "cal",
////                                                                                AGG: "",
////                                                                                PK_YN: "",
////                                                                                TYPE: "DIM",
////                                                                                VISIBLE: true,
////                                                                                COL_ID: "0"
////																			});
////																			
////                                                                            $('#ExpressArea').dxDataGrid('instance').refresh()
////																			$("#ds_name_change").dxPopup("instance").hide();
//																		}
//																	});
//																	
//																	$("#btn_tabpanel_cancel").dxButton({
//																		text: "확인",
//																		type: "normal",
//																		onClick: function(e) {
//																			$("#ds_name_change").dxPopup("instance").hide();
//																		}
//																	});
//																}
//															});
														}
															
													});
													
													//20200122 AJKIM 계산된 컬럼 추가 DOGFOOT
													$("#add_group_field").dxButton({
														height: 30,
														type: "normal",
														onClick: function(e) {
															gDashboard.customFieldManager.createCustomField(_data, dsInfo, 'dsgrp')
														}
															
													});

													$("#ds_query_button").dxButton({
														height: 30,
														type: "normal",
														onClick: function(e) {
															var html = '<div id="query_tabpanel" class="query_tabpanel" style="height: calc(100% - 85px);"></div>';
															html += "<div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
															"	<div class=\"row center\">\r\n" + 
															"		<a id=\"btn_tabpanel_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
															"	</div>\r\n" + 
															"</div>\r\n";
															$('#ds_name_change').dxPopup({
																showCloseButton: true,
																showTitle: true,
																visible: true,
																title: "쿼리 실행 결과보기",
																closeOnOutsideClick: false,
																contentTemplate: function() {
																	return html;
																},
																width: '90vw',
													            height: '90vh',
													            maxWidth: 1000,
													            maxHeight: 800,
																onShown: function () {
																	var item =  [{ 'title' : 'SQL'}, {'title' : 'SQL Data'}];
																	var tabPanel = $("#query_tabpanel").dxTabPanel({
																        height: 'calc(100% - 85px)',
																        selectedIndex: 0,
																        loop: false,
																        animationEnabled: false,
																        swipeEnabled: true,
																        items: item,
																        onContentReady: function(e) {
																        	setTimeout(function () {
																        		$('#query_tabpanel .dx-multiview-item-content').attr('id', 'sqlArea');
																        		var sqlAreaText;
																        		var selectionList = $('#ExpressArea').dxDataGrid('instance').option('dataSource');
																				$.each(selectionList,function(_i,_data){
																					if(_data.TBL_NM.indexOf("(")!=-1){
																						_data.TBL_NM = _data.TBL_NM.substring(_data.TBL_NM.indexOf("(")+1,_data.TBL_NM.indexOf(")"));
																					}
																				});
																        		
																        		var param = {
																					dsId: dsInfo.DS_ID,
																					selArray:selectionList,
																					whereArray :[],
																					relArray:[],
																					etcArray:[{
																						STRATIFIED:"N",
																						DISTINCT:"N",
																						CHANGE_COND:"",
																			        	SEL_COND : "",//empty
																			        	SEL_NUMERIC : 0//0
																					}]
																				};
																        		/* DOGFOOT ktkang 통계 부분 DISTINCT 제거  20201105 */
																        		var statics = false;
																				if(gDashboard.reportType == 'StaticAnalysis') {
																					statics = true;
																				}
																				
																				$.ajax({
																					type : 'post',
																					async: false,
																					url : WISE.Constants.context + '/report/testData.do',
																					data:{
																						Infos:JSON.stringify(param),
																						execType:'singleDS',
																						statics : statics
																					},
																					success:function(data){
																						sqlAreaText = data;
																					}
																				});
																	        	
																	        	$("#sqlArea").dxTextArea({
																					width: 956,
																					height: '100%',
																					value: sqlAreaText
																				});
																        	}, 50);
																        },
																        onSelectionChanged: function(e) {
																        	if($('.dx-multiview-item-content').eq(1).attr('id') == null) {
																        		setTimeout(function () {
																        			$('.dx-multiview-item-content').eq(1).attr('id', 'query_data');

																        			$("#query_data").append('<div id="sqlButtonArea" style="height: 40px;"><div id="sqlStartButton" class="btn crud neutral" style="margin-left:5px; margin-top:5px;"></div><div id="sqlDownloadButton" class="btn crud neutral" style="margin-top:5px;"></div><span id="sqlRowNumber" style="margin-top:19px; margin-left:20px; display: inline-block;"></span></div><div id="filter-item2" class="filter-item"></div><div id="sqlFiltersArea" style="height: 50px;"></div><div id="sqlDatagridArea"><div>');
																        			
																        			$("#sqlStartButton").dxButton({
																						text: "SQL 실행",
																						icon: "refresh",
																						type: "normal",
																						onClick: function(e) {
																							//$('#progress_box').css({'display' : 'block'});
																							gProgressbar.show();
																							var sqlText = $("#sqlArea").dxTextArea('instance').option('value');
																							
																							if(sqlText) {
																							var condition = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
																							var param = {
																									'dsid' : ds_id,
																									'dstype' : 'DS_SQL',
																									'sql' : sqlText,
																									'params' : $.toJSON(condition)
																							};
																							
																							$.ajax({
																								type : 'post',
																								data: param,
																								url : WISE.Constants.context + '/report/directSql.do',
																								success : function(data) {
																									var result = data.data;
																									
//																									if(result){
																									/* DOGFOOT ktkang 테스트 쿼리보기용 쿼리 수정  20200629 */
//																										$('#edit_sqlRowNumber').text('총 건수 : ' + result.length + " 건");
//																										WISE.alert('테스트 데이터는 100건만 보여집니다.');
//																									}

																									$('#sqlDatagridArea').dxDataGrid({
																										columnAutoWidth: true,
																										width: 956,
																										height: 500,
																										dataSource: result,
																										showColumnLines: true,
																										filterRow: { visible: false },
																								        filterPanel: { visible: false },
																								        headerFilter: { visible: false },
																								        /* DOGFOOT ktkang DOMO용 컬럼 선택기 및 페이징 처리  20210123*/
																								        columnChooser: {
																								            enabled: true
																								        },
																								        paging: {
																								            pageSize: 50,
																								            enabled: true
																								        },
																								        pager: {
																								            showPageSizeSelector: true,
																								            allowedPageSizes: [20, 50, 100],
																								            showInfo: true
																								        },
																								        showBorders: true,
																								        onContentReady: function() {
																								        	gProgressbar.hide();
																								        },
																								        filterBuilderPopup: {
																								            width: 600,
																								            height: 300
																								        }
																									});
																								},error: function(_response) {
																									gProgressbar.hide();
																									WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
																								}
																							});
																							} else {
																								WISE.alert('쿼리가 없습니다.');
																							}
																						}
																					});
																        			
																        			$("#sqlDownloadButton").dxButton({
																						text: "내려받기",
																						icon: "export",
																						type: "normal",
																						onClick: function(e) {
																							var sqlDatagridIns = $('#sqlDatagridArea').dxDataGrid('instance');
																							
																							if(sqlDatagridIns) {
																								$('#sqlDatagridArea').dxDataGrid('instance').exportToExcel();
																							}
																						}
																        			});
																        			
//																        			if(gDashboard.structure.ReportMasterInfo.paramJson) {
//																						gDashboard.parameterHandler.init();
//																						gDashboard.parameterHandler.render(true);
//																						gDashboard.parameterHandler.resize();
//																					}
																        		}, 50);
																        	}
																        }
																    });
																    
																    $("#btn_tabpanel_ok").dxButton({
																		text: "확인",
																		type: "normal",
																		onClick: function(e) {
																			$("#ds_name_change").dxPopup("instance").hide();
																			$('#filter-item2').empty();
																		}
																	});
																}
															});
														}
													});
													
													$('#btn_datadesign_check').dxButton({
														onClick:function(){
															var sameDsName = false;
															$.each(gDashboard.datasetMaster.state.datasets, function(id, ds) {
																if (ds.DATASET_NM === $('#ds_name_text').text()) {
																	sameDsName = true;
																}
															});
															if(sameDsName) {
																WISE.alert('현재 같은 이름의 데이터 집합명이 존재합니다.');
															} else {
																/* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
																WISE.Context.isCubeReport = false;
																
																var selectionList = $('#ExpressArea').dxDataGrid('instance').option('dataSource');
																$.each(selectionList,function(_i,_data){
																	if(_data.TBL_NM.indexOf("(")!=-1){
																		_data.TBL_NM = _data.TBL_NM.substring(_data.TBL_NM.indexOf("(")+1,_data.TBL_NM.indexOf(")"));
																	}
																});
																
																var param = {
																	dsId: dsInfo.DS_ID,
																	selArray:selectionList,
																	whereArray :[],
																	relArray:[],
																	etcArray:[{
																		STRATIFIED:"N",
																		DISTINCT:"N",
																		CHANGE_COND:"",
															        	SEL_COND : "",//empty
															        	SEL_NUMERIC : 0//0
																	}]
																};
												        		/* DOGFOOT ktkang 통계 부분 DISTINCT 제거  20201105 */
																var statics = false;
																if(gDashboard.reportType == 'StaticAnalysis') {
																	statics = true;
																}
																
																$.ajax({
																	type : 'post',
																	async: false,
																	url : WISE.Constants.context + '/report/testData.do',
																	data:{
																		Infos:JSON.stringify(param),
																		execType:'singleDS',
																		statics : statics
																	},
																	success:function(data){
																		sqlAreaText = data;
																	}
																});
																
																var param = {
										        					datasetNm:$('#ds_name_text').text(),
										        					'DATASRC_ID' : dsInfo.DS_ID,
										        					'SQL_QUERY' : sqlAreaText,
										            				SelArea : $('#ExpressArea').dxDataGrid('instance').option('dataSource'),
										            				CondArea : [],
										            				ParamArea : [],
										            				RelArea : [],
										            				EtcArea:[{
										            					STRATIFIED:"N",
																		DISTINCT:"N",
																		CHANGE_COND:'',
															        	SEL_COND : "",//empty
															        	SEL_NUMERIC : 0//0
																	}],
																	DataSetType:'DataSetSingleDs'
										            			};
										        				var jsonParam = {};
										            			jsonParam['JSON_DATASET'] = JSON.stringify(param);
																

																$.ajax({
										        					method : 'POST',
											                        dataType: "json",
											                        data:jsonParam,
										        					url :  WISE.Constants.context + '/report/DatasetGenerateSingle.do',
										        					/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//										        					async: false,
										        					beforeSend: function() {
										        						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
										        						gProgressbar.show();
										        					},
										        					success: function(data){
										        						if(gDashboard.dataSourceQuantity > 0 && gDashboard.reportType == 'AdHoc' && WISE.Constants.editmode != 'viewer') {
																			if(gDashboard.dataSourceQuantity > 0) {
																				confirmOk = confirm('비정형모드에서는 데이터 집합이 1개만 사용됩니다. 기존 데이터집합을 삭제하고 추가하시겠습니까?');
																				if(confirmOk){
																					gDashboard.dataSourceQuantity = 0;
																					gDashboard.dataSourceManager.datasetInformation = {};
																					gDashboard.dataSetCreate.lookUpItems = [];
																					gDashboard.dataSetCreate.infoTreeList = [];
																					gDashboard.parameterFilterBar.parameterInformation = {};
																					gDashboard.datasetMaster.state.params = [];
																					/*dogfoot 비정형 필터 영역 초기화 shlim 20210319*/
																					/*dogfoot shlim 20210415*/
																					$('#report-filter-item').empty();
																					$('.panelClear').click();
																					var pivot = gDashboard.itemGenerateManager.dxItemBasten[0].type === 'PIVOT_GRID'? gDashboard.itemGenerateManager.dxItemBasten[0] : gDashboard.itemGenerateManager.dxItemBasten[1];
																					pivot.deltaItems=[];
																					gDashboard.itemGenerateManager.clearItemData();
																					$('.wise-area-deltaval').css('display', 'none');
																				} else {
																					return false;
																				}
																			} else {
																				confirmOk = true;
																			}
																		} else {
																			confirmOk = true;
																		}
										        						
										        						if(confirmOk){
										        							gDashboard.dataSourceQuantity++;
											        						self.createDxItems();
											        						data = data.DATA_SET;
											        						data.DATASET_JSON ={
										        								DATA_SET:{
										        									COL_ELEMENT: data['COL_ELEMENT'],
										        									ETC_ELEMENT : data['ETC_ELEMENT'],
										        									TBL_ELEMENT : data['TBL_ELEMENT']
										        								}
											        						}
											        						
											        						var columnList = data['COL_ELEMENT'];
											        						var TBL_name = data['TBL_ELEMENT']
											        						$.each(data['COL_ELEMENT']['COLUMN'], function(_i, _o) {
											        							if(_o.TYPE== 'DIM'){
											        								_o.icon = '../images/icon_dimension.png';
																				} else {
																					_o.icon = '../images/spr_global.png';
																				}
											        							_o.PARENT_ID = '0';
											        							
											        							_o.UNI_NM = "["+TBL_name+"].["+_o.COL_NM+"]";
																				_o.CAPTION = _o.COL_CAPTION;
											        						});
											        						
											        						for(var i = 0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
																				if('dataSource'+gDashboard.dataSourceQuantity == _.keys(gDashboard.dataSourceManager.datasetInformation)[i]){
																					gDashboard.dataSourceQuantity++;
																				}
																			}
											        						
											        						var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE': 'dataSource' + gDashboard.dataSourceQuantity}];
																			data['mapid'] = 'dataSource'+gDashboard.dataSourceQuantity;
																			gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity] = data;
																			gDashboard.dataSetCreate.infoTreeList[data['DATASET_NM']] = dataSetInfoTree.concat(data['COL_ELEMENT']['COLUMN']);
																			gDashboard.dataSetCreate.subjectInfoList['dataSource' + gDashboard.dataSourceQuantity] = dsInfo;
																			data['DATA_META'] = data['COL_ELEMENT']['COLUMN'];	
																			gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName':'dataSource' + gDashboard.dataSourceQuantity,"Name":data['DATASET_NM']})
											        						
																			$('.filter-item').empty();
//																			gDashboard.parameterHandler.init();
//																			gDashboard.parameterHandler.render();
//																			gDashboard.parameterHandler.resize();
																			$('.cont_query').empty();
																			//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
																			$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
																			$('#btn_query').off();
											            					$('#btn_query').on('click', function() {
											            						/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
											            						if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
											            							gDashboard.itemGenerateManager.selectedTabList = [];
											            							gDashboard.tabQuery = true;
											            						}
											            						
	//										            						if (!self.button.enabled) {return;}
											            						gDashboard.queryByGeneratingSql = true;
											            						gDashboard.itemGenerateManager.clearTrackingConditionAll();
											            						/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
											            						gDashboard.itemGenerateManager.clearItemData();
											            						gDashboard.query();
											            						this.blur();
											            					});
											            															            					
											            					gDashboard.dataSetCreate.lookUpItems.push({
																				DATASET_NM:data['DATASET_NM'],
																				mapid:data['mapid']
																			});
											            					
																			var newLookUpItems=[];
																			$.each(gDashboard.dataSetCreate.lookUpItems, function(_id, _ds) {
																				if (typeof _ds === 'string') {
																					newLookUpItems.push(_ds);
																				} else {
																					newLookUpItems.push(_ds.DATASET_NM);
																				}
																			});
																			
																			var $dataSetLookUp = $("#dataSetLookUp");
																			
																			if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
																				$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
																			}
											            															            					
											            					var lookUpIns = $dataSetLookUp.dxLookup('instance');	
											            					self.insertDataSet(data['DATA_META'],'dataSource'+gDashboard.dataSourceQuantity);
																			lookUpIns.option('items', newLookUpItems);
																			lookUpIns.option('value', data['DATASET_NM']);

																			//2020.05.20 HJKIM refactoring state add DOGFOOT
																			gDashboard.datasetMaster.migDatasetToState('dataSource'+gDashboard.dataSourceQuantity);
										        						}
										        						
																		gProgressbar.hide();
																		$("#columnType_popup").dxPopup("instance").hide();
																		setTimeout(function(){
																			$('#columnType_popup').remove();
											        						$('body').append('<div id="columnType_popup"></div>');
																		},300);
//																		$('#columnType_popup').remove();
//										        						$('body').append('<div id="columnType_popup"></div>');
//																		setTimeout(function(){$('#columnType_popup').remove();},300);
																		
										        						
										        					},error:function(_data){

										        						gProgressbar.hide();
										        						WISE.alert('집합 생성에 실패했습니다.<br>관리자에게 문의하세요'+ajax_error_message(_data));
										        						$("#columnType_popup").dxPopup("instance").hide();
//										        						$('#columnType_popup').remove();
//										        						$('body').append('<div id="columnType_popup"></div>');
										        						setTimeout(function(){
																			$('#columnType_popup').remove();
											        						$('body').append('<div id="columnType_popup"></div>');
																		},300);
										        					}
																});
															}
														}
													});
													
													$('#btn_datadesign_cancel').dxButton({
														onClick:function(){
															$("#columnType_popup").dxPopup("instance").hide();
//															$('#columnType_popup').remove();
//							        						$('body').append('<div id="columnType_popup"></div>');
															setTimeout(function(){
																$('#columnType_popup').remove();
								        						$('body').append('<div id="columnType_popup"></div>');
															},300);
														}
													});
												}
											});
										}
									});
									$('#TBLList_popup').dxPopup('instance').hide();
									$('#TBLList_popup').empty();
								}
							});
							$('#btn_table_cancel2').dxButton({
								onClick:function(){
									$('#TBLList_popup').dxPopup('instance').hide();
									$('#TBLList_popup').empty();
								}
							})
						}
					});
				},
				error: function(error) {
					WISE.alert('error'+ajax_error_message(error),'error');
				}
			});
		}else if(ds_type =='DS_VIEW_SINGLE'){
			$.ajax({
				type : 'post',
				/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//				async: false,
				url : WISE.Constants.context + '/report/getViewTableList.do',
				data:{
					'dsid': ds_id,
					'dstype' : 'DS_VIEW'
				},
				complete: function() {
					gProgressbar.hide();
				},
				success : function(data) {
					tableList = data.data;

					var html = "<div class=\"modal-inner\">\r\n" + 
					"                    <div class=\"modal-body\">\r\n" + 
					"                        <div class=\"row\">\r\n" + 
					"                            <div class=\"column\" style=\"width:100%; height: 672px;\">\r\n" + 
					"                                <div class=\"modal-article\">\r\n" + 
					"                                    <div class=\"modal-tit\">\r\n" + 
					"                                        <span>대상 테이블 목록</span>\r\n" + 
					"                                    </div>\r\n" + 
					"                                    <div id=\"Table_list\"/>\r\n" + 
					"                                </div>\r\n" + 
					"                            </div>\r\n" + 
					"                        </div>\r\n" + 
					"                    </div>\r\n" + 
					"                    <div class=\"modal-footer\">\r\n" + 
					"                        <div class=\"row center\">\r\n" + 
					"                            <a id=\"btn_table_check2\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
					"                            <a id=\"btn_table_cancel2\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
					"                        </div>\r\n" + 
					"                    </div>\r\n" + 
					"                </div>";
					$.each(tableList,function(_i,_table){
						if(_table.TBL_CAPTION == ""){
							_table.TBL_CAPTION = _table.TBL_NM;
						}
					});
					$('#TBLList_popup').dxPopup({
						showCloseButton: true,
						showTitle: true,
						title:"데이터 원본 선택",
						visible: true,
						closeOnOutsideClick: false,
						contentTemplate: function() {
							return html;
						},
						width: '90vw',
			            height: '90vh',
			            maxWidth: 1300,
			            maxHeight: 830,
						onShown: function () {
							$('#Table_list').dxDataGrid({
								height:'580px',
								dataSource:tableList,
								selection:{
									mode:'single'
								},
								/* DOGFOOT ajkim 테이블 검색기능 추가 20201109*/
								filterRow: { visible: true },
								/* DOGFOOT ktkang 단일테이블 테이블 캡션 수정  20200716  */
								columns:[
									{
										caption:'테이블 물리명',
										dataField:'TBL_NM',
										allowEditing:false,
									},{
										caption:'테이블 논리명',
										dataField:'TBL_CAPTION',
										allowEditing:false,
									}],
								pager: {
						            showPageSizeSelector: true,
						            allowedPageSizes: [10, 25, 50, 100]
						        }
							});
							$('#btn_table_check2').dxButton({
								onClick:function(){
									var selectedTable = $("#Table_list").dxDataGrid('instance').getSelectedRowsData();
									var selectedTBL_NM = selectedTable[0].TBL_NM;
									if(selectedTBL_NM.indexOf("(")!=-1){
										selectedTBL_NM = selectedTBL_NM.substring(selectedTBL_NM.indexOf("(")+1,selectedTBL_NM.indexOf(")"));
									}
									dsInfo.TBL_NM = selectedTBL_NM;
									
									$.ajax({
										type : 'post'
										/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/,
//										async: false,
										url : WISE.Constants.context + '/report/getDsViewColumnList.do',
										data:{
											'dsid': ds_id,
											'dstype' : "DS_VIEW",
											'tableNm' : selectedTBL_NM
										},
										success : function(_data) {
											_data = _data.data;
											
											$.each(_data,function(_i,_dataItem){
												if(_dataItem.COL_CAPTION == ""){
													_dataItem.COL_CAPTION = _dataItem.COL_NM;
												}
												if(_dataItem.DATA_TYPE.toLowerCase() == 'int' || _dataItem.DATA_TYPE.toLowerCase() == 'decimal' || 
														_dataItem.DATA_TYPE.toLowerCase() == 'bigint' || _dataItem.DATA_TYPE.toLowerCase() == 'number' ||
														/* DOGFOOT ktkang 단일테이블 NETEZZA 추가  20200910 */
														_dataItem.DATA_TYPE.toLowerCase() == 'float' || _dataItem.DATA_TYPE.toLowerCase() == 'double' || 
														_dataItem.DATA_TYPE.toLowerCase() == 'numeric'){
													_dataItem.TYPE = 'MEA'
												}else{
													_dataItem.TYPE = 'DIM'
												}
												_dataItem.AGG = "";
												_dataItem.VISIBLE = true;
											});
											$('#TBLList_popup').dxPopup('instance').hide();
											var html = "		<div class=\"modal-inner\">\r\n" + 
											"                    <div class=\"modal-body\">\r\n" + 
											"                        <div class=\"row\">\r\n" + 
											"                            <div class=\"column\" style=\"width:25%\">\r\n" + 
											"                                <div class=\"modal-article\">\r\n" + 
											"                                   <div class=\"modal-tit\">\r\n" + 
											"                                   <span>데이터 원본 정보</span>\r\n" + 
											"                                   </div>\r\n" + 
											"                                   <div id=\"ds_info\" />\r\n" + 
											"                                </div>\r\n" +
											"                                <div class=\"modal-article\" style=\"display:none;margin-top:30px;\">\r\n" + 
											"                                   <div class=\"modal-tit\">\r\n" + 
											"                                   <span>데이터 항목</span>\r\n" + 
											"                                   </div>\r\n" + 
//											"									<div id=\"dataSetTableInfo\" style=\"width: 300px; height: 400px;\" />\r\n" + 
											"									<div id=\"dataSetTableInfo\" style=\"width: 300px; height: 400px;\" />\r\n" + 
											"                                </div>\r\n" +
											// 2020.01.07 mksong 리사이즈 버튼 주석 dogfoot
//											"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
											"                            </div>\r\n" + 
											"                            <div class=\"column\" style=\"width:75%\">\r\n" +
											"                            	<div class=\"row horizen\">\r\n" + 
											" 		                            <div class=\"column\" style=\"height: 600px;\">\r\n" +
											"		                                <div class=\"modal-article\">\r\n" + 
											"       	                           		<div class=\"modal-tit\">\r\n" +
											'												<div class="right-item"><a id="ds_query_button" class="btn crud neutral" style="float:right;">쿼리보기</a><div id="ds_query_popup"></div></div>'+
//											"           	                            	<span>쿼리</span>\r\n" + 
											'												<div class="right-item">' +
											'													<a id="ds_name_change_button" class="gui edit minPop-btn" href="#">데이터 집합 명 변경</a>'+
									        '													<div class="mini-box">'+
									        '														<div><em class="primary">데이터 집합 명 변경</em></div>'+
									        '														<div id="ds_name_change_text"></div>'+
									        '														<div class="row center">' +
									        '															<div class="column">' +
									        '																<a id="btn_ds_name_change_popup_ok" class="btn crud positive" href="#">변경</a>' +
									        '																<a id="btn_ds_name_change_popup_cancel" class="btn crud neutral" href="#">취소</a>' +
									        '															</div>' +
									        '														</div>' +
									        '													</div>' +
											'												</div>' +
											'												<p id="ds_name_text" style="float:right;height:30px;"></p>' +
											'											</div>' +
											'											<div id="ds_name_change"></div></div>'
//											'											<div id="sql_area" class="sql_area" style="float:right;">'+
											+'<div class="column">'
											+'<h4 class="tit-level3 pre" style="padding: 10px 9px 9px 20px">표시 항목</h4>'
											+'<div class="panel-inner componet-res scrollbar">'
											+'<div id="ExpressArea" class="tbl data-form preferences-tbl"></div>'
											+'</div>'
											+'</div>'
											+"                           		   	</div>\r\n" +
//											"                                       <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" +
											"                              		</div>\r\n" + //column끝
//											" 		                            <div class=\"column\" style=\"padding-bottom:0px; height: 345px;\">\r\n" +
//											'										<div class="modal-article">' +
//											"											<div id=\"param_area\" class=\"param_area modal-tit\">\r\n" + 
//											"   		                                     <span>매개변수<em class=\"red\">*매개변수는 영문만 가능합니다.</em></span>" + 
//											'												 <div class="right-item">' +
//											'												 	<a id=\"param_create_btn\" class="btn crud positive" href="#">생성</a>' +
//											'												 	<a id=\"param_edit_btn\" class="btn crud neutral" href="#">편집</a>' +
//											'												 	<a id=\"param_delete_btn\" class="btn crud negative" href="#">삭제</a>' +
//											'												 </div>' +
//											"       	                	            </div>\r\n" +
//											"											<div id=\"param_grid\" class=\"active\"></div>\r\n" +
//											"       	                	        </div>\r\n" +
//											" 									</div>" + //column 끝
										    " 								 </div>" + //row horizon 끝
											"                            </div>\r\n" +  //column 끝 
											"                        </div>\r\n" + //row 끝
											"                    </div>\r\n" + //modal-body 끝
											"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
											"                        <div class=\"row center\">\r\n" + 
											"                            <a id=\"btn_datadesign_check\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
											"                            <a id=\"btn_datadesign_cancel\" class=\"btn neutral close\" href=\"#\">취소</a>\r\n" + 
											"                        </div>\r\n" + 
											"                    </div>\r\n" + 
											"                </div>";
											
											$('#columnType_popup').dxPopup({
												showCloseButton: true,
												showTitle: true,
												title: "데이터 집합 디자이너",
												visible: true,
												closeOnOutsideClick: false,
												contentTemplate: function() {
													return html;
												},
												width: '100vw',
									            height: '90vh',
									            maxWidth: 1500,
									            maxHeight: 800,
									            onContentReady: function() {
									            	gDashboard.fontManager.setFontConfigForListPopup('columnType_popup');
									            },
												onShown: function () {
													miniPop();
													var tableList;
													var colList;
													var listId = 1;
													
													$("#ds_info").dxForm({
														width: 300,
														height: 200,
														readOnly: true,
														formData: dsInfo,
														items: [{
															label: {
																text: "데이터 원본 유형",
											                },
															dataField: "dataType",
														},{
															label: {
																text: "테이블 명",
											                },
															dataField: "TBL_NM",
														},{
															label: {
																text: "데이터 원본 명",
											                },
															dataField: "DS_NM",
														},{
															label: {
																text: "서버 주소(명)",
											                },
															dataField: "IP",
														},{
															label: {
																text: "DB 명",
											                },
															dataField: "DB_NM",
														},{
															label: {
																text: "DB 유형",
											                },
															dataField : "DBMS_TYPE",
														}]
													});
													
													/* DOGFOOT ktkang 단일테이블 데이터 집합 명 수정  20200716  */
													$('#ds_name_text').text(selectedTBL_NM + (gDashboard.dataSourceQuantity+1));
													
													$("#ds_name_change_text").dxTextArea({
														width: 350,
														height: 35,
														value: $('#ds_name_text').text()
													});
													
													$("#btn_ds_name_change_popup_ok").dxButton({
														text: "확인",
														type: "normal",
														onClick: function(e) {
															if($('#ds_name_change_text').dxTextArea('instance').option('value')==='') {
																WISE.alert('데이터집합명을 입력해주세요.');
															} else {															
																$("#ds_name_change_button").removeClass('on');
																$('#ds_name_text').text($('#ds_name_change_text').dxTextArea('instance').option('value'));
															}
														}
													});
													
													$("#btn_ds_name_change_popup_cancel").dxButton({
														text: "취소",
														type: "normal",
														onClick: function(e) {
															$("#ds_name_change_button").removeClass('on');
														}
													});													
													
													$('#dataSetTableInfo').dxTreeView({
														dataSource: [],
														height:100,
														noDataText:"",
													});
													
													$('#ExpressArea').dxDataGrid({
														allowColumnResizing: true,
														height:500,
														selection: {
															mode: 'single'
														},
														columns:[
															{
																caption:'컬럼 물리명',
																dataField:'COL_NM',
																allowEditing:false,
															},{
																caption:'컬럼 논리명',
																dataField:'COL_CAPTION',
															},{
																width:'100px',
																caption:'데이터 유형',
																dataField:'DATA_TYPE',
																allowEditing:false,
															},{
																width:'120px',
																caption:'유형',
																dataField:'TYPE',
																visible: false,
																lookup:{
																	dataSource: [{
																		caption:'측정값',
																		value:'MEA'
																	},{
																		caption:'차원',
																		value:'DIM'
																	}],
																	displayExpr: "caption",
												                    valueExpr: "value",
																}
															},{
																width:'150px',
																caption:'집계',
																dataField:'AGG',
																visible: false,
																lookup:{
																	dataSource: [{
																		caption:'',
																		value : ''
																	},{
																		caption: 'Sum',
																		value : 'Sum'
																	},{
																		caption: 'Avg',
																		value : 'Avg'
																	},{
																		caption: 'Count',
																		value : 'Count'
																	},{
																		caption: 'Distinct Count',
																		value : 'Distinct Count'
																	},{
																		caption: 'Max',
																		value : 'Max'
																	},{
																		caption: 'Min',
																		value : 'Min'
																	}],
																	displayExpr: "caption",
												                    valueExpr: "value"
																}
															},{
																caption:'표시여부',
																dataField:'VISIBLE',
																alignment:"center",
																dataType:'boolean',
																width:'80px'
															},{
																caption:'표시순서',
																dataField:'COL_ID',
																width:'80px',
															},
															
														],
														noDataText:"",
														dataSource:_data,
														editing: {
												            mode: "cell",
												            allowUpdating: true,
												            texts: {
												                confirmDeleteMessage: ""
												            }
														},onRowUpdated:function(_e){

//															if(_e.key.TYPE != undefined){
//																if(_e.key.TYPE === 'MEA'){
//																	_e.key.AGG = 'Sum';
//																}else{
//																	_e.key.AGG = '';
//																}	
//															}
														}
													});
													
													$("#ds_query_button").dxButton({
														height: 30,
														type: "normal",
														onClick: function(e) {
															var html = '<div id="query_tabpanel" class="query_tabpanel" style="height: calc(100% - 85px);"></div>';
															html += "<div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
															"	<div class=\"row center\">\r\n" + 
															"		<a id=\"btn_tabpanel_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
															"	</div>\r\n" + 
															"</div>\r\n";
															$('#ds_name_change').dxPopup({
																showCloseButton: true,
																showTitle: true,
																visible: true,
																title: "쿼리 실행 결과보기",
																closeOnOutsideClick: false,
																contentTemplate: function() {
																	return html;
																},
																width: '90vw',
													            height: '90vh',
													            maxWidth: 1000,
													            maxHeight: 800,
																onShown: function () {
																	var item =  [{ 'title' : 'SQL'}, {'title' : 'SQL Data'}];
																	var tabPanel = $("#query_tabpanel").dxTabPanel({
																        height: 'calc(100% - 85px)',
																        selectedIndex: 0,
																        loop: false,
																        animationEnabled: false,
																        swipeEnabled: true,
																        items: item,
																        onContentReady: function(e) {
																        	setTimeout(function () {
																        		$('#query_tabpanel .dx-multiview-item-content').attr('id', 'sqlArea');
																        		var sqlAreaText;
																        		var selectionList = $('#ExpressArea').dxDataGrid('instance').option('dataSource');
																				$.each(selectionList,function(_i,_data){
																					if(_data.TBL_NM.indexOf("(")!=-1){
																						_data.TBL_NM = _data.TBL_NM.substring(_data.TBL_NM.indexOf("(")+1,_data.TBL_NM.indexOf(")"));
																					}
																				});
																        		
																        		var param = {
																					dsId: ds_id,
																					selArray:selectionList,
																					whereArray :[],
																					relArray:[],
																					etcArray:[{
																						STRATIFIED:"N",
																						DISTINCT:"N",
																						CHANGE_COND:"",
																			        	SEL_COND : "",//empty
																			        	SEL_NUMERIC : 0//0
																					}]
																				};
																        		/* DOGFOOT ktkang 통계 부분 DISTINCT 제거  20201105 */
																        		var statics = false;
																				if(gDashboard.reportType == 'StaticAnalysis') {
																					statics = true;
																				}

																				$.ajax({
																					type : 'post',
																					async: false,
																					url : WISE.Constants.context + '/report/testData.do',
																					data:{
																						Infos:JSON.stringify(param),
																						execType:'singleDS',
																						statics : statics
																					},
																					success:function(data){
																						sqlAreaText = data;
																					}
																				});
																	        	
																	        	$("#sqlArea").dxTextArea({
																					width: 956,
																					height: '100%',
																					value: sqlAreaText
																				});
																        	}, 50);
																        },
																        onSelectionChanged: function(e) {
																        	if($('.dx-multiview-item-content').eq(1).attr('id') == null) {
																        		setTimeout(function () {
																        			$('.dx-multiview-item-content').eq(1).attr('id', 'query_data');

																        			$("#query_data").append('<div id="sqlButtonArea" style="height: 40px;"><div id="sqlStartButton" class="btn crud neutral" style="margin-left:5px; margin-top:5px;"></div><div id="sqlDownloadButton" class="btn crud neutral" style="margin-top:5px;"></div><span id="sqlRowNumber" style="margin-top:19px; margin-left:20px; display: inline-block;"></span></div><div id="filter-item2" class="filter-item"></div><div id="sqlFiltersArea" style="height: 50px;"></div><div id="sqlDatagridArea"><div>');
																        			
																        			$("#sqlStartButton").dxButton({
																						text: "SQL 실행",
																						icon: "refresh",
																						type: "normal",
																						onClick: function(e) {
																							//$('#progress_box').css({'display' : 'block'});
																							gProgressbar.show();
																							var sqlText = $("#sqlArea").dxTextArea('instance').option('value');
																							
																							if(sqlText) {
																							var condition = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
																							var param = {
																									'dsid' : ds_id,
																									'dstype' : 'DS_VIEW',
																									'sql' : sqlText,
																									'params' : $.toJSON(condition)
																							};
																							
																							$.ajax({
																								type : 'post',
																								data: param,
																								url : WISE.Constants.context + '/report/directSql.do',
																								success : function(data) {
																									var result = data.data;
																									
																									if(result){
																									/* DOGFOOT ktkang 테스트 쿼리보기용 쿼리 수정  20200629 */
//																										$('#edit_sqlRowNumber').text('총 건수 : ' + result.length + " 건");
																										WISE.alert('테스트 데이터는 100건만 보여집니다.');
																									}

																									$('#sqlDatagridArea').dxDataGrid({
																										columnAutoWidth: true,
																										width: 956,
																										height: 500,
																										dataSource: result,
																										showColumnLines: true,
																										filterRow: { visible: false },
																								        filterPanel: { visible: false },
																								        headerFilter: { visible: false },
																								        scrolling: {
																								            mode: "virtual"
																								        },
																								        showBorders: true,
																								        onContentReady: function() {
																								        	gProgressbar.hide();
																								        },
																								        filterBuilderPopup: {
																								            width: 600,
																								            height: 300
																								        }
																									});
																								},error: function(_response) {
																									gProgressbar.hide();
																									WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
																								}
																							});
																							} else {
																								WISE.alert('쿼리가 없습니다.');
																							}
																						}
																					});
																        			
																        			$("#sqlDownloadButton").dxButton({
																						text: "내려받기",
																						icon: "export",
																						type: "normal",
																						onClick: function(e) {
																							var sqlDatagridIns = $('#sqlDatagridArea').dxDataGrid('instance');
																							
																							if(sqlDatagridIns) {
																								$('#sqlDatagridArea').dxDataGrid('instance').exportToExcel();
																							}
																						}
																        			});
																        			
//																        			if(gDashboard.structure.ReportMasterInfo.paramJson) {
//																						gDashboard.parameterHandler.init();
//																						gDashboard.parameterHandler.render(true);
//																						gDashboard.parameterHandler.resize();
//																					}
																        		}, 50);
																        	}
																        }
																    });
																    
																    $("#btn_tabpanel_ok").dxButton({
																		text: "확인",
																		type: "normal",
																		onClick: function(e) {
																			$("#ds_name_change").dxPopup("instance").hide();
																			$('#filter-item2').empty();
																		}
																	});
																}
															});
														}
													});
													
													$('#btn_datadesign_check').dxButton({
														onClick:function(){
															/* DOGFOOT ktkang 주제영역과 데이터 집합 섞어서 사용 못하도록 수정  20200716 */
															WISE.Context.isCubeReport = false;
															
															var selectionList = $('#ExpressArea').dxDataGrid('instance').option('dataSource');
															$.each(selectionList,function(_i,_data){
																if(_data.TBL_NM.indexOf("(")!=-1){
																	_data.TBL_NM = _data.TBL_NM.substring(_data.TBL_NM.indexOf("(")+1,_data.TBL_NM.indexOf(")"));
																}
															});
															
															var param = {
																	dsId: dsInfo.DS_ID,
																	selArray:selectionList,
																	whereArray :[],
																	relArray:[],
																	etcArray:[{
																		STRATIFIED:"N",
																		DISTINCT:"N",
																		CHANGE_COND:"",
															        	SEL_COND : "",//empty
															        	SEL_NUMERIC : 0//0
																	}]
																};
												        		/* DOGFOOT ktkang 통계 부분 DISTINCT 제거  20201105 */
																var statics = false;
																if(gDashboard.reportType == 'StaticAnalysis') {
																	statics = true;
																}
															
																$.ajax({
																	type : 'post',
																	async: false,
																	url : WISE.Constants.context + '/report/testData.do',
																	data:{
																		Infos:JSON.stringify(param),
																		execType:'singleDS',
																		statics : statics
																	},
																	success:function(data){
																		sqlAreaText = data;
																	}
																});
																
																var param = {
										        					datasetNm:$('#ds_name_text').text(),
										        					'DATASRC_ID' : ds_id,
										        					'SQL_QUERY' : sqlAreaText,
										            				SelArea : $('#ExpressArea').dxDataGrid('instance').option('dataSource'),
										            				CondArea : [],
										            				ParamArea : [],
										            				RelArea : [],
										            				EtcArea:[{
										            					STRATIFIED:"N",
																		DISTINCT:"N",
																		CHANGE_COND:'',
															        	SEL_COND : "",//empty
															        	SEL_NUMERIC : 0//0
																	}],
																	DataSetType:'DataSetSingleDsView'
										            			};
										        				var jsonParam = {};
										            			jsonParam['JSON_DATASET'] = JSON.stringify(param);
																

																$.ajax({
										        					method : 'POST',
											                        dataType: "json",
											                        data:jsonParam,
										        					url :  WISE.Constants.context + '/report/DatasetGenerateSingle.do',
										        					/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//										        					async: false,
										        					beforeSend: function() {
										        						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
										        						gProgressbar.show();
										        					},
										        					success: function(data){

										        						gDashboard.dataSourceQuantity++;
										        						self.createDxItems();
										        						data = data.DATA_SET;
										        						data.DATASET_JSON ={
									        								DATA_SET:{
									        									COL_ELEMENT: data['COL_ELEMENT'],
									        									ETC_ELEMENT : data['ETC_ELEMENT'],
									        									TBL_ELEMENT : data['TBL_ELEMENT']
									        								}
										        						}
										        						
										        						var columnList = data['COL_ELEMENT'];
										        						var TBL_name = data['TBL_ELEMENT']
										        						$.each(data['COL_ELEMENT']['COLUMN'], function(_i, _o) {
										        							if(_o.TYPE== 'DIM'){
										        								_o.icon = '../images/icon_dimension.png';
																			} else {
																				_o.icon = '../images/spr_global.png';
																			}
										        							_o.PARENT_ID = '0';
										        							
										        							_o.UNI_NM = "["+TBL_name+"].["+_o.COL_NM+"]";
																			_o.CAPTION = _o.COL_CAPTION;
										        						});
										        						
										        						for(var i = 0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
																			if('dataSource'+gDashboard.dataSourceQuantity == _.keys(gDashboard.dataSourceManager.datasetInformation)[i]){
																				gDashboard.dataSourceQuantity++;
																			}
																		}
										        						
										        						var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE': 'dataSource' + gDashboard.dataSourceQuantity}];
																		data['mapid'] = 'dataSource'+gDashboard.dataSourceQuantity;
																		gDashboard.dataSourceManager.datasetInformation['dataSource'+gDashboard.dataSourceQuantity] = data;
																		gDashboard.dataSetCreate.infoTreeList[data['DATASET_NM']] = dataSetInfoTree.concat(data['COL_ELEMENT']['COLUMN']);
																		gDashboard.dataSetCreate.subjectInfoList['dataSource' + gDashboard.dataSourceQuantity] = dsInfo;
																		
																		gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName':'dataSource' + gDashboard.dataSourceQuantity,"Name":data['DATASET_NM']})
										        						
																		$('.filter-item').empty();
//																		gDashboard.parameterHandler.init();
//																		gDashboard.parameterHandler.render();
//																		gDashboard.parameterHandler.resize();
																		$('.cont_query').empty();
																		//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
																		$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
																		$('#btn_query').off();
										            					$('#btn_query').on('click', function() {
										            						/* goyong ktkang 본사 탭컨테이너 개별 조회 기능 추가  20210616 */
										            						if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab){
										            							gDashboard.itemGenerateManager.selectedTabList = [];
										            							gDashboard.tabQuery = true;
										            						}
										            						
//										            						if (!self.button.enabled) {return;}
										            						gDashboard.queryByGeneratingSql = true;
										            						gDashboard.itemGenerateManager.clearTrackingConditionAll();
										            						/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
										            						gDashboard.itemGenerateManager.clearItemData();
										            						gDashboard.query();
										            						this.blur();
										            					});
										            					
										            					gDashboard.dataSetCreate.lookUpItems.push(data['DATASET_NM']);
										            					
										            					var $dataSetLookUp = $("#dataSetLookUp");
										            					
										            					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
										            						$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
										            					}
										            					
										            					var lookUpIns = $dataSetLookUp.dxLookup('instance');
																		lookUpIns.option('items', gDashboard.dataSetCreate.lookUpItems);
																		lookUpIns.option('value', data['DATASET_NM']);
																		
																		//2020.05.20 HJKIM refactoring state add DOGFOOT
																		gDashboard.datasetMaster.migDatasetToState('dataSource'+gDashboard.dataSourceQuantity);
																		
																		gProgressbar.hide();
																		$("#columnType_popup").dxPopup("instance").hide();
																		$('#columnType_popup').remove();
										        						$('body').append('<div id="columnType_popup"></div>');
//																		setTimeout(function(){$('#columnType_popup').remove();},300);
										        					},error:function(_data){

										        						gProgressbar.hide();
										        						WISE.alert('집합 생성에 실패했습니다.<br>관리자에게 문의하세요'+ajax_error_message(_data));
										        						$("#columnType_popup").dxPopup("instance").hide();
										        						$('#columnType_popup').remove();
										        						$('body').append('<div id="columnType_popup"></div>');
										        					}
																});
														}
													});
													
													$('#btn_datadesign_cancel').dxButton({
														onClick:function(){
															$("#columnType_popup").dxPopup("instance").hide();
															$('#columnType_popup').remove();
							        						$('body').append('<div id="columnType_popup"></div>');
														}
													});
												}
											});
										}
									});
									$('#TBLList_popup').dxPopup('instance').hide();
									$('#TBLList_popup').empty();
								}
							});
							$('#btn_table_cancel2').dxButton({
								onClick:function(){
									$('#TBLList_popup').dxPopup('instance').hide();
									$('#TBLList_popup').empty();
								}
							})
						}
					});
				},
				error: function(error) {
					WISE.alert('error'+ajax_error_message(error),'error');
				}
			});
		}
	};
	this.createDxItems = function() {
		var $dataSetLookUp = $("#dataSetLookUp");
		
		if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
			$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
		}
		
		$dataSetLookUp.dxLookup({
			item:{},
			placeholder: "데이터 집합을 선택하세요",
			showPopupTitle: false,
			searchEnabled: false,
			showPopupTitle: false,
			showCancelButton: false,
			closeOnOutsideClick: true,
			onValueChanged: function(e) {
				if(e.value != ''){
					if(gDashboard.dataSetCreate.infoTreeList.length > 0 || (typeof gDashboard.dataSetCreate.infoTreeList) == 'object'){
						if(gDashboard.dataSetCreate.infoTreeList[e.value][0]['DATASOURCE'] != undefined){
							if(WISE.Constants.editmode != 'viewer'){
				            	$('.drop-down.tree-menu > ul').empty();	
				            }else{
				            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
				            }
							self.insertDataSet(gDashboard.dataSetCreate.infoTreeList[e.value], gDashboard.dataSetCreate.infoTreeList[e.value][0]['DATASOURCE']);
							var valueTrees = gDashboard.datasetMaster.getState('FIELDS');
							var dsId = gDashboard.datasetMaster.utility.getMapIdByDatasetName(e.value);
	                        if (dsId && valueTrees[dsId]) {
	                            gDashboard.datasetMaster.setState({ selectedDataset: dsId });
	                            gDashboard.datasetMaster.createDatasetFieldTree(valueTrees[dsId], dsId);	
	                        }
						}
					}else{
						if(WISE.Constants.editmode != 'viewer'){
			            	$('.drop-down.tree-menu > ul').empty();	
			            }else{
			            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
			            }
					}
					
				}else{
					if(WISE.Constants.editmode != 'viewer'){
		            	$('.drop-down.tree-menu > ul').empty();	
		            }else{
		            	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').empty();
		            }
				}
			}
		});
	};
	
	/*dogfoot 분석항목 폴더 그룹화 shlim 20210319*/
	this.insertDataSet = function(_dataSet,_dataSourceId){
		if(typeof _dataSet.length != 'undefined') {
//			_dataSet.sort(function(a,b){
//				return (a.ORDER <b.ORDER) ? -1 : (a.ORDER > b.ORDER) ? 1 : 0;
//			});
			
			/*dogfoot 분석항목 정렬  shlim 20210329 */
//			if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
//				_dataSet.sort(function(a,b){
//	    		if(typeof a.DATASOURCE != "undefined"){
//	    			return -1;
//	            }
//	            if(typeof b.DATASOURCE != "undefined"){
//	    			return 1;
//	            }
//				return a.CAPTION.localeCompare(b.CAPTION);
//				//return a.CAPTION < b.CAPTION ? -1 : a.CAPTION < b.CAPTION ? 1 : 0;
//				})
//			}
			
			var html = '<li class="active"  id="'+_dataSourceId+'">';
			var meaCount = 0; dimCount = 0,meaHtml = ""; dimHtml = "", sortCount = 0, sortHtml = "";
			$.each(_dataSet,function(_i,_data){
				if(_i == 0){
					html += '<a href="#" class="ico arrow">'+_data.CAPTION+'</a>';
					html += '<ul class="dep dataset" style="display:block">';
				}else{
					var _hideColumn = false;
					if(WISE.Constants.companyname == "고용정보원"){
						if(WISE.Constants.editmode == "viewer" && (_data.CAPTION.indexOf("H_") == 0
								|| _data.CAPTION.indexOf('S_') == 0)){
							_hideColumn = true;
						}
					}
					if(!_hideColumn){
						if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
							if(_data.VISIBLE === true){
								if(_data.TYPE == 'MEA'){
									if(meaCount == 0){
										meaHtml += '<li id="측정값" class="wise-fld-area active" >';
										meaHtml += '<a href="#" class="ico arrow" dataset-caption="측정값">측정값</a>';
										meaHtml += '<ul class="dep dataset" style="display:block">';
									}
									meaCount++;
									meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
								}else if(_data.CAPTION.indexOf('S_') == 0 || _data.CAPTION.indexOf('H_') == 0){
									if(sortCount == 0){
										sortHtml += '<li id="정렬항목" class="wise-fld-area active" >';
										sortHtml += '<a href="#" class="ico arrow" dataset-caption="정렬항목">정렬항목</a>';
										sortHtml += '<ul class="dep dataset" style="display:block">';
											
									}
									sortCount++;
									sortHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
								} else {
									if(dimCount == 0){
										dimHtml += '<li id="분석항목" class="wise-fld-area active" >';
										dimHtml += '<a href="#" class="ico arrow" dataset-caption="분석항목(행, 열)">분석항목(행, 열)</a>';
										dimHtml += '<ul class="dep dataset" style="display:block">';
											
									}
									dimCount++;
									dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
								}
							}
						}else{
			                if(_data.VISIBLE === true){
								if(_data.TYPE == 'MEA'){
									html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
								}else{
									html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
								}
							}
						}
					}
				}
			});
			if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
				dimHtml += '</ul></li>';
				sortHtml += '</ul></li>';
				meaHtml += '</ul></li>';
				html += dimHtml;
				html += sortHtml;
				html += meaHtml;
			}
			html += '</ul>';
			html += '</li>';
		} else {
			var html = '<li class="active"  id="'+_dataSourceId+'">';
			html += '<a href="#" class="ico arrow">'+_dataSet.CAPTION+'</a>';
			html += '<ul class="dep dataset" style="display:block">';
			if(_dataSet.VISIBLE === true){
				if(_dataSet.TYPE == 'MEA'){
					html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _dataSet.CAPTION +'" title="'+ _dataSet.CAPTION +'"><a href="#" class="ico sigma"><div class="fieldName">'+_dataSet.CAPTION+'</div></a></li>';	
				}else{
					html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _dataSet.CAPTION +'" title="'+ _dataSet.CAPTION +'"><a href="#" class="ico block"><div class="fieldName">'+_dataSet.CAPTION+'</div></a></li>';	
				}
			}

			html += '</ul>';
			html += '</li>';
		}

		
		
		if(WISE.Constants.editmode != 'viewer'){
			$('.drop-down.tree-menu > ul').append(html);	
        }else{
        	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu > ul').append(html);
        }
		
		$('.dataset > li').not('.wise-fld-area').draggable(gDashboard.dragNdropController.draggableOptions);
		treeMenuUi();
	};
};

WISE.libs.CubeData = function() {
	var self = this;
	
	this.paramType = [
		{
			caption:'In',
			value:'In'
		},
		{
			caption:'Between',
			value:'Between'
		},
		{
			caption:'Equals',
			value:'Equals'
		}
	];
	
	this.render = function() {
		var subjects;
		var subjectInfos;
		var indexId;
		var dsViewId;
		var cubeId;
		var dsInfo;
		$("#sql_popup").empty();
		$("#ds_popup").empty();

//		var html = '<div id="dataset_list" class="dataset_list" style="float:left; margin-right:20px;"></div><div id="dataset_info" class="dataset_info" style="float:left;"></div><div id="btn_popup2" class="btn_popup"><p id="btn_subject_check2" class="btn_subject"></p><p id="btn_subject_cancel2" class="btn_subject"></p></div>';
		var html = "			<div class=\"modal-inner\"  style=\"height: calc(100% - 85px); width: 100%;\" >\r\n" + 
		"                    <div class=\"modal-body\" style=\"height:100% ;\">\r\n" + 
		"                        <div class=\"row\" style=\"height: 100%;\">\r\n" + 
		"                            <div class=\"column\" style=\"width:50%; height: 100%;\">\r\n" + 
										/* DOGFOOT syjin 데이터 집합 주제영역 높이 수정  20210316 */
		"                                <div class=\"modal-article\" style=\"height: 100%;\">\r\n" + 
		"                                    <div class=\"modal-tit\">\r\n" + 
		"                                        <span>데이터원본 목록</span>\r\n" + 
		"                                    </div>\r\n" + 
		"                                    <div id=\"dataset_list\"/>\r\n" + 
		"                                </div>\r\n" + 
//		"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
		"                            </div>\r\n" + 
		"                            <div class=\"column\" style=\"width:50%; height: 100%;\">\r\n" + 									 
		"                                <div class=\"modal-article\" style=\"height: 80%;\">\r\n" + 
		"                                    <div class=\"modal-tit\">\r\n" + 
		"                                        <span>주제영역 리스트</span>\r\n" + 
		"                                    </div>\r\n" + 
		"                                    <div id=\"cube_list\" style=\"height: 70%;\">\r\n" + 
		"                                    </div>\r\n" + 
		"									<div class=\"modal-tit\">\r\n" + 
		"                                        <span>주제영역 설명</span>\r\n" + 
		"                                    </div>\r\n" + 
		"                                    <div id=\"cube_desc\" style=\"height: 30%;\">\r\n" + 
		"                                    </div>\r\n" + 
		"                                </div>\r\n" + 
		"                            </div>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                    <div class=\"modal-footer\">\r\n" + 
		"                        <div class=\"row center\">\r\n" + 
		"                            <a id=\"btn_cubedata_check2\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
		"                            <a id=\"btn_cubedata_cancel2\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                </div>";
		$('#sql_popup').dxPopup({
			showCloseButton: true,
			showTitle: true,
			title:"데이터 원본 선택",
			visible: true,
			closeOnOutsideClick: false,
			contentTemplate: function() {
				return html;
			},
			width: '90vw',
            height: '90vh',
            maxWidth: 1300,
            maxHeight: 830,
			onShown: function () {
				var cube_id="",cube_nm="",cube_desc="";
				$.ajax({
					type : 'post',
					url : WISE.Constants.context + '/report/subjectViewAndCube.do',
					data:{
						'userId':userJsonObject.userId
					},
					complete: function() {
						//$('#progress_box').css({'display' : 'none'});
					},
					success : function(data) {
						//$('#progress_box').css({'display' : 'none'});

						data = jQuery.parseJSON(data);

						subjects = data["subjectViews"];
						cubeInfos = data["cubeInfos"];
						
						$("#dataset_list").dxDataGrid({
							dataSource: subjects,
							width: "100%",
							/* DOGFOOT syjin 데이터 집합 주제영역 높이 수정  20210316 */
							//height: "calc(100% - 80px)",
							height: "95%",
							showBorders: true,
							paging: {
								pageSize: 20
							},
							visible : true,
							columnAutoWidth: true,
							allowColumnResizing: true,
							columns: 
								[{dataField : '데이터원본 뷰 명', width : "45%"}, {dataField : '데이터원본 명', width : "35%"}, 
									{dataField : 'DB 유형', width : "20%"}]
							,
							selection:{
								mode:'single'
							},
							onContentReady: function(){
								gDashboard.fontManager.setFontConfigForListPopup('dataset_list')
							},
							onSelectionChanged: function (selectedItems) {
								indexId = selectedItems.selectedRowsData[0]['ID'];
								dsViewId = selectedItems.selectedRowsData[0]['DS_VIEW_ID'];

								//DS_VIEW_ID
								var selectedCubeInfos = new Array();
								$.each(cubeInfos, function(i, d) {
									if(d.DS_VIEW_ID == dsViewId)
										selectedCubeInfos.push(d);
								});
								
								$("#cube_list").dxDataGrid({
									dataSource: selectedCubeInfos,
									width: "100%",
									height: "70%",
									readOnly: true,
									showBorders: true,
									visible : true,
									columnAutoWidth: true,
									allowColumnResizing: true,
									columns: 
										[{dataField : 'CUBE_NM', caption: '주제영역 명', width : "100%"}]
									,
									selection:{
										mode:'single'
									},
									onSelectionChanged: function (selectedItems) {
										indexId = selectedItems.selectedRowsData[0]['ID'];
										cubeId = selectedItems.selectedRowsData[0]['CUBE_ID'];
										
										$("#cube_desc").dxTextArea('instance').option('value', selectedItems.selectedRowsData[0]['CUBE_DESC']);
									}
								});
								
								$("#cube_desc").dxTextArea({
									width: "100%",
									height: "30%",
									readOnly: true,
									showBorders: true,
									visible : true
								});


								$("#btn_cubedata_check2").dxButton({
									text: "확인",
									type: "normal",
									onClick: function(e) {
										if(cubeId){
											WISE.Context.isCubeReport = true;
											gDashboard.dataSetCreate.cubeListInfo(cubeId, 'CUBE');
											$("#sql_popup").dxPopup("instance").hide();
										} else {
											WISE.alert('주제영역이 선택되지 않았습니다.');
										}
									}
								});

								$("#btn_cubedata_cancel2").dxButton({
									text: "취소",
									type: "normal",
									onClick: function(e) {
										$("#sql_popup").dxPopup("instance").hide();
									}
								});								

//								$.ajax({
//						        	method : 'POST',
//						            url: WISE.Constants.context + '/report/getCubeList.do',
//						            data: {'ds_view_id' : dsViewId},
//						            dataType: "json",
//						            async:false,
//						            beforeSend:function(){
//										gProgressbar.show();
//									},
//									complete:function(){
//										gProgressbar.hide();
//									},
//						            success: function(result) {
//						            	/* DOGFOOT ktkang 개인보고서 기능 추가  20200106 */
//						            	result = result.data;
//						            	
//						            	$.each(result, function(_i,_items){
//				            				switch(_items.TYPE){
//				            				case 'CUBE':
//				            					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_shapeLabels.png';
//				            					break;
//				            				case 'FOLDER':
//				            					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
//				            					break;
//				            				}
//				            			});
//						            	
//						            	$('#cube_list').dxTreeView({
//						            		dataSource:result,
//						            		dataStructure:'plain',
//						            		keyExpr: "ID",
//						            		parentIdExpr: "UPPERID",
//						            		displayExpr: "TEXT",
//						            		searchEnabled: true,
//											searchMode : "contains",
//											searchTimeout:undefined,
//											searchValue:"",
//											noDataText:"조회된 주제영역이 없습니다.",
//						            		height:"460",
//						            		showCloseButton: false,
//						            		onItemClick:function(_e){
//						            			/* DOGFOOT ktkang 주제영역 폴더 선택 후 확인 눌러도 동작하는 부분 수정  20200305 */
//						            			if(_e.itemData['TYPE'] != 'FOLDER') {
//						            				cube_id = _e.itemData['ID'];
//							            			cube_nm = _e.itemData['TEXT'];
//							            			cube_desc = _e.itemData['CUBE_DESC'];
//						            			} else {
//						            				cube_id = "";
//						            				cube_nm = "";
//						            				cube_desc = "";
//						            			}
//						            			
//						            			$("#cube_desc").dxTextArea('instance').option('value', cube_desc);
//						            		}
//						            	});
//						            }
//								});
//								
//								$("#cube_desc").dxTextArea({
//									width: "100%",
//									height: 100,
//									readOnly: true,
//									showBorders: true,
//									visible : true
//								});
									
							}
						});
						
						$("#btn_cubedata_check2").dxButton({
							text: "확인",
							type: "normal",
							onClick: function(e) {
								/* DOGFOOT ktkang 주제영역 선택 안했을 때 경고창 표시  20200130 */
								if(cube_id) {
									gProgressbar.show();
									$("#sql_popup").dxPopup("instance").hide();
									WISE.Context.isCubeReport = true;
									gDashboard.dataSetCreate.cubeListInfo(cube_id, 'CUBE');
								} else {
									WISE.alert('주제영역이 선택되지 않았습니다.');
								}
							}
						});

						$("#btn_cubedata_cancel2").dxButton({
							text: "취소",
							type: "normal",
							onClick: function(e) {
								$("#sql_popup").dxPopup("instance").hide();
							}
						});
					},
					error: function(error) {
						WISE.alert('error'+ajax_error_message(error),'error');
					}
				});
			}
		});
	}
	/*dogfoot 분석항목 폴더 그룹화 shlim 20210319*/
	this.insertDataSet = function(_dataSetOrigin,_dataSourceId, searchText){
		var _dataSet = [];
		$.each(_dataSetOrigin,function(_i,_data){
			_dataSet.push(_data);
		})
		
		if(WISE.Constants.editmode != 'viewer'){
			$('.drop-down.tree-menu ul').empty();	
        }else{
        	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu ul').empty();
        }
        /*dogfoot 분석항목 정렬  shlim 20210329 */
//		if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
//			_dataSet.sort(function(a,b){
//				if(typeof a.DATASOURCE != "undefined" && a.FLD_TYPE == "CUBE" && a.TYPE == "measure"){
//	    			return 0;
//	            }
//	            if(typeof b.DATASOURCE != "undefined" && b.FLD_TYPE == "CUBE" &&  b.TYPE == "measure"){
//	    			return 0;
//	            }
//	            return a.ORDINAL - b.ORDINAL;
////				return a.ORDINAL < b.ORDINAL ? -1 : a.ORDINAL < b.ORDINAL ? 1 : 0;
//			});
//		}
		
		var sortArr = _dataSet.filter(function(x) { 
				return typeof x.ORDINAL != 'undefined'
			});
		var sortArr2 = _dataSet.filter(function(x) { 
			return typeof x.ORDINAL == 'undefined'
			});
		sortArr.sort(function(a,b){
            return a.ORDINAL - b.ORDINAL;
		});
		
		_dataSet = sortArr2.concat(sortArr); 

        var tempDataSet = [];
		if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER == 'undefined' || !menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
            $.each(sortArr2, function(i, folder){
            	tempDataSet.push(folder);
            	tempDataSet = tempDataSet.concat(sortArr.filter(function(x){
            		return x.PARENT_ID == folder.ORDER;
            	}))
            })
            _dataSet = tempDataSet;
		}
			
		var html = '';
		var fldTitle = "";
		var meaCount = 0; dimCount = 0,meaHtml = ""; dimHtml = "", sortCount = 0, sortHtml = "";
		$.each(_dataSet,function(_i,_data){
			/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
			var orderByColumn = '';
			if(_data.ORDER_BY) {
				if(_data.ORDER_BY == 'Key Column') {
					orderByColumn = _data.ORDER_BY_KEY;
				} else if(_data.ORDER_BY == 'Name Column') {
					orderByColumn = _data.ORDER_BY_NAME;
				} else {
					orderByColumn = _data.ORDER_BY;
				}
			}
			var tableNm;
			var title = "";
			if(typeof _data.PARENT_ID == 'undefined' || _data.PARENT_ID == null){
				if(!(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN)){
					fldTitle = _data.CAPTION;
					if(_i != 0) {
						html += '</ul>';
						html += '</li>';
					}
					html += '<li id=' + _dataSourceId + ' class="wise-column-chooser wise-area-field wise-field-group" prev-container="allList" data-field-type="'+_data.TYPE+'" data-source-id="'+_dataSourceId+'">';
					html += '<a href="#" class="ico arrow '+ _data.TYPE+'-group">'+fldTitle+'</a>';
					html += '<ul class="dep dataset" style="display:none">';
				}
			} else if(_data.MEAFLD) {
				tableNm = _data['CUBE_UNI_NM'].split('.')[0];
				if(_data.TYPE == 'FLD') {
					html += '<li>';
					html += '<a href="#" class="ico arrow">'+_data.CAPTION+'</a>';
					html += '<ul class="dep dataset" style="display:none">';

					$.each(_dataSet,function(_ii,_ee){
						if(_ee.MEAFLD == _data.CAPTION){
							if(_ee.TYPE == 'MEA'){
						        title = fldTitle + ">" + _data.CAPTION;
							    html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _ee.CUBE_UNI_NM + '" UNI_NM="'+ _ee.CAPTION +'" title="'+ title +'"><a href="#" class="ico sigma"><div class="fieldName">'+_ee.CAPTION+'</div></a></li>';	
						    }else if(_ee.TYPE == 'DIM'){
						    	title = fldTitle + ">" + _data.CAPTION;
							    html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _ee.CUBE_UNI_NM + '" UNI_NM="'+ _ee.CAPTION +'" title="'+ title +'"><a href="#" class="ico block"><div class="fieldName">'+_ee.CAPTION+'</div></a></li>';	
						    }
						}
					});

					html += '</ul>';
					html += '</li>';
				}
			} else {
				var _hideColumn = false;
				/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
				if(typeof _data['CUBE_UNI_NM'] != 'undefined') {
					tableNm = _data['CUBE_UNI_NM'].split('.')[0];
				}
				if(WISE.Constants.companyname == "고용정보원"){
					if(WISE.Constants.editmode == "viewer" && (_data.CAPTION.indexOf("H_") == 0
							|| _data.CAPTION.indexOf('S_') == 0)){
						_hideColumn = true;
					}
				}

				if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
					if(!_hideColumn){
					    if(_data.TYPE == 'MEA'){
						    title = fldTitle + ">" + _data.CAPTION;

							if(meaCount == 0){
	//							meaHtml += '<li id="측정값" class="wise-fld-area" >';
								meaHtml += '<li id="'+ _dataSourceId +'"class="wise-column-chooser wise-area-field wise-field-group active" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'">';
								meaHtml += '<a href="#" class="ico arrow" dataset-caption="측정값">측정값</a>';
								meaHtml += '<ul class="dep dataset" style="display:block">';
							}
							meaCount++;
							if(_data.isCustomField){
								meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+ '" CUSTOM_DATA="Y" isCustomField="' + _data.isCustomField + '" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico custom sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
							}else{
								meaHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
							}
						
				    	} else if(_data.CAPTION.indexOf('S_') == 0 || _data.CAPTION.indexOf('H_') == 0) {
							title = fldTitle + ">" + _data.CAPTION;
							if(sortCount == 0){
	//							sortHtml += '<li id="정렬항목" class="wise-fld-area" >';
								sortHtml += '<li id="'+ _dataSourceId +'"class="wise-column-chooser wise-area-field wise-field-group" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'">';
								sortHtml += '<a href="#" class="ico arrow" dataset-caption="정렬항목">정렬항목</a>';
								sortHtml += '<ul class="dep dataset" style="display:none">';

							}
							sortCount++;
							/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
							sortHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'" orderByColumn="' + tableNm + '.['+ orderByColumn +']"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
					    
					    } else {
					    	title = fldTitle + ">" + _data.CAPTION;
							if(dimCount == 0){
	//							dimHtml += '<li id="분석항목" class="wise-fld-area" >';
								dimHtml += '<li id="'+ _dataSourceId +'"class="wise-column-chooser wise-area-field wise-field-group active" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'">';
								dimHtml += '<a href="#" class="ico arrow" dataset-caption="분석항목(행, 열)">분석항목(행, 열)</a>';
								dimHtml += '<ul class="dep dataset" style="display:block">';

							}
							dimCount++;
							/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
							dimHtml += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'" orderByColumn="' + tableNm + '.['+ orderByColumn +']"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
					    }
					}
				}else{
					if(!_hideColumn){
						if(_data.TYPE == 'MEA'){
							title = fldTitle + ">" + _data.CAPTION;
							if(_data.isCustomField){
								html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+ '" CUSTOM_DATA="Y" isCustomField="' + _data.isCustomField + '" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico custom sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
							}else{
								html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
							}

						} else {
							title = fldTitle + ">" + _data.CAPTION;
							/* goyong ktkang 주제영역 정렬 기준 CS기분으로 추가  20210607 */
							html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'" orderByColumn="' + tableNm + '.['+ orderByColumn +']"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
						}
					}
				}
				
			}
		});
		if(typeof menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER != "undefined" && menuConfigManager.getMenuConfig.Menu.GROUP_FOLDER.GROUP_FOLDER_YN){
			dimHtml += '</ul></li>';
			sortHtml += '</ul></li>';
			meaHtml += '</ul></li>';
			html += dimHtml;
			html += sortHtml;
			html += meaHtml;
		}
		
		html += '</ul>';
		html += '</li>';
		
		//2020.04.06 MKSONG 스크롤 영역 수정 DOGFOOT
		if(WISE.Constants.editmode != 'viewer'){
			$('.drop-down.tree-menu ul').append(html);	
        }else{
        	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu ul').append(html);
        }
		
		/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200212 */
		if((typeof searchText != 'undefined' && searchText != null) || WISE.Context.isCubeRelation) {
			$.each($('ul.dep.dataset'),function(_i, _e){
				if(_e.children.length == 0) {
					_e.parentNode.parentNode.removeChild(_e.parentNode);
				}
			});
		}
		/* DOGFOOT ktkang 주제영역 일 때 검색창 추가 끝  20200130 */
		$('.dataset > li').draggable(gDashboard.dragNdropController.draggableOptions);
		treeMenuUi();
		
		//2020.02.27 MKSONG 그룹 아이콘 변경 및 그룹별 드래그앤드롭 기능 추가 DOGFOOT
		$('.dataset').parent().draggable(gDashboard.dragNdropController.draggableOptions);
	};

	
	
	/* DOGFOOT ktkang 주제영역 검색 기능 개선 시작  20200305 */
//	this.insertDataSet = function(_dataSet,_dataSourceId, searchText){
//		//2020.04.06 MKSONG 스크롤 영역 수정 DOGFOOT
//		if(WISE.Constants.editmode != 'viewer'){
//			$('.drop-down.tree-menu ul').empty();	
//        }else{
//        	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu ul').empty();
//        }
//		
//		var html = '';
//		/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
//		var fldTitle = "";
//		$.each(_dataSet,function(_i,_data){
//			var tableNm;
//			/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
//			var title = "";
//			if(typeof _data.PARENT_ID == 'undefined' || _data.PARENT_ID == null){
//				/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
//				fldTitle = _data.CAPTION;
//				if(_i != 0) {
//					html += '</ul>';
//					html += '</li>';
//				}
//				html += '<li id=' + _dataSourceId + ' class="wise-column-chooser wise-area-field wise-field-group" prev-container="allList" data-field-type="'+_data.TYPE+'" data-source-id="'+_dataSourceId+'">';
//				/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
//				html += '<a href="#" class="ico arrow '+ _data.TYPE+'-group">'+fldTitle+'</a>';
//				html += '<ul class="dep dataset" style="display:none">';
//			} else if(_data.MEAFLD) {
//				tableNm = _data['CUBE_UNI_NM'].split('.')[0];
//				if(_data.TYPE == 'FLD') {
//					html += '<li>';
//					html += '<a href="#" class="ico arrow">'+_data.CAPTION+'</a>';
//					html += '<ul class="dep dataset" style="display:none">';
//
//					$.each(_dataSet,function(_ii,_ee){
//						if(_ee.MEAFLD == _data.CAPTION){
//						/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
//							if(_ee.TYPE == 'MEA'){
//						        title = fldTitle + ">" + _data.CAPTION;
//							    html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _ee.CUBE_UNI_NM + '" UNI_NM="'+ _ee.CAPTION +'" title="'+ title +'"><a href="#" class="ico sigma"><div class="fieldName">'+_ee.CAPTION+'</div></a></li>';	
//						    }else if(_ee.TYPE == 'DIM'){
//						    	title = fldTitle + ">" + _data.CAPTION;
//							    html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _ee.CUBE_UNI_NM + '" UNI_NM="'+ _ee.CAPTION +'" title="'+ title +'"><a href="#" class="ico block"><div class="fieldName">'+_ee.CAPTION+'</div></a></li>';	
//						    }
//						}
//					});
//
//					html += '</ul>';
//					html += '</li>';
//				}
//			} else {
//				if(_data.TYPE == 'MEA'){
//				/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
//					title = fldTitle + ">" + _data.CAPTION;
//					//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
//					if(_data.isCustomField){
//						/*dogfoot 비정형 사용자 정의 데이터 rename 제거 shlim 20200717*/
//						/* dogfoot 사용자 정의 데이터 아이콘 변경 shlim 20201022 */
//						html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+ '" CUSTOM_DATA="Y" isCustomField="' + _data.isCustomField + '" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico custom sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
//					}else{
//						html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
//					}
//					
//				} else {
//				/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
//					title = fldTitle + ">" + _data.CAPTION;
//					html += '<li class="wise-column-chooser wise-area-field" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
//				}
//			}
//		});
//		
//		html += '</ul>';
//		html += '</li>';
//		
//		//2020.04.06 MKSONG 스크롤 영역 수정 DOGFOOT
//		if(WISE.Constants.editmode != 'viewer'){
//			$('.drop-down.tree-menu ul').append(html);	
//        }else{
//        	$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu ul').append(html);
//        }
//		
//		/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200212 */
//		if((typeof searchText != 'undefined' && searchText != null) || WISE.Context.isCubeRelation) {
//			$.each($('ul.dep.dataset'),function(_i, _e){
//				if(_e.children.length == 0) {
//					_e.parentNode.parentNode.removeChild(_e.parentNode);
//				}
//			});
//		}
//		/* DOGFOOT ktkang 주제영역 일 때 검색창 추가 끝  20200130 */
//		$('.dataset > li').draggable(gDashboard.dragNdropController.draggableOptions);
//		treeMenuUi();
//		
//		//2020.02.27 MKSONG 그룹 아이콘 변경 및 그룹별 드래그앤드롭 기능 추가 DOGFOOT
//		$('.dataset').parent().draggable(gDashboard.dragNdropController.draggableOptions);
//	};
	
	this.cubeSearchText = function(searchText, relationEvent){
		var treeList = $('.drop-down.tree-menu > ul').find('li');
		if(WISE.Constants.editmode == "viewer" && $("#dataArea_" + WISE.Constants.pid + " .drop-down.tree-menu > ul").length > 0){
			treeList = $("#dataArea_" + WISE.Constants.pid + " .drop-down.tree-menu > ul").find('li');
		}
		
		if(WISE.Context.isCubeRelation && searchText) {
			$.each(treeList, function(_i,_e){
				//2020.03.09 MKSONG 검색 오류 수정 DOGFOOT
				if(typeof $(_e).attr('cubeUninm') == 'undefined') {
					$(_e).css('display', 'none');
				} else {
					var tableNm = $(_e).attr('cubeUninm').split('.')[0];
					if($(_e).text().indexOf(searchText) > -1 && gDashboard.dataSetCreate.cubeRelationTable.indexOf(tableNm) != -1) {
						$(_e).parent().parent().css('display', 'block');
						$(_e).parent().parent().addClass('active');
						$(_e).parent('ul').css('display', 'block');
						$(_e).css('display', 'block');
					} else {
						$(_e).css('display', 'none');
					}
				}
			});
		} else if(!WISE.Context.isCubeRelation && searchText) {
			$.each(treeList, function(_i,_e){
				//2020.03.09 MKSONG 검색 오류 수정 DOGFOOT
				if(typeof $(_e).attr('cubeUninm') == 'undefined') {
					$(_e).css('display', 'none');
				} else {
					if($(_e).text().indexOf(searchText) > -1) {
						$(_e).parent().parent().css('display', 'block');
						$(_e).parent().parent().addClass('active');
						$(_e).parent('ul').css('display', 'block');
						$(_e).css('display', 'block');
					} else {
						$(_e).css('display', 'none');
					}
				}
			});
		} else if(!relationEvent && searchText == "" && !WISE.Context.isCubeRelation){
			$.each(treeList, function(_i,_e){
				//2020.03.09 MKSONG 검색 오류 수정 DOGFOOT
				// 고용정보원 본사처리 - 15 begin
//				if(typeof $(_e).attr('cubeUninm') == 'undefined') {
//					$(_e).css('display', 'block');
//					$(_e).removeClass('active');
//					$(_e).children('a').removeClass('on');
//				} else {
//					$(_e).parent('ul').css('display', 'none');
//					$(_e).css('display', 'block');
//				}
				//
				if(typeof $(_e).attr('cubeUninm') == 'undefined') {
					$(_e).css('display', 'block');
					$(_e).parent().parent().css('display', 'block');
					$(_e).parent('ul').css('display', 'block');
					$(_e).children('ul').css('display', 'none');
					$(_e).removeClass('active');
					$(_e).css('display', 'none');
				} else {
					$(_e).parent().parent().css('display', 'block');
					$(_e).parent('ul').css('display', 'none');
					$(_e).removeClass('active');
					$(_e).css('display', 'block');
				}
				// 고용정보원 본사처리 - 15 end
			});
		} else if(!relationEvent && searchText == "" && WISE.Context.isCubeRelation){
			$.each(treeList, function(_i,_e){
				//2020.03.09 MKSONG 검색 오류 수정 DOGFOOT
				if(typeof $(_e).attr('cubeUninm') == 'undefined') {
				/* DOGFOOT ktkang 주제영역 관계 표현 오류 수정  20200318 */
					if($(_e).css('opacity') == '0.5') {
						$(_e).removeClass('active');
						$(_e).children('a').removeClass('on');
						$(_e).css('display', 'none');
					} else {
						$(_e).removeClass('active');
						$(_e).children('a').removeClass('on');
						$(_e).css('display', 'block');
					}
				} else {
				/* DOGFOOT ktkang 주제영역 관계 표현 오류 수정  20200318 */
					$(_e).parent('ul').css('display', 'none');
					$(_e).css('display', 'block');
				}
			});
		}
	};
	/* DOGFOOT ktkang 주제영역 검색 기능 개선 끝  20200305 */
	
	this.cubeRalationTree = function(){
		var treeList = $('.drop-down.tree-menu > ul').find('li');
		if(WISE.Constants.editmode == "viewer" && $("#dataArea_" + WISE.Constants.pid + " .drop-down.tree-menu > ul").length > 0){
			treeList = $("#dataArea_" + WISE.Constants.pid + " .drop-down.tree-menu > ul").find('li');
		}
		
		
		if(gDashboard.dataSetCreate.cubeRelationTable.length > 0 && WISE.Context.isCubeRelation) {
			$.each(treeList, function(_i,_e){
				var tableNm = ""; 
				/* DOGFOOT ktkang 주제영역 관계 표시 부분 오류 수정 시작  20200305 */
				if(typeof $(_e).attr('cubeUninm') == 'undefined') {
					$(_e).css('display', 'none');
				}
				else {
					tableNm = $(_e).attr('cubeUninm').split('.')[0];
					if($(_e).attr('data-field-type') == 'measure') {
						$(_e).parent().parent().css('display', 'block');
						$(_e).parent().parent().css('opacity', '1');
						$(_e).parent().parent().draggable({ disabled: false});
						$(_e).css('display', 'block');
						$(_e).css('opacity', '1');
						$(_e).draggable({ disabled: false});
					} else if(tableNm != "" && gDashboard.dataSetCreate.cubeRelationTable.indexOf(tableNm) != -1) {
						$(_e).parent().parent().css('display', 'block');
						$(_e).parent().parent().css('opacity', '1');
						$(_e).parent().parent().draggable({ disabled: false});
						$(_e).css('display', 'block');
						$(_e).css('opacity', '1');
						$(_e).draggable({ disabled: false});
					} else {
						$(_e).css('display', 'none');
						$(_e).css('opacity', '0.5');
						$(_e).draggable({ disabled: true});
					}
				} 
			});
		} else if(gDashboard.dataSetCreate.cubeRelationTable.length > 0 && !WISE.Context.isCubeRelation) {
			$.each(treeList, function(_i,_e){
			/* DOGFOOT ktkang 주제영역 관계 오류 수정  20200310 */
				if(typeof $(_e).attr('cubeUninm') != 'undefined') {
					$(_e).parent().parent().css('display', 'block');
					$(_e).parent().parent().css('opacity', '1');
					$(_e).parent().parent().draggable({ disabled: false});
					$(_e).css('display', 'block');
					$(_e).css('opacity', '1');
					$(_e).draggable({ disabled: false});
					var tableNm = $(_e).attr('cubeUninm').split('.')[0];
					if($(_e).attr('data-field-type') != 'measure' && !(tableNm != "" && gDashboard.dataSetCreate.cubeRelationTable.indexOf(tableNm) != -1)) {
						$(_e).parent().parent().css('display', 'block');
//						$(_e).parent().parent().css('opacity', '0.5');
						$(_e).parent().parent().draggable({ disabled: true});
						$(_e).css('opacity', '0.5');
						$(_e).draggable({ disabled: true});
					}
				}
			});
			/* DOGFOOT ktkang 주제영역 관계 오류 수정  20200310 */
			$.each(treeList, function(_i,_e){
				if(typeof $(_e).attr('cubeUninm') != 'undefined' && $(_e).attr('data-field-type') == 'measure') {
					$(_e).parent().parent().css('display', 'block');
					$(_e).parent().parent().css('opacity', '1');
					$(_e).parent().parent().draggable({ disabled: false});
					$(_e).css('display', 'block');
					$(_e).css('opacity', '1');
					$(_e).draggable({ disabled: false});
				}
			});
		} else {
			$.each(treeList, function(_i,_e){
				if(typeof $(_e).attr('cubeUninm') == 'undefined') {
					$(_e).css('display', 'block');
					$(_e).css('opacity', '1');
					$(_e).draggable({ disabled: false});
				} else {
					$(_e).parent().parent().css('display', 'block');
					$(_e).css('display', 'block');
					$(_e).css('opacity', '1');
					$(_e).draggable({ disabled: false});
				}
			});
		}
	};
	/* DOGFOOT ktkang 주제영역 관계 표시 부분 오류 수정 끝  20200305 */
};
