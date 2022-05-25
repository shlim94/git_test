var datasetManager = (function() {
	var ConstraintList,ColumnList,allList,datasetType,dsInfo;
	var selectedTables = [];
	var MeaTables = [];
	var DimTables = [];
	var relationLength = 1;
	var dataset_id="";
	var parameterInformation = {};
	var parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
	var datasetInfo;
	var selectedTargetDataSet;
	var commonParamType = [
		{key:'LIST', caption:'리스트'},{key:'INPUT', caption:'입력창'},{key:'CAND', caption:'달력'}
	]
	var betweenParamType = [
		{key:'BETWEEN_LIST', caption:'between 리스트'},{key:'BETWEEN_INPUT', caption:'between 입력창'},{key:'BETWEEN_CAND', caption:'between 달력'}
	];
	
	function toArray(_o) {
		if (_o) {
			return $.type(_o) === 'array' ? _o : [_o];
		} else {
			return [];
		}
	};
	
	function initDataSetList() {
		$.ajax({
			url : './getDataSetList.do',
			async: false,
			data:{
				userId:userJsonObject.userId
			},
			beforeSend: function() {
				gProgressbar.show();
			},
			success: function(_data){
				_data = JSON.parse(_data);
				ConstraintList=undefined,ColumnList=undefined,allList=undefined,datasetType=undefined,dsInfo=undefined;
				parameterInformation = {};
				selectedTables = [];
				MeaTables = [];
				DimTables = [];
				relationLength = 1;
				dataset_id="";
				var timeout = null;
            	var lastComponent = {};
				$('#DatasetSelectTable').dxTreeView({
					dataSource: _data.dataSetFolders,
					dataStructure: 'plain',
					keyExpr: "FLD_ID",
					parentIdExpr:"PARENT_FLD_ID",
					displayExpr: "FLD_NM",
					visible: true,
					selectNodesRecursive: false,
					selectByClick:true,
			        showCheckBoxesMode: "none",
			        selectionMode:'single',
					height: $('.preferences-cont').height() - 90,
					onItemClick:function(_e){

						if (!timeout) {
        			        timeout = setTimeout(function () {
        			            lastComponent = _e.itemData;
        			            timeout = null;
        			        }, 300);
        			    } else if(_e.itemData.ItemType !="FOLDER" && _e.itemData == lastComponent) {
        			    	datasetInfo = (_e.itemData);
        			    	gProgressbar.show();
        			    	openDataSet(_e.itemData.DATASET_ID,_e.itemData.DATASRC_ID,_e.itemData.DATASRC_TYPE,_e.itemData.DATASET_TYPE);
        			    	gProgressbar.hide();
        			    }
					},
					onItemSelectionChanged: function(e) {
						selectedTargetDataSet = e.itemData;
					},
					onInitialized: function(_e) {
						$.each(_e.component.option('dataSource'),function(_i,_items){
            				if(typeof _items['PARENT_FLD_ID'] == 'undefined') {
            					_items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
            					_items['ItemType'] = 'FOLDER';
            				} else {
            					_items['icon']= WISE.Constants.context + '/resources/main/images/ico_dataset.png';
            					_items['ItemType'] = 'DataSet';
            				}
            			});
						$(window).resize(function() {
							_e.component.option('height', $('.preferences-cont').height() - 90);
						});
					},
					onContentReady: function(e) {
						gProgressbar.hide();
					}
				});
				
				$('#dataSetFormInfo').dxForm({
					height: 230,
					readOnly: true,
					formData: [],
					items: [{
						label: {
							text: "데이터 원본 유형",
		                },
						dataField: "dataType",
					},{
						label: {
							text: "데이터 원본 명",
		                },
						dataField: "DB_NM",
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
				
				$('#dataSetTableInfo').dxTreeView({
					dataSource: [],
					parentIdExpr: "TBL_NM",
					keyExpr: "ID",
					displayExpr: "COL_NM",
					dataStructure: "plain",
					noDataText:'',
					visible: true,
					selectNodesRecursive: false,
					height: 460,
					onItemRendered: function(e) {
	                    if(e.itemData.TYPE === "TABLE") {
	                    	e.itemElement.attr('type','TABLE');
	                    }else{
	                    	e.itemElement.attr('type','COLUMN');
	                    	e.itemElement.attr('parentTable',e.itemData.parentTable);
	                    }
	                    e.itemElement.attr('targetName',e.itemData.COL_NM);
	                    e.itemElement.attr('prev-container','dataSetTableInfo');
	                },
					onContentReady: function(e) {
						var treeDraggableOptions = {
								appendTo: document.body, 
								helper: 'clone',
								cancel: '',
								revertDuration : 300,
								scroll: false,
								zIndex: 10000,
								start: function(_event, _ui) {
									
									$(_ui.helper).css('background-color','#337AB7');
									$(_ui.helper).css('color','#ffffff');
									$(_ui.helper).css('font-size','20px');
									$(_ui.helper).css('width',$(_ui.helper.prevObject[0]).width());
									$(_ui.helper).css('height',$(_ui.helper.prevObject[0]).height());
									$(_ui.helper).css('vertical-align','middle');
									if($(_ui.helper.prevObject[0]).attr('type') == 'COLUMN'){
										$.each(ColumnList,function(_i,_columns){
											if(_columns.ID == $(_ui.helper.prevObject[0]).parent().attr('data-item-id')){

												return false;
											}
										})
										
									}
//									_event.orignalEvent.dataTransfer.setData("text/plain", _ui.helper[0].innerText);
								}
						}
						
						$('.dx-treeview-item').draggable(treeDraggableOptions);
						gProgressbar.hide();
					}
				});
			}
			
		});
	};
	
	function newDataSetLoad(){
		$('#DataSet_popover').dxPopover({
			height: 250,
			width: 340,
			position: 'bottom',
			visible: false,
		});
		var p = $('#DataSet_popover').dxPopover('instance');
		p.option({
			target: $('#newConfig'),
			contentTemplate: function(contentElement) {
				contentElement.empty();
				contentElement.append('<div id="selectType"></div>');
//				contentElement.append('		<div id="typeDS">신규 데이터 집합(데이터 원본 기준)</div>')
				/*1212 cshan 디자인 적용 DOGFOOT*/
				$('#selectType').dxList({
					dataSource:[
//						{caption:'신규 데이터 집합(데이터 원본 기준)',value:'TypeDS',},
//						{caption:'신규 데이터 집합(주제 영역 기준)',value:'TypeDSView'},
//						{caption:'신규 데이터 집합(쿼리 직접 입력)',value:'TypeQuery'},
//						{caption:'신규 데이터 집합(단일 테이블)',value:'TypeSingleTable'}
						{caption:'신규 데이터 집합(데이터 원본 기준)',value:'TypeDS',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png'},
						/* 개발 cshan 1211 */
						{caption:'신규 데이터 집합(주제영역 기준)',value:'TypeCUBE',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png'},
						{caption:'신규 데이터 집합(쿼리 직접 입력)',value:'TypeQuery',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_sqlInput.png'},
						{caption:'신규 데이터 집합(단일 테이블)',value:'TypeSingle',ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_singleTable.png'},
					],
					displayExpr:'caption',
					keyExpr:'value',
					width:300,
					height:250,
					itemTemplate: function(data, index) {
			            var result = $("<div>");
			            $("<img>").attr("src", data.ImageSrc).css('width','32px').appendTo(result);
			            $("<span>").text(data.caption).css('padding-left','5px').appendTo(result);
			            return result;
					},
					onItemClick:function(_e){
						getDataSourceByType(_e.itemData.value);
						p.hide();
					},
				})
				
			},
		});
		p.show();
	};
	/*
	 * dataSetId(DATASET_MSTR PK)
	 * dataSrcID(DS_MSTR PK)
	 * dataSrcType(DS, CUBE)
	 * dataSetType(DataSetDs,DataSetCUBE,DataSetSQL,DataSetSingleDs)
	 * */
	function openDataSet(dataSetId, dataSrcID, dataSrcType, dataSetType){
		$.ajax({
			url : './openDataSet.do',
			async: false,
			type:'POST',
			data:{
				'dataSetID':dataSetId,
				'dataSrcID' : dataSrcID,
				'dataSrcType' : dataSrcType,
				'userNo' : userJsonObject.userNo,
			},
			beforeSend: function() {
				gProgressbar.show();
			},
			success:function(data){
				ConstraintList=undefined,ColumnList=undefined,allList=undefined,datasetType=undefined,dsInfo=undefined;
				parameterInformation = {};
				selectedTables = [];
				MeaTables = [];
				DimTables = [];
				relationLength = 1;
				dataset_id="";
				data = jQuery.parseJSON(data);
				dataset_id = dataSetId;
				switch(dataSetType){
				case 'DataSetDs':
					data.DS_Info.dataSrc_Type = dataSrcType;
					data.DS_Info.dataSet_Type = dataSetType;
					data.DS_Info.dataType = "데이터원본";
					dsInfo = data.DS_Info;
					
					$('#dataSetFormInfo').dxForm('instance').option('formData',dsInfo);
					getTBLList(dataSrcID,dataSrcType);
					initAnalysisArea(dataSetType);
					setTimeout(function(){setAnalysisArea(data.SQL_XML.DATA_SET)},100);
					break;
				case 'DataSetCUBE':
					break;
				case 'DataSetSQL':
					break;
				case 'DataSetSingleDs':
					break;
				}
				
			}
		})
	}
	
	function getDataSourceByType(_DatasetType){
		var sendUrl = "";
		switch(_DatasetType){
			case 'TypeDS':
				sendUrl = './getAuthDSList.do';
				datasetType = "DataSetDs";
				break;
			case 'TypeDSView':
				WISE.alert('준비중입니다.');
				datasetType = "DataSetCube";
//				sendUrl = './getDSViewList.do';
				break;
			case 'TypeQuery':
				WISE.alert('준비중입니다.');
				datasetType = "DataSetSQL";
//				sendUrl = './getQueryList.do';
				break;
			case 'TypeSingleTable':
				datasetType = "DataSetSingleDs";
				sendUrl = './getSingleTBLList.do';
				break;
		}
		if(sendUrl != ""){
			$.ajax({
				url : sendUrl,
				async: false,
				data:{
					userNo:userJsonObject.userNo
				},
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(_data){
					_data = JSON.parse(_data);
					if(datasetType == 'DataSetDs'){
						if(_data.length >1){
							gProgressbar.hide();
							selectDSList(datasetType,_data);
						}else if(_data.length == 1){
							_data[0].dataType = "데이터원본";
							dsInfo = _data[0];
							dsInfo.dataSrc_Type = "DS";
//							dsInfo.dataSet_Type = "DataSetDs";
							dsInfo.dataSet_Type = datasetType;
							$('#dataSetFormInfo').dxForm('instance').option('formData',_data[0]);
							setTimeout(getTBLList(_data[0].DS_ID,"DS"),100);
							
						}
						initAnalysisArea(datasetType);
					}else if(datasetType == 'DataSetSingleDs'){
						selectDSList(datasetType,_data);
						gProgressbar.hide();
					}
					
				},
				error:function(_e){
					gProgressbar.hide();
				}
			});
		}
	};
	function selectDSList(_datasetType,_data){
		$("#ds_popup").empty();
		var html = "<div class=\"modal-inner\">\r\n" + 
		"                    <div class=\"modal-body\">\r\n" + 
		"                        <div class=\"row\">\r\n" + 
		"                            <div class=\"column\" style=\"width:50%; height: 672px;\">\r\n" + 
		"                                <div class=\"modal-article\">\r\n" +
		"                                <div id='switchDSType'></div>\r\n" + 
		"                                    <div class=\"modal-tit\">\r\n" + 
		"                                        <span>데이터원본 목록</span>\r\n" + 
		"                                    </div>\r\n" + 
		"									<div id='changeType'></div>"+
		"                                    <div id=\"dataset_list\"/>\r\n" + 
		"                                </div>\r\n" + 
//		"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
		"                            </div>\r\n" + 
		"                            <div class=\"column\" style=\"width:50%; height: 672px;\">\r\n" + 
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
			width: 1300,
			height: 830,
			onShown: function () {
				var selectDSType =[{
			        "text": "데이터 원본",
			        "value": "DS"
			    },{
			        "text": "데이터 원본 뷰",
			        "value": "DS_VIEW"
			    }];
				if(_datasetType == 'DataSetSingleDs'){
					$('#switchDSType').dxRadioGroup({
						layout:"horizontal",
						dataSource:selectDSType,
						value:selectDSType[0],
						onValueChanged:function(_e){

							if(_e.value.value == 'DS'){
								$.ajax({
									url : './getSingleTBLList.do',
									async: false,
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
									}
								});
							}else{
								$.ajax({
									url : './getSingleViewTBLList.do',
									async: false,
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
									}
								});
							}
						}
					});
				}
				$("#dataset_list").dxDataGrid({
					dataSource: _data,
					width: "100%",
					height: 550,
					showBorders: true,
					paging: {
						pageSize: 20
					},
					visible : true,
					columnAutoWidth: true,
					allowColumnResizing: true,
					columns: 
					[
						{caption : '데이터원본 명',dataField:'DS_NM', width : "40%"},  
						{caption : 'DB 유형',dataField:'DBMS_TYPE', width : "15%"},  
						{caption : '서버 주소(명)',dataField:'IP', width : "25%"},  
						{caption : '사용자 데이터',dataField:'USER_AREA_YN', width : "20%"}
					],
					selection:{
						mode:'single'
					},
					onSelectionChanged: function (selectedItems) {
						var form = $("#dataset_info").dxForm('instance');
						form.option("formData", selectedItems.selectedRowsData[0]);
					}
				});
				
				$("#dataset_info").dxForm({
					width: "100%",
					height: 550,
					readOnly: true,
					formData: {},
					onContentReady: function(){
						gDashboard.fontManager.setFontConfigForListPopup('dataset_list')
					},
					items: [
					{
						label: {
							text: "데이터 원본 명",
		                },
						dataField:'DS_NM',
						editorOptions: {
							readOnly: true
						}
					},
					{
						label: {
							text: "서버 주소(명)",
		                },
						dataField:'IP',
						editorOptions: {
							readOnly: true
						}
					},
					{
						label: {
							text: "DB 명",
		                },
						dataField:'DB_NM',
						editorOptions: {
							readOnly: true
						}
					},
					{
						label: {
							text: "DB 유형",
		                },
						dataField:'DBMS_TYPE',
						editorOptions: {
							readOnly: true
						}
					},
					{
						label: {
							text: "Port",
		                },
						dataField: "PORT",
						editorOptions: {
							readOnly: true
						}
					},
					{
						label: {
							text: "소유자",
		                },
						dataField: "OWNER_NM",
						editorOptions: {
							readOnly: true
						}
					},
					{
						label: {
							text: "접속 ID",
		                },
						dataField: "USER_ID",
						editorOptions: {
							readOnly: true
						}
					},
					{
						label: {
							text: "설명",
		                },
						dataField: "DS_DESC",
						editorType: "dxTextArea",
						editorOptions: {
//							readOnly: true,
							height: 130
						}
					}]
				});
				
				$("#btn_subject_check2").dxButton({
					text: "확인",
					type: "normal",
					onClick:function(){
						if(_datasetType == 'DataSetDs'){
							var selectDS = $("#dataset_list").dxDataGrid('instance').getSelectedRowsData();
							selectDS[0].dataType = "데이터원본";
							$('#dataSetFormInfo').dxForm('instance').option('height','230px');
							$('#dataSetFormInfo').dxForm('instance').option('formData',selectDS[0]);
							dsInfo = selectDS[0];
							dsInfo.dataSrc_Type = "DS";
							dsInfo.dataSet_Type = "DataSetDs";
							
							$("#ds_popup").dxPopup("instance").hide();
							setTimeout(getTBLList(selectDS[0].DS_ID,"DS"),100);
						}else if(_datasetType == 'DataSetSingleDs'){
							var dsTypeValue = $('#switchDSType').dxRadioGroup('instance').option('value').value;

							if(dsTypeValue == 'DS'){
								var selectDS = $("#dataset_list").dxDataGrid('instance').getSelectedRowsData();
								selectDS[0].dataType = "단일테이블";
								$('#dataSetFormInfo').dxForm('instance').option('formData',selectDS[0]);
								dsInfo = selectDS[0];
								dsInfo.dataSrc_Type = "DS";
								dsInfo.dataSet_Type = "DataSetSingleDs";
								
								$("#ds_popup").dxPopup("instance").hide();
								setTimeout(getTBLList(selectDS[0].DS_ID,"DS_SINGLE"),100);
							}else{
								var selectDS = $("#dataset_list").dxDataGrid('instance').getSelectedRowsData();
								selectDS[0].dataType = "단일테이블";
								$('#dataSetFormInfo').dxForm('instance').option('formData',selectDS[0]);
								dsInfo = selectDS[0];
								dsInfo.dataSrc_Type = "DS_VIEW";
								dsInfo.dataSet_Type = "DataSetSingleDsView";
								
								$("#ds_popup").dxPopup("instance").hide();
								setTimeout(getTBLList(selectDS[0].DS_VIEW_ID,"DS_VIEW_SINGLE"),100);
							}
							
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
	
	function getTBLList(ds_id,ds_type){
		if(ds_type == 'DS'){
			var tableList, colList, listId = 1;
			$.ajax({
				type : 'post',
				async: false,
				url : WISE.Constants.context + '/report/getTableList.do',
				data:{
					'dsid': ds_id,
					'dstype' : ds_type
				},
				complete: function() {
					gProgressbar.hide();
				},
				success : function(data) {
					tableList = data.data;

					$.each(tableList, function(_i, _o) {
						var tbl_nm = tableList[_i]['TBL_NM'];
						tableList[_i]['COL_NM'] = tbl_nm;
						tableList[_i]['ID'] = listId;
						tableList[_i]['TYPE'] = 'TABLE';
						listId++;
						delete tableList[_i]['TBL_CAPTION'];
						delete tableList[_i]['TBL_NM'];
					});
				}
			});

			$.ajax({
				type : 'post',
				async: false,
				url : WISE.Constants.context + '/report/getColumnList.do',
				data:{
					'dsid': ds_id,
					'dstype' : ds_type,
					'tableNm' : ''
				},
				success : function(data) {
					colList = data.data;

					$.each(colList, function(_i, _o) {
						$.each(tableList, function(_ii, _oo) {
							var tbl_nm = tableList[_ii]['COL_NM'];
							if(colList[_i]['TBL_NM'] == tbl_nm) {
								colList[_i]['TBL_NM'] = tableList[_ii]['ID'];
								colList[_i]['TYPE'] = 'COLUMN';
								colList[_i]['parentTable'] = tbl_nm;
							}
						});
						colList[_i]['ID'] = listId;
						listId++;
					});
					ColumnList = colList;
					allList = tableList.concat(colList);
					$("#dataSetTableInfo").dxTreeView('instance').option('dataSource',allList);
				}
			});
			
			$.ajax({
				type : 'post',
				async: false,
				url : WISE.Constants.context + '/report/getConstraintList.do',
				data:{
					'dsid': ds_id,
					'dstype' : ds_type,
					'tableNm' : ''
				},
				success : function(data) {
					ConstraintList = data.data;

				}
			});
		}else if(ds_type == 'DS_SINGLE'){
			$.ajax({
				type : 'post',
				async: false,
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
						width: 1300,
						height: 830,
						onShown: function () {
							$('#Table_list').dxDataGrid({
								height:'580px',
								dataSource:tableList,
								selection:{
									mode:'single'
								},
								/* DOGFOOT ktkang 단일테이블에 페이지 갯수 선택 추가  20200716  */
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
									var items = [
										{label: {text: "데이터 원본 유형",},dataField: "dataType"},
										{label: {text: "테이블 이름",},dataField : "TBL_NM"},
										{label: {text: "데이터 원본 명",},dataField: "DB_NM"},
										{label: {text: "서버 주소(명)",},dataField: "IP"},
										{label: {text: "DB 명"},dataField: "DB_NM"},
										{label: {text: "DB 유형",},dataField : "DBMS_TYPE"},
									];
									var dataSetFormInfoData = $('#dataSetFormInfo').dxForm('instance').option('formData');
									
									$('#dataSetFormInfo').dxForm('instance').option('height','280px');
									$('#dataSetFormInfo').dxForm('instance').option('items',items);
									dataSetFormInfoData.TBL_NM = selectedTBL_NM;
									$('#dataSetFormInfo').dxForm('instance').option('formData',dataSetFormInfoData);
									$.ajax({
										type : 'post',
										async: false,
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
												if(_dataItem.DATA_TYPE.toLowerCase() == 'int' || _dataItem.DATA_TYPE.toLowerCase() == 'decimal' || 
														_dataItem.DATA_TYPE.toLowerCase() == 'bigint' || _dataItem.DATA_TYPE.toLowerCase() == 'number' ||
														_dataItem.DATA_TYPE.toLowerCase() == 'float' || _dataItem.DATA_TYPE.toLowerCase() == 'double'){
													_dataItem.TYPE = 'MEA'
												}else{
													_dataItem.TYPE = 'DIM'
												}
												_dataItem.AGG = "";
												_dataItem.VISIBLE = true;
											});
											initAnalysisArea('DataSetSingleDs');
											setTimeout(function(){initSingleTableData(_data)},100);
//											$("#dataSetTableInfo").dxTreeView('instance').option('dataSource',allList);
										}
									});
									$('#TBLList_popup').dxPopup('instance').hide();
								}
							});
							$('#btn_table_cancel2').dxButton({
								onClick:function(){
									$('#TBLList_popup').dxPopup('instance').hide();
								}
							})
						}
					});
				}
			});
		}
		else if(ds_type =='DS_VIEW_SINGLE'){
			$.ajax({
				type : 'post',
				async: false,
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
						width: 1300,
						height: 830,
						onShown: function () {
							$('#Table_list').dxDataGrid({
								height:'580px',
								dataSource:tableList,
								selection:{
									mode:'single'
								},
								/* DOGFOOT ktkang 단일테이블에 페이지 갯수 선택 추가  20200716  */
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
									
									$.ajax({
										type : 'post',
										async: false,
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
														_dataItem.DATA_TYPE.toLowerCase() == 'float' || _dataItem.DATA_TYPE.toLowerCase() == 'double'){
													_dataItem.TYPE = 'MEA'
												}else{
													_dataItem.TYPE = 'DIM'
												}
												_dataItem.AGG = "";
												_dataItem.VISIBLE = true;
											});
											initAnalysisArea('DataSetSingleDs');
											setTimeout(function(){initSingleTableData(_data)},100);
//											$("#dataSetTableInfo").dxTreeView('instance').option('dataSource',allList);
										}
									});
									$('#TBLList_popup').dxPopup('instance').hide();
								}
							});
							$('#btn_table_cancel2').dxButton({
								onClick:function(){
									$('#TBLList_popup').dxPopup('instance').hide();
								}
							})
						}
					});
				}
			});
		}
	};
	
	function initAnalysisArea(_DatasetType){
		$('#dataSetAnalysisArea').empty();
		if(_DatasetType == 'DataSetDs'){
			var html =''
				+'<div class="column" style="height:35%;border-bottom:1px solid #e7e7e7;">'
				+'<h4 class="tit-level3 pre" style="padding: 20px 9px 9px 20px">표시 항목</h4>'
				+'<div class="panel-inner componet-res scrollbar">'
				+'<div id="ExpressArea" class="tbl data-form preferences-tbl"></div>'
				+'</div>'
				+'</div>'
				+'<div class="column" style="height:34%;border-bottom:1px solid #e7e7e7;">'
				+'<h4 class="tit-level3 pre" style="padding: 10px 9px 9px 20px">조건 항목</h4>'
				+'<div class="panel-inner componet-res scrollbar">'
				+'<div style="float:left;padding-top:10px;padding-bottom:10px;"><span style="float:left;font-size:14px;padding-top: 14px;padding-right: 20px;">조건식 변경</span><div id="logicArea" style="float:left"></div><a id="checkLogic" class="btn positive ok-hide" href="#" style="float:left">조건식 점검</a></div>'
				+'<div id="ConditionArea" class="tbl data-form preferences-tbl" style="float:left"></div>'
				+'</div>'
				+'</div>'
				+'<div class="column" style="height:27%;border-bottom:1px solid #e7e7e7;">'
				+'<h4 class="tit-level3 pre" style="padding: 10px 9px 9px 20px">연결정보 & 정렬</h4>'
				+'<div class="panel-inner componet-res scrollbar">'
				+'<div id="RelationArea" class="tbl data-form preferences-tbl"></div>'
				+'</div>'
				+'</div>';
			var selectTypehtml ="<div class=\"modal-inner\">\r\n" + 
			"                    <div class=\"modal-body\">\r\n" + 
			"                        <div class=\"row\">\r\n" + 
			"                            <div class=\"column\" style=\"width:100%; height: 180px;\">\r\n" + 
			"                                <div class=\"modal-article\">\r\n" + 
			"                                    <div id=\"setDataType\">\r\n" +
			"                                    	<span>데이터 형식을 지정해 주시기 바랍니다.</span><br><br>\r\n" +
			"                         	         	<div id=\"TypeMea\"/><span> &nbsp;측정값 데이터는 집계 데이터를 의미합니다.</span><br><br>" +
			"                         	         	<div id=\"TypeDim\"/><span> &nbsp;차원 데이터는 집계 기준 데이터를 의미합니다.</span><br>" +
			"                                    </div>\r\n" +
			"                                </div>\r\n" + 
			"                            </div>\r\n" + 
			"                        </div>\r\n" + 
			"                    </div>\r\n" + 
			"                </div>";
			if($('#ExpressArea').length  == 0 && $('#ConditionArea').length == 0 && $('#RelationArea').length == 0){
				$('#dataSetAnalysisArea').append(html);
			}
			$('#ExpressArea').dxDataGrid({
				height:300,
				columns:[
					{
						width:'7%',
						caption:'집계',
						dataField:'AGG',
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
						caption:'컬럼 물리명',
						dataField:'COL_NM',
						allowEditing:false,
					},{
						caption:'Alias',
						dataField:'COL_CAPTION',
						
					},{
						width:'13%',
						caption:'데이터 유형',
						dataField:'DATA_TYPE',
						allowEditing:false,
					},{
						caption:'테이블 논리명',
						dataField:'TBL_NM',
						allowEditing:false,
					},{
						width:'9%',
						caption:'유형',
						dataField:'TYPE',
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
					}
				],
				noDataText:"",
				dataSource:[],
				editing: {
		            mode: "cell",
		            allowUpdating: true,
		            texts: {
		                confirmDeleteMessage: ""
		            }
				},
				
				onContentReady:function(e){
					var treeDraggableOptions2 = {
						appendTo: document.body, 
						helper: 'clone',
						cancel: '',
						revertDuration : 300,
						scroll: false,
						zIndex: 10000,
						start: function(_event, _ui) {
							$(_ui.helper).text($($(_ui.helper.prevObject[0]).children()[1]).text());
							$(_ui.helper).css('background-color','#337AB7');
							$(_ui.helper).css('color','#ffffff');
							$(_ui.helper).css('font-size','20px');
							$(_ui.helper).css('width','250px');
							$(_ui.helper).css('height','22px');
							$(_ui.helper).css('vertical-align','middle');
						}
					}
					$('.dx-data-row').draggable(treeDraggableOptions2);
				},
				onRowUpdated:function(_e){

					for(var i=0;i<selectedTables.length;i++){
						if(selectedTables[i].parentTable === _e.key.TBL_NM){
							selectedTables[i].DimMea = _e.key.TYPE;
							if(_e.key.TYPE === 'MEA'){
								_e.key.AGG = 'Sum';
							}else{
								_e.key.AGG = '';
							}
							
							break;
						}
					}
				}
			});
			$('#logicArea').dxTextArea({
				width:'960px',
				value:''
					
			});
			$('#checkLogic').dxButton({
				onClick:function(){
					var logic = $('#logicArea').dxTextArea('instance').option('value');
					var conditionList = $('#ConditionArea').dxDataGrid('instance').option('dataSource');
					var logicBoolean = true;
					$.each(conditionList,function(_i,_list){
						if(logic.indexOf("["+_list.COND_ID+"]") == -1){
							logicBoolean = false;
							return false;
						}
					});
					if(logicBoolean == true){
						WISE.alert("누락된 조건식이 없습니다.");
					}else{
						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
						WISE.alert("사용되지 않은 조건식이 있습니다.<br>조건식을 다시 확인하세요.",'error');
					}
					
				}
			});
			$('#ConditionArea').dxDataGrid({
				noDataText:"",
				columns:[
					{
						width:'5%',
						type: "buttons",
						buttons:[{
							hint: "매개변수 편집",
		                    icon: "edit",
		                    onClick: function(e) {

		                    	if(e.row.data.PARAM_YN == 'True' || e.row.data.PARAM_YN == true)
		                    		editDatasetFilter();
		                    }
						}]
					},
					{
						width:'6%',
						caption:'조건ID',
						dataField:'COND_ID',
						allowEditing:false,
					},{
						caption:'컬럼 논리명',
						dataField:'COL_NM',
						allowEditing:false,
					},{
						caption:'테이블 논리명',
						dataField:'TBL_NM',
						allowEditing:false,
					},{
						width:'8%',
						caption:'조건',
						dataField:'OPER',
						lookup:{
							dataSource: [{
								caption:'In',
								value:'In'
							},{
								caption:'Between',
								value:'Betwen'
							}],
							displayExpr: "caption",
		                    valueExpr: "value"
						}
					},{
						caption:'조건 값',
						dataField:'VALUES'
					},{
						width:'5%',
						type: "buttons",
						buttons:[{
							hint: "조건 값 편집",
		                    icon: "edit",
		                    onClick: function(e) {
		                    	var rowdata = e.row.data;
		                    	$('#dataList_popup').dxPopup({
		                    		showCloseButton: true,
									showTitle: true,
									visible: true,
									title: "컬럼 값 선택",
									closeOnOutsideClick: false,
									contentTemplate: function() {
										var html = '<div class="modal-inner">' + 
										'                    <div class="modal-body">' + 
										'                        <div class="row">' + 
										'                            <div class="column">' + 
										'                                <div class="modal-article">' + 
										'                                   <div class="modal-tit">' + 
										'                                   	<span>테이블 조회 결과</span>' + 
										'                                   </div>' + 
										'                                   <div id="dataListSelection" />' + 
										'                                </div>' +
										'							</div>'+
										'						</div>'+
										'					</div>'+
										'                   <div class="modal-footer" style="padding-top:15px;">' + 
										'                        <div class="row center">' + 
										'                            <a id="btn_dataselect_check" class="btn positive ok-hide" href="#" >확인</a>' + 
										'                            <a id="btn_dataselect_cancel" class="btn neutral close" href="#">취소</a>' + 
										'                        </div>' + 
										'                   </div>' + 
										'           </div>';
										return html;
									},
									width:'600px',
									height:'700px',
									onShown:function(){
										var allSelected;
										var param = {
											'COLUMN_NM': rowdata.COL_NM,
											'TABLE_NM': rowdata.TBL_NM,
											'DATASRC_TYPE': 'DS',
											'DS_ID': dsInfo.DS_ID,
										};
									
										$.ajax({
											cache: false,
											type: 'post',
											async: false,
											data: param,
											url: WISE.Constants.context + '/report/getDataList.do',
											success: function(_data) {
												var ret = _data.data;

												$('#dataListSelection').dxList({
													selectionMode:'all',
													height:460,
													showSelectionControls:true,
													dataSource:ret,
													onSelectAllValueChanged:function(_e){
														allSelected = _e.value;
													},
													onContentReady:function(_e){
														if(e.row.data.VALUES == '[All]')
															$('#dataListSelection').dxList('instance').selectAll();
														else{
															$('#dataListSelection').dxList('instance').option('selectedItemKeys',e.row.data.VALUES.split(','))
															$('#dataListSelection').dxList('instance').option('selectedItems',e.row.data.VALUES.split(','));
														}
													}
												})
											}
										});
										$('#btn_dataselect_check').dxButton({
											onClick:function(){

												var condtionDataSource = $('#ConditionArea').dxDataGrid('instance').option('dataSource');
												if(allSelected == true){
													condtionDataSource[e.row.rowIndex].VALUES = '[All]';
													condtionDataSource[e.row.rowIndex].VALUES_CAPTION = '전체';
													parameterInformation[e.row.data.UNI_NM].DEFAULT_VALUE = '[All]';
//													e.row.data.VALUE = '[All]';
//													e.row.data.VALUES_CAPTION = '전체';
												}else{
													condtionDataSource[e.row.rowIndex].VALUES = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",")
													condtionDataSource[e.row.rowIndex].VALUES_CAPTION = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",")
													parameterInformation[e.row.data.UNI_NM].DEFAULT_VALUE = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",");
													
//													e.row.data.VALUE = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",");
//													e.row.data.VALUES_CAPTION = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",");
												}
												$('#ConditionArea').dxDataGrid('instance').option('dataSource',condtionDataSource);
												$('#dataList_popup').dxPopup('instance').hide();
//												$('#dataList_popup').empty();
											}
										})
										$('#btn_dataselect_cancel').dxButton({
											onClick:function(){
												$('#dataList_popup').dxPopup('instance').hide();
//												$('#dataList_popup').empty();
											}
										})
									}
		                    	});
		                    }
						}]
					},{
						width:'5%',
						caption:'조회',
						dataField:'DATA_BIND_YN',
						alignment:"center",
						dataType:'boolean',
					},{
						width:'9%',
						caption:'집계',
						dataField:'AGG',
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
						},
					},{
						width:'6%',
						caption:'매개변수',
						dataField:'PARAM_YN',
//						allowEditing:false,
						alignment:"center",
						dataType:'boolean',
					},{
//						type: "buttons",
						caption:'매개변수 명',
						dataField:'PARAM_NM',
					},{
						width:'5%',
						caption:'유형',
						dataField:'TYPE',
						lookup:{
							dataSource: [{
								caption:'측정값',
								value:'MEA'
							},{
								caption:'차원',
								value:'DIM'
							}],
							displayExpr: "caption",
		                    valueExpr: "value"
						}
					}
				],
				height:165,
				dataSource:[],
				editing: {
		            mode: "cell",
		            allowUpdating: true,
		            texts: {
		                confirmDeleteMessage: ""
		            }
				},
				onContentReady:function(e){
					var treeDraggableOptions2 = {
						appendTo: document.body, 
						helper: 'clone',
						cancel: '',
						revertDuration : 300,
						scroll: false,
						zIndex: 10000,
						start: function(_event, _ui) {
							$(_ui.helper).text($($(_ui.helper.prevObject[0]).children()[1]).text());
							$(_ui.helper).css('background-color','#337AB7');
							$(_ui.helper).css('color','#ffffff');
							$(_ui.helper).css('font-size','20px');
							$(_ui.helper).css('width','250px');
							$(_ui.helper).css('height','22px');
							$(_ui.helper).css('vertical-align','middle');
						}
					}
					$('.dx-data-row').draggable(treeDraggableOptions2);
				},
				onRowUpdated:function(_e){

					if(_e.data.PARAM_NM != undefined){
						var changeParam = $.extend(true, {}, gDashboard.parameterFilterBar.parameterInformation[_e.key.UNI_NM]);
						changeParam['PARAM_NM'] = _e.key.PARAM_NM;
						gDashboard.parameterFilterBar.parameterInformation[_e.key.UNI_NM]['PARAM_NM']  = _e.key.PARAM_NM;
						gDashboard.FieldFilter.parameterInformation[_e.key.UNI_NM]['PARAM_NM']  = _e.key.PARAM_NM;
						
					}else if(_e.data.PARAM_YN != undefined){
						var changeParam = $.extend(true, {}, gDashboard.parameterFilterBar.parameterInformation[_e.key.UNI_NM]);
						var conditionDataSource = _e.component.option('dataSource');
						if(_e.data.PARAM_YN == true){
							$.each(conditionDataSource,function(_i,_data){
								if(_data.COND_ID === _e.key.COND_ID){
									_data.PARAM_NM = '@'+_e.key.COL_NM;
									return false;
								}
							});
							changeParam['VISIBLE'] = 'Y';
							gDashboard.parameterFilterBar.parameterInformation[_e.key.UNI_NM]['VISIBLE']  = 'Y';
							gDashboard.FieldFilter.parameterInformation[_e.key.UNI_NM]['VISIBLE']  = 'Y';
						}else{
							$.each(conditionDataSource,function(_i,_data){
								if(_data.COND_ID === _e.key.COND_ID){
									_data.PARAM_NM = '';
									return false;
								}
							});
							changeParam['VISIBLE'] = 'N';
							gDashboard.parameterFilterBar.parameterInformation[_e.key.UNI_NM]['VISIBLE']  = 'N';
							gDashboard.FieldFilter.parameterInformation[_e.key.UNI_NM]['VISIBLE']  = 'N';
						}
						_e.component.option('dataSource',conditionDataSource);
					}
				}
			});
			$('#RelationArea').dxDataGrid({
				noDataText:"",
				columns:[
					{
						caption:'원본테이블',
						dataField:'FK_TBL_NM'
					},{
						caption:'원본 컬럼',
						dataField:'FK_COL_NM'
					},{
						caption:'대상 테이블',
						dataField:'PK_TBL_NM'
					},{
						caption:'대상 컬럼',
						dataField:'PK_COL_NM'
					},{
						width:'13%',
						caption:'연결 유형',
						dataField:'JOIN_TYPE'
					}
				],
				height:135,
				dataSource:[]
			});
			
			$('#queryopen').dxButton({
				text:'쿼리',
				onClick:function(){
					event.preventDefault();
					var whereItems = new Array();
					
					$.each(parameterInformation,function (_key,_val){
						whereItems.push(_val);
					});
					$.each(whereItems,function(_i,_where){
						$.each($('#ConditionArea').dxDataGrid('instance').option('dataSource'),function(_j,_condition){
							if(_condition.UNI_NM === _where.UNI_NM){
								_where.COND_ID = _condition.COND_ID;
								_where.AGG = _condition.AGG;
								_where.TYPE = _condition.TYPE;
								_where.PARAM_YN = _condition.PARAM_YN;
							}
						});
					});
					
					var param = {
						dsId: dsInfo.DS_ID,
						selArray:$('#ExpressArea').dxDataGrid('instance').option('dataSource'),
						whereArray :whereItems,
						relArray:$('#RelationArea').dxDataGrid('instance').option('dataSource'),
						etcArray:[{
							STRATIFIED:"N",
							DISTINCT:"N",
							CHANGE_COND:$('#logicArea').dxTextArea('instance').option('value'),
				        	SEL_COND : "",//empty
				        	SEL_NUMERIC : 0//0
						}],
						execType:"DS"
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
    						execType:'DS',
    						statics : statics
						},
						success:function(data){

							$('body').append('<div id="ds_query_popup"></div>');
							var html = '<div id="edit_query_tabpanel" class="query_tabpanel" style="height: 650px;"></div>';
							html += "<div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
									"    <div class=\"row center\">\r\n" + 
									"        <a id=\"edit_btn_tabpanel_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
									"    </div>\r\n" + 
									"</div>\r\n";
							$('#ds_query_popup').dxPopup({
								showCloseButton: true,
								showTitle: true,
								visible: true,
								title: "쿼리 실행 결과보기",
								closeOnOutsideClick: false,
								contentTemplate: function() {
									return html;
								},
								width: 1000,
								height: 800,
								onShown: function () {
									var item =  [{ 'title' : 'SQL'}, {'title' : 'SQL Data'}];
									var tabPanel = $("#edit_query_tabpanel").dxTabPanel({
										height: 650,
										selectedIndex: 0,
										loop: false,
										animationEnabled: false,
										swipeEnabled: true,
										items: item,
										onContentReady: function(e) {
											setTimeout(function () {

												
												$('.dx-multiview-item-content').attr('id', 'edit_sqlArea');
												
												var sqlAreaText = data;
												
												$("#edit_sqlArea").dxTextArea({
													width: 956,
													height: 604.8,
													value: sqlAreaText
												});
											}, 50);
										},
										onSelectionChanged: function(e) {
											if($('.dx-multiview-item-content').eq(1).attr('id') == null) {
												setTimeout(function () {
													$('.dx-multiview-item-content').eq(1).attr('id', 'edit_query_data');
													var html3 = '';
													html3 += '<div id="edit_sqlButtonArea" style="height: 40px;">';
													html3 += '	<div id="edit_sqlStartButton" class="btn crud neutral" style="margin-left:5px; margin-top:5px;"></div>';
													html3 += '	<div id="edit_sqlDownloadButton" class="btn crud neutral" style="margin-top:5px;"></div>';
													html3 += '	<span id="edit_sqlRowNumber" style="margin-top:19px; margin-left:20px; display: inline-block;"></span>';
													html3 += '</div>';
													html3 += '<div id="edit_filter-item2" class="filter-item"></div>';
													html3 += '<div id="edit_sqlFiltersArea" style="height: 50px;"></div>';
													html3 += '<div id="edit_sqlDatagridArea"></div>';

													$("#edit_query_data").append(html3);
													
													$("#edit_sqlStartButton").dxButton({
														text: "SQL 실행",
														icon: "refresh",
														type: "normal",
														onClick: function(e) {
															$('#progress_box').css({'display' : 'block'});
															var sqlText = $("#edit_sqlArea").dxTextArea('instance').option('value');
															
															if(sqlText) {
															var condition = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
//															var condition = {}; 
															var param = {
																	'dsid' : dsInfo.DS_ID,
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
																	
																	if(result){
																	/* DOGFOOT ktkang 테스트 쿼리보기용 쿼리 수정  20200629 */
//																		$('#edit_sqlRowNumber').text('총 건수 : ' + result.length + " 건");
																		WISE.alert('테스트 데이터는 100건만 보여집니다.');
																	}

																	$('#edit_sqlDatagridArea').dxDataGrid({
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
																		}
																	});
																},error: function(_response) {
																	gProgressbar.hide();
																	//2020.01.21 mksong 경고창 타입 지정 dogfoot
																	WISE.alert('쿼리가 부적합 합니다.','error');
																}
															});
															} else {
																WISE.alert('쿼리가 없습니다.');
															}
														}
													});
													
													$("#edit_sqlDownloadButton").dxButton({
														text: "내려받기",
														icon: "export",
														type: "normal",
														onClick: function(e) {
															var sqlDatagridIns = $('#edit_sqlDatagridArea').dxDataGrid('instance');
															
															if(sqlDatagridIns) {
																$('#edit_sqlDatagridArea').dxDataGrid('instance').exportToExcel();
															}
														}
													});
													
													if(parameterInformation) {
														parameterHandler.initForDataSet(parameterInformation);
														parameterHandler.render(true);
														parameterHandler.resize();
													}
												}, 50);
											}
										}
									});
									
									$("#edit_btn_tabpanel_ok").dxButton({
										text: "확인",
										type: "normal",
										onClick: function(e) {
											$("#ds_query_popup").dxPopup("instance").hide();
											$("#ds_query_popup").remove();
											$('#edit_filter-item2').empty();
										}
									});
								}
							});
						
						}
					});
				}
			})
			
			var droppableOption = {
				deactivate: function(_event, _ui) {
					$(this).removeClass("wise-area-drop-over");
				},
				drop: function(_event, _ui) {
					var container = $(this).attr('id');
					var targetContainer = $('#' + container);
					
					var prevContainer = _ui.draggable.attr('prev-container');
					var type = _ui.draggable.attr('type');
					var dataItem = _ui.helper;
					
					if(type == 'COLUMN'){
						if(targetContainer.attr('id') == 'ExpressArea'){
							var selectedItemsType;
							
							var itemattr= {
								COL_NM: _ui.draggable.attr('targetName'),
								parentTable : _ui.draggable.attr('parentTable'),
							}
							
							$.each(selectedTables,function(_i,_tables){
								if(_tables.parentTable === itemattr.parentTable && _tables.selectedCount != 0){
									selectedItemsType = _tables;
									selectedItemsType.selectedCount = selectedItemsType.selectedCount+1;
									return false;
								}
							});
							if(selectedItemsType == undefined){
								$('#columnType_popup').dxPopup({
									showCloseButton: true,
									showTitle: true,
									title:"데이터 형식 지정",
									visible: true,
									closeOnOutsideClick: false,
									contentTemplate: function() {
										return selectTypehtml;
									},
									width: 500,
									height: 250,
									onShown: function () {
										$('#TypeMea').dxButton({
											text:'측정값',
											onClick:function(){
												var selectedTableCount = 1;
												for(var i=0;i<selectedTables.length;i++){
													if(selectedTables[i].parentTable === itemattr.parentTable){
														selectedTableCount = selectedTables[i].selectedCount +1;
													}
												}
												selectedItemsType = {
													parentTable:itemattr.parentTable,
													DimMea : 'MEA',
													selectedCount:selectedTableCount
												}
												selectedTables.push(selectedItemsType);
												$('#columnType_popup').dxPopup('instance').hide();
												setArea(container,selectedItemsType,itemattr);
											}
										});
										$('#TypeDim').dxButton({
											text:'차원',
											onClick:function(){
												var selectedTableCount = 1;
												for(var i=0;i<selectedTables.length;i++){
													if(selectedTables[i].parentTable === itemattr.parentTable){
														selectedTableCount = selectedTables[i].selectedCount +1;
													}
												}
												selectedItemsType = {
													parentTable:itemattr.parentTable,
													DimMea : 'DIM',
													selectedCount:selectedTableCount
												}
												selectedTables.push(selectedItemsType);
												$('#columnType_popup').dxPopup('instance').hide();
												setArea(container,selectedItemsType,itemattr);
											}
										})
									}
								})
							}else{
								setArea(container,selectedItemsType,itemattr)
							}
						}else if(targetContainer.attr('id') == 'ConditionArea'){
							var selectedItemsType;
							
							var itemattr= {
								COL_NM: _ui.draggable.attr('targetName'),
								parentTable : _ui.draggable.attr('parentTable'),
							}
							
							$.each(selectedTables,function(_i,_tables){
								if(_tables.parentTable === itemattr.parentTable && _tables.selectedCount != 0){
									selectedItemsType = _tables;
									selectedItemsType.selectedCount = selectedItemsType.selectedCount+1;
									return false;
								}
							});
							if(selectedItemsType == undefined){
								$('#columnType_popup').dxPopup({
									showCloseButton: true,
									showTitle: true,
									title:"데이터 형식 지정",
									visible: true,
									closeOnOutsideClick: false,
									contentTemplate: function() {
										return selectTypehtml;
									},
									width: 500,
									height: 250,
									onShown: function () {
										$('#TypeMea').dxButton({
											text:'측정값',
											onClick:function(){
												var selectedTableCount = 1;
												for(var i=0;i<selectedTables.length;i++){
													if(selectedTables[i].parentTable === itemattr.parentTable){
														selectedTableCount = selectedTables[i].selectedCount +1;
													}
												}
												selectedItemsType = {
													parentTable:itemattr.parentTable,
													DimMea : 'MEA',
													selectedCount:selectedTableCount
												}
												selectedTables.push(selectedItemsType);
												$('#columnType_popup').dxPopup('instance').hide();
												setArea(container,selectedItemsType,itemattr);
											}
										});
										$('#TypeDim').dxButton({
											text:'차원',
											onClick:function(){
												var selectedTableCount = 1;
												for(var i=0;i<selectedTables.length;i++){
													if(selectedTables[i].parentTable === itemattr.parentTable){
														selectedTableCount = selectedTables[i].selectedCount +1;
													}
												}
												selectedItemsType = {
													parentTable:itemattr.parentTable,
													DimMea : 'DIM',
													selectedCount:selectedTableCount
												}
												selectedTables.push(selectedItemsType);
												$('#columnType_popup').dxPopup('instance').hide();
												setArea(container,selectedItemsType,itemattr);
											}
										})
									}
								})
							}else{
								setArea(container,selectedItemsType,itemattr)
							}
						}
					}
				}
			};
			var removeDroppableOption = {
				drop: function(_event, _ui) {
					var container = $(this).attr('id');
					var targetContainer = $('#' + container);
//					var removeTargetDataSource = $('#'+container).dxDataGrid('instance').option('dataSource');
					
					var removeTargetIndex = _ui.draggable.attr('aria-rowindex');
					var fromContainer = "";
					if($(_ui.draggable).closest('#ExpressArea').length != 0 ){
						fromContainer = 'ExpressArea';
					}else if($(_ui.draggable).closest('#ConditionArea').length != 0){
						fromContainer = 'ConditionArea';
					}
					if(fromContainer != ""){
						var targetGridData = $('#'+fromContainer).dxDataGrid('instance').getKeyByRowIndex(removeTargetIndex-1);
						for(var i=0;i<selectedTables.length;i++){
							if(selectedTables[i].parentTable === targetGridData.TBL_NM){
								selectedTables[i].selectedCount = selectedTables[i].selectedCount -1;
							}
						}
						for(var i=0;i<selectedTables.length;i++){
							if(selectedTables[i].selectedCount === 0){
								selectedTables.splice(i,1);
							}
						}
						if(fromContainer === 'ConditionArea'){
							delete parameterInformation[targetGridData.UNI_NM];
						}
						
						var counter = 0;
						var targetRemoveGridDatas = $('#'+fromContainer).dxDataGrid('instance').option('dataSource');
						$.each(targetRemoveGridDatas,function(_i,_e){
							if(_e.TBL_NM === targetGridData.TBL_NM){
								counter++;
							}
						});
						if(counter == 1){
							var relationGridDatas = $('#RelationArea').dxDataGrid('instance').option('dataSource');
							var PK_FK_TABLE;
							if(targetGridData.TYPE == 'DIM'){
								for(var i=0;i<selectedTables.length;i++){
									if(selectedTables[i].parentTable === targetGridData.TBL_NM && selectedTables[i].selectedCount == 0){
										$.each(relationGridDatas,function(_i,_e){
											if(_e.PK_TBL_NM === targetGridData.TBL_NM){
												relationGridDatas.splice(_i,1);
											}
										});
									}
								}
//								$.each(relationGridDatas,function(_i,_e){
//									if(_e.PK_TBL_NM === targetGridData.TBL_NM){
//										relationGridDatas.splice(_i,1);
//									}
//								});
							}else{
								for(var i=0;i<selectedTables.length;i++){
									if(selectedTables[i].parentTable === targetGridData.TBL_NM && selectedTables[i].selectedCount == 0){
										$.each(relationGridDatas,function(_i,_e){
											if(_e.FK_TBL_NM === targetGridData.TBL_NM){
												relationGridDatas.splice(_i,1);
											}
										});
									}
								}
//								$.each(relationGridDatas,function(_i,_e){
//									if(_e.FK_TBL_NM === targetGridData.TBL_NM){
//										relationGridDatas.splice(_i,1);
//									}
//								});
							}
							$('#RelationArea').dxDataGrid('instance').option('dataSource',relationGridDatas);
						}
						$('#'+fromContainer).dxDataGrid('instance').deleteRow(removeTargetIndex-1);
					}
					
				}
			}
			$('#ExpressArea').droppable(droppableOption);
			$('#ConditionArea').droppable(droppableOption);
			$('#dataSetTableInfo').droppable(removeDroppableOption);
			$('#DatasetSelectTable').droppable(removeDroppableOption);
		}else if(_DatasetType == 'DataSetSingleDs'){
			var html = ""
			+'<div id="queryopen"></div>'
			+'<div class="column" style="height:100%;border-bottom:1px solid #e7e7e7;">'
			+'<h4 class="tit-level3 pre" style="padding: 20px 9px 9px 20px">표시 항목</h4>'
			+'<div class="panel-inner componet-res scrollbar">'
			+'<div id="ExpressArea" class="tbl data-form preferences-tbl"></div>'
			+'</div>'
			+'</div>'
			if($('#ExpressArea').length  == 0){
				$('#dataSetAnalysisArea').append(html);
			}
			$('#ExpressArea').dxDataGrid({
				columns:[
					{
						caption:'컬럼 물리명',
						dataField:'COL_NM',
						allowEditing:false,
					},{
						caption:'컬럼 논리명',
						dataField:'COL_CAPTION',
					},{
						width:'13%',
						caption:'데이터 유형',
						dataField:'DATA_TYPE',
						allowEditing:false,
					},{
						width:'9%',
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
						width:'10%',
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
						width:'7%'
					},{
						caption:'표시순서',
						dataField:'COL_ID',
						width:'7%',
					},
					
				],
				noDataText:"",
				dataSource:[],
				editing: {
		            mode: "cell",
		            allowUpdating: true,
		            texts: {
		                confirmDeleteMessage: ""
		            }
				},
				height:700,
				onContentReady:function(e){
					
				}
			});
			$('#queryopen').dxButton({
				text:'쿼리',
				onClick:function(){
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
						}],
						execType:"DS"
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

							$('body').append('<div id="ds_query_popup"></div>');
							var html = '<div id="edit_query_tabpanel" class="query_tabpanel" style="height: 650px;"></div>';
							html += "<div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
									"    <div class=\"row center\">\r\n" + 
									"        <a id=\"edit_btn_tabpanel_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
									"    </div>\r\n" + 
									"</div>\r\n";
							$('#ds_query_popup').dxPopup({
								showCloseButton: true,
								showTitle: true,
								visible: true,
								title: "쿼리 실행 결과보기",
								closeOnOutsideClick: false,
								contentTemplate: function() {
									return html;
								},
								width: 1000,
								height: 800,
								onShown: function () {
									var item =  [{ 'title' : 'SQL'}, {'title' : 'SQL Data'}];
									var tabPanel = $("#edit_query_tabpanel").dxTabPanel({
										height: 650,
										selectedIndex: 0,
										loop: false,
										animationEnabled: false,
										swipeEnabled: true,
										items: item,
										onContentReady: function(e) {
											setTimeout(function () {

												
												$('.dx-multiview-item-content').attr('id', 'edit_sqlArea');
												
												var sqlAreaText = data;
												
												$("#edit_sqlArea").dxTextArea({
													width: 956,
													height: 604.8,
													value: sqlAreaText
												});
											}, 50);
										},
										onSelectionChanged: function(e) {
											if($('.dx-multiview-item-content').eq(1).attr('id') == null) {
												setTimeout(function () {
													$('.dx-multiview-item-content').eq(1).attr('id', 'edit_query_data');
													var html3 = '';
													html3 += '<div id="edit_sqlButtonArea" style="height: 40px;">';
													html3 += '	<div id="edit_sqlStartButton" class="btn crud neutral" style="margin-left:5px; margin-top:5px;"></div>';
													html3 += '	<div id="edit_sqlDownloadButton" class="btn crud neutral" style="margin-top:5px;"></div>';
													html3 += '	<span id="edit_sqlRowNumber" style="margin-top:19px; margin-left:20px; display: inline-block;"></span>';
													html3 += '</div>';
													html3 += '<div id="edit_filter-item2" class="filter-item"></div>';
													html3 += '<div id="edit_sqlFiltersArea" style="height: 50px;"></div>';
													html3 += '<div id="edit_sqlDatagridArea"></div>';

													$("#edit_query_data").append(html3);
													
													$("#edit_sqlStartButton").dxButton({
														text: "SQL 실행",
														icon: "refresh",
														type: "normal",
														onClick: function(e) {
															$('#progress_box').css({'display' : 'block'});
															var sqlText = $("#edit_sqlArea").dxTextArea('instance').option('value');
															
															if(sqlText) {
															var condition = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
//															var condition = {}; 
															var param = {
																	'dsid' : dsInfo.DS_ID,
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
																	
																	if(result){
																	/* DOGFOOT ktkang 테스트 쿼리보기용 쿼리 수정  20200629 */
//																		$('#edit_sqlRowNumber').text('총 건수 : ' + result.length + " 건");
																		WISE.alert('테스트 데이터는 100건만 보여집니다.');
																	}

																	$('#edit_sqlDatagridArea').dxDataGrid({
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
																		}
																	});
																},error: function(_response) {
																	gProgressbar.hide();
																	//2020.01.21 mksong 경고창 타입 지정 dogfoot
																	WISE.alert('쿼리가 부적합 합니다.','error');
																}
															});
															} else {
																WISE.alert('쿼리가 없습니다.');
															}
														}
													});
													
													$("#edit_sqlDownloadButton").dxButton({
														text: "내려받기",
														icon: "export",
														type: "normal",
														onClick: function(e) {
															var sqlDatagridIns = $('#edit_sqlDatagridArea').dxDataGrid('instance');
															
															if(sqlDatagridIns) {
																$('#edit_sqlDatagridArea').dxDataGrid('instance').exportToExcel();
															}
														}
													});
													
													if(parameterInformation) {
														parameterHandler.initForDataSet(parameterInformation);
														parameterHandler.render(true);
														parameterHandler.resize();
													}
												}, 50);
											}
										}
									});
									
									$("#edit_btn_tabpanel_ok").dxButton({
										text: "확인",
										type: "normal",
										onClick: function(e) {
											$("#ds_query_popup").dxPopup("instance").hide();
											$("#ds_query_popup").remove();
											$('#edit_filter-item2').empty();
										}
									});
								}
							});
						}
					});
					
				}
			})
		}
	};
	function initSingleTableData(data){
		$('#ExpressArea').dxDataGrid('instance').option('dataSource',data)
	} 
	function setAnalysisArea(DataSetSqlXml){
//		$('#ExpressArea').dxDataGrid('instance').option(DataSetSqlXml.SEL_ELEMENT.SELECT_CLAUSE);
//		$('#ConditionArea')

		var selElements, paramElements, relElements,whereElements,etcElements;
		
		if(DataSetSqlXml.SEL_ELEMENT === ""){
			selElements = [];
		}else{
			selElements = toArray(DataSetSqlXml.SEL_ELEMENT.SELECT_CLAUSE);
		}
		if(DataSetSqlXml.PARAM_ELEMENT === ""){
			paramElements = [];
		}else{
			paramElements = toArray(DataSetSqlXml.PARAM_ELEMENT.PARAM);
			$.each(paramElements,function(_i,_param){
				parameterInformation[_param.PARAM_NM] = _param;
			});
		}
		if(DataSetSqlXml.REL_ELEMENT === ""){
			relElements = [];
		}else{
			relElements = toArray(DataSetSqlXml.REL_ELEMENT.JOIN_CLAUSE);
			$.each(relElements, function(_i,_e){
				_e.JOIN_SET_OWNER = 'SYSTEM';
				_e.DATA_BIND_YN = _e.DATA_BIND_YN == 'True' ? true:false;
				_e.PARAM_YN = _e.PARAM_YN == 'True' ? true:false;
			});
		}
		if(DataSetSqlXml.WHERE_ELEMENT === ""){
			whereElements = [];
		}else{
			whereElements = toArray(DataSetSqlXml.WHERE_ELEMENT.WHERE_CLAUSE);
		}
		if(DataSetSqlXml.ETC_ELEMENT === ""){
			etcElements = [];
		}else{
			etcElements = WISE.util.Object.toArray(DataSetSqlXml.ETC_ELEMENT);
			$.each(etcElements,function(_i,_etc){
				$('#logicArea').dxTextArea('instance').option('value',_etc.CHANGE_COND);
			});
		}
		$('#ExpressArea').dxDataGrid('instance').option('dataSource', selElements);
		$('#ConditionArea').dxDataGrid('instance').option('dataSource', whereElements);
		$('#RelationArea').dxDataGrid('instance').option('dataSource', relElements);
		
		var count = 1;
		$.each(selElements,function(_i,_sel){
			if(_sel.TYPE == 'MEA'){
				count = 1;
				$.each(selectedTables,function(_j,_tables){
					if(_tables.parentTable === _sel.TBL_NM){
						_tables.selectedCount++;
						count++;
					}
				});
				if(count ==1){
					var obj = {
						DimMea:'MEA',
						parentTable : _sel.TBL_NM,
						selectedCount : 1
					}
					selectedTables.push(obj);
				}/*else{
					_sel.selectedCount = count;
				}*/
			}
			else if(_sel.TYPE == 'DIM'){
				count = 1;
				$.each(selectedTables,function(_j,_tables){
					if(_tables.parentTable === _sel.TBL_NM){
						_tables.selectedCount++;
						count++;
					}
				});
				if(count ==1){
					var obj = {
						DimMea:'DIM',
						parentTable : _sel.TBL_NM,
						selectedCount : 1
					}
					selectedTables.push(obj);
				}
				/*else{
					_sel.selectedCount = count;
				}*/
			}
		});
		$.each(paramElements,function(_i,_param){
			if(_param.TYPE == 'MEA'){
				count = 1;
				$.each(selectedTables,function(_j,_tables){
					if(_tables.parentTable === _param.TBL_NM){
						_tables.selectedCount++;
						count++;
					}
				});
				if(count ==1){
					var obj = {
						DimMea:'MEA',
						parentTable : _param.TBL_NM,
						selectedCount : 1
					}
					selectedTables.push(obj);
				}
				/*else{
					_param.selectedCount = count;
				}*/
			}
			else if(_param.TYPE == 'DIM'){
				count = 1;
				$.each(selectedTables,function(_j,_tables){
					if(_tables.parentTable === _param.TBL_NM){
						_tables.selectedCount++;
						count++;
					}
				});
				if(count ==1){
					var obj = {
						DimMea:'DIM',
						parentTable : _param.TBL_NM,
						selectedCount : 1
					}
					selectedTables.push(obj);
				}/*else{
					_param.selectedCount = count;
				}*/
			}
		});


	};
	
	
	this.initParamInformation = function(_targetId){
		
		var html = "";
		html +="<div id='paramInfoSetting' style='height:30%;'></div>";
		html +="<div id='paramShowing'></div>";
		html +="<div id='paramTypeSetting' style='height:70%;width:95%;float:left;display:none'></div>";
		$('#'+_targetId).append(html);
		html = '';
		html += '<div id="nameArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
		html += '<div id="captionArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
		html += '<div id="dataTypeArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
		html += '<div id="paramTypeArea" style="width:100%;height:20%;float:left;padding:3px"></div>';
		html += '<div id="etcArea" style="width:100%;height:20%;float:left;padding:5px"></div>'
		$('#paramInfoSetting').append(html);
		html ='';
		html += '<div id="paramNameArea" style="width:50%;float:left;"></div>';
//		html += '<div id="warning" style="width:50%;float:left;padding-left:10px;">* 매개변수 명은 영문으로 설정하세요</div>';
		html += '<div id="warning" style="width:50%;float:left;padding-left:10px;"></div>';
		$('#nameArea').append(html);
		
		html = '';
		html += '<div id="paramCaptionArea" style="width:50%;float:left;"></div>';
		html += '<div id="dataSearchArea" style="width:50%;float:left;padding-left:10px;"><div id="dataSearch" style="padding: 8px 15px 9px 0;"></div></div>';
		$('#captionArea').append(html);
		
		html = '';
		html += '<div id="dataTypeListArea" style="width:50%;float:left;"></div>';
		html += '<div id="dataBindingArea" style="width:50%;float:left;padding-left:10px;"><div id="dataBind"  style="padding: 8px 15px 9px 0;"></div></div>';
		$('#dataTypeArea').append(html);
		
		html = '';
		html += '<div id="paramTypeListArea" style="width:50%;float:left;"></div>';
//		html += '<div id="paramDelArea" style="width:50%;float:left;padding-left:10px;"><div id="paramDelYN"  style="padding: 8px 15px 9px 0;"></div></div>';
		$('#paramTypeArea').append(html);
		
		html = '';
		html += '<div id="paramETCAreaA" style="width:45%;float:left;">';
		html += '<div id="orderArea" style="width:45%;float:left;"></div><div id="widthArea" style="width:45%;float:right;"></div>';
		html += '</div>';
		html += '<div id="paramETCAreaB" style="width:50%;float:left;margin-left:30px;">';
		html += '<div id="visibleArea" style="width:45%;float:left;"><div id="visibleYN" style="padding: 8px 15px 9px 0;"/></div>';
		html += '<div id="conditionArea" style="width:45%;float:left;"></div>';
		html += '</div>';
		$('#etcArea').append(html);
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 명</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="paramName"></div>';
		html += '</div>';
		html += '</div>';
		$('#paramNameArea').append(html);
		$('#paramName').dxTextBox({
			readOnly:true
		});
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 Caption</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="paramCaption"></div>';
		html += '</div>';
		html += '</div>';
		$('#paramCaptionArea').append(html);
		$('#paramCaption').dxTextBox();
		$('#dataSearch').dxCheckBox({text:'데이터 검색'});
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">데이터 유형</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="dataType"></div>';
		html += '</div>';
		html += '</div>';
		$('#dataTypeListArea').append(html);
		
		$('#dataType').dxSelectBox({
			dataSource:[{key:'STRING', caption:'String'},{key:'NUMERIC', caption:'Numeric'},{key:'DATETIME', caption:'DateTime'}],
			displayExpr:'caption',
			valueExpr:'key'
		});
		$('#dataBind').dxCheckBox({text:'데이터 바인딩',value: true});
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">매개변수 유형</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="paramType"></div>';
		html += '</div>';
		html += '</div>';
		$('#paramTypeListArea').append(html);
		
		$('#paramType').dxSelectBox({
			dataSource:commonParamType,
			displayExpr:'caption',
			valueExpr:'key',
			onSelectionChanged:function(_e){
				$('#paramShowing').empty();
				$('#paramTypeSetting').empty();
				$('#paramTypeSetting').css('display','none');
				if(_e.selectedItem != null){
					
					$.each(parameterInformation,function(_i,_paramInfo){
						if($('#paramName').dxTextBox('instance').option('value') === _paramInfo.PARAM_NM){
							self.paramTypeSetting(_e.selectedItem.key,parameterInformation[_paramInfo.UNI_NM]);
							return false;
						}
						
					});
					
				}
			}
		});
		
		
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">순서</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="orderInput"></div>';
		html += '</div>';
		html += '</div>';
		$('#orderArea').append(html);
		$('#orderInput').dxNumberBox({
			showSpinButtons: true
		});
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">넓이</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="widthInput"></div>';
		html += '</div>';
		html += '</div>';
		$('#widthArea').append(html);
		$('#widthInput').dxNumberBox({
			showSpinButtons: true
		});
		
		
		$('#visibleYN').dxCheckBox({text:'Visible'});
		html = '';
		html += '<div class="dx-field">';
		html += '<div class="dx-field-label">조건 명</div>';
		html += '<div class="dx-field-value">';
		html += '<div id="conditionInput"></div>';
		html += '</div>';
		html += '</div>';
		$('#conditionArea').append(html);
//		$('#conditionInput').dxTextBox({
//			text:''
//		});
		/* DOGFOOT ktkang 필터 NotIn 추가  20200716  */
		var commonOperationList = [{key:'In', caption:'In'},{key:'NotIn', caption:'NotIn'}];
		
		$('#conditionInput').dxSelectBox({
			dataSource:commonOperationList,
			displayExpr:'caption',
			valueExpr:'key'
		});
	};
	function setArea(targetId,selectedItemsType,itemattr){
		if(targetId == 'ExpressArea'){
			var expressDataSource = $('#ExpressArea').dxDataGrid('instance').option('dataSource');
			var relations = $('#RelationArea').dxDataGrid('instance').option('dataSource');
			var summaryType = '';
			$.each(allList,function(_i,_items){
				if(_items.COL_NM === itemattr.COL_NM && _items.parentTable === itemattr.parentTable){
					if(selectedItemsType.DimMea == 'MEA')
						summaryType = 'Sum'
					var obj = {
						AGG:summaryType,
						COL_NM : _items.COL_NM,
						COL_CAPTION : (_items.COL_CAPTION == "" ? _items.COL_NM : _items.COL_CAPTION),
						DATA_TYPE : _items.DATA_TYPE,
						TBL_NM: selectedItemsType.parentTable,
						TYPE : selectedItemsType.DimMea,
						COL_EXPRESS : '',
					};
					expressDataSource.push(obj);
					return false;
				}
			});
			var Constarr = new Array();
			Constarr = Constarr.concat(relations);
			var alreadyStored = false;
			$.each(expressDataSource,function(_i,_express){
				$.each(ConstraintList,function(_j,_const){
					if(_express.TBL_NM === _const.PK_TBL_NM){
						$.each(selectedTables,function(_k,_tables){
							if(_tables.parentTable === _const.FK_TBL_NM && _tables.DimMea == 'MEA'){
//								$.each(relations,function(_l,_rel){
								$.each(Constarr,function(_l,_rel){
									if(_rel.FK_TBL_NM === _const.FK_TBL_NM && 
											_rel.FK_COL_NM === _const.FK_COL_NM &&
											_rel.PK_TBL_NM === _const.PK_TBL_NM &&
											_rel.PK_COL_NM === _const.PK_COL_NM &&
											_rel.JOIN_TYPE === _const.JOIN_TYPE){
										alreadyStored = true;
										return false;
									}
								});
								if(alreadyStored == false){
									var Constobj = {
											CONST_NM : _const.CONST_NM,
											FK_TBL_NM : _const.FK_TBL_NM,
											FK_COL_NM : _const.FK_COL_NM,
											PK_TBL_NM : _const.PK_TBL_NM,
											PK_COL_NM : _const.PK_COL_NM,
											JOIN_TYPE : _const.JOIN_TYPE,
											JOIN_SET_OWNER : _const.JOIN_SET_OWNER,
										}
										Constarr.push(Constobj);
										return false;
								}
							}
						});
					}
				})
			});
			$('#RelationArea').dxDataGrid('instance').option('dataSource',Constarr);
			$('#ExpressArea').dxDataGrid('instance').option('dataSource',expressDataSource);
		}else if(targetId == 'ConditionArea'){
			var conditionDataSource = $('#ConditionArea').dxDataGrid('instance').option('dataSource');
			var relations = $('#RelationArea').dxDataGrid('instance').option('dataSource');
			var summaryType = '';
			$.each(allList,function(_i,_items){
				if(_items.COL_NM === itemattr.COL_NM && _items.parentTable === itemattr.parentTable){
//					if(selectedItemsType.DimMea == 'MEA')
//						summaryType = 'Sum'
							
					var obj = {
						COND_ID : 'A'+relationLength,
						COL_NM : _items.COL_NM,
						TBL_NM: selectedItemsType.parentTable,
						OPER : 'In',
						VALUES:'[All]',
						VALUES_CAPTION:'전체',
						DATA_BIND_YN:'true',
						AGG:summaryType,
						PARAM_YN:false,
//						PARAM_NM : '@'+_items.COL_NM,
						PARAM_NM :'',
						TYPE : selectedItemsType.DimMea,
						COL_CAPTION : (_items.COL_CAPTION == "" ? _items.COL_NM : _items.COL_CAPTION),
						DATA_TYPE : _items.DATA_TYPE,
						UNI_NM: '@'+_items.COL_NM,
						COL_EXPRESS : '',
					};
					
					var paramObj = {
						PARAM_NM : '@'+_items.COL_NM,
        				UNI_NM : '@'+_items.COL_NM,
            			PARAM_CAPTION : _items.COL_NM,
            			DATA_TYPE : 'STRING',
            			PARAM_TYPE : 'LIST',
            			ORDER :relationLength,
            			WIDTH : '300',
            			VISIBLE : 'NY',
            			OPER : 'In',
            			SEARCH_YN : 'N',
						BIND_YN : 'Y',
						DATASRC_TYPE : 'TBL',
						DATASRC : selectedItemsType.parentTable,
						KEY_VALUE_ITEM : _items.COL_NM,
	    				CAPTION_VALUE_ITEM : _items.COL_NM,
	    				HIDDEN_VALUE : '',
	    				SORT_TYPE : '',
	    				DEFAULT_VALUE : '[All]',
	    				DEFAULT_VALUE_USE_SQL_SCRIPT:'N',
	    				MULTI_SEL:'Y',
	    				ALL_YN :'Y',
	    				WHERE_CLAUSE : selectedItemsType.parentTable+"."+_items.COL_NM, 
	    				DEFAULT_VALUE_MAINTAIN:'N',
	    				SORT_VALUE_ITEM :'',
	    				wiseVariables: [],
	    				DS_ID:dsInfo.DS_ID,
	    				CAPTION_FORMAT : '',
	    				KEY_FORMAT:'',
	    				CAND_DEFAULT_TYPE:'',
	    				/*dogfoot 캘린더 기간 설정 shlim 20210427*/
	    				CAND_MAX_GAP:'',
	    				CAND_PERIOD_BASE : '',
	    				CAND_PERIOD_VALUE : '',
	    				EDIT_YN:'N',
	    				INPUT_EDIT_YN:'Y',
	    				LINE_BREAK:'N',/*dogfoot shlim 20210415*/
	    				RANGE_YN:'N',
	    				RANGE_VALUE:'',
	    				TYPE_CHANGE_YN:'Y',
					}
					
					parameterInformation['@'+_items.COL_NM] = paramObj; 
					
					conditionDataSource.push(obj);
					relationLength++;
					return false;
				}
			});
			var Constarr = new Array();
			Constarr = Constarr.concat(relations); 
			var alreadyStored = false;
			$.each(conditionDataSource,function(_i,_express){
				$.each(ConstraintList,function(_j,_const){
					if(_express.TBL_NM === _const.PK_TBL_NM){
						$.each(selectedTables,function(_k,_tables){
							if(_tables.parentTable === _const.FK_TBL_NM && _tables.DimMea == 'MEA'){
//								$.each(relations,function(_l,_rel){
								$.each(Constarr,function(_l,_rel){
									if(_rel.FK_TBL_NM === _const.FK_TBL_NM && 
											_rel.FK_COL_NM === _const.FK_COL_NM &&
											_rel.PK_TBL_NM === _const.PK_TBL_NM &&
											_rel.PK_COL_NM === _const.PK_COL_NM &&
											_rel.JOIN_TYPE === _const.JOIN_TYPE){
										alreadyStored = true;
										return false;
									}
								});
								if(alreadyStored == false){
									var Constobj = {
											CONST_NM : _const.CONST_NM,
											FK_TBL_NM : _const.FK_TBL_NM,
											FK_COL_NM : _const.FK_COL_NM,
											PK_TBL_NM : _const.PK_TBL_NM,
											PK_COL_NM : _const.PK_COL_NM,
											JOIN_TYPE : _const.JOIN_TYPE,
											JOIN_SET_OWNER : _const.JOIN_SET_OWNER,
										}
										Constarr.push(Constobj);
										return false;
								}
							}
						});
					}
				})
			});
			$('#RelationArea').dxDataGrid('instance').option('dataSource',Constarr);
			$('#ConditionArea').dxDataGrid('instance').option('dataSource',conditionDataSource);
		}
	}
	function newDataSetSave(){
		$('body').append('<div id="datasetSavePopup"/>');
		if(dsInfo != undefined){
			if(dataset_id =="" ){
				var html = "<div class=\"modal-inner\">\r\n" + 
				"                    <div class=\"modal-body\">\r\n" + 
				"                        <div class=\"row\">\r\n" + 
				"                            <div class=\"column\" style=\"width:100%; height: 450px;\">\r\n" + 
				"                                <div class=\"modal-article\">\r\n" + 
				"                                	 <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" + 
				"                                   	<div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
				"                                   		<span>데이터 집합 명</span>\r\n" + 
				"                                 	 	 </div>\r\n" + 
				"										 <div id=\"dataSetNm\"></div>\r\n" +
				"                              	     </div>\r\n" +
				"                                	 <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" + 
				"                                   	<div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
				"                                   		<span>폴더 명</span>\r\n" + 
				"                                 	 	 </div>\r\n" + 
				"										 <div style='text-align: right;'>"+								
				"								 			<div id=\"dataSetFolder\" style='float:left'></div>\r\n" +
				"								 			<div id=\"findFolder\"></div>\r\n" +
				"										 </div>"+
				"                              	     </div>\r\n" +
				"                                	 <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" + 
				"                                   	<div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
				"                                   		<span>설명</span>\r\n" + 
				"                                 	 	 </div>\r\n" + 
				"										 <div id=\"dataSetDesc\"></div>\r\n" +
				"                              	     </div>\r\n" +
				"                                </div>\r\n" + 
				"                            </div>\r\n" + 
				"                        </div>\r\n" + 
				"                    </div>\r\n" + 
				"                    <div class=\"modal-footer\">\r\n" + 
				"                        <div class=\"row center\">\r\n" + 
				"                            <a id=\"btn_dataset_check2\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
				"                            <a id=\"btn_dataset_cancel2\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
				"                        </div>\r\n" + 
				"                    </div>\r\n" + 
				"                </div>";
				$('#datasetSavePopup').dxPopup({
					title:'데이터 집합 저장',
					width:'500px',
					height:'650px',
					visible:true,
					closeOnOutsideClick: false,
					showCloseButton: false,
				    contentTemplate: function() {
		                return html;
		            },
		            onContentReady:function(){
		            	$('#dataSetNm').dxTextBox();
		            	$('#dataSetFolder').dxTextBox({
		            		readOnly:true,
		            		'value': "",
		            		'text': "",
		            		'fld_id':"",
		            		'width':'91%'
		            	});
		            	$('#dataSetDesc').dxTextArea({
		            		value: ""
		            	});
		            	$('#findFolder').dxButton({
		            		icon:'search',
		            		onClick:function(){
		            			$('body').append("<div id='selectFolder'></div>");
		            			var folderhtml = "<div class=\"modal-body\" style='height:87%'>\r\n" + 
		    					"                        <div class=\"row\" style='height:100%'>\r\n" + 
		    					"                            <div class=\"column\" style='width:100%'>\r\n" + 
		    					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
		    					"                                   <div class=\"modal-tit\">\r\n" + 
		    					"                                   <span>폴더 목록</span>\r\n" + 
		    					"                                   </div>\r\n" + 
		    					"									<div id=\"folder_tree\" />\r\n" + 
		    					"                                </div>\r\n" +
		    					"                            </div>\r\n" + 
		    					"                        </div>\r\n" + //row 끝
		    					"                    </div>\r\n" + //modal-body 끝
		    					"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
		    					"                        <div class=\"row center\">\r\n" + 
		    					"                            <a id=\"folder_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
		    					"                            <a id=\"folder_cancel\" class=\"btn neutral close\" href=\"#\">취소</a>\r\n" + 
		    					"                        </div>\r\n" + 
		    					"                    </div>\r\n" + 
		    					"                </div>";
		            			$('#selectFolder').dxPopup({
		            				title:'폴더 선택',
		            				width:'500px',
		            				height:'700px',
		            				visible:true,
		            				showCloseButton: false,
		            				contentTemplate: function() {
		            					return folderhtml;
		            		        },
		            		        onInitialized:function(_e){
				            			$.each(_e.component.option('dataSource'),function(_i,_items){
				            				_items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
				            			});
				            		},
		            				onContentReady:function(){
		        						$.ajax({
		        				        	method : 'POST',
		        				            url: WISE.Constants.context + '/report/getDataSetFolderList.do',
		        				            dataType: "json",
		        				            data:{
		        								userId:userJsonObject.userId
		        							},
		        				            async:false,
		        				            success: function(result) {
		        				            	var selectFLDNm="",selectFLDId="";
		        				            	var result = result.dataSetFolders
		        				            	$('#folder_tree').dxTreeView({
		        				            		dataSource:result,
		        				            		dataStructure:'plain',
		        				            		keyExpr: "FLD_ID",
		        				            		parentIdExpr: "PARENT_FLD_ID",
		        				            		displayExpr: "FLD_NM",
													// mksong 2019.12.20 보고서 검색 추가 dogfoot
		        				            		searchEnabled: true,
		        									searchMode : "contains",
		        									searchTimeout:undefined,
		        									searchValue:"",
		        									// 2019.12.20 mksong nodata 텍스트 수정 dogfoot
		        									noDataText:"조회된 보고서가 없습니다.",
		        				            		height:"460",
		        				            		showCloseButton: false,
		        				            		onInitialized: function(_e) {
		        										$.each(_e.component.option('dataSource'),function(_i,_items){
	        				            					_items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
		        				            			});
		        										$(window).resize(function() {
		        											_e.component.option('height', $('.preferences-cont').height() - 90);
		        										});
		        									},
		        				            		onItemClick:function(_e){
		        				            			selectFLDNm = _e.itemData['FLD_NM'];
		        				            			selectFLDId = _e.itemData['FLD_ID'];
		        				            		},
		        				            		
		        				            	});
		        				            	$('#folder_ok').dxButton({
		        				            		type:'default',
		        				            		text:'확인',
		        				            		onClick:function(){
		        				            			if(selectFLDNm != "" && selectFLDId != ""){
		        				            				$('#dataSetFolder').dxTextBox('instance').option('value',selectFLDNm);
		        				            				$('#dataSetFolder').dxTextBox('instance').option('fld_id',selectFLDId);
		        				            				$('#selectFolder').dxPopup('instance').hide();
		        				            				$('#selectFolder').remove();
		        				            			}
		        				            		}
		        		            			});
		        		            			$('#folder_cancel').dxButton({
		        		            				type:'danger',
		        		                    		text:'취소',
		        		                    		onClick:function(){
		    				            				$('#selectFolder').dxPopup('instance').hide();
		    				            				$('#selectFolder').remove();
		        				            		}
		        		            			});
		        		            			gProgressbar.hide();
		        				            }
		        				        });
		            				}
		            			});
		            		}
		            	});
		            	$('#btn_dataset_check2').dxButton({
		            		onClick:function(){

		            			var DatasetNm = $('#dataSetNm').dxTextBox('instance').option('value');
		            			var dataSetFolderId = $('#dataSetFolder').dxTextBox('instance').option('fld_id');
		            			var dataSetDesc = $('#dataSetDesc').dxTextArea('instance').option('value');
		            			var dataSetQuery = "";
		            			var whereItems = new Array();
		        				
		        				$.each(parameterInformation,function (_key,_val){
		        					whereItems.push(_val);
		        				});
		        				$.each(whereItems,function(_i,_where){
									$.each($('#ConditionArea').dxDataGrid('instance').option('dataSource'),function(_j,_condition){
										if(_condition.UNI_NM === _where.UNI_NM){
											_where.COND_ID = _condition.COND_ID;
											_where.AGG = _condition.AGG;
											_where.TYPE = _condition.TYPE;
											_where.PARAM_YN = _condition.PARAM_YN;
										}
									});
								});
		        				
		        				var param = {
		        					dsId: dsInfo.DS_ID,
		        					selArray:$('#ExpressArea').dxDataGrid('instance').option('dataSource'),
		        					whereArray :whereItems,
		        					relArray:$('#RelationArea').dxDataGrid('instance').option('dataSource'),
		        					etcArray:[{
		        						STRATIFIED:"N",
		        						DISTINCT:"N",
		        						CHANGE_COND:$('#logicArea').dxTextArea('instance').option('value'),
		        			        	SEL_COND : "",//empty
		        			        	SEL_NUMERIC : 0//0
		        					}],
		    						execType:"DS"
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
	            						execType:'DS',
	            						statics : statics
	            					},
	            					success:function(data){
	            						dataSetQuery = data;
	            					}
	            				});
		            			if(DatasetNm == "" && dataSetFolderId == ""){
		            				WISE.alert('데이터 집합 이름 또는 폴더를 입력하세요');
		            			}else if(dataSetQuery == 'REL ERROR'){
		            				WISE.alert('데이터 집합의 연결 정보가 없습니다');
		            			}else{
		            				var param = {
	            						datasetId:0,
		            					dataSetNM : DatasetNm,
	    	            				fldId : dataSetFolderId,
		            					ds_id : dsInfo.DS_ID,
	    	            				dataSrcType : dsInfo.dataSrc_Type,
	    	            				dataSetType : dsInfo.dataSet_Type,
	    	            				SelArea : $('#ExpressArea').dxDataGrid('instance').option('dataSource'),
	    	            				CondArea : $('#ConditionArea').dxDataGrid('instance').option('dataSource'),
	    	            				ParamArea : parameterInformation,
	    	            				RelArea : $('#RelationArea').dxDataGrid('instance').option('dataSource'),
	    	            				EtcArea : {
	    	        						STRATIFIED:"N",
	    	        						DISTINCT:"N",
	    	        						CHANGE_COND:$('#logicArea').dxTextArea('instance').option('value'),
	    	        			        	SEL_COND : "",//empty
	    	        			        	SEL_NUMERIC : 0//0
	    	        					},
	    	            				dataSetQuery : dataSetQuery,
	    	            				dataSetDesc : dataSetDesc,
	    	            				userNo:userJsonObject.userNo,
	    	            			};
		            				var jsonParam = {};
			            			jsonParam['JSON_DATASET'] = JSON.stringify(param);

		            				$.ajax({
		            					method : 'POST',
				                        dataType: "json",
				                        data:jsonParam,
		            					url : "./saveDataSet.do",
		            					async: false,
		            					beforeSend: function() {
		            						gProgressbar.show();
		            					},
		            					success: function(_data){
		            						gProgressbar.hide();
		            						if(_data.code === 200){
		            							$('#datasetSavePopup').dxPopup('instance').hide();
		            							$('#datasetSavePopup').remove();
		            							var options = {
		        										buttons: {
		        											confirm: {
		        												id: 'confirm',
		        												className: 'blue',
		        												text: '확인',
		        												action: function() {
			        												//2020.01.21 mksong 경고창 hide 수정 dogfoot
		        													$AlertPopup.hide();
		        													
		        													initDataSetList();
		        													$('#dataSetAnalysisArea').empty();
		        													$('#dataSetAnalysisArea').append('<div id="queryopen"></div>');
		        													return false;
		        												}
		        											}
		        										}
		        								};
		        								//2020.01.21 mksong 경고창 타입 지정 dogfoot
		            							WISE.confirm('데이터 집합을 생성하였습니다.',options);
		            						}else{
		            							//2020.01.21 mksong 경고창 타입 지정 dogfoot
		            							WISE.alert('데이터 집합을 생성하는데 실패했습니다.<br>관리자에게 문의하세요','error');
		            							$('#datasetSavePopup').dxPopup('instance').hide();
		            							$('#datasetSavePopup').remove();
		            						}
		            					}
		            				});
		            				
		            			}
		            			
		            		}
		            	})
		            	$('#btn_dataset_cancel2').dxButton({
		            		onClick:function(){
		            			$('#datasetSavePopup').dxPopup('instance').hide();
								$('#datasetSavePopup').remove();
		            		}
		            	})
		            }
				});
			}else{

				var dataSetQuery = "";
    			var whereItems = new Array();
				$.each(parameterInformation,function (_key,_val){
					whereItems.push(_val);
				});
				$.each(whereItems,function(_i,_where){
					$.each($('#ConditionArea').dxDataGrid('instance').option('dataSource'),function(_j,_condition){
						if(_condition.UNI_NM === _where.UNI_NM){
							_where.COND_ID = _condition.COND_ID;
							_where.AGG = _condition.AGG;
							_where.TYPE = _condition.TYPE;
							_where.PARAM_YN = _condition.PARAM_YN;
						}
					});
				});
				
				var param = {
					dsId: dsInfo.DS_ID,
					selArray:$('#ExpressArea').dxDataGrid('instance').option('dataSource'),
					whereArray :whereItems,
					relArray:$('#RelationArea').dxDataGrid('instance').option('dataSource'),
					etcArray:[{
						STRATIFIED:"N",
						DISTINCT:"N",
						CHANGE_COND:$('#logicArea').dxTextArea('instance').option('value'),
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
						execType:'DS',
						statics : statics
					},
					success:function(data){
						dataSetQuery = data;
					}
				});
				var param = {
					datasetId:datasetInfo.DATASET_ID,
					dataSetNM : datasetInfo.FLD_NM,
    				fldId : datasetInfo.PARENT_FLD_ID,
					ds_id : dsInfo.DS_ID,
    				dataSrcType : dsInfo.dataSrc_Type,
    				dataSetType : dsInfo.dataSet_Type,
    				SelArea : $('#ExpressArea').dxDataGrid('instance').option('dataSource'),
    				CondArea : $('#ConditionArea').dxDataGrid('instance').option('dataSource'),
    				ParamArea : parameterInformation,
    				RelArea : $('#RelationArea').dxDataGrid('instance').option('dataSource'),
    				EtcArea : {
						STRATIFIED:"N",
						DISTINCT:"N",
						CHANGE_COND:$('#logicArea').dxTextArea('instance').option('value'),
			        	SEL_COND : "",//empty
			        	SEL_NUMERIC : 0//0
					},
    				dataSetQuery : dataSetQuery,
    				dataSetDesc : datasetInfo.DATASET_DESC,
    				userNo:userJsonObject.userNo,
    			};
				var jsonParam = {};
    			jsonParam['JSON_DATASET'] = JSON.stringify(param);

				$.ajax({
					method : 'POST',
                    dataType: "json",
                    data:jsonParam,
					url : "./saveDataSet.do",
					async: false,
					beforeSend: function() {
						gProgressbar.show();
					},
					success: function(_data){
						gProgressbar.hide();
						if(_data.code === 200){
							var options = {
								buttons: {
									confirm: {
										id: 'confirm',
										className: 'blue',
										text: '확인',
										action: function() { 
											//2020.01.21 mksong 경고창 hide 수정 dogfoot
											$AlertPopup.hide();
											
											initDataSetList();
											$('#dataSetAnalysisArea').empty();
											$('#dataSetAnalysisArea').append('<div id="queryopen"></div>');
											return false;
										}
									}
								}
							};
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.confirm('데이터 집합을 변경하였습니다.',options);
						}else{
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert('데이터 집합을 변경하는데 실패했습니다.<br>관리자에게 문의하세요','error');
						}
					}
				});
			}
		}
	};
	
	function newDataSetSaveAs(){
		$('body').append('<div id="datasetSavePopup"/>');
		if(dsInfo != undefined){
			var html = "<div class=\"modal-inner\">\r\n" + 
			"                    <div class=\"modal-body\">\r\n" + 
			"                        <div class=\"row\">\r\n" + 
			"                            <div class=\"column\" style=\"width:100%; height: 450px;\">\r\n" + 
			"                                <div class=\"modal-article\">\r\n" + 
			"                                	 <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" + 
			"                                   	<div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
			"                                   		<span>데이터 집합 명</span>\r\n" + 
			"                                 	 	 </div>\r\n" + 
			"										 <div id=\"dataSetNm\"></div>\r\n" +
			"                              	     </div>\r\n" +
			"                                	 <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" + 
			"                                   	<div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
			"                                   		<span>폴더 명</span>\r\n" + 
			"                                 	 	 </div>\r\n" + 
			"										 <div style='text-align: right;'>"+								
			"								 			<div id=\"dataSetFolder\" style='float:left'></div>\r\n" +
			"								 			<div id=\"findFolder\"></div>\r\n" +
			"										 </div>"+
			"                              	     </div>\r\n" +
			"                                	 <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" + 
			"                                   	<div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
			"                                   		<span>설명</span>\r\n" + 
			"                                 	 	 </div>\r\n" + 
			"										 <div id=\"dataSetDesc\"></div>\r\n" +
			"                              	     </div>\r\n" +
			"                                </div>\r\n" + 
			"                            </div>\r\n" + 
			"                        </div>\r\n" + 
			"                    </div>\r\n" + 
			"                    <div class=\"modal-footer\">\r\n" + 
			"                        <div class=\"row center\">\r\n" + 
			"                            <a id=\"btn_dataset_check2\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" + 
			"                            <a id=\"btn_dataset_cancel2\" href=\"#\" class=\"btn neutral close\">취소</a>\r\n" + 
			"                        </div>\r\n" + 
			"                    </div>\r\n" + 
			"                </div>";
			$('#datasetSavePopup').dxPopup({
				title:'보고서 저장',
				width:'500px',
				height:'650px',
				visible:true,
				closeOnOutsideClick: false,
				showCloseButton: false,
			    contentTemplate: function() {
	                return html;
	            },
	            onContentReady:function(){
	            	$('#dataSetNm').dxTextBox();
	            	$('#dataSetFolder').dxTextBox({
	            		readOnly:true,
	            		'value': "",
	            		'text': "",
	            		'fld_id':"",
	            		'width':'91%'
	            	});
	            	$('#dataSetDesc').dxTextArea({
	            		value: ""
	            	});
	            	$('#findFolder').dxButton({
	            		icon:'search',
	            		onClick:function(){
	            			$('body').append("<div id='selectFolder'></div>");
	            			var folderhtml = "<div class=\"modal-body\" style='height:87%'>\r\n" + 
	    					"                        <div class=\"row\" style='height:100%'>\r\n" + 
	    					"                            <div class=\"column\" style='width:100%'>\r\n" + 
	    					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
	    					"                                   <div class=\"modal-tit\">\r\n" + 
	    					"                                   <span>폴더 목록</span>\r\n" + 
	    					"                                   </div>\r\n" + 
	    					"									<div id=\"folder_tree\" />\r\n" + 
	    					"                                </div>\r\n" +
	    					"                            </div>\r\n" + 
	    					"                        </div>\r\n" + //row 끝
	    					"                    </div>\r\n" + //modal-body 끝
	    					"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
	    					"                        <div class=\"row center\">\r\n" + 
	    					"                            <a id=\"folder_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
	    					"                            <a id=\"folder_cancel\" class=\"btn neutral close\" href=\"#\">취소</a>\r\n" + 
	    					"                        </div>\r\n" + 
	    					"                    </div>\r\n" + 
	    					"                </div>";
	            			$('#selectFolder').dxPopup({
	            				title:'폴더 선택',
	            				width:'500px',
	            				height:'700px',
	            				visible:true,
	            				showCloseButton: false,
	            				contentTemplate: function() {
	            					return folderhtml;
	            		        },
	            		        onInitialized:function(_e){
			            			$.each(_e.component.option('dataSource'),function(_i,_items){
			            				_items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
			            			});
			            		},
	            				onContentReady:function(){
	        						$.ajax({
	        				        	method : 'POST',
	        				            url: WISE.Constants.context + '/report/getDataSetFolderList.do',
	        				            dataType: "json",
	        				            data:{
	        								userId:userJsonObject.userId
	        							},
	        				            async:false,
	        				            success: function(result) {
	        				            	var selectFLDNm="",selectFLDId="";
	        				            	var result = result.dataSetFolders
	        				            	$('#folder_tree').dxTreeView({
	        				            		dataSource:result,
	        				            		dataStructure:'plain',
	        				            		keyExpr: "FLD_ID",
	        				            		parentIdExpr: "PARENT_FLD_ID",
	        				            		displayExpr: "FLD_NM",
												// mksong 2019.12.20 보고서 검색 추가 dogfoot
	        				            		searchEnabled: true,
	        									searchMode : "contains",
	        									searchTimeout:undefined,
	        									searchValue:"",
	        									// 2019.12.20 mksong nodata 텍스트 수정 dogfoot
	        									noDataText:"조회된 보고서가 없습니다.",
	        				            		height:"460",
	        				            		showCloseButton: false,
	        				            		onInitialized: function(_e) {
	        										$.each(_e.component.option('dataSource'),function(_i,_items){
        				            					_items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
	        				            			});
	        										$(window).resize(function() {
	        											_e.component.option('height', $('.preferences-cont').height() - 90);
	        										});
	        									},
	        				            		onItemClick:function(_e){
	        				            			selectFLDNm = _e.itemData['FLD_NM'];
	        				            			selectFLDId = _e.itemData['FLD_ID'];
	        				            		},
	        				            		
	        				            	});
	        				            	$('#folder_ok').dxButton({
	        				            		type:'default',
	        				            		text:'확인',
	        				            		onClick:function(){
	        				            			if(selectFLDNm != "" && selectFLDId != ""){
	        				            				$('#dataSetFolder').dxTextBox('instance').option('value',selectFLDNm);
	        				            				$('#dataSetFolder').dxTextBox('instance').option('fld_id',selectFLDId);
	        				            				$('#selectFolder').dxPopup('instance').hide();
	        				            				$('#selectFolder').remove();
	        				            			}
	        				            		}
	        		            			});
	        		            			$('#folder_cancel').dxButton({
	        		            				type:'danger',
	        		                    		text:'취소',
	        		                    		onClick:function(){
	    				            				$('#selectFolder').dxPopup('instance').hide();
	    				            				$('#selectFolder').remove();
	        				            		}
	        		            			});
	        		            			gProgressbar.hide();
	        				            }
	        				        });
	            				}
	            			});
	            		}
	            	});
	            	$('#btn_dataset_check2').dxButton({
	            		onClick:function(){

	            			var DatasetNm = $('#dataSetNm').dxTextBox('instance').option('value');
	            			var dataSetFolderId = $('#dataSetFolder').dxTextBox('instance').option('fld_id');
	            			var dataSetDesc = $('#dataSetDesc').dxTextArea('instance').option('value');
	            			var dataSetQuery = "";
	            			var whereItems = new Array();
	        				
	        				$.each(parameterInformation,function (_key,_val){
	        					whereItems.push(_val);
	        				});
	        				$.each(whereItems,function(_i,_where){
								$.each($('#ConditionArea').dxDataGrid('instance').option('dataSource'),function(_j,_condition){
									if(_condition.UNI_NM === _where.UNI_NM){
										_where.AGG = _condition.AGG;
										_where.TYPE = _condition.TYPE;
										_where.PARAM_YN = _condition.PARAM_YN;
									}
								});
							});
	        				
	        				var param = {
	        					dsId: dsInfo.DS_ID,
	        					selArray:$('#ExpressArea').dxDataGrid('instance').option('dataSource'),
	        					whereArray :whereItems,
	        					relArray:$('#RelationArea').dxDataGrid('instance').option('dataSource'),
	    						execType:"DS"
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
            						execType:'DS',
            						statics : statics
            					},
            					success:function(data){
            						dataSetQuery = data;
            					}
            				});
	            			if(DatasetNm == "" && dataSetFolderId == ""){
	            				WISE.alert('데이터 집합 이름 또는 폴더를 입력하세요');
	            			}else if(dataSetQuery == 'REL ERROR'){
	            				WISE.alert('데이터 집합의 연결 정보가 없습니다');
	            			}else{
	            				var param = {
            						datasetId:0,
	            					dataSetNM : DatasetNm,
    	            				fldId : dataSetFolderId,
	            					ds_id : dsInfo.DS_ID,
    	            				dataSrcType : dsInfo.dataSrc_Type,
    	            				dataSetType : dsInfo.dataSet_Type,
    	            				SelArea : $('#ExpressArea').dxDataGrid('instance').option('dataSource'),
    	            				CondArea : $('#ConditionArea').dxDataGrid('instance').option('dataSource'),
    	            				ParamArea : parameterInformation,
    	            				RelArea : $('#RelationArea').dxDataGrid('instance').option('dataSource'),
    	            				EtcArea : {
    	        						STRATIFIED:"N",
    	        						DISTINCT:"N",
    	        						CHANGE_COND:$('#logicArea').dxTextArea('instance').option('value'),
    	        			        	SEL_COND : "",//empty
    	        			        	SEL_NUMERIC : 0//0
    	        					},
    	            				dataSetQuery : dataSetQuery,
    	            				dataSetDesc : dataSetDesc,
    	            				userNo:userJsonObject.userNo,
    	            			};
	            				var jsonParam = {};
		            			jsonParam['JSON_DATASET'] = JSON.stringify(param);

	            				$.ajax({
	            					method : 'POST',
			                        dataType: "json",
			                        data:jsonParam,
	            					url : "./saveDataSet.do",
	            					async: false,
	            					beforeSend: function() {
	            						gProgressbar.show();
	            					},
	            					success: function(_data){
	            						gProgressbar.hide();
	            						if(_data.code === 200){
	            							$('#datasetSavePopup').dxPopup('instance').hide();
	            							$('#datasetSavePopup').remove();
	            							var options = {
	        										buttons: {
	        											confirm: {
	        												id: 'confirm',
	        												className: 'blue',
	        												text: '확인',
	        												action: function() { 
		        												//2020.01.21 mksong 경고창 hide 수정 dogfoot
	        													$AlertPopup.hide();
	        													
	        													initDataSetList();
	        													$('#dataSetAnalysisArea').empty();
	        													$('#dataSetAnalysisArea').append('<div id="queryopen"></div>');
	        													return false;
	        												}
	        											}
	        										}
	        								};
	        								//2020.01.21 mksong 경고창 타입 지정 dogfoot
	            							WISE.confirm('데이터 집합을 생성하였습니다.',options);
	            						}else{
	            							//2020.01.21 mksong 경고창 타입 지정 dogfoot
	            							WISE.alert('데이터 집합을 생성하는데 실패했습니다.<br>관리자에게 문의하세요','error');
	            							$('#datasetSavePopup').dxPopup('instance').hide();
	            							$('#datasetSavePopup').remove();
	            						}
	            					}
	            				});
	            				
	            			}
	            			
	            		}
	            	})
	            	$('#btn_dataset_cancel2').dxButton({
	            		onClick:function(){
	            			$('#datasetSavePopup').dxPopup('instance').hide();
							$('#datasetSavePopup').remove();
	            		}
	            	})
	            }
			});
		}
	};
	
	function deleteDataSet(){

		if(selectedTargetDataSet.DATASET_ID != undefined){
			// 2020.01.16 mksong confirm 기능 추가 dogfoot
			var options = {
				buttons: {
					confirm: {
						id: 'confirm',
						className: 'blue',
						text: '확인',
						action: function() { 
							$AlertPopup.hide();
							$.ajax({
            					method : 'POST',
		                        dataType: "json",
		                        data:{
		                        	'dataSetId':selectedTargetDataSet.DATASET_ID
		                        },
            					url : "./deleteDataSet.do",
            					async: false,
            					beforeSend: function() {
            						gProgressbar.show();
            					},
            					success: function(_data){
            						gProgressbar.hide();
            						if(_data.code == 200){
            							initDataSetList();
            							$('#dataSetAnalysisArea').empty();
            							$('#dataSetAnalysisArea').append('<div id="queryopen"></div>');
            						}else{
            							//2020.01.21 mksong 경고창 타입 지정 dogfoot
            							WISE.alert('데이터 집합 삭제에 실패했습니다<br>관리자에게 문의하세요.','error');
            						}
            					}
							});
							return false;
						}
					},
					cancel: {
						id: 'cancel',
						className: 'negative',
						text: '취소',
						action: function() { $AlertPopup.hide(); }
					}
				}
			};
			WISE.confirm('데이터 집합<br>'+selectedTargetDataSet.FLD_NM+"<br>을(를) 삭제하시겠습니까?",options);
			// 2020.01.16 mksong confirm 기능 추가 수정 끝 dogfoot
		}
	}
	
	function editDatasetFilter(){
		$('body').append('<div id="editFilterPopup"></div>');
		var paramArray = [];
		
		$.each(parameterInformation,function(_i,_items){
			paramArray.push(_items);
		});
		
		var html = "<div class=\"modal-body\" style='height:93%'>\r\n" + 
		"                        <div class=\"row\" style='height:100%'>\r\n" + 
		"                            <div class=\"column\" style='width:30%'>\r\n" + 
		"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
		"                                   <div class=\"modal-tit\">\r\n" + 
		"                                   <span>매개변수 목록</span>\r\n" + 
		"                                   </div>\r\n" + 
		"									<div id=\"paramItemListArea\" />\r\n" + 
		"                                </div>\r\n" +
//		"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
		"                            </div>\r\n" + 
		"                            <div class=\"column\" style=\"width:70%\">\r\n" +
		"                            	<div class=\"row horizen\">\r\n" + 
		" 		                            <div class=\"column\" style=\"padding-bottom:0px;\">\r\n" +
		'										<div class="modal-article">' +
		"											<div id=\"param_area\" class=\"param_area modal-tit\">\r\n" + 
		"   		                                     <span>매개변수 정보</span>" + 
		"       	                	            </div>\r\n" +
		"											<div id=\"paramItemDescArea\"></div>\r\n" +
		"       	                	        </div>\r\n" +
		" 									</div>" + //column 끝
	    " 								 </div>" + //row horizon 끝
		"                            </div>\r\n" +  //column 끝 
		"                        </div>\r\n" + //row 끝
		"                    </div>\r\n" + //modal-body 끝
		"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
		"                        <div class=\"row center\">\r\n" + 
		"                            <a id=\"paramBtnOK\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
		"                            <a id=\"paramBtnCancel\" class=\"btn neutral close\" href=\"#\">취소</a>\r\n" + 
		"                        </div>\r\n" + 
		"                    </div>\r\n" + 
		"                </div>";
		
		$('#editFilterPopup').dxPopup({
			visible:true,
			title: "매개변수 편집",
			width: 1250,
			height: 900,
			contentTemplate:function() {
                return html;
            },
            onShown:function(){
            	var selectedItem;
            	/**
            	 * 매개변수 정보 초기화
            	 **/
            	self.initParamInformation("paramItemDescArea");
            	$('#paramItemListArea').dxDataGrid({
            		dataSource:paramArray,
            		columns:[
            			{
    			            dataField: "PARAM_NM",
    			            caption:"매개변수 명",
    			            alignment:"center",
            			},
            			{
    			            dataField: "PARAM_CAPTION",
    			            caption:"매개변수 캡션",
    			            alignment:"center",
            			},
            			{
    			            dataField: "ORDER",
    			            caption:"순서",
    			            alignment:"center",
            			},
            		],
                    selection: {
                        mode: "single"
                    },
                    onSelectionChanged:function(_e){
            			if(typeof selectedItem != 'undefined'){
            				selectedItem.PARAM_NM = $('#paramName').dxTextBox('instance').option('value');
            				selectedItem.UNI_NM = $('#paramName').dxTextBox('instance').option('value');
                			selectedItem.PARAM_CAPTION = $('#paramCaption').dxTextBox('instance').option('value');
                			selectedItem.DATA_TYPE = $('#dataType').dxSelectBox('instance').option('value');
                			selectedItem.PARAM_TYPE = $('#paramType').dxSelectBox('instance').option('value');
                			
                			selectedItem.ORDER = $('#orderInput').dxNumberBox('instance').option('value');
                			selectedItem.WIDTH = $('#widthInput').dxNumberBox('instance').option('value');
                			selectedItem.VISIBLE = $('#visibleYN').dxCheckBox('instance').option('value') ? 'Y':'N';
                			/* DOGFOOT ktkang 필터 NotIn 추가  20200716  */
                			selectedItem.OPER = $('#conditionInput').dxSelectBox('instance').option('value');
                			
                			var paramType = $('#paramType').dxSelectBox('instance').option('value')
                			if(paramType == 'LIST'){
                				selectedItem.DATASRC_TYPE = $('#dataOriginType').dxSelectBox('instance').option('value');
                				selectedItem.SEARCH_YN = $('#dataSearch').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.BIND_YN = $('#dataBind').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = $('#orderByButton').dxSelectBox('instance').option('value');
//                				selectedItem.DEFAULT_VALUE = $('#UseSqlScriptYN').dxCheckBox('instance').option('value') ? selectedItem.DEFAULT_VALUE :$('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = $('#MultiSelectYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				if(selectedItem.DATASRC_TYPE == 'QUERY'){
                					$.each(parameterInformation,function(_i,_e){
                						var paramName = _e.PARAM_NM;
                						if((selectedItem.DATASRC).indexOf(paramName) > -1){
                							selectedItem.wiseVariables.push(paramName);
                							selectedItem.wiseVariables.push(_e.WHERE_CLAUSE);
                						}
                					});
                				}

                			}else if(paramType == 'INPUT'){
                				selectedItem.DATASRC_TYPE = '';
                				selectedItem.SEARCH_YN = 'N';
                				selectedItem.BIND_YN = 'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = 'ASC';
                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = $('#MultiSelectYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                			}else if (paramType == 'CAND'){
                				if($('#candDefaultType').dxSelectBox('instance').option('value')== 'QUERY'){
                					selectedItem.CAND_DEFAULT_TYPE = 'QUERY';
                					selectedItem.CAND_PERIOD_BASE = "";
                					selectedItem.CAND_PERIOD_VALUE = "";
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					selectedItem.DEFAULT_VALUE = $('#DefaultValueQuery').dxTextArea('instance').option('value');
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					selectedItem.SORT_VALUE_ITEM = '';
                				}else{
                					selectedItem.CAND_DEFAULT_TYPE = 'NOW';
                					selectedItem.CAND_PERIOD_BASE = $("#DefaultValueNow").dxSelectBox('instance').option('value');
                					selectedItem.CAND_PERIOD_VALUE = $("#candMoveValue").dxNumberBox('instance').option('value');
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					selectedItem.DEFAULT_VALUE = "";
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					selectedItem.SORT_VALUE_ITEM = '';
                				}
                				selectedItem.wiseVariables = [];
                			}else if(paramType == 'BETWEEN_CAND'){
                				if($('#candDefaultType').dxSelectBox('instance').option('value')== 'QUERY'){
                					var fromValue = Number($("#DefaultValueQueryFrom").dxTextArea('instance').option('value'));
                					var toValue = Number($("#DefaultValueQueryTo").dxTextArea('instance').option('value'));
                					selectedItem.CAND_DEFAULT_TYPE = 'QUERY';
                					selectedItem.CAND_PERIOD_BASE = "";
                					selectedItem.CAND_PERIOD_VALUE = "";
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					selectedItem.DEFAULT_VALUE = fromValue + ','+toValue;//('#DefaultValue').dxTextArea('instance').option('value');
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT=$('#defaultQuery').dxCheckBox('instance').option('value')? 'Y':'N';
                					selectedItem.SORT_VALUE_ITEM = '';
                					
                				}else{
                					var fromPeriod = $("#DefaultValueNowFrom").dxSelectBox('instance').option('value');
                					var toPeriod = $("#DefaultValueNowTo").dxSelectBox('instance').option('value');
                					var fromValue = Number($("#candMoveValueFrom").dxNumberBox('instance').option('value'));
                					var toValue = Number($("#candMoveValueTo").dxNumberBox('instance').option('value'));
                					selectedItem.CAND_DEFAULT_TYPE = 'NOW';
                					selectedItem.CAND_PERIOD_BASE = fromPeriod + ',' + toPeriod;
                					selectedItem.CAND_PERIOD_VALUE = fromValue + ',' + toValue;
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					
                					var ToDate = new Date();
                					
                					if(toPeriod == 'YEAR'){
                						ToDate.setYear(ToDate.getFullYear()+toValue);
                					}else if(toPeriod == 'MONTH'){
                						ToDate.setMonth(ToDate.getMonth()+toValue);
                					}else{
                						ToDate.setDate(ToDate.getDate()+toValue);
                					}
                					
                					var FromDate = new Date(ToDate);
                					if(fromPeriod == 'YEAR'){
                						FromDate.setYear(FromDate.getFullYear()+fromValue);
                					}else if(fromPeriod == 'MONTH'){
                						FromDate.setMonth(FromDate.getMonth()+fromValue)
                					}else{
                						FromDate.setDate(FromDate.getDate()+fromValue);
                					}
                					
                					selectedItem.DEFAULT_VALUE = self.getFormatDate(FromDate)+","+ self.getFormatDate(ToDate);
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					selectedItem.SORT_VALUE_ITEM = '';
                					selectedItem.wiseVariables = [];
                				}
                			}
                			else if(paramType == 'BETWEEN_LIST'){
                				var fromValue = $("#DefaultValueFrom").dxTextArea('instance').option('value');
            					var toValue = $("#DefaultValueTo").dxTextArea('instance').option('value');
            					
                				selectedItem.DATASRC_TYPE = $('#dataOriginType').dxSelectBox('instance').option('value');
                				selectedItem.SEARCH_YN = $('#dataSearch').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.BIND_YN = $('#dataBind').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = $('#orderByButton').dxSelectBox('instance').option('value');
//                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value') == '[All]' ? '[All]' : $('#DefaultValue').dxTextArea('instance').option('value');
                				
                				selectedItem.DEFAULT_VALUE = [fromValue,toValue];
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = 'N'
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                			}else if(paramType == 'BETWEEN_INPUT'){
                				var fromValue = $("#DefaultValueFrom").dxTextArea('instance').option('value');
            					var toValue = $("#DefaultValueTo").dxTextArea('instance').option('value');
            					
                				selectedItem.DATASRC_TYPE = '';
                				selectedItem.SEARCH_YN = 'N';
                				selectedItem.BIND_YN = 'N';
                				selectedItem.DATASRC = '';
                				selectedItem.KEY_VALUE_ITEM = "";
                				selectedItem.CAPTION_VALUE_ITEM = "";
                				selectedItem.SORT_TYPE = '';
                				selectedItem.DEFAULT_VALUE = [fromValue, toValue];
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = '';
                				selectedItem.ALL_YN = 'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                			}
            			}
            			$('#paramType').dxSelectBox('instance').option('value','');
                    	selectedItem = _e.selectedRowsData[0];
            			self.setParamInfo(_e.selectedRowsData[0]);
                    	
            		},
            		onContentReady:function(_e){
            			$(_e.element).dxDataGrid('selectRowsByIndexes',0)
            		}
            	});
            	
            	$('#paramBtnOK').dxButton({
            		text:"확인",
            		type:"success",
            		onClick:function(){
            			if(typeof selectedItem != 'undefined'){
            				selectedItem.PARAM_NM = $('#paramName').dxTextBox('instance').option('value');
            				selectedItem.UNI_NM = $('#paramName').dxTextBox('instance').option('value');
                			selectedItem.PARAM_CAPTION = $('#paramCaption').dxTextBox('instance').option('value');
                			selectedItem.DATA_TYPE = $('#dataType').dxSelectBox('instance').option('value');
                			selectedItem.PARAM_TYPE = $('#paramType').dxSelectBox('instance').option('value');
                			
                			selectedItem.ORDER = $('#orderInput').dxNumberBox('instance').option('value');
                			selectedItem.WIDTH = $('#widthInput').dxNumberBox('instance').option('value');
                			selectedItem.VISIBLE = $('#visibleYN').dxCheckBox('instance').option('value') ? 'Y':'N';
                			/* DOGFOOT ktkang 필터 NotIn 추가  20200716  */
                			selectedItem.OPER = $('#conditionInput').dxSelectBox('instance').option('value');
                			
                			var paramType = $('#paramType').dxSelectBox('instance').option('value');
                			
                			if(paramType == 'LIST'){
                				selectedItem.DATASRC_TYPE = $('#dataOriginType').dxSelectBox('instance').option('value');
                				selectedItem.SEARCH_YN = $('#dataSearch').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.BIND_YN = $('#dataBind').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = $('#orderByButton').dxSelectBox('instance').option('value');
//                				selectedItem.DEFAULT_VALUE = $('#UseSqlScriptYN').dxCheckBox('instance').option('value') ? selectedItem.DEFAULT_VALUE :$('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value') == '[All]' ? '[All]' : $('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = $('#MultiSelectYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                				if(selectedItem.DATASRC_TYPE == 'QUERY'){
                					$.each(parameterInformation,function(_i,_e){
                						var paramName = _e.PARAM_NM;
                						if((selectedItem.DATASRC).indexOf(paramName) > -1){
                							selectedItem.wiseVariables.push(paramName);
                							selectedItem.wiseVariables.push(_e.WHERE_CLAUSE);
                						}
                					});
                				}
                			}else if(paramType == 'INPUT'){
                				selectedItem.DATASRC_TYPE = '';
                				selectedItem.SEARCH_YN = 'N';
                				selectedItem.BIND_YN = 'N';
                				selectedItem.DATASRC = "";
                				selectedItem.KEY_VALUE_ITEM = "";
                				selectedItem.CAPTION_VALUE_ITEM = "";
                				selectedItem.SORT_TYPE = 'ASC';
                				selectedItem.DEFAULT_VALUE = $('#DefaultValue').dxTextArea('instance').option('value');
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = 'N';
                				selectedItem.ALL_YN = 'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                			}else if (paramType == 'CAND'){
                				if($('#candDefaultType').dxSelectBox('instance').option('value')== 'QUERY'){
                					selectedItem.CAND_DEFAULT_TYPE = 'QUERY';
                					selectedItem.CAND_PERIOD_BASE = "";
                					selectedItem.CAND_PERIOD_VALUE = "";
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					selectedItem.DEFAULT_VALUE = $('#DefaultValueQuery').dxTextArea('instance').option('value');
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT=$('#defaultQuery').dxCheckBox('instance').option('value')? 'Y':'N';
                					selectedItem.SORT_VALUE_ITEM = '';
                				}else{
                					selectedItem.CAND_DEFAULT_TYPE = 'NOW';
                					selectedItem.CAND_PERIOD_BASE = $("#DefaultValueNow").dxSelectBox('instance').option('value');
                					selectedItem.CAND_PERIOD_VALUE = $("#candMoveValue").dxNumberBox('instance').option('value');
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					selectedItem.DEFAULT_VALUE = "";
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					selectedItem.SORT_VALUE_ITEM = '';
                				}
                				selectedItem.wiseVariables = [];
                			}
                			else if(paramType == 'BETWEEN_CAND'){
                				if($('#candDefaultType').dxSelectBox('instance').option('value')== 'QUERY'){
                					var fromValue = $("#DefaultValueQueryFrom").dxTextArea('instance').option('value');
                					var toValue = $("#DefaultValueQueryTo").dxTextArea('instance').option('value');
                					selectedItem.CAND_DEFAULT_TYPE = 'QUERY';
                					/*dogfoot 캘린더 기간 설정 shlim 20210427*/
                					selectedItem.CAND_MAX_GAP = '0';
                					selectedItem.CAND_PERIOD_BASE = "";
                					selectedItem.CAND_PERIOD_VALUE = "";
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					var defaultVal = new Array();
                					defaultVal.push(fromValue);
                					defaultVal.push(toValue);
                					selectedItem.DEFAULT_VALUE  = defaultVal;
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT=$('#defaultQuery').dxCheckBox('instance').option('value')? 'Y':'N';
                					selectedItem.SORT_VALUE_ITEM = '';
                					
                				}else{
                					var fromPeriod = $("#DefaultValueNowFrom").dxSelectBox('instance').option('value');
                					var toPeriod = $("#DefaultValueNowTo").dxSelectBox('instance').option('value');
                					var fromValue = Number($("#candMoveValueFrom").dxNumberBox('instance').option('value'));
                					var toValue = Number($("#candMoveValueTo").dxNumberBox('instance').option('value'));
                					selectedItem.CAND_DEFAULT_TYPE = 'NOW';
                					/*dogfoot 캘린더 기간 설정 shlim 20210427*/
                					selectedItem.CAND_MAX_GAP = '0';
                					selectedItem.CAND_PERIOD_BASE = fromPeriod + ',' + toPeriod;
                					selectedItem.CAND_PERIOD_VALUE = fromValue + ',' + toValue;
                					selectedItem.CAPTION_FORMAT = $('#CaptionType').dxSelectBox('instance').option('value');
                					selectedItem.KEY_FORMAT = $('#KeyType').dxSelectBox('instance').option('value');
                					
                					var ToDate = new Date();
                					
                					if(toPeriod == 'YEAR'){
                						ToDate.setYear(ToDate.getFullYear()+toValue);
                					}else if(toPeriod == 'MONTH'){
                						ToDate.setMonth(ToDate.getMonth()+toValue);
                					}else{
                						ToDate.setDate(ToDate.getDate()+toValue);
                					}
                					var FromDate = new Date(ToDate);
                					if(fromPeriod == 'YEAR'){
                						FromDate.setYear(FromDate.getFullYear()+fromValue);
                					}else if(fromPeriod == 'MONTH'){
                						FromDate.setMonth(FromDate.getMonth()+fromValue)
                					}else{
                						FromDate.setDate(FromDate.getDate()+fromValue);
                					}
                					
                					selectedItem.DEFAULT_VALUE = self.getFormatDate(FromDate)+","+ self.getFormatDate(ToDate);
                					selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT='N';
                					selectedItem.SORT_VALUE_ITEM = '';
                					selectedItem.wiseVariables = [];
                				}
                			}else if(paramType == 'BETWEEN_LIST'){
                				var fromValue = $("#DefaultValueFrom").dxTextArea('instance').option('value');
            					var toValue = $("#DefaultValueTo").dxTextArea('instance').option('value');
            					
                				selectedItem.DATASRC_TYPE = $('#dataOriginType').dxSelectBox('instance').option('value');
                				selectedItem.SEARCH_YN = $('#dataSearch').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.BIND_YN = $('#dataBind').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
                				selectedItem.KEY_VALUE_ITEM = $('#KeyType').dxTextBox('instance').option('value');
                				selectedItem.CAPTION_VALUE_ITEM = $('#CaptionType').dxTextBox('instance').option('value');
                				selectedItem.SORT_TYPE = $('#orderByButton').dxSelectBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE = [fromValue,toValue];
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = 'N';
                				selectedItem.ALL_YN = $('#allCheck').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                			} else if(paramType == 'BETWEEN_INPUT'){
                				var fromValue = $("#DefaultValueFrom").dxTextArea('instance').option('value');
            					var toValue = $("#DefaultValueTo").dxTextArea('instance').option('value');
            					
                				selectedItem.DATASRC_TYPE = '';
                				selectedItem.SEARCH_YN = 'N';
                				selectedItem.BIND_YN = 'N';
                				selectedItem.DATASRC = '';
                				selectedItem.KEY_VALUE_ITEM = "";
                				selectedItem.CAPTION_VALUE_ITEM = "";
                				selectedItem.SORT_TYPE = '';
                				selectedItem.DEFAULT_VALUE = [fromValue, toValue];
                				selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT = $('#UseSqlScriptYN').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.MULTI_SEL = '';
                				selectedItem.ALL_YN = 'N';
                				selectedItem.WHERE_CLAUSE = $('#whereArea').dxTextBox('instance').option('value');
                				selectedItem.DEFAULT_VALUE_MAINTAIN = $('#maintainArea').dxCheckBox('instance').option('value')? 'Y':'N';
                				selectedItem.SORT_VALUE_ITEM = '';
                				selectedItem.wiseVariables = [];
                			}
                			if(selectedItem.DEFAULT_VALUE_USE_SQL_SCRIPT == 'Y'){
                				if(paramType == 'BETWEEN_CAND'){
                					var fromDataValue = '', toDataValue = '';
                					var fromparam ={
                    					'dsid':selectedItem.DS_ID,
                    					'dstype':'DS',
                    					'defaultSql':$('#DefaultValueQueryFrom').dxTextArea('instance').option('value')
                    				};
                					$.ajax({
                    					type : 'post',
                						data:fromparam,
                						async:false,
                						url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                						success: function(_data) {
                							fromDataValue = _data.data;
                							var toparam ={
                            					'dsid':selectedItem.DS_ID,
                            					'dstype':'DS',
                            					'defaultSql':$('#DefaultValueQueryTo').dxTextArea('instance').option('value')
                            				};
                							$.ajax({
                            					type : 'post',
                        						data:toparam,
                        						async:false,
                        						url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                        						success: function(_data) {
                        							toDataValue = _data.data;
                        							selectedItem.HIDDEN_VALUE = $('#DefaultValueQueryFrom').dxTextArea('instance').option('value')+','+$('#DefaultValueQueryTo').dxTextArea('instance').option('value');
                        							selectedItem.DEFAULT_VALUE = fromDataValue.concat(toDataValue)
                        							$('#editFilterPopup').dxPopup('hide');
                        							$('#editFilterPopup').remove();
                        						}
                        					});
                						}
                					});
                				}else if(paramType == 'BETWEEN_LIST' || paramType == 'BETWEEN_INPUT'){
                					var fromDataValue = '', toDataValue = '';
                					var fromparam ={
                    					'dsid':selectedItem.DS_ID,
                    					'dstype':'DS',
                    					'defaultSql':$('#DefaultValueFrom').dxTextArea('instance').option('value')
                    				};
                					$.ajax({
                    					type : 'post',
                						data:fromparam,
                						async:false,
                						url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                						success: function(_data) {
//                							selectedItem.HIDDEN_VALUE
                							fromDataValue = _data.data;
                							var toparam ={
                            					'dsid':selectedItem.DS_ID,
                            					'dstype':'DS',
                            					'defaultSql':$('#DefaultValueTo').dxTextArea('instance').option('value')
                            				};
                							$.ajax({
                            					type : 'post',
                        						data:toparam,
                        						async:false,
                        						url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                        						success: function(_data) {
                        							toDataValue = _data.data;
                        							selectedItem.HIDDEN_VALUE = $('#DefaultValueFrom').dxTextArea('instance').option('value')+','+$('#DefaultValueTo').dxTextArea('instance').option('value');
                        							selectedItem.DEFAULT_VALUE = fromDataValue.concat(toDataValue)
                        							$('#editFilterPopup').dxPopup('hide');
                        							$('#editFilterPopup').remove();
                        						}
                        					});
                						}
                					});
                				}else{
                					var sql = "";
                					if(paramType == 'CAND'){
                						sql = $('#DefaultValueQuery').dxTextArea('instance').option('value')
                					}else{
                						sql = $('#DefaultValue').dxTextArea('instance').option('value');
                					}
                					var param ={
                    					'dsid':selectedItem.DS_ID,
                    					'dstype':'DS',
                    					'defaultSql':sql
                    				};
                    				$.ajax({
                    					type : 'post',
                						data:param,
                						url : WISE.Constants.context + '/report/condition/defaultQueries.do',
                						success: function(_data) {
                							if(paramType == 'CAND'){
                								selectedItem.HIDDEN_VALUE = $('#DefaultValueQuery').dxTextArea('instance').option('value');
                							}else{
                								selectedItem.HIDDEN_VALUE = $('#DefaultValue').dxTextArea('instance').option('value');
                							}
                							selectedItem.DEFAULT_VALUE = _data.data;
                							$('#editFilterPopup').dxPopup('hide');
                							$('#editFilterPopup').remove();
                						},
                						error:function(error){
                							gProgressbar.hide();
                							//2020.01.21 mksong 경고창 타입 지정 dogfoot
                							WISE.alert("code:"+error.status+"\n"+"message:"+error.responseJSON.message,'error');
                						}
                    				});
                				}
                			}else{
    							$('#editFilterPopup').dxPopup('hide');
    							$('#editFilterPopup').remove();
    						}
    						
            				var paramGridDatas = $('#ConditionArea').dxDataGrid('instance').option('dataSource');
            				
            				$.each(parameterInformation ,function(_i, _o){
            					for(var i =0; i< paramGridDatas.length;i++){
            						if(paramGridDatas[i].PARAM_NM === parameterInformation.PARAM_NM){
            							var param = {
        									COND_ID : paramGridDatas[i].COND_ID,
        	        						COL_NM : _o.KEY_VALUE_ITEM,
        	        						TBL_NM: _o.DATASRC,
        	        						OPER : _o.OPER,
        	        						VALUES: _o.DEFAULT_VALUE,
        	        						VALUES_CAPTION: _o.DEFAULT_VALUE === '[All]' ? '전체' : _o.DEFAULT_VALUE,
        	        						DATA_BIND_YN: _o.BIND_YN,
        	        						AGG : paramGridDatas[i].AGG,
        	        						PARAM_YN:'Y',
        	        						PARAM_NM : _o.PARAM_NM,
        	        						TYPE : paramGridDatas[i].TYPE,
        	        						COL_CAPTION : _o.KEY_VALUE_ITEM,
        	        						DATA_TYPE : _o.DATA_TYPE,
            							}
            							paramGridDatas[i] = param;
            						}
            					}
							});

            				$('#ConditionArea').dxDataGrid('instance').option('dataSource',paramGridDatas);
            			}else{
            				$('#editFilterPopup').dxPopup('hide');
            				$('#editFilterPopup').remove();
            			}
            			
            		}
            	});
            	$('#paramBtnCancel').dxButton({
            		onClick:function(){
            			$('#editFilterPopup').dxPopup('hide');
            			$('#editFilterPopup').remove();
            		}
            	});
            }
		});
	}
	this.setParamInfo = function(_paramItem){
		var typeList = $('#paramType').dxSelectBox('instance').option('dataSource');
		var dataList = $('#dataType').dxSelectBox('instance').option('dataSource');
		$('#paramName').dxTextBox('instance').option('value',_paramItem['PARAM_NM']);
		$('#paramCaption').dxTextBox('instance').option('value',_paramItem['PARAM_CAPTION']);
		$('#dataType').dxSelectBox('instance').option('value',_paramItem['DATA_TYPE']);
		$('#paramType').dxSelectBox('instance').option('value',_paramItem['PARAM_TYPE']);
		if(_paramItem['OPER'] == 'Between'){
			$('#paramType').dxSelectBox('instance').option('dataSource',betweenParamType);
		}
		$('#orderInput').dxNumberBox('instance').option('value', _paramItem['ORDER']);
		$('#widthInput').dxNumberBox('instance').option('value', _paramItem['WIDTH']);
		$('#visibleYN').dxCheckBox('instance').option('value',_paramItem['VISIBLE'] == 'Y'? true:false);
		$('#dataSearch').dxCheckBox('instance').option('value',_paramItem['SEARCH_YN'] == 'Y'? true:false);
		$('#dataBind').dxCheckBox('instance').option('value',_paramItem['BIND_YN'] == 'Y'? true:false);
		/* DOGFOOT ktkang 필터 NotIn 추가  20200716  */
		$('#conditionInput').dxSelectBox('instance').option('value', _paramItem['OPER']);
	};
	
	this.paramTypeSetting = function(_paramType,_paramItem){

		var html = '';
		var showinghtml = '';
		switch(_paramType){
		case 'INPUT':
			showinghtml += '<div id="toggleSpecific"></div>'
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터원본 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOriginType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터 원본</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOrigin" style="width:90%;float:left"></div>';
			html += '<div id="TableSearchButton" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption 항목</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="captionSearchButton"  style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key 항목</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '<div id="keySearchButton" style="float:left"></div>';
			html += '<div id="orderByButton" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">매개변수 기본값</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="DefaultValue"></div>';
			html += '<div id="UseSqlScriptYN" style="float:left"></div>';
			html += '<div id="MultiSelectYN" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">[전체]항목 표시</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="AllArea"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">조건절</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="whereArea" style="float:left;width:60%"></div><div id="maintainArea" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'입력창 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
			$('#paramTypeSetting').append(html);

			
			$('#dataOriginType').dxSelectBox({
				readOnly:true,
				disabled:true
			});
			
			$('#dataOrigin').dxTextArea({
				readOnly:true,
				disabled:true
			});
			
			$('#CaptionType').dxTextBox({
				readOnly:true,
				disabled:true
			});
			
			$('#KeyType').dxTextBox({
				readOnly:true,
				disabled:true
			});
			
			$('#orderByButton').dxSelectBox({
				readOnly:true,
				disabled:true
			});
			
			$('#MultiSelectYN').dxCheckBox({
				text:'다중 선택',
				readOnly:true,
				disabled:true
			});
			
			$('#DefaultValue').dxTextArea({
				value:_paramItem['DEFAULT_VALUE']
			});
			$('#UseSqlScriptYN').dxCheckBox({
				text:'Use SQL Script',
				value:_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'? true:false
			});
			
			$('#AllArea').append("<div id='allCheck' style='float:left'></div>");
			
			$('#allCheck').dxCheckBox({
				readOnly:true,
				disabled:true
			});
			$('#whereArea').dxTextBox({
				value:_paramItem['WHERE_CLAUSE']
			});
			$('#maintainArea').dxCheckBox({
				text:'기본값유지',
				value:_paramItem['DEFAULT_VALUE_MAINTAIN']=='Y'? true:false
			});
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:true,disabled:true});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',readOnly:true});
			break;
		case 'LIST':
			showinghtml += '<div id="toggleSpecific"></div>'
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터원본 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOriginType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터 원본</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOrigin" style="width:90%;float:left"></div>';
			html += '<div id="TableSearchButton" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption 항목</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="captionSearchButton"  style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key 항목</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '<div id="keySearchButton" style="float:left"></div>';
			html += '<div id="orderByButton" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">매개변수 기본값</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="DefaultValue"></div>';
			html += '<div id="UseSqlScriptYN" style="float:left"></div>';
			html += '<div id="MultiSelectYN" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
//			html += '<div class="dx-field">';
//			
//			html += '</div>';
//			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">[전체]항목 표시</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="AllArea"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">조건절</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="whereArea" style="float:left;width:60%"></div><div id="maintainArea" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'리스트 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
			$('#paramTypeSetting').append(html);
			
			$('#dataOriginType').dxSelectBox({
				dataSource:[{key:'TBL', caption:'테이블'},/*{key:'StoredProcedure', caption:'StoredProcedure'},*/{key:'QUERY', caption:'쿼리'}],
				displayExpr:'caption',
				valueExpr:'key',
				onSelectionChanged:function(_selection){
					if(_selection.selectedItem.key == "QUERY"){
						$('#TableSearchButton').css('display','none');
						$('#keySearchButton').css('display','none');
						$('#captionSearchButton').css('display','none');
					}
					else{
						$('#TableSearchButton').css('display','block');
						$('#keySearchButton').css('display','block');
						$('#captionSearchButton').css('display','block');
					}
				}
			});
			
			$('#dataOrigin').dxTextArea({
				value:_paramItem['DATASRC']
			});
			
			$('#TableSearchButton').dxButton({
				icon:'search',
				onClick:function(_e){
				  	var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					var param = {
						'dsid':selectedItem.DS_ID,
						'dstype':'DS'
					}
					$.ajax({
						type : 'post',
						data:param,
						url : WISE.Constants.context + '/report/getTableList.do',
						success: function(_data) {
							gProgressbar.hide();
							var html = "<div id='paramTableSelect'></div>";
							$(".filter-bar").append(html);
							$('#paramTableSelect').dxPopup({
								title:'대상 테이블 목록',
								visible:true,
								width:600,
								height:700,
								contentTemplate:function() {
									return "<div style='height:90%'>" +
											"<div id='overflowScroll' style='height:100%;overflow:auto'>" +
											"<div id='paramTableList'>" +
											"</div>" +
											"</div>" +
											"</div>" +
											"<div style='width:100%;height:8%;text-align:center'>" +
											"<div id='tblApply'>" +
											"</div>" +
											"</div>"
								},
								onShown:function(){
									$('#paramTableList').dxDataGrid({
										dataSource:_data.data,
										paging:{
											enabled:false
										},
										selection:{
											mode:'single'
										}
									});
									$('#tblApply').dxButton({
										text:"확인",
										onClick:function(){
											var selected = $('#paramTableList').dxDataGrid('getSelectedRowsData')[0];
											if(typeof selected != 'undefined'){
												$('#paramTableSelect').dxPopup('hide');
												$('#dataOrigin').dxTextArea('instance').option('value',selected.TBL_NM);
												_paramItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
											}
										}
									});
//									$('#overflowScroll').dxScrollView({
//										width:'100%',
//										height:'100%',
//									});
								}
							});
						}
					});
				}
			})
			
			$('#CaptionType').dxTextBox({
				value:_paramItem['CAPTION_VALUE_ITEM']
			});
			
			$('#captionSearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var param = {
								'dsid':selectedItem.DS_ID,
								'dstype':'DS',
								'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
							};
							$.ajax({
								type : 'post',
								data:param,
								url : WISE.Constants.context + '/report/getColumnList.do',
								success: function(_data) {
									gProgressbar.hide();
									var html = "<div id='paramColumnSelect'></div>";
									$(".filter-bar").append(html);
									$('#paramColumnSelect').dxPopup({
										visible:true,
										width:600,
										height:700,
										contentTemplate:function() {
											return "<div style='height:90%'>" +
													"<div id='overflowScroll' style='height:100%;overflow:auto'>" +
													"<div id='paramColumnList'>" +
													"</div>" +
													"</div>" +
													"</div>" +
													"<div style='width:100%;height:8%;text-align:center'>" +
													"<div id='colApply'>" +
													"</div>" +
													"</div>"
										},
										onShown:function(){
											$('#overflowScroll').dxScrollView({
												width:'100%',
												height:'100%',
											});
											$('#paramColumnList').dxDataGrid({
												dataSource:_data.data,
												columns:[
													{
														dataField:"COL_NM",
														caption:"컬럼명"
													},
													
												],
												paging:{
													enabled:false
												},
												selection:{
													mode:'single'
												}
											});
											$('#colApply').dxButton({
												text:"확인",
												onClick:function(){
													var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
													if(typeof selected != 'undefined'){
														$('#paramColumnSelect').dxPopup('hide');
														$('#CaptionType').dxTextBox('instance').option('value',selected.COL_NM);
														_paramItem.CAPTION_VALUE_ITEM =$('#CaptionType').dxTextBox('instance').option('value');
													}
												}
											});
										}
									});
								}
							});
					}else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
				}
			});
			
			$('#keySearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var param = {
								'dsid':selectedItem.DS_ID,
								'dstype':'DS',
								'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
							};
							$.ajax({
								type : 'post',
								data:param,
								url : WISE.Constants.context + '/report/getColumnList.do',
								success: function(_data) {
									gProgressbar.hide();
									var html = "<div id='paramColumnSelect'></div>";
									$(".filter-bar").append(html);
									$('#paramColumnSelect').dxPopup({
										visible:true,
										width:600,
										height:700,
										contentTemplate:function() {
											return "<div style='height:90%'>" +
													"<div id='overflowScroll' style='height:100%;overflow:auto'>" +
													"<div id='paramColumnList'>" +
													"</div>" +
													"</div>" +
													"</div>" +
													"<div style='width:100%;height:8%;text-align:center'>" +
													"<div id='colApply'>" +
													"</div>" +
													"</div>"
										},
										onShown:function(){
											$('#overflowScroll').dxScrollView({
												width:'100%',
												height:'100%',
											});
											$('#paramColumnList').dxDataGrid({
												dataSource:_data.data,
												columns:[
													{
														dataField:"COL_NM",
														caption:"컬럼명"
													},
													
												],
												paging:{
													enabled:false
												},
												selection:{
													mode:'single'
												}
											});
											$('#colApply').dxButton({
												text:"확인",
												onClick:function(){
													var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
													if(typeof selected != 'undefined'){
														$('#paramColumnSelect').dxPopup('hide');
														$('#KeyType').dxTextBox('instance').option('value',selected.COL_NM);
														_paramItem.KEY_VALUE_ITEM =$('#KeyType').dxTextBox('instance').option('value');
													}
												}
											});
										}
									});
								}
							});
					}else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
				}
			});
			
			$('#KeyType').dxTextBox({
				value:_paramItem['KEY_VALUE_ITEM']
			});
			var orderByButtonDataSource = [{key:'ASC',caption:'오름차순'},{key:'DESC',caption:'내림차순'}];
			$('#orderByButton').dxSelectBox({
				dataSource: orderByButtonDataSource,
				displayExpr:'caption',
				valueExpr:'key',
				value:'ASC'
			});
			
			$('#MultiSelectYN').dxCheckBox({
				text:'다중 선택',
				value:_paramItem['MULTI_SEL'] == 'Y'? true:false
			})
			
			var defaultVal = '';
			if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'){
				defaultVal = _paramItem['HIDDEN_VALUE'];
			}else{
				if(_paramItem['DEFAULT_VALUE']  == '_ALL_VALUE_'){
					defaultVal = '[All]';
				}else{
					defaultVal = _paramItem['DEFAULT_VALUE'];
				}
			}
			$('#DefaultValue').dxTextArea({
				value: defaultVal
				
			});
			$('#UseSqlScriptYN').dxCheckBox({
				text:'Use SQL Script',
				value:_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'? true:false
			});
			
			$('#AllArea').append("<div id='allCheck' style='float:left'></div>");
			
			$('#allCheck').dxCheckBox({
				value:_paramItem['ALL_YN'] == 'Y'? true:false
			});
			
			
			$('#whereArea').dxTextBox({
				value:_paramItem['WHERE_CLAUSE']
			});
			$('#maintainArea').dxCheckBox({
				text:'기본값유지',
				value:_paramItem['DEFAULT_VALUE_MAINTAIN']=='Y'? true:false
			});
			$.each($('#dataOriginType').dxSelectBox('instance').option('dataSource'),function(_i,_items){
				if(_paramItem['DATASRC_TYPE'] == _items['key']){
					$('#dataOriginType').dxSelectBox('instance').option('value',_items['key']);
					return false;
				}
				else if(_paramItem['DATASRC_TYPE'].length == 0){
					$('#dataOriginType').dxSelectBox('instance').option('value','TBL');
					return false;
				}
			});

			$.each($('#orderByButton').dxSelectBox('instance').option('dataSource'),function(_i,_items){
				if(_paramItem['SORT_TYPE'] == _items['key']){
					$('#orderByButton').dxSelectBox('instance').option('value',_items['key']);
					return false;
				}
			});
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:false,disabled:false});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',readOnly:false});
			break;
		case 'CAND':
			showinghtml += '<div id="toggleSpecific"></div>'
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">기본 값 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="candDefaultType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div id="nowSettingArea">' 
			html += '<div class="dx-field">';
			html += '<div id="defaultValueCaption" class="dx-field-label">기본 값 계산</div>';
			html += '<div id="candInputArea" class="dx-field-value">';
			html += '<div id="DefaultValueNow" style="width:90%;float:left"></div><span style="float:left">을 기준으로 </span><div id="candMoveValue" style="float:left"></div><span>이동 값을 기본 값으로 합니다</span><div>* 기본 계산 값 계산 앞 부분을 [년도]를 선택하고 뒤 부분의 숫자를 -1로 설정하면 매개변수 기본 값 유형에서 선택 한 기본 값을 기준으로 전년도 값을 자동으로 가져옵니다.</div><div>년도, 월, 주, 일을 기준으로 기간을 설정할 수 있습니다.</div>'
			html += '</div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div id="querySettingArea">' 
			html += '<div class="dx-field">';
			html += '<div id="defaultValueCaption" class="dx-field-label">기본 값</div>';
			html += '<div id="candInputArea" class="dx-field-value">';
			html += '<div id="DefaultValueQuery" style="width:90%;float:left"></div>';
			html += '<div id="defaultQuery" style="float:left"/>';
			html += '</div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption Value 형식 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="defaultValueMaintain" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key Value 형식 *</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'달력 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
//			$('#candDefaultType').dxSelectBox('instance').option('value',_paramItem['CAND_DEFAULT_TYPE'] == "" ? "NOW":_paramItem['CAND_DEFAULT_TYPE']  );
			$('#paramTypeSetting').append(html);
			var candDefaultTypeArr = [{key:'NOW', caption:'현재'},{key:'QUERY', caption:'쿼리'}];
			$('#candDefaultType').dxSelectBox({
				dataSource:[{key:'NOW', caption:'현재'},{key:'QUERY', caption:'쿼리'}],
				displayExpr:'caption',
				valueExpr:'key',
				value : _paramItem['CAND_DEFAULT_TYPE'] == "" ? "NOW":_paramItem['CAND_DEFAULT_TYPE'],  
				onSelectionChanged:function(_selection){
					if(_selection.selectedItem.key == "QUERY"){
						$('#nowSettingArea').css('display','none');
						$('#querySettingArea').css('display','block');
					}
					else{
						$('#nowSettingArea').css('display','block');
						$('#querySettingArea').css('display','none');
					}
				}
			});
			
			$('#DefaultValueQuery').dxTextArea();
			
			$('#DefaultValueNow').dxSelectBox({
				dataSource:[{key:'YEAR', caption:'년도'},{key:'MONTH', caption:'월'},{key:'DAY', caption:'일'}],
				displayExpr:'caption',
				valueExpr:'key',
				width:100
			});
			
			$('#candMoveValue').dxNumberBox({
				width:150,
				showSpinButtons: true,
			});
			
			$('#defaultQuery').dxCheckBox({
				text:'use SQL Script',
				value : _paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y' ? true : false
			});
			$('#KeyType').dxSelectBox({
				dataSource:[{key:'yyyy', caption:'yyyy'},{key:'yyyyMM', caption:'yyyyMM'},{key:'yyyyMMdd', caption:'yyyyMMdd'},{key:'yyyy-MM', caption:'yyyy-MM'},{key:'yyyy-MM-dd', caption:'yyyy-MM-dd'}],
				displayExpr:'caption',
				valueExpr:'key'
			});
			$('#CaptionType').dxSelectBox({
				dataSource:[{key:'yyyy', caption:'yyyy'},{key:'yyyyMM', caption:'yyyyMM'},{key:'yyyyMMdd', caption:'yyyyMMdd'},{key:'yyyy-MM', caption:'yyyy-MM'},{key:'yyyy-MM-dd', caption:'yyyy-MM-dd'}],
				displayExpr:'caption',
				valueExpr:'key'
			});
			
			
			$('#KeyType').dxSelectBox('instance').option('value',_paramItem['KEY_FORMAT']);
			$('#CaptionType').dxSelectBox('instance').option('value',_paramItem['CAPTION_FORMAT']);
			
			if(_paramItem['CAND_DEFAULT_TYPE'] == 'QUERY'){
				if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'){
					$('#DefaultValueQuery').dxTextArea('instance').option('value',_paramItem['HIDDEN_VALUE']);
				}else{
					$('#DefaultValueQuery').dxTextArea('instance').option('value',_paramItem['DEFAULT_VALUE']);
				}
				
			}else{
				$('#DefaultValueNow').dxSelectBox('instance').option('value',_paramItem['CAND_PERIOD_BASE']);
				$('#candMoveValue').dxNumberBox('instance').option('value',_paramItem['CAND_PERIOD_VALUE']);
			}
			break;
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:false,disabled:false});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',readOnly:false});
		case 'BETWEEN_INPUT':
			showinghtml += '<div id="toggleSpecific"></div>'
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">데이터원본 유형</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="dataOriginType" style="float:left"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">데이터 원본</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="dataOrigin" style="width:90%;float:left"></div>';
				html += '<div id="TableSearchButton" style="float:left"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">Caption 항목</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="CaptionType" style="float:left"></div>';
				html += '<div id="captionSearchButton"  style="float:left"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">Key 항목</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="KeyType" style="float:left"></div>';
				html += '<div id="keySearchButton" style="float:left"></div>';
				html += '<div id="orderByButton" style="float:right"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">매개변수 기본값</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="DefaultValueFrom" style="width:48%;float:left"></div>';
				html += '<div id="DefaultValueTo" style="width:48%;float:right"></div>';
				html += '<div id="UseSqlScriptYN" style="float:left"></div>';
				html += '<div id="MultiSelectYN" style="float:right"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">[전체]항목 표시</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="AllArea"></div>';
				html += '</div>';
				html += '</div>';
				
				html += '<div class="dx-field">';
				html += '<div class="dx-field-label">조건절</div>';
				html += '<div class="dx-field-value">';
				html += '<div id="whereArea" style="float:left;width:60%"></div><div id="maintainArea" style="float:right"></div>';
				html += '</div>';
				html += '</div>';
				
				$('#paramShowing').append(showinghtml);
				$('#toggleSpecific').dxButton({
					text:'입력창 상세 설정',
					onClick:function(){
						if($('#paramTypeSetting').css('display') == 'none'){
							$('#paramTypeSetting').css('display','block');
						}else{
							$('#paramTypeSetting').css('display','none');
						}
					}
				});
				$('#paramTypeSetting').append(html);
				
				var defaultToVal = '',defaultFromVal = '';
				if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'){
					var splitVal = _paramItem['HIDDEN_VALUE'].split(',');
					defaultFromVal = splitVal[0];
					defaultToVal = splitVal[1];
				}else{
					var splitVal = _paramItem['HIDDEN_VALUE'].split(',');
					if(splitVal[0]  == '_ALL_VALUE_'){
						defaultFromVal = '[All]';
					}else{
						defaultFromVal = _paramItem['DEFAULT_VALUE'][0];
					}
					if(splitVal[1]  == '_ALL_VALUE_'){
						defaultToVal = '[All]';
					}else{
						defaultToVal = _paramItem['DEFAULT_VALUE'][1];
					}
				}
				
				$('#dataOriginType').dxSelectBox({
					readOnly:true,
					disabled:true
				});
				
				$('#dataOrigin').dxTextArea({
					readOnly:true,
					disabled:true
				});
				
				$('#CaptionType').dxTextBox({
					readOnly:true,
					disabled:true
				});
				
				$('#KeyType').dxTextBox({
					readOnly:true,
					disabled:true
				});
				
				$('#orderByButton').dxSelectBox({
					readOnly:true,
					disabled:true
				});
				
				$('#MultiSelectYN').dxCheckBox({
					text:'다중 선택',
					readOnly:true,
					disabled:true
				});

				$('#DefaultValueFrom').dxTextArea({
					value:_paramItem['DEFAULT_VALUE']
				});
				$('#DefaultValueTo').dxTextArea({
					value:defaultFromVal
				});
				$('#UseSqlScriptYN').dxCheckBox({
					text:'Use SQL Script',
					value:_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'? true:false
				});
				
				$('#AllArea').append("<div id='allCheck' style='float:left'></div>");
				
				$('#allCheck').dxCheckBox({
					readOnly:true,
					disabled:true
				});
				$('#whereArea').dxTextBox({
					value:_paramItem['WHERE_CLAUSE']
				});
				$('#maintainArea').dxCheckBox({
					text:'기본값유지',
					value:_paramItem['DEFAULT_VALUE_MAINTAIN']=='Y'? true:false
				});
				$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:true,disabled:true});
				$('#dataBind').dxCheckBox({text:'데이터 바인딩',readOnly:true});
				break;
			break;
		case 'BETWEEN_LIST':
			showinghtml += '<div id="toggleSpecific"></div>'
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터원본 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOriginType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">데이터 원본</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="dataOrigin" style="width:90%;float:left"></div>';
			html += '<div id="TableSearchButton" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption 항목</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="captionSearchButton"  style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key 항목</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '<div id="keySearchButton" style="float:left"></div>';
			html += '<div id="orderByButton" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">매개변수 기본값</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="DefaultValueFrom" style="width:48%;float:left"></div>';
			html += '<div id="DefaultValueTo" style="width:48%;float:right"></div>';
			html += '<div id="UseSqlScriptYN" style="float:left"></div>';
			html += '<div id="MultiSelectYN" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
//				html += '<div class="dx-field">';
//				
//				html += '</div>';
//				html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">[전체]항목 표시</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="AllArea"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">조건절</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="whereArea" style="float:left;width:60%"></div><div id="maintainArea" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'리스트 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
			$('#paramTypeSetting').append(html);
			
			$('#dataOriginType').dxSelectBox({
				dataSource:[{key:'TBL', caption:'테이블'},/*{key:'StoredProcedure', caption:'StoredProcedure'},*/{key:'QUERY', caption:'쿼리'}],
				displayExpr:'caption',
				valueExpr:'key',
				onSelectionChanged:function(_selection){
					if(_selection.selectedItem.key == "QUERY"){
						$('#TableSearchButton').css('display','none');
						$('#keySearchButton').css('display','none');
						$('#captionSearchButton').css('display','none');
					}
					else{
						$('#TableSearchButton').css('display','block');
						$('#keySearchButton').css('display','block');
						$('#captionSearchButton').css('display','block');
					}
				}
			});
			
			$('#dataOrigin').dxTextArea({
				value:_paramItem['DATASRC']
			});
			
			$('#TableSearchButton').dxButton({
				icon:'search',
				onClick:function(_e){
				  	var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					var param = {
						'dsid':selectedItem.DS_ID,
						'dstype':'DS'
					}
					$.ajax({
						type : 'post',
						data:param,
						url : WISE.Constants.context + '/report/getTableList.do',
						success: function(_data) {
							gProgressbar.hide();
							var html = "<div id='paramTableSelect'></div>";
							$(".filter-bar").append(html);
							$('#paramTableSelect').dxPopup({
								title:'대상 테이블 목록',
								visible:true,
								width:600,
								height:700,
								contentTemplate:function() {
									return "<div style='height:90%'><div id='overflowScroll' style='height:100%;overflow:auto'><div id='paramTableList'></div></div></div><div style='width:100%;height:8%;text-align:center'><div id='tblApply'></div></div>"
								},
								onShown:function(){
									$('#paramTableList').dxDataGrid({
										dataSource:_data.data,
										paging:{
											enabled:false
										},
										selection:{
											mode:'single'
										}
									});
									$('#tblApply').dxButton({
										text:"확인",
										onClick:function(){
											var selected = $('#paramTableList').dxDataGrid('getSelectedRowsData')[0];
											if(typeof selected != 'undefined'){
												$('#paramTableSelect').dxPopup('hide');
												$('#dataOrigin').dxTextArea('instance').option('value',selected.TBL_NM);
												_paramItem.DATASRC = $('#dataOrigin').dxTextArea('instance').option('value');
											}
										}
									});
//									$('#overflowScroll').dxScrollView({
//										width:'100%',
//										height:'100%',
//									});
								}
							});
						}
					});
				}
			})
			
			$('#CaptionType').dxTextBox({
				value:_paramItem['CAPTION_VALUE_ITEM']
			});
			
			$('#captionSearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var param = {
							'dsid':selectedItem.DS_ID,
							'dstype':'DS',
							'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
						};
						$.ajax({
							type : 'post',
							data:param,
							url : WISE.Constants.context + '/report/getColumnList.do',
							success: function(_data) {
								gProgressbar.hide();
								var html = "<div id='paramColumnSelect'></div>";
								$(".filter-bar").append(html);
								$('#paramColumnSelect').dxPopup({
									visible:true,
									width:600,
									height:700,
									contentTemplate:function() {
										return "<div style='height:90%'><div id='overflowScroll'><div id='paramColumnList'></div></div></div><div style='width:100%;height:8%;text-align:center'><div id='colApply'></div></div>"
									},
									onShown:function(){
										$('#overflowScroll').dxScrollView({
											width:'100%',
											height:'100%',
										});
										$('#paramColumnList').dxDataGrid({
											dataSource:_data.data,
											columns:[
												{
													dataField:"COL_NM",
													caption:"컬럼명"
												},
												
											],
											paging:{
												enabled:false
											},
											selection:{
												mode:'single'
											}
										});
										$('#colApply').dxButton({
											text:"확인",
											onClick:function(){
												var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
												if(typeof selected != 'undefined'){
													$('#paramColumnSelect').dxPopup('hide');
													$('#CaptionType').dxTextBox('instance').option('value',selected.COL_NM);
													_paramItem.CAPTION_VALUE_ITEM =$('#CaptionType').dxTextBox('instance').option('value');
												}
											}
										});
									}
								});
							}
						});
					}
					else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
					
				}
			});
			
			$('#keySearchButton').dxButton({
				icon:'search',
				onClick:function(){
					var selectedItem = $('#paramItemListArea').dxDataGrid('getSelectedRowsData')[0];
					if($('#dataOrigin').dxTextArea('instance').option('value') != ""){
						var param = {
							'dsid':selectedItem.DS_ID,
							'dstype':'DS',
							'tableNm':$('#dataOrigin').dxTextArea('instance').option('value')
						};
						$.ajax({
							type : 'post',
							data:param,
							url : WISE.Constants.context + '/report/getColumnList.do',
							success: function(_data) {
								gProgressbar.hide();
								var html = "<div id='paramColumnSelect'></div>";
								$(".filter-bar").append(html);
								$('#paramColumnSelect').dxPopup({
									visible:true,
									width:600,
									height:700,
									contentTemplate:function() {
										return "<div style='height:90%'><div id='overflowScroll'><div id='paramColumnList'></div></div></div><div style='width:100%;height:8%;text-align:center'><div id='colApply'></div></div>"
									},
									onShown:function(){
										$('#overflowScroll').dxScrollView({
											width:'100%',
											height:'100%',
										});
										$('#paramColumnList').dxDataGrid({
											dataSource:_data.data,
											columns:[
												{
													dataField:"COL_NM",
													caption:"컬럼명"
												},
												
											],
											paging:{
												enabled:false
											},
											selection:{
												mode:'single'
											}
										});
										$('#colApply').dxButton({
											text:"확인",
											onClick:function(){
												var selected = $('#paramColumnList').dxDataGrid('getSelectedRowsData')[0];
												if(typeof selected != 'undefined'){
													$('#paramColumnSelect').dxPopup('hide');
													$('#KeyType').dxTextBox('instance').option('value',selected.COL_NM);
													_paramItem.KEY_VALUE_ITEM =$('#KeyType').dxTextBox('instance').option('value');
												}
											}
										});
									}
								});
							}
						});
					}else{
						WISE.alert("데이터 원본은 필수로 입력해야 합니다!");
						return false;
					}
				}
			});
			
			$('#KeyType').dxTextBox({
				value:_paramItem['KEY_VALUE_ITEM']
			});
			var orderByButtonDataSource = [{key:'ASC',caption:'오름차순'},{key:'DESC',caption:'내림차순'}];
			$('#orderByButton').dxSelectBox({
				dataSource: orderByButtonDataSource,
				displayExpr:'caption',
				valueExpr:'key',
				value:'ASC'
			});
			
			var defaultToVal = '',defaultFromVal = '';
			if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'){
				var splitVal = _paramItem['HIDDEN_VALUE'].split(',');
				defaultFromVal = splitVal[0];
				defaultToVal = splitVal[1];
			}else{
				var splitVal = _paramItem['HIDDEN_VALUE'].split(',');
				if(splitVal[0]  == '_ALL_VALUE_'){
					defaultFromVal = '[All]';
				}else{
					defaultFromVal = _paramItem['DEFAULT_VALUE'][0];
				}
				if(splitVal[1]  == '_ALL_VALUE_'){
					defaultToVal = '[All]';
				}else{
					defaultToVal = _paramItem['DEFAULT_VALUE'][1];
				}
			}
			
			
			$('#DefaultValueFrom').dxTextArea({
				value: defaultFromVal
			});
			$('#DefaultValueTo').dxTextArea({
				value: defaultToVal
			});
			$('#UseSqlScriptYN').dxCheckBox({
				text:'Use SQL Script',
				value:_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y'? true:false
			});
			
			$('#AllArea').append("<div id='allCheck' style='float:left'></div>");
			
			$('#allCheck').dxCheckBox({
				value:_paramItem['ALL_YN'] == 'Y'? true:false
			});
			$('#whereArea').dxTextBox({
				value:_paramItem['WHERE_CLAUSE']
			});
			$('#maintainArea').dxCheckBox({
				text:'기본값유지',
				value:_paramItem['DEFAULT_VALUE_MAINTAIN']=='Y'? true:false
			});
			$.each($('#dataOriginType').dxSelectBox('instance').option('dataSource'),function(_i,_items){
				if(_paramItem['DATASRC_TYPE'] == _items['key']){
					$('#dataOriginType').dxSelectBox('instance').option('value',_items['key']);
					return false;
				}
				else if(_paramItem['DATASRC_TYPE'].length == 0){
					$('#dataOriginType').dxSelectBox('instance').option('value','TBL');
					return false;
				}
			});

			$.each($('#orderByButton').dxSelectBox('instance').option('dataSource'),function(_i,_items){
				if(_paramItem['SORT_TYPE'] == _items['key']){
					$('#orderByButton').dxSelectBox('instance').option('value',_items['key']);
					return false;
				}
			});
			
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:false,disabled:false});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',readOnly:false});
			break;
		case 'BETWEEN_CAND':
			showinghtml += '<div id="toggleSpecific"></div>';
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">기본 값 유형</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="candDefaultType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div id="nowSettingArea">';
			html += '<div class="dx-field">';
			html += '<div id="defaultValueCaption" class="dx-field-label">기본 값 계산</div>';
			html += '<div id="candInputArea" class="dx-field-value">';
			html += '<div>From : </div><div id="DefaultValueNowFrom" style="width:90%;float:left"></div>';
			html += '<span style="float:left">을 기준으로 </span>';
			html += '<div id="candMoveValueFrom" style="float:left"></div>';
			html += '<span>이동 값을 기본 값으로 합니다</span>';
			/* DOGFOOT syjin 비트윈 달력에서 화면 수정  20200716 */
			html += '<div style="margin-top:10px;">To : </div><div id="DefaultValueNowTo" style="width:90%;float:left"></div>';
			html += '<span style="float:left">을 기준으로 </span>';
			html += '<div id="candMoveValueTo" style="float:left"></div>';
			html += '<span>이동 값을 기본 값으로 합니다</span><div style="margin-top:10px;">* 기본 계산 값 계산 앞 부분을 [년도]를 선택하고 뒤 부분의 숫자를 -1로 설정하면 매개변수 기본 값 유형에서 선택 한 기본 값을 기준으로 전년도 값을 자동으로 가져옵니다.</div><div>년도, 월, 주, 일을 기준으로 기간을 설정할 수 있습니다.</div>';
			html += '</div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div id="querySettingArea">';
			html += '<div class="dx-field">';
			html += '<div id="defaultValueCaption" class="dx-field-label">기본 값 </div>';
			html += '<div id="candInputArea" class="dx-field-value">';
			html += '<div id="DefaultValueQueryFrom" style="width:49%;float:left"></div>';
			html += '<div id="DefaultValueQueryTo" style="width:49%;float:right"></div>';
			html += '<div id="defaultQuery" style="float:left"/>';
			html += '</div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Caption Value 형식</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="CaptionType" style="float:left"></div>';
			html += '<div id="defaultValueMaintain" style="float:right"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '<div class="dx-field">';
			html += '<div class="dx-field-label">Key Value 형식</div>';
			html += '<div class="dx-field-value">';
			html += '<div id="KeyType" style="float:left"></div>';
			html += '</div>';
			html += '</div>';
			
			$('#paramShowing').append(showinghtml);
			$('#toggleSpecific').dxButton({
				text:'달력 상세 설정',
				onClick:function(){
					if($('#paramTypeSetting').css('display') == 'none'){
						$('#paramTypeSetting').css('display','block');
					}else{
						$('#paramTypeSetting').css('display','none');
					}
				}
			});
			
			$('#paramTypeSetting').append(html);
			var candDefaultTypeArr = [{key:'NOW', caption:'현재'},{key:'QUERY', caption:'쿼리'}];
			$('#candDefaultType').dxSelectBox({
				dataSource:[{key:'NOW', caption:'현재'},{key:'QUERY', caption:'쿼리'}],
				displayExpr:'caption',
				valueExpr:'key',
				value:"NOW",
				onSelectionChanged:function(_selection){
					if(_selection.selectedItem.key == "QUERY"){
						$('#querySettingArea').css('display','block');
						$('#nowSettingArea').css('display','none');
					}
					else{
						$('#querySettingArea').css('display','none');
						$('#nowSettingArea').css('display','block');
					}
				}
			});
			
			$('#KeyType').dxSelectBox({
				dataSource:[{key:'yyyy', caption:'yyyy'},{key:'yyyyMM', caption:'yyyyMM'},{key:'yyyyMMdd', caption:'yyyyMMdd'},{key:'yyyy-MM', caption:'yyyy-MM'},{key:'yyyy-MM-dd', caption:'yyyy-MM-dd'}],
				displayExpr:'caption',
				valueExpr:'key'
			});
			$('#CaptionType').dxSelectBox({
				dataSource:[{key:'yyyy', caption:'yyyy'},{key:'yyyyMM', caption:'yyyyMM'},{key:'yyyyMMdd', caption:'yyyyMMdd'},{key:'yyyy-MM', caption:'yyyy-MM'},{key:'yyyy-MM-dd', caption:'yyyy-MM-dd'}],
				displayExpr:'caption',
				valueExpr:'key'
			});
			
			$('#candDefaultType').dxSelectBox('instance').option('value',_paramItem['CAND_DEFAULT_TYPE'] == "" ? "NOW":_paramItem['CAND_DEFAULT_TYPE']  );
			$('#KeyType').dxSelectBox('instance').option('value',_paramItem['KEY_FORMAT']);
			$('#CaptionType').dxSelectBox('instance').option('value',_paramItem['CAPTION_FORMAT']);
			
			
			$('#DefaultValueNowFrom').dxSelectBox({
				dataSource:[{key:'YEAR', caption:'년도'},{key:'MONTH', caption:'월'},{key:'DAY', caption:'일'}],
				displayExpr:'caption',
				valueExpr:'key',
				width:100,
				height:25,
			});
			$('#DefaultValueNowTo').dxSelectBox({
				dataSource:[{key:'YEAR', caption:'년도'},{key:'MONTH', caption:'월'},{key:'DAY', caption:'일'}],
				displayExpr:'caption',
				valueExpr:'key',
				width:100,
				height:25,
			});
			$('#candMoveValueFrom').dxNumberBox({
				width:150,
				height:25,
				showSpinButtons: true,
			});
			$('#candMoveValueTo').dxNumberBox({
				width:150,
				height:25,
				showSpinButtons: true,
			});
			
			$('#DefaultValueQueryFrom').dxTextArea({
			});
			$('#DefaultValueQueryTo').dxTextArea({
			});
			$('#defaultQuery').dxCheckBox({
				text:'use SQL Script',
				value : _paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] == 'Y' ? true : false
			});
			self.BetweenCandSetting(_paramItem);
			$('#dataSearch').dxCheckBox({text:'데이터 검색',readOnly:false,disabled:false});
			$('#dataBind').dxCheckBox({text:'데이터 바인딩',readOnly:false});
			break;
		};
	};
	
	this.getFormatDate = function(date){
		var year = date.getFullYear();	//yyyy 
		var month = (1 + date.getMonth());	//M 
		month = month >= 10 ? month : '0' + month;	//month 두자리로 저장 
		var day = date.getDate();	//d 
		day = day >= 10 ? day : '0' + day;	//day 두자리로 저장 
		return year + '' + month + '' + day; 
	}

	this.BetweenCandSetting = function(_paramItem){
		if(_paramItem['CAND_DEFAULT_TYPE'] == 'QUERY'){
			if(_paramItem['DEFAULT_VALUE_USE_SQL_SCRIPT'] =='Y'){
				var betweenDefault = _paramItem['HIDDEN_VALUE'].split(',');
				$('#DefaultValueQueryFrom').dxTextArea('instance').option('value',betweenDefault[0]);
				$('#DefaultValueQueryTo').dxTextArea('instance').option('value',betweenDefault[1]);
			}else{
				$('#DefaultValueQueryFrom').dxTextArea('instance').option('value',_paramItem.DEFAULT_VALUE[0]);
				$('#DefaultValueQueryTo').dxTextArea('instance').option('value',_paramItem.DEFAULT_VALUE[1]);
			}
			
		}else if(_paramItem['CAND_DEFAULT_TYPE'] == 'NOW'){
			var betweenDefault = _paramItem['CAND_PERIOD_BASE'].split(',');
			var betweenMoveValue = _paramItem['CAND_PERIOD_VALUE'].split(',');
			$('#DefaultValueNowFrom').dxSelectBox('instance').option('value',betweenDefault[0]);
			$('#DefaultValueNowTo').dxSelectBox('instance').option('value',betweenDefault[1]);
			$('#candMoveValueFrom').dxNumberBox('instance').option('value',betweenMoveValue[0]);
			$('#candMoveValueTo').dxNumberBox('instance').option('value',betweenMoveValue[1]);
		}
	};
	
	return {
		loadDataSetList: function() {
			gProgressbar.show();
			initDataSetList();
		},
		handleDataSetRefresh:function(){
			gProgressbar.show();
		},
		handleDataSetCreate:function(){
			event.preventDefault();
			newDataSetLoad();
		},
		handleDataSetSave:function(){
			event.preventDefault();
			newDataSetSave();
		},
		handleDataSetSaveAs:function(){
			event.preventDefault();
			newDataSetSaveAs();
		},
		handleDataSetDelete:function(){
			event.preventDefault();
			deleteDataSet();
		},
	}
})();