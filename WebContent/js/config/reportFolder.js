/**
 * Report/Folder manager class.
 */
var reportFolderManager = (function() {
	/* private variables and methods */
	var selectedPublicReportId;
	var selectedPublicFolderNode;
	/*dogfoot shlim 20210414*/
	var preSelectedPublicFolderNode;

	/**
	 * Initialize functions for report page.
	 */
	function initReportLayout() {
		selectedPublicReportId = undefined;
		$.ajax({
			url: WISE.Constants.context + '/report/getPublicReportList.do',
			method: 'GET',
			async: false,
			dataType: "json",
			success: function(result) {
				$.each(result, function(_i,_items) {
					switch (_items.TYPE) {
						case 'REPORT':
							if (_items.REPORT_TYPE === 'DashAny') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_squariFied.png';
							} else if (_items.REPORT_TYPE === 'AdHoc') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_atypical01.png';	            						
							} else if (_items.REPORT_TYPE === 'Spread' || _items.REPORT_TYPE === 'Excel') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msexcell.png';
							} else if (_items.REPORT_TYPE === 'Word' || _items.REPORT_TYPE === 'WordGrp') {
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msword.png';
							}
							break;
						case 'FOLDER':
							_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
							break;
						default: break;
					}
				});
				/*dogfoot 환경설정 보고서 관리 폴더,보고서 Key 중복 오류 수정 shlim 20210217*/
				$('#reportList').dxTreeView({
					dataSource: result,
					dataStructure:'plain',
					keyExpr: "uniqueKey",
					parentIdExpr: "upperKey",
					rootValue: "F_0",
					// mksong 2019.12.20 보고서 검색 추가 dogfoot
					searchEnabled: true,
        			searchMode : "contains",
        			searchTimeout:undefined,
        			searchValue:"",
        			// 2019.12.20 mksong nodata 텍스트 수정 dogfoot
        			noDataText:"조회된 보고서가 없습니다.",
					displayExpr: "TEXT",
					showCloseButton: false,
					selectionMode: 'single',
					selectByClick: true,
					selectNodesRecursive: false,
					focusStateEnabled: false,
					repaintChangesOnly: true,
					onItemClick:function(_e) {
						var item = _e.itemData;
						if (item.TYPE === 'REPORT') {
							$('#reportId').text(item.ID);
							$('#reportDataLoad').prop('checked', item.PROMPT === 'Y');
							$('#reportTitle').val(item.TEXT);
							$('#reportSubtitle').val(item.SUBTITLE);
							$('#reportType').text(item.REPORT_TYPE);
							/*dogfoot 보고서 관리 폴더 저장 기능 추가 shlim 20201117*/
							$('#reportFolder').val(_e.node.parent != null ? _e.node.parent.text : "");
							/*dogfoot 환경설정 보고서 관리 폴더,보고서 Key 중복 오류 수정 shlim 20210217*/
							$('#reportFolder').attr("UPPERID",_e.node.parent != null ? _e.node.parent.itemData.ID : 0);
							$('#publisherName').text(item.CREATED_BY);
							$('#publishedDate').text(item.CREATED_DATE);
							$('#reportTag').val(item.TAG);
							$('#reportOrder').val(item.ORDINAL);
							$('#reportDesc').val(item.DESCRIPTION);
							/* DOGFOOT ktkang KERIS 보고서 폴더 보기에서 쿼리때문에 너무 느려서 뺌  20200130 */
//							$('#reportQuerySql').val(item.QUERY);
							selectedPublicReportId = item.ID;
						} else if (item.TYPE === 'FOLDER') {
							$('#reportId').text('');
							$('#reportDataLoad').prop('checked', false);
							$('#reportTitle').val('');
							$('#reportSubtitle').val('');
							$('#reportType').text('');
							/*dogfoot 보고서 관리 폴더 저장 기능 추가 shlim 20201117*/
							$('#reportFolder').val('');
							$('#reportFolder').removeAttr("UPPERID");
							$('#publisherName').text('');
							$('#publishedDate').text('');
							$('#reportTag').val('');
							$('#reportOrder').val('');
							$('#reportDesc').val('');
							/* DOGFOOT ktkang KERIS 보고서 폴더 보기에서 쿼리때문에 너무 느려서 뺌  20200130 */
//							$('#reportQuerySql').val('');
							selectedPublicReportId = undefined;
						}
					},
					onContentReady: function() {
						gDashboard.fontManager.setFontConfigForList('reportList')
						gProgressbar.hide();
					},
					onInitialized: function(e) {
						$('.panel-head').on('click', function() {
							if ($(this).find('.select-category').data('category') === 'repfol-report') {
								e.component.updateDimensions();
								initReportLayout();
							}
						});
					}
				});
				/*dogfoot 보고서 관리 폴더 드래그 이동 기능 추가 dev20 에서만 동작 shlim 20201117*/
				function createSortable(selector, driveName) {
				    $(selector).dxSortable({
				        filter: ".dx-treeview-item",
				        group: "shared",
				        data: driveName,
				        allowDropInsideItem: true,
				        allowReordering: true,
				        onDragChange: function(e) {
				            if(e.fromComponent === e.toComponent) {
				                var $nodes = e.element.find(".dx-treeview-node");
				                var isDragIntoChild = $nodes.eq(e.fromIndex).find($nodes.eq(e.toIndex)).length > 0;
				                if(isDragIntoChild) {
				                    e.cancel = true;
				                }
				            }
				        },
				        onDragEnd: function(e) {
				            if(e.fromComponent === e.toComponent && e.fromIndex === e.toIndex) {
				                return;
				            }
				            
				            var fromTreeView = getTreeView(e.fromData);
				            var toTreeView = getTreeView(e.toData);

				            var fromNode = findNode(fromTreeView, e.fromIndex);
				            var toNode = findNode(toTreeView, calculateToIndex(e));
                            

				            if(fromNode.itemData.TYPE == "FOLDER"){
                            	return;
                            }

				            if(e.dropInsideItem && toNode !== null && !(toNode.itemData.TYPE == "FOLDER")) {
				                return;
				            }

				            selectedPublicReportId = fromNode.itemData.ID;

				            var fromTopVisibleNode = getTopVisibleNode(fromTreeView);
				            var toTopVisibleNode = getTopVisibleNode(toTreeView);

				            var fromItems = fromTreeView.option('items');
				            var toItems = toTreeView.option('items');
				            moveNode(fromNode, toNode, fromItems, toItems, e.dropInsideItem);

				            fromTreeView.option("items", fromItems);
				            toTreeView.option("items", toItems);
				            fromTreeView.scrollToItem(fromTopVisibleNode);
				            toTreeView.scrollToItem(selectedPublicReportId);

				            if(selectedPublicReportId){
                                $('#reportList').dxTreeView('instance').selectItem(fromNode.itemData.ID)
                                
                                $('#reportId').text(fromNode.itemData.ID);
								$('#reportDataLoad').prop('checked', fromNode.itemData.PROMPT === 'Y');
								$('#reportTitle').val(fromNode.itemData.TEXT);
								$('#reportSubtitle').val(fromNode.itemData.SUBTITLE);
								$('#reportType').text(fromNode.itemData.REPORT_TYPE);
								/*dogfoot 보고서 관리 폴더 저장 기능 추가 shlim 20201117*/
								const folderString = toNode.itemData.TYPE === "FOLDER" ? toNode.itemData.TEXT :
													toNode.parent != null ? toNode.parent.text : ""
								$('#reportFolder').val(folderString);
								$('#reportFolder').attr("UPPERID",fromNode.itemData.UPPERID);
								$('#publisherName').text(fromNode.itemData.CREATED_BY);
								$('#publishedDate').text(fromNode.itemData.CREATED_DATE);
								$('#reportTag').val(fromNode.itemData.TAG);
								$('#reportOrder').val(fromNode.itemData.ORDINAL);
								$('#reportDesc').val(fromNode.itemData.DESCRIPTION);
								
								gProgressbar.show();
								$.ajax({
									url: WISE.Constants.context + '/report/savePublicReport.do',
									method: 'POST',
									data: { 
										ID: selectedPublicReportId,
										PROMPT: $('#reportDataLoad').prop('checked') ? 'Y' : 'N',
										TEXT: $('#reportTitle').val(),
										SUBTITLE: $('#reportSubtitle').val(),
										TAG: $('#reportTag').val(),
										ORDINAL: $('#reportOrder').val(),
										/*dogfoot 보고서 관리 폴더 저장 기능 추가 shlim 20201117*/
										DESCRIPTION: $('#reportDesc').val(),
										FLD_ID: parseInt($("#reportFolder").attr("UPPERID")),
									},
									success: function() {
										gProgressbar.hide();
									},
									error: function() {
										//2020.01.21 mksong 경고창 타입 지정 dogfoot
										WISE.alert(gMessage.get('config.save.failed'),'error');
									}
								});
				            }
				        }
				    });
				}

				function getTreeView(driveName) {
				    return  $('#reportList').dxTreeView('instance');
				}

				function calculateToIndex(e) {
				    if(e.fromComponent != e.toComponent || e.dropInsideItem) {
				        return e.toIndex;
				    }

				    return e.fromIndex >= e.toIndex
				        ? e.toIndex
				        : e.toIndex + 1;
				}

				function findNode(treeView, index) {
				    var nodeElement = treeView.element().find('.dx-treeview-node')[index];
				    if(nodeElement) {
				        return findNodeById(treeView.getNodes(), nodeElement.getAttribute('data-item-id'));
				    }
				    return null;
				}
				/*dogfoot 환경설정 보고서 관리 폴더,보고서 Key 중복 오류 수정 shlim 20210217*/
				function findNodeById(nodes, id) {
				    for(var i = 0; i < nodes.length; i++) {
				        if(nodes[i].itemData.ID == id.toString().replace(/F_/gi,"")) {
				            return nodes[i];
				        }
				        if(nodes[i].children) {
				            var node = findNodeById(nodes[i].children, id.toString().replace(/F_/gi,""));
				            if(node != null) {
				                return node;
				            }
				        }
				    }
				    return null;
				}

				function moveNode(fromNode, toNode, fromItems, toItems, isDropInsideItem) {
				    var fromIndex = findIndex(fromItems, fromNode.itemData.ID);
				    fromItems.splice(fromIndex, 1);

				    var toIndex = toNode === null || isDropInsideItem
				        ? toItems.length
				        : findIndex(toItems, toNode.itemData.ID);
				    toItems.splice(toIndex, 0, fromNode.itemData);

				    moveChildren(fromNode, fromItems, toItems);
				    if(isDropInsideItem) {
				        fromNode.itemData.UPPERID = toNode.itemData.ID;
				        fromNode.itemData.upperKey = toNode.itemData.uniqueKey;
				    } else {
				        fromNode.itemData.UPPERID = toNode != null
				            ? toNode.itemData.UPPERID
				            : undefined;

				        fromNode.itemData.upperKey = toNode != null
				            ? toNode.itemData.upperKey
				            : undefined;
				    }
				}

				function moveChildren(node, fromItems, toItems) {
				    if(!(node.itemData.TYPE == "FOLDER")) {
				        return;
				    }

				    node.children.forEach(function(child) {
				        if((child.itemData.TYPE == "FOLDER")) {
				            moveChildren(child, fromItems, toItems);
				        }

				        var fromIndex = findIndex(fromItems, child.itemData.ID);
				        fromItems.splice(fromIndex, 1);
				        toItems.splice(toItems.length, 0, child.itemData);
				    });
				}

				function findIndex(array, id) {
				    var idsArray = array.map(function(elem) { return elem.ID; });
				    return idsArray.indexOf(parseInt(id.toString().replace(/F_/gi,"")));
				}

				function getTopVisibleNode(component) {
				    var treeViewElement = component.element().get(0);
				    var treeViewTopPosition = treeViewElement.getBoundingClientRect().top;
				    var nodes = treeViewElement.querySelectorAll(".dx-treeview-node");
				    for(var i = 0; i < nodes.length; i++) {
				        var nodeTopPosition = nodes[i].getBoundingClientRect().top;
				        if(nodeTopPosition >= treeViewTopPosition) {
				            return nodes[i];
				        }
				    }

				    return null;
				}
				
				createSortable('#reportList', 'reportList');
				
				/*dogfoot 보고서 관리 폴더 저장 기능 추가 shlim 20201117*/
				var folderSelect;
            	if(userJsonObject.selectCubeId) {
            		folderSelect = [
	        			{
	        				text:"개인폴더",
	        				value:"MY"
	        			}
	        		];
            	} else {
            		folderSelect = [
	        			{
	        				text:"공용폴더",
	        				value:"PUBLIC"
	        			}
	        		];
            	}
            	var folder_type;
            	folder_type = folderSelect[0];
//				$('#report_folder_type').dxRadioGroup({
//            		dataSource:folderSelect,
//            		layout: "horizontal",
//            		value:folder_type
//        		});
				
				$('#findFolder').dxButton({
					icon:'search',
					onClick:function(){
						if (!selectedPublicReportId) {
							return;
						}
						$('#save_box').append("<div id='selectFolder'></div>");
//						if(typeof  $('#report_folder_type').dxRadioGroup('instance').option('value').value == 'undefined'){
//							return;
//						}
						var folderhtml = "<div class=\"modal-body\" style='height:87%'>\r\n" + 
						"                        <div class=\"row\" style='height:100%'>\r\n" + 
						"                            <div class=\"column\" style='width:100%'>\r\n" + 
						"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
						"                                   <div class=\"modal-tit\">\r\n" + 
						"                                   <span>폴더 목록</span>\r\n";
						folderhtml += "                                   </div>\r\n" +
						"									<div id=\"folder_tree\" />\r\n" + 
						"                                </div>\r\n" +
						"                            </div>\r\n" + 
						"                        </div>\r\n" + // row 끝
						"                    </div>\r\n" + // modal-body 끝
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
								var fld_type = folderSelect[0];
								var param = {};
								param['fld_type'] = fld_type.value
								var param = {
										'user_id' : userJsonObject.userId,
										'fld_type' : fld_type.value
								};
								$.ajax({
									method : 'POST',
									url: WISE.Constants.context + '/report/getFolderList.do',
									dataType: "json",
									data:param,
									/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//									async:false,
									success: function(result) {
										var datasource = result.data;
										var selectFLDNm ;
										var selectFLDId ;
										$('#folder_tree').dxTreeView({
											dataSource:datasource,
											dataStructure:'plain',
											keyExpr: "FLD_ID",
											parentIdExpr: "PARENT_FLD_ID",
											displayExpr: "FLD_NM",
											searchEnabled: true,
											searchMode : "contains",
											searchTimeout:undefined,
											searchValue:"",
											noDataText:"조회된 보고서가 없습니다.",
											height:"460",
											showCloseButton: false,
											onItemClick:function(_e){
												selectFLDNm = _e.itemData['FLD_NM'];
												selectFLDId = _e.itemData['FLD_ID'];
											},
											onContentReady: function(){
												gDashboard.fontManager.setFontConfigForListPopup('folder_tree')
											}
										});
										$('#folder_ok').dxButton({
											type:'default',
											text:'확인',
											onClick:function(){
												if(selectFLDNm != "" && selectFLDId != ""){
											        $('#reportFolder').val(selectFLDNm);
													$('#reportFolder').attr("UPPERID",selectFLDId);
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
			}
		});
		$('#deleteReportPopup').dxPopup({
			title: '보고서 삭제',
			width: 500,
			height: 'auto',
			contentTemplate: function(e) {
				var html = 	'<p id="reportDeleteConfirmText">' + gMessage.get('config.delete.confirm') + '</p>' +
							'<div class="row center popup-footer">' +
								'<a href="#" class="btn positive report-delete-ok">확인</a>' +
								'<a href="#" class="btn neutral report-delete-cancel">취소</a>' +
							'</div>';
				e.append(html);
			},
			onContentReady: function(e) {
				$('.report-delete-ok').on('click', function() {
					e.component.hide();
				});
				$('.report-delete-cancel').on('click', function() {
					e.component.hide();
				});
			}
		});
	}

	/**
	 * Initialize functions for folder page.
	 */
	function initFolderLayout() {
		/*dogfoot shlim 20210414*/
		preSelectedPublicFolderNode=[],selectedPublicFolderNode = undefined;
		var selectFLDNm,selectFLDId,selectedItem ;
		/*dogfoot 폴더 리스트 재활용을 위한 함수화 shlim 20210413*/
		function getPublicReportListF(_fieldname) {
			return $.ajax({
				url: WISE.Constants.context + '/report/getPublicFolderList.do',
				method: 'GET',
				async: false,
				dataType: "json",
				success: function(result) {
						$.each(result, function(_i,_items) {
							_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
						});
						$('#'+_fieldname).dxTreeView({
							dataSource: result,
							dataStructure: 'plain',
							keyExpr: "FLD_ID",
							parentIdExpr: "PARENT_FLD_ID",
							displayExpr: "FLD_NM",
							// mksong 2019.12.20 보고서 검색 추가 dogfoot
							searchEnabled: true,
							searchMode : "contains",
							searchTimeout:undefined,
							searchValue:"",
							showCloseButton: false,
							selectionMode: 'single',
							selectNodesRecursive: false,
							focusStateEnabled: false,
							onItemClick:function(_e) {
								var node = _e.node;
								if (node.selected) {
									_e.component.unselectItem(node.key);
									selectedPublicFolderNode = undefined;
								} else {
									_e.component.selectItem(node.key);
									selectedPublicFolderNode = node;
								}
								selectFLDNm = _e.itemData['FLD_NM'];
								selectFLDId = _e.itemData['FLD_ID'];
								selectedItem = _e
							},
							onContentReady: function() {
								gDashboard.fontManager.setFontConfigForList('folderList')
								gProgressbar.hide();
							},
							onInitialized: function(e) {
								$('.panel-head').on('click', function() {
									if ($(this).find('.select-category').data('category') === 'repfol-folder') {
										e.component.updateDimensions();
									}
								});
							}
						});
					}
				});
		}
		getPublicReportListF("folderList");
		$('#folderNamePopup').dxPopup({
			title: '이름 편집',
			width: 500,
			height: 'auto',
			contentTemplate: function(e) {
				
				var html = "<div class=\"modal-body\" style='height:88%'>\r\n" +
					"                        <div class=\"row\" style='height:88%'>\r\n" +
					"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" +
					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
					"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
					"                                   	<span>폴더 명</span>\r\n" +
					"                                   </div>\r\n" +
					"									<div style='text-align: right;'>\r\n"+
					"										<div id=\"folder_name\" class=\"wise-text-input folder-name-edit\"></div>\r\n" +
					"									</div>\r\n"+
					"                                </div>\r\n" +
					"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
					"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
					"                                   	<span>저장 위치</span>\r\n" +
					"                                   </div>\r\n" +
					"								 <div id=\"folder_name_locate\" style=\"float:left; margin-right: 5px\"></div><div id=\"change_folder_config\" style=\"display: inline-block;\"></div>\r\n" +
					"                            </div>\r\n" +
					"                        </div>\r\n" + 
					"                    </div>\r\n" + 
					"					 <div id='save_box_folder' style='text-align: center;'/>"+
					"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
					"                        <div class=\"row center\">\r\n" +
					"							<a href=\"#\" class=\"btn positive folder-edit-ok\">확인</a>\r\n" +
					"							<a href=\"#\" class=\"btn neutral folder-edit-cancel\">취소</a>\r\n" +
					"                        </div>\r\n" +
					"                    </div>\r\n" +
					"                </div>";
					"         </div>";
				
//				var html = 	'<div class="tbl data-form">' +
//								'<table>' +
//									'<colgroup class="folder-name-col">' +
//										'<col style="width: auto">' +
//									'</colgroup>' +
//									'<tbody>' +
//										'<tr>' +
//											'<th>폴더 이름</th>' +
//											'<td class="ipt">' +
//												'<input class="wise-text-input folder-name-edit" type="text">' +
//											'</td>' +
//										'</tr>' +
//										'<tr>' +
//											'<th>폴더 이름</th>' +
//											'<td class="ipt">' +
//												'<input class="wise-text-input folder-name-edit" type="text">' +
//											'</td>' +
//										'</tr>' +
//									'</tbody>' +
//								'</table>' +
//							'</div>' +
//							'<div class="row center popup-footer">' +
//								'<a href="#" class="btn positive folder-edit-ok">확인</a>' +
//								'<a href="#" class="btn neutral folder-edit-cancel">취소</a>' +
//							'</div>';
				e.append(html);
			},
			onContentReady: function(e) {
				
				var title = $('#folder_name').dxTextBox({
					value: ""
            	}).dxTextBox('instance');
				
				var folderName = $('#folder_name_locate').dxTextBox({
            		readOnly: true,
            		width: "calc(100% - 40px)"
            	}).dxTextBox('instance');

            	var changeFolder = $('#change_folder_config').dxButton({
            		icon: "search",
            		width: "35px",
            		onClick: function(e) {
            			$('#save_box_folder').append("<div id='selectFolder_config'></div>");
    					var folderhtml = "<div class=\"modal-body\" style='height:87%'>\r\n" +
    					"                        <div class=\"row\" style='height:100%'>\r\n" +
    					"                            <div class=\"column\" style='width:100%'>\r\n" +
    					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
    					"                                   <div class=\"modal-tit\">\r\n" +
    					"                                   <span>폴더 목록</span>\r\n";
    					folderhtml += "                                   </div>\r\n" +
    					"									<div id=\"folder_tree\" />\r\n" +
    					"                                </div>\r\n" +
    					"                            </div>\r\n" +
    					"                        </div>\r\n" + // row 끝
    					"                    </div>\r\n" + // modal-body 끝
    					"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
    					"                        <div class=\"row center\">\r\n" +
    					"                            <a id=\"folder_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" +
    					"                            <a id=\"folder_cancel\" class=\"btn neutral close\" href=\"#\">취소</a>\r\n" +
    					"                        </div>\r\n" +
    					"                    </div>\r\n" +
    					"                </div>";
            			$('#selectFolder_config').dxPopup({
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
            					getPublicReportListF("folder_tree");
								/* 2021-07-08 jhseo 폴더팝업의 크기가 달라서 제대로 맞춰주려면 450px로 가야함*/
		            			$('#folder_tree').css('height','450px');
            					
            					preSelectedPublicFolderNode.push(selectedPublicFolderNode);
            					$('#folder_ok').dxButton({
				            		type:'default',
				            		text:'확인',
				            		onClick:function(){
				            			var getAllFldNm = function(node, check){
				            				if(check === 0 && node.parent === null){
				            					return node.itemData.FLD_NM;
				            				}else if(node.parent === null){
				            					return node.itemData.FLD_NM+" > ";
				            				}else if(check === 0){
				            					return getAllFldNm(node.parent, 1) + node.itemData.FLD_NM
				            				}
				            				else{
				            					return getAllFldNm(node.parent, 1) + node.itemData.FLD_NM + " > ";
				            				}
				            			}

				            			if(selectedPublicFolderNode){
                                            if(selectedPublicFolderNode.text != "" && selectedPublicFolderNode.key != ""){
												$('#folder_name_locate').dxTextBox('instance').option('value', getAllFldNm(selectedPublicFolderNode, 0));
												$('#folder_name_locate').dxTextBox('instance').option('fld_id',selectedPublicFolderNode.text);
												$('#folder_name_locate').dxTextBox('instance').option('fld_nm',selectedPublicFolderNode.key);
												$('#selectFolder_config').dxPopup('instance').hide();
												$('#selectFolder_config').remove();
											}	
                                        }
				            		}
		            			});
		            			$('#folder_cancel').dxButton({
		            				type:'danger',
		                    		text:'취소',
		                    		onClick:function(){
		                    			selectedPublicFolderNode = preSelectedPublicFolderNode[0];
		                    			preSelectedPublicFolderNode=[];
		                    			$('#selectFolder_config').dxPopup('instance').hide();
			            				$('#selectFolder_config').remove();
				            		}
		            			});
        						
            				}
            			});
                    }
            	})
				
				$('.folder-edit-ok').on('click', function() {
					e.component.hide();
				});
				$('.folder-edit-cancel').on('click', function() {
					e.component.hide();
				});
			}
		});
		$('#deleteFolderPopup').dxPopup({
			title: '폴더 삭제',
			width: 500,
			height: 'auto',
			contentTemplate: function(e) {
				var html = 	'<p id="deleteConfirmText"></p>' +
							'<div class="row center popup-footer">' +
								'<a href="#" class="btn positive folder-delete-ok">확인</a>' +
								'<a href="#" class="btn neutral folder-delete-cancel">취소</a>' +
							'</div>';
				e.append(html);
			},
			onContentReady: function(e) {
				$('.folder-delete-ok').on('click', function() {
					e.component.hide();
				});
				$('.folder-delete-cancel').on('click', function() {
					e.component.hide();
				});
			}
		});
	}

	/**
	 * Return a list of all folders in parent folder, including the parent folder itself.
	 * @param {dxTreeViewNode} folderNode
	 * @returns {number[]}
	 */
	function getFolderStructure(folderNode) {
		var list = [];
		if (!folderNode) {
			return list;
		} if (folderNode.children.length > 0) {
			list.push(folderNode.key);
			folderNode.children.forEach(function(child) {
				var secondChildrenIds = getFolderStructure(child);
				list = list.concat(secondChildrenIds);
			});
			return list;
		} else {
			return [folderNode.key];
		}
	}

	/* public variables and methods */
	return {
		/**
		 * Initialize report & folder pages.
		 */
		initReportFolder: function() {	
			initReportLayout();
			initFolderLayout();
		},

		/**
		 * Refresh contents of report page.
		 * @listens click
		 */
		handlePublicReportRefresh: function() {
			$.ajax({
				url: WISE.Constants.context + '/report/getPublicReportList.do',
				dataType: "json",
				method: 'GET',
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(result) {
					$.each(result, function(_i,_items) {
						switch (_items.TYPE) {
							case 'REPORT':
								if (_items.REPORT_TYPE == 'DashAny') {
									_items.icon = WISE.Constants.context + '/resources/main/images/ico_squariFied.png';
								}else if (_items.REPORT_TYPE == 'AdHoc') {
									_items.icon = WISE.Constants.context + '/resources/main/images/ico_atypical01.png';	            						
								} else if (_items.REPORT_TYPE === 'Spread' || _items.REPORT_TYPE === 'Excel') {
									_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msexcell.png';
								} else if (_items.REPORT_TYPE === 'Word' || _items.REPORT_TYPE === 'WordGrp') {
									_items.icon = WISE.Constants.context + '/resources/main/images/ico_ept_msword.png';
								}
								break;
							case 'FOLDER':
								_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
								break;
							default: break;
						}
					});
					$('#reportList').dxTreeView('instance').option('dataSource', result);
					$('#reportId').text('');
					$('#reportDataLoad').prop('checked', false);
					$('#reportTitle').val('');
					$('#reportSubtitle').val('');
					$('#reportType').text('');
					/*dogfoot 보고서 관리 폴더 저장 기능 추가 shlim 20201117*/
					$('#reportFolder').val('');
					$('#reportFolder').removeAttr("UPPERID");
					$('#publisherName').text('');
					$('#publishedDate').text('');
					$('#reportTag').val('');
					$('#reportDesc').val('');
					/* DOGFOOT ktkang KERIS 보고서 폴더 보기에서 쿼리때문에 너무 느려서 뺌  20200130 */
//					$('#reportQuerySql').val('');
					/*dogfoot 보고서 관리 폴더 저장 기능 추가 dev 20.2 버전에서만 작동 shlim 20201117*/
					//$('#reportList').dxTreeView('instance').scrollToItem(selectedPublicReportId);
					selectedPublicReportId = undefined;
				}
			});
		},

		/**
		 * Save changes made to selected report.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handlePublicReportSave: function(event) {
			event.preventDefault();
			if (selectedPublicReportId) {
				$.ajax({
					url: WISE.Constants.context + '/report/savePublicReport.do',
					method: 'POST',
					data: { 
						ID: selectedPublicReportId,
						PROMPT: $('#reportDataLoad').prop('checked') ? 'Y' : 'N',
						TEXT: $('#reportTitle').val(),
						SUBTITLE: $('#reportSubtitle').val(),
						TAG: $('#reportTag').val(),
						ORDINAL: $('#reportOrder').val(),
						/*dogfoot 보고서 관리 폴더 저장 기능 추가 shlim 20201117*/
						DESCRIPTION: $('#reportDesc').val(),
						FLD_ID:$("#reportFolder").attr("UPPERID"),
					},
					success: function() {
						reportFolderManager.handlePublicReportRefresh();
						//2020.01.21 mksong 경고창 타입 지정 dogfoot
						WISE.alert(gMessage.get('config.save.success'),'success');
					},
					error: function() {
						//2020.01.21 mksong 경고창 타입 지정 dogfoot
						WISE.alert(gMessage.get('config.save.failed'),'error');
					}
				});
			}
		},

		/**
		 * Deletes selected report from database.
		 * @param {MouseEvent} event 
		 * @listens click
		 */
		handlePublicReportDelete: function(event) {
			event.preventDefault();
			if (selectedPublicReportId) {
				$('#deleteReportPopup').dxPopup('instance').show();
				$('.report-delete-ok').off('click').on('click', function() {
					$.ajax({
						url: WISE.Constants.context + '/report/deletePublicReport.do',
						method: 'POST',
						data: { id: selectedPublicReportId },
						beforeSend: function() {
							$('#deleteReportPopup').dxPopup('instance').hide();
						},
						success: function() {
							reportFolderManager.handlePublicReportRefresh();
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.delete.success'),'success');
						},
						error: function(error) {
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.delete.failed'),'error');
						}
					});
				});
			}
		},

		/**
		 * Refresh contents of folder page.
		 * @listens click
		 */
		handlePublicFolderRefresh: function() {
			gProgressbar.show();
			$.ajax({
				url: WISE.Constants.context + '/report/getPublicFolderList.do',
				method: 'GET',
				dataType: "json",
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(result) {
					$.each(result, function(_i,_items) {
						_items.icon = WISE.Constants.context + '/resources/main/images/ico_load.png';
					});
					$('#folderList').dxTreeView('instance').option('dataSource', result);
					selectedPublicFolderNode = undefined;
					gProgressbar.hide();
				}
			});
		},

		/**
		 * Create a new folder in parent. If a folder is selected, 
		 * create a new folder as child of selected folder. 
		 * @param {MouseEvent} event
		 * @listens click 
		 */
		handlePublicFolderCreate: function(event) {
			event.preventDefault();
			$('#folderNamePopup').dxPopup('instance').show();
//			$('.folder-name-edit').val('');
			$('#folder_name').dxTextBox("instance").option("value","");
			var getAllFldNm = function(node, check){
				if(check === 0 && node.parent === null){
					return node.itemData.FLD_NM;
				}else if(node.parent === null){
					return node.itemData.FLD_NM+" > ";
				}else if(check === 0){
					return getAllFldNm(node.parent, 1) + node.itemData.FLD_NM
				}
				else{
					return getAllFldNm(node.parent, 1) + node.itemData.FLD_NM + " > ";
				}
			}
			$('#folder_name_locate').dxTextBox("instance").option("value",
			    selectedPublicFolderNode ? getAllFldNm(selectedPublicFolderNode,0) : ""
			);
			$('.folder-edit-ok').off('click').on('click', function() {
//				var folderName = $('.folder-name-edit').val();
				var folderName = $('#folder_name').dxTextBox("instance").option("value");
				if (folderName.length > 0) {
					$.ajax({
						url: WISE.Constants.context + '/report/createNewPublicFolder.do',
						method: 'POST',
						data: {
							name: folderName,
							parentFolder: selectedPublicFolderNode ? selectedPublicFolderNode.itemData.FLD_ID : 0,
						},
						success: function(msg) {
							if (msg) {
								WISE.alert(msg);
							} else {
								$('#folderNamePopup').dxPopup('instance').hide();
								reportFolderManager.handlePublicFolderRefresh();
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.save.success'),'success');
							}
						},
						error: function() {
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.save.failed'),'error');
						}
					});
				} else {
					WISE.alert(gMessage.get('config.folder.name.isnull'));
				}
			});
		},

		/**
		 * Edit the name of an existing folder.
		 * @param {MouseEvent} event
		 * @listens click 
		 */
		handlePublicFolderEdit: function(event) {
			event.preventDefault();
			if (selectedPublicFolderNode) {
				$('#folderNamePopup').dxPopup('instance').show();
//				$('.folder-name-edit').val(selectedPublicFolderNode.itemData.FLD_NM);
				$('#folder_name').dxTextBox("instance").option("value",selectedPublicFolderNode.itemData.FLD_NM);
				var getAllFldNm = function(node, check){
					if(check === 0 && node.parent === null){
						return node.itemData.FLD_NM;
					}else if(node.parent === null){
						return node.itemData.FLD_NM+" > ";
					}else if(check === 0){
						return getAllFldNm(node.parent, 1) + node.itemData.FLD_NM
					}
					else{
						return getAllFldNm(node.parent, 1) + node.itemData.FLD_NM + " > ";
					}
				}

				$('#folder_name_locate').dxTextBox("instance").option("value",
				    selectedPublicFolderNode.parent ? getAllFldNm(selectedPublicFolderNode.parent,0) : ""
				);
				preSelectedPublicFolderNode=[];
				$('.folder-edit-ok').off('click').on('click', function() {
//					var folderName = $('.folder-name-edit').val();
					var folderName = $('#folder_name').dxTextBox("instance").option("value");
					if (folderName.length > 0) {
						$.ajax({
							url: WISE.Constants.context + '/report/editPublicFolderName.do',
							method: 'POST',
							data: {
								id: preSelectedPublicFolderNode[0] ? preSelectedPublicFolderNode[0].itemData.FLD_ID : selectedPublicFolderNode.itemData.FLD_ID,
								name: folderName,
								originalName: preSelectedPublicFolderNode[0] ? preSelectedPublicFolderNode[0].itemData.FLD_NM : selectedPublicFolderNode.itemData.FLDNM,
								parentId: preSelectedPublicFolderNode[0] ? selectedPublicFolderNode.itemData.FLD_ID : selectedPublicFolderNode.itemData.PARENT_FLD_ID,
							},
							success: function(msg) {
								if (msg) {
									WISE.alert(msg);
								} else {
									$('#folderNamePopup').dxPopup('instance').hide();
									reportFolderManager.handlePublicFolderRefresh();
									//2020.01.21 mksong 경고창 타입 지정 dogfoot
									WISE.alert(gMessage.get('config.folder.name.change.success'),'success');
								}
							},
							error: function() {
								//2020.01.21 mksong 경고창 타입 지정 dogfoot
								WISE.alert(gMessage.get('config.folder.name.change.failed'),'error');
							}
						});
					} else {
						WISE.alert(gMessage.get('config.folder.name.isnull'));
					}
				});
			}
		},

		/**
		 * Delete a folder from the database. If folder contains items
		 * such as reports and other folders, recursively delete
		 * all items in the folder.
		 * @param {MouseEvent} event
		 * @listens click 
		 */
		handlePublicFolderDelete: function(event) {
			event.preventDefault();
			if (selectedPublicFolderNode) {
				$('#deleteFolderPopup').dxPopup('instance').show();
				var folderList = getFolderStructure(selectedPublicFolderNode);

				if (selectedPublicFolderNode.children.length > 0) {
					$('#deleteConfirmText').text(gMessage.get('config.folder.multiple-folder-delete'));
				} else {
					$('#deleteConfirmText').text(gMessage.get('config.delete.confirm'));
				}
				$('.folder-delete-ok').off('click').on('click', function() {
					$.ajax({
						url: WISE.Constants.context + '/report/nestedReportsExist.do',
						method: 'POST',
						data: {folders: folderList},
						beforeSend: function() {
							$('#deleteFolderPopup').dxPopup('instance').hide();
						},
						success: function(exists) {
							if (exists === 'Y') {
								$('#deleteFolderPopup').dxPopup('instance').show();
								$('#deleteConfirmText').text(gMessage.get('config.folder.multiple-report-delete'));
								$('.folder-delete-ok').off('click').on('click', function() {
									$.ajax({
										url: WISE.Constants.context + '/report/deleteSelectedFoldersAndReports.do',
										method: 'POST',
										data: {
											parent: selectedPublicFolderNode.key,
											folders: folderList
										},
										beforeSend: function() {
											$('#deleteFolderPopup').dxPopup('instance').hide();
										},
										success: function() {
											//2020.01.21 mksong 경고창 타입 지정 dogfoot
											WISE.alert(gMessage.get('config.delete.success'),'success');
											reportFolderManager.handlePublicFolderRefresh();
										},
										error: function() {
											//2020.01.21 mksong 경고창 타입 지정 dogfoot
											WISE.alert(gMessage.get('config.delete.failed'),'error');
										}
									});
								});
							} else {
								$.ajax({
									url: WISE.Constants.context + '/report/deleteSelectedFolders.do',
									method: 'POST',
									data: {
										parent: selectedPublicFolderNode.key,
										folders: folderList
									},
									success: function() {
										//2020.01.21 mksong 경고창 타입 지정 dogfoot
										WISE.alert(gMessage.get('config.delete.success'),'success');
										reportFolderManager.handlePublicFolderRefresh();
									},
									error: function() {
										//2020.01.21 mksong 경고창 타입 지정 dogfoot
										WISE.alert(gMessage.get('config.delete.failed'),'error');
									}
								});
							}
						},
						error: function() {
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert(gMessage.get('config.delete.failed'),'error');
						}
					});
				});
			}
		}
	};
})();