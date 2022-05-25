/**
 *
 */
WISE.libs.ReportUtility = function() {
	var self = this;

	this.dashboardid;
	this.reportInfo;
	this.itemordering = 1;
	this.nullDataCon = false;
	this.dsUtility = WISE.libs.Dashboard.item.DatasetUtility;

	this.init = function(_structure){
		//20210313 AJKIM reportInfo 얕은 복사 -> 깊은 복사로 변경 dogfoot
		if(_structure != null)
			self.reportInfo = $.extend({}, _structure);
		else{
			self.reportInfo = self.initNewReport();
		}
	};

	this.activeButton = function(){
		$('.saveReport').off('click');
		$('#openReport').off('click');
		$('#saveReportAs').off('click');
		/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
		$('.restoreReport').off('click');
		$('#restoreReportAs').off('click');
		// ymbin : 레포트 속성
		$('#reportProperty').off('click');
		/* DOGFOOT ktkang 직접 경로 뷰어 기능 추가  20201014 */
		$('#reportProperty2').off('click');

		$('#reportHistory').off('click');

		/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
		$('#queryView').off('click');


		$('.saveReport').click(function(){
			self.saveReport("true");
		});
		$('#openReport').click(function(){
			self.openReport();
		});
		/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
		$('#load_dataset_viewer').click(function(){
			gDashboard.datasetMaster.openDataset();
		});
		$('#saveReportAs').click(function(){
			self.saveReport("false");
		});
		$('#addLinkedReport').click(function(){
			if(!gDashboard.isNewReport) {
				self.addLinkedReport(false);
			} else {
				// 2020.01.07 mksong 경고창 UI 변경 dogfoot
				WISE.alert("보고서를 저장 한 후 연결보고서를 등록 할 수 있습니다.",'error');
			}
		});
		// ymbin : 레포트 속성
		$('#reportProperty').click(function(){
			self.reportProperty();
		});

		/* DOGFOOT ktkang 직접 경로 뷰어 기능 추가  20201014 */
		$('#reportProperty2').click(function(){
			self.reportProperty();
		});

		$('#reportHistory').click(function(){
			self.reportHistory();
		});

		$('.restoreReport').click(function(){
			self.restoreReport(false);
		});

		$('#restoreReportAs').click(function(){
			self.restoreReport(true);
		});
		/* DOGFOOT syjin 보고서 레이아웃 설정  20200814 */
//		$('#reportSetting').click(function(){
//			self.reportSetting();
//		});
		/* DOGFOOT shlim 보고서 레이아웃 설정 재 구현  20200820 */
		$('#reportSetting').click(function(){
			gDashboard.reportLayoutManager.reportSetting('reportset');
		});

		/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
		$('#queryView').click(function(){
			self.queryView();
		});

		/* DOGFOOT ktkang 보고서 삭제 기능 추가  20200214 */
		$('#deleteReport').click(function(){
			self.deleteReport();
		});

		$('#newReport').click(function(e){
			e.preventDefault();
			self.newReport();
		});

	};

	this.newReport = function(){
		// 2019.12.10 수정자 : mksong 새로만들기 메세지 수정 DOGFOOT
		/*dogfoot 알림창 형식 변경 shlim 20200717*/
		var options = {
				buttons: {
					confirm: {
						id: 'confirm',
						className: 'blue',
						text: '확인',
						action: function() {
							/* DOGFOOT ktkang KERIS 큐브로 연보고서 새로만들기 하면 reload  20200219 */
							if(userJsonObject.selectCubeId){
								location.reload();
							}
							else if(gDashboard.reportType == 'AdHoc') {
								var url = window.location.href;
								url = url.substring(0, url.lastIndexOf('/') + 1);
								var frm = document.mainAdhocName;
								frm.action = url + 'edit.do';
								frm.target = "oldPage";
								frm.submit();
							} else if(gDashboard.reportType == 'DashAny'){
								var url = window.location.href;
								window.location.replace(url.substring(0, url.lastIndexOf('/') + 1) + 'edit.do');
							} else {
								window.location.reload(true);
							}
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

		WISE.confirm('현재 저장되지 않은 작업 내용은 모두 소멸됩니다. 새로 만들기를 계속 진행하시겠습니까?', options);

	}
	/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
	this.queryView = function(){
		var html = "<div class=\"modal-body\" style='height:93%'>\r\n" +
		"                        <div class=\"row\" style='height:100%'>\r\n" +
		"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top: 5px;height:100%;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>쿼리보기</span>\r\n" +
		"								 		<div id=\"itemSelect\" style=\"float:right;\"></div>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"queryArea\" style=\"height:95%;\"></div>\r\n" +
		"                                </div>\r\n" +
		"                            </div>\r\n" +
		"                        </div>\r\n" + // row 끝
		"                    </div>\r\n" + // modal-body 끝
		"					 <div id='save_box' style='text-align: center;'/>"+
		"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
		"                        <div class=\"row center\">\r\n" +
		"                            <a id=\"ok_query_button\" class=\"btn positive ok-hide\">확인</a>\r\n" +
		"                            <a id=\"cancel_query_button\" class=\"btn neutral ok-hide\">취소</a>\r\n" +
		"                        </div>\r\n" +
		"                    </div>\r\n" +
		"                </div>";

		if($('#queryViewPopup').length == 0){
			$('body').append("<div id='queryViewPopup'></div>");
		}

		var page = window.location.pathname.split('/');
		var isViewer = page[page.length - 1] === 'viewer.do' ? true : false;
		$('#queryViewPopup').dxPopup({
			title:'쿼리보기',
			/*dogfoot 쿼리보기 text 뷰로 변경 shlim 20201130*/
			width:'1000px',
			height:'800px',
			visible:true,
			closeOnOutsideClick: false,
			showCloseButton: false,
			contentTemplate: function() {
				return html;
			},
			onShown:function(){
				if(gDashboard.itemGenerateManager.dxItemBasten.length != 0) {
					if(gDashboard.reportType != 'AdHoc') {
						var itemList = [];
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
							itemList.push(_e.itemNm)
						});
						$("#itemSelect").dxLookup({
							dataSource:itemList,
							value:itemList[0],
							placeholder: "아이템을 선택하세요",
							showPopupTitle: false,
							searchEnabled: false,
							showPopupTitle: false,
							showCancelButton: false,
							closeOnOutsideClick: true,
							onValueChanged: function(e) {
								$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
									if(_e.itemNm == e.value) {
//										$('#queryArea').dxTextArea('instance').option('value', _e.showQuery);
										/*dogfoot 쿼리보기 텍스트뷰어로 변경 shlim 20201130*/
										editor.setValue(_e.showQuery);
									}
								});
							}
						});
					}
					/*dogfoot 쿼리보기 텍스트뷰어로 변경 shlim 20201130*/
//					$('#queryArea').dxTextArea({
//						readOnly: true,
//						height: "600px",
//						value: gDashboard.itemGenerateManager.dxItemBasten[0].showQuery
//					}).dxTextArea('instance');
					/*dogfoot 쿼리보기 텍스트뷰어로 변경 shlim 20201130*/
					var editor = ace.edit(
			            'queryArea',
			            {
			                mode: 'ace/mode/sql',
			                theme: 'ace/theme/crimson_editor',
//			                value: gDashboard.itemGenerateManager.dxItemBasten[0].showQuery,
							/*dogfoot 비정형 그리드만보기 쿼리보기 오류 수정 shlim 20210329 */
			                value: gDashboard.structure.Layout === 'G' ? gDashboard.itemGenerateManager.dxItemBasten[1].showQuery : gDashboard.itemGenerateManager.dxItemBasten[0].showQuery,
			                showPrintMargin: false,
			            }
			        );
			        editor.setReadOnly(true);
				}
				$('#ok_query_button').dxButton({
					text:'확인',
					onClick:function(){
						$('#queryViewPopup').dxPopup('instance').hide();
						$('#queryViewPopup').remove();
					}
				});
				$('#cancel_query_button').dxButton({
					text: '취소',
					onClick: function() {
						$('#queryViewPopup').dxPopup('instance').hide();
						$('#queryViewPopup').remove();
					}
				});

			}
		});
	};

	this.saveReport = function(_ex){
		self.reportInfo.DataSources = self.dsUtility.getDatasourcesForLayoutXml();
		/**
		 * KERIS 수정
		 */
		var html = "<div class=\"modal-body\" style='height:93%'>\r\n" +
		"                        <div class=\"row\" style='height:100%'>\r\n" +
		"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>보고서 명</span>\r\n" +
		"                                   </div>\r\n" +
		"									<div style='text-align: right;'>\r\n"+
		"										<div id=\"report_title\"></div>\r\n" +
		"									</div>\r\n"+
		"                                </div>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>보고서 부제목</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"report_subtitle\"></div>\r\n" +
		"                                </div>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>폴더 구분 및 저장 폴더</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"report_folder_type\"></div>\r\n" +
		"								 <div style='text-align: right;'>"+
		"								 	<div id=\"report_target_folder\" style='float:left'></div>\r\n" +
		"								 	<div id=\"findFolder\"></div>\r\n" +
		"								 </div>"+
		"                                </div>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>표시순서</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"report_show_order\"></div>\r\n" +
		"                                </div>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>주석</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"report_annotiation\"></div>\r\n" +
		"                                </div>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top: 5px;height:20%;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>설명</span>\r\n" +
		"                                   </div>\r\n" +
		/* DOGFOOT ktkang 저장 버튼 위치 수정  20200619 */
		"								 <div id=\"report_description\" style=\"height:70%;\"></div>\r\n" +
		"                                </div>\r\n" +
		"                            </div>\r\n" +
		"                        </div>\r\n" + // row 끝
		"                    </div>\r\n" + // modal-body 끝
		"					 <div id='save_box' style='text-align: center;'/>"+
		"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
		"                        <div class=\"row center\">\r\n" +
		"                            <a id=\"save_ok\" class=\"btn positive ok-hide\">확인</a>\r\n" +
		"                            <a id=\"save_cancel\" class=\"btn neutral close\">취소</a>\r\n" +
		"                        </div>\r\n" +
		"                    </div>\r\n" +
		"                </div>";

		if($('#savePopup').length == 0){
			$('body').append("<div id='savePopup'></div>");
		}
		
		if (gDashboard.fldType == "PUBLIC" && gDashboard.structure.ReportMasterInfo.publish_yn == 'N') {
			WISE.alert('보고서 수정 권한이 없습니다.');
			return;
		}
		
		if(WISE.Constants.pid == "" || _ex == "false"){
			/* DOGFOOT ktkang  SpreadSheet 필터있는 보고서 안열리는 오류 수정  20191218 */
			if(gDashboard.fieldManager && gDashboard.fieldManager.isChange == true){
				WISE.alert('데이터 항목 변경사항이 조회 되지 않았습니다. 조회 후 저장하여 주시기 바랍니다.');
				return;
//				gDashboard.query();
			}
// var dupleCheck = false;
			if(reportType != 'Spread') {
				//2020.02.05 mksong 간격 조정 dogfoot
				if(gDashboard.itemGenerateManager.dxItemBasten == 0 ){
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('빈 보고서는 생성하실 수 없습니다.','error');
					return false;
				}
				// 2021-03-15 yyb 아이템이 하나일때 Loop에서 차트를 먼저 체크하는 에러 수정(차트가 null)
	            var _dxItemBasten;
				var exit = true;
	            var sLayout = gDashboard.structure.Layout;
//	            var sKind = sLayout == 'G' ? 'pivotGrid' : sLayout == 'C' ? 'chart' : '';
				/*dogfoot 그리드만 보기 구조 변경
				* 그리드만 보기 저장후 불러와서 다시 저장 하면 오류 & 차트 보기 변경시 오류
				* 차트 meta 정보는 저장되어있어야함
				shlim 20210324*/
	            var sKind = '';
	            if (sKind != '') {
	            	_dxItemBasten = gDashboard.itemGenerateManager.dxItemBasten.filter(function(el) {
	            		return el.kind == sKind;
	            	});
	            }
	            else {
	            	_dxItemBasten = gDashboard.itemGenerateManager.dxItemBasten;
	            }
				$.each(_dxItemBasten,function(_i,_e) {
					if (_e.meta == undefined && exit == true) {
						/*dogfoot 알림창 형식 변경 shlim 20200714*/
	    				WISE.alert("보고서 데이터가 조회되지 않습니다.");
	    				exit = false;
	    				return false;
					}
					else if (exit ==false) {
						return false;
					}
				});
				if (exit == false) {
					return false;
				}
			}
			$('#savePopup').dxPopup({
				title:'보고서 저장',
				width:'600px',
				height:'750px',
				visible:true,
				closeOnOutsideClick: false,
				showCloseButton: false,
			    contentTemplate: function() {
	                return html;
	            },
	            onContentReady:function(){
	            	/* DOGFOOT ktkang KERIS 직접 큐브로 접근해서 저장 할 때 개인폴더만 보이도록 수정  20200306 */
	            	var folderSelect;
	            	/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
	            	if(userJsonObject.selectCubeId || WISE.Constants.editmode === "viewer") {
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
		        			},
		        			{
		        				text:"개인폴더",
		        				value:"MY"
		        			}
		        		];
	            	}
					/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
	            	$('#report_title').dxTextBox({
						value:  WISE.Constants.editmode === "viewer"? $('.report-tab ul').find('li.on').find('em').text():$('.report-tab ul').find('li').find('em').text(),
	            	});
	            	$('#report_subtitle').dxTextBox({
						/* DOGFOOT hsshim 2020-01-15 보고서 부재목 저장 오류 수정 */
	            		value:_ex == "true" ? self.reportInfo.ReportMasterInfo.report_sub_title:""
	            	});

	            	var folder_type;
	            	if(self.reportInfo.ReportMasterInfo.fld_type != ""){
	            		if(self.reportInfo.ReportMasterInfo.fld_type == folderSelect[0].value){
	            			folder_type = folderSelect[0];
	            		}
	            		else{
	            			folder_type = folderSelect[1];
	            		}
	            	}else{
	            		folder_type = folderSelect[0];
	            	}
	            	/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
	            	if(WISE.Constants.editmode ==="viewer")
	            		folder_type = folderSelect[0];

	            	$('#report_folder_type').dxRadioGroup({
	            		dataSource:folderSelect,
	            		layout: "horizontal",
	            		value:folder_type
	        		});

	            	$('#report_target_folder').dxTextBox({
	            		readOnly:true,
	            		'value': _ex == "true" ? self.reportInfo.ReportMasterInfo.fld_nm : "",
	            		'text': _ex == "true" ? self.reportInfo.ReportMasterInfo.fld_nm : "",
	            		'fld_id': _ex == "true" ? self.reportInfo.ReportMasterInfo.fld_id : "",
	            		'width':'91%'
	            	});
	            	$('#findFolder').dxButton({
	            		icon:'search',
	            		onClick:function(){
	            			$('#save_box').append("<div id='selectFolder'></div>");
	    					if(typeof  $('#report_folder_type').dxRadioGroup('instance').option('value').value == 'undefined'){
	    						return;
	    					}
	    					var folderhtml = "<div class=\"modal-body\" style='height:87%'>\r\n" +
	    					"                        <div class=\"row\" style='height:100%'>\r\n" +
	    					"                            <div class=\"column\" style='width:100%'>\r\n" +
	    					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
	    					"                                   <div class=\"modal-tit\">\r\n" +
	    					"                                   <span>폴더 목록</span>\r\n";
	    					/* DOGFOOT ktkang KERIS 보고서 저장 시 개인폴더 추가하는 기능 주석처리  20200306 */
//	    					if($('#report_folder_type').dxRadioGroup('instance').option('value').value == 'MY') {
//	    						folderhtml += "									<div id=\"addMyfolder\" style=\"float: right\"></div>\r\n";
//	    					}
	    					folderhtml += "                                   </div>\r\n" +
	    					"									<div id=\"folder_tree\" />\r\n" +
	    					"                                </div>\r\n" +
	    					"                            </div>\r\n" +
	    					"                        </div>\r\n" + // row 끝
	    					"                    </div>\r\n" + // modal-body 끝
	    					"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
	    					"                        <div class=\"row center\">\r\n" +
	    					"                            <a id=\"folder_ok\" class=\"btn positive ok-hide\">확인</a>\r\n" +
	    					"                            <a id=\"folder_cancel\" class=\"btn neutral close\">취소</a>\r\n" +
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
	            					var fld_type = $('#report_folder_type').dxRadioGroup('instance').option('value');
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
	        				            async:false,
	        				            success: function(result) {
	        				            	var datasource = result.data;
// var selectFLDNm="",selectFLDId="";
	        				            	var selectFLDNm = self.reportInfo.ReportMasterInfo.fld_nm;
	        				            	var selectFLDId = self.reportInfo.ReportMasterInfo.fld_id;
	        				            	$('#folder_tree').dxTreeView({
	        				            		dataSource:datasource,
	        				            		dataStructure:'plain',
	        				            		keyExpr: "FLD_ID",
	        				            		parentIdExpr: "PARENT_FLD_ID",
	        				            		displayExpr: "FLD_NM",
		            							// mksong 2019.12.20 보고서 검색기능 추가 수정 dogfoot
	        				            		searchEnabled: true,
	        									searchMode : "contains",
	        									searchTimeout:undefined,
	        									searchValue:"",
	        									// 2019.12.10 수정자 : mksong nodataText DOGFOOT
	        									noDataText:"조회된 폴더가 없습니다.",
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
	        				            				$('#report_target_folder').dxTextBox('instance').option('value',selectFLDNm);
	        				            				$('#report_target_folder').dxTextBox('instance').option('fld_id',selectFLDId);
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
	        		            			/* DOGFOOT ktkang KERIS 보고서 저장 시 개인폴더 추가하는 기능 주석처리  20200306 */
//	        		            			$('#addMyfolder').dxButton({
//	        		                    		text:'개인폴더 추가',
//	        		                    		onClick:function(){
//	        		                    			$('#save_box').append("<div id='addFolderPop'></div>");
//	        		                    			var html = '<p>개인폴더 이름 </p><div id="addMyFld">';
//	        		                    			html += '</div>';
//	        		                                html += '<div class="modal-footer" style="padding-bottom:0px;">';
//	        		        						html += '<div class="row center">';
//	        		        						html += '<a id="addMyFolderOk" href="#" class="btn positive ok-hide">확인</a>';
//	        		        						html += '<a id="addMyFolderClose" href="#" class="btn neutral close">취소</a>';
//	        		        						html += '</div>';
//	        		        						html += '</div>';
//	        		        						$('#addFolderPop').dxPopup({
//	        		    	            				title:'개인폴더 추가',
//	        		    	            				visible:true,
//	        		    	            				width: 500,
//	        		    	            				height: 230,
//	        		    	            				contentTemplate: function() {
//	        		    	            					return html;
//	        		    	            		        },
//	        		    	            		        onContentReady:function(){
//	        		    	            		        	 $('#addMyFld').dxTextBox({
//	        		    	         							text: ''
//	        		    	                                 });
//
//	        		    	            		        	 $('#addMyFolderOk').off('click').on('click', function(){
//	        		    	            		        		 var selectFLDNm = $('#addMyFld').dxTextBox('instance').option('value');
//	        		    	            		        		 if (selectFLDNm.length > 0) {
//	        		    	            		        			 $.ajax({
//	        		    	            		        				 url: WISE.Constants.context + '/report/createNewUserFolder.do',
//	        		    	            		        				 method: 'POST',
//	        		    	            		        				 data: {
//	        		    	            		        					 name: selectFLDNm,
//	        		    	            		        					 parentFolder: selectFLDId ? selectFLDId : 0,
//	        		    	            		        							 user_no : userJsonObject.userNo
//	        		    	            		        				 },
//	        		    	            		        				 success: function(msg) {
//	        		    	            		        					 if (msg) {
//	        		    	            		        						 WISE.alert(msg);
//	        		    	            		        					 } else {
//	        		    	            		        						 $('#addFolderPop').dxPopup('instance').hide();
//	        		    	            		        						 $('#addFolderPop').remove();
//	        		    	            		        						 WISE.alert(gMessage.get('config.save.success'),'success');
//
//	        		    	            		        						 var param = {
//	        		    	            		 	            						'user_id' : userJsonObject.userId,
//	        		    	            		 	            						'fld_type' : 'MY'
//	        		    	            		 	            					};
//	        		    	            		 	        						$.ajax({
//	        		    	            		 	        				        	method : 'POST',
//	        		    	            		 	        				            url: WISE.Constants.context + '/report/getFolderList.do',
//	        		    	            		 	        				            dataType: "json",
//	        		    	            		 	        				            data:param,
//	        		    	            		 	        				            async:false,
//	        		    	            		 	        				            success: function(result) {
//	        		    	            		 	        				            	var datasource = result.data;
//	        		    	            		 	        				            	$('#folder_tree').dxTreeView('instance').option('dataSource', datasource);
//	        		    	            		 	        				            }
//	        		    	            		 	        						});
//	        		    	            		        					 }
//	        		    	            		        				 },
//	        		    	            		        				 error: function() {
//	        		    	            		        					 //2020.01.21 mksong 경고창 타입 지정 dogfoot
//	        		    	            		        					 $('#addFolderPop').dxPopup('instance').hide();
//	        		    	            		        					 $('#addFolderPop').remove();
//	        		    	            		        					 WISE.alert(gMessage.get('config.save.failed'),'error');
//	        		    	            		        				 }
//	        		    	            		        			 });
//	        		    	            		        		 } else {
//	        		    	            		        			 $('#addFolderPop').dxPopup('instance').hide();
//	        		    	            		        			 $('#addFolderPop').remove();
//	        		    	            		        			 WISE.alert(gMessage.get('config.folder.name.isnull'));
//	        		    	            		        		 }
//	        		    	            		        	 });
//	        		    	            		        	 $('#addMyFolderClose').off('click').on('click', function(){
//	        		    	            		        		 $('#addFolderPop').dxPopup('instance').hide();
//	        		    	            		        		 $('#addFolderPop').remove();
//	        		    	            		        	 });
//	        		    	            		        }
//	        		        						});
//	        				            		}
//	        		            			});

	        		            			gProgressbar.hide();
	        				            }
	        				        });
	            				}
	            			});
	            		}
	            	});
	            	$('#report_show_order').dxNumberBox({
	            		value: _ex == "true" ? Number(self.reportInfo.ReportMasterInfo.ordinal) : "0",
	            		//2020.02.05 mksong , 제거 dogfoot
	            		width:"20%"
	            	});
	            	$('#report_annotiation').dxTextBox({
	            		value: _ex == "true" ? self.reportInfo.ReportMasterInfo.tag : ""
	            	});
	            	$('#report_description').dxTextArea({
	            		value:_ex == "true" ? self.reportInfo.ReportMasterInfo.description : ""
	            	});

	            	$('#save_ok').dxButton({
	            		type:'success',
	            		text:'저장',
	            		onClick:function(){
//	            			if(gDashboard.fieldManager && gDashboard.fieldManager.isChange == true){
//	            				gDashboard.query();
//	            			}
	            			/* DOGFOOT hsshim 200107
							 * 스프레드 저장 기능 개선
							 */
							if(WISE.Constants.editmode !== 'spreadsheet' && WISE.Constants.editmode !== 'viewer'){
								/*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
								if(gDashboard.reportType === 'StaticAnalysis'){
									self.reportInfo.LayoutTree = self.setAysLayoutTree();
							 	}else{
							 		self.reportInfo.LayoutTree = self.setLayoutTree();
								}

								self.setupITEM_Layout();
							}else if(WISE.Constants.editmode == 'viewer'){
								if(gDashboard.reportType === 'StaticAnalysis'){
									self.reportInfo.LayoutTree = self.setAysLayoutTree(WISE.Constants.pid);
							 	}else{
							 		self.reportInfo.LayoutTree = self.setLayoutTree(WISE.Constants.pid);
								}

								self.setupITEM_Layout();
							}

	            			if($('#report_target_folder').dxTextBox('instance').option('fld_id') == ''){
	            				// 2020.01.07 mksong 경고창 UI 변경 dogfoot
	            				WISE.alert("보고서 저장위치를 체크하세요.",'error');
	    	            		return false;
	            			}

	            			var param;
	            			if(reportType !== 'Spread' && gDashboard.reportType == 'AdHoc'){
								/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
								var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByField();
								var dataset = gDashboard.dataSourceManager.datasetInformation[dataSrcId];
	            				var report_meta = gDashboard.adhocReportUtility.Save(dataset);
	            				var REPORT_XML = {},CHART_XML = {},PARAM_XML = {},DATASET_XML = {};

	                			var sql = report_meta['REPORT_META']['DATASET']['SQL_QUERY'] == undefined ? report_meta['REPORT_META']['DATASET']['sql'] : report_meta['REPORT_META']['DATASET']['SQL_QUERY'];

	                			/* DOGFOOT ktkang 비정형 레이아웃 저장 오류 수정  20200228 */
	                			/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
	                			if($('#canvas-container').find('.lm_splitter').length > 0 && WISE.Constants.editmode !== 'viewer'){
	                				if($('.lm_horizontal').length > 0){
										// 2021-03-16 yyb 레이아웃 저장 오류 수정
										if ($('.lm_horizontal').css("display") != 'none') {
											if ($('.lm_row').children().eq(0).attr('id').indexOf('chart') == 0) {
		                						gDashboard.structure.Layout = 'CLGR';
		                					}
											else {
		                						gDashboard.structure.Layout = 'CRGL';
		                					}
										}
	                				}
									else {
										// 2021-03-16 yyb 레이아웃 저장 오류 수정
										if ($('.lm_vertical').css("display") != 'none') {
		                					if ($('.lm_column').children().eq(0).attr('id').indexOf('chart') == 0) {
		                						gDashboard.structure.Layout = 'CTGB';
		                					}
											else {
		                						gDashboard.structure.Layout = 'CBGT';
		                					}
										}
	                				}
	                				/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
	                			}else if(WISE.Constants.editmode !== 'viewer'){
	                				if($('.lm_item_container').children().attr('id').indexOf('chart') == 0){
	                					gDashboard.structure.Layout = 'C';
	                				}else{
	                					gDashboard.structure.Layout = 'G';
	                				}
	                			}

	                			REPORT_XML['REPORT_XML'] = report_meta['REPORT_META']['REPORT_XML'];
	                			CHART_XML['CHART_XML'] = report_meta['REPORT_META']['CHART_XML'];
	                			PARAM_XML['PARAM_XML'] = report_meta['REPORT_META']['PARAM_XML'];
// DATASET_XML['DATASET'] =
// report_meta['REPORT_META']['DATASET']['dataset']['DATA_SET'];
// report_meta['REPORT_META']['DATASET']['sql'] =
// gDashboard.queryHandler.querySql;
	            				if(typeof report_meta['REPORT_META']['originSql'] != 'undefined')
	            					sql = (report_meta['REPORT_META']['originSql']);
	            				else{
	            					/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
	            					sql =  dataset.DATASET_QUERY;
	            				}
	            				/* DOGFOOT ktkang 주제영역일 때 파라미터 저장 수정  20200704 */
	            				var param_xml = WISE.libs.Dashboard.item.DatasetUtility.getParamObject(gDashboard.datasetMaster.state.params);
	            				if(WISE.Context.isCubeReport && gDashboard.isNewReport) {
	            					param_xml = gDashboard.parameterFilterBar.parameterInformation.length ==0? {}:gDashboard.parameterFilterBar.parameterInformation
	            				}
	            				/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
	            				if(WISE.Constants.editmode === "viewer"){
	            					var tempParam = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
	            					
	            					var fld_type = $('#report_folder_type').dxRadioGroup('instance').option('value').value;
 
                                    if(fld_type == "MY"){
                                    	$.each(tempParam, function(name, data){
											var defaultValue;
											if(data.value.length == 1 && data.value[0] == '_ALL_VALUE_'){
												defaultValue = "[ALL]";

											}else{
												var _i;
												defaultValue = "";
												if(data.value.length === 1){
													defaultValue = data.value[0]
												}else {
													for(_i = 0; _i < data.value.length; _i++){
														defaultValue += (data.value[_i] + ",");
													}
												}

											}

											if(data.parameterType && data.parameterType.indexOf("BETWEEN") > -1){
												if(name.indexOf("_fr") > -1){
													var tempNm = data.cubeUniqueName||name.replace("_fr", "");
													param_xml[tempNm].DEFAULT_VALUE[0] = defaultValue;
													param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
												}else if(name.indexOf("_to") > -1){
													var tempNm = data.cubeUniqueName||name.replace("_to", "");
													param_xml[tempNm].DEFAULT_VALUE[1] = defaultValue;
													param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
												}
											}else{ 
												var tempNm = data.cubeUniqueName; 
												param_xml[tempNm].DEFAULT_VALUE = defaultValue;
												if(param_xml[tempNm].parameterValues){
													var temp = JSON.parse(param_xml[tempNm].parameterValues);
													temp[name].defaultValue = defaultValue;
													param_xml[tempNm].parameterValues = JSON.stringify(temp);
													param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
												}
											}
										});
                                    }
									
								}


	            				var layout_config;
	            				if(WISE.Constants.editmode === "viewer")
	            					layout_config = gDashboard.layoutConfig[self.reportInfo.ReportMasterInfo.id];
	            				else
	            					layout_config = gDashboard.layoutConfig;

	            				var direct_view = gDashboard.structure.ReportMasterInfo.direct_view;
	            				if(typeof direct_view == 'undefined') {
	            					direct_view = 'N';
	            				}
	            				
	            				param = {
	            						'isNew' : 'true',
	            						'report_id': _ex == "true" ? WISE.Constants.pid+"" : "",
										'report_nm': $('#report_title').dxTextBox('instance').option('value'),
										/* DOGFOOT hsshim 2020-01-15 보고서 부재목 저장 오류 수정 */
	                					'report_sub_title': $('#report_subtitle').dxTextBox('instance').option('value')+'',
	                					'fld_id' : $('#report_target_folder').dxTextBox('instance').option('fld_id'),
	                					'fld_type': $('#report_folder_type').dxRadioGroup('instance').option('value').value,
	                					'report_ordinal':$('#report_show_order').dxNumberBox('instance').option('value')+'',
	                					'report_type': gDashboard.reportType,
	                					'report_tag':$('#report_annotiation').dxTextBox('instance').option('value'),
	                					'report_desc' : $('#report_description').dxTextArea('instance').option('value'),
	                					/* DOGFOOT ktkang 비정형 레이아웃 저장 오류 수정  20200228 */
//	                					'report_layout': gDashboard.goldenLayoutManager.getAdhocLayout(),
	                					'report_layout': gDashboard.structure.Layout,
	                					/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
										'datasrc_id': dataset.DATASRC_ID + "",
										'datasrc_type': dataset.DATASRC_TYPE,
										'dataset_type': dataset.DATASET_TYPE,
	    	        					/* DOGFOOT hsshim 2020-01-15 끝 */
	                					'report_xml': REPORT_XML,
	                					'chart_xml': CHART_XML,
	                					'param_xml': param_xml,
	                					'dataset_xml' : DATASET_XML,
	                					'dataset_query':sql? sql : '',
// 'reg_user_Id':userJsonObject.userId,
	                					'userid' : userJsonObject.userId+"",
	                					'prompt_yn':self.reportInfo.ReportMasterInfo.promptYn,
	                					/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
	                					'layout_config' : JSON.stringify(layout_config? layout_config : {}),
	                					'direct_view' : direct_view,
	    	        					'linkReport' : gDashboard.structure.linkReport,
	    	        					'subLinkReport' : gDashboard.structure.subLinkReport,
	    	        					'reportItemList': gDashboard.datasetMaster.getState().fields,
	    	        					'allowDuplication': userJsonObject.siteNm == 'KAMKO',
	    	        				};
	            			}else if(reportType == 'Spread' || reportType == 'Excel'){
	            				/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
	            				var param_xml = WISE.libs.Dashboard.item.DatasetUtility.getParamObject(gDashboard.datasetMaster.state.params);
	            				if(WISE.Context.isCubeReport && gDashboard.isNewReport) {
	            					param_xml = gDashboard.parameterFilterBar.parameterInformation.length ==0? {}:gDashboard.parameterFilterBar.parameterInformation
	            				}

	            				if(WISE.Constants.editmode === "viewer"){
	            					var tempParam = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

									$.each(tempParam, function(name, data){
										var defaultValue
										if(data.value.length == 1 && data.value[0] == '_ALL_VALUE_'){
											defaultValue = "[ALL]";

										}else{
											var _i;
											defaultValue = "";
											if(data.value.length === 1){
												defaultValue = data.value[0]
											}else {
												for(_i = 0; _i < data.value.length; _i++){
                                                    defaultValue += (data.value[_i] + ",");
												}
											}

										}
										/* DOGFOOT ktkang 고용정보원09 뷰어에서 저장 오류 수정  */
//										if(data.parameterType && data.parameterType.indexOf("BETWEEN") > -1){
//				                        	if(name.indexOf("_fr") > -1){
//				                        		var tempNm = name.replace("_fr", "");
//				                        		param_xml[tempNm].DEFAULT_VALUE[0] = defaultValue;
//				                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//				                        	}else if(name.indexOf("_to") > -1){
//				                        		var tempNm = name.replace("_to", "");
//				                        		param_xml[tempNm].DEFAULT_VALUE[1] = defaultValue;
//				                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//				                        	}
//				                        }else{
//				                        	param_xml[name].DEFAULT_VALUE = defaultValue;
//											var temp = JSON.parse(param_xml[name].parameterValues);
//											temp[name].defaultValue = defaultValue;
//											param_xml[name].parameterValues = JSON.stringify(temp);
//											param_xml[name].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//				                        }
									});
								}

	            				var layout_config;
	            				if(WISE.Constants.editmode === "viewer")
	            					layout_config = gDashboard.layoutConfig[self.reportInfo.ReportMasterInfo.id];
	            				else
	            					layout_config = gDashboard.layoutConfig;
	            				
	            				var direct_view = gDashboard.structure.ReportMasterInfo.direct_view;
	            				if(typeof direct_view == 'undefined') {
	            					direct_view = 'N';
	            				}
	            				
	            				param = {
	    	            				'isNew' : 'true',
	    	        					'report_id': _ex == "true" ? WISE.Constants.pid+"" : "",
										'report_nm': $('#report_title').dxTextBox('instance').option('value'),
										/* DOGFOOT hsshim 2020-01-15 보고서 부재목 저장 오류 수정 */
	    	        					'report_sub_title': $('#report_subtitle').dxTextBox('instance').option('value')+'',
	    	        					'fld_id' : $('#report_target_folder').dxTextBox('instance').option('fld_id')+'',
	    	        					'fld_type': $('#report_folder_type').dxRadioGroup('instance').option('value').value,
	    	        					'fld_nm' : $('#report_target_folder').dxTextBox('instance').option('value')+"",
	    	        					'report_ordinal':$('#report_show_order').dxNumberBox('instance').option('value')+'',
	    	        					'report_type': 'Excel',
	    	        					'report_tag':$('#report_annotiation').dxTextBox('instance').option('value'),
	    	        					'report_desc' : $('#report_description').dxTextArea('instance').option('value'),
	    	        					'report_layout':'',
	    	        					'datasrc_id': '0',
	    	        					'datasrc_type': '',
	    	        					'dataset_type': '',
	    	        					//'report_xml': '<EXCEL_XML><SHEET_ELEMENT /></EXCEL_XML>',
	    	        					/*dogfoot 테이블 바인드 바인드 위치값 저장 shlim 20200727*/
	    	        					'report_xml': gDashboard.spreadsheetManager.getReportXml(),
	    	        					'chart_xml': self.reportInfo.MapOption,
	    	        					'layout_xml' : {"DataSources":self.reportInfo.DataSources,"Items":self.reportInfo.Items, "LayoutTree":self.reportInfo.LayoutTree,"Title":{"Text":$('#report_title').dxTextBox('instance').option('value'),"Alignment":"Left"}},
	    	        					'param_xml': param_xml,
	    	        					'dataset_xml' : {},// gDashboard.dataSourceManager.datasetInformation,
	    	        					'dataset_query': '',
									// 'reg_user_Id':userJsonObject.userId+'',
	    	        					'prompt_yn':self.reportInfo.ReportMasterInfo.promptYn,
	    	        					/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
	    	        					'layout_config' : JSON.stringify(layout_config? layout_config : {}),
	    	        					'direct_view' : direct_view,
	    	        					/**
								 * KERIS 수정
								 */
	    	        					'userid' : userJsonObject.userId+"",
	    	        					'linkReport' : self.reportInfo.linkReport,
	    	        					'subLinkReport' : self.reportInfo.subLinkReport,
	    	        					'reportItemList': gDashboard.datasetMaster.getState().fields,
	    	        					'allowDuplication': userJsonObject.siteNm == 'KAMKO',
	    	        				};
	            				/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
	            				if(WISE.Constants.editmode === "viewer"){
		            				var layout_item = (param.layout_xml.LayoutTree.LayoutItem || param.layout_xml.LayoutTree.LayoutGroup[0].LayoutItem);

		            				$.each(layout_item, function(i, data){
		            					data.DashboardItem = data.DashboardItem.slice(0, data.DashboardItem.lastIndexOf("_"))
		            				})
		            			}
	            			}else {
	            			/* DOGFOOT ktkang 주제영역일 때 파라미터 저장 수정  20200704 */
	            				var param_xml = WISE.libs.Dashboard.item.DatasetUtility.getParamObject(gDashboard.datasetMaster.state.params);
	            				if(WISE.Context.isCubeReport && gDashboard.isNewReport) {
	            					param_xml = gDashboard.parameterFilterBar.parameterInformation.length ==0? {}:gDashboard.parameterFilterBar.parameterInformation
	            				}

	            				if(WISE.Constants.editmode === "viewer"){
	            					var tempParam = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

									$.each(tempParam, function(name, data){
										var defaultValue
										if(data.value.length == 1 && data.value[0] == '_ALL_VALUE_'){
											defaultValue = "[ALL]";

										}else{
											var _i;
											defaultValue = "";
											if(data.value.length === 1){
												defaultValue = data.value[0]
											}else {
												for(_i = 0; _i < data.value.length; _i++){
                                                    defaultValue += (data.value[_i] + ",");
												}
											}

										}
										/* DOGFOOT ktkang 고용정보원09 뷰어에서 저장 오류 수정  */
//										if(data.parameterType && data.parameterType.indexOf("BETWEEN") > -1){
//				                        	if(name.indexOf("_fr") > -1){
//				                        		var tempNm = name.replace("_fr", "");
//				                        		param_xml[tempNm].DEFAULT_VALUE[0] = defaultValue;
//				                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//				                        	}else if(name.indexOf("_to") > -1){
//				                        		var tempNm = name.replace("_to", "");
//				                        		param_xml[tempNm].DEFAULT_VALUE[1] = defaultValue;
//				                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//				                        	}
//				                        }else{
//				                        	param_xml[name].DEFAULT_VALUE = defaultValue;
//											var temp = JSON.parse(param_xml[name].parameterValues);
//											temp[name].defaultValue = defaultValue;
//											param_xml[name].parameterValues = JSON.stringify(temp);
//											param_xml[name].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//				                        }
									});
								}

	            				var layout_config;
	            				if(WISE.Constants.editmode === "viewer")
	            					layout_config = gDashboard.layoutConfig[self.reportInfo.ReportMasterInfo.id];
	            				else
	            					layout_config = gDashboard.layoutConfig;
	            				
	            				var direct_view = gDashboard.structure.ReportMasterInfo.direct_view;
	            				if(typeof direct_view == 'undefined') {
	            					direct_view = 'N';
	            				}
	            				
	            				param = {
	    	            				'isNew' : 'true',
	    	        					'report_id': _ex == "true" ? WISE.Constants.pid+"" : "",
										'report_nm': $('#report_title').dxTextBox('instance').option('value'),
										/* DOGFOOT hsshim 2020-01-15 보고서 부재목 저장 오류 수정 */
	    	        					'report_sub_title': $('#report_subtitle').dxTextBox('instance').option('value')+'',
	    	        					'fld_id' : $('#report_target_folder').dxTextBox('instance').option('fld_id')+'',
	    	        					'fld_type': $('#report_folder_type').dxRadioGroup('instance').option('value').value,
	    	        					'fld_nm' : $('#report_target_folder').dxTextBox('instance').option('value')+"",
	    	        					'report_ordinal':$('#report_show_order').dxNumberBox('instance').option('value')+'',
// 'report_type':'DashAny', //고정
	    	        					'report_type': gDashboard.reportType,
	    	        					'report_tag':$('#report_annotiation').dxTextBox('instance').option('value'),
	    	        					'report_desc' : $('#report_description').dxTextArea('instance').option('value'),
	    	        					'report_layout':'',
	    	        					'datasrc_id': '0',
	    	        					'datasrc_type': '',
	    	        					'dataset_type': '',
	    	        					'report_xml': '<REPORT_XML><REALTIME_ELEMENT>0</REALTIME_ELEMENT></REPORT_XML>',
	    	        					'chart_xml': self.reportInfo.MapOption,
	    	        					'layout_xml' : {"DataSources":self.reportInfo.DataSources,"Items":self.reportInfo.Items, "LayoutTree":self.reportInfo.LayoutTree,"Title":{"Text":$('#report_title').dxTextBox('instance').option('value'),"Alignment":"Left"}},
	    	        					'param_xml': param_xml,
	    	        					//'dataset_xml' : {},
	    	        					'dataset_xml' : gDashboard.dataSourceManager.datasetInformation,
	    	        					'dataset_query': '',
// 'reg_user_Id':userJsonObject.userId+'',
	    	        					'prompt_yn':self.reportInfo.ReportMasterInfo.promptYn,
	    	        					/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
	    	        					'layout_config' : JSON.stringify(layout_config? layout_config : {}),
	    	        					'direct_view' : direct_view,
	    	        					/**
								 * KERIS 수정
								 */
	    	        					'userid' : userJsonObject.userId+"",
	    	        					'linkReport' : gDashboard.structure.linkReport,
	    	        					'subLinkReport' : gDashboard.structure.subLinkReport,
	    	        					'reportItemList': gDashboard.datasetMaster.getState().fields,
	    	        					'allowDuplication': userJsonObject.siteNm == 'KAMKO',
	    	        				};

		            				if(WISE.Constants.editmode === "viewer"){
			            				var layout_item = (param.layout_xml.LayoutTree.LayoutItem || param.layout_xml.LayoutTree.LayoutGroup[0].LayoutItem);

			            				$.each(layout_item, function(i, data){
			            					data.DashboardItem = data.DashboardItem.slice(0, data.DashboardItem.lastIndexOf("_"))
			            				})
			            			}
	            			}
	            			/* dogfoot What If 분석용 매개변수 저장 shlim 20201022 */
	            			if (gDashboard.customParameterHandler.getArrayCalcParamInfomation().length > 0){
								$.extend(param.param_xml, gDashboard.customParameterHandler.calcParameterInformation);
							}

	            			/*20210305 AJKIM 비트윈 저장 오류 수정 dogfoot*/
	            			$.each(param.param_xml, function(i, data){
	        					if(data.PARAM_TYPE.indexOf("BETWEEN") > -1&& data.DEFAULT_VALUE_USE_SQL_SCRIPT === 'N'
	        					&& typeof data.DEFAULT_VALUE === "object"){
	        						data.DEFAULT_VALUE = data.DEFAULT_VALUE[0] + "," + data.DEFAULT_VALUE[1];
	        					}
	        				});

							self.insertDatasetSaveInfo(param.dataset_xml);

	            			var jsonParam = {};
	            			jsonParam['JSON_REPORT'] = JSON.stringify(param);


	            			if(reportType == 'Spread' || reportType == 'Excel'){
	            				gDashboard.spreadsheetManager.getBlobFromSpreadJS(JSON.stringify(param));
	            			}
	            			else if(gDashboard.reportType == 'AdHoc'){
	            				$.ajax({
			                    	method : 'POST',
			                        url: WISE.Constants.context + '/report/saveAdhocReport.do',
			                        dataType: "json",
			                        data:jsonParam,
// async:false,
			                        success: function(result) {

			                        	if(result['return_status'] == 200){
			                        		$('#savePopup').dxPopup('instance').hide();
			                        		$('#savePopup').remove();
											/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
			                        		if(WISE.Constants.editmode != "viewer"){
			                        			var reportTabLi= $('.report-tab ul').find('li');
				                        	    var reportTabLiL = reportTabLi.length;

				                        		var reportTab = $('.report-tab');
				        				        var reportTabUl = $('.report-tab ul');
				        				            reportTabLiL = reportTabLiL +1;

				        				        var createTab='';
				        				            createTab+='<li><span><em>'+ param.report_nm +'</em></span></li>';

				        				        reportTab.find('ul').empty().append(createTab);
				        				        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
				        				        reportTab.find('li').width(100 / reportTabLiL + '%');

				        				        $('.report-tab ul').find('li').each(function(){
				        				            var createTabCustomData = $(this).find('em').text();
				        				        });

				        				        $(document).on('click', '.report-tab li', function(e){
				        				            $(this).addClass('on').siblings().removeClass('on');
				        				        });

					            				if(result['report_id'] != 1){
					            					WISE.Constants.pid = result['report_id'];
					            					self.reportInfo.ReportMasterInfo.id = result['report_id'];
					            				}
	// if(result['report_ordinal'] != 1){
					            				self.reportInfo.ReportMasterInfo.ordinal = result['report_ordinal']+"";
	// }

					            				self.reportInfo.ReportMasterInfo.all_fld_nm = result['all_fld_nm'];
												self.reportInfo.ReportMasterInfo.name = param.report_nm;
												/* DOGFOOT hsshim 2020-01-15 보고서 부재목 저장되게 적용 */
					            				self.reportInfo.ReportMasterInfo.report_sub_title = param.report_sub_title;
					            				self.reportInfo.ReportMasterInfo.tag = param.report_tag;
					            				self.reportInfo.ReportMasterInfo.fld_id = param.fld_id;
					            				self.reportInfo.ReportMasterInfo.fld_type = param.fld_type;
					            				self.reportInfo.ReportMasterInfo.fld_nm = param.fld_nm;
												self.reportInfo.ReportMasterInfo.description = param.report_desc;
												gDashboard.isNewReport = false;
			                        		}


											// 2020.01.07 mksong 경고창 UI 변경 dogfoot
			                        		WISE.alert("보고서를 저장하였습니다",'success');
			                        	}
			                        	else if(result['return_status'] == 422){
			                        		// 2020.01.07 mksong 경고창 UI 변경 dogfoot
			                        		WISE.alert(result.return_msg,'error');
			                        	}
			                        	else{
				                        	// 2020.01.07 mksong 경고창 UI 변경 dogfoot
			                        		WISE.alert("보고서 저장에 실패하였습니다.<br>관리자에게 문의하세요.",'error');
			                        	}
			                        }
		            			});
	            			}else{
	            				$.ajax({
			                    	method : 'POST',
			                        url: WISE.Constants.context + '/report/saveReport.do',
			                        dataType: "json",
			                        data:jsonParam,
			                        /* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//			                        async:false,
			                        success: function(result) {

			                        	if(result['return_status'] == 200){
			                        		$('#savePopup').dxPopup('instance').hide();
			                        		$('#savePopup').remove();

											/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
			                        		if(WISE.Constants.editmode != "viewer"){
			                        			var reportTabLi= $('.report-tab ul').find('li');
				                        	    var reportTabLiL = reportTabLi.length;

				                        		var reportTab = $('.report-tab');
				        				        var reportTabUl = $('.report-tab ul');
				        				            reportTabLiL = reportTabLiL +1;

				        				        var createTab='';
				        				            createTab+='<li><span><em>'+ param.report_nm +'</em></span></li>';

				        				        reportTab.find('ul').empty().append(createTab);
				        				        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
				        				        reportTab.find('li').width(100 / reportTabLiL + '%');

				        				        $('.report-tab ul').find('li').each(function(){
				        				            var createTabCustomData = $(this).find('em').text();
				        				        });

				        				        $(document).on('click', '.report-tab li', function(e){
				        				            $(this).addClass('on').siblings().removeClass('on');
				        				        });

					            				if(result['report_id'] != 1){
					            					WISE.Constants.pid = result['report_id'];
					            					self.reportInfo.ReportMasterInfo.id = result['report_id'];
					            				}
	// if(result['report_ordinal'] != 1){
					            				self.reportInfo.ReportMasterInfo.ordinal = result['report_ordinal']+"";
	// }

					            				self.reportInfo.ReportMasterInfo.all_fld_nm = result['all_fld_nm'];
					            				self.reportInfo.ReportMasterInfo.name = param.report_nm;
					            				self.reportInfo.ReportMasterInfo.tag = param.report_tag;
					            				self.reportInfo.ReportMasterInfo.fld_id = param.fld_id;
					            				self.reportInfo.ReportMasterInfo.fld_type = param.fld_type;
					            				self.reportInfo.ReportMasterInfo.fld_nm = param.fld_nm;
												self.reportInfo.ReportMasterInfo.description = param.report_desc;
												/* DOGFOOT hsshim 2020-01-15 보고서 부재목 저장되게 적용 */
					            				self.reportInfo.ReportMasterInfo.report_sub_title = param.report_sub_title;
					            				gDashboard.isNewReport = false;
			                        		}

				            				// 2020.01.07 mksong 경고창 UI 변경 dogfoot
			                        		WISE.alert("보고서를 저장하였습니다",'success');
			                        	}
			                        	else if(result['return_status'] == 422){
			                        		// 2020.01.07 mksong 경고창 UI 변경 dogfoot
			                        		WISE.alert(result.return_msg,'error');
			                        	}
			                        	else{
			                        		// 2020.01.07 mksong 경고창 UI 변경 dogfoot
			                        		WISE.alert("보고서 저장에 실패하였습니다.<br>관리자에게 문의하세요.",'error');
			                        	}
			                        }
		            			});
	            			}
	            		}
	            	});
	            	$('#save_cancel').dxButton({
	            		type:'danger',
	            		text:'취소',
	            		onClick:function(){
		            		$('#savePopup').dxPopup('instance').hide();
		            		$('#savePopup').remove();
	            		}
	            	});
	            	gDashboard.fontManager.setFontConfigForOption('savePopup');
	            }
			});
		}else{
			/* DOGFOOT ktkang  SpreadSheet 필터있는 보고서 안열리는 오류 수정  20191218 */
			if(gDashboard.fieldManager && gDashboard.fieldManager.isChange == true){
				WISE.alert('데이터 항목 변경사항이 조회 되지 않았습니다. 조회 후 저장하여 주시기 바랍니다.');
				return;
//				gDashboard.query();
			}
			/*dogfoot 비정형 그리드만 보기 저장 불러오기 오류 수정 shlim 20210322 2021-03-15*/
			var _dxItemBasten
		    var sLayout = gDashboard.structure.Layout;
//			var sKind = sLayout == 'G' ? 'pivotGrid' : sLayout == 'C' ? 'chart' : '';
			/*dogfoot 그리드만 보기 구조 변경
			* 그리드만 보기 저장후 불러와서 다시 저장 하면 오류 & 차트 보기 변경시 오류
			* 차트 meta 정보는 저장되어있어야함
			shlim 20210324*/
			var sKind = '';
			if (sKind != '') {
				gDashboard.itemGenerateManager.dxItemBasten = gDashboard.itemGenerateManager.dxItemBasten.filter(function(el) {
					return el.kind == sKind;
				});
			}
			/* DOGFOOT hsshim 200107
			 * 스프레드 저장 기능 개선
			 */
			if(WISE.Constants.editmode !== 'spreadsheet'){

				/*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
				if(gDashboard.reportType === 'StaticAnalysis'){
					self.reportInfo.LayoutTree = self.setAysLayoutTree();
			 	}else{
			 		self.reportInfo.LayoutTree = self.setLayoutTree();
				}
//				self.reportInfo.LayoutTree = self.setLayoutTree();
				self.setupITEM_Layout();
			}

			var exit = true;
			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_e){
				if(_e.meta == undefined && exit == true){
					/*dogfoot 알림창 형식 변경 shlim 20200714*/
    				WISE.alert(" 보고서 데이터가 조회되지 않습니다.");
    				exit = false;
    				return false;
				}else if(exit ==false){
					return false;
				}
			});
			if(exit == false){
				return false;
			}

			if(gDashboard.reportType == 'AdHoc'){
				/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
				var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByField();
				var dataset = gDashboard.dataSourceManager.datasetInformation[dataSrcId];
				var report_meta = gDashboard.adhocReportUtility.Save(dataset);
				var REPORT_XML = {},CHART_XML = {},PARAM_XML = {},DATASET_XML = {};

    			var sql = report_meta['REPORT_META']['DATASET']['sql'];

				/* DOGFOOT ktkang 비정형 레이아웃 저장 오류 수정  20200228 */
    			if(gDashboard.structure.Layout != 'C' && gDashboard.structure.Layout != 'G'){
    				if($('#canvas-container').find('.lm_splitter').length > 0){
        				if($('.lm_horizontal').length > 0){
        					if($('.lm_row').children().eq(0).attr('id').indexOf('chart') == 0){
        						gDashboard.structure.Layout = 'CLGR';
        					}else{
        						gDashboard.structure.Layout = 'CRGL';
        					}
        				}else{
        					if($('.lm_column').children().eq(0).attr('id').indexOf('chart') == 0){
        						gDashboard.structure.Layout = 'CTGB';
        					}else{
        						gDashboard.structure.Layout = 'CBGT';
        					}
        				}
        			}
    			}

    			REPORT_XML['REPORT_XML'] = report_meta['REPORT_META']['REPORT_XML'];
    			CHART_XML['CHART_XML'] = report_meta['REPORT_META']['CHART_XML'];
    			PARAM_XML['PARAM_XML'] = report_meta['REPORT_META']['PARAM_XML'];

				if(typeof report_meta['REPORT_META']['originSql'] != 'undefined')
					sql = (report_meta['REPORT_META']['originSql']);
				else{
					/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
					 sql =  dataset.DATASET_QUERY == undefined ? '' : dataset.DATASET_QUERY;
				}

				var param_xml = WISE.libs.Dashboard.item.DatasetUtility.getParamObject(gDashboard.datasetMaster.state.params);
				if(WISE.Context.isCubeReport && gDashboard.isNewReport) {
					param_xml = gDashboard.parameterFilterBar.parameterInformation.length ==0? {}:gDashboard.parameterFilterBar.parameterInformation
				}

				if(WISE.Constants.editmode === "viewer"){
					var tempParam = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

					$.each(tempParam, function(name, data){
						var defaultValue
						if(data.value.length == 1 && data.value[0] == '_ALL_VALUE_'){
							defaultValue = "[ALL]";

						}else{
							var _i;
							defaultValue = "";
							if(data.value.length === 1){
								defaultValue = data.value[0]
							}else {
								for(_i = 0; _i < data.value.length; _i++){
                                    defaultValue += (data.value[_i] + ",");
								}
							}

						}
						/* DOGFOOT ktkang 고용정보원09 뷰어에서 저장 오류 수정  */
//						if(data.parameterType && data.parameterType.indexOf("BETWEEN") > -1){
//                        	if(name.indexOf("_fr") > -1){
//                        		var tempNm = name.replace("_fr", "");
//                        		param_xml[tempNm].DEFAULT_VALUE[0] = defaultValue;
//                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        	}else if(name.indexOf("_to") > -1){
//                        		var tempNm = name.replace("_to", "");
//                        		param_xml[tempNm].DEFAULT_VALUE[1] = defaultValue;
//                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        	}
//                        }else{
//                        	param_xml[name].DEFAULT_VALUE = defaultValue;
//							var temp = JSON.parse(param_xml[name].parameterValues);
//							temp[name].defaultValue = defaultValue;
//							param_xml[name].parameterValues = JSON.stringify(temp);
//							param_xml[name].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        }
					});
				}

				var layout_config;
				if(WISE.Constants.editmode === "viewer")
					layout_config = gDashboard.layoutConfig[self.reportInfo.ReportMasterInfo.id];
				else
					layout_config = gDashboard.layoutConfig;

				var direct_view = gDashboard.structure.ReportMasterInfo.direct_view;
				if(typeof direct_view == 'undefined') {
					direct_view = 'N';
				}
				
				var param = {
					'isNew' : 'false',
					'report_id': WISE.Constants.pid+"",
					'report_nm' : $('.report-tab ul').find('li').find('em').text(),
					/* DOGFOOT hsshim 2020-01-15 보고서 부재목 저장되게 적용 */
					'report_sub_title':  self.reportInfo.ReportMasterInfo.report_sub_title+'',
					'fld_id' : self.reportInfo.ReportMasterInfo.fld_id+'',
					'fld_type': self.reportInfo.ReportMasterInfo.fld_type+'',
					'fld_nm' : self.reportInfo.ReportMasterInfo.fld_nm+"",
					'report_ordinal': self.reportInfo.ReportMasterInfo.ordinal+"",
					'report_type' : gDashboard.reportType,
					'report_tag': self.reportInfo.ReportMasterInfo.tag == undefined? "" :self.reportInfo.ReportMasterInfo.tag ,
					'report_desc' :self.reportInfo.ReportMasterInfo.description == undefined ? "" : self.reportInfo.ReportMasterInfo.description,
					/* DOGFOOT ktkang 비정형 레이아웃 저장 오류 수정  20200228 */
//					'report_layout': gDashboard.goldenLayoutManager.getAdhocLayout(),
					'report_layout': gDashboard.structure.Layout,
					/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
					/*dogfoot 비정형 저장 오류 수정 shlim 20200911*/
//					'datasrc_id': dataset.DATASRC_ID,
					'datasrc_id': (dataset.DATASRC_ID).toString(),
					'datasrc_type': dataset.DATASRC_TYPE,
					'dataset_type': dataset.DATASET_TYPE,
					/* DOGFOOT hsshim 2020-01-15 끝 */
					'report_xml': REPORT_XML,
					'chart_xml': CHART_XML,
					'param_xml': param_xml,
					'dataset_xml' : DATASET_XML,
					'dataset_query':sql,
					/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
					'layout_config' : JSON.stringify(layout_config? layout_config : {}),
					'direct_view' : direct_view,
					'prompt_yn':self.reportInfo.ReportMasterInfo.promptYn,
					'userid' : userJsonObject.userId+"", // '2087' + ""
					'linkReport' : self.reportInfo.linkReport,
					'subLinkReport' : self.reportInfo.subLinkReport,
					'reportItemList': gDashboard.datasetMaster.getState().fields,
					'allowDuplication': userJsonObject.siteNm == 'KAMKO',
				};
				/* dogfoot What If 분석용 매개변수 저장 shlim 20201022 */
				if (gDashboard.customParameterHandler.getArrayCalcParamInfomation().length > 0){
					$.extend(param.param_xml, gDashboard.customParameterHandler.calcParameterInformation);
				}
				self.insertDatasetSaveInfo(param.dataset_xml);

				var jsonParam = {};
				jsonParam['JSON_REPORT'] = JSON.stringify(param);


				if(gDashboard.reportType == 'AdHoc'){
    				$.ajax({
                    	method : 'POST',
                        url: WISE.Constants.context + '/report/saveAdhocReport.do',
                        dataType: "json",
                        async:false,
                        data:jsonParam,
                        success: function(result) {

                        	if(result['return_status'] == 200){

                        		var reportTabLi= $('.report-tab ul').find('li');
                        	    var reportTabLiL = reportTabLi.length;

                        		var reportTab = $('.report-tab');
        				        var reportTabUl = $('.report-tab ul');
        				            reportTabLiL = reportTabLiL +1;

        				        var createTab='';
        				            createTab+='<li><span><em>'+ param.report_nm +'</em></span></li>';

        				        reportTab.find('ul').empty().append(createTab);
        				        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
        				        reportTab.find('li').width(100 / reportTabLiL + '%');

        				        $('.report-tab ul').find('li').each(function(){
        				            var createTabCustomData = $(this).find('em').text();
        				        });

        				        $(document).on('click', '.report-tab li', function(e){
        				            $(this).addClass('on').siblings().removeClass('on');
        				        });

	            				if(result['report_id'] != 1){
	            					WISE.Constants.pid = result['report_id'];
	            					self.reportInfo.ReportMasterInfo.id = result['report_id'];
	            				}
// if(result['report_ordinal'] != 1){
	            				self.reportInfo.ReportMasterInfo.ordinal = result['report_ordinal']+"";
// }

	            				self.reportInfo.ReportMasterInfo.all_fld_nm = result['all_fld_nm'];
	            				self.reportInfo.ReportMasterInfo.name = param.report_nm;
	            				self.reportInfo.ReportMasterInfo.tag = param.report_tag;
	            				self.reportInfo.ReportMasterInfo.fld_id = param.fld_id;
	            				self.reportInfo.ReportMasterInfo.fld_type = param.fld_type;
	            				self.reportInfo.ReportMasterInfo.fld_nm = param.fld_nm;
	            				self.reportInfo.ReportMasterInfo.description = param.report_desc;
	            				// 2020.01.07 mksong 경고창 UI 변경 dogfoot
                        		WISE.alert("보고서를 저장하였습니다",'success');

                        	}
                        	else if(result['return_status'] == 422){
                        		// 2020.01.07 mksong 경고창 UI 변경 dogfoot
                        		WISE.alert(result.return_msg,'error');
                        	}
                        	else{
                        		// 2020.01.07 mksong 경고창 UI 변경 dogfoot
                        		WISE.alert("보고서 저장에 실패하였습니다.<br>관리자에게 문의하세요.",'error');
                        	}
                        }
        			});
    			}
			}else if(reportType == 'Spread' || reportType == 'Excel'){

				var param_xml = WISE.libs.Dashboard.item.DatasetUtility.getParamObject(gDashboard.datasetMaster.state.params);
				if(WISE.Context.isCubeReport && gDashboard.isNewReport) {
					param_xml = gDashboard.parameterFilterBar.parameterInformation.length ==0? {}:gDashboard.parameterFilterBar.parameterInformation
				}

				if(WISE.Constants.editmode === "viewer"){
					var tempParam = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

					$.each(tempParam, function(name, data){
						var defaultValue
						if(data.value.length == 1 && data.value[0] == '_ALL_VALUE_'){
							defaultValue = "[ALL]";

						}else{
							var _i;
							defaultValue = "";
							if(data.value.length === 1){
								defaultValue = data.value[0]
							}else {
								for(_i = 0; _i < data.value.length; _i++){
                                    defaultValue += (data.value[_i] + ",");
								}
							}

						}
						/* DOGFOOT ktkang 고용정보원09 뷰어에서 저장 오류 수정  */
//						if(data.parameterType && data.parameterType.indexOf("BETWEEN") > -1){
//                        	if(name.indexOf("_fr") > -1){
//                        		var tempNm = name.replace("_fr", "");
//                        		param_xml[tempNm].DEFAULT_VALUE[0] = defaultValue;
//                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        	}else if(name.indexOf("_to") > -1){
//                        		var tempNm = name.replace("_to", "");
//                        		param_xml[tempNm].DEFAULT_VALUE[1] = defaultValue;
//                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        	}
//                        }else{
//                        	param_xml[name].DEFAULT_VALUE = defaultValue;
//							var temp = JSON.parse(param_xml[name].parameterValues);
//							temp[name].defaultValue = defaultValue;
//							param_xml[name].parameterValues = JSON.stringify(temp);
//							param_xml[name].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        }
					});
				}

				var layout_config;
				if(WISE.Constants.editmode === "viewer")
					layout_config = gDashboard.layoutConfig[self.reportInfo.ReportMasterInfo.id];
				else
					layout_config = gDashboard.layoutConfig;
				
				var direct_view = gDashboard.structure.ReportMasterInfo.direct_view;
				if(typeof direct_view == 'undefined') {
					direct_view = 'N';
				}
				
				param = {
						'isNew' : 'false',
						'report_id': WISE.Constants.pid+"",
						'report_nm' : $('.report-tab ul').find('li').find('em').text(),
						'fld_id' : self.reportInfo.ReportMasterInfo.fld_id+'',
						'fld_type': self.reportInfo.ReportMasterInfo.fld_type+'',
						'fld_nm' : self.reportInfo.ReportMasterInfo.fld_nm+"",
						'report_ordinal': self.reportInfo.ReportMasterInfo.ordinal+"",
						'report_sub_title': self.reportInfo.ReportMasterInfo.report_subtitle+"",
    					'report_type': 'Excel',
    					'report_tag': self.reportInfo.ReportMasterInfo.tag == undefined ? "":self.reportInfo.ReportMasterInfo.tag,
    					'report_desc' :self.reportInfo.ReportMasterInfo.description == undefined ? "" : self.reportInfo.ReportMasterInfo.description,
    					'report_layout':'',
    					'datasrc_id': '0',
    					'datasrc_type': '',
    					'dataset_type': '',
    					//'report_xml': '<EXCEL_XML><SHEET_ELEMENT /></EXCEL_XML>',
    					/*dogfoot 테이블 바인드 바인드 위치값 저장 shlim 20200727*/
    					'report_xml':  gDashboard.spreadsheetManager.getReportXml(),
    					'chart_xml': self.reportInfo.MapOption,
    					'layout_xml' : {},
    					'param_xml': param_xml,
    					'dataset_xml' : {},// gDashboard.dataSourceManager.datasetInformation,
    					'dataset_query': '',
//'reg_user_Id':userJsonObject.userId+'',
    					'prompt_yn':self.reportInfo.ReportMasterInfo.promptYn,
    					/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
    					'layout_config' : JSON.stringify(layout_config? layout_config : {}),
    					'direct_view' : direct_view,
    					/**
					 * KERIS 수정
					 */
    					'userid' : userJsonObject.userId+"",
    					'linkReport' : self.reportInfo.linkReport,
    					'subLinkReport' : self.reportInfo.subLinkReport,
    					'reportItemList': gDashboard.datasetMaster.getState().fields,
    					'allowDuplication': userJsonObject.siteNm == 'KAMKO',
    				};

				self.insertDatasetSaveInfo(param.dataset_xml);

				var jsonParam = {};
				jsonParam['JSON_REPORT'] = JSON.stringify(param);
				/* DOGFOOT hsshim 200103
				 * 스프레드 저장 기능 개선
 				 */
				gDashboard.spreadsheetManager.getBlobFromSpreadJS(JSON.stringify(param));


			}else{
				/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
				var param_xml = WISE.libs.Dashboard.item.DatasetUtility.getParamObject(gDashboard.datasetMaster.state.params);
				if(WISE.Context.isCubeReport && gDashboard.isNewReport) {
					param_xml = gDashboard.parameterFilterBar.parameterInformation.length ==0? {}:gDashboard.parameterFilterBar.parameterInformation
				}

				if(WISE.Constants.editmode === "viewer"){
					var tempParam = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

					$.each(tempParam, function(name, data){
						var defaultValue
						if(data.value.length == 1 && data.value[0] == '_ALL_VALUE_'){
							defaultValue = "[ALL]";

						}else{
							var _i;
							defaultValue = "";
							if(data.value.length === 1){
								defaultValue = data.value[0]
							}else {
								for(_i = 0; _i < data.value.length; _i++){
                                    defaultValue += (data.value[_i] + ",");
								}
							}

						}
						/* DOGFOOT ktkang 고용정보원09 뷰어에서 저장 오류 수정  */
//						if(data.parameterType && data.parameterType.indexOf("BETWEEN") > -1){
//                        	if(name.indexOf("_fr") > -1){
//                        		var tempNm = name.replace("_fr", "");
//                        		param_xml[tempNm].DEFAULT_VALUE[0] = defaultValue;
//                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        	}else if(name.indexOf("_to") > -1){
//                        		var tempNm = name.replace("_to", "");
//                        		param_xml[tempNm].DEFAULT_VALUE[1] = defaultValue;
//                        		param_xml[tempNm].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        	}
//                        }else{
//                        	param_xml[name].DEFAULT_VALUE = defaultValue;
//							var temp = JSON.parse(param_xml[name].parameterValues);
//							temp[name].defaultValue = defaultValue;
//							param_xml[name].parameterValues = JSON.stringify(temp);
//							param_xml[name].DEFAULT_VALUE_USE_SQL_SCRIPT = "N"
//                        }
					});
				}

				var layout_config;
				if(WISE.Constants.editmode === "viewer")
					layout_config = gDashboard.layoutConfig[self.reportInfo.ReportMasterInfo.id];
				else
					layout_config = gDashboard.layoutConfig;
				
				var direct_view = gDashboard.structure.ReportMasterInfo.direct_view;
				if(typeof direct_view == 'undefined') {
					direct_view = 'N';
				}
				
				var param = {
					'isNew' : 'false',
					'report_id': WISE.Constants.pid+"",
					'report_nm' : $('.report-tab ul').find('li').find('em').text(),
// 'report_nm': self.reportInfo.ReportMasterInfo.name+"",
					'fld_id' : self.reportInfo.ReportMasterInfo.fld_id+'',
					'fld_type': self.reportInfo.ReportMasterInfo.fld_type+'',
					'fld_nm' : self.reportInfo.ReportMasterInfo.fld_nm+"",
					'report_ordinal': self.reportInfo.ReportMasterInfo.ordinal+"",
//					'report_type':'DashAny', // 고정
					/*dogfoot 20201030 shlim 통계 분석 저장 작업 중 */
					'report_type': gDashboard.reportType,
					/* DOGFOOT hsshim 2020-01-16 보고서 부재목 저장 오류 수정 */
					'report_sub_title': self.reportInfo.ReportMasterInfo.report_sub_title == undefined ? "" : self.reportInfo.ReportMasterInfo.report_sub_title,
					'report_tag': self.reportInfo.ReportMasterInfo.tag == undefined ? "":self.reportInfo.ReportMasterInfo.tag,
					'report_desc' :self.reportInfo.ReportMasterInfo.description == undefined ? "" : self.reportInfo.ReportMasterInfo.description,
					'report_layout':'',
					'datasrc_id': '0',
					'datasrc_type': '',
					'dataset_type': '',
					'report_xml': '<REPORT_XML><REALTIME_ELEMENT>0</REALTIME_ELEMENT></REPORT_XML>',
					'chart_xml': self.reportInfo.MapOption,
					'layout_xml' : {"DataSources":self.reportInfo.DataSources,"Items":self.reportInfo.Items, "LayoutTree":self.reportInfo.LayoutTree,"Title":{"Text": $('.report-tab ul').find('li').find('em').text(),"Alignment":"Left"}},
					'param_xml': param_xml,
					'dataset_xml' : {},// gDashboard.dataSourceManager.datasetInformation,
					'dataset_query': '',
// 'reg_user_Id':userJsonObject.userId+'',
					/* DOGFOOT ktkang 보고서별 LAYOUT_CONFIG 저장 추가  20200812 */
					'layout_config' : JSON.stringify(layout_config? layout_config : {}),
					'direct_view' : direct_view,
					'prompt_yn':self.reportInfo.ReportMasterInfo.promptYn,
					/**
					 * KERIS 수정
					 */
					'userid' : userJsonObject.userId+"", // '2087' + "",
					'linkReport' : self.reportInfo.linkReport,
					'subLinkReport' : self.reportInfo.subLinkReport,
					'reportItemList': gDashboard.datasetMaster.getState().fields,
					'allowDuplication': userJsonObject.siteNm == 'KAMKO',
				};

				if(WISE.Constants.editmode === "viewer"){
    				var layout_item = (param.layout_xml.LayoutTree.LayoutItem || param.layout_xml.LayoutTree.LayoutGroup[0].LayoutItem);

    				$.each(layout_item, function(i, data){
    					data.DashboardItem = data.DashboardItem.slice(0, data.DashboardItem.lastIndexOf("_"))
    				})
    			}

				/* dogfoot What If 분석용 매개변수 저장 shlim 20201022 */
				if (gDashboard.customParameterHandler.getArrayCalcParamInfomation().length > 0){
					$.extend(param.param_xml, gDashboard.customParameterHandler.calcParameterInformation);
				}
				/*20210305 AJKIM BETWEEN 저장 오류 수정 dogfoot*/
				$.each(param.param_xml, function(i, data){
					if(data.PARAM_TYPE.indexOf("BETWEEN") > -1&& data.DEFAULT_VALUE_USE_SQL_SCRIPT === 'N'
					&& typeof data.DEFAULT_VALUE === "object"){
						data.DEFAULT_VALUE = data.DEFAULT_VALUE[0] + "," + data.DEFAULT_VALUE[1];
					}
				});

				self.insertDatasetSaveInfo(param.dataset_xml);

				var jsonParam = {};
				jsonParam['JSON_REPORT'] = JSON.stringify(param);


				$.ajax({
	            	method : 'POST',
	                url: WISE.Constants.context + '/report/saveReport.do',
	                dataType: "json",
	                data:jsonParam,
	                /* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//	                async:false,
	                success: function(result) {

	                	if(result['return_status'] == 200){

	                		var reportTabLi= $('.report-tab ul').find('li');
	                	    var reportTabLiL = reportTabLi.length;

	                		var reportTab = $('.report-tab');
					        var reportTabUl = $('.report-tab ul');
					            reportTabLiL = reportTabLiL +1;

					        var createTab='';
					            createTab+='<li><span><em>'+ param.report_nm +'</em></span></li>';

					        reportTab.find('ul').empty().append(createTab);
					        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
					        reportTab.find('li').width(100 / reportTabLiL + '%');

					        $('.report-tab ul').find('li').each(function(){
					            var createTabCustomData = $(this).find('em').text();
					        });

					        $(document).on('click', '.report-tab li', function(e){
					            $(this).addClass('on').siblings().removeClass('on');
					        });

	        				if(result['report_id'] != 1){
	        					WISE.Constants.pid = result['report_id'];
	        					self.reportInfo.ReportMasterInfo.id = result['report_id'];
	        				}
// if(result['report_ordinal'] != 1){
// self.reportInfo.ReportMasterInfo.ordinal = result['report_ordinal'];
// }
	        				self.reportInfo.ReportMasterInfo.all_fld_nm = result['all_fld_nm'];
	        				self.reportInfo.ReportMasterInfo.name = param.report_nm;
	        				self.reportInfo.ReportMasterInfo.tag = param.report_tag;
	        				self.reportInfo.ReportMasterInfo.fld_id = param.fld_id;
	        				self.reportInfo.ReportMasterInfo.fld_type = param.fld_type;
	        				self.reportInfo.ReportMasterInfo.fld_nm = param.fld_nm;
	        				self.reportInfo.ReportMasterInfo.description = param.report_desc;
	        				self.reportInfo.ReportMasterInfo.ordinal = param.report_ordinal+"";
	        				// 2020.01.07 mksong 경고창 UI 변경 dogfoot
	                		WISE.alert("보고서를 저장하였습니다",'success');

	                	}
	                	else{
	                		// 2020.01.07 mksong 경고창 UI 변경 dogfoot
	                		WISE.alert("보고서 저장에 실패하였습니다.<br>관리자에게 문의하세요.",'error');
	                	}
	                }
				});


			}
		}
	};

	/* DOGFOOT ktkang 보고서 삭제 기능 추가  20200214 */
	this.deleteReport = function() {
		if(WISE.Constants.pid != ""){
			var options = {
					buttons: {
						confirm: {
							id: 'confirm',
							className: 'blue',
							text: '확인 ',
							action: function() {
								$AlertPopup.hide();
								$.ajax({
									url: WISE.Constants.context + '/report/deletePublicReport.do',
									method: 'POST',
									data: {
										'id': WISE.Constants.pid
									},
									success: function(result) {
										var options2 = {
												buttons: {
													confirm: {
														id: 'confirm',
														className: 'blue',
														text: '확인 ',
														action: function() {
															if(gDashboard.reportType == 'AdHoc') {
																var url = window.location.href;
																url = url.substring(0, url.lastIndexOf('/') + 1);
																var frm = document.mainAdhocName;
																frm.action = url + 'edit.do';
																frm.target = "oldPage";
																frm.submit();
															} else {
																var url = window.location.href;
																window.location.replace(url.substring(0, url.lastIndexOf('/') + 1) + 'edit.do');
															}
														}
													}
												}
											};
										WISE.alert(gMessage.get('config.delete.success'),'success',options2);
									},
									error: function(_e) {
										WISE.alert(gMessage.get('config.delete.failed')+ajax_error_message(_e),'error');
									}
								});
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
			    WISE.confirm(gMessage.get('config.delete.confirm'), options);
		} else {
			/*dogfoot 알림창 형식 변경 shlim 20200714*/
			WISE.alert(gMessage.get('config.delete.notopened'));
		}
	}
	/* DOGFOOT ktkang 보고서 삭제 기능 추가 끝  20200214 */

	/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  20200123 */
	//KERIS
	this.reportProperty = function(){
		var html = "<div class=\"modal-body\" style='height:88%'>\r\n" +
		"                        <div class=\"row\" style='height:100%'>\r\n" +
		"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>보고서 명</span>\r\n" +
		"                                   </div>\r\n" +
		"									<div style='text-align: right;'>\r\n"+
		"										<div id=\"report_title\"></div>\r\n" +
		"									</div>\r\n"+
		"                                </div>\r\n" +
//		"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
//		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
//		"                                   	<span>보고서 부제목</span>\r\n" +
//		"                                   </div>\r\n" +
//		"								 <div id=\"report_subtitle\"></div>\r\n" +
//		"                                </div>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>저장 폴더</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"report_folder_name\" style=\"float:left; margin-right: 5px\"></div><div id=\"change_folder\" style=\"display: inline-block;\"></div>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>표시순서</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"report_show_order\"></div>\r\n" +
		"                                </div>\r\n" +
//		"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
//		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
//		"                                   	<span>주석</span>\r\n" +
//		"                                   </div>\r\n" +
//		"								 <div id=\"report_annotiation\"></div>\r\n" +
//		"                                </div>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top: 5px;height:150px;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>설명</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"report_description\" style=\"height:70%;\"></div>\r\n" +
		"                                </div>\r\n" +
		"								 <div id=\"reportDirectView\" style=\"margin-top: 20px; float: right;\"></div>" +
//		"                                <div class=\"modal-article\" style=\"margin-top: 5px;height: 200px;\">\r\n" +
//		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
//		"                                   	<span>보고서 필드 정보</span>\r\n" +
//		"                                   </div>\r\n" +
//		"								 <div id=\"report_fields\" style=\"height:100%;\"></div>\r\n" +
		"                                </div>\r\n" +
		"                            </div>\r\n" +
		"                        </div>\r\n" + // row 끝
		"                    </div>\r\n" + // modal-body 끝
		"					 <div id='save_box' style='text-align: center;'/>"+
		"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
		"                        <div class=\"row center\">\r\n" +
		"                            <a id=\"ok_button\" class=\"btn positive ok-hide\">확인</a>\r\n" +
		"                            <a id=\"cancel_button\" class=\"btn neutral ok-hide\">취소</a>\r\n" +
		"                        </div>\r\n" +
		"                    </div>\r\n" +
		"                </div>";

		if($('#propertyPopup').length == 0){
			$('body').append("<div id='propertyPopup'></div>");
		}

		if(WISE.Constants.pid != ""){
			var page = window.location.pathname.split('/');
			var isViewer = page[page.length - 1] === 'viewer.do' ? true : false;
			$('#propertyPopup').dxPopup({
				title:'보고서 속성',
				width:'600px',
				height:'600px',
				visible:true,
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForOption('propertyPopup');
				},
				closeOnOutsideClick: false,
				showCloseButton: false,
			    contentTemplate: function() {
	                return html;
	            },
	            onShown:function(){
	            	if (isViewer) {
	            		// $('#cancel_button').hide();
	            	}

	            	/* DOGFOOT ktkang 뷰어에서 보고서 속성 꼬이는 오류 수정  20200110 */
	            	var reportInfomation = "";
	            	$.each(gDashboard.structureBuffer, function(_i,_e){
	    				if(_e.reportId == WISE.Constants.pid){
	    					reportInfomation = _e.structure.ReportMasterInfo;
	    				}
	    			});
	            	if(reportInfomation == "") {
	            		reportInfomation = gDashboard.reportUtility.reportInfo.ReportMasterInfo;
	            	}

	            	var title = $('#report_title').dxTextBox({
	            		readOnly: isViewer,
						value: reportInfomation.name
	            	}).dxTextBox('instance');
//	            	var subtitle = $('#report_subtitle').dxTextBox({
//	            		readOnly: isViewer,
//	            		value: reportInfomation.report_sub_title
//	            	}).dxTextBox('instance');
	            	var folderName = $('#report_folder_name').dxTextBox({
	            		readOnly: true,
	            		value: reportInfomation.all_fld_nm,
	            		width: "calc(100% - 40px)"
	            	}).dxTextBox('instance');

	            	var changeFolder = $('#change_folder').dxButton({
	            		icon: "search",
	            		width: "35px",
	            		onClick: function(e) {
	            			$('#save_box').append("<div id='selectFolder'></div>");
	    					if(typeof  gDashboard.structure.ReportMasterInfo.fld_type == 'undefined'){
	    						return;
	    					}
	    					var folderhtml = "<div class=\"modal-body\" style='height:87%'>\r\n" +
	    					"                        <div class=\"row\" style='height:100%'>\r\n" +
	    					"                            <div class=\"column\" style='width:100%'>\r\n" +
	    					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
	    					"                                   <div class=\"modal-tit\">\r\n" +
	    					"                                   <span>폴더 목록</span>\r\n";
	    					/* DOGFOOT ktkang KERIS 보고서 저장 시 개인폴더 추가하는 기능 주석처리  20200306 */
//	    					if($('#report_folder_type').dxRadioGroup('instance').option('value').value == 'MY') {
//	    						folderhtml += "									<div id=\"addMyfolder\" style=\"float: right\"></div>\r\n";
//	    					}
	    					folderhtml += "                                   </div>\r\n" +
	    					"									<div id=\"folder_tree\" />\r\n" +
	    					"                                </div>\r\n" +
	    					"                            </div>\r\n" +
	    					"                        </div>\r\n" + // row 끝
	    					"                    </div>\r\n" + // modal-body 끝
	    					"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
	    					"                        <div class=\"row center\">\r\n" +
	    					"                            <a id=\"folder_ok\" class=\"btn positive ok-hide\">확인</a>\r\n" +
	    					"                            <a id=\"folder_cancel\" class=\"btn neutral close\">취소</a>\r\n" +
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
	            					var fld_type = gDashboard.structure.ReportMasterInfo.fld_type;
	            					var param = {};
	            					param['fld_type'] = fld_type
	            					var param = {
	            						'user_id' : userJsonObject.userId,
	            						'fld_type' : fld_type
	            					};
	        						$.ajax({
	        				        	method : 'POST',
	        				            url: WISE.Constants.context + '/report/getFolderList.do',
	        				            dataType: "json",
	        				            data:param,
	        				            async:false,
	        				            success: function(result) {
	        				            	var datasource = result.data;
// var selectFLDNm="",selectFLDId="";
	        				            	var selectFLDNm = self.reportInfo.ReportMasterInfo.fld_nm;
	        				            	var selectFLDId = self.reportInfo.ReportMasterInfo.fld_id;
	        				            	var selectedItem;
	        				            	$('#folder_tree').dxTreeView({
	        				            		dataSource:datasource,
	        				            		dataStructure:'plain',
	        				            		keyExpr: "FLD_ID",
	        				            		parentIdExpr: "PARENT_FLD_ID",
	        				            		displayExpr: "FLD_NM",
		            							// mksong 2019.12.20 보고서 검색기능 추가 수정 dogfoot
	        				            		searchEnabled: true,
	        									searchMode : "contains",
	        									searchTimeout:undefined,
	        									searchValue:"",
	        									// 2019.12.10 수정자 : mksong nodataText DOGFOOT
	        									noDataText:"조회된 폴더가 없습니다.",
	        				            		height:"460",
	        				            		showCloseButton: false,
	        				            		onItemClick:function(_e){
	        				            			selectFLDNm = _e.itemData['FLD_NM'];
	        				            			selectFLDId = _e.itemData['FLD_ID'];
	        				            			selectedItem = _e;
	        				            		},
	        				            		onContentReady: function(){
	        				            			gDashboard.fontManager.setFontConfigForListPopup('folder_tree')
	        				            		}
	        				            	});
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

	        				            			if(selectFLDNm != "" && selectFLDId != ""){
	        				            				$('#report_folder_name').dxTextBox('instance').option('value', getAllFldNm(selectedItem.node, 0));
	        				            				$('#report_folder_name').dxTextBox('instance').option('fld_id',selectFLDId);
	        				            				$('#report_folder_name').dxTextBox('instance').option('fld_nm',selectFLDNm);
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
	            	})
	            	var showOrder = $('#report_show_order').dxNumberBox({
	            		readOnly: isViewer,
	            		value: reportInfomation.ordinal,
	            		width:"20%"
	            	}).dxNumberBox('instance');
//	            	var annotation = $('#report_annotiation').dxTextBox({
//	            		readOnly: isViewer,
//	            		value: reportInfomation.tag
//	            	}).dxTextBox('instance');
	            	var description = $('#report_description').dxTextArea({
	            		readOnly: isViewer,
//	            		height: "110px",
	            		value: reportInfomation.description,
	            		onContentReady: function() {
	    					gDashboard.fontManager.setFontConfigForOption('propertyPopup');
	    				}
	            	}).dxTextArea('instance');

	            	/*
	            	$.ajax({
    					url: WISE.Constants.context + '/report/getReportFieldList.do',
    					method: 'POST',
    					data: {
    						'reportId': gDashboard.structure.ReportMasterInfo.id
    					},
    					success: function(result) {
    						result = result.data;

    						var fieldType = [{'ID' : 'DIM', 'FIELD_TYPE' : '차원'}, {'ID' : 'MEA', 'FIELD_TYPE' : '측정값'},  {'ID' : 'TBL', 'FIELD_TYPE' : '테이블'}];
    						var editing = true;
    						if(isViewer) {
    							editing = false;
    						}
    						$("#report_fields").dxDataGrid({
    							dataSource: result,
    							showBorders: true,
    							scrolling: {
    								mode: "infinite"
    							},
    							editing: {
    					            mode: "batch",
    					            allowUpdating: editing,
    					            allowAdding: editing,
    					            allowDeleting: editing,
    					            selectTextOnEditStart: editing,
    					            startEditAction: "click"
    							},
    							columns: [
    								{
    									dataField: "FIELD_NM",
    									caption: "필드 명",
    								},
    								{
    									dataField: "FIELD_TYPE",
    									caption: "필드 타입",
    									lookup: {
    										dataSource: fieldType,
    										displayExpr: "FIELD_TYPE",
    										valueExpr: "ID"
    									}
    								}
    							]
    						});
    					},
    					error: function(_e) {
        					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
    						WISE.alert(gMessage.get('config.save.failed')+ajax_error_message(_e),'error');
    					}
    				});
    				*/

	            	/* DOGFOOT ktkang 인수테스트 및 BMT 내용  20200109 */
	            	var directView = false;
	            	if(typeof gDashboard.structure.ReportMasterInfo.direct_view != 'undefined' && gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
	            		directView = true;
	            	}
	            	$('#reportDirectView').dxCheckBox({
						text:"바로 조회 옵션",
						value: directView,
						onValueChanged: function() {
							var directView = $('#reportDirectView').dxCheckBox('instance').option('value');
							if(directView) {
								gDashboard.structure.ReportMasterInfo.direct_view = 'Y';
							} else {
								gDashboard.structure.ReportMasterInfo.direct_view = 'N';
							}
							
						}
					});

	            	$('#ok_button').dxButton({
// type:'danger',
	            		text:'확인',
	            		onClick:function(){
//	            			if(page[page.length - 1] !== 'viewer.do'){
//	            				$('.report-tab ul').find('li').find('em').text($('#report_title').dxTextBox('instance').option('text'));
//		            			gDashboard.reportUtility.reportInfo.ReportMasterInfo.ordinal = self.reportInfo.ReportMasterInfo.ordinal = $('#report_show_order').dxNumberBox('instance').option('value')+'';
//		            			setTimeout(function () {self.saveReport("true")},100);
//	            			}

	            			if(!isViewer){
//	            				var reportFieldGrid = $("#report_fields").dxDataGrid('instance');
//	            				reportFieldGrid = reportFieldGrid.option('dataSource');
//	            				reportFieldGrid = JSON.stringify(reportFieldGrid);
	            				$.ajax({
	            					url: WISE.Constants.context + '/report/savePublicReport.do',
	            					method: 'POST',
	            					data: {
	            						'ID': gDashboard.structure.ReportMasterInfo.id,
	            						'PROMPT': gDashboard.structure.ReportMasterInfo.promptYn,
	            						'TEXT': title.option('value'),
	            						'FLD_ID': folderName.option("fld_id")? folderName.option("fld_id"): gDashboard.structure.ReportMasterInfo.fld_id,
//	            						'SUBTITLE': subtitle.option('value'),
//	            						'TAG': annotation.option('value'),
	            						'ORDINAL': showOrder.option('value'),
	            						/* DOGFOOT ktkang KERIS 보고서 필드 정보에 설명도 추가  20200207 */
	            						'DESCRIPTION': description.option('value')? description.option('value'): "",
	            						'DIRECTVIEW' : gDashboard.structure.ReportMasterInfo.direct_view
//	            						'REPORTFIELDLIST': reportFieldGrid
	            					},
	            					success: function() {
										gDashboard.structure.ReportMasterInfo.name = title.option('value');
										/* DOGFOOT hsshim 2020-01-15 보고서 부재목 저장 오류 수정 */
										/* DOGFOOT ktkang KERIS 보고서 필드 정보에 설명도 추가  20200207 */
										if(folderName.option("fld_id")){
											gDashboard.structure.ReportMasterInfo.fld_id = folderName.option("fld_id");
											gDashboard.structure.ReportMasterInfo.all_fld_nm = folderName.option('value');
											gDashboard.structure.ReportMasterInfo.fld_nm = folderName.option("fld_nm");
										}

//	    	            				gDashboard.structure.ReportMasterInfo.report_sub_title = subtitle.option('value') + '';
	    	            				gDashboard.structure.ReportMasterInfo.ordinal = showOrder.option('value') + '';
//	    	            				gDashboard.structure.ReportMasterInfo.tag = annotation.option('value') + '';
	    	            				gDashboard.structure.ReportMasterInfo.description = (description.option('value')? description.option('value'): "") + '';
	    	            				$('.report-tab').find('em').text(title.option('value'));
	    	            				// 2020.01.07 mksong 경고창 UI 변경 dogfoot
	            						WISE.alert(gMessage.get('config.save.success'),'success');
	            					},
	            					error: function(_e) {
		            					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
	            						WISE.alert(gMessage.get('config.save.failed')+ajax_error_message(_e),'error');
	            					}
	            				});
	            			}
		            		$('#propertyPopup').dxPopup('instance').hide();
		            		$('#propertyPopup').remove();
	            		}
	            	});
	            	$('#cancel_button').dxButton({
	            		text: '취소',
	            		onClick: function() {
	            			$('#propertyPopup').dxPopup('instance').hide();
		            		$('#propertyPopup').remove();
	            		}
	            	});

	            }
			});
		}else{
			/* DOGFOOT hsshim 200107
			 * 스프레드 저장 기능 개선
			 */
			if(WISE.Constants.editmode !== 'spreadsheet'){
				self.setupITEM_Layout();
			}

			var exit = true;
			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_e){
				/*dogfoot 저장 안된 보고서 보고서 속성버튼 반응 하도록 변경 20200724*/
//				if(_e.meta == undefined && exit == true){
				if(gDashboard.isNewReport == true && exit == true){
					/*dogfoot 알림창 형식 변경 shlim 20200714*/
    				WISE.alert("보고서 정보가 없습니다.");
    				exit = false;
    				return false;
				}else if(exit ==false){
					return false;
				}
			});
			if(exit == false){
				return false;
			}
		}
	};

	/* DOGFOOT shlim 보고서 레이아웃 js파일 분리 20200820 */

	/* DOGFOOT ktkang KERIS 보고서 별 필드 정보 추가기능  20200123 */
	this.adhocQueryView = function(){
		var html = "<div class=\"modal-body\" style='height:93%'>\r\n" +
		"                        <div class=\"row\" style='height:100%'>\r\n" +
		"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top: 5px;height:100%;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>주제영역 쿼리</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"adhocCubeQuery\" style=\"height:100%;\"></div>\r\n" +
		"                                </div>\r\n" +
		"                            </div>\r\n" +
		"                        </div>\r\n" + // row 끝
		"                    </div>\r\n" + // modal-body 끝
		"					 <div id='save_box' style='text-align: center;'/>"+
		"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
		"                        <div class=\"row center\">\r\n" +
		"                            <a id=\"ok_cube_query_button\" class=\"btn positive ok-hide\">확인</a>\r\n" +
		"                            <a id=\"cancel_cube_query_button\" class=\"btn neutral ok-hide\">취소</a>\r\n" +
		"                        </div>\r\n" +
		"                    </div>\r\n" +
		"                </div>";

		if($('#queryViewPopup').length == 0){
			$('body').append("<div id='queryViewPopup'></div>");
		}

		var page = window.location.pathname.split('/');
		var isViewer = page[page.length - 1] === 'viewer.do' ? true : false;
		$('#queryViewPopup').dxPopup({
			title:'주제영역 쿼리',
			width:'600px',
			height:'800px',
			visible:true,
			closeOnOutsideClick: false,
			showCloseButton: false,
			contentTemplate: function() {
				return html;
			},
			onShown:function(){
				if(Object.keys(gDashboard.dataSourceManager.datasetInformation).length != 0) {
					$('#adhocCubeQuery').dxTextArea({
						readOnly: isViewer,
						height: "600px",
						value: gDashboard.dataSourceManager.datasetInformation.dataSource1.DATASET_QUERY
					}).dxTextArea('instance');
				}
				$('#ok_cube_query_button').dxButton({
					text:'확인',
					onClick:function(){
						$('#queryViewPopup').dxPopup('instance').hide();
						$('#queryViewPopup').remove();
					}
				});
				$('#cancel_cube_query_button').dxButton({
					text: '취소',
					onClick: function() {
						$('#queryViewPopup').dxPopup('instance').hide();
						$('#queryViewPopup').remove();
					}
				});

			}
		});
	};

	this.setupITEM_Layout = function(){
		self.reportInfo.Items = {};
		self.reportInfo.Items['Pivot'] = [];
		self.reportInfo.Items['Grid'] = [];
		self.reportInfo.Items['Chart'] = [];
		self.reportInfo.Items['Pie'] = [];
		self.reportInfo.Items['Card'] = [];
		/* DOGFOOT hsshim 2020-02-03 게이지 저장 기능 작업 */
		self.reportInfo.Items['Gauge'] = [];
		self.reportInfo.Items['ChoroplethMap'] = [];
		self.reportInfo.Items['Treemap'] = [];
		self.reportInfo.Items['Parallel'] = [];
		self.reportInfo.Items['BubblePackChart'] = [];
		self.reportInfo.Items['WordCloudV2'] = [];
		self.reportInfo.Items['DendrogramBarChart'] = [];
		self.reportInfo.Items['CalendarViewChart'] = [];
		self.reportInfo.Items['CalendarView2Chart'] = [];
		self.reportInfo.Items['CalendarView3Chart'] = [];
		self.reportInfo.Items['CollapsibleTreeChart'] = [];
		self.reportInfo.Items['HeatMap'] = [];
		self.reportInfo.Items['HeatMap2'] = [];
		self.reportInfo.Items['CoordinateDot'] = [];
		self.reportInfo.Items['SynchronizedChart'] = [];
		self.reportInfo.Items['WordCloud'] = [];
		self.reportInfo.Items['RangeBarChart'] = [];
		self.reportInfo.Items['RangeAreaChart'] = [];
		self.reportInfo.Items['TimeLineChart'] = [];
		self.reportInfo.Items['HistogramChart'] = [];
		self.reportInfo.Items['DivergingChart']=[];
		self.reportInfo.Items['DependencyWheel']=[];
		self.reportInfo.Items['SequencesSunburst']=[];
		self.reportInfo.Items['BoxPlot']=[];
		self.reportInfo.Items['CoordinateLine']=[];
		self.reportInfo.Items['ScatterPlot']=[];
		self.reportInfo.Items['ScatterPlot2']=[];
		self.reportInfo.Items['RadialTidyTree'] = [];
		self.reportInfo.Items['ScatterPlotMatrix'] = [];
		self.reportInfo.Items['HistoryTimeline'] = [];
		self.reportInfo.Items['LiquidFillGauge']=[];
		self.reportInfo.Items['ArcDiagram']=[];
		self.reportInfo.Items['Starchart'] = [];
		self.reportInfo.Items['ListBox'] = [];
		self.reportInfo.Items['TreeView'] = [];
		self.reportInfo.Items['ComboBox'] = [];
		self.reportInfo.Items['RectangularAreaChart'] = [];
		self.reportInfo.Items['Waterfallchart'] = [];
		self.reportInfo.Items['Bipartitechart'] = [];
		self.reportInfo.Items['Pyramidchart'] = [];
		/* DOGFOOT syjin 카카오 지도 추가  20200820 */
		self.reportInfo.Items['KakaoMap'] = [];
		self.reportInfo.Items['KakaoMap2'] = [];
		self.reportInfo.Items['Funnelchart'] = [];
		self.reportInfo.Items['Sankeychart'] = [];
		self.reportInfo.Items['BubbleD3'] = [];
		self.reportInfo.Items['BubbleChart'] = [];
		self.reportInfo.Items['Image'] = []; // ymbin
		self.reportInfo.Items['TextBox'] = []; // ymbin
		self.reportInfo.Items['Hierarchical'] = [];
		self.reportInfo.Items['ForceDirect'] = [];
		self.reportInfo.Items['ForceDirectExpand'] = [];

		/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
		var tabContainerInfo;
		if(WISE.Constants.editmode === "viewer")
			tabContainerInfo = gDashboard.goldenLayoutManager[self.reportInfo.ReportMasterInfo.id].getTabContainerInfo();
		else
			tabContainerInfo = gDashboard.goldenLayoutManager.getTabContainerInfo();


		if (tabContainerInfo) {
			self.reportInfo.Items['TabContainer'] = tabContainerInfo;
		/* DOGFOOT ktkang 탭컨테이너 삭제하면 저장안되는 오류 수정  20201113 */
		} else if(tabContainerInfo == null){
			self.reportInfo.Items['TabContainer'] = [];
		}

		this.CU = WISE.libs.Dashboard.item.ChartUtility;
		// web-only settings
		/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
		if(typeof self.reportInfo.MapOption === 'undefined'){
			self.reportInfo.MapOption = {
				'DASHBOARD_XML' : {
					WEB : {},
					MAIN_ELEMENT : {CANVAS_WIDTH: 0, CANVAS_AUTO: true, CANVAS_WIDTH: 0}
				}
			}
		}
		self.reportInfo.MapOption.DASHBOARD_XML.WEB = {};
		// initialize item elements
		_.each(gDashboard.itemGenerateManager.dxItemBasten,function(_e){
			switch(_e.type){
				case 'PIVOT_GRID':
					self.reportInfo.MapOption.DASHBOARD_XML.PIVOT_GRID_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.PIVOT_GRID_ELEMENT = [];
					break;
				case 'DATA_GRID':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.DATA_GRID_ELEMENT = [];
					/*dogfoot 통계 분석 추가 shlim 20201103*/
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT = [];
					break;
				case 'PIE_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.PIE_DATA_ELEMENT = [];
					break;
				case 'SIMPLE_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.TIME_SERIES_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT = [];
					break;
				case 'CARD_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CARD_DATA_ELEMENT = [];
					break;
				/* DOGFOOT hsshim 2020-02-03 게이지 저장 기능 작업 */
				case 'GAUGE_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.GAUGE_DATA_ELEMENT = [];
					break;
				case 'CHOROPLETH_MAP':
					//2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가  dogfoot
					self.reportInfo.MapOption.DASHBOARD_XML.CHOROPLETH_MAP_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CHOROPLETH_MAP_ELEMENT = [];
					break;
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case 'KAKAO_MAP':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP_ELEMENT = [];
					break;
				case 'KAKAO_MAP2':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP2_ELEMENT = [];
					break;
				case 'STAR_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.STAR_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.STAR_DATA_ELEMENT = [];
					break;
				case 'FUNNEL_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.FUNNEL_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.FUNNEL_CHART_DATA_ELEMENT = [];
					break;
				case 'PYRAMID_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.PYRAMID_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.PYRAMID_CHART_DATA_ELEMENT = [];
					break;
				case 'TREEMAP':
					self.reportInfo.MapOption.DASHBOARD_XML.TREEMAP_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.TREEMAP_DATA_ELEMENT = [];
					break;
				case 'PARALLEL_COORDINATE':
					self.reportInfo.MapOption.DASHBOARD_XML.PARALLEL_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.PARALLEL_DATA_ELEMENT = [];
					break;
				case 'BUBBLE_PACK_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.BUBBLE_PACK_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.BUBBLE_PACK_CHART_DATA_ELEMENT = [];
					break;
				case 'WORD_CLOUD_V2':
					self.reportInfo.MapOption.DASHBOARD_XML.WORD_CLOUD_V2_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.WORD_CLOUD_V2_DATA_ELEMENT = [];
					break;
				case 'DENDROGRAM_BAR_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.DENDROGRAM_BAR_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.DENDROGRAM_BAR_CHART_DATA_ELEMENT = [];
					break;
				case 'CALENDAR_VIEW_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.CALENDAR_VIEW_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW_CHART_DATA_ELEMENT = [];
					break;
				case 'CALENDAR_VIEW2_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.CALENDAR_VIEW2_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW2_CHART_DATA_ELEMENT = [];
					break;
				case 'CALENDAR_VIEW3_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.CALENDAR_VIEW3_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW3_CHART_DATA_ELEMENT = [];
					break;
				case 'COLLAPSIBLE_TREE_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.COLLAPSIBLE_TREE_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.COLLAPSIBLE_TREE_CHART_DATA_ELEMENT = [];
					break;
				case 'RANGE_BAR_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.RANGE_BAR_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.RANGE_BAR_CHART_DATA_ELEMENT = [];
					break;
				case 'RANGE_AREA_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.RANGE_AREA_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.RANGE_AREA_CHART_DATA_ELEMENT = [];
					break;
				case 'TIME_LINE_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.TIME_LINE_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.TIME_LINE_CHART_DATA_ELEMENT = [];
					break;
				case 'BUBBLE_D3':
					self.reportInfo.MapOption.DASHBOARD_XML.BUBBLE_D3_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.BUBBLE_D3_DATA_ELEMENT = [];
					break;
				case 'BUBBLE_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT = [];
					break;
				case 'RECTANGULAR_ARAREA_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.RECTANGULAR_ARAREA_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.RECTANGULAR_ARAREA_CHART_DATA_ELEMENT = [];
					break;
				case 'WATERFALL_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.WATERFALL_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.WATERFALL_CHART_DATA_ELEMENT = [];
					break;
				case 'BIPARTITE_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.BIPARTITE_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.BIPARTITE_CHART_DATA_ELEMENT = [];
					break;
				case 'SANKEY_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.SANKEY_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SANKEY_CHART_DATA_ELEMENT = [];
					break;
				case 'HEATMAP':
					self.reportInfo.MapOption.DASHBOARD_XML.HEATMAP_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HEATMAP_DATA_ELEMENT = [];
					break;
				case 'HEATMAP2':
					self.reportInfo.MapOption.DASHBOARD_XML.HEATMAP2_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HEATMAP2_DATA_ELEMENT = [];
					break;
				case 'SYNCHRONIZED_CHARTS':
					self.reportInfo.MapOption.DASHBOARD_XML.SYNCHRONIZED_CHARTS_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SYNCHRONIZED_CHARTS_DATA_ELEMENT = [];
					break;
				case 'COORDINATE_DOT':
					self.reportInfo.MapOption.DASHBOARD_XML.COORDINATE_DOT_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.COORDINATE_DOT_DATA_ELEMENT = [];
					break;
				case 'WORD_CLOUD':
					self.reportInfo.MapOption.DASHBOARD_XML.WORD_CLOUD_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.WORD_CLOUD_DATA_ELEMENT = [];
					break;
				case 'HISTOGRAM_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.HISTOGRAM_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HISTOGRAM_CHART_DATA_ELEMENT = [];
					break;
				case 'DIVERGING_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.DIVERGING_CHART_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.DIVERGING_CHART_DATA_ELEMENT = [];
					break;
				case 'DEPENDENCY_WHEEL':
					self.reportInfo.MapOption.DASHBOARD_XML.DEPENDENCY_WHEEL_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.DEPENDENCY_WHEEL_DATA_ELEMENT = [];
					break;
				case 'SEQUENCES_SUNBURST':
					self.reportInfo.MapOption.DASHBOARD_XML.SEQUENCES_SUNBURST_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SEQUENCES_SUNBURST_DATA_ELEMENT = [];
					break;
				case 'BOX_PLOT':
					self.reportInfo.MapOption.DASHBOARD_XML.BOX_PLOT_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.BOX_PLOT_DATA_ELEMENT = [];
					break;
				case 'COORDINATE_LINE':
					self.reportInfo.MapOption.DASHBOARD_XML.COORDINATE_LINE_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.COORDINATE_LINE_DATA_ELEMENT = [];
					break;
				case 'SCATTER_PLOT':
					self.reportInfo.MapOption.DASHBOARD_XML.SCATTER_PLOT_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SCATTER_PLOT_DATA_ELEMENT = [];
					break;
				case 'SCATTER_PLOT2':
					self.reportInfo.MapOption.DASHBOARD_XML.SCATTER_PLOT2_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SCATTER_PLOT2_DATA_ELEMENT = [];
					break;
				case 'RADIAL_TIDY_TREE':
					self.reportInfo.MapOption.DASHBOARD_XML.RADIAL_TIDY_TREE_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.RADIAL_TIDY_TREE_DATA_ELEMENT = [];
					break;
				case 'SCATTER_PLOT_MATRIX':
					self.reportInfo.MapOption.DASHBOARD_XML.SCATTER_PLOT_MATRIX_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SCATTER_PLOT_MATRIX_DATA_ELEMENT = [];
					break;
				case 'HISTORY_TIMELINE':
					self.reportInfo.MapOption.DASHBOARD_XML.HISTORY_TIMELINE_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HISTORY_TIMELINE_DATA_ELEMENT = [];
					break;
				case 'ARC_DIAGRAM':
					self.reportInfo.MapOption.DASHBOARD_XML.ARC_DIAGRAM_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.ARC_DIAGRAM_DATA_ELEMENT = [];
					break;
				case 'LIQUID_FILL_GAUGE':
					self.reportInfo.MapOption.DASHBOARD_XML.LIQUID_FILL_GAUGE_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.LIQUID_FILL_GAUGE_DATA_ELEMENT = [];
					break;
				case 'LISTBOX':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.LISTBOX_DATA_ELEMENT = [];
					break;
				case 'TREEVIEW':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.TREEVIEW_DATA_ELEMENT = [];
					break;
				case 'COMBOBOX':
					self.reportInfo.MapOption.DASHBOARD_XML.COMBOBOX_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.COMBOBOX_DATA_ELEMENT = [];
					break;
				case 'IMAGE': // ymbin
					self.reportInfo.MapOption.DASHBOARD_XML.IMAGE_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.IMAGE_DATA_ELEMENT = [];
					break;
				case 'TEXTBOX': // ymbin
					self.reportInfo.MapOption.DASHBOARD_XML.TEXTBOX_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.TEXTBOX_DATA_ELEMENT = [];
					break;
				case 'HIERARCHICAL_EDGE':
					self.reportInfo.MapOption.DASHBOARD_XML.HIERARCHICAL_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HIERARCHICAL_DATA_ELEMENT = [];
					break;
				case 'FORCEDIRECT':
					self.reportInfo.MapOption.DASHBOARD_XML.FORCEDIRECT_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.FORCEDIRECT_DATA_ELEMENT = [];
					break;
				case 'FORCEDIRECTEXPAND':
					self.reportInfo.MapOption.DASHBOARD_XML.FORCEDIRECTEXPAND_DATA_ELEMENT = [];
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.FORCEDIRECTEXPAND_DATA_ELEMENT = [];
					break;
			}
		});
		_.each(gDashboard.itemGenerateManager.dxItemBasten,function(_e){
			if(_e.meta != undefined){
				if (typeof _e.meta.DataItems !== 'undefined') {
					var measureElements = [];
					$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure), function(index, measure) {
						measureElements.push({
							UNI_NM: measure.UniqueName,
							NAME: measure.Name,
							NUMERIC_FORMAT: {
								FORMAT_TYPE: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.FormatType : 'Number',
								UNIT: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.Unit : 'Ones',
								SUFFIX_ENABLED: (typeof measure.NumericFormat !== 'undefined' && measure.NumericFormat.SuffixEnabled) ? 'Y' : 'N',
								SUFFIX: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.Suffix : { O: '', K: '천', M: '백만', B: '십억' },
								PRECISION: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.Precision : 0,
								PRECISION_OPTION: (typeof measure.NumericFormat !== 'undefined') ? measure.NumericFormat.PrecisionOption : '반올림',
								INCLUDE_GROUP_SEPARATOR: (typeof measure.NumericFormat !== 'undefined' && measure.NumericFormat.IncludeGroupSeparator) ? 'Y' : 'N',
							},
							DELTA_ITEM : (typeof measure.DeltaItem != 'undefined') ? measure.DeltaItem : ''
						})
					});
				}
				if(!(_e.meta.MemoText)) _e.meta.MemoText  = '';
				switch(_e.type){
				case 'PIVOT_GRID':
//					var deltaArray = [];
//					var deltaElement = {};
//					$.each(_e.meta.deltaItems,function(_i,_delta){
//						var eachItem = {
//							'FLD_NM' : _delta.FLD_NM,
//							'CAPTION' : _delta.CAPTION,
//							'BASE_UNI_NM' : _delta.BASE_UNI_NM,
//							'BASE_FLD_NM' : _delta.BASE_FLD_NM,
//							'DELTA_VALUE_TYPE' : _delta.DELTA_VALUE_TYPE
//						};
//						deltaArray.push(eachItem);
//					});

					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'DataSource' :  _e.dataSourceId,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataItems': _e.meta.DataItems,
						'Rows': typeof _e.meta.Rows == 'undefined' ? {'Row':[]} :  _e.meta.Rows,
						'Columns' : typeof _e.meta.Columns == 'undefined'? {'Column': []} : _e.meta.Columns,
						'Values':_e.meta.Values,
//						'DeltaArray': deltaArray,
//						'DeltaValue': deltaElement,
						'AutoExpandColumnGroups' : _e.meta.AutoExpandColumnGroups,
						'AutoExpandRowGroups' : _e.meta.AutoExpandRowGroups,
						'HiddenMeasures' : _e.meta.HiddenMeasures
					};

					if(_e.isAdhocItem){
						obj.adhocIndex = _e.adhocIndex;
						obj.isAdhocItem = true;
					}

					if(typeof _e.meta.PagingOptions != 'undefined'){
						obj.PagingOptions = _e.meta.PagingOptions;
					}
					
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
// if(typeof _e.meta.ShowColumnGrandTotals !='undefined'){
					var rowtotalPosition = _e.meta.RowTotalsPosition;
					if(typeof _e.meta.RowTotalsPosition == 'boolean'){
						if( _e.meta.RowTotalsPosition==true){
							rowtotalPosition= 'Near';
						}
						else{
							rowtotalPosition= 'Far';
						}
					}
					else if(typeof  _e.meta.RowTotalsPosition == 'undefined'){
						rowtotalPosition= 'Far';
					}
					else{
						rowtotalPosition = _e.meta.RowTotalsPosition;
					}
// if(typeof _e.meta.RowTotalsPosition){
// if(_e.meta.RowTotalsPosition == true){
// rowtotalPosition = 'Near';
// }else{
// rowtotalPosition = 'Far';
// }
// }
					var columntotalPosition =  _e.meta.ColumnTotalsPosition;
					if(typeof _e.meta.ColumnTotalsPosition == 'boolean'){
						if( _e.meta.ColumnTotalsPosition==true){
							columntotalPosition= 'Near';
						}
						else{
							columntotalPosition= 'Far';
						}
					}
					else if(typeof  _e.meta.ColumnTotalsPosition == 'undefined'){
						columntotalPosition= 'Far';
					}
					else{
						columntotalPosition =  _e.meta.ColumnTotalsPosition;
					}
					
					/*dogfoot 피벗 그리드 측정값 행열 위치 설정 저장 dev20 이상에서만 작동 shlim 20210324*/
					if(typeof _e.meta.DataFieldPosition != 'undefined'){
                    	obj.DataFieldPosition = _e.meta.DataFieldPosition;
                    }
					
					var layoutType = _e.meta.LayoutType;
					if(_e.meta.LayoutType == 'standard'){
						layoutType = 'TABULAR';
					}else{
						layoutType = 'COMPACT';
					}
					/* DOGFOOT ktkang Null 데이터 제거 구현  20200904 */
					var nullRemoveType =  _e.meta.NullRemoveType;
					if(typeof _e.meta.NullRemoveType != 'undefined'){
						nullRemoveType = _e.meta.NullRemoveType;
					}
// if(typeof _e.meta.ColumnTotalsPosition =='boolean'){
// if(_e.meta.ColumnTotalsPosition == true){
// columntotalPosition = 'Near';
// }else{
// columntotalPosition = 'Far';
// }
// }
					var pivotFields = [];
					$.each(_e.dataSourceConfig.fields, function(_ii, _dd){
						if(_dd.area == 'column' || _dd.area == 'row' || _dd.area == 'hidden') {
							pivotFields.push(_dd);
						} else {
							$.each(_e.DI.Measure, function(_iii, _ddd){
								if(_ddd.UNI_NM == _dd.UNI_NM){
									pivotFields.push(_dd);
								}
							});
						}
					});
					var gridData = pivotFields;
					var gridArray = [];
					var deltaArray = [];
					var dataSortArray = [];
					/*dogfoot 비정형 정렬 오류 수정 shlim 20200620*/
					var dataArray = [];
					var highlightArray = [];
					var topBottomArray = [];
					if(_e.isAdhocItem){
						$.each(gridData,function(_i,_ee){
							var grid_option = {};
							var sort_option = {};
							switch(_ee.area){
							case 'column':
							case 'row':
								if(WISE.Context.isCubeReport) {
									grid_option['UNI_NM'] = _ee.cubeUNI_NM;
									grid_option['TYPE'] = 'DIM';
								} else {
									grid_option['UNI_NM'] = _ee.UNI_NM;
									grid_option['TYPE'] = 10;
								}

								grid_option['FLD_NM'] = _ee.UNI_NM;
								grid_option['CAPTION'] = _ee.caption;
								grid_option['FORMAT_STRING'] = '';

								grid_option['VISIBLE'] = _ee.visible == true ? 'Y':'N';
								grid_option['DRAW_CHART'] =  _ee.DRAW_CHART == true ? 'Y':'N';
								grid_option['SUMMARY_TYPE'] = '';
								gridArray.push(grid_option);

								if(_ee.sortByField != undefined){
									sort_option['SORT_FLD_NM'] = _ee.UNI_NM;
									sort_option['BASE_FLD_NM'] = _ee.sortByField;
									sort_option['SORT_MODE'] = _ee.sortOrder == 'asc' ? 'ASC' : 'DESC';
									dataSortArray.push(sort_option);
								//2020.03.10 mksong 비정형 정렬 오류 수정 dogfoot
								}else{
									sort_option['SORT_FLD_NM'] = _ee.UNI_NM;
									sort_option['BASE_FLD_NM'] = _ee.UNI_NM;
									sort_option['SORT_MODE'] = _ee.sortOrder == 'asc' ? 'ASC' : 'DESC';
									dataSortArray.push(sort_option);
								}
								break;
							case 'data':
								if(_ee.UNI_NM.indexOf('DELTA_FIELD') != -1){
									if(WISE.Context.isCubeReport) {
										grid_option['UNI_NM'] = _ee.cubeUNI_NM;
									} else {
										grid_option['UNI_NM'] = _ee.UNI_NM;
									}
									grid_option['VISIBLE'] = _ee.visible == true ? 'Y':'N';
									grid_option['DRAW_CHART'] =  _ee.DRAW_CHART == true ? 'Y':'N';
									grid_option['TYPE'] = 'DELTA';
									grid_option['FLD_NM'] = _ee.UNI_NM;
									grid_option['CAPTION'] = _ee.caption;
									grid_option['FORMAT_STRING'] =  _ee.format.key;

									grid_option['SUMMARY_TYPE'] = '';
								}
								else{
									if(WISE.Context.isCubeReport) {
										grid_option['UNI_NM'] = _ee.cubeUNI_NM;
										grid_option['TYPE'] = 'MEA';
									} else {
										grid_option['UNI_NM'] = _ee.UNI_NM;
										grid_option['TYPE'] = 11;
									}
									grid_option['VISIBLE'] = _ee.visible == true ? 'Y':'N';
									grid_option['DRAW_CHART'] =  _ee.DRAW_CHART == true ? 'Y':'N';
									grid_option['FLD_NM'] = _ee.UNI_NM;
									grid_option['CAPTION'] = _ee.caption;
									grid_option['FORMAT_STRING'] = _ee.format.key;

									switch(_ee.summaryType){
									case 'count':
										grid_option['SUMMARY_TYPE'] = '0';
										break;
									case 'sum':
										grid_option['SUMMARY_TYPE'] = '1';
										break;
									case 'min':
										grid_option['SUMMARY_TYPE'] = '2';
										break;
									case 'max':
										grid_option['SUMMARY_TYPE'] = '3';
										break;
									case 'avg':
										grid_option['SUMMARY_TYPE'] = '4';
										break;
									/*dogfoot shlim  본사적용 필요 20210701*/
									case 'countdistinct':
										grid_option['SUMMARY_TYPE'] = '5';
										break;
									}
								}
								gridArray.push(grid_option);
								break;
							case 'hidden':
								if(WISE.Context.isCubeReport) {
									grid_option['UNI_NM'] = _ee.cubeUNI_NM;
								} else {
									grid_option['UNI_NM'] = _ee.UNI_NM;
								}

								grid_option['VISIBLE'] = 'N';
								grid_option['DRAW_CHART'] =  'N';
								if(_ee.summaryType != undefined){
									if(WISE.Context.isCubeReport) {
										grid_option['TYPE'] = 'MEA';
									}else{
										grid_option['TYPE'] = 11;
									}
									switch(_ee.summaryType){
									case 'count':
										grid_option['SUMMARY_TYPE'] = '0';
										break;
									case 'sum':
										grid_option['SUMMARY_TYPE'] = '1';
										break;
									case 'min':
										grid_option['SUMMARY_TYPE'] = '2';
										break;
									case 'max':
										grid_option['SUMMARY_TYPE'] = '3';
										break;
									case 'avg':
										grid_option['SUMMARY_TYPE'] = '4';
										break;
									/*dogfoot shlim  본사적용 필요 20210701*/
									case 'countdistinct':
										grid_option['SUMMARY_TYPE'] = '5';
										break;
									}
									/*dogfoot 비정형 정렬 오류 수정 shlim 20200620*/
									dataArray.push(grid_option);
								}else{
									if(WISE.Context.isCubeReport) {
										grid_option['TYPE'] = 'DIM';
									} else {
										grid_option['TYPE'] = 10;
									}
								}

			//report_option['SUMMARY_TYPE'] = '1';
								grid_option['FLD_NM'] = _ee.dataField;
								grid_option['CAPTION'] = _ee.caption;
								/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */

								gridArray.push(grid_option);
								break;
							}
						});

						$.each(_e.deltaItems,function(_i,_delta){
							var eachItem = {
								'FLD_NM' : _delta.FLD_NM,
								'CAPTION' : _delta.CAPTION,
								'BASE_UNI_NM' : _delta.BASE_UNI_NM,
								'BASE_FLD_NM' : _delta.BASE_FLD_NM,
								'DELTA_VALUE_TYPE' : _delta.DELTA_VALUE_TYPE
							};
							deltaArray.push(eachItem);
						});

						$.each(_e.highlightItems,function(_i,_highlight){
							var back_color = gDashboard.itemColorManager.hexToRgb(_highlight.BACK_COLOR);
							var fore_color = gDashboard.itemColorManager.hexToRgb(_highlight.FORE_COLOR);
							var eachItem = {
								'SEQ':_highlight.ID+1000,
								'UNI_NM':_highlight.FLD_NM,
								'FLD_NM':_highlight.FLD_NM,
								'COND':_highlight.COND,
								'VALUE1':_highlight.VALUE1,
								'VALUE2':_highlight.VALUE2 == null ? '' : _highlight.VALUE2,
								'BACK_COLOR':back_color.r+","+back_color.g+","+back_color.b,
								'FORE_COLOR':fore_color.r+","+fore_color.g+","+fore_color.b,
								'APPLY_CELL': _highlight.APPLY_CELL == true ? 'Y':'N',
								'APPLY_TOTAL': _highlight.APPLY_TOTAL == true ? 'Y':'N',
								'APPLY_GRANDTOTAL' : _highlight.APPLY_GRANDTOTAL == true ? 'Y':'N',
								'IMAGE_INDEX':_highlight.IMAGE_INDEX == ""? "": (Number(_highlight.IMAGE_INDEX) -1)+""
							}
							highlightArray.push(eachItem);
						});

						if(_e.topBottomInfo.DATA_FLD_NM != ''){
							var topBottomInfo = _e.topBottomInfo;
							var eachItem = {
								'DATA_UNI_NM': topBottomInfo.DATA_FLD_NM,
								'DATA_FLD_NM' : topBottomInfo.DATA_FLD_NM,
								'APPLY_UNI_NM' : topBottomInfo.APPLY_FLD_NM,
								'APPLY_FLD_NM' : topBottomInfo.APPLY_FLD_NM,
								'TOPBOTTOM_TYPE': topBottomInfo.TOPBOTTOM_TYPE,
								'TOPBOTTOM_CNT': topBottomInfo.TOPBOTTOM_CNT,
								'PERCENT' : topBottomInfo.PERCENT == true ? 'Y':'N',
								'SHOW_OTHERS' : topBottomInfo.SHOW_OTHERS == true ? 'Y':'N'
							};
							topBottomArray.push(eachItem);
						}
					}

					self.reportInfo.MapOption.DASHBOARD_XML.PIVOT_GRID_ELEMENT.push({
						'CTRL_NM':_e.meta.ComponentName,
						'SHOWCOLUMNTOTALS':_e.meta.ShowColumnTotals+"",
						'SHOWROWTOTALS':_e.meta.ShowRowTotals+"",
						'SHOWCOLUMNGRANDTOTALS':_e.meta.ShowColumnGrandTotals+"",
						'SHOWROWGRANDTOTALS' : _e.meta.ShowRowGrandTotals+"",
						'COLUMNTOTALSLOCATION': columntotalPosition,
						'ROWTOTALSLOCATION' : rowtotalPosition,
						'VALUESPOSITION' : _e.meta.valuePosition == true ? 'Near':'Far',
						'LAYOUTTYPE' : layoutType,
						/*dogfoot 피벗그리드 필터표시 설정 추가 shlim 20201130*/
						'NULLREMOVETYPE' : nullRemoveType,
						'DIMFILTERMODE' : _e.meta.DimFilterMode,
						
						// 20210826 행열 전환 저장
						'COLROWSWITCH': _e.meta.ColRowSwitch ? true : false
					});
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.PIVOT_GRID_ELEMENT.push({
						CTRL_NM: _e.meta.ComponentName,
						MEASURES: measureElements,
						/* DOGFOOT hsshim 1220
						 * 틀고정 기능 추가
						 */
						AUTO_SIZE_ENABLED: _e.meta.AutoSizeEnabled,
						GRID_ELEMENT : {'GRID' : gridArray},
						DELTAVALUE_ELEMENT : {DELTA_VALUE : deltaArray},
						HIGHLIGHT_ELEMENT : {HIGHLIGHT : highlightArray},
						TOPBOTTOM_ELEMENT : {TOPBOTTOM_VALUE : highlightArray},
						SUBQUERY_ELEMENT : {SUB_QUERY : ''},
						DATASORT_ELEMENT : {DATA_SORT : dataSortArray}
					});

					self.reportInfo.Items.Pivot.push(obj);
					break;
				case 'DATA_GRID':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'DataSource' : _e.dataSourceId,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataItems': _e.meta.DataItems,
						'GridColumns' : _e.meta.GridColumns,
						'HiddenMeasures' : _e.meta.HiddenMeasures,
					};


					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						obj["Palette"] = _e.meta.Palette
					}
					
					/*dogfoot 그리드 헤더추가 기능 저장  shlim 20210317*/
					if(typeof _e.headerList != "undefined" && Object.keys(_e.headerList).length > -1){
						obj["HeaderList"] = JSON.stringify(_e.headerList);
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.DATA_GRID_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.STATIC_ANALYSIS_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						ANALYSIS_TYPE: _e.staticAnalysisType,
						/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
						ALPHA_LEVEL: _e.staticOptions.alphaLevel,
						PAIRED: _e.staticOptions.paired,
						ALTERNATIVE: _e.staticOptions.alternative,
						VAREQUAL: _e.staticOptions.varequal,
						/* DOGFOOT ktkang 다변량분석 추가  20210215 */
						MUTEST: _e.staticOptions.mutest,
						METHOD: _e.staticOptions.method,
						DISTANCE: _e.staticOptions.distance,
						CLUSTER: _e.staticOptions.cluster,
						STDEV: _e.staticOptions.stdev,
						/* DOGFOOT syjin 카이제곱 검정 옵션 추가  20210315 */
						CHISQTYPE: _e.staticOptions.chisqType
					});
// if(_e.filterEditData.filterType!=''){
// if(_e.filterEditData.filterType == 'Single'){
// str +=
// _e.filterEditData.filterConditions[0]+
// "(["+ _e.filterEditData.filterDataFields[0]+"],'"+
// _e.filterEditData.filterDataName[0]+"')";
// }else{
// for(var i=0;i<_e.filterEditData.filterConditions.length;i++){
// str +=
// _e.filterEditData.filterConditions[i]+
// "(["+ _e.filterEditData.filterDataFields[i]+"],'"+
// _e.filterEditData.filterDataName[i]+"')";
// if(_e.filterEditData.filterConditions.length > (i+1)){
// str += " "+_e.filterEditData.filterGroupOperation[i]+" "
// }
// }
// }
// }
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}

					var gridWidth = [];
					var totalWidth = 0;
					var undefinedColumnCount = 0;
					for(var i=0;i<_e.dxItem.columnCount();i++){
						if(_e.dxItem.columnOption(i).width != undefined){
							totalWidth += Number((_e.dxItem.columnOption(i).width).replace('%',''))
						}else{
							undefinedColumnCount++;
						}
						// gridWidth.push(_e.dxItem.columnOption(i).width);
					}
					for(var i=0;i<_e.dxItem.columnCount();i++){
						if(_e.dxItem.columnOption(i).width != undefined){
							gridWidth.push(_e.dxItem.columnOption(i).width);
						}
						else{
							gridWidth.push(((100- totalWidth)/undefinedColumnCount).toFixed(3)+"%");
						}
					}
					obj.gridWidth = gridWidth;
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.GridOptions != 'undefined'){
						obj.GridOptions = _e.meta.GridOptions;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.SparklineArgument != 'undefined'){
						if(_e.meta.SparklineArgument.length != 0){
							obj.SparklineArgument = _e.meta.SparklineArgument;
						}
					}

					self.reportInfo.Items.Grid.push(obj);
					break;
				case 'SIMPLE_CHART':
					var seriesDim = typeof _e.meta.SeriesDimensions == 'undefined' ? {'SeriesDimension': []} : _e.meta.SeriesDimensions;
					var arguments = typeof _e.meta.Arguments == 'undefined' ? {'Argument':[]} : _e.meta.Arguments;
					if(seriesDim == ""){
						seriesDim = {'SeriesDimension': []};
					}
					if(arguments == ""){
						arguments = {'Argument':[]};
					}

					var obj = {
						'Arguments': arguments,
						'ComponentName' : _e.meta.ComponentName,
						'DataItems': _e.meta.DataItems,
						'DataSource' : _e.dataSourceId,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'Panes': _e.meta.Panes,
						'Rotated':_e.meta.Rotated,
						'SeriesDimensions': seriesDim,
						'ChartLegend':_e.meta.ChartLegend,
						'ChartXOption':_e.meta.AxisX,
						'ChartYOption':_e.meta.AxisY,
						//20210318 AJKIM 차원 하이라이트 기능 추가 dogfoot
						'PointHighlight': _e.meta.PointHighlight,
						'HiddenMeasures' : _e.meta.HiddenMeasures
					};

					if(_e.isAdhocItem){
						obj.adhocIndex = _e.adhocIndex;
						obj.isAdhocItem = true;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					var chartDataElementJson = {
						CTRL_NM: _e.meta.ComponentName,
						PANE_ELEMENT: {}
					};
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj.ColoringOption = 'Hue';
						obj.UseGlobalColors = 'false';
						obj.ColorSheme = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT.push({
							CTRL_NM: _e.meta.ComponentName,
							BACK_COLOR: '0,0,0',
							NULL_DATA_BACK_COLOR: '0,0,0',
							PALETTE_NM: _e.meta.Palette,
							COLOR_SCHEME: undefined
						});
					}
					if(typeof _e.meta.Animation != 'undefined'){
						chartDataElementJson.ANIMATION = _e.meta.Animation;
					}
					if (typeof _e.meta.AxisX != 'undefined') {
						chartDataElementJson.AXISX_OPTION = {
							AXISX_ANGLE: _e.meta.AxisX.Rotation
						};
					}
					if (typeof _e.meta.AxisY != 'undefined' || typeof _e.meta.Panes.Pane.Series.Simple != 'undefined' ||
						typeof _e.meta.Panes.Pane.Series.Weighted != 'undefined' || _e.meta.Panes.Pane.Series.Ranged != 'undefined') {
						// series options
						var seriesElement = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure), function(i, measure) {
							var uniqueName = measure.UniqueName;
							var name = measure.Name;
							var found = false;
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Simple), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'SimpleSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor),
										//2020.12.24 mksong 차트 y축 역순으로 보기 dogfoot
										INVERTED: series.Inverted ? 'Y' : 'N'
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Weighted), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'WeightedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor),
										//2020.12.24 mksong 차트 y축 역순으로 보기 dogfoot
										INVERTED: series.Inverted ? 'Y' : 'N'
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Ranged), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'RangedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor),
										//2020.12.24 mksong 차트 y축 역순으로 보기 dogfoot
										INVERTED: series.Inverted ? 'Y' : 'N'
									});
								}
							});
						});
						chartDataElementJson.PANE_ELEMENT.SERIES_ELEMENT = seriesElement;
						// Y axis options
						if (typeof _e.meta.AxisY != 'undefined') {
							chartDataElementJson.PANE_ELEMENT.PANE_NM = _e.meta.Panes.Pane.Name;
							chartDataElementJson.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN = _e.meta.AxisY.SuffixEnabled ? 'Y' : 'N';
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_O = _e.meta.AxisY.MeasureFormat.O;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_K = _e.meta.AxisY.MeasureFormat.K;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_M = _e.meta.AxisY.MeasureFormat.M;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_B =  _e.meta.AxisY.MeasureFormat.B;
						}
					}
					self.reportInfo.MapOption.DASHBOARD_XML.CHART_DATA_ELEMENT.push(chartDataElementJson);
					//yhkim 시계열 분석 관련 추가 20200907 dogfoot
					if(_e.type == 'SIMPLE_CHART') {
						self.reportInfo.MapOption.DASHBOARD_XML.WEB.TIME_SERIES_ELEMENT.push({
							CTRL_NM:_e.meta.ComponentName,
							FORECAST: _e.timeSeries.forecast,
							SERIES_COLORS: _e.timeSeries.seriesColors,
							PERIOD_TYPE: _e.timeSeries.periodType,
							PERIOD: _e.timeSeries.period,
							SERIES_COLORS: _e.timeSeries.seriesColors,
							//yhkim 시계열 분석(자동, 수동) 추가 20201118 dogfoot
							LAST_SERIES: _e.timeSeries.lastSeries,
							AUTO_ORDER_YN: _e.timeSeries.autoOrderYn,
							P_ORDER: _e.timeSeries.pOrder,
							D_ORDER: _e.timeSeries.dOrder,
							Q_ORDER: _e.timeSeries.qOrder
						});
					}

					self.reportInfo.Items.Chart.push(obj);
					break;
				case 'BUBBLE_CHART':
					var seriesDim = typeof _e.meta.SeriesDimensions == 'undefined' ? {'SeriesDimension': []} : _e.meta.SeriesDimensions;
					var arguments = typeof _e.meta.Arguments == 'undefined' ? {'Argument':[]} : _e.meta.Arguments;
					if(seriesDim == ""){
						seriesDim = {'SeriesDimension': []};
					}
					if(arguments == ""){
						arguments = {'Argument':[]};
					}

					var obj = {
						'Arguments': arguments,
						'ComponentName' : _e.meta.ComponentName,
						'DataItems': _e.meta.DataItems,
						'DataSource' : _e.dataSourceId,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'Panes': _e.meta.Panes,
						'Rotated':_e.meta.Rotated,
						'SeriesDimensions': seriesDim,
						'ChartLegend':_e.meta.ChartLegend,
						'ChartXOption':_e.meta.AxisX,
						'ChartYOption':_e.meta.AxisY,
						'HiddenMeasures' : _e.meta.HiddenMeasures
					};

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					var chartDataElementJson = {
						CTRL_NM: _e.meta.ComponentName,
						PANE_ELEMENT: {}
					};
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj.ColoringOption = 'Hue';
						obj.UseGlobalColors = 'false';
						obj.ColorSheme = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT.push({
							CTRL_NM: _e.meta.ComponentName,
							BACK_COLOR: '0,0,0',
							NULL_DATA_BACK_COLOR: '0,0,0',
							PALETTE_NM: _e.meta.Palette,
							COLOR_SCHEME: undefined
						});
					}
					if(typeof _e.meta.Animation != 'undefined'){
						chartDataElementJson.ANIMATION = _e.meta.Animation;
					}
					if (typeof _e.meta.AxisX != 'undefined') {
						chartDataElementJson.AXISX_OPTION = {
							AXISX_ANGLE: _e.meta.AxisX.Rotation
						};
					}
					if (typeof _e.meta.AxisY != 'undefined' || typeof _e.meta.Panes.Pane.Series.Simple != 'undefined' ||
						typeof _e.meta.Panes.Pane.Series.Weighted != 'undefined' || _e.meta.Panes.Pane.Series.Ranged != 'undefined') {
						// series options
						var seriesElement = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure), function(i, measure) {
							var uniqueName = measure.UniqueName;
							var name = measure.Name;
							var found = false;
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Simple), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'SimpleSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Weighted), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'WeightedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Ranged), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'RangedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
								}
							});
						});
						chartDataElementJson.PANE_ELEMENT.SERIES_ELEMENT = seriesElement;
						// Y axis options
						if (typeof _e.meta.AxisY != 'undefined') {
							chartDataElementJson.PANE_ELEMENT.PANE_NM = _e.meta.Panes.Pane.Name;
							chartDataElementJson.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN = _e.meta.AxisY.SuffixEnabled ? 'Y' : 'N';
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_O = _e.meta.AxisY.MeasureFormat.O;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_K = _e.meta.AxisY.MeasureFormat.K;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_M = _e.meta.AxisY.MeasureFormat.M;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_B =  _e.meta.AxisY.MeasureFormat.B;
						}
					}
					self.reportInfo.MapOption.DASHBOARD_XML.CHART_DATA_ELEMENT.push(chartDataElementJson);

					self.reportInfo.Items.BubbleChart.push(obj);
					break;
				case 'PIE_CHART':
					var seriesDim = typeof _e.meta.SeriesDimensions == 'undefined' ? {'SeriesDimension': []} : _e.meta.SeriesDimensions;
					var arguments = typeof _e.meta.Arguments == 'undefined' ? {'Argument':[]} : _e.meta.Arguments;
					if(seriesDim == ""){
						seriesDim = {'SeriesDimension': []};
					}
					if(arguments == ""){
						arguments = {'Argument':[]};
					}
					var pieDataElement = {
						CTRL_NM:_e.meta.ComponentName,
						LABELPOSITION: _e.meta.LabelPosition,
						LABEL_OPTIONS: {
							CONTENT_TYPE: _e.meta.LabelContentType,
							MEASURE: _e.meta.LabelMeasureFormat,
							PREFIX_ENABLED_YN: _e.meta.LabelPrefixEnabled ? 'Y' : 'N',
							PREFIX_FORMAT: _e.meta.LabelPrefixFormat,
							SUFFIX_ENABLED_YN: _e.meta.LabelSuffixEnabled ? 'Y' : 'N',
							SUFFIX_O: _e.meta.LabelSuffix.O,
							SUFFIX_K: _e.meta.LabelSuffix.K,
							SUFFIX_M: _e.meta.LabelSuffix.M,
							SUFFIX_B: _e.meta.LabelSuffix.B,
							PRECISION: _e.meta.LabelPrecision,
							PRECISION_OPTION: _e.meta.LabelPrecisionOption,
						},
						TOOLTIP_OPTIONS: {
							CONTENT_TYPE: _e.meta.TooltipContentType,
							MEASURE: _e.meta.TooltipMeasureFormat,
							PREFIX_ENABLED_YN: _e.meta.TooltipPrefixEnabled ? 'Y' : 'N',
							PREFIX_FORMAT: _e.meta.TooltipPrefixFormat,
							SUFFIX_ENABLED_YN: _e.meta.TooltipSuffixEnabled ? 'Y' : 'N',
							SUFFIX_O: _e.meta.TooltipSuffix.O,
							SUFFIX_K: _e.meta.TooltipSuffix.K,
							SUFFIX_M: _e.meta.TooltipSuffix.M,
							SUFFIX_B: _e.meta.TooltipSuffix.B,
							PRECISION: _e.meta.TooltipPrecision,
							PRECISION_OPTION: _e.meta.TooltipPrecisionOption,
						}
					};

					if(_e.meta.Animation != null){
						pieDataElement['ANIMATION'] = _e.meta.Animation;
					}

					var obj = {
						'Arguments': arguments,
						'ComponentName' : _e.meta.ComponentName,
						'DataItems': _e.meta.DataItems,
						'DataSource' :  _e.dataSourceId,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'Values': _e.meta.Values,
						'SeriesDimensions': seriesDim,
						'PieType':_e.meta.PieType,
						'LabelContentType': _e.meta.LabelContentType,
						'LabelPosition':_e.meta.LabelPosition,
						'TooltipContentType' : _e.meta.TooltipContentType,
						'HiddenMeasures' : _e.meta.HiddenMeasures,
						'Legend' : _e.meta.Legend
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.PIE_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(_e.meta.DataItems.Measure,function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT.push({
							CTRL_NM: _e.meta.ComponentName,
							BACK_COLOR: '0,0,0',
							NULL_DATA_BACK_COLOR: '0,0,0',
							PALETTE_NM: _e.meta.Palette,
							COLOR_SCHEME: undefined
						});
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}
					self.reportInfo.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT.push(pieDataElement);
// if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
// obj["ColoringOption"] = 'Hue';
// obj["UseGlobalColors"] = 'false';
// obj["ColorSheme"] = [];
// $.each(_e.meta.DataItems.Measure,function(_i,_mea){
// var colorObj = {
// 'DataSource':_e.meta.DataSource,
// 'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[_i]),
// 'MeasureKey':_mea.DataMember
// }
// obj.ColorSheme.push(colorObj);
// });
// }else{
// self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT.push({
// 'CTRL_NM':_e.meta.ComponentName,
// 'PALETTE_NM':_e.meta.Palette
// })
// }
	                self.reportInfo.Items.Pie.push(obj);
// var pieConfigs = {
// CTRL_NM: _e.meta.ComponentName,
// LABELPOSITION: _e.meta.LabelPosition
// };
// self.reportInfo.MapOption.DASHBOARD_XML.PIE_DATA_ELEMENT = pieConfigs;
					break;
				case 'CARD_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CARD_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements,
						ABSOLUTE_VARIATION: _e.meta.Card.AbsoluteVariationNumericFormat,
						PERCENT_VARIATION: _e.meta.Card.PercentVariationNumericFormat,
						/* DOGFOOT mksong 2020-08-05 카드 폭 저장 */
						PERCENT_OF_TARGET: _e.meta.Card.PercentOfTargetNumericFormat,
						CARD_MINWIDTH: _e.meta.Card.LayoutTemplate.CardMinWidth,
						CARD_MAXWIDTH: _e.meta.Card.LayoutTemplate.CardMaxWidth
					});
					var obj = _e.meta;
					self.reportInfo.Items.Card.push(obj);
					break;
				/* DOGFOOT hsshim 2020-02-03 게이지 저장 기능 작업 */
				case 'GAUGE_CHART':
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.GAUGE_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements,
						ABSOLUTE_VARIATION: _e.meta.GaugeElement.AbsoluteVariationNumericFormat,
						PERCENT_VARIATION: _e.meta.GaugeElement.PercentVariationNumericFormat,
						PERCENT_OF_TARGET: _e.meta.GaugeElement.PercentOfTargetNumericFormat,
						SCALE_LABEL: _e.meta.GaugeElement.ScaleLabelNumericFormat
					});
					var obj = _e.meta;
					self.reportInfo.Items.Gauge.push(obj);
					break;
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case 'KAKAO_MAP':
					var mapArr= [];
					$.each(WISE.util.Object.toArray(_e.meta.Maps.ValueMap),function(_i,_map){
						if(_map.Value.UniqueName != undefined){
							mapArr.push(_map);
						}
					});
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' :  _e.dataSourceId,
						'ShapefileArea' : _e.meta.ShapefileArea,
						'AttributeName': _e.meta.AttributeName,
						'DataItems': _e.meta.DataItems,
						'CustomShapefile' : _e.meta.CustomShapefile,
						'ViewArea' : _e.meta.ViewArea,
						'MapLegend': _e.meta.MapLegend,
						'LockNavigation' : _e.meta.LockNavigation,
						'WeightedLegend': _e.meta.WeightedLegend,
						'AttributeDimension': _e.meta.AttributeDimension,
						'Maps' : {'ValueMap':mapArr},
						'Palette': typeof _e.meta.Palette != 'string' ? 'Custom' : _e.meta.Palette,
						//2020.09.22 mksong dogfoot 카카오지도 포인트타입, 로케이션타입 추가
						'ShowPointType': _e.meta.ShowPointType,
						'LocationType': _e.meta.LocationType
					};

					/*dogfoot polygonEditOptions bgColor 추가 syjin 20201029*/
					/*dogfoot polygonEditOptions bgColor 주석처리  syjin 20201105*/
		           // _e.setBgColor();
					var webItemObject = {
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements,
						//2020.10.21 MKSONG 차트옵션 저장 DOGFOOT
						ChartEditOptions : _e.meta.chartEditOptions,
						//2020.10.22 syjin 폴리곤옵션 저장 DOGFOOT
						PolygonEditOptions : _e.meta.polygonEditOptions,
						//2020.10.23 syjin 마커옵션 저장 DOGFOOT
						MarkerEditOptions : _e.meta.markerEditOptions,
						//2020.12.04 syjin  마커 즐겨찾기 선택 후 다른 마커 클릭시 오류 - 해당보고서 저장 후 불러오기 오류 수정 dogfoot
						//2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
						MkInfo : {
							address : {
								image : Base64.encode(JSON.stringify(_e.meta.mkInfo.address.image)),
								favorite : Base64.encode(JSON.stringify(_e.meta.mkInfo.address.favorite))
							},
							coordinate : {
								standardDimension : _e.meta.mkInfo.coordinate.standardDimension,
								image : _e.meta.mkInfo.coordinate.image,
								favorite : Base64.encode(JSON.stringify(_e.meta.mkInfo.coordinate.favorite))
							}
						},
//						Base64.encode(JSON.stringify(_e.meta.mkInfo)),
						//2020.12.07 MKSONG 카카오맵 저장 옵션 기능 추가  DOGFOOT
						SaveOptions : _e.meta.SaveOptions
					};

//					if(_e.meta.LocationType == 'coordinate'){
//						$.each(_e.meta.mkInfo.coordinate.image,function(_key, _array){
//							webItemObject.MkInfo.coordinate['image'][_key] = Base64.encode(JSON.stringify(_array));
//						});
//					}
					//2020.12.15 mksong 카카오맵 마커 이미지 변경 기능 수정 dogfoot
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP_ELEMENT.push(webItemObject);

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					//2020.11.05 mksong 카카오맵 중심좌표 줌레벨 값 저장 오류 수정 dogfoot
					//2020.11.18 syjin 카카오맵 중심좌표 줌레벨 값 저장 오류 수정 dogfoot
					if(typeof _e.map != 'undefined'){
						var latlng = _e.map.getCenter();
						var lng = latlng.getLng();
						var lat = latlng.getLat();
						var level = _e.map.getLevel();

						//2020.12.07 MKSONG 카카오맵 저장 옵션 기능 추가  DOGFOOT
						if(_e.meta.SaveOptions.SaveAutoZoomLevel){
							obj.Level = String(level);
						}else{
							obj.Level = String(_e.mapInitInfo.zoomLevel);
						}

						if(_e.meta.SaveOptions.SaveAutoLatLng){
							obj.Lng = String(lng);
							obj.Lat = String(lat);
						}else{
							obj.Lng = String(_e.mapInitInfo.lng);
							obj.Lat = String(_e.mapInitInfo.lat);
						}
					}

					self.reportInfo.Items.KakaoMap.push(obj);
					break;
				case 'KAKAO_MAP2':
					var mapArr= [];
					$.each(WISE.util.Object.toArray(_e.meta.Maps.ValueMap),function(_i,_map){
						if(_map.Value.UniqueName != undefined){
							mapArr.push(_map);
						}
					});
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' :  _e.dataSourceId,
						'ShapefileArea' : _e.meta.ShapefileArea,
						'AttributeName': _e.meta.AttributeName,
						'DataItems': _e.meta.DataItems,
						'CustomShapefile' : _e.meta.CustomShapefile,
						'ViewArea' : _e.meta.ViewArea,
						'MapLegend': _e.meta.MapLegend,
						'LockNavigation' : _e.meta.LockNavigation,
						'WeightedLegend': _e.meta.WeightedLegend,
						'AttributeDimension': _e.meta.AttributeDimension,
						'Maps' : {'ValueMap':mapArr},
						'Palette': typeof _e.meta.Palette != 'string' ? 'Custom' : _e.meta.Palette
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP2_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.Items.KakaoMap2.push(obj);
					break;
				case 'CHOROPLETH_MAP':
					var mapArr= [];
					$.each(WISE.util.Object.toArray(_e.meta.Maps.ValueMap),function(_i,_map){
						if(_map.Value.UniqueName != undefined){
							mapArr.push(_map);
						}
					});
					//2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가  dogfoot
					var choroplethMapDataElement = {
						CTRL_NM:_e.meta.ComponentName,
						TOOLTIP_OPTIONS: {
							CONTENT_TYPE: _e.meta.TooltipContentType,
							MEASURE: _e.meta.TooltipMeasureFormat,
							PREFIX_ENABLED_YN: _e.meta.TooltipPrefixEnabled ? 'Y' : 'N',
							PREFIX_FORMAT: _e.meta.TooltipPrefixFormat,
							SUFFIX_ENABLED_YN: _e.meta.TooltipSuffixEnabled ? 'Y' : 'N',
							SUFFIX_O: _e.meta.TooltipSuffix.O,
							SUFFIX_K: _e.meta.TooltipSuffix.K,
							SUFFIX_M: _e.meta.TooltipSuffix.M,
							SUFFIX_B: _e.meta.TooltipSuffix.B,
							PRECISION: _e.meta.TooltipPrecision,
							PRECISION_OPTION: _e.meta.TooltipPrecisionOption,
						}
					};

					self.reportInfo.MapOption.DASHBOARD_XML.CHOROPLETH_MAP_DATA_ELEMENT.push(choroplethMapDataElement);
					
					if(!Array.isArray(_e.CustomUrl)){
						var CustomUrl = [];
					    for(var i=0; i<_e.CustomUrl.length; i++){
		                    var urlObject = {
		                    	"Url" : _e.CustomUrl[i].Url
		                    };
		                    CustomUrl.push(urlObject);
					    }
					}else{
						for(var i=0; i<_e.CustomUrl.length; i++){
						    if(_e.CustomUrl[i] == ""){
						    	_e.CustomUrl[i] = {};
						    }
						    if(typeof _e.CustomUrl[i] == "string"){
						    	var object = {
						    		Url : _e.CustomUrl[i]
						    	}
						        _e.CustomUrl[i] = object;
						    }
						}
					}
					
					var attributeName = [];
					if(_e.attributeName.Name == undefined){
						attributeName = _e.attributeName;
					}else{
						var array = _e.attributeName['Name'];

						$.each(array, function(_i, _v){
							$.each(_v, function(_i2, _v2){
							    attributeName.push(_v2);
							})
						})
					}
											
					$.each(_e.meta.ViewArea.area, function(_i, _v){
						if(_v == ""){
							_e.meta.ViewArea.area[_i] = {};
						}
					})
					
					if(_e.meta.EditPaletteOption.paletteArray == ""){
						_e.meta.EditPaletteOption.paletteArray = WISE.util.Object.toArray(_e.meta.EditPaletteOption.paletteArray);
					}
					
					if(_e.meta.EditPaletteOption.paletteRangeArray == ""){
						_e.meta.EditPaletteOption.paletteRangeArray = WISE.util.Object.toArray(_e.meta.EditPaletteOption.paletteRangeArray);
					}
					
					$.each(_e.meta.FileMeta, function(_i, _v){
						delete _v.data;
						delete _v.customUrl;
						delete _v.viewArea;
						$.each(_v, function(_i, _v2){
						    if(_v2.fileName == undefined) _v2.fileName = "";
						    if(_v2.filePropertiesItems == undefined) _v2.filePropertiesItems = "";
						    if(_v2.fileProperties == undefined) _v2.fileProperties = "";
						})
					})
					
					_e.meta.CurrentLocation.City = _e.meta.CurrentLocation.State.toString(_e.meta.CurrentLocation.City);
					_e.meta.CurrentLocation.State = _e.meta.CurrentLocation.State.toString(_e.meta.CurrentLocation.State); 
					
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' :  _e.dataSourceId,
						'ShapefileArea' : _e.meta.ShapefileArea,
						'AttributeName': attributeName,
						'DataItems': _e.meta.DataItems,
						'CustomShapefile' : Array.isArray(_e.CustomUrl)?_e.CustomUrl:CustomUrl,
						'ViewArea' : _e.meta.ViewArea,
						'ShpIndex' : _e.shpIndex,
						'TargetIndex' : _e.targetIndex==undefined?-1:_e.targetIndex,
						'LocationName' : ""+_e.LocationName,
						'MapLegend': _e.meta.MapLegend,
						//2020.11.27 mksong 코로플레스지도 레이블 표기 dogfoot
						'MapLabel': _e.meta.MapLabel,
						'LockNavigation' : _e.meta.LockNavigation,
						//2020.10.07 MKSONG 코로플레스 툴팁 설정 기능 추가  dogfoot
						'TooltipContentType' : _e.meta.TooltipContentType,
						'WeightedLegend': _e.meta.WeightedLegend,
						'AttributeDimension': _e.meta.AttributeDimension,
						'Maps' : {'ValueMap':mapArr},
						'Palette': typeof _e.meta.Palette != 'string' ? 'Custom' : _e.meta.Palette,
						'FileMeta' : _e.meta.FileMeta,
						//레이블 추가
						'LabelOption' : _e.meta.LabelOption,
						//색상편집 추가
						'EditPaletteOption' : _e.meta.EditPaletteOption,
						//2021.06.21 syjin 팔레트 사용자 지정 추가
						//'PaletteStartColor' : _e.meta.PaletteStartColor,
						//'PaletteLastColor' : _e.meta.PaletteLastColor,
						'PaletteCustomCheck' : _e.meta.PaletteCustomCheck,
						//현재지역
						'CurrentLocation' : _e.meta.CurrentLocation
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CHOROPLETH_MAP_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					/*dogfoot 코로플레스 맵 마스터필터 저장 shlim 20201126*/
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.Items.ChoroplethMap.push(obj);
					break;
				case 'TREEMAP':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' :  _e.dataSourceId,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.TREEMAP_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.TREEMAP_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.Treemap.push(obj);
					break;
				case 'FUNNEL_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' :  _e.dataSourceId,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'LabelPosition':_e.meta.LabelPosition,
						'LabelContentType': _e.meta.LabelContentType,
						'TooltipContentType' : _e.meta.TooltipContentType,
						'Legend' : _e.meta.Legend
					};

					var funnelDataElement = {
						CTRL_NM:_e.meta.ComponentName,
						LABELPOSITION: _e.meta.LabelPosition,
						LABEL_OPTIONS: {
							CONTENT_TYPE: _e.meta.LabelContentType,
							MEASURE: _e.meta.LabelMeasureFormat,
							PREFIX_ENABLED_YN: _e.meta.LabelPrefixEnabled ? 'Y' : 'N',
							PREFIX_FORMAT: _e.meta.LabelPrefixFormat,
							SUFFIX_ENABLED_YN: _e.meta.LabelSuffixEnabled ? 'Y' : 'N',
							SUFFIX_O: _e.meta.LabelSuffix.O,
							SUFFIX_K: _e.meta.LabelSuffix.K,
							SUFFIX_M: _e.meta.LabelSuffix.M,
							SUFFIX_B: _e.meta.LabelSuffix.B,
							PRECISION: _e.meta.LabelPrecision,
							PRECISION_OPTION: _e.meta.LabelPrecisionOption,
						},
						TOOLTIP_OPTIONS: {
							CONTENT_TYPE: _e.meta.TooltipContentType,
							MEASURE: _e.meta.TooltipMeasureFormat,
							PREFIX_ENABLED_YN: _e.meta.TooltipPrefixEnabled ? 'Y' : 'N',
							PREFIX_FORMAT: _e.meta.TooltipPrefixFormat,
							SUFFIX_ENABLED_YN: _e.meta.TooltipSuffixEnabled ? 'Y' : 'N',
							SUFFIX_O: _e.meta.TooltipSuffix.O,
							SUFFIX_K: _e.meta.TooltipSuffix.K,
							SUFFIX_M: _e.meta.TooltipSuffix.M,
							SUFFIX_B: _e.meta.TooltipSuffix.B,
							PRECISION: _e.meta.TooltipPrecision,
							PRECISION_OPTION: _e.meta.TooltipPrecisionOption,
						}
					};

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.FUNNEL_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						funnelDataElement.PALETTE_NM = _e.meta.Palette
					}

					self.reportInfo.Items.Funnelchart.push(obj);
					self.reportInfo.MapOption.DASHBOARD_XML.FUNNEL_CHART_DATA_ELEMENT.push(funnelDataElement);
					break;
				case 'PYRAMID_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' :  _e.dataSourceId,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'LabelPosition':_e.meta.LabelPosition,
						'LabelContentType': _e.meta.LabelContentType,
						'TooltipContentType' : _e.meta.TooltipContentType,
						'Legend' : _e.meta.Legend
					};

					var pyramidDataElement = {
						CTRL_NM:_e.meta.ComponentName,
						LABELPOSITION: _e.meta.LabelPosition,
						LABEL_OPTIONS: {
							CONTENT_TYPE: _e.meta.LabelContentType,
							MEASURE: _e.meta.LabelMeasureFormat,
							PREFIX_ENABLED_YN: _e.meta.LabelPrefixEnabled ? 'Y' : 'N',
							PREFIX_FORMAT: _e.meta.LabelPrefixFormat,
							SUFFIX_ENABLED_YN: _e.meta.LabelSuffixEnabled ? 'Y' : 'N',
							SUFFIX_O: _e.meta.LabelSuffix.O,
							SUFFIX_K: _e.meta.LabelSuffix.K,
							SUFFIX_M: _e.meta.LabelSuffix.M,
							SUFFIX_B: _e.meta.LabelSuffix.B,
							PRECISION: _e.meta.LabelPrecision,
							PRECISION_OPTION: _e.meta.LabelPrecision,
						},
						TOOLTIP_OPTIONS: {
							CONTENT_TYPE: _e.meta.TooltipContentType,
							MEASURE: _e.meta.TooltipMeasureFormat,
							PREFIX_ENABLED_YN: _e.meta.TooltipPrefixEnabled ? 'Y' : 'N',
							PREFIX_FORMAT: _e.meta.TooltipPrefixFormat,
							SUFFIX_ENABLED_YN: _e.meta.TooltipSuffixEnabled ? 'Y' : 'N',
							SUFFIX_O: _e.meta.TooltipSuffix.O,
							SUFFIX_K: _e.meta.TooltipSuffix.K,
							SUFFIX_M: _e.meta.TooltipSuffix.M,
							SUFFIX_B: _e.meta.TooltipSuffix.B,
							PRECISION: _e.meta.TooltipPrecision,
							PRECISION_OPTION: _e.meta.TooltipPrecisionOption
						}
					};

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.PYRAMID_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						pyramidDataElement.PALETTE_NM = _e.meta.Palette
					}

					self.reportInfo.Items.Pyramidchart.push(obj);
					self.reportInfo.MapOption.DASHBOARD_XML.PYRAMID_CHART_DATA_ELEMENT.push(pyramidDataElement);
					break;
				case 'KAKAO_MAP':
					var mapArr= [];
					$.each(WISE.util.Object.toArray(_e.meta.Maps.ValueMap),function(_i,_map){
						if(_map.Value.UniqueName != undefined){
							mapArr.push(_map);
						}
					});
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' :  _e.dataSourceId,
						'ShapefileArea' : _e.meta.ShapefileArea,
						'AttributeName': _e.meta.AttributeName,
						'DataItems': _e.meta.DataItems,
						'CustomShapefile' : _e.meta.CustomShapefile,
						'ViewArea' : _e.meta.ViewArea,
						'MapLegend': _e.meta.MapLegend,
						'LockNavigation' : _e.meta.LockNavigation,
						'WeightedLegend': _e.meta.WeightedLegend,
						'AttributeDimension': _e.meta.AttributeDimension,
						'Maps' : {'ValueMap':mapArr},
						'Palette': typeof _e.meta.Palette != 'string' ? 'Custom' : _e.meta.Palette
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.Items.KakaoMap.push(obj);
					break;
				case 'KAKAO_MAP2':
					var mapArr= [];
					$.each(WISE.util.Object.toArray(_e.meta.Maps.ValueMap),function(_i,_map){
						if(_map.Value.UniqueName != undefined){
							mapArr.push(_map);
						}
					});
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' :  _e.dataSourceId,
						'ShapefileArea' : _e.meta.ShapefileArea,
						'AttributeName': _e.meta.AttributeName,
						'DataItems': _e.meta.DataItems,
						'CustomShapefile' : _e.meta.CustomShapefile,
						'ViewArea' : _e.meta.ViewArea,
						'MapLegend': _e.meta.MapLegend,
						'LockNavigation' : _e.meta.LockNavigation,
						'WeightedLegend': _e.meta.WeightedLegend,
						'AttributeDimension': _e.meta.AttributeDimension,
						'Maps' : {'ValueMap':mapArr},
						'Palette': typeof _e.meta.Palette != 'string' ? 'Custom' : _e.meta.Palette
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP2_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.Items.KakaoMap2.push(obj);
					break;
				case 'PARALLEL_COORDINATE':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ChartYOption':_e.meta.AxisY,/*dogfoot Y축 설정 추가 shlim 20200831*/
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.PARALLEL_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.PARALLEL_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.Parallel.push(obj);
					break;
				case 'BUBBLE_PACK_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'TextFormat' : _e.meta.TextFormat,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.BUBBLE_PACK_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.BUBBLE_PACK_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.BubblePackChart.push(obj);
					break;
				case 'WORD_CLOUD_V2':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.WORD_CLOUD_V2_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.WORD_CLOUD_V2_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.WordCloudV2.push(obj);
					break;
				case 'DEPENDENCY_WHEEL':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.DEPENDENCY_WHEEL_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey':''
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DEPENDENCY_WHEEL_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.DependencyWheel.push(obj);
					break;
				case 'DENDROGRAM_BAR_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.DENDROGRAM_BAR_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DENDROGRAM_BAR_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.DendrogramBarChart.push(obj);
					break;
				case 'CALENDAR_VIEW_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
						'TextFormat' : _e.meta.TextFormat,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.CALENDAR_VIEW_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.CalendarViewChart.push(obj);
					break;
				case 'CALENDAR_VIEW2_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'TextFormat' : _e.meta.TextFormat,
						'ZoomAble' : _e.meta.ZoomAble,
				};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW2_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
										'DataSource':_e.meta.DataSource,
										'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
										'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.CALENDAR_VIEW2_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.CalendarView2Chart.push(obj);
					break;
				case 'CALENDAR_VIEW3_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
						'TextFormat' : _e.meta.TextFormat,
				};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW3_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
										'DataSource':_e.meta.DataSource,
										'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
										'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.CALENDAR_VIEW3_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.CalendarView3Chart.push(obj);
					break;
				case 'COLLAPSIBLE_TREE_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.COLLAPSIBLE_TREE_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
										'DataSource':_e.meta.DataSource,
										'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
										'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.COLLAPSIBLE_TREE_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.CollapsibleTreeChart.push(obj);
					break;
				case 'RANGE_BAR_CHART':
					var arguments = typeof _e.meta.Arguments == 'undefined' ? {'Argument':[]} : _e.meta.Arguments;

					if(arguments == ""){
						arguments = {'Argument':[]};
					}

					var obj = {
						'Arguments': arguments,
						'ComponentName' : _e.meta.ComponentName,
						'DataItems': _e.meta.DataItems,
						'DataSource' : _e.dataSourceId,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'Panes': _e.meta.Panes,
						'Rotated':_e.meta.Rotated,
						'ChartLegend':_e.meta.ChartLegend,
						'ChartXOption':_e.meta.AxisX,
						'ChartYOption':_e.meta.AxisY,
						'HiddenMeasures' : _e.meta.HiddenMeasures
					};


					self.reportInfo.MapOption.DASHBOARD_XML.WEB.RANGE_BAR_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					var chartDataElementJson = {
						CTRL_NM: _e.meta.ComponentName,
						PANE_ELEMENT: {}
					};
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj.ColoringOption = 'Hue';
						obj.UseGlobalColors = 'false';
						obj.ColorSheme = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT.push({
							CTRL_NM: _e.meta.ComponentName,
							BACK_COLOR: '0,0,0',
							NULL_DATA_BACK_COLOR: '0,0,0',
							PALETTE_NM: _e.meta.Palette,
							COLOR_SCHEME: undefined
						});
					}
					if(typeof _e.meta.Animation != 'undefined'){
						chartDataElementJson.ANIMATION = _e.meta.Animation;
					}
					if (typeof _e.meta.AxisX != 'undefined') {
						chartDataElementJson.AXISX_OPTION = {
							AXISX_ANGLE: _e.meta.AxisX.Rotation
						};
					}
					if (typeof _e.meta.AxisY != 'undefined' || typeof _e.meta.Panes.Pane.Series.Simple != 'undefined' ||
						typeof _e.meta.Panes.Pane.Series.Weighted != 'undefined' || _e.meta.Panes.Pane.Series.Ranged != 'undefined') {
						// series options
						var seriesElement = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure), function(i, measure) {
							var uniqueName = measure.UniqueName;
							var name = measure.Name;
							var found = false;
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Simple), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'SimpleSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Weighted), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'WeightedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Ranged), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'RangedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
								}
							});
						});
						chartDataElementJson.PANE_ELEMENT.SERIES_ELEMENT = seriesElement;
						// Y axis options
						if (typeof _e.meta.AxisY != 'undefined') {
							chartDataElementJson.PANE_ELEMENT.PANE_NM = _e.meta.Panes.Pane.Name;
							chartDataElementJson.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN = _e.meta.AxisY.SuffixEnabled ? 'Y' : 'N';
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_O = _e.meta.AxisY.MeasureFormat.O;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_K = _e.meta.AxisY.MeasureFormat.K;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_M = _e.meta.AxisY.MeasureFormat.M;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_B =  _e.meta.AxisY.MeasureFormat.B;
						}
					}
					self.reportInfo.MapOption.DASHBOARD_XML.RANGE_BAR_CHART_DATA_ELEMENT.push(chartDataElementJson);

					self.reportInfo.Items.RangeBarChart.push(obj);
					break;
				case 'RANGE_AREA_CHART':
					var arguments = typeof _e.meta.Arguments == 'undefined' ? {'Argument':[]} : _e.meta.Arguments;

					if(arguments == ""){
						arguments = {'Argument':[]};
					}

					var obj = {
							'Arguments': arguments,
							'ComponentName' : _e.meta.ComponentName,
							'DataItems': _e.meta.DataItems,
							'DataSource' : _e.dataSourceId,
							'Name' : _e.meta.Name+"",
							'MemoText' : _e.meta.MemoText + "",
							'Panes': _e.meta.Panes,
							'Rotated':_e.meta.Rotated,
							'ChartLegend':_e.meta.ChartLegend,
							'ChartXOption':_e.meta.AxisX,
							'ChartYOption':_e.meta.AxisY,
							'HiddenMeasures' : _e.meta.HiddenMeasures
					};


					self.reportInfo.MapOption.DASHBOARD_XML.WEB.RANGE_AREA_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					var chartDataElementJson = {
							CTRL_NM: _e.meta.ComponentName,
							PANE_ELEMENT: {}
					};
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj.ColoringOption = 'Hue';
						obj.UseGlobalColors = 'false';
						obj.ColorSheme = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
										'DataSource': _e.dataSourceId,
										'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
										'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT.push({
							CTRL_NM: _e.meta.ComponentName,
							BACK_COLOR: '0,0,0',
							NULL_DATA_BACK_COLOR: '0,0,0',
							PALETTE_NM: _e.meta.Palette,
							COLOR_SCHEME: undefined
						});
					}
					if(typeof _e.meta.Animation != 'undefined'){
						chartDataElementJson.ANIMATION = _e.meta.Animation;
					}
					if (typeof _e.meta.AxisX != 'undefined') {
						chartDataElementJson.AXISX_OPTION = {
								AXISX_ANGLE: _e.meta.AxisX.Rotation
						};
					}
					if (typeof _e.meta.AxisY != 'undefined' || typeof _e.meta.Panes.Pane.Series.Simple != 'undefined' ||
							typeof _e.meta.Panes.Pane.Series.Weighted != 'undefined' || _e.meta.Panes.Pane.Series.Ranged != 'undefined') {
						// series options
						var seriesElement = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure), function(i, measure) {
							var uniqueName = measure.UniqueName;
							var name = measure.Name;
							var found = false;
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Simple), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'SimpleSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Weighted), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'WeightedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
												SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
														SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
																SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Ranged), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'RangedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
												SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
														SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
																SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
								}
							});
						});
						chartDataElementJson.PANE_ELEMENT.SERIES_ELEMENT = seriesElement;
						// Y axis options
						if (typeof _e.meta.AxisY != 'undefined') {
							chartDataElementJson.PANE_ELEMENT.PANE_NM = _e.meta.Panes.Pane.Name;
							chartDataElementJson.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN = _e.meta.AxisY.SuffixEnabled ? 'Y' : 'N';
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_O = _e.meta.AxisY.MeasureFormat.O;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_K = _e.meta.AxisY.MeasureFormat.K;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_M = _e.meta.AxisY.MeasureFormat.M;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_B =  _e.meta.AxisY.MeasureFormat.B;
						}
					}
					self.reportInfo.MapOption.DASHBOARD_XML.RANGE_AREA_CHART_DATA_ELEMENT.push(chartDataElementJson);

					self.reportInfo.Items.RangeAreaChart.push(obj);
					break;
				case 'TIME_LINE_CHART':
					var seriesDim = typeof _e.meta.SeriesDimensions == 'undefined' ? {'SeriesDimension': []} : _e.meta.SeriesDimensions;
					var arguments = typeof _e.meta.Arguments == 'undefined' ? {'Argument':[]} : _e.meta.Arguments;
					var startDateDim = typeof _e.meta.StartDate == 'undefined' ? {'StartDate':[]} : _e.meta.StartDate;
					var endDateDim = typeof _e.meta.EndDate == 'undefined' ? {'EndDate':[]} : _e.meta.EndDate;

					if(arguments == ""){
						arguments = {'Argument':[]};
					}

					var obj = {
						'Arguments': arguments,
						'ComponentName' : _e.meta.ComponentName,
						'DataItems': _e.meta.DataItems,
						'DataSource' : _e.dataSourceId,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'Panes': _e.meta.Panes,
						'Rotated':_e.meta.Rotated,
						'SeriesDimensions': seriesDim,
						'ChartLegend':_e.meta.ChartLegend,
						'ChartXOption':_e.meta.AxisX,
						'ChartYOption':_e.meta.AxisY,
						'HiddenMeasures' : _e.meta.HiddenMeasures,
						'StartDate': startDateDim,
						'EndDate': endDateDim,
					};


					self.reportInfo.MapOption.DASHBOARD_XML.WEB.TIME_LINE_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					var chartDataElementJson = {
						CTRL_NM: _e.meta.ComponentName,
						PANE_ELEMENT: {}
					};
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj.ColoringOption = 'Hue';
						obj.UseGlobalColors = 'false';
						obj.ColorSheme = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DATA_ELEMENT.push({
							CTRL_NM: _e.meta.ComponentName,
							BACK_COLOR: '0,0,0',
							NULL_DATA_BACK_COLOR: '0,0,0',
							PALETTE_NM: _e.meta.Palette,
							COLOR_SCHEME: undefined
						});
					}
					if(typeof _e.meta.Animation != 'undefined'){
						chartDataElementJson.ANIMATION = _e.meta.Animation;
					}
					if (typeof _e.meta.AxisX != 'undefined') {
						chartDataElementJson.AXISX_OPTION = {
							AXISX_ANGLE: _e.meta.AxisX.Rotation
						};
					}
					if (typeof _e.meta.AxisY != 'undefined' || typeof _e.meta.Panes.Pane.Series.Simple != 'undefined' ||
						typeof _e.meta.Panes.Pane.Series.Weighted != 'undefined' || _e.meta.Panes.Pane.Series.Ranged != 'undefined') {
						// series options
						var seriesElement = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure), function(i, measure) {
							var uniqueName = measure.UniqueName;
							var name = measure.Name;
							var found = false;
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Simple), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'SimpleSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Weighted), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'WeightedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
									found = true;
									return false;
								}
							});
							if (found) {
								return true;
							}
							$.each(WISE.util.Object.toArray(_e.meta.Panes.Pane.Series.Ranged), function(j, series) {
								if (uniqueName === series.Value.UniqueName) {
									seriesElement.push({
										SERIES_KEY: 'Series_' + i,
										UNI_NM: uniqueName,
										SERIES_INDEX: i,
										SERIES_NAME: name,
										SERIES_PANE_NAME: _e.meta.Panes.Pane.Name,
										SERIES_CODE: 'RangedSeries',
										SERIES_TYPE: series.SeriesType,
										LINE_STYLE_TYPE: 0,
										SERIES_WIDTH: 0.5,
										SERIES_BACK_COLOR_VISIBLE: series.PointLabelOptions.FillBackground ? 'Y' : 'N',
										SERIES_BORDER_VISIBLE: series.PointLabelOptions.ShowBorder ? 'Y' : 'N',
										SERIES_FONT_COLOR_YN: series.PointLabelOptions.ShowCustomTextColor ? 'Y' : 'N',
										SERIES_FONT_COLOR: gDashboard.itemColorManager.rgbToHex(series.PointLabelOptions.CustomTextColor)
									});
								}
							});
						});
						chartDataElementJson.PANE_ELEMENT.SERIES_ELEMENT = seriesElement;
						// Y axis options
						if (typeof _e.meta.AxisY != 'undefined') {
							chartDataElementJson.PANE_ELEMENT.PANE_NM = _e.meta.Panes.Pane.Name;
							chartDataElementJson.PANE_ELEMENT.USE_AXISY_CUSTOM_UNIT_YN = _e.meta.AxisY.SuffixEnabled ? 'Y' : 'N';
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_O = _e.meta.AxisY.MeasureFormat.O;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_K = _e.meta.AxisY.MeasureFormat.K;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_M = _e.meta.AxisY.MeasureFormat.M;
							chartDataElementJson.PANE_ELEMENT.AXISY_UNIT_B =  _e.meta.AxisY.MeasureFormat.B;
						}
					}
					self.reportInfo.MapOption.DASHBOARD_XML.TIME_LINE_CHART_DATA_ELEMENT.push(chartDataElementJson);

					self.reportInfo.Items.TimeLineChart.push(obj);
					break;
				//임성현 주임 히스토그램 추가
				case 'HISTOGRAM_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
//						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
						'TextFormat' : _e.meta.TextFormat,
						'ChartXOption':_e.meta.AxisX,
						'ChartYOption':_e.meta.AxisY
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HISTOGRAM_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.HISTOGRAM_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.HistogramChart.push(obj);
					break;
				case 'STAR_CHART':
					var seriesDim = typeof _e.meta.SeriesDimensions == 'undefined' ? {'SeriesDimension': []} : _e.meta.SeriesDimensions;
					var arguments = typeof _e.meta.Arguments == 'undefined' ? {'Argument':[]} : _e.meta.Arguments;
					var obj = {
						'Arguments': arguments,
						'ComponentName' : _e.meta.ComponentName,
						'DataItems': _e.meta.DataItems,
						'DataSource' : _e.dataSourceId,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'Panes': _e.meta.Panes,
						'SeriesDimensions': seriesDim,
					};

					/* DOGFOOT ktkang 캡션보기 저장 오류 수정  20200207 */
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.STAR_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource': _e.dataSourceId,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.STAR_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.Starchart.push(obj);
					break;
				case 'LISTBOX':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'DataSource' : _e.meta.DataSource,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataItems': _e.meta.DataItems,
						'FilterDimensions' : _e.meta.FilterDimensions,
						'HiddenMeasures' : _e.meta.HiddenMeasures
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.LISTBOX_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
// if(_e.filterEditData.filterType!=''){
// if(_e.filterEditData.filterType == 'Single'){
// str +=
// _e.filterEditData.filterConditions[0]+
// "(["+ _e.filterEditData.filterDataFields[0]+"],'"+
// _e.filterEditData.filterDataName[0]+"')";
// }else{
// for(var i=0;i<_e.filterEditData.filterConditions.length;i++){
// str +=
// _e.filterEditData.filterConditions[i]+
// "(["+ _e.filterEditData.filterDataFields[i]+"],'"+
// _e.filterEditData.filterDataName[i]+"')";
// if(_e.filterEditData.filterConditions.length > (i+1)){
// str += " "+_e.filterEditData.filterGroupOperation[i]+" "
// }
// }
// }
// }
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.ListBoxType != 'undefined'){
						obj.ListBoxType = _e.meta.ListBoxType;
					}
					if(typeof _e.meta.ShowAllValue != 'undefined'){
						obj.ShowAllValue = _e.meta.ShowAllValue;
					}
					if(typeof _e.meta.EnableSearch != 'undefined'){
						obj.EnableSearch = _e.meta.EnableSearch;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.Items.ListBox.push(obj);
					break;
				case 'TREEVIEW':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'DataSource' : _e.meta.DataSource,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataItems': _e.meta.DataItems,
						'FilterDimensions' : _e.meta.FilterDimensions,
						'HiddenMeasures' : _e.meta.HiddenMeasures
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.TREEVIEW_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
// if(_e.filterEditData.filterType!=''){
// if(_e.filterEditData.filterType == 'Single'){
// str +=
// _e.filterEditData.filterConditions[0]+
// "(["+ _e.filterEditData.filterDataFields[0]+"],'"+
// _e.filterEditData.filterDataName[0]+"')";
// }else{
// for(var i=0;i<_e.filterEditData.filterConditions.length;i++){
// str +=
// _e.filterEditData.filterConditions[i]+
// "(["+ _e.filterEditData.filterDataFields[i]+"],'"+
// _e.filterEditData.filterDataName[i]+"')";
// if(_e.filterEditData.filterConditions.length > (i+1)){
// str += " "+_e.filterEditData.filterGroupOperation[i]+" "
// }
// }
// }
// }
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.AutoExpand != 'undefined'){
						obj.ShowAllValue = _e.meta.AutoExpand;
					}
					if(typeof _e.meta.EnableSearch != 'undefined'){
						obj.EnableSearch = _e.meta.EnableSearch;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.Items.TreeView.push(obj);
					break;
				case 'COMBOBOX':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'DataSource' : _e.meta.DataSource,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataItems': _e.meta.DataItems,
						'FilterDimensions' : _e.meta.FilterDimensions,
						'HiddenMeasures' : _e.meta.HiddenMeasures
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.COMBOBOX_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
// if(_e.filterEditData.filterType!=''){
// if(_e.filterEditData.filterType == 'Single'){
// str +=
// _e.filterEditData.filterConditions[0]+
// "(["+ _e.filterEditData.filterDataFields[0]+"],'"+
// _e.filterEditData.filterDataName[0]+"')";
// }else{
// for(var i=0;i<_e.filterEditData.filterConditions.length;i++){
// str +=
// _e.filterEditData.filterConditions[i]+
// "(["+ _e.filterEditData.filterDataFields[i]+"],'"+
// _e.filterEditData.filterDataName[i]+"')";
// if(_e.filterEditData.filterConditions.length > (i+1)){
// str += " "+_e.filterEditData.filterGroupOperation[i]+" "
// }
// }
// }
// }
					if(_e.meta.FilterString && _e.meta.FilterString.length != 0){
						obj.FilterString = JSON.stringify(_e.meta.FilterString);
						obj.FilterString = obj.FilterString.replace(/null/gi,'"@null"');
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					if(typeof _e.meta.IsMasterFilterCrossDataSource != 'undefined'){
						obj.IsMasterFilterCrossDataSource = _e.meta.IsMasterFilterCrossDataSource;
					}
					if(typeof _e.meta.ComboBoxType != 'undefined'){
						obj.ListBoxType = _e.meta.ComboBoxType;
					}
					if(typeof _e.meta.ShowAllValue != 'undefined'){
						obj.ShowAllValue = _e.meta.ShowAllValue;
					}
					if(typeof _e.meta.EnableSearch != 'undefined'){
						obj.EnableSearch = _e.meta.EnableSearch;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.Items.ComboBox.push(obj);
					break;
				case 'RECTANGULAR_ARAREA_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
						'TextFormat' : _e.meta.TextFormat,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.RECTANGULAR_ARAREA_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.RECTANGULAR_ARAREA_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}
					self.reportInfo.Items.RectangularAreaChart.push(obj);
					break;
					// 임성현 주임 저장 불러오기
				case 'WATERFALL_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ChartYOption':_e.meta.AxisY,/*dogfoot Y축 설정 추가 shlim 20200831*/
						'ZoomAble' : _e.meta.ZoomAble,
						'TextFormat' : _e.meta.TextFormat,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.WATERFALL_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.WATERFALL_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.Waterfallchart.push(obj);
					break;
				case 'BIPARTITE_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
//						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.BIPARTITE_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
//						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
//									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
//						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.BIPARTITE_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.Bipartitechart.push(obj);
					break;
				case 'SANKEY_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
//						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SANKEY_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
//						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
//									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
//						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.SANKEY_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.Sankeychart.push(obj);
					break;
				case 'BUBBLE_D3':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
						'TextFormat' : _e.meta.TextFormat,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.BUBBLE_D3_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.BUBBLE_D3_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.BubbleD3.push(obj);
					break;
				case 'HEATMAP':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
						'TextFormat' : _e.meta.TextFormat,
						'HiddenMeasures' : _e.meta.HiddenMeasures,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HEATMAP_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.HEATMAP_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.HeatMap.push(obj);
					break;
				case 'HEATMAP2':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
						'TextFormat' : _e.meta.TextFormat,
						'HiddenMeasures' : _e.meta.HiddenMeasures,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HEATMAP2_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.HEATMAP2_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.HeatMap2.push(obj);
					break;
				case 'WORD_CLOUD':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.WORD_CLOUD_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette && _e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.WORD_CLOUD_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.WordCloud.push(obj);
					break;
//				case 'HISTOGRAM_CHART':
//					var obj = {
//						'ComponentName' : _e.meta.ComponentName,
//						'Name' : _e.meta.Name+"",
//						'MemoText' : _e.meta.MemoText + "",
//						'DataSource' : _e.meta.DataSource,
//						'DataItems': _e.meta.DataItems,
//						'Values':_e.meta.Values,
//						'Arguments' : _e.meta.Arguments,
//						'ZoomAble' : _e.meta.ZoomAble,
//					};
//
//					if(_e.meta.LayoutOption){
//						obj['LayoutOption'] = _e.meta.LayoutOption;
//					}
//					if(typeof _e.meta.InteractivityOptions != 'undefined'){
//						obj.InteractivityOptions = _e.meta.InteractivityOptions;
//					}
//					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HISTOGRAM_CHART_DATA_ELEMENT.push({
//						CTRL_NM:_e.meta.ComponentName,
//						MEASURES: measureElements
//					});
//
//					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
//						obj["ColoringOption"] = 'Hue';
//						obj["UseGlobalColors"] = 'false';
//						obj["ColorSheme"] = [];
//						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
//							for(var i=0;i<_e.meta.Palette.length;i++){
//								var colorObj = {
//									'DataSource':_e.meta.DataSource,
//									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
//									'MeasureKey':_mea.DataMember
//								}
//								obj.ColorSheme.push(colorObj);
//							}
//						});
//					}else{
//						self.reportInfo.MapOption.DASHBOARD_XML.HISTOGRAM_CHART_DATA_ELEMENT.push({
//							'CTRL_NM':_e.meta.ComponentName,
//							'PALETTE_NM':_e.meta.Palette
//						})
//					}
//
//					self.reportInfo.Items.Histogramchart.push(obj);
//					break;
				case 'DIVERGING_CHART':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'SeriesDimensions' : _e.meta.SeriesDimensions,
						'Legend' : _e.meta.Legend,
						'ChartXOption' : _e.meta.AxisX,
						'HiddenMeasures' : _e.meta.HiddenMeasures,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.DIVERGING_CHART_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.DIVERGING_CHART_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.DivergingChart.push(obj);
					break;
				case 'ARC_DIAGRAM':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'Rotated' : _e.meta.Rotated,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.ARC_DIAGRAM_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey': ""
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.ARC_DIAGRAM_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.ArcDiagram.push(obj);
					break;
				case 'HISTORY_TIMELINE':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HISTORY_TIMELINE_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey': ""
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.HISTORY_TIMELINE_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.HistoryTimeline.push(obj);
					break;
				case 'SCATTER_PLOT':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
//						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ChartXOption' : _e.meta.AxisX,
						'ChartYOption' : _e.meta.AxisY,
						'HiddenMeasures' : _e.meta.HiddenMeasures,
						'Round' : _e.meta.Round,
						'ZoomAble' : _e.meta.ZoomAble,
					};


					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SCATTER_PLOT_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];

						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey': ""
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.SCATTER_PLOT_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.ScatterPlot.push(obj);
					break;
				case 'SCATTER_PLOT_MATRIX':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ChartXOption' : _e.meta.AxisX,
						'ChartYOption' : _e.meta.AxisY,
						'Round' : _e.meta.Round,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SCATTER_PLOT_MATRIX_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];

						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey': ""
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.SCATTER_PLOT_MATRIX_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.ScatterPlotMatrix.push(obj);
					break;
				case 'SCATTER_PLOT2':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ChartXOption' : _e.meta.AxisX,
						'ChartYOption' : _e.meta.AxisY,
						'HiddenMeasures' : _e.meta.HiddenMeasures,
						'Round' : _e.meta.Round,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SCATTER_PLOT2_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];

						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey': ""
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.SCATTER_PLOT2_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.ScatterPlot2.push(obj);
					break;
				case 'RADIAL_TIDY_TREE':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
//						'Values': ,
						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.RADIAL_TIDY_TREE_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					self.reportInfo.Items.RadialTidyTree.push(obj);
					break;
				case 'BOX_PLOT':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ChartYOption' : _e.meta.AxisY,
						'ChartXOption' : _e.meta.AxisX,
						'ExpandOption' : _e.meta.ExpandOption,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.BOX_PLOT_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.BOX_PLOT_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.BoxPlot.push(obj);
					break;
				case 'COORDINATE_LINE':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
//						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ChartYOption' : _e.meta.AxisY,
						'ChartXOption' : _e.meta.AxisX,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.COORDINATE_LINE_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey':""
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.COORDINATE_LINE_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.CoordinateLine.push(obj);
					break;
				case 'COORDINATE_DOT':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
//						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ChartYOption' : _e.meta.AxisY,
						'ChartXOption' : _e.meta.AxisX,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.COORDINATE_DOT_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey':""
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.COORDINATE_DOT_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.CoordinateDot.push(obj);
					break;
				case 'SYNCHRONIZED_CHARTS':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
//						'Legend' : _e.meta.Legend,
						'ChartYOption' : _e.meta.AxisY,
						'ChartXOption' : _e.meta.AxisX,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SYNCHRONIZED_CHARTS_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						for(var i=0;i<_e.meta.Palette.length;i++){
							var colorObj = {
								'DataSource':_e.meta.DataSource,
								'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
								'MeasureKey':""
							}
							obj.ColorSheme.push(colorObj);
						}
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.SYNCHRONIZED_CHARTS_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.SynchronizedChart.push(obj);
					break;
				case 'SEQUENCES_SUNBURST':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'TextFormat' : _e.meta.TextFormat,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.SEQUENCES_SUNBURST_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.SEQUENCES_SUNBURST_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.SequencesSunburst.push(obj);
					break;
				case 'LIQUID_FILL_GAUGE':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'TextFormat' : _e.meta.TextFormat,
						'ZoomAble' : _e.meta.ZoomAble,
						'ContentOption' : _e.meta.ContentOption
					};

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.LIQUID_FILL_GAUGE_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.LIQUID_FILL_GAUGE_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.LiquidFillGauge.push(obj);
					break;
					// 임성현 주임 저장 불러오기
				case 'IMAGE': // ymbin
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'Url': _e.meta.Url
					};
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.IMAGE_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName
					});

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.SizeMode != 'undefined'){
						obj.SizeMode = _e.meta.SizeMode;
					}
					if(typeof _e.meta.HorizontalAlignment != 'undefined'){
						obj.HorizontalAlignment = _e.meta.HorizontalAlignment;
					}
					if(typeof _e.meta.VerticalAlignment != 'undefined'){
						obj.VerticalAlignment = _e.meta.VerticalAlignment;
					}

					self.reportInfo.Items.Image.push(obj);
					break;
				case 'TEXTBOX': // ymbin
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'Text' : _e.meta.Text, // chart_xml의  HTML_DATA에 저장
						'DataItems': _e.meta.DataItems,
						'DataSource' :  _e.dataSourceId,
						'Values': _e.meta.Values,
						'HiddenMeasures' : _e.meta.HiddenMeasures
					};

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}

					//2020.01.21 mksong textbox 보고서 저장 오류 수정 dogfoot
					var html_data;
					if(_e.meta.HTML_DATA == undefined){
						html_data = "";
					}else{
						html_data = Base64.encode(_e.meta.HTML_DATA);
					}
					self.reportInfo.MapOption.DASHBOARD_XML.TEXTBOX_DATA_ELEMENT.push({
						CTRL_NM: _e.meta.ComponentName,
						HTML_DATA: html_data
//						HTML_DATA: Base64.encode(_e.meta.HTML_DATA) // base64 encoding
					});
					//2020.01.21 mksong textbox 보고서 저장 오류 수정 끝 dogfoot
					self.reportInfo.Items.TextBox.push(obj);
					break;
				case 'HIERARCHICAL_EDGE':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.HIERARCHICAL_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					self.reportInfo.MapOption.DASHBOARD_XML.HIERARCHICAL_DATA_ELEMENT.push({
						'CTRL_NM':_e.meta.ComponentName,
						'PALETTE_NM':_e.meta.Palette
					});

					self.reportInfo.Items.Hierarchical.push(obj);
					break;
				case 'FORCEDIRECT':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
//						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.FORCEDIRECT_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
//						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
//									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
//						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.FORCEDIRECT_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.ForceDirect.push(obj);
					break;
				case 'FORCEDIRECTEXPAND':
					var obj = {
						'ComponentName' : _e.meta.ComponentName,
						'Name' : _e.meta.Name+"",
						'MemoText' : _e.meta.MemoText + "",
						'DataSource' : _e.meta.DataSource,
						'DataItems': _e.meta.DataItems,
//						'Values':_e.meta.Values,
						'Arguments' : _e.meta.Arguments,
						'Legend' : _e.meta.Legend,
						'ZoomAble' : _e.meta.ZoomAble,
					};

					if(typeof _e.meta.ShowCaption != 'undefined'){
						obj.ShowCaption = _e.meta.ShowCaption;
					}

					if(_e.meta.LayoutOption){
						obj['LayoutOption'] = _e.meta.LayoutOption;
					}
					if(typeof _e.meta.InteractivityOptions != 'undefined'){
						obj.InteractivityOptions = _e.meta.InteractivityOptions;
					}
					self.reportInfo.MapOption.DASHBOARD_XML.WEB.FORCEDIRECTEXPAND_DATA_ELEMENT.push({
						CTRL_NM:_e.meta.ComponentName,
						MEASURES: measureElements
					});

					if(_e.meta.Palette.length != 0 && typeof _e.meta.Palette != 'string'){
						obj["ColoringOption"] = 'Hue';
						obj["UseGlobalColors"] = 'false';
						obj["ColorSheme"] = [];
//						$.each(WISE.util.Object.toArray(_e.meta.DataItems.Measure),function(_i,_mea){
							for(var i=0;i<_e.meta.Palette.length;i++){
								var colorObj = {
									'DataSource':_e.meta.DataSource,
									'Color': gDashboard.itemColorManager.rgbToHex(_e.meta.Palette[i]),
//									'MeasureKey':_mea.DataMember
								}
								obj.ColorSheme.push(colorObj);
							}
//						});
					}else{
						self.reportInfo.MapOption.DASHBOARD_XML.FORCEDIRECTEXPAND_DATA_ELEMENT.push({
							'CTRL_NM':_e.meta.ComponentName,
							'PALETTE_NM':_e.meta.Palette
						})
					}

					self.reportInfo.Items.ForceDirectExpand.push(obj);
					break;
				}
			}
		});
		if(self.reportInfo.Items['Pivot'].length ==0){
			delete self.reportInfo.Items['Pivot'];
		}
		if(self.reportInfo.Items['Grid'].length ==0){
			delete self.reportInfo.Items['Grid'];
		}
		if(self.reportInfo.Items['Chart'].length ==0){
			delete self.reportInfo.Items['Chart'];
		}
		if(self.reportInfo.Items['DivergingChart'].length ==0){
			delete self.reportInfo.Items['DivergingChart'];
		}
		if(self.reportInfo.Items['DependencyWheel'].length ==0){
			delete self.reportInfo.Items['DependencyWheel'];
		}
		if(self.reportInfo.Items['SequencesSunburst'].length ==0){
			delete self.reportInfo.Items['SequencesSunburst'];
		}
		if(self.reportInfo.Items['BoxPlot'].length ==0){
			delete self.reportInfo.Items['BoxPlot'];
		}
		if(self.reportInfo.Items['ScatterPlot'].length ==0){
			delete self.reportInfo.Items['ScatterPlot'];
		}
		if(self.reportInfo.Items['CoordinateLine'].length ==0){
			delete self.reportInfo.Items['CoordinateLine'];
		}
		if(self.reportInfo.Items['ScatterPlot2'].length ==0){
			delete self.reportInfo.Items['ScatterPlot2'];
		}
		if(self.reportInfo.Items['RadialTidyTree'].length ==0){
			delete self.reportInfo.Items['RadialTidyTree'];
		}
		if(self.reportInfo.Items['ScatterPlotMatrix'].length ==0){
			delete self.reportInfo.Items['ScatterPlotMatrix'];
		}
		if(self.reportInfo.Items['HistoryTimeline'].length ==0){
			delete self.reportInfo.Items['HistoryTimeline'];
		}
		if(self.reportInfo.Items['ArcDiagram'].length ==0){
			delete self.reportInfo.Items['ArcDiagram'];
		}
		if(self.reportInfo.Items['LiquidFillGauge'].length ==0){
			delete self.reportInfo.Items['LiquidFillGauge'];
		}
		if(self.reportInfo.Items['Pie'].length ==0){
			delete self.reportInfo.Items['Pie'];
		}
		if(self.reportInfo.Items['Card'].length ==0){
			delete self.reportInfo.Items['Card'];
		}
		/* DOGFOOT hsshim 2020-02-03 게이지 저장 기능 작업 */
		if(self.reportInfo.Items['Gauge'].length ==0){
			delete self.reportInfo.Items['Gauge'];
		}
		if(self.reportInfo.Items['ChoroplethMap'].length ==0){
			delete self.reportInfo.Items['ChoroplethMap'];
		}
		if(self.reportInfo.Items['Treemap'].length ==0){
			delete self.reportInfo.Items['Treemap'];
		}
		if(self.reportInfo.Items['Pyramidchart'].length ==0){
			delete self.reportInfo.Items['Pyramidchart'];
		}
		/* DOGFOOT syjin 카카오 지도 추가  20200820 */
		if(self.reportInfo.Items['KakaoMap'].length ==0){
			delete self.reportInfo.Items['KakaoMap'];
		}
		if(self.reportInfo.Items['KakaoMap2'].length ==0){
			delete self.reportInfo.Items['KakaoMap2'];
		}
		if(self.reportInfo.Items['Funnelchart'].length ==0){
			delete self.reportInfo.Items['Funnelchart'];
		}
		if(self.reportInfo.Items['Parallel'].length ==0){
			delete self.reportInfo.Items['Parallel'];
		}
		if(self.reportInfo.Items['BubblePackChart'].length ==0){
			delete self.reportInfo.Items['BubblePackChart'];
		}
		if(self.reportInfo.Items['WordCloudV2'].length ==0){
			delete self.reportInfo.Items['WordCloudV2'];
		}
		if(self.reportInfo.Items['DendrogramBarChart'].length ==0){
			delete self.reportInfo.Items['DendrogramBarChart'];
		}
		if(self.reportInfo.Items['CalendarViewChart'].length ==0){
			delete self.reportInfo.Items['CalendarViewChart'];
		}
		if(self.reportInfo.Items['CalendarView2Chart'].length ==0){
			delete self.reportInfo.Items['CalendarView2Chart'];
		}
		if(self.reportInfo.Items['CalendarView3Chart'].length ==0){
			delete self.reportInfo.Items['CalendarView3Chart'];
		}
		if(self.reportInfo.Items['CollapsibleTreeChart'].length ==0){
			delete self.reportInfo.Items['CollapsibleTreeChart'];
		}
		if(self.reportInfo.Items['RangeBarChart'].length ==0){
			delete self.reportInfo.Items['RangeBarChart'];
		}
		if(self.reportInfo.Items['RangeAreaChart'].length ==0){
			delete self.reportInfo.Items['RangeAreaChart'];
		}
		if(self.reportInfo.Items['TimeLineChart'].length ==0){
			delete self.reportInfo.Items['TimeLineChart'];
		}
		if(self.reportInfo.Items['Starchart'].length == 0){
			delete self.reportInfo.Items['Starchart'];
		}
		if(self.reportInfo.Items['ListBox'].length == 0){
			delete self.reportInfo.Items['ListBox'];
		}
		if(self.reportInfo.Items['HeatMap'].length == 0){
			delete self.reportInfo.Items['HeatMap'];
		}
		if(self.reportInfo.Items['HeatMap2'].length == 0){
			delete self.reportInfo.Items['HeatMap2'];
		}
		if(self.reportInfo.Items['SynchronizedChart'].length == 0){
			delete self.reportInfo.Items['SynchronizedChart'];
		}
		if(self.reportInfo.Items['CoordinateDot'].length == 0){
			delete self.reportInfo.Items['CoordinateDot'];
		}
		if(self.reportInfo.Items['WordCloud'].length == 0){
			delete self.reportInfo.Items['WordCloud'];
		}
		if(self.reportInfo.Items['TreeView'].length == 0){
			delete self.reportInfo.Items['TreeView'];
		}
		if(self.reportInfo.Items['ComboBox'].length == 0){
			delete self.reportInfo.Items['ComboBox'];
		}
		if(self.reportInfo.Items['RectangularAreaChart'].length ==0){
			delete self.reportInfo.Items['RectangularAreaChart'];
		}
		if(self.reportInfo.Items['Waterfallchart'].length ==0){
			delete self.reportInfo.Items['Waterfallchart'];
		}
		if(self.reportInfo.Items['BubbleD3'].length ==0){
			delete self.reportInfo.Items['BubbleD3'];
		}
		if(self.reportInfo.Items['BubbleChart'].length ==0){
			delete self.reportInfo.Items['BubbleChart'];
		}
		if(self.reportInfo.Items['Image'].length ==0){ // ymbin
			delete self.reportInfo.Items['Image'];
		}
		if(self.reportInfo.Items['TextBox'].length ==0){ // ymbin
			delete self.reportInfo.Items['TextBox'];
		}
		if(self.reportInfo.Items['Hierarchical'].length ==0){
			delete self.reportInfo.Items['Hierarchical'];
		}
		if(self.reportInfo.Items['ForceDirect'].length ==0){
			delete self.reportInfo.Items['ForceDirect'];
		}
		if(self.reportInfo.Items['ForceDirectExpand'].length ==0){
			delete self.reportInfo.Items['ForceDirectExpand'];
		}

		if(typeof self.reportInfo.ReportMasterInfo.paramJson =='undefined'){
			self.reportInfo.ReportMasterInfo.paramJson = {};
		}
	}


	this.initNewReport = function(){
		var newReportStructure = {};
		newReportStructure.CurrencyCulture = "ko-KR";
		newReportStructure.DataSources = {"DataSource":[]};
		newReportStructure.Items = {};
// newReportStructure.LayoutTree =
// {"LayoutGroup":{"LayoutItem":[],"Orientation": "Vertical"}};
		newReportStructure.LayoutTree = {"LayoutGroup":{}};
		newReportStructure.LayoutTreeHtml = "";
		newReportStructure.MapOption = {
			"DASHBOARD_XML":{
				"MAIN_ELEMENT":{
					"CANVAS_AUTO": true,
					"CANVAS_HEIGHT": 0,
					"CANVAS_WIDTH": 0
				}
			}
		}
		newReportStructure.ReportMasterInfo = {
			"datasetJson":{"DATASET_ELEMENT":[]}
			, "id":""
			, "name" : ""
			, "fld_id":""
			, "fld_type":""
			, "fld_nm" : ""
			, "ordinal":"0"
			, "type":"DashAny"
			, "tag" : ""
			, "subtitle" : ""
			, "description" : ""
			, "paramJson":{}
			, "promptYn":"N"
		};
		newReportStructure.Title = {
			"Alignment":"Left"
			,"Text":""
		}
		newReportStructure.linkReport=[];
		newReportStructure.subLinkReport=[];

		newReportStructure.layoutConfig = {
			//보고서 레이아웃 설정
					//타이틀
					'TITLE_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.TITLE_HEIGHT_SETTING:25,
					'TITLE_MAIN_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.TITLE_MAIN_FONT_SETTING:"sans-serif",
					'TITLE_MAIN_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.TITLE_MAIN_FONTSIZE_SETTING:13,
					'TITLE_MAIN_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.TITLE_MAIN_COLOR_SETTING:"#6a6f7f",
					'TITLE_SERVE_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.TITLE_SERVE_FONT_SETTING:"Noto Sans KR",
					'TITLE_SERVE_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.TITLE_SERVE_FONTSIZE_SETTING:12,
					'TITLE_SERVE_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.TITLE_SERVE_COLOR_SETTING:"#646464",

					//차트
					'CHART_X_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.CHART_X_FONT_SETTING:"맑은 고딕",
					'CHART_X_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.CHART_X_FONTSIZE_SETTING:12,
					'CHART_X_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.CHART_X_COLOR_SETTING:"#646464",
					'CHART_Y_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.CHART_Y_FONT_SETTING:"맑은 고딕",
					'CHART_Y_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.CHART_Y_FONTSIZE_SETTING:12,
					'CHART_Y_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.CHART_Y_COLOR_SETTING:"#646464",
					'CHART_LEGEND_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.CHART_LEGEND_FONT_SETTING:"맑은 고딕",
					'CHART_LEGEND_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.CHART_LEGEND_FONTSIZE_SETTING:12,

					//그리드
					'GRID_HEADER_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_HEADER_FONT_SETTING:"맑은 고딕",
					'GRID_HEADER_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_HEADER_FONTSIZE_SETTING:12,
					'GRID_HEADER_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_HEADER_COLOR_SETTING:"#959595",
					'GRID_HEADER_BGCOLORT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_HEADER_BGCOLORT_SETTING:"#fafafa",
					'GRID_HEADER_BGCOLORB_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_HEADER_BGCOLORB_SETTING:"#ececed",
					'GRID_HEADER_BGCOLORT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_HEADER_BOCOLORT_SETTING:"#e7e7e7",
					'GRID_HEADER_BOCOLORB_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_HEADER_BOCOLORB_SETTING:"#546493",
					'GRID_HEADER_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_HEADER_HEIGHT_SETTING:31,
					'GRID_DATA_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_DATA_FONT_SETTING:"맑은 고딕",
					'GRID_DATA_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_DATA_FONTSIZE_SETTING:12,
					'GRID_DATA_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_DATA_COLOR_SETTING:"#333333",
					'GRID_DATA_BGCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_DATA_BGCOLOR_SETTING:"#ffffff",
					'GRID_DATA_BOCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_DATA_BOCOLOR_SETTING:"#ffffff",
					'GRID_DATA_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.GRID_DATA_HEIGHT_SETTING:31,

					//피벗 그리드
					'PIBOT_HEADER_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_HEADER_FONT_SETTING:"맑은 고딕",
					'PIBOT_HEADER_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_HEADER_FONTSIZE_SETTING:14,
					'PIBOT_HEADER_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_HEADER_COLOR_SETTING:"#333333",
					'PIBOT_HEADER_BGCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_HEADER_BGCOLOR_SETTING:"#ffffff",
					'PIBOT_HEADER_BOCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_HEADER_BOCOLOR_SETTING:"#ffffff",
					'PIBOT_HEADER_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_HEADER_HEIGHT_SETTING:67,

					'PIBOT_LEFTHEADER_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_FONT_SETTING:"맑은 고딕",
					'PIBOT_LEFTHEADER_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_FONTSIZE_SETTING:14,
					'PIBOT_LEFTHEADER_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_COLOR_SETTING:"#333333",
					//'PIBOT_LEFTHEADER_BGCOLORT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_BGCOLORT_SETTING:"#ffffff",
					//'PIBOT_LEFTHEADER_BGCOLORB_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_BGCOLORB_SETTING:"#ffffff",
					'PIBOT_LEFTHEADER_BGCOLORT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_BGCOLORT_SETTING:"#ffffff",
					'PIBOT_LEFTHEADER_BGCOLORB_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_BGCOLORB_SETTING:"#ffffff",
					'PIBOT_LEFTHEADER_BOCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_BOCOLOR_SETTING:"#ffffff",
					'PIBOT_LEFTHEADER_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_LEFTHEADER_HEIGHT_SETTING:31.2,

					'PIBOT_DATA_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_DATA_FONT_SETTING:"맑은 고딕",
					'PIBOT_DATA_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_DATA_FONTSIZE_SETTING:14,
					'PIBOT_DATA_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_DATA_COLOR_SETTING:"#6A6F7F",
					'PIBOT_DATA_BGCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_DATA_BGCOLOR_SETTING:"#ffffff",
					'PIBOT_DATA_BOCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_DATA_BOCOLOR_SETTING:"#ffffff",
					'PIBOT_DATA_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_DATA_HEIGHT_SETTING:34.4,

					'PIBOT_ST_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_ST_FONT_SETTING:"맑은 고딕",
					'PIBOT_ST_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_ST_FONTSIZE_SETTING:14,
					'PIBOT_ST_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_ST_COLOR_SETTING:"#333333",
					'PIBOT_ST_BGCOLORT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_ST_BGCOLORT_SETTING:"#fafafa",
					'PIBOT_ST_BGCOLORB_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_ST_BGCOLORB_SETTING:"#ececed",
					'PIBOT_ST_BOCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_ST_BOCOLOR_SETTING:"#ffffff",
					'PIBOT_ST_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_ST_HEIGHT_SETTING:30.8,

					'PIBOT_TOTAL_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_TOTAL_FONT_SETTING:"맑은 고딕",
					'PIBOT_TOTAL_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_TOTAL_FONTSIZE_SETTING:14,
					'PIBOT_TOTAL_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_TOTAL_COLOR_SETTING:"#333333",
					'PIBOT_TOTAL_BGCOLORT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_TOTAL_BGCOLORT_SETTING:"#fafafa",
					'PIBOT_TOTAL_BGCOLORB_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_TOTAL_BGCOLORB_SETTING:"#ececed",
					'PIBOT_TOTAL_BOCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_TOTAL_BOCOLOR_SETTING:"#ffffff",
					'PIBOT_TOTAL_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.PIBOT_TOTAL_HEIGHT_SETTING:35.2,

					//필터 레이아웃
					'FILTER_LD_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_LD_SETTING:0,
					'FILTER_RD_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_RD_SETTING:0,
					'FILTER_D_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_D_SETTING:0,
					'FILTER_HEIGHT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING:40,
					'FILTER_LABEL_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_LABEL_FONT_SETTING:"Noto Sans KR",
					'FILTER_LABEL_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_LABEL_FONTSIZE_SETTING:12,
					'FILTER_LABEL_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_LABEL_COLOR_SETTING:"#646464",
					'FILTER_DATA_FONT_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_DATA_FONT_SETTING:"Noto Sans KR",
					'FILTER_DATA_FONTSIZE_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_DATA_FONTSIZE_SETTING:14,
					'FILTER_DATA_COLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_DATA_COLOR_SETTING:"#333333",
					'FILTER_DATA_BOCOLOR_SETTING' : userJsonObject.layoutConfig?userJsonObject.layoutConfig.FILTER_DATA_BOCOLOR_SETTING:"#F4F4F4"
		};


		return newReportStructure;
	};

	/**
	 * 2019-11-13 KERIS 수정
	 */
	this.setLayoutTree = function(reportId) {
		var layoutTree;
		if (reportId) {
			layoutTree = gDashboard.goldenLayoutManager[reportId].canvasLayout.root.element.children();
		} else {
			layoutTree = $('.lm_goldenlayout').children();
		}
		var orientation = layoutTree.hasClass('lm_column') ? 'Vertical' : 'Horizontal';
		var reportInfoLayoutTree = {};

		function calculateItemWeight(_item, type) {
			var parentLength;
			var itemLength;
			if(type == 'Horizontal') {
				parentLength = _item.parent().parent().height();
				itemLength = _item.height();
			}else{
				parentLength = _item.parent().parent().width();
				itemLength = _item.width();
			}
			return itemLength / parentLength * 100;
		};

		function parseLayoutTree(_layoutTree, _orientation) {
			var layoutGroup = {};
			var layoutGroups = [];
			var layoutItems = [];
			var layoutTabContainers = [];
			var groupIndex = 0;
			$.each(_layoutTree, function(i, item) {
				var component = $(item);
				// don't add duplicate nested groups to layout
				if (component.hasClass('lm_column') || component.hasClass('lm_row')) {
					while (component.children().length === 1 && component.children().hasClass('lm_item')
							&& (component.children().hasClass('lm_row') || component.children().hasClass('lm_column'))) {
						component = $(component.children()[0]);
					}
				}
				// horizontal group
				if (component.hasClass('lm_item') && component.hasClass('lm_column')) {
					var childLayoutGroup = parseLayoutTree(component.children(), 'Horizontal');
					childLayoutGroup.Index = groupIndex++;
					layoutGroups.push(childLayoutGroup);
				}
				// vertical group
				else if (component.hasClass('lm_item') && component.hasClass('lm_row')) {
					var childLayoutGroup = parseLayoutTree(component.children(), 'Vertical');
					childLayoutGroup.Index = groupIndex++;
					layoutGroups.push(childLayoutGroup);
				}
				// vertical splitter
				else if (component.hasClass('lm_splitter') && component.hasClass('lm_vertical')) {
					layoutGroup.Weight = calculateItemWeight(component, 'Vertical');
					layoutGroup.Orientation = 'Vertical';
				}
				// horizontal splitter
				else if (component.hasClass('lm_splitter') && component.hasClass('lm_horizontal')) {
					layoutGroup.Weight = calculateItemWeight(component, 'Horizontal');
					layoutGroup.Orientation = 'Horizontal';
				}
				// component item
				else if (component.hasClass('lm_item') && component.hasClass('cont_box')) {
					layoutItems.push({
						DashboardItem: component.attr('id'),
						Weight: calculateItemWeight(component, _orientation),
						Index: groupIndex++
					});
				}
				// tab container item
				else if (component.hasClass('lm_item') && component.hasClass('tab_cont_box')) {
					var tabs = component.children('.lm_header').find('.lm_tabs').children();
					var layoutTabPages = [];
					var tabIndex = 0;
					$.each(tabs, function(j, tab) {
						var orientation;
						var name = $(tab).attr('id').replace('_item_title', '');
						var container = $('#' + name);
						if ($(container).hasClass('lm_stack')) {
							container = $(container).children('.lm_items').children();
						}
						// don't add duplicate nested groups to layout
						if ($(container).hasClass('lm_column') || $(container).hasClass('lm_row')) {
							while ($(container).children().length === 1 && $(container).children().hasClass('lm_item')
									&& ($(container).children().hasClass('lm_row') || $(container).children().hasClass('column'))) {
								container = $(container).children()[0];
							}
						}
						if ($(container).hasClass('lm_column')) {
							orientation = 'Vertical';
						} else {
							orientation = 'Horizontal';
						}
						var tabPage = parseLayoutTree($(container), orientation);
						tabPage.DashboardItem = name;
						tabPage.Orientation = orientation;
						tabPage.Index = tabIndex++;
						layoutTabPages.push(tabPage);
					});
					layoutTabContainers.push({
						DashboardItem: component.attr('id'),
						Weight: calculateItemWeight(component, _orientation),
						LayoutTabPage: layoutTabPages,
						Index: groupIndex++
					});
				}
			});
			if (layoutItems.length > 0) {
				layoutGroup['LayoutItem'] = layoutItems;
			}
			if (layoutGroups.length > 0) {
				layoutGroup['LayoutGroup'] = layoutGroups;
			}
			if (layoutTabContainers.length > 0) {
				layoutGroup['LayoutTabContainer'] = layoutTabContainers;
			}
			return layoutGroup;
		}

		return parseLayoutTree(layoutTree, orientation);
	}


	/*dogfoot 통계분석용 layouttree 생성기 shlim 20201111*/
	this.setAysLayoutTree = function(reportId) {
		var layoutTree;
		if (reportId) {
			layoutTree = gDashboard.goldenLayoutManager[reportId].canvasLayout.root.element.children();
		} else {
			layoutTree = $('.lm_goldenlayout').children();
		}
		var orientation = layoutTree.hasClass('lm_column') ? 'Vertical' : 'Horizontal';
		var reportInfoLayoutTree = {};

		function calculateItemWeight(_item, type) {
			var parentLength;
			var itemLength;
			if(type == 'Horizontal') {
				parentLength = _item.parent().parent().height();
				itemLength = _item.height();
			}else{
				parentLength = _item.parent().parent().width();
				itemLength = _item.width();
			}
			return itemLength / parentLength * 100;
		};

		function parseLayoutTree(_layoutTree, _orientation) {
			var layoutGroup = {};
			var layoutGroups = [];
			/*dogfoot 통계 분석 추가 shlim 20201102*/
			var layoutAysGroups = [];
			var layoutItems = [];
			var layoutTabContainers = [];
			var groupIndex = 0;
			$.each(_layoutTree, function(i, item) {
				var component = $(item);
				// don't add duplicate nested groups to layout
				if (component.hasClass('lm_column') || component.hasClass('lm_row')) {
					while (component.children().length === 1 && component.children().hasClass('lm_item')
							&& (component.children().hasClass('lm_row') || component.children().hasClass('lm_column'))) {
						component = $(component.children()[0]);
					}
				}
				// horizontal group
				if (component.hasClass('lm_item') && component.hasClass('lm_column')) {
					var childLayoutGroup = parseLayoutTree(component.children(), 'Horizontal');
					childLayoutGroup.Index = groupIndex++;
					layoutGroups.push(childLayoutGroup);
				}
				// vertical group
				else if (component.hasClass('lm_item') && component.hasClass('lm_row')) {
					var childLayoutGroup = parseLayoutTree(component.children(), 'Vertical');
					childLayoutGroup.Index = groupIndex++;
					layoutGroups.push(childLayoutGroup);
				}
				// vertical splitter
				else if (component.hasClass('lm_splitter') && component.hasClass('lm_vertical')) {
					layoutGroup.Weight = calculateItemWeight(component, 'Vertical');
					layoutGroup.Orientation = 'Vertical';
				}
				// horizontal splitter
				else if (component.hasClass('lm_splitter') && component.hasClass('lm_horizontal')) {
					layoutGroup.Weight = calculateItemWeight(component, 'Horizontal');
					layoutGroup.Orientation = 'Horizontal';
				}
				// component item
				else if (component.hasClass('lm_item') && component.hasClass('cont_box')) {
					layoutItems.push({
						DashboardItem: component.attr('id'),
						Weight: calculateItemWeight(component, _orientation),
						Index: groupIndex++
					});
				}
				// tab container item
				else if (component.hasClass('lm_item') && component.hasClass('tab_cont_box')) {
					var tabs = component.children('.lm_header').find('.lm_tabs').children();
					var layoutTabPages = [];
					var tabIndex = 0;
					$.each(tabs, function(j, tab) {
						var orientation;
						var name = $(tab).attr('id').replace('_item_title', '');
						var container = $('#' + name);
						if ($(container).hasClass('lm_stack')) {
							container = $(container).children('.lm_items').children();
						}
						// don't add duplicate nested groups to layout
						if ($(container).hasClass('lm_column') || $(container).hasClass('lm_row')) {
							while ($(container).children().length === 1 && $(container).children().hasClass('lm_item')
									&& ($(container).children().hasClass('lm_row') || $(container).children().hasClass('column'))) {
								container = $(container).children()[0];
							}
						}
						if ($(container).hasClass('lm_column')) {
							orientation = 'Vertical';
						} else {
							orientation = 'Horizontal';
						}
						var tabPage = parseLayoutTree($(container), orientation);
						tabPage.DashboardItem = name;
						tabPage.Orientation = orientation;
						tabPage.Index = tabIndex++;
						layoutTabPages.push(tabPage);
					});
					layoutTabContainers.push({
						DashboardItem: component.attr('id'),
						Weight: calculateItemWeight(component, _orientation),
						LayoutTabPage: layoutTabPages,
						/*dogfoot 통계 분석 추가 shlim 20201103*/
						Index: groupIndex++,
						LayoutType: gDashboard.analysisType != undefined && gDashboard.analysisType !="" ? gDashboard.analysisType : "none",
					});
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				}else if (component.hasClass('lm_item') && component.hasClass('lm_stack')) { /*dogfoot 20201030 shlim 통계 분석 저장 작업 중 */
					if(component.children('.lm_items').length !=0){
						if(component.children('.lm_items').children().length > 1){
							var checkCont = false;
							 $.each(component.children('.lm_items').children(),function(_itemIdx,items){
							     if($(items).hasClass('lm_column'))checkCont = true;
							 });


							 if(checkCont){
							 	var layoutConItems = [];
                               $.each(component.children('.lm_items').children(),function(_itemIdx,items){
									 if($(items).hasClass('lm_column')){
                                       $.each($(items).find('.dashboard-item'),function(_itemIdx,items){
											layoutItems.push({
												DashboardItem: $(items).attr('id').replace('_item',''),
												Weight: calculateItemWeight(component, _orientation),
												Index: groupIndex++
											});
										});
										layoutConItems.push({
											Orientation: 'Horizontal',
											LayoutItem: layoutItems,
											Weight: 100,
											Index: groupIndex++,
										});
									 }else{
									 	$.each($(items).find('.dashboard-item'),function(_itemIdx,items){
											layoutItems.push({
												DashboardItem: $(items).attr('id').replace('_item',''),
												Weight: calculateItemWeight(component, _orientation),
												Index: groupIndex++
											});
										});
									 	layoutConItems.push({
											Orientation: 'Horizontal',
											LayoutItem: layoutItems,
											Weight: 100,
											Index: groupIndex++,
										});
									 }
                                    layoutItems = [];
								 });

								 layoutGroups.push({
									Orientation: 'Horizontal',
									LayoutGroup: layoutConItems,
									Weight: 100,
									Index: groupIndex++,
								});
							 }else{
							 	$.each(component.children('.lm_items').children().find('.dashboard-item'),function(_itemIdx,items){
									layoutItems.push({
										DashboardItem: $(items).attr('id').replace('_item',''),
										Weight: calculateItemWeight(component, _orientation),
										Index: groupIndex++
									});
								});

								layoutGroups.push({
									Orientation: 'Horizontal',
									LayoutItem: layoutItems,
									Weight: 100,
									Index: groupIndex++,
								});
							 }


							layoutItems=[]
						}else{
							layoutItems.push({
								DashboardItem: component.attr('id'),
								Weight: calculateItemWeight(component, _orientation),
								Index: groupIndex++
							});
						}
					}
				}
			});
			if (layoutItems.length > 0) {
				layoutGroup['LayoutItem'] = layoutItems;
			}
			if (layoutGroups.length > 0) {
				layoutGroup['LayoutGroup'] = layoutGroups;
			}
			/*dogfoot 통계 분석 추가 shlim 20201103*/
			if (layoutAysGroups.length > 0) {
				layoutGroup['LayoutAysGroup'] = layoutAysGroups;
			}
			if (layoutTabContainers.length > 0) {
				layoutGroup['LayoutTabContainer'] = layoutTabContainers;
			}
			return layoutGroup;
		}

		return parseLayoutTree(layoutTree, orientation);
	}

	this.openReport = function(){
		//yhkim 시계열분석 초기값 20200907 dogfoot
		$.each(this.dxItemBasten, function(_i, _item) {
			if(_item.type == 'SIMPLE_CHART') {
				_item.timeSeries.forecast = false;
				_item.timeSeries.periodType = '';
				_item.timeSeries.period = '';
				_item.timeSeries.seriesColors = [];
				_item.timeSeries.lastSeries = '';
				_item.timeSeries.filteredData = [];
				_item.timeSeries.globalData = [];
				_item.lastSeries = '';
			}
		});

		$('body').append("<div id='openPopup'></div>");
		var openhtml = "<div class=\"modal-body\" style='height:87%'>\r\n" +
		"                        <div class=\"row\" style='height:100%'>\r\n" +
		"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
		/* DOGFOOT ktkang 개인보고서 추가  20200107 */
		"                                		<div class=\"tab-title rowColumn\">\r\n" +
		"                                			<ul  class=\"col-2\">\r\n" +
		"                                				<li rel=\"panelReportA-1\"><a>공용보고서</a></li>\r\n" +
		"                                				<li rel=\"panelReportA-2\"><a>개인보고서</a></li>\r\n" +
		"                                			</ul>\r\n" +
		"                                		</div>\r\n" +
		"                                		<div class=\"panel-inner scrollbar\" style=\"overflow-y:visible !important\">\r\n" +
		"                                		<div id=\"panelReportA\" class=\"tab-component\">\r\n" +
		"                                			<div class=\"panelReportA-1 tab-content\">\r\n" +
		"												<div id=\"folder_tree\" />\r\n" +
		"                                			</div>\r\n" +
		"                               			 <div class=\"panelReportA-2 tab-content\">" +
		"												<div id=\"user_folder_tree\" />\r\n" +
		"											</div>\r\n" +
		"                                		</div>\r\n" +
		"                                	</div>\r\n" +
		"                                </div>\r\n" +
		"                            </div>\r\n" +
		"                        </div>\r\n" + // row 끝
		"                    </div>\r\n" + // modal-body 끝
		"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
		"                        <div class=\"row center\">\r\n" +
		"                            <a id=\"folder_ok\" class=\"btn positive ok-hide\">확인</a>\r\n" +
		"                            <a id=\"folder_cancel\" class=\"btn neutral close\">취소</a>\r\n" +
		"                        </div>\r\n" +
		"                    </div>\r\n" +
		"                </div>";
		$('#openPopup').dxPopup({
			title:'보고서 열기',
			width:'500px',
			height:'700px',
			visible:true,
			showCloseButton: false,
			contentTemplate: function() {
				return openhtml;
	        },
			onContentReady:function(){
				tabUi();
// $.ajax({
// method:'GET',
// url: WISE.Constants.context + '/sql/storage/clear.do',
// success: function(result) {

// }
// });
				var param = {
					/* DOGFOOT ktkang 개인보고서 기능 추가  20200106 */
					'fld_type':'ALL',
					'user_id': userJsonObject.userId,
					'report_type': reportType
				};
				$.ajax({
		        	method : 'POST',
		            url: WISE.Constants.context + '/report/getReportList.do',
		            dataType: "json",
		            data:param,
		            /* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//		            async:false,
		            beforeSend:function(){
						gProgressbar.show();
					},
					complete:function(){
						gProgressbar.hide();
					},
		            success: function(result) {
		            	var pubResult = result.pubReport;
		            	var userResult = result.userReport;
		            	var report_id="",item_type="",report_type="",fld_type="";
		            	var tempPubResult=[], tempUserResult=[];
		            	var menu = userJsonObject.menuconfig.Menu.PROG_MENU_TYPE;
		            	
		            	pubResult.sort(function(a, b) {
		            		if(a.UPPERID < b.UPPERID) return -1;
							if(a.UPPERID > b.UPPERID) return 1;
							if(a.ORDINAL < b.ORDINAL) return -1;
							if(a.ORDINAL > b.ORDINAL) return 1;
							return 0;
	            		});

		            	/* DOGFOOT ktkang 보고서 불러오기 창 닫았다 열면 아이콘 사라지는 버그 수정  20200120 */
		            	$.each(pubResult,function(_i,_items){
            				switch(_items.TYPE){
            				case 'REPORT':
            					/*dogfoot 통계 분석 추가 shlim 20201102*/
            					if(_items.REPORT_TYPE == 'DashAny' || _items.REPORT_TYPE == 'StaticAnal'){
            						_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
            					}else if(_items.REPORT_TYPE == 'AdHoc'){
            						_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';
            					}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
            						_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';
            					}

            					break;
            				case 'FOLDER':
            					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
            					break;
            				}

            				if(reportType == 'Spread' || reportType == 'Excel'){
            					if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel' || _items.TYPE == 'FOLDER'){
            						tempPubResult.push(_items);
        						}
        					}else{
        						if(gDashboard.reportType == 'AdHoc' && _items.REPORT_TYPE == 'AdHoc'){
            						tempPubResult.push(_items);
        						}

            					if(gDashboard.reportType == 'DashAny' && _items.REPORT_TYPE == 'DashAny'){
            						tempPubResult.push(_items);
        						}
            					/*dogfoot 통계 분석 추가 shlim 20201102*/
            					if(gDashboard.reportType == 'StaticAnalysis' && _items.REPORT_TYPE == 'StaticAnal'){
            						tempPubResult.push(_items);
        						}

            					if(_items.TYPE == 'FOLDER'){
            						tempPubResult.push(_items);
        						}
        					}

            			});

		            	$.each(userResult,function(_i,_items){
            				switch(_items.TYPE){
            				case 'REPORT':
            					/*dogfoot 통계 분석 추가 shlim 20201102*/
            					if(_items.REPORT_TYPE == 'DashAny' || _items.REPORT_TYPE == 'StaticAnal'){
            						_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
            					}else if(_items.REPORT_TYPE == 'AdHoc'){
            						_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';
            					}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
            						_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';
            					}

            					break;
            				case 'FOLDER':
            					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
            					break;
            				}

            				if(reportType == 'Spread' || reportType == 'Excel'){
            					if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel' || _items.TYPE == 'FOLDER'){
            						tempUserResult.push(_items);
        						}
        					}else{
        						if(gDashboard.reportType == 'AdHoc' && _items.REPORT_TYPE == 'AdHoc'){
                					tempUserResult.push(_items);
        						}

            					if(gDashboard.reportType == 'DashAny' && _items.REPORT_TYPE == 'DashAny'){
            						tempUserResult.push(_items);
        						}
        						/*dogfoot 통계 분석 추가 shlim 20201102*/
            					if(gDashboard.reportType == 'StaticAnalysis' && _items.REPORT_TYPE == 'StaticAnal'){
            						tempUserResult.push(_items);
        						}

            					if(_items.TYPE == 'FOLDER'){
            						tempUserResult.push(_items);
        						}
        					}
            			});

		            	pubResult = tempPubResult;
	            		userResult = tempUserResult

		            	$('#folder_tree').dxTreeView({
		            		dataSource:pubResult,
		            		dataStructure:'plain',
		            		keyExpr: "uniqueKey",
		            		parentIdExpr: "upperKey",
		            		rootValue: "F_0",
		            		displayExpr: "TEXT",
		            		searchEnabled: true,
							searchMode : "contains",
							searchTimeout:undefined,
							searchValue:"",
							noDataText:"조회된 폴더가 없습니다.",
		            		height:"460",
		            		showCloseButton: false,
		            		onItemClick:function(_e){
		            			report_id = _e.itemData['ID'];
		            			item_type = _e.itemData['TYPE'];
		            			report_type = _e.itemData['REPORT_TYPE'];
		            			/*dogfoot 통계 분석 추가 shlim 20201102*/
		            			if(_e.itemData['REPORT_TYPE'] === "StaticAnal"){
		            				report_type = "StaticAnalysis";
		            			}else{
		            				report_type = _e.itemData['REPORT_TYPE'];
		            			}
		            			/* DOGFOOT ktkang 개인보고서 추가  20200107 */
		            			fld_type = _e.itemData['FLD_TYPE'];
		            		}
		            	});

		            	$('#user_folder_tree').dxTreeView({
		            		dataSource:userResult,
		            		dataStructure:'plain',
		            		keyExpr: "uniqueKey",
		            		parentIdExpr: "upperKey",
		            		rootValue: "F_0",
		            		displayExpr: "TEXT",
		            		searchEnabled: true,
							searchMode : "contains",
							searchTimeout:undefined,
							searchValue:"",
							noDataText:"조회된 폴더가 없습니다.",
		            		height:"460",
		            		showCloseButton: false,
		            		onItemClick:function(_e){
		            			report_id = _e.itemData['ID'];
		            			item_type = _e.itemData['TYPE'];
		            			report_type = _e.itemData['REPORT_TYPE'];
		            			/*dogfoot 통계 분석 추가 shlim 20201102*/
		            			if(_e.itemData['REPORT_TYPE'] === "StaticAnal"){
		            				report_type = "StaticAnalysis";
		            			}else{
		            				report_type = _e.itemData['REPORT_TYPE'];
		            			}
		            			fld_type = _e.itemData['FLD_TYPE'];
		            		}
		            	});

		            	//보고서 불러오기 창 닫았다 열면 아이콘 사라지는 버그 수정 끝
		            	$('#folder_ok').dxButton({
		            		type:'default',
		            		text:'확인',
		            		onClick:function(){
		            			if(item_type != 'FOLDER'){
		            				/* DOGFOOT ktkang 동시 작업 제한 기능 구현  20200922 */
		            				var works = gDashboard.selectReportWorks();
		            				if(userJsonObject.limitWorks > 0 && works >= userJsonObject.limitWorks) {
		            					WISE.alert('지금 진행하신 작업이 서버의 동시 작업 제한 건수를 넘어서 취소되었습니다.');
		            					gDashboard.updateReportLog('99');
		            					$('#progress_box').css('display', 'none');
		            					return false;
		            				} else {
		            					gProgressbar.show();

		            					/* DOGFOOT ktkang 보고서 열 때 로딩바 바로 나오도록 수정  20200110 */
		            					$('#openPopup').dxPopup('hide');

		            					//2020.02.04 mksong 레포트 열기 오류 수정dogfoot
//		            					$('#openPopup').remove();

		            					//20201019 AJKIM setTimeout 제거 dogfoot
	            						try{
	            							if(report_id != "" && item_type === "REPORT"){
	            								switch (report_type) {
		            								case 'AdHoc':
		            									// 프로그래스바 비활성화
		            									gProgressbar.setStopngoProgress(false);
		            									gDashboard.reportType = 'AdHoc';
		            									break;
		            								default:
		            									gDashboard.reportType = report_type;
	            								}

	            								/* DOGFOOT ktkang 개인보고서 추가  20200107 */
	            								gDashboard.fldType = fld_type;
	            								self.isOpened = false;
	            								/*dogfoot 통계 분석 추가 shlim 20201102*/
												if(report_type == 'AdHoc' || report_type == 'DashAny'|| report_type == "StaticAnalysis") {
	            									WISE.Context.isCubeReport = false;
	            									//2020.02.06 mksong itemQuantity 내용 추가 dogfoot
	            									gDashboard.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'parallel':0
	            											, 'choroplethMap':0,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0, 'comboBox':0, 'image':0
	            											, 'textBox':0, 'RectangularAreaChart':0, 'waterfallchart':0,'bubbled3':0, 'histogramchart':0, 'card':0
	            											, 'bubble':0, 'gauge': 0,'adhocItem':0, 'hierarchical':0,'bipartitechart':0, 'funnelchart':0, 'pyramidchart':0
	            											, 'forceDirect':0,'forceDirectExpand':0,'sankeychart':0,'rangebarchart':0,'rangeareachart':0,'timelinechart':0
	            											, 'bubblepackchart':0, 'wordcloudv2':0, 'dendrogrambarchart':0, 'calendarviewchart':0
	            											, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0, 'boxplot': 0, 'coordinateline': 0, 'scatterplot': 0, 'scatterplotmatrix': 0, 'radialtidytree': 0, 'historytimeline': 0, 'arcdiagram':0,'scatterplot2': 0, 'liquidfillgauge': 0
	            											, 'kakaoMap':0, 'kakaoMap2':0, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0};

	            									/* DOGFOOT syjin 카카오 지도 추가  20200820 */

	            									$('.content').children().remove();
	            									gDashboard.itemGenerateManager.dxItemBasten = [];
	            									gDashboard.insertItemManager.clearCanvasLayout();
	            									gDashboard.dataSetCreate.lookUpItems = [];
	            									gDashboard.dataSetCreate.infoTreeList = [];
	            									gDashboard.dataSourceQuantity = 0;
	            									gDashboard.structure.Items = {};
	            									gDashboard.structure.sortedItemIdx = [];
	            									gDashboard.dataSetCreate.subjectInfoList = [];
	            									WISE.Constants.pid = report_id;
	            									// gDashboard = new
	            									// WISE.libs.Dashboard('gDashboard','openReport');
	            									gDashboard.isNewReport = (WISE.Constants.pid == "");
	            									gDashboard.init();
	            									/* DOGFOOT ktkang 주제영역 필터 삭제하는 기능 추가 필터를 주제영역으로 판단한 후에 그리도록 수정  20200221*/
	            									$.each(gDashboard.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT,function(_i,_dataset){
	            										//2020.01.31 MKSONG dataSourceId 지정 DOGFOOT
	            										if(_dataset.DATASET_TYPE == "CUBE") {
	            											WISE.Context.isCubeReport = true;
	            											gDashboard.queryByGeneratingSql = false;
	            										}
	            									});

	            									gDashboard.dataSetCreate.createDxItemsForOpen();

	            									self.setDataSetInfo();

	            									// gDashboard.dataSourceManager.datasetInformation = {};


	            									//2020.03.06 mksong setDataSetInfo 함수화해서 필요없는 부분 삭제 dogfoot

	            									gDashboard.FieldFilter.parameterInformation = gDashboard.parameterFilterBar.parameterInformation;
	            									/* DOGFOOT hsshim 2020-01-13 비정형 사용자 정의 데이터 불러오기 기능 작업 */
	            									if(gDashboard.reportType == 'AdHoc'){
	            										/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
	            										var dataSrcName = gDashboard.structure.ReportMasterInfo.cube_nm;
	            										var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(dataSrcName);

	            										gDashboard.insertItemManager.openAdHocItem(gDashboard.structure.Layout);
	            										$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
	            											_item.dataSourceId = dataSrcId;
	            											if(_item.type === 'PIVOT_GRID'){
	            												_item.dragNdropController.loadAdhocItemData(_item);
	            												_item.dragNdropController.addSortableOptionsForOpen(_item);
	            											}
	            										});
	            										//gDashboard.customFieldManager.setCustomFieldsForOpen(dataSrcId);
	            										/* DOGFOOT hsshim 2020-01-15 끝 */
	            									}else{
	            											/*dogfoot 통계 분석 추가 shlim 20201102*/
															if(typeof gDashboard.reportType != 'undefined' && gDashboard.reportType == 'StaticAnalysis'){
																gDashboard.insertItemManager.openAysItem(gDashboard.analysisType);
															}else{
																$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
																	gDashboard.insertItemManager.openItem(_item);
																});
															}
//		            										$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
//		            											gDashboard.insertItemManager.openItem(_item);
//		            										});

	            										gDashboard.goldenLayoutManager.openInit();
	            									}
	            									/* DOGFOOT hsshim 2020-01-13 끝 */


	            									/* DOGFOOT ktkang 보고서 바로 조회 기능 옵션 추가  20201015 */
	            									if(gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
	            										/* DOGFOOT ktkang 고용정보원10 보고서 바로 조회 기능 옵션 추가 */
	            										gDashboard.datasetMaster.addBetParam();
	            									} else {
	            										gProgressbar.stopngo = true;
	            										gProgressbar.hide();
	            									}

	            								} else if(report_type == 'Excel' || report_type == 'Spread') {
	            									//time code for sparedJS
	            									window.startTime = window.performance.now();

	            									WISE.Context.isCubeReport = false;
	            									WISE.Constants.pid = report_id;
	            									/* DOGFOOT hsshim 200103
	            									 * 스프레드 불러오기 기능 개선
	            									 */
	            									gDashboard.spreadsheetManager.reportId = report_id;
	            									gDashboard.dataSetCreate.lookUpItems = [];
	            									gDashboard.dataSetCreate.infoTreeList = [];
	            									gDashboard.dataSourceQuantity = 0;
	            									gDashboard.dataSetCreate.subjectInfoList = [];

	            									gDashboard.isNewReport = (WISE.Constants.pid == "");
	            									gDashboard.init();

	            									/* DOGFOOT hsshim 200103
	            									 * 스프레드 불러오기 기능 개선
	            									 */
	            									gDashboard.spreadsheetManager.loadDatasetInfo();
	            									gDashboard.spreadsheetManager.fileOpenFromServer();
	            								}
	            								$('#openPopup').dxPopup('hide');
	            								$('#openPopup').remove();
	            								/* DOGFOOT ktkang 보고서 아무것도 선택하지 않고 확인 눌렀을 때 오류 수정  20200120 */
	            							} else {
	            								WISE.alert('선택하신 보고서가 없습니다.<br>다시 선택해주세요.');
	            								gProgressbar.hide();
	            							}
	            							if(gDashboard.structure.linkReport) {
	            								$('#linkReportList').empty();
	            								$.each(gDashboard.structure.linkReport,function(_i,_o){
	            									$('#linkReportList').append('<li><a id=' + _o.target_id + ' href="#">' + _o.target_nm + '</a></li>');

	            									$('#' + _o.target_id).click(function(e) {
	            										//20200709 AJKIM 연결보고서 파라미터 전달 부분 수정 dogfoot
	            										var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

	            										var linkReportMeta = gDashboard.structure.linkReport;
	            										var linkJsonMatch = {};
	            										var target_id;

	            										$.each(linkReportMeta,function(_i,_linkMeta){
	            											if(_linkMeta.link_type == 'LP')
	            											{
	            												target_id = _linkMeta.target_id;
	            												if(typeof _linkMeta.linkJson.LINKDATA_XML != 'undefined' && _linkMeta.linkJson.LINKDATA_XML !== "") {
	            													// 2019.12.24 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
	            													$.each(WISE.util.Object.toArray(_linkMeta.linkJson.LINKDATA_XML.ARG_DATA? _linkMeta.linkJson.LINKDATA_XML.ARG_DATA : _linkMeta.linkJson.LINKDATA_XML[0].ARG_DATA),function(_j,_linkJson){
	            														var isBetween = false;
	            														$.each(paramListValue, function(_key,_paramValue){
	            															if(_paramValue.orgParamName == _linkJson.FK_COL_NM){
	            																if(_paramValue.parameterType.indexOf('BETWEEN') != -1){
	            																	isBetween = true;
	            																	if(isBetween){
	            																		/* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
	            																		linkJsonMatch[_linkJson.FK_COL_NM] = [encodeURI(paramListValue[_linkJson.FK_COL_NM+'_fr'].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM+'_fr'].value),
	            																			encodeURI(paramListValue[_linkJson.FK_COL_NM+'_to'].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM+'_to'].value)]
	            																	}
	            																}
	            															}
	            														});
	            														// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
	            														if(!isBetween){
	            															/* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
	            															linkJsonMatch[_linkJson.FK_COL_NM] = encodeURI(paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value);
	            														}
	            													});
	            												}else {
	            													linkJsonMatch = {};
	            												}

	            											}
	            										});

	            										var locationStr = "";
	            										if(linkJsonMatch != {}) {
	            											$.each(linkJsonMatch,function(_key,_val){
	            												// 2020.01.16 수정자 : mksong 연결보고서 VALUE값 암호화 DOGFOOT
	            												locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(_val)+'&';
	            											});
	            											locationStr = (locationStr.substring(0,locationStr.length-1));

	            											if(locationStr.length > 1) {
	            												locationStr = "&" + locationStr;
	            											}
	            										}
	            										var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_o.target_id+'/viewer.do?USER=admin&assign_name=bWVpcw==' + locationStr;
	            										window.open(urlString);
	            									});
	            								});
	            							}

	            							if(gDashboard.structure.subLinkReport) {
	            								$.each(gDashboard.structure.subLinkReport,function(_i,_ee){
	            									$('#' + _ee.target_item + '_' + _ee.target_id + '_item_title').click(function(e) {
	            										if(_ee.target_item +'_' + _ee.arg_id +'_item' == self.itemid && _ee.link_type == 'LP'){
	            											target_id = _ee.target_id;

	            											linkJsonMatch = {};

	            											if(!(typeof _ee.linkJson == "object" && !Object.keys(_ee.linkJson).length)) {
	            												$.each(_ee.linkJson.LINK_XML_PARAM.ARG_DATA,function(_j,_linkJson){
	            													if(!Array.isArray(_ee.linkJson.LINK_XML_PARAM.ARG_DATA)) {
	            														linkJsonMatch[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.PK_COL_NM] = paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value;
	            													} else if(_linkJson.PK_COL_NM) {
	            														linkJsonMatch[_linkJson.PK_COL_NM] = encodeURI(paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value);
	            													}
	            												});
	            											}

	            											var locationStr = "";
	            											$.each(linkJsonMatch,function(_key,_val){
	            												// 2019.12.24 수정자 : mksong 연결보고서 VALUE값 암호화 DOGFOOT
	            												locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(_val)+'&';
	            											});
	            											locationStr = (locationStr.substring(0,locationStr.length-1));
	            											if(locationStr.length > 1) {
	            												locationStr = "&" + locationStr;
	            											}
	            											var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_ee.target_id+'/viewer.do?USER=admin&assign_name=bWVpcw==' + locationStr;
	            											window.open(urlString);
	            										}
	            									});
	            								});
	            							}
	            						}catch(e){
	            							/* DOGFOOT hsshim 200103
	            							 * 스프레드 오류 매시지 보기
	            							 */
	            							console.error(e.stack);
	            							// 2020.01.07 mksong 경고창 UI 변경 dogfoot
	            							WISE.alert("보고서를 불러오는데 실패하였습니다.<br>관리자에게 문의하세요.",'error');
	            							$('#openPopup').dxPopup('hide');
	            							$('#openPopup').remove();
	            							gProgressbar.hide();
	            						}
		            				}
		            			}
		            			else{
		            				/* DOGFOOT ktkang 보고서 아무것도 선택하지 않고 확인 눌렀을 때 오류 수정  20200120 */
		            				WISE.alert('선택하신 보고서가 없습니다.<br>다시 선택해주세요.');
		            			}

		            		}
            			});
            			$('#folder_cancel').dxButton({
            				type:'danger',
                    		text:'취소',
                    		onClick:function(){
                    			$('#openPopup').dxPopup('hide');
	            				$('#openPopup').remove();
		            		},
		            		onContentReady: function(){
		            			$('#folder_tree').css('font-size', gDashboard.fontManager.getFontSize(14, 'Menu'))
		            			$('#folder_tree').css('font-family', gDashboard.fontManager.getFontFamily('Menu'))
		            			$('#user_folder_tree').css('font-size', gDashboard.fontManager.getFontSize(14, 'Menu'))
		            			$('#user_folder_tree').css('font-family', gDashboard.fontManager.getFontFamily('Menu'))
		            			$('.dx-overlay-wrapper').css('font-family', gDashboard.fontManager.getFontFamily('Menu'))
		            			$('.dx-overlay-content .dx-widget').css('font-family', gDashboard.fontManager.getFontFamily('Menu'))
		            			$('.dx-popup-content .dx-texteditor-input').css('font-family', gDashboard.fontManager.getFontFamily('Menu'))
		            		}
            			});
            			/* DOGFOOT ktkang 보고서 열 때 로딩바 바로 나오도록 수정  20200110 */
		            }
		        });
			}
		});
	};

	//2020.03.06 mksong setDataSetInfo 함수화 dogfoot
	this.setDataSetInfo = function(){
		$.each(gDashboard.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT,function(_i,_dataset){
			//2020.01.31 MKSONG dataSourceId 지정 DOGFOOT
			var dataSourceId;
			if(gDashboard.structure.DataSources.DataSource){
				$.each(gDashboard.structure.DataSources.DataSource,function(_index,_dataSource){
					if(_dataset.DATASET_NM == _dataSource.Name){
						dataSourceId = _dataSource.ComponentName;
					}
				});
			}

			if(_dataset.DATASET_TYPE == "CUBE") {
				/* DOGFOOT ktkang 주제영역 필터 삭제하는 기능 추가 필터를 주제영역으로 판단한 후에 그리도록 수정  20200221*/

				_dataset.mapid = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(_dataset.DATASET_NM);
				gDashboard.dataSetCreate.cubeListInfo(_dataset.DATASRC_ID, 'CUBE');
				//20201019 AJKIM setTimeout 제거 dogfoot
				var $dataSetLookUp = $("#dataSetLookUp");
				
				if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
					$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
				}
				var lookUpIns = $dataSetLookUp.dxLookup('instance');
				lookUpIns.option('value', gDashboard.structure.ReportMasterInfo.cube_nm);
				self.settingByDatasetMapid(_dataset);
			
			}
			// 2021-07-16  조회 개선 굳이 데이터집합 목록을 불러오기위해 아래것들을 다시 할 필요가 없다.
			else if (_dataset.DATASET_TYPE == "DataSetCube"||_dataset.DATASET_TYPE == "DataSetDs"){
				//gDashboard.dataSetCreate.openDataSetInfo(_dataset);
			}
			else {
				//2020.01.31 MKSONG dataSourceId 지정 DOGFOOT
				//gDashboard.dataSetCreate.openDirectQueryTblColInfo(_dataset,dataSourceId);
			}
			//2020.01.17 mksong 매개변수 목록 오류 수정 dogfoot

//			$.ajax({
//				type : 'post',
//				async:false,
//				url : WISE.Constants.context + '/report/subjectListForOpen.do',
//				data:{
//					'dataType': _dataset.DATASRC_TYPE,
//					'dsid': _dataset.DATASRC_ID,
//				},
//				success : function(data) {
//					data = JSON.parse(data);
//					gDashboard.dataSetCreate.subjectInfoList[_dataset.mapid] = data.subjectInfos[0];
//					// gDashboard.dataSetCreate.paramTreeList[_dataset.mapid];
//				}
//			});
		});
	};

	this.settingByDatasetMapid = function(_dataset){
		gDashboard.FieldFilter.dataSourceparameterInformation[_dataset.mapid] = [];
		gDashboard.dataSetCreate.paramTreeList[_dataset.mapid] = [];
		if(gDashboard.reportType == 'AdHoc'){
			$.each(gDashboard.dataSourceManager.datasetInformation,function(_i,_e){
				if(_e.PARAM_ELEMENT != undefined){
					$.each(WISE.util.Object.toArray(_e.PARAM_ELEMENT.PARAM),function(_j,_ee){
						gDashboard.dataSetCreate.paramTreeList[_dataset.mapid].push(_ee.PARAM_NM);
					})

				}
			});
			/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
			if (typeof gDashboard.dataSourceManager.datasetInformation[_dataset.mapid].PARAM_ELEMENT !== 'undefined') {
				$.each(WISE.util.Object.toArray(gDashboard.dataSourceManager.datasetInformation[_dataset.mapid].PARAM_ELEMENT.PARAM),function(_i,_e){
					gDashboard.dataSetCreate.paramTreeList[_dataset.mapid].push(_e.PARAM_NM);
					//2020.01.17 mksong 매개변수 목록 오류 수정 dogfoot
					gDashboard.FieldFilter.dataSourceparameterInformation[_dataset.mapid].push(gDashboard.parameterFilterBar.parameterInformation[_e.PARAM_NM]);
				});
			}
		}else{
			if (_dataset.DATASET_TYPE === 'DataSetSQL') {
				var ds = gDashboard.dataSourceManager.datasetInformation[_dataset.mapid];
				if (ds && ds.SQL_QUERY) {
					/* DOGFOOT ktkang 매개변수 명이 한글 일 때 처리  20200706 */
					var listParams = ds.SQL_QUERY.match(/@\S*/g);
					var params;
					if(listParams) {
						var listParamsArray = [];
						$.each(listParams, function(_i, _e) {
							listParamsArray.push(_e.toString().replace(/\)/g, ''))
						});
						params = _.uniq(listParamsArray);
					} else {
						params = [];
					}
					for (var i = 0; i < params.length; i++) {
						gDashboard.dataSetCreate.paramTreeList[_dataset.mapid].push(params[i]);
						//2020.01.17 mksong 매개변수 목록 오류 수정 dogfoot
						gDashboard.FieldFilter.dataSourceparameterInformation[_dataset.mapid].push(gDashboard.parameterFilterBar.parameterInformation[params[i]]);
					}
				}
			}
			else if(_dataset.DATASET_TYPE != "DataSetSingleDs" && _dataset.DATASET_TYPE != "DataSetSingleDsView"){
				if(_dataset.DATASET_JSON){
					$.each(WISE.util.Object.toArray(_dataset.DATASET_JSON.DATA_SET.PARAM_ELEMENT.PARAM),function(_i,_e){
						gDashboard.dataSetCreate.paramTreeList[_dataset.mapid].push(_e.PARAM_NM);
						//2020.01.17 mksong 매개변수 목록 오류 수정 dogfoot
						gDashboard.FieldFilter.dataSourceparameterInformation[_dataset.mapid].push(gDashboard.parameterFilterBar.parameterInformation[_e.PARAM_NM]);
					});
				}
			}
		}
		/* DOGFOOT hsshim 2020-01-13 데이터 집합 트리 리스트 적용후 사용자 정의 데이터를 적용 */
		gDashboard.customFieldManager.setCustomFieldsForOpen(_dataset.mapid);

		if(_.keys(gDashboard.dataSetCreate.paramTreeList).length == _.keys(gDashboard.dataSourceManager.datasetInformation).length){
			/* DOGFOOT ktkang 아이템이 다 그려지기 전에 로딩바 사라지는 오류 수정  20201014 */
			if(gDashboard.itemGenerateManager.dxItemBasten.length == 0 || gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length) {
				gProgressbar.hide();
			}
		}
	};

	this.capitalizeFirstLetter =function(string) {
	    return string.charAt(0).toUpperCase() + string.slice(1);
	};

	this.addLinkedReport = function(subYn, item){
		var report_id, item_type, report_type, report_nm;
		var selectReportId = 0;
		var newLinkReportList = [];
		var newSubLinkReportList = [];

		$('body').append("<div id='linkedReportPopup'></div>");
		var openhtml = "<div class=\"modal-body\">\r\n" +
				"            <!-- drag 시 column 의 너비를 조정하세요 -->\r\n" +
				"            <div class=\"row col-2\">\r\n" +
				"                <div class=\"column\" style=\"width:50%;\">\r\n" +
				"                    <div class=\"modal-article\">\r\n" +
				"                        <div class=\"modal-tit\">\r\n" +
				"	                        <span>보고서 목록</span>\r\n" +
				"	                    </div>\r\n" +
				"                        <div class=\"scroll-wrapper line-area scrollbar h420\" style=\"position: relative;\"><div class=\"line-area scrollbar h420 scroll-content\" style=\"height: 418px; margin-bottom: 0px; margin-right: 0px; max-height: none;\">\r\n" +
				"                            <div id=\"reportListTree\" class=\"drop-down tree-menu\">\r\n" +
				"                            </div>\r\n" +
				"                        </div><div class=\"scroll-element scroll-x\"><div class=\"scroll-element_outer\"><div class=\"scroll-element_size\"></div><div class=\"scroll-element_track\"></div><div class=\"scroll-bar\" style=\"width: 96px;\"></div></div></div><div class=\"scroll-element scroll-y\"><div class=\"scroll-element_outer\"><div class=\"scroll-element_size\"></div><div class=\"scroll-element_track\"></div><div class=\"scroll-bar\" style=\"height: 96px;\"></div></div></div></div>\r\n" +
				"                    </div>\r\n" +
//				"                    <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" +
				"                    <button id=\"linkedReportMoveLeft\" class=\"btn-move-left\" type=\"button\">move left</button>\r\n" +
				"                    <button id=\"linkedReportMoveRight\" class=\"btn-move-right\" type=\"button\">move right</button>\r\n" +
				"                </div>\r\n" +
				"                <div class=\"column\" style=\"width:50%;\">\r\n" +
				"                    <div class=\"modal-article\">\r\n" +
				"                        <div class=\"modal-tit\">\r\n" +
				"	                        <span>연결 보고서 목록</span>\r\n" +
				"	                        <div style='float:right;'><a id='connectSetting'><img style='height:35px; width:35px;' src='" + WISE.Constants.context + "/resources/main/images/ico_connectReportSettings.png'></a> </div>\r\n" +
				"	                    </div>\r\n" +
				"                        <div class=\"scroll-wrapper line-area scrollbar h420\" style=\"position: relative;\"><div class=\"line-area scrollbar h420 scroll-content\" style=\"height: 418px; margin-bottom: 0px; margin-right: 0px; max-height: none;\">\r\n" +
				"                            <div id=\"selectListGrid\" class=\"select-list tree\">      \r\n" +
				"                            </div>\r\n" +
				"                        </div><div class=\"scroll-element scroll-x\"><div class=\"scroll-element_outer\"><div class=\"scroll-element_size\"></div><div class=\"scroll-element_track\"></div><div class=\"scroll-bar\" style=\"width: 96px;\"></div></div></div><div class=\"scroll-element scroll-y\"><div class=\"scroll-element_outer\"><div class=\"scroll-element_size\"></div><div class=\"scroll-element_track\"></div><div class=\"scroll-bar\" style=\"height: 96px;\"></div></div></div></div>\r\n" +
				"                    </div>\r\n" +
				"                </div>\r\n" +
				"            </div>\r\n" +
				"        </div>\r\n" +
				"        <div class=\"modal-footer\">\r\n" +
				"            <div class=\"row center col-0\">\r\n" +
				"                <a id=\"linkedReportPopupOk\" class=\"btn positive ok-hide\">확인</a>\r\n" +
				"                <a id=\"linkedReportPopupCancel\"class=\"btn neutral close\">취소</a>\r\n" +
				"            </div>\r\n" +
				"        </div>\r\n";

		var originLinkReport = [];
		originLinkReport = originLinkReport.concat(gDashboard.structure.linkReport);
		var originSubLinkReport = [];
		originSubLinkReport = originSubLinkReport.concat(gDashboard.structure.subLinkReport);

		$('#linkedReportPopup').dxPopup({
			width:'1000px',
			height:'700px',
			visible:true,
			showCloseButton: false,
			contentTemplate: function() {
				return openhtml;
	        },
			onContentReady:function(){
				var param = {
					'fld_type':'PUBLIC',
					'user_id': userJsonObject.userId,
					'report_type': 'ALL'
				};
				$.ajax({
		        	method : 'POST',
		            url: WISE.Constants.context + '/report/getReportList.do',
		            dataType: "json",
		            data:param,
		            async:false,
		            beforeSend:function(){
						gProgressbar.show();
					},
					complete:function(){
						gProgressbar.hide();
					},
		            success: function(result) {
		            	result = result.data;
		            	$('#reportListTree').dxTreeView({
		            		dataSource:result,
		            		dataStructure:'plain',
		            		keyExpr: "uniqueKey",
		            		parentIdExpr: "upperKey",
		            		rootValue: "F_0",
		            		// mksong 2019.12.20 보고서 검색기능 추가 수정 dogfoot
		            		searchEnabled: true,
							searchMode : "contains",
							searchTimeout:undefined,
							searchValue:"",
							// 2019.12.10 수정자 : mksong nodataText DOGFOOT
							noDataText:"조회된 폴더가 없습니다.",
		            		displayExpr: "TEXT",
		            		height:"500",
		            		showCloseButton: false,
		            		onInitialized:function(_e){
		            			$.each(_e.component.option('dataSource'),function(_i,_items){
		            				switch(_items.TYPE){
		            				case 'REPORT':
		            					// 2019.12.23 mksong 아이콘 통일 dogfoot
		            					if(_items.REPORT_TYPE == 'DashAny'){
		            						_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
		            					}else if(_items.REPORT_TYPE == 'AdHoc'){
		            						_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';
		            					}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
		            						_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';
		            					}
		            					break;
		            				case 'FOLDER':
		            					_items['icon']= WISE.Constants.context + '/resources/main/images/ico_load.png';
		            					break;
		            				}
		            			});
		            		},
		            		onItemClick:function(_e){
		            			report_id = _e.itemData['ID'];
		            			report_nm = _e.itemData['TEXT'];
		            			item_type = _e.itemData['TYPE'];
		            			report_type = _e.itemData['REPORT_TYPE'];
		            		},
		            		onContentReady: function(){
		            			gDashboard.fontManager.setFontConfigForListPopup('reportListTree')
		            		}
		            	});

		            	$('#connectSetting').on('click', function(e){
		            		if(selectReportId == 0) {
		            			// 2020.01.07 mksong 경고창 UI 변경 dogfoot
		            			WISE.alert('선택된 보고서가 없습니다.','error');
		            			return;
		            		}
		            		if(gDashboard.parameterFilterBar.parameterInformation) {
								/* DOGFOOT mksong 서브연결보고서 오류 수정 20200116 */
		            			var heightSub = 400;
		            			if(subYn) {
		            				heightSub = 700;
		            			}
		            			var html = "<div class=\"modal-inner\">\r\n" +
		            			"           	<div class=\"modal-body\">\r\n" +
		            			"               	<div class=\"modal-article\">\r\n" +
		            			"						<div class=\"modal-tit\">\r\n" +
		                        "							<span>매개변수 연결</span>\r\n" +
		                        "						</div>\r\n" +
		                        						// 2019.12.24 수정자 : mksong 스크롤바 추가 DOGFOOT
		            			"                       <div id=\"filterCon_list\" class=\"scrollbar\"/>\r\n" +
		            			"                   </div>\r\n";
		            			// 2020.02.13 수정자 : mksong DATAGRID 데이터 연결 추가 DOGFOOT
								// 2021-03-17 yyb 데이터 연결 Treemap 추가
		            			if(subYn && (item.kind == 'chart'
												|| item.kind == 'pieChart'
												|| item.kind == 'pivotGrid'
												|| item.kind == 'dataGrid'
												|| item.kind == 'funnelchart'
												|| item.kind == 'pyramidchart'
												|| item.kind == 'rangebarchart'
												|| item.kind == 'rangeareachart'
												|| item.kind == 'timelinechart'
												|| item.kind == 'bubble'
												|| item.kind == 'Treemap')) {
		            				html +=
			            			"               <div class=\"modal-article\">\r\n" +
			            			"					<div class=\"modal-tit\">\r\n" +
			                        "						<span>데이터 연결</span>\r\n" +
			                        "					</div>\r\n" +
      		                        					// 2019.12.24 수정자 : mksong 스크롤바 추가 DOGFOOT
			            			"                   <div id=\"dataCon_list\" class=\"scrollbar\"/>\r\n" +
			            			"               </div>\r\n";
		            			}
		            			html +=
		            			"               </div>\r\n" +
		            			"               <div class=\"modal-footer\">\r\n" +
		            			"               	<div class=\"row center\">\r\n" +
		            			"                   	<a id=\"btn_reportcon_check\" class=\"btn positive ok-hide\">확인</a>\r\n" +
		            			"                       <a id=\"btn_reportcon_cancel\" class=\"btn neutral close\">취소</a>\r\n" +
		            			"                   </div>\r\n" +
		            			"               </div>\r\n" +
		            			"           </div>";
		            			$('#ds_popup').dxPopup({
		            				showCloseButton: true,
		            				showTitle: true,
		            				title:"연결보고서 데이터 설정",
		            				visible: true,
		            				closeOnOutsideClick: false,
		            				contentTemplate: function(){
		            					return html;
		            				},
		            				onContentReady: function() {
		            					gDashboard.fontManager.setFontConfigForEditText('ds_popup');
		            				},
		            				width: 600,
		            				height: heightSub,
		            				onShown: function () {
		            					var gridData = [];
		            					var dataConData = [];
		            					var dataJson;
		            					var dataConJson;

		            					var paramNameData = [];

		            					if(selectReportId != 0) {
		            					$.ajax({
		            						type : 'post',
		            						data: {'reportId' : selectReportId},
		            						url : WISE.Constants.context + '/report/getParamNames.do',
		            						success : function(data) {
		            							data = jQuery.parseJSON(data);

		            							var dataParamNameJson;
		            							dataParamNameJson = new Object();

  												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
	            								dataParamNameJson.nparamName = "";
	            								//
	            								dataParamNameJson.nparamCaptions = "";
	            								paramNameData.push(dataParamNameJson);

		            							$.each(data.paramNames, function(_i, _o) {
		            								dataParamNameJson = new Object();
     												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
		            								dataParamNameJson.nparamName = _o.PARAM_NM;
		            								//
		            								dataParamNameJson.nparamCaptions = _o.PARAM_CAPTION;
		            								paramNameData.push(dataParamNameJson);
		            							});

												/* DOGFOOT ktkang 연결보고서 매개변수 안뜨는 오류 수정  20200731 */
		            							$.each(gDashboard.parameterFilterBar.state.params, function(_i, _o) {
				            						dataJson = new Object()

													// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
				            						dataJson.oparamName = _o.PARAM_NM;
				            						//
				            						dataJson.oparamCaption = _o.PARAM_CAPTION;

				            						var paramValue = "";

			            							if(subYn) {
			            								$.each(gDashboard.structure.subLinkReport, function(_i,_ee){
			            									if(report_nm == _ee.target_nm) {
																// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            										if(typeof _ee.linkJson != 'undefined' && _ee.linkJson != "" && _ee.linkJson.LINK_XML_PARAM != undefined && _ee.linkJson.LINK_XML_PARAM != "") {
			            											if(_ee.linkJson.LINK_XML_PARAM.ARG_DATA.length < 1){
			            												if(_ee.linkJson.LINK_XML_PARAM.ARG_DATA == undefined) {
			            										//
			            													paramValue = "";
			            												}else{
		  														            // 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            													$.each(WISE.util.Object.toArray(_ee.linkJson.LINK_XML_PARAM),function(_k,_arg){
			            														if(dataJson.oparamName == _arg.ARG_DATA.PK_COL_NM){
			            													//
			            															paramValue = _arg.ARG_DATA.PK_COL_NM;
			            														}
			            													});
			            												}
			            											}else{
			            												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            												$.each(WISE.util.Object.toArray(_ee.linkJson.LINK_XML_PARAM.ARG_DATA),function(_k,_arg){
			            													if(dataJson.oparamName == _arg.PK_COL_NM){
			            														paramValue = _arg.PK_COL_NM;
																		//
			            													}
			            												});
			            											}
		            												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            											dataJson.nparamName = paramValue;
																	//
			            										}
			            									}
			            								});
			            							} else {
			            								$.each(gDashboard.structure.linkReport, function(_i,_ee){
			            									if(report_nm == _ee.target_nm) {
			            										if(typeof _ee.linkJson != 'undefined' && _ee.linkJson != "" && _ee.linkJson.LINKDATA_XML != undefined) {
			            											if(_ee.linkJson.LINKDATA_XML.length < 1){
//			            												if(_ee.linkJson.LINKDATA_XML.ARG_DATA.PK_COL_NM == "@undefined") {
			            												if(_ee.linkJson.LINKDATA_XML.ARG_DATA == undefined) {
			            													paramValue = "";
			            												}else{
			            													$.each(WISE.util.Object.toArray(_ee.linkJson.LINKDATA_XML),function(_k,_arg){
				            													// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
				            													if(dataJson.oparamName == _arg.ARG_DATA.PK_COL_NM){
				            													//
				            														paramValue = _arg.ARG_DATA.PK_COL_NM;
				            													}
				            												});
			            												}

			            											} else {
			            												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            												$.each(WISE.util.Object.toArray(_ee.linkJson.LINKDATA_XML),function(_k,_arg){
			            													$.each(WISE.util.Object.toArray(_arg.ARG_DATA), function(_j,_arg_data){
			            														if(dataJson.oparamName == _arg_data.PK_COL_NM){
				            														paramValue = dataJson.oparamCaption;
				            													}
			            													});
			            												});
			            											}
																		//
			            											dataJson.nparamCaptions = paramValue;
			            										}
			            									}
			            								});
			            							}

				            						gridData.push(dataJson);
				            					});

		            							if(subYn) {
				            						$.each(item.dimensions, function(_i, _o) {
				            							var paramValue2 = "";
				            							dataConJson = new Object()

				            							dataConJson.oparamCaption = _o.caption;

				            							$.each(gDashboard.structure.subLinkReport, function(_i,_ee){
			            									if(_ee.target_item == item.ComponentName  && report_nm == _ee.target_nm) {
		           												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            										if(typeof _ee.linkJson2 != 'undefined' && _ee.linkJson2 != "" && _ee.linkJson2.LINK_XML_DATA != undefined && _ee.linkJson2.LINK_XML_DATA != "") {
			            											if(_ee.linkJson2.LINK_XML_DATA.ARG_DATA.PK_COL_NM == "@undefined") {
			            												paramValue2 = "";
			            											} else {
			            												$.each(WISE.util.Object.toArray(_ee.linkJson2.LINK_XML_DATA.ARG_DATA),function(_k,_arg){
			            													if(dataConJson.oparamCaption == _arg.FK_COL_NM){
			            														if(_arg.PK_COL_NM == "@undefined"){
			            															paramValue2 = "";
			            														}else{
			            															paramValue2 = _arg.PK_COL_NM;
			            														}
			            														return;
			            													}
			            												});
			            											}

			            											dataConJson.nparamName = paramValue2;
			            										//수정 끝
			            										}
			            									}
			            								});

				            							dataConData.push(dataConJson);
				            						});
				            					}

		            							$.each(gridData,function(_i,_data){
		            								$.each(paramNameData,function(_k,_paramNdata){
		            									if(_data.nparamName == _paramNdata.nparamName){
		            										_data.nparamCaptions = _paramNdata.nparamCaptions;
		            									}
		            								});
		            							});

		            							$.each(dataConData,function(_i,_data){
		            								$.each(paramNameData,function(_k,_paramNdata){
		            									if(_data.nparamName == _paramNdata.nparamName){
		            										_data.nparamCaptions = _paramNdata.nparamCaptions;
		            									}
		            								});
		            							});

		            							$("#filterCon_list").dxDataGrid({
		            								dataSource: gridData,
		            								showBorders: true,
		            								editing: {
		    								            mode: "cell",
		    								            allowUpdating: true
		    										},
		            								columns: [
		            									{
		            										dataField: "oparamCaption",
		            										caption: "원본 보고서 매개변수",
		            									},
		            									{
		            										dataField: "nparamCaptions",
		            										caption: "대상 보고서 매개변수",
		            										setCellValue: function(rowData, value) {
		            											rowData.nparamCaptions = value.nparamCaptions;
		            											rowData.nparamName = value.nparamName;
		            										},
		            										lookup: {
		            											dataSource: paramNameData,
		            											displayExpr: "nparamCaptions"
		            										}
		            									}
		            								],
		            								onContentReady: function(){
	            		            					gDashboard.fontManager.setFontConfigForEditText('filterCon_list');
		            								}
		            							});
		            							// 2020.02.13 수정자 : mksong DATAGRID 데이터 연결 추가 DOGFOOT
												// 2021-03-17 yyb 데이터 연결 Treemap 추가
		            							if(subYn && (item.kind == 'chart'
															|| item.kind == 'pieChart'
															|| item.kind == 'pivotGrid'
															|| item.kind == 'dataGrid'
															|| item.kind == 'funnelchart'
															|| item.kind == 'pyramidchart'
															|| item.kind == 'rangebarchart'
															|| item.kind == 'rangeareachart'
															|| item.kind == 'timelinechart'
															|| item.kind == 'bubble'
															|| item.kind == 'Treemap')) {
		            								$("#dataCon_list").dxDataGrid({
		            									dataSource: dataConData,
		            									showBorders: true,
		            									editing: {
			    								            mode: "cell",
			    								            allowUpdating: true
			    										},
		            									columns: [
		            										{
		            											dataField: "oparamCaption",
		            											caption: "원본 보고서 차원",
		            										},
		            										{
		            											dataField: "nparamCaptions",
		            											caption: "대상 보고서 매개변수",
		            											setCellValue: function(rowData, value) {
		            												rowData.nparamCaptions = value.nparamCaptions;
		            											},
		            											lookup: {
		            												dataSource: paramNameData,
		            												displayExpr: "nparamCaptions"
		            											}
		            										}
		            									],
			            								onContentReady: function(){
		            		            					gDashboard.fontManager.setFontConfigForEditText('dataCon_list');
			            								}
		            								});
		            							}
		            						}
		            					});
		            					} else {
		            						// 2020.01.07 mksong 경고창 UI 변경 dogfoot
		            						WISE.alert('선택된 보고서가 없습니다.','error')
		            					}
		            				}
		            			});

		            			$("#btn_reportcon_check").dxButton({
		            				text: "확인",
		            				type: "normal",
		            				onClick: function(e) {
		            					var gridins = $("#filterCon_list").dxDataGrid('instance');
		            					var gridRowData = gridins.getVisibleRows();

		            					if(subYn) {
		            						var dataSubC = "";
		            						if(typeof gridins != 'undefined') {
		            							dataSubC = gridins.getVisibleRows();
		            						}

		            						var dataSubC2;
		            						if(typeof $("#dataCon_list").dxDataGrid('instance') != 'undefined') {
		            							dataSubC2  = $("#dataCon_list").dxDataGrid('instance').getVisibleRows();
		            						}

		            						var linkSubJson = {};
		            						var linkType = "LP";
//		            						if(dataSubC != "" && typeof dataSubC[0].data['nparamCaptions'] != "undefined" && dataSubC[0].data['nparamCaptions'] != "") {
//		            							linkSubJson = {"LINK_XML_PARAM" : {"ARG_DATA" : {"FK_COL_NM" : "@" + dataSubC[0].values[0], "PK_COL_NM" : "@" + dataSubC[0].data['nparamCaptions']}}};
//		            						}

		            						var arg_data = [];
			            					if(dataSubC != ""){
			            						$.each(WISE.util.Object.toArray(dataSubC),function(_i,_d){
			            							if(_d.data['nparamCaptions'] != 'undefined' && _d.data['nparamCaptions'] != ""){
           												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            								$.each($("#filterCon_list").dxDataGrid('option','columns')[1].lookup.dataSource,function(_index,_nparam){
			            									if(_d.data.nparamCaptions == _nparam.nparamCaptions){
			            										var arg = {"FK_COL_NM" : _d.data.oparamName, "PK_COL_NM" : _nparam.nparamName};
					            								arg_data.push(arg);
			            									}
			            								});
			            								//
			            							}
			            						});

			            						linkSubJson = {"LINK_XML_PARAM" : {"ARG_DATA" : arg_data}};
			            					}

		            						var linkSubJson2 = {};
		            						if(dataSubC2 != ""){
		            							var arg_data2 = [];
												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
		            							$.each(WISE.util.Object.toArray(dataSubC2),function(_i,_d){
			            							if(_d.data['nparamCaptions'] != 'undefined' && _d.data['nparamCaptions'] != ""){
			            								$.each($("#dataCon_list").dxDataGrid('option','columns')[1].lookup.dataSource,function(_index,_nparam){
			            									if(_d.data.nparamCaptions == _nparam.nparamCaptions){
			            										var arg = {"FK_COL_NM" : _d.data.oparamCaption, "PK_COL_NM" : _nparam.nparamName};
			            										arg_data2.push(arg);
			            									}
			            								});
			            							}
			            						});
			            						// 수정 끝
		            							if(arg_data2.length !=0){
		            								linkType = "LD";
		            							}
			            						linkSubJson2 = {"LINK_XML_DATA" : {"ARG_DATA" : arg_data2}};
			            					}

		            						var dataS = $('#selectListGrid').dxDataGrid('instance').option('dataSource');

		            						if(gDashboard.structure.subLinkReport!=undefined) {
		            							newSubLinkReportList = gDashboard.structure.subLinkReport;
		            						}

		            						if(newSubLinkReportList.length > 0) {
			            						var newR = true;
			            						$.each(newSubLinkReportList,function(_i,_e){
			            							//2020.02.18 MKSONG 서브연결보고서 저장 오류 수정 DOGFOOT
				            						if(report_id == _e.target_id && item.ComponentName == _e.target_item) {
				            							newR = false;
				            						}
				            					});

			            						if(newR) {
				            						newSubLinkReportList.push({"arg_id" : WISE.Constants.pid, "linkJson" : linkSubJson, "linkJson2" : linkSubJson2, "link_type" : linkType, "target_id" : report_id, "target_type" : report_type, "target_nm" : report_nm, "target_item": item.ComponentName});
			            						} else{
			            							var updateSubLinkReportListt = newSubLinkReportList;
			            							$.each(newSubLinkReportList,function(_i,_subLinkReportList){
			            								if( item.ComponentName == _subLinkReportList.target_item && report_id == _subLinkReportList.target_id){
			            									newSubLinkReportList[_i] = {"arg_id" : WISE.Constants.pid, "linkJson" : linkSubJson, "linkJson2" : linkSubJson2, "link_type" : linkType, "target_id" : report_id, "target_type" : report_type, "target_nm" : report_nm, "target_item": item.ComponentName};
			            								}
			            							});
			            							newSubLinkReportList = updateSubLinkReportListt;
			            						}
			            					} else {
			            						newSubLinkReportList.push({"arg_id" : WISE.Constants.pid, "linkJson" : linkSubJson, "linkJson2" : linkSubJson2, "link_type" : linkType, "target_id" : report_id, "target_type" : report_type, "target_nm" : report_nm, "target_item": item.ComponentName});
			            					}
		            					} else {
		            						var dataC = "";
			            					if(typeof gridins != 'undefined') {
			            						dataC = gridins.getVisibleRows();
			            					}

			            					var arg_data = [];
			            					if(dataC != ""){
			            						$.each(WISE.util.Object.toArray(dataC),function(_i,_d){
			            							if(_d.data['nparamCaptions'] != 'undefined' && _d.data['nparamCaptions'] != ""){
           												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            								$.each($("#filterCon_list").dxDataGrid('option','columns')[1].lookup.dataSource,function(_index,_nparam){
			            									if(_d.data.nparamCaptions == _nparam.nparamCaptions){
			            										var arg = {"ARG_DATA" : {"FK_COL_NM" : _d.data.oparamName, "PK_COL_NM" : _nparam.nparamName}};
					            								arg_data.push(arg);
			            									}
			            								});
			            								// 수정 끝
			            							}
			            						});
			            					}

		            						var linkJson;
		            						linkJson = {"LINKDATA_XML" : arg_data};

			            					if(gDashboard.structure.linkReport!=undefined) {
			            						newLinkReportList = gDashboard.structure.linkReport;
		            						}

			            					if(newLinkReportList.length > 0) {
			            						var newR = true;
			            						$.each(newLinkReportList,function(_i,_e){
				            						if(report_id == _e.target_id) {
				            							newR = false;
				            						}
				            					});

			            						if(newR) {
					            					newLinkReportList.push({"arg_id" : WISE.Constants.pid, "linkJson" : linkJson, "link_type" : "LP", "target_id" : report_id, "target_type" : report_type, "target_nm" : report_nm});
			            						}else{
			            							var updateLinkReportList = newLinkReportList;
			            							$.each(newLinkReportList,function(_i,_linkReportList){
			            								if(report_id == _linkReportList.target_id){
			            									updateLinkReportList[_i] = {"arg_id" : WISE.Constants.pid, "linkJson" : linkJson, "link_type" : "LP", "target_id" : report_id, "target_type" : report_type, "target_nm" : report_nm};
			            								}
			            							});
			            							newLinkReportList = updateLinkReportList;
			            						}
			            					} else {
				            					newLinkReportList.push({"arg_id" : WISE.Constants.pid, "linkJson" : linkJson, "link_type" : "LP", "target_id" : report_id, "target_type" : report_type, "target_nm" : report_nm});
			            					}
		            					}

		            					$("#ds_popup").dxPopup("instance").hide();
		            				}
		            			});

		            			$("#btn_reportcon_cancel").dxButton({
		            				text: "취소",
		            				type: "normal",
		            				onClick: function(e) {
		            					$("#ds_popup").dxPopup("instance").hide();
		            				}
		            			});
		            		} else {
		            			// 2020.01.07 mksong 경고창 UI 변경 dogfoot
		            			WISE.alert('연결 할 매개변수가 없습니다.','error')
		            		}
				        });

		            	$('#linkedReportPopupOk').dxButton({
		            		type:'default',
		            		text:'확인',
		            		onClick:function(){
		            			if(subYn) {
		            				var dataSubS = $('#selectListGrid').dxDataGrid('instance').option('dataSource');

		            				gDashboard.structure.subLinkReport =
		            					gDashboard.structure.subLinkReport.filter(function(report) {
		            						return report.target_item !== item.ComponentName;
		            					})
		            				if(newSubLinkReportList.length > 0) {
			            				gDashboard.structure.subLinkReport = newSubLinkReportList;
			            			} else if(dataSubS.length > 0){
			            				$.each(dataSubS,function(_i,_o){
			            					gDashboard.structure.subLinkReport.push({"arg_id" : WISE.Constants.pid, "linkJson" : "", "linkJson2" : "", "link_type" : "LD", "target_id" : _o.report_id, "target_type" : _o.report_type, "target_nm" : _o['연결 보고서 목록'], "target_item": item.ComponentName});
				            			});
			            			}
		            			} else {
		            				gDashboard.structure.linkReport = [];

			            			var dataS = $('#selectListGrid').dxDataGrid('instance').option('dataSource');
			            			if(newLinkReportList.length > 0) {
			            				gDashboard.structure.linkReport = newLinkReportList;
			            			} else if(dataS.length > 0){
			            				$.each(dataS,function(_i,_o){
				            				gDashboard.structure.linkReport.push({"arg_id" : WISE.Constants.pid, "linkJson" : "", "link_type" : "LP", "target_id" : _o.report_id, "target_type" : _o.report_type, "target_nm" : _o['연결 보고서 목록']});
				            			});
			            			}
		            			}

		            			if(gDashboard.structure.linkReport) {
		            				$('#linkReportList').empty();
		            				$.each(gDashboard.structure.linkReport,function(_i,_o){
		            					$('#linkReportList').append('<li><a id=' + _o.target_id + ' href="#">' + _o.target_nm + '</a></li>');

		            					$('#' + _o.target_id).click(function(e) {
											// 2019.12.24 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
		            						var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

		            						var linkReportMeta = gDashboard.structure.linkReport;
		            						var linkJsonMatch = {};
		            						var target_id;

		            						$.each(linkReportMeta,function(_i,_linkMeta){
		            							if(_linkMeta.link_type == 'LP')
		            							{
		            								target_id = _linkMeta.target_id;
		            								if(typeof _linkMeta.linkJson.LINKDATA_XML != 'undefined' && _linkMeta.linkJson.LINKDATA_XML !== "") {
		            									// 2020.11.23 mksong 연결보고서 연계필터 데이터 전송 오류 수정 DOGFOOT
														if(_linkMeta.linkJson.LINKDATA_XML.ARG_DATA){
															$.each(WISE.util.Object.toArray(_linkMeta.linkJson.LINKDATA_XML.ARG_DATA),function(_j,_linkJson){
			            									    var isBetween = false;
			            									    $.each(paramListValue, function(_key,_paramValue){
			            									        if(_paramValue.orgParamName == _linkJson.FK_COL_NM){
			            									            if(_paramValue.parameterType.indexOf('BETWEEN') != -1){
			            									                isBetween = true;
			            									                if(isBetween){
			            									                    /* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
			            									                	linkJsonMatch[_linkJson.FK_COL_NM] = [encodeURI(paramListValue[_linkJson.FK_COL_NM+'_fr'].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM+'_fr'].value),
				            									                    encodeURI(paramListValue[_linkJson.FK_COL_NM+'_to'].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM+'_to'].value)]
			            									                }
			            									            }
			            									        }
			            									    });
			            									    // 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            									    if(!isBetween){
			            									        /* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
			            									        linkJsonMatch[_linkJson.FK_COL_NM] = encodeURI(paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value);
			            									    }
			            									});
														}else{
															$.each(WISE.util.Object.toArray(_linkMeta.linkJson.LINKDATA_XML),function(_j,_linkJson){
			            									    var isBetween = false;
			            									    $.each(paramListValue, function(_key,_paramValue){
			            									        if(_paramValue.orgParamName == _linkJson.ARG_DATA.FK_COL_NM){
			            									            if(_paramValue.parameterType.indexOf('BETWEEN') != -1){
			            									                isBetween = true;
			            									                if(isBetween){
			            									                    /* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
			            									                	linkJsonMatch[_linkJson.ARG_DATA.FK_COL_NM] = [encodeURI(paramListValue[_linkJson.ARG_DATA.FK_COL_NM+'_fr'].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.ARG_DATA.FK_COL_NM+'_fr'].value),
				            									                    encodeURI(paramListValue[_linkJson.ARG_DATA.FK_COL_NM+'_to'].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.ARG_DATA.FK_COL_NM+'_to'].value)]
			            									                }
			            									            }
			            									        }
			            									    });
			            									    // 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            									    if(!isBetween){
			            									        /* DOGFOOT hsshim 2020-02-19 연결보고서 필터 오류 수정 */
			            									        linkJsonMatch[_linkJson.ARG_DATA.FK_COL_NM] = encodeURI(paramListValue[_linkJson.ARG_DATA.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.ARG_DATA.FK_COL_NM].value);
			            									    }
			            									});
														}
		            								}else {
		            									linkJsonMatch = {};
		            								}

		            							}
		            						});

		            						var locationStr = "";
		            						if(linkJsonMatch != {}) {
		            							$.each(linkJsonMatch,function(_key,_val){
													// 2020.01.16 수정자 : mksong 연결보고서 VALUE값 암호화 DOGFOOT
		            								locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(_val)+'&';
		            							});
		            							locationStr = (locationStr.substring(0,locationStr.length-1));

		            							if(locationStr.length > 1) {
		            								locationStr = "&" + locationStr;
		            							}
		            						}
		            						var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_o.target_id+'/viewer.do?USER=admin&assign_name=bWVpcw==' + locationStr;
		            						window.open(urlString);
		            					});
			            			});
		            			}

		            			//20201112 AJKIM 통계 분석 서브 연결 보고서 삭제 dogfoot
		            			if(subYn && gDashboard.reportType !== 'StaticAnalysis'){
		            				var contextMenuItems;
		            				if(gDashboard.structure && gDashboard.structure.subLinkReport) {
		            					contextMenuItems = [{
		            						text : '서브 연결 보고서 설정'
		            					}];

		            					$.each(gDashboard.structure.subLinkReport,function(_i,_linkMeta){
		            						if(item.ComponentName == _linkMeta.target_item) {
		            							var targetNm = {"text" : _linkMeta.target_nm, "item" : _linkMeta.target_item};
		            							contextMenuItems.push(targetNm);
		            						}
		            					});
		            				} else {
		            					contextMenuItems = [{
		            						text : '서브 연결 보고서 설정'
		            					}];
		            				}
		            				$("#" + item.ComponentName + "_contextMenu").dxContextMenu('instance').option('dataSource', contextMenuItems);
		            			}

		            			$('#linkedReportPopup').dxPopup('hide');
		            		}
            			});
            			$('#linkedReportPopupCancel').dxButton({
            				type:'danger',
                    		text:'취소',
                    		onClick:function(){
                    			gDashboard.structure.linkReport = originLinkReport;
                    			gDashboard.structure.subLinkReport = originSubLinkReport;

                    			$('#linkedReportPopup').dxPopup('hide');
	            				$('#linkedReportPopup').remove();
		            		}
            			});

            			gDashboard.fontManager.setFontConfigForEditText('linkedReportPopup');
            			gProgressbar.hide();
		            }
		        });
			}
		});

		var linkReportList = [];
		if(subYn) {
			$.each(gDashboard.structure.subLinkReport,function(_i,_linkMeta){
				if(item.ComponentName == _linkMeta.target_item) {
					linkReportList.push({"report_nm" : _linkMeta.target_nm, "report_id" : _linkMeta.target_id, "연결 보고서 목록" : _linkMeta.target_nm, "report_type" : _linkMeta.target_type});
				}
			});
		} else {
			$.each(gDashboard.structure.linkReport,function(_i,_linkMeta){
				linkReportList.push({"report_nm" : _linkMeta.target_nm, "report_id" : _linkMeta.target_id, "연결 보고서 목록" : _linkMeta.target_nm, "report_type" : _linkMeta.target_type});
			});
		}
		$("#selectListGrid").dxDataGrid({
	        columns: ["연결 보고서 목록"],
	        dataSource: linkReportList,
	        showBorders: true,
	        height:"400",
	        selection: {
	            mode: "single"
	        },
	        onSelectionChanged:function(_e){
	        	if(_e.selectedRowsData.length > 0) {
	        		selectReportId = _e.selectedRowsData[0]['report_id'];
	        		report_id = _e.selectedRowsData[0]['report_id'];
	    			report_nm = _e.selectedRowsData[0]['연결 보고서 목록'];
	    			report_type = _e.selectedRowsData[0]['report_type'];
	        	} else {
	        		selectReportId = 0;
	        	}
    		}
	    });

		$('#linkedReportMoveLeft').on('click', function() {
			var selectedIndex = $('#selectListGrid').dxDataGrid('instance').getRowIndexByKey($('#selectListGrid').dxDataGrid('instance').option('selectedRowKeys')[0]);
			if (selectedIndex != null) {
				$('#selectListGrid').dxDataGrid('instance').deleteRow(selectedIndex);
			}
		});

		$('#linkedReportMoveRight').on('click', function() {
			if (report_id && report_type != "") {
				var dataS = $('#selectListGrid').dxDataGrid('instance').option('dataSource');
				var newR = true;
				$.each(dataS,function(_i,_e){
					if(report_id == _e.report_id) {
						newR = false;
					}
				});

				if(newR) {
					if(dataS.length > 0) {
						dataS.push({"report_id" : report_id, "연결 보고서 목록" : report_nm, "item_type" : item_type, "report_type" : report_type});
					} else {
						dataS = [{"report_id" : report_id, "연결 보고서 목록" : report_nm, "item_type" : item_type, "report_type" : report_type}];
					}

					$('#selectListGrid').dxDataGrid('instance').option('dataSource', dataS);
				} else {
					// 2020.01.07 mksong 경고창 UI 변경 dogfoot
					WISE.alert('이미 동일한 보고서가 있습니다.','error')
				}
			} else {
				WISE.alert('연결보고서 오류<br>보고서를 선택해주시기 바랍니다.')
			}
		});
	};

	/**
	 * Helper function for saveReport(). Generate DATASET_XML params for saving.
	 * @param {object} datasetXml
	 */
	this.insertDatasetSaveInfo = function(datasetXml) {
		var _cnt = 0;
		$.each(gDashboard.datasetMaster.getState('DATASETS'), function(id, dataset) {
			_cnt++;
			switch (dataset.DATASET_TYPE) {
				case 'DataSetCube':
					datasetXml[dataset.mapid] = {
						'DATASET_NM': dataset.DATASET_NM,
						'DATASET_TYPE': dataset.DATASET_TYPE,
						'DATASRC_ID': dataset.DATASRC_ID,
						'DATASRC_TYPE': dataset.DATASRC_TYPE,
						'mapid': dataset.mapid,
						'SQL_QUERY': dataset.DATASET_QUERY,
						'SEL_ELEMENT': { SELECT_CLAUSE: self.dsUtility.convertSelectClauseToCubeFormat(dataset.SEL_CLAUSE) },
						'WHERE_ELEMENT': { WHERE_CLAUSE: self.dsUtility.convertWhereClauseToCubeFormat(dataset.WHERE_CLAUSE) },
						'ORDER_ELEMENT': { ORDER_CLAUSE: self.dsUtility.convertOrderClauseToCubeFormat(dataset.ORDER_CLAUSE) },
						'PARAM_ELEMENT': { PARAM: self.dsUtility.getParamByMapId(dataset.mapid) },
						'SHEET_ID': dataset.SHEET_ID || ''
					};
					break;
				case 'DataSetDs':
					datasetXml[dataset.mapid] = {
						'DATASET_NM': dataset.DATASET_NM,
						'DATASET_TYPE': dataset.DATASET_TYPE,
						'DATASRC_ID': dataset.DATASRC_ID,
						'DATASRC_TYPE': dataset.DATASRC_TYPE,
						'mapid': dataset.mapid,
						'SQL_QUERY': dataset.DATASET_QUERY,
						'SelArea': dataset.SEL_CLAUSE,
						'CondArea': dataset.WHERE_CLAUSE,
						'ORDER_ELEMENT': dataset.ORDER_CLAUSE,
						"JOIN_TYPE" : typeof dataset.JOIN_TYPE === "undefined" ? 'N':dataset.JOIN_TYPE,
						'ParamArea': { PARAM: self.dsUtility.getParamByMapId(dataset.mapid) },
						'RelArea': dataset.FROM_CLAUSE,
						//20210318 AJKIM 데이터 원본 기준 인메모리 추가 dogfoot
						'IN_MEMORY': dataset.IN_MEMORY? "true":"false",
						'EtcArea': {
							STRATIFIED: 'N',
							DISTINCT: 'N',
							SEL_COND: '',
							SEL_NUMERIC: 0,
							CHANGE_COND: dataset.CHANGE_COND||''
						},
						'SHEET_ID': dataset.SHEET_ID || ''
					};
					break;
				case 'DataSetSingleDs':
				case 'DataSetSingleDsView':
					/* DOGFOOT ktkang 기본데이터 집합 단일테이블 기능 구현  20201112 */
					var colElement;
					if(typeof dataset.DATASET_JSON == 'undefined') {
						colElement = dataset.COL_ELEMENT[0];
					} else {
						colElement = dataset.DATASET_JSON.DATA_SET.COL_ELEMENT
					}

					var EtcElement;
					if(typeof dataset.DATASET_JSON == 'undefined') {
						EtcElement = dataset.ETC_ELEMENT[0];
					} else {
						EtcElement = dataset.DATASET_JSON.DATA_SET.ETC_ELEMENT
					}

					if(colElement == undefined || colElement == ""){
						colElement = [];
					}else{
						if(Array.isArray(colElement.COLUMN)){
							colElement = colElement.COLUMN;
						}else{
							temp = [];
							temp.push(colElement.COLUMN);
							colElement = temp;
						}
					}

					for(var colidx=0;colidx<colElement.length;colidx++){
						if(typeof dataset.DATASET_JSON == 'undefined') {
							colElement[colidx].TBL_NM = dataset.TBL_ELEMENT[0];
						} else {
							colElement[colidx].TBL_NM = dataset.DATASET_JSON.DATA_SET.TBL_ELEMENT;
						}

					}

					datasetXml[dataset.mapid] = {
						'DATASET_NM': dataset.DATASET_NM,
						'DATASET_TYPE': dataset.DATASET_TYPE,
						'DATASRC_ID': dataset.DATASRC_ID,
						'DATASRC_TYPE': dataset.DATASRC_TYPE,
						'mapid': dataset.mapid,
						'SQL_QUERY': dataset.DATASET_QUERY,
						'SelArea': colElement,
						'EtcArea': EtcElement,
						'SHEET_ID': dataset.SHEET_ID || ''
					};
					break;
				case 'DataSetDs':
				default:
					datasetXml[dataset.mapid] = {
						'DATASET_NM': dataset.DATASET_NM,
						'DATASET_TYPE': dataset.DATASET_TYPE,
						'DATASRC_ID': dataset.DATASRC_ID,
						'DATASRC_TYPE' : dataset.DATASRC_TYPE,
						'mapid' : dataset.mapid,
						'SQL_QUERY' : dataset.DATASET_QUERY,
						'SHEET_ID': dataset.SHEET_ID || '',
						'PARAM_ELEMENT': self.dsUtility.getParamByMapId(dataset.mapid),
					};
			}
		});
		if(_cnt==0) {
			//주제영역일때
			var dataSourceIndex = 1;
			_.each(gDashboard.dataSourceManager.datasetInformation,function(_e){
				var paramelements = [];
				if(_e.param_element == undefined){
					paramelements = [];
				}else{
					$.each(_e.param_element,function(_i,_paramElements){
						$.each(_paramElements,function(_paramKey,_paramVal){
							paramelements.push(_paramKey);
						})
					})
				}
				/* DOGFOOT hsshim 200107
				 * 스프레드 시트 이름 저장 안되는 오류 수정
				 */
				var obj = {
					'DATASET_NM':_e.DATASET_NM+"",
					'DATASET_TYPE':_e.DATASET_TYPE+"",
					'DATASRC_ID':_e.DATASRC_ID,
					'DATASRC_TYPE' : _e.DATASRC_TYPE+"",
					'mapid' : _e.mapid,
					'SQL_QUERY' : _e.SQL_QUERY,
					'SHEET_ID': _e.SHEET_ID || "",
					'PARAM_ELEMENT': paramelements
				}
				/* DOGFOOT hsshim 200107 끝 */
				datasetXml["dataSource"+(dataSourceIndex+'')] = obj;
				dataSourceIndex++;
			});
		}
	}
	/* DOGFOOT ktkang 보고서 형상관리 기능 구현  20200903 */
	this.reportHistory = function(){
		var html = "<div class=\"modal-body\" style='height:93%'>\r\n" +
		"                        <div class=\"row\" style='height:100%'>\r\n" +
		"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" +
		"                                <div class=\"modal-article\" style=\"margin-top: 5px;height:100%;\">\r\n" +
		"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
		"                                   	<span>보고서 형상관리</span>\r\n" +
		"                                   </div>\r\n" +
		"								 <div id=\"reportHis\" style=\"height:100%;\"></div>\r\n" +
		"                                </div>\r\n" +
		"                            </div>\r\n" +
		"                        </div>\r\n" + // row 끝
		"                    </div>\r\n" + // modal-body 끝
		"					 <div id='save_box' style='text-align: center;'/>"+
		"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
		"                        <div class=\"row center\">\r\n" +
		"                            <a id=\"ok_his_button\" class=\"btn positive ok-hide\">확인</a>\r\n" +
		"                            <a id=\"cancel_his_button\" class=\"btn neutral ok-hide\">취소</a>\r\n" +
		"                        </div>\r\n" +
		"                    </div>\r\n" +
		"                </div>";

		if($('#hisViewPopup').length == 0){
			$('body').append("<div id='hisViewPopup'></div>");
		}

		$('#hisViewPopup').dxPopup({
			title:'보고서 형상관리',
			width:'600px',
			height:'800px',
			visible:true,
			closeOnOutsideClick: false,
			showCloseButton: false,
			contentTemplate: function() {
				return html;
			},
			onShown:function(){
				var reportSeq;
				if(!gDashboard.isNewReport) {
					$.ajax({
						method : 'POST',
						url: WISE.Constants.context + '/report/getReportHisList.do',
						dataType: "json",
						data:{
							'reportId' : WISE.Constants.pid
						},
						async:false,
						success: function(result) {
							$("#reportHis").dxDataGrid({
								/*dogfoot 보고서 형상관리 그리드 사이즈 조절 shlim 20201130*/
								height: 620,
								columns: [
									{
										caption: '순서',
										dataField: 'REPORT_SEQ',
										width: '25%'
									},
									{
										caption: '수정일자',
										dataField: 'MOD_DT',
										width: '75%'
									}
								],
								dataSource: result.reportHisLists,
								selection: {
			            			mode: "single"
			            		},
								onSelectionChanged: function(e) {
									reportSeq = e.selectedRowsData[0].REPORT_SEQ;
								}
							});
						}
					});
				}

				$('#ok_his_button').dxButton({
					text:'열기',
					onClick:function(){
						$('#reportId').val(gDashboard.structure.ReportMasterInfo.id);
						$('#reportSeq').val(reportSeq);
						$('#reportType').val(gDashboard.reportType);

						$('#reportHisForm').submit();

						$('#hisViewPopup').dxPopup('instance').hide();
						$('#hisViewPopup').remove();
					}
				});
				$('#cancel_his_button').dxButton({
					text: '취소',
					onClick: function() {
						$('#hisViewPopup').dxPopup('instance').hide();
						$('#hisViewPopup').remove();
					}
				});

			}
		});
	};

	this.restoreReport = function(restoreReportAs){
		if(!restoreReportAs) {
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/report/restoreReport.do',
				dataType: "json",
				data:{
					'reportId' : WISE.Constants.pid,
					'reportSeq' : userJsonObject.userReportSeq
				},
				async:false,
				success: function(result) {
					if(result.status == '200') {
						WISE.alert("성공 했습니다.", "success");
					} else if(result.status == '500') {
						WISE.alert("실패 했습니다.", "error");
					}
				}
			});
		} else {
			var html = "<div class=\"modal-body\" style='height:93%'>\r\n" +
			"                        <div class=\"row\" style='height:100%'>\r\n" +
			"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" +
			"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
			"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
			"                                   	<span>보고서 명</span>\r\n" +
			"                                   </div>\r\n" +
			"									<div style='text-align: right;'>\r\n"+
			"										<div id=\"report_title\"></div>\r\n" +
			"									</div>\r\n"+
			"                                </div>\r\n" +
			"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
			"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
			"                                   	<span>보고서 부제목</span>\r\n" +
			"                                   </div>\r\n" +
			"								 <div id=\"report_subtitle\"></div>\r\n" +
			"                                </div>\r\n" +
			"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
			"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
			"                                   	<span>폴더 구분 및 저장 폴더</span>\r\n" +
			"                                   </div>\r\n" +
			"								 <div id=\"report_folder_type\"></div>\r\n" +
			"								 <div style='text-align: right;'>"+
			"								 	<div id=\"report_target_folder\" style='float:left'></div>\r\n" +
			"								 	<div id=\"findFolder\"></div>\r\n" +
			"								 </div>"+
			"                                </div>\r\n" +
			"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
			"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
			"                                   	<span>표시순서</span>\r\n" +
			"                                   </div>\r\n" +
			"								 <div id=\"report_show_order\"></div>\r\n" +
			"                                </div>\r\n" +
			"                                <div class=\"modal-article\" style=\"margin-top:5px;\">\r\n" +
			"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
			"                                   	<span>주석</span>\r\n" +
			"                                   </div>\r\n" +
			"								 <div id=\"report_annotiation\"></div>\r\n" +
			"                                </div>\r\n" +
			"                                <div class=\"modal-article\" style=\"margin-top: 5px;height:20%;\">\r\n" +
			"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" +
			"                                   	<span>설명</span>\r\n" +
			"                                   </div>\r\n" +
			"								 <div id=\"report_description\" style=\"height:70%;\"></div>\r\n" +
			"                                </div>\r\n" +
			"                            </div>\r\n" +
			"                        </div>\r\n" + // row 끝
			"                    </div>\r\n" + // modal-body 끝
			"					 <div id='save_box' style='text-align: center;'/>"+
			"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
			"                        <div class=\"row center\">\r\n" +
			"                            <a id=\"restore_ok\" class=\"btn positive ok-hide\">복원</a>\r\n" +
			"                            <a id=\"restore_cancel\" class=\"btn neutral close\">취소</a>\r\n" +
			"                        </div>\r\n" +
			"                    </div>\r\n" +
			"                </div>";

			if($('#restorePopup').length == 0){
				$('body').append("<div id='restorePopup'></div>");
			}
			if(gDashboard.fieldManager && gDashboard.fieldManager.isChange == true){
				WISE.alert('데이터 항목 변경사항이 조회 되지 않았습니다. 조회 후 저장하여 주시기 바랍니다.');
				return;
			}
			if(reportType != 'Spread') {
				if(gDashboard.itemGenerateManager.dxItemBasten == 0 ){
					WISE.alert('빈 보고서는 생성하실 수 없습니다.','error');
					return false;
				}
				var exit = true;
				$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_e){
					if(_e.meta == undefined && exit == true){
						if(_e.type == 'TEXTBOX')
							return true;
						WISE.alert("보고서 데이터가 조회되지 않습니다.");
						exit = false;
						return false;
					}else if(exit ==false){
						return false;
					}
				})
				if(exit == false){
					return false;
				}
			}
			$('#savePopup').dxPopup({
				title:'보고서 복원',
				width:'600px',
				height:'750px',
				visible:true,
				closeOnOutsideClick: false,
				showCloseButton: false,
				contentTemplate: function() {
					return html;
				},
				onContentReady:function(){
					var folderSelect = [
						{
							text:"공용폴더",
							value:"PUBLIC"
						},
						{
							text:"개인폴더",
							value:"MY"
						}
						];

					$('#report_title').dxTextBox({
						value: $('.report-tab ul').find('li').find('em').text(),
					});
					$('#report_subtitle').dxTextBox({
						value:self.reportInfo.ReportMasterInfo.report_sub_title
					});

					var folder_type;
					if(self.reportInfo.ReportMasterInfo.fld_type != ""){
						if(self.reportInfo.ReportMasterInfo.fld_type == folderSelect[0].value){
							folder_type = folderSelect[0];
						}
						else{
							folder_type = folderSelect[1];
						}
					}else{
						folder_type = folderSelect[0];
					}
					$('#report_folder_type').dxRadioGroup({
						dataSource:folderSelect,
						layout: "horizontal",
						value:folder_type
					});

					$('#report_target_folder').dxTextBox({
						readOnly:true,
						'value': self.reportInfo.ReportMasterInfo.fld_nm,
						'text': self.reportInfo.ReportMasterInfo.fld_nm,
						'fld_id': self.reportInfo.ReportMasterInfo.fld_id,
						'width':'91%'
					});
					$('#findFolder').dxButton({
						icon:'search',
						onClick:function(){
							$('#save_box').append("<div id='selectFolder'></div>");
							if(typeof  $('#report_folder_type').dxRadioGroup('instance').option('value').value == 'undefined'){
								return;
							}
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
							"                            <a id=\"folder_ok\" class=\"btn positive ok-hide\">확인</a>\r\n" +
							"                            <a id=\"folder_cancel\" class=\"btn neutral close\">취소</a>\r\n" +
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
									var fld_type = $('#report_folder_type').dxRadioGroup('instance').option('value');
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
//										async:false,
										success: function(result) {
											var datasource = result.data;
											var selectFLDNm = self.reportInfo.ReportMasterInfo.fld_nm;
											var selectFLDId = self.reportInfo.ReportMasterInfo.fld_id;
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
	        									noDataText:"조회된 폴더가 없습니다.",
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
														$('#report_target_folder').dxTextBox('instance').option('value',selectFLDNm);
														$('#report_target_folder').dxTextBox('instance').option('fld_id',selectFLDId);
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
					$('#report_show_order').dxNumberBox({
						value: Number(self.reportInfo.ReportMasterInfo.ordinal),
						//2020.02.05 mksong , 제거 dogfoot
						width:"20%"
					});
					$('#report_annotiation').dxTextBox({
						value: self.reportInfo.ReportMasterInfo.tag
					});
					$('#report_description').dxTextArea({
						value: self.reportInfo.ReportMasterInfo.description
					});

					$('#restore_ok').dxButton({
						type:'success',
						text:'복원',
						onClick:function(){
							/* DOGFOOT ktkang 보고서 형상관리 오류 수정  20201126 */
							var param = {
									'report_id': restoreReportAs == "true" ? WISE.Constants.pid+"" : "",
									'report_nm': $('#report_title').dxTextBox('instance').option('value'),
									'report_sub_title': typeof $('#report_subtitle').dxTextBox('instance').option('value') != 'undefined' ? $('#report_subtitle').dxTextBox('instance').option('value') : '',
									'fld_id' : $('#report_target_folder').dxTextBox('instance').option('fld_id'),
									'fld_type': $('#report_folder_type').dxRadioGroup('instance').option('value').value,
									'report_ordinal':$('#report_show_order').dxNumberBox('instance').option('value')+'',
									'report_type': gDashboard.reportType,
									'report_tag': '',
									'report_desc' : typeof $('#report_description').dxTextArea('instance').option('value') != 'undefined' ? $('#report_description').dxTextArea('instance').option('value') : '',
									'user_id' : userJsonObject.userId+"",
									'linkReport' : gDashboard.structure.linkReport,
									'subLinkReport' : gDashboard.structure.subLinkReport,
									'reportSeq' : userJsonObject.userReportSeq,
									'old_report_id': WISE.Constants.pid
							};

							var jsonParam = {};
							jsonParam['JSON_REPORT'] = JSON.stringify(param);

							$.ajax({
								method : 'POST',
								url: WISE.Constants.context + '/report/restoreReportAs.do',
								dataType: "json",
								data: jsonParam,
								/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//								async:false,
								success: function(result) {
									if(result.status == '200') {
										WISE.alert("성공 했습니다.", "success");
									} else if(result.status == '500') {
										WISE.alert("실패 했습니다.", "error");
									}


									$('#savePopup').dxPopup('instance').hide();
									$('#savePopup').remove();
								},
				      			error : function(request, status, error) {
				      				WISE.alert("code: "+request.status+"\n"+"message: "+request.responseText+"\n"+"error: "+error);
				      				gProgressbar.hide();
				      			}
							});
						}
					});

					$('#restore_cancel').dxButton({
						type:'danger',
						text:'취소',
						onClick:function(){
							$('#savePopup').dxPopup('instance').hide();
							$('#savePopup').remove();
						}
					});
				}
			});
		}
	};
}