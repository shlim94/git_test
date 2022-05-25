var generalConfigManager = (function() {
	/* Variables */
	var loginImage;
	var logo;
	/**
	 * Initialize functions for general config page.
	 * @param {Object} config Config master info.
	 */
	function initConfigLayout(config) {
		// 일반 설정
		$('#licenseKey').val(config['LICENSES_KEY']);
		$('#spreadJsLicenseKey').val(config['SPREAD_JS_LICENSE']);
		/* DOGFOOT syjin kakao api key 추가 설정 20020819*/
		$("#kakaoApiKey").val(config['KAKAO_MAP_API_KEY']);
		/* DOGFOOT syjin 한국소방 안쓰는 기능 안보이도록 수정 20210901 */
		if(userJsonObject.siteNm == 'KFI'){
			$('#spreadLicenseKeyTr').css('display', 'none');
			$('#kakaoApiKeyTr').css('display', 'none');
		}
		// 20210409 AJKIM 타이틀 특수문자 처리 dogfoot
		var title = config['MAIN_TITLE'];
		title = title.replace(/&lt;/g,"<");
		title = title.replace(/&gt;/g,">");
		title = title.replace(/&quot;/g,"\"");
		title = title.replace(/&#39;/g,"'");
		title = title.replace(/&amp;/g,"&");
		$('#solutionTitle').val(title);
		$('#defaultUrl').val(config['WEB_URL']);
		loginImage = config['LOGIN_IMAGE'];
		logo = config['LOGO'];
		self.layoutConfCheck = false;
		var fontJson = config['FONT_CONFIG'];
		/* DOGFOOT syjin 보고서 레이아웃 설정  20200814 */
		
								
		if(fontJson != undefined){
			$('#fontFamily').val(fontJson.FONT_FAMILY);
			$('#fontSize').val(fontJson.FONT_SIZE);
			$('#FONT_COVERAGE-Menu').prop("checked", fontJson.FONT_COVERAGE.Menu);
			$('#FONT_COVERAGE-Item').prop("checked", fontJson.FONT_COVERAGE.Item);
		}else{
			$('#fontFamily').val('Basic');
			$('#fontSize').val(0);
			$('#FONT_COVERAGE-Menu').prop("checked", false);
			$('#FONT_COVERAGE-Item').prop("checked", false);
		}
		/* DOGFOOT syjin 보고서 레이아웃 설정  20200814 */
	
		
		
		$("#report-layout-btn").dxButton({			
			"text" : "설정하기",
			"onClick" : function(){
				gDashboard.reportLayoutManager.reportSetting('configset');
			}			
		})
			
		 //고급 설정
		$('#searchLimitTime').val(config['SEARCH_LIMIT_TIME']);
		$('#searchLimitRow').val(config['SEARCH_LIMIT_SIZE']);
		/* DOGFOOT ktkang 동시 작업 제한 기능 추가  20200922 */
		$('#limitWorks').val(config['LIMIT_WORKS']);
		$('#useTerm').val(config['USE_TERM']);
		$('#limitConnections').val(config['LIMIT_CONNECTIONS']);
		$('#pwChangePeriod').val(config['PW_CHANGE_PERIOD']);
		$('#loginLockCnt').val(config['LOGIN_LOCK_CNT']);	
		$('#reportLogCleanHour').val(config['REPORT_LOG_CLEAN_HOUR']);
		$('#excelDownloadServerCount').val(config['EXCEL_DOWNLOAD_SERVER_COUNT']);
		/* DOGFOOT ktkang 보고서 바로 조회 기능 옵션 추가  20201015 */
		$('#reportDirectView').prop('checked', config['REPORT_DIRECT_VIEW'] === 'Y');
		// 보고서 설정
		$('#mainLayout').val(config['DASHBOARD_LAYOUT']);
		$('#reportAuthDetail').val(config['AUTH_REPORT_DETAIL_YN']);
		if(config['DEFAULT_LAYOUT'] === 'C' || config['DEFAULT_LAYOUT'] === 'G' || config['DEFAULT_LAYOUT'] === 'CTGB')
			$('#adhocLayout').val(config['DEFAULT_LAYOUT']);
		else
			$('#adhocLayout').val('CTGB');
		$('#showNullValue').prop('checked', config['NULL_VALUE_YN'] === 'Y');
		/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
		$('#downloadFilter').prop('checked', config['DOWNLOAD_FILTER_YN'] === 'Y');
		/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
		$('#oldSchedule').prop('checked', config['OLD_SCHEDULE_YN'] === 'Y');
		$('#pivotAlignCenter').prop('checked', config['PIVOT_ALIGN_CENTER'] === 'Y');
		$('#pivotDrillUpDown').prop('checked', config['PIVOT_DRILL_UPDOWN'] === 'Y');
		$('#gridAutoAlign').prop('checked', config['GRID_AUTO_ALIGN'] === 'Y');
		/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
		$('#gridDataPaging').prop('checked', config['GRID_DATA_PAGING'] === 'Y');
		$('#nullValue').val(config['NULL_VALUE_STRING']);
		$('#defaultPalette').val(config['DASHBOARD_DEFAULT_PALETTE']);
		
		// 이미지 및 로고
		$('#loginImage').attr('src', WISE.Constants.context + '/resources/main/images/custom/' + loginImage);
		$('#logo').attr('src', WISE.Constants.context + '/resources/main/images/custom/' + logo);
		$('#uploadLoginImage').dxFileUploader({
			accept: 'image/*',
			multiple: false,
			selectButtonText: '파일 업로드',
			labelText: '드래그 위치',
			readyToUploadMessage: '',
			uploadedMessage: '',
			uploadFailedMessage: '업로드 실패 했습니다.',
			showFileList: false,
			uploadMethod: 'POST',
			uploadUrl: WISE.Constants.context + '/report/uploadLoginImage.do',
			onUploaded: function(e) {
				//20210409 AJKIM 로고 및 아이콘 업로드 엑스박스 오류 수정 dogfoot
				var value = e.component.option('value');
                if(value.length > 0){
                	var reader = new FileReader();
                	reader.onload = function(e){
                		$('#loginImage').attr('src', e.target.result);
                	}
                	reader.readAsDataURL(value[0]);  
                }
				loginImage = e.request.responseText;
				e.component.reset();
//				loginImage = e.request.responseText;
//				$('#loginImage').attr('src', WISE.Constants.context + '/resources/main/images/custom/' + loginImage);
//				e.component.reset();
			},
		});
		$('#uploadLogo').dxFileUploader({
			accept: 'image/*',
			multiple: false,
			selectButtonText: '파일 업로드',
			labelText: '드래그 위치',
			readyToUploadMessage: '',
			uploadedMessage: '',
			uploadFailedMessage: '업로드 실패 했습니다.',
			showFileList: false,
			uploadMethod: 'POST',
			uploadUrl: WISE.Constants.context + '/report/uploadLogo.do',
			onUploaded: function(e) {
				//20210409 AJKIM 로고 및 아이콘 업로드 엑스박스 오류 수정 dogfoot
				var value = e.component.option('value');
                if(value.length > 0){
                	var reader = new FileReader();
                	reader.onload = function(e){
                		$('#logo').attr('src', e.target.result);
                	}
                	reader.readAsDataURL(value[0]);  
                }
				e.component.reset();
				logo = e.request.responseText;
//				$('#logo').attr('src', WISE.Constants.context + '/resources/main/images/custom/' + logo);
//				e.component.reset();
			}
		});
		$('#resetLoginImage').dxButton({
			text: '기본 사진으로 변경',
			onClick: function() {
				loginImage = "login_visual.png";
				$('#loginImage').attr('src', WISE.Constants.context + '/resources/main/images/custom/' + loginImage);
			}
		});
		$('#resetLogo').dxButton({
			text: '기본 사진으로 변경',
			onClick: function() {
				logo = "logo.png";
				$('#logo').attr('src', WISE.Constants.context + '/resources/main/images/custom/' + logo);
			}
		});
		
		//메뉴설정
		var menuJson = config['MENU_CONFIG'];
		if(menuJson!=undefined) {
			var menu = menuJson.Menu;
			$('#PROG_MENU_TYPE-AdHocVisible').prop("checked", menu.PROG_MENU_TYPE.AdHoc.visible);
			$('#PROG_MENU_TYPE-AdHocPopup').prop("checked", menu.PROG_MENU_TYPE.AdHoc.popup);
			$('#PROG_MENU_TYPE-DashAnyVisible').prop("checked", menu.PROG_MENU_TYPE.DashAny.visible);
			$('#PROG_MENU_TYPE-DashAnyPopup').prop("checked", menu.PROG_MENU_TYPE.DashAny.popup);
			$('#PROG_MENU_TYPE-ExcelVisible').prop("checked", menu.PROG_MENU_TYPE.Excel.visible);
			$('#PROG_MENU_TYPE-ExcelPopup').prop("checked", menu.PROG_MENU_TYPE.Excel.popup);
			/* DOGFOOT syjin 한국소방 안쓰는 기능 안보이도록 수정 20210901 */
			if(userJsonObject.siteNm == 'KFI'){
				$('#PROG_MENU_TYPE-ExcelVisibleLabel').css('display', 'none');
				$('#PROG_MENU_TYPE-ExcelVisible').css('display', 'none');
				
				$('#PROG_MENU_TYPE-ExcelPopupLabel').css('display', 'none');
				$('#PROG_MENU_TYPE-ExcelPopup').css('display', 'none');
			}
			/* DOGFOOT yhkim 통계분석 추가 20201125 */
			if(typeof menu.PROG_MENU_TYPE.Analysis !== 'undefined'){
				$('#PROG_MENU_TYPE-AnalysisVisible').prop("checked", menu.PROG_MENU_TYPE.Analysis.visible);
				$('#PROG_MENU_TYPE-AnalysisPopup').prop("checked", menu.PROG_MENU_TYPE.Analysis.popup);
				/* DOGFOOT syjin 한국소방 안쓰는 기능 안보이도록 수정 20210901 */
				if(userJsonObject.siteNm == 'KFI'){
					$('#PROG_MENU_TYPE-AnalysisVisibleLabel').css('display', 'none');
					$('#PROG_MENU_TYPE-AnalysisVisible').css('display', 'none');
					
					$('#PROG_MENU_TYPE-AnalysisPopupLabel').css('display', 'none');
					$('#PROG_MENU_TYPE-AnalysisPopup').css('display', 'none');
				}
			}
			/* DOGFOOT ajkim 데이터 집합 뷰어 추가 20210202 */
			if(typeof menu.PROG_MENU_TYPE.DSViewer !== 'undefined'){
				$('#PROG_MENU_TYPE-DSViewerVisible').prop("checked", menu.PROG_MENU_TYPE.DSViewer.visible);
				$('#PROG_MENU_TYPE-DSViewerPopup').prop("checked", menu.PROG_MENU_TYPE.DSViewer.popup);
				/* DOGFOOT syjin 한국소방 안쓰는 기능 안보이도록 수정 20210901 */
				if(userJsonObject.siteNm == 'KFI'){
					$('#PROG_MENU_TYPE-DSViewerVisibleLabel').css('display', 'none');
					$('#PROG_MENU_TYPE-DSViewerVisible').css('display', 'none');
					
					$('#PROG_MENU_TYPE-DSViewerPopupLabel').css('display', 'none');
					$('#PROG_MENU_TYPE-DSViewerPopup').css('display', 'none');
				}
			}
			$('#PROG_MENU_TYPE-DataSetVisible').prop("checked", menu.PROG_MENU_TYPE.DataSet.visible);
			$('#PROG_MENU_TYPE-DataSetPopup').prop("checked", menu.PROG_MENU_TYPE.DataSet.popup);
			$('#PROG_MENU_TYPE-ConfigVisible').prop("checked", menu.PROG_MENU_TYPE.Config.visible);
			$('#PROG_MENU_TYPE-ConfigPopup').prop("checked", menu.PROG_MENU_TYPE.Config.popup);	
			
			$('#TOP_MENU_TYPE-SchedulerVisible').prop("checked", menu.TOP_MENU_TYPE.Scheduler.visible);
			$('#TOP_MENU_TYPE-ContainerVisible').prop("checked", menu.TOP_MENU_TYPE.Container.visible);
			$('#TOP_MENU_TYPE-InsertAdHocVisible').prop("checked", menu.TOP_MENU_TYPE.InsertAdHoc.visible);
			/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
			$('#TOP_MENU_TYPE-QueryViewVisible').prop("checked", menu.TOP_MENU_TYPE.QueryView.visible);
			/* DOGFOOT ktkang MEIS 뷰어에서 홈버튼 구현  20200818 */
			$('#TOP_MENU_TYPE-ViewerHomeVisible').prop("checked", menu.TOP_MENU_TYPE.ViewerHome.visible);
			
			$('#DATASET_MENU_TYPE-CUBE').prop("checked", menu.DATASET_MENU_TYPE.CUBE);
			$('#DATASET_MENU_TYPE-DataSetCube').prop("checked", menu.DATASET_MENU_TYPE.DataSetCube);
			$('#DATASET_MENU_TYPE-DataSetDs').prop("checked", menu.DATASET_MENU_TYPE.DataSetDs);
			/* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
			$('#DATASET_MENU_TYPE-DataSetDsJoin').prop("checked", menu.DATASET_MENU_TYPE.DataSetDsJoin);
			$('#DATASET_MENU_TYPE-DataSetSQL').prop("checked", menu.DATASET_MENU_TYPE.DataSetSQL);
			$('#DATASET_MENU_TYPE-DataSetSingleDs').prop("checked", menu.DATASET_MENU_TYPE.DataSetSingleDs);
			$('#DATASET_MENU_TYPE-DataSetUser').prop("checked", menu.DATASET_MENU_TYPE.DataSetUser);
			$('#DATASET_MENU_TYPE-DataSetLoad').prop("checked", menu.DATASET_MENU_TYPE.DataSetLoad);
			
			$('#SPREAD_MENU_TYPE-Print').prop("checked", menu.SPREAD_MENU_TYPE.Print);
			$('#GROUP_FOLDER_YN').prop("checked", menu.GROUP_FOLDER_YN);
			$("input:radio[name='bind_type']:radio[value="+ menu.SPREAD_MENU_TYPE.BindType+"]").prop('checked', true); 
	
			$('#DOWNLOAD_MENU_TYPE-OfficeVisible').prop("checked", menu.DOWNLOAD_MENU_TYPE.Office.visible);
			$('#DOWNLOAD_MENU_TYPE-OfficeXlsx').prop("checked", menu.DOWNLOAD_MENU_TYPE.Office.xlsx);
			$('#DOWNLOAD_MENU_TYPE-OfficeXls').prop("checked", menu.DOWNLOAD_MENU_TYPE.Office.xls);
			$('#DOWNLOAD_MENU_TYPE-OfficeDoc').prop("checked", menu.DOWNLOAD_MENU_TYPE.Office.doc);
			$('#DOWNLOAD_MENU_TYPE-OfficePpt').prop("checked", menu.DOWNLOAD_MENU_TYPE.Office.ppt);
	
			$('#DOWNLOAD_MENU_TYPE-HancomVisible').prop("checked", menu.DOWNLOAD_MENU_TYPE.Hancom.visible);
			$('#DOWNLOAD_MENU_TYPE-HancomHwp').prop("checked", menu.DOWNLOAD_MENU_TYPE.Hancom.hwp);
			$('#DOWNLOAD_MENU_TYPE-HancomCell').prop("checked", menu.DOWNLOAD_MENU_TYPE.Hancom.cell);
			$('#DOWNLOAD_MENU_TYPE-HancomShow').prop("checked", menu.DOWNLOAD_MENU_TYPE.Hancom.show);
	
			$('#DOWNLOAD_MENU_TYPE-EtcVisible').prop("checked", menu.DOWNLOAD_MENU_TYPE.Etc.visible);
			$('#DOWNLOAD_MENU_TYPE-EtcImg').prop("checked", menu.DOWNLOAD_MENU_TYPE.Etc.img);
			$('#DOWNLOAD_MENU_TYPE-EtcHtml').prop("checked", menu.DOWNLOAD_MENU_TYPE.Etc.html);
			$('#DOWNLOAD_MENU_TYPE-EtcPdf').prop("checked", menu.DOWNLOAD_MENU_TYPE.Etc.pdf);
			
			/* DOGFOOT ajkim 다운로드 확장 추가 20210202 */
			if(typeof menu.ITEM_DOWNLOAD !== 'undefined'){
				$('#analR').prop("checked", menu.ITEM_DOWNLOAD.Expand);
			}
			
			if(typeof menu.DOWNLOAD_TYPE !== 'undefined'){
				$('#reportDownloadType').val(menu.DOWNLOAD_TYPE.DownLoadType);
			}
			
			if(typeof menu.GROUP_FOLDER !== 'undefined'){
				$('#GROUP_FOLDER_YN').prop("checked", menu.GROUP_FOLDER.GROUP_FOLDER_YN);
			}
			
			/* DOGFOOT syjin 통계 분석 설정 추가 수정 20210219 */
			if(menu.ANALISYS != undefined){
				if(typeof menu.ANALISYS.analUseType !== 'undefined'){
					if(parseInt(menu.ANALISYS.analUseType) == 0){
						$('#analR').prop("checked", true);
					}else{
						$('#analJava').prop("checked", true);	
					}
				}
			}else{
				$('#analR').prop("checked", true);
			}
			
			/* DOGFOOT syjin 한국소방 안쓰는 기능 안보이도록 수정 20210901 */
			if(userJsonObject.siteNm == 'KFI'){
				$('#analysisTitle').css('display', 'none');
				$('#statisticalAnalysis').css('display', 'none');
			}
			
			// 20210324 AJKIM 피벗 행열 별도 정렬 추가 dogfoot
			if(typeof menu.PIVOT_SORTING_OPTION !== 'undefined'){
				$('#pivotSortingOption').prop("checked", menu.PIVOT_SORTING_OPTION);
			}
			
			if(typeof menu.PIVOT_PAGING_OPTION !== 'undefined'){
				$('#pivotPagingOption').prop("checked", menu.PIVOT_PAGING_OPTION);
			}
			
			// 20210419 AJKIM 뷰어 대시보드 데이터 항목 추가 dogfoot
			if(typeof menu.DASH_DATA_FIELD !== 'undefined'){
				$('#dashDataField').prop("checked", menu.DASH_DATA_FIELD);
			}
			/*dogfoot shlim 뷰어 디자이너 바로가기 기능 구현 20210614*/
			if(typeof menu.VIEWER_DIRECT_DSIGNER !== 'undefined'){
				$('#directDesigner').prop("checked", menu.VIEWER_DIRECT_DSIGNER);
			}
			
			// 20210420 Jhseo 뷰어(URL, 연결보고서 포함) 다운로드 레이아웃 항목 추가
			if(typeof menu.DASHBOARD_DOWNLOAD_OPTION !== 'undefined'){
				$('#dashboardDownloadOption').prop("checked", menu.DASHBOARD_DOWNLOAD_OPTION);
			}else{
				$('#dashboardDownloadOption').prop("checked", true);
			}
			
			// 20210420 Jhseo 뷰어(URL, 연결보고서 포함) 데이터 항목 자동 노출 활성화 추가
			if(typeof menu.VIEWER_DATA_FIELD_OPTION !== 'undefined'){
				$('#viewerDataFieldOption').prop("checked", menu.VIEWER_DATA_FIELD_OPTION);
			}else{
				$('#viewerDataFieldOption').prop("checked", true);
			}
			
			// 20210324 AJKIM 인메모리 기능 옵션처리 dogfoot
			if(typeof menu.IN_MEMORY !== 'undefined'){
				$('#IN_MEMORY').prop("checked", menu.IN_MEMORY);
			}
			
			// 20211102 AJKIM 필드 제외 데이터 집합 수정 추가 dogfoot
			if(typeof menu.MODIFY_EXCEPT_FIELD !== 'undefined'){
				$('#MODIFY_EXCEPT_FIELD').prop("checked", menu.MODIFY_EXCEPT_FIELD);
			}
			
			
			if(typeof menu.USE_MENU_AUTH !== 'undefined'){
				$('#USE_MENU_AUTH').prop("checked", menu.USE_MENU_AUTH);
			}
			
			//20210723 AJKIM SQL 에러 로그 공개 추가 dogfoot
			if(typeof menu.SQL_ERROR_LOG !== 'undefined'){
				$('#SQLErrorLogVisible').prop("checked", menu.SQL_ERROR_LOG);
			}
			
			if(menu.WI_DEFAULT_PAGE){
				$('#defaultPage').val(menu.WI_DEFAULT_PAGE);
			}else{
				$('#defaultPage').val('DashAny');
			}
			
			// 2021-07-08 yyb 데이터집합 저장여부 체크 기능 옵션처리
			if(typeof menu.DSSAVE_CHECK !== 'undefined'){
				$('#dsSaveChk').prop('checked', menu.DSSAVE_CHECK);		// 데이터집합 저장여부 체크
			}
			
			// 쿼리 캐시기능 사용여부
			if(typeof menu.QRY_CASH_USE !== 'undefined'){
				$('#qryCashUse').prop('checked', menu.QRY_CASH_USE);
			}
			
			// 측정값 위치 옵션
			if(typeof menu.MEASURE_POSITION_BOTTOM !== 'undefined'){
				$('#measurePositionBottom').prop('checked', menu.MEASURE_POSITION_BOTTOM);
			}
			
			
		}
	}

	return {
		/**
		 * Main.
		 */
		initPreferences: function() {
			var config = {};
			$.ajax({
				url: WISE.Constants.context + '/report/getConfigMstr.do',
				async: false,
				beforeSend: function() {
					gProgressbar.show();
				},
				success: function(data) {
					config = JSON.parse(data).configJson;
				},
				complete: function() {
					gProgressbar.hide();
				}
			});
			
			initConfigLayout(config);
		},

		handleConfigRefresh: function() {
			generalConfigManager.initPreferences();
		},

		configSaveButtonEvent: function(event) {
			if (event.which == 13) {
				return false;
			}
			event.preventDefault();
			var menuConfig = {
				'Menu' : {
			        'PROG_MENU_TYPE' : {
			            'AdHoc' : {
			            	'visible':$('#PROG_MENU_TYPE-AdHocVisible').is(':checked'), 
			            	'popup':$('#PROG_MENU_TYPE-AdHocPopup').is(':checked')
			            },
			            'DashAny' : {
			            	'visible':$('#PROG_MENU_TYPE-DashAnyVisible').is(':checked'), 
			            	'popup':$('#PROG_MENU_TYPE-DashAnyPopup').is(':checked')
			            },
			            'Excel': {
			            	'visible':$('#PROG_MENU_TYPE-ExcelVisible').is(':checked'), 
			            	'popup':$('#PROG_MENU_TYPE-ExcelPopup').is(':checked')
			            },
			            /* DOGFOOT yhkim 통계분석 추가 20201125 */
			            'Analysis': {
			            	'visible':$('#PROG_MENU_TYPE-AnalysisVisible').is(':checked'), 
			            	'popup':$('#PROG_MENU_TYPE-AnalysisPopup').is(':checked')
			            },
			            /* DOGFOOT ajkim 데이터 집합 뷰어 추가 20210202 */
			            'DSViewer': {
			            	'visible':$('#PROG_MENU_TYPE-DSViewerVisible').is(':checked'), 
			            	'popup':$('#PROG_MENU_TYPE-DSViewerPopup').is(':checked')
			            },
			            'DataSet': {
			            	'visible':$('#PROG_MENU_TYPE-DataSetVisible').is(':checked'), 
			            	'popup':$('#PROG_MENU_TYPE-DataSetPopup').is(':checked')
			            },
			            'Config':{
			            	'visible':$('#PROG_MENU_TYPE-ConfigVisible').is(':checked'), 
			            	'popup':$('#PROG_MENU_TYPE-ConfigPopup').is(':checked')
			            }
			        },
			        'TOP_MENU_TYPE' : {
			            'Scheduler' : {
			            	'visible':$('#TOP_MENU_TYPE-SchedulerVisible').is(':checked')
			            },
			            'Container' : {
			            	'visible':$('#TOP_MENU_TYPE-ContainerVisible').is(':checked')			            
            			},
            			'InsertAdHoc' : {
			            	'visible':$('#TOP_MENU_TYPE-InsertAdHocVisible').is(':checked')			            
            			},
            			/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
            			'QueryView' : {
			            	'visible':$('#TOP_MENU_TYPE-QueryViewVisible').is(':checked')			            
            			},
            			/* DOGFOOT ktkang MEIS 뷰어에서 홈버튼 구현  20200818 */
            			'ViewerHome' : {
			            	'visible':$('#TOP_MENU_TYPE-ViewerHomeVisible').is(':checked')			            
            			}
			        },
			        'DATASET_MENU_TYPE' : {
			            'CUBE' : $('#DATASET_MENU_TYPE-CUBE').is(':checked'),
			            'DataSetCube' : $('#DATASET_MENU_TYPE-DataSetCube').is(':checked'),
			            'DataSetDs' : $('#DATASET_MENU_TYPE-DataSetDs').is(':checked'), 
			            /* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
			            'DataSetDsJoin' : $('#DATASET_MENU_TYPE-DataSetDsJoin').is(':checked'),
			            'DataSetSQL' : $('#DATASET_MENU_TYPE-DataSetSQL').is(':checked'),
			            'DataSetSingleDs' : $('#DATASET_MENU_TYPE-DataSetSingleDs').is(':checked'),
			            'DataSetUser' : $('#DATASET_MENU_TYPE-DataSetUser').is(':checked'),
			            'DataSetLoad' : $('#DATASET_MENU_TYPE-DataSetLoad').is(':checked')
			        },
			        'SPREAD_MENU_TYPE' : {
			            'Print' : $('#SPREAD_MENU_TYPE-Print').is(':checked'),
			            'BindType' : $('input[name="bind_type"]:checked').val()
			        },
			        'DOWNLOAD_MENU_TYPE' : {
			            'Office' : { 
			            	'visible' : $('#DOWNLOAD_MENU_TYPE-OfficeVisible').is(':checked'), 
			            	'xlsx': $('#DOWNLOAD_MENU_TYPE-OfficeXlsx').is(':checked'), 
			            	'xls': $('#DOWNLOAD_MENU_TYPE-OfficeXls').is(':checked'), 
			            	'doc': $('#DOWNLOAD_MENU_TYPE-OfficeDoc').is(':checked'), 
			            	'ppt': $('#DOWNLOAD_MENU_TYPE-OfficePpt').is(':checked')
			            },
			            'Hancom' : { 
			            	'visible' : $('#DOWNLOAD_MENU_TYPE-HancomVisible').is(':checked'), 
			            	'hwp': $('#DOWNLOAD_MENU_TYPE-HancomHwp').is(':checked'), 
			            	'cell': $('#DOWNLOAD_MENU_TYPE-HancomCell').is(':checked'), 
			            	'show': $('#DOWNLOAD_MENU_TYPE-HancomShow').is(':checked')
			            },
			            'Etc' : { 
			            	'visible' : $('#DOWNLOAD_MENU_TYPE-EtcVisible').is(':checked'), 
			            	'img': $('#DOWNLOAD_MENU_TYPE-EtcImg').is(':checked'), 
			            	'html': $('#DOWNLOAD_MENU_TYPE-EtcHtml').is(':checked'), 
			            	'pdf': $('#DOWNLOAD_MENU_TYPE-EtcPdf').is(':checked')
			            }
		            },
		            'ITEM_DOWNLOAD' : {
		            	'Expand' : $('#ITEM_DOWNLOAD-Expand').is(':checked'),
		            	'DownLoadType' : $('#reportDownloadType').val()
		            },
		            'DOWNLOAD_TYPE' : {
		            	'DownLoadType' : $('#reportDownloadType').val()
		            },
		            /* DOGFOOT syjin JAVA R 분기처리 방식 설정 추가 20210218 */
		            'ANALISYS' : {
		            	"analUseType" : $('input[name="anal"]:checked').val() 
		            },
		            'GROUP_FOLDER':{
		            	"GROUP_FOLDER_YN" : $('#GROUP_FOLDER_YN').is(':checked') 
		            },
		            'PIVOT_SORTING_OPTION': $('#pivotSortingOption').prop('checked'),
		            'PIVOT_PAGING_OPTION': $('#pivotPagingOption').prop('checked'),
		            'IN_MEMORY' : $('#IN_MEMORY').prop('checked'),
		            // 20211102 AJKIM 필드 제외 데이터 집합 수정 추가 dogfoot
		            'MODIFY_EXCEPT_FIELD' : $('#MODIFY_EXCEPT_FIELD').prop('checked'),
		            // 20210721 AJKIM 메뉴 권한 적용 여부 추가 dogfoot
		            'USE_MENU_AUTH' : $('#USE_MENU_AUTH').prop('checked'),
		            //20210723 AJKIM SQL 에러 로그 공개 추가 dogfoot
		            'SQL_ERROR_LOG' : $("#SQLErrorLogVisible").prop('checked'),
		            // 20210419 AJKIM 뷰어 대시보드 데이터 항목 추가 dogfoot
		            'DASH_DATA_FIELD' : $('#dashDataField').prop('checked'),

					// 20210420 Jhseo 뷰어(URL, 연결보고서) 다운로드 레이아웃 항목 추가
		            'DASHBOARD_DOWNLOAD_OPTION' : $('#dashboardDownloadOption').prop('checked'),

					// 20210428 Jhseo 뷰어(URL, 연결보고서) 데이터 항목 자동 노출 활성화 추가
		            'VIEWER_DATA_FIELD_OPTION' : $('#viewerDataFieldOption').prop('checked'),
		            
		            /*dogfoot 로그인 초기값 설정 shlim 20210531*/
					'WI_DEFAULT_PAGE': $('#defaultPage').val(),
					/*dogfoot shlim 뷰어 디자이너 바로가기 기능 구현 20210614*/
					'VIEWER_DIRECT_DSIGNER' : $('#directDesigner').is(':checked'),
					
					// 2021-07-08 yyb 데이터집합을 저장했는지 체크 여부 추가
					'DSSAVE_CHECK': $('#dsSaveChk').prop('checked'),
					
					// 쿼리 캐시기능 사용
					'QRY_CASH_USE': $('#qryCashUse').prop('checked'),
					'MEASURE_POSITION_BOTTOM': $('#measurePositionBottom').prop('checked')
			    }
			};
			
			var fontConfig = {
				'FONT_FAMILY': $('#fontFamily').val(),
				'FONT_SIZE': $('#fontSize').val() === ''? 0 : $('#fontSize').val(),
				'FONT_COVERAGE': {
					'Menu': $('#FONT_COVERAGE-Menu').prop('checked'),
					'Item': $('#FONT_COVERAGE-Item').prop('checked')
				}
			}
			
			if(gDashboard.reportLayoutManager.layoutConfCheck){
				var layoutConfig = gDashboard.layoutConfig;
			}else{
				var layoutConfig = userJsonObject.layoutConfig
			}
			
			var param = {
					// 일반 설정
					'LICENSES_KEY': $('#licenseKey').val(),
					'MAIN_TITLE': $('#solutionTitle').val(),
					'WEB_URL': $('#defaultUrl').val(),
					'LOGIN_IMAGE': loginImage,
					'LOGO': logo,
					// 고급 설정
					'SEARCH_LIMIT_TIME': $('#searchLimitTime').val(),
					'SEARCH_LIMIT_SIZE': $('#searchLimitRow').val(),
					'LIMIT_WORKS': $('#limitWorks').val(),
					'USE_TERM': $('#useTerm').val(),
					'LIMIT_CONNECTIONS': $('#limitConnections').val(),
					'PW_CHANGE_PERIOD': $('#pwChangePeriod').val(),
					'LOGIN_LOCK_CNT': $('#loginLockCnt').val(),
					'REPORT_LOG_CLEAN_HOUR': $('#reportLogCleanHour').val(),
					'EXCEL_DOWNLOAD_SERVER_COUNT': $('#excelDownloadServerCount').val(),
					/* DOGFOOT ktkang 보고서 바로 조회 기능 옵션 추가  20201015 */
					'REPORT_DIRECT_VIEW': $('#reportDirectView').prop('checked') ? 'Y' : 'N',
					// 보고서 설정
					'DASHBOARD_LAYOUT': $('#mainLayout').val(),
					'AUTH_REPORT_DETAIL_YN': $('#reportAuthDetail').val(),
					'DEFAULT_LAYOUT': $('#adhocLayout').val(),
					'NULL_VALUE_YN': $('#showNullValue').prop('checked') ? 'Y' : 'N',
					/* DOGFOOT ktkang 다운로드 필터 추가 옵션, 피벗 드릴다운 막기 옵션 추가  20201013 */
					'DOWNLOAD_FILTER_YN': $('#downloadFilter').prop('checked') ? 'Y' : 'N',
					/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
					'OLD_SCHEDULE_YN': $('#oldSchedule').prop('checked') ? 'Y' : 'N',
					'PIVOT_ALIGN_CENTER': $('#pivotAlignCenter').prop('checked') ? 'Y' : 'N',
					'PIVOT_DRILL_UPDOWN': $('#pivotDrillUpDown').prop('checked') ? 'Y' : 'N',
					'GRID_AUTO_ALIGN': $('#gridAutoAlign').prop('checked') ? 'Y' : 'N',
					/* DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 */
					'GRID_DATA_PAGING' : $('#gridDataPaging').prop('checked') ? 'Y' : 'N',
					'NULL_VALUE_STRING': $('#nullValue').val(),
					'DASHBOARD_DEFAULT_PALETTE': $('#defaultPalette').val(),
					'MENU_CONFIG': JSON.stringify(menuConfig),
					'FONT_CONFIG': JSON.stringify(fontConfig),
					'SPREAD_JS_LICENSE': $('#spreadJsLicenseKey').val(),
					/* DOGFOOT syjin kakao api key 추가 설정 20020819*/
					'KAKAO_MAP_API_KEY' : $("#kakaoApiKey").val(),
					'LAYOUT_CONFIG' : JSON.stringify(layoutConfig)
			}			
						
			$.ajax({
				type : 'post',
				data : param,
				url: WISE.Constants.context + '/report/saveConfigMstr.do',
				async: false,
				success: function(data) {
					$('a.logo').attr('background', 'url(' + WISE.Constants.context + '/resources/main/images/custom/' + logo + ') no-repeat');
					//2020.01.21 mksong 경고창 타입 지정 dogfoot
					WISE.alert(gMessage.get('config.save.success'),'success');
				},
				error: function(){
					//2020.01.21 mksong 경고창 타입 지정 dogfoot
					WISE.alert(gMessage.get('config.save.failed'),'error');
				}
			});
		}
	}
})();