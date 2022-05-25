/**
 * 환경 설정 마스터
 */
WISE.libs.Dashboard.Preferences = function() {
	var self = this;
	this.config;

	/**
	 * Initialize prefrences master.
	 * @param {object} config Object containing configuration attributes. 
	 */
	this.init = function(config) {
		// load config if it exists, else create new config
		self.config = config;
		if (!(self.config)) {
			self.config = {
				autoUpdate: false
			}
		}
		self.initProductInfoWindow();
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'config.do') {
			self.initConfigPage();
		}
		var url = window.location.href;
		/* DOGFOOT ktkang 보고서 열고 개인환경설정 열면 창이 여러개 열리는 오류 수정  20200702 */
		$('.settings-button').off().on('click',function(e){
			url = url.substring(0, url.lastIndexOf('/') + 1);
			window.open(url + 'account.do');
			$('.click-pop').removeClass('click-show');
		});
	}

	/**
	 * Initialize WiseIntelligence information window.
	 */
	this.initProductInfoWindow = function() {
		// init popup
		$('header').append('<div id="productInfoPopup"></div>')
		var popup = $('#productInfoPopup').dxPopup({
			title: '솔루션 정보',
			height: 350,
			width: 500,
			visible: false,
			showCloseButton: false,
			contentTemplate: function(contentElement) {
				contentElement.append(
					'<div class="tbl data-form">' +
						'<div id="information-center"><img src="' + WISE.Constants.context + '/resources/main/images/logo.png" width="40px" height="40px" alt=""> WiseIntelligence™ V6.0</div>' +
					'</div>' +
//					'<div id="information-version" class="tbl data-form">' +
//						'<div id="buildversion">빌드  : (19.04.01.1)</div>' +
//						'<div id="deployversion">배포  : (19.07.18.2)</div>' +
//					'</div>' +
					'<div class="tbl data-form information-footer">' +
						'<div>Copyright 1998, WISEiTECH, Co,Ltd</div>' +
					'</div>' +
					'<div class="tbl data-form information-footer">' +
						'<div>For more information, visit  <a href= "http://www.wise.co.kr" target="_blank"> www.wise.co.kr</a></div>' +
					'</div>' +
					'<div class="modal-footer">' +
						'<div class="row center">' +
							'<a href="#" class="btn positive info-ok-hide">확인</a>' +
						'</div>' +
					'</div>'
				);
				$('.info-ok-hide').on('click', function() {
					popup.hide();
				});
			}
		}).dxPopup('instance');

		$('#mainLogo').on('click', function() {
			popup.show();
		});
	}

	/**
	 * Initialize widgets on the configuration page. Only called if the current page is "config.do".
	 */
	this.initConfigPage = function() {
		// default layout
		var category = 'preferences';
		gProgressbar.show();
		self.hideFilterContainer();
		$('.preferences-cont').load('preferences.do', function() {
			generalConfigManager.initPreferences();
			$('.tab-container').hide();
			gProgressbar.hide();
			
			$('#refreshButton').off('click').on('click', generalConfigManager.handleConfigRefresh);
			$('#saveConfig').off('click').on('click', generalConfigManager.configSaveButtonEvent);
			$('#configGeneralTab').show();
//			$('.scrollbar').scrollbar();
			if(gDashboard)
				gDashboard.scrollbar();
		});
		$('.preferences-lnb.preferences').find('.panel-head.default').addClass('on');
		preferencesTabMo();
		$('.preferences-lnb').hide();
		$('.preferences-lnb.' + category).show();
		$('#saveConfig').on('click', function(e) {
			e.preventDefault();
		});

		/* categories */
		$('.configuration').on('click', function() {
			category = $(this).attr('class').split(' ').pop();
			categoryName = $(this).find('a').text();
			switch(category) {
				// 환경 설정
				case 'preferences':
					if ($('#preferencesPage').length === 0) {
						gProgressbar.show();
						$('.preferences-cont').load('preferences.do', function() {
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.preferences').find('.panel-head.default').addClass('on');
							preferencesTabMo();

							gDashboard.layoutManager.configNavLayoutSave();
							self.hideFilterContainer();
							$('#configGeneralTab').show();
							generalConfigManager.initPreferences();

							$('#refreshButton').off('click').on('click', generalConfigManager.handleConfigRefresh);
							$('#saveConfig').off('click').on('click', generalConfigManager.configSaveButtonEvent);
//							$('.scrollbar').scrollbar();
							if(gDashboard)
								gDashboard.scrollbar();

							gProgressbar.hide();
						});
					}
					break;
				// 사용자/그룹 관리
				case 'user-group':
					if ($('#userGroupPage').length === 0) {
						gProgressbar.show();
						$('.preferences-cont').load('usergroup.do', function() {
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.user-group').find('.panel-head.default').addClass('on');
							preferencesTabMo();

							gDashboard.layoutManager.configNavLayoutNewSaveDeletePw();
							self.hideFilterContainer();
							$('#userManagerTab').show();
							userGroupManager.initUserGroup();

							$('#refreshButton').off('click').on('click', userGroupManager.handleUserGroupRefresh);
							$('#newConfig').off('click').on('click', userGroupManager.handleUserCreate);
							$('#saveConfig').off('click').on('click', userGroupManager.handleUserSave);
							$('#deleteConfig').off('click').on('click', userGroupManager.handleUserDelete);
							$('#passwordConfig').off('click').on('click', userGroupManager.handleUserChangePassword);
//							$('.scrollbar').scrollbar();
							if(gDashboard)
								gDashboard.scrollbar();

							gProgressbar.hide();
						});
					}
					break;
				// 리포트/폴더 관리
				case 'report-folder':
					if ($('#reportFolderPage').length === 0) {
						gProgressbar.show();
						$('.preferences-cont').load('reportfolder.do', function() {
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.report-folder').find('.panel-head.default').addClass('on');
							preferencesTabMo();

							gDashboard.layoutManager.configNavLayoutSaveDelete();
							self.hideFilterContainer();
							$('#reportManagerTab').show();
							reportFolderManager.initReportFolder();

							$('#refreshButton').off('click').on('click', reportFolderManager.handlePublicReportRefresh);
							$('#saveConfig').off('click').on('click', reportFolderManager.handlePublicReportSave);
							$('#deleteConfig').off('click').on('click', reportFolderManager.handlePublicReportDelete);
//							$('.scrollbar').scrollbar();
							if(gDashboard)
								gDashboard.scrollbar();

							gProgressbar.hide();
						});
					}
					break;
				// 로그
				case 'log':
					if ($('#logPage').length === 0) {
						gProgressbar.show();
						$('.preferences-cont').load('log.do', function() {
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.log').find('.panel-head.default').addClass('on');
							preferencesTabMo();

							gDashboard.layoutManager.configNavLayoutEmpty();
							$('#logUserTab').show();
							logManager.initLog();

							$('#refreshButton').off('click').on('click', logManager.handleLogQuery);
//							$('.scrollbar').scrollbar();
							if(gDashboard)
								gDashboard.scrollbar();

							gProgressbar.hide();
						});
					}
					break;
				case 'data-source':
					if($("#dataSourcePage").length === 0){
						gProgressbar.show();
						
						$(".preferences-cont").load('datasource.do', function(){
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.data-source').find('.panel-head.default').addClass('on');
							preferencesTabMo();
							
							gDashboard.layoutManager.configNavLayoutNewSaveDelete();
							//dogfoot syjin 원본 추가 일때 refresh 버튼 비활성화 20210325
							$("#refreshButton").css('display', 'none');
							self.hideFilterContainer();
							$('#dataSourceTab').show();
							dataSourceManager.initDataSource();
							dataSourceManager.initAccessButton();
							
							$('#newConfig').off('click').on('click', dataSourceManager.handleDataSourceNew);
							$('#saveConfig').off('click').on('click', dataSourceManager.handleDataSourceSave);
							$('#deleteConfig').off('click').on('click', dataSourceManager.handleDatasourceDelete);
							
							if(gDashboard)
								gDashboard.scrollbar();
						
							gProgressbar.hide();
						})					
					}
				break;
				case 'session':
					if ($('#sessionPage').length === 0) {
						gProgressbar.show();
						$('.preferences-cont').load('configSession.do', function() {
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.session').find('.panel-head.default').addClass('on');
							preferencesTabMo();

							gDashboard.layoutManager.configNavLayoutEmpty();
							self.hideFilterContainer();
							$('#sessionJobTab').show();
							sessionManager.initSession();

							$('#refreshButton').off('click').on('click', sessionManager.handleCurrentSqlRefresh);
//							$('.scrollbar').scrollbar();
							if(gDashboard)
								gDashboard.scrollbar();

							gProgressbar.hide();
						});
					}
					break;
				// 모니터링
				case 'monitoring':
					if ($('#monitoringPage').length === 0) {
						gProgressbar.show();
						$('.preferences-cont').load('monitoring.do', function() {
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.monitoring').find('.panel-head.default').addClass('on');
							preferencesTabMo();

							/* DOGFOOT ktkang 모니터링 부분 기능 추가  20201014 */
							gDashboard.layoutManager.configNavLayoutDelete();
							self.hideFilterContainer();
							/* DOGFOOT ktkang 모니터링에서 시스템 부분 주석처리  20200924*/
//							$('#overviewTab').show();
							$('#processesTab').show();
							monitorManager.initMonitoring();
							/*dogfoot 모니터링 첫 페이지 로딩시 프로세스 조회버튼 활성화 shlim 20201130*/
							$('#refreshButton').off('click').on('click', authenticationManager.handleAuthGroupDataRefresh);
							$('#deleteConfig').off('click').on('click', monitorManager.handleProcessDelete);
//							$('.scrollbar').scrollbar();
							if(gDashboard)
								gDashboard.scrollbar();

							gProgressbar.hide();
						});
					}
					break;
				// 권한
				case 'authentication':
					if ($('#authenticationPage').length === 0) {
						gProgressbar.show();
						$('.preferences-cont').load('auth.do', function() {
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.authentication').find('.panel-head.default').addClass('on');
							preferencesTabMo();

							gDashboard.layoutManager.configNavLayoutSave();
							self.hideFilterContainer();
							$('#authGroupDataTab').show();
							authenticationManager.loadAuthGroupData();

							$('#refreshButton').off('click').on('click', authenticationManager.handleAuthGroupDataRefresh);
							$('#saveConfig').off('click').on('click', authenticationManager.handleAuthGroupDataSave);
//							$('.scrollbar').scrollbar();
							if(gDashboard)
								gDashboard.scrollbar();

							gProgressbar.hide();
						});
					}
					break;
				case 'DataSet':
					if ($('#addDatasetlist').length === 0) {
						gProgressbar.show();
						$('.preferences-cont').load('addDataSetlist.do', function() {
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.DataSet').find('.panel-head.default').addClass('on');
							preferencesTabMo();
							$('#filterContainer').empty();
							$('#DataSetList').show();
							gDashboard.layoutManager.configDataSetNewSaveSaveasDel();
							datasetManager.loadDataSetList();
							
							$('#refreshButton').off('click').on('click', datasetManager.handleDataSetRefresh);
							$('#newConfig').off('click').on('click', datasetManager.handleDataSetCreate);
							$('#saveConfig').off('click').on('click', datasetManager.handleDataSetSave);
							$('#saveAsConfig').off('click').on('click', datasetManager.handleDataSetSaveAs);
							$('#deleteConfig').off('click').on('click', datasetManager.handleDataSetDelete);
//							$('.scrollbar').scrollbar();
							if(gDashboard)
								gDashboard.scrollbar();

							gProgressbar.hide();
						});
					}
					break;
					//20210329 AJKIM 스파크 메모리 관리 페이지 추가 dogfoot
				case 'spark-memory':
					if($("#sparkMemoryPage").length === 0){
						gProgressbar.show();
						
						$(".preferences-cont").load('sparkmemory.do', function(){
							$('.tab-container').hide();
							$('.preferences-lnb').find('.panel-head.on').removeClass('on');
							$('.preferences-lnb.data-source').find('.panel-head.default').addClass('on');
							preferencesTabMo();
							
							gDashboard.layoutManager.configNavLayoutDelete();
							//dogfoot syjin 원본 추가 일때 refresh 버튼 비활성화 20210325
							$("#refreshButton").css('display', 'none');
							self.hideFilterContainer();
							$('#sparkMemoryTab').show();
							sparkMemoryManager.initSparkMemory();

							$('#deleteConfig').off('click').on('click', sparkMemoryManager.handleSparkMemoryDelete);
							
							if(gDashboard)
								gDashboard.scrollbar();
						
						})					
					}
				default: break;
			}
			if(category == 'DataSet'){
				$('.preferences-cont').addClass('DataSet');
			}else{
				$('.preferences-cont').removeClass('DataSet');
			}
			$('.preferences-lnb').hide();
			$('.preferences-lnb.' + category).show();
		});
		/* subcategories */
		$('.panel-head').on('click', function() {
			var category = $(this).find('.select-category').data('category');
			$('.preferences-lnb').find('.panel-head.on').removeClass('on');
			$(this).addClass('on');
			preferencesTabMo();
			$('.tab-container').hide();
			switch(category) {
				case 'config-general':
					$('#configGeneralTab').show();
					$('#refreshButton').off('click').on('click', generalConfigManager.handleConfigRefresh);
					$('#saveConfig').off('click').on('click', generalConfigManager.configSaveButtonEvent);
					break;
				case 'config-advanced':
					$('#configAdvancedTab').show();
					$('#refreshButton').off('click').on('click', generalConfigManager.handleConfigRefresh);
					$('#saveConfig').off('click').on('click', generalConfigManager.configSaveButtonEvent);
					break;
				case 'config-report':
					$('#configReportTab').show();
					$('#refreshButton').off('click').on('click', generalConfigManager.handleConfigRefresh);
					$('#saveConfig').off('click').on('click', generalConfigManager.configSaveButtonEvent);
					break;
				case 'config-menu':
					$('#configMenuTab').show();
					$('#refreshButton').off('click').on('click', generalConfigManager.handleConfigRefresh);
					$('#saveConfig').off('click').on('click', generalConfigManager.configSaveButtonEvent);
					break;
				// 사용자/그룹 관리
				case 'usrgrp-user':
					gDashboard.layoutManager.configNavLayoutNewSaveDeletePw();
					self.hideFilterContainer();
					$('#refreshButton').off('click').on('click', userGroupManager.handleUserGroupRefresh);
					$('#newConfig').off('click').on('click', userGroupManager.handleUserCreate);
					$('#saveConfig').off('click').on('click', userGroupManager.handleUserSave);
					$('#deleteConfig').off('click').on('click', userGroupManager.handleUserDelete);
					$('#passwordConfig').off('click').on('click', userGroupManager.handleUserChangePassword);
					$('#userManagerTab').show();
					break;
				case 'usrgrp-group':
					gDashboard.layoutManager.configNavLayoutNewSaveDelete();
					self.hideFilterContainer();
					$('#groupManagerTab').show();
					$('#refreshButton').off('click').on('click', userGroupManager.handleUserGroupRefresh);
					$('#newConfig').off('click').on('click', userGroupManager.handleGroupCreate);
					$('#saveConfig').off('click').on('click', userGroupManager.handleGroupSave);
					$('#deleteConfig').off('click').on('click', userGroupManager.handleGroupDelete);
					break;
				//  리포트/폴더 관리
				case 'repfol-report':
					gDashboard.layoutManager.configNavLayoutSaveDelete();
					self.hideFilterContainer();
					$('#reportManagerTab').show();
					$('#refreshButton').off('click').on('click', reportFolderManager.handlePublicReportRefresh);
					$('#saveConfig').off('click').on('click', reportFolderManager.handlePublicReportSave);
					$('#deleteConfig').off('click').on('click', reportFolderManager.handlePublicReportDelete);
					break;
				case 'repfol-folder':
					gDashboard.layoutManager.configNavLayoutNewEditDelete();
					self.hideFilterContainer();
					$('#folderManagerTab').show();
					$('#refreshButton').off('click').on('click', reportFolderManager.handlePublicFolderRefresh);
					$('#newConfig').off('click').on('click', reportFolderManager.handlePublicFolderCreate);
					$('#editConfig').off('click').on('click', reportFolderManager.handlePublicFolderEdit);
					$('#deleteConfig').off('click').on('click', reportFolderManager.handlePublicFolderDelete);
					
					//dogfoot 폴더 관리 스크롤 오류 수정 20210507 syjin
					$("#folderList").css("height","");
					break;
				// 로그
				case 'log-user':
					$('#logUserTab').show();
					break;
				case 'log-report':
					$('#logReportTab').show();
					break;
				case 'log-export':
					$('#logExportTab').show();
					break;
				case 'log-query':
					$('#logQueryTab').show();
					break;
				case 'log-analysis':
					$('#logAnalysisTab').show();
					break;
				//세션
				case 'session-job':
					gDashboard.layoutManager.configNavLayoutEmpty();
					self.hideFilterContainer();	
					$('#sessionJobTab').show();
					$('#refreshButton').off('click').on('click', sessionManager.handleCurrentSqlRefresh);
					break;
				case 'session-users':
					gDashboard.layoutManager.configNavLayoutDownloadLogout();
					$('#sessionUserTab').show();
					$('#refreshButton').off('click').on('click', sessionManager.handleUserRefresh);
					// $('#downloadConfig').off('click').on('click', sessionManager.handleUserDownload);
					$('#logoutConfig').off('click').on('click', sessionManager.handleUserLogout);
					sessionManager.initSessionLoginFilter();
					break;
				case 'session-inactive-users':
					gDashboard.layoutManager.configNavLayoutUnlock();
					$('#sessionInactiveUserTab').show();
					$('#refreshButton').off('click').on('click', sessionManager.handleInactiveUserRefresh);
					// $('#downloadConfig').off('click').on('click', sessionManager.handleInactiveUserDownload);
					$('#unlockConfig').off('click').on('click', sessionManager.handleInactiveUserUnlock);
					sessionManager.initSessionUserFilter();
					break;
				case 'session-locked-users':
					gDashboard.layoutManager.configNavLayoutUnlock();
					self.hideFilterContainer();
					$('#sessionLockedUserTab').show();
					$('#refreshButton').off('click').on('click', sessionManager.handleLockedUserRefresh);
					$('#unlockConfig').off('click').on('click', sessionManager.handleLockedUserUnlock);
					break;
				//모니터링
				case 'monitoring-system':
					$('#overviewTab').show();
					break;
				case 'monitoring-processes':
					$('#processesTab').show();
					/* DOGFOOT ktkang 모니터링 프로세스 부분 오류 수정  20201015 */
					$('#deleteConfig').show();
					$('#deleteConfig').off('click').on('click', monitorManager.handleProcessDelete);
					$('#refreshButton').off('click').on('click', monitorManager.handleMonitorJobRefresh);
					break;
				case 'monitoring-users':
					$('#activeUsersTab').show();
					/* DOGFOOT ktkang 모니터링 프로세스 부분 오류 수정  20201015 */
					$('#deleteConfig').off('click');
					$('#deleteConfig').hide();
					$('#refreshButton').off('click').on('click', monitorManager.handleMonitorUserRefresh);
					break;
				// 권한
				case 'authentication-userdata':
					authenticationManager.loadAuthUserData();
					self.hideFilterContainer();
					$('#authUserDataTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthUserDataRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthUserDataSave);
					break;
				case 'authentication-groupdata':
					authenticationManager.loadAuthGroupData();
					self.hideFilterContainer();
					$('#authGroupDataTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthGroupDataRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthGroupDataSave);
					break;
				case 'authentication-userreport':
					authenticationManager.loadAuthUserReport();
					self.hideFilterContainer();
					$('#authUserReportTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthUserReportRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthUserReportSave);
					authenticationManager.initAuthUserReportSelectDeselect();
					break;
				case 'authentication-groupreport':
					authenticationManager.loadAuthGroupReport();
					self.hideFilterContainer();
					$('#authGroupReportTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthGroupReportRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthGroupReportSave);
					authenticationManager.initAuthGroupReportSelectDeselect();
					break;
				case 'authentication-userdataset':
					authenticationManager.loadAuthUserDataset();
					self.hideFilterContainer();
					$('#authUserDatasetTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthUserDatasetRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthUserDatasetSave);
					break;
				case 'authentication-groupdataset':
					authenticationManager.loadAuthGroupDataset();
					self.hideFilterContainer();
					$('#authGroupDatasetTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthGroupDatasetRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthGroupDatasetSave);
					break;
				//20210705 AJKIM 메뉴 권한 추가 dogfoot
				case 'authentication-groupwb':
					authenticationManager.loadAuthGroupWebApp();
					self.hideFilterContainer();
					$('#authGroupWbTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthGroupWbRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthGroupWbSave);
					break;
				case 'authentication-userwb':
					authenticationManager.loadAuthUserWebApp();
					self.hideFilterContainer();
					$('#authUserWbTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthUserWbRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthUserWbSave);
					break;
					//20210520 AJKIM 데이터 원본 권한 추가 dogfoot
				case 'authentication-groupds':
					authenticationManager.loadAuthGroupDs();
					self.hideFilterContainer();
					$('#authGroupDsTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthGroupDsRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthGroupDsSave);
					break;
				case 'authentication-userds':
					authenticationManager.loadAuthUserDs();
					self.hideFilterContainer();
					$('#authUserDsTab').show();
					$('#refreshButton').off('click').on('click', authenticationManager.handleAuthUserDsRefresh);
					$('#saveConfig').off('click').on('click', authenticationManager.handleAuthUserDsSave);
					break;
				case 'dataSet-list':
					self.hideFilterContainer();
					$('#newConfig').off('click').on('click', reportFolderManager.handlePublicFolderCreate);
					$('#editConfig').off('click').on('click', reportFolderManager.handlePublicFolderEdit);
					$('#deleteConfig').off('click').on('click', reportFolderManager.handlePublicFolderDelete);
					$('#DataSetList').show();
					break;
				default: break;
			}
		});
	}

	/**
	 * Helper function for config pages.
	 * Adjust a data grid's page size according to the container's height.
	 * @param {String} pageId
	 * @param {String} gridId
	 * @param {boolean} noHeader
	 */
	this.calculateGridPageSize = function(pageId, gridId, options) {
		// container height
		var container = $(pageId).height();
		if (container <= 0) {
			container = $('.preferences-cont').height() - 20;
		} else if (pageId === '.preferences-cont') {
			container -= 20;
		}
		// height from other objects
		var header = 63;
		var other = 0;
		if (options) {
			header = 0;
			if (options === 'querybox') {
				other = 265;
			}
		}
		// dxDataGrid padding and margin height
		var gridPadding = $(gridId).outerHeight() - $(gridId).height();
		// dxDataGrid pager height
		var gridNav = 55
		// dxDataGrid row height
		var rowHeight = 34;
		return Math.floor((container - header - gridPadding - gridNav - other) / rowHeight) - 1;
	}

	this.hideFilterContainer = function() {
		$('#filterContainer').empty();
		$('.menu-comp.pre-search').hide();
	}
}