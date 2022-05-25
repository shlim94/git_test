WISE.libs.Dashboard = function(_id, _containerId) {
	var self = this;
	
	this.id;
	this.containerId;

	this.structure;
	
	this.layoutManager;
	this.dataSourceManager;
	this.parameterFilterBar;
	this.queryHandler;
	this.itemGenerateManager;
	this.itemColorManager;
	this.panelResizer;
	this.windowSet;
	this.itemQuantity;
	this.dataSourceQuantity;
	this.FieldFilter;
	this.columnChooserManager;
	this.reportUtility;
	this.dataSetCreate;
	this.dragNdropController;
	this.customFieldCalculater
	this.goldenLayoutManager;
	this.reportLayoutManager;
	this.insertItemManager;
	this.changeReportTypeManager;
    this.downloadManager;
    this.customFieldManager;
    this.customParameterHandler;
	this.scheduler;
	this.preferences;
	this.reportType;
	this.fontManager;
	this.d3Manager;
	this.pivotUtility;
	
	this.fldType;
	
	this.isSingleView = false;
	
	this.queryByGeneratingSql;
	this.fullData;
	
	this.nullDataYN = false;
	
	this.button = {
		'printScreen': '인쇄'	
	};
	this.tabN = 0;
	this.maxReportOpen = 10;
	this.isOpened =false;
	
	this.portalView = false;
	this.downloadFull = false;
	this.downloadReady = false;
	
	this.structureBuffer = [];
	this.totalConditionBuffer = [];
	this.itemGenerateBuffer = [];
	this.LayoutManagerBuffer = [];
	this.itemCalcParamListBuffer = [];
	this.itemCustomFieldBuffer = [];
	this.stateBuffer = [];
	this.viewerParameterBars = {};
	this.contentReadyParamList = [];
	this.queriesDoParam = [];
	this.schedulePath;
	
	this.openCanceled = false;
	this.devVersionFlag = (Number(DevExpress.VERSION.split('.')[0])>=20);
	
	this.tabQuery = false;
	this.hasTab = false;
	
	this.finishParams = 0;
	this.authPublishArr = [];
	
	(function() {
		$(document).ajaxSuccess(function(event, data) {
			if (data.responseText && data.responseText.length > 0) {
				if (Object.prototype.toString.call(data.responseText) === "[object String]") {
					try {
						redirect = JSON.parse(data.responseText);
						if (redirect && redirect.redirectUrl) {
							window.location.replace(redirect.redirectUrl);
						}
					} catch(e) {}
				}
			}
		});
		
		sessionStorage.setItem("login", "true");
		self.id = _id;
		self.containerId = _containerId;
		if(WISE.Constants.editmode === 'viewer'){
			self.layoutConfig = [];
		}else{
			self.layoutConfig = "";
		}
		self.configCustomPalette = 
        {'Sunset': ['#fff5bc','#fedbaa','#fdc8a2','#fcb49c','#fca296','#f98b90','#f5738b','#ee5b86','#e24a85','#c93a8c','#a62d99','#86239a','#6a1b9a','#5b168d','#4f1380','#430f71','#340c5a','#24083f','#160525','#222222']
        };
		
		window.name = 'oldPage';
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'config.do') {
			self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
			self.preferences = new WISE.libs.Dashboard.Preferences();
			self.fontManager = new WISE.libs.Dashboard.FontManager();
			self.reportLayoutManager = new WISE.libs.Dashboard.ReportLayoutManager();
		}else if (page[page.length - 1] === 'account.do') {
			self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
			self.preferences = new WISE.libs.Dashboard.Preferences();
			self.fontManager = new WISE.libs.Dashboard.FontManager();
		}else if(page[page.length - 1] === 'viewer.do' || page[page.length - 1] === 'excelView.do'){
			if(userJsonObject.userItemType === 'AdHoc') {
				self.reportType = 'AdHoc';
			} else if(userJsonObject.userItemType === 'StaticAnalysis') {
				self.reportType = 'StaticAnalysis';
				self.analysisType = userJsonObject.userAnalysisType;
			} else if(userJsonObject.userItemType === 'RAnalysis') {
				self.reportType = 'RAnalysis';
			} else if(userJsonObject.userItemType === 'DSViewer') {
				self.reportType = 'DSViewer';
			} else if(userJsonObject.userItemType === 'DashAny') {
				self.reportType = 'DashAny';
			} else {
				/*dogfoot 로그인후 디자이너 초기화면 설정기능 추가  shlim 20210531*/
				if(userJsonObject.menuconfig.Menu.WI_DEFAULT_PAGE){
					self.reportType = userJsonObject.menuconfig.Menu.WI_DEFAULT_PAGE;
				}else{
                    self.reportType = 'DashAny';					
				}
			}
			self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
			self.preferences = new WISE.libs.Dashboard.Preferences();
			self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
			self.datasetMaster = new WISE.libs.Dashboard.DatasetMaster();
			self.datasetDesigner = new WISE.libs.Dashboard.DatasetDesigner();
			self.datasetDesignerSelector = new WISE.libs.Dashboard.DatasetDesignerSelector();
			self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
			self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
			self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
			self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
			self.itemColorManager = new WISE.libs.Dashboard.item.ItemColorManager();
			self.changeReportTypeManager = new WISE.libs.Dashboard.item.ChangeReportTypeManager();
			self.spreadsheetManager = new WISE.libs.Dashboard.item.SpreadsheetManager();
			self.adhocReportUtility = WISE.libs.Dashboard.item.AdhocReportUtility;
			self.panelResizer = new WISE.libs.Dashboard.util.PanelResizer();
			self.fieldFilter = null;
			self.fieldChooser = new WISE.libs.Dashboard.item.FieldChooser();
			self.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'parallel':0
								, 'choroplethMap':0,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0, 'comboBox':0, 'image':0
								, 'textBox':0, 'RectangularAreaChart':0, 'waterfallchart':0,'bubbled3':0, 'histogramchart':0
								, 'card':0,'adhocItem':0,'hierarchical':0, 'bipartitechart':0, 'funnelchart':0, 'pyramidchart':0
								, 'forceDirect':0,'forceDirectExpand':0,'sankeychart':0, 'bubble':0, 'rangebarchart':0, 'rangeareachart':0
								, 'timelinechart':0, 'bubblepackchart':0, 'wordcloudv2':0, 'dendrogrambarchart':0, 'calendarviewchart':0
								, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0, 'boxplot': 0, 'coordinateline': 0, 'scatterplot': 0, 'scatterplotmatrix': 0, 'radialtidytree': 0, 'historytimeline': 0, 'arcdiagram':0, 'scatterplot2': 0,'liquidfillgauge': 0
								, 'kakaoMap':0, 'kakaoMap2':0, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0
								, 'onewayAnova':0, 'onewayAnova2':0, 'twowayAnova':0, 'pearsonsCorrelation':0, 'spearmansCorrelation':0
								, 'simpleRegression':0, 'multipleRegression':0, 'logisticRegression':0 , 'multipleLogisticRegression':0
								, 'tTest':0, 'zTest':0, 'chiTest':0, 'fTest':0, 'multivariate':0};
			self.dragNdropController = new WISE.widget.DragNDropController();
			self.customFieldCalculater = new WISE.libs.Dashboard.CustomFieldCalculater();
			self.customFieldManager = new WISE.libs.Dashboard.CustomFieldManager();
			self.customParameterHandler = new WISE.libs.Dashboard.CustomParameterHandler();
			self.downloadManager = new WISE.libs.Dashboard.DownloadManager();
			self.dataSourceQuantity = 0;
			
			self.insertItemManager = new WISE.libs.Dashboard.item.InsertItemManager();
			
			self.isNewReport = (WISE.Constants.pid == "");
			self.FieldFilter = new WISE.libs.Dashboard.FieldFilter();
			self.dataSetCreate = new WISE.libs.DataSet();
			self.reportUtility = new WISE.libs.ReportUtility();
			self.goldenLayoutManager = {};
			self.reportLayoutManager = new WISE.libs.Dashboard.ReportLayoutManager();
			self.fontManager = new WISE.libs.Dashboard.FontManager();
			
			self.pivotUtility = WISE.libs.Dashboard.item.PivotUtility;
			self.d3Manager = new WISE.libs.Dashboard.item.D3Manager();
		} else if (page[page.length - 1] === 'spreadsheet.do') {
			self.reportType = 'Spread';
			self.spreadsheetManager = new WISE.libs.Dashboard.item.SpreadsheetManager();
			self.panelResizer = new WISE.libs.Dashboard.util.PanelResizer();
			self.windowSet = new WISE.libs.Dashboard.util.WindowSet();
			self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
			self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
			self.datasetMaster = new WISE.libs.Dashboard.DatasetMaster();
			self.datasetDesigner = new WISE.libs.Dashboard.DatasetDesigner();
			self.datasetDesignerSelector = new WISE.libs.Dashboard.DatasetDesignerSelector();
			self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
			self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
			self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
			self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
			self.fieldFilter = null;
			self.fieldChooser = new WISE.libs.Dashboard.item.FieldChooser();

			self.dataSourceQuantity = 0;
			self.dragNdropController = new WISE.widget.DragNDropController();
			self.customFieldCalculater = new WISE.libs.Dashboard.CustomFieldCalculater();
			self.customFieldManager = new WISE.libs.Dashboard.CustomFieldManager();
			self.customParameterHandler = new WISE.libs.Dashboard.CustomParameterHandler();
			self.scheduler = new WISE.libs.Dashboard.Scheduler();
			self.preferences = new WISE.libs.Dashboard.Preferences();
			self.goldenLayoutManager = new WISE.libs.Dashboard.GoldenLayoutManager();
			
			self.reportLayoutManager = new WISE.libs.Dashboard.ReportLayoutManager();
			self.isNewReport = (WISE.Constants.pid == "");
			self.FieldFilter = new WISE.libs.Dashboard.FieldFilter();
			self.dataSetCreate = new WISE.libs.DataSet();
			self.reportUtility = new WISE.libs.ReportUtility();
			self.downloadManager = new WISE.libs.Dashboard.DownloadManager();
			self.fontManager = new WISE.libs.Dashboard.FontManager();
			
			self.pivotUtility = WISE.libs.Dashboard.item.PivotUtility;
		}else {
			if(userJsonObject.userItemType === 'AdHoc') {
				self.reportType = 'AdHoc';
			} else if(userJsonObject.userItemType === 'StaticAnalysis') {
				self.reportType = 'StaticAnalysis';
				self.analysisType = userJsonObject.userAnalysisType;
			} else if(userJsonObject.userItemType === 'RAnalysis') {
				self.reportType = 'RAnalysis';
			} else if(userJsonObject.userItemType === 'DSViewer') {
				self.reportType = 'DSViewer';
			} else {
				self.reportType = 'DashAny';
			}
			self.panelResizer = new WISE.libs.Dashboard.util.PanelResizer();
			self.windowSet = new WISE.libs.Dashboard.util.WindowSet();
			self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
			self.datasetMaster = new WISE.libs.Dashboard.DatasetMaster();
			self.datasetDesigner = new WISE.libs.Dashboard.DatasetDesigner();
			self.datasetDesignerSelector = new WISE.libs.Dashboard.DatasetDesignerSelector();
			self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
			self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
			self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
			self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
			self.itemColorManager = new WISE.libs.Dashboard.item.ItemColorManager();
			self.fieldFilter = null;
			self.fieldChooser = new WISE.libs.Dashboard.item.FieldChooser();
			self.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'parallel':0
								, 'choroplethMap':0,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0, 'comboBox':0, 'image':0
								, 'textBox':0, 'RectangularAreaChart':0, 'waterfallchart':0,'bubbled3':0, 'histogramchart':0
								, 'card':0, 'bubble':0,'adhocItem':0,'hierarchical':0,'bipartitechart':0, 'funnelchart':0
								, 'pyramidchart':0, 'forceDirect':0,'forceDirectExpand':0,'sankeychart':0, 'rangebarchart':0
								, 'rangeareachart':0, 'timelinechart':0, 'bubblepackchart':0, 'wordcloudv2':0, 'dendrogrambarchart':0
								, 'calendarviewchart':0, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0, 'boxplot': 0, 'coordinateline': 0
								, 'scatterplot': 0, 'scatterplotmatrix': 0, 'radialtidytree': 0, 'historytimeline': 0, 'arcdiagram':0, 'scatterplot2': 0, 'liquidfillgauge': 0, 'kakaoMap':0, 'kakaoMap2':0
								, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0
								, 'onewayAnova':0, 'onewayAnova2':0, 'twowayAnova':0, 'pearsonsCorrelation':0, 'spearmansCorrelation':0
								, 'simpleRegression':0, 'multipleRegression':0, 'logisticRegression':0, 'multipleLogisticRegression':0
								, 'tTest':0, 'zTest':0, 'chiTest':0, 'fTest':0, 'multivariate':0};

			self.dataSourceQuantity = 0;
			self.dragNdropController = new WISE.widget.DragNDropController();
			self.customFieldCalculater = new WISE.libs.Dashboard.CustomFieldCalculater();
			self.customFieldManager = new WISE.libs.Dashboard.CustomFieldManager();
			self.customParameterHandler = new WISE.libs.Dashboard.CustomParameterHandler();
			self.scheduler = new WISE.libs.Dashboard.Scheduler();
			self.preferences = new WISE.libs.Dashboard.Preferences();
			
			self.insertItemManager = new WISE.libs.Dashboard.item.InsertItemManager();
			self.changeReportTypeManager = new WISE.libs.Dashboard.item.ChangeReportTypeManager();
			self.goldenLayoutManager = new WISE.libs.Dashboard.GoldenLayoutManager();
			self.reportLayoutManager = new WISE.libs.Dashboard.ReportLayoutManager();
			
			self.isNewReport = (WISE.Constants.pid == "");
			self.FieldFilter = new WISE.libs.Dashboard.FieldFilter();
			self.dataSetCreate = new WISE.libs.DataSet();
			self.reportUtility = new WISE.libs.ReportUtility();
			self.adhocReportUtility = WISE.libs.Dashboard.item.AdhocReportUtility;
			self.downloadManager = new WISE.libs.Dashboard.DownloadManager();
			self.fontManager = new WISE.libs.Dashboard.FontManager();
			
			self.pivotUtility = WISE.libs.Dashboard.item.PivotUtility;
			self.d3Manager = new WISE.libs.Dashboard.item.D3Manager();
		}
	})();
	
	this.scrollbar = function() {
		 $('.scrollbar').dxScrollView({
	        scrollByContent: true,
	        scrollByThumb: true,
	        showScrollbar: "onHover",
	        onScroll: function(e) {
	        	 if(WISE.Constants.editmode!=='viewer' && $('.other-menu-ico').length){
	 	            $('.other-menu-ico').removeClass('on');
	 	        }
	        }
	    })
	}
	
	this.updateReportLog = function(status_id) {
		if(gDashboard.isNewReport == false) {
			var status = '60';
			if(typeof status_id != 'undefined' && status_id == '50') {
				status = '50';
			} else if(typeof status_id != 'undefined' && status_id == '99') {
				status = '99';
			}
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/report/updateReportLog.do', 
				data: {
					logSeq: gDashboard.structure.ReportMasterInfo.log_seq,
					status: status
				},
				success: function(data) {
				}
			});
		}
	}
	
	this.updateReportLog = function() {
		if(gDashboard.isNewReport == false) {
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/report/updateReportLog.do', 
				data: {
					logSeq: gDashboard.structure.ReportMasterInfo.log_seq,
					status: 60
				},
				success: function(data) {
				}
			});
		}
	}
	
	this.insertReportLog = function() {
		if(gDashboard.isNewReport == false) {
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/report/insertReportLog.do', 
				data: {
					reportType: gDashboard.reportType,
					reportName: gDashboard.structure.ReportMasterInfo.name,
					reportId : WISE.Constants.pid,
					userId : userJsonObject.userId
				},
				success: function(data) {
				}
			});
		} else {
			$.ajax({
				method : 'POST',
				url: WISE.Constants.context + '/report/insertReportLog.do', 
				data: {
					reportType: gDashboard.reportType,
					reportName: "",
					reportId : "0",
					userId : userJsonObject.userId
				},
				success: function(data) {
				}
			});
		}
	}
	
	this.selectReportWorks = function() {
		var works = 0;
		$.ajax({
			method : 'POST',
			url: WISE.Constants.context + '/report/selectReportWorks.do', 
			async: false,
			success: function(data) {
				works = data.works;
			}
		});
		return works;
	}
	
	this.init = function() {
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'viewer.do' || page[page.length - 1] === 'excelView.do') {
			if(WISE.Constants.pid == ""){
				self.reportUtility.init();
				var newReport = self.reportUtility.reportInfo;
				self.structure = newReport;
				self.layoutManager.init();
				self.queryHandler.init();
				self.customFieldManager.init();
				$('.container-inner').css('padding-top', 62);
				$('#treeopen').show();
				self.render();
				self.panelResizer.render();
				self.preferences.init();
				self.downloadManager.init();
				self.fontManager.init();
				
				if(page[page.length - 1] != 'excelView.do') {
					self.folderList();
				}
			}else{
				$('.progress_back_panel2').css('display','none');
				$('.img_progress2').css('display','none');
				$('#treeopen').show();
				gProgressbar.show();
				
				$.ajax({
					type:'post',
					url:WISE.Constants.context + '/report/getReportType.do',
					data:{pid:WISE.Constants.pid},
					async:false,
					success:function(_data){
						self.reportType = _data.reportType;
						self.fldType = _data.fldType;
						var portalReportList = _data.portalReportList;
						$.each(_data.portalReportList, function(_i, _e){
							if(_e.REPORT_ID == WISE.Constants.pid) {
								gDashboard.portalView = true;
							}
						});
						
						$('.tree-view').css('display','none');
						if(gDashboard.portalView) {
							$('.reportListArea').css('display','none');
							$('header').hide();
							$('.filter-gui').hide();
							$('.filter-bar').hide();
							$('.container-inner').css('padding-top', 0);
							$('.container-inner').css('padding-left', 0);
							$('.dashboard-item').css('padding', 10);
						} else {
							self.layoutManager.viewheaderLayout();
							self.downloadManager.init();
						}
						if(gDashboard.portalView) {
							$('.lm_maximise').hide();
							$('.lm_header').hide();
							$('div[id^="contentContainer"]').css('overflow', 'hidden');
						}
					}
				});

	    		self.isNewReport = (WISE.Constants.pid == "");

				$('.reportListArea').css('display','none');
				$('header').hide();
				$('.filter-gui').hide();
				$('.container-inner').css('padding-top', 0);
				$('.tree-view').css('display','none');
				$.ajax({
					type:'post',
					url:WISE.Constants.context + '/report/getReportType.do',
					data:{pid:WISE.Constants.pid},
					async:false,
					success:function(_data){
						self.reportType = _data.reportType;
						self.fldType = _data.fldType;
						if(userJsonObject.menuconfig.Menu.VIEWER_DIRECT_DSIGNER){
							if(_data.AUTH_PUBLISH){
								self.authPublishArr[WISE.Constants.pid] = _data.AUTH_PUBLISH
							}
                        }
						self.openViewerReportGL(WISE.Constants.pid, self.reportType, true);
					}
				});				
	    		self.isNewReport = (WISE.Constants.pid == "");
				$('.reportListArea').css('display','none');
				$('header').css('display','none');
				$('.tree-view').css('display','none');
				$('.container-inner').css('padding-top',0);											
			}
			
			if(gDashboard.structure) {
				if(gDashboard.isSingleView){
			        $('body').append('<div id="seriesOptions"></div>');
			        $('body').append('<div id="formatOptions"></div>');
			        $('body').append('<div id="fieldRename"></div>');	
				}	
				
				$('#linkReportList').empty();
				$.each(gDashboard.structure.linkReport,function(_i,_o){
					$('#linkReportList').append('<li><a id=' + _o.target_id + ' href="#">' + _o.target_nm + '</a></li>');
					
					$('#' + _o.target_id).click(function(e) { 
						
						var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
						
						var linkReportMeta = gDashboard.structure.linkReport;
						var linkJsonMatch = {};
						var target_id;
						
						$.each(linkReportMeta,function(_i,_linkMeta){
							if(_linkMeta.link_type == 'LP')
							{
								target_id = _linkMeta.target_id;
								if(typeof _linkMeta.linkJson.LINKDATA_XML != 'undefined') {
									$.each(_linkMeta.linkJson.LINKDATA_XML.ARG_DATA,function(_j,_linkJson){
    									linkJsonMatch[_linkJson] = paramListValue[_linkJson].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson].value;
    								});
								} else {
									linkJsonMatch = [];
								}
								
							}
						});
						
						var locationStr = "";
						if(linkJsonMatch != []) {
							$.each(linkJsonMatch,function(_key,_val){
								locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(encodeURIComponent(_val))+'&';
							});
							locationStr = (locationStr.substring(0,locationStr.length-1));

							if(locationStr.length > 1) {
								locationStr = "&" + locationStr;
							}
						}
						var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_o.target_id+'/viewer.do?USER='+userJsonObject.userId+'&assign_name=bWVpcw==' + locationStr;
						window.open(urlString);
					});
    			});
			}
		}
		else if (page[page.length - 1] === 'config.do' || page[page.length - 1] === 'account.do') {
			self.layoutManager = new WISE.libs.Dashboard.LayoutManager();

			self.layoutManager.dashboardid = self.id;
			self.layoutManager.containerId = self.containerId;
			self.layoutManager.init();
			self.layoutManager.render();
			self.preferences.init();
			self.fontManager.init();
		}
		else if(!self.isNewReport){
			if(WISE.Constants.pid != ""){
				$.ajax({
					type:'post',
					url:WISE.Constants.context + '/report/getReportType.do',
					data:{pid:WISE.Constants.pid},
					async:false,
					success:function(_data){
						self.reportType = _data.reportType;
						self.fldType = _data.fldType;
						
						var jsondoUrl;
						if(typeof userJsonObject.userReportSeq != 'undefined' && userJsonObject.userReportSeq != '1001' && userJsonObject.userReportSeq != '') {
							jsondoUrl = WISE.Constants.context + '/report/' + WISE.Constants.pid + '/info/json.do?reportType='+self.reportType + '&fldType=' + self.fldType + '&reportSeq=' + userJsonObject.userReportSeq + '&closYm=' + userJsonObject.closYm + '&userId=' + userJsonObject.userId;
						} else {
							jsondoUrl = WISE.Constants.context + '/report/' + WISE.Constants.pid + '/info/json.do?reportType='+self.reportType + '&fldType=' + self.fldType + '&closYm=' + userJsonObject.closYm + '&userId=' + userJsonObject.userId;
						}
						$.ajax({
							type: 'get',
							dataType: "json",
							url: jsondoUrl,
							async:false,
							beforeSend:function(){
								gProgressbar.show();
							},
							success: function(_data) {
								self.dataSourceQuantity = 0;
								self.reportType = self.reportType === "StaticAnal" ? "StaticAnalysis" : self.reportType;
								if (_data.Dashboard) {
									self.structure = _data.Dashboard;
									WISE.Context.isCubeReport = false;
									self.layoutConfig = self.structure.ReportMasterInfo.layout_config;
									if(self.reportType == "StaticAnalysis"){
										self.analysisType = self.structure.LayoutTree["LayoutTabContainer"].LayoutType;
									}
								} else {
									if(self.reportType == 'Excel' || self.reportType == 'Spread') {
										self.reportUtility.init();
										var newReport = self.reportUtility.reportInfo;
										self.structure = newReport;
										self.structureSetting(_data.ReportMasterInfo);
										
										var x2js = new X2JS();	
										var reportXml = x2js.xml_str2json(_data.ReportMasterInfo.report_xml);
										gDashboard.spreadsheetManager.setReportXml(reportXml);
									} else if(self.reportType != 'DashAny' || self.reportType != 'StaticAnalysis'){/*dogfoot 통계 분석 추가 shlim 20201102*/										
										self.structureSetting(_data.ReportMasterInfo);
										self.layoutConfig = self.structure.ReportMasterInfo.layout_config;
										self.structure.linkReport = _data.linkReport;
										self.structure.subLinkReport = _data.subLinkReport;
										self.structure.drillThru = _data.drillThru;
									} else{
										WISE.alert('set dashboard page structure json data first!');
										return;
									}
								}

								if(page[page.length - 1] === 'view.do'){
									$('#'+self.containerId).attr('id',self.containerId+"_"+WISE.Constants.pid);
								}
								var TitleVisible = typeof self.structure.Title.Visible =='undefined' ? true : false; 
								if(TitleVisible){
									var reportTabLi = $('.report-tab ul').find('li');
			                	    var reportTabLiL = reportTabLi.length;
			                	    
									var reportTab = $('.report-tab');
							        var reportTabUl = $('.report-tab ul');
							            reportTabLiL = reportTabLiL +1;
				
							        var createTab='';
							            createTab+='<li><span title="'+ self.structure.ReportMasterInfo.name +'"><em>'+ self.structure.ReportMasterInfo.name +'</em></span></li>';
							            
							        reportTab.find('ul').empty().append(createTab);
							        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
							        reportTab.find('li').width(100 / reportTabLiL + '%');
				
							        $('.report-tab ul').find('li').each(function(){
							            var createTabCustomData = $(this).find('em').text();
							        });
				
							        $(document).on('click', '.report-tab li', function(e){
							            $(this).addClass('on').siblings().removeClass('on');
							        });
									
								}
								else{
									$('#report-title').parent().remove();
									$('#contentContainer').css('height','95%');
								}

								
								self.queryByGeneratingSql = false;
								
								self.parameterFilterBar.parameterInformation = {};
								
								self.layoutManager.reportId = WISE.Constants.pid;
								self.layoutManager.dashboardid = self.id;
								self.layoutManager.containerId = self.containerId;
								self.layoutManager.init();
								
								self.dataSourceManager.dashboardid = self.id;
								self.dataSourceManager.init();
								
								self.queryHandler.dashboardid = self.id;
								self.queryHandler.init();
								
								self.fontManager.init();
								self.reportUtility.dashboardid = self.id;
								self.render();
								self.panelResizer.render();

								gDashboard.datasetMaster.setDataFromStructure();
								if(gDashboard.customParameterHandler.getArrayCalcParamInfomation().length > 0){
									gDashboard.customParameterHandler.setCalcFilterButton(undefined,true);
								}else{
									gDashboard.customParameterHandler.setCalcFilterButton(undefined,false);
								}
								if(WISE.Context.isCubeReport) {
									self.dataSourceQuantity = 0;
									if(typeof userJsonObject.userReportSeq != 'undefined' && userJsonObject.userReportSeq != '1001' && userJsonObject.userReportSeq != '') {
										WISE.Context.isCubeReport = true;
										var dataset = self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT;
										$.each(dataset, function(_i, _e) {
											if(_e.DATASRC_TYPE == 'CUBE') {
												gDashboard.dataSetCreate.cubeListInfo(_e.DATASRC_ID, 'CUBE');
											}
										});
									}
								}
								
								if(reportType != 'Excel' && reportType != 'Spread') {
									self.itemGenerateManager.dashboardid = self.id;
									self.itemGenerateManager.init();
									
									self.itemColorManager.dashboardid = self.id;
									self.itemColorManager.init();
									self.customFieldManager.init();
				                    self.scheduler.init();
									self.downloadManager.init();
									self.fieldChooser.init();
									self.fieldChooser.setFieldArea();
									self.insertItemManager.init();
									self.changeReportTypeManager.init();
								}
								self.preferences.init();
								if(self.structure.ReportMasterInfo.export_yn == 'N') {
            						$('#downloadId').css('display', 'none');
            					} else {
            						$('#downloadId').css('display', 'table');
            					}
								
								self.resize();

								$(window).resize(function() {
									self.resize();
								});
								
								self.reportUtility.init(self.structure);
								if(typeof userJsonObject.userReportSeq != 'undefined' && userJsonObject.userReportSeq != '1001' && userJsonObject.userReportSeq != '') {
									$(document).off('click', '.report-tab li');
								}
								if(!TitleVisible){
									$('#contentContainer').css('position','static');
								}
							},
							error: function(error) {
								WISE.alert('error'+ajax_error_message(error),'error');
							}
						});
					}
				});
				
				
			}
			
		}
		else{
			self.reportUtility.init();
			var newReport = self.reportUtility.reportInfo;
			self.structure = newReport;

			self.dataSourceManager.init();
			self.layoutManager.init();
			self.fontManager.init();
			
			self.queryHandler.init();
			
			self.windowSet.render();
			
            self.render();
            
            self.panelResizer.render();
            
            self.preferences.init();
            
            if(reportType !== 'Excel' && reportType !== 'Spread') {
            	self.customFieldManager.init();
                self.scheduler.init();
    			self.downloadManager.init();
    			self.fieldChooser.init();
    			self.fieldChooser.setFieldArea();
				self.insertItemManager.init();
				self.changeReportTypeManager.init();
			
				var reportTabLi = $('.report-tab ul').find('li');
				var reportTabLiL = reportTabLi.length;
				
				var reportTab = $('.report-tab');
				var reportTabUl = $('.report-tab ul');
					reportTabLiL = reportTabLiL +1;

				var createTab ='<li><span><em>새 보고서</em> </span></li>';
					
				if(gDashboard.reportType == 'DSViewer') createTab ='<li><span><em>데이터집합 뷰어</em> </span></li>'
				reportTab.find('ul').empty().append(createTab);
				reportTab.find('li').last().addClass('on').siblings().removeClass('on');
				reportTab.find('li').width(100 / reportTabLiL + '%');

				$('.report-tab ul').find('li').each(function(){
					var createTabCustomData = $(this).find('em').text();
				});
				
				if(gDashboard.reportType !== 'DSViewer')
				$(document).on('click', '.report-tab li', function(e){
					$('#cont_popup').dxPopup({
						height: 'auto',
						width: 500,
						visible: false,
						showCloseButton: false
					});
					
					var p = $('#cont_popup').dxPopup('instance');
					
					p.option({
						title: '이름 편집',
						contentTemplate: function(contentElement) {
							contentElement.append('<p>보고서 이름 </p><div id="newName_titleInput">');
							var html = '<div class="modal-footer" style="padding-bottom:0px;">';
							html += '<div class="row center">';
							html += '<a id="cont-ok-hide" href="#" class="btn positive ok-hide">확인</a>';
							html += '<a id="cont-close" href="#" class="btn neutral close">취소</a>';
							html += '</div>';
							html += '</div>';
							html += '</div>';
							contentElement.append(html);
							
							$('#cont-ok-hide').on('click', function() {
								var newName = $('#newName_titleInput').dxTextBox('instance').option('text');
								$('.report-tab ul').find('li').find('em').text(newName);
								p.hide();
							});
							$('#cont-close').on('click', function() {
								p.hide();
							});
							
							$('#newName_titleInput').dxTextBox({
								text: $('.report-tab ul').find('li').find('em').text()
							});
						}
					});
					
					p.show();
				});
				if(gDashboard.reportType != "AdHoc" && gDashboard.reportType != "StaticAnalysis" && gDashboard.reportType != "RAnalysis" && gDashboard.reportType != "DSViewer"){
					var insertType, seriesType;
					var defaultLayout = userJsonObject.userItemType ? userJsonObject.userItemType : userJsonObject.dashboardLayout;
					
					switch(defaultLayout) {
						case 'Bar':
							insertType = 'insertChart';
							seriesType = 'Bar';
							break;
						case 'StackedBar':
							insertType = 'insertChart';
							seriesType = 'StackedBar';
							break;	
						case 'FullStackedBar':
							insertType = 'insertChart';
							seriesType = 'FullStackedBar';
							break;	
						case 'Point':
							insertType = 'insertChart';
							seriesType = 'Point';
							break;	
						case 'Line':
							insertType = 'insertChart';
							seriesType = 'Line';
							break;
						case 'StackedLine':
							insertType = 'insertChart';
							seriesType = 'StackedLine';
							break;	
						case 'FullStackedLine':
							insertType = 'insertChart';
							seriesType = 'FullStackedLine';
							break;	
						case 'StepLine':
							insertType = 'insertChart';
							seriesType = 'StepLine';
							break;
						case 'Spline':
							insertType = 'insertChart';
							seriesType = 'Spline';
							break;
						case 'Area':
							insertType = 'insertChart';
							seriesType = 'Area';
							break;
						case 'StackedArea':
							insertType = 'insertChart';
							seriesType = 'StackedArea';
							break;
						case 'FullStackedArea':
							insertType = 'insertChart';
							seriesType = 'FullStackedArea';
							break;
						case 'StepArea':
							insertType = 'insertChart';
							seriesType = 'StepArea';
							break;
						case 'SplineArea':
							insertType = 'insertChart';
							seriesType = 'SplineArea';
							break;
						case 'StackedSplineArea':
							insertType = 'insertChart';
							seriesType = 'StackedSplineArea';
							break;
						case 'FullStackedSplineArea':
							insertType = 'insertChart';
							seriesType = 'FullStackedSplineArea';
							break;
						case 'Bubble':
							insertType = 'insertChart';
							seriesType = 'Bubble';
							break;
						case 'PivotGrid':
							insertType = 'insertPivotGrid';
							break;
						case 'DataGrid':
							insertType = 'insertDataGrid';
							break;
						case 'PieChart':
							insertType = 'insertPieChart';
							break;
						case 'Card':
							insertType = 'insertCard';
							break;
						case 'ChoroplethMap':
							insertType = 'insertChoroplethMap';
							break;
						case 'ParallelCoordinate':
							insertType = 'insertParallelCoordinate';
							break;
						case 'BubblePackChart':
							insertType = 'insertBubblePackChart';
							break;
						case 'WordCloudV2':
							insertType = 'insertWordCloudV2';
							break;
						case 'DendrogramBarChart':
							insertType = 'insertDendrogramBarChart';
							break;
						case 'CalendarViewChart':
							insertType = 'insertCalendarViewChart';
							break;
						case 'CalendarView2Chart':
							insertType = 'insertCalendarView2Chart';
							break;
						case 'CalendarView3Chart':
							insertType = 'insertCalendarView3Chart';
							break;
						case 'CollapsibleTreeChart':
							insertType = 'insertCollapsibleTreeChart';
							break;
						case 'Waterfallchart':
							insertType = 'insertWaterfallchart';
							break;
						case 'HistogramChart':
							insertType = 'insertHistogramChart';
							break;
						case 'BubbleD3':
							insertType = 'insertBubbleD3';
							break;
						case 'RectangularAreaChart':
							insertType = 'insertRectangularAreaChart';
							break;
						case 'TreeMap':
							insertType = 'insertTreemap';
							break;
						case 'StarChart':
							insertType = 'insertStarchart';
							break;
						case 'HeatMap':
							insertType = 'insertHeatMap';
							break;
						case 'HeatMap2':
							insertType = 'insertHeatMap2';
							break;
						case 'SynchronizedChart':
							insertType = 'insertSynchronizedChart';
							break;
						case 'CoordinateDot':
							insertType = 'insertCoordinateDot';
							break;
						case 'WordCloud':
							insertType = 'insertWordCloud';
							break;
						case 'HierarchicalEdge':
							insertType = 'insertHierarchicalEdge';
							break;
						case 'ForceDirect':
							insertType = 'insertForceDirect';
							break;
						case 'ForceDirectExpand':
							insertType = 'insertForceDirectExpand';
							break;
						case 'RangeBarChart':
							insertType = 'insertRangeBarChart';
							seriesType = 'rangeBar';
							break;
						case 'RangeAreaChart':
							insertType = 'insertRangeAreaChart';
							seriesType = 'rangeArea';
							break;
						case 'FunnelChart':
							insertType = 'insertFunnelChart';
							break;
						case 'PyramidChart':
							insertType = 'insertPyramidChart';
							break;
						case 'TimeLineChart':
							insertType = 'insertTimeLineChart';
							seriesType = 'timeline';
							break;
						case 'KakaoMap':
							insertType = 'insertKakaoMap';
							seriesType = 'kakaoMap';
							break;
						case 'KakaoMap2':
							insertType = 'insertKakaoMap2';
							seriesType = 'kakaoMap2';
							break;
						default:
							insertType = 'insertChart';
							seriesType = 'Bar';
							break;
					}
					gDashboard.insertItemManager.insertItem(insertType, seriesType);
				} else if(gDashboard.reportType == "StaticAnalysis") {
					gDashboard.insertItemManager.insertItem(userJsonObject.userAnalysisType == '' ? 'insertOnewayAnova' : userJsonObject.userAnalysisType); 
				} else if(gDashboard.reportType == 'RAnalysis'){
					gDashboard.insertItemManager.insertItem('insertTextBox');
				} else if(gDashboard.reportType == 'DSViewer'){
					gDashboard.insertItemManager.insertItem('insertDataGrid');
				} else {
					gDashboard.changeReportTypeManager.initAdhocLayout();
				}
	        }
		}
	};
	
	this.structureSetting = function(_reportMasterInfo){
		if(_reportMasterInfo.datasetJson.DATASET_ELEMENT.length == 1){
			self.structure.DataSources = {DataSource : [{ComponentName: "dataSource1",	Name: _reportMasterInfo.datasetJson.DATASET_ELEMENT[0].DATASET_NM}]}; 
		}else{
			self.structure.DataSources = [];
			$.each(_reportMasterInfo.datasetJson.DATASET_ELEMENT,function(_i,_d){				
				if(_d.DATASET_NM){
					self.structure.DataSources.push({ComponentName: "dataSource"+(_i+1), Name: _d.DATASET_NM});
				}else{
					self.structure.DataSources.push({ComponentName: "dataSource"+(_i+1), Name: ""});
				}	
			});				
		}
		
		self.structure.Title.Text = _reportMasterInfo.name;
		self.structure.ReportMasterInfo = _reportMasterInfo;
		self.structure.Layout = _reportMasterInfo.layout;
		self.structure.chartXml = _reportMasterInfo.chartJson.CHART_XML;
		self.structure.linkReport = _reportMasterInfo.linkReport;
		self.structure.subLinkReport = _reportMasterInfo.subLinkReport;
	}
	
	this.render = function() {
		var __CONFIG = WISE.widget.getCustom('common','Config');
		var runnable = function() {
			self.dataSourceManager.connect();
			self.customFieldManager.init();
			self.layoutManager.render();
			if (WISE.Constants.editmode === 'designer') {
				self.datasetDesignerSelector.render({ 
					userId: userJsonObject.userId, 
					userNo: userJsonObject.userNo, 
					reportType: gDashboard.reportType 
				});
			}			
			
			if (__CONFIG.parameter.showButton) {
				$('.cont_query').append('<button class="cont_query_bt" style="right: 90px;" onclick="alert($.toJSON(' + self.id + '.getParameterValue()));">values!</button>');
			}
			
			if (__CONFIG.searchOnStart === true) {
				if(self.structure.ReportMasterInfo.promptYn == 'Y'){
					return;
				}
				else{
				}
			} 
			else {
			}
		};
		
		if (__CONFIG.debug) {
			runnable();
		}
		else {
			try {
				runnable();
			}
			catch (e) {
				WISE.libs.Dashboard.MessageHandler.error(e);
			}
		}
	};
	/**
	 * 개인 설정 적용하는 기능
	 */
	this.applyUserSettings = function() {
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'edit.do') {
			if (userJsonObject.userReportId && userJsonObject.userReportType) {
				self.openUserReport(userJsonObject.userReportId, userJsonObject.userReportType);
			} else if (userJsonObject.userDatasetId) {
				self.openUserDataset(userJsonObject.userDatasetId, 'dataSource1');
			}
			if(userJsonObject.selectCubeId){
				WISE.Context.isCubeReport = true;
				gDashboard.dataSetCreate.cubeListInfo(userJsonObject.selectCubeId, 'CUBE');
			}
		} else if (page[page.length - 1] === 'viewer.do' || page[page.length - 1] === 'excelView.do') {
			if (userJsonObject.userViewerReportId && userJsonObject.userViewerReportType) {
				if(WISE.Constants.pid != undefined && WISE.Constants.pid == '' && WISE.Constants.pid != userJsonObject.userViewerReportId){
					self.openViewerReportGL(userJsonObject.userViewerReportId, userJsonObject.userViewerReportType);	
				}
			}
		}
	}

	this.openUserReport = function(reportId, reportType) {
		gProgressbar.show();
		try{
			gDashboard.reportType = reportType;
			if(reportType == 'AdHoc' || reportType == 'DashAny' || reportType == 'StaticAnalysis') {
				gDashboard.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'card': 0
											, 'gauge': 0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'histogramchart':0, 'parallel':0, 'choroplethMap':0
											,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0, 'comboBox':0, 'image':0
											, 'textBox':0, 'RectangularAreaChart':0, 'waterfallchart':0,'bubbled3':0
											, 'histogramchart':0,'adhocItem':0,'hierarchical':0,'bipartitechart':0
											, 'funnelchart':0, 'pyramidchart':0, 'forceDirect':0,'forceDirectExpand':0
											,'sankeychart':0,'rangebarchart':0, 'rangeareachart':0, 'timelinechart':0
											, 'bubblepackchart':0, 'wordcloudv2':0, 'dendrogrambarchart':0, 'calendarviewchart':0
											, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0, 'boxplot': 0, 'coordinateline': 0
											, 'scatterplot': 0, 'scatterplotmatrix': 0, 'radialtidytree': 0, 'historytimeline': 0, 'arcdiagram':0, 'scatterplot2': 0, 'liquidfillgauge': 0, 'kakaoMap':0, 'kakaoMap2':0
											, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0
											, 'onewayAnova':0, 'onewayAnova2':0, 'twowayAnova':0, 'pearsonsCorrelation':0, 'spearmansCorrelation':0
											, 'simpleRegression':0, 'multipleRegression':0, 'logisticRegression':0, 'multipleLogisticRegression':0
											, 'tTest':0, 'zTest':0, 'chiTest':0, 'fTest':0, 'multivariate':0};
				
				$('.content').children().remove();
				gDashboard.itemGenerateManager.dxItemBasten = [];
				gDashboard.insertItemManager.clearCanvasLayout();
				gDashboard.dataSetCreate.lookUpItems = [];
				gDashboard.dataSetCreate.infoTreeList = [];
				gDashboard.dataSourceQuantity = 0;
				gDashboard.structure.Items = {};
				gDashboard.structure.sortedItemIdx = [];
				gDashboard.dataSetCreate.subjectInfoList = [];
				WISE.Constants.pid = reportId;
				gDashboard.isNewReport = (WISE.Constants.pid == "");
				gDashboard.init();

				gDashboard.dataSetCreate.createDxItemsForOpen();
				$.each(gDashboard.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT,function(_i,_dataset){
					if(_dataset.DATASET_TYPE == "CUBE") {
						gDashboard.queryByGeneratingSql = false;
						WISE.Context.isCubeReport = true;
						setTimeout(function () {
							var lookUpIns = $("#dataSetLookUp").dxLookup('instance');
							if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
								lookUpIns = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").dxLookup('instance');
							}
							lookUpIns.option('value', gDashboard.structure.ReportMasterInfo.cube_nm);
						}, 100);
						
					}else if(_dataset.DATASET_TYPE == "DataSetCube"||_dataset.DATASET_TYPE == "DataSetDs"){
						gDashboard.dataSetCreate.openDataSetInfo(_dataset);
					}else{
						gDashboard.dataSetCreate.openDirectQueryTblColInfo(_dataset);
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
						},
						success : function(data) {
							data = JSON.parse(data);
							gDashboard.dataSetCreate.subjectInfoList[_dataset.mapid] = data.subjectInfos[0];
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
					gDashboard.customFieldManager.setCustomFieldsForOpen(_dataset.mapid);
				});
				gDashboard.FieldFilter.parameterInformation = gDashboard.parameterFilterBar.parameterInformation;
				if(gDashboard.reportType == 'AdHoc'){
					gDashboard.insertItemManager.openAdHocItem(gDashboard.structure.Layout);
					var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(gDashboard.structure.ReportMasterInfo.cube_nm);
					$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
						_item.dataSourceId = dataSrcId;
						if(_item.type === 'PIVOT_GRID'){
							_item.dragNdropController.loadAdhocItemData(_item);
							_item.dragNdropController.addSortableOptionsForOpen(_item);
						}
					});
					$.each(gDashboard.dataSourceManager.datasetInformation, function(_dsId) {
						gDashboard.customFieldManager.setCustomFieldsForOpen(_dsId);
					});
				}else{
					$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
						gDashboard.insertItemManager.openItem(_item);
					});
					$.each(gDashboard.dataSourceManager.datasetInformation, function(_dsId) {
						gDashboard.customFieldManager.setCustomFieldsForOpen(_dsId);
					});
					gDashboard.goldenLayoutManager.openInit();
				}

				if(gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
					/* DOGFOOT ktkang 고용정보원09  바로조회 기능 오류 수정  */
					gDashboard.datasetMaster.addBetParam();
				} else {
					gProgressbar.stopngo = true;
					gProgressbar.hide();
				}

			} else if(reportType == 'Excel' || reportType == 'Spread') {
				WISE.Context.isCubeReport = false;
				WISE.Constants.pid = reportId;
				gDashboard.spreadsheetManager.reportId = report_id;
				gDashboard.dataSetCreate.lookUpItems = [];
				gDashboard.dataSetCreate.infoTreeList = [];
				gDashboard.dataSourceQuantity = 0;
				gDashboard.dataSetCreate.subjectInfoList = [];
				
				gDashboard.isNewReport = (WISE.Constants.pid == "");
				gDashboard.init();
				gDashboard.dataSetCreate.createDxItemsForOpen();
				
				$.each(gDashboard.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT,function(_i,_dataset){
					if(_dataset.DATASET_TYPE == "DataSetCube"){
						gDashboard.dataSetCreate.openDataSetInfo(_dataset);
					}else{
						gDashboard.dataSetCreate.openDirectQueryTblColInfo(_dataset);
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
							},
							success : function(data) {
								data = JSON.parse(data);
								gDashboard.dataSetCreate.subjectInfoList[_dataset.mapid] = data.subjectInfos[0];
							}
						});
						gDashboard.dataSetCreate.paramTreeList[_dataset.mapid] = [];
						$.each(WISE.util.Object.toArray(_dataset.DATASET_JSON.DATA_SET.PARAM_ELEMENT.PARAM),function(_i,_e){
							gDashboard.dataSetCreate.paramTreeList[_dataset.mapid].push(_e.PARAM_NM);
						});
					});
					gDashboard.FieldFilter.parameterInformation = gDashboard.parameterFilterBar.parameterInformation;
					gDashboard.spreadsheetManager.loadDatasetInfo();
					var param = gDashboard.spreadsheetManager.getParams();
					$.ajax({
						type : 'POST',
						data : param,
						cache : false,
						contentType: "application/x-www-form-urlencoded; charset=utf-8",
						url : WISE.Constants.context + '/report/openSpreadReport.do',
						beforeSend:function(){
							gProgressbar.show();
						},
						success: function(result) {
							result = JSON.parse(result);
							if (result.message) {
								WISE.alert(result.message);
							}
						},
						complete:function(){
							gProgressbar.hide();
						}
					});
					
					$('#btn_query').off();
					$('#btn_query').on('click', function() {
						gProgressbar.show();
						gDashboard.queryByGeneratingSql = true;
						gDashboard.query();
						this.blur();
					});
				}
				$('#openPopup').dxPopup('hide');
				$('#openPopup').remove();
				
		}catch(e){
			console.error(e.stack);
			WISE.alert("보고서를 불러오는데 실패하였습니다.<br>관리자에게 문의하세요.",'error');
			gProgressbar.hide();
		}
	};
	
	this.openViewerReport = function(reportId, reportType, isSingleView) {
		gProgressbar.show();
		
		if (!isSingleView) {
			$('#reportContainer').removeClass('on');
	    	var duplicateCheck = false;
	    	$.each(self.structureBuffer,function(_i,_structure){
				if(reportId == _structure.reportId){
					duplicateCheck = true;
					return false;
				}
			});
	    	if(duplicateCheck == true){
	    		var report_id = reportId;
	    		var report_Type = reportType;
	    		var options = {
	    				buttons: {
	    					confirm: {
	    						id: 'confirm',
	    						className: 'blue',
	    						text: '확인',
	    						action: function() { 
	    							$AlertPopup.hide();
	    							$('#report'+report_id).trigger('click');
	    							// 2019.12.24 수정자 : mksong 뷰어 treeopen ui 수정 DOGFOOT
	    							if($('.reportListArea').hasClass('on')){
	    								$('.tree-view').click();
//	    								$('#treeopen').removeClass('on');
//	    								$('.reportListArea').removeClass('on');
	    								//gDashboard.parameterHandler.resize();
	    							}
	    							// 2019.12.24 수정자 : mksong 뷰어 treeopen ui 수정 DOGFOOT
	    							//20210420 AJKIM 뷰어 대시보드 데이터 항목 수정 추가 dogfoot
	    							if(report_Type != 'DSViewer' && report_Type != 'AdHoc' && !(userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && report_Type == 'DashAny')){
	    								$('.data-view').css('display','none');
	    								$('.activeChangeLayout').css('display','none');
	    								/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
	    								$('.design').css('display','none');
	    								$('.filter-bar.viewer').css({paddingLeft:'40px'});
	    							}
									else {
	    								/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
										/* 2021-04-30 데이터항목 visible 권한 처리 */
										if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
											$('.data-view').css('display','block');
										}
										else {
											$('.data-view').css('display','none');
										}
	    								if(report_Type == 'AdHoc'){
	    									$('.activeChangeLayout').css('display','block');
	    									$('.design').css('display','block');
	    								}
	    								else{
	    									$('.activeChangeLayout').css('display','none');
	    									$('.design').css('display','none');
	    								}
	    									
	    								//$('.design').css('display','block');
	    								$('.filter-bar.viewer').css({paddingLeft:'79px'});
	    							}
	    							return false;
	    						}
	    					}
	    				}
	    		};
	    		
	    		gProgressbar.setStopngoProgress(true);
	    		gProgressbar.hide();
				WISE.alert('해당 보고서는 이미 열려있습니다!', '', options);
	    		return false;
	    	}
			if(self.tabN == self.maxReportOpen){
				WISE.alert('보고서는 최대 '+self.maxReportOpen+'개 까지만 열 수 있습니다!');
				gProgressbar.hide();
	    		return false;
			}
			$('div[report_id]').each(function(_i,_container){
	        	if($(_container).attr('report_id') == reportId){
	        		$(_container).css('display','block');
	        	}else{
	        		$(_container).css('display','none');
	        	}
	        });
		}else{
			//20210420 AJKIM 뷰어 대시보드 데이터 항목 수정 추가 dogfoot
			if (report_Type != 'DSViewer' && report_Type != 'AdHoc' && !(userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && report_type == 'DashAny')){
				$('.data-view').css('display','none');
	    		//2020.01.22 MKSONG 비정형 아이콘 활성화 DOGFOOT
				$('.activeChangeLayout').css('display','none');
				/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
				$('.design').css('display','none');
			}
		}
		$('#reportContainer').append('<div id="contentContainer_'+reportId+'" class="contentContainer reportChangeClass" report_id="'+reportId+'"></div>');
		if($(window).width() <= 640){
			$('#contentContainer_'+reportId).css('overflow','auto');
		}
		self.isNewReport = (reportId == "");
		
		$.ajax({
			type: 'get',
			dataType: "json",
			url: WISE.Constants.context + '/report/' + reportId + '/info/json.do?reportType=' + self.reportType + '&fldType=' + self.fldType + '&closYm=' + userJsonObject.closYm + '&userId=' + userJsonObject.userId,
			beforeSend:function() {
				gProgressbar.show();
			},
			success: function(_data) {
				self.dataSourceQuantity = 0;
				self.tabN++;
				if (_data.Dashboard) {
					WISE.Context.isCubeReport = false;
					self.structure = _data.Dashboard;
					self.structureBuffer.push({structure : _data.Dashboard, reportId:reportId,reportType:self.reportType,schedulePath:self.schdulePath});
					self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
					self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
//					self.parameterHandler = new WISE.libs.Dashboard.ParameterHandler();
					self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
					self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
					self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
					self.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'parallel':0
										, 'parallel':0, 'choroplethMap':0,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0
										, 'comboBox':0, 'image':0, 'textBox':0, 'RectangularAreaChart':0, 'waterfallchart':0
										,'bubbled3':0, 'histogramchart':0, 'card':0, 'bubble':0,'adhocItem':0,'hierarchical':0
										,'bipartitechart':0, 'funnelchart':0, 'pyramidchart':0,'forceDirect':0,'forceDirectExpand':0
										,'sankeychart':0,'rangebarchart':0, 'rangeareachart':0, 'timelinechart':0, 'bubblepackchart':0
										, 'wordcloudv2':0, 'dendrogrambarchart':0, 'calendarviewchart':0
										, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0, 'boxplot': 0, 'coordinateline': 0, 'scatterplot': 0, 'scatterplotmatrix': 0, 'radialtidytree': 0, 'historytimeline': 0, 'arcdiagram':0,'scatterplot2': 0
										, 'liquidfillgauge': 0, 'kakaoMap':0, 'kakaoMap2':0
										, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0
										, 'onewayAnova':0, 'onewayAnova2':0, 'twowayAnova':0, 'pearsonsCorrelation':0, 'spearmansCorrelation':0
										, 'simpleRegression':0, 'multipleRegression':0, 'logisticRegression':0, 'multipleLogisticRegression':0
										, 'tTest':0, 'zTest':0, 'chiTest':0, 'fTest':0, 'multivariate':0};
					self.dataSourceQuantity = 0;
					
					WISE.Constants.pid = reportId;
					self.isNewReport = (WISE.Constants.pid == "");
					self.dataSetCreate = new WISE.libs.DataSet();
					
				} else if(self.reportType == 'AdHoc'){
					self.structure = _data;
					self.structureBuffer.push({structure : _data, reportId:reportId,reportType:self.reportType,schedulePath:self.schedulePath});
					self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
					self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
//					self.parameterHandler = new WISE.libs.Dashboard.ParameterHandler();
					self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
					self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
					self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
					self.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'parallel':0
										, 'choroplethMap':0,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0, 'comboBox':0
										, 'image':0, 'textBox':0, 'RectangularAreaChart':0, 'waterfallchart':0,'bubbled3':0
										, 'histogramchart':0, 'card':0, 'bubble':0,'adhocItem':0,'hierarchical':0
										,'bipartitechart':0,'funnelchart':0, 'pyramidchart':0,'forceDirect':0
										,'forceDirectExpand':0,'sankeychart':0,'rangebarchart':0, 'rangeareachart':0
										, 'timelinechart':0, 'bubblepackchart':0, 'wordcloudv2':0, 'dendrogrambarchart':0
										, 'calendarviewchart':0, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0
										, 'boxplot': 0, 'coordinateline': 0, 'scatterplot': 0, 'scatterplotmatrix': 0, 'radialtidytree': 0, 'historytimeline': 0, 'arcdiagram':0, 'scatterplot2': 0, 'liquidfillgauge': 0, 'kakaoMap':0, 'kakaoMap2':0
										, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0
										, 'onewayAnova':0, 'onewayAnova2':0, 'twowayAnova':0, 'pearsonsCorrelation':0, 'spearmansCorrelation':0
										, 'simpleRegression':0, 'multipleRegression':0, 'logisticRegression':0, 'multipleLogisticRegression':0
										, 'tTest':0, 'zTest':0, 'chiTest':0, 'fTest':0, 'multivariate':0};
					self.dataSourceQuantity = 0;
					WISE.Constants.pid = reportId;
					self.isNewReport = (WISE.Constants.pid == "");
					self.dataSetCreate = new WISE.libs.DataSet();
					
					self.customFieldCalculater.meta = self.structure;
					
					if(self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT.length > 0 && self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT[0].DATASET_TYPE == 'CUBE') {
						self.structure.DataSources = {DataSource:[{ComponentName: "dataSource1", Name:self.structure.ReportMasterInfo.cube_nm}]};
						WISE.Context.isCubeReport = true;
					} else {
						self.structure.DataSources = {DataSource:[{ComponentName: "dataSource1", Name:self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT["0"].DATASET_NM}]};
					}
					
				} else if(reportType == 'Excel' || reportType == 'Spread'){
					WISE.Context.isCubeReport = false;
					self.structure = _data;
					self.structureBuffer.push({structure : _data, reportId:reportId,reportType:reportType,schedulePath:self.schedulePath});
					self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
					self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
					self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
					self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
					self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
					self.dataSourceQuantity = 0;
					
					WISE.Constants.pid = reportId;
					self.isNewReport = (WISE.Constants.pid == "");
					
					self.structure.DataSources = {DataSource:[{ComponentName: "dataSource1", Name:self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT["0"].DATASET_NM}]}
					
				} else {
					WISE.alert('set dashboard page structure json data first!');
					return;
				}
				var TitleVisible;
				if(reportType == 'AdHoc' || reportType == 'Spread'|| reportType == 'Excel'){
					TitleVisible = true;
				}else{
					if(self.structure.Title){
						TitleVisible = typeof self.structure.Title.Visible =='undefined' ? true : false; 
					}
				}
			
				
				if(TitleVisible){
					var reportTabLi = $('.report-tab ul').find('li');
            	    var reportTabLiL = reportTabLi.length;
            	    
					var reportTab = $('.report-tab');
			        var reportTabUl = $('.report-tab ul');
			        reportTabLiL = reportTabLiL +1;

			        var createTab='';
			        createTab+='<li report_id='+reportId+' id = "report'+reportId+'">';
			        createTab+='<span title="'+ self.structure.ReportMasterInfo.name +'">';
			        createTab+='<em>'+ self.structure.ReportMasterInfo.name +'</em>'
			        createTab+='<a href="#" class="gui close">close</a>';
			        createTab+='</span>'
			        createTab+='</li>';
			        
			        reportTab.find('ul').append(createTab);
			        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
			        reportTab.find('li').width(100 / reportTabLiL + '%');

			        $('.report-tab ul').find('li').each(function(){
			            var createTabCustomData = $(this).find('em').text();
			        });
			        
			        $(document).off('click', '.report-tab li');
			        $(document).on('click', '.report-tab li', function(e){
			            $(this).addClass('on').siblings().removeClass('on');
			            var focusId;
			            $.each($('.report-tab .on'),function(_i,_onClass){
			            	focusId = $(_onClass).attr('report_id');
			            });
			            $.each($('#reportContainer').children('.reportChangeClass'),function(_i,_container){
			            	if($(_container).attr('report_id') == focusId){
			            		$(_container).css('display','block');
			            		$.each(self.structureBuffer,function(_i,_e){
			            			if(_e.reportId == focusId){
			            				self.structure = _e.structure;
			            				reportType = _e.reportType;
			            				
			            				if(gDashboard.structure.Items.TabContainer != undefined && reportType == 'DashAny') {
			            					gDashboard.hasTab = true;
			            				}else{
			            					gDashboard.hasTab = false;
			            				}
			            				WISE.Constants.pid = focusId;
			            				self.dataSourceManager.init();
			            				self.itemGenerateManager.dxItemBasten= [];
			            				self.itemGenerateManager.init();
			            				$.each(self.itemGenerateBuffer,function(_j,_generate){
			            					if(_generate.reportId == focusId){
			            						self.itemGenerateManager.dxItemBasten = _generate.dxItemBasten;
			            						return false;
			            					}
			            				});
			            				$.each(self.LayoutManagerBuffer,function(_j,_layout){
			            					if(_layout.reportId == focusId){
			            						self.layoutManager.itemidBasten = _layout.itemidBasten;
			            						return false;
			            					}
			            				})
		            					self.resize();
			            			
			            				self.parameterFilterBar.toggleParameter(focusId);
			            			}
			            		});
			            	}else{
			            		$(_container).css('display','none');
			            	}
			            });
			            
			          //20210420 AJKIM 뷰어 대시보드 데이터 항목 수정 추가 dogfoot
						if(gDashboard.reportType == 'AdHoc' || gDashboard.reportType == 'DSViewer' || (userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && gDashboard.reportType == 'DashAny')){
							/* 2021-04-30 데이터항목 visible 권한 처리 */
							if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
								$('.data-view').css('display', 'block');	
							}
							else {
								$('.data-view').css('display', 'none');	
							}
							//2020.01.22 MKSONG 비정형 아이콘 활성화 DOGFOOT
							if(gDashboard.reportType == 'AdHoc'){
								$('.activeChangeLayout').css('display','block');
								$('.design').css('display','block');
							}
							else{
								$('.activeChangeLayout').css('display','none');
								$('.design').css('display','none');
							}
							//$('.filter-bar.viewer').css({paddingLeft:'79px'});
							
							$.each($('.reportChangePanel'),function(_i,_panel){
								if($(_panel).attr('report_id') == focusId){
									$(_panel).css('display','block');
								}else{
									$(_panel).css('display','none');
								}
							});	
						}else{
							/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
							$('.data-view').css('display','none');
							$('.activeChangeLayout').css('display','none');
							$('.design').css('display','none');
							$('.filter-bar.viewer').css({paddingLeft:'40px'});
							$('.reportChangePanel').css('display','none');
						}
			        });
				}

				gDashboard.reportUtility.activeButton();
				self.layoutManager.reportId = reportId;
				self.layoutManager.dashboardid = self.id;
				self.layoutManager.containerId = self.containerId;
				self.layoutManager.init();
				
				self.dataSourceManager.dashboardid = self.id;
				self.dataSourceManager.init();
				
				self.customFieldManager.init();
				
				self.queryHandler.dashboardid = self.id;
				self.queryHandler.init();
				
				self.itemGenerateManager.dashboardid = self.id;
				self.itemGenerateManager.init();
				gDashboard.layoutManager.viewsectionLayout(gDashboard.structure.ReportMasterInfo.id);
				gDashboard.layoutManager.viewactivateBasicFunction();
				
				self.reportUtility.dashboardid = self.id;
				
				self.itemGenerateBuffer.push({reportId:reportId, dxItemBasten : self.itemGenerateManager.dxItemBasten});
				self.LayoutManagerBuffer.push({reportId:reportId, itemidBasten : self.layoutManager.itemidBasten});
				
				self.parameterHandler.render();
				
				self.fieldChooser.init();
				self.fieldChooser.setFieldArea();
				
				if($('#treeopen').hasClass('on') || $('.reportListArea').hasClass('on')){
					$('.reportListArea').removeClass('on')
					$('.viewr-ui-option .tree-view').removeClass('on');
					$('#reportContainer').css({paddingLeft:'0px'});
				}
				if ($('#reportContainer').hasClass('on')) {
					$('#reportContainer').removeClass('on');
				}
//
				
				try {
					if(reportType == 'AdHoc'){
						$('.data-view').css('display','block');
						if(gDashboard.isSingleView && userJsonObject.dataScroll == 'Y' && !$('.data-view').hasClass('on')) {
							$('.data-view').click();
						}
						$('.activeChangeLayout').css('display','block');
						$('.design').css('display','block');
						
						gDashboard.customFieldManager.init();
						gDashboard.structure.Layout = gDashboard.structure.ReportMasterInfo.layout;
						self.itemGenerateManagerAdhocInit(gDashboard.structure.ReportMasterInfo.layout,gDashboard.structure.ReportMasterInfo.id);
						var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(gDashboard.structure.ReportMasterInfo.cube_nm);
						$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
							_item.dataSourceId = dataSrcId;
							if(_item.type === 'PIVOT_GRID'){
								_item.dragNdropController.loadAdhocItemData(_item);
								_item.dragNdropController.addSortableOptionsForOpen(_item);
							}
						});
						$.each(gDashboard.dataSourceManager.datasetInformation, function(_dsId) {
							gDashboard.customFieldManager.setCustomFieldsForOpen(_dsId);
						});
					}
					else if(reportType == 'DashAny' || reportType == 'StaticAnalysis' || reportType == 'DSViewer'){/*dogfoot 통계 분석 추가 shlim 20201102*/
						// 2019.12.24 수정자 : mksong 뷰어 treeopen ui 수정 DOGFOOT   
						if(!(userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && report_type == 'DashAny') && reportType !== 'DSViewer'){
							$('.data-view').css('display','none');
							//2020.01.22 MKSONG 비정형 아이콘 활성화 DOGFOOT
							$('.activeChangeLayout').css('display','none');
							/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
							$('.design').css('display','none');
						}
						else {
							/* 2021-04-30 데이터항목 visible 권한 처리 */
							if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
								$('.data-view').css('display','block');
							}
							else {
								$('.data-view').css('display','none');
							}
							//2020.01.22 MKSONG 비정형 아이콘 활성화 DOGFOOT
							if(reportType == 'AdHoc'){
								$('.activeChangeLayout').css('display','block');
								$('.design').css('display','block');
							}
							else{
								$('.activeChangeLayout').css('display','none');
								$('.design').css('display','none');
							}
						}
						
						$('.filter-bar.viewer').css({paddingLeft:'40px'});
						try {
							self.render();
							//2020.02.18 MKSONG 패널 리사이즈 기능 추가 DOGFOOT
							self.panelResizer.render();
						} catch (e) {
							/* DOGFOOT hsshim 1231
							 * 오류 스텍 보기
							 */
							console.error(e.stack);
							//2020.01.21 mksong 경고창 타입 지정 dogfoot
							WISE.alert('보고서 불러오기 실페 했습니다.','error');
						}
					} else if (reportType == 'Spread' || reportType == 'Excel'){
						gProgressbar.show();
						var page = (WISE.Constants.editmode == 'viewer') ? 'viewer' : 'index';
						
						var frame_header = 
							'<div class="lm_header">' +
								'<ul class="lm_tabs">' +
									'<li class="lm_tab cont_box_top_tit lm_active" title="스프레드" style="border: none">' +
									'	<i class="lm_left"></i>' +
									'	<span class="lm_title">스프레드 시트</span>' +
									'	<div class="lm_close_tab"></div>' +
									'</li>' +
								'</ul>'+
								'<ul class="cont_box_top_icon" id="spread-top-icon">' +
								'</ul>' +
							'</div>';
						
						$('#' + self.containerId + '_' + reportId).append(frame_header);
						
						var new_frame = $('<iframe id="ss'+reportId+'" style="width:100%; height: 100%" src="'+WISE.Constants.context+'/resources/spreadJS/designer_sourceV13/index/'+page+'.html"></iframe>');
						new_frame.appendTo('#' + self.containerId + '_' + reportId);
						
						var x2js = new X2JS();	
						var reportXml = x2js.xml_str2json(gDashboard.structure.ReportMasterInfo.report_xml);
						gDashboard.spreadsheetManager.setReportXml(reportXml);	
						gDashboard.spreadsheetManager.renderButtons(reportId);						
						gDashboard.spreadsheetManager.reportId = reportId;						
						initStart(true);
						function initStart(counter){
							 if(counter){
								 setTimeout(function(){
									 if(gDashboard.spreadsheetManager.spreadJS){
										gDashboard.spreadsheetManager.fileOpenFromServer();	
										counter=false;
									 }else{
										 gDashboard.spreadsheetManager.init();
									 }
									 initStart(counter);
								 }, 200);
							 }
						}		         
						
						$('#btn_query').off('click').on('click', function() {
							gProgressbar.show();
							gDashboard.queryByGeneratingSql = true;
							gDashboard.itemGenerateManager.clearTrackingConditionAll();
							self.query();
							this.blur();
						});
					
						return;
					}
				} catch (e) {
					/* DOGFOOT hsshim 1231
					 * 오류 스텍 보기
					 */
					console.error(e.stack);
				}
				
				self.itemGenerateBuffer.push({reportId:reportId, dxItemBasten : self.itemGenerateManager.dxItemBasten});
				self.LayoutManagerBuffer.push({reportId:reportId, itemidBasten : self.layoutManager.itemidBasten});
				/*
				 * 2019.12.16 수정자 : cshan 뷰어 파라미터 2번 그리는부분 제거 dogfoot
				 * */
//				self.parameterHandler.render();
				/* DOGFOOT ktkang 리포트 다운로드 권한 구현  20201109 */
				if(self.structure.ReportMasterInfo.export_yn == 'N') {
					$('#dl_viewer_report').css('display', 'none');
				} else {
					$('#dl_viewer_report').css('display', 'block');
				}
				
				self.resize();
				$(window).resize(function() {
					self.resize();
				});
				
				self.reportUtility.init(self.structure);
//				self.folderList();
//				self.refreshFolderList();
				/* DOGFOOT hsshim 1226
				 * 
				 */
				if (isSingleView) {
					$('.filter-bar').css({paddingLeft:'39px'});
				}
				
				//self.parameterHandler.resize();
				$('#btn_query').off();
				$('#btn_query').on('click', function() {
					//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
					gProgressbar.show();
					if(WISE.Constants.editmode == 'viewer' && gDashboard.hasTab) {
						gDashboard.itemGenerateManager.selectedTabList = [];
						gDashboard.tabQuery = true;
					}
					gDashboard.queryByGeneratingSql = true;
					gDashboard.itemGenerateManager.clearTrackingConditionAll();
					/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
					gDashboard.itemGenerateManager.clearItemData();
					self.query();
					this.blur();
				});
				
				gProgressbar.show();
				try {
					/* DOGFOOT ktkang 보고서 불러 올 때 조회 안하는 기능 추가 수정  20201015 */
					if(gDashboard.structure.ReportMasterInfo.direct_view == 'Y') {
						/* DOGFOOT ktkang 고용정보원09  바로조회 기능 오류 수정  */
						gDashboard.datasetMaster.addBetParam();
					} else {
						gProgressbar.stopngo = true;
						gProgressbar.hide();
					}
				} catch (e) {
					/* DOGFOOT hsshim 1231
					 * 오류 스텍 보기
					 */
					console.error(e.stack);
				}
				// gProgressbar.hide();
				
				if(gDashboard.structure.linkReport) {
					$('#linkReportList').empty();
					//2020.01.22 MKSONG 연결보고서 아이콘 활성화 DOGFOOT
					$('.connectR').attr('style','opacity: 1 !important');
    				$.each(gDashboard.structure.linkReport,function(_i,_o){
    					$('#linkReportList').append('<li><a id=' + _o.target_id + ' href="#">' + _o.target_nm + '</a></li>');
    					
    					$('#' + _o.target_id).click(function(e) { 
    						
    						var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
    						
    						var linkReportMeta = gDashboard.structure.linkReport;
    						var linkJsonMatch = {};
    						var target_id;
    						
    						$.each(linkReportMeta,function(_i,_linkMeta){
    							if(_linkMeta.link_type == 'LP')
    							{
    								target_id = _linkMeta.target_id;
    								if(typeof _linkMeta.linkJson.LINKDATA_XML != 'undefined') {
    									$.each(_linkMeta.linkJson.LINKDATA_XML.ARG_DATA,function(_j,_linkJson){
        									linkJsonMatch[_linkJson] = paramListValue[_linkJson].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson].value;
        								});
    								} else {
    									linkJsonMatch = [];
    								}
    								
    							}
    						});
    						
    						var locationStr = "";
    						if(linkJsonMatch != []) {
    							$.each(linkJsonMatch,function(_key,_val){
    								// 2020.02.13 mksong 연결보고서 VALUE값 암호화 DOGFOOT
    								locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(encodeURIComponent(_val))+'&';
    							});
    							locationStr = (locationStr.substring(0,locationStr.length-1));

    							if(locationStr.length > 1) {
    								locationStr = "&" + locationStr;
    							}
    						}
    						var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_o.target_id+'/viewer.do?USER='+userJsonObject.userId+'&assign_name=bWVpcw==' + locationStr;
    						window.open(urlString);
    					});
        			});
    			}else{
	    			//2020.01.22 MKSONG 연결보고서 아이콘 활성화 DOGFOOT
    				$('.connectR').css('opacity','0.7');
    			}
    			
    			if(gDashboard.structure.subLinkReport) {
    				$.each(gDashboard.structure.subLinkReport,function(_i,_ee){
    					$('#' + _ee.target_item + '_' + _ee.arg_id + '_item_title').click(function(e) { 
    						if(_ee.target_item +'_' + _ee.arg_id +'_item_title' == e.toElement.id && _ee.link_type == 'LP'){
    							
    							var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
    							
    							target_id = _ee.target_id;

    							linkJsonMatch = {};

    							if(!(typeof _ee.linkJson == "object" && !Object.keys(_ee.linkJson).length)) {
    								$.each(_ee.linkJson.LINK_XML_PARAM.ARG_DATA,function(_j,_linkJson){
    									if(!Array.isArray(_ee.linkJson.LINK_XML_PARAM.ARG_DATA)) {
    										linkJsonMatch[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.PK_COL_NM] = encodeURI(paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value);
    									} else if(_linkJson.PK_COL_NM) {
    										linkJsonMatch[_linkJson.PK_COL_NM] = encodeURI(paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value);
    									}
    								});
    							}

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
        			});
    			}
			}
		});
	};

	/* DOGFOOT hsshim 1226
 	 * 불러오기 함수 작업
 	 */
	/**
	 * (GoldenLayout) Open viewer report with corresponding reportId and reportType.
	 */
	this.openViewerReportGL = function(reportId, reportType, isSingleView) {
		self.isOpened = false;
		self.isSingleView = isSingleView;
		if(isSingleView && userJsonObject.siteNm == 'KAMKO'){
			$('.filter-bar').css('padding-left', '0px');
			$('.filter-bar').find('.filter-item').css('width', 'calc(100% - 150px)');
		}
		gProgressbar.show();
		$('#queryCancel').dxButton({
			text:"작업 취소",
			type:'default',
			async: false,
			onClick:function(_e){
				//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();
				$.ajax({
					type : 'post',
					cache : false,
					url : WISE.Constants.context + '/report/cancelqueries.do',
					complete: function(_e) {
						gProgressbar.cancelQuery();
//						gProgressbar.hide();
					}
				});
			}
		});
		if (!isSingleView) {
			$('#reportContainer').removeClass('on');
	    	var duplicateCheck = false;
	    	$.each(self.structureBuffer,function(_i,_structure){
				if(reportId == _structure.reportId){
					duplicateCheck = true;
					return false;
				}
			});
	    	if(duplicateCheck == true){
	    		//2020.01.22 KERIS MKSONG 열린보고서 포커스 오류 수정 DOGFOOT
	    		var report_id = reportId;
	    		var report_Type = reportType;
	    		var options = {
	    				buttons: {
	    					confirm: {
	    						id: 'confirm',
	    						className: 'blue',
	    						text: '확인',
	    						action: function() { 
	    							$AlertPopup.hide();
	    							$('#report'+report_id).trigger('click');
	    							
	    							if(gDashboard.structure.linkReport.length != 0){
	    								$('.connectR').attr('style','opacity: 1 !important');
	    								/* DOGFOOT ktkang 뷰어에서 연결보고서 없을 때 숨김  20200525 */
	    								$('.connectR').css('display', 'block');
	    							}else{
	    								$('.connectR').attr('style','opacity: .7 !important');
	    								$('.connectR').css('display', 'none');
	    			    			}
	    							
	    							// 2019.12.24 수정자 : mksong 뷰어 treeopen ui 수정 DOGFOOT
	    							if($('.reportListArea').hasClass('on')){
//	    								$('#treeopen').removeClass('on');
//	    								$('.reportListArea').removeClass('on');
	    								//gDashboard.parameterHandler.resize();
	    							}
	    							// 2019.12.24 수정자 : mksong 뷰어 treeopen ui 수정 DOGFOOT
	    							if(report_Type != 'DSViewer' && report_Type != 'AdHoc' && !(userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && report_Type == 'DashAny')){
	    								//20210906 AJKIM 확인 버튼 누를 시 보고서 레이아웃 깨지는 오류 수정 dogfoot
	    								gDashboard.goldenLayoutManager[report_id].canvasLayout.updateSize($("#contentContainer_"+report_id).width(),$("#contentContainer_"+report_id).height());
	    								$('.data-view').css('display','none');
	    								$('.activeChangeLayout').css('display','none');
	    								/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
	    								$('.design').css('display','none');
	    								//20210726 AJKIM 열린 보고서 열 때 필터 버튼 오류 수정 dogfoot
	    								//$('.filter-bar.viewer').css({paddingLeft:'40px'});
	    							}else{
	    								//20210906 AJKIM 확인 버튼 누를 시 보고서 레이아웃 깨지는 오류 수정 dogfoot
	    								gDashboard.goldenLayoutManager[report_id].canvasLayout.updateSize($("#contentContainer_"+report_id).width(),$("#contentContainer_"+report_id).height());
	    								/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
										/* 2021-04-30 데이터항목 visible 권한 처리 */
										if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
	    									$('.data-view').css('display','block');
										}
										else {
											$('.data-view').css('display','none');
										}
										if(report_Type == 'AdHoc'){
	    									$('.activeChangeLayout').css('display','block');
	    									$('.design').css('display','block');
	    								}
	    								else{
	    									$('.activeChangeLayout').css('display','none');
	    									$('.design').css('display','none');
	    								}
	    								//$('.filter-bar.viewer').css({paddingLeft:'79px'});
	    							}
	    							return false;
	    						}
	    					}
	    				}
	    		};
	    		
	    		gProgressbar.setStopngoProgress(true);
	    		gProgressbar.hide();
				WISE.alert('해당 보고서는 이미 열려있습니다!','', options);
				//2020.01.22 KERIS MKSONG 열린보고서 포커스 오류 수정 끝 DOGFOOT
				// WISE.alert('');
	    		return false;
	    	}
			if(self.tabN == self.maxReportOpen){
				WISE.alert('보고서는 최대 '+self.maxReportOpen+'개 까지만 열 수 있습니다!');
				gProgressbar.hide();
	    		return false;
			}
//	    	if(self.isOpened == false){
			$('div[report_id]').each(function(_i,_container){
	        	if($(_container).attr('report_id') == reportId){
	        		$(_container).css('display','block');
	        	}else{
	        		$(_container).css('display','none');
	        	}
	        });
		}else{
			//2020.01.22 KERIS MKSONG 비정형 아이콘 활성화 수정 DOGFOOT
			//20210420 AJKIM 뷰어 대시보드 데이터 항목 수정 추가 dogfoot
			if(reportType != 'AdHoc'){
				if(!(userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && reportType == 'DashAny') && reportType != 'DSViewer'){
					$('.data-view').css('display','none');
					//2020.01.22 MKSONG 비정형 아이콘 활성화 DOGFOOT
					$('.activeChangeLayout').css('display','none');
					/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
					$('.design').css('display','none');
					/*dogfoot shlim 뷰어 디자이너 바로가기 기능 구현 20210614*/
					$('.design').off('click').on('click',function(){
						/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200219 */
//						window.open(window.location.href.substring(0,window.location.href.indexOf("/report")+8)+"/edit.do");
						$('#reportId').val(gDashboard.structure.ReportMasterInfo.id);
						//DOGFOOT MKSONG KERIS CUBEID 함께 전송 20200219
						$('#cubeId').val(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.dxItemBasten[0].dataSourceId].DATASRC_ID);
						
						$('#editForm').submit();
					});
				}
				else {
					/* 2021-04-30 데이터항목 visible 권한 처리 */
					if(self.structure){
					    if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
							$('.data-view').css('display','block');
						}
					    else {
							$('.data-view').css('display','none');
						}
					}
					else {
						$('.data-view').css('display','none');
					}
					//2020.01.22 MKSONG 비정형 아이콘 활성화 DOGFOOT
					$('.activeChangeLayout').css('display','none');
					if(typeof self.authPublishArr[WISE.Constants.pid] != 'undefined'){
						if(self.authPublishArr[WISE.Constants.pid] == 'Y'){
						 $('.design').css('display','block');		
						}else{
							$('.design').css('display','none');
						}
					}else{
						$('.design').css('display','none');
					}
				}
			}else{
				/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
				$('.data-view').css('display','block');
				$('.activeChangeLayout').css('display','block');
				$('.design').css('display','block');
				$('.design').off('click').on('click',function(){
					/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200219 */
//					window.open(window.location.href.substring(0,window.location.href.indexOf("/report")+8)+"/edit.do");
					$('#reportId').val(gDashboard.structure.ReportMasterInfo.id);
					//DOGFOOT MKSONG KERIS CUBEID 함께 전송 20200219
					$('#cubeId').val(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.dxItemBasten[0].dataSourceId].DATASRC_ID);
					
					$('#editForm').submit();
				});
			}
		}
		$('#reportContainer').append('<div id="contentContainer_'+reportId+'" class="contentContainer reportChangeClass" report_id="'+reportId+'"></div>');
		if($(window).width() <= 640){
			$('#contentContainer_'+reportId).css('overflow','auto');
		}
		self.isNewReport = (reportId == "");
		
		$.ajax({
			type: 'get',
			dataType: "json",
			//2020.01.22 KERIS MKSONG 보고서 열기 타입 지정 오류 수정 DOGFOOT
			url: WISE.Constants.context + '/report/' + reportId + '/info/json.do?reportType=' + reportType + '&fldType=' + (self.fldType? self.fldType: 'PUBLIC') + '&closYm=' + userJsonObject.closYm + '&userId=' + userJsonObject.userId,
			async:false,
			beforeSend:function() {
				gProgressbar.show();
				$('#queryCancel').dxButton({
					text:"작업 취소",
					type:'default',
					onClick:function(_e){
						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
						gProgressbar.setStopngoProgress(true);
						gProgressbar.hide();
						$.ajax({
							type : 'post',
							cache : false,
							async: false,
							url : WISE.Constants.context + '/report/cancelqueries.do',
							complete: function(_e) {
								gProgressbar.cancelQuery();
//								gProgressbar.hide();
							}
						});
					}
				});
			},
			success: function(_data) {
				//2020.02.04 mksong itemQuantity 내용 추가 dogfoot			
				self.dataSourceQuantity = 0;
				self.tabN++;
				gDashboard.finishParams = 0;
			//2020.01.22 MKSONG 보고서 열기 타입 지정 오류 수정 DOGFOOT				
			/*dogfoot 통계 분석 추가 shlim 20201102*/
				gDashboard.reportType = reportType = reportType == "StaticAnal" ? "StaticAnalysis" : reportType;
				if (_data.Dashboard) {
					WISE.Context.isCubeReport = false;
					self.structure = _data.Dashboard;
					/*dogfoot 보고서 레이아웃 설정 뷰어불러오기 수정 shlim 20200821*/
					self.layoutConfig[reportId] = self.structure.ReportMasterInfo.layout_config
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
					$.each(self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT,function(_i,_dataset){
    					//2020.01.31 MKSONG dataSourceId 지정 DOGFOOT
						if(_dataset.DATASET_TYPE == "CUBE") {
							WISE.Context.isCubeReport = true;
							gDashboard.queryByGeneratingSql = false;
						} else {
							WISE.Context.isCubeReport = false;
						}
					});
					/*dogfoot 통계 분석 추가 shlim 20201102*/
					if(self.reportType == "StaticAnalysis"){
						self.analysisType = self.structure.LayoutTree["LayoutTabContainer"].LayoutType;
					}
					self.structureBuffer.push({structure : _data.Dashboard, reportId:reportId,reportType:self.reportType,schedulePath:self.schedulePath});
					self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
					self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
//					self.parameterHandler = new WISE.libs.Dashboard.ParameterHandler();
					self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
					self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
					self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
					self.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'parallel':0
										, 'parallel':0, 'choroplethMap':0,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0
										, 'comboBox':0, 'image':0, 'textBox':0, 'RectangularAreaChart':0, 'waterfallchart':0
										,'bubbled3':0, 'histogramchart':0, 'card':0, 'bubble':0,'adhocItem':0,'hierarchical':0
										,'bipartitechart':0,'funnelchart':0, 'pyramidchart':0,'forceDirect':0,'forceDirectExpand':0
										,'sankeychart':0,'rangebarchart':0, 'rangeareachart':0, 'timelinechart':0, 'bubblepackchart':0
										, 'wordcloudv2':0, 'dendrogrambarchart':0, 'calendarviewchart':0
										, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0, 'boxplot': 0, 'coordinateline': 0, 'scatterplot': 0, 'scatterplotmatrix': 0, 'radialtidytree': 0, 'historytimeline': 0, 'arcdiagram':0, 'scatterplot2': 0
										, 'liquidfillgauge': 0, 'kakaoMap':0, 'kakaoMap2':0, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0
										, 'onewayAnova':0, 'onewayAnova2':0, 'twowayAnova':0, 'pearsonsCorrelation':0, 'spearmansCorrelation':0
										, 'simpleRegression':0, 'multipleRegression':0, 'logisticRegression':0, 'multipleLogisticRegression':0
										, 'tTest':0, 'zTest':0, 'chiTest':0, 'fTest':0, 'multivariate':0};
					self.dataSourceQuantity = 0;
					
					WISE.Constants.pid = reportId;
					self.isNewReport = (WISE.Constants.pid == "");
//					self.FieldFilter = new WISE.libs.Dashboard.FieldFilter();
					self.dataSetCreate = new WISE.libs.DataSet();
//					self.reportUtility = new WISE.libs.ReportUtility();
//					self.downloadManager = new WISE.libs.Dashboard.DownloadManager();
					
				} else if(self.reportType == 'AdHoc'){
					self.structure = _data;
					/*dogfoot shlim 20210415*/
					self.layoutConfig[reportId] = self.structure.ReportMasterInfo.layout_config
					self.structureBuffer.push({structure : _data, reportId:reportId,reportType:self.reportType,schedulePath:self.schedulePath});
					self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
					self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
//					self.parameterHandler = new WISE.libs.Dashboard.ParameterHandler();
					self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
					self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
					self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
					//2020.02.04 mksong itemQuantity 내용 추가 dogfoot
					self.itemQuantity = {'wordcloud':0,'pivotGrid': 0,'dataGrid':0,'chart':0,'pieChart':0, 'heatmap':0, 'heatmap2':0, 'coordinatedot':0, 'syncchart':0, 'parallel':0
										, 'parallel':0, 'choroplethMap':0,'Treemap':0, 'Starchart':0, 'listBox':0, 'treeView':0
										, 'comboBox':0, 'image':0, 'textBox':0, 'RectangularAreaChart':0, 'waterfallchart':0
										,'bubbled3':0, 'histogramchart':0, 'card':0, 'bubble':0,'adhocItem':0,'hierarchical':0
										,'bipartitechart':0,'forceDirect':0,'funnelchart':0, 'pyramidchart':0,'forceDirectExpand':0
										,'sankeychart':0,'rangebarchart':0, 'rangeareachart':0, 'timelinechart':0, 'bubblepackchart':0
										, 'wordcloudv2':0, 'dendrogrambarchart':0, 'calendarviewchart':0
										, 'divergingchart':0, 'dependencywheel':0, 'sequencessunburst':0, 'boxplot': 0, 'coordinateline': 0, 'scatterplot': 0, 'scatterplotmatrix': 0, 'radialtidytree': 0, 'historytimeline': 0, 'arcdiagram':0, 'scatterplot2': 0
										, 'liquidfillgauge': 0, 'kakaoMap':0, 'kakaoMap2':0, 'calendarview2chart':0, 'calendarview3chart':0, 'collapsibletreechart':0
										, 'onewayAnova':0, 'onewayAnova2':0, 'twowayAnova':0, 'pearsonsCorrelation':0, 'spearmansCorrelation':0
										, 'simpleRegression':0, 'multipleRegression':0, 'logisticRegression':0, 'multipleLogisticRegression':0
										, 'tTest':0, 'zTest':0, 'chiTest':0, 'fTest':0, 'multivariate':0};
					self.dataSourceQuantity = 0;
					WISE.Constants.pid = reportId;
					self.isNewReport = (WISE.Constants.pid == "");
//					self.FieldFilter = new WISE.libs.Dashboard.FieldFilter();
					self.dataSetCreate = new WISE.libs.DataSet();
//					self.reportUtility = new WISE.libs.ReportUtility();
//					self.downloadManager = new WISE.libs.Dashboard.DownloadManager();
					
					/* custom field calculator */
					self.customFieldCalculater.meta = self.structure;
					
					if(self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT.length > 0 && self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT[0].DATASET_TYPE == 'CUBE') {
						self.structure.DataSources = {DataSource:[{ComponentName: "dataSource1", Name:self.structure.ReportMasterInfo.cube_nm}]};
						WISE.Context.isCubeReport = true;
					} else {
						self.structure.DataSources = {DataSource:[{ComponentName: "dataSource1", Name:self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT["0"].DATASET_NM}]};
						WISE.Context.isCubeReport = false;
					}
					
					/* item generator */
//						self.itemGenerateManager.init();
				} else if(reportType == 'Excel' || reportType == 'Spread'){
					WISE.Context.isCubeReport = false;
					self.structure = _data;
					self.structureBuffer.push({structure : _data, reportId:reportId,reportType:reportType,schedulePath:self.schedulePath});
					self.layoutManager = new WISE.libs.Dashboard.LayoutManager();
					self.dataSourceManager = new WISE.libs.Dashboard.DataSourceManager();
//					self.parameterHandler = new WISE.libs.Dashboard.ParameterHandler();
					self.parameterFilterBar = new WISE.libs.Dashboard.ParameterBar();
					self.queryHandler = new WISE.libs.Dashboard.QueryHandler();
					self.itemGenerateManager = new WISE.libs.Dashboard.item.ItemGenerateManager();
					self.dataSourceQuantity = 0;
					
					WISE.Constants.pid = reportId;
					self.isNewReport = (WISE.Constants.pid == "");
//					self.FieldFilter = new WISE.libs.Dashboard.FieldFilter();
//					self.dataSetCreate = new WISE.libs.DataSet();
//					self.reportUtility = new WISE.libs.ReportUtility();
//					self.downloadManager = new WISE.libs.Dashboard.DownloadManager();
					
				    
					/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
					$("#saveReportAs").parent().css('display', 'none');
					
					self.structure.DataSources = {DataSource:[{ComponentName: "dataSource1", Name:self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT["0"].DATASET_NM}]}
					
					/* item generator */
//						self.itemGenerateManager.init();
				} else {
					WISE.alert('set dashboard page structure json data first!');
					return;
				}
				/* report title */
				var TitleVisible;
				if(reportType == 'AdHoc' || reportType == 'Spread' || reportType == 'Excel'){
					TitleVisible = true;
				}else{
					if(self.structure.Title){
						TitleVisible = typeof self.structure.Title.Visible =='undefined' ? true : false; 
					}
				}
		
				
				if(TitleVisible){
					var reportTabLi = $('.report-tab ul').find('li');
            	    var reportTabLiL = reportTabLi.length;
            	    
					var reportTab = $('.report-tab');
			        var reportTabUl = $('.report-tab ul');
			        reportTabLiL = reportTabLiL +1;

			        var createTab='';
			        createTab+='<li report_id='+reportId+' id = "report'+reportId+'">';
			        createTab+='<span title="'+ self.structure.ReportMasterInfo.name +'">';
			        /* DOGFOOT ktkang 직접 경로로 접속했을 때는 보고서 닫기 버튼 제거  20200221 */
			        createTab+='<em>'+ self.structure.ReportMasterInfo.name +'</em>';
			        if(!isSingleView) {
			        	createTab+='<a href="#" class="gui close">close</a>';
			        }
			        createTab+='</span>';
			        createTab+='</li>';
			        
//			        reportTab.find('ul').empty().append(createTab);
			        reportTab.find('ul').append(createTab);
			        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
			        reportTab.find('li').width(100 / reportTabLiL + '%');

			        $('.report-tab ul').find('li').each(function(){
			            var createTabCustomData = $(this).find('em').text();
			        });
			        
			        $(document).off('click', '.report-tab li');
			        /*20210302 AJKIM reportmasterInfo 오류 수정 dogfoot*/
			        var check = false;
			        $(document).on('click', '.report-tab li', function(e){
			        	if(check) return;
			        	check = true;
			            $(this).addClass('on').siblings().removeClass('on');
			            /* DOGFOOT ktkang 무한로딩 오류 수정  20200717 */
			            /*dogfoot shlim 20210414*/
			            var focusId;
					    gDashboard.clickedfolderList = true;
		            	$.each($('.report-tab .on'),function(_i,_onClass){
		            		focusId = $(_onClass).attr('report_id');
		            	});
		            	//20210426 AJKIM 뷰어 닫기 오류 수정 dogfoot
			            if($('.report-tab li').length > 0) {
			            	var prevReportId = WISE.Constants.pid;
//			            	focusId = $(this).attr('report_id');
			            	$.each($('#reportContainer').children('.reportChangeClass'),function(_i,_container){
			            		
			            		
			            		if($(_container).attr('report_id') == focusId){
			            			$(_container).css('display','block');
			            			$.each(self.structureBuffer,function(_i,_e){
			            				if(_e.reportId == prevReportId){
			            					_e.structure.dataFieldDisplay = $('.data-view').hasClass('on');
			            				}
			            				if(_e.reportId == focusId){
			            					self.structure = _e.structure;
			            					reportType = _e.reportType;
			            					self.reportType = _e.reportType;
			            					//20210827 AJKIM 스프레드 시트 여러개 열 때 spreadManager 변경되지 않던 오류 수정 dogfoot
			            					if(_e.reportType == 'Spread' || _e.reportType == 'Excel'){
			            						gDashboard.spreadsheetManager = gDashboard.spreadManagerBuffer[_e.reportId];
			            					}
											self.schedulePath = _e.schedulePath;
//											gDashboard.reportUtility.reportInfo.ReportMasterInfo
			            					/* DOGFOOT ktkang 뷰어에서 보고서 2개이상 열고 한두번 변경하면 structureBuffer에 ReportMasterInfo 가 꼬이는 오류  20200110 */
											gDashboard.reportUtility.reportInfo.ReportMasterInfo = {};
			            					gDashboard.reportUtility.reportInfo.ReportMasterInfo =  _e.structure.ReportMasterInfo;
			            					WISE.Constants.pid = focusId;
//			            					self.parameterHandler.init();
			            					self.dataSourceManager.init();
			            					self.itemGenerateManager.dxItemBasten= [];
			            					self.itemGenerateManager.viewedItemList= [];
			            					self.itemGenerateManager.init();
			            					$.each(self.itemGenerateBuffer,function(_j,_generate){
			            						if(_generate.reportId == focusId){
			            							self.itemGenerateManager.dxItemBasten = _generate.dxItemBasten;
			            							return false;
			            						}
			            					});
			            					
			            					/*dogfoot 뷰어 주제영역 필터 릴레이션 체크 오류 수정 20210430*/
			            					//gDashboard.parameterFilterBar.parameterInformation = [];
			            					/*dogfoot 매개변수 파라미터 데이터 타입 초기화 객체로 변경 syjin 20210723*/
			            					gDashboard.parameterFilterBar.parameterInformation = {};
			            					gDashboard.parameterFilterBar.setParameterInformation(gDashboard.viewerParameterBars[focusId].state.params);
			            					//20210313 AJKIM 탭 이동 시 데이터 소스 오류 수정 dogfoot
			            					if(reportType == 'AdHoc'){
			            						self.fieldManager = self.itemGenerateManager.dxItemBasten[0].fieldManager;
			            					}
			            					
			            					$.each(self.dataSourceManager.datasetInformation, function(_ds, _dsInfo){
			            						if(_dsInfo.DATASRC_TYPE == 'CUBE'){
			            							WISE.Context.isCubeReport = true;
			            						}else{
			            							WISE.Context.isCubeReport = false;
			            						}
			            						return false;
			            					})
			            					$.each(self.LayoutManagerBuffer,function(_j,_layout){
			            						if(_layout.reportId == focusId){
			            							self.layoutManager.itemidBasten = _layout.itemidBasten;
			            							return false;
			            						}
			            					})
											
			            					
											/* dogfoot WHATIF 분석 뷰어 탭 선택 변경 시 버퍼 사용하여 셋팅 shlim 20201022 */
			            					$.each(self.itemCalcParamListBuffer,function(_j,_layout){
			            						if(_layout.reportId == focusId){
			            							self.customParameterHandler.calcParameterInformation = _layout.calcParamaList;
			            							return false;
			            						}
			            					})

			            					$.each(self.itemCustomFieldBuffer,function(_j,_layout){
			            						if(_layout.reportId == focusId){
			            							self.customFieldManager.fieldInfo = _layout.customFileds;
			            							return false;
			            						}
			            					})
											/* dogfoot WHATIF 분석 매개변수 filter button 생성 shlim 20201022 */
			            					if(self.customParameterHandler.getArrayCalcParamInfomation().length > 0){
												gDashboard.customParameterHandler.setCalcFilterButton(undefined,true);
											}else{
												gDashboard.customParameterHandler.setCalcFilterButton(undefined,false);
											}
											/* DOGFOOT ktkang 리포트 다운로드 권한 구현  20201109 */
			            					if(self.structure.ReportMasterInfo.export_yn == 'N') {
			            						$('#dl_viewer_report').css('display', 'none');
			            					} else {
			            						$('#dl_viewer_report').css('display', 'block');
			            					}
			            					
			            					/*20210302 AJKIM 뷰어 다른이름으로 저장 추가 dogfoot*/
			            					if(reportType === "Spread" || reportType === "Excel"){
			            						$("#saveReportAs").parent().css('display', 'none');
			            					} else {
			            					//20210726 AJKIM 다른 이름응로 저장 버튼 권한 따라 숨김 처리 dogfoot
			            						if(self.structure.ReportMasterInfo.publish_yn == 'N') {
			            							$('#saveReportAs').parent().css('display', 'none');
			            						} else {
			            							$('#saveReportAs').parent().css('display', 'block');
			            						}
			            					}
			            					
//			            					self.itemGenerateManager.generate(self.structure.Items);
											/* DOGFOOT ktkang 뷰어에서 보고서 여러개 열었을 때 오류 수정  20200805 */
			            					$.each(self.stateBuffer,function(_j, _state){
			            						if(_state.reportId == focusId){
			            							gDashboard.datasetMaster.state = _state.state;
			            							return false;
			            						}
			            					});
			            					
			            					self.parameterFilterBar.toggleParameter(focusId);
			            					
			            					self.resize();
//			            					self.parameterHandler.resize();
			            					//2020.01.22 MKSONG 연결보고서 동기화 DOGFOOT	
			            					if(gDashboard.structure.linkReport) {
			            						if(gDashboard.structure.linkReport.length != 0){
			            							$('.connectR').attr('style','opacity: 1 !important');
			            							/* DOGFOOT ktkang 뷰어에서 연결보고서 없을 때 숨김  20200525 */
			            							$('.connectR').css('display', 'block');
			            						}else{
			            							$('.connectR').attr('style','opacity: .7 !important');
			            							$('.connectR').css('display', 'none');
			            						}

			            						$('#linkReportList').empty();
			            						$.each(gDashboard.structure.linkReport,function(_i,_o){
			            							$('#linkReportList').append('<li><a id=' + _o.target_id + ' href="#">' + _o.target_nm + '</a></li>');

			            							$('#' + _o.target_id).click(function(e) { 

			            								var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();

			            								var linkReportMeta = gDashboard.structure.linkReport;
			            								var linkJsonMatch = {};
			            								var target_id;

			            								$.each(linkReportMeta,function(_i,_linkMeta){
			            									if(_linkMeta.link_type == 'LP')
			            									{
			            										target_id = _linkMeta.target_id;
			            										if(typeof _linkMeta.linkJson.LINKDATA_XML != 'undefined') {
			            											// 2019.12.24 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            											$.each(WISE.util.Object.toArray(_linkMeta.linkJson.LINKDATA_XML.ARG_DATA),function(_j,_linkJson){
			            												// 2019.12.10 수정자 : mksong 연결보고서 오류 수정 DOGFOOT
			            												linkJsonMatch[_linkJson.FK_COL_NM] = encodeURI(paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value);
			            												//
			            											});
			            										} else {
			            											linkJsonMatch = [];
			            										}

			            									}
			            								});

			            								var locationStr = "";
			            								if(linkJsonMatch != []) {
			            									$.each(linkJsonMatch,function(_key,_val){
			            										// 2020.02.13 mksong 연결보고서 VALUE값 암호화 DOGFOOT
			            										locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(encodeURIComponent(_val))+'&';
			            									});
			            									locationStr = (locationStr.substring(0,locationStr.length-1));

			            									if(locationStr.length > 1) {
			            										locationStr = "&" + locationStr;
			            									}
			            								}
			            								var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_o.target_id+'/viewer.do?USER='+userJsonObject.userId+'&assign_name=bWVpcw==' + locationStr;
			            								window.open(urlString);
			            							});
			            						});
			            					}else{
			            						$('.connectR').attr('style','opacity: .7 !important');
			            					}
			            					//2020.01.22 MKSONG 연결보고서 동기화 수정 끝 DOGFOOT	
			            				}
			            			});
			            			
			            			//20210415 AJKIM 필터 바 기본값 펼친 상태로 변경 dogfoot
			            			//20210712 AJKIM 탭 바꿀 땐 기본값 저굥ㅇ되지 않게 수정
//									if(!$('.filter-bar').hasClass('on') && $("#"+WISE.Constants.pid+"_paramContainer").children().length > 0)
//										$('.filter-more').click();
//
//									if($("#"+WISE.Constants.pid+"_paramContainer").children().length == 0 && $('.filter-bar').hasClass('on')){
//										$('.filter-more').click();
//									}
			            		}else{
			            			$(_container).css('display','none');
			            		}
			            	});
			            //20210712 AJKIM 보고시 1개일 경우 버튼 제거 dogfoot
			            }else{
			            	$('.design').css('display', 'none');
			            	$('.activeChangeLayout').css('display', 'none');
			            	$('#dl_viewer_report').css('display', 'none');
			            	//20210726 AJKIM 다른 이름응로 저장 버튼 권한 따라 숨김 처리 dogfoot
			            	$('#saveReportAs').parent().css('display', 'none')
			            	$('.filter-bar.viewer').css({paddingLeft:'40px'});
			            	
			            	try{
			            			gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id].canvasLayout.updateSize($('#reportContainer').width(),$('#reportContainer').height());
							}catch(e){
								console.error(e);
							}
							check = false;
							return false;
			            }
			            
						//2020.01.22 MKSONG 보고서 열기 타입 지정 오류 수정 DOGFOOT
						//2020.01.22 MKSONG 비정형 아이콘 활성화 수정 DOGFOOT
						//20210420 AJKIM 뷰어 대시보드 데이터 항목 수정 추가 dogfoot
						if(gDashboard.structure.ReportMasterInfo.type == 'AdHoc' || gDashboard.structure.ReportMasterInfo.type == 'DSViewer' || (userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && gDashboard.structure.ReportMasterInfo.type == 'DashAny')){
							/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
							/* 2021-04-30 데이터항목 visible 권한 처리 */
							if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {  						            
								$('.data-view').css('display','block');
							}
							else {
								$('.data-view').css('display','none');
							}

							if(typeof self.structure.dataFieldDisplay !== 'undefined'){
								if($('.data-view').hasClass('on') != self.structure.dataFieldDisplay){
								    $('.data-view').click();
							    }
							}
							if(gDashboard.structure.ReportMasterInfo.type == 'AdHoc'){
								$('.activeChangeLayout').css('display','block');
								$('.design').css('display','block');
							}
							else{
								$('.activeChangeLayout').css('display','none');
								$('.design').css('display','none');
							}
								
							if(!$('.tree-view').hasClass('on')){
								//$('.filter-bar.viewer').css({paddingLeft:'79px'});
							}							
							
							$.each($('.reportChangePanel'),function(_i,_panel){
								if($(_panel).attr('report_id') == focusId){
									$(_panel).css('display','block');
									if((gDashboard.reportType == "DashAny" && userJsonObject.menuconfig.Menu.DASH_DATA_FIELD) || gDashboard.reportType == 'DSViewer'){
										var focusItem = gDashboard.itemGenerateManager.dxItemBasten[0];
										gDashboard.fieldManager = focusItem.fieldManager;
										gDashboard.itemGenerateManager.focusItem(focusItem,focusItem);
										gDashboard.fieldChooser.resetAnalysisFieldArea(focusItem);
									}
								    else
								    	$(_panel).find('.column-drop-body').css('display','block');
								}else{
									$(_panel).css('display','none');
								}
							});	
						}else{
							// 2019.12.24 수정자 : mksong 뷰어 treeopen ui 수정 DOGFOOT
							if($('.data-view').hasClass('on')){
								$('.data-view').click();
							}
							
							$('.data-view').css('display','none');
							$('.activeChangeLayout').css('display','none');
							/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
							/*dogfoot shlim 뷰어 디자이너 바로가기 기능 구현 20210614*/
							if($('.report-tab li').length > 0){
								if(typeof self.authPublishArr[WISE.Constants.pid] != 'undefined'){
                            		if(self.authPublishArr[WISE.Constants.pid] == 'Y'){
                       	             $('.design').css('display','block');		
                    	        	}else{
                        	    		$('.design').css('display','none');
                            		}
	                            }else{
    	                        	$('.design').css('display','none');
        	                    }
							}else{
								$('.design').css('display','none');
							}
							
							if(!$('.tree-view').hasClass('on')){
								$('.filter-bar.viewer').css({paddingLeft:'40px'});	
							}
							$('.reportChangePanel').css('display','none');
						}
						try{
							gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id].canvasLayout.updateSize($('#reportContainer').width(),$('#reportContainer').height());
						}catch(e){
							console.error(e);
						}
						check = false;
			        
			        });
			        //2020.01.22 MKSONG 비정형 아이콘 활성화 수정 끝 DOGFOOT
				}

				/* parameter */
//				self.parameterHandler.reportId = reportId;
//				self.parameterHandler.dashboardid = self.id;
//				self.parameterHandler.init();
				
				/* layout */
				self.layoutManager.reportId = reportId;
				self.layoutManager.dashboardid = self.id;
				self.layoutManager.containerId = self.containerId;
				self.layoutManager.init();
				
				/* data source*/
				self.dataSourceManager.dashboardid = self.id;
				self.dataSourceManager.init();

				/* DOGFOOT hsshim 2020-01-13 비정형 사용자 정의 데이터 저장 기능 작업 */
				/* custom fields */
				self.customFieldManager.init();
				
				/* query */
				self.queryHandler.dashboardid = self.id;
				self.queryHandler.init();
				
				/* item generator */
				self.itemGenerateManager.dashboardid = self.id;
				self.itemGenerateManager.init();
				
				self.reportUtility.dashboardid = self.id;
				// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
				gDashboard.layoutManager.viewsectionLayout(gDashboard.structure.ReportMasterInfo.id);
				gDashboard.layoutManager.viewactivateBasicFunction();
				
				// 2019.12.16 수정자 : mksong 중복 제거  DOGFOOT 
				
//				// 2019.12.16 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT - Viewer Goldenlayout 사용시 주석
//				if(self.reportType == 'AdHoc'){
//					self.itemGenerateManagerAdhocInit(gDashboard.structure.ReportMasterInfo.layout,gDashboard.structure.ReportMasterInfo.id);
//				}
//				else if(self.reportType == 'DashAny'){
//					self.render();
//				}
				self.itemGenerateBuffer.push({reportId:reportId, dxItemBasten : self.itemGenerateManager.dxItemBasten});
				self.LayoutManagerBuffer.push({reportId:reportId, itemidBasten : self.layoutManager.itemidBasten});
				
				//self.parameterHandler.render();
				
				self.fieldChooser.init();
				self.fieldChooser.setFieldArea();
				
				gDashboard.datasetMaster.setDataFromStructure();
				/* DOGFOOT ktkang 뷰어에서 보고서 여러개 열었을 때 오류 수정  20200805 */
				self.stateBuffer.push({reportId:reportId, state: gDashboard.datasetMaster.state});
				
				/* dogfoot WHATIF 분석 매개변수 필터 버튼생성 shlim 20201022 */
				if(gDashboard.customParameterHandler.getArrayCalcParamInfomation().length > 0){
					gDashboard.customParameterHandler.setCalcFilterButton(undefined,true);
				}else{
					gDashboard.customParameterHandler.setCalcFilterButton(undefined,false);
				}
				/* dogfoot WHATIF 분석 매개변수 뷰어용 버퍼 생성 shlim 20201022 */
				self.itemCalcParamListBuffer.push({reportId:reportId, calcParamaList : gDashboard.customParameterHandler.calcParameterInformation});
				self.itemCustomFieldBuffer.push({reportId:reportId, customFileds : gDashboard.customFieldManager.fieldInfo});
				
				if(WISE.Context.isCubeReport) {
					self.dataSourceQuantity = 0;
				}
				
				// DOGFOOT hsshim 1220 보고서 열기전에 폴더텝 닫침
				if($('#treeopen').hasClass('on') || $('.reportListArea').hasClass('on')){
					// 2019.12.24 수정자 : mksong 뷰어 treeopen ui 수정 DOGFOOT        							
//		        								$('#treeopen').removeClass('on');
					$('.reportListArea').removeClass('on')
					$('.viewr-ui-option .tree-view').removeClass('on');
					$('#reportContainer').css({paddingLeft:'0px'});
//		        								$('.filter-bar').css({paddingLeft:'0px'});
				}
				if ($('#reportContainer').hasClass('on')) {
					$('#reportContainer').removeClass('on');
				}
				// DOGFOOT hsshim 1220 보고서 열기전에 폴더텝 닫침 끝
//
				
				try {
					if(reportType == 'AdHoc'){
						/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */     							
						if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
							$('.data-view').css('display', 'block');
						}
						else {
							$('.data-view').css('display', 'none');
						}
						
//						/* goyong ktkang EIS에서 파라미터 받아서 데이터 항목 펼치는 부분 추가  20210604 */
//						if(gDashboard.isSingleView && userJsonObject.dataScroll == 'Y' && !$('.data-view').hasClass('on')) {
//							$('.data-view').click();
//						}
						
						//2021-06-29 Jhseo 싱글뷰 이면서 비정형 보고서 일때 비정형레이아웃 버튼 활성화 
						if(gDashboard.structure.ReportMasterInfo.type == 'AdHoc' && gDashboard.isSingleView) {
							$('#viewerAdhoc').css('display', 'block');
//							var htmlAdhoc = '			<ul class="more-link right-type" style="left: 10px; z-index:1501;">';
//							htmlAdhoc += '			<li><a id="changeLayoutC" class="changeLayout" href="#">차트만 보기</a></li>';
//							htmlAdhoc += '			<li><a id="changeLayoutG" class="changeLayout" href="#">그리드만 보기</a></li>';
//							//2020.01.21 mksong 비정형 레이아웃 수정 dogfoot
//							htmlAdhoc += '			<li><a id="changeLayoutCG" class="changeLayout" href="#">차트와 그리드 동시에 보기</a></li>';
////							htmlAdhoc += '			<li><a id="changeLayoutCLGR" class="changeLayout" href="#">차트 왼쪽 / 그리드 오른쪽</a></li>';
////							htmlAdhoc += '			<li><a id="changeLayoutCRGL" class="changeLayout" href="#">차트 오른쪽 / 그리드 왼쪽</a></li>';
////							htmlAdhoc += '			<li><a id="changeLayoutCTGB" class="changeLayout" href="#">차트 위 / 그리드 아래</a></li>';
////							htmlAdhoc += '			<li><a id="changeLayoutCBGT" class="changeLayout" href="#">차트 아래 / 그리드 위</a></li>';
//							htmlAdhoc += '			</ul>';
//							$('#viewerAdhoc').append(htmlAdhoc);
							
							$('.panel-inner.scrollbar.dx-scrollable').css('max-height', '100%');
							$('.panel-inner.scrollbar.dx-scrollable').css('height', 'calc(100% - 80px)');
							$('#allList').css('height', '100%');
							$('#viewerDownload').css('display', 'block');
							
							$('#dl_popover').dxPopover({
								target: $('#viewerDownload'),
								deferRendering: false,
								contentTemplate: function() {
									$('.dx-popup-content').css('padding',0);
									return $(
										'<div style="width:200px;">' +
											'<div class="add-item noitem office">'+
												'<span class="add-item-head on">MS Office</span>'+
												'<ul class="add-item-body">'+
													'<li><a id="downloadReportXLSX" class="downloadReport xlsx" href="#" title="MS Office Excel(xlsx)"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xlsx.png" alt=""><span>MS Office Excel(xlsx)</span></a></li>'+
													'<li><a id="downloadReportXLS" class="downloadReport xls" href="#" title="MS Office Excel(xls)"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xls.png" alt=""><span>MS Office Excel(xls)</span></a></li>'+
												'</ul>'+
											'</div>'+
										'</div>'
									);
								},
								onShowing: function() {
									if (gDashboard.reportType === 'Spread' || gDashboard.reportType === 'Excel') {
										$('.add-item.office #downloadReportXLS').parent().hide();
									} else {
										$('.add-item.office #downloadReportXLS').parent().show();
									}
								}
							});
						}
						//2020.01.22 MKSONG 비정형 아이콘 활성화 수정 DOGFOOT
						$('.activeChangeLayout').css('display','block');
						$('.design').css('display','block');
						/*dogfoot 비정형 뷰어 필터 펼치기 안보이는 오류 수정 shlim 20200720*/
						$('.filter-bar.viewer').css({paddingLeft:'79px'});
						// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT					
						gDashboard.customFieldManager.init();
						gDashboard.structure.Layout = gDashboard.structure.ReportMasterInfo.layout;
						
						// DOGFOOT hsshim 1220 골든레이아웃 UI 적용
						gDashboard.openAdhocViewerReport(reportId);
						// 2019.12.20 mksong 뷰어 기본 함수 적용 dogfoot
						/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
						var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(gDashboard.structure.ReportMasterInfo.cube_nm);
						$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
							_item.dataSourceId = dataSrcId;
							if(_item.type === 'PIVOT_GRID'){
								_item.dragNdropController.loadAdhocItemData(_item);
								_item.dragNdropController.addSortableOptionsForOpen(_item);
							}
						});
						$.each(gDashboard.datasetMaster.state.datasets, function(_dsId) {
							gDashboard.customFieldManager.setCustomFieldsForOpen(_dsId);
						});
						/* DOGFOOT hsshim 2020-01-15 끝 */
						// 수정 끝
					}
					/*dogfoot 통계 분석 추가 shlim 20201102*/
					else if(reportType == 'DashAny' || reportType == 'StaticAnalysis' || reportType == 'DSViewer'){
						if((reportType == 'DashAny' && userJsonObject.menuconfig.Menu.DASH_DATA_FIELD) || reportType == 'DSViewer'){
							/* 2021-04-30 데이터항목 visible 권한 처리 */
							if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
								$('.data-view').css('display', 'block');
							}
							else {
								$('.data-view').css('display', 'none');
							}
							//2020.01.22 MKSONG 비정형 아이콘 활성화 DOGFOOT
							$('.activeChangeLayout').css('display','none');
							if(typeof self.authPublishArr[WISE.Constants.pid] != 'undefined'){
                            	if(self.authPublishArr[WISE.Constants.pid] == 'Y'){
                                    $('.design').css('display','block');		
                            	}else{
                            		$('.design').css('display','none');
                            	}
                            }else{
                            	$('.design').css('display','none');
                            }
						}
						else {
							$('.data-view').css('display','none');
							//2020.01.22 MKSONG 비정형 아이콘 활성화 DOGFOOT
							$('.activeChangeLayout').css('display','none');
							/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
//							$('.design').css('display','none');
							/*dogfoot shlim 뷰어 디자이너 바로가기 기능 구현 20210614*/
							if(typeof self.authPublishArr[WISE.Constants.pid] != 'undefined'){
                            	if(self.authPublishArr[WISE.Constants.pid] == 'Y'){
                                    $('.design').css('display','block');		
                            	}else{
                            		$('.design').css('display','none');
                            	}
                            }else{
                            	$('.design').css('display','none');
                            }
						}

						if(gDashboard.isSingleView) {
							$('#viewerDownload').css('display', 'block');
							$('#dl_popover').dxPopover({
								target: $('#viewerDownload'),
								deferRendering: false,
								contentTemplate: function() {
									$('.dx-popup-content').css('padding',0);
									return $(
										'<div style="width:200px;">' +
											'<div class="add-item noitem office">'+
												'<span class="add-item-head on">MS Office</span>'+
												'<ul class="add-item-body">'+
													'<li><a id="downloadReportXLSX" class="downloadReport xlsx" href="#" title="MS Office Excel(xlsx)"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xlsx.png" alt=""><span>MS Office Excel(xlsx)</span></a></li>'+
													'<li><a id="downloadReportXLS" class="downloadReport xls" href="#" title="MS Office Excel(xls)"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xls.png" alt=""><span>MS Office Excel(xls)</span></a></li>'+
													//'<li><a id="downloadReportPDF" class="downloadReport pdf" href="#" title="PDF"><img src="' + WISE.Constants.context + '/resources/main/images/ico_exportPDF.png" alt=""><span>PDF</span></a></li>'+
												'</ul>'+
											'</div>'+
//											'<div class="add-item noitem etc">'+
//											'<span class="add-item-head on">기타 항목</span>'+
//												'<ul class="add-item-body">'+
//													'<li><a id="downloadReportPDF" class="downloadReport pdf" href="#" title="PDF"><img src="' + WISE.Constants.context + '/resources/main/images/ico_exportPDF.png" alt=""><span>PDF</span></a></li>'+
//												'</ul>'+
//											'</div>' +
										'</div>'
									);
								},
								onShowing: function() {
									if (gDashboard.reportType === 'Spread' || gDashboard.reportType === 'Excel') {
										$('.add-item.office #downloadReportXLS').parent().hide();
									} else {
										$('.add-item.office #downloadReportXLS').parent().show();
									}
								}
							});
						}
						
						if(gDashboard.structure.Items.TabContainer != undefined && reportType == 'DashAny'){
							gDashboard.hasTab = true;
						}else{
        					gDashboard.hasTab = false;
        				}
						
						//2020.01.22 MKSONG 비정형 아이콘 활성화 수정 DOGFOOT
						$('.activeChangeLayout').css('display','none');
						/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200217 */
						$('.design').css('display','none');
						$('.filter-bar.viewer').css({paddingLeft:'40px'});
						/* DOGFOOT hsshim 1220
						 * 골든레이아웃 뷰어 UI 적용
						 */
						self.itemGenerateManager.generate(gDashboard.structure.Items, reportId);
						// 2021-04-13 뷰어(대시보드) 연결 보고서 메뉴 추가(마우스 우클릭) jhseo

						$.each(self.itemGenerateManager.dxItemBasten, function(_k, _item){
							gDashboard.insertItemManager.contextMenuItem(_item);
						});
						//20210420 AJKIM 뷰어 대시보드 데이터 항목 수정 추가 dogfoot
						if((userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && reportType == "DashAny") || reportType == 'DSViewer'){
							$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_k,_item){
								gDashboard.insertItemManager.openItem(_item);
							});
						}

						self.goldenLayoutManager[reportId] = new WISE.libs.Dashboard.GoldenLayoutManager();
						self.goldenLayoutManager[reportId].init('open', false, reportId);
					} else if (reportType == 'Spread' || reportType == 'Excel'){

						//$('#' + self.containerId + '_' + reportId).load('openSpreadViewer.do?reportId=' + reportId);
						gProgressbar.show();
						var page = (WISE.Constants.editmode == 'viewer') ? 'viewer' : 'index';
						
						var frame_header = 
							'<div class="lm_header">' +
								'<ul class="lm_tabs">' +
									'<li class="lm_tab cont_box_top_tit lm_active" title="스프레드" style="border: none">' +
									'	<i class="lm_left"></i>' +
									'	<span class="lm_title">스프레드 시트</span>' +
									'	<div class="lm_close_tab"></div>' +
									'</li>' +
								'</ul>'+
								'<ul class="cont_box_top_icon" id="spread-top-icon">' +
								'</ul>' +
							'</div>';
						
						$('#' + self.containerId + '_' + reportId).append(frame_header);
						
						var new_frame = $('<iframe id="ss'+reportId+'" style="width:100%; height:100%;" src="'+WISE.Constants.context+'/resources/spreadJS/designer_sourceV13/index/'+page+'.html"></iframe>');
						new_frame.appendTo('#' + self.containerId + '_' + reportId);
						
						gDashboard.spreadsheetManager.renderButtons(reportId);
						gDashboard.spreadsheetManager.reportId = reportId;						
						/*dogfoot 스프레드시트 좌표 값 추가 shlim 20200728*/
						var x2js = new X2JS();	
						var reportXml = x2js.xml_str2json(_data.ReportMasterInfo.report_xml);
						gDashboard.spreadsheetManager.setReportXml(reportXml);
						
						initStart(true);
						function initStart(counter){
							 if(counter){
								 setTimeout(function(){
									 if(gDashboard.spreadsheetManager.spreadJS){
										gDashboard.spreadsheetManager.fileOpenFromServer();	
										counter=false;
									 }else{
										 gDashboard.spreadsheetManager.init();
									 }
									 initStart(counter);
								 }, 200);
							 }
						}		         
						
						$('#btn_query').off('click').on('click', function() {
							gProgressbar.show();
							gDashboard.queryByGeneratingSql = true;
							gDashboard.itemGenerateManager.clearTrackingConditionAll();
							self.query();
							this.blur();
						});
					
						return;
					}
				} catch (e) {
					/* DOGFOOT hsshim 1231
					 * 오류 스텍 보기
					 */
					console.error(e.stack);
				}
				
				self.itemGenerateBuffer.push({reportId:reportId, dxItemBasten : self.itemGenerateManager.dxItemBasten});
				self.LayoutManagerBuffer.push({reportId:reportId, itemidBasten : self.layoutManager.itemidBasten});
				/*
				 * 2019.12.16 수정자 : cshan 뷰어 파라미터 2번 그리는부분 제거 dogfoot
				 * */
//				self.parameterHandler.render();
				/* DOGFOOT ktkang 리포트 다운로드 권한 구현  20201109 */
				if(self.structure.ReportMasterInfo.export_yn == 'N') {
					$('#dl_viewer_report').css('display', 'none');
				} else {
					$('#dl_viewer_report').css('display', 'block');
				}
				
				self.resize();
				$(window).resize(function() {
					self.resize();
				});
				
				self.reportUtility.init(self.structure);
//				self.folderList();
//				self.refreshFolderList();
				if (isSingleView) {
					/* DOGFOOT ktkang 직접 경로 뷰어 기능 추가  20201020 */
					//20210826 AJKIM KAMKO 버튼 위치 변경 dogfoot
					$('.filter-bar').css({paddingLeft:userJsonObject.siteNm == 'KAMKO'? '0px':'79px'});
					//2020.11.23 mksong viewer reportID 열기 필터 영역 오류 수정  dogfoot
					/* DOGFOOT syjin 자산관리공사 아이콘 위치변경 시 겹침 현상 수정 20211007 */
					if(userJsonObject.siteNm == 'KAMKO'){
						$('.filter-row').css({width: 'calc(100% - 300px)'});
						/* DOGFOOT syjin 자산관리공사 selectBox 사각형으로 수정 20211007 */
						$(".dx-texteditor-input").css('border-radius', '0px');
					}
					else{
						$('.filter-row').css({width: 'calc(100% - 130px)'});
					}
										
					/* 2021-04-20 Jhseo 환경설정 뷰어(URL, 연결보고서) 다운로드 레이아웃 체크or미체크 시 UI 구현 */
					if(userJsonObject.menuconfig.Menu.DASHBOARD_DOWNLOAD_OPTION || typeof userJsonObject.menuconfig.Menu.DASHBOARD_DOWNLOAD_OPTION == 'undefined'){
						var html = '';
						var display = "none";
						if(userJsonObject.siteNm == 'KAMKO') display = 'flex';
						html += '<div id="kamko_row" style="display:' + display +'; align-items:center; margin-left:10px; height:40px; width: 160px; float:'+(userJsonObject.siteNm == 'KAMKO'?'right; position:relative; right: 176px': 'left')+';">';
//						html += '<div style="padding-right: 20px; position: relative; height:38px; width:60px; float:left;" title="보고서 속성">	';
//						html += '<a id="designBtn" href="#" class="lnb-link design">';			
//						html += '<img src="' + WISE.Constants.context + '/resources/main/images/ico_dashboardAdd.png" style="margin-left: 12px; margin-right: 12px; height:38px;" alt="">';			
//						html += '</a></div>';
						//아이콘 사용 시 style 삭제
						html += 	'<div class="icon_kako" style="margin-right: 12px; background-color:#1b8466; color:white; visibility:hidden;" title="보고서 속성">	';
						if(userJsonObject.siteNm == 'KAMKO'){
							html +=			'<a id="reportProperty2" class="btn crud double" href="#" style="color:white;">';
							html += 			'속성'; 
							html +=			'</a>';
						}else{
							html += 		'<a id="reportProperty2" href="#" class="" style="">';
							html += 			'<img src="' + WISE.Constants.context + '/resources/main/images/ico_reportProperty.png" style="height:38px; width:40px;" alt="">';
							html += 		'</a>';
						}
						html += 	'</div>';
						html += 	'<div class="icon_kako" style="margin-right: 12px; background-color:#1b8466; color:white;">';
						html += 		'<div id="dl_popover2" style="display: none;"></div>';
						
						if(userJsonObject.siteNm == 'KAMKO'){
							html += 		'<a id="dl_viewer_report2" style ="color:white;" class="btn crud double" href="#" title="다운로드">';
							html += 			'다운로드';
							html +=			'</a>';	
						}else{
							html += 		'<a href="#" title="다운로드">';
							html += 			'<img id="dl_viewer_report2" style="height:38px; width:40px;" src="' + WISE.Constants.context + '/resources/main/images/ico-download_new.png" style="margin-left: 12px; margin-right: 12px; margin-bottom: 12px;" alt=""></a>';
							html +=			'</a>';	
						}
						html +=		'</div>';
						html +=		'<div class="icon_kako" style="background-color:#1b8466; color:white;">';
						
						if(userJsonObject.siteNm == 'KAMKO'){						
							html +=			'<a id="designBtn" title="디자이너로 이동" href="#" class="btn crud double" style="color:white;">';
							html +=				'디자이너';
							html +=			'</a>';
							
						}else{							
							html +=			'<a id="designBtn" title="디자이너로 이동" href="#" class="" style="">';
							html +=				'<img src="'+WISE.Constants.context+'/resources/main/images/ico_dashboardAdd.png" style="height:38px; width:40px;" alt="">';
							html +=			'</a>';						
						}						
						html +=		'</div>';
						html += '</div>';
						
						if(userJsonObject.siteNm == 'KAMKO'){
							$('.filter-bar').append(html);							
						}else{
							$('.filter-bar').prepend(html);
						}
						
						$('#designBtn').off('click').on('click',function(){
							/* DOGFOOT MKSONG KERIS 뷰어 비정형일 때 디자이너로 레포트 아이디 이동 위해 수정 20200219 */
//							window.open(window.location.href.substring(0,window.location.href.indexOf("/report")+8)+"/edit.do");
							$('#reportId').val(gDashboard.structure.ReportMasterInfo.id);
							//DOGFOOT MKSONG KERIS CUBEID 함께 전송 20200219
							//DOGFOOT syjin 직접접근 스프레드시트 디자이너로 이동 추가 20211013
							if(reportType == 'Excel'){
								$('#cubeId').val(gDashboard.datasetMaster.state.datasets[Object.keys(gDashboard.datasetMaster.state.datasets)].DATASRC_ID);
							}else{
								$('#cubeId').val(gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.dxItemBasten[0].dataSourceId].DATASRC_ID);
							}
							
							$('#editForm').submit();
						});
						
						//if(userJsonObject.siteNm == 'KAMKO'){
						//	$('#designBtn').css('left', '');
						//	$('#designBtn').css('right', '110px');
						//}
						
						$('#dl_popover2').dxPopover({
							target: $('#dl_viewer_report2'),
							deferRendering: false,
							showEvent: "dxclick",
							contentTemplate: function() {
								return $(
									'<div style="width:200px;">' +
										'<div class="add-item noitem office">'+
											'<span class="add-item-head on">MS Office</span>'+
											'<ul class="add-item-body">'+
												'<li><a id="downloadReportXLSX" class="downloadReport xlsx" href="#" title="MS Office Excel(xlsx)"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xlsx.png" alt=""><span>MS Office Excel(xlsx)</span></a></li>'+
												'<li><a id="downloadReportXLS" class="downloadReport xls" href="#" title="MS Office Excel(xls)"><img src="' + WISE.Constants.context + '/resources/main/images/ico_xls.png" alt=""><span>MS Office Excel(xls)</span></a></li>'+
												// '<li><a id="downloadReportDOC" class="downloadReport doc" href="#" title="MS Office Word"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_msword.png" alt=""><span>MS Office Word</span></a></li>'+
												// '<li><a id="downloadReportPPT" class="downloadReport ppt" href="#" title="MS Office Powerpoint"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_msppt.png" alt=""><span>MS Office Powerpoint</span></a></li>'+
											'</ul>'+
										'</div>'+
										// '<div class="add-item noitem hanoffice">'+
										// 	'<span class="add-item-head on">한컴 오피스</span>'+
										// 	'<ul class="add-item-body">'+
										// 		'<li><a id="downloadReportHanHWP" class="downloadReport hwp" href="#" title="한글"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcword.png" alt=""><span>한컴</span></a></li>'+
										// 		'<li><a id="downloadReportHanCell" class="downloadReport cell" href="#" title="한셀"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcexcell.png" alt=""><span>한셀</span></a></li>'+
										// 		'<li><a id="downloadReportHanShow" class="downloadReport show" href="#" title="한쇼"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcshow.png" alt=""><span>한쇼</span></a></li>'+
										// 	'</ul>'+
										// '</div>'+		
										'<div class="add-item noitem etc">'+
											'<span class="add-item-head on">기타 항목</span>'+
											'<ul class="add-item-body">'+
												'<li><a id="downloadReportIMG" class="downloadReport img" href="#" title="이미지"><img src="' + WISE.Constants.context + '/resources/main/images/ico_exportImages.png" alt=""><span>이미지</span></a></li>'+
												'<li><a id="downloadReportPDF" class="downloadReport pdf" href="#" title="PDF"><img src="' + WISE.Constants.context + '/resources/main/images/ico_exportPDF.png" alt=""><span>PDF</span></a></li>'+
												'<li><a id="downloadReportHTML" class="downloadReport html" href="#" title="HTML"><img src="' + WISE.Constants.context + '/resources/main/images/ico_exportHTML.png" alt=""><span>HTML</span></a></li>'+
												'<li><a id="downloadReportCSV" class="downloadReport csv" href="#" title="CSV"><img src="' + WISE.Constants.context + '/resources/main/images/ico_ept_hcexcell.png" alt=""><span>CSV</span></a></li>'+
											'</ul>'+
										'</div>' +
									'</div>'
								);
							},
							onShowing: function() {
								if (gDashboard.reportType === 'Spread' || gDashboard.reportType === 'Excel') {
									$('.add-item.office #downloadReportXLS').parent().hide();
									$('.add-item.etc #downloadReportIMG').parent().hide();
									$('.add-item.etc #downloadReportHTML').parent().hide();
									/*dogfoot 뷰어 엑셀보고서 PDF 다운로드 버튼 제거 shlim 20200724*/
									$('.add-item.etc #downloadReportPDF').parent().hide();
									$('.add-item.etc #downloadReportCSV').parent().show();
								} else {
									$('.add-item.office #downloadReportXLS').parent().show();
									$('.add-item.etc #downloadReportIMG').parent().show();
									$('.add-item.etc #downloadReportHTML').parent().show();
									$('.add-item.etc #downloadReportCSV').parent().hide();
								}
							}
						});
					}
					/* DOGFOOT ktkang 리포트 다운로드 권한 구현  20201109 */
					if(self.structure.ReportMasterInfo.export_yn == 'N') {
						$('#dl_viewer_report2').css('display', 'none');
					} else {
						$('#dl_viewer_report2').css('display', 'block');
					}
					
					//20210726 AJKIM 다른 이름응로 저장 버튼 권한 따라 숨김 처리 dogfoot
					if(reportType === "Spread" || reportType === "Excel"){
						$("#saveReportAs").parent().css('display', 'none');
						//20211013 syjin 자산관리공사 다운로드 숨김처리 dogfoot
						if(userJsonObject.siteNm == 'KAMKO'){
							$("#reportContainer .lm_header").css('display', 'none')
						}
					} else {
						if(self.structure.ReportMasterInfo.publish_yn == 'N') {
							$('#saveReportAs').parent().css('display', 'none');
						} else {
							$('#saveReportAs').parent().css('display', 'block');
						}
					}
					
					$('.filter-row').css({float:'left'});
					
					//20211015 syjin 자산관리공사 관리자 외 숨김처리 dogfoot					
					$.each($(".icon_kako"), function(_i, _v){
						if(_v.children[0].text != '속성'){
							if((userJsonObject.userAuth != 'admin') || (userJsonObject.grpNm != '관리자 그룹')){
								$(_v).css('display', 'none');
							}
						}
					})
					if((userJsonObject.userAuth != 'admin') || (userJsonObject.grpNm != '관리자 그룹'))
						$("#kamko_row").css("right", '10px');
					
					self.downloadManager = new WISE.libs.Dashboard.DownloadManager();
					self.downloadManager.init();
				}
				
				gDashboard.reportUtility.activeButton();
				
				if(userJsonObject.menuconfig.Menu.VIEWER_DATA_FIELD_OPTION || typeof userJsonObject.menuconfig.Menu.VIEWER_DATA_FIELD_OPTION == 'undefined'){
					//20210713 AJKIM iFrame에서 엑셀 타지 않게 수정 dogfoot
					if(gDashboard.reportType !== 'Spread' && gDashboard.reportType !== 'Excel' && !(gDashboard.reportType == 'DashAny' && !(userJsonObject.menuconfig.Menu.DASH_DATA_FIELD || typeof userJsonObject.menuconfig.Menu.DASH_DATA_FIELD == 'undefined'))){
						/* 2021-04-30 데이터항목 visible 권한 처리 */
						if (self.structure.ReportMasterInfo.dataitem_use_yn == 'Y') {
							$("#container > .container-inner > .content > .panel-tab > .viewr-ui-option >.data-view").trigger("click");
						}
					}
				}
				
				if(gDashboard.structure.linkReport) {
					//2020.01.22 MKSONG 연결보고서 아이콘 활성화 DOGFOOT
					if(gDashboard.structure.linkReport.length != 0){
						$('.connectR').attr('style','opacity: 1 !important');
						/* DOGFOOT ktkang 뷰어에서 연결보고서 없을 때 숨김  20200525 */
						$('.connectR').css('display', 'block');
					}else{
						$('.connectR').attr('style','opacity: .7 !important');
						$('.connectR').css('display', 'none');
	    			}
					
					$('#linkReportList').empty();
    				$.each(gDashboard.structure.linkReport,function(_i,_o){
    					$('#linkReportList').append('<li><a id=' + _o.target_id + ' href="#">' + _o.target_nm + '</a></li>');
    					
    					$('#' + _o.target_id).click(function(e) { 
    						
    						var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
    						
    						var linkReportMeta = gDashboard.structure.linkReport;
    						var linkJsonMatch = {};
    						var target_id;
    						
    						$.each(linkReportMeta,function(_i,_linkMeta){
    							if(_linkMeta.link_type == 'LP')
    							{
    								target_id = _linkMeta.target_id;
    								if(typeof _linkMeta.linkJson.LINKDATA_XML != 'undefined') {
        								//2020.01.22 MKSONG 연결보고서 연결 오류 수정 DOGFOOT
    									$.each(WISE.util.Object.toArray(_linkMeta.linkJson.LINKDATA_XML.ARG_DATA),function(_j,_linkJson){
        									linkJsonMatch[_linkJson.FK_COL_NM] = encodeURI(paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value);
        								});
    								} else {
    									linkJsonMatch = [];
    								}
    								
    							}
    						});
    						
    						var locationStr = "";
    						if(linkJsonMatch != []) {
    							$.each(linkJsonMatch,function(_key,_val){
        							//2020.01.22 MKSONG 연결보고서 연결 오류 수정 DOGFOOT
    								locationStr += encodeURI(encodeURIComponent(_key))+'='+btoa(_val)+'&';
    							});
    							locationStr = (locationStr.substring(0,locationStr.length-1));

    							if(locationStr.length > 1) {
    								locationStr = "&" + locationStr;
    							}
    						}
    						var urlString = window.location.protocol+'//'+window.location.host+WISE.Constants.context +'/report/'+_o.target_id+'/viewer.do?USER='+userJsonObject.userId+'&assign_name=bWVpcw==' + locationStr;
    						window.open(urlString);
    					});
        			});
      			//2020.01.22 MKSONG 연결보고서 아이콘 활성화 DOGFOOT
    			}else{
    				$('.connectR').attr('style','opacity: .7 !important');
    			}
    			
    			if(gDashboard.structure.subLinkReport) {
    				$.each(gDashboard.structure.subLinkReport,function(_i,_ee){
    				//2020.01.22 MKSONG 서브연결보고서 연결 오류 수정 DOGFOOT
    					$('#' + _ee.target_item + '_' + _ee.arg_id + '_item_title').dblclick(function(e) { 
//    						if(_ee.target_item +'_' + _ee.arg_id +'_item' == self.itemid && _ee.link_type == 'LP'){
    						if(_ee.link_type == 'LP'){
    							target_id = _ee.target_id;
    							var paramListValue = WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
    							linkJsonMatch = {};

    							if(!(typeof _ee.linkJson == "object" && !Object.keys(_ee.linkJson).length)) {
    								$.each(_ee.linkJson.LINK_XML_PARAM.ARG_DATA,function(_j,_linkJson){
    									if(!Array.isArray(_ee.linkJson.LINK_XML_PARAM.ARG_DATA)) {
    										//2020.01.22 MKSONG 서브연결보고서 연결 오류 수정 DOGFOOT
    										linkJsonMatch[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.PK_COL_NM] = paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_ee.linkJson.LINK_XML_PARAM.ARG_DATA.FK_COL_NM].value;
    									} else if(_linkJson.PK_COL_NM) {
    										linkJsonMatch[_linkJson.PK_COL_NM] = encodeURI(paramListValue[_linkJson.FK_COL_NM].value =='_EMPTY_VALUE_' ? '[All]' : paramListValue[_linkJson.FK_COL_NM].value);
    									}
    								});
    							}

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
        			});
    			}
			}
		});
		

		/*2021-07-15 jhseo 모든 필터 펼치기 */
		if($('#filter-bar').height() <= 45 && Object.keys(gDashboard.parameterFilterBar.parameterInformation).length > 0){
			$('.filter-more').click();
		}
	};
	/* DOGFOOT hsshim 200103
	 * 데이터 집합 불러오기 오류 수정
	 */
	this.openUserDataset = function(datasetId, targetId) {
		$.ajax({
			method : 'POST',
			url: WISE.Constants.context + '/report/dataSetInfo.do',
			data: {
				'DATASET_ID' : datasetId
			},
			beforeSend:function() {
				//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
				gProgressbar.show();
			},
			complete: function() {
			},
			success: function(data) {
				// 20200721 ajkim 유저 설정 > 데이터 집합 즐겨찾기 소스 리팩토링 소스로 변경 dogfoot
				data = jQuery.parseJSON(data); 
                // generate dataset info
                var mapid = 'dataSource' + (gDashboard.dataSourceQuantity + 1);
                var dataset = {
                    DATASET_SEQ: data.DATASET_SEQ,
                    DATASET_NM: data.DATASET_NM,
                    DATASET_TYPE: data.DATASET_TYPE,
                    DATASRC_ID: data.DATASRC_ID,
                    DATASRC_TYPE: data.DATASRC_TYPE,
                    DATASET_QUERY: data.DATASET_QUERY || data.SQL_QUERY,
                    SQL_QUERY: data.DATASET_QUERY || data.SQL_QUERY,
                    DATASET_XML: data.DATASET_XML,
                    SHEET_ID: data.SHEET_ID,
                    data: data.data,
                    mapid: mapid,
                    PARAM: data.PARAM_ELEMENT || data.param_element,
                };                           
                switch (data.DATASET_TYPE) {
                    case 'DataSetCube':
                        var datasetInfo = data.DATASET_JSON ? data.DATASET_JSON.DATA_SET : data;
                        $.extend(dataset, {
                            SEL_CLAUSE: $.isPlainObject(datasetInfo.SEL_ELEMENT) 
                                ? self.utility.convertSelectClauseToNonCubeFormat(datasetInfo.SEL_ELEMENT.SELECT_CLAUSE) 
                                : [],
                            FROM_CLAUSE: [],
                            WHERE_CLAUSE: $.isPlainObject(datasetInfo.WHERE_ELEMENT) 
                                ? self.utility.convertWhereClauseToNonCubeFormat(datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE)
                                : [],
                            ORDER_CLAUSE: $.isPlainObject(datasetInfo.ORDER_ELEMENT) 
                                ? self.utility.convertOrderClauseToNonCubeFormat(datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE)
                                : [],
                        });
                        break;
                    case 'DataSetDs':
                        var datasetInfo = data.DATASET_JSON ? data.DATASET_JSON.DATA_SET : data;
                        /* DOGFOOT ktkang 데이터 원본 기준 불러오기 오류 수정  20200713 */
                        var selClause = [];
                        if(typeof datasetInfo.SEL_ELEMENT != 'undefined' && typeof datasetInfo.SEL_ELEMENT.SELECT_CLAUSE != 'array') {
                        	selClause.push(datasetInfo.SEL_ELEMENT.SELECT_CLAUSE);
                        } else {
                        	selClause = $.isPlainObject(datasetInfo.SEL_ELEMENT) ? datasetInfo.SEL_ELEMENT.SELECT_CLAUSE : [];
                        }
                        var fromClause = [];
                        if(typeof datasetInfo.REL_ELEMENT != 'undefined' && typeof datasetInfo.REL_ELEMENT.JOIN_CLAUSE != 'array') {
                        	fromClause.push(datasetInfo.REL_ELEMENT.JOIN_CLAUSE);
                        } else {
                        	fromClause = $.isPlainObject(datasetInfo.REL_ELEMENT) ? datasetInfo.REL_ELEMENT.JOIN_CLAUSE : [];
                        }
                        var whereClause = [];
                        if(typeof datasetInfo.WHERE_ELEMENT != 'undefined' && typeof datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE != 'array') {
                        	whereClause.push(datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE);
                        } else {
                        	whereClause = $.isPlainObject(datasetInfo.WHERE_ELEMENT) ? datasetInfo.WHERE_ELEMENT.WHERE_CLAUSE : [];
                        }
                        var orderClause = [];
                        if(typeof datasetInfo.ORDER_ELEMENT != 'undefined' && typeof datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE != 'array') {
                        	orderClause.push(datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE);
                        } else {
                        	orderClause = $.isPlainObject(datasetInfo.ORDER_ELEMENT) ? datasetInfo.ORDER_ELEMENT.ORDER_CLAUSE : [];
                        }
                        var changeCond = '';
                        if(typeof datasetInfo.ETC_ELEMENT != 'undefined' && typeof datasetInfo.ETC_ELEMENT.CHANGE_COND != 'array') {
                        	changeCond = $.isPlainObject(datasetInfo.ETC_ELEMENT) ? datasetInfo.ETC_ELEMENT.CHANGE_COND : '';
                        }
                        $.extend(dataset, {
                            SEL_CLAUSE: selClause,
                            FROM_CLAUSE: fromClause,
                            WHERE_CLAUSE: whereClause,
                            ORDER_CLAUSE: orderClause,
							CHANGE_COND: changeCond,
                        });
                        break;
                    default:
                        $.extend(dataset, {
                            SEL_CLAUSE: [],
                            FROM_CLAUSE: [],
                            WHERE_CLAUSE: [],
                            ORDER_CLAUSE: [],
                        });
                }

                // generate datasource info
                var dsRequestHeader = [{ mapid: mapid, dsid: dataset.DATASRC_ID, dstype: dataset.DATASRC_TYPE }];
                $.ajax({
                    method: 'GET',
                    url: WISE.Constants.context + '/report/getDatasourceInfoById.do',
                    data: { ids: $.toJSON(dsRequestHeader) },
                    success: function(response) {
                        if (response.status === 200) {
                        	gDashboard.datasetMaster.addDatasetToState(response.data[mapid], dataset, dataset.PARAM);
                        } else {
                            WISE.alert('Error finding datasources');
                        }
                    },
                    error: function() {
                        WISE.alert('Error finding datasources');
                    },
                });
				gProgressbar.hide();
			}
		});
	}
	
	this.getParameterValue = function() {
		return WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues();
	};
	
	/* DOGFOOT hsshim 2020-02-06
	 * - 마스터 필터 기능 리팩토링 적용 (코드 정리)
	 * - 마스터 필터 속도 개선
	 * - 마스터 필터 렌더링 표시 추가
	 * - 매계변수 필터가 적용 되있을때 마스터 필터가 제대로 적용이 안되는 오류 수정
	 */
	this.filterData = function(_itemid, _filteredData) {
		var a = performance.now();
		var itemCount = gDashboard.itemGenerateManager.dxItemBasten.length;
		/*dogfoot 아이템 하나라도 삭제하면 프로그레스바 무한로딩되는 오류 수정 shlim 20200618*/
		gDashboard.itemGenerateManager.viewedItemList = [];
		gProgressbar.beginListening(itemCount - 1);
		setTimeout(function() {
			self.itemGenerateManager.setFilteredData(_itemid, _filteredData);
			/*dogfoot 마스터필터 무시 설정시 프로그레스바 무한로딩 오류 수정 shlim 20200616*/
			gProgressbar.finishListening();
		}, 10);
		var b = performance.now();
		console.log('마스터 필터 시간 (렌더링 없이): ' + (b - a) + ' ms');
		if(itemCount === 1) gProgressbar.hide();
	};
	/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
	this.getLayoutType = function() {
		
		var type = "Item",layout;
		/*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
		if(gDashboard.reportType === 'StaticAnalysis'){
			layout = gDashboard.reportUtility.setAysLayoutTree();
		}else{
			layout = gDashboard.reportUtility.setLayoutTree();
		}
		
		
		if(layout['LayoutTabContainer']){
		    type = "Container"	
		}else{
			if(layout["LayoutGroup"]){
				if(layout["LayoutGroup"][0]["LayoutTabContainer"]){
					type = "Container"
				}
			}
		}
		 
		
		return type
	};
	/*dogfoot 컨테이너별 마스터필터 적용 shlim 20201013*/
	this.setContainerList = function(currentItem) {
		self.containerLayout = [];
		var layoutOj={},layout = gDashboard.reportUtility.setLayoutTree();
		/*dogfoot 통계분석 레이아웃 트리 설정 구분 shlim 20201111*/
		if(gDashboard.reportType === 'StaticAnalysis'){
			layout = gDashboard.reportUtility.setAysLayoutTree();
		}else{
			layout = gDashboard.reportUtility.setLayoutTree();
		}
		$.each(layout['LayoutTabContainer'][0].LayoutTabPage,function(_i,_Page){
            if(_Page.LayoutGroup){
            	//self.containerLayout[_Page.DashboardItem] = [];
                $.each(_Page.LayoutGroup[0].LayoutItem,function(_j,_Item){
                	if(_Item.DashboardItem === currentItem.ComponentName){
                	    self.containerLayout = _Page.LayoutGroup[0].LayoutItem;	
                	}
			        
		        })
            }	
		})
        return self.containerLayout
	};
	/* DOGFOOT hsshim 2020-02-06 끝 */
	
	this.query = function() {
		
		/* DOGFOOT ajkim R분석 추가 20201201*/
//		if(self.reportType === "RAnalysis"){
//			$.ajax({
//				method : 'POST',
//				url: WISE.Constants.context + '/static/rScript.do',
//				data: {
//					script : $('#rscript').val()
//				},
//				success: function(data){
//					gDashboard.itemGenerateManager.dxItemBasten[0].setText(data.replaceAll("\n", "<br>"));
//				},
//				error: function(){
//					
//				}});
//		}
		var parameterLength = 0;
		
		$.each(gDashboard.parameterFilterBar.parameterInformation, function(_i, _param){
			if(_param.VISIBLE != "N") parameterLength++;
		})

		if(gDashboard.reportType != 'DashAny' && WISE.Constants.editmode == 'viewer' && self.isOpened == false && parameterLength != gDashboard.contentReadyParamList.length && self.tabN < 2
				&& gDashboard.contentReadyParamList.length != 0) {
			WISE.alert('초기 필터 데이터를 가져오는 중입니다. 잠시 후에 조회하시기 바랍니다.');
			gProgressbar.hide();
			return false;
		} else {
			self.isOpened = true;
		}
	
		// jhseo 고용정보원09 최대 조회 기간 설정		
		var param = gDashboard.getParameterValue();
		var frval = 0;
		var toval = 0;
		var gapTF = false;
		var returnval = false;
		var frName = "";
		var dateLength = 0;
//		var dateType = "";
//		var dateTypeKR = "";
		$.each(param,function(_key,_param){
			if(_key.indexOf("_fr") > -1 && _param.parameterType == "BETWEEN_CAND") {
				if(WISE.Constants.editmode == 'DashAny' || WISE.Constants.editmode == 'designer'){
					for(var i=0; i<gDashboard.parameterFilterBar.state.params.length; i++){
						if(_param.orgParamName == gDashboard.parameterFilterBar.state.params[i].PARAM_NM && gDashboard.parameterFilterBar.state.params[i].CAND_MAX_GAP != 0){
							dateLength = gDashboard.parameterFilterBar.state.params[i].CAND_MAX_GAP;
							dateType = gDashboard.parameterFilterBar.state.params[i].KEY_FORMAT.toUpperCase();
						}
					}
				}else if(WISE.Constants.editmode == 'viewer'){
					for(var i=0; i<gDashboard.viewerParameterBars[self.layoutManager.reportId].state.params.length; i++){
						if(_param.orgParamName == gDashboard.viewerParameterBars[self.layoutManager.reportId].state.params[i].PARAM_NM && gDashboard.viewerParameterBars[self.layoutManager.reportId].state.params[i].CAND_MAX_GAP != 0){
							dateLength = gDashboard.viewerParameterBars[self.layoutManager.reportId].state.params[i].CAND_MAX_GAP;
							dateType = gDashboard.viewerParameterBars[self.layoutManager.reportId].state.params[i].KEY_FORMAT.toUpperCase();
						}
					}
				}

					

				
				var frId = '';
				if(WISE.Constants.editmode == 'viewer') {
					frId = _param.uniqueName.replace("@", "");
					frId = "param_" + frId + '_' + WISE.Constants.pid + '_fr';
				}else {
					frId = _key.replace("@", "");
					frId = "param_" + frId;
				}
				gapTF = true;
				frval = $('#' + frId).dxDateBox('instance').option('value');
				frName = _param.uniqueName;
			} else if(gapTF && _key == frName + "_to") {
				var toId = '';
				if(WISE.Constants.editmode == 'viewer') {
					toId = _param.uniqueName.replace("@", "");
					toId = "param_" + toId + '_' + WISE.Constants.pid + '_to';
				}else {
					toId = _key.replace("@", "");
					toId = "param_" + toId;
				}
				toval = $('#' + toId).dxDateBox('instance').option('value');
			}
		});
        
		if(gapTF && dateLength != 0) {
            if(dateType.indexOf('DD') != -1){
            	// 윤년일때는 20200101~20201231 이 366일 이라서 Year로 계산해줘서 강제로 넘김(고용정보원은 365일을 원하는게 아닌 1년을 원하기떄문)
            	if(dateLength % 365 == 0){
            		var dt = moment(frval).add((dateLength/365), 'Year');
            	}else{
            		var dt = moment(frval).add(dateLength-1, 'day');
            	}
            	dateTypeKR = dateLength + "일";
            	if(dateLength >= 365){
            		if(dateLength % 365 == 0 ){
						dateTypeKR = Math.floor(dateLength/365) + "년";	
            		}
            	}
				if(toval > dt){
					returnval= true;
				}
            }else if(dateType.indexOf('MM') != -1){
            	var dt = moment(frval).add(dateLength-1, 'Month');
            	dateTypeKR = dateLength + "개월";
            	if(dateLength >= 12){
            		if(dateLength % 12 == 0){
            			dateTypeKR = Math.floor(dateLength/12) + "년";
            		}else{
						dateTypeKR = Math.floor(dateLength/12) + "년";
						dateTypeKR += " " + (dateLength%12) + "개월";	
            		}
            	}
				if(toval > dt){
					returnval= true;
				}
            }else if(dateType.includes('YYYY') != -1){
            	var dt = moment(frval).add( (dateLength*365) - 1, 'day');
            	dateTypeKR = dateLength + "년";
				if(toval > dt){
					returnval= true;
				}
            }else{
            	var dt = moment(frval).add(1824, 'day');
            	// 초기값 5년
            	dateTypeKR ="5년"
				if(toval > dt){
					returnval= true;
				}
            }
			
	        
	        if(returnval) {
	        	gProgressbar.hide();
	        	WISE.alert('조회기간이 최대 ' + dateTypeKR +'(으)로 제한되어있습니다.. <br> 날짜를 다시 선택해 주세요.');	
	        	return false;
	        }
		}
    	
		
		var queryCheck = false;
		if(gDashboard.tabQuery && !gDashboard.downloadFull) {
			if(WISE.Constants.editmode == 'viewer' && gDashboard.reportType == 'DashAny' && gDashboard.structure.Items.TabContainer != undefined) {
				queryCheck = gDashboard.itemGenerateManager.setSelectedItemList();
			}
		}
		
		
		if(!queryCheck) {
			/* DOGFOOT ktkang 동시 작업 제한 기능 구현  20200922 */
			var works = gDashboard.selectReportWorks();
			if(userJsonObject.limitWorks > 0 && works > userJsonObject.limitWorks) {
				WISE.alert('지금 진행하신 작업이 서버의 동시 작업 제한 건수를 넘어서 취소되었습니다.');
				gDashboard.updateReportLog('99');
				$('#progress_box').css('display', 'none');
				return false;
			} else {
				gProgressbar.show(true);
				/* goyong ktkang 조회할때 로그 추가하도록 수정  20210603 */
				gDashboard.insertReportLog();
				$('#queryCancel').dxButton({
					text:"작업 취소",
					type:'default',
					onClick:function(_e){
						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
						gProgressbar.setStopngoProgress(true);
						gProgressbar.hide();
						$.ajax({
							type : 'post',
							cache : false,
							async: false,
							url : WISE.Constants.context + '/report/cancelqueries.do',
							complete: function(_e) {
								gProgressbar.cancelQuery();
//								gProgressbar.hide();
							}
						});
					}
				});
				//2020.05.15 tbchoi 쿼리 실행 시 매개변수 필터 창 닫기
				$('.ui-button-cancel').click(); 

				//2020.02.12 mksong 보고서 아이템 모두 view 했을 때 프로그레스바 사라지도록 수정 dogfoot
				gDashboard.itemGenerateManager.viewedItemList = [];


				/* DOGFOOT ktkang KERIS 다운로드 시 상세현황 재 조회  20200308 */
				if(!gDashboard.downloadFull) {
					gDashboard.downloadReady = false;
					$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
						$('#'+_item.itemid).css('display','none');
					});

					if(gDashboard.fieldManager != undefined){
						gDashboard.fieldManager.isChange = false;
					}
				} else {
					if(gDashboard.hasTab && !gDashboard.tabQuery) {
						gDashboard.itemGenerateManager.selectedTabList = [];
						$.each(gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id].canvasLayout.container.find('.tab_cont_box_top_tit'),function(_k,_tab){
							var tabid = $(_tab).attr('id').replace('_item_title',''); 
							gDashboard.itemGenerateManager.selectedTabList.push(tabid);
						});
					}
				}

				gDashboard.queryHandler.query(gDashboard.itemGenerateManager);
			}
		}
	};
	
	this.resize = function() {
		//this.parameterHandler.resize();
		$.each(self.layoutManager.itemidBasten,function(_i,_itemId){
			self.layoutManager.resize(_itemId);
		});
		var page = window.location.pathname.split('/');
		if (page[page.length - 1] === 'viewer.do') {
			$.each(self.itemGenerateManager.dxItemBasten,function(_j,_items){
				if(_items.dxItem != undefined){
					switch (_items.type) {
		                case 'PIVOT_GRID':
		                	_items.dxItem.option('width',$('#' + _items.itemid).parent().width());
		                	_items.dxItem.option('height',$('#' + _items.itemid).parent().height());
		                	_items.dxItem.repaint();
		                    break;
		                case 'DATA_GRID':
		                	_items.dxItem.repaint();
		                    break;
		                case 'SIMPLE_CHART':
		                	_items.dxItem.render();
		                    break;
		                case 'RANGE_BAR_CHART':
		                	_items.dxItem.render();
		                    break;
		                case 'RANGE_AREA_CHART':
		                	_items.dxItem.render();
		                	break;
		                case 'TIME_LINE_CHART':
		                	_items.dxItem.render();
		                	break;
		                case 'PIE_CHART':
		                    if (_items.dxItem.length == 1) {
		                        var size = { 'height': $('#' + _items.itemid).height(), 'width': $('#' + _items.itemid).width() };
		                        _items.dxItem[0].option('size', size);
		                        _items.dxItem[0].render();
		                    } else {
		                    	_items.resize();
		                    }
		                    break;
		                case 'TREEMAP':
		                	_items.dxItem.option('size',{'height': $('#'+_items.itemid).height(),'width': $('#'+_items.itemid).width()});
		                	break;
		                case 'HEATMAP':
		                case 'HEATMAP2':
		                	_items.resize();
		                    break;
		                case 'WordCloud':
		                	_items.resize();
		        			break;
		                case 'HISTOGRAM_CHART':
		                	_items.resize();
		                    break;
		                case 'PARALLEL_COORDINATE':
		                case 'BUBBLE_PACK_CHART':
		                case 'WORD_CLOUD_V2':
		                case 'DENDROGRAM_BAR_CHART':
		                case 'CALENDAR_VIEW_CHART':
		                case 'CALENDAR_VIEW2_CHART':
		                case 'CALENDAR_VIEW3_CHART':
		                case 'COLLAPSIBLE_TREE_CHART':
		                case 'COORDINATE_DOT':
                        case 'SYNCHRONIZED_CHARTS':
		                	_items.resize();
		                    break;
		                case 'STAR_CHART':
		                	_items.dxItem.render();
		                	break;
		                case 'HIERARCHICAL_EDGE':
		                	_items.resize();
		                    break;
		            }
				}
			});
		}
	};
	
	this.printScreen = function() {

//		 var beforePrint = function() {

//	    };
//	    var afterPrint = function() {

//	    };
//	 
//	    if (window.matchMedia) {
//	        var mediaQueryList = window.matchMedia('print');
//	        mediaQueryList.addListener(function(mql) {
//	            if (mql.matches) {
//	                beforePrint();
//	            } else {
//	                afterPrint();
//	            }
//	        });
//	    }
//	 
//	    window.onbeforeprint = beforePrint;
//	    window.onafterprint = afterPrint;
		var param = {
			'pid': WISE.Constants.pid,
			'userId':userJsonObject.userId
		}
		$.ajax({
			type : 'post',
			data : param,
			cache : false,
			url : WISE.Constants.context + '/report/printLog.do',
			complete: function() {
				gProgressbar.hide();
			}
		});
		window.print();
	};
	this.folderList = function(){
		var param = {
			'fld_type':'ALL',
			'user_id': userJsonObject.userId,
			'report_type': 'ALL'
		};
		$.ajax({
        	method : 'POST',
            url: WISE.Constants.context + '/report/getReportList.do',
            dataType: "json",
            data:param,
            success: function(result) {
            	var pubResult = result.pubReport;
//				pubResult = pubResult.concat(result.pubScheduleReport);
            	var userResult = result.userReport;
//				userResult = userResult.concat(result.userScheduleReport);
            	
//            	if(typeof userJsonObject.adhocView != 'undefined' && userJsonObject.adhocView == 'wise') {
//            	} else {
//            		var finalResult = [];
//            		$.each(pubResult,functloion(_i, _e){
//            			if(_e.UPPERID == 0 && _e.ID != 2201) {
//            				finalResult.push(_i)
//            			}
//            		});
//
//            		$.each(finalResult,function(_i, _e){
//            			pubResult.splice((_e - _i), 1);
//            		});
//            	}
            	
            	var report_id="",report_type="",fld_type="";
            	var timeout = null;
            	var lastComponent = {};
            	
            	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
            	if(userJsonObject.oldSchedule == 'Y') {
            		var oldPubScheduleList = [];
            		var oldUserScheduleList = [];
            		var oldScheduleList = result.resultAllScheduleList;
            		var oldScheduleform = {};
            		oldScheduleform = {
            				CREATED_BY: "",
            				CREATED_DATE: "",
            				DATASET_XML: "",
            				DESCRIPTION: "",
            				FLD_ID: 0,
            				ID: 9995,
            				ORDINAL: 999,
            				PROMPT: "",
            				QUERY: "",
            				REG_DT: "",
            				REPORT_TYPE: "",
            				SUBTITLE: "",
            				TAG: "",
            				TEXT: "스케줄링 보고서",
            				TYPE: "FOLDER",
            				UPPERID: 0,
            				queryFromDatasetXml: "",
            				schedulePath: "",
            				uniqueKey: "F_9995",
            				upperKey: "F_0"
            		}
            		oldPubScheduleList.push(oldScheduleform);
            		oldUserScheduleList.push(oldScheduleform);
            		
            		oldScheduleform = {
            				CREATED_BY: "",
            				CREATED_DATE: "",
            				DATASET_XML: "",
            				DESCRIPTION: "",
            				FLD_ID: 0,
            				ID: 9996,
            				ORDINAL: 1,
            				PROMPT: "",
            				QUERY: "",
            				REG_DT: "",
            				REPORT_TYPE: "",
            				SUBTITLE: "",
            				TAG: "",
            				TEXT: "완료",
            				TYPE: "FOLDER",
            				UPPERID: 0,
            				queryFromDatasetXml: "",
            				schedulePath: "",
            				uniqueKey: "F_9996",
            				upperKey: "F_9995"
            		}
            		oldPubScheduleList.push(oldScheduleform);
            		oldUserScheduleList.push(oldScheduleform);
            		
            		oldScheduleform = {
            				CREATED_BY: "",
            				CREATED_DATE: "",
            				DATASET_XML: "",
            				DESCRIPTION: "",
            				FLD_ID: 0,
            				ID: 9997,
            				ORDINAL: 1,
            				PROMPT: "",
            				QUERY: "",
            				REG_DT: "",
            				REPORT_TYPE: "",
            				SUBTITLE: "",
            				TAG: "",
            				TEXT: "진행중",
            				TYPE: "FOLDER",
            				UPPERID: 0,
            				queryFromDatasetXml: "",
            				schedulePath: "",
            				uniqueKey: "F_9997",
            				upperKey: "F_9995"
            		}
            		oldPubScheduleList.push(oldScheduleform);
            		oldUserScheduleList.push(oldScheduleform);
            		
            		oldScheduleform = {
            				CREATED_BY: "",
            				CREATED_DATE: "",
            				DATASET_XML: "",
            				DESCRIPTION: "",
            				FLD_ID: 0,
            				ID: 9998,
            				ORDINAL: 1,
            				PROMPT: "",
            				QUERY: "",
            				REG_DT: "",
            				REPORT_TYPE: "",
            				SUBTITLE: "",
            				TAG: "",
            				TEXT: "오류",
            				TYPE: "FOLDER",
            				UPPERID: 0,
            				queryFromDatasetXml: "",
            				schedulePath: "",
            				uniqueKey: "F_9998",
            				upperKey: "F_9995"
            		}
            		oldPubScheduleList.push(oldScheduleform);
            		oldUserScheduleList.push(oldScheduleform);
            		
            		$.each(oldScheduleList,function(_i, _e){
            			var upperId = 0;
            			if(_e.STATUS_CD == 50) {
            				upperId = 'F_9997';
            			} else if(_e.STATUS_CD == 60) {
            				upperId = 'F_9996';
            			} else {
            				upperId = 'F_9998';
            			}
            			var uniqueId = _i + 50000;
            			oldScheduleform = {
                				CREATED_BY: "",
                				CREATED_DATE: "",
                				DATASET_XML: "",
                				DESCRIPTION: "",
                				FLD_ID: 0,
                				ID: _e.REPORT_ID,
                				ORDINAL: _i,
                				PROMPT: "",
                				QUERY: "",
                				REG_DT: "",
                				REPORT_TYPE: _e.REPORT_TYPE,
                				SUBTITLE: "",
                				TAG: "",
                				TEXT: _e.REPORT_NM,
                				TYPE: "REPORT",
                				UPPERID: 0,
                				queryFromDatasetXml: "",
                				uniqueKey: "F_" + uniqueId,
                				upperKey: upperId,
                				icon: WISE.Constants.context+'/resources/main/images/ico_bell.png',
                				schedulePath: _e.EXEC_DATA,
                				STATUS_CD: _e.STATUS_CD
                		};
            			
            			if(_e.FLD_TYPE == 'MY') {
            				oldUserScheduleList.push(oldScheduleform);
            			} else {
            				oldPubScheduleList.push(oldScheduleform);
            			}
        			});
            		
            		pubResult = pubResult.concat(oldPubScheduleList);
            		userResult = userResult.concat(oldUserScheduleList);
            	}
            	
            	$.each(pubResult,function(_i,_items){
            		if(_items.TYPE == 'FOLDER'){
            			_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
            		}else{
            			var schedule = false;
            			/* DOGFOOT ktkang 스케줄링 오류 수정  20201007 */
            			if(userJsonObject.oldSchedule == 'N') {
            				var schedulePath = '';
            				$.each(result.pubScheduleReport,function(_ii,_s){
            					if(_s.TEXT == _items.TEXT) {
            						schedule = true;
            						schedulePath = _s.schedulePath;
            					} 
            				});
            			} else {
            				if(_items.STATUS_CD != '') {
            					schedule = true;
            				}
            			}
            			if(schedule) {
            				_items['icon']= WISE.Constants.context+'/resources/main/images/ico_bell.png';
            				if(userJsonObject.oldSchedule == 'N') {
            					_items['schedulePath'] = schedulePath;
                			}
            			}else if(_items.REPORT_TYPE == 'DashAny' || _items.REPORT_TYPE == 'StaticAnal'){/*dogfoot 통계 분석 추가 shlim 20201102*/
        					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
        				}else if(_items.REPORT_TYPE == 'AdHoc'){
        					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';		            						
        				}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
        					_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';		            						
        				}
            		}
            	});
            	
            	$.each(userResult,function(_i,_items){
            		if(_items.TYPE == 'FOLDER'){
            			_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
            		}else{
            			var schedule = false;
            			/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
            			if(userJsonObject.oldSchedule == 'N') {
            				var schedulePath = '';
            				$.each(result.pubScheduleReport,function(_ii,_s){
            					if(_s.TEXT == _items.TEXT) {
            						schedule = true;
            						schedulePath = _s.schedulePath;
            					} 
            				});
            			} else {
            				if(_items.STATUS_CD != '') {
            					schedule = true;
            				}
            			}
            			if(schedule) {
            				_items['icon']= WISE.Constants.context+'/resources/main/images/ico_bell.png';
            				if(userJsonObject.oldSchedule == 'N') {
            					_items['schedulePath'] = schedulePath;
                			}
            			}else if(_items.REPORT_TYPE == 'DashAny' || _items.REPORT_TYPE == 'StaticAnal'){/*dogfoot 통계 분석 추가 shlim 20201102*/
        					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
        				}else if(_items.REPORT_TYPE == 'AdHoc'){
        					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';		            						
        				}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
        					_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';		            						
        				}
            		}
            	});
            	
            	if(!$('#treeopen').hasClass('on') && !userJsonObject.userViewerReportId){
					$('#treeopen').addClass('on');
				}
				
				var toolTipContent = '<div id="tooltip"><p id="tooltipContent"></p></div>';
				$('body').append(toolTipContent);
				
			    var tooltip = $("#tooltip").dxTooltip({
			        deferRendering: false
			    }).dxTooltip("instance");

				// 2020.01.16 mksong 뷰어 보고서 목록  높이 수정 dogfoot
            	var height = $('#treeopen').height() * 0.87;
        		$('#reportList').dxTreeView({
        			activeStateEnabled: true,
            		dataSource:pubResult,
            		dataStructure:'plain',
            		keyExpr: "uniqueKey",
            		height: height,
            		parentIdExpr: "upperKey",
            		rootValue: "F_0",
            		displayExpr: "TEXT",
            		searchEnabled: true,
        			searchMode : "contains",
        			searchTimeout:undefined,
        			searchValue:"",
					noDataText:"조회된 폴더가 없습니다.",
            		showCloseButton: false,
            		selection: {
            			mode: "single",
            		},
            		onContentReady: function(e){
            			gDashboard.fontManager.setFontConfigForList('reportList');
            		},
            		onItemClick:function(_e){
            			 if (!timeout) {
        			        timeout = setTimeout(function () {
        			            lastComponent = _e.itemData;
        			            timeout = null;
        			        }, 300);
         			    } else if(_e.itemData.TYPE !="FOLDER") {
         			    	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
         			    	if(userJsonObject.oldSchedule == 'Y') {
     			    			if(_e.itemData.STATUS_CD == 60) {
     			    				self.schedulePath = _e.itemData.schedulePath;

         			    			$('.filter-more').css('display','block');
         			    			$('.filter-gui').css('display','block');

         			    			self.openViewerReportGL(_e.itemData.ID, self.reportType);
     			    			} else {
     			    				WISE.alert('지금 진행중이거나 실행 중 오류가 있는 보고서 입니다. 다시 한번 확인해주시기 바랍니다.');
     			    			}
     			    		} else {
     			    			gProgressbar.show();
         			    		/* DOGFOOT hsshim 1226
         			    		 * 불러오기 함수 작업
         			    		 */

         			    		//20201019 AJKIM setTimeout 제거 dogfoot
         			    		$.ajax({
         			    			type:'post',
         			    			url: WISE.Constants.context + '/report/getReportType.do',
         			    			data: { pid: _e.itemData.ID },
         			    			/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//       			    			async:false,
         			    			success:function(_data){

         			    				gProgressbar.setStopngoProgress(false);
         			    				self.reportType = _data.reportType;
         			    				self.fldType = _data.fldType;

         			    				self.schedulePath = _e.itemData.schedulePath;

         			    				$('.filter-more').css('display','block');
         			    				$('.filter-gui').css('display','block');
         			    				
         			    				if(WISE.Constants.editmode == 'viewer'){
         			    					if(userJsonObject.menuconfig.Menu.VIEWER_DIRECT_DSIGNER){
         			    					    if(_e.itemData.AUTH_PUBLISH){
													self.authPublishArr[_e.itemData.ID] = _e.itemData.AUTH_PUBLISH
												}	
                                            }
                                        }
         			    				
         			    				// 2019.12.26 hsshim 뷰어 골든레이아웃 적용과 original 구분 SwitchLayout dogfoot
//       			    				self.openViewerReport(_e.itemData.ID, self.reportType);
         			    				self.openViewerReportGL(_e.itemData.ID, self.reportType);
         			    			}
         			    		});
     			    		}
        			    }
            		},
			        onItemRendered: function (e) {
			            e.itemElement.on({
			                "dxhoverend": function () {
			                    tooltip.hide();
			                },
			                "dxhoverstart": function () {
								if(e.itemData.schedulePath!='') {
									var strArr = e.itemData.schedulePath.split("-");
									var execDateStr = "실행일 : " 
										+ strArr[2].substr(0,4) + "-"
										+ strArr[2].substr(4,2) + "-"
										+ strArr[2].substr(6,2) + " "
										+ strArr[2].substr(8,2) + ":"
										+ strArr[2].substr(10,2);
				                    $("#tooltipContent").text(execDateStr);
				                    tooltip.show(e.itemElement);
								}
			                }
			            });
			        }
            	});
        		
        		/* DOGFOOT ktkang 개인보고서 추가  20200107 */
        		$('#userReportList').dxTreeView({
        			activeStateEnabled: true,
            		dataSource:userResult,
            		dataStructure:'plain',
            		keyExpr: "uniqueKey",
            		height: height,
            		parentIdExpr: "upperKey",
            		rootValue: "F_0",
            		displayExpr: "TEXT",
            		searchEnabled: true,
        			searchMode : "contains",
        			searchTimeout:undefined,
        			searchValue:"",
					noDataText:"조회된 폴더가 없습니다.",
            		showCloseButton: false,
            		selection: {
            			mode: "single",
            		},
            		onContentReady: function(e){
						gDashboard.fontManager.setFontConfigForList('userReportList');
            		},
            		onItemClick:function(_e){
            			 if (!timeout) {
        			        timeout = setTimeout(function () {
        			            lastComponent = _e.itemData;
        			            timeout = null;
        			        }, 300);
         			    } else if(_e.itemData.TYPE !="FOLDER") {
         			    	if(userJsonObject.oldSchedule == 'Y') {
     			    			if(_e.itemData.STATUS_CD == 60) {
     			    				self.schedulePath = _e.itemData.schedulePath;

         			    			$('.filter-more').css('display','block');
         			    			$('.filter-gui').css('display','block');

         			    			self.openViewerReportGL(_e.itemData.ID, self.reportType);
     			    			} else {
     			    				WISE.alert('지금 진행중이거나 실행 중 오류가 있는 보고서 입니다. 다시 한번 확인해주시기 바랍니다.');
     			    			}
     			    		} else {
     			    			gProgressbar.show();
         			    		/* DOGFOOT hsshim 1226
         			    		 * 불러오기 함수 작업
         			    		 */

         			    		//20201019 AJKIM setTimeout 제거 dogfoot
         			    		$.ajax({
         			    			type:'post',
         			    			url: WISE.Constants.context + '/report/getReportType.do',
         			    			data: { pid: _e.itemData.ID },
         			    			/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//       			    			async:false,
         			    			success:function(_data){

         			    				gProgressbar.setStopngoProgress(false);
         			    				self.reportType = _data.reportType;
         			    				self.fldType = _data.fldType;

         			    				self.schedulePath = _e.itemData.schedulePath;
         			    				
         			    				/*dogfoot shlim 뷰어 디자이너 바로가기 기능 구현 20210614*/
         			    				if(userJsonObject.menuconfig.Menu.VIEWER_DIRECT_DSIGNER){
         			    					self.authPublishArr[_e.itemData.ID] = 'Y';
                                        }

         			    				$('.filter-more').css('display','block');
         			    				$('.filter-gui').css('display','block');
         			    				// 2019.12.26 hsshim 뷰어 골든레이아웃 적용과 original 구분 SwitchLayout dogfoot
//       			    				self.openViewerReport(_e.itemData.ID, self.reportType);
         			    				self.openViewerReportGL(_e.itemData.ID, self.reportType);
         			    			}
         			    		});
     			    		}
        			    }
            		},
			        onItemRendered: function (e) {
			            e.itemElement.on({
			                "dxhoverend": function () {
			                    tooltip.hide();
			                },
			                "dxhoverstart": function () {
								if(e.itemData.schedulePath!='') {
									var strArr = e.itemData.schedulePath.split("-");
									var execDateStr = "실행일 : " 
										+ strArr[2].substr(0,4) + "-"
										+ strArr[2].substr(4,2) + "-"
										+ strArr[2].substr(6,2) + " "
										+ strArr[2].substr(8,2) + ":"
										+ strArr[2].substr(10,2);
				                    $("#tooltipContent").text(execDateStr);
				                    tooltip.show(e.itemElement);
								}
			                }
			            });
			        }
            	});
	            //2020.11.03 mksong resource Import 동적 테스트 dogfoot
				console.log('뷰어 완료 타임 : ' + new Date());
            }
    	});
		$('#refreshFolderList').off().on('click',function(){
			self.refreshFolderList();
//			self.folderList();
		});
	}
	this.refreshFolderList = function(){
		var param = {
				'fld_type':'ALL',
				'user_id': userJsonObject.userId,
				'report_type': 'ALL'
		};
		$.ajax({
        	method : 'POST',
            url: WISE.Constants.context + '/report/getReportList.do',
            dataType: "json",
            data:param,
            /* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//            async:false,
            cache: false,
            beforeSend:function(){
            	gProgressbar.show();
            },
            success: function(result) {
            /* DOGFOOT ktkang 개인보고서 추가  20200107 */
            	var pubResult = result.pubReport;
            	var userResult = result.userReport;
            	
            	/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
				if(userJsonObject.oldSchedule == 'Y') {
            		var oldPubScheduleList = [];
            		var oldUserScheduleList = [];
            		var oldScheduleList = result.resultAllScheduleList;
            		var oldScheduleform = {};
            		oldScheduleform = {
            				CREATED_BY: "",
            				CREATED_DATE: "",
            				DATASET_XML: "",
            				DESCRIPTION: "",
            				FLD_ID: 0,
            				ID: 9995,
            				ORDINAL: 999,
            				PROMPT: "",
            				QUERY: "",
            				REG_DT: "",
            				REPORT_TYPE: "",
            				SUBTITLE: "",
            				TAG: "",
            				TEXT: "스케줄링 보고서",
            				TYPE: "FOLDER",
            				UPPERID: 0,
            				queryFromDatasetXml: "",
            				schedulePath: "",
            				uniqueKey: "F_9995",
            				upperKey: "F_0"
            		}
            		oldPubScheduleList.push(oldScheduleform);
            		oldUserScheduleList.push(oldScheduleform);
            		
            		oldScheduleform = {
            				CREATED_BY: "",
            				CREATED_DATE: "",
            				DATASET_XML: "",
            				DESCRIPTION: "",
            				FLD_ID: 0,
            				ID: 9996,
            				ORDINAL: 1,
            				PROMPT: "",
            				QUERY: "",
            				REG_DT: "",
            				REPORT_TYPE: "",
            				SUBTITLE: "",
            				TAG: "",
            				TEXT: "완료",
            				TYPE: "FOLDER",
            				UPPERID: 0,
            				queryFromDatasetXml: "",
            				schedulePath: "",
            				uniqueKey: "F_9996",
            				upperKey: "F_9995"
            		}
            		oldPubScheduleList.push(oldScheduleform);
            		oldUserScheduleList.push(oldScheduleform);
            		
            		oldScheduleform = {
            				CREATED_BY: "",
            				CREATED_DATE: "",
            				DATASET_XML: "",
            				DESCRIPTION: "",
            				FLD_ID: 0,
            				ID: 9997,
            				ORDINAL: 1,
            				PROMPT: "",
            				QUERY: "",
            				REG_DT: "",
            				REPORT_TYPE: "",
            				SUBTITLE: "",
            				TAG: "",
            				TEXT: "진행중",
            				TYPE: "FOLDER",
            				UPPERID: 0,
            				queryFromDatasetXml: "",
            				schedulePath: "",
            				uniqueKey: "F_9997",
            				upperKey: "F_9995"
            		}
            		oldPubScheduleList.push(oldScheduleform);
            		oldUserScheduleList.push(oldScheduleform);
            		
            		oldScheduleform = {
            				CREATED_BY: "",
            				CREATED_DATE: "",
            				DATASET_XML: "",
            				DESCRIPTION: "",
            				FLD_ID: 0,
            				ID: 9998,
            				ORDINAL: 1,
            				PROMPT: "",
            				QUERY: "",
            				REG_DT: "",
            				REPORT_TYPE: "",
            				SUBTITLE: "",
            				TAG: "",
            				TEXT: "오류",
            				TYPE: "FOLDER",
            				UPPERID: 0,
            				queryFromDatasetXml: "",
            				schedulePath: "",
            				uniqueKey: "F_9998",
            				upperKey: "F_9995"
            		}
            		oldPubScheduleList.push(oldScheduleform);
            		oldUserScheduleList.push(oldScheduleform);
            		
            		$.each(oldScheduleList,function(_i, _e){
            			var upperId = 0;
            			if(_e.STATUS_CD == 50) {
            				upperId = 'F_9997';
            			} else if(_e.STATUS_CD == 60) {
            				upperId = 'F_9996';
            			} else {
            				upperId = 'F_9998';
            			}
            			var uniqueId = _i + 50000;
            			oldScheduleform = {
                				CREATED_BY: "",
                				CREATED_DATE: "",
                				DATASET_XML: "",
                				DESCRIPTION: "",
                				FLD_ID: 0,
                				ID: _e.REPORT_ID,
                				ORDINAL: _i,
                				PROMPT: "",
                				QUERY: "",
                				REG_DT: "",
                				REPORT_TYPE: _e.REPORT_TYPE,
                				SUBTITLE: "",
                				TAG: "",
                				TEXT: _e.REPORT_NM,
                				TYPE: "REPORT",
                				UPPERID: 0,
                				queryFromDatasetXml: "",
                				uniqueKey: "F_" + uniqueId,
                				upperKey: upperId,
                				icon: WISE.Constants.context+'/resources/main/images/ico_bell.png',
                				schedulePath: _e.EXEC_DATA,
                				STATUS_CD: _e.STATUS_CD
                		};
            			
            			if(_e.FLD_TYPE == 'MY') {
            				oldUserScheduleList.push(oldScheduleform);
            			} else {
            				oldPubScheduleList.push(oldScheduleform);
            			}
        			});
            		
            		pubResult = pubResult.concat(oldPubScheduleList);
            		userResult = userResult.concat(oldUserScheduleList);
            	}
				
            	var report_id="",report_type="",fld_type="";
            	var timeout = null;
            	$.each(pubResult,function(_i,_items){
            		if(_items.TYPE == 'FOLDER'){
            			_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
            		}else{
            			var schedule = false;
            			/* DOGFOOT ktkang BMT 스케줄링 옵션처리 추가  20201201 */
            			if(userJsonObject.oldSchedule == 'N') {
            				var schedulePath = '';
            				$.each(result.pubScheduleReport,function(_ii,_s){
            					if(_s.TEXT == _items.TEXT) {
            						schedule = true;
            						schedulePath = _s.schedulePath;
            					} 
            				});
            			} else {
            				if(_items.STATUS_CD != '') {
            					schedule = true;
            				}
            			}
            			if(schedule) {
            				_items['icon']= WISE.Constants.context+'/resources/main/images/ico_bell.png';
            				if(userJsonObject.oldSchedule == 'N') {
            					_items['schedulePath'] = schedulePath;
                			}
            			}else if(_items.REPORT_TYPE == 'DashAny' || _items.REPORT_TYPE == 'StaticAnal'){/*dogfoot 통계 분석 추가 shlim 20201102*/
        					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
        				}else if(_items.REPORT_TYPE == 'AdHoc'){
        					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';		            						
        				}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
        					_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';		            						
        				}
            		}
            	});
            	
            	$.each(userResult,function(_i,_items){
            		if(_items.TYPE == 'FOLDER'){
            			_items['icon']= WISE.Constants.context+'/resources/main/images/ico_load.png';
            		}else{
            			var schedule = false;
            			/* DOGFOOT ktkang 스케줄링 오류 수정  20201007 */
            			if(userJsonObject.oldSchedule == 'N') {
            				var schedulePath = '';
            				$.each(result.pubScheduleReport,function(_ii,_s){
            					if(_s.TEXT == _items.TEXT) {
            						schedule = true;
            						schedulePath = _s.schedulePath;
            					} 
            				});
            			} else {
            				if(_items.STATUS_CD != '') {
            					schedule = true;
            				}
            			}
            			if(schedule) {
            				_items['icon']= WISE.Constants.context+'/resources/main/images/ico_bell.png';
            				if(userJsonObject.oldSchedule == 'N') {
            					_items['schedulePath'] = schedulePath;
                			}
            			}else if(_items.REPORT_TYPE == 'DashAny' || _items.REPORT_TYPE == 'StaticAnal'){/*dogfoot 통계 분석 추가 shlim 20201102*/
        					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_squariFied.png';
        				}else if(_items.REPORT_TYPE == 'AdHoc'){
        					_items['icon']= WISE.Constants.context+'/resources/main/images/ico_atypical01.png';		            						
        				}else if(_items.REPORT_TYPE == 'Spread' || _items.REPORT_TYPE == 'Excel'){
        					_items['icon']= WISE.Constants.context+'/resources/main/images/excelFile_icon.png';		            						
        				}
            		}
            	});
            	
        		$('#reportList').dxTreeView('instance').option('dataSource',pubResult);
        		$('#reportList').dxTreeView('instance').repaint();
        		
        		$('#userReportList').dxTreeView('instance').option('dataSource',userResult);
        		$('#userReportList').dxTreeView('instance').repaint();
        		
            },
            complete:function(){
            	gProgressbar.hide();
            }
		})
	}
	// DOGFOOT hsshim 1220 골든레이아웃 뷰어 기능 추가
	/**
	 * Open adhoc report in viewer mode. 골든레이아웃
	 */
	this.openAdhocViewerReport = function(reportId) {
		// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
		var fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
		fieldManager.focusItemType = 'adhocItem';
		gDashboard.itemQuantity[fieldManager.focusItemType]++;
		//
		/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
		var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(gDashboard.structure.ReportMasterInfo.cube_nm);
		
		//2020.11.06 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('itemJS','Chart');
		// chart 넣기
		var item = new WISE.libs.Dashboard.item.ChartGenerator();
		item.kind = 'chart';
		gDashboard.itemQuantity[item.kind]++;
		if(gDashboard.structure.ReportMasterInfo.reportJson != undefined){
			if(gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT != undefined){
				item.Name = gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT.CHART_TITLE == undefined ? "차트" : gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT.CHART_TITLE;
			}else{
				item.Name = "차트";	
			}
			if(gDashboard.structure.ReportMasterInfo.reportJson.WEB != undefined){
				item.memoText = gDashboard.structure.ReportMasterInfo.reportJson.WEB.MEMO_ELEMENT.CHART_MEMO == undefined ? "" : gDashboard.structure.ReportMasterInfo.reportJson.WEB.MEMO_ELEMENT.CHART_MEMO
			}else{
				item.memoText = "";	
			}
		}else{
			item.memoText = "";
			item.Name = "차트";
		}
		item.ComponentName = 'chartDashboardItem' + gDashboard.itemQuantity[item.kind] + '_' + reportId;
		item.isAdhocItem = true;
		item.adhocIndex = gDashboard.itemQuantity[fieldManager.focusItemType];
		// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
		gDashboard.fieldManager = item.fieldManager = fieldManager;
		item.fieldManager.focusItemType = 'adhocItem';
		item.index = gDashboard.itemQuantity[item.kind] + '_' + reportId;
		item.fieldManager.index = gDashboard.itemQuantity[item.fieldManager.focusItemType] + '_' + reportId;
		item.fieldManager.seriesType = 'Bar';
		//
		item.itemid = item.ComponentName + '_item';
		/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
		item.dataSourceId = dataSrcId;

		var chartXml = gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML;
		var chartMeta = {
			AxisX: {
				Rotation: chartXml.X_ANGLE,
				Title: chartXml.AXISX_TITLE,
				Visible: true
			},
			AxisY: {
				FormatType: "Number",
				MeasureFormat: {O: "", K: "천", M: "백만", B: "십억"},
				Precision: 0,
				Separator: true,
				SuffixEnabled: false,
				Title: chartXml.AXISY_TITLE,
				Unit: "Ones",
				Visible: true
			},
			ChartLegend: {
				Visible: chartXml.LEGEND_ENABLE,
				IsInsidePosition: chartXml.LEGEND_POSITION? chartXml.LEGEND_POSITION : false,
				/* DOGFOOT hsshim 2020-02-06 비정형 범례 저장 오류 수정 */
				InsidePosition: WISE.libs.Dashboard.item.ChartUtility.Legend.getAdhoc(chartXml.LEGEND_DOCK),
				OutsidePosition: WISE.libs.Dashboard.item.ChartUtility.Legend.getAdhoc(chartXml.LEGEND_DOCK),
			},
			Animation: chartXml.ANIMATION,
			Palette: chartXml.PALETTE,
			Panes: {},
			SeriesType: WISE.libs.Dashboard.item.ChartUtility.Series.Simple.getChartName(chartXml.CHART_TYPE)
		};
		
		//2020.11.13 mksong 비정형 보고서 showCaption 기능 추가 dogfoot
		if(gDashboard.structure.ReportMasterInfo.reportJson.DISP_CHART_CAPTION_ELEMENT != undefined){
			chartMeta['ShowCaption'] = gDashboard.structure.ReportMasterInfo.reportJson.DISP_CHART_CAPTION_ELEMENT;
			if(WISE.Constants.editmode != 'viewer'){
				gDashboard.structure.ReportMasterInfo.reportJson.DISP_CHART_CAPTION_ELEMENT = undefined;
			}	
		}
		
		item.meta = chartMeta;
		gDashboard.itemGenerateManager.dxItemBasten.push(item);

		// 피벗 생성
		//2020.11.06 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('itemJS','PivotGrid');
		var item2 = new WISE.libs.Dashboard.item.PivotGridGenerator();
		item2.kind = 'pivotGrid';
		gDashboard.itemQuantity[item2.kind]++;
		
		if(gDashboard.structure.ReportMasterInfo.reportJson != undefined){
			if(gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT != undefined){
				item2.Name = gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT.PIVOT_TITLE == undefined ? "피벗" : gDashboard.structure.ReportMasterInfo.reportJson.TITLE_ELEMENT.PIVOT_TITLE;
			}else{
				item2.Name = '피벗';
			}
			if(gDashboard.structure.ReportMasterInfo.reportJson.WEB != undefined){
				item2.memoText = gDashboard.structure.ReportMasterInfo.reportJson.WEB.MEMO_ELEMENT.PIVOT_MEMO == undefined ? "" : gDashboard.structure.ReportMasterInfo.reportJson.WEB.MEMO_ELEMENT.PIVOT_MEMO;
			}else{
				item2.memoText = "";	
			}
		}else{
			item2.memoText = "";
			item2.Name = '피벗';	
		}
		item2.ComponentName = 'pivotDashboardItem' + gDashboard.itemQuantity[item2.kind] + '_' + reportId;
		// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
		item2.itemid = item2.ComponentName + '_item';
		//
		item2.isAdhocItem = true;
		item2.adhocIndex = gDashboard.itemQuantity[fieldManager.focusItemType];
		/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
		item2.dataSourceId = dataSrcId;
		
		//2020.11.13 mksong 비정형 보고서 showCaption 기능 추가 dogfoot
		if(gDashboard.structure.ReportMasterInfo.reportJson.DISP_PIVOT_CAPTION_ELEMENT != undefined){
			item2['ShowCaption'] = gDashboard.structure.ReportMasterInfo.reportJson.DISP_PIVOT_CAPTION_ELEMENT;
			if(WISE.Constants.editmode != 'viewer'){
				gDashboard.structure.ReportMasterInfo.reportJson.DISP_PIVOT_CAPTION_ELEMENT = undefined;
			}	
		}
		
		// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
		gDashboard.fieldManager = item2.fieldManager = fieldManager;
		item2.fieldManager.focusItemType = 'adhocItem';
		item2.index = gDashboard.itemQuantity[item2.kind] + '_' + reportId;
		item2.fieldManager.index = gDashboard.itemQuantity[item.fieldManager.focusItemType] + '_' + reportId;
		gDashboard.fieldChooser.setAnalysisFieldArea(item2, true);
		//

		gDashboard.itemGenerateManager.dxItemBasten.push(item2);
		
		self.goldenLayoutManager[reportId] = new WISE.libs.Dashboard.GoldenLayoutManager();
		gDashboard.structure.Layout = gDashboard.structure.ReportMasterInfo.layout;
		self.goldenLayoutManager[reportId].render('adhoc', true, reportId);
		gDashboard.changeReportTypeManager.init();
		gDashboard.changeReportTypeManager.activeAdhocLayout(gDashboard.structure.Layout);
		gDashboard.itemGenerateManager.init();
		
		// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
		item.dragNdropController = new WISE.widget.DragNDropController(item);
		item2.dragNdropController = new WISE.widget.DragNDropController(item2);
		//
		// 2019.12.10 수정자 : mksong 뷰어 비정형 포커싱 DOGFOOT
		gDashboard.itemGenerateManager.focusItem(self.itemGenerateManager.dxItemBasten[1], self.itemGenerateManager.dxItemBasten[1]);
		
		//2020.01.21 mksong 비정형 레이아웃 수정 dogfoot
		//2020.03.09 MKSONG 뷰어에서 비정형 레이아웃 변경 오류 수정 DOGFOOT
		
//		gDashboard.changeReportTypeManager.activeViewerAdhocLayout();
	}
	// 1220 끝
	
	/**
	 * Open adhoc report in viewer mode.
	 */
	this.itemGenerateManagerAdhocInit = function(layout, reportId){
		// 2019.12.16 수정자 : mksong 뷰어 비정형 GoldenLayout 아닐 경우 주석 제거 DOGFOOT
		// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
		var fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
		/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
		var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(gDashboard.structure.ReportMasterInfo.cube_nm);
		
		var insertChart = function(fieldManager){
			//chart 넣기
			//2020.11.06 mksong resource Import 동적 구현 dogfoot
			WISE.loadedSourceCheck('itemJS','Chart');
			var item = new WISE.libs.Dashboard.item.ChartGenerator();
			item.kind = 'chart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '차트 ';
			item.ComponentName = 'chartDashboardItem' + gDashboard.itemQuantity[item.kind]+'_'+WISE.Constants.pid;
			item.isAdhocItem = true;
			item.adhocIndex = 0;
			// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
			gDashboard.fieldManager = item.fieldManager = fieldManager;
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind] + '_' + reportId;
			item.fieldManager.seriesType = 'Bar';
			/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
			item.dataSourceId = dataSrcId;
			
			item.itemid = item.ComponentName + '_item';
			
			gDashboard.itemGenerateManager.dxItemBasten.push(item);
			gDashboard.itemGenerateManager.init();
			
			item.dragNdropController = new WISE.widget.DragNDropController(item);	
			item.dragNdropController.addSortableOptionsForOpen(item);
		}
		
		var insertPivot = function(fieldManager){
			//피벗 생성
			//2020.11.06 mksong resource Import 동적 구현 dogfoot
			WISE.loadedSourceCheck('itemJS','PivotGrid');
			var item2 = new WISE.libs.Dashboard.item.PivotGridGenerator();
			item2.kind = 'pivotGrid';
			gDashboard.itemQuantity[item2.kind]++;
			item2.Name = '피벗 ';
			item2.ComponentName = 'pivotDashboardItem' + gDashboard.itemQuantity[item2.kind]+'_'+WISE.Constants.pid;
			item2.isAdhocItem = true;
			item2.adhocIndex = 0;
			/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
			item2.dataSourceId = dataSrcId;
			
			// 2019.12.10 수정자 : mksong 뷰어 비정형 컬럼선택기 추가 위한 수정 DOGFOOT
			gDashboard.fieldManager = item2.fieldManager = fieldManager;
			item2.fieldManager.index = item2.index = gDashboard.itemQuantity[item2.kind] + '_' + reportId;
			gDashboard.fieldChooser.setAdhocAnalysisFieldAreaForViewer(item2,reportId);
			item2.itemid = item2.ComponentName + '_item';
			
			gDashboard.itemGenerateManager.dxItemBasten.push(item2);
			gDashboard.itemGenerateManager.init();
		}
		
		var fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
		
		if($('#columnSelectorPopup').length < 1){
			$('<div id="columnSelectorPopup">').dxPopup({
				height: 'auto',
				width: 800,
				visible: false,
				showCloseButton: false
			}).appendTo('body');	
		}
		
		var contentPanel = function(_itemid) {
			var html;
			html = '<div class="cont_box">';
			html += '<div class="cont_box_top">';
			html += '<div id="' + _itemid + '_title' + '" class="cont_box_top_tit"></div>';
			html += '<ul id="' + _itemid + '_topicon' + '" class="cont_box_top_icon"></ul>';
			html += '</div>'; // end of cont_box_top
			
//			html += '<div id="' + _itemid + '_item" class="cont_box_cont" style="padding:20px"></div>';
			html += '<div id="' + _itemid+ '" class="cont_box_cont" style="padding:20px"></div>';
			html += '</div>'; // end of cont_box
			
			return html;
		};
		
		var html;
		insertChart(fieldManager);
		insertPivot(fieldManager);
		switch (layout){
			case 'C':
				html = '<div id="' + self.itemGenerateManager.dxItemBasten[0].ComponentName + '" class="content-full" style=\"width:100%;height:100%;float:left\">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[0].itemid);
				html += '</div>'; 
				html += '<div id="' + self.itemGenerateManager.dxItemBasten[1].ComponentName + '" class="content-full" style=\"display:none;float:left\">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[1].itemid);
				html += '</div>';
				break;
			case 'G':
				html = '<div id="' + self.itemGenerateManager.dxItemBasten[0].ComponentName + '" class="content-full" style=\"display:none;float:left\">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[0].itemid);
				html += '</div>'; 
				html += '<div id="' + self.itemGenerateManager.dxItemBasten[1].ComponentName + '" class="content-full" style=\"width:100%;height:100%;float:left\">';
				html += contentPanel(self.itemGenerateManager.dxItemBasten[1].itemid);
				html += '</div>';
				break;
			case 'CTGB':
				html = '<div id="' + self.itemGenerateManager.dxItemBasten[0].ComponentName + '" class="content-top" style="height:50%;width:100%;float:left">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[0].itemid);
				html += '</div>'; 
				html += '<div id="' + self.itemGenerateManager.dxItemBasten[1].ComponentName + '" class="content-bottom" style="height:50%;width:100%;float:left">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[1].itemid);
				html += '</div>';
				break;
			case 'CLGR':
				html = '<div id="' + self.itemGenerateManager.dxItemBasten[0].ComponentName + '" class="content-left" style="height:100%;width:50%;float:left">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[0].itemid);
				html += '</div>'; 
				html += '<div id="' + self.itemGenerateManager.dxItemBasten[1].ComponentName + '" class="content-right" style="height:100%;width:50%;float:left">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[1].itemid);
				html += '</div>';
				break;
			case 'CBGT':
				html = '<div id="' + self.itemGenerateManager.dxItemBasten[1].ComponentName + '" class="content-top" style="height:50%;width:100%;float:left">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[1].itemid);
				html += '</div>'; 
				html += '<div id="' + self.itemGenerateManager.dxItemBasten[0].ComponentName + '" class="content-bottom" style="margin-top:30px;height:50%;width:100%;float:left">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[0].itemid);
				html += '</div>';
				break;
			case 'CRGL':
				html = '<div id="' + self.itemGenerateManager.dxItemBasten[1].ComponentName + '" class="content-left" style="height:100%;width:50%;float:left">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[1].itemid);
				html += '</div>'; 
				html += '<div id="' + self.itemGenerateManager.dxItemBasten[0].ComponentName + '" class="content-right" style="height:100%;width:50%;float:left">'; 
				html += contentPanel(self.itemGenerateManager.dxItemBasten[0].itemid);
				html += '</div>';
				$('#' + self.containerId+"_"+WISE.Constants.pid).html(html);
				break;
		}
		$('#' + self.containerId+"_"+WISE.Constants.pid).html(html);
		gDashboard.structure.Layout = layout;
		//2020.01.21 mksong 비정형 레이아웃 수정 dogfoot
		gDashboard.changeReportTypeManager.activeAdhocLayout();
//		gDashboard.changeReportTypeManager.activeViewerAdhocLayout();
		gDashboard.structure.MapOption = {DASHBOARD_XML: undefined};
		
		gDashboard.itemGenerateManager.focusItem(self.itemGenerateManager.dxItemBasten[1],self.itemGenerateManager.dxItemBasten[1]);
		// 2019.12.16 수정자 : mksong 뷰어 비정형 GoldenLayout 아닐 경우 주석제거 끝 DOGFOOT
	};
	
	this.editDataSourceByTarget = function(targetId,targetCaption, targetType){
		gProgressbar.show();
		this.ConstraintList;
		this.ColumnList;
		this.allList;
		this.datasetType;
		this.dsInfo;
		this.selectedTables = [];
		var MeaTables = [];
		var DimTables = [];
		this.relationLength = 1;
		var dataset_id="";
		var datasetInfo;
		var selectedTargetDataSet;
		var ds_id = gDashboard.dataSourceManager.datasetInformation[targetId].DATASRC_ID;
		var wise_sql_id = gDashboard.dataSourceManager.datasetInformation[targetId].wise_sql_id;
		var commonParamType = [
			{key:'LIST', caption:'리스트'},{key:'INPUT', caption:'입력창'},{key:'CAND', caption:'달력'}
		]
		var betweenParamType = [
			{key:'BETWEEN_LIST', caption:'between 리스트'},{key:'BETWEEN_INPUT', caption:'between 입력창'},{key:'BETWEEN_CAND', caption:'between 달력'}
		];

		if(targetType =='DataSetSingleDs'){
			//신규데이타집합(단일테이블)
			var ds_id = gDashboard.dataSourceManager.datasetInformation[targetId].DATASRC_ID;
			var wise_sql_id = gDashboard.dataSourceManager.datasetInformation[targetId].wise_sql_id;
			
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
//			"                                <div class=\"modal-article\" style=\"margin-top:30px;\">\r\n" + 
//			"                                   <div class=\"modal-tit\">\r\n" + 
//			"                                   <span>데이터 항목</span>\r\n" + 
//			"                                   </div>\r\n" + 
//			"									<div id=\"dataSetTableInfo\" style=\"width: 300px; height: 400px;\" />\r\n" + 
//			"                                </div>\r\n" +
			// 2020.01.07 mksong 리사이즈 버튼 주석 dogfoot
//			"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
			"                            </div>\r\n" + 
			"                            <div class=\"column\" style=\"width:75%\">\r\n" +
			"                            	<div class=\"row horizen\">\r\n" + 
			" 		                            <div class=\"column\" style=\"height: 600px;\">\r\n" +
			"		                                <div class=\"modal-article\">\r\n" + 
			"       	                           		<div class=\"modal-tit\">\r\n" +
			'												<div class="right-item"><a id="ds_query_button" class="btn crud neutral" style="float:right;">쿼리보기</a><div id="ds_query_popup"></div></div>'+
			'												<div class="right-item"><a id="ds_param_button" class="btn crud neutral" style="float:right;">매개변수</a></div>'+
															//20210122 AJKIM 계산된 컬럼 추가 DOGFOOT
			'												<div class="left-item"><a id="add_calculated_field" class="btn crud neutral" style="float:right; margin-right: 10px;">계산된 컬럼 추가</a><div id="add_calculated_field"></div></div>'+
			'												<div class="left-item"><a id="add_group_field" class="btn crud neutral" style="display: none; float:right; margin-right: 10px;">그룹 컬럼 추가</a><div id="add_calculated_field"></div></div>'+
//			"           	                            	<span>쿼리</span>\r\n" + 
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
//			'											<div id="sql_area" class="sql_area" style="float:right;">'+
			+'<div class="column">'
			+'<h4 class="tit-level3 pre" style="padding: 10px 9px 9px 20px">표시 항목</h4>'
			+'<div class="panel-inner componet-res">'
			+'<div id="ExpressArea" class="tbl data-form preferences-tbl"></div>'
			+'</div>'
			+'</div>'
			+"                           		   	</div>\r\n" +
//			"                                       <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" +
			"                              		</div>\r\n" + //column끝
//			" 		                            <div class=\"column\" style=\"padding-bottom:0px; height: 345px;\">\r\n" +
//			'										<div class="modal-article">' +
//			"											<div id=\"param_area\" class=\"param_area modal-tit\">\r\n" + 
//			"   		                                     <span>매개변수<em class=\"red\">*매개변수는 영문만 가능합니다.</em></span>" + 
//			'												 <div class="right-item">' +
//			'												 	<a id=\"param_create_btn\" class="btn crud positive" href="#">생성</a>' +
//			'												 	<a id=\"param_edit_btn\" class="btn crud neutral" href="#">편집</a>' +
//			'												 	<a id=\"param_delete_btn\" class="btn crud negative" href="#">삭제</a>' +
//			'												 </div>' +
//			"       	                	            </div>\r\n" +
//			"											<div id=\"param_grid\" class=\"active\"></div>\r\n" +
//			"       	                	        </div>\r\n" +
//			" 									</div>" + //column 끝
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
			
			$('#edit_ds_popup').dxPopup({
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
				onShown: function () {
					miniPop();
					var tableList;
					var colList;
					var listId = 1;
					gDashboard.dataSetCreate.subjectInfoList[targetId]['데이터 원본 유형'] = '단일테이블';
					if(!gDashboard.dataSetCreate.subjectInfoList[targetId].dataType){
						gDashboard.dataSetCreate.subjectInfoList[targetId].dataType = '단일테이블';
					}
					if(!gDashboard.dataSetCreate.subjectInfoList[targetId].TBL_NM){
						gDashboard.dataSetCreate.subjectInfoList[targetId].TBL_NM = gDashboard.datasetMaster.getState('DATASETS')[targetId].DATASET_NM;
					}
					$("#ds_info").dxForm({
						width: 300,
						height: 200,
						readOnly: true,
						formData: gDashboard.dataSetCreate.subjectInfoList[targetId],
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
					
					$('#ds_name_text').text(gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_NM);
					
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
								visible: false,
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
								caption:'표시',
								dataField:'VISIBLE',
								alignment:"center",
								dataType:'boolean',
								width:'80px'
							},{
								caption:'순서',
								//dataField:'COL_ID',
								dataField:'ORDER',
								width:'80px',
				                setCellValue: function(newData, value, currentRowData) {
									if(value<0) newData.ORDER = 0;
				                    else newData.ORDER = value;
				                }
							},
							
						],
						noDataText:"",
						dataSource:gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.COL_ELEMENT.COLUMN,
						editing: {
				            mode: "cell",
				            allowUpdating: true,
				            texts: {
				                confirmDeleteMessage: ""
				            }
						},onRowUpdated:function(_e){

//							if(_e.key.TYPE != undefined){
//								if(_e.key.TYPE === 'MEA'){
//									_e.key.AGG = 'Sum';
//								}else{
//									_e.key.AGG = '';
//								}	
//							}
						},
						onSelectionChanged: function(_e){
							if(_e.selectedRowsData[0].TYPE == "DIM" && _e.selectedRowsData[0].DATA_TYPE !== 'grp' && _e.selectedRowsData[0].DATA_TYPE !== 'cal')
								$("#add_group_field").css("display", "inline-block")
							else
								$("#add_group_field").css("display", "none")
						}
					});
					
					/* DOGFOOT ktkang 단일테이블 필터 수정 추가  20201125 */
					$("#ds_param_button").dxButton({
						height: 30,
						type: "normal",
						onClick: function(e) {
							if(gDashboard.isNewReport) {
								/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
								gDashboard.FieldFilter.editFilter(true, null, null, null, true);
							} else {
								gDashboard.FieldFilter.editFilter(true, gDashboard.datasetMaster.state.datasources.dataSource1.DS_ID, gDashboard.datasetMaster.state.params, gDashboard.datasetDesigner.onParamEditConfirm, true);
							}
						}
					});
					
					//20200122 AJKIM 계산된 컬럼 추가 DOGFOOT
					$("#add_calculated_field").dxButton({
						height: 30,
						type: "normal",
						onClick: function(e) {
							
							var columnList = gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.COL_ELEMENT.COLUMN;
							var dsInfo = {
									DS_ID :gDashboard.dataSourceManager.datasetInformation[targetId].DATASRC_ID,
									TBL_NM : gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.TBL_ELEMENT
							}
							
							gDashboard.customFieldManager.createCustomField(columnList, dsInfo, 'dscal');
////							var html = '<div id="cal_panel" class="cal_panel" style="height: calc(100% - 85px);"></div>';
//							var html = "<div class=\"modal-body\" style='height:80%'>\r\n" + 
//							"                        <div class=\"row\" style='height:100%'>\r\n" + 
//							"                            <div class=\"column\" style='width:100%;padding-top:0px'>\r\n" + 
//							"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
//							"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
//							"                                   	<span>컬럼명</span>\r\n" + 
//							"                                   </div>\r\n" +
//							"									<div style='text-align: right;'>\r\n"+
//							"										<div id=\"field_name\"></div>\r\n" +
//							"									</div>\r\n"+
//							"                                </div>\r\n" +
//							"                                <div class=\"modal-article\" style=\"margin-top: 5px;height:80%;\">\r\n" + 
//							"                                   <div class=\"modal-tit\" style='padding-bottom: 5px;'>\r\n" + 
//							"                                   	<span>계산식</span>\r\n" + 
//							"                                   </div>\r\n" + 
//							/* DOGFOOT ktkang 저장 버튼 위치 수정  20200619 */
//							"								 <div id=\"field_cal\" style=\"height:70%;\"></div>\r\n" +
//							"                                </div>\r\n" +
//							"                            </div>\r\n" + 
//							"                        </div>\r\n" + // row 끝
//							"                    </div>\r\n"; // modal-body 끝
//							html += "<div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
//							"	<div class=\"row center\">\r\n" + 
//							"		<a id=\"btn_tabpanel_ok\" class=\"btn positive ok-hide\" href=\"#\" >확인</a>\r\n" + 
//							"		<a id=\"btn_tabpanel_cancel\" class=\"btn neutral ok-hide\" href=\"#\" >취소</a>\r\n" + 
//							"	</div>\r\n" + 
//							"</div>\r\n";
//							$('#ds_name_change').dxPopup({
//								showCloseButton: true,
//								showTitle: true,
//								visible: true,
//								title: "계산된 컬럼 추가",
//								closeOnOutsideClick: false,
//								contentTemplate: function() {
//									return html;
//								},
//								width: '90vw',
//								height: '90vh',
//								maxWidth: 700,
//								maxHeight: 500,
//								onShown: function () {
//									$('#field_name').dxTextBox();
//									$('#field_cal').dxTextArea();
//								}, onContentReady : function() {
//									$("#btn_tabpanel_ok").dxButton({
//										text: "확인",
//										type: "normal",
//										onClick: function(e) {
//											var _data = gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.COL_ELEMENT.COLUMN;
//											
//											var temp = {
//													TBL_NM: _data[0].TBL_NM,
//													COL_NM: $('#field_cal').dxTextArea('option').value,
//													COL_CAPTION: $('#field_name').dxTextBox('option').value,
//													DATA_TYPE: "cal",
//	                                                AGG: "",
//	                                                PK_YN: "",
//	                                                TYPE: "DIM",
//	                                                VISIBLE: true,
//	                                                COL_ID: "0"
//												};
//											
//											var param = {
//													'dsid' : gDashboard.dataSourceManager.datasetInformation[targetId].DATASRC_ID,
//													'dstype' : 'DS_SQL',
//													'sql' : "SELECT  TOP 1 "+ temp.COL_NM +" AS ["+ temp.COL_CAPTION +"] FROM " + gDashboard.dataSourceManager.datasetInformation["dataSource2"].DATASET_JSON.DATA_SET.TBL_ELEMENT,
//													'params' :{}
//											};
//											
//											$.ajax({
//												type : 'post',
//												data: param,
//												url : WISE.Constants.context + '/report/directSql.do',
//												success : function(data) {
//													var result = data.data;
//													
//													if(result){
//														gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.COL_ELEMENT.COLUMN.push(temp);
//														
//			                                            $('#ExpressArea').dxDataGrid('instance').refresh()
//														$("#ds_name_change").dxPopup("instance").hide();
//													}
//													
//												},error: function(_response) {
//													gProgressbar.hide();
//													WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
//												}
//											});
//											
//											
//										}
//									});
//									
//									$("#btn_tabpanel_cancel").dxButton({
//										text: "확인",
//										type: "normal",
//										onClick: function(e) {
//											$("#ds_name_change").dxPopup("instance").hide();
//										}
//									});
//								}
//							});
						}
							
					});
					
					//20200122 AJKIM 계산된 컬럼 추가 DOGFOOT
					$("#add_group_field").dxButton({
						height: 30,
						type: "normal",
						onClick: function(e) {
							var columnList = gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.COL_ELEMENT.COLUMN;
							var dsInfo = {
									DS_ID :gDashboard.dataSourceManager.datasetInformation[targetId].DATASRC_ID,
									TBL_NM : gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.TBL_ELEMENT
							}
							
							gDashboard.customFieldManager.createCustomField(columnList, dsInfo, 'dsgrp')
						}
							
					});
					
					$("#ds_query_button").dxButton({
						height: 30,
						type: "normal",
						onClick: function(e) {
							var html = '<div id="query_tabpanel" class="query_tabpanel" style="height: calc(100% - 45px);"></div>';
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
								        height: 'calc(100% - 45px)',
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
													dsId: gDashboard.datasetMaster.getSelectedDataset().DATASRC_ID,
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
																	
																	if(result){
																	/* DOGFOOT ktkang 테스트 쿼리보기용 쿼리 수정  20200629 */
//																		$('#edit_sqlRowNumber').text('총 건수 : ' + result.length + " 건");
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
								        			
//								        			if(gDashboard.structure.ReportMasterInfo.paramJson) {
//														gDashboard.parameterHandler.init();
//														gDashboard.parameterHandler.render(true);
//														gDashboard.parameterHandler.resize();
//													}
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
							var tbl_nm = gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.TBL_ELEMENT;
							var selectionList = $('#ExpressArea').dxDataGrid('instance').option('dataSource');
							$.each(selectionList,function(_i,_data){
								if(tbl_nm.indexOf("(")!=-1){
									tbl_nm = tbl_nm.substring(tbl_nm.indexOf("(")+1,tbl_nm.indexOf(")"));
//									_data.TBL_NM = tbl_nm.substring(tbl_nm.indexOf("(")+1,tbl_nm.indexOf(")"));
								}
								_data.TBL_NM = tbl_nm;
//								if(_data.TBL_NM.indexOf("(")!=-1){
//									_data.TBL_NM = _data.TBL_NM.substring(_data.TBL_NM.indexOf("(")+1,_data.TBL_NM.indexOf(")"));
//								}
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
							var sqlAreaText;
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
//	        					async: false,
	        					beforeSend: function() {
	        						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
	        						gProgressbar.show();
	        					},
	        					success: function(data){

//		        						self.createDxItems();
	        						data = data.DATA_SET;
	        						data.DATASET_JSON ={
        								DATA_SET:{
        									COL_ELEMENT: data['COL_ELEMENT'],
        									ETC_ELEMENT : data['ETC_ELEMENT'],
        									TBL_ELEMENT : data['TBL_ELEMENT']
        								}
	        						}
	        						gDashboard.dataSourceManager.datasetInformation[targetId].wise_sql_id = wise_sql_id;
									gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_NM = data.DATASET_NM;
									gDashboard.dataSourceManager.datasetInformation[targetId].SQL_QUERY = data.SQL_QUERY;
									//20210122 AJKIM 계산된 컬럼 추가 DOGFOOT
									gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_QUERY = data.SQL_QUERY;
									
									$.each(gDashboard.dataSourceManager.datasetInformation,function(_i,_e){
										$.ajax({
											url: WISE.Constants.context + '/sql/storage/clearSqlId.do',
											data:{
												'wise_sql_id':_e.wise_sql_id
											},
											async:false,
											success:function(_data){

											}
										});
									});
									
									
	        						var columnList = data['COL_ELEMENT'];
	        						var TBL_name = data['TBL_ELEMENT']
	        						$.each(data['COL_ELEMENT']['COLUMN'], function(_i, _o) {
	        							if(_o.TYPE== 'DIM'){
	        								_o.icon = '../images/icon_dimension.png';
										} else {
											_o.icon = '../images/spr_global.png';
										}
	        							_o.PARENT_ID = '0';
	        							
	        							_o.UNI_NM = _o.COL_CAPTION;
										_o.CAPTION = _o.COL_CAPTION;
	        						});
	        						
//		        						for(var i = 0; i < _.keys(gDashboard.dataSourceManager.datasetInformation).length; i++){
//											if('dataSource'+gDashboard.dataSourceQuantity == _.keys(gDashboard.dataSourceManager.datasetInformation)[i]){
//												gDashboard.dataSourceQuantity++;
//											}
//										}
	        						
	        						var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE': targetId,'DATASET_TYPE':'DataSetSingleDs'}];
									data['mapid'] = 'dataSource'+gDashboard.dataSourceQuantity;
									gDashboard.dataSourceManager.datasetInformation[targetId] = data;
									gDashboard.dataSetCreate.infoTreeList[data['DATASET_NM']] = dataSetInfoTree.concat(data['COL_ELEMENT']['COLUMN']);
									/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
									var newState = {};
				                    newState[targetId] = gDashboard.dataSetCreate.infoTreeList[data['DATASET_NM']];
				                    gDashboard.datasetMaster.setState(newState, 'FIELDS');
//										gDashboard.dataSetCreate.subjectInfoList['dataSource' + gDashboard.dataSourceQuantity] = dsInfo;
									
									gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName':targetId,"Name":data['DATASET_NM']})
	        						
									$('.filter-item').empty();
//									gDashboard.parameterHandler.init();
//									gDashboard.parameterHandler.render();
//									gDashboard.parameterHandler.resize();
									$('.cont_query').empty();
									//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
									$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
									$('#btn_query').off();
	            					$('#btn_query').on('click', function() {
//		            						if (!self.button.enabled) {return;}
	            						gDashboard.queryByGeneratingSql = true;
	            						gDashboard.itemGenerateManager.clearTrackingConditionAll();
	            						/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
	            						gDashboard.itemGenerateManager.clearItemData();
	            						gDashboard.query();
	            						this.blur();
	            					});
	            					/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
	            					var filterBarElement;
	                				switch (WISE.Constants.editmode) {
	                				case 'designer':
	                					filterBarElement = $('#report-filter-item');
	                					break;
	                				default:
	                					filterBarElement = $('.filter-item');
	                				}
	                				gDashboard.parameterFilterBar.render({
	                					element: filterBarElement,
	                					params: gDashboard.datasetMaster.state.params
	                				});
	                				
//		            					gDashboard.dataSetCreate.lookUpItems.push(data['DATASET_NM']);
	            					var lookupidx = Number(targetId.replace('dataSource',''))-1;
									gDashboard.dataSetCreate.lookUpItems[lookupidx] = data['DATASET_NM'];
									gDashboard.reportUtility.reportInfo.DataSources.DataSource[lookupidx] = {'ComponentName':targetId,"Name":data['DATASET_NM']};
	            					
	            					var lookUpIns = $("#dataSetLookUp").dxLookup('instance');
	            					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
	    								lookUpIns = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").dxLookup('instance');
	    							}
									lookUpIns.option('items', gDashboard.dataSetCreate.lookUpItems);
									lookUpIns.option('value','');
									lookUpIns.option('value', data['DATASET_NM']);
									
									gProgressbar.hide();
									$("#edit_ds_popup").dxPopup("instance").hide();
//										$('#columnType_popup').empty();
									setTimeout(function(){
										$('#edit_ds_popup').remove();
		        						$('body').append('<div id="edit_ds_popup"></div>');
									},300);
//										setTimeout(function(){$('#columnType_popup').remove();},300);
	        					},error:function(_data){

	        						gProgressbar.hide();
	        						WISE.alert('집합 생성에 실패했습니다.'+ajax_error_message(_data));
	        						$("#edit_ds_popup").dxPopup("instance").hide();
//		        						$('#columnType_popup').empty();
	        						setTimeout(function(){
										$('#edit_ds_popup').remove();
		        						$('body').append('<div id="edit_ds_popup"></div>');
									},300);
	        					}
							});
						}
					});
					
					$('#btn_datadesign_cancel').dxButton({
						onClick:function(){
							$("#edit_ds_popup").dxPopup("instance").hide();
//							$('#columnType_popup').empty();
							setTimeout(function(){
								$('#edit_ds_popup').remove();
        						$('body').append('<div id="edit_ds_popup"></div>');
							},300);
						}
					});
					
				}
			});
			gProgressbar.hide();
		}else if(targetType =='DataSetSingleDsView'){
			//신규데이터집합(단일테이블뷰)
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
					// 2020.01.07 mksong 리사이즈 드래그 버튼 주석 dogfoot
//					"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
					"                            </div>\r\n" + 
					"                            <div class=\"column\" style=\"width:75%\">\r\n" +
					"                            	<div class=\"row horizen\">\r\n" + 
					" 		                            <div class=\"column\" style=\"height: 600px;\">\r\n" +
					"		                                <div class=\"modal-article\">\r\n" + 
					"       	                           		<div class=\"modal-tit\">\r\n" +
					'												<div class="right-item"><a id="ds_query_button" class="btn crud neutral" style="float:right;">쿼리보기</a><div id="ds_query_popup"></div></div>'+
					'												<div class="right-item"><a id="ds_param_button" class="btn crud neutral" style="float:right;">매개변수</a></div>'+
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
					+'<div class="panel-inner componet-res">'
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
						height: 800,
						onShown: function () {
							miniPop();
							var tableList;
							var colList;
							var listId = 1;
							gDashboard.dataSetCreate.subjectInfoList[targetId]['데이터 원본 유형'] = '단일테이블';
							if(!gDashboard.dataSetCreate.subjectInfoList[targetId].dataType){
								gDashboard.dataSetCreate.subjectInfoList[targetId].dataType = '단일테이블';
							}
							if(!gDashboard.dataSetCreate.subjectInfoList[targetId].TBL_NM){
								gDashboard.dataSetCreate.subjectInfoList[targetId].TBL_NM = gDashboard.datasetMaster.getState('DATASETS')[targetId].DATASET_NM;
							}
							$("#ds_info").dxForm({
								width: 300,
								height: 200,
								readOnly: true,
								formData: gDashboard.dataSetCreate.subjectInfoList[targetId],
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
							
							$('#ds_name_text').text(gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_NM);
							
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
										dataField:'ORDER',
										width:'80px',
									},
									
								],
								noDataText:"",
								dataSource:gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.COL_ELEMENT.COLUMN,
								editing: {
						            mode: "cell",
						            allowUpdating: true,
						            texts: {
						                confirmDeleteMessage: ""
						            }
								},onRowUpdated:function(_e){

								}
							});
							
							/* DOGFOOT ktkang 단일테이블 필터 수정 추가  20201125 */
							$("#ds_param_button").dxButton({
								height: 30,
								type: "normal",
								onClick: function(e) {
									if(gDashboard.isNewReport) {
										gDashboard.FieldFilter.editFilter(true, null);
									} else {
										gDashboard.FieldFilter.editFilter(true, gDashboard.datasetMaster.state.datasources.dataSource1.DS_ID, gDashboard.datasetMaster.state.params, gDashboard.datasetDesigner.onParamEditConfirm);
									}
								}
							});
								
							$("#ds_query_button").dxButton({
								height: 30,
								type: "normal",
								onClick: function(e) {
									var html = '<div id="query_tabpanel" class="query_tabpanel" style="height: calc(100% - 45px);"></div>';
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
										width: 1000,
										height: '90vh',
										onShown: function () {
											var item =  [{ 'title' : 'SQL'}, {'title' : 'SQL Data'}];
											var tabPanel = $("#query_tabpanel").dxTabPanel({
										        height: 'calc(100% - 45px)',
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
//																				$('#edit_sqlRowNumber').text('총 건수 : ' + result.length + " 건");
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
																		        }
																			});
																		},error: function(_response) {
																			gProgressbar.hide();
																			//2020.01.21 mksong 경고창 타입 지정 dogfoot
																			WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response),'error');
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
										        			
//										        			if(gDashboard.structure.ReportMasterInfo.paramJson) {
//																gDashboard.parameterHandler.init();
//																gDashboard.parameterHandler.render(true);
//																gDashboard.parameterHandler.resize();
//															}
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
									
									var tbl_nm = gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_JSON.DATA_SET.TBL_ELEMENT;
									var selectionList = $('#ExpressArea').dxDataGrid('instance').option('dataSource');
									$.each(selectionList,function(_i,_data){
										if(tbl_nm.indexOf("(")!=-1){
											tbl_nm = tbl_nm.substring(tbl_nm.indexOf("(")+1,tbl_nm.indexOf(")"));
//											_data.TBL_NM = tbl_nm.substring(tbl_nm.indexOf("(")+1,tbl_nm.indexOf(")"));
										}
										_data.TBL_NM = tbl_nm;
//										if(_data.TBL_NM.indexOf("(")!=-1){
//											_data.TBL_NM = _data.TBL_NM.substring(_data.TBL_NM.indexOf("(")+1,_data.TBL_NM.indexOf(")"));
//										}
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
				        					async: false,
				        					beforeSend: function() {
				        						//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
				        						gProgressbar.show();
				        					},
				        					success: function(data){

				        						data = data.DATA_SET;
				        						data.DATASET_JSON ={
			        								DATA_SET:{
			        									COL_ELEMENT: data['COL_ELEMENT'],
			        									ETC_ELEMENT : data['ETC_ELEMENT'],
			        									TBL_ELEMENT : data['TBL_ELEMENT']
			        								}
				        						}
				        						gDashboard.dataSourceManager.datasetInformation[targetId].wise_sql_id = wise_sql_id;
												gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_NM = data.DATASET_NM;
												gDashboard.dataSourceManager.datasetInformation[targetId].SQL_QUERY = data.SQL_QUERY;
												//20210122 AJKIM 계산된 컬럼 추가 DOGFOOT
												gDashboard.dataSourceManager.datasetInformation[targetId].DATASET_QUERY = data.SQL_QUERY;
												
												$.each(gDashboard.dataSourceManager.datasetInformation,function(_i,_e){
													$.ajax({
														url: WISE.Constants.context + '/sql/storage/clearSqlId.do',
														data:{
															'wise_sql_id':_e.wise_sql_id
														},
														async:false,
														success:function(_data){

														}
													});
												});
												
				        						var columnList = data['COL_ELEMENT'];
				        						var TBL_name = data['TBL_ELEMENT']
				        						$.each(data['COL_ELEMENT']['COLUMN'], function(_i, _o) {
				        							if(_o.TYPE== 'DIM'){
				        								_o.icon = '../images/icon_dimension.png';
													} else {
														_o.icon = '../images/spr_global.png';
													}
				        							_o.PARENT_ID = '0';
				        							
				        							_o.UNI_NM = _o.COL_CAPTION;
													_o.CAPTION = _o.COL_CAPTION;
				        						});
				        						
				        						var dataSetInfoTree = [{'CAPTION': data['DATASET_NM'], 'ORDER': 0, 'expanded': true, 'DATASOURCE': targetId, 'DATASET_TYPE':data.DATASET_TYPE}];
												data['mapid'] = 'dataSource'+gDashboard.dataSourceQuantity;
												gDashboard.dataSourceManager.datasetInformation[targetId] = data;
												gDashboard.dataSetCreate.infoTreeList[data['DATASET_NM']] = dataSetInfoTree.concat(data['COL_ELEMENT']['COLUMN']);
//												gDashboard.dataSetCreate.subjectInfoList['dataSource' + gDashboard.dataSourceQuantity] = dsInfo;
												
												/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
												var newState = {};
				                    			newState[targetId] = gDashboard.dataSetCreate.infoTreeList[data['DATASET_NM']];
				                    			gDashboard.datasetMaster.setState(newState, 'FIELDS');
												
												gDashboard.reportUtility.reportInfo.DataSources.DataSource.push({'ComponentName':targetId,"Name":data['DATASET_NM']})
				        						
												$('.filter-item').empty();
//												gDashboard.parameterHandler.init();
//												gDashboard.parameterHandler.render();
//												gDashboard.parameterHandler.resize();
												$('.cont_query').empty();
												//2020.02.19 MKSONG 타이틀 추가 DOGFOOT
												$('.cont_query').append('<button id="btn_query" type="button" class="btn point cont_query_bt search-button" title="'+ gMessage.get('WISE.message.page.widget.button.common.search') + '">' + gMessage.get('WISE.message.page.widget.button.common.search') + '</button>');
												$('#btn_query').off();
				            					$('#btn_query').on('click', function() {
//										            						if (!self.button.enabled) {return;}
				            						gDashboard.queryByGeneratingSql = true;
				            						gDashboard.itemGenerateManager.clearTrackingConditionAll();
				            						/* DOGFOOT ktkang 조회 전 기존 데이터 삭제  20200228 */
				            						gDashboard.itemGenerateManager.clearItemData();
				            						gDashboard.query();
				            						this.blur();
				            					});
				            					/* DOGFOOT ktkang 단일테이블 필터 오류 수정  20201127 */
				            					var filterBarElement;
				                				switch (WISE.Constants.editmode) {
				                				case 'designer':
				                					filterBarElement = $('#report-filter-item');
				                					break;
				                				default:
				                					filterBarElement = $('.filter-item');
				                				}
				                				gDashboard.parameterFilterBar.render({
				                					element: filterBarElement,
				                					params: gDashboard.datasetMaster.state.params
				                				});
				                				
				            					var lookupidx = Number(targetId.replace('dataSource',''))-1;
												gDashboard.dataSetCreate.lookUpItems[lookupidx] = data['DATASET_NM'];
												gDashboard.reportUtility.reportInfo.DataSources.DataSource[lookupidx] = {'ComponentName':targetId,"Name":data['DATASET_NM']};
				            					
				            					var lookUpIns = $("#dataSetLookUp").dxLookup('instance');
				            					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
				    								lookUpIns = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").dxLookup('instance');
				    							}
												lookUpIns.option('items', gDashboard.dataSetCreate.lookUpItems);
												lookUpIns.option('value','');
												lookUpIns.option('value', data['DATASET_NM']);
												
												gProgressbar.hide();
												$("#columnType_popup").dxPopup("instance").hide();
//												$('#columnType_popup').empty();
												setTimeout(function(){
													$('#columnType_popup').remove();
					        						$('body').append('<div id="columnType_popup"></div>');
												},300);
//																		setTimeout(function(){$('#columnType_popup').remove();},300);
				        					},error:function(_data){

				        						gProgressbar.hide();
				        						//2020.01.21 mksong 경고창 타입 지정 dogfoot
				        						WISE.alert('집합 생성에 실패했습니다.'+ajax_error_message(_data),'error');
				        						$("#columnType_popup").dxPopup("instance").hide();
//				        						$('#columnType_popup').empty();
				        						/* DOGFOOT 20201022 ajkim setTimeout 시간 변경 300 > 100*/
				        						setTimeout(function(){
													$('#columnType_popup').remove();
					        						$('body').append('<div id="columnType_popup"></div>');
												},100);
				        					}
										});
								}
							});
							
							$('#btn_datadesign_cancel').dxButton({
								onClick:function(){
									$("#columnType_popup").dxPopup("instance").hide();
//									$('#columnType_popup').empty();
	        						/* DOGFOOT 20201022 ajkim setTimeout 시간 변경 300 > 100*/
									setTimeout(function(){
										$('#columnType_popup').remove();
		        						$('body').append('<div id="columnType_popup"></div>');
									},100);
								}
							});
						}
					});
				}
			});
		}
	};
	this.getTBLList = function(ds_id){
		
		var tableList;
		var colList;
		var listId = 1;
		
		$.ajax({
			type : 'post',
			/* DOGFOOT 20201023 ajkim ajax 비동기로 수정*/
//			async: false,
			cache : false,
			url : WISE.Constants.context + '/report/getTableList.do',
			data:{
				'dsid': ds_id,
				'dstype' : 'DS'
			},
//			complete: function() {
//				gProgressbar.hide();
//			},
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
				
				$.ajax({
					type : 'post',
					async: false,
					cache : false,
					url : WISE.Constants.context + '/report/getColumnList.do',
					data:{
						'dsid': ds_id,
						'dstype' : 'DS',
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
						
						$.ajax({
							type : 'post',
							async: false,
							cache : false,
							url : WISE.Constants.context + '/report/getConstraintList.do',
							data:{
								'dsid': ds_id,
								'dstype' : 'DS',
								'tableNm' : ''
							},
							success : function(data) {
								ConstraintList = data.data;
								gProgressbar.hide();
							}
						});
					}
				});
			}
		});//테이블 리스트 불러오기 끝
		
	}
	/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
	this.getDownloadDesginerHtml = function(){
		var html = '<div class="panel-tab">';
			html += '<div class="panel tree active" style="border-left: none">';
			html += '<div class="panel-head" style="height: 39px; padding: 5px 15px 9px;"><h3 class="tit-level2" style="float: left;margin-right: calc(0.5vh - 4px);padding-top: 5px;">데이터 원본</h3>';
			html += '</div>';
			
			html += '	<div id="allList_de" class="wise-area-content-pane-all drop-panel panel-body" style="padding: 5px;height:85%;">';
			html += '		<div class="panel-inner scrollbar" style="overflow-y:visible !important;height:100%;">';
			html += '			<div class="drop-down tree-menu">';
			/* DOGFOOT ktkang KERIS IE에서 UI 오류 수정  20200310 */
			html += '			<ul>';
			html += '			</ul>';
			html += '			</div>';
			html += '		</div>';
			html += '	</div>';//allList
			html += '</div>';//panel tree active
			//2020.02.20 MKSONG 스크롤 오류 수정 끝 DOGFOOT
			
			//데이터 항목
			html += '<div class="panel data active" style="border-left: none">';
			html += '<div class="panel-head" style="height: 39px; padding: 5px 15px 9px;"><h3 class="tit-level2" style="float: left;margin-right: calc(0.5vh - 4px);padding-top: 5px;">필드</h3>';
			html += '</div>';
//			html += '<h3 class="tit-level2">데이터항목</h3>';
			
			//scrollbar
			html += '<div class="panel-inner scrollbar" style="height: 100%; overflow-y:visible !important">';
			
			//panel-body
			html += '<div id="panelDataA_de" class="tab-component">';
			html += '<div class="panelDataA-1 tab-content">';
			html += '<div class="column-drop-body">';
			html += '</div>';
			html += '</div>';
			html += '<div class="panelDataA-2 tab-content data-menu"></div>';
			html += '</div>';
			html += '</div>';
			
			html += '</div>';//스크롤
			
			//캔버스
			html += '<div class="panel grid" style="border-left: none">';
			
			//필터 Bar
			html += '<div id="filter-bar" class="filter-bar'+(userJsonObject.siteNm === 'KAMKO'? ' kamko': '')+'">';
			html += '<div class="filter-row">';
			html += '<div class="filter-gui">';
			html += '<div class="filter-col ui">';
			html += '<a href="#" class="filter filter-more"><span>Filter</span></a>';
			html += '</div>';
			html += '</div>';
			
			//2020.03.02 MKSONG 본사 소스 누락 부분 추가 DOGFOOT
			html += '<div id="report-filter-item-de" class="filter-item">';
			html += '</div>';
			
			html += '</div>';
			/* dogfoot WHATIF 분석 매개변수 필터 버튼  shlim 20201022 */
			html += '<div id="calcParamButton" style="display: none;top: 0px;position: absolute;right: 20px;"></div>';
			html += '</div>';
			
			//아이템 샘플
			
			//아이템 HEAD - cont-box-head
			html += '<div class="panel-inner">';
			html += '<div class="cont-box" style="height:100%;">';
			/**
			 * KERIS 수정
			 */
			//아이템 Body - cont-box-body
			html += '<div class="cont-box-body" style="height:100%">';
			html += '<div id="canvas-container-de" class="goldenLayout-custom-div" style="height:99%; width: 100%;">';
			html += '<div id="download_expand_grid_item" style="height: 100%; width: 100%"></div>'
			html += '</div>';
			html += '</div>';
			
			html += '</div>';
			html += '</div>';
						
			html += '</div>';
			html += '</div>'; //SECTION 끝
			
//			$('.content').html(html);
//			$('<div id="fieldRename" />').append('html');
//			/*2020-01-14 LSH topN */
//			$('<div id="topNset" />').append('html');
//			self.activeDataSourceFunction();
		
		return html;
	}
	
	this.insertDataSetDE = function(_dataSet, _dataSourceId){
		
		var html = '<li class="active" id="'+_dataSourceId+'">';
		/* 20200330 ajkim 측정값이 앞쪽에 정렬되도록 수정 dogfoot */
		if(_dataSet.length <= 0) return;
		_dataSet.sort(function(a,b){
			return (a.ORDER <b.ORDER) ? -1 : (a.ORDER > b.ORDER) ? 1 : 0;
		});
		$.each(_dataSet,function(_i,_data){
			var iconField = (_data.TYPE == 'MEA')?"sigma":"block";
			var dataFieldType = (_data.TYPE == 'MEA')?"measure":"dimension";
			if(_i == 0){
				html += '<a href="#" class="ico arrow" dataset-caption="'+_data.CAPTION+'">'+_data.CAPTION+'</a>';
				html += '<ul class="dep dataset" style="display:block">';		
			}else{
				if(_data.VISIBLE == undefined || _data.VISIBLE == true){
					if(_data.UNI_NM != undefined){
						//2020.01.21 mksong title 추가 dogfoot
						/*dogfoot 사용자정의 데이터  구분자 추가 shlim 20200716*/
						if(_data.CUSTOM_DATA){
							/* dogfoot 사용자 정의 데이터 아이콘 변경 shlim 20201022 */
                            html += '<li class="wise-column-chooser wise-area-field-de" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" CUSTOM_DATA="Y" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico custom '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
						}else{
						    html += '<li class="wise-column-chooser wise-area-field-de" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" TABLE_NM="'+ _data.UNI_NM.substr(_data.UNI_NM.indexOf('[')+1,_data.UNI_NM.indexOf(']')-1) +'" WISE_UNI_NM="'+ _data.UNI_NM +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';		
						}	
					}else{
						//2020.01.21 mksong title 추가 dogfoot
						html += '<li class="wise-column-chooser wise-area-field-de" prev-container="allList" data-field-type="'+dataFieldType+'" data-source-id="'+_dataSourceId+'" UNI_NM="'+ _data.CAPTION +'" title="'+ _data.CAPTION +'"><a href="#" class="ico '+iconField+'"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
					}
				}
			}
		});
		
		html += '</ul>';
		html += '</li>';

		$('#allList_de .drop-down.tree-menu > ul').append(html);
		$('#allList_de .dataset > li').draggable(gDashboard.dragNdropController.draggableOptionsDE);
		treeMenuUi();
	};
	
	this.insertDataSetCubeDE = function(_dataSet,_dataSourceId, searchText){
		//2020.04.06 MKSONG 스크롤 영역 수정 DOGFOOT
		$('#allList_de .drop-down.tree-menu ul').empty();	
		
		var html = '';
		/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
		var fldTitle = "";
		$.each(_dataSet,function(_i,_data){
			var tableNm;
			/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
			var title = "";
			if(typeof _data.PARENT_ID == 'undefined' || _data.PARENT_ID == null){
				/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
				fldTitle = _data.CAPTION;
				if(_i != 0) {
					html += '</ul>';
					html += '</li>';
				}
				html += '<li id=' + _dataSourceId + ' class="wise-column-chooser wise-area-field-de wise-field-group" prev-container="allList" data-field-type="'+_data.TYPE+'" data-source-id="'+_dataSourceId+'">';
				/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
				html += '<a href="#" class="ico arrow '+ _data.TYPE+'-group">'+fldTitle+'</a>';
				html += '<ul class="dep dataset" style="display:none">';
			} else if(_data.MEAFLD) {
				tableNm = _data['CUBE_UNI_NM'].split('.')[0];
				if(_data.TYPE == 'FLD') {
					html += '<li>';
					html += '<a href="#" class="ico arrow">'+_data.CAPTION+'</a>';
					html += '<ul class="dep dataset" style="display:none">';

					$.each(_dataSet,function(_ii,_ee){
						if(_ee.MEAFLD == _data.CAPTION){
						/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
							if(_ee.TYPE == 'MEA'){
						        title = fldTitle + ">" + _data.CAPTION;
							    html += '<li class="wise-column-chooser wise-area-field-de" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _ee.CUBE_UNI_NM + '" UNI_NM="'+ _ee.CAPTION +'" title="'+ title +'"><a href="#" class="ico sigma"><div class="fieldName">'+_ee.CAPTION+'</div></a></li>';	
						    }else if(_ee.TYPE == 'DIM'){
						    	title = fldTitle + ">" + _data.CAPTION;
							    html += '<li class="wise-column-chooser wise-area-field-de" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _ee.CUBE_UNI_NM + '" UNI_NM="'+ _ee.CAPTION +'" title="'+ title +'"><a href="#" class="ico block"><div class="fieldName">'+_ee.CAPTION+'</div></a></li>';	
						    }
						}
					});

					html += '</ul>';
					html += '</li>';
				}
			} else {
				if(_data.TYPE == 'MEA'){
				/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
					title = fldTitle + ">" + _data.CAPTION;
					//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
					if(_data.isCustomField){
						/*dogfoot 비정형 사용자 정의 데이터 rename 제거 shlim 20200717*/
						/* dogfoot 사용자 정의 데이터 아이콘 변경 shlim 20201022 */
						html += '<li class="wise-column-chooser wise-area-field-de" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+ '" CUSTOM_DATA="Y" isCustomField="' + _data.isCustomField + '" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico custom sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
					}else{
						html += '<li class="wise-column-chooser wise-area-field-de" prev-container="allList" data-field-type="measure" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico sigma"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';	
					}
					
				} else {
				/* DOGFOOT ktkang 주제영역 항목 타이틀에 폴더도 나오도록 수정  20200306 */
					title = fldTitle + ">" + _data.CAPTION;
					html += '<li class="wise-column-chooser wise-area-field-de" prev-container="allList" data-field-type="dimension" data-source-id="'+_dataSourceId+'" cubeUniNm="' + _data.CUBE_UNI_NM + '" UNI_NM="'+ _data.CAPTION +'" title="'+ title +'"><a href="#" class="ico block"><div class="fieldName">'+_data.CAPTION+'</div></a></li>';
				}
			}
		});
		
		html += '</ul>';
		html += '</li>';
		
		$('#allList_de .drop-down.tree-menu ul').append(html);	
		
		/* DOGFOOT ktkang 주제영역 연계되어있는 측정값이나 차원만 보여주는 기능   20200212 */
		if((typeof searchText != 'undefined' && searchText != null) || WISE.Context.isCubeRelation) {
			$.each($('ul.dep.dataset'),function(_i, _e){
				if(_e.children.length == 0) {
					_e.parentNode.parentNode.removeChild(_e.parentNode);
				}
			});
		}
		/* DOGFOOT ktkang 주제영역 일 때 검색창 추가 끝  20200130 */
		$('#allList_de .dataset > li').draggable(gDashboard.dragNdropController.draggableOptionsDE);
		treeMenuUi();
		
		//2020.02.27 MKSONG 그룹 아이콘 변경 및 그룹별 드래그앤드롭 기능 추가 DOGFOOT
		$('#allList_de .dataset').parent().draggable(gDashboard.dragNdropController.draggableOptionsDE);
	};
	
	this.appendDownloadExpandField = function(dataFieldType, dataUniNm, dataCaption,dataCubeNm, dataSourceId, fieldManager, index){
		var dataType = dataFieldType;  
		var SortOrderBy;
	            
		var element = $('<ul class="display-unmove analysis-data" />');
		
		var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser other-menu wise-area-field-de" '+
				'data-field-type = "'+dataType+'" '+
				'prev-container="downloadexpand_colList" '+
				'data-source-id="' + dataSourceId + '" '+
				'cubeuninm="' + dataCubeNm + '"'+
				'uni_nm="'+dataUniNm+'" ' +
//				'cubeuninm= "' + cubeUniqueName + '" ' +
				'dataitem="'+ 'DataItem' + fieldManager.dataItemNo  +'" '+
				'caption = "'+dataCaption +'" '+
				'title = "'+dataCaption +'" '+
				'style="height: 31px;">'+
				'<a href="#" class="ico block btn neutral">'  +
				'<div class="fieldName">'+dataCaption +"</div>"
				+ '</a></li>');
		
		element.append(dataItem);
		
		if(index == 0){
			$('#downloadexpand_colList').empty();
			element.appendTo($('#downloadexpand_colList'));
		}else{
			element.insertAfter($('#downloadexpand_colList').children().get(index-1));
		}
		
		if(dataFieldType == 'dimension'){
			compMoreMenuUi();
		}else{
			compMoreMenuUi();
			modalUi();
		}
		dataItem.draggable(gDashboard.dragNdropController.draggableOptionsDE2);
		fieldManager.dataItemNo++;
	}
	
	this.cubePerformQuery = function(_item){
		// 2020.01.16 mksong 작업 취소 문구 처음부터 보이도록 수정 dogfoot
		/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
		var DU = WISE.libs.Dashboard.item.DataUtility;
		var DCU = WISE.libs.Dashboard.item.DataCubeUtility;
		var ReportMeta = gDashboard.structure.ReportMasterInfo;
		var selectedDsId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByField();
		WISE.Context.isCubeReport = true;

		//2020.02.13 mksong 프로그레스바 작업취소 최적화 dogfoot
		gProgressbar.show();
		
		//20200903 ajkim 주제영역 마스터 필터 오류 수정 dogfoot
		var trackingItems = [];

		dsId = _item.dataSourceId;
		ds = gDashboard.dataSourceManager.datasetInformation[dsId];
		/* DOGFOOT ktkang 텍스트 박스 무한로딩 오류 수정  20200717 */
		/* DOGFOOT ktkang 대시보드 주제영역 필터 부분 수정  20200706 */
		var params = $.toJSON(self.parameterBarDE.getKeyParamValues());
		/* DOGFOOT ktkang 주제영역 필터 유형 추가  20200806 */
		var betweenParam = {};
		var paramName = '';
		var betweenValue = [];
		$.each(JSON.parse(params), function(_i, _e) {
			if(_e.operation == 'Between' && _e.name.indexOf('_fr')) {
				betweenParam[_e.uniqueName] = {
						uniqueName: _e.uniqueName,
						name: _e.name.replace('_fr', ''),
						/*dogfoot 리스트 필터 쿼리일때 key caption 명 다르면 못찾는 오류 수정 shlim 20200728*/
						captionName : _e.captionName,
						keyName : _e.keyName,
						paramName: _e.paramName.replace('_fr', ''),
						/*dogfoot 기본값 있는 보고서 불러올시 적용 안되는 오류 수정 shlim 20200716*/
						value: _e.value,
						type: _e.type,
						defaultValue: _e.defaultValue,
						whereClause: _e.whereClause,
						parameterType: _e.parameterType,
						betweenCalendarValue: _e.betweenCalendarValue,
						/* DOGFOOT ktkang 주제영역 쿼리 만들기 오류 수정  20200704 */
						orgParamName: _e.orgParamName,
						cubeUniqueName: _e.cubeUniqueName,
						operation: _e.operation
				};
				betweenValue.push(_e.value);
				paramName = _e.uniqueName;
			} else if(_e.operation == 'Between' && _e.name.indexOf('_to')) {
				betweenValue.push(_e.value);
				/* DOGFOOT ktkang 주제영역 비트윈달력 오류 수정  20200810 */
			} else {
				betweenParam[_e.uniqueName] = _e;
			}
		});
		if(paramName != '') {
			betweenParam[paramName].value = betweenValue;
			params = JSON.stringify(betweenParam);
		}
		var param = {
				dsid: ds.DATASRC_ID,
				dsnm: ds.DATASET_NM,
				dstype: 'CUBE',
				params: params,
				sqlTimeout: userJsonObject.searchLimitTime,
				skipQuery: "",
				schId: undefined,
				mapid: dsId,
				reportType: 'DashAny'
		};
		/* DOGFOOT ktkang 대시보드 주제영역 부분 추가  20200423 */
		
		if(gDashboard.isNewReport) {
			var DI = [];
			var HM = [];
			var selected = {dim:[],mea:[]};
			gDashboard.itemGenerateManager.getherFields(_item.fieldManager, _item.type, false);
			/* DOGFOOT ktkang 주제영역 대시보드 오류 수정  20200525 */
			DI = _item.fieldManager['DataItems'];
			/*dogfoot 20200511 정렬순서 항목 오류 수정 shlim*/
			if(WISE.Context.isCubeReport){
                HM = _item.fieldManager['HiddenMeasures'] ? _item.fieldManager['HiddenMeasures'] : [];
			}else{
			    HM = _item.fieldManager['hiddenMeasures'];	
			}
			
			var dNameArr = [];
			if(typeof DI['Dimension'] != 'undefined' && DI['Dimension'].length > 0) {
				_.each(DI['Dimension'], function(_R) {
					selected.dim.push({uid:_R.CubeUniqueName});
					dNameArr.push(_R.CubeUniqueName);
				});
			}
				
			if(typeof DI['Measure'] != 'undefined' && DI['Measure'].length > 0) {
				_.each(DI['Measure'], function(_D) {
					selected.mea.push({uid:_D.CubeUniqueName});
				});
			}
			/* DOGFOOT ktkang 주제영역 대시보드 오류 수정  20200525 */
			if(typeof HM['Measure'] != 'undefined' && HM['Measure'].length > 0) {
				_.each(HM['Measure'], function(_HM) {
					selected.dim.push({uid:_HM.cubeUniqueName});
				});
			}
//							if(typeof HM['Measure'] != 'undefined' && HM['Measure'].length > 0) {
//								_.each(HM['Measure'], function(_HM) {
//									$.each(DI.Measure,function(_i,_val){
//										if(_HM.UniqueName == _val.UniqueName){
//									        selected.dim.push({uid:_val.CubeUniqueName});		
//										}
//									})
//								});
//							}
		} else {
			var DI = [];
			var HM = [];
			var selected = {dim:[],mea:[]};

			gDashboard.itemGenerateManager.getherFields(_item.fieldManager, _item.type, false);
			
			if(typeof _item.fieldManager != 'undefined' && typeof _item.fieldManager.DataItems != 'undefined') {
				DI = _item.fieldManager.DataItems;
				/*dogfoot 정렬기준 항목 보고서 열기 오류 수정 shlim 20200715*/
				if(typeof _item.fieldManager.HiddenMeasures === 'undefined' ){
				    HM = _item.fieldManager.HiddenMeasures;
				}else{
					if(typeof _item.fieldManager.HiddenMeasures.Measure === 'undefined'){
						 HM = _item.fieldManager.HiddenMeasures;
					}else{
						HM = _item.fieldManager.HiddenMeasures.Measure;
					}
				}
			} else {
				DI = _item.DI;
				HM = _item.HM;
			}

			if(typeof DI != 'undefined') {
				var dNameArr = [];
				if(typeof DI['Dimension'] != 'undefined' && typeof DI['Dimension'].CubeUniqueName != 'undefined') {
					selected.dim.push({uid:DI['Dimension'].CubeUniqueName})
					dNameArr.push(DI['Dimension'].CubeUniqueName);
				} else if(typeof DI['Dimension'] != 'undefined' && DI['Dimension'].length > 0){
					_.each(DI['Dimension'], function(_R) {
						selected.dim.push({uid:_R.CubeUniqueName});
						dNameArr.push(_R.CubeUniqueName);
					});
				}

				if(typeof DI['Measure'] != 'undefined' && typeof DI['Measure'].CubeUniqueName != 'undefined') {
					selected.mea.push({uid:DI['Measure'].CubeUniqueName})
				} else if(typeof DI['Measure'] != 'undefined' && DI['Measure'].length > 0){
					_.each(DI['Measure'], function(_D) {
						selected.mea.push({uid:_D.CubeUniqueName});
					});
				}
			}
			
			if(typeof HM != 'undefined' && HM.length > 0) {
				_.each(HM, function(_HM) {
				/* DOGFOOT ktkang 주제영역 정렬기준 항목 오류 수정  20201126 */
					if(typeof _HM.cubeUniqueName != 'undefined') {
						selected.dim.push({uid:_HM.cubeUniqueName});
					} else {
						_.each(DI['Dimension'], function(_R) {
							if(_R.UniqueName == _HM.UniqueName) {
								selected.dim.push({uid:_R.CubeUniqueName});
							}
						});
						_.each(DI['Measure'], function(_R) {
							if(_R.UniqueName == _HM.UniqueName) {
								selected.dim.push({uid:_R.CubeUniqueName});
							}
						});
					}
				});
			}
		}
		
		param.cols = $.toJSON(selected);
		
		if(selected.mea.length == 0) {
			if(_item.type == "STAR_CHART" || _item.type == "SIMPLE_CHART" || _item.type == "TREEMAP" || _item.type == "PIE_CHART") {
				WISE.alert('보고서 조회 오류<br>' + _item.Name + ' 아이템에 측정값 항목이 없습니다.');
				if(gDashboard.itemGenerateManager.viewedItemList.indexOf(_item.ComponentName) < 0 ){
					gDashboard.itemGenerateManager.viewedItemList.push(_item.ComponentName);
				}
				if(gDashboard.itemGenerateManager.dxItemBasten.length == gDashboard.itemGenerateManager.viewedItemList.length){
					gProgressbar.hide();
					gDashboard.updateReportLog('99');
				}
				return false;
			}
		} else if((_item.type == "HEATMAP" || _item.type == 'HEATMAP2') && (selected.mea.length != 1 || selected.dim.length != 2) && gDashboard.reportType != 'StaticAnalysis') {
			WISE.alert('보고서 조회 오류<br>히트맵 아이템은 측정값 1개 차원이 2개 있어야 조회가 가능합니다.');
			gProgressbar.hide();
			gDashboard.updateReportLog('99');
			return false;
		}

		$.ajax({
			type : 'post',
			data : param,
			/* DOGFOOT ktkang 작업 취소 기능 구현  20200923 */
			async: false,
			url : WISE.Constants.context + '/report/cube/queries.do',
			success : function(_dataSet) {
				var param2 = {
						'pid': WISE.Constants.pid,
						'dsid': ds['DATASRC_ID'], 
						'dstype' : ds['DATASRC_TYPE'],
						/* DOGFOOT ktkang 상세현황 자르기  20200123 */
						'dsnm': ds['DATASET_NM'],
						'reportType' : gDashboard.reportType,
						'fldType' : gDashboard.reportUtility.reportInfo.ReportMasterInfo.fld_type,
						'mapid': dsId, 
						'sqlid': 0, 
						/* DOGFOOT ktkang 대시보드 주제영역 필터 부분 수정  20200706 */
						'params': params,
						'userId':userJsonObject.userId,
						/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
						'sql_query_nosqlid': Base64.encode(_dataSet.sql),
						'sqlTimeout':userJsonObject.searchLimitTime
				};
				/* DOGFOOT ktkang 쿼리 암호화 추가  20200721 */
				var sql = Base64.decode(_dataSet.sql);
				_item.cubeQuery = sql;
				/* DOGFOOT ktkang 대시보드 주제영역 불러오기 오류 수정  20200707 */
				gDashboard.dataSourceManager.datasetInformation[dsId].DATASET_QUERY = sql;
				gDashboard.dataSourceManager.datasetInformation[dsId].SQL_QUERY = sql;
				
				gDashboard.itemGenerateManager.customFieldCalculater
				.$calculate(param2)  // when useing jquery promise
				.then(
						function(_response) {
							var calculatedData = new Array();
							var resultData = new Array();
							_item.selectedChartType = undefined; // for ChartGenerator instance
							_item.tracked = false;
							gDashboard.itemGenerateManager.sqlConfigWhere = [];
							_item.bindData([], null, null);
						}
				);
			}
		});
};
	
	this.openDownloadExpand = function(item, type){
		$('#editPopup').dxPopup({
			height: 'auto',
			width: 500,
			visible: false,
			showCloseButton: false
		});
		
		var p = $('#editPopup').dxPopup('instance');
		p.option({
			title: '다운로드 항목 편집',
			width : '90%',
			height: '90%',
			onContentReady: function() {
				gDashboard.fontManager.setFontConfigForEditText('editPopup');
			},
			contentTemplate: function(contentElement) {
				var html = 
					'<div style="padding-bottom:15px;">' +
					'<div class="row right col-0">' + 
					'<a id="btn_query_de" href="#" class="global-lookup search triple" title="조회" style="margin:53px; text-indent: 100px; right: -30px; width: 28px; height: 28px">lookup</a>'+
					'</div></div>' +
					'<div class="container-inner" style="height:85%; width:100%">'+
					'<section class="download-designer" style="height:100%; width:100%"></section> </div>'+
					'<div class="modal-footer" style="padding-bottom:0px; border-top: none;">' +
						'<div class="row center">' +
							'<a id="expand_download" href="#" class="btn positive close">내려받기</a>' +
							'<a id="close" href="#" class="btn neutral close">닫기</a>' +
						'</div>' +
					'</div>';
				contentElement.append(html);

                                     
				$('.download-designer').append(self.getDownloadDesginerHtml());
				gDashboard.layoutManager.activateBasicFunction();
				
				if(WISE.Context.isCubeReport) {
					WISE.Context.isCubeReport = true;
					var dataset = self.structure.ReportMasterInfo.datasetJson.DATASET_ELEMENT;
					$.each(dataset, function(_i, _e) {
						if(_e.DATASRC_TYPE == 'CUBE') {
							gDashboard.dataSetCreate.cubeListInfo(_e.DATASRC_ID, 'CUBE', undefined, true);
						}
					});
				}
				
				//데이터 원본
//				if(gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_TYPE !== 'CUBE')
//					self.insertDataSetDE(gDashboard.dataSetCreate.infoTreeList[gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_NM], item.dataSourceId);
//				else self.insertDataSetCubeDE(gDashboard.dataSetCreate.infoTreeList[gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_NM], item.dataSourceId);
				//데이터 원본
				if((gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_TYPE 
						|| gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASRC_TYPE) !== 'CUBE')
					self.insertDataSetDE(gDashboard.datasetMaster.getState('FIELDS')[item.dataSourceId], item.dataSourceId);
				else {
					if(WISE.Constants.editmode === 'viewer')
						self.insertDataSetCubeDE(gDashboard.dataSetCreate.infoTreeList[gDashboard.datasetMaster.getState('DATASOURCES')[item.dataSourceId].CUBE_NM], item.dataSourceId);
					else if(!gDashboard.isNewReport)
						self.insertDataSetCubeDE(gDashboard.dataSetCreate.infoTreeList[gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_NM], item.dataSourceId);
					else
						self.insertDataSetCubeDE(gDashboard.datasetMaster.getState('FIELDS')[item.dataSourceId], item.dataSourceId);
				}
				
				dsType = (gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_TYPE 
						|| gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASRC_TYPE);
				
				self.singleTableDE = (dsType == "DataSetSingleDs" || dsType == "DataSetSingleDsView");
				
				//아이템 생성
				WISE.loadedSourceCheck('itemJS','DataGrid');
				var datagridItem = new WISE.libs.Dashboard.item.DataGridGenerator();
				datagridItem.kind = 'dataGrid';
				datagridItem.ComponentName = 'download_expand_grid';
				datagridItem.Name = item.Name;
				datagridItem.itemid = 'download_expand_grid';
				if(WISE.Constants.editmode === 'viewer')
					datagridItem.itemid = 'download_expand_grid_item';
				datagridItem.dataSourceId = item.dataSourceId;
				datagridItem.isDownloadExpand = true;
				datagridItem.fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
				
				//필드 생성
				gDashboard.fieldChooser.downloadExpandAnalysisFieldArea(datagridItem);
				
				gDashboard.fieldManager = datagridItem.fieldManager;
				gDashboard.fieldManager.panelManager['allContentPanel'].droppable(gDashboard.dragNdropController.droppableOptionsDE).sortable(gDashboard.dragNdropController.sortableOptions);
				gDashboard.fieldManager.panelManager['allContentPanel'].sortable('disable');
				gDashboard.fieldManager.panelManager['downloadexpandContentPanel'].droppable(gDashboard.dragNdropController.droppableOptionsDE).sortable(gDashboard.dragNdropController.sortableOptions);
				gDashboard.fieldManager.panelManager['downloadexpandContentPanel'].sortable('disable');

				self.dataSourceDE = item.dataSource;
				
				//매개변수 생성
				self.parameterBarDE = new WISE.libs.Dashboard.ParameterBar();
				self.parameterBarDE.setState({'isDownloadExpand': true});
				
//				var dataset = gDashboard.datasetMaster.getState('DATASETS')[item.dataSourceId];
				
//				var params = [];
//				var reportParams = gDashboard.parameterFilterBar.getKeyParamValues();
//				
//				$.each(gDashboard.datasetMaster.getState('PARAMS'), function(index, info){
//					var temp = info;
//					temp.value = reportParams[info.PARAM_NM].value;
//					params[index] = temp;
//				})
				self.parameterBarDE.render({
					element: $("#report-filter-item-de"),
					params : gDashboard.datasetMaster.getState('PARAMS')
				})
				
				
				//필드 불러오기
				var DataItems = item.meta.DataItems;
				var isCubeReport = ((gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_TYPE 
						|| gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASRC_TYPE) == 'CUBE');
				var isViewer = (WISE.Constants.editmode === 'viewer');
				var infoTree;
				
				if((isViewer || !gDashboard.isNewReport) && isCubeReport){
					infoTree = gDashboard.dataSetCreate.infoTreeList[gDashboard.datasetMaster.getState('DATASOURCES')[item.dataSourceId].CUBE_NM];
				}
				
				var index = 0;
				if(!Array.isArray(DataItems.Dimension)){
					dim = DataItems.Dimension;
					if((isViewer || !gDashboard.isNewReport) && isCubeReport){
						$.each(infoTree, function(i, info) {
							if(info.CAPTION === dim.DataMember){
								dim.CubeUniqueName = info.CUBE_UNI_NM;
								return false;
							}
						})
					}
					
					self.appendDownloadExpandField("dimension", dim.DataMember, dim.Name, dim.CubeUniqueName, item.dataSourceId, datagridItem.fieldManager, index);
					index++;
				}
				else{
					$.each(DataItems.Dimension, function(i, dim){
						if((isViewer || !gDashboard.isNewReport) && isCubeReport){
							$.each(infoTree, function(i, info) {
								if(info.CAPTION === dim.DataMember){
									dim.CubeUniqueName = info.CUBE_UNI_NM;
									return false;
								}
							})
						}
						self.appendDownloadExpandField("dimension", dim.DataMember, dim.Name, dim.CubeUniqueName, item.dataSourceId, datagridItem.fieldManager, index);
						index++;
					})
				}
				
				if(!Array.isArray(DataItems.Measure)){
					mea = DataItems.Measure;
					if((isViewer || !gDashboard.isNewReport) && isCubeReport){
						$.each(infoTree, function(i, info) {
							if(info.CAPTION === mea.DataMember){
								mea.CubeUniqueName = info.CUBE_UNI_NM;
								return false;
							}
						})
					}
					self.appendDownloadExpandField("measure", mea.DataMember, mea.Name, mea.CubeUniqueName, item.dataSourceId, datagridItem.fieldManager, index);
				}else{
					$.each(DataItems.Measure, function(i, mea){
						if((isViewer || !gDashboard.isNewReport) && isCubeReport){
							$.each(infoTree, function(i, info) {
								if(info.CAPTION === mea.DataMember){
									mea.CubeUniqueName = info.CUBE_UNI_NM;
									return false;
								}
							})
						}
						self.appendDownloadExpandField("measure", mea.DataMember, mea.Name, mea.CubeUniqueName, item.dataSourceId, datagridItem.fieldManager, index);
						index++;
					})
				}
				
				datagridItem.bindData();
				// confirm and cancel
				contentElement.find('#close').on('click', function() {
					p.hide();
					$('.download-designer').remove();
					gDashboard.fieldManager = gDashboard.itemGenerateManager.focusedItem? gDashboard.itemGenerateManager.focusedItem.fieldManager : null;
					p.option({height: 'auto', width: 500});
				});
				
				$("#btn_query_de").off().on('click', function(){
					if((gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASET_TYPE 
							|| gDashboard.dataSourceManager.datasetInformation[item.dataSourceId].DATASRC_TYPE))
						self.cubePerformQuery(datagridItem);
					datagridItem.bindData();
				})
				
				$("#expand_download").off().on("click", function(){
					if(type == "typeCsv"){
						gDashboard.downloadManager.downloadCSV(datagridItem);
					}else if(type === "typeTxt"){
						gDashboard.downloadManager.downloadTXT(datagridItem);
					}
					
//					p.hide();
//					$('.download-designer').remove();
//					gDashboard.fieldManager = gDashboard.itemGenerateManager.focusedItem.fieldManager? gDashboard.itemGenerateManager.focusedItem.fieldManager : null;
//					p.option({height: 'auto', width: 500});
				})
			}
		});
		// show popup
		p.show();
	}
	/* 20210212 AJKIM 다운로드 확장 기능 추가 끝 dogfoot*/
	
	this.initArea = function(ds_id){
		$('#ExpressArea').dxDataGrid({
			height:195,
			selection: {
				mode: 'single'
			},
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
//	                    onSelectionChanged:function(_e){

////	                    	for(var i=0;i<selectedTables.length;i++){
////	                    		
////	                    	}
//	                    }
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

				for(var i=0;i<self.selectedTables.length;i++){
					if(self.selectedTables[i].parentTable === _e.key.TBL_NM){
						self.selectedTables[i].DimMea = _e.key.TYPE;
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
			width:'70%',
			height:'40px'
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
					WISE.alert("사용되지 않은 조건식이 있습니다.<br>조건식을 다시 확인하세요.");
				}
				
			}
		});
		$('#ConditionArea').dxDataGrid({
			noDataText:"",
			height: '14vh',
	        maxHeight: 115,
			columns:[
				{
					width:'5%',
					type: "buttons",
					buttons:[{
						hint: "매개변수 편집",
	                    icon: "edit",
	                    onClick: function(e) {

//	                    	editDatasetFilter();
	                    	gDashboard.FieldFilter.editFilter(true);
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
								width: '90vw',
					            height: '90vh',
					            maxWidth: 600,
					            maxHeight: 700,
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
												gDashboard.parameterFilterBar.parameterInformation[e.row.data.UNI_NM].DEFAULT_VALUE = '[All]';
												gDashboard.FieldFilter.parameterInformation[e.row.data.UNI_NM].DEFAULT_VALUE = '[All]';
//												e.row.data.VALUE = '[All]';
//												e.row.data.VALUES_CAPTION = '전체';
											}else{
												condtionDataSource[e.row.rowIndex].VALUES = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",")
												condtionDataSource[e.row.rowIndex].VALUES_CAPTION = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",")
												gDashboard.parameterFilterBar.parameterInformation[e.row.data.UNI_NM].DEFAULT_VALUE = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",");
												gDashboard.FieldFilter.parameterInformation[e.row.data.UNI_NM].DEFAULT_VALUE = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",");
												
//												e.row.data.VALUE = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",");
//												e.row.data.VALUES_CAPTION = $('#dataListSelection').dxList('instance').option("selectedItemKeys").join(",");
											}
											$('#ConditionArea').dxDataGrid('instance').option('dataSource',condtionDataSource);
											$('#dataList_popup').dxPopup('instance').hide();
//											$('#dataList_popup').empty();
										}
									})
									$('#btn_dataselect_cancel').dxButton({
										onClick:function(){
											$('#dataList_popup').dxPopup('instance').hide();
//											$('#dataList_popup').empty();
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
//					allowEditing:false,
					alignment:"center",
					dataType:'boolean',
				},{
//					type: "buttons",
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
			wordWrapEnabled:true,
			height:115,
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
					var conditionDataSource = _e.component.option('dataSource');
					var changeParam = $.extend(true, {}, gDashboard.parameterFilterBar.parameterInformation[_e.key.UNI_NM]);
					if(_e.data.PARAM_YN == true){
						$.each(conditionDataSource,function(_i,_data){
							if(_data.COND_ID === _e.key.COND_ID){
								_e.key.PARAM_NM = '@'+_e.key.COL_NM;
								return false;
							}
						});
						changeParam['VISIBLE'] = 'Y';
						gDashboard.parameterFilterBar.parameterInformation[_e.key.UNI_NM]['VISIBLE']  = 'Y';
						gDashboard.FieldFilter.parameterInformation[_e.key.UNI_NM]['VISIBLE']  = 'Y';
					}else{
						$.each(conditionDataSource,function(_i,_data){
							if(_data.COND_ID === _e.key.COND_ID){
								_e.key.PARAM_NM = '';
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
			height:105,
			dataSource:[]
		});
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
							
							$.each(self.selectedTables,function(_i,_tables){
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
												for(var i=0;i<self.selectedTables.length;i++){
													if(self.selectedTables[i].parentTable === itemattr.parentTable){
														selectedTableCount = self.selectedTables[i].selectedCount +1;
													}
												}
												selectedItemsType = {
													parentTable:itemattr.parentTable,
													DimMea : 'MEA',
													selectedCount:selectedTableCount
												}
												self.selectedTables.push(selectedItemsType);
												$('#columnType_popup').dxPopup('instance').hide();
												setDataSetArea(container,selectedItemsType,itemattr,ds_id);
											}
										});
										$('#TypeDim').dxButton({
											text:'차원',
											onClick:function(){
												var selectedTableCount = 1;
												for(var i=0;i<self.selectedTables.length;i++){
													if(self.selectedTables[i].parentTable === itemattr.parentTable){
														selectedTableCount = self.selectedTables[i].selectedCount +1;
													}
												}
												selectedItemsType = {
													parentTable:itemattr.parentTable,
													DimMea : 'DIM',
													selectedCount:selectedTableCount
												}
												self.selectedTables.push(selectedItemsType);
												$('#columnType_popup').dxPopup('instance').hide();
												setDataSetArea(container,selectedItemsType,itemattr,ds_id);
											}
										})
									}
								})
							}else{
								setDataSetArea(container,selectedItemsType,itemattr,ds_id)
							}
						}else if(targetContainer.attr('id') == 'ConditionArea'){
							var selectedItemsType;
							
							var itemattr= {
								COL_NM: _ui.draggable.attr('targetName'),
								parentTable : _ui.draggable.attr('parentTable'),
							}
							
							$.each(self.selectedTables,function(_i,_tables){
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
												for(var i=0;i<self.selectedTables.length;i++){
													if(self.selectedTables[i].parentTable === itemattr.parentTable){
														selectedTableCount = self.selectedTables[i].selectedCount +1;
													}
												}
												selectedItemsType = {
													parentTable:itemattr.parentTable,
													DimMea : 'MEA',
													selectedCount:selectedTableCount
												}
												self.selectedTables.push(selectedItemsType);
												$('#columnType_popup').dxPopup('instance').hide();
												setDataSetArea(container,selectedItemsType,itemattr,ds_id);
											}
										});
										$('#TypeDim').dxButton({
											text:'차원',
											onClick:function(){
												var selectedTableCount = 1;
												for(var i=0;i<self.selectedTables.length;i++){
													if(self.selectedTables[i].parentTable === itemattr.parentTable){
														selectedTableCount = self.selectedTables[i].selectedCount +1;
													}
												}
												selectedItemsType = {
													parentTable:itemattr.parentTable,
													DimMea : 'DIM',
													selectedCount:selectedTableCount
												}
												self.selectedTables.push(selectedItemsType);
												$('#columnType_popup').dxPopup('instance').hide();
												setDataSetArea(container,selectedItemsType,itemattr,ds_id);
											}
										})
									}
								})
							}else{
								setDataSetArea(container,selectedItemsType,itemattr,ds_id)
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
						for(var i=0;i<self.selectedTables.length;i++){
							if(self.selectedTables[i].parentTable === targetGridData.TBL_NM){
								self.selectedTables[i].selectedCount = self.selectedTables[i].selectedCount -1;
							}
						}
						for(var i=0;i<self.selectedTables.length;i++){
							if(self.selectedTables[i].selectedCount === 0){
								self.selectedTables.splice(i,1);
							}
						}
						if(fromContainer === 'ConditionArea'){
							delete gDashboard.parameterFilterBar.parameterInformation[targetGridData.UNI_NM];
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
	};
	function setDataSetArea(targetId,selectedItemsType,itemattr,ds_id){
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
						$.each(self.selectedTables,function(_k,_tables){
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
					if(selectedItemsType.DimMea == 'MEA')
						summaryType = 'Sum'
							
					var obj = {
						COND_ID : 'A'+self.relationLength,
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
            			ORDER :self.relationLength,
            			WIDTH : '300',
            			VISIBLE : 'N',
            			OPER : 'In',
            			SEARCH_YN : 'N',
						BIND_YN : 'Y',
						DATASRC_TYPE : 'TBL',
						DATASRC : selectedItemsType.parentTable,
						//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
            			CAPTION_WIDTH_VISIBLE: N,
                        CAPTION_WIDTH: 86.5,
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
	    				DS_ID:ds_id,
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
					
					gDashboard.parameterFilterBar.parameterInformation['@'+_items.COL_NM] = paramObj; 
					
					conditionDataSource.push(obj);
					self.relationLength++;
					return false;
				}
			});
			var Constarr = new Array();
			Constarr = Constarr.concat(relations); 
			var alreadyStored = false;
			$.each(conditionDataSource,function(_i,_express){
				$.each(ConstraintList,function(_j,_const){
					if(_express.TBL_NM === _const.PK_TBL_NM){
						$.each(self.selectedTables,function(_k,_tables){
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
	this.setArea = function(targetId,selectedItemsType,itemattr,targetDataSource){
		if(targetId == 'ExpressArea'){
			var expressDataSource = $('#ExpressArea').dxDataGrid('instance').option('dataSource');
			$.each(self.allList,function(_i,_items){
				if(_items.NAME === itemattr.COL_NM && _items.parentTable === itemattr.parentTable){
					var obj = {
						AGG:_items.summaryType,
						COL_NM : _items.NAME,
						COL_CAPTION : (_items.captionName == "" ? _items.NAME : _items.captionName),
						CAPTION : _items.NAME,
						DATA_TYPE : _items.dataType,
						TBL_NM: selectedItemsType.parentTable,
						tableName : _items.tableName,
						TYPE : selectedItemsType.DimMea,
						COL_EXPRESS : _items.expression,
						UNI_NM : _items.uniqueName,
						physicalTableName : _items.physicalTableName,
						
					};
					expressDataSource.push(obj);
					return false;
				}
			});
			
			$('#ExpressArea').dxDataGrid('instance').option('dataSource',expressDataSource);
		}else if(targetId == 'ConditionArea'){
			var conditionDataSource = $('#ConditionArea').dxDataGrid('instance').option('dataSource');
			var summaryType = '';
			$.each(self.allList,function(_i,_items){
				if(_items.NAME  === itemattr.COL_NM && _items.parentTable === itemattr.parentTable){
					var itemDataType = _items.dataType;
					if(itemDataType == 'varchar'){
						itemDataType = 'STRING';
					}else if (itemDataType == 'int' || itemDataType == 'number'){
						itemDataType = 'number';
					}
					var obj = {
						COL_NM : _items.NAME,
						CAPTION : _items.NAME,
						TBL_NM: selectedItemsType.parentTable,
						OPER : 'In',
						VALUES:'[All]',
						VALUES_CAPTION:'전체',
						DATA_BIND_YN:'true',
						AGG:summaryType,
						PARAM_YN:false,
						PARAM_NM :'',
						TYPE : selectedItemsType.DimMea,
						COL_CAPTION : (_items.COL_CAPTION == "" ? _items.NAME : _items.COL_CAPTION),
						DATA_TYPE : itemDataType,
						UNI_NM: '@'+_items.NAME,
						COL_EXPRESS : '',
						PARAM_ITEM_UNI_NM:_items.HIE_HIE_UNI_NM
					};
					
					var paramObj = {
						PARAM_NM : '@'+_items.NAME,
        				UNI_NM : '@'+_items.NAME,
            			PARAM_CAPTION : _items.NAME,
            			DATA_TYPE : 'STRING',
            			PARAM_TYPE : 'LIST',
            			ORDER :WISE.util.Object.toArray(gDashboard.dataSourceManager.datasetInformation[targetDataSource].DATASET_JSON.DATA_SET.WHERE_ELEMENT.WHERE_CLAUSE)+1,
            			WIDTH : 300,
            			VISIBLE : 'N',
            			OPER : 'In',
            			SEARCH_YN : 'N',
						BIND_YN : 'Y',
						//dogfoot syjin 매개변수 편집 caption 너비 추가 20210722
            			CAPTION_WIDTH_VISIBLE: N,
                        CAPTION_WIDTH: 86.5,
						DATASRC_TYPE : 'TBL',
						DATASRC : selectedItemsType.parentTable,
						KEY_VALUE_ITEM : _items.NAME,
	    				CAPTION_VALUE_ITEM : _items.NAME,
	    				HIDDEN_VALUE : '',
	    				SORT_TYPE : '',
	    				DEFAULT_VALUE : '[All]',
	    				DEFAULT_VALUE_USE_SQL_SCRIPT:'N',
	    				MULTI_SEL:'Y',
	    				ALL_YN :'Y',
	    				WHERE_CLAUSE : selectedItemsType.parentTable+"."+_items.NAME, 
	    				DEFAULT_VALUE_MAINTAIN:'N',
	    				SORT_VALUE_ITEM :'',
	    				wiseVariables: [],
	    				DS_ID: gDashboard.dataSourceManager.datasetInformation[targetDataSource].DATASRC_ID,
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
					
					gDashboard.parameterFilterBar.parameterInformation['@'+_items.NAME] = paramObj; 
					gDashboard.FieldFilter.parameterInformation['@'+_items.NAME] = paramObj;
					conditionDataSource.push(obj);
					return false;
				}
			});
			$('#ConditionArea').dxDataGrid('instance').option('dataSource',conditionDataSource);
		}else if(targetId == 'OrderArea'){
			var orderDataSource = $('#OrderArea').dxDataGrid('instance').option('dataSource');
			$.each(self.allList,function(_i,_items){
				if(_items.NAME === itemattr.COL_NM && _items.parentTable === itemattr.parentTable){
					var obj = {
						COL_NM : _items.NAME,
						COL_CAPTION : (_items.captionName == "" ? _items.NAME : _items.captionName),
						DATA_TYPE : _items.dataType,
						TBL_NM: selectedItemsType.parentTable,
						tableName : _items.tableName,
						TYPE : selectedItemsType.DimMea,
						SORT_TYPE:'ASC',
						UNI_NM : _items.uniqueName,
					};
					orderDataSource.push(obj);
					return false;
				}
			});
			
			$('#OrderArea').dxDataGrid('instance').option('dataSource',orderDataSource);
		}
	};
	
	this.setQueriesDoParam = function(pid,dsId,param){
		this.queriesDoParam[pid+"_"+dsId] = JSON.stringify(param);
	};
	
	this.checkQueriesDoParamSame = function(pid,dsId,param){
		var returnVal = false
			if(this.queriesDoParam[pid+"_"+dsId]){
				if(this.queriesDoParam[pid+"_"+dsId] == JSON.stringify(param)){
					returnVal = true;
				}
			}
		return returnVal;
	};
	
};

WISE.namespace('WISE.libs.Dashboard.Config');
WISE.namespace('WISE.libs.Dashboard.item');
WISE.namespace('WISE.libs.Dashboard.util');