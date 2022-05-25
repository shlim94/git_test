/**
 * 보고서 레이아웃 설정 추가 shlim 20200820
 */
WISE.libs.Dashboard.ReportLayoutManager = function() {
	var self = this;
	
	/* DOGFOOT syjin 보고서 레이아웃 설정  20200814 */
	this.lc = {};

	this.setDefaultValueSettingObject  = {
				"TITLE_HEIGHT_SETTING": "25",
				"TITLE_MAIN_FONT_SETTING" : "sans-serif",
				"TITLE_MAIN_FONTSIZE_SETTING" : "13",
				"TITLE_MAIN_COLOR_SETTING" : "#6a6f7f",
				
				"TITLE_SERVE_FONT_SETTING" : "Noto Sans KR",
				"TITLE_SERVE_FONTSIZE_SETTING" : "12",
				"TITLE_SERVE_COLOR_SETTING" : "#646464",
				
				"CHART_X_FONT_SETTING" : "맑은 고딕",
				"CHART_X_FONTSIZE_SETTING" : "12",
				"CHART_X_COLOR_SETTING" : "#646464",
				
				"CHART_Y_FONT_SETTING" : "맑은 고딕",
				"CHART_Y_FONTSIZE_SETTING" : "12",
				"CHART_Y_COLOR_SETTING" : "#646464",
				
				"CHART_LEGEND_FONT_SETTING" : "맑은 고딕",
				"CHART_LEGEND_FONTSIZE_SETTING" : "12",
				
				"GRID_HEADER_FONT_SETTING" : "맑은 고딕",
				"GRID_HEADER_FONTSIZE_SETTING" : "12",
				"GRID_HEADER_COLOR_SETTING" : "#959595",
				"GRID_HEADER_BGCOLORT_SETTING" : "#fafafa",
				"GRID_HEADER_BGCOLORB_SETTING" : "#ececed",
				"GRID_HEADER_BOCOLORT_SETTING" : "#e7e7e7",
				"GRID_HEADER_BOCOLORB_SETTING" : "#546493",
				"GRID_HEADER_HEIGHT_SETTING" : "31",
				
				"GRID_DATA_FONT_SETTING" : "맑은 고딕",
				"GRID_DATA_FONTSIZE_SETTING" : "12",
				"GRID_DATA_COLOR_SETTING" : "#333333",
				"GRID_DATA_BGCOLOR_SETTING" : "#ffffff",
				"GRID_DATA_BOCOLOR_SETTING" : "#ffffff",
				"GRID_DATA_HEIGHT_SETTING" : "31",
				
				"PIBOT_HEADER_FONT_SETTING" : "맑은 고딕",
				"PIBOT_HEADER_FONTSIZE_SETTING" : "14",
				"PIBOT_HEADER_COLOR_SETTING" : "#333333",
				"PIBOT_HEADER_BGCOLOR_SETTING" : "#ffffff",
				"PIBOT_HEADER_BOCOLOR_SETTING" : "#e7e7e7",
				"PIBOT_HEADER_HEIGHT_SETTING" : "18",
				
				"PIBOT_LEFTHEADER_FONT_SETTING" : "맑은 고딕",
				"PIBOT_LEFTHEADER_FONTSIZE_SETTING" : "14",
				"PIBOT_LEFTHEADER_COLOR_SETTING" : "#333333",
				"PIBOT_LEFTHEADER_BGCOLORT_SETTING" : "#ffffff",
				"PIBOT_LEFTHEADER_BGCOLORB_SETTING" : "#ffffff",
				"PIBOT_LEFTHEADER_BOCOLOR_SETTING" : "#e7e7e7",
				"PIBOT_LEFTHEADER_HEIGHT_SETTING" : "18",
				
				"PIBOT_DATA_FONT_SETTING" : "맑은 고딕",
				"PIBOT_DATA_FONTSIZE_SETTING" : "14",
				"PIBOT_DATA_COLOR_SETTING" : "#6A6F7F",
				"PIBOT_DATA_BGCOLOR_SETTING" : "#ffffff",
				"PIBOT_DATA_BOCOLOR_SETTING" : "#e7e7e7",
				
				"PIBOT_ST_FONT_SETTING" : "맑은 고딕",
				"PIBOT_ST_FONTSIZE_SETTING" : "14",
				"PIBOT_ST_COLOR_SETTING" : "#333333",
				"PIBOT_ST_BGCOLORT_SETTING" : "#fafafa",
				"PIBOT_ST_BGCOLORB_SETTING" : "#eeeeee",
				"PIBOT_ST_BOCOLOR_SETTING" : "#e7e7e7",
				
				"PIBOT_TOTAL_FONT_SETTING" : "맑은 고딕",
				"PIBOT_TOTAL_FONTSIZE_SETTING" : "14",
				"PIBOT_TOTAL_COLOR_SETTING" : "#333333",
				"PIBOT_TOTAL_BGCOLORT_SETTING" : "#fafafa",
				"PIBOT_TOTAL_BGCOLORB_SETTING" : "#eeeeee",
				"PIBOT_TOTAL_BOCOLOR_SETTING" : "#e7e7e7",
				/*dogfoot 여백제거 기능 추가 shlim 20201020*/
				"PIBOT_ALL_MARGIN_SETTING" : false,
				
				"FILTER_LD_SETTING" : "0",
				"FILTER_RD_SETTING" : "0",
				"FILTER_D_SETTING" : "0",
				"FILTER_HEIGHT_SETTING" : "40",
				
				"FILTER_LABEL_FONT_SETTING" : "Noto Sans KR",
				"FILTER_LABEL_FONTSIZE_SETTING" : "12",
				"FILTER_LABEL_COLOR_SETTING" : "#646464",
				
				"FILTER_DATA_FONT_SETTING" : "Noto Sans KR",
				"FILTER_DATA_FONTSIZE_SETTING" : "14",
				"FILTER_DATA_COLOR_SETTING" : "#333333",
				"FILTER_DATA_BOCOLOR_SETTING" : "#F4F4F4"
		}
	this.defaultValueSettingString = JSON.stringify(this.setDefaultValueSettingObject);
	this.reportSetting = function(_page){
		var popupDiv = $("<div>").attr("id", "reportSetting-popup");
		var btnType ="";
		var pageset = _page;
		self.layoutConfCheck = false;
		var defaultValueSetting;
		var defaultValueSettingObject = self.setDefaultValueSettingObject;

		if(pageset === 'reportset'){
			defaultValueSetting = typeof userJsonObject.layoutConfig != 'undefined' && userJsonObject.layoutConfig != "" && userJsonObject.layoutConfig != "1001"? userJsonObject.layoutConfig : defaultValueSettingObject
		}else{
			defaultValueSetting = defaultValueSettingObject
		}
		
		$('body').append(popupDiv);
		//self.lc = gDashboard.structure.layoutConfig != undefined ? gDashboard.structure.layoutConfig :{
		self.lc = typeof gDashboard.layoutConfig != 'undefined' && gDashboard.layoutConfig != "" && gDashboard.layoutConfig != "1001" && gDashboard.layoutConfig !="\"\"" && Object.keys(gDashboard.layoutConfig).length != 0?  gDashboard.layoutConfig :
				typeof userJsonObject.layoutConfig != 'undefined' && userJsonObject.layoutConfig != "" && userJsonObject.layoutConfig != "1001"? userJsonObject.layoutConfig : defaultValueSetting
		
		titleHeight = self.lc.TITLE_HEIGHT_SETTING;	
		titleMainFont = self.lc.TITLE_MAIN_FONT_SETTING;
		titleMainFontSize = self.lc.TITLE_MAIN_FONTSIZE_SETTING;
		titleMainColor = self.lc.TITLE_MAIN_COLOR_SETTING;
		
		titleServeFont = self.lc.TITLE_SERVE_FONT_SETTING;
		titleServeFontSize = self.lc.TITLE_SERVE_FONTSIZE_SETTING;
		titleServeColor = self.lc.TITLE_SERVE_COLOR_SETTING;
		
		chartXFont = self.lc.CHART_X_FONT_SETTING;
		chartXFontSize = self.lc.CHART_X_FONTSIZE_SETTING;
		chartXColor = self.lc.CHART_X_COLOR_SETTING;
		
		chartYFont = self.lc.CHART_Y_FONT_SETTING;
		chartYFontSize = self.lc.CHART_Y_FONTSIZE_SETTING;
		chartYColor = self.lc.CHART_Y_COLOR_SETTING;
		
		chartLegendFont = self.lc.CHART_LEGEND_FONT_SETTING;
		chartLegendFontSize = self.lc.CHART_LEGEND_FONTSIZE_SETTING;
		
		gridHeaderFont = self.lc.GRID_HEADER_FONT_SETTING;
		gridHeaderFontSize= self.lc.GRID_HEADER_FONTSIZE_SETTING;
		gridHeaderColor = self.lc.GRID_HEADER_COLOR_SETTING;
		gridHeaderBgcolorT = self.lc.GRID_HEADER_BGCOLORT_SETTING;
		gridHeaderBgcolorB = self.lc.GRID_HEADER_BGCOLORB_SETTING;
		gridHeaderBocolorT = self.lc.GRID_HEADER_BOCOLORT_SETTING;
		gridHeaderBocolorB = self.lc.GRID_HEADER_BOCOLORB_SETTING;
		gridHeaderHeight = self.lc.GRID_HEADER_HEIGHT_SETTING;
		
		gridDataFont = self.lc.GRID_DATA_FONT_SETTING;
		gridDataFontSize = self.lc.GRID_DATA_FONTSIZE_SETTING;
		gridDataColor = self.lc.GRID_DATA_COLOR_SETTING;
		gridDataBgcolor = self.lc.GRID_DATA_BGCOLOR_SETTING;
		gridDataBocolor = self.lc.GRID_DATA_BOCOLOR_SETTING;
		gridDataHeight = self.lc.GRID_DATA_HEIGHT_SETTING;
		
		pibotHeaderFont = self.lc.PIBOT_HEADER_FONT_SETTING;
		pibotHeaderFontSize = self.lc.PIBOT_HEADER_FONTSIZE_SETTING;
		pibotHeaderColor = self.lc.PIBOT_HEADER_COLOR_SETTING;
		pibotHeaderBgcolor = self.lc.PIBOT_HEADER_BGCOLOR_SETTING;
		pibotHeaderBocolor = self.lc.PIBOT_HEADER_BOCOLOR_SETTING;
		pibotHeaderHeight = self.lc.PIBOT_HEADER_HEIGHT_SETTING;
		
		pibotLeftHeaderFont = self.lc.PIBOT_LEFTHEADER_FONT_SETTING;
		pibotLeftHeaderFontSize = self.lc.PIBOT_LEFTHEADER_FONTSIZE_SETTING;
		pibotLeftHeaderColor = self.lc.PIBOT_LEFTHEADER_COLOR_SETTING;
		pibotLeftHeaderBgcolorT = self.lc.PIBOT_LEFTHEADER_BGCOLORT_SETTING;
		pibotLeftHeaderBgcolorB = self.lc.PIBOT_LEFTHEADER_BGCOLORB_SETTING;
		pibotLeftHeaderBocolor = self.lc.PIBOT_LEFTHEADER_BOCOLOR_SETTING;
		pibotLeftHeaderHeight = self.lc.PIBOT_LEFTHEADER_HEIGHT_SETTING;
		
		pibotDataFont = self.lc.PIBOT_DATA_FONT_SETTING;
		pibotDataFontSize = self.lc.PIBOT_DATA_FONTSIZE_SETTING;
		pibotDataColor = self.lc.PIBOT_DATA_COLOR_SETTING;
		pibotDataBgcolor = self.lc.PIBOT_DATA_BGCOLOR_SETTING;
		pibotDataBocolor = self.lc.PIBOT_DATA_BOCOLOR_SETTING;
		pibotDataHeight = self.lc.PIBOT_DATA_HEIGHT_SETTING;
		
		pibotStFont = self.lc.PIBOT_ST_FONT_SETTING;
		pibotStFontSize = self.lc.PIBOT_ST_FONTSIZE_SETTING;
		pibotStColor = self.lc.PIBOT_ST_COLOR_SETTING;
		pibotStBgcolorT = self.lc.PIBOT_ST_BGCOLORT_SETTING;
		pibotStBgcolorB = self.lc.PIBOT_ST_BGCOLORB_SETTING;
		pibotStBocolor = self.lc.PIBOT_ST_BOCOLOR_SETTING;
		pibotStHeight = self.lc.PIBOT_ST_HEIGHT_SETTING;
		
		pibotTotalFont = self.lc.PIBOT_TOTAL_FONT_SETTING;
		pibotTotalFontSize = self.lc.PIBOT_TOTAL_FONTSIZE_SETTING;
		pibotTotalColor = self.lc.PIBOT_TOTAL_COLOR_SETTING;
		pibotTotalBgcolorT = self.lc.PIBOT_TOTAL_BGCOLORT_SETTING;
		pibotTotalBgcolorB = self.lc.PIBOT_TOTAL_BGCOLORB_SETTING;
		pibotTotalBocolor = self.lc.PIBOT_TOTAL_BOCOLOR_SETTING;
		pibotTotalHeight = self.lc.PIBOT_TOTAL_HEIGHT_SETTING;
		/*dogfoot 여백제거 기능 추가 shlim 20201020*/
		pibotAllmargin = self.lc.PIBOT_ALL_MARGIN_SETTING;
		
		filterLd = self.lc.FILTER_LD_SETTING;
		filterRd = self.lc.FILTER_RD_SETTING;
		filterD = self.lc.FILTER_D_SETTING;
		filterHeight = self.lc.FILTER_HEIGHT_SETTING;
		
		filterLabelFont = self.lc.FILTER_LABEL_FONT_SETTING;
		filterLabelFontSize = self.lc.FILTER_LABEL_FONTSIZE_SETTING;
		filterLabelColor = self.lc.FILTER_LABEL_COLOR_SETTING;
		
		filterDataFont = self.lc.FILTER_DATA_FONT_SETTING;
		filterDataFontSize = self.lc.FILTER_DATA_FONTSIZE_SETTING;
		filterDataColor = self.lc.FILTER_DATA_COLOR_SETTING;
		filterDataBocolor = self.lc.FILTER_DATA_BOCOLOR_SETTING;
		
		var previewFlag = false;
		
		var initInputValTitle = function(layoutObject){
			$("#title-height-setting").val(layoutObject.TITLE_HEIGHT_SETTING);															
			$("#title-main-font-setting").val(layoutObject.TITLE_MAIN_FONT_SETTING);
			$("#title-main-fontsize-setting").val(layoutObject.TITLE_MAIN_FONTSIZE_SETTING);
			$("#title-main-color-setting").dxColorBox('instance').option('value', layoutObject.TITLE_MAIN_COLOR_SETTING);
																							
			$("#title-serve-font-setting").val(layoutObject.TITLE_SERVE_FONT_SETTING);
			$("#title-serve-fontsize-setting").val(layoutObject.TITLE_SERVE_FONTSIZE_SETTING);
			$("#title-serve-color-setting").dxColorBox('instance').option('value', layoutObject.TITLE_SERVE_COLOR_SETTING);
		};
		var initInputValChart = function(layoutObject){
			//차트
			$("#chart-x-font-setting").val(layoutObject.CHART_X_FONT_SETTING);
			$("#chart-x-fontsize-setting").val(layoutObject.CHART_X_FONTSIZE_SETTING);
			$("#chart-x-color-setting").dxColorBox('instance').option('value', layoutObject.CHART_X_COLOR_SETTING);
			
			$("#chart-y-font-setting").val(layoutObject.CHART_Y_FONT_SETTING);
			$("#chart-y-fontsize-setting").val(layoutObject.CHART_Y_FONTSIZE_SETTING);
			$("#chart-y-color-setting").dxColorBox('instance').option('value', layoutObject.CHART_Y_COLOR_SETTING);
			
			$("#chart-legend-font-setting").val(layoutObject.CHART_LEGEND_FONT_SETTING);
			$("#chart-legend-fontsize-setting").val(layoutObject.CHART_LEGEND_FONTSIZE_SETTING);
		};
		var initInputValGrid = function(layoutObject){	
			//그리드
			$("#grid-header-font-setting").val(layoutObject.GRID_HEADER_FONT_SETTING);
			$("#grid-header-fontsize-setting").val(layoutObject.GRID_HEADER_FONTSIZE_SETTING);
			$("#grid-header-color-setting").dxColorBox('instance').option('value', layoutObject.GRID_HEADER_COLOR_SETTING);
			$("#grid-header-bgcolort-setting").dxColorBox('instance').option('value', layoutObject.GRID_HEADER_BGCOLORT_SETTING);
			$("#grid-header-bgcolorb-setting").dxColorBox('instance').option('value', layoutObject.GRID_HEADER_BGCOLORB_SETTING);
			$("#grid-header-bocolort-setting").dxColorBox('instance').option('value', layoutObject.GRID_HEADER_BOCOLORT_SETTING);
			$("#grid-header-bocolorb-setting").dxColorBox('instance').option('value', layoutObject.GRID_HEADER_BOCOLORB_SETTING);
			$("#grid-header-height-setting").val(layoutObject.GRID_HEADER_HEIGHT_SETTING);
			
			$("#grid-data-font-setting").val(layoutObject.GRID_DATA_FONT_SETTING);
			$("#grid-data-fontsize-setting").val(layoutObject.GRID_DATA_FONTSIZE_SETTING);
			$("#grid-data-color-setting").dxColorBox('instance').option('value', layoutObject.GRID_DATA_COLOR_SETTING);
			$("#grid-data-bgcolor-setting").dxColorBox('instance').option('value', layoutObject.GRID_DATA_BGCOLOR_SETTING);
			$("#grid-data-bocolor-setting").dxColorBox('instance').option('value', layoutObject.GRID_DATA_BOCOLOR_SETTING);
			$("#grid-data-height-setting").val(layoutObject.GRID_DATA_HEIGHT_SETTING);
		};
		var initInputValPibot = function(layoutObject){	
			//피벗
			$("#pibot-header-font-setting").val(layoutObject.PIBOT_HEADER_FONT_SETTING);
			$("#pibot-header-fontsize-setting").val(layoutObject.PIBOT_HEADER_FONTSIZE_SETTING);
			$("#pibot-header-color-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_HEADER_COLOR_SETTING);
			$("#pibot-header-bgcolor-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_HEADER_BGCOLOR_SETTING);
			$("#pibot-header-bocolor-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_HEADER_BOCOLOR_SETTING);
			$("#pibot-header-height-setting").val(layoutObject.PIBOT_HEADER_HEIGHT_SETTING);
			
			$("#pibot-leftheader-font-setting").val(layoutObject.PIBOT_LEFTHEADER_FONT_SETTING);
			$("#pibot-leftheader-fontsize-setting").val(layoutObject.PIBOT_LEFTHEADER_FONTSIZE_SETTING);
			$("#pibot-leftheader-color-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_LEFTHEADER_COLOR_SETTING);
			$("#pibot-leftheader-bgcolort-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_LEFTHEADER_BGCOLORT_SETTING);
			$("#pibot-leftheader-bgcolorb-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_LEFTHEADER_BGCOLORB_SETTING);
			$("#pibot-leftheader-bocolor-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_LEFTHEADER_BOCOLOR_SETTING);
			$("#pibot-leftheader-height-setting").val(layoutObject.PIBOT_LEFTHEADER_HEIGHT_SETTING);
			
			$("#pibot-data-font-setting").val(layoutObject.PIBOT_DATA_FONT_SETTING);
			$("#pibot-data-fontsize-setting").val(layoutObject.PIBOT_DATA_FONTSIZE_SETTING);
			$("#pibot-data-color-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_DATA_COLOR_SETTING);
			$("#pibot-data-bgcolor-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_DATA_BGCOLOR_SETTING);
			$("#pibot-data-bocolor-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_DATA_BOCOLOR_SETTING);
			$("#pibot-data-height-setting").val(layoutObject.PIBOT_DATA_HEIGHT_SETTING);
			
			$("#pibot-st-font-setting").val(layoutObject.PIBOT_ST_FONT_SETTING);
			$("#pibot-st-fontsize-setting").val(layoutObject.PIBOT_ST_FONTSIZE_SETTING);
			$("#pibot-st-color-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_ST_COLOR_SETTING);
			$("#pibot-st-bgcolort-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_ST_BGCOLORT_SETTING);
			$("#pibot-st-bgcolorb-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_ST_BGCOLORB_SETTING);
			$("#pibot-st-bocolor-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_ST_BOCOLOR_SETTING);
			$("#pibot-st-height-setting").val(layoutObject.PIBOT_ST_HEIGHT_SETTING);
			
			$("#pibot-total-font-setting").val(layoutObject.PIBOT_TOTAL_FONT_SETTING);
			$("#pibot-total-fontsize-setting").val(layoutObject.PIBOT_TOTAL_FONTSIZE_SETTING);
			$("#pibot-total-color-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_TOTAL_COLOR_SETTING);
			$("#pibot-total-bgcolort-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_TOTAL_BGCOLORT_SETTING);
			$("#pibot-total-bgcolorb-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_TOTAL_BGCOLORB_SETTING);
			$("#pibot-total-bocolor-setting").dxColorBox('instance').option('value', layoutObject.PIBOT_TOTAL_BOCOLOR_SETTING);
			$("#pibot-total-height-setting").val(layoutObject.PIBOT_TOTAL_HEIGHT_SETTING);
			/*dogfoot 여백제거 기능 추가 shlim 20201020*/
			$("#margin-check").dxCheckBox('instance').option('value',layoutObject.PIBOT_ALL_MARGIN_SETTING == true ? true : false)
		};
		var initInputValFilter = function(layoutObject){	
			//필터
			$("#filter-ld-setting").val(layoutObject.FILTER_LD_SETTING);
			$("#filter-rd-setting").val(layoutObject.FILTER_RD_SETTING);
			$("#filter-d-setting").val(layoutObject.FILTER_D_SETTING);
			$("#filter-height-setting").val(layoutObject.FILTER_HEIGHT_SETTING);
			
			$("#filter-label-font-setting").val(layoutObject.FILTER_LABEL_FONT_SETTING);
			$("#filter-label-fontsize-setting").val(layoutObject.FILTER_LABEL_FONTSIZE_SETTING);
			$("#filter-label-color-setting").dxColorBox('instance').option('value', layoutObject.FILTER_LABEL_COLOR_SETTING);
		
			$("#filter-data-font-setting").val(layoutObject.FILTER_DATA_FONT_SETTING);
			$("#filter-data-fontsize-setting").val(layoutObject.FILTER_DATA_FONTSIZE_SETTING);
			$("#filter-data-color-setting").dxColorBox('instance').option('value', layoutObject.FILTER_DATA_COLOR_SETTING);
			$("#filter-data-bocolor-setting").dxColorBox('instance').option('value', layoutObject.FILTER_DATA_BOCOLOR_SETTING);
		};
		
		var preViewInitTitle = function(){
			//타이틀
			titleHeight = $("#title-height-setting").val();
			if(titleHeight){
//				$("#layout_lm_close_tab").css('top',(titleHeight/2 - 7));
//				$("#layout_lm_close_tab").css('margin-top',5);
//				$("#layout_lm_header").attr("style", "height:"+titleHeight+"px !important; line-height:"+(titleHeight - 6)+"px; z-index: inherit; display:flex; align-items:center");
//				$("#layout_chartDashboardItem1_item_title").attr("style", "height:"+titleHeight+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
				
				
//				$(".lm_controls").css('margin','0px');
//				$(".lm_controls").css('position','absolute');
				
				if(pageset ==='reportset'){
					$(".lm_close_tab").css('top',((titleHeight)/2 - 7));
					$(".lm_close_tab").css('margin-top',5);
					$(".lm_header").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight - 7)+"px; z-index: inherit; display:flex; align-items:center;");
					$(".lm_tabs").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
					$(".lm_tab").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
				}else{
					$(".lm_close_tab").css('top',((titleHeight)/2 - 7));
					$(".lm_close_tab").css('margin-right','5px');
					$(".lm_close_tab").css('margin-left','10px');
					$(".lm_close_tab").css('margin-top','0px');
					$(".lm_header").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight - 7)+"px; z-index: inherit; display:flex; align-items:center;justify-content: space-between;");
					$(".lm_tabs").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
					$(".lm_tab").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
					$(".lm_controls").removeClass('cont_box_top_icon');
					$(".lm_controls").css('margin-right','10px');
					$(".lm_tab").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative;padding-left:10px");
				}
				
				
				
				//$(".lm_controls").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;");
				//$(".lm_controls").find('li').not('.invisible').not('.lm_tabdropdown').attr("style", "display:flex; align-items:center;");
			}
//			if(titleHeight) $(".lm_header").attr("style", "height:"+titleHeight+"px !important; line-height:"+titleHeight+"px; display:flex; align-items:flex-end;");
//			if(titleHeight) $(".lm_tab").attr("style", "height:"+titleHeight+"px !important; line-height:"+titleHeight+"px; display:flex; align-items:flex-end");
			titleMainFont = $("#title-main-font-setting").val();
			if(titleMainFont) $(".lm_title").css("font-family", titleMainFont);
			titleMainFontSize = $("#title-main-fontsize-setting").val();
			if(titleMainFontSize){
				$(".lm_title").css("font-size", titleMainFontSize+"px");
//				$(".lm_header").attr("style", " !important; display:flex; align-items:flex-end;");	
//				$(".lm_tab").attr("style", "!important; display:flex; padding-left:10px; align-items:center");	
				
			}
			titleMainColor = $("#title-main-color-setting").dxColorBox('instance').option('value');
			
			if(titleMainColor) $(".lm_title").css("color", titleMainColor); else $(".lm_title").css("color", "#6a6f7f");
			
			titleServeFont = $("#title-serve-font-setting").val();
			if(titleServeFont) $("#layout_chartDashboardItem1_item_text").css("font-family", titleServeFont);
			titleServeFontSize = $("#title-serve-fontsize-setting").val();
			if(titleServeFontSize) $("#layout_chartDashboardItem1_item_text").css("font-size", titleServeFontSize+"px");
			titleServeColor = $("#title-serve-color-setting").dxColorBox('instance').option('value');
			if(titleServeColor) $("#layout_chartDashboardItem1_item_text").css("color", titleServeColor);
			
			colorBoxSetting("title-main-color-setting", titleMainColor);
			colorBoxSetting("title-serve-color-setting", titleServeColor);
		};
		var preViewInitItem;
		var preViewInitChart = function(){
			//차트
			if(pageset === 'reportset'){
				chartXFont = $("#chart-x-font-setting").val();
				chartXFontSize = $("#chart-x-fontsize-setting").val();
				chartXColor = $("#chart-x-color-setting").dxColorBox('instance').option('value');
				
				var xFontC = {
					family : chartXFont,
					size : chartXFontSize,
					color : chartXColor
				}
				
				chartYFont = $("#chart-y-font-setting").val();
				chartYFontSize = $("#chart-y-fontsize-setting").val();
				chartYColor = $("#chart-y-color-setting").dxColorBox('instance').option('value');
				
				var yFontC = {
					family : chartYFont,
					size : chartYFontSize,
					color : chartYColor
				}
				
				chartLegendFont = $("#chart-legend-font-setting").val();
				chartLegendFontSize = $("#chart-legend-fontsize-setting").val();
				
				var legendFontC = {
					family : chartLegendFont,
					size : chartLegendFontSize
				}
				
				$("#chart-view").dxChart('instance').option('argumentAxis[label][font]', xFontC); 
				$("#chart-view").dxChart('instance').option('valueAxis[label][font]', yFontC);
				$("#chart-view").dxChart('instance').option('legend[font]', legendFontC); 
			}else if(pageset === 'configset'){
				chartXFont = $("#chart-x-font-setting").val();
				chartXFontSize = $("#chart-x-fontsize-setting").val();
				chartXColor = $("#chart-x-color-setting").dxColorBox('instance').option('value');
				
				var xFontC = {
					family : chartXFont,
					size : chartXFontSize,
					color : chartXColor
				}
				
				chartYFont = $("#chart-y-font-setting").val();
				chartYFontSize = $("#chart-y-fontsize-setting").val();
				chartYColor = $("#chart-y-color-setting").dxColorBox('instance').option('value');
				
				var yFontC = {
					family : chartYFont,
					size : chartYFontSize,
					color : chartYColor
				}
				
				chartLegendFont = $("#chart-legend-font-setting").val();
				chartLegendFontSize = $("#chart-legend-fontsize-setting").val();
				
				var legendFontC = {
					family : chartLegendFont,
					size : chartLegendFontSize
				}
				
				$("#chart-view").dxChart('instance').option('argumentAxis[label][font]', xFontC); 
				$("#chart-view").dxChart('instance').option('valueAxis[label][font]', yFontC);
				$("#chart-view").dxChart('instance').option('legend[font]', legendFontC); 
			}
			
		};
		
		var preViewInitChartConfirm = function(){
			if(pageset === 'reportset'){
				chartXFont = $("#chart-x-font-setting").val();
				chartXFontSize = $("#chart-x-fontsize-setting").val();
				chartXColor = $("#chart-x-color-setting").dxColorBox('instance').option('value');
	
				chartYFont = $("#chart-y-font-setting").val();
				chartYFontSize = $("#chart-y-fontsize-setting").val();
				chartYColor = $("#chart-y-color-setting").dxColorBox('instance').option('value');
			
				chartLegendFont = $("#chart-legend-font-setting").val();
				chartLegendFontSize = $("#chart-legend-fontsize-setting").val();
				
				if(gDashboard.itemGenerateManager.dxItemBasten){
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i,v){
						var chartType = v['type'];
//						chartType = chartType.slice(-5);
						/*dogfoot 차트 refresh오류 수정 shlim 20200828*/
						if(chartType=='SIMPLE_CHART'){
						/*dogfoot shlim 20210415*/
							if(v.dxItem){								
								//x축 설정								
								if(chartXFont)	v.dxItem.option('argumentAxis.label.font.family', chartXFont);	// 폰트
								if(chartXFontSize)	v.dxItem.option('argumentAxis.label.font.size', chartXFontSize+"px"); // 글꼴 크기								
								if(chartXColor!="#000000"){
									v.dxItem.option('argumentAxis.label.font.color', chartXColor);	//색상
								}
								
								//y축설정								
								$.each(v.dxItem.option().valueAxis, function(i,_v){									
									if(typeof _v.label.font !== 'undefined'){
								        if(chartYFont)	_v.label.font.family = chartYFont;
									    if(chartYFontSize)	_v.label.font.size = chartYFontSize;
										if(chartYColor!="#000000"){
											_v.label.font.color = chartYColor;	
									    }		
								    }						
								});
								
								v.dxItem.refresh();
								
								//범례 설정
								if(chartLegendFont)	v.dxItem.option('legend.font.family', chartLegendFont);
								if(chartLegendFontSize)	v.dxItem.option('legend.font.size', chartLegendFontSize);
							}								
						}
					});
				}
			}else if(pageset === 'configset'){
				layoutJson = self.lc 
			}
		}
		
		var preViewInitGrid = function(){
			//그리드
			gridHeaderFont = $("#grid-header-font-setting").val();
			gridHeaderFontSize = $("#grid-header-fontsize-setting").val();
			gridHeaderColor = $("#grid-header-color-setting").dxColorBox('instance').option('value');							
			gridHeaderBgcolorT = $("#grid-header-bgcolort-setting").dxColorBox('instance').option('value');	
			gridHeaderBgcolorB = $("#grid-header-bgcolorb-setting").dxColorBox('instance').option('value');	
			gridHeaderBocolorT = $("#grid-header-bocolort-setting").dxColorBox('instance').option('value');	
			gridHeaderBocolorB = $("#grid-header-bocolorb-setting").dxColorBox('instance').option('value');	
			gridHeaderHeight = $("#grid-header-height-setting").val();
			
			gridDataFont = $("#grid-data-font-setting").val();
			gridDataFontSize = $("#grid-data-fontsize-setting").val();
			gridDataColor = $("#grid-data-color-setting").dxColorBox('instance').option('value');	
			gridDataBgcolor =$("#grid-data-bgcolor-setting").dxColorBox('instance').option('value');	
			gridDataBocolor = $("#grid-data-bocolor-setting").dxColorBox('instance').option('value');	
			gridDataHeight = $("#grid-data-height-setting").val();
			
			$(".dx-datagrid-headers").css({
				"font-family": gridHeaderFont,
	            "font-size": gridHeaderFontSize+"px",
				"color" : gridHeaderColor,
			});												
			$(".dx-datagrid-borders .dx-datagrid-headers .dx-datagrid-table").css({
				"background-image" : "linear-gradient(to bottom,"+gridHeaderBgcolorT +"," + gridHeaderBgcolorB+")",
				"border-bottom" : "1px solid " + gridHeaderBocolorB,
				"border-top" : "1px solid " + gridHeaderBocolorT
			});							
//			$(".dx-row.dx-column-lines.dx-header-row").css("height" , gridHeaderHeight+"px");	
			
			$(".dx-datagrid-rowsview").css({	//데이터 영역
				"font-family" : gridDataFont,
				"font-size" : gridDataFontSize+"px",
				"color" : gridDataColor,
				"background-color" : gridDataBgcolor,
				"border" : "solid 1px #ddd"
			});
			$(".dx-datagrid-rowsview td").css("height", gridDataHeight+"px");
			$("#grid-view").find('td').css('vertical-align','middle');
		};
		var preViewInitPibot = function(){
			//피벗
			/*dogfoot 여백제거 기능 추가 shlim 20201020*/
			pibotAllmargin = $("#margin-check").dxCheckBox('instance').option('value');
			
			pibotHeaderFont = $("#pibot-header-font-setting").val();
			pibotHeaderFontSize = $("#pibot-header-fontsize-setting").val();
			pibotHeaderColor = $("#pibot-header-color-setting").dxColorBox('instance').option('value');	
			pibotHeaderBgcolor = $("#pibot-header-bgcolor-setting").dxColorBox('instance').option('value');	
			pibotHeaderBocolor = $("#pibot-header-bocolor-setting").dxColorBox('instance').option('value');	
			pibotHeaderHeight = $("#pibot-header-height-setting").val();
			
			pibotDefaultSetting();
			
			pibotLeftHeaderFont = $("#pibot-leftheader-font-setting").val();
			pibotLeftHeaderFontSize = $("#pibot-leftheader-fontsize-setting").val();
			pibotLeftHeaderColor =  $("#pibot-leftheader-color-setting").dxColorBox('instance').option('value');	
			pibotLeftHeaderBgcolorT = $("#pibot-leftheader-bgcolort-setting").dxColorBox('instance').option('value');
			pibotLeftHeaderBgcolorB =  $("#pibot-leftheader-bgcolorb-setting").dxColorBox('instance').option('value');
			pibotLeftHeaderBocolor =  $("#pibot-leftheader-bocolor-setting").dxColorBox('instance').option('value');
			pibotLeftHeaderHeight = $("#pibot-leftheader-height-setting").val();
			
			pibotLeftHeaderDefault();
			
			pibotDataFont = $("#pibot-data-font-setting").val();
			pibotDataFontSize = $("#pibot-data-fontsize-setting").val();
			pibotDataColor =  $("#pibot-data-color-setting").dxColorBox('instance').option('value');
			pibotDataBgcolor = $("#pibot-data-bgcolor-setting").dxColorBox('instance').option('value');
			pibotDataBocolor = $("#pibot-data-bocolor-setting").dxColorBox('instance').option('value');
			pibotDataHeight = $("#pibot-data-height-setting").val();
			
			pibotDataDefault();
			
			pibotStFont = $("#pibot-st-font-setting").val();
			pibotStFontSize = $("#pibot-st-fontsize-setting").val();
			pibotStColor = $("#pibot-st-color-setting").dxColorBox('instance').option('value');
			pibotStBgcolorT = $("#pibot-st-bgcolort-setting").dxColorBox('instance').option('value');
			pibotStBgcolorB = $("#pibot-st-bgcolorb-setting").dxColorBox('instance').option('value');		
			pibotStBocolor = $("#pibot-st-bocolor-setting").dxColorBox('instance').option('value');
			pibotStHeight = $("#pibot-st-height-setting").val();
			
			pibotStDefault();
			
			pibotTotalFont = $("#pibot-total-font-setting").val();
			pibotTotalFontSize = $("#pibot-total-fontsize-setting").val();
			pibotTotalColor = $("#pibot-total-color-setting").dxColorBox('instance').option('value');
			pibotTotalBgcolorT = $("#pibot-total-bgcolort-setting").dxColorBox('instance').option('value');
			pibotTotalBgcolorB = $("#pibot-total-bgcolorb-setting").dxColorBox('instance').option('value');	
			pibotTotalBocolor = $("#pibot-total-bocolor-setting").dxColorBox('instance').option('value');
			pibotTotalHeight = $("#pibot-total-height-setting").val();
			
			pibotTotalDefault();
		};
		var preViewInitFilter = function(_check){
			filterLd = $("#filter-ld-setting").val();
			filterRd = $("#filter-rd-setting").val();
			filterD = $("#filter-d-setting").val();
			filterHeight = $("#filter-height-setting").val();
			
			filterLabelFont = $("#filter-label-font-setting").val();
			filterLabelFontSize = $("#filter-label-fontsize-setting").val();
			filterLabelColor = $("#filter-label-color-setting").dxColorBox('instance').option('value');
			filterDataFont = $("#filter-data-font-setting").val();
			filterDataFontSize = $("#filter-data-fontsize-setting").val();
			filterDataColor = $("#filter-data-color-setting").dxColorBox('instance').option('value');
			filterDataBocolor = $("#filter-data-bocolor-setting").dxColorBox('instance').option('value');
			
			filterSetting(_check);
		};
		
		var reportLayoutPopup = $("#reportSetting-popup").dxPopup({
			
					"visible": true,
					"showCloseButton" : false,
					"onContentReady" : function(){
						gDashboard.fontManager.setFontConfigForOption('serisOptions')
					},
					//"height": 900,
					"width": 1517,
					"height": 821,
					"onShown" : function(){	//그려진 후
						/* DOGFOOT syjin 보고서 레이아웃 기본값 설정  20200814 */
						
						flag = 1;
						$('#right-col').dxScrollView({
							//width: '1019px',
							height: '540px'
						}).dxScrollView('instance');
						
						//타이틀		
						//if(titleHeight) $(".lm_header").attr("style", "height:"+titleHeight+"px !important; display:flex; align-items:center");
						if(titleHeight){
//							$("#layout_lm_header").attr("style", "height:"+(titleHeight)+"px !important; z-index: inherit;  display:flex; align-items:center");
//							$("#layout_chartDashboardItem1_item_title").attr("style", "height:"+(titleHeight)+"px !important; display:flex; align-items:center");
//							$("#layout_chartDashboardItem1_item_text").attr("style", "height:"+(titleHeight-6)+"px !important;  display:flex; align-items:center");
							if(pageset ==='reportset'){
								$(".lm_close_tab").css('top',((titleHeight)/2 - 7));
								$(".lm_close_tab").css('margin-top',5);
								$(".lm_header").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight - 7)+"px; z-index: inherit; display:flex; align-items:center;");
								$(".lm_tabs").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
								$(".lm_tab").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
							}else{
								$(".lm_close_tab").css('top',((titleHeight)/2 - 7));
								$(".lm_close_tab").css('margin-right','5px');
								$(".lm_close_tab").css('margin-left','10px');
								$(".lm_close_tab").css('margin-top','0px');
								$(".lm_header").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight - 7)+"px; z-index: inherit; display:flex; align-items:center;justify-content: space-between;");
								$(".lm_tabs").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
								$(".lm_tab").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
								$(".lm_controls").removeClass('cont_box_top_icon');
								$(".lm_controls").css('margin-right','10px');
								$(".lm_tab").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative;padding-left:10px");
							}
//							$(".lm_close_tab").css('top',((titleHeight)/2 - 7));
//							$(".lm_close_tab").css('margin-top',5);
//							$(".lm_header").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight - 7)+"px; z-index: inherit; display:flex; align-items:center;");
//							$(".lm_tabs").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;position:relative");
							//$(".lm_controls").attr("style", "height:"+(titleHeight)+"px !important; line-height:"+(titleHeight)+"px; display:flex; align-items:center;");
							//$(".lm_controls").find('li').not('.invisible').not('.lm_tabdropdown').attr("style", "display:flex; align-items:center;");
//							$(".lm_header").attr("style", "height:"+titleHeight+"px !important; display:flex; align-items:center");
//							$(".lm_tab").attr("style", "height:"+titleHeight+"px !important; display:flex; align-items:flex-end");
						}
						if(titleMainFont) $(".lm_title").css("font-family", titleMainFont);
						if(titleMainFontSize) $(".lm_title").css("font-size", titleMainFontSize+"px");
						if(titleMainColor) $(".lm_title").css("color", titleMainColor); else $(".lm_title").css("color", "#6a6f7f");
						
						if(titleServeFont) $("#layout_chartDashboardItem1_item_text").css("font-family", titleServeFont);
						if(titleServeFontSize) $("#layout_chartDashboardItem1_item_text").css("font-size", titleServeFontSize+"px");
						if(titleServeColor) $("#layout_chartDashboardItem1_item_text").css("color", titleServeColor);
						
						//그리드
						$(".dx-datagrid-headers").css({
							"font-family": gridHeaderFont,
				            "font-size": gridHeaderFontSize+"px",
							"color" : gridHeaderColor,
						});		
															
						$(".dx-datagrid-borders .dx-datagrid-headers .dx-datagrid-table").css({
										"background-image" : "linear-gradient(to bottom,"+gridHeaderBgcolorT +"," + gridHeaderBgcolorB+")",
					 					"border-bottom" : "1px solid " + gridHeaderBocolorB,
										"border-top" : "1px solid " + gridHeaderBocolorT
						});		
											
//						$(".dx-row.dx-column-lines.dx-header-row").css("height" , gridHeaderHeight+"px");		
						
						$(".dx-datagrid-rowsview").css({
							"font-family" : gridDataFont,
							"font-size" : gridDataFontSize+"px",
							"color" : gridDataColor,
							"background-color" : gridDataBgcolor,
							"border" : "solid 1px #ddd"
						});
						$(".dx-datagrid-rowsview td").css("height", gridDataHeight+"px");
						
						//필터
						filterSetting = function(_check){
							var marginL = filterLd;
							var marginR = filterRd;
							var marginD = filterD;
							if(_check){
//                                $(".condition-item-container").attr("style", "margin-left:"+marginL+"px; margin-right:"+marginR+"px");
								if(filterD!=""){
								    $(".condition-item-container").attr("style", "margin-right:"+marginD+"px");	
								}
								if(filterRd!="" && filterLd!=""){
								/*dogfoot shlim 20210415*/
									$(".condition-caption").css({
										'white-space': 'pre',
										'margin-left': marginL+"px",
										'margin-right': marginR+"px"
									});
								}						

								if(filterHeight!=""){
									
									$("#filter-bar").css({
										"max-height" : "1000px",
										"height" : filterHeight+"px"
									});
									
									//dogfoot 자산관리공사 필터 영역 4분할 syjin 20210826
									var kamkoWidth = 'auto';
									if(userJsonObject.siteNm == 'KAMKO'){
										kamkoWidth = '25%';
									}
									
									$.each($(".condition-item-container"),function(_i,_v){
										if($(_v).attr('paramVisible') === 'block'){
											$(_v).css({
												"max-height" : "1000px",
												"height" : filterHeight+"px",
												"display" : "flex",
//												"flex-wrap" : "wrap",
												"align-items" : "center",
												"width" : kamkoWidth
											});
										}else{
											$(_v).css({
												"max-height" : "1000px",
												"height" : filterHeight+"px",
												"display" : "none",
//												"flex-wrap" : "wrap",
												"align-items" : "center",
												"width" : kamkoWidth
											});
										}
									})
									
									$(".filter-item").css({
										"max-height" : "1000px",
										"height" : filterHeight+"px",
										"display" : "flex",
										"flex-wrap" : "wrap",
										"align-items" : "center"
									});
								}
								//라벨
								$(".condition-caption").css({
									"font-family" : filterLabelFont,
									"font-size" : filterLabelFontSize+"px",
									"color" : '#222',
									"font-weight" : 'normal',
									"white-space":"pre"/*dogfoot shlim 20210415*/
								});

								//데이터
								/*dogfoot shlim 20210415*/
								$(".condition-item").not('.between-item').css({															
									"border" : "solid 2px "+filterDataBocolor
								});
								$(".dx-texteditor-input.layout-config").css({
									"font-family" : filterDataFont,
									"font-size" : filterDataFontSize+"px",
									"font-weight" : '400'
								});

								$(".dx-texteditor-container>.dx-texteditor-input.layout-config").css({
									"font-family" : filterDataFont,
									"color" : "#222",
									"line-height" : "0px",
									"font-weight" : '400'
								});
							}else{
//								$(".condition-item-container.layout-config").attr("style", "margin-left:"+marginL+"px; margin-right:"+marginR+"px");
								
								if(filterD!=""){
								    $(".condition-item-container.layout-config").attr("style", "margin-right:"+marginD+"px");	
								}
								
								if(filterRd!="" && filterLd!=""){
								/*dogfoot shlim 20210415*/
								    $(".condition-caption.layout-config").attr("style", "white-space:pre;margin-left:"+marginL+"px; margin-right:"+marginR+"px");
								}	
								if(filterHeight!=""){
									$(".filter-bar.layout-config").css({
										"max-height" : "1000px",
										"height" : filterHeight+"px"
									});
									//dogfoot 자산관리공사 필터 영역 4분할 syjin 20210826
									var kamkoWidth = 'auto';
									if(userJsonObject.siteNm == 'KAMKO'){
										kamkoWidth = '25%';
									}
									
									$.each($(".condition-item-container"),function(_i,_v){
										if($(_v).attr('paramVisible') === 'block'){
											$(_v).css({
												"max-height" : "1000px",
												"height" : filterHeight+"px",
												"display" : "flex",
//												"flex-wrap" : "wrap",
												"align-items" : "center",
												"width" : kamkoWidth
											});
										}else{
											$(_v).css({
												"max-height" : "1000px",
												"height" : filterHeight+"px",
												"display" : "none",
//												"flex-wrap" : "wrap",
												"align-items" : "center",
												"width" : kamkoWidth
											});
										}
									})
									
									$(".filter-item.layout-config").css({
										"max-height" : "1000px",
										"height" : filterHeight+"px",
										"display" : "flex",
										"flex-wrap" : "wrap",
										"align-items" : "center"
									});
								}
								//라벨
								$(".condition-caption.layout-config").css({
									"font-family" : filterLabelFont,
									"font-size" : filterLabelFontSize+"px",
									"color" : '#222',
									"font-weight" : 'normal',
									"white-space":"pre"/*dogfoot shlim 20210415*/
								});

								//데이터
								$(".condition-item.layout-config").css({															
									"border" : "solid 2px "+filterDataBocolor
								});
								$(".dx-texteditor-input.layout-config").css({
									"font-family" : filterDataFont,
									"font-size" : filterDataFontSize+"px",
									"font-weight" : '400'
								})

								$(".dx-texteditor-container>.dx-texteditor-input.layout-config").css({
									"font-family" : filterDataFont,
									"color" : "#222",
									"font-weight" : '400'
								});
							}
							
						}	
						filterSetting(false);														
					},
					"onShowing" : function(){ //그려지기 전
							//타이틀	
						colorBoxSetting = function(id, val){
							$("#"+id).dxColorBox({
								value: "#ffffff",
								width: 74,
								height:30
							}).dxColorBox('instance');
							
							$("#"+id).dxColorBox('instance').option('value', val);
						}
						
						colorBoxSetting("title-main-color-setting", titleMainColor);
						colorBoxSetting("title-serve-color-setting", titleServeColor);
						colorBoxSetting("chart-x-color-setting", chartXColor);
						colorBoxSetting("chart-y-color-setting", chartYColor);
						colorBoxSetting("grid-header-color-setting", gridHeaderColor);
						colorBoxSetting("grid-header-bgcolort-setting", gridHeaderBgcolorT);
						colorBoxSetting("grid-header-bgcolorb-setting", gridHeaderBgcolorB);
						colorBoxSetting("grid-header-bocolort-setting", gridHeaderBocolorT);
						colorBoxSetting("grid-header-bocolorb-setting", gridHeaderBocolorB);
						colorBoxSetting("grid-data-color-setting", gridDataColor);
						colorBoxSetting("grid-data-bgcolor-setting", gridDataBgcolor);
						colorBoxSetting("grid-data-bocolor-setting", gridDataBocolor);
						colorBoxSetting("pibot-header-color-setting", pibotHeaderColor);
						colorBoxSetting("pibot-header-bgcolor-setting", pibotHeaderBgcolor);
						colorBoxSetting("pibot-header-bocolor-setting", pibotHeaderBocolor);
						colorBoxSetting("pibot-leftheader-color-setting", pibotLeftHeaderColor);
						colorBoxSetting("pibot-leftheader-bgcolort-setting", pibotLeftHeaderBgcolorT);
						colorBoxSetting("pibot-leftheader-bgcolorb-setting", pibotLeftHeaderBgcolorB);
						colorBoxSetting("pibot-leftheader-bocolor-setting", pibotLeftHeaderBocolor);
						colorBoxSetting("pibot-data-color-setting", pibotDataColor);
						colorBoxSetting("pibot-data-bgcolor-setting", pibotDataBgcolor);
						colorBoxSetting("pibot-data-bocolor-setting", pibotDataBocolor);
						colorBoxSetting("pibot-st-color-setting", pibotStColor);
						colorBoxSetting("pibot-st-bgcolort-setting", pibotStBgcolorT);
						colorBoxSetting("pibot-st-bgcolorb-setting", pibotStBgcolorB);
						colorBoxSetting("pibot-st-bocolor-setting", pibotStBocolor);
						colorBoxSetting("pibot-total-color-setting", pibotTotalColor);
						colorBoxSetting("pibot-total-bgcolort-setting", pibotTotalBgcolorT);
						colorBoxSetting("pibot-total-bgcolorb-setting", pibotTotalBgcolorB);
						colorBoxSetting("pibot-total-bocolor-setting", pibotTotalBocolor);
						colorBoxSetting("filter-label-color-setting", filterLabelColor);
						colorBoxSetting("filter-data-color-setting", filterDataColor);
						colorBoxSetting("filter-data-bocolor-setting", filterDataBocolor);
						
						initInputValTitle(self.lc);
						//initInputValItem();
						initInputValChart(self.lc);
						initInputValGrid(self.lc);
						initInputValPibot(self.lc);
						initInputValFilter(self.lc);
						////////
						//차트
						
						var xFont = {
							
								family : chartXFont,
								size : chartXFontSize,
								color : chartXColor
											
							};
						var yFont = {
								family : chartYFont,
								size : chartYFontSize,
								color : chartYColor
						}
						var legendFont = {
								family : chartLegendFont,
								size : chartLegendFontSize
						}
						
						$("#chart-view").dxChart({
							dataSource: [
								{
								    arg: 1950,
								    val: 2525778669
								}, {
								    arg: 1960,
								    val: 3026002942
								}, {
								    arg: 1970,
								    val: 3691172616
								}, {
								    arg: 1980,
								    val: 4449048798
								}, {
								    arg: 1990,
								    val: 5320816667
								}, {
								    arg: 2000,
								    val: 6127700428
								}, {
								    val: 6916183482
								}
							],
							legend: {
					            visible: true,
								font : legendFont
					        },
					        series: {
					            type: "bar"
					        },
					        argumentAxis: {
					            tickInterval: 10,
					            label: {
					                format: {
					                    type: "decimal"
					                },
									font : xFont
					            }
					        },
							valueAxis: {
								label: {
									font: yFont
								}
							}
						});					
						
						//그리드
						 $("#grid-view").dxDataGrid({
							dataSource: [{
							    "ID" : 1,
							    "CompanyName" : "Premier Buy",
							    "Address" : "7601 Penn Avenue South",
							    "City" : "Richfield",
							    "State" : "Minnesota",
							    "Zipcode" : 55423,
							    "Phone" : "(612) 291-1000",
							    "Fax" : "(612) 291-2001",
							    "Website" : "http =//www.nowebsitepremierbuy.com"
							}, {
							    "ID" : 2,
							    "CompanyName" : "ElectrixMax",
							    "Address" : "263 Shuman Blvd",
							    "City" : "Naperville",
							    "State" : "Illinois",
							    "Zipcode" : 60563,
							    "Phone" : "(630) 438-7800",
							    "Fax" : "(630) 438-7801",
							    "Website" : "http =//www.nowebsiteelectrixmax.com"
							}, {
							    "ID" : 3,
							    "CompanyName" : "Video Emporium",
							    "Address" : "1201 Elm Street",
							    "City" : "Dallas",
							    "State" : "Texas",
							    "Zipcode" : 75270,
							    "Phone" : "(214) 854-3000",
							    "Fax" : "(214) 854-3001",
							    "Website" : "http =//www.nowebsitevideoemporium.com"
							}, {
							    "ID" : 4,
							    "CompanyName" : "Screen Shop",
							    "Address" : "1000 Lowes Blvd",
							    "City" : "Mooresville",
							    "State" : "North Carolina",
							    "Zipcode" : 28117,
							    "Phone" : "(800) 445-6937",
							    "Fax" : "(800) 445-6938",
							    "Website" : "http =//www.nowebsitescreenshop.com"
							}, {
							    "ID" : 5,
							    "CompanyName" : "Braeburn",
							    "Address" : "1 Infinite Loop",
							    "City" : "Cupertino",
							    "State" : "California",
							    "Zipcode" : 95014,
							    "Phone" : "(408) 996-1010",
							    "Fax" : "(408) 996-1012",
							    "Website" : "http =//www.nowebsitebraeburn.com"
							}, {
							    "ID" : 6,
							    "CompanyName" : "PriceCo",
							    "Address" : "30 Hunter Lane",
							    "City" : "Camp Hill",
							    "State" : "Pennsylvania",
							    "Zipcode" : 17011,
							    "Phone" : "(717) 761-2633",
							    "Fax" : "(717) 761-2334",
							    "Website" : "http =//www.nowebsitepriceco.com"
							}, {
							    "ID" : 7,
							    "CompanyName" : "Ultimate Gadget",
							    "Address" : "1557 Watson Blvd",
							    "City" : "Warner Robbins",
							    "State" : "Georgia",
							    "Zipcode" : 31093,
							    "Phone" : "(995) 623-6785",
							    "Fax" : "(995) 623-6786",
							    "Website" : "http =//www.nowebsiteultimategadget.com"
							}, {
							    "ID" : 8,
							    "CompanyName" : "EZ Stop",
							    "Address" : "618 Michillinda Ave.",
							    "City" : "Arcadia",
							    "State" : "California",
							    "Zipcode" : 91007,
							    "Phone" : "(626) 265-8632",
							    "Fax" : "(626) 265-8633",
							    "Website" : "http =//www.nowebsiteezstop.com"
							}, {
							    "ID" : 9,
							    "CompanyName" : "Clicker",
							    "Address" : "1100 W. Artesia Blvd.",
							    "City" : "Compton",
							    "State" : "California",
							    "Zipcode" : 90220,
							    "Phone" : "(310) 884-9000",
							    "Fax" : "(310) 884-9001",
							    "Website" : "http =//www.nowebsiteclicker.com"
							}, {
							    "ID" : 10,
							    "CompanyName" : "Store of America",
							    "Address" : "2401 Utah Ave. South",
							    "City" : "Seattle",
							    "State" : "Washington",
							    "Zipcode" : 98134,
							    "Phone" : "(206) 447-1575",
							    "Fax" : "(206) 447-1576",
							    "Website" : "http =//www.nowebsiteamerica.com"
							}, {
							    "ID" : 11,
							    "CompanyName" : "Zone Toys",
							    "Address" : "1945 S Cienega Boulevard",
							    "City" : "Los Angeles",
							    "State" : "California",
							    "Zipcode" : 90034,
							    "Phone" : "(310) 237-5642",
							    "Fax" : "(310) 237-5643",
							    "Website" : "http =//www.nowebsitezonetoys.com"
							}, {
							    "ID" : 12,
							    "CompanyName" : "ACME",
							    "Address" : "2525 E El Segundo Blvd",
							    "City" : "El Segundo",
							    "State" : "California",
							    "Zipcode" : 90245,
							    "Phone" : "(310) 536-0611",
							    "Fax" : "(310) 536-0612",
							    "Website" : "http =//www.nowebsiteacme.com"
							}],
					        showBorders: true,
					        //paging: {
					        //    pageSize: 10
					        //},
					        //pager: {
					            //showPageSizeSelector: true,
					            //allowedPageSizes: [5, 10, 20],
					            //showInfo: true
					        //},
					        columns: ["CompanyName", "City", "State", "Phone", "Fax"]
						 });
						var sales = getPivotSample();			
					    reportLayoutPibot = $("#pibot-view").dxPivotGrid({
					        allowSortingBySummary: true,
					        allowSorting: true,
					        allowFiltering: true,
					        allowExpandAll: true,
					        height: 'auto',
							scrolling: {
					            mode: "virtual"
					        },
					        showBorders: true,
					        fieldChooser: {
					        	enabled: false,
					            allowSearch: false
					        },
					        dataSource: {
					            fields: [{
					                caption: "Region",
					                width: 120,
					                dataField: "region",
					                area: "row",
					                sortBySummaryField: "Total"
					            }, {
					                caption: "City",
					                dataField: "city",
					                width: 150,
					                area: "row"
					            }, {
					                dataField: "date",
					                dataType: "date",
					                area: "column"
					            }, {
					                groupName: "date",
					                groupInterval: "month",
					                visible: false
					            }, {
					                caption: "Total",
					                dataField: "amount",
					                dataType: "number",
					                summaryType: "sum",
					                format: "currency",
					                area: "data"
					            }],
					            store: sales
					        },
							onCellPrepared: function(){
								$("#pibot-view").find("table").css('border-collapse', 'separate');
								//피벗 기본값 세팅
								
							},
							onContentReady: function() {
								pibotDefaultSetting = function(){
								/*dogfoot 여백제거 기능 추가 shlim 20201020*/
									
									if(pibotAllmargin){
										$(".dx-pivotgrid-horizontal-headers td").css({
											"font-family" : pibotHeaderFont,
											"font-size" : pibotHeaderFontSize+"px",
											"color" : pibotHeaderColor,							
											"background-color" : pibotHeaderBgcolor,
											"border" : "solid 1px " + pibotHeaderBocolor,
											"padding": "4px",
											"font-weight":"400!important"
											//"height" : pibotHeaderHeight+"px" 						
										});
									}else{
										$(".dx-pivotgrid-horizontal-headers td").css({
											"font-family" : pibotHeaderFont,
											"font-size" : pibotHeaderFontSize+"px",
											"color" : pibotHeaderColor,							
											"background-color" : pibotHeaderBgcolor,
											"border" : "solid 1px " + pibotHeaderBocolor,
											"font-weight":"400!important"
											//"height" : pibotHeaderHeight+"px" 						
										});
									}
									
									$(".dx-area-column-cell").parent().css("height", pibotHeaderHeight+"px");
									//$(".dx-pivotgrid-horizontal-headers tr").css("height", pibotHeaderHeight/2+"px");
								}
								
								pibotLeftHeaderDefault = function(){
									
									if(pibotAllmargin){
										$('.dx-pivotgrid-vertical-headers').find('td').not('.dx-row-total').css({
											"font-family" : pibotLeftHeaderFont,
											"font-size" : pibotLeftHeaderFontSize+"px",					
											"background-image" : "linear-gradient(to bottom,"+pibotLeftHeaderBgcolorT +"," + pibotLeftHeaderBgcolorB+")",
											"border" : "solid 1px " + pibotLeftHeaderBocolor,
											"padding": "4px",
											"font-weight":"400!important"
										});
									}else{
										$('.dx-pivotgrid-vertical-headers').find('td').not('.dx-row-total').css({
											"font-family" : pibotLeftHeaderFont,
											"font-size" : pibotLeftHeaderFontSize+"px",					
											"background-image" : "linear-gradient(to bottom,"+pibotLeftHeaderBgcolorT +"," + pibotLeftHeaderBgcolorB+")",
											"border" : "solid 1px " + pibotLeftHeaderBocolor,
											"font-weight":"400!important"
										});
									}
									
									
									$('.dx-pivotgrid-vertical-headers td').css({
										"color" : pibotLeftHeaderColor,
										//"height" : pibotLeftHeaderHeight + "px"
									})
									
									$(".dx-bottom-row td").css("height", pibotLeftHeaderHeight+"px");
								}
								
								pibotDataDefault = function(){
									//데이터 영역
									
									if(pibotAllmargin){
										$('.dx-pivotgrid-area-data').find('td:not(.dx-grandtotal, .dx-total)').css({
											"font-family" : pibotDataFont,
											"font-size" : pibotDataFontSize+"px",	
											"color" : pibotDataColor,						
											"background-color" : pibotDataBgcolor,
											"border" : "solid 1px " + pibotDataBocolor,
											"padding": "4px",
											"font-weight":"400!important"
											//"height" : pibotDataHeight 
										});	
									}else{
										$('.dx-pivotgrid-area-data').find('td:not(.dx-grandtotal, .dx-total)').css({
											"font-family" : pibotDataFont,
											"font-size" : pibotDataFontSize+"px",	
											"color" : pibotDataColor,						
											"background-color" : pibotDataBgcolor,
											"border" : "solid 1px " + pibotDataBocolor,
											"font-weight":"400!important"
											//"height" : pibotDataHeight 
										});	
									}
									
								}
								
								pibotStDefault = function(){
									//소계 영역					
									
									if(pibotAllmargin){
										$('.dx-pivotgrid .dx-total').css({
											"font-family" : pibotStFont,
											"font-size" : pibotStFontSize+"px",	
											"color" : pibotStColor,						
											"background-image" : "linear-gradient(to bottom,"+pibotStBgcolorT +"," + pibotStBgcolorB+")",
											"border" : "solid 1px " + pibotStBocolor,
											"padding":"4px",
											"font-weight":"400!important"
											//"height" : pibotStHeight
										});
									}else{
										$('.dx-pivotgrid .dx-total').css({
											"font-family" : pibotStFont,
											"font-size" : pibotStFontSize+"px",	
											"color" : pibotStColor,						
											"background-image" : "linear-gradient(to bottom,"+pibotStBgcolorT +"," + pibotStBgcolorB+")",
											"border" : "solid 1px " + pibotStBocolor,
											"font-weight":"400!important"
											//"height" : pibotStHeight
										});
									}
									
								}
								
								pibotTotalDefault = function(){
									if(pibotAllmargin){
										$('.dx-pivotgrid .dx-grandtotal').css({
											"font-family" : pibotTotalFont,
											"font-size" : pibotTotalFontSize+"px",							
											"background-image" : "linear-gradient(to bottom,"+pibotTotalBgcolorT +"," + pibotTotalBgcolorB+")",
											"border" : "solid 1px " + pibotTotalBocolor,
											"padding":"4px",
											"font-weight":"600!important"
											//"height" : pibotTotalHeight 
										});
									}else{
										$('.dx-pivotgrid .dx-grandtotal').css({
											"font-family" : pibotTotalFont,
											"font-size" : pibotTotalFontSize+"px",							
											"background-image" : "linear-gradient(to bottom,"+pibotTotalBgcolorT +"," + pibotTotalBgcolorB+")",
											"border" : "solid 1px " + pibotTotalBocolor,
											"font-weight":"600!important"
											//"height" : pibotTotalHeight 
										});
									}
									
									$(".dx-pivotgrid .dx-grandtotal span").css({
										color : pibotTotalColor
									});
								}
								/*dogfoot 여백제거 기능 추가 shlim 20201020*/
								pibotAllmargin = $("#margin-check").dxCheckBox('instance').option('value');
								
								pibotHeaderFont = $("#pibot-header-font-setting").val();
								pibotHeaderFontSize = $("#pibot-header-fontsize-setting").val();
								pibotHeaderColor = $("#pibot-header-color-setting").dxColorBox('instance').option('value');	
								pibotHeaderBgcolor = $("#pibot-header-bgcolor-setting").dxColorBox('instance').option('value');	
								pibotHeaderBocolor = $("#pibot-header-bocolor-setting").dxColorBox('instance').option('value');	
								pibotHeaderHeight = $("#pibot-header-height-setting").val();
								
								pibotDefaultSetting();
								
								pibotLeftHeaderFont = $("#pibot-leftheader-font-setting").val();
								pibotLeftHeaderFontSize = $("#pibot-leftheader-fontsize-setting").val();
								pibotLeftHeaderColor =  $("#pibot-leftheader-color-setting").dxColorBox('instance').option('value');	
								pibotLeftHeaderBgcolorT = $("#pibot-leftheader-bgcolort-setting").dxColorBox('instance').option('value');
								pibotLeftHeaderBgcolorB =  $("#pibot-leftheader-bgcolorb-setting").dxColorBox('instance').option('value');
								pibotLeftHeaderBocolor =  $("#pibot-leftheader-bocolor-setting").dxColorBox('instance').option('value');
								pibotLeftHeaderHeight = $("#pibot-leftheader-height-setting").val();
								
								pibotLeftHeaderDefault();
								
								pibotDataFont = $("#pibot-data-font-setting").val();
								pibotDataFontSize = $("#pibot-data-fontsize-setting").val();
								pibotDataColor =  $("#pibot-data-color-setting").dxColorBox('instance').option('value');
								pibotDataBgcolor = $("#pibot-data-bgcolor-setting").dxColorBox('instance').option('value');
								pibotDataBocolor = $("#pibot-data-bocolor-setting").dxColorBox('instance').option('value');
								pibotDataHeight = $("#pibot-data-height-setting").val();
								
								pibotDataDefault();
								
								pibotStFont = $("#pibot-st-font-setting").val();
								pibotStFontSize = $("#pibot-st-fontsize-setting").val();
								pibotStColor = $("#pibot-st-color-setting").dxColorBox('instance').option('value');
								pibotStBgcolorT = $("#pibot-st-bgcolort-setting").dxColorBox('instance').option('value');
								pibotStBgcolorB = $("#pibot-st-bgcolorb-setting").dxColorBox('instance').option('value');		
								pibotStBocolor = $("#pibot-st-bocolor-setting").dxColorBox('instance').option('value');
								pibotStHeight = $("#pibot-st-height-setting").val();
								
								pibotStDefault();
								
								pibotTotalFont = $("#pibot-total-font-setting").val();
								pibotTotalFontSize = $("#pibot-total-fontsize-setting").val();
								pibotTotalColor = $("#pibot-total-color-setting").dxColorBox('instance').option('value');
								pibotTotalBgcolorT = $("#pibot-total-bgcolort-setting").dxColorBox('instance').option('value');
								pibotTotalBgcolorB = $("#pibot-total-bgcolorb-setting").dxColorBox('instance').option('value');	
								pibotTotalBocolor = $("#pibot-total-bocolor-setting").dxColorBox('instance').option('value');
								pibotTotalHeight = $("#pibot-total-height-setting").val();
								
								pibotTotalDefault();
								$("#pibot-view").find('.dx-scrollable-scrollbar').css('display','none');
								$("#pibot-view").find("td").css('vertical-align', 'middle');
								$("#pibot-view").dxPivotGrid('instance').option('height','515');
								$("#pibot-view").dxPivotGrid('instance').option('height','auto');
							}  
					    }).dxPivotGrid('instance');				
					},
					"title": "보고서 레이아웃 설정",
					"contentTemplate": function(contentElement) {			
						contentElement.css('padding', '0');
						
						var html = '<div class="modal-inner">' +
						'<div class="modal-body">' +
						'<div class="tab-title focus">' +
							'<ul class="tab-m" style="justify-content:center">' +
								'<li rel="tabP1-1" id="titleOptions"><a href="#" style="font-size:18px; background-image: -webkit-gradient(linear, left top, left bottom, from(#6a6f7f), to(#979aa3)); color: #fff;">타이틀 설정</a></li>' +
								'<li rel="tabP1-6" id="filterOptions"><a href="#" style="font-size:18px">필터 레이아웃 설정</a></li>' +
								'<li rel="tabP1-2" id="itemOptions" style="display:none;"><a href="#" style="font-size:18px">아이템 설정</a></li>' +
								'<li rel="tabP1-3" id="chartOptions"><a href="#" style="font-size:18px">차트 설정</a></li>' +
								'<li rel="tabP1-4" id="gridOptions"><a href="#" style="font-size:18px">그리드 설정</a></li>' +
								'<li rel="tabP1-5" id="pibotOptions"><a href="#" style="font-size:18px">피벗 그리드 설정</a></li>' +
								
							'</ul>' +
						'</div>' +
						
						'<div class="row">' +
							'<div id="left-colview" class="column" style="width:30%:height:690px">' +
							'<div id="left-col" style="width:100%;height:605px">' +
								'<div id="tabP1" class="tab-component">' +
									'<div class="tabP1-1 tab-content">' +
										'<div class="modal-article">' +	
											'<div class="add-item">' +
												'<a href="#" class="add-item-head on" style="font-size:17px;color:#577df6">공통</a>' +
												'<ul class="add-item-body">' +
													'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
													'<table>' +
														'<tr>' +
															'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">높이</th>' +
															'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text""number" id="title-height-setting" style="width:55px"></td>' +
														'</tr>' +
													'</table>' +
													'</div>' +
												'</ul>' +
											'</div>' +
											'<div class="add-item">' +
												'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">타이틀 제목</a>' +
												'<ul class="add-item-body">' +
													'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
													'<table>' +
														'<tr>' +
															'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
															'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																'<select style="width:130px !important;" id="title-main-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
															'</td>' +
															'<td class="ipt" style="width:60px; padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="title-main-fontsize-setting" style="width:55px"/></td>' +
															'<td class="ipt" style="width:100px; padding: 8px 8px 8px !important;">' +
																'<div id="title-main-color-setting" style="padding: 5px 5px 5px !important;">' +
																'</div>' +
															'</td>' +
														'</tr>' +
													'</table>' +
													'</div>' +	
												'</ul>' +													
											'</div>' +
											'<div class="add-item">' +
											'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">부 제목</a>' +
												'<ul class="add-item-body">' +
													'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
													'<table>' +
														'<tr>' +
															'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
															'<td class="ipt" style="width:130px; padding: 8px 8px 8px !important;">' +
																'<select style="width:130px !important;" id="title-serve-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
															'</td>' +
															'<td class="ipt" style="width:60px; padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="title-serve-fontsize-setting" style="width:55px"></td>' +
															'<td class="ipt" style="width:100px; padding: 8px 8px 8px !important;">' +
																'<div id="title-serve-color-setting">' +
																'</div>' +
															'</td>' +
														'</tr>' +
													'</table>' +
													'</div>' +
												'</ul>' +
											'</div>' +
										'</div>' +
									'</div>' +
									
									'<div id="tabP2" class="tab-component">' +
										'<div class="tabP1-2 tab-content" style="display:none">' +
											'<div class="modal-article">' +	
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">아이탬</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">아이템 간격</th>' +
																'<td class="ipt"><input class="wise-text-input" type="text" id="item-distance-setting" style="width:55px"></td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더</th>' +
																/*'<td class="ipt"><input class="wise-text-input" type="text" id="item-border-setting" style="width:55px"></td>' +*/
																'<td class="ipt">' +
																'<div id="item-border-setting">' +
																'</div>' +
															'</td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상</th>' +
																/*'<td class="ipt"><input type="color" id="item-bocolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt">' +
																'<div id="item-bocolor-setting">' +
																'</div>' +
															'</td>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
											'</div>' +
										'</div>' +
									'</div>' +
									
									'<div id="tabP3" class="tab-component">' +
										'<div class="tabP1-3 tab-content" style="display:none">' +
											'<div class="modal-article">' +	
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">x축 설정</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="chart-x-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="chart-x-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="chart-x-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">y축 설정</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="chart-y-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="chart-y-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="chart-y-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">범례 설정</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px !important;padding-right: 8px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="chart-legend-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="chart-legend-fontsize-setting" style="width:55px"></td>' +
																'<td></td>'+
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +																
											'</div>' +
										'</div>' +
									'</div>' +
									
									'<div id="tabP4" class="tab-component">' +
										'<div class="tabP1-4 tab-content" style="display:none">' +
											'<div class="modal-article">' +	
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">헤더 영역</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">높이</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="grid-header-height-setting" style="width:55px"></td>' +
																'<th></th>' +
																'<td></td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="grid-header-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="grid-header-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="grid-header-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상 top</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="grid-header-bgcolort-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="grid-header-bgcolort-setting">' +
																'</div>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상 bottom</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="grid-header-bgcolorb-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="grid-header-bgcolorb-setting">' +
																'</div>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상 top</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="grid-header-bocolort-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="grid-header-bocolort-setting">' +
																'</div>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상 bottom</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="grid-header-bocolorb-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="grid-header-bocolorb-setting">' +
																'</div>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">데이터 영역</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">높이</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="grid-data-height-setting" style="width:55px"></td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="tbl data-form preferences-tbl" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="grid-data-font-setting">' +
																        '<option value="Basic">기본</option>' +
																        '<option value="Noto Sans KR">Noto Sans KR</option>' +
																        '<option value="Nanum Square">Nanum Square</option>' +
																        '<option value="Roboto">Roboto</option>' +
																        '<option value="Georgia, serif">Georgia</option>' +
																        '<option value="sans-serif">sans-serif</option>' +
																        '<option value="monospace">monospace</option>' +
																        '<option value="cursive">cursive</option>' +
															         	'<option value="맑은 고딕">맑은 고딕</option>' +
															         	'<option value="굴림">굴림</option>' +
						    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="grid-data-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="grid-data-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="grid-data-bgcolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																	'<div id="grid-data-bgcolor-setting">' +
																	'</div>' +
																'</td>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="grid-data-bocolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																	'<div id="grid-data-bocolor-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
															'<tr>' +
																
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
											'</div>' +
										'</div>' +
									'</div>' +
									
									'<div id="tabP5" class="tab-component">' +
										'<div class="tabP1-5 tab-content" style="display:none">' +
											'<div class="modal-article">' +	
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">헤더 영역</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">높이</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="pibot-header-height-setting" style="width:55px"></td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="pibot-header-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="pibot-header-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="pibot-header-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-header-bgcolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																	'<div id="pibot-header-bgcolor-setting">' +
																	'</div>' +	
																'</td>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-header-bocolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																	'<div id="pibot-header-bocolor-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">컬럼 영역</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">높이</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="pibot-leftheader-height-setting" style="width:55px"></td>' +
																'<th></th>' +
																'<td></td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="pibot-leftheader-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="pibot-leftheader-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="pibot-leftheader-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상 top</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-leftheader-bgcolort-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-leftheader-bgcolort-setting">' +
																'</div>' +	
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상 bottom</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-leftheader-bgcolorb-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-leftheader-bgcolorb-setting">' +
																'</div>' +	
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-leftheader-bocolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-leftheader-bocolor-setting">' +
																'</div>' +	
																'<th></th>' +
																'<td></td>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">데이터 영역</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="pibot-data-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="pibot-data-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="pibot-data-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-data-bgcolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-data-bgcolor-setting">' +
																'</div>' +	
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-data-bocolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																	'<div id="pibot-data-bocolor-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">소계 영역</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="pibot-st-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="pibot-st-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="pibot-st-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상 top</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-st-bgcolort-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-st-bgcolort-setting">' +
																'</div>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상 bottom</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-st-bgcolorb-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-st-bgcolorb-setting">' +
																'</div>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-st-bocolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-st-bocolor-setting">' +
																'</div>' +
																'<th></th>' +
																'<td></td>' +
															'</tr>' +
															/*'<tr>' +
																'<th class="left" style="width:100px">높이</th>' +
																'<td class="ipt"><input class="wise-text-input" type="text" id="pibot-st-height-setting" style="width:55px"></td>' +
																'<th></th>' +
																'<td></td>' +
															'</tr>' +*/
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">합계 영역</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="pibot-total-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="pibot-total-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="pibot-total-color-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상 top</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-total-bgcolort-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-total-bgcolort-setting">' +
																'</div>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">배경 색상 bottom</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-total-bgcolorb-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-total-bgcolorb-setting">' +
																'</div>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더 색상</th>' +
																/*'<td class="ipt" style="width:100px"><input type="color" id="pibot-total-bocolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																'<div id="pibot-total-bocolor-setting">' +
																'</div>' +
																'<th></th>' +
																'<td></td>' +
															'</tr>' +
															/*'<tr>' +
																'<th class="left" style="width:100px">높이</th>' +
																'<td class="ipt"><input class="wise-text-input" type="text" id="pibot-total-height-setting" style="width:55px"></td>' +
																'<th></th>' +
																'<td></td>' +
															'</tr>' +*/
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												/*dogfoot 여백제거 기능 추가 shlim 20201020*/
												'<div class="add-item">' +
												'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">전체 영역</a>' +
												'<ul class="add-item-body">' +
													'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
													'<table>' +
														'<tr>' +
															'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">여백 제거</th>' +
															'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																'<div id="margin-check"></div>'+
															'</td>' +
														'</tr>' +
													'</table>' +
													'</div>' +
												'</ul>' +
											'</div>' +	
												
											'</div>' +
										'</div>' +
									'</div>' +
									
									'<div id="tabP6" class="tab-component">' +
										'<div class="tabP1-6 tab-content" style="display:none">' +
											'<div class="modal-article">' +
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">공통 영역</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">높이</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="filter-height-setting" style="width:55px"></td>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">필터간격</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="filter-d-setting" style="width:55px"></td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">왼쪽간격</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="filter-ld-setting" style="width:55px"></td>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">오른쪽간격</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="filter-rd-setting" style="width:55px"></td>' +
																
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">라벨</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="width:130px;padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="filter-label-font-setting">' +
															        '<option value="Basic">기본</option>' +
															        '<option value="Noto Sans KR">Noto Sans KR</option>' +
															        '<option value="Nanum Square">Nanum Square</option>' +
															        '<option value="Roboto">Roboto</option>' +
															        '<option value="Georgia, serif">Georgia</option>' +
															        '<option value="sans-serif">sans-serif</option>' +
															        '<option value="monospace">monospace</option>' +
															        '<option value="cursive">cursive</option>' +
														         	'<option value="맑은 고딕">맑은 고딕</option>' +
														         	'<option value="굴림">굴림</option>' +
					    										'</select>' +
																'</td>' +
																'<td class="ipt" style="width:60px;padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="filter-label-fontsize-setting" style="width:55px"></td>' +
																'<td class="ipt" style="width:100px;padding: 8px 8px 8px !important;">' +
																	'<div id="filter-label-color-setting">' +
																	'</div>' +
																'</tr>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
												
												'<div class="add-item">' +
													'<a href="#" class="add-item-head on" style="font-size:17px; color:#577df6">데이터</a>' +
													'<ul class="add-item-body">' +
														'<div class="tbl data-form preferences-tbl" style="overflow-y:hidden">' +
														'<table>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																	'<select style="width:130px !important;" id="filter-data-font-setting">' +
																        '<option value="Basic">기본</option>' +
																        '<option value="Noto Sans KR">Noto Sans KR</option>' +
																        '<option value="Nanum Square">Nanum Square</option>' +
																        '<option value="Roboto">Roboto</option>' +
																        '<option value="Georgia, serif">Georgia</option>' +
																        '<option value="sans-serif">sans-serif</option>' +
																        '<option value="monospace">monospace</option>' +
																        '<option value="cursive">cursive</option>' +
															         	'<option value="맑은 고딕">맑은 고딕</option>' +
															         	'<option value="굴림">굴림</option>' +
						    										'</select>' +
																'</td>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">글꼴크기</th>' +
																'<td class="ipt" style="padding: 8px 8px 8px !important;"><input class="wise-text-input" type="text" id="filter-data-fontsize-setting" style="width:55px"></td>' +
															'</tr>' +
															'<tr>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">색상</th>' +
																/*'<td class="ipt"><input type="color" id="filter-data-color-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																	'<div id="filter-data-color-setting">' +
																	'</div>' +
																'</td>' +
																'<th class="left" style="width:100px; padding: 14px 13px 16px !important;">보더색상</th>' +
																/*'<td class="ipt"><input type="color" id="filter-data-bocolor-setting" style="width:55px"></td>' +*/
																'<td class="ipt" style="padding: 8px 8px 8px !important;">' +
																	'<div id="filter-data-bocolor-setting">' +
																	'</div>' +
																'</td>' +
															'</tr>' +
														'</table>' +
														'</div>' +
													'</ul>' +
												'</div>' +
											'</div>' +
										'</div>' +
									'</div>' +
								'</div>' +
							'</div>' +
							'<div>' +
							
								'<div style="display:flex; justify-content:center; margin-top:30px">' +
									'<div id="preview-btn" style="margin-right:20px">' +
									
									'</div>' +
								
									'<div id="back-btn">' +
									
									'</div>' +
								'</div>' +
							
							
							'</div>' +
							'</div>' +																		
							'<div id="" class="column" style="width:70%;">' +			
							
							'<div style="display:flex; justify-content: space-between; align-items:flex-start;">' +
								'<div>' +
									'<div class="modal-tit chart-tit" style="width: 1030px; font-size:18px; font-family: "Noto Sans KR, sans-serif;">' +
										'<div style="display:flex; justify-content:space-between;">' +
											'<span>' +
												'차트' +
											'</span>' +
											
											'<div class="defaultValue-btn">'	+
											
											'</div>' +
										'</div>' +
									'</div>' +
									
									'<div class="modal-tit grid-tit" style="display:none; width: 1030px; font-size:18px; font-family: "Noto Sans KR, sans-serif;">' +
										'<div style="display:flex; justify-content:space-between;">' +
											'<span>' +
												'그리드' +
											'</span>' +
											
											'<div class="defaultValue-btn">'	+
											
											'</div>' +
										'</div>' +
									'</div>' +
								
									'<div class="modal-tit pibot-tit" style="display:none; width: 1030px; font-size:18px; font-family: "Noto Sans KR, sans-serif;">' +
										'<div style="display:flex; justify-content:space-between;">' +
											'<span>' +
												'피벗 그리드' +
											'</span>' +
											
											'<div class="defaultValue-btn">'	+
											
											'</div>' +
										'</div>' +
									'</div>' +																	
								'</div>' +							
							'</div>' +	
							'<div id="right-col" style="height:515px;">' +
								//필터
								/* goyong ktkang 디자인 수정  20210513 */
								'<div id="filter-bar-config" class="filter-bar ui-droppable ui-sortable ui-sortable-disabled layout-config" style="height: 40px;"><div class="filter-row"><div class="filter-gui"><div class="filter-col ui"><a href="#" class="filter filter-more" style="display: none;"><span>Filter</span></a></div></div><div id="report-filter-item" class="filter-item layout-config"><div class="condition-item-container layout-config" paramVisible="block" style="display:block;"><div id="param_DEMO_01_D_공공_일자기준일명_caption" class="condition-caption layout-config">기준일명</div><div id="param_DEMO_01_D_공공_일자기준일명" class="condition-item dx-textbox dx-texteditor dx-editor-outlined dx-state-readonly dx-widget layout-config" style="width: 250px; height: 26px;"><div class="dx-texteditor-container"><input autocomplete="off" value="전체" class="dx-texteditor-input layout-config" type="text" readonly="" aria-readonly="true" spellcheck="false" tabindex="0" role="textbox" style="min-height: 0px;"><div data-dx_placeholder="" class="dx-placeholder dx-state-invisible"></div><div class="dx-texteditor-buttons-container"></div></div></div><div id="param_DEMO_01_D_공공_일자기준일명_list_cont" class="dx-overlay dx-popup dx-popover dx-widget dx-state-invisible dx-visibility-change-handler"><div class="dx-overlay-content dx-popup-normal dx-resizable" aria-hidden="true" style="width: 250px; height: 300px;"><div class="dx-popover-arrow"></div><div class="dx-popup-content"><div id="param_DEMO_01_D_공공_일자기준일명_list" style="height:210px;" class="dx-scrollable dx-scrollview dx-visibility-change-handler dx-scrollable-vertical dx-scrollable-simulated dx-scrollable-customizable-scrollbars dx-list dx-widget dx-collection dx-has-next dx-list-select-decorator-enabled" role="listbox" tabindex="0" aria-activedescendant="dx-bcec2201-cfbb-3935-8c63-5a3d384478ad"><div class="dx-scrollable-wrapper"><div class="dx-scrollable-container"><div class="dx-scrollable-content" style="left: 0px; top: 0px; transform: none; padding-bottom: 12px;"><div class="dx-scrollview-top-pocket"><div class="dx-scrollview-pull-down" style="display: none;"><div class="dx-scrollview-pull-down-image"></div><div class="dx-scrollview-pull-down-indicator"><div class="dx-loadindicator dx-widget"><div class="dx-loadindicator-wrapper"><div class="dx-loadindicator-content"><div class="dx-loadindicator-icon"><div class="dx-loadindicator-segment dx-loadindicator-segment7"></div><div class="dx-loadindicator-segment dx-loadindicator-segment6"></div><div class="dx-loadindicator-segment dx-loadindicator-segment5"></div><div class="dx-loadindicator-segment dx-loadindicator-segment4"></div><div class="dx-loadindicator-segment dx-loadindicator-segment3"></div><div class="dx-loadindicator-segment dx-loadindicator-segment2"></div><div class="dx-loadindicator-segment dx-loadindicator-segment1"></div><div class="dx-loadindicator-segment dx-loadindicator-segment0"></div></div></div></div></div></div><div class="dx-scrollview-pull-down-text"><div class="dx-scrollview-pull-down-text-visible">Pull down to refresh...</div><div>Release to refresh...</div><div>Refreshing...</div></div></div></div><div class="dx-scrollview-content"><div class="dx-list-select-all"><div class="dx-list-select-all-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true" tabindex="0"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div><div class="dx-list-select-all-label">전체</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">01일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">02일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">03일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">04일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">05일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">06일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">07일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">08일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">09일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">10일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">11일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">12일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">13일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">14일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">15일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">16일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">17일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">18일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">19일</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">20일</div></div><div class="dx-list-next-button"><div class="dx-button dx-button-mode-contained dx-widget dx-button-has-text" role="button" aria-label="More" tabindex="0"><div class="dx-button-content"><span class="dx-button-text">More</span></div></div></div></div><div class="dx-scrollview-bottom-pocket"><div class="dx-scrollview-scrollbottom" style="display: none;"><div class="dx-scrollview-scrollbottom-indicator"><div class="dx-loadindicator dx-widget"><div class="dx-loadindicator-wrapper"><div class="dx-loadindicator-content"><div class="dx-loadindicator-icon"><div class="dx-loadindicator-segment dx-loadindicator-segment7"></div><div class="dx-loadindicator-segment dx-loadindicator-segment6"></div><div class="dx-loadindicator-segment dx-loadindicator-segment5"></div><div class="dx-loadindicator-segment dx-loadindicator-segment4"></div><div class="dx-loadindicator-segment dx-loadindicator-segment3"></div><div class="dx-loadindicator-segment dx-loadindicator-segment2"></div><div class="dx-loadindicator-segment dx-loadindicator-segment1"></div><div class="dx-loadindicator-segment dx-loadindicator-segment0"></div></div></div></div></div></div><div class="dx-scrollview-scrollbottom-text">Loading...</div></div></div></div><div class="dx-scrollable-scrollbar dx-widget dx-scrollbar-vertical dx-scrollbar-hoverable"><div class="dx-scrollable-scroll dx-state-invisible" style="height: 15px; transform: translate(0px, 0px);"><div class="dx-scrollable-scroll-content"></div></div></div></div></div><div class="dx-scrollview-loadpanel dx-overlay dx-widget dx-state-invisible dx-visibility-change-handler dx-loadpanel"><div class="dx-overlay-content" aria-hidden="true" style="width: 222px; height: 90px;"></div></div></div><div class="popover_btn_space"><button id="param_DEMO_01_D_공공_일자기준일명_btn_ok" type="button" class="ui-button-ok" role="button"><span class="ui-button-text">확인</span></button><button id="param_DEMO_01_D_공공_일자기준일명_btn_cancel" type="button" class="ui-button-cancel" role="button"><span class="ui-button-text">취소</span></button></div></div></div></div><div id="기준일명_tooltip" class="dx-overlay dx-popup dx-popover dx-widget dx-state-invisible dx-visibility-change-handler dx-tooltip"><div class="dx-overlay-content dx-popup-normal" aria-hidden="true" id="dx-3a10363c-9474-c24c-4e32-4822eab62654" role="tooltip" style="width: auto; height: auto;"><div class="dx-popover-arrow"></div><div class="dx-popup-content"></div></div></div></div><div class="condition-item-container layout-config" paramVisible="block" style="display:block;"><div id="param_DEMO_01_D_공공_일자기준분기명_caption" class="condition-caption layout-config">기준분기명</div><div id="param_DEMO_01_D_공공_일자기준분기명" class="condition-item dx-textbox dx-texteditor dx-editor-outlined dx-state-readonly dx-widget layout-config" style="width: 250px; height: 26px;"><div class="dx-texteditor-container"><input autocomplete="off" value="전체" class="dx-texteditor-input layout-config" type="text" readonly="" aria-readonly="true" spellcheck="false" tabindex="0" role="textbox" style="min-height: 0px;"><div data-dx_placeholder="" class="dx-placeholder dx-state-invisible"></div><div class="dx-texteditor-buttons-container"></div></div></div><div id="param_DEMO_01_D_공공_일자기준분기명_list_cont" class="dx-overlay dx-popup dx-popover dx-widget dx-state-invisible dx-visibility-change-handler"><div class="dx-overlay-content dx-popup-normal dx-resizable" aria-hidden="true" style="width: 250px; height: 300px;"><div class="dx-popover-arrow"></div><div class="dx-popup-content"><div id="param_DEMO_01_D_공공_일자기준분기명_list" style="height:210px;" class="dx-scrollable dx-scrollview dx-visibility-change-handler dx-scrollable-vertical dx-scrollable-simulated dx-scrollable-customizable-scrollbars dx-list dx-widget dx-collection dx-list-select-decorator-enabled" role="listbox" tabindex="0" aria-activedescendant="dx-0e451636-bcc3-aa9a-f45e-0c8d327e64bb"><div class="dx-scrollable-wrapper"><div class="dx-scrollable-container"><div class="dx-scrollable-content" style="left: 0px; top: 0px; transform: none;"><div class="dx-scrollview-top-pocket"><div class="dx-scrollview-pull-down" style="display: none;"><div class="dx-scrollview-pull-down-image"></div><div class="dx-scrollview-pull-down-indicator"><div class="dx-loadindicator dx-widget"><div class="dx-loadindicator-wrapper"><div class="dx-loadindicator-content"><div class="dx-loadindicator-icon"><div class="dx-loadindicator-segment dx-loadindicator-segment7"></div><div class="dx-loadindicator-segment dx-loadindicator-segment6"></div><div class="dx-loadindicator-segment dx-loadindicator-segment5"></div><div class="dx-loadindicator-segment dx-loadindicator-segment4"></div><div class="dx-loadindicator-segment dx-loadindicator-segment3"></div><div class="dx-loadindicator-segment dx-loadindicator-segment2"></div><div class="dx-loadindicator-segment dx-loadindicator-segment1"></div><div class="dx-loadindicator-segment dx-loadindicator-segment0"></div></div></div></div></div></div><div class="dx-scrollview-pull-down-text"><div class="dx-scrollview-pull-down-text-visible">Pull down to refresh...</div><div>Release to refresh...</div><div>Refreshing...</div></div></div></div><div class="dx-scrollview-content"><div class="dx-list-select-all"><div class="dx-list-select-all-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true" tabindex="0"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div><div class="dx-list-select-all-label">전체</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">1분기</div></div><div class="dx-item dx-list-item dx-list-item-selected" role="option" aria-selected="true"><div class="dx-list-item-before-bag dx-list-select-checkbox-container"><div class="dx-list-select-checkbox dx-checkbox dx-widget dx-checkbox-checked" role="checkbox" aria-checked="true"><input type="hidden" value="true"><div class="dx-checkbox-container"><span class="dx-checkbox-icon"></span></div></div></div><div class="dx-item-content dx-list-item-content">2분기</div></div></div><div class="dx-scrollview-bottom-pocket"><div class="dx-scrollview-scrollbottom" style="display: none;"><div class="dx-scrollview-scrollbottom-indicator"><div class="dx-loadindicator dx-widget"><div class="dx-loadindicator-wrapper"><div class="dx-loadindicator-content"><div class="dx-loadindicator-icon"><div class="dx-loadindicator-segment dx-loadindicator-segment7"></div><div class="dx-loadindicator-segment dx-loadindicator-segment6"></div><div class="dx-loadindicator-segment dx-loadindicator-segment5"></div><div class="dx-loadindicator-segment dx-loadindicator-segment4"></div><div class="dx-loadindicator-segment dx-loadindicator-segment3"></div><div class="dx-loadindicator-segment dx-loadindicator-segment2"></div><div class="dx-loadindicator-segment dx-loadindicator-segment1"></div><div class="dx-loadindicator-segment dx-loadindicator-segment0"></div></div></div></div></div></div><div class="dx-scrollview-scrollbottom-text">Loading...</div></div></div></div><div class="dx-scrollable-scrollbar dx-widget dx-scrollbar-vertical dx-scrollbar-hoverable"><div class="dx-scrollable-scroll dx-state-invisible" style="height: 15px; transform: translate(0px, 0px);"><div class="dx-scrollable-scroll-content"></div></div></div></div></div><div class="dx-scrollview-loadpanel dx-overlay dx-widget dx-state-invisible dx-visibility-change-handler dx-loadpanel"><div class="dx-overlay-content" aria-hidden="true" style="width: 222px; height: 90px;"></div></div></div><div class="popover_btn_space"><button id="param_DEMO_01_D_공공_일자기준분기명_btn_ok" type="button" class="ui-button-ok" role="button"><span class="ui-button-text">확인</span></button><button id="param_DEMO_01_D_공공_일자기준분기명_btn_cancel" type="button" class="ui-button-cancel" role="button"><span class="ui-button-text">취소</span></button></div></div></div></div><div id="기준분기명_tooltip" class="dx-overlay dx-popup dx-popover dx-widget dx-state-invisible dx-visibility-change-handler dx-tooltip"><div class="dx-overlay-content dx-popup-normal" aria-hidden="true" id="dx-58db3b9d-281f-3535-6317-eac7438b2258" role="tooltip" style="width: auto; height: auto;"><div class="dx-popover-arrow"></div><div class="dx-popup-content"></div></div></div></div></div></div></div>' +
								
								//타이틀
							
								'<div class="panel-inner" style="height: 60px;">' +
									'<div class="cont-box" style="height:100%;">' +
										'<div class="cont-box-body">' +
											'<div id="canvas-container" class="goldenLayout-custom-div" style="height: 450px; width:100%;">' +
												'<div class="lm_goldenlayout lm_item lm_root" style=" height: 450px;">' +	
													'<div lm_item lm_column style="width:height:450px;">' +
														'<div lm_item lm_row style="height:450px;">' +
															'<div class="lm_item lm_stack cont_box active tabactive" id="layout_chartDashboardItem1" style="height:450px";>' +
																'<div class="lm_header" id="layout_lm_header" style="height:21px; display:flex; align-items:center;">' +
																	'<ul class="lm_tabs" id="layout_lm_tabs" style=" display:flex; align-items:center">' +
																		'<li class="lm_tab cont_box_top_tit lm_active" title="타이틀 제목" id="layout_chartDashboardItem1_item_title" style="height:27px; display:flex; padding-left:10px;">' +
																			'<i class="lm_left" style="width:2px; height:19px;">' +
																			'</i>' +
																			'<span class="lm_title">' +
																			'타이틀 제목' +
																			'</span>' +
																			'<div class="lm_close_tab" id="layout_lm_close_tab" style="margin-left:14px; margin-top:5px;">' +
																			'</div>' +
																			'<i class="lm_right">' +
																			'</i>' +
																		'</li>' +			
																	'</ul>' +	
																	'<ul class="lm_controls cont_box_top_icon" id="layout_chartDashboardItem1_item_topicon" style="margin-left:530px;">' +
																		'<ul class="lm_text" title="부 제목 영역" id="layout_chartDashboardItem1_item_text" style="font-size:33px; color:#646464;">' +
																			'부 제목' +														
																		'</ul>' + 
																		'<li class="lm_tabdropdown" title="additional tabs" style="display:none;">' +
																		'</li>' +
																	'</ul>' +
																	'<ul class="lm_tabdropdown_list" style="display: none;">' +
																	'</ul>' +
																'</div>' +	
																
																'<div class="lm_items" style="width:; height:;">' +
																	'<div class="lm_item_container" style="width:; height:;">' +
																		'<div class="lm_content" style="width:; height:;">' +
																			
																			'<div class="dashboard-item" id="chart-view">' +
																			'</div>' +
																			
																			
																			'<div class="dashboard-item" id="grid-view" style="display:none">' +
																			'</div>' +
																			
																			
																			'<div class="dashboard-item" id="pibot-view" style="display:none; height:343px;">' +
																			'</div>' +
																			
																			/*'<div style="display:flex; justify-content:center; margin-top:30px">' +
																				'<div id="preview-btn" style="margin-right:20px">' +
																				
																				'</div>' +
																			
																				'<div id="confirm-btn" style="margin-right:20px">' +
																					
																				'</div>' +
																				
																				'<div id="cancel-btn">' +
																					
																				'</div>' +
																			'</div>' +*/
																			
																		'</div>' +
																	'</div>' +
																'</div>' +
																
																
															'</div>' +
														'</div>' +
													'</div>' +
												'</div>' +
											'</div>' +
										'</div>' +
									'</div>' +					
								'</div>' +
							'</div>' +
							
							
								'<div>' +
								
									'<div style="display:flex; justify-content:center; margin-top:30px">' +
									
										'<div id="confirm-btn" style="margin-right:20px">' +
											
										'</div>' +
										
										'<div id="cancel-btn"  style="margin-right:20px">' +
											
										'</div>' +
										
									'</div>' +
								
								
								'</div>' +
							'</div>' +
						'</div>' +
						
						
						
						
					'</div>';
						
						
						
						contentElement.append(html);
						
					
							
						var none = function(se){
							$(se).css("display", "none");
						}
						var block = function(se){
							$(se).css("display", "block");
						}
						
						$(".add-item-head").click(function(e){
							if($(e.target).hasClass("on")){
								$(e.target).removeClass("on");
								$(e.target).addClass("off");
							}else{
								$(e.target).removeClass("off");
								$(e.target).addClass("on");
							}
						});
						
						var clickFocus = function(e){
							$('#left-col').dxScrollView('instance').scrollTo(0);
							$('#right-col').dxScrollView('instance').scrollTo(0);
							$.each(e.target.parentElement.parentElement.children, function(i, v){

								if(e.target.parentElement.id!=v.id){
                                    $(v).removeClass('click-focus');
                                    if(v.id!="itemOptions")	$(v).attr("style","");
                                    if(v.id=="titleOptions") $(v.firstChild).css("background-image", "url('')");
                                    
								}else{
									$(v).addClass("click-focus");
								}
							});
							
							$(".click-focus").css({
								'background-image': '-webkit-gradient(linear, left top, left bottom, from(#6a6f7f), to(#979aa3))',
								'background-image': '-webkit-linear-gradient(top, #6a6f7f, #979aa3)',
								'background-image': '-o-linear-gradient(top, #6a6f7f, #979aa3)',
								'background-image': 'linear-gradient(to bottom, #6a6f7f, #979aa3)',
								'color': '#fff'
							});
						}
						/*dogfoot 여백제거 기능 추가 shlim 20201020*/
						$("#margin-check").dxCheckBox({
					        value: false,
					        onValueChanged: function(data) {
					        	
					        }
					    });

						$("#titleOptions").click(function(e){
							block(".tabP1-1");
							none(".tabP1-2");
							none(".tabP1-3");
							none(".tabP1-4");
							none(".tabP1-5");
							none(".tabP1-6");
							
							none("#grid-view");
							block("#chart-view");
							none("#pibot-view");
							
							none(".grid-tit");
							block(".chart-tit");
							none(".pibot-tit");
							$('#left-col').dxScrollView({
								width: '100%',
								height: '605px'
							});
							
							flag = 1;
							clickFocus(e);
						});
						
						$("#itemOptions").click(function(e){
							none(".tabP1-1");
							block(".tabP1-2");
							none(".tabP1-3");
							none(".tabP1-4");
							none(".tabP1-5");
							none(".tabP1-6");
							
							none("#grid-view");
							block("#chart-view");
							none("#pibot-view");
							
							none(".grid-tit");
							block(".chart-tit");
							none(".pibot-tit");
							$('#left-col').dxScrollView({
								width: '100%',
								height: '605px'
							});
							
							flag = 2;
							clickFocus(e);
						});
						
						$("#chartOptions").click(function(e){
							none(".tabP1-1");
							none(".tabP1-2");
							block(".tabP1-3");
							none(".tabP1-4");
							none(".tabP1-5");
							none(".tabP1-6");
							
							none("#grid-view");
							block("#chart-view");
							none("#pibot-view");
							
							none(".grid-tit");
							block(".chart-tit");
							none(".pibot-tit");
							
							$('#left-col').dxScrollView({
								width: '100%',
								height: '605px'
							});
							
							flag = 3;
							clickFocus(e);
						});
						
						$("#gridOptions").click(function(e){
							none(".tabP1-1");
							none(".tabP1-2");
							none(".tabP1-3");
							block(".tabP1-4");
							none(".tabP1-5");
							none(".tabP1-6");
							
							none("#chart-view");
							block("#grid-view");
							none("#pibot-view");
							
							block(".grid-tit");
							none(".chart-tit");
							none(".pibot-tit");
							$('#left-col').dxScrollView({
								width: '100%',
								height: '605px'
							});
							
							flag = 4;
							clickFocus(e);
						});
						
						$("#pibotOptions").click(function(e){
							none(".tabP1-1");
							none(".tabP1-2");
							none(".tabP1-3");
							none(".tabP1-4");
							block(".tabP1-5");
							none(".tabP1-6");
							
							none("#chart-view");
							none("#grid-view");
							block("#pibot-view");
							
							none(".grid-tit");
							none(".chart-tit");
							block(".pibot-tit");
							$('#left-col').dxScrollView({
								width: '100%',
								height: '605px'
							});
	
							flag = 5;
							clickFocus(e);
							$("#pibot-view").dxPivotGrid('instance').repaint();
							var pvDataSource = $("#pibot-view").dxPivotGrid('instance').getDataSource();								
							var dsFields =$("#pibot-view").dxPivotGrid('instance').getDataSource().fields();								

							$.each(dsFields, function(_id, _f) {
								pvDataSource.expandAll(_f.index);
							}); 
						});
						
						$("#filterOptions").click(function(e){
							none(".tabP1-1");
							none(".tabP1-2");
							none(".tabP1-3");
							none(".tabP1-4");
							none(".tabP1-5");
							block(".tabP1-6");
							
							block("#chart-view");
							none("#grid-view");
							none("#pibot-view");
							
							none(".grid-tit");
							block(".chart-tit");
							none(".pibot-tit");
							$('#left-col').dxScrollView({
								width: '100%',
								height: '605px'
							});
							
							flag = 6;
							clickFocus(e);
						});
						
						$("#confirm-btn").dxButton({
							"text" : '확인',
							"onClick" : function(){
								self.layoutConfCheck = true;
								/*dogfoot shlim 확인 클릭시 기존 object 변경 안하고 새로 담도록 변경*/
								var jc={};
								jc.TITLE_HEIGHT_SETTING = $("#title-height-setting").val();	
								jc.TITLE_MAIN_FONT_SETTING = $("#title-main-font-setting").val();
								jc.TITLE_MAIN_FONTSIZE_SETTING = $("#title-main-fontsize-setting").val();
								jc.TITLE_MAIN_COLOR_SETTING = $("#title-main-color-setting").dxColorBox('instance').option('value');
								
								jc.TITLE_SERVE_FONT_SETTING = $("#title-serve-font-setting").val();
								jc.TITLE_SERVE_FONTSIZE_SETTING = $("#title-serve-fontsize-setting").val();
								jc.TITLE_SERVE_COLOR_SETTING = $("#title-serve-color-setting").dxColorBox('instance').option('value');
								
								jc.CHART_X_FONT_SETTING = $("#chart-x-font-setting").val();
								jc.CHART_X_FONTSIZE_SETTING = $("#chart-x-fontsize-setting").val();
								jc.CHART_X_COLOR_SETTING = $("#chart-x-color-setting").dxColorBox('instance').option('value');
								
								jc.CHART_Y_FONT_SETTING = $("#chart-y-font-setting").val();
								jc.CHART_Y_FONTSIZE_SETTING = $("#chart-y-fontsize-setting").val();
								jc.CHART_Y_COLOR_SETTING = $("#chart-y-color-setting").dxColorBox('instance').option('value');
								
								jc.CHART_LEGEND_FONT_SETTING = $("#chart-legend-font-setting").val();
								jc.CHART_LEGEND_FONTSIZE_SETTING = $("#chart-legend-fontsize-setting").val();
								
								jc.GRID_HEADER_FONT_SETTING = $("#grid-header-font-setting").val();
								jc.GRID_HEADER_FONTSIZE_SETTING = $("#grid-header-fontsize-setting").val();
								jc.GRID_HEADER_COLOR_SETTING = $("#grid-header-color-setting").dxColorBox('instance').option('value');
								jc.GRID_HEADER_BGCOLORT_SETTING = $("#grid-header-bgcolort-setting").dxColorBox('instance').option('value');
								jc.GRID_HEADER_BGCOLORB_SETTING = $("#grid-header-bgcolorb-setting").dxColorBox('instance').option('value');
								jc.GRID_HEADER_BOCOLORT_SETTING = $("#grid-header-bocolort-setting").dxColorBox('instance').option('value');
								jc.GRID_HEADER_BOCOLORB_SETTING = $("#grid-header-bocolorb-setting").dxColorBox('instance').option('value');
								jc.GRID_HEADER_HEIGHT_SETTING = $("#grid-header-height-setting").val();
								
								jc.GRID_DATA_FONT_SETTING = $("#grid-data-font-setting").val();
								jc.GRID_DATA_FONTSIZE_SETTING = $("#grid-data-fontsize-setting").val();
								jc.GRID_DATA_COLOR_SETTING = $("#grid-data-color-setting").dxColorBox('instance').option('value');
								jc.GRID_DATA_BGCOLOR_SETTING = $("#grid-data-bgcolor-setting").dxColorBox('instance').option('value');
								jc.GRID_DATA_BOCOLOR_SETTING = $("#grid-data-bocolor-setting").dxColorBox('instance').option('value');
								jc.GRID_DATA_HEIGHT_SETTING = $("#grid-data-height-setting").val();
								
								jc.PIBOT_HEADER_FONT_SETTING = $("#pibot-header-font-setting").val();
								jc.PIBOT_HEADER_FONTSIZE_SETTING = $("#pibot-header-fontsize-setting").val();
								jc.PIBOT_HEADER_COLOR_SETTING = $("#pibot-header-color-setting").dxColorBox('instance').option('value');
								jc.PIBOT_HEADER_BGCOLOR_SETTING = $("#pibot-header-bgcolor-setting").dxColorBox('instance').option('value');
								jc.PIBOT_HEADER_BOCOLOR_SETTING = $("#pibot-header-bocolor-setting").dxColorBox('instance').option('value');
								jc.PIBOT_HEADER_HEIGHT_SETTING = $("#pibot-header-height-setting").val();
																
								jc.PIBOT_LEFTHEADER_FONT_SETTING = $("#pibot-leftheader-font-setting").val();
								jc.PIBOT_LEFTHEADER_FONTSIZE_SETTING = $("#pibot-leftheader-fontsize-setting").val();
								jc.PIBOT_LEFTHEADER_COLOR_SETTING = $("#pibot-leftheader-color-setting").dxColorBox('instance').option('value');
								jc.PIBOT_LEFTHEADER_BGCOLORT_SETTING = $("#pibot-leftheader-bgcolort-setting").dxColorBox('instance').option('value');
								jc.PIBOT_LEFTHEADER_BGCOLORB_SETTING = $("#pibot-leftheader-bgcolorb-setting").dxColorBox('instance').option('value');
								jc.PIBOT_LEFTHEADER_BOCOLOR_SETTING = $("#pibot-leftheader-bocolor-setting").dxColorBox('instance').option('value');
								jc.PIBOT_LEFTHEADER_HEIGHT_SETTING = $("#pibot-leftheader-height-setting").val();
								
								jc.PIBOT_DATA_FONT_SETTING = $("#pibot-data-font-setting").val();
								jc.PIBOT_DATA_FONTSIZE_SETTING = $("#pibot-data-fontsize-setting").val();
								jc.PIBOT_DATA_COLOR_SETTING = $("#pibot-data-color-setting").dxColorBox('instance').option('value');
								jc.PIBOT_DATA_BGCOLOR_SETTING = $("#pibot-data-bgcolor-setting").dxColorBox('instance').option('value');
								jc.PIBOT_DATA_BOCOLOR_SETTING = $("#pibot-data-bocolor-setting").dxColorBox('instance').option('value');
								jc.PIBOT_DATA_HEIGHT_SETTING = $("#pibot-data-height-setting").val();
								
								jc.PIBOT_ST_FONT_SETTING = $("#pibot-st-font-setting").val();
								jc.PIBOT_ST_FONTSIZE_SETTING = $("#pibot-st-fontsize-setting").val();
								jc.PIBOT_ST_COLOR_SETTING = $("#pibot-st-color-setting").dxColorBox('instance').option('value');
								jc.PIBOT_ST_BGCOLORT_SETTING = $("#pibot-st-bgcolort-setting").dxColorBox('instance').option('value');
								jc.PIBOT_ST_BGCOLORB_SETTING = $("#pibot-st-bgcolorb-setting").dxColorBox('instance').option('value');
								jc.PIBOT_ST_BOCOLOR_SETTING = $("#pibot-st-bocolor-setting").dxColorBox('instance').option('value');
								jc.PIBOT_ST_HEIGHT_SETTING = $("#pibot-st-height-setting").val();
								
								jc.PIBOT_TOTAL_FONT_SETTING = $("#pibot-total-font-setting").val();
								jc.PIBOT_TOTAL_FONTSIZE_SETTING = $("#pibot-total-fontsize-setting").val();
								jc.PIBOT_TOTAL_COLOR_SETTING = $("#pibot-total-color-setting").dxColorBox('instance').option('value');
								jc.PIBOT_TOTAL_BGCOLORT_SETTING = $("#pibot-total-bgcolort-setting").dxColorBox('instance').option('value');
								jc.PIBOT_TOTAL_BGCOLORB_SETTING = $("#pibot-total-bgcolorb-setting").dxColorBox('instance').option('value');
								jc.PIBOT_TOTAL_BOCOLOR_SETTING = $("#pibot-total-bocolor-setting").dxColorBox('instance').option('value');
								jc.PIBOT_TOTAL_HEIGHT_SETTING = $("#pibot-total-height-setting").val();
								/*dogfoot 여백제거 기능 추가 shlim 20201020*/
								jc.PIBOT_ALL_MARGIN_SETTING = $("#margin-check").dxCheckBox('instance').option('value');
								
								jc.FILTER_LD_SETTING = $("#filter-ld-setting").val();
								jc.FILTER_RD_SETTING = $("#filter-rd-setting").val();
								jc.FILTER_D_SETTING = $("#filter-d-setting").val();
								jc.FILTER_HEIGHT_SETTING = $("#filter-height-setting").val();
								
								jc.FILTER_LABEL_FONT_SETTING = $("#filter-label-font-setting").val();
								jc.FILTER_LABEL_FONTSIZE_SETTING = $("#filter-label-fontsize-setting").val();
								jc.FILTER_LABEL_COLOR_SETTING = $("#filter-label-color-setting").dxColorBox('instance').option('value');
								
								jc.FILTER_DATA_FONT_SETTING = $("#filter-data-font-setting").val();
								jc.FILTER_DATA_FONTSIZE_SETTING = $("#filter-data-fontsize-setting").val();
								jc.FILTER_DATA_COLOR_SETTING = $("#filter-data-color-setting").dxColorBox('instance').option('value');
								jc.FILTER_DATA_BOCOLOR_SETTING = $("#filter-data-bocolor-setting").dxColorBox('instance').option('value');
								
								
								gDashboard.layoutConfig = jc;
								
								reportLayoutPopup.hide();
								if(pageset === 'reportset'){
									preViewInitTitle();
									preViewInitChartConfirm();
									btnType="conf";
									preViewInitGrid();
									preViewInitPibot();
									preViewInitFilter(true);
															
									if(gDashboard.goldenLayoutManager.canvasLayout){
						                $('.panel.cont').css('height', 'calc(100vh - ' + (123 - 39 + $('.filter-bar').height()) + 'px)')
						                gDashboard.goldenLayoutManager.canvasLayout.updateSize($('.panel.cont').width());
						                
						                setTimeout(function(){
						                    $.each($('.lm_item'), function(i, ele){
						                        var h = $(ele).height() - $(ele).find('.lm_header').height();

						                    	$(ele).find('.lm_items').height(h);
						        		         $(ele).find('.lm_item_container').height(h);
						        		         $(ele).find('.lm_content').height(h);
						                    })
						                    gDashboard.goldenLayoutManager.resize();
						                }, 300)
						            }
								}
							}
						})
						
						$("#cancel-btn").dxButton({
							"text" : "취소",
							"onClick" : function(){
								
								initInputValTitle(self.lc); preViewInitTitle();
								
								initInputValChart(self.lc); preViewInitChart();
								
								initInputValGrid(self.lc); preViewInitGrid();
								
								initInputValPibot(self.lc); preViewInitPibot();
							
								initInputValFilter(self.lc); preViewInitFilter(true);
																	
								reportLayoutPopup.hide();
							}
						})
						
						$("#back-btn").dxButton({
							"text" : '되돌리기',
							"onClick" : function(){
								if(flag==1) {initInputValTitle(self.lc); preViewInitTitle();}
								//if(flag==2) {initInputValItem(); preViewInitItem();}
								if(flag==3) {initInputValChart(self.lc); preViewInitChart();}
								if(flag==4) {initInputValGrid(self.lc); preViewInitGrid();}
								if(flag==5) {initInputValPibot(self.lc); preViewInitPibot();}
								if(flag==6) {initInputValFilter(self.lc); preViewInitFilter(false);}
								$("#pibot-view").dxPivotGrid('instance').repaint();
								//
								//reportLayoutPopup.show();
							}
						})
						
						$(".defaultValue-btn").dxButton({
							"text" : '기본값 초기화',
							"onClick" : function(){
							//if(flag==1) {
								initInputValTitle(defaultValueSetting); preViewInitTitle();
								//}
							//if(flag==2) {initInputValItem(); preViewInitItem();}
							//if(flag==3) {
								initInputValChart(defaultValueSetting); preViewInitChart();
								//}
							//if(flag==4) {
								initInputValGrid(defaultValueSetting); preViewInitGrid();
								//}
							//if(flag==5) {
								initInputValPibot(defaultValueSetting); preViewInitPibot();
								//}
							//if(flag==6) {
								initInputValFilter(defaultValueSetting); preViewInitFilter(false);
								//}
								$("#pibot-view").dxPivotGrid('instance').repaint();
//								WISE.alert('설정값이 초기화 되었습니다.');
								WISE.alert('설정값 초기화 완료.');
							}
						});
						
						$("#preview-btn").dxButton({
							"text" : '미리보기',
							"onClick" : function(){
								
								
								preViewInitTitle();
																
								preViewInitChart();
								
								preViewInitChart();
																							
								preViewInitGrid();
								
								preViewInitPibot();
															
								preViewInitFilter(false);
								
								previewFlag = true;
								$("#pibot-view").dxPivotGrid('instance').repaint();
							}
						});
						return contentElement;
					}
		}).dxPopup('instance');
	};
		
}