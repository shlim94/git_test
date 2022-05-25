var WISE = {
	Context: {
		isCubeReport: undefined,
		/* DOGFOOT ktkang 주제영역 연결되어있는 차원 및 측정값만 보이는 기능   20200212 */
		isCubeRelation: false
	},
	Console: function() {
		this.loggable = true;
		this.logger = window.console || {log:function(){},info:function(){},error:function(){},warn:function(){},dir:function(){},clear:function(){}};
		this.log = function(_msg) {
			if(this.loggable) this.logger.log(_msg);
		};
		this.info = function(_msg) {
			if(this.loggable) this.logger.info(_msg);
		};
		this.error = function(_msg) {
			if(this.loggable) this.logger.error(_msg);
		};
		this.warn = function(_msg) {
			if(this.loggable) this.logger.warn(_msg);
		};
		this.dir = function(_obj) {
			if(this.loggable) this.logger.dir(_obj);
		};
		this.clear = function() {
			if(this.loggable) this.logger.clear();
		};
	},
	//2020.01.22 KERIS MKSONG 경고창 옵션 설정 기능 추가 DOGFOOT
	alert: function (_content, _state, _options){
		Alert(_content, _state, _options);
		$('#apprise-btn-confirm').focus();
	},
	// 2020.01.16 mksong confirm 기능 추가 dogfoot
	confirm: function (_content, _option){
		var confirm = Confirm(_content, _option);
		$('#apprise-btn-confirm').focus();
		return confirm;
	},
	namespace: function(_ns) {
		var exist = function(_pkg) {
			try {
				_pkg = _pkg.substring(0, _pkg.length - 1);
				var e = eval('(' + _pkg + ')');
				if (!e) {
					eval(_pkg + ' = {};');
				}
			} catch (e) {
				alert(e.message);
			}
		};
		var p = '', nspl = _ns.split('.');
		for (var x0 = 0; x0 < nspl.length; x0++) {
			p += nspl[x0] + '.';
			exist(p);
		}
	},
	//2020.11.03 mksong resource Import 동적 구현 dogfoot
	loadingSource: function(_sourceUrl, _sourceType){
		var resourceTag;
		switch(_sourceType){
			case 'js':
				//2020.11.04 mksong 로컬에서는  context 변경 dogfoot
				resourceTag = '<script async type="text/javascript" src="'+ WISE.Constants.context + "/" + _sourceUrl +'" charset="utf-8"></script>';
				$('head').append(resourceTag);
				eval($('head').find("script").text());				
				break;
			case 'css':
				//2020.11.04 mksong 로컬에서는  context 변경 dogfoot
				resourceTag = '<link async rel="stylesheet" type="text/css" href="' + WISE.Constants.context + "/" + _sourceUrl +'"/>';
				$('head').append(resourceTag);
				eval($('head').find('link'));
				break;
			case 'library':
				resourceTag = _sourceUrl;
				$('head').append(resourceTag);
				eval($('head').find("script").text());
				break;
		}
	},
	//2020.11.03 mksong resource Import 동적 구현 dogfoot
	loadedSourceCheck: function(type, itemName){
		//2020.11.12 mksong 탭컨테이너 오류 수정 dogfoot
		if(itemName != 'TabContainer'){
			switch(type){
				case 'itemJS':
					if (!this.itemSourceCheck(itemName)){
						if(itemName.indexOf('Map') != -1 && WISE.libs.Dashboard.item.MapGenerator == undefined){
							if(WISE.Constants.minFile){
								this.loadingSource('js.min/item/detail/WISE.widget.Map.min.js','js');	
							}else{
								this.loadingSource('js/item/detail/WISE.widget.Map.js','js');
							}
						}
						
						if(itemName == 'Map.KakaoMap' && typeof kakao == 'undefined'){
//							this.loadingSource('<script type="text/javascript" src="//dapi.kakao.com/v2/maps/sdk.js?appkey=' + WISE.Constants.kakaoApi + '&libraries=services,clusterer,drawing"></script>','library');
						}
						
						//2020.11.04 mksong 차트에서 버블차트 사용하는 부분 위해 버블 차트 import 추가 dogfoot
						if(itemName == 'Chart'){
							if(WISE.Constants.minFile){
								this.loadingSource('js.min/item/detail/WISE.widget.BubbleChart.min.js','js');	
							}else{
								this.loadingSource('js/item/detail/WISE.widget.BubbleChart.js','js');
							}
						}
						
						if(itemName == 'Card'){
							if(WISE.Constants.minFile){
								this.loadingSource('js.min/item/detail/WISE.widget.Card.$.plugin.min.js','js');	
							}else{
								this.loadingSource('js/item/detail/WISE.widget.Card.$.plugin.js','js');
							}
						}
						
						if(WISE.Constants.minFile){
							this.loadingSource('js.min/item/detail/WISE.widget.' + itemName + '.min.js','js');	
						}else{
							this.loadingSource('js/item/detail/WISE.widget.' + itemName + '.js','js');
						}
					}
					break;
				case 'd3':
					//2020.11.10 mksong 동적로딩 d4 오류 수정 dogfoot
					if (typeof d3 == 'undefined' || typeof d4 == 'undefined' || d3 == null || d4 == null){
						this.loadingSource('resources/visual/paletteValArea.js','js');
						this.loadingSource('resources/visual/circos.min.js','js');
						
						this.loadingSource('resources/visual/d3.calender.js','js');
						d3vCal = d3;
						window.d3 = null;
						
						this.loadingSource('resources/visual/d3.v3.js','js');
						d3v3 = d3;
	 		  			window.d3 = null;
						
						this.loadingSource('resources/visual/d3.v5.min.js','js');
						d3min = d3;
	 		  			window.d3 = null;
			
						this.loadingSource('resources/visual/d3.js','js');
						this.loadingSource('resources/visual/d3.v3.min.js','js');
						this.loadingSource('resources/visual/d3.v4.js','js');
						this.loadingSource('resources/visual/d3.v4.min.js','js');
						
						this.loadingSource('resources/visual/d3.scale.chromatic.js','js');
						this.loadingSource('resources/visual/d3.layout.cloud.js','js');
						this.loadingSource('resources/visual/viz.v1.3.0.min.js','js');
						this.loadingSource('resources/visual/d3-legend.min.js','js');
						
						this.loadingSource('resources/visual/sankey/d3-collection.v1.min.js','js');
						this.loadingSource('resources/visual/sankey/d3-array.v2.min.js','js');
						this.loadingSource('resources/visual/sankey/d3-path.v1.min.js','js');
						this.loadingSource('resources/visual/sankey/d3-shape.v1.min.js','js');
						this.loadingSource('resources/visual/sankey/d3-sankey.js','js');
						this.loadingSource('resources/visual/sankey/sk.d3.js','js');
						
						this.loadingSource('resources/visual/saveSvgAsPng.js','js');
						
						this.loadingSource('resources/visual/viz.v1.js','js');
						this.loadingSource('resources/visual/d3-legend.min.js','js');
						
						this.loadingSource('resources/visual/sankey/sk.d3.css','css');
						 		  
					}
					break;
				case 'html2canvas':
					if(typeof html2canvas == 'undefined'){
						this.loadingSource('resources/html2canvas/html2canvas.js','js');
						this.loadingSource('resources/html2canvas/html2canvas.svg.js','js');
						this.loadingSource('resources/html2canvas/html2canvas.1.0.0.rc5.js','js');
					}
					break;
			}		
		}
	},
	itemSourceCheck: function(itemName){
		var itemSourceLoadCheck = false;
		var itemObject = WISE.libs.Dashboard.item;
		switch(itemName){
			case 'AdhocItem':
				itemSourceLoadCheck = itemObject['ChangeReportTypeManager'] != undefined ? true : false;
				break; 
			case 'ArcDiagram':
				itemSourceLoadCheck = itemObject['ArcDiagramGenerator'] != undefined ? true : false;
				break; 
			case 'BoxPlot': 
				itemSourceLoadCheck = itemObject['BoxPlotGenerator'] != undefined ? true : false;
				break;
			case 'CoordinateLine': 
				itemSourceLoadCheck = itemObject['CoordinateLineGenerator'] != undefined ? true : false;
				break;
			case 'BipartiteChart':
				itemSourceLoadCheck = itemObject['BipartiteChartGenerator'] != undefined ? true : false;
				break; 
			case 'BubbleChart':
				itemSourceLoadCheck = itemObject['BubbleChartGenerator'] != undefined ? true : false;
				break; 
			case 'BubbleD3':
				itemSourceLoadCheck = itemObject['BubbleD3Generator'] != undefined ? true : false;
				break;
			case 'BubblePackChart':
				itemSourceLoadCheck = itemObject['BubblePackChartGenerator'] != undefined ? true : false;
				break;
			case 'CalendarView':
				itemSourceLoadCheck = itemObject['CalendarViewChartGenerator'] != undefined ? true : false;
				break;
			case 'CalendarView2chart':
				itemSourceLoadCheck = itemObject['CalendarView2ChartGenerator'] != undefined ? true : false;
				break; 
			case 'CalendarView3chart':
				itemSourceLoadCheck = itemObject['CalendarView3ChartGenerator'] != undefined ? true : false;
				break; 
			case 'Card':
				itemSourceLoadCheck = itemObject['CardGenerator'] != undefined ? true : false;
				break;
			case 'Chart':
				itemSourceLoadCheck = itemObject['ChartGenerator'] != undefined ? true : false;
				break; 
			case 'CollapsibleTree':
				itemSourceLoadCheck = itemObject['CollapsibleTreeChartGenerator'] != undefined ? true : false;
				break;
			case 'ComboBox':
				itemSourceLoadCheck = itemObject['ComboBoxGenerator'] != undefined ? true : false;
				break; 
			case 'DataGrid':
				itemSourceLoadCheck = itemObject['DataGridGenerator'] != undefined ? true : false;
				break;
			case 'DependencyWheel':
				itemSourceLoadCheck = itemObject['DependencyWheelGenerator'] != undefined ? true : false;
				break; 
			case 'DendrogramBarChart':
				itemSourceLoadCheck = itemObject['DendrogramBarChartGenerator'] != undefined ? true : false;
				break; 
			case 'DivergingChart':
				itemSourceLoadCheck = itemObject['DivergingChartGenerator'] != undefined ? true : false;
				break; 
			case 'ForceDirect':
				itemSourceLoadCheck = itemObject['ForceDirectGenerator'] != undefined ? true : false;
				break;
			case 'ForceDirectExpand':
				itemSourceLoadCheck = itemObject['ForceDirectExpandGenerator'] != undefined ? true : false;
				break;
			case 'FunnelChart':
				itemSourceLoadCheck = itemObject['FunnelChartGenerator'] != undefined ? true : false;
				break; 
			case 'Gauge':
				itemSourceLoadCheck = itemObject['GaugeGenerator'] != undefined ? true : false;
				break; 
			case 'HeatMap':
				itemSourceLoadCheck = itemObject['HeatMapGenerator'] != undefined ? true : false;
				break; 
			case 'HeatMap2':
				itemSourceLoadCheck = itemObject['HeatMap2Generator'] != undefined ? true : false;
				break; 
			case 'CoordinateDot':
				itemSourceLoadCheck = itemObject['CoordinateDotGenerator'] != undefined ? true : false;
				break; 
			case 'SynchronizedChart':
				itemSourceLoadCheck = itemObject['SynchronizedChartGenerator'] != undefined ? true : false;
				break; 
			case 'HistogramChart':
				itemSourceLoadCheck = itemObject['HistogramChartGenerator'] != undefined ? true : false;
				break;
			case 'HistoryTimeline': 
				itemSourceLoadCheck = itemObject['HistoryTimelineGenerator'] != undefined ? true : false;
				break; 
			case 'HierarchicalEdge':
				itemSourceLoadCheck = itemObject['HierarchicalEdgeGenerator'] != undefined ? true : false;
				break; 
			case 'Image':
				itemSourceLoadCheck = itemObject['ImageGenerator'] != undefined ? true : false;
				break;
			case 'ListBox':
				itemSourceLoadCheck = itemObject['ListBoxGenerator'] != undefined ? true : false;
				break; 
			case 'LiquidFillGauge':
				itemSourceLoadCheck = itemObject['LiquidFillGaugeGenerator'] != undefined ? true : false;
				break;
			case 'Map.Choropleth':
				itemSourceLoadCheck = itemObject['ChoroplethMapGenerator'] != undefined ? true : false;
				break; 
			case 'Map.GeoPointMap':
				itemSourceLoadCheck = itemObject['GeoPointMapGenerator'] != undefined ? true : false;
				break; 
			case 'Map.KakaoMap':
				itemSourceLoadCheck = itemObject['KakaoMapGenerator'] != undefined ? true : false;
				break; 
			case 'Map.KakaoMap2':
				itemSourceLoadCheck = itemObject['KakaoMap2Generator'] != undefined ? true : false;
				break;
			case 'ParallelCoordinate':
				itemSourceLoadCheck = itemObject['ParallelCoorGenerator'] != undefined ? true : false;
				break; 
			case 'Pie':
				itemSourceLoadCheck = itemObject['PieGenerator'] != undefined ? true : false;
				break;
			case 'PivotGrid':
				itemSourceLoadCheck = itemObject['PivotGridGenerator'] != undefined ? true : false; 
				break;  
			case 'PyramidChart':
				itemSourceLoadCheck = itemObject['PyramidChartGenerator'] != undefined ? true : false;
				break;
			case 'RadialTidyTree': 
				itemSourceLoadCheck = itemObject['RadialTidyTreeGenerator'] != undefined ? true : false;
				break; 
			case 'RangeBar':
				itemSourceLoadCheck = itemObject['RangeBarChartGenerator'] != undefined ? true : false;
				break; 
			case 'RangeAreaChart':
				itemSourceLoadCheck = itemObject['RangeAreaChartGenerator'] != undefined ? true : false;
				break;
			case 'RectangularAreaChart':
				itemSourceLoadCheck = itemObject['RectangularAreaChartGenerator'] != undefined ? true : false;
				break; 
			case 'Sankeychart':
				itemSourceLoadCheck = itemObject['SankeyChartGenerator'] != undefined ? true : false;
				break; 
			case 'ScatterPlot': 
				itemSourceLoadCheck = itemObject['ScatterPlotGenerator'] != undefined ? true : false;
				break; 
			case 'ScatterPlot2': 
				itemSourceLoadCheck = itemObject['ScatterPlot2Generator'] != undefined ? true : false;
				break;
			case 'ScatterPlotMatrix': 
				itemSourceLoadCheck = itemObject['ScatterPlotMatrixGenerator'] != undefined ? true : false;
				break;
			case 'SequencesSunburst':
				itemSourceLoadCheck = itemObject['SequencesSunburstGenerator'] != undefined ? true : false;
				break;
			case 'Starchart':
				itemSourceLoadCheck = itemObject['StarChartGenerator'] != undefined ? true : false;
				break;
			case 'TextBox':
				itemSourceLoadCheck = itemObject['TextBoxGenerator'] != undefined ? true : false;
				break;
			case 'TimeLineChart':
				itemSourceLoadCheck = itemObject['TimeLineChartGenerator'] != undefined ? true : false;
				break;    
			case 'TreeMap':
				itemSourceLoadCheck = itemObject['TreeMapGenerator'] != undefined ? true : false;
				break; 
			case 'TreeView':
				itemSourceLoadCheck = itemObject['TreeViewGenerator'] != undefined ? true : false;
				break; 
			case 'WaterfallChart':
				itemSourceLoadCheck = itemObject['WaterfallChartGenerator'] != undefined ? true : false;
				break; 
			case 'WordCloud':
				itemSourceLoadCheck = itemObject['WordCloud'] != undefined ? true : false;
				break;
			case 'WordCloudv2':
				itemSourceLoadCheck = itemObject['WordCloudV2Generator'] != undefined ? true : false;
				break; 
		}
		
		return itemSourceLoadCheck	
	}
};




/**
 * package name : WISE.util
 * @desc : utility labrary package
 * @author : jylee
 * @since : 2015.06.10
 */
WISE.namespace('WISE.util');

/*
//ajax고유키를 할당시켜 각각 프로그래스바를 만든다
function ajaxEvent(event, jqXHR, ajaxSettings, data_or_error) {
//	console.log("event.type",event.type,"ajaxSettings.url",ajaxSettings.url,"jqXHR.requestId",jqXHR.requestId);
//	console.log("ajaxSettings",ajaxSettings);
//	console.log("data_or_error",data_or_error);
	if(event.type=='ajaxSend') {
		if(ajaxSettings.url.indexOf('cancelquery')==-1) {
			$(document.body).append('<div id="progress_box_'+jqXHR.requestId+'" class="progress_box"><div class="img_progress"></div><div class="queryCancel"></div><div class="progress_back_panel"></div></div>');
			$('#progress_box_'+jqXHR.requestId+' .queryCancel').dxButton({
				text:"작업 취소",
				type:'default',
				onClick:function(_e){
					$('#progress_box_'+jqXHR.requestId).remove();
					$.ajax({
						type : 'post',
						cache : false,
						url : WISE.Constants.context + '/report/cancelqueries.do'
					});
				}
			});
			$('#progress_box_'+jqXHR.requestId+' .queryCancel').addClass('progress-btn-type');
		}
	} else if(event.type=='ajaxSuccess') {
		//ajaxSuccess
	} else if(event.type=='ajaxError') {
		//ajaxError
	} else if(event.type=='ajaxComplete') {
		$('#progress_box_'+jqXHR.requestId).remove();
	}
}

$(document)
	.ajaxSend(ajaxEvent)
	.ajaxSuccess(ajaxEvent)
	.ajaxError(ajaxEvent)
	.ajaxComplete(ajaxEvent);

$.ajaxPrefilter(function(options, originalOptions, jqXHR) {
	jqXHR.requestId = Math.floor((Math.random() * 99999999) + 1);
});

*/

//javascript error 처리
//window.onerror = function(message, source, lineNo, colNo, error) {
//	console.log("message="+message);
//	console.log("source="+source);
//	console.log("lineNo="+lineNo);
//	console.log("colNo="+colNo);
//	console.log("error="+error);
//}

function ajax_error_message(_response) {
	var error_message = '';
	if(_response.responseText != undefined) {
		$.each($(_response.responseText.toString()),function(i,d){
			if($(d).prop('tagName')=='ERROR_MESSAGE') {
				error_message = ' '+$(d).text();
			}
		});
	}
	return error_message;
}

WISE.namespace('WISE.libs');
WISE.namespace('WISE.libs.Dashboard');

$.ajaxPrefilter(function(settings, originalOptions, xhr) {
	if (!(/^http:.*/.test(settings.url) || /^https:.*/.test(settings.url))) {
		if (!csrfSafeMethod(settings.type)) {
			var token = $("meta[name='_csrf']").attr("content");
    		var header = $("meta[name='_csrf_header']").attr("content");
    		xhr.setRequestHeader(header, token);
		}
	}
});

$.ajaxSetup({
	cache: false,
//	beforeSend: function(xhr, settings) {
//		if (!(/^http:.*/.test(settings.url) || /^https:.*/.test(settings.url))) {
//			if (!csrfSafeMethod(settings.type)) {
//				var token = $("meta[name='_csrf']").attr("content");
//	    		var header = $("meta[name='_csrf_header']").attr("content");
//	    		xhr.setRequestHeader(header, token);
//			}
//		}
//	},
//	complete: function() {
//		gProgressbar.hide();
//	},
//	success: function() {
//		gProgressbar.hide();
//	},
	error: function(_response) {
		gProgressbar.hide();
//		switch(_response.status) {
//		case 404:
//			document.location.replace(WISE.Constants.context + '/error/404.do'); break;
//		default:
////			WISE.alert(_response.status + '   >>>>>   ' + _response.responseText);
//			document.location.replace(WISE.Constants.context + '/error/500.do'); break;
//		}
	}
});

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}



$(document).keydown(function(_e) { // backspace 방지
	if (_e.keyCode === 8) { // ymbin : dx-htmleditor 추가
		if ($(_e.target).hasClass('dx-texteditor-input') || $(_e.target).hasClass('wise-text-input') || $(_e.target).hasClass('dx-htmleditor-content')) {
			return true;
		}
		return false;
	}
});

//	KERIS 주석 해제
//$(document).bind('contextmenu', function(e){
//    return false;
//}); 
//	KERIS주석끝

