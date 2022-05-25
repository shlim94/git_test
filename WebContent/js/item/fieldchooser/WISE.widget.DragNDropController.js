/*
	2020.03.02 MKSONG WISE.widget.DragNDropController 리팩토링 DOGFOOT
	- 불필요한 소스 제거
	- 공통 부분 함수화
	- 그룹별 항목 이동 기능 추가
	- self.item undefined 오류 수정
	- 기타
*/
WISE.widget.DragNDropController = function(_item){
	var self = this;

	this.item = _item;
	this.itemData;
	this.itemFormat;
	/*dogfoot 사용자정의 데이터  구분 shlim 20200716*/
	this.customMeasureFieldOptionMenu = ''
		+'<div class="divide-menu other-menu">'
			+'<a href="#" class="other-menu-ico"></a>'
			+'<ul class="more-link right-type">'
				+'<li><a href="#" class="summaryType" summaryType="count">카운트</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="countdistinct">고유 카운트</a></li>'
				+'<li class="on"><a href="#" class="summaryType" summaryType="sum">합계</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="min">최소값</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="max">최대값</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="avg">평균</a></li>'
				+'<li><a href="#formatOptions" class="setFormat">Format...</a></li>'
			+'</ul>'
		+'</div>';
	this.measureFieldOptionMenu = ''
		+'<div class="divide-menu other-menu">'
			+'<a href="#" class="other-menu-ico"></a>'
			+'<ul class="more-link right-type">'
				+'<li><a href="#" class="summaryType" summaryType="count">카운트</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="countdistinct">고유 카운트</a></li>'
				+'<li class="on"><a href="#" class="summaryType" summaryType="sum">합계</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="min">최소값</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="max">최대값</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="avg">평균</a></li>'
//				+'<li class="more">'
//					+'<a href="#">More</a>'
//					+'<ul class="more-link">'
//						+'<li><a href="#" class="summaryType" summaryType="stdev">StdDev</a></li>'
//						+'<li><a href="#" class="summaryType" summaryType="stdevp">StdDevP</a></li>'
//						+'<li><a href="#" class="summaryType" summaryType="var">Var</a></li>'
//						+'<li><a href="#" class="summaryType" summaryType="varp">VarP</a></li>'
//						+'<li><a href="#" class="summaryType" summaryType="median">Median</a></li>'
//						+'<li><a href="#" class="summaryType" summaryType="mode">Mode</a></li>'
//					+'</ul>'
//				+'</li>';
				+'<li><a href="#formatOptions" class="setFormat">Format...</a></li>'
				+'<li><a href="#" class="fieldRename">Rename...</a></li>'
			+'</ul>'
		+'</div>';
	/* DOGFOOT ktkang 정렬기준항목은 무조건 최소값으로 정하고 숨김  20200702 */
//	this.hiddenMeasureFieldOptionMenu = ''
//		+'<div class="divide-menu other-menu">'
//			+'<a href="#" class="other-menu-ico"></a>'
//			+'<ul class="more-link right-bottom-type meaFieldOption">'
//				+'<li><a href="#" class="summaryType" summaryType="count">카운트</a></li>'
//				+'<li><a href="#" class="summaryType" summaryType="countdistinct">고유 카운트</a></li>'
//				/* DOGFOOT ktkang 숨겨진 데이터 항목을 기본으로 최소값 설정  20200318 */
//				+'<li><a href="#" class="summaryType" summaryType="sum">합계</a></li>'
//				+'<li class="on"><a href="#" class="summaryType" summaryType="min">최소값</a></li>'
//				+'<li><a href="#" class="summaryType" summaryType="max">최대값</a></li>'
//				+'<li><a href="#" class="summaryType" summaryType="avg">평균</a></li>'
////				+'<li class="more">'
////					+'<a href="#">More</a>'
////					+'<ul class="more-link">'
////						+'<li><a href="#" class="summaryType" summaryType="stddev">StdDev</a></li>'
////						+'<li><a href="#" class="summaryType" summaryType="stddevp">StdDevP</a></li>'
////						+'<li><a href="#" class="summaryType" summaryType="var">Var</a></li>'
////						+'<li><a href="#" class="summaryType" summaryType="varp">VarP</a></li>'
////						+'<li><a href="#" class="summaryType" summaryType="median">Median</a></li>'
////						+'<li><a href="#" class="summaryType" summaryType="mode">Mode</a></li>'
////					+'</ul>'
////				+'</li>';
//				+'<li><a href="#formatOptions" class="setFormat">Format...</a></li>'
//				+'<li><a href="#" class="fieldRename">Rename...</a></li>'
//			+'</ul>'
//		+'</div>';

	this.hiddenMeasureFieldOptionMenu = ''
		+'<div class="divide-menu other-menu" style="display:none;">'
			+'<a href="#" class="other-menu-ico"></a>'
			+'<ul class="more-link right-bottom-type meaFieldOption">'
				+'<li><a href="#" class="summaryType" summaryType="sum">합계</a></li>'
				+'<li class="on"><a href="#" class="summaryType" summaryType="min">최소값</a></li>'
			+'</ul>'
		+'</div>';

	this.dimensionFieldOptionMenuNoTopN = ''
		+'<div class="divide-menu other-menu">'
			+'<a href="#" class="other-menu-ico dimensionFieldMenu"></a>'
			+'<ul class="more-link right-type dimFieldOption">'
				//+'<li class="on"><a href="#">Sort Ascending</a></li>'
				//+'<li><a href="#">Sort Descending</a></li>'
				+'<li class="more">'
				+'<a href="#">Sort By</a>'
				/*dogfoot shlim 20210415*/
				+'<ul class="more-link measureList" style="height:250px;overflow-y:scroll;">'
					+'<li class="on"><a href="#">Value</a></li>'
				+'</ul>'
				+'</li>'
				//2020-01-14 LSH topN 기능 활성화
//				+'<li><a href="#" class="topNset">Top N</a></li>'
//				+'<li class="disabled"><a href="#">최소값</a></li>'
//				+'<li><a href="#">그룹화 없음</a></li>'
//				+'<li><a href="#">Alphabetical</a></li>'
				+'<li><a href="#" class="fieldRename">Rename...</a></li>'
			+'</ul>'
		+'</div>';

	this.dimensionFieldOptionMenu = ''
		+'<div class="divide-menu other-menu">'
			+'<a href="#" class="other-menu-ico dimensionFieldMenu"></a>'
			+'<ul class="more-link right-type dimFieldOption">'
				//+'<li class="on"><a href="#">Sort Ascending</a></li>'
				//+'<li><a href="#">Sort Descending</a></li>'
				+'<li class="more">'
				+'<a href="#">Sort By</a>'
				/*dogfoot shlim 20210415*/
				+'<ul class="more-link measureList" style="height:250px;overflow-y:scroll;">'
					+'<li class="on"><a href="#">Value</a></li>'
				+'</ul>'
				+'</li>'
				//2020-01-14 LSH topN 기능 활성화
				+'<li><a href="#" class="topNset">Top N</a></li>'
//				+'<li class="disabled"><a href="#">최소값</a></li>'
//				+'<li><a href="#">그룹화 없음</a></li>'
//				+'<li><a href="#">Alphabetical</a></li>'
				+'<li><a href="#" class="fieldRename">Rename...</a></li>'
			+'</ul>'
		+'</div>';

	this.dimensionFieldOptionMenuNoSort = ''
		+'<div class="divide-menu other-menu">'
			+'<a href="#" class="other-menu-ico dimensionFieldMenu"></a>'
			+'<ul class="more-link right-type dimFieldOption">'
				//+'<li class="on"><a href="#">Sort Ascending</a></li>'
				//+'<li><a href="#">Sort Descending</a></li>'
				//2020-01-14 LSH topN 기능 활성화
				+'<li><a href="#" class="topNset">Top N</a></li>'
//				+'<li class="disabled"><a href="#">최소값</a></li>'
//				+'<li><a href="#">그룹화 없음</a></li>'
//				+'<li><a href="#">Alphabetical</a></li>'
				+'<li><a href="#" class="fieldRename">Rename...</a></li>'
			+'</ul>'
		+'</div>';

	this.dimensionFieldOptionMenuNoTopNNoSort = ''
		+'<div class="divide-menu other-menu">'
			+'<a href="#" class="other-menu-ico dimensionFieldMenu"></a>'
			+'<ul class="more-link right-type dimFieldOption">'
				+'<li><a href="#" class="fieldRename">Rename...</a></li>'
			+'</ul>'
		+'</div>';

	this.addressFieldOptionMenu = ''
		+'<div class="divide-menu other-menu">'
			+'<a href="#" class="other-menu-ico dimensionFieldMenu"></a>'
			+'<ul class="more-link right-type dimFieldOption">'
			// 2020.10.23 syjin 주소 타입 지정 주석 처리 dogfoot
//				+'<li class="more">'
//				+'<a href="#">주소타입 지정</a>'
//				+'<ul class="more-link addressTypeList">'
//					+'<li addressType="Sido" class="on"><a href="#">시도</a></li>'
//					+'<li addressType="SiGunGu" ><a href="#">시도+시군구</a></li>'
//					+'<li addressType="EupMyeonDong"><a href="#">시도+시군구+읍면동</a></li>'
//					+'<li addressType="Detail"><a href="#">상세주소</a></li>'
//				+'</ul>'
//				+'</li>'
				+'<li><a href="#" class="fieldRename">Rename...</a></li>'
			+'</ul>'
		+'</div>';

	// 2020.06.03 ajkim 일부 아이템 TopN 기능 임시 제거 dogfoot
	this.setDimensionFieldOptionMenu = function(dataItem){
		if(!self.item){
			if(gDashboard.itemGenerateManager.dxItemBasten[0].isAdhocItem=== true){
				dataItem.append(self.dimensionFieldOptionMenuNoTopN);
				return;
			}
		}else{
			if(self.item.isAdhocItem === true){
				dataItem.append(self.dimensionFieldOptionMenuNoTopN);
				return;
			}
		}
		
		var prevContainer = dataItem.parent().attr("id");

		var noSort = false;

		if(prevContainer.indexOf("historyTimeline") > -1 || prevContainer.indexOf("plot") > -1 || prevContainer.indexOf("Plot") > -1
				|| prevContainer.indexOf("arc") > -1 || prevContainer.indexOf("bubbled3") > -1 || prevContainer.indexOf("wordcloud") > -1
				|| prevContainer.indexOf("Rectangular") > -1 || prevContainer.indexOf("plot") > -1 || prevContainer.indexOf("waterfall") > -1
				|| prevContainer.indexOf("bipart") > -1 || prevContainer.indexOf("dependency") > -1
				|| prevContainer.indexOf("hierarchical") > -1 || prevContainer.indexOf("forceDirect") > -1 || prevContainer.indexOf("calendarview") > -1
				|| prevContainer.indexOf("calendarview") > -1 || prevContainer.indexOf("sunburst") > -1 || prevContainer.indexOf("dendrogram") > -1
				|| prevContainer.indexOf("collapsibletreechart") > -1 || prevContainer.indexOf("radialTidyTree") > -1 || prevContainer.indexOf("parallel") > -1
				|| prevContainer.indexOf("bubblepackchart") > -1 || prevContainer.indexOf("sankey") > -1 || prevContainer.indexOf("coordinate") > -1){
			noSort = true;
		}

		switch(self.item.type){
			case 'SIMPLE_CHART':
			case 'PIE_CHART':
			case 'PIVOT_GRID':
			case 'DATA_GRID':
				if(noSort){
					dataItem.append(self.dimensionFieldOptionMenuNoSort);
				}else{
					dataItem.append(self.dimensionFieldOptionMenu);
				}
				break;
			default:
				if(noSort){
					dataItem.append(self.dimensionFieldOptionMenuNoTopNNoSort);
				}else{
					dataItem.append(self.dimensionFieldOptionMenuNoTopN);
				}
				break;
		}
		//20201112 AJKIM 통계 분석일 경우 필드 메뉴 제거 dogfoot
		/* 20210201 AJKIM 데이터집합 뷰어 추가 dogfoot */
		if(gDashboard.reportType === 'StaticAnalysis' || gDashboard.reportType == 'DSViewer'){
			dataItem.find('.divide-menu').remove();
		}
	}

	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
	this.dataItemContainerTypeCheck = function(dataItem, containerType) {
		var check = false;
		/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
		if(dataItem.attr('data-field-type') === 'dimension' &&  (containerType === 'rowList' || containerType === 'colList' || containerType === 'chartParameterList' || containerType === 'rowAdHocList' || containerType === 'colAdHocList' ||
				containerType === 'chartSeriesList' || containerType === 'pieParameterList' || containerType === 'pieSeriesList' || containerType === 'pie_hide_dimension_list' || containerType === 'pie_hide_measure_list' ||
				containerType === 'columnList' || containerType === 'sparkline' || containerType === 'mapParameterList' || containerType === 'pivot_hide_measure_list' || containerType === 'bubbleChartXList' ||  containerType === 'bubbleChartYList' ||
				containerType === 'starchartParameterList' || containerType === 'starchartSeriesList' || containerType === 'grid_hide_measure_list' || containerType === 'chart_hide_dimension_list' || containerType === 'chart_hide_measure_list' || containerType === 'grid_hide_measure_list' ||
				containerType === 'RectangularAreaChartParameterList' || containerType === 'treemapParameterList' || containerType === 'waterfallchartParameterList' || containerType === 'bipartitechartParameterList' || containerType === 'funnelchartParameterList' || containerType === 'pyramidchartParameterList' || containerType === 'sankeychartParameterList' || containerType === 'divergingchartParameterList' ||
				containerType === 'bubbled3ParameterList' || containerType === 'heatmapParameterList' || containerType === 'heatmap2ParameterList' || containerType === 'wordcloudParameterList' || containerType === 'parallelParameterList' || containerType === 'card_hide_measure_list' || containerType === 'cardSeriesList' || containerType === 'rangebarchartParameterList' || containerType === 'rangeareachartParameterList' || containerType === 'kakaoMapParameterList'  || containerType === 'kakaomap2ParameterList' || containerType === 'kakaoMapLatitudeList' || containerType === 'kakaoMapLongitudeList' || containerType === 'kakaoMapAddressList' || containerType === 'kakaomapFieldList' ||
				containerType === 'timelinechartSeriesList' || containerType === 'timelinechartParameterList' || containerType === 'timelinechartStartDateList' ||  containerType === 'timelinechartEndDateList' ||
				containerType === 'histogramchartParameterList' || container === 'cardSeriesList' || container === 'cardSparkline' || container === 'gaugeSeriesList' || containerType === 'sparkline' || containerType === 'forceDirectParameterList' || containerType === 'divergingchartSeries' ||
				containerType === 'forceDirectExpandParameterList' || containerType === 'hierarchicalParameterList' ||
				containerType === 'bubblepackchartParameterList'|| containerType === 'wordcloudv2ParameterList'||  containerType === 'divergingchartSeriesList' || containerType === 'divergingchart_hide_measure_list' || containerType === 'scatterplotXList' ||containerType === 'scatterplotYList' || containerType === 'scatterplotZList' ||containerType === 'scatterplot_hide_measure_list' ||
				containerType === 'dendrogrambarchartParameterList'|| containerType === 'calendarviewchartParameterList' || containerType === 'scatterplot2XList' ||containerType === 'scatterplot2YList' ||containerType === 'scatterplot2ZList' ||containerType === 'scatterplot2_hide_measure_list' ||
				containerType === 'dependencywheelParameterList' || containerType === 'sequencessunburstParameterList' || containerType === 'boxplotParameterList'|| containerType === 'coordinatelineParameterList' || containerType === 'coordinatedotParameterList'|| containerType === 'scatterplotParameterList' || containerType === 'scatterplot2ParameterList' || containerType === 'liquidfillgaugeParameterList'|| containerType === 'boxplotValueList'||
				containerType === 'calendarview2chartParameterList' || containerType === 'calendarview3chartParameterList' || containerType === 'collapsibletreechartParameterList' || containerType === 'radialTidyTreeParameterList'|| containerType === 'scatterPlotMatrixX1List'|| containerType === 'scatterPlotMatrixX2List'||
				containerType === 'scatterPlotMatrixY1List'|| containerType === 'scatterPlotMatrixY2List'|| containerType === 'scatterPlotMatrixParameterList'|| containerType === 'historyTimelineParameterList'|| containerType === 'historyTimelineEndList'|| containerType === 'historyTimelineStartList' || containerType === 'arcdiagramParameterList' ||
				/* DOGFOOT ktkang 다변량분석 추가  20210215 */
				containerType === 'onewayAnovaObservedList' || containerType === 'onewayAnovaFactorList'|| containerType === 'rFieldList'||
				containerType === 'twowayAnovaObservedList' || containerType === 'twowayAnovaFactorList'||
				containerType === 'onewayAnova2ObservedList' || containerType === 'onewayAnova2FactorList' || containerType === 'onewayAnova2ItemList' ||
				containerType === 'pearsonsCorrelationNumericalList' || containerType === 'spearmansCorrelationNumericalList' ||
				containerType === 'simpleRegressionIndpnList' || containerType === 'simpleRegressionDpndnList' || containerType === 'simpleRegressionVectorList' ||
				containerType === 'multipleRegressionIndpnList' || containerType === 'multipleRegressionDpndnList' || containerType === 'multipleRegressionVectorList' ||
				containerType === 'logisticRegressionIndpnList' || containerType === 'logisticRegressionDpndnList' || containerType === 'logisticRegressionVectorList' ||
				containerType === 'multipleLogisticRegressionIndpnList' || containerType === 'multipleLogisticRegressionDpndnList' || containerType === 'multipleLogisticRegressionVectorList' ||
				containerType === 'heatmap_hide_measure_list' || containerType === 'heatmap2_hide_measure_list' || containerType === 'syncchart_hide_measure_list'  || containerType === 'syncchartParameterList' ||
				containerType === 'multivariateParameterList' ||
				// yyb 비정형보고서 주제영역 추가시 오류 수정 20210205
				/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
				containerType === 'adhoc_hide_measure_list' || containerType === 'downloadexpand_colList'

				)) {
			check = true;
		} else if(dataItem.attr('data-field-type') === 'measure' && (containerType === 'chartValueList' || containerType === 'pieValueList' || containerType === 'columnList' || containerType === 'chart_hide_measure_list' || containerType === 'dataAdHocList' ||
				containerType === 'mapValueList' || containerType === 'treemapValueList' || containerType === 'parallelValueList' || containerType === 'starchartValueList' || containerType === 'pie_hide_dimension_list' || containerType === 'pie_hide_measure_list' || containerType === 'bubbleChartValueList' || containerType === 'divergingchartValueList' ||
				containerType === 'RectangularAreaChartValueList' || containerType === 'waterfallchartValueList' || containerType === 'bipartitechartValueList' || containerType === 'funnelchartValueList' || containerType === 'pyramidchartValueList' || containerType === 'sankeychartValueList' || containerType === 'bubbled3ValueList' || containerType === 'grid_hide_measure_list' || containerType === 'kakaoMapValueList' || containerType === 'kakaomap2ValueList' || containerType === 'kakaoMapLatitudeList' || containerType === 'kakaoMapLongitudeList' ||
				containerType === 'heatmapValueList' ||containerType === 'heatmap2ValueList' || containerType === 'syncchartValueList'|| containerType === 'wordcloudValueList' || containerType === 'histogramchartValueList' || containerType === 'pivot_hide_measure_list' || containerType === 'chart_hide_measure_list' || containerType === 'grid_hide_measure_list' || containerType === 'scatterplot_hide_measure_list' || containerType === 'scatterplot2_hide_measure_list'  ||containerType === 'rangebarchartValueList' || containerType === 'rangeareachartValueList' || containerType === 'timelinechartValueList' ||
				/* DOGFOOT ktkang 측정값 및 차원 이동 시 화살표 아이콘 사라지는 오류 수정  20200619 */
				containerType === 'textboxValueList' || containerType === 'cardValueList' || containerType === 'dataList' || containerType === 'gaugeValueList' || containerType === 'sparkline' || containerType === 'card_hide_measure_list' || containerType === 'forceDirectValueList' || containerType === 'forceDirectExpandValueList'||  containerType === 'divergingchartSeries' ||
				containerType === 'bubblepackchartValueList' || containerType === 'wordcloudv2ValueList' || containerType === 'divergingchartSeriesList' || containerType === 'divergingchart_hide_measure_list' || containerType === 'scatterplotXList' ||containerType === 'scatterplotYList' ||containerType === 'scatterplotZList' || containerType === 'scatterplot2XList' ||containerType === 'scatterplot2YList' ||containerType === 'scatterplot2ZList' ||
				containerType === 'dendrogrambarchartValueList'|| containerType === 'calendarviewchartValueList' || containerType === 'dependencywheelValueList' || containerType === 'sequencessunburstValueList' || containerType === 'boxplotValueList'|| containerType === 'scatterplotValueList' || containerType === 'liquidfillgaugeValueList'||
				containerType === 'calendarview2chartValueList' || containerType === 'calendarview3chartValueList' || containerType === 'collapsibletreechartValueList' || containerType === 'coordinatelineXList' || containerType === 'coordinatelineYList' || containerType === 'coordinatedotXList' || containerType === 'coordinatedotYList'
				|| containerType === 'scatterPlotMatrixX1List'|| containerType === 'scatterPlotMatrixX2List'|| containerType === 'scatterPlotMatrixY1List'|| containerType === 'scatterPlotMatrixY2List'|| containerType === 'historyTimelineParameterList'|| containerType === 'historyTimelineEndList'|| containerType === 'historyTimelineStartList' || containerType === 'arcdiagramParameterList'
		) || containerType === 'dataAdHocList' ||
		containerType === 'onewayAnovaObservedList' || containerType === 'onewayAnovaFactorList' ||containerType === 'rFieldList'||
		containerType === 'twowayAnovaObservedList' || containerType === 'twowayAnovaFactorList' ||
		containerType === 'onewayAnova2ObservedList' || containerType === 'onewayAnova2FactorList' || containerType === 'onewayAnova2ItemList' ||
		containerType === 'pearsonsCorrelationNumericalList' || containerType === 'spearmansCorrelationNumericalList' || containerType === 'heatmap_hide_measure_list' || containerType === 'heatmap2_hide_measure_list' || containerType === 'syncchart_hide_measure_list'||
		containerType === 'simpleRegressionIndpnList' || containerType === 'simpleRegressionDpndnList' || containerType === 'simpleRegressionVectorList' ||
		containerType === 'multipleRegressionIndpnList' || containerType === 'multipleRegressionDpndnList' || containerType === 'multipleRegressionVectorList' ||
		containerType === 'logisticRegressionIndpnList' || containerType === 'logisticRegressionDpndnList' || containerType === 'logisticRegressionVectorList' ||
		containerType === 'multipleLogisticRegressionIndpnList' || containerType === 'multipleLogisticRegressionDpndnList' || containerType === 'multipleLogisticRegressionVectorList' ||
		containerType === 'tTestNumericalList' || containerType === 'zTestNumericalList' || containerType === 'chiTestNumericalList' || containerType === 'fTestNumericalList' ||
		containerType === 'multivariateNumericalList' ||
		// yyb 비정형보고서 주제영역 추가시 오류 수정 20210205
		/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
		containerType === 'adhoc_hide_measure_list' || containerType === 'downloadexpand_colList') {
			check = true;
		}
		return check;
	};
	/* 2020-06-29 LSH topN
	 * LSH topN 필드 설정
	 * topN UI 수정 및 기능 수정
	 * */
	this.topNset = function(_dataItem) {
		_dataItem.parent().find('.topNset').off('click').on('click',function(e){
			e.preventDefault();
			var popup = $('#topNset').dxPopup({
				height: 'auto',
				title: 'TopN 설정',
				width:500,
				visible: true,
				showCloseButton: false,
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForOption('topNset');
				},
				contentTemplate: function(contentElement) {
					// initialize title input box
					/*dogfoot 차원 TopN UI 수정 shlim 20200527*/
//					contentElement.append('<p>topN 적용 여부</p><br/><div id="topn_enabled">');
//                    var html = '<div class="modal-footer" style="padding-bottom:0px;">';
//                    html += '<div class="row center">';
//					html += '</div>';
//					html += '</div>';
//					html += '</div>';

//					contentElement.append(html);
					/*dogfoot 차원 TopN UI 수정 shlim 20200528*/
					contentElement.append('<p>※ Top 카운트 </p><div id="top_count">');
                    var html = '<div class="modal-footer" style="padding-bottom:0px;">';
					html += '<div class="row center">';
					html += '</div>';
					html += '</div>';
					html += '</div>';
					contentElement.append(html);

					contentElement.append('<p>측정값 </p><div id="top_measure">');
                    var html = '<div class="modal-footer" style="padding-bottom:0px;">';
					html += '<div class="row center">';
					html += '</div>';
					html += '</div>';
					html += '</div>';
					html += '<div>';
					/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
					if(gDashboard.fieldManager.focusItemType === 'chart'){
						html += '    <div  style="width:25%; display:inline-block; margin-left:30px;">';
						html += '	    <div style="width:80px; display:inline-block"><p>설정 적용</p></div>';
						html += '	    <div id="top_Enabled" style="width:30px; display:inline-block"></div>';
						html += '    </div>';
						html += '    <div  style="width:25%; display:inline-block; margin-left:20px;">';
						html += '	    <div style="width:80px; display:inline-block"><p>기타 값 표시</p></div>';
						html += '	    <div id="top_showother" style="width:30px; display:inline-block"></div>';
						html += '    </div>';
						html += '    <div  style="width:25%; display:inline-block; margin-left:20px;">';
						html += '	    <div style="width:80px; display:inline-block"><p>측정값 정렬</p></div>';
						html += '	    <div id="top_order" style="width:30px; display:inline-block"></div>';
						html += '    </div>';
					}else{
						html += '    <div  style="width:40%; display:inline-block; margin-left:30px;">';
						html += '	    <div style="width:100px; display:inline-block"><p>설정 적용</p></div>';
						html += '	    <div id="top_Enabled" style="width:30px; display:inline-block"></div>';
						html += '    </div>';
						html += '    <div  style="width:40%; display:inline-block; margin-left:20px;">';
						html += '	    <div style="width:100px; display:inline-block"><p>기타 값 표시</p></div>';
						html += '	    <div id="top_showother" style="width:30px; display:inline-block"></div>';
						html += '    </div>';
						html += '    <div  style="width:25%; display:none; margin-left:20px;">';
						html += '	    <div style="width:80px; display:inline-block"><p>측정값 정렬</p></div>';
						html += '	    <div id="top_order" style="width:30px; display:inline-block"></div>';
						html += '    </div>';
					}
					html += '</div>';
					contentElement.append(html);

                    var html = '<br/><div class="modal-footer" style="padding-bottom:0px;">';
					html += '<div class="row center">';
					html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
					html += '<a id="close" href="#" class="btn neutral close">취소</a>';
					html += '</div>';
					html += '</div>';
					html += '</div>';
					contentElement.append(html);
					/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
      				var TopNEnabled
      				,TopNShowOthers
      				,TopNOrder;



					if(_dataItem.attr('TopNCount')==undefined || _dataItem.attr('TopNCount')=='undefined' || _dataItem.attr('TopNCount')==''){
						_dataItem.attr('TopNCount',5);
					}
					var captionBox = contentElement.find('#top_count').dxTextBox({
						text: _dataItem.attr('TopNCount')
                    }).dxTextBox('instance');

					var simpleProducts = new Array();
					$.each(gDashboard.fieldManager.stateFieldChooser.find('.drop-panel').not('.dimension').find('.fieldName').parent().parent(),function(_i,_o){
						var topDataItem={};
						if($(_o).attr('data-field-type') == "measure"){
							topDataItem['name'] = $(_o).attr('UNI_NM');
							topDataItem['uniqueName'] = $(_o).attr('dataitem')
							simpleProducts.push(topDataItem);
						}
					});
		            var TopNMeasure;
		            var topNMember;
                    if(_dataItem.attr('TopNMeasure') == undefined || _dataItem.attr('TopNMeasure') == 'undefined'){
                        TopNMeasure = '';
                    }else{
                        TopNMeasure = _dataItem.attr('TopNMeasure');
                    }
					$("#top_measure").dxSelectBox({
				        items: simpleProducts,
				        displayExpr: "name",
				        showClearButton: true,
				        valueExpr: "uniqueName",
                        value:TopNMeasure,
				        onSelectionChanged: function(e) {
							if(e.selectedItem != null){
							    TopNMeasure=e.selectedItem.uniqueName;
							    topNMember=e.selectedItem.name;
							}else{
								TopNMeasure = ""
								topNMember = ""
							}
						}
				    });

	                if(typeof _dataItem.attr('TopNShowOthers') != 'undefined'){
                        if(_dataItem.attr('TopNShowOthers') == 'true'){
                            TopNShowOthers = true;
                        }else if(_dataItem.attr('TopNShowOthers') == 'false'){
                        	TopNShowOthers = false;
                        }
	                }else{
                        TopNShowOthers = false;
	                }

	                if(typeof _dataItem.attr('TopNEnabled') != 'undefined'){
                        if(_dataItem.attr('TopNEnabled') == 'true'){
                            TopNEnabled = true;
                        }else if(_dataItem.attr('TopNEnabled') == 'false'){
                        	TopNEnabled = false;
                        }
	                }else{
                        TopNEnabled = false;
	                }
	                /*dogfoot topN 정렬 설정 추가 shlim 20201112*/
	                if(typeof _dataItem.attr('TopNOrder') != 'undefined'){
	                	if(_dataItem.attr('TopNOrder') == 'true'){
	                		TopNOrder = true;
	                	}else if(_dataItem.attr('TopNOrder') == 'false'){
	                		TopNOrder = false;
	                	}
	                }else{
	                	TopNOrder = false;
	                }

	                $('#top_showother').dxCheckBox({
						value : _dataItem.attr('TopNShowOthers') && _dataItem.attr('TopNShowOthers')!="undefined" ? TopNShowOthers : false
					});

                    $('#top_Enabled').dxCheckBox({
						value : _dataItem.attr('TopNEnabled') && _dataItem.attr('TopNEnabled')!="undefined" ? TopNEnabled : false
					});
                    /*dogfoot topN 정렬 설정 추가 shlim 20201112*/
                    $('#top_order').dxCheckBox({
                    	value : _dataItem.attr('TopNOrder') && _dataItem.attr('TopNOrder')!="undefined" ? TopNOrder : false
                    });


					contentElement.find('#ok-hide').on('click', function() {
						gDashboard.fieldManager.isChange = true;
                        var TopNCount = captionBox.option('text');
                            TopNEnabled = $('#top_Enabled').dxCheckBox('instance').option('value')
                        	if(TopNMeasure.trim() == ''){
                        		TopNEnabled = false;
                        	}
	                        if(TopNEnabled===true && TopNCount.trim() == '') {
	                        	WISE.alert('※필수 항목을 입력하지 않았습니다.');
	                        }else{
	                        	_dataItem.attr('TopNCount',TopNCount);
	                        	_dataItem.attr('TopNEnabled',TopNEnabled);
	                        	/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
	                        	_dataItem.attr('TopNOrder',$('#top_order').dxCheckBox('instance').option('value'));
	                        	_dataItem.attr('TopNShowOthers',$('#top_showother').dxCheckBox('instance').option('value'));
	                        	_dataItem.attr('TopNMeasure',TopNMeasure);
	                        	_dataItem.attr('topMember',topNMember);
	                        	popup.hide();
	                        }
					});

					contentElement.find('#close').on('click', function() {
						popup.hide();
					});
				}
			}).dxPopup('instance');
		});
	};

	this.fieldRename = function(_dataItem) {
		/*dogfoot 레인지 차트 측정값 이름 변경 오류 수정 shlim 20201020*/
		_dataItem.parent().find('.fieldRename').not(".setRename").off('click').on('click',function(e){
			e.preventDefault();
			var popup = $('#fieldRename').dxPopup({
				height: 'auto',
				title: '필드 이름 편집',
				width:500,
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForEditText('fieldRename');
				},
				visible: true,
				showCloseButton: false,
				contentTemplate: function(contentElement) {
					// initialize title input box
					contentElement.append('<p>필드 이름 </p><div id="dataItem_rename">');
                    var html = '<div class="modal-footer" style="padding-bottom:0px;">';
					html += '<div class="row center">';
					html += '<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>';
					html += '<a id="close" href="#" class="btn neutral close">취소</a>';
					html += '</div>';
					html += '</div>';
					html += '</div>';
					contentElement.append(html);

                    var captionBox = contentElement.find('#dataItem_rename').dxTextBox({
						text: _dataItem.attr('caption')
                    }).dxTextBox('instance');

                    // confirm and cancel
					contentElement.find('#ok-hide').on('click', function() {
						gDashboard.fieldManager.isChange = true;
                        var newName = captionBox.option('text');
                        if(newName.trim() == '') {
                        	WISE.alert('필드 이름에 빈 값을 넣을 수 없습니다.');
                        	captionBox.option('value', _dataItem.attr('caption'));
                        } else {
                        	/*dogfoot 비정형 rename 특수문자 입력시 알림 처리 shlim 20200629*/
                        	/*dogfoot shlim 20210419*/
                        	var regExp = /[^(가-힣ㄱ-ㅎㅏ-ㅣa-zA-Z0-9"_""<br>"\s)]/gi;
                        	if(regExp.test(newName)){
                        		WISE.alert('특수문자는 입력할 수 없습니다.');
                        	}else{
								_dataItem.attr('caption',newName);
								// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
								_dataItem.attr('title',newName);
								_dataItem.find('.fieldName').text(newName);
	//                        	_dataItem.find('.btn').text(newName);
								/* dogfoot shlim 비정형에서 차트 Y축설청이후 rename이 안먹는 현상 수정 20200402*/
								if(gDashboard.reportType === 'AdHoc'){
									if(typeof gDashboard.itemGenerateManager.dxItemBasten != undefined){
										$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
											if(_o.itemid.indexOf('chartDashboardItem') > -1){
												_o.Chart.AxisY.TitleRename = false;
											}
										})
									}
								}
								popup.hide();
                        	}
                        }
					});
					contentElement.find('#close').on('click', function() {
						popup.hide();
					});
				}
			}).dxPopup('instance');
		});
		/*dogfoot 레인지 차트 측정값 이름 변경 오류 수정 shlim 20201020*/
		_dataItem.parent().find('.fieldRename').addClass("setRename")
	};

	this.changeSummaryType = function(_dataItem){
		$($(_dataItem).parent().children().get(_dataItem.parent().children().index(_dataItem)+1)).find('.summaryType').off('click').on('click',function(e){
			gDashboard.fieldManager.isChange = true;
			e.preventDefault();
//			_dataItem.parent().find('.summaryType').parent('.on').toggleClass('on');
			$($(_dataItem).parent().children().get(_dataItem.parent().children().index(_dataItem)+1)).find('.summaryType').parent('.on').toggleClass('on');
			$(e.target).parent().addClass('on');
		});
	};

	this.addFormat = function(_dataItem,_dataField) {
		self.changeSummaryType(_dataItem);
		var options = {
				FormatType: "Number",
				Unit: "Ones",
				SuffixEnabled: false,
				Suffix: {
					O: '',
					K: '천',
					M: '백만',
					B: '십억'
				},
				Precision: gDashboard.reportType === 'StaticAnalysis'? 2 : 0,
				PrecisionOption: '반올림',
				IncludeGroupSeparator : true
			};
		if(typeof _dataField != "undefined"){
			if(_dataField.NUMERIC_FORMAT){
				options = {
						FormatType: _dataField.NUMERIC_FORMAT.FormatType ? _dataField.NUMERIC_FORMAT.FormatType : "Number",
						Unit: _dataField.NUMERIC_FORMAT.Unit ? _dataField.NUMERIC_FORMAT.Unit : "Ones",
						SuffixEnabled: _dataField.NUMERIC_FORMAT.SuffixEnabled ? _dataField.NUMERIC_FORMAT.SuffixEnabled :false,
						Suffix: _dataField.NUMERIC_FORMAT.Suffix ? _dataField.NUMERIC_FORMAT.Suffix :{
									O: '',
									K: '천',
									M: '백만',
									B: '십억'
								},
						Precision: _dataField.NUMERIC_FORMAT.Precision ? _dataField.NUMERIC_FORMAT.Precision : gDashboard.reportType === 'StaticAnalysis'? 2 : 0,
						PrecisionOption: _dataField.NUMERIC_FORMAT.PrecisionOption ? _dataField.NUMERIC_FORMAT.PrecisionOption : '반올림',
						/*dogfoot shlim 20210420*/
						IncludeGroupSeparator : _dataField.NUMERIC_FORMAT.IncludeGroupSeparator ? _dataField.NUMERIC_FORMAT.IncludeGroupSeparator =="Y" ? true : _dataField.NUMERIC_FORMAT.IncludeGroupSeparator =="N" ? false : true : true
//						IncludeGroupSeparator : _dataField.NUMERIC_FORMAT.IncludeGroupSeparator ? _dataField.NUMERIC_FORMAT.IncludeGroupSeparator : true
					};
					/*dogfoot shlim 20210420*/
				_dataField.NUMERIC_FORMAT = options
			}
		}
//		var options = {
//			FormatType: "Number",
//			Unit: "Ones",
//			SuffixEnabled: false,
//			Suffix: {
//				O: '',
//				K: '천',
//				M: '백만',
//				B: '십억'
//			},
//			Precision: gDashboard.reportType === 'StaticAnalysis'? 2 : 0,
//			IncludeGroupSeparator : true
//		};

		// 비정형 변동측정값 포맷옵션 불러오기
		if (gDashboard.reportType == 'AdHoc' && !isNull(_dataItem.attr('id'))) {
			if (_dataItem.attr('id').indexOf('delta') > -1) {
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e){
					if (_e.type == 'PIVOT_GRID') {
						if (typeof _e.meta.deltaOpt !== 'undefined') {
							if (!isNull(_e.meta.deltaOpt.formatOptions[_dataItem.attr('id')])) {
								options = _e.meta.deltaOpt.formatOptions[_dataItem.attr('id')];
							}
						}
					}
				});
			}
		}
		
		_dataItem.data('formatOptions', options);

		_dataItem.parent().find('.setFormat').off('click').on('click',function(e) {
			e.preventDefault();
			var formatOptions = _dataItem.data('formatOptions');
			var containerType = _dataItem.parent().parent().attr("id") || _dataItem.parent().parent().parent().attr("id")
			
			containerType = containerType.substring(0,containerType.lastIndexOf("t")+1);
			
			$('#formatOptions').dxPopup({
				title: '숫자 형식',
				height: 'auto',
				width: 400,
				visible: true,
				showCloseButton: false,

				contentTemplate: function(contentElement) {
					var html = 	'<div id="numberFormatOptions"></div>' +
								'<textarea id="formatExampleText" style="width: 100%; height: 50px; text-align: center; font-size: 1.5em;" disabled></textarea>' +
								'<div style="padding-bottom:20px;"></div>' +
								'<div class="modal-footer" style="padding-bottom:0px;">' +
									'<div class="row center">' +
										'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
										'<a id="close" href="#" class="btn neutral close">취소</a>' +
									'</div>' +
								'</div>';
					contentElement.append(html);
				},
				onContentReady: function(popup) {
					var example = 1234567890.123,
						initialized = false;
					// edit Y axis measures
					var formatOptionsForm = $('#numberFormatOptions').dxForm({
						items: [
							{
								dataField: '포맷 형식',
								editorType: 'dxSelectBox',
								editorOptions: {
									items: ['Auto', 'General', 'Number', 'Currency', 'Scientific', 'Percent'],
									value: typeof formatOptions.FormatType !== 'undefined' ? formatOptions.FormatType : 'Number',
									onValueChanged: function(e) {
										if (e.value === 'Auto' || e.value === 'General') {
											formatOptionsForm.getEditor('단위').option('disabled', true);
											formatOptionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
											formatOptionsForm.getEditor('O').option('disabled', true);
											formatOptionsForm.getEditor('K').option('disabled', true);
											formatOptionsForm.getEditor('M').option('disabled', true);
											formatOptionsForm.getEditor('B').option('disabled', true);
											formatOptionsForm.getEditor('정도').option('disabled', true);
											formatOptionsForm.getEditor('정도 옵션').option('disabled', true);
											formatOptionsForm.getEditor('그룹 구분 포함').option('disabled', true);
										} else if (e.value === 'Scientific' || e.value === 'Percent') {
											formatOptionsForm.getEditor('단위').option('disabled', true);
											formatOptionsForm.getEditor('사용자 지정 접미사').option('disabled', true);
											formatOptionsForm.getEditor('O').option('disabled', true);
											formatOptionsForm.getEditor('K').option('disabled', true);
											formatOptionsForm.getEditor('M').option('disabled', true);
											formatOptionsForm.getEditor('B').option('disabled', true);
											formatOptionsForm.getEditor('정도').option('disabled', false);
											formatOptionsForm.getEditor('정도 옵션').option('disabled', false);
											formatOptionsForm.getEditor('그룹 구분 포함').option('disabled', true);
										} else {
											formatOptionsForm.getEditor('단위').option('disabled', false);
											formatOptionsForm.getEditor('사용자 지정 접미사').option('disabled', false);
											if (formatOptionsForm.getEditor('사용자 지정 접미사').option('value')) {
												formatOptionsForm.getEditor('O').option('disabled', false);
												formatOptionsForm.getEditor('K').option('disabled', false);
												formatOptionsForm.getEditor('M').option('disabled', false);
												formatOptionsForm.getEditor('B').option('disabled', false);
											}
											formatOptionsForm.getEditor('정도').option('disabled', false);
											formatOptionsForm.getEditor('정도 옵션').option('disabled', false);
											formatOptionsForm.getEditor('그룹 구분 포함').option('disabled', false);
										}
									}
								}
							},
							{
								dataField: '단위',
								editorType: 'dxSelectBox',
								editorOptions: {
									items: ['Auto', 'Ones', 'Thousands', 'Millions', 'Billions'],
									value: typeof formatOptions.Unit !== 'undefined' ? formatOptions.Unit : 'Ones',
									onInitialized: function(e) {
										var formatType = formatOptions.FormatType;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: '사용자 지정 접미사',
								editorType: 'dxCheckBox',
								editorOptions: {
									value: typeof formatOptions.SuffixEnabled !== 'undefined' ? formatOptions.SuffixEnabled : false,
									onInitialized: function(e) {
										var formatType = formatOptions.FormatType;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									},
									onValueChanged: function(e) {
										if (e.value) {
											formatOptionsForm.getEditor('O').option('disabled', false);
											formatOptionsForm.getEditor('K').option('disabled', false);
											formatOptionsForm.getEditor('M').option('disabled', false);
											formatOptionsForm.getEditor('B').option('disabled', false);
										} else {
											formatOptionsForm.getEditor('O').option('disabled', true);
											formatOptionsForm.getEditor('K').option('disabled', true);
											formatOptionsForm.getEditor('M').option('disabled', true);
											formatOptionsForm.getEditor('B').option('disabled', true);
										}
									}
								}
							},
							{
								dataField: 'O',
								editorType: 'dxTextBox',
								editorOptions: {
									value: typeof formatOptions.Suffix !== 'undefined' ? formatOptions.Suffix.O : '',
									onInitialized: function(e) {
										var formatType = formatOptions.FormatType;
										var suffixEnabled = formatOptions.SuffixEnabled;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: 'K',
								editorType: 'dxTextBox',
								editorOptions: {
									value: typeof formatOptions.Suffix !== 'undefined' ? formatOptions.Suffix.K : '천',
									onInitialized: function(e) {
										var formatType = formatOptions.FormatType;
										var suffixEnabled = formatOptions.SuffixEnabled;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: 'M',
								editorType: 'dxTextBox',
								editorOptions: {
									value: typeof formatOptions.Suffix !== 'undefined' ? formatOptions.Suffix.M : '백만',
									onInitialized: function(e) {
										var formatType = formatOptions.FormatType;
										var suffixEnabled = formatOptions.SuffixEnabled;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: 'B',
								editorType: 'dxTextBox',
								editorOptions: {
									value: typeof formatOptions.Suffix !== 'undefined' ? formatOptions.Suffix.B : '십억',
									onInitialized: function(e) {
										var formatType = formatOptions.FormatType;
										var suffixEnabled = formatOptions.SuffixEnabled;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent' || !suffixEnabled) {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							},
							{
								dataField: '정도',
								editorType: 'dxNumberBox',
								editorOptions: {
									step: 1,
									min: 0,
									max: 5,
									showSpinButtons: true,
									value: typeof formatOptions.Precision !== 'undefined' ? formatOptions.Precision : 0,
									onInitialized: function(e) {
										var formatType = formatOptions.FormatType;
										if (formatType === 'Auto' || formatType === 'General') {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									},
								}
							},
							{
								dataField: '정도 옵션',
								editorType: 'dxSelectBox',
								visible: containerType =='chartValueList' || containerType =='columnList' ||containerType =='funnelchartValueList' || containerType =='chartValueList'
									|| containerType =='dataList' || containerType =='pieValueList' || containerType =='dataAdHocList' || containerType =='bubbleChartValueList' || containerType =='deltavalueList' ? true : false,
								editorOptions: {
									items: ['반올림', '올림', '버림'],
									value: typeof formatOptions.PrecisionOption !== 'undefined' ? formatOptions.PrecisionOption : "반올림",
								}
							},
							{
								dataField: '그룹 구분 포함',
								editorType: 'dxCheckBox',
								editorOptions: {
									value: typeof formatOptions.IncludeGroupSeparator !== 'undefined' ? formatOptions.IncludeGroupSeparator : true,
									onInitialized: function(e) {
										var formatType = formatOptions.FormatType;
										if (formatType === 'Auto' || formatType === 'General' || formatType === 'Scientific' || formatType === 'Percent') {
											e.component.option('disabled', true);
										} else {
											e.component.option('disabled', false);
										}
									}
								}
							}
						],
						onContentReady: function(form) {
							gDashboard.fontManager.setFontConfigForOption('numberFormatOptions');
							if (!initialized) {
								initialized = true;
								var updateExample = function(e) {
									var formData = e.component.option('formData');
									var type = formData['포맷 형식'];
									var	unit = formData['단위'];
									var precision = formData['정도'];
									var precisionOption = formData['정도 옵션'];
									var separator = formData['그룹 구분 포함'];
									var prefix = undefined;
									var suffix = {
										O: formData['O'],
										K: formData['K'],
										M: formData['M'],
										B: formData['B']
									};
									var suffixEnabled = formData['사용자 지정 접미사'];
									$('#formatExampleText').val(WISE.util.Number.unit(example, type, unit, precision, separator, prefix, suffix, suffixEnabled, precisionOption));
								}
								updateExample(form);
								form.component.option('onFieldDataChanged', updateExample);
							}
							// confirm and cancel
							popup.element.find('#ok-hide').off('click').on('click', function() {
								var formData = formatOptionsForm.option('formData');
								var newFormat = {
									FormatType: formData['포맷 형식'],
									Unit: formData['단위'],
									SuffixEnabled: formData['사용자 지정 접미사'],
									Precision: formData['정도'],
									PrecisionOption: formData['정도 옵션'],
									Suffix: {
										O: formData['O'],
										K: formData['K'],
										M: formData['M'],
										B: formData['B']
									},
									/*dogfoot shlim 20210420*/
									IncludeGroupSeparator: formData['그룹 구분 포함'] == "Y" ? true : formData['그룹 구분 포함'] == "N" ? false : formData['그룹 구분 포함']
//									IncludeGroupSeparator: formData['그룹 구분 포함']
								};
								_dataItem.data('formatOptions', newFormat);
								
								// 비정형 변동측정값 포맷옵션 저장하기
								if (gDashboard.reportType == 'AdHoc' && !isNull(_dataItem.attr('id'))) {
									if (_dataItem.attr('id').indexOf('delta') > -1) {
										$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e){
											if (_e.type == 'PIVOT_GRID') {
												if (typeof _e.meta.deltaOpt === 'undefined') {
													_e.meta.deltaOpt = {
		                                				formatOptions: {}
		                                			};
		                                		}

												_e.meta.deltaOpt.formatOptions[_dataItem.attr('id')] = newFormat;
											}
										});
	                                }
								}
								popup.component.hide();
							});
							popup.element.find('#close').off('click').on('click', function() {
								popup.component.hide();
							});
						}
					}).dxForm('instance');
				}
			});
		});
	};

	this.setFormatOptionModal = function(_e) {
		var options = $(_e).data('formatOptions');

		$('#selectFormat').val(options.FormatType).attr('selected', 'selected');
		$('#selectUnit').val(options.Unit).attr('selected', 'selected');
		$('#precision').val(options.Precision);
		$('#checkSeperate').prop('checked', options.IncludeGroupSeparator);
	};

	this.setFormatOptionModalForOpen = function(_e) {
		var options = $(_e).data('formatOptions');

//		$('#selectFormat').prop('selected', options.FormatType);
//		$('#selectUnit').prop('selected', options.Unit);
//		$('#precision').val(options.Precision);
//		$('#checkSeperate').prop('checked', options.IncludeGroupSeparator);

		// $('#selectFormat').val(options.FormatType).attr('selected', 'selected');
		// $('#selectUnit').val(options.Unit).attr('selected', 'selected');
		// $('#precision').val(options.Precision);
		// $('#checkSeperate').prop('checked', options.IncludeGroupSeparator);

		$(_e).children('li').data('formatOptions', options);
	};

	this.setFormatOption = function(_e) {
		var options = $(_e).data('formatOptions');

		options.FormatType = $('#selectFormat').val();
		options.Unit = $('#selectUnit').val();
		options.Precision = $('#precision').val();
		options.IncludeGroupSeparator = $('#checkSeperate').prop('checked');

		$(_e).data('formatOptions',options);
	};

	this.activeGridOption = function(dataItem){
		dataItem.find('.btn').off('click').on('click',function(e){
			e.preventDefault();
			if(dataItem.attr('data-field-type') == 'dimension'){
				if(dataItem.hasClass('arrayUp')){
					dataItem.removeClass('arrayUp').addClass('arrayDown');
				}else if(dataItem.hasClass('arrayDown')){
					dataItem.removeClass('arrayDown').addClass('arrayUp');
				}
			}
		});
	};

	this.addEventChangeType = function(otherBtn){
		otherBtn.off('click').click(function(e){
			e.preventDefault();
			var p = $('#editPopup').dxPopup('instance');
			p.option({
				title: '열 옵션 설정',
				width: 1100,
				height: 340,
				contentTemplate: function(contentElement) {
					// initialize title input box
					var changeTypeHtml = "<div class=\"modal-body\">\r\n" +
					"                        <div class=\"row\" style='height:100%'>\r\n" +
					"                            <div class=\"column\" style='width:35%'>\r\n" +
					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
					"                                   <div class=\"modal-tit\">\r\n" +
					"                                	   <span>필드 타입 유형</span>\r\n" +
					"                                   </div>\r\n" +
					"									<div id=\"gridOptionsSet\"/>" +
					"                                </div>\r\n" +
					"                            </div>\r\n" +
					"							 <div class=\"column\" style='width:65%'>\r\n" +
					"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" +
					"                                   <div class=\"modal-tit\">\r\n" +
					"                                   	<span>세부 설정</span>\r\n" +
					"                                   </div>\r\n" +
					"	                                <div class=\"setDetailOption\" />" +//그리드 부분
					"                                </div>\r\n" +
					"                            </div>\r\n" +
					"                        </div>\r\n" + //row 끝
					"                    </div>\r\n" + //modal-body 끝
					"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" +
					"                        <div class=\"row center\">\r\n" +
					"                            <a id=\"gridOptionsOk\" href=\"#\" class=\"btn positive ok-hide\">확인</a>\r\n" +
					"                            <a id='gridOptionsCancel' class='btn neutral close' href='#'>취소</a>\r\n" +
					"                        </div>\r\n" +
					"                    </div>\r\n" +
					"                </div>";

					contentElement.append(changeTypeHtml);

					var dataItem = $(e.target).parent().parent().hasClass('wise-area-field') ? $(e.target).parent().parent() : $(e.target).parent();
					var dataItemType = dataItem.attr('datatype');
					var detailType = dataItem.attr('detailtype');
					var updateType;
					var changeDetailType = detailType;
					var radioGroupItems = [
					    { text: "dimension", type: "차원"},
					    { text: "measure", type: "측정값"},
					    { text: "delta", type: "델타"},
					    { text: "sparkline", type: "스파크 라인"}
					];

					var measureRadioGroupItems = [
					    { text: "value", type: "값"},
					    { text: "bar", type: "바"}
					];

					var sparklineHtml = ''+
					  '        <div class="tbl data-form deltaform1">'+
                      '	        <table>'+
                      '		        <colgroup>'+
                      '					<col style="width: 100%">' +
                      '		        </colgroup>'+
                      '				<tbody>' +
                      '					<tr>' +
                      '						<th style="padding-top:6px; text-align: left;">' +
                      '							<input class="check HighlightStartEndPoints" id="HighlightStartEndPoints" type="checkbox" name="check-set">'+
                      '							<label for="HighlightStartEndPoints" style="color: #333 !important;">시작/끝 값 포인트 강조</label>'+
                      '						</th>' +
                      '					</tr>' +
                      '					<tr>' +
                      '						<th style="padding-top:6px; text-align: left;">' +
                      '							<input class="check HighlightMinMaxPoints" id="HighlightMinMaxPoints" type="checkbox" name="check-set">'+
                      '							<label for="HighlightMinMaxPoints" style="color: #333 !important;">최소/최대 포인트를 강조</label>'+
                      '						</th>' +
                      '					</tr>' +
                      '		   	 </table>'+
                      '		   </div>';

					var deltaDetailHtml = '<div class="tab-title">'+
								          '      <ul>'+
								          '          <li rel="deltatab-1" class="on">'+
								          '              <a href="#">공통</a>'+
								          '          </li>'+
//								          '          <li rel="deltatab-2" class="">'+
//								          '              <a href="#">형식</a>'+
//								          '          </li>'+
								          '      </ul>'+
								          '</div>'+
								          '<div id="deltatab" class="tab-component">'+
	                                      '     <div class="deltatab-1 tab-content">'+
	                                      '        <div class="tbl data-form deltaform1">'+
	                                      '	        <table>'+
	                                      '		        <colgroup>'+
	                                      '					<col style="width: 150px">' +
                                          '					<col style="width: auto">' +
	                                      '		        </colgroup>'+
	                                      '				<tbody>' +
	                                      '					<tr>' +
	                                      '						<th style="padding-top:7px;">'+
	                                      '							<label for="AlwaysShowZeroLevel">항상 제로 수준 표시</label>'+
	                                      '						</th>'+
	                                      '						<td style="padding-top:6px;">' +
	                                      '							<input class="check AlwaysShowZeroLevel" id="AlwaysShowZeroLevel" type="checkbox" name="check-set">'+
	                                      '							<label for="AlwaysShowZeroLevel"></label>'+
	                                      '						</td>' +
	                                      '					</tr>' +
	                                      '					<tr>' +
	                                      '						<th class=\"left\">' +
	                                      '							<label>값 유형</label>'+
	                                      '						</th>' +
	                                      '						<td>' +
	                                      '							<select id="ValueType">'+
                                          '     		             <option value="ActualValue" data-display="Select">Actual value</option>'+
                                          '			                 <option value="AbsoluteVariation">Absolute variation</option>'+
                                          '         		         <option value="PercentVariation">Percent variation</option>'+
                                          '                 		 <option value="PercentOfTarget">Percent of target</option>'+
                                          '				            </select>'+
	                                      '						</td>' +
	                                      '					</tr>' +
	                                      '					<tr>' +
	                                      '						<th class=\"left\">' +
	                                      '							<label>결과 표시</label>'+
	                                      '						</th>' +
	                                      '						<td>' +
	                                      '							<select id="ResultIndicationMode">'+
                                          '			                  <option value="GreaterIsGood" data-display="Select">Greater is good</option>'+
                                          '                  		  <option value="LessIsGood">Less is good</option>'+
                                          '			                  <option value="WarningIfGreater">Warning if greater</option>'+
                                          '        			          <option value="WarningIfLess">Warning if less</option>'+
                                          '			                  <option value="NoIndication">No indication</option>'+
                                          '         			     </select>'+
	                                      '						</td>' +
	                                      '					</tr>' +
	                                      '					<tr>' +
	                                      '						<th class=\"left\">' +
	                                      '							<label>임계값 유형</label>'+
	                                      '						</th>' +
	                                      '						<td>' +
	                                      '							<select id="ResultIndicationThresholdType">'+
                                          '			                  <option value="Absolute" data-display="Select">Absolute</option>'+
                                          '                  		  <option value="Percent">Percent</option>'+
                                          '				            </select>'+
	                                      '						</td>' +
	                                      '					</tr>' +
	                                      '					<tr>' +
	                                      '						<th class=\"left\">' +
	                                      '							<label for="ResultIndicationThreshold">임계값 값</label>'+
	                                      '						</th>' +
	                                      '						<td>' +
	                                      '							<div class="ResultIndicationThreshold" id="ResultIndicationThreshold" />'+
	                                      '						</td>' +
	                                      '					</tr>' +
	                                      '		   	 </table>'+
	                                      '		   </div>'+
	                                      '     </div>'+
//	                                      '     <div class="deltatab-2 tab-content">'+
//	                                      '        <div class="deltaform2"/>'+
//	                                      '     </div>'+
	                                      '</div>';

					if(dataItem.attr('originType') == 'dimension'){
						radioGroupItems[2].disabled = true;
					}

					$('#gridOptionsSet').dxRadioGroup({
						dataSource: radioGroupItems,
				        displayExpr: "type",
				        valueExpr: "text",
				        onValueChanged: function(e) {
				        	updateType = e.value;
				        	$('.setDetailOption').empty();
				        	if(e.value != 'delta'){
				        		p.option('height',340);
				        	}

				        	switch(e.value){
				        		case "dimension":
				        			break;
				        		case "measure":
				        			$('.setDetailOption').dxRadioGroup({
										dataSource: measureRadioGroupItems,
								        displayExpr: "type",
								        valueExpr: "text",
								        value: detailType == "undefined" ? 'value' : detailType,
								        onValueChanged: function(e) {
								        	changeDetailType = e.value;
								        }
				        			});

				        			$('.setDetailOption').dxRadioGroup('instance').repaint();
				        			break;
				        		case "delta":
				        			//2020.07.30 MKSONG DOGFOOT 그리드 팝업 사이즈 오류 수정
				        			p.option('height',450);
				        			$('.setDetailOption').append(deltaDetailHtml);
				        			$("#ResultIndicationThreshold").dxNumberBox({
				        		        value: 0,
				        		        min: 0,
				        		        showSpinButtons: true
				        		    });

				        			if(dataItem.attr('AlwaysShowZeroLevel')){
				        				$("input:checkbox[id='AlwaysShowZeroLevel']").prop("checked", dataItem.attr('AlwaysShowZeroLevel') == 'true' ? true : false);
				        			}

				        			if(dataItem.attr('ResultIndicationMode')){
				        				$('#ResultIndicationMode').val(dataItem.attr('ResultIndicationMode'));
				        			}

				        			if(dataItem.attr('ResultIndicationThresholdType')){
				        				$('#ResultIndicationThresholdType').val(dataItem.attr('ResultIndicationThresholdType'));
				        			}

				        			if(dataItem.attr('ResultIndicationThreshold')){
				        				$("#ResultIndicationThreshold").dxNumberBox('instance').option('value',dataItem.attr('ResultIndicationThreshold'));
				        			}

				        			if(dataItem.attr('ValueType')){
				        				$('#ValueType').val(dataItem.attr('ValueType'));
				        			}

				        			tabUi();
				        			break;
				        		case "sparkline":
				        			$('.setDetailOption').append(sparklineHtml);
				        			var highlightStartEndPoints = true, highlightMinMaxPoints = true;
				        			if(dataItem.attr('highlightStartEndPoints')){
				        				highlightStartEndPoints = dataItem.attr('highlightStartEndPoints') == 'true' ? true : false;
				        			}

				        			if(dataItem.attr('highlightMinMaxPoints')){
				        				highlightMinMaxPoints = dataItem.attr('highlightMinMaxPoints') == 'true' ? true : false;
				        			}

				        			$("input:checkbox[id='HighlightStartEndPoints']").prop("checked", highlightStartEndPoints);
				        			$("input:checkbox[id='HighlightMinMaxPoints']").prop("checked", highlightMinMaxPoints);
				        			break;
				        	}

				        }
					});

					$('#gridOptionsOk').dxButton({
						text:"확인",
						onClick:function(){
							var updateType = $('#gridOptionsSet').dxRadioGroup('instance').option('value');
							var options = {};
							if(updateType == 'sparkline'){
								options = {
										ViewType: 'Line',
										HighlightStartEndPoints: $("input:checkbox[id='HighlightStartEndPoints']").is(":checked"),
										HighlightMinMaxPoints: $("input:checkbox[id='HighlightMinMaxPoints']").is(":checked")
								};
							}else if(updateType == 'delta'){
								options = {
									AlwaysShowZeroLevel: $("input:checkbox[id='AlwaysShowZeroLevel']").is(":checked"),
									ValueType: $("#ValueType").val(),
									ResultIndicationMode:  $("#ResultIndicationMode").val(),
									ResultIndicationThresholdType:  $("#ResultIndicationThresholdType").val(),
									ResultIndicationThreshold: $("#ResultIndicationThreshold").dxNumberBox('instance').option('value')
								};
							}
							dataItem.attr('detailtype',changeDetailType);
							gDashboard.dragNdropController.changeType(e,updateType,options);
							p.option('height', 'auto');
							p.hide();
						}
					});
					$('#gridOptionsCancel').dxButton({
						text:"취소",
						onClick:function(){
							p.option('height', 'auto');
							p.hide();
						}
					});

					$('#gridOptionsSet').dxRadioGroup('instance').option('value',dataItemType);
				}
			});
			// show popup


			p.show();
		});
	}

//	this.changeGridOption = function(e){
//		$('#gridOptionsSet').dxRadioGroup({
//			dataSource: radioGroupItems,
//	        displayExpr: "type",
//	        valueExpr: "text",
//	        value: dataItemType,
//	        onValueChanged: function(e) {
//	        	updateType = e.value;
//	        }
//		});
//	};

	this.changeType = function(e,updateType,options){
		self.item = gDashboard.itemGenerateManager.focusedItem;
		var dataItem = $(e.target).parent().parent();
		var dataItemType = dataItem.attr('dataType');

		if(dataItemType != updateType && dataItemType == 'delta'){
			dataItem.parent().children('li.delta-drop').remove();
			dataItem.children('.otherBtn').height('30px');
			if(dataItem.parent().children('.divide-menu').length > 1){
				dataItem.parent().children('.divide-menu').get(1).remove();
			}
			dataItem.parent().children('.divide-menu')
			dataItem.attr('target-field-uninm',undefined);
		}
			switch (updateType){
				case 'dimension' :
					if(gDashboard.reportType !== 'DSViewer')
					dataItem.addClass('arrayUp');
					dataItem.attr('dataType','dimension');
					dataItem.find('.otherBtn').empty();
					var fieldName = dataItem.find('.fieldName');
					dataItem.find('.btn').empty();
					dataItem.find('.btn').append(fieldName);
					dataItem.parent().find('.divide-menu.other-menu').remove();
					self.appendFieldOptionMenu(dataItem,'dimension',false);
//					dataItem.parent().append(self.dimensionFieldOptionMenu);
					self.fieldRename(dataItem);
					//2020-01-14 LSH topN
					self.topNset(dataItem);
					dataItem.find('.otherBtn').append('<img src="' + WISE.Constants.context + '/resources/main/images/ico_axis.png" alt>');
					compMoreMenuUi();
					break;
				case 'measure' :
					dataItem.removeClass('arrayUp');
					dataItem.removeClass('arrayDown');
					dataItem.attr('dataType','measure');
					dataItem.find('.otherBtn').empty();
					var fieldName = dataItem.find('.fieldName');
					dataItem.find('.btn').empty();
					dataItem.find('.btn').append(fieldName);

					dataItem.parent().find('.divide-menu.other-menu').remove();
					self.appendFieldOptionMenu(dataItem,'measure',false);
//					if(dataItem.parent().find('.divide-menu.other-menu').length == 0){
//						dataItem.parent().append(self.measureFieldOptionMenu);
//					}
					self.addFormat(dataItem);
					self.fieldRename(dataItem);
					dataItem.find('.otherBtn').append('<img src="' + WISE.Constants.context + '/resources/main/images/ico_sigma.png" alt>');
					compMoreMenuUi();
					modalUi();
					if(dataItem.attr('data-field-type') == 'dimension'){
						dataItem.parent().find('.more-link').children('.on').toggleClass('on');
						dataItem.parent().find('.more-link').find('[summaryType|="count"]').parent().toggleClass('on');
					}
					break;
				case 'delta' :
					var target;
					var thisItem;
					if(dataItem.parent().hasClass('display-move-wrap')){
						thisItem = dataItem.children('li');
					}else{
						thisItem = dataItem;
					}

					thisItem.attr('AlwaysShowZeroLevel',options.AlwaysShowZeroLevel+'');
					thisItem.attr('ValueType',options.ValueType+'');
					thisItem.attr('ResultIndicationMode',options.ResultIndicationMode+'');
					thisItem.attr('ResultIndicationThresholdType',options.ResultIndicationThresholdType+'');
					thisItem.attr('ResultIndicationThreshold',options.ResultIndicationThreshold+'');

					thisItem.removeClass('arrayUp');
					thisItem.removeClass('arrayDown');
					thisItem.attr('dataType','delta');
					if(!thisItem.find('.otherBtn').hasClass('delta')){
						thisItem.find('.otherBtn').empty();
					}else{
						thisItem.find('.otherBtn').addClass('delta');
					}

//					var fieldName = thisItem.find('.fieldName');
//					thisItem.find('.btn').empty();
//					thisItem.find('.btn').append(fieldName);
//					dataItem.parent().append(self.measureFieldOptionMenu);
					self.addFormat(thisItem);
					self.fieldRename(thisItem);
					//2020-01-14 LSH topN
					self.topNset(thisItem);
					thisItem.addClass('drop-target');

					if(thisItem.parent().find('.drop-target').length == 1){
						thisItem.parent().append($('<li id="delta-drop' + self.item.index + '_'+ ($('.delta-drop').length + 1) + '" class="drop-target delta-drop" style="margin-top: 0px;height: 31px;margin-bottom: 4px;" drop-type="deltaTarget"><a href="#" class="btn neutral" style="width: calc(100% - 35px); margin-bottom: 4px;">' + gMessage.get('WISE.message.page.widget.drop.target') + '</a></li>'));
						thisItem.find('.otherBtn').height('66px');
						thisItem.find('.otherBtn').append('<img src="' + WISE.Constants.context + '/resources/main/images/ico_triangle.png" alt>');
					}

					compMoreMenuUi();
					modalUi();

					$('.delta-drop').droppable(this.droppableOptions);

					break;
				case 'sparkline' :
					dataItem.removeClass('arrayUp');
					dataItem.removeClass('arrayDown');
					dataItem.attr('dataType','sparkline');
					dataItem.attr('highlightStartEndPoints',options.HighlightStartEndPoints+'');
					dataItem.attr('highlightMinMaxPoints',options.HighlightMinMaxPoints+'');


					dataItem.find('.otherBtn').addClass('sparkline');
					dataItem.find('.otherBtn').empty();
					var fieldName = dataItem.find('.fieldName');
					dataItem.find('.btn').empty();
					dataItem.find('.btn').append(fieldName);
					dataItem.parent().find('.divide-menu.other-menu').remove();
					self.appendFieldOptionMenu(dataItem,'measure',false);
//					if(dataItem.parent().find('.divide-menu.other-menu').length == 0){
//						dataItem.parent().append(self.measureFieldOptionMenu);
//					}
					self.addFormat(dataItem);
					self.fieldRename(dataItem);
					//2020-01-14 LSH topN
					self.topNset(dataItem);
					dataItem.find('.otherBtn').append('<img src="' + WISE.Constants.context + '/resources/main/images/ico_graph.png" alt>');
					compMoreMenuUi();
					modalUi();
					break;
			}
		//}
	};

	this.expandMeasureList = function(_dataItem){
		var dataItem = $(_dataItem).parent().parent();
		// mksong 2019.12.20 sort By 오류 수정 dogfoot
		var selectedDataItem = dataItem.find('.measureList').children('.on').attr('dataitem') == undefined ? '' : dataItem.find('.measureList').children('.on').attr('dataitem');
		var isDeletedDataItem;
		if(selectedDataItem != ''){
			isDeletedDataItem = true;
		}
		$.each(dataItem.find('.measureList').children(),function(_k,_j){
			if (typeof $(_j).attr('dataitem') !== 'undefined' && $(_j).attr('dataitem') !== false) {
				$(_j).remove();
			}
		});
		$.each(gDashboard.fieldManager.stateFieldChooser.find('.drop-panel').not('.dimension').find('.analysis-data').find('.fieldName'),function(_i,_o){
			var fieldName = $(_o).text();
			var li = $(_o).parent().parent();
			var addMeasure;
			if(selectedDataItem == li.attr('dataitem')){
				addMeasure = $('<li id="'+ li.attr('dataitem') +'" dataitem="'+ li.attr('dataitem') +'" uni_nm="'+ li.attr('uni_nm') +'" class="on"><a href="#">'+ fieldName +'</a></li>');
				isDeletedDataItem = false;
			}else{
				/*dogfoot 차원 행열 이동시 정렬기준 값 가져가도록 수정 shlim 20210402*/
				if(self.dimensionSortByField == li.attr('dataitem')){
					addMeasure = $('<li id="'+ li.attr('dataitem') +'" dataitem="'+ li.attr('dataitem') +'" uni_nm="'+ li.attr('uni_nm') +'" class="on"><a href="#">'+ fieldName +'</a></li>');
				    isDeletedDataItem = false;
				    selectedDataItem = li.attr('dataitem');
				    self.dimensionSortByField=undefined;
				}else{
				    addMeasure = $('<li id="'+ li.attr('dataitem') +'" dataitem="'+ li.attr('dataitem') +'" uni_nm="'+ li.attr('uni_nm') +'"><a href="#">'+ fieldName +'</a></li>');	
				}
//				addMeasure = $('<li id="'+ li.attr('dataitem') +'" dataitem="'+ li.attr('dataitem') +'" uni_nm="'+ li.attr('uni_nm') +'"><a href="#">'+ fieldName +'</a></li>');
			}
			dataItem.find('.measureList').append(addMeasure);
		});

//		if(selectedDataItem == '' || isDeletedDataItem){
//			$(dataItem.find('.measureList').children().get(0)).addClass('on');
//		}
		/*dogfoot 차원 행열 이동시 정렬기준 값 가져가도록 수정 shlim 20210402*/
		if(selectedDataItem == '' || isDeletedDataItem){
			$(dataItem.find('.measureList').children().get(0)).addClass('on');
		}else{
			$(dataItem.find('.measureList').children().get(0)).removeClass('on');
		}
		// mksong 2019.12.20 sort By 오류 수정 끝 dogfoot

		$('.measureList').children().off('click').click(function(e){
			e.preventDefault();
			$(e.target).parent().parent().children('.on').toggleClass('on');
			$(e.target).parent().addClass('on');
		});

	};

	this.synchronizeAddressTypeList = function(_dataItem, _addressType){
		var dataItem = $(_dataItem).parent().parent();

		$('.addressTypeList').children().off('click').click(function(e){
			e.preventDefault();
			$(e.target).parent().parent().children('.on').toggleClass('on');
			$(e.target).parent().addClass('on');
			$(dataItem).attr('addressType', $(dataItem.find('.addressTypeList').children('.on')).attr('addressType'));
		});

		if(_addressType != undefined){
			dataItem.find('.addressTypeList').children('[addressType="'+_addressType+'"]').click();
		}
	};


	this.draggableOptions = {
		connectToSortable: '.connectedSortableList',
//		appendTo: WISE.Context.isCubeReport ? document.body : '#column-selector',
		appendTo: document.body,
		helper: 'clone',
		revertDuration : 300,
		scroll: false,
		zIndex: 10000,
		start: function(_event, _ui) {
			$('.divide-menu .other-menu-ico').css('display','none');

			//2020.03.02 MKSONG self.item undefined 오류 수정 DOGFOOT
			self.item = gDashboard.itemGenerateManager.focusedItem;

			self.itemData = undefined;
			self.itemFormat = undefined;

			$('.drop-down li > a.on').removeClass('on');

			var ToArray = WISE.util.Object.toArray;
//			var deltaColumns = gDashboard.structure['REPORT_XML']['DELTAVALUE_ELEMENT'] ? ToArray(gDashboard.structure['REPORT_XML']['DELTAVALUE_ELEMENT']['DELTA_VALUE']) : [];

			var isDeltaSource = false;
			var referencedDeltaCaptions = '';
//			_.each(deltaColumns, function(_delta) {
//				if (_delta['BASE_UNI_NM'] === $(_ui.helper).data('field-uname')) {
//					isDeltaSource = true;
//					referencedDeltaCaptions += _delta['CAPTION'] + ',';
//				}
//			});
			if (referencedDeltaCaptions) referencedDeltaCaptions = referencedDeltaCaptions.substring(0, referencedDeltaCaptions.length - 1);

			var helperWidth = parseInt($(this).css('width'), 10) + 'px';
//			var helperHeight = parseInt($(this).css('height'), 10)*2 + 'px';
			var helperHeight = '31px';
				$(_ui.helper).css('width', helperWidth);
				$(_ui.helper).css('height', helperHeight);
				$(_ui.helper).children('.ico').css('color','#7d8291');
			if($(_ui.helper).children('.btn.neutral').length > 0){
				$(_ui.helper).children('.btn.neutral').removeClass('btn neutral');
				$(_ui.helper).children().remove('.other-menu-ico');
			}else{
				$(_ui.helper).css('width', helperWidth);
				$(_ui.helper).css('height', helperHeight).addClass('btn neutral');

				if($(_ui.helper).attr('prev-container') == 'allList'){
//					$(_ui.helper).wrap('<ul class="display-unmove more analysis-data sortable"/>');
				}
			}
			$(this)
				.css('width', helperWidth)
				.data('cannot-move', false);

			var draggableParent = $(this).parent();

			if (isDeltaSource) {
				$(this)
					.attr('data-delta-source', true)
					.attr('data-delta-referenced', referencedDeltaCaptions)
					.addClass('wise-area-field wise-drag');
			}
			else {
//				draggableParent.addClass('wise-area-drop-over');

//				$(this)
//					.draggable("option", "revert", false)
//					.attr('data-delta-source', false)
//					.addClass('wise-area-field wise-drag wise-area-drop-over wise-field-leaf');
				$(this).draggable("option", "revert", false);
				$(this).attr('data-delta-source', false);
				$(this).clone().addClass('wise-area-field wise-drag wise-field-leaf');
//				$(this).addClass('wise-area-field wise-drag wise-area-drop-over wise-field-leaf');

				/* 홍유한
				 $(this)
					.draggable("option", "revert", false)
					.addClass('wise-drag')
					.attr('data-delta-source', false)
					.attr('data-prevList',$(this).parent().attr('id'))
					.attr('style','display:none;');*/

				//2020.02.26 MKSONG 필드 드롭 가능한 지역 css 수정 DOGFOOT

				var itemType;

				if($(_ui.helper).attr('originType')){
					itemType = $(_ui.helper).attr('originType');
				}else {
					itemType = $(_ui.helper).data('fieldType');
				}
				/* DOGFOOT ktkang 단일테이블 필터 기능 추가 20200717 */
				var $dataSetLookUp = $("#dataSetLookUp");
				
				if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
					$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
				}
				var lookUpIns = $dataSetLookUp.dxLookup('instance');
				var focusDs = lookUpIns.option('value');
				var singleTable = false;
				if(WISE.Constants.editmode == "viewer" && ((userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && gDashboard.reportType == "DashAny") || gDashboard.reportType == 'DSViewer') || (WISE.Constants.editmode == "viewer" && $("#dataArea_" + WISE.Constants.pid +" #dataSetLookUp.dx-textbox").length == 0)){
					var dataset = gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.focusedItem.dataSourceId]
					if(dataset.DATASET_TYPE == "DataSetSingleDs" || dataset.DATASET_TYPE == "DataSetSingleDsView") {
						singleTable = true;
					}					
				}else{
					/* DOGFOOT ktkang 단일테이블 필터 기능 추가 20200717 */
					var lookUpIns = $("#dataSetLookUp").dxLookup('instance');
					var focusDs = lookUpIns.option('value');
					$.each(gDashboard.datasetMaster.state.datasets, function(_i,_o){
						if(_o.DATASET_TYPE == "DataSetSingleDs" || _o.DATASET_TYPE == "DataSetSingleDsView") {
							if(_o.DATASET_NM == focusDs) {
								singleTable = true;
							}
						}
					});
				}

				if(WISE.Context.isCubeReport || gDashboard.reportType == 'AdHoc'){
					if(itemType == 'measure'){
						$('.drop-data').addClass('focus-use');
						/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
						$('.drop-hiddendata').addClass('focus-use');
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}else{
						//2020.03.02 MKSONG 그룹별 데이터 항목 추가 기능 DOGFOOT
						if((WISE.Context.isCubeReport && !$(_ui.helper).hasClass('wise-field-group')) || singleTable){
							/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
							if(WISE.Constants.editmode == 'viewer') {
								$('.filter-row').addClass('focus-use');
							} else {
								$('.filter-bar').addClass('focus-use');
							}
						}
						$('.drop-column').addClass('focus-use');
						$('.drop-row').addClass('focus-use');
						/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
						$('.drop-hiddendata').addClass('focus-use');
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				}else if((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType !== 'DSViewer')){
					//2020.04.23 AJKIM 필드 드롭 가능한 지역 대시보드 적용 DOGFOOT
					if(itemType == 'measure'){
						$('.drop-data').addClass('focus-use');
						/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
						$('.drop-hiddendata').addClass('focus-use');
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}else{
					/* DOGFOOT ktkang 단일테이블 필터 기능 추가 20200717 */
						if((WISE.Context.isCubeReport && !$(_ui.helper).hasClass('wise-field-group')) || singleTable){
							/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
							if(WISE.Constants.editmode == 'viewer') {
								$('.filter-row').addClass('focus-use');
							} else {
								$('.filter-bar').addClass('focus-use');
							}
						}

						$('.drop-dimension').addClass('focus-use');
						$('.drop-hiddendata').addClass('focus-use');
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}
				}
			}
		},
		stop: function(_event, _ui) {
			$('.other-menu-ico').css('display','block');
			// 고용정보원09 싱글뷰 일때만 display가 나오는데 .other-menu-ico block 해주면서 다 나타남
			if(typeof gDashboard.isSingleView == 'undefined' || gDashboard.isSingleView == false){
				$('#viewerDownload').css('display','none');
				$('#viewerAdhoc').css('display','none');
			}
			
			/*dogfoot 뷰어 연결보고서 없는 보고서 버튼 표시안하도록 수정 shlim 20200731*/
			if(gDashboard.structure.linkReport.length != 0){
				$('.connectR').attr('style','opacity: 1 !important');
				/* DOGFOOT ktkang 뷰어에서 연결보고서 없을 때 숨김  20200525 */
				$('.connectR').css('display', 'block');
			}else{
				$('.connectR').attr('style','opacity: .7 !important');
				$('.connectR').css('display', 'none');
			}
//			draggableParent.removeClass('wise-area-drop-over');
			$(this)
				.attr('style','position: relative;')
//				.appendTo($('#'+$(this).attr('data-prevList')))
				.removeClass('wise-drag wise-area-drop-over')
				.removeAttr('data-delta-source')
				.removeAttr('data-delta-referenced')
				.removeAttr('data-cannot-move')
				.removeAttr('data-prevList');

			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
			var $dataSetLookUp = $("#dataSetLookUp");
			
			if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
				$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
			}
			var lookUpIns = $dataSetLookUp.dxLookup('instance');
			var focusDs = lookUpIns.option('value');
			var singleTable = false;
			if(WISE.Constants.editmode == "viewer" && ((userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && gDashboard.reportType == "DashAny") || gDashboard.reportType == 'DSViewer') || (WISE.Constants.editmode == "viewer" && $("#dataArea_" + WISE.Constants.pid +" #dataSetLookUp.dx-textbox").length == 0)){
				var dataset = gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.focusedItem.dataSourceId]
				if(dataset.DATASET_TYPE == "DataSetSingleDs" || dataset.DATASET_TYPE == "DataSetSingleDsView") {
					singleTable = true;
				}					
			}else{
				/* DOGFOOT ktkang 단일테이블 필터 기능 추가 20200717 */
				var lookUpIns = $("#dataSetLookUp").dxLookup('instance');
				var focusDs = lookUpIns.option('value');
				$.each(gDashboard.datasetMaster.state.datasets, function(_i,_o){
					if(_o.DATASET_TYPE == "DataSetSingleDs" || _o.DATASET_TYPE == "DataSetSingleDsView") {
						if(_o.DATASET_NM == focusDs) {
							singleTable = true;
						}
					}
				});
			}

			if((WISE.Context.isCubeReport || gDashboard.reportType == 'AdHoc') || singleTable){
				$('.drop-data').removeClass('focus-use');
				$('.drop-column').removeClass('focus-use');
				$('.drop-row').removeClass('focus-use');
				/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
				if(WISE.Constants.editmode == 'viewer') {
					$('.filter-row').removeClass('focus-use');
				} else {
					$('.filter-bar').removeClass('focus-use');
				}
				/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
				$('.drop-hiddendata').removeClass('focus-use');

				//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
				if(WISE.Constants.editmode === 'viewer'){
					$('#allList.scrollbar').dxScrollView('instance').option('disabled', false);
					$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
				}else{
					$('#allList .scrollbar').dxScrollView('instance').option('disabled', false);
					$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
				}
			/*dogfoot 통계 분석 추가 shlim 20201102*/
			}else if((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer')){

				$('.drop-data').removeClass('focus-use');
				$('.drop-dimension').removeClass('focus-use');
				$('.drop-hiddendata').removeClass('focus-use');
				$('.drop-hiddendata').removeClass('focus-use');
				if(WISE.Context.isCubeReport || singleTable) {
					if(WISE.Constants.editmode == 'viewer') {
						$('.filter-row').removeClass('focus-use');
					} else {
						$('.filter-bar').removeClass('focus-use');
					}
				}

				if(WISE.Constants.editmode === 'viewer'){
					$('#allList.scrollbar').dxScrollView('instance').option('disabled', false);
					$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
				}else{
					$('#allList .scrollbar').dxScrollView('instance').option('disabled', false);
					$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
				}
			}
			//2020.07.30 MKSONG DOGFOOT 델타 이동시 z-index 오류 수정
			$(_ui.helper).css('z-index','auto');
		}
	};
	/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
	this.draggableOptionsDE = {
			connectToSortable: '.connectedSortableListDE',
//			appendTo: WISE.Context.isCubeReport ? document.body : '#column-selector',
			appendTo: document.body, 
			helper: 'clone',
			revertDuration : 300,
			scroll: false,
			zIndex: 10000,
			start: function(_event, _ui) {
				$('.divide-menu .other-menu-ico').css('display','none');

				//2020.03.02 MKSONG self.item undefined 오류 수정 DOGFOOT
				self.item = gDashboard.itemGenerateManager.focusedItem;

				self.itemData = undefined;
				self.itemFormat = undefined;

				$('.drop-down li > a.on').removeClass('on');

				var ToArray = WISE.util.Object.toArray;
//				var deltaColumns = gDashboard.structure['REPORT_XML']['DELTAVALUE_ELEMENT'] ? ToArray(gDashboard.structure['REPORT_XML']['DELTAVALUE_ELEMENT']['DELTA_VALUE']) : [];

				var isDeltaSource = false;
				var referencedDeltaCaptions = '';
//				_.each(deltaColumns, function(_delta) {
//				if (_delta['BASE_UNI_NM'] === $(_ui.helper).data('field-uname')) {
//				isDeltaSource = true;
//				referencedDeltaCaptions += _delta['CAPTION'] + ',';
//				}
//				});
				if (referencedDeltaCaptions) referencedDeltaCaptions = referencedDeltaCaptions.substring(0, referencedDeltaCaptions.length - 1);

				var helperWidth = parseInt($(this).css('width'), 10) + 'px';
//				var helperHeight = parseInt($(this).css('height'), 10)*2 + 'px';
				var helperHeight = '31px';
				$(_ui.helper).css('width', helperWidth);
				$(_ui.helper).css('height', helperHeight);
				$(_ui.helper).children('.ico').css('color','#7d8291');
				if($(_ui.helper).children('.btn.neutral').length > 0){
					$(_ui.helper).children('.btn.neutral').removeClass('btn neutral');
					$(_ui.helper).children().remove('.other-menu-ico');	
				}else{
					$(_ui.helper).css('width', helperWidth);
					$(_ui.helper).css('height', helperHeight).addClass('btn neutral');

					if($(_ui.helper).attr('prev-container') == 'allList'){
//						$(_ui.helper).wrap('<ul class="display-unmove more analysis-data sortable"/>');
					}
				}
				$(this)
				.css('width', helperWidth)
				.data('cannot-move', false);

				var draggableParent = $(this).parent();

				if (isDeltaSource) {
					$(this)
					.attr('data-delta-source', true)
					.attr('data-delta-referenced', referencedDeltaCaptions)
					.addClass('wise-area-field-de wise-drag');
				}
				else {
//					draggableParent.addClass('wise-area-drop-over');

//					$(this)
//					.draggable("option", "revert", false)
//					.attr('data-delta-source', false)
//					.addClass('wise-area-field wise-drag wise-area-drop-over wise-field-leaf');
					$(this).draggable("option", "revert", false);
					$(this).attr('data-delta-source', false);
					$(this).clone().addClass('wise-area-field-de wise-drag wise-field-leaf');
//					$(this).addClass('wise-area-field wise-drag wise-area-drop-over wise-field-leaf');

					/* 홍유한
					 $(this)
						.draggable("option", "revert", false)
						.addClass('wise-drag')
						.attr('data-delta-source', false)
						.attr('data-prevList',$(this).parent().attr('id'))
						.attr('style','display:none;');*/

					//2020.02.26 MKSONG 필드 드롭 가능한 지역 css 수정 DOGFOOT

					var itemType;

					if($(_ui.helper).attr('originType')){
						itemType = $(_ui.helper).attr('originType');
					}else {
						itemType = $(_ui.helper).data('fieldType');
					}

					var singleTable = gDashboard.singeTableDE;

					if(WISE.Context.isCubeReport || gDashboard.reportType == 'AdHoc'){
						if(itemType == 'measure'){
							$('.drop-data').addClass('focus-use');
							/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
							$('.drop-hiddendata').addClass('focus-use');
							//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
							if(WISE.Constants.editmode === 'viewer'){
								$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
								$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
							}else{
								$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
								$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
							}
						}else{
							//2020.03.02 MKSONG 그룹별 데이터 항목 추가 기능 DOGFOOT
							if((WISE.Context.isCubeReport && !$(_ui.helper).hasClass('wise-field-group')) || singleTable){
								/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
								if(WISE.Constants.editmode == 'viewer') {
									$('.filter-row').addClass('focus-use');	
								} else {
									$('.filter-bar').addClass('focus-use');	
								}
							}
							$('.drop-column').addClass('focus-use');
							$('.drop-row').addClass('focus-use');
							/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
							$('.drop-hiddendata').addClass('focus-use');
							//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
							if(WISE.Constants.editmode === 'viewer'){
								$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
								$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
							}else{
								$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
								$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
							}
						}
						/*dogfoot 통계 분석 추가 shlim 20201102*/	
					}else if((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType !== 'DSViewer')){
						//2020.04.23 AJKIM 필드 드롭 가능한 지역 대시보드 적용 DOGFOOT
						if(itemType == 'measure'){
							$('.drop-data').addClass('focus-use');
							/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
							$('.drop-hiddendata').addClass('focus-use');
							//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
							if(WISE.Constants.editmode === 'viewer'){
								$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
								$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
							}else{
								$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
								$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
							}
						}else{
							/* DOGFOOT ktkang 단일테이블 필터 기능 추가 20200717 */
							if((WISE.Context.isCubeReport && !$(_ui.helper).hasClass('wise-field-group')) || singleTable){
								/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
								if(WISE.Constants.editmode == 'viewer') {
									$('.filter-row').addClass('focus-use');	
								} else {
									$('.filter-bar').addClass('focus-use');	
								}
							}

							$('.drop-dimension').addClass('focus-use');
							$('.drop-hiddendata').addClass('focus-use');
							//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
							if(WISE.Constants.editmode === 'viewer'){
								$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
								$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
							}else{
								$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
								$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
							}
						}	
					}
				}
			},
			stop: function(_event, _ui) {
				$('.other-menu-ico').css('display','block');
				/*dogfoot 뷰어 연결보고서 없는 보고서 버튼 표시안하도록 수정 shlim 20200731*/
				if(gDashboard.structure.linkReport.length != 0){
					$('.connectR').attr('style','opacity: 1 !important');
					/* DOGFOOT ktkang 뷰어에서 연결보고서 없을 때 숨김  20200525 */
					$('.connectR').css('display', 'block');
				}else{
					$('.connectR').attr('style','opacity: .7 !important');
					$('.connectR').css('display', 'none');
				}
//				draggableParent.removeClass('wise-area-drop-over');
				$(this)
				.attr('style','position: relative;')
//				.appendTo($('#'+$(this).attr('data-prevList')))
				.removeClass('wise-drag wise-area-drop-over')
				.removeAttr('data-delta-source')
				.removeAttr('data-delta-referenced')
				.removeAttr('data-cannot-move')
				.removeAttr('data-prevList');

				var singleTable = gDashboard.singeTableDE;

				if((WISE.Context.isCubeReport || gDashboard.reportType == 'AdHoc') || singleTable){
					$('.drop-data').removeClass('focus-use');
					$('.drop-column').removeClass('focus-use');
					$('.drop-row').removeClass('focus-use');
					/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
					if(WISE.Constants.editmode == 'viewer') {
						$('.filter-row').removeClass('focus-use');	
					} else {
						$('.filter-bar').removeClass('focus-use');	
					}
					/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
					$('.drop-hiddendata').removeClass('focus-use');

					//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
					if(WISE.Constants.editmode === 'viewer'){
						$('#allList.scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}else{
						$('#allList .scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}
					/*dogfoot 통계 분석 추가 shlim 20201102*/
				}else if((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer')){

					$('.drop-data').removeClass('focus-use');
					$('.drop-dimension').removeClass('focus-use');
					$('.drop-hiddendata').removeClass('focus-use');
					$('.drop-hiddendata').removeClass('focus-use');
					if(WISE.Context.isCubeReport || singleTable) {
						if(WISE.Constants.editmode == 'viewer') {
							$('.filter-row').removeClass('focus-use');	
						} else {
							$('.filter-bar').removeClass('focus-use');	
						}
					}

					if(WISE.Constants.editmode === 'viewer'){
						$('#allList.scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}else{
						$('#allList .scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}
				}	
				//2020.07.30 MKSONG DOGFOOT 델타 이동시 z-index 오류 수정
				$(_ui.helper).css('z-index','auto');
			}
	};
	
	this.droppableOptionsDE = {
			accept: '.wise-area-field-de',
			tolerance: 'pointer',
			deactivate: function(_event, _ui) {
				$(this).removeClass("wise-area-drop-over");
			},
			drop: function(_event, _ui) {
				var fieldFilter = new WISE.libs.Dashboard.FieldFilter();	
				
				var divideMenu = $(_ui.helper).children('.divide-menu');
				/* DOGFOOT ktkang 주제영역 중복체크 기능 개선  20200308 */
				var dupleCheck = false;
				
				var container = $(this).attr('id');
				//2020.02.19 MKSONG 필드 드롭 가능한 지역 BORDER 추가 위해 불필요한 부분 제거 DOGFOOT
				
				if (_ui.draggable) _ui.draggable.removeClass("wise-area-drop-over");
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				var containerType = container.substring(0,container.lastIndexOf('t')+1);
				
				var targetContainer;
				
				/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
				var cubeInsertYN = true;
				
				if (_ui.draggable.data('delta-source')) {
					$(_ui.draggable).draggable("option", "revert", true);
					WISE.alert(gMessage.get('WISE.message.page.widget.pivot.exist.referenced.fileds', [_ui.draggable.data('delta-referenced')]));
				} else if($(this).hasClass('drop-target')){
					targetContainer = $('#'+container);
					container = 'delta-drop';
				} else if (_ui.draggable.data('cannot-move')) {
//					$(_ui.draggable).draggable("option", "revert", true);
					$(_ui.helper).remove();
				} else if (container === 'downloadexpand_colList'){
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
					if($(_ui.draggable).hasClass('wise-field-group')){
						$.each($(_ui.helper).find('.dataset').children(),function(_i,_dataItem){
							if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
								dupleCheck = self.duplicatedCheck(container,$(_dataItem));
							} 
							/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
							if(dupleCheck) {
								cubeInsertYN = false;
							}
						});
					}else {
						dupleCheck = self.duplicatedCheck(container,$(_ui.helper));

						if(dupleCheck) {
							cubeInsertYN = false;
						}
					}
					targetContainer = $('#' + container);

					_ui.draggable.removeClass("wise-field-leaf");
					_ui.draggable.removeClass("wise-no-border");
				}
				//필터
				else if (container === 'filter-bar' || container === 'filter-row'){
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
					var $dataSetLookUp = $("#dataSetLookUp");
					
					if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
						$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
					}
					var lookUpIns = $dataSetLookUp.dxLookup('instance');
					var focusDs = lookUpIns.option('value');
					var singleTable = gDashboard.singeTableDE;

					if((typeof WISE.Context.isCubeReport != 'undefined' && WISE.Context.isCubeReport)) {
						if(_ui.draggable.attr('data-field-type') === 'dimension' && !_ui.draggable.hasClass('wise-field-group') && _ui.draggable.children().length == 1) {
							gProgressbar.show();
							/* DOGFOOT 20201021 ajkim setTimeout 제거*/
							fieldFilter.addFilter(_ui.draggable.clone());
				  
						} else {
							//2020.03.07 MKSONG 필터 그룹 필드 드롭 방지 DOGFOOT
							if(_ui.draggable.hasClass('wise-field-group')){
								//2020.03.09 MKSONG 문구 수정 DOGFOOT
								if(_ui.draggable.attr('data-field-type') == 'measure'){
									WISE.alert('해당 영역에 측정값 그룹을<br>올리실 수 없습니다.');
								}else{
									WISE.alert('해당 영역에 차원그룹을<br>올리실 수 없습니다.');	
								}
								/* DOGFOOT ktkang 주제영역에서 필터 추가 시 오류 수정  20200310 */
							} else if(_ui.draggable.children().length == 2) {
								WISE.alert('필터를 사용하실 때에는 데이터 원본에 있는 차원을 사용하시기 바랍니다.');
							} else{
								WISE.alert('주제영역에서 필터를 사용하실 때에는 차원만 사용하실 수 있습니다.');
							}
						}
					} else if(singleTable != "") {
						if(_ui.draggable.attr('data-field-type') === 'dimension' && !_ui.draggable.hasClass('wise-field-group') && _ui.draggable.children().length == 1) {
							gProgressbar.show();
							/* DOGFOOT 20201021 ajkim setTimeout 제거*/
							fieldFilter.addFilterSingle(_ui.draggable.clone(), singleTable);
				  
						} else {
							//2020.03.07 MKSONG 필터 그룹 필드 드롭 방지 DOGFOOT
							if(_ui.draggable.hasClass('wise-field-group')){
								//2020.03.09 MKSONG 문구 수정 DOGFOOT
								if(_ui.draggable.attr('data-field-type') == 'measure'){
									WISE.alert('해당 영역에 측정값 그룹을<br>올리실 수 없습니다.');
								}else{
									WISE.alert('해당 영역에 차원그룹을<br>올리실 수 없습니다.');	
								}
								/* DOGFOOT ktkang 주제영역에서 필터 추가 시 오류 수정  20200310 */
							} else if(_ui.draggable.children().length == 2) {
								WISE.alert('필터를 사용하실 때에는 데이터 원본에 있는 차원을 사용하시기 바랍니다.');
							} else{
								WISE.alert('주제영역에서 필터를 사용하실 때에는 차원만 사용하실 수 있습니다.');
							}
						}
					} else {
						$(_ui.helper).remove();
					}
				}
				//필터

				gDashboard.fieldManager.isChange = true;
				/*if (container !== _ui.draggable.attr('data-prevList')){
					self.fieldManager.isChange = true;
				}*/
				 
				var prevContainer = _ui.draggable.attr('prev-container');
				var dataItem = _ui.helper;
				
				if(targetContainer != undefined){			
					// 계산필드인지 확인
					var customFieldFlag = false;
					var customFieldInfo = gDashboard.customFieldManager.fieldInfo;
					if(!($.isEmptyObject(customFieldInfo))) {
						$.each(gDashboard.customFieldManager.fieldInfo[_ui.helper.attr('data-source-id')],function(i,item){
							if(item.Name==_ui.helper.attr('uni_nm')) customFieldFlag = true;
						});			
					}
					
					var dataItem = _ui.helper;
					/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
					if(cubeInsertYN) {
						if(dataItem.hasClass('wise-field-group')){
							$.each(dataItem.find('.dataset').children(),function(_i,_dataItem){
								if(_i == 0){
									/* DOGFOOT ktkang 주제영역에서 항목 추가시 오류 수정  20200404 */
									if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
										self.dataItemSetting('drop', $(_ui.draggable), $(_dataItem), container, prevContainer, targetContainer, self.item, 'single');
									}
								}else{
									if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
										self.dataItemSetting('drop', $(_ui.draggable), $(_dataItem), container, prevContainer, targetContainer, self.item, 'multiple');
									}
								}

							});
							dataItem.remove();
						}else{
//							if(customFieldFlag && container.indexOf('ValueList')<0 && container.indexOf('dataAdHocList')<0 && container.indexOf('dataList')<0  && container.indexOf('columnList')<0 && container != 'allList'){
//								$(_ui.helper).remove();
//								WISE.alert('사용자 정의 데이터는<br>측정값 외에 넣을 수 없습니다.');
//							}else{
								if(container == 'delta-drop'){
									$(_ui.helper).addClass('selected');
								}
								self.dataItemSetting('drop', _ui.draggable, dataItem, container, prevContainer, targetContainer, self.item, 'single');
//							}	
						}
					}
				}
				/* DOGFOOT ktkang 주제영역 관계 표시 부분 오류 수정  20200305 */
				if(WISE.Context.isCubeReport && _ui.draggable.attr('data-field-type') === 'measure'){
					self.cubeRelationCheck(_item);
				}
			},
			over: function(_event, _ui) {
				if($(_ui.helper).hasClass('other-menu-ico') && $(_ui.helper).is('a')){
					$(_ui.helper).remove();
					$('.other-menu-ico').css('display','block');
					return;
				}else{
					$('.divide-menu .other-menu-ico').css('display','none');
				}
				compMoreMenuUi();
				
				var container = $(this).attr('id');
				var draggableType = _ui.draggable.attr('data-field-type');
				
				if(gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id') != undefined){
					if(_ui.draggable.attr('data-source-id') != gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id')){
						_ui.draggable.data('cannot-move', false);
					}
				}
			},
			out: function(_event, _ui) {

				//2020.02.19 MKSONG 필드 드롭 가능한 지역 BORDER 추가 DOGFOOT
				$(this).removeClass("focus-none");
				_ui.draggable.data('cannot-move', false);
//				}
				
			}
		};

	this.draggableOptions2 = {
			connectToSortable: '.connectedSortableList',
//			appendTo: WISE.Context.isCubeReport ? document.body : '#column-selector',
			appendTo: document.body,
			helper: 'clone',
			revertDuration : 300,
			scroll: false,
			zIndex: 10000,
			start: function(_event, _ui) {
				if($(_ui.helper).hasClass('other-menu-ico') && $(_ui.helper).is('a')){
					$(_ui.helper).remove();
					$('.other-menu-ico').css('display','block');
					return;
				}
				/*dogfoot 차원 행열 이동시 정렬기준 값 가져가도록 수정 shlim 20210402*/
				if(typeof $(this).parent().find('.measureList').find('.on').attr('dataItem') != undefined){
					self.dimensionSortByField = $(this).parent().find('.measureList').find('.on').attr('dataItem');
				}

				$('.divide-menu .other-menu-ico').css('display','none');

				//2020.03.02 MKSONG self.item undefined 오류 수정 DOGFOOT
				self.item = gDashboard.itemGenerateManager.focusedItem;

				if ($(this).find('.seriesoption').length > 0) {
					self.itemData = $(this).find('.seriesoption').data('dataItemOptions');
				} else {
					self.itemData = undefined;
				}
				if (typeof $(this).data('formatOptions') !== 'undefined') {
					self.itemFormat = $(this).data('formatOptions');
				} else {
					self.itemFormat = undefined;
				}

				if($(_ui.helper.prevObject).attr('datatype') == 'delta' && !$(_ui.helper.prevObject).hasClass('delta-drop')){
					$(_ui.helper.prevObject).parent();
//					var actualField = $($(_ui.helper.prevObject).parent().children('li').get(0));
					var targetField = $($(_ui.helper.prevObject).parent().children('li').get(1));
					targetField.remove();
				}

				$(_ui.helper.prevObject).parent().children('.divide-menu').remove();

//				var divideMenu = $(_ui.helper.prevObject).parent().children('.divide-menu');
//				$(_ui.helper).append(divideMenu);

				if($(_ui.helper).attr('deltaid') != undefined){
					$(_ui.helper).attr('childrenLength',gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').children().length);
				}


				$('.drop-down li > a.on').removeClass('on');
				var ToArray = WISE.util.Object.toArray;
//				var deltaColumns = gDashboard.structure['REPORT_XML']['DELTAVALUE_ELEMENT'] ? ToArray(gDashboard.structure['REPORT_XML']['DELTAVALUE_ELEMENT']['DELTA_VALUE']) : [];

				var isDeltaSource = false;
				var referencedDeltaCaptions = '';
//				_.each(deltaColumns, function(_delta) {
//					if (_delta['BASE_UNI_NM'] === $(_ui.helper).data('field-uname')) {
//						isDeltaSource = true;
//						referencedDeltaCaptions += _delta['CAPTION'] + ',';
//					}
//				});
				if (referencedDeltaCaptions) referencedDeltaCaptions = referencedDeltaCaptions.substring(0, referencedDeltaCaptions.length - 1);

				$(this).find('.otherBtn').remove();
				var hasOtherBtn = _ui.helper.children('.otherBtn').length > 0 ? true : false;
				$(_ui.helper).children('.ico').css('color','#7d8291');
				if(hasOtherBtn){
					_ui.helper.children('.otherBtn').remove();
					_ui.helper.prevObject.unwrap('ul');
					_ui.helper.unwrap('ul');
					_ui.helper.removeClass('arrayUp other-menu');
					_ui.helper.addClass('btn neutral');
					_ui.helper.children('.btn').removeClass('btn neutral');
				}else{
					_ui.helper.prevObject.unwrap('ul');
					_ui.helper.unwrap('ul');
					_ui.helper.removeClass('arrayUp other-menu');
					_ui.helper.addClass('btn neutral');
					_ui.helper.children('.btn').removeClass('btn neutral');
				}


				var helperWidth = parseInt($(this).css('width'), 10) + 'px';
//				var helperHeight = parseInt($(this).css('height'), 10) + 'px';
				var helperHeight = '31px';
					$(_ui.helper).css('width', helperWidth);
					$(_ui.helper).css('height', helperHeight);
				if($(_ui.helper).children('.btn.neutral').length > 0){
//					$(_ui.helper).removeClass('btn neutral');
					$(_ui.helper).children().remove('.other-menu-ico');
				}else{
					$(_ui.helper).css('width', helperWidth);
					$(_ui.helper).css('height', helperHeight)//.addClass('btn neutral');

					if($(_ui.helper).attr('prev-container') == 'allList'){
//						$(_ui.helper).wrap('<ul class="display-unmove more analysis-data sortable"/>');
					}
				}
				$(this)
					.css('width', helperWidth)
					.data('cannot-move', false);

				var draggableParent = $(this).parent();

				if (isDeltaSource) {
					$(this)
						.attr('data-delta-source', true)
						.attr('data-delta-referenced', referencedDeltaCaptions)
						.addClass('wise-area-field wise-drag');
				}
				else {
//					draggableParent.addClass('wise-area-drop-over');

//					$(this)
//						.draggable("option", "revert", false)
//						.attr('data-delta-source', false)
//						.addClass('wise-area-field wise-drag wise-area-drop-over wise-field-leaf');
					$(this).draggable("option", "revert", false);
					$(this).attr('data-delta-source', false);
//					$(this).clone().addClass('wise-area-field wise-drag wise-field-leaf');
//					$(this).addClass('wise-area-field wise-drag wise-area-drop-over wise-field-leaf');

					/* 홍유한
					 $(this)
						.draggable("option", "revert", false)
						.addClass('wise-drag')
						.attr('data-delta-source', false)
						.attr('data-prevList',$(this).parent().attr('id'))
						.attr('style','display:none;');*/
				}

				var itemType;

				if($(_ui.helper).attr('originType')){
					itemType = $(_ui.helper).attr('originType');
				}else {
					itemType = $(_ui.helper).data('fieldType');
				}
				/* DOGFOOT ktkang 단일테이블 필터 기능 추가 20200717 */
				var $dataSetLookUp = $("#dataSetLookUp");
				
				if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
					$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
				}
				var lookUpIns = $dataSetLookUp.dxLookup('instance');
				var focusDs = lookUpIns.option('value');
				var singleTable = false;
				if(WISE.Constants.editmode == "viewer" && ((userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && gDashboard.reportType == "DashAny") || gDashboard.reportType == 'DSViewer') || (WISE.Constants.editmode == "viewer" && $("#dataArea_" + WISE.Constants.pid +" #dataSetLookUp.dx-textbox").length == 0)){
					var dataset = gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.focusedItem.dataSourceId]
					if(dataset.DATASET_TYPE == "DataSetSingleDs" || dataset.DATASET_TYPE == "DataSetSingleDsView") {
						singleTable = true;
					}					
				}else{
					/* DOGFOOT ktkang 단일테이블 필터 기능 추가 20200717 */
					var lookUpIns = $("#dataSetLookUp").dxLookup('instance');
					var focusDs = lookUpIns.option('value');
					$.each(gDashboard.datasetMaster.state.datasets, function(_i,_o){
						if(_o.DATASET_TYPE == "DataSetSingleDs" || _o.DATASET_TYPE == "DataSetSingleDsView") {
							if(_o.DATASET_NM == focusDs) {
								singleTable = true;
							}
						}
					});
				}

				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				if(WISE.Context.isCubeReport || gDashboard.reportType == 'AdHoc'){
					if(itemType == 'measure'){
						$('.drop-data').addClass('focus-use');
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}else{
						$('.drop-column').addClass('focus-use');
						$('.drop-row').addClass('focus-use');
						/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
						$('.drop-hiddendata').addClass('focus-use');
						//2020.03.02 MKSONG 그룹별 데이터 항목 추가 기능 DOGFOOT
						if(WISE.Context.isCubeReport && !$(_ui.helper).hasClass('wise-field-group') || singleTable){
							/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
							if(WISE.Constants.editmode == 'viewer') {
								$('.filter-row').addClass('focus-use');
							} else {
								$('.filter-bar').addClass('focus-use');
							}
						}
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				}else if((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer')){
					//2020.04.23 AJKIM 필드 드롭 가능한 지역 대시보드 적용 DOGFOOT
					if(itemType == 'measure'){
						$('.drop-data').addClass('focus-use');
						/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
						$('.drop-hiddendata').addClass('focus-use');
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}else{
						$('.drop-dimension').addClass('focus-use');
						$('.drop-hiddendata').addClass('focus-use');
						if((WISE.Context.isCubeReport && !$(_ui.helper).hasClass('wise-field-group')) || singleTable){
							/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
							if(WISE.Constants.editmode == 'viewer') {
								$('.filter-row').addClass('focus-use');
							} else {
								$('.filter-bar').addClass('focus-use');
							}
						}
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}
				}

				_ui.helper.prevObject.remove();
			},
			stop: function(_event, _ui) {
				$('.other-menu-ico').css('display','block');
				/*dogfoot 뷰어 연결보고서 없는 보고서 버튼 표시안하도록 수정 shlim 20200731*/
				if(gDashboard.structure.linkReport.length != 0){
					$('.connectR').attr('style','opacity: 1 !important');
					/* DOGFOOT ktkang 뷰어에서 연결보고서 없을 때 숨김  20200525 */
					$('.connectR').css('display', 'block');
				}else{
					$('.connectR').attr('style','opacity: .7 !important');
					$('.connectR').css('display', 'none');
				}
				if($(_ui.helper).hasClass('other-menu-ico') && $(_ui.helper).is('a')){
					$(_ui.helper).remove();

					return;
				}
				compMoreMenuUi();
				if($(_ui.helper).attr('deltaid') != undefined){
					var childLength = gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').children().length;
					if(Number($(_ui.helper).attr('childrenLength')) != childLength){
						var deltaId  = $(_ui.helper).attr('deltaid');
						var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//						var _item;
//						$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//							if(_o.ComponentName == itemId){
//								_item = _o;
//								return false;
//							}
//						});

						var _item = gDashboard.itemGenerateManager.dxItemBasten[1].deltaItems?
								gDashboard.itemGenerateManager.dxItemBasten[1] : gDashboard.itemGenerateManager.dxItemBasten[0];

						$.each(_item.deltaItems,function(_i,_delta){
							if(_delta.ID == deltaId){
								_item.deltaItems.splice(_i, 1);
								_item.deltaItemlength = _item.deltaItems.length;
								return false;
							}
						});

						if(_item.deltaItemlength === 0){
							$('#deltavalueList'+_item.adhocIndex).parent().css('display', 'none')
						}
					}
				}


//				draggableParent.removeClass('wise-area-drop-over');
//				if($(_ui.helper).attr('deltaid') != undefined){
//					if(gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').length > 0){
//						if(Math.abs(_event.offsetX) > gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').width()/2){
//							var deltaId  = $(_ui.helper).attr('deltaid');
//
//							var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//							var _item;
//							$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//								if(_o.ComponentName == itemId){
//									_item = _o;
//									return false;
//								}
//							});
//
//							$.each(_item.deltaItems,function(_i,_delta){
//								if(_delta.ID == deltaId){
//									_item.deltaItems.splice(_i, 1);
//									_item.deltaItemlength--;
//									return false;
//								}
//							});
//						}
//					}
//
//				}
//
//				if($(_ui.helper).attr('deltaid') != undefined){
//					if(gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').length > 0){
//						if(gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children(_ui.helper).index() != -1){
//							var height;
//							if(gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').length-1 == 0){
//								height = gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').height()+31;
//
//								if(Math.abs(_event.offsetY) > height / 2){
//
//									var deltaId  = $(_ui.helper).attr('deltaid');
//
//									var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//									var _item;
//									$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//										if(_o.ComponentName == itemId){
//											_item = _o;
//											return false;
//										}
//									});
//
//									$.each(_item.deltaItems,function(_i,_delta){
//										if(_delta.ID == deltaId){
//											_item.deltaItems.splice(_i, 1);
//											_item.deltaItemlength--;
//											return false;
//										}
//									});
//								}
//
//							}else{
//								if(_event.offsetY + gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').height() > gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel')-31){
//
//									var deltaId  = $(_ui.helper).attr('deltaid');
//
//									var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//									var _item;
//									$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//										if(_o.ComponentName == itemId){
//											_item = _o;
//											return false;
//										}
//									});
//
//									$.each(_item.deltaItems,function(_i,_delta){
//										if(_delta.ID == deltaId){
//											_item.deltaItems.splice(_i, 1);
//											_item.deltaItemlength--;
//											return false;
//										}
//									});
//								}
//							}
//
//
//						}
//
//					}
//				}


				var currentContainer = $(_ui.helper).attr('prev-container');
				if(currentContainer != undefined){
					if($('#'+currentContainer).children().length == 0){
						if(gDashboard.fieldManager.stateFieldChooser.children().find('.other-menu-ico').length == 0){
							gDashboard.fieldManager.stateFieldChooser.children().removeAttr('data-source-id');
						}

						if(currentContainer.indexOf('sparkLine') != -1 || currentContainer.indexOf('cardSpark') != -1){
							self.recovery($('#'+currentContainer));
						}else if(currentContainer.indexOf('deltavalueList') == -1){
							$('#'+currentContainer).droppable("enable").sortable('disable');
							//2020.03.02 MKSONG recovery 부분 함수화 DOGFOOT
							if(currentContainer != 'delta-drop'){
								self.recovery($('#'+currentContainer));
							}else{
								var actualfield;
								if(gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)] != undefined){
								    actualfield = gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].find('li[target-field-dataitem="'+$(_ui.helper).attr('dataitem')+'"]');
								    self.recoveryDataGridDelta(actualfield);
								}
								if(gDashboard.fieldManager.panelManager["rangebarchartValueContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)] != undefined){
									actualfield = gDashboard.fieldManager.panelManager["rangebarchartValueContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].find('li[target-field-dataitem="'+$(_ui.helper).attr('dataitem')+'"]');
									self.recoveryDataGridDelta(actualfield);
								}
								if(gDashboard.fieldManager.panelManager["rangeareachartValueContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)] != undefined){
									actualfield = gDashboard.fieldManager.panelManager["rangeareachartValueContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].find('li[target-field-dataitem="'+$(_ui.helper).attr('dataitem')+'"]');
									self.recoveryDataGridDelta(actualfield);
								}
							}
						}
					}
				}


/*				if($(_ui.helper).attr('deltaid') != undefined){
					var deltaId  = $(_ui.helper).attr('deltaid');

					var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
					var _item;
					$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
						if(_o.ComponentName == itemId){
							_item = _o;
							return false;
						}
					});

					$.each(_item.deltaItems,function(_i,_delta){
						if(_delta.ID == deltaId){
							_item.deltaItems.splice(_i, 1);
							_item.deltaItemlength--;
							return false;
						}
					});
				}*/
				$(this)
					.attr('style','position: relative;')
//					.appendTo($('#'+$(this).attr('data-prevList')))
					.removeClass('wise-drag wise-area-drop-over')
					.removeAttr('data-delta-source')
					.removeAttr('data-delta-referenced')
					.removeAttr('data-cannot-move')
					.removeAttr('data-prevList');

				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				if(WISE.Context.isCubeReport || gDashboard.reportType == 'AdHoc'){
					$('.drop-data').removeClass('focus-use');
					$('.drop-column').removeClass('focus-use');
					$('.drop-row').removeClass('focus-use');
					//2020.04.06 MKSONG 필터 추가 영역 조정 DOGFOOT
					if(WISE.Constants.editmode == 'viewer') {
						$('.filter-row').removeClass('focus-use');
					} else {
						$('.filter-bar').removeClass('focus-use');
					}
					$('.drop-hiddendata').removeClass('focus-use');
					//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
					if(WISE.Constants.editmode === 'viewer'){
						$('#allList.scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}else{
						$('#allList .scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				}else if((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer')){
					$('.drop-data').removeClass('focus-use');
					$('.drop-dimension').removeClass('focus-use');
					$('.drop-hiddendata').removeClass('focus-use');
					$('.drop-hiddendata').removeClass('focus-use');
					//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
					if(WISE.Constants.editmode === 'viewer'){
						$('#allList.scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}else{
						$('#allList .scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}
				}
				//2020.07.30 MKSONG DOGFOOT 델타 이동시 z-index 오류 수정
				$(_ui.helper).css('z-index','auto');
			}
		};
	
	this.draggableOptionsDE2 = {
			connectToSortable: '.connectedSortableListDE',
//			appendTo: WISE.Context.isCubeReport ? document.body : '#column-selector',
			appendTo: document.body,
			helper: 'clone',
			revertDuration : 300,
			scroll: false,
			zIndex: 10000,
			start: function(_event, _ui) {
				if($(_ui.helper).hasClass('other-menu-ico') && $(_ui.helper).is('a')){
					$(_ui.helper).remove();
					$('.other-menu-ico').css('display','block');
					return;
				}

				$('.divide-menu .other-menu-ico').css('display','none');

				//2020.03.02 MKSONG self.item undefined 오류 수정 DOGFOOT
				self.item = gDashboard.itemGenerateManager.focusedItem;

				if ($(this).find('.seriesoption').length > 0) {
					self.itemData = $(this).find('.seriesoption').data('dataItemOptions');
				} else {
					self.itemData = undefined;
				}
				if (typeof $(this).data('formatOptions') !== 'undefined') {
					self.itemFormat = $(this).data('formatOptions');
				} else {
					self.itemFormat = undefined;
				}

				if($(_ui.helper.prevObject).attr('datatype') == 'delta' && !$(_ui.helper.prevObject).hasClass('delta-drop')){
					$(_ui.helper.prevObject).parent();
//					var actualField = $($(_ui.helper.prevObject).parent().children('li').get(0));
					var targetField = $($(_ui.helper.prevObject).parent().children('li').get(1));
					targetField.remove();
				}

				$(_ui.helper.prevObject).parent().children('.divide-menu').remove();

//				var divideMenu = $(_ui.helper.prevObject).parent().children('.divide-menu');
//				$(_ui.helper).append(divideMenu);

				if($(_ui.helper).attr('deltaid') != undefined){
					$(_ui.helper).attr('childrenLength',gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').children().length);
				}


				$('.drop-down li > a.on').removeClass('on');
				var ToArray = WISE.util.Object.toArray;
//				var deltaColumns = gDashboard.structure['REPORT_XML']['DELTAVALUE_ELEMENT'] ? ToArray(gDashboard.structure['REPORT_XML']['DELTAVALUE_ELEMENT']['DELTA_VALUE']) : [];

				var isDeltaSource = false;
				var referencedDeltaCaptions = '';
//				_.each(deltaColumns, function(_delta) {
//					if (_delta['BASE_UNI_NM'] === $(_ui.helper).data('field-uname')) {
//						isDeltaSource = true;
//						referencedDeltaCaptions += _delta['CAPTION'] + ',';
//					}
//				});
				if (referencedDeltaCaptions) referencedDeltaCaptions = referencedDeltaCaptions.substring(0, referencedDeltaCaptions.length - 1);

				$(this).find('.otherBtn').remove();
				var hasOtherBtn = _ui.helper.children('.otherBtn').length > 0 ? true : false;
				$(_ui.helper).children('.ico').css('color','#7d8291');
//				if(hasOtherBtn){
//					_ui.helper.children('.otherBtn').remove();
//					_ui.helper.prevObject.unwrap('ul');
//					_ui.helper.unwrap('ul');
//					_ui.helper.removeClass('arrayUp other-menu');
//					_ui.helper.addClass('btn neutral');
//					_ui.helper.children('.btn').removeClass('btn neutral');
//				}else{
					_ui.helper.prevObject.unwrap('ul');
					_ui.helper.unwrap('ul');
					_ui.helper.removeClass('arrayUp other-menu');
					_ui.helper.addClass('btn neutral');
					_ui.helper.children('.btn').removeClass('btn neutral');
//				}


				var helperWidth = parseInt($(this).css('width'), 10) + 'px';
//				var helperHeight = parseInt($(this).css('height'), 10) + 'px';
				var helperHeight = '31px';
					$(_ui.helper).css('width', helperWidth);
					$(_ui.helper).css('height', helperHeight);
				if($(_ui.helper).children('.btn.neutral').length > 0){
//					$(_ui.helper).removeClass('btn neutral');
					$(_ui.helper).children().remove('.other-menu-ico');
				}else{
					$(_ui.helper).css('width', helperWidth);
					$(_ui.helper).css('height', helperHeight)//.addClass('btn neutral');

					if($(_ui.helper).attr('prev-container') == 'allList'){
//						$(_ui.helper).wrap('<ul class="display-unmove more analysis-data sortable"/>');
					}
				}
				$(this)
					.css('width', helperWidth)
					.data('cannot-move', false);

				var draggableParent = $(this).parent();

				if (isDeltaSource) {
					$(this)
						.attr('data-delta-source', true)
						.attr('data-delta-referenced', referencedDeltaCaptions)
						.addClass('wise-area-field wise-drag');
				}
				else {
//					draggableParent.addClass('wise-area-drop-over');

//					$(this)
//						.draggable("option", "revert", false)
//						.attr('data-delta-source', false)
//						.addClass('wise-area-field wise-drag wise-area-drop-over wise-field-leaf');
					$(this).draggable("option", "revert", false);
					$(this).attr('data-delta-source', false);
//					$(this).clone().addClass('wise-area-field wise-drag wise-field-leaf');
//					$(this).addClass('wise-area-field wise-drag wise-area-drop-over wise-field-leaf');

					/* 홍유한
					 $(this)
						.draggable("option", "revert", false)
						.addClass('wise-drag')
						.attr('data-delta-source', false)
						.attr('data-prevList',$(this).parent().attr('id'))
						.attr('style','display:none;');*/
				}

				var itemType;

				if($(_ui.helper).attr('originType')){
					itemType = $(_ui.helper).attr('originType');
				}else {
					itemType = $(_ui.helper).data('fieldType');
				}

				var singleTable = gDashboard.singeTableDE;

				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				if(WISE.Context.isCubeReport || gDashboard.reportType == 'AdHoc'){
					if(itemType == 'measure'){
						$('.drop-data').addClass('focus-use');
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}else{
						$('.drop-column').addClass('focus-use');
						$('.drop-row').addClass('focus-use');
						/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
						$('.drop-hiddendata').addClass('focus-use');
						//2020.03.02 MKSONG 그룹별 데이터 항목 추가 기능 DOGFOOT
						if(WISE.Context.isCubeReport && !$(_ui.helper).hasClass('wise-field-group') || singleTable){
							/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
							if(WISE.Constants.editmode == 'viewer') {
								$('.filter-row').addClass('focus-use');
							} else {
								$('.filter-bar').addClass('focus-use');
							}
						}
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				}else if((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer')){
					//2020.04.23 AJKIM 필드 드롭 가능한 지역 대시보드 적용 DOGFOOT
					if(itemType == 'measure'){
						$('.drop-data').addClass('focus-use');
						/* DOGFOOT ktkang 차원 정렬기준 항목에 하이라이트  20200311 */
						$('.drop-hiddendata').addClass('focus-use');
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}else{
						$('.drop-dimension').addClass('focus-use');
						$('.drop-hiddendata').addClass('focus-use');
						if((WISE.Context.isCubeReport && !$(_ui.helper).hasClass('wise-field-group')) || singleTable){
							/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
							if(WISE.Constants.editmode == 'viewer') {
								$('.filter-row').addClass('focus-use');
							} else {
								$('.filter-bar').addClass('focus-use');
							}
						}
						//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
						if(WISE.Constants.editmode === 'viewer'){
							$('#allList.scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}else{
							$('#allList .scrollbar').dxScrollView('instance').option('disabled', true);
							$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', true);
						}
					}
				}

				_ui.helper.prevObject.remove();
			},
			stop: function(_event, _ui) {
				$('.other-menu-ico').css('display','block');
				/*dogfoot 뷰어 연결보고서 없는 보고서 버튼 표시안하도록 수정 shlim 20200731*/
				if(gDashboard.structure.linkReport.length != 0){
					$('.connectR').attr('style','opacity: 1 !important');
					/* DOGFOOT ktkang 뷰어에서 연결보고서 없을 때 숨김  20200525 */
					$('.connectR').css('display', 'block');
				}else{
					$('.connectR').attr('style','opacity: .7 !important');
					$('.connectR').css('display', 'none');
				}
				if($(_ui.helper).hasClass('other-menu-ico') && $(_ui.helper).is('a')){
					$(_ui.helper).remove();

					return;
				}
				compMoreMenuUi();
				if($(_ui.helper).attr('deltaid') != undefined){
					var childLength = gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').children().length;
					if(Number($(_ui.helper).attr('childrenLength')) != childLength){
						var deltaId  = $(_ui.helper).attr('deltaid');
						var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//						var _item;
//						$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//							if(_o.ComponentName == itemId){
//								_item = _o;
//								return false;
//							}
//						});

						var _item = gDashboard.itemGenerateManager.dxItemBasten[1].deltaItems?
								gDashboard.itemGenerateManager.dxItemBasten[1] : gDashboard.itemGenerateManager.dxItemBasten[0];

						$.each(_item.deltaItems,function(_i,_delta){
							if(_delta.ID == deltaId){
								_item.deltaItems.splice(_i, 1);
								_item.deltaItemlength = _item.deltaItems.length;
								return false;
							}
						});

						if(_item.deltaItemlength === 0){
							$('#deltavalueList'+_item.adhocIndex).parent().css('display', 'none')
						}
					}
				}


//				draggableParent.removeClass('wise-area-drop-over');
//				if($(_ui.helper).attr('deltaid') != undefined){
//					if(gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').length > 0){
//						if(Math.abs(_event.offsetX) > gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').width()/2){
//							var deltaId  = $(_ui.helper).attr('deltaid');
//
//							var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//							var _item;
//							$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//								if(_o.ComponentName == itemId){
//									_item = _o;
//									return false;
//								}
//							});
//
//							$.each(_item.deltaItems,function(_i,_delta){
//								if(_delta.ID == deltaId){
//									_item.deltaItems.splice(_i, 1);
//									_item.deltaItemlength--;
//									return false;
//								}
//							});
//						}
//					}
//
//				}
//
//				if($(_ui.helper).attr('deltaid') != undefined){
//					if(gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').length > 0){
//						if(gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children(_ui.helper).index() != -1){
//							var height;
//							if(gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').length-1 == 0){
//								height = gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').height()+31;
//
//								if(Math.abs(_event.offsetY) > height / 2){
//
//									var deltaId  = $(_ui.helper).attr('deltaid');
//
//									var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//									var _item;
//									$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//										if(_o.ComponentName == itemId){
//											_item = _o;
//											return false;
//										}
//									});
//
//									$.each(_item.deltaItems,function(_i,_delta){
//										if(_delta.ID == deltaId){
//											_item.deltaItems.splice(_i, 1);
//											_item.deltaItemlength--;
//											return false;
//										}
//									});
//								}
//
//							}else{
//								if(_event.offsetY + gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel').height() > gDashboard.fieldManager.stateFieldChooser.find('.wise-area-deltaval').children('.drop-panel')-31){
//
//									var deltaId  = $(_ui.helper).attr('deltaid');
//
//									var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//									var _item;
//									$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//										if(_o.ComponentName == itemId){
//											_item = _o;
//											return false;
//										}
//									});
//
//									$.each(_item.deltaItems,function(_i,_delta){
//										if(_delta.ID == deltaId){
//											_item.deltaItems.splice(_i, 1);
//											_item.deltaItemlength--;
//											return false;
//										}
//									});
//								}
//							}
//
//
//						}
//
//					}
//				}


				var currentContainer = $(_ui.helper).attr('prev-container');
				if(currentContainer != undefined){
					if($('#'+currentContainer).children().length == 0){
						if(gDashboard.fieldManager.stateFieldChooser.children().find('.other-menu-ico').length == 0){
							gDashboard.fieldManager.stateFieldChooser.children().removeAttr('data-source-id');
						}

						if(currentContainer.indexOf('sparkLine') != -1 || currentContainer.indexOf('cardSpark') != -1){
							self.recovery($('#'+currentContainer));
						}else if(currentContainer.indexOf('deltavalueList') == -1){
							$('#'+currentContainer).droppable("enable").sortable('disable');
							//2020.03.02 MKSONG recovery 부분 함수화 DOGFOOT
							if(currentContainer != 'delta-drop'){
								self.recovery($('#'+currentContainer));
							}else{
								var actualfield;
								if(gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)] != undefined){
								    actualfield = gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].find('li[target-field-dataitem="'+$(_ui.helper).attr('dataitem')+'"]');
								    self.recoveryDataGridDelta(actualfield);
								}
								if(gDashboard.fieldManager.panelManager["rangebarchartValueContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)] != undefined){
									actualfield = gDashboard.fieldManager.panelManager["rangebarchartValueContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].find('li[target-field-dataitem="'+$(_ui.helper).attr('dataitem')+'"]');
									self.recoveryDataGridDelta(actualfield);
								}
								if(gDashboard.fieldManager.panelManager["rangeareachartValueContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)] != undefined){
									actualfield = gDashboard.fieldManager.panelManager["rangeareachartValueContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].find('li[target-field-dataitem="'+$(_ui.helper).attr('dataitem')+'"]');
									self.recoveryDataGridDelta(actualfield);
								}
							}
						}
					}
				}


/*				if($(_ui.helper).attr('deltaid') != undefined){
					var deltaId  = $(_ui.helper).attr('deltaid');

					var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
					var _item;
					$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
						if(_o.ComponentName == itemId){
							_item = _o;
							return false;
						}
					});

					$.each(_item.deltaItems,function(_i,_delta){
						if(_delta.ID == deltaId){
							_item.deltaItems.splice(_i, 1);
							_item.deltaItemlength--;
							return false;
						}
					});
				}*/
				$(this)
					.attr('style','position: relative;')
//					.appendTo($('#'+$(this).attr('data-prevList')))
					.removeClass('wise-drag wise-area-drop-over')
					.removeAttr('data-delta-source')
					.removeAttr('data-delta-referenced')
					.removeAttr('data-cannot-move')
					.removeAttr('data-prevList');

				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				if(WISE.Context.isCubeReport || gDashboard.reportType == 'AdHoc'){
					$('.drop-data').removeClass('focus-use');
					$('.drop-column').removeClass('focus-use');
					$('.drop-row').removeClass('focus-use');
					//2020.04.06 MKSONG 필터 추가 영역 조정 DOGFOOT
					if(WISE.Constants.editmode == 'viewer') {
						$('.filter-row').removeClass('focus-use');
					} else {
						$('.filter-bar').removeClass('focus-use');
					}
					$('.drop-hiddendata').removeClass('focus-use');
					//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
					if(WISE.Constants.editmode === 'viewer'){
						$('#allList.scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}else{
						$('#allList .scrollbar').dxScrollView('instance').option('disabled', false);
						$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
					}
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				}else if(WISE.Constants.editmode != 'viewer' && (gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis' || gDashboard.reportType == 'DSViewer')){
					$('.drop-data').removeClass('focus-use');
					$('.drop-dimension').removeClass('focus-use');
					$('.drop-hiddendata').removeClass('focus-use');
					$('.drop-hiddendata').removeClass('focus-use');
					//2020806 ajkim 아이템 이동 중에 스크롤 비활성화
					$('#allList .scrollbar').dxScrollView('instance').option('disabled', false);
					$('.panel-inner.scrollbar:last').dxScrollView('instance').option('disabled', false);
				}
				//2020.07.30 MKSONG DOGFOOT 델타 이동시 z-index 오류 수정
				$(_ui.helper).css('z-index','auto');
			}
		};

	this.droppableOptions = {
		accept: '.wise-area-field:not(.wise-area-field-de)',
		tolerance: 'pointer',
		deactivate: function(_event, _ui) {
			$(this).removeClass("wise-area-drop-over");
		},
		drop: function(_event, _ui) {
			var fieldFilter = new WISE.libs.Dashboard.FieldFilter();

			var divideMenu = $(_ui.helper).children('.divide-menu');
			/* DOGFOOT ktkang 주제영역 중복체크 기능 개선  20200308 */
			var dupleCheck = false;

			var container = $(this).attr('id');
			//2020.02.19 MKSONG 필드 드롭 가능한 지역 BORDER 추가 위해 불필요한 부분 제거 DOGFOOT

			if (_ui.draggable) _ui.draggable.removeClass("wise-area-drop-over");
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
			var containerType = container.substring(0,container.lastIndexOf('t')+1);
			var prevContainer = _ui.draggable.attr('prev-container');
			var dataItem = _ui.helper;
			var cubeInsertYN = true;

//			if(WISE.Constants.editmode == "viewer" && gDashboard.reportType == 'AdHoc' && userJsonObject.goyongList.indexOf(Number(WISE.Constants.pid)) > -1
//				&& prevContainer == 'allList' && containerType != 'allList') {
//				var dimNumber = 0;
//				if(dataItem.hasClass('wise-field-group')){
//					$.each(dataItem.find('.dataset').children(),function(_i,_dataItem){
//						if(typeof $(_dataItem).attr('data-field-type') != 'undefined' && $(_dataItem).attr('data-field-type') == 'dimension') {
//							if(_i == 0){
//								dimNumber++;
//							}else{
//								dimNumber++;
//							}
//						}
//
//					});
//				} else {				
//					var columnList = $('#colAdHocList' + _item.index).children().children('li');
//					var rowList = $('#rowAdHocList' + _item.index).children().children('li');
//					$.each(rowList, function(_i, _row){
//						if(typeof $(_row).attr('data-field-type') != 'undefined' && $(_row).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//					$.each(columnList, function(_i, _col){
//						if(typeof $(_col).attr('data-field-type') != 'undefined' && $(_col).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//				}
//				if(dimNumber > 3 && $(_ui.helper).attr('data-field-type') == 'dimension') {
//					WISE.alert('고용행정통계 보고서는 차원을 4개이상으로 조회하실 수 없습니다.');
//					$(_ui.helper).remove();
//					cubeInsertYN = false;
//				}
//			} else if(WISE.Constants.editmode == "viewer" && gDashboard.reportType == 'AdHoc' && userJsonObject.goyongAdhocList.indexOf(Number(WISE.Constants.pid)) == -1
//					&& prevContainer == 'allList' && containerType != 'allList') {
//				var dimNumber = 0;
//				if(dataItem.hasClass('wise-field-group')){
//					$.each(dataItem.find('.dataset').children(),function(_i,_dataItem){
//						if(typeof $(_dataItem).attr('data-field-type') != 'undefined' && $(_dataItem).attr('data-field-type') == 'dimension') {
//							if(_i == 0){
//								dimNumber++;
//							}else{
//								dimNumber++;
//							}
//						}
//					});
//				} else {
//					var columnList = $('#colAdHocList' + _item.index).children().children('li');
//					var rowList = $('#rowAdHocList' + _item.index).children().children('li');
//					$.each(rowList, function(_i, _row){
//						if(typeof $(_row).attr('data-field-type') != 'undefined' && $(_row).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//					$.each(columnList, function(_i, _col){
//						if(typeof $(_col).attr('data-field-type') != 'undefined' && $(_col).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//				}
//				if(dimNumber > 7 && $(_ui.helper).attr('data-field-type') == 'dimension') {
//					WISE.alert('일반 비정형 보고서는 차원을 8개이상으로 조회하실 수 없습니다.');
//					$(_ui.helper).remove();
//					cubeInsertYN = false;
//				}
//			}
			
			var targetContainer;

			if (_ui.draggable.data('delta-source')) {
				$(_ui.draggable).draggable("option", "revert", true);
				WISE.alert(gMessage.get('WISE.message.page.widget.pivot.exist.referenced.fileds', [_ui.draggable.data('delta-referenced')]));
			} else if($(this).hasClass('drop-target')){
				targetContainer = $('#'+container);
				container = 'delta-drop';
			} else if (_ui.draggable.data('cannot-move')) {
//				$(_ui.draggable).draggable("option", "revert", true);
				$(_ui.helper).remove();
			} else if ((_ui.draggable.attr('data-field-type') === 'dimension' && container === 'rowList'+_item.index)
						||(_ui.draggable.attr('data-field-type') === 'dimension' && container === 'colList'+_item.index)
						||(_ui.draggable.attr('data-field-type') === 'dimension' && container === 'pivot_hide_measure_list'+_item.index)
						||(_ui.draggable.attr('data-field-type') === 'measure' && container === 'dataList'+_item.index)
						||(_ui.draggable.attr('data-field-type') === 'dimension' && container === 'rowAdHocList'+_item.adhocIndex)
						||(_ui.draggable.attr('data-field-type') === 'dimension' && container === 'colAdHocList'+_item.adhocIndex)
						||(_ui.draggable.attr('data-field-type') === 'dimension' && container === 'adhoc_hide_measure_list'+_item.adhocIndex)
						||(_ui.draggable.attr('data-field-type') === 'measure' && container === 'dataAdHocList'+_item.adhocIndex)
						||(container === "sparkLine" + _item.index && WISE.Context.isCubeReport)
						|| container === "cardSparkLine" + _item.index && WISE.Context.isCubeReport) {

				//2020.03.02 MKSONG 그룹별 데이터 항목 추가 기능 DOGFOOT
				if(_ui.draggable.hasClass('wise-field-group')){
					$.each(_ui.draggable.find('.dataset').children(),function(_i,_dataItem){
					/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
						dupleCheck = self.duplicatedCheck(container,$(_dataItem));
						if(dupleCheck) {
							cubeInsertYN = false;
						}
					});
				}else{
				/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
					dupleCheck = self.duplicatedCheck(container,$(_ui.helper));
					if(dupleCheck) {
						cubeInsertYN = false;
					}
				}
				targetContainer = $('#' + container);
			} else if (container === 'chartValueList' + _item.index || container === 'chartParameterList' + _item.index || container === 'chartSeriesList' + _item.index || container === 'chart_hide_dimension_list' + _item.index || container === 'chart_hide_measure_list' + _item.index ||
					container === 'pieValueList' + _item.index || container === 'pieParameterList' + _item.index || container === 'pieSeriesList' + _item.index || container === 'pie_hide_dimension_list' + _item.index || container === 'pie_hide_measure_list' + _item.index || container === 'card_hide_measure_list' + _item.index ||
					container === 'columnList' + _item.index || container === 'sparkline' + _item.index || container === 'hide_dimension_list' + _item.index || container === 'hide_measure_list' + _item.index || container === 'mapParameterList'+_item.index || container === 'mapValueList'+_item.index ||
					container === 'treemapValueList'+_item.index || container === 'treemapParameterList'+_item.index || container === 'parallelValueList'+_item.index || container === 'parallelParameterList'+_item.index || container === 'RectangularAreaChartValueList'+_item.index ||
					container === 'RectangularAreaChartParameterList'+_item.index || container === 'waterfallchartValueList'+_item.index || container === 'waterfallchartParameterList'+_item.index || container === 'bipartitechartValueList'+_item.index || container === 'bipartitechartParameterList'+_item.index ||
					container === 'sankeychartValueList'+_item.index || container === 'sankeychartParameterList'+_item.index || container === 'adhoc_hide_measure_list'+_item.index || container === 'funnelchartValueList'+_item.index || container === 'funnelchartParameterList'+_item.index ||
					container === 'bubbled3ValueList'+_item.index || container === 'bubbled3ParameterList'+_item.index|| container === 'heatmapValueList'+_item.index || container === 'heatmap2ParameterList'+_item.index || container === 'heatmap2ValueList'+_item.index|| container === 'syncchartParameterList'+_item.index || container === 'syncchartValueList'+_item.index||
					container === 'pyramidchartValueList'+_item.index || container === 'pyramidchartParameterList'+_item.index || container === 'heatmap_hide_measure_list'+_item.index || container === 'heatmap2_hide_measure_list'+_item.index|| container === 'syncchart_hide_measure_list'+_item.index||
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
					container === 'kakaoMapValueList'+_item.index || container === 'kakaoMapParameterList'+_item.index || container === 'kakaoMapLatitudeList'+_item.index || container === 'kakaoMapLongitudeList'+_item.index ||
					container === 'kakaoMap2ValueList'+_item.index || container === 'kakaoMap2ParameterList'+_item.index || container === 'kakaomapLatitudeList'+_item.index || container === 'kakaomapLongitudeList'+_item.index || container === 'kakaomapAddressList'+_item.index || container === 'kakaomapFieldList'+_item.index ||
					container === 'bubbleChartValueList'+_item.index || container === 'wordcloudValueList'+_item.index || container === 'wordcloudParameterList'+_item.index ||container === 'pivot_hide_measure_list'+_item.index ||
					/* DOGFOOT ktkang 버블차트2 추가  20200721 */
					container === 'histogramchartValueList'+_item.index || container === 'histogramchartParameterList'+_item.index || container === 'hierarchicalParameterList'+_item.index ||
					//2020.02.07 mksong listbox_hide_measure_list 추가 dogfoot
					container === 'textboxValueList'+_item.index ||container === 'textboxValueList'+_item.index || container === 'textbox_measure_list'+_item.index || container === 'listbox_hide_measure_list'+_item.index || container === 'bubbleChartXList'+_item.index ||  container === 'bubbleChartYList'+_item.index ||
					/* DOGFOOT ktkang 주제영역 일 때 차원은 행,열에 측정값은 측정값에 넣도록 경고 창 추가  20200130 */
					container === 'cardValueList' + _item.index || container === 'cardSeriesList' + _item.index || container === 'cardSparklineList' + _item.index ||
					container === 'rowList'+_item.index || container === 'colList'+_item.index || container === 'dataList'+_item.index ||
					container === 'rowAdHocList'+_item.adhocIndex || container === 'colAdHocList'+_item.adhocIndex || container === 'dataAdHocList'+_item.adhocIndex ||
					container === 'gaugeValueList' + _item.index || container === 'gaugeSeriesList' || container === 'forceDirectParameterList'+_item.index || container === 'forceDirectExpandParameterList'+_item.index ||
					container === 'rangebarchartParameterList'+_item.index || container === 'rangeareachartParameterList'+_item.index || container === 'timelinechartParameterList'+_item.index || container === 'timelinechartSeriesList' + _item.index ||
					container === 'timelinechartStartDateList'+_item.index || container === 'timelinechartEndDateList'+_item.index ||
					container === 'bubblepackchartValueList'+_item.index || container === 'bubblepackchartParameterList'+_item.index ||
					container === 'wordcloudv2ValueList'+_item.index || container === 'wordcloudv2ParameterList'+_item.index ||  container === 'scatterplot_hide_measure_list'+_item.index ||  container === 'scatterplot2_hide_measure_list'+_item.index || container === 'divergingchartSeriesList'+_item.index || container === 'divergingchart_hide_measure_list'+_item.index || container === 'scatterplotXList'+_item.index ||container === 'scatterplotYList'+_item.index ||container === 'scatterplotZList'+_item.index ||
					container === 'dendrogrambarchartValueList'+_item.index || container === 'dendrogrambarchartParameterList'+_item.index || container === 'scatterplot2XList'+_item.index ||container === 'scatterplot2YList'+_item.index ||container === 'scatterplot2ZList'+_item.index ||
					container === 'calendarviewchartValueList'+_item.index || container === 'calendarviewchartParameterList'+_item.index ||
					container === 'divergingchartValueList'+_item.index || container === 'divergingchartParameterList'+_item.index || container === 'divergingchartSeriesList'+_item.index
					|| container === 'dependencywheelValueList'+_item.index || container === 'dependencywheelParameterList'+_item.index
					|| container === 'sequencessunburstValueList'+_item.index || container === 'sequencessunburstParameterList'+_item.index
					|| container === 'boxplotValueList'+_item.index || container === 'boxplotParameterList'+_item.index || container === 'coordinatelineParameterList'+_item.index || container === 'coordinatelineXList'+_item.index || container === 'coordinatelineYList'+_item.index
					|| container === 'coordinatedotParameterList'+_item.index || container === 'coordinatedotXList'+_item.index || container === 'coordinatedotYList'+_item.index
					|| container === 'scatterplotValueList'+_item.index || container === 'scatterplotParameterList'+_item.index || container === 'scatterplot2ParameterList'+_item.index
					|| container === 'liquidfillgaugeValueList'+_item.index || container === 'liquidfillgaugeParameterList'+_item.index ||
					container === 'calendarview2chartValueList'+_item.index || container === 'calendarview2chartParameterList'+_item.index ||
					container === 'calendarview3chartValueList'+_item.index || container === 'calendarview3chartParameterList'+_item.index ||
					container === 'collapsibletreechartValueList'+_item.index || container === 'collapsibletreechartParameterList'+_item.index ||
					container === 'radialTidyTreeParameterList'+_item.index || container === 'scatterPlotMatrixX1List'+_item.index ||
					container === 'scatterPlotMatrixX2List'+_item.index || container === 'scatterPlotMatrixY1List'+_item.index ||
					container === 'scatterPlotMatrixY2List'+_item.index || container === 'scatterPlotMatrixParameterList'+_item.index ||
					container === 'historyTimelineParameterList'+_item.index || container === 'historyTimelineEndList'+_item.index ||
					container === 'historyTimelineStartList'+_item.index || container === 'arcdiagramParameterList' + _item.index
					|| container === 'onewayAnovaObservedList1' || container === 'onewayAnovaFactorList1' || container === 'rFieldList1'
						|| container === 'twowayAnovaObservedList1' || container === 'twowayAnovaFactorList1'
						|| container === 'onewayAnova2ObservedList1' || container === 'onewayAnova2FactorList1' || container === 'onewayAnova2ItemList1'
						|| container === 'pearsonsCorrelationNumericalList1' || container === 'spearmansCorrelationNumericalList1'
						|| container === 'simpleRegressionIndpnList1' || container === 'simpleRegressionDpndnList1' || container === 'simpleRegressionVectorList1'
						|| container === 'multipleRegressionIndpnList1' || container === 'multipleRegressionDpndnList1' || container === 'multipleRegressionVectorList1'
						|| container === 'logisticRegressionIndpnList1' || container === 'logisticRegressionDpndnList1' || container === 'logisticRegressionVectorList1'
						|| container === 'multipleLogisticRegressionIndpnList1' || container === 'multipleLogisticRegressionDpndnList1' || container === 'multipleLogisticRegressionVectorList1'
						|| container === 'tTestNumericalList1' || container === 'zTestNumericalList1' || container === 'chiTestNumericalList1' || container === 'fTestNumericalList1'
						|| container === 'multivariateNumericalList1' || container === 'multivariateParameterList1'


			){
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				if (WISE.Context.isCubeReport && container != 'adhoc_hide_measure_list'+_item.index && !(_ui.draggable.hasClass('wise-field-group')) && gDashboard.reportType == 'AdHoc'){
					WISE.alert('주제영역을 사용하실 때 측정값은 측정값 부분에 차원은 행이나 열 부분에 넣으셔야 합니다.');
					/* DOGFOOT ktkang 주제영역에서 항목 추가시 오류 수정  20200308 */
					/* DOGFOOT ktkang 주제영역 관계 오류 수정  20200308 */
				}
				else {
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
					if($(_ui.draggable).hasClass('wise-field-group')){
						$.each($(_ui.helper).find('.dataset').children(),function(_i,_dataItem){
						/* DOGFOOT ktkang 주제영역 오류 수정  20200717 */
							if(self.dataItemContainerTypeCheck($(_dataItem), containerType) == "" && WISE.Context.isCubeReport){
								WISE.alert('주제영역을 사용하실 때 측정값은 측정값 부분에 차원은 차원 부분(ex. 행, 열)에 넣으셔야 합니다.');
								cubeInsertYN = false;
							} else if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
								dupleCheck = self.duplicatedCheck(container,$(_dataItem));
							} else if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
								dupleCheck = self.duplicatedCheck(container,$(_dataItem));
							}
							/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
							if(dupleCheck) {
								cubeInsertYN = false;
							}
						});
					}else {
						/* DOGFOOT ktkang 주제영역 오류 수정  20200717 */
						if(self.dataItemContainerTypeCheck($(_ui.helper), containerType) == "" && WISE.Context.isCubeReport){
							WISE.alert('주제영역을 사용하실 때 측정값은 측정값 부분에 차원은 차원 부분(ex. 행, 열)에 넣으셔야 합니다.');
							cubeInsertYN = false;
						} else {
							dupleCheck = self.duplicatedCheck(container,$(_ui.helper));
						}

						if(dupleCheck) {
							cubeInsertYN = false;
						}
					}
					targetContainer = $('#' + container);
				}

				_ui.draggable.removeClass("wise-field-leaf");
				_ui.draggable.removeClass("wise-no-border");
			}
			//필터
			else if (container === 'filter-bar' || container === 'filter-row'){
			/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				var $dataSetLookUp = $("#dataSetLookUp");
				
				if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
					$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
				}
				var lookUpIns = $dataSetLookUp.dxLookup('instance');
				var focusDs = lookUpIns.option('value');
				var singleTable = "";
				if(WISE.Constants.editmode == "viewer" && ((userJsonObject.menuconfig.Menu.DASH_DATA_FIELD && gDashboard.reportType == "DashAny") || gDashboard.reportType == 'DSViewer') || (WISE.Constants.editmode == "viewer" && $("#dataArea_" + WISE.Constants.pid +" #dataSetLookUp.dx-textbox").length == 0)){
					var dataset = gDashboard.datasetMaster.state.datasets[gDashboard.itemGenerateManager.focusedItem.dataSourceId]
					if(dataset.DATASET_TYPE == "DataSetSingleDs" || dataset.DATASET_TYPE == "DataSetSingleDsView") {
						singleTable = dataset;
					}					
				}else{
					var lookUpIns = $("#dataSetLookUp").dxLookup('instance');
					var focusDs = lookUpIns.option('value');
					$.each(gDashboard.datasetMaster.state.datasets, function(_i,_o){
						if(_o.DATASET_TYPE == "DataSetSingleDs" || _o.DATASET_TYPE == "DataSetSingleDsView") {
							if(_o.DATASET_NM == focusDs) {
								singleTable = _o;
							}
						}
					});
				}
				
				if((typeof WISE.Context.isCubeReport != 'undefined' && WISE.Context.isCubeReport)) {
					if(_ui.draggable.attr('data-field-type') === 'dimension' && !_ui.draggable.hasClass('wise-field-group') && _ui.draggable.children().length == 1) {
						gProgressbar.show();
						/* DOGFOOT 20201021 ajkim setTimeout 제거*/
						fieldFilter.addFilter(_ui.draggable.clone());

					} else {
						//2020.03.07 MKSONG 필터 그룹 필드 드롭 방지 DOGFOOT
						if(_ui.draggable.hasClass('wise-field-group')){
							//2020.03.09 MKSONG 문구 수정 DOGFOOT
							if(_ui.draggable.attr('data-field-type') == 'measure'){
								WISE.alert('해당 영역에 측정값 그룹을<br>올리실 수 없습니다.');
							}else{
								WISE.alert('해당 영역에 차원그룹을<br>올리실 수 없습니다.');
							}
							/* DOGFOOT ktkang 주제영역에서 필터 추가 시 오류 수정  20200310 */
						} else if(_ui.draggable.children().length == 2) {
							WISE.alert('필터를 사용하실 때에는 데이터 원본에 있는 차원을 사용하시기 바랍니다.');
						} else{
							WISE.alert('주제영역에서 필터를 사용하실 때에는 차원만 사용하실 수 있습니다.');
						}
					}
				} else if(singleTable != "") {
					if(_ui.draggable.attr('data-field-type') === 'dimension' && !_ui.draggable.hasClass('wise-field-group') && _ui.draggable.children().length == 1) {
						gProgressbar.show();
						/* DOGFOOT 20201021 ajkim setTimeout 제거*/
						fieldFilter.addFilterSingle(_ui.draggable.clone(), singleTable);

					} else {
						//2020.03.07 MKSONG 필터 그룹 필드 드롭 방지 DOGFOOT
						if(_ui.draggable.hasClass('wise-field-group')){
							//2020.03.09 MKSONG 문구 수정 DOGFOOT
							if(_ui.draggable.attr('data-field-type') == 'measure'){
								WISE.alert('해당 영역에 측정값 그룹을<br>올리실 수 없습니다.');
							}else{
								WISE.alert('해당 영역에 차원그룹을<br>올리실 수 없습니다.');
							}
							/* DOGFOOT ktkang 주제영역에서 필터 추가 시 오류 수정  20200310 */
						} else if(_ui.draggable.children().length == 2) {
							WISE.alert('필터를 사용하실 때에는 데이터 원본에 있는 차원을 사용하시기 바랍니다.');
						} else{
							WISE.alert('주제영역에서 필터를 사용하실 때에는 차원만 사용하실 수 있습니다.');
						}
					}
				} else {
					$(_ui.helper).remove();
				}
			}
			else if(container != 'deltavalueList'+_item.index  && _ui.draggable.attr('deltaid') != undefined){
				var deltaId  = _ui.draggable.attr('deltaid');
//				var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//				var _deltaitem;
//				$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//					if(_o.ComponentName == itemId){
//						/* 보고서 불러오기 후 변동 측정값 뺄 때, Chartitem을 가리키기 때문에 추가 */
//						_item = _o;
//						_deltaitem = _o;
//						return false;
//					}
//				});

				var _deltaitem = gDashboard.itemGenerateManager.dxItemBasten[1].deltaItems?
						gDashboard.itemGenerateManager.dxItemBasten[1] : gDashboard.itemGenerateManager.dxItemBasten[0];

				$.each(_deltaitem.deltaItems,function(_i,_delta){
					if(_delta.ID == deltaId){
						_item.deltaItems.splice(_i, 1);
						_item.deltaItemlength = _item.deltaItems.length;
						return false;
					}
				});

				if(_item.deltaItemlength === 0){
					$('#deltavalueList'+_item.adhocIndex).parent().css('display', 'none')
				}

				$(_ui.helper).remove();
			}
			else{
				targetContainer = $('#' + container);
			}

			//필터

			gDashboard.fieldManager.isChange = true;
			/*if (container !== _ui.draggable.attr('data-prevList')){
				self.fieldManager.isChange = true;
			}*/

			var prevContainer = _ui.draggable.attr('prev-container');

			if(targetContainer != undefined){
				//2020.03.02 MKSONG 불필요한 부분 삭제 DOGFOOT
				if(gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id') != undefined){
					var helperDataSourceId = _ui.helper.children().attr('data-source-id') == undefined ? _ui.helper.attr('data-source-id') : _ui.helper.children().attr('data-source-id');
					if(helperDataSourceId != gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id')){
						if(container !=  'deltavalueList'+_item.index){
							var deleteField = confirm('현재 아이템에 사용되고 있는 데이터집합과 다른 데이터 집합의 필드입니다.\n추가하시길 원하신다면 기존의 데이터집합 필드는 모두 소멸됩니다. 진행하시겠습니까?');
							if(deleteField){
								//2020.01.31 MKSONG 데이터 소스 변경 오류 수정 DOGFOOT
								gDashboard.itemGenerateManager.focusedItem.dataSourceId = helperDataSourceId;
								$.each(gDashboard.fieldManager.stateFieldChooser.children().find('.drop-panel'),function(_i, _o){
									var $o = $(_o);
									$o.empty();
									//2020.03.02 MKSONG recovery 부분 함수화 DOGFOOT
									self.recovery($o);
									//2020.01.31 MKSONG 데이터 소스 변경 오류 수정 끝 DOGFOOT
								});
							}else{
								_ui.helper.remove();
							}
						}
					}
				}

				// 계산필드인지 확인
				var customFieldFlag = false;
				var customFieldInfo = gDashboard.customFieldManager.fieldInfo;
				if(!($.isEmptyObject(customFieldInfo))) {
					$.each(gDashboard.customFieldManager.fieldInfo[_ui.helper.attr('data-source-id')],function(i,item){
						if(item.Name==_ui.helper.attr('uni_nm')) customFieldFlag = true;
					});
				}

				var dataItem = _ui.helper;
				/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
				if(cubeInsertYN) {
					if(dataItem.hasClass('wise-field-group')){
						$.each(dataItem.find('.dataset').children(),function(_i,_dataItem){
							if(_i == 0){
								/* DOGFOOT ktkang 주제영역에서 항목 추가시 오류 수정  20200404 */
								if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
									self.dataItemSetting('drop', $(_ui.draggable), $(_dataItem), container, prevContainer, targetContainer, self.item, 'single');
								}
							}else{
								if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
									self.dataItemSetting('drop', $(_ui.draggable), $(_dataItem), container, prevContainer, targetContainer, self.item, 'multiple');
								}
							}

						});
						dataItem.remove();
					}else{
//						if(customFieldFlag && container.indexOf('ValueList')<0 && container.indexOf('dataAdHocList')<0 && container.indexOf('dataList')<0  && container.indexOf('columnList')<0 && container != 'allList'){
//							$(_ui.helper).remove();
//							WISE.alert('사용자 정의 데이터는<br>측정값 외에 넣을 수 없습니다.');
//						}else{
							if(container == 'delta-drop'){
								$(_ui.helper).addClass('selected');
							}
							self.dataItemSetting('drop', _ui.draggable, dataItem, container, prevContainer, targetContainer, self.item, 'single');
//						}
					}
				}
			}
			/* DOGFOOT ktkang 주제영역 관계 표시 부분 오류 수정  20200305 */
			if(WISE.Context.isCubeReport && _ui.draggable.attr('data-field-type') === 'measure'){
				self.cubeRelationCheck(_item);
			}
		},
		over: function(_event, _ui) {
			if($(_ui.helper).hasClass('other-menu-ico') && $(_ui.helper).is('a')){
				$(_ui.helper).remove();
				$('.other-menu-ico').css('display','block');
				return;
			}else{
				$('.divide-menu .other-menu-ico').css('display','none');
			}
			compMoreMenuUi();

			var container = $(this).attr('id');
			var draggableType = _ui.draggable.attr('data-field-type');

			if(_item != undefined){
//				switch (container) {
////				case 'colList' + _item.index + '':
////				case 'rowList' + _item.index + '':
////				case 'chartParameterList' + _item.index + '':
////				case 'pieParameterList' + _item.index + '':
////				case 'chartSeriesList' + _item.index + '':
////				case 'starchartParameterList' + _item.index + '':
////				case 'starchartSeriesList' + _item.index + '':
////				case 'treemapParameterList' + _item.index + '':
////				case 'heatmapParameterList' + _item.index + '':
////					if (draggableType === 'measure') {
////						$(this).addClass("focus-none");
////						_ui.draggable.data('cannot-move', true);
////					}
////					else {
////						$(this).addClass("focus-use");
////						_ui.draggable.data('cannot-move', false);
////					}
////					return;
//				case 'dataList' + _item.index + '':
//				case 'sparkline' + _item.index + '':
//				case 'chartValueList' + _item.index + '':
//				case 'pieValueList' + _item.index + '':
//				case 'starchartValueList' + _item.index + '':
//				case 'treemapValueList' + _item.index + '':
//				case 'heatmapValueList' + _item.index + '':
//				case 'textboxValueList' + _item.index + '':
//				case 'cardValueList' + _item.index + '':
//					if (draggableType === 'dimension') {
//						$(this).addClass("focus-none");
//						_ui.draggable.data('cannot-move', true);
//					}
//					else {
//						$(this).addClass("focus-use");
//						_ui.draggable.data('cannot-move', false);
//					}
//					return;
//				default:
//					$(this).addClass("focus-use");
//					_ui.draggable.data('cannot-move', false);
//				}
			}
//			else{
//				if(gDashboard.fieldManager.stateFieldChooser.attr('id').indexOf('grid') != -1){
//					if($(this).hasClass('drop-target')){
//						if(gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].sortable != undefined){
//							gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].sortable('disable');
//						}
//					}
//				}
//			}

			if(gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id') != undefined){
				if(_ui.draggable.attr('data-source-id') != gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id')){
					//2020.03.02 MKSONG focus-none 주석 처리 DOGFOOT
//					$(this).addClass("focus-none");
					_ui.draggable.data('cannot-move', false);
				}
			}
		},
		out: function(_event, _ui) {
//			if($(this).find('ul.wise-area-drop-over')){
//				$(this).find('ul.wise-area-drop-over').removeClass("wise-area-drop-over");
//			} else{
			if(gDashboard.fieldManager.stateFieldChooser.attr('id').indexOf('grid') != -1){
				if($(this).hasClass('drop-target')){
					if(gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].sortable != undefined){
						gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].sortable('enable');
					}
				}
			}
			//2020.02.19 MKSONG 필드 드롭 가능한 지역 BORDER 추가 DOGFOOT
			$(this).removeClass("focus-none");
			_ui.draggable.data('cannot-move', false);
//			}

		}
	};

	this.droppableOptions2 = {
			accept: '.wise-area-field:not(.wise-area-field-de)',
			tolerance: 'pointer',
			deactivate: function(_event, _ui) {
				$(this).removeClass("wise-area-drop-over");
			},
			drop: function(_event, _ui) {
				var container = $(this).attr('id');
				var itemid = $('.subQuerySet').attr('itemid');
				var item;
				$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
					if(itemid == _o.itemid){
						item = _o;
					}
				});
				var dataItem = _ui.helper;
				switch(container){
					case 'sub-target-detail':
						if(_ui.helper.attr('data-field-type') == 'dimension'){
							$(this).find('tr').attr('WISE_UNI_NM',dataItem.attr('WISE_UNI_NM'));
							$('.targetId').text(dataItem.attr('UNI_NM'));
							$('.targetName').dxTextBox('instance').option('value',dataItem.text());
							$('.targetDataType').text('varchar');
							$('.targetType').text('차원');
							var fk_tbl_nm = '';
							var fk_col_nm = '';
							var pk_col_nm = '';
							var JOIN_TYPE = '';

							if(gDashboard.dataSourceManager.datasetInformation.dataSource1.CUBE_REL_INFO != undefined){
								$.each(gDashboard.dataSourceManager.datasetInformation.dataSource1.CUBE_REL_INFO,function(_i,_o){
									if(dataItem.attr('TABLE_NM') == _o.PK_TBL_NM){
										fk_tbl_nm = _o.FK_TBL_NM;
										fk_col_nm = _o.FK_COL_NM;
										pk_col_nm = _o.PK_COL_NM;
										JOIN_TYPE = _o.JOIN_TYPE;
									}
								});
							}

							$('.targetGroup').text(fk_tbl_nm);
							$('.targetGroup').attr('PK_TBL_NM', dataItem.attr('TABLE_NM'));
							$('.targetGroup').attr('FK_COL_NM', fk_col_nm);
							$('.targetGroup').attr('PK_COL_NM', pk_col_nm);
							$('.targetGroup').attr('JOIN_TYPE', JOIN_TYPE);

							item.subqueryTarget['targetId'] = dataItem.attr('UNI_NM');
							item.subqueryTarget['targetName'] = dataItem.text();
						}
						break;
					case 'sub-having-detail':
						var appendHtml = "<tr id="+ item.subqueryArrayIndex +" TABLE_NM=\""+ dataItem.attr('TABLE_NM') +"\" WISE_UNI_NM=\""+dataItem.attr('WISE_UNI_NM')+"\" TYPE=\""+dataItem.attr('data-field-type')+"\">" +
						"					<td class=\"left\"></td>" +
						"					<td class=\"conditionTargetName left\" style=\"padding:2px;\">"+ dataItem.attr('UNI_NM') +"</td>" +
						"					<td class=\"ipt\">"+
                        "                       <select class=\"condition\">"+
                        "					        <option data-display=\"Select\" value=\"Equals\">Equals</option>"+
                        "                   		<option value=\"NotEquals\">Not Equals</option>"+
                        "                           <option value=\"GreaterThan\">Greater Than</option>"+
                        "                   		<option value=\"GreaterOrEquals\">Greater Or Equals</option>"+
                        "                   		<option value=\"LessThan\">Less Than</option>"+
                        "                   		<option value=\"LessOrEquals\">Less Or Equals</option>"+
                        "                   		<option value=\"Between\">Between</option>"+
                        "                   		<option value=\"Like\">Like</option>"+
                        "                   		<option value=\"NotLike\">Not Like</option>"+
                        "                   		<option value=\"In\">In</option>"+
                        "                   		<option value=\"NotIn\">Not In</option>"+
                        "                   		<option value=\"IsNull\">IsNull</option>"+
                        "                   		<option value=\"NotIsNull\">Not IsNull</option>"+
                        "					      </select>"+
                        "                   </td>";

						if(dataItem.attr('data-field-type') == 'dimension'){
							appendHtml +=  "    <td class=\"right\">" +
	                        "						<input class=\"left conditionValue\" type=\"text\" value=\"\" style=\"width:93%;\" readonly>" +
						    "                       <a class=\"dimensionType\" href=\"#\">" +
						    "                       	<img class=\"tbl-ico\" src=\""+WISE.Constants.context+"/resources/main/images/ico_tbl_more.png\" alt=\"\" style=\"width:10px;\">" +
						    "                       </a>" +
						    "                   </td>";
						}else{
							appendHtml +=  "    <td class=\"right\">" +
	                        "						<input class=\"left conditionValue\" type=\"number\" value=\"0\" style=\"width:93%;\" readonly>" +
						    "                       <a class=\"measureType\" href=\"#\">" +
						    "                       	<img class=\"tbl-ico\" src=\""+WISE.Constants.context+"/resources/main/images/ico_tbl_more.png\" alt=\"\" style=\"width:10px;\">" +
						    "                       </a>" +
						    "                   </td>";
						}

					    appendHtml +=  "    <td class=\"center ipt\">" +
                        "                   	<input class=\"selectCheck\" id=\"selectChk"+ item.subqueryArrayIndex +"\" type=\"checkbox\" name=\"selectChk"+ item.subqueryArrayIndex +"\" checked>"+
                        "                       <label for=\"selectChk"+ item.subqueryArrayIndex +"\"></label>"+
                        "                   </td>" +
						"					<td class=\"ipt\">"+
                        "                       <select class=\"aggregator\">"+
                        "                           <option data-display=\"Select\" value=\"\"></option>"+
                        "                           <option value=\"Count\">Count</option>"+
                        "					        <option value=\"Distinct Count\">Distinct Count</option>"+
                        "                   		<option value=\"Max\">Max</option>"+
                        "                   		<option value=\"Min\">Min</option>"+
                        "                   		<option value=\"StdDev\">StdDev</option>"+
                        "                   		<option value=\"StdDevp\">StdDevp</option>"+
                        "                   		<option value=\"Sum\">Sum</option>"+
                        "                   		<option value=\"Var\">Var</option>"+
                        "                   		<option value=\"Varp\">Varp</option>"+
                        "					    </select>"+
                        "                   </td>"+
                        "					<td class=\"deleteCheck center ipt\">" +
                        "                       <input class=\"check\" id=\"deleteCheck"+ item.subqueryArrayIndex +"\" type=\"checkbox\" name=\"deleteCheck"+ item.subqueryArrayIndex +"\">"+
                        "                       <label for=\"deleteCheck"+ item.subqueryArrayIndex +"\"></label>"+
                        "                   </td>" +
						"				</tr>" ;

						if($('#sub-having-detail').find('.conditionTargetName').length == 1 && $('#sub-having-detail').find('.conditionTargetName').text() == ''){
							$('#sub-having-detail').find('tr').remove();
						}

						$('#sub-having-detail').find('tbody').append(appendHtml);

						item.subqueryArrayIndex++;

						$('.measureType').off('click').click(function(e){
							e.preventDefault();
							var target = e.target;

							if($(target).hasClass('tbl-ico')){
								target = $(e.target).parent();
							}

							$('#meaValue').dxNumberBox('instance').option('value',Number($(target).parent().children('.conditionValue').val()));

							var p = $('#editPopup').dxPopup('instance');
							p.option('title', '조건 값 설정');
							p.option('width',600);
							$('#multiView').dxMultiView('instance').option('selectedIndex', 1);

							$('.meaValueOk').off('click').click(function(e){
								$('#multiView').dxMultiView('instance').option('selectedIndex', 0);
								p.option('width',1350);
								p.option('title', '데이터 집합 군 설정');
								$(target).parent().children('.conditionValue').val($('#meaValue').dxNumberBox('instance').option('value'));
							});

							$('.meaValueCancel').off('click').click(function(e){
								$('#multiView').dxMultiView('instance').option('selectedIndex', 0);
								p.option('width',1350);
								p.option('title', '데이터 집합 군 설정');
							});
						});

						$('.dimensionType').off('click').click(function(e){
							e.preventDefault();

							var target = $(e.target);

							if($(target).hasClass('tbl-ico')){
								target = $(e.target).parent();
							}

							var tr = target.parent().parent();
							var condition = tr.find('.condition').val();

							var selectionMode;
							switch(condition){
								case 'Equals': case 'NotEquals': case 'Like': case 'NotLike': case 'IsNull': case 'NotIsNull':
									selectionMode = 'single';
									break;
								case 'In': case 'NotIn':
									selectionMode = 'multiple';
									break;
								default :
									selectionMode = 'none';
							}

							if(selectionMode != 'none'){
								$('#multiView').dxMultiView('instance').option('selectedIndex', 2);
								var p = $('#editPopup').dxPopup('instance');

								var param = {
										'COLUMN_NM': tr.children('.conditionTargetName').text(),
										'TABLE_NM': tr.attr('TABLE_NM'),
										'DATASRC_TYPE': gDashboard.dataSourceManager.datasetInformation[dataItem.attr('data-source-id')].DATASRC_TYPE,
										'DS_ID': gDashboard.dataSourceManager.datasetInformation[dataItem.attr('data-source-id')].DATASRC_ID,
									};

								$.ajax({
									cache: false,
									type: 'post',
									async: false,
									data: param,
									url: WISE.Constants.context + '/report/getDataList.do',
									success: function(_data) {
										var ret = _data.data;

										p.option('title', '조건 값 설정');
										p.option('width',600);

										$('#dimValue').dxList({
											dataSource: ret,
										    editEnabled: false,
										    readOnly: false,
										    showSelectionControls: true,
										    selectionMode: selectionMode,
										    disabled: false,
										    searchMode: "contains",
										    searchEnabled: true,
										    onSelectionChanged: function(_e) {
										    }
										});
									},
									error: function(_response) {
										WISE.alert('<b>조건쿼리 에러: ' + _response.status + '</b><br/>' + +ajax_error_message(_response));
									}
								});

								$('.dimValueOk').off('click').click(function(e){
									$('#multiView').dxMultiView('instance').option('selectedIndex', 0);
									p.option('width',1350);
									p.option('title', '데이터 집합 군 설정');
									$(target).parent().children('.conditionValue').val($('#dimValue').dxList('instance').option('selectedItems'));
								});

								$('.dimValueCancel').off('click').click(function(e){
									$('#multiView').dxMultiView('instance').option('selectedIndex', 0);
									p.option('width',1350);
									p.option('title', '데이터 집합 군 설정');
								});
							}else{
								WISE.alert('조건을 변경하여 주시기 바랍니다.');
							}

						});
						break;
				}
			},
			over: function(_event, _ui) {
				compMoreMenuUi();
			},
			out: function(_event, _ui) {
				compMoreMenuUi();
			}
		};

	this.isDuplicateField = function(container,draggableText){
		var checked = false;

		$.each($('#' + container).children(), function(_i, _o) {
			if ($(_o).text() === draggableText) {
				checked = true;
				return false;
			}
		});

		return checked;
	}

	/*dogfoot shlim 차트별 측정값및 차원 개수 제한 함수 추가 20200630*/
	this.chartLengOptins = function(_containerType,_dataLength){
		var chartmaxLength = -1;
		if(typeof _containerType != 'undefined' && typeof _dataLength != 'undefined'){
			switch (_containerType) {
				case 'parallelParameterList'  :
				case 'mapParameterList' :
				case 'heatmapValueList' :
				case 'heatmap2ValueList' :
				case 'syncchartValue' :
				case 'rangeareachartValueList' :
				case 'timelinechartValueList':
				case 'timelinechartSeriesList':
				case 'calendarviewchartParameterList':
				case 'calendarview2chartParameterList':
				case 'calendarview3chartParameterList':
				case 'scatterplotXList':
				case 'scatterplotYList':
				case 'scatterplotZList':
				case 'scatterPlotMatrixX1List':
				case 'scatterPlotMatrixX2List':
				case 'scatterPlotMatrixY1List':
				case 'scatterPlotMatrixY2List':
				case 'historyTimelineEndList':
				case 'historyTimelineStartList':
				case 'scatterplot2XList':
				case 'scatterplot2YList':
				case 'scatterplot2ZList':
				case 'divergingchartSeriesList':
				 /* DOGFOOT syjin 위도 경도 개수 1개로 제한  20200924 */
				case 'kakaoMapLatitudeList':
				case 'kakaoMapLongitudeList':
				/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
				case 'onewayAnovaObservedList':
				case 'onewayAnovaFactorList':
				case 'twowayAnovaObservedList':
				case 'onewayAnova2ObservedList':
				case 'onewayAnova2ItemList':
				case 'simpleRegressionIndpnList':
				case 'simpleRegressionDpndnList':
				case 'logisticRegressionIndpnList':
				case 'logisticRegressionDpndnList':
				case 'multipleRegressionIndpnList':
				case 'multipleLogisticRegressionIndpnList':
				case 'coordinatelineYList':
				case 'coordinatelineXList':
				case 'coordinatedotYList':
				case 'coordinatedotXList':
					chartmaxLength = 1;
					break;
				case 'heatmapParameterList' :
				case 'heatmap2ParameterList' :
				case 'bipartitechartParameterList':
				case 'onewayAnova2FactorList':
				case 'twowayAnovaFactorList':
					chartmaxLength = 2;
					break;
				case 'sankeychartParameterList' :
					chartmaxLength = 4;
					break;
				case 'scatterplotValueList' :
					chartmaxLength = 3;
					break;
				case 'waterfallchartParameterList' :
				case 'bubbled3ValueList' :
				case 'histogramchartValueList' :
				case 'histogramchartParameterList' :
				case 'bubbled3ParameterList' :
				case 'sparkline' :
				case 'mapValueList' :
				case 'treemapValueList' :
				case 'treemapParameterList' :
				case 'cardValueList' :
				case 'cardSeriesList' :
				case 'cardSparkline' :
				case 'starchartValueList' :
				case 'starchartParameterList' :
				case 'starchartSeriesList' :
				case 'parallelValueList' :
				case 'RectangularAreaChartValueList' :
				case 'RectangularAreaChartParameterList'  :
				case 'waterfallchartValueList' :
				case 'wordcloudValueList' :
				case 'wordcloudParameterList' :
				case 'pivot_hide_measure_list' :
				case 'grid_hide_measure_list' :
				case 'chart_hide_measure_list' :
				case 'pie_hide_measure_list' :
				case 'listbox_hide_measure_list' :
				case 'card_hide_measure_list' :
				case 'gaugeValueList' :
				case 'gaugeSeriesList' :
				case 'divergingchartParameterList' :
				case 'divergingchartValueList' :
				case 'dependencywheelParameterList' :
				case 'dependencywheelValueList' :
				case 'sequencessunburstParameterList' :
				case 'sequencessunbursttValueList' :
				case 'boxplotParameterList' :
				case 'boxplotValueList' :
				case 'scatterplotParameterList' :
				case 'scatterplot2ParameterList' :
				case 'liquidfillgaugeParameterList' :
				case 'liquidfillgaugeValueList' :
				case 'divergingchart_hide_measure_list':
				case 'scatterplot_hide_measure_list':
				case 'scatterplot2_hide_measure_list':
	                chartmaxLength = -1;
					break;
				default:
					chartmaxLength = -1;
					break;
			}

			if(chartmaxLength != -1){
				if(_dataLength >= chartmaxLength){
					return false;
				} else {
					return true;
				}
			}else {
				if(WISE.Constants.companyname == "고용정보원" && WISE.Constants.editmode == "viewer" && 
				    _containerType.indexOf("measure") == -1 && _containerType.indexOf("Value") == -1 ){
					
					if(WISE.Constants.domain.indexOf("7100")){
                        chartmaxLength = 7;
					}else if(WISE.Constants.domain.indexOf("9100")){
						chartmaxLength = 3;
					}
			        

			        if(_dataLength >= chartmaxLength){
						return false;
					} else {
						return true;
					}
					
				    	
				}else{
				    return true;	
				}
					
			}
		}
	}

	this.sortableOptions = {
//	    placeholder: "sortable-placeholder",
	    connectWith: ".sortable",
	    items : "ul:not('.unsortable')",
	    receive: function(_event, _ui) {
	    	if($(_ui.helper).hasClass('other-menu-ico') && $(_ui.helper).is('a')){
	    		$(_ui.helper).remove();
	    		$('.other-menu-ico').css('display','block');
				return;
			}

			var divideMenu = $(_ui.helper).children('.divide-menu');

			var currentItem = gDashboard.itemGenerateManager.focusedItem;

			var container = $(this).attr('id');
			//2020.02.19 MKSONG 필드 드롭 가능한 지역 BORDER 추가 위해 불필요한 부분 제거 DOGFOOT

			if (_ui.helper) _ui.helper.removeClass("wise-area-drop-over");

			var targetContainer;
			var containerType = container.substring(0,container.lastIndexOf('t')+1);

			if($(_ui.helper).hasClass('selected') && $(_ui.helper).attr('prev-container') != 'deltavalueList'){
	    		$(_ui.helper).remove();
	    		return;
	    	}


			var prevContainer;
			if(_ui.helper.attr('prev-container') != undefined){
				prevContainer = _ui.helper.attr('prev-container');
			}else{
				prevContainer = _ui.helper.children().attr('prev-container');
			}
			var dataItem = _ui.helper;
			var cubeInsertYN = true;
			
//			if(WISE.Constants.editmode == "viewer" && gDashboard.reportType == 'AdHoc' && userJsonObject.goyongList.indexOf(Number(WISE.Constants.pid)) > -1
//					&& prevContainer == 'allList' && containerType != 'allList') {
//				var dimNumber = 0;
//				if(dataItem.hasClass('wise-field-group')){
//					$.each(dataItem.find('.dataset').children(),function(_i,_dataItem){
//						if(typeof $(_dataItem).attr('data-field-type') != 'undefined' && $(_dataItem).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//				}else{
//					var columnList = $('#colAdHocList' + currentItem.index).children().children('li');
//					var rowList = $('#rowAdHocList' + currentItem.index).children().children('li');
//					var dimNumber = 0;
//					$.each(rowList, function(_i, _row){
//						if(typeof $(_row).attr('data-field-type') != 'undefined' && $(_row).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//					$.each(columnList, function(_i, _col){
//						if(typeof $(_col).attr('data-field-type') != 'undefined' && $(_col).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//				}
//				if(dimNumber > 3 && $(_ui.helper).attr('data-field-type') == 'dimension') {
//					WISE.alert('고용행정통계 보고서는 차원을 4개이상으로 조회하실 수 없습니다.');
//					$(_ui.helper).remove();
//					cubeInsertYN = false;
//				}
//			} else if(WISE.Constants.editmode == "viewer" && gDashboard.reportType == 'AdHoc' && userJsonObject.goyongAdhocList.indexOf(Number(WISE.Constants.pid)) == -1
//					&& prevContainer == 'allList' && containerType != 'allList') {
//				var dimNumber = 0;
//				if(dataItem.hasClass('wise-field-group')){
//					$.each(dataItem.find('.dataset').children(),function(_i,_dataItem){
//						if(typeof $(_dataItem).attr('data-field-type') != 'undefined' && $(_dataItem).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//				}else{
//					var columnList = $('#colAdHocList' + currentItem.index).children().children('li');
//					var rowList = $('#rowAdHocList' + currentItem.index).children().children('li');
//					$.each(rowList, function(_i, _row){
//						if(typeof $(_row).attr('data-field-type') != 'undefined' && $(_row).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//					$.each(columnList, function(_i, _col){
//						if(typeof $(_col).attr('data-field-type') != 'undefined' && $(_col).attr('data-field-type') == 'dimension') {
//							dimNumber++;
//						}
//					});
//				}
//				if(dimNumber > 7 && $(_ui.helper).attr('data-field-type') == 'dimension') {
//					WISE.alert('일반 비정형 보고서는 차원을 8개이상으로 조회하실 수 없습니다.');
//					$(_ui.helper).remove();
//					cubeInsertYN = false;
//				}
//			}

			var prevContainerType = prevContainer == undefined ? '' : prevContainer.substring(0,prevContainer.lastIndexOf('t')+1);

			if(container.indexOf('hide_measure') === -1 && prevContainer.indexOf('hide_measure') !== -1){
				_ui.helper.attr('data-field-type', _ui.helper.attr('originType'))
			}

			/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
			var dupleCheck = true;

			if (_ui.helper.data('delta-source')) {
				$(_ui.helper).draggable("option", "revert", true);
				WISE.alert(gMessage.get('WISE.message.page.widget.pivot.exist.referenced.fileds', [_ui.helper.data('delta-referenced')]));
			} else if (_ui.helper.data('cannot-move')) {
//				$(_ui.helper).draggable("option", "revert", true);
				$(_ui.helper).remove();

				var currentContainer = $(_ui.helper).attr('prev-container');
				if(currentContainer != undefined){
					if($('#'+currentContainer).children().length == 0){
						if(gDashboard.fieldManager.stateFieldChooser.children().find('.other-menu-ico').length == 0){
							gDashboard.fieldManager.stateFieldChooser.children().removeAttr('data-source-id');
						}

						//2020.03.02 MKSONG recovery 부분 함수화 DOGFOOT
						self.recovery($('#'+currentContainer));
						$('#'+currentContainer).droppable("enable").sortable('disable');
					}
				}

			} else if ((_ui.helper.attr('data-field-type') === 'dimension' && containerType === 'rowList')
						||(_ui.helper.attr('data-field-type') === 'dimension' && containerType === 'colList')
						/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
						||(_ui.helper.attr('data-field-type') === 'measure' && containerType === 'dataList')
						||(_ui.helper.attr('data-field-type') === 'measure' && containerType === 'dataAdHocList')
						|| (_ui.helper.attr('data-field-type') === 'dimension' && containerType === 'rowAdHocList')
						|| (_ui.helper.attr('data-field-type') === 'dimension' && containerType === 'colAdHocList')) {
				//2020.03.02 MKSONG 그룹별 데이터 항목 추가 기능 DOGFOOT
				if($(_ui.helper).hasClass('wise-field-group')){
					$.each($(_ui.helper).find('.dataset').children(),function(_i,_dataItem){
					/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
						dupleCheck = self.duplicatedCheck(container,$(_dataItem));
						if(dupleCheck) {
							cubeInsertYN = false;
							$(_ui.helper).remove();
						}
					});
				} else {
				/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
					dupleCheck = self.duplicatedCheck(container,$(_ui.helper), prevContainer);
					if(dupleCheck) {
						cubeInsertYN = false;
					}
				}
				targetContainer = $('#' + container);
			} else if (containerType === 'downloadexpand_colList' || containerType === 'chartValueList' || containerType === 'chartParameterList' || containerType === 'chartSeriesList' || containerType === 'chart_hide_dimension_list' || containerType === 'chart_hide_measure_list' ||
					containerType === 'pieValueList' || containerType === 'pieParameterList' || containerType === 'pieSeriesList' || containerType === 'pie_hide_dimension_list' || containerType === 'pie_hide_measure_list' || containerType === 'card_hide_measure_list' ||
					containerType === 'columnList' || containerType === 'sparkLine' || containerType === 'hide_dimension_list' || containerType === 'hide_measure_list' || containerType === 'mapParameterList' || containerType === 'mapValueList' ||
					containerType === 'treemapValueList' || containerType === 'treemapParameterList' || containerType === 'parallelValueList' || containerType === 'parallelParameterList'  || containerType === 'RectangularAreaChartValueList' || containerType === 'RectangularAreaChartParameterList'  || containerType === 'waterfallchartValueList' || containerType === 'waterfallchartParameterList' ||
					containerType === 'bipartitechartValueList' || containerType === 'bipartitechartParameterList' || containerType === 'funnelchartValueList' || containerType === 'funnelchartParameterList' || containerType === 'pyramidchartValueList' || containerType === 'pyramidchartParameterList' ||
					containerType === 'sankeychartValueList' || containerType === 'sankeychartParameterList' || containerType === 'adhoc_hide_measure_list' || containerType === 'divergingchartParameterList' || containerType === 'divergingchartValueList' || containerType === 'divergingchartSeriesList' ||
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
					containerType === 'kakaoMapValueList' || containerType === 'kakaoMapParameterList' || containerType === 'kakaoMapLatitudeList' || containerType === 'kakaoMapLongitudeList' ||
					containerType === 'kakaoMap2ValueList' || containerType === 'kakaoMap2ParameterList' || containerType === 'kakaomapLatitudeList' || containerType === 'kakaomapLongitudeList' || containerType === 'kakaomapAddressList' || containerType === 'kakaomapFieldList' ||
					containerType === 'bubbled3ValueList' || containerType === 'bubbled3ParameterList' || containerType === 'heatmapValueList' || containerType === 'heatmapParameterList' || containerType === 'heatmap_hide_measure_list' || containerType === 'heatmap2_hide_measure_list'|| containerType === 'syncchart_hide_measure_list'||
					 containerType === 'wordcloudValueList' || containerType === 'wordcloudParameterList' ||containerType === 'pivot_hide_measure_list' || containerType == 'grid_hide_measure_list' || containerType == 'chart_hide_measure_list' || containerType == 'pie_hide_measure_list' ||
					containerType === 'histogramchartValueList' || containerType === 'histogramchartParameterList' || containerType === 'hierarchicalParameterList' || containerType === 'heatmap2ValueList' || containerType === 'heatmap2ParameterList' || containerType === 'syncchartValueList' || containerType === 'syncchartParameterList' ||
					//2020.02.07 mksong listbox_hide_measure_list 추가 dogfoot
					containerType === 'textboxValueList' || containerType === 'textbox_measure_list' || containerType == 'listbox_hide_measure_list' || containerType === 'divergingchart_hide_measure_list' || containerType === 'scatterplotXList' ||containerType === 'scatterplotYList' ||containerType === 'scatterplotZList' || containerType === 'scatterplot_hide_measure_list' ||
					/* DOGFOOT ktkang 버블차트2 추가  20200721 */
					containerType === 'scatterplot2XList' ||containerType === 'scatterplot2YList' ||containerType === 'scatterplot2ZList' || containerType === 'scatterplot2_hide_measure_list' ||
					containerType === 'cardValueList' || containerType === 'cardSeriesList' || containerType === 'cardSparkLine' || container === 'bubbleChartXList' ||  container === 'bubbleChartYList' ||
					/* DOGFOOT ktkang 측정값 및 차원 이동 시 화살표 아이콘 사라지는 오류 수정  20200619 */
					containerType === 'rowList' || containerType === 'colList' || containerType === 'dataList' || containerType === 'dataAdHocList' ||
					containerType === 'gaugeValueList' || containerType === 'gaugeSeriesList' || containerType === 'forceDirectParameterList' || containerType === 'forceDirectExpandParameterList' ||
					containerType === 'rangebarchartParameterList' ||  containerType === 'rangeareachartParameterList' ||  containerType === 'timelinechartParameterList' ||  containerType === 'timelinechartStartDateList' ||  containerType === 'timelinechartEndDateList' ||
					containerType === 'bubblepackchartValueList' || containerType === 'bubblepackchartParameterList' || containerType === 'divergingchart_hide_measure_list' || containerType === 'scatterplotXList' ||containerType === 'scatterplotYList' ||containerType === 'scatterplotZList' ||
					containerType === 'wordcloudv2ValueList' || containerType === 'wordcloudv2ParameterList' || containerType === 'scatterplot_hide_measure_list' ||
					containerType === 'dendrogrambarchartValueList' || containerType === 'dendrogrambarchartParameterList' ||
					containerType === 'calendarviewchartValueList' || containerType === 'calendarviewchartParameterList' ||
					containerType === 'divergingchartValueList' || containerType === 'divergingchartParameterList' ||
					containerType === 'divergingchartSeriesList'|| containerType === 'dependencywheelParameterList' ||
					containerType === 'sequencessunburstParameterList' || containerType === 'boxplotParameterList'|| containerType === 'coordinatelineParameterList' ||
					containerType === 'scatterplot2ParameterList' || containerType === 'scatterplotParameterList' || containerType === 'liquidfillgaugeParameterList' ||
					containerType === 'dependencywheelParameterList' || containerType === 'sequencessunburstParameterList' ||
					containerType === 'boxplotParameterList'|| containerType === 'scatterplotParameterList' || containerType === 'liquidfillgaugeParameterList'||
					containerType === 'calendarview2chartValueList' || containerType === 'calendarview2chartParameterList'||
					containerType === 'calendarview3chartValueList' || containerType === 'calendarview3chartParameterList'||
					containerType === 'collapsibletreechartValueList' || containerType === 'collapsibletreechartParameterList'
					|| containerType === 'radialTidyTreeParameterList'|| containerType === 'scatterPlotMatrixX1List'|| containerType === 'scatterPlotMatrixX2List'|| containerType === 'scatterPlotMatrixY1List'|| containerType === 'scatterPlotMatrixY2List'||
					containerType === 'scatterPlotMatrixParameterList'|| containerType === 'historyTimelineParameterList'|| containerType === 'historyTimelineEndList'|| containerType === 'historyTimelineStartList' || containerType === 'arcdiagramParameterList'
						/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
						|| containerType === 'onewayAnovaObservedList' || containerType === 'onewayAnovaFactorList' || containerType === 'rFieldList'
						|| containerType === 'onewayAnova2ObservedList' || containerType === 'onewayAnova2FactorList' || containerType === 'onewayAnova2ItemList'
						|| containerType === 'twowayAnovaObservedList' || containerType === 'twowayAnovaFactorList'
						|| containerType === 'pearsonsCorrelationNumericalList' || containerType === 'spearmansCorrelationNumericalList'
						|| containerType === 'simpleRegressionIndpnList' || containerType === 'simpleRegressionDpndnList' || containerType === 'simpleRegressionVectorList'
						|| containerType === 'multipleRegressionIndpnList' || containerType === 'multipleRegressionDpndnList' || containerType === 'multipleRegressionVectorList'
						|| containerType === 'logisticRegressionIndpnList' || containerType === 'logisticRegressionDpndnList' || containerType === 'logisticRegressionVectorList'
						|| containerType === 'multipleLogisticRegressionIndpnList' || containerType === 'multipleLogisticRegressionDpndnList' || containerType === 'multipleLogisticRegressionVectorList'
						|| containerType === 'tTestNumericalList' || containerType === 'zTestNumericalList' || containerType === 'chiTestNumericalList' || containerType === 'fTestNumericalList'
						|| containerType === 'multivariateNumericalList' || containerType === 'multivariateParameterList'
			){
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
				// yyb containerType에 hide_measure_list 포함여부 체크로 변경 20210205
				if (WISE.Context.isCubeReport && containerType.indexOf('hide_measure_list') == -1 && !(_ui.helper.hasClass('wise-field-group')) && gDashboard.reportType == 'AdHoc'){
					WISE.alert('주제영역을 사용하실 때 측정값은 측정값 부분에 차원은 행이나 열 부분에 넣으셔야 합니다.');
					$(_ui.helper).remove();
				}
				else{
					var fType = _ui.helper.attr('data-field-type');

					if((container.indexOf("rowList") >= 0 || container.indexOf("colList") >= 0 || container.indexOf("Parameter") > 0) &&
						fType === 'measure' && gDashboard.reportType === 'AdHoc')
					{
						_ui.helper.remove();
						WISE.alert('비정형 보고서에서는 측정값을 측정값 항목에 넣으셔야 합니다.');
						return;
					}else if((container.indexOf("Value") >= 0 || container.indexOf("data") >= 0) && fType === 'dimension' && gDashboard.reportType === 'AdHoc'){
						_ui.helper.remove();
						WISE.alert('비정형 보고서에서는 차원을 차원(행/열) 항목에 넣으셔야 합니다.');
						return;
					}
					/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 20200618 */
					if($(_ui.helper).hasClass('wise-field-group')){
						$.each($(_ui.helper).find('.dataset').children(),function(_i,_dataItem){
						/* DOGFOOT ktkang 주제영역 오류 수정  20200717 */
							if(self.dataItemContainerTypeCheck($(_dataItem), containerType) == "" && WISE.Context.isCubeReport){
								WISE.alert('주제영역을 사용하실 때 측정값은 측정값 부분에 차원은 차원 부분(ex. 행, 열)에 넣으셔야 합니다.');
								cubeInsertYN = false;
							} else if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
								dupleCheck = self.duplicatedCheck(container,$(_dataItem));
							} else if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
								dupleCheck = self.duplicatedCheck(container,$(_dataItem));
							}
							/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
							if(dupleCheck) {
								cubeInsertYN = false;

							}
						});
						if(!cubeInsertYN) {
							$(_ui.helper).remove();
						}
					}
					else {
						/* DOGFOOT ktkang 주제영역 오류 수정  20200717 */
						if(self.dataItemContainerTypeCheck($(_ui.helper), containerType) == "" && WISE.Context.isCubeReport){
							WISE.alert('주제영역을 사용하실 때 측정값은 측정값 부분에 차원은 차원 부분(ex. 행, 열)에 넣으셔야 합니다.');
							cubeInsertYN = false;
							$(_ui.helper).remove();
						} else {
							dupleCheck = self.duplicatedCheck(container,$(_ui.helper));
						}

						if(dupleCheck) {
							cubeInsertYN = false;
						}
					}
					/*dogfoot 측정값 그룹 추가 오류 수정 shlim 20200716*/
					targetContainer = $('#' + container);
//					targetContainer = $('#'+container).children().eq($('#' + container).children().index(_ui.helper)+1);
				}
				_ui.helper.removeClass("wise-field-leaf");
				_ui.helper.removeClass("wise-no-border");
			}
			//필터
			else if (container === 'cont_query' && _ui.helper.attr('data-field-type') === 'dimension' && _ui.helper.attr('data-field-uname').indexOf('HieLvl') === -1){
				if (self.reportType === 'cube'){
					self.fieldFilter.addFilter(_ui.helper.clone());
					gDashboard.queryHandler.query();
				}
			}
			else if(containerType != 'deltavalueList' &&  _ui.helper.attr('deltaid') != undefined){
				var deltaId  = _ui.helper.attr('deltaid');
//				var itemId = gDashboard.fieldManager.stateFieldChooser.attr('id').substring(0,gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager'));
//				var _item;
//				$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_o){
//					if(_o.ComponentName == itemId){
//						_item = _o;
//						return false;
//					}
//				});
				var _item = gDashboard.itemGenerateManager.dxItemBasten[1].deltaItems?
						gDashboard.itemGenerateManager.dxItemBasten[1] : gDashboard.itemGenerateManager.dxItemBasten[0];

				$.each(_item.deltaItems,function(_i,_delta){
					if(_delta.ID == deltaId){
						_item.deltaItems.splice(_i, 1);
						_item.deltaItemlength = _item.deltaItems.length;
						return false;
					}
				});
				if(_item.deltaItemlength === 0){
					$('#deltavalueList'+_item.adhocIndex).parent().css('display', 'none')
				}
				$(_ui.helper).remove();
			}else if(containerType == 'deltavalueList' &&  _ui.helper.attr('deltaid') != undefined){
				targetContainer = $('#'+container);
			}
			else{
				targetContainer = $('#'+container).children().eq($('#' + container).children().index(_ui.helper)+1);
			}

			//필터

			gDashboard.fieldManager.isChange = true;
			/*if (container !== _ui.draggable.attr('data-prevList')){
				self.fieldManager.isChange = true;
			}*/
			/*dogfoot shlim 차트별 측정값및 차원 개수 제한 함수 추가 20200630*/
			/*dogfoot 피벗그리드 뷰어 컬럼선택기 오류 수정 shlim 20200717*/
			if(WISE.Constants.editmode == 'viewer') {
				//var dataLength = $('#'+containerType + self.item.index).children('ul.analysis-data') ? $('#'+containerType + self.item.index).children('ul.analysis-data').length : 0;
				var addCheck =  self.chartLengOptins(containerType,-1); ;
			}else{
				var dataLength = $('#'+containerType + self.item.index).children('ul.analysis-data') ? $('#'+containerType + self.item.index).children('ul.analysis-data').length : 0;
				if(gDashboard.reportType === 'StaticAnalysis' && dataLength === 0){
					dataLength = $('#'+containerType + 1).children('ul.analysis-data') ? $('#'+containerType + 1).children('ul.analysis-data').length : 0;
				}
				var addCheck =  self.chartLengOptins(containerType,dataLength); ;
			}


			if(targetContainer != undefined){
				if (container != 'allList'){
					if(gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id') != undefined){
			    		var helperDataSourceId = _ui.helper.children().attr('data-source-id') == undefined ? _ui.helper.attr('data-source-id') : _ui.helper.children().attr('data-source-id');
						if(helperDataSourceId != gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id')){
							var deleteFiled;
							if(_ui.helper.attr('deltaid') == undefined){
								deleteFiled = confirm('현재 아이템에 사용되고 있는 데이터집합과 다른 데이터 집합의 필드입니다.\n추가하시길 원하신다면 기존의 데이터집합 필드는 모두 소멸됩니다. 진행하시겠습니까?');
							}else{
								deleteFiled = false;
							}

							if(deleteFiled){
								//2020.01.31 MKSONG 데이터 소스 변경 오류 수정 DOGFOOT
								gDashboard.itemGenerateManager.focusedItem.dataSourceId = helperDataSourceId;
								$.each(gDashboard.fieldManager.stateFieldChooser.children().find('.drop-panel'),function(_i, _o){
									var $o = $(_o);
									$o.empty();
									self.recovery($o);
								});
							}else{
								if(_ui.helper.attr('deltaid') != undefined){
									_ui.helper.appendTo(targetContainer);
								}else{
									_ui.helper.remove();
								}

							}
						}
					}

					// 계산필드인지 확인
					var customFieldFlag = false;
					var customFieldInfo = gDashboard.customFieldManager.fieldInfo;
					if(!($.isEmptyObject(customFieldInfo))) {
						$.each(gDashboard.customFieldManager.fieldInfo[_ui.helper.attr('data-source-id')],function(i,item){
							if(item.Name==_ui.helper.attr('uni_nm')) customFieldFlag = true;
						});
					}

					/* DOGFOOT ktkang 주제영역 폴더 드래그앤 드롭 기능 오류 수정  20200709 */
					if(cubeInsertYN) {
						if(dataItem.hasClass('wise-field-group')){
							$.each(dataItem.find('.dataset').children(),function(_i,_dataItem){
								/*dogfoot shlim 차트별 측정값및 차원 개수 제한 함수 추가 20200630*/
								addCheck = self.chartLengOptins(containerType,dataLength);
								/* DOGFOOT ktkang 측정값 및 차원 이동 시 화살표 아이콘 사라지는 오류 수정  20200619 */
								if(!addCheck){
									WISE.alert('해당 영역에 데이터 항목을 <br> 더이상 넣을 수 없습니다.');
									$(_ui.helper).remove();
								}else{
									if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
										self.dataItemSetting('drop', _ui.helper, $(_dataItem), container, prevContainer, targetContainer, self.item, 'multiple');
										dataLength++;
									} else if(self.dataItemContainerTypeCheck($(_dataItem), containerType)) {
										self.dataItemSetting('drop', _ui.helper, $(_dataItem), container, prevContainer, targetContainer, self.item, 'multiple');
										dataLength++;
									}
								}
							});
							dataItem.remove();
						}else{
							if(containerType === "deltavalueList" && typeof _ui.helper.prevObject.attr('deltaid') === "undefined"){
								$(_ui.helper).remove();
								WISE.alert('변동측정값에는 일반 차원을<br>넣을 수 없습니다.');
							}
//							else if(customFieldFlag && container.indexOf('ValueList')<0 && container.indexOf('dataAdHocList')<0 && container.indexOf('columnList')<0 && container.indexOf('dataList')<0 && container != 'allList'){
//								$(_ui.helper).remove();
//								WISE.alert('사용자 정의 데이터는<br>측정값 외에 넣을 수 없습니다.');
//							}
							else{
								/*dogfoot shlim 차트별 측정값및 차원 개수 제한 함수 추가 20200630*/
								if(!addCheck){
									WISE.alert('해당 영역에 데이터 항목을 <br> 더이상 넣을 수 없습니다.');
									$(_ui.helper).remove();
								}else{
									self.dataItemSetting('receive', _ui.helper, dataItem, container, prevContainer, targetContainer, self.item, 'single');
								}
//								self.dataItemSetting('receive', _ui.helper, dataItem, container, prevContainer, targetContainer, self.item, 'single');
							}
						}
					}
//					$(_ui.helper).remove();
				}
			}

//					$('.ui-draggable-dragging').remove();
//			$('.ui-draggable-dragging:not(.other-menu)').remove();

			//검색10
			_ui.helper
				.children("div.wise-area-caption")
				.text(_ui.helper.children("div.wise-area-caption").text());

			//검색10

			/* update chart options in real time */
//			2019.12.16 mksong preferences config undefined 오류 수정 dogfoot
			if (gDashboard.preferences.config != undefined){
				if (gDashboard.preferences.config.autoUpdate) {
					var currentItem = gDashboard.itemGenerateManager.focusedItem;
					if (currentItem.dxItem && currentItem.type === 'SIMPLE_CHART') {
						currentItem.setChart();
						currentItem.bindData(currentItem.globalData, true);
					} else if (_item.type === 'SIMPLE_CHART') {
						gDashboard.itemGenerateManager.clearTrackingConditionAll();
						gDashboard.query();
					}
				}
			}
			/* DOGFOOT ktkang 주제영역 관계 표시 부분 오류 수정  20200305 */
			if(WISE.Context.isCubeReport && _ui.helper.attr('data-field-type') === 'measure' && (containerType != 'rowList' || containerType != 'colList' && containerType != 'pivot_hide_measure_list')){
				self.cubeRelationCheck(currentItem);
			}

		}, over: function(_event, _ui) {
			if($(_ui.helper).hasClass('other-menu-ico') && $(_ui.helper).is('a')){
				$(_ui.helper).remove();
				$('.other-menu-ico').css('display','block');
				return;
			}else{
				$('.divide-menu .other-menu-ico').css('display','none');
			}
			compMoreMenuUi();
			var container = $(this).attr('id');
			var containerType = container.substring(0,container.lastIndexOf('t')+1);
			var draggableType = _ui.helper.attr('dataType');

			if(_item != undefined){
//				switch (containerType) {
//	//			case 'colList':
//	//			case 'rowList':
//	//			case 'chartParameterList':
//	//			case 'pieParameterList':
//	//			case 'chartSeriesList':
//	//			case 'parallelParameterList':
//	//			case 'starchartParameterList':
//	//			case 'treemapParameterList':
//	//			case 'starchartSeriesList':
//	//				if (draggableType === 'measure') {
//	//					$(this).addClass("focus-none");
//	//					_ui.helper.data('cannot-move', true);
//	//				}
//	//				else {
//	//					$(this).addClass("focus-use");
//	//					_ui.helper.data('cannot-move', false);
//	//				}
//	//				return;
//				case 'dataList':
//				case 'sparkline':
//				case 'chartValueList':
//				case 'pieValueList':
//				case 'parallelValueList':
//				case 'RectangularAreaChartValueList':
//				case 'waterfallchartValueList':
//				case 'histogramchartValueList':
//				case 'bubbled3ValueList':
//				case 'treemapValueList':
//				case 'starchartValueList':
//				case 'textboxValueList':
//				case 'cardValueList':
//					if (draggableType === 'dimension') {
//						$(this).addClass("focus-none");
//						_ui.helper.data('cannot-move', true);
//					}
//					else {
//						$(this).addClass("focus-use");
//						_ui.helper.data('cannot-move', false);
//					}
//					return;
//				case 'chart_hide_dimension_list':
//				case 'pie_hide_dimension_list':
//				case 'hide_dimension_list':
//					if (draggableType === 'measure') {
//						$(this).addClass("focus-none");
//						_ui.helper.data('cannot-move', true);
//					}
//					else {
//						$(this).addClass("focus-use");
//						_ui.helper.data('cannot-move', false);
//					}
//					return;
//				case 'chart_hide_measure_list':
//				case 'pie_hide_measure_list':
//				case 'textbox_hide_measure_list':
//				case 'hide_measure_list':
//				case 'card_hide_measure_list':
//					if (draggableType === 'dimension') {
//						$(this).addClass("focus-none");
//						_ui.helper.data('cannot-move', true);
//					}
//					else {
//						$(this).addClass("focus-use");
//						_ui.helper.data('cannot-move', false);
//					}
//					return;
//				case 'deltavalueList':
//					 if($(_ui.helper).attr('deltaid') == undefined){
//					 	$(this).addClass("focus-none");
//						_ui.helper.data('cannot-move', true);
//					 }
//					break;
//				default:
//					$(this).addClass("focus-use");
//					_ui.helper.data('cannot-move', false);
//				}
			}

			if(gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id') != undefined){
				if(_ui.helper.attr('data-source-id') != gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id')){
//					$(this).addClass("focus-none");
				}
			}
		},	out: function(_event, _ui) {
				compMoreMenuUi();
	//		if($(this).find('ul.wise-area-drop-over')){
	//			$(this).find('ul.wise-area-drop-over').removeClass("wise-area-drop-over");
	//		} else{

				if(_ui.helper != null){
					_ui.helper.data('cannot-move', false);
				}

				//2020.02.19 MKSONG 필드 드롭 가능한 지역 BORDER 추가 위해 불필요한 부분 제거 DOGFOOT
				$(this).removeClass("focus-none");
	//		}

		}, stop:function(event, _ui){
			$('.other-menu-ico').css('display','block');
			// 고용정보원09 싱글뷰 일때만 display가 나오는데 .other-menu-ico block 해주면서 다 나타남
			if(typeof gDashboard.isSingleView == 'undefined' || gDashboard.isSingleView == false){
				$('#viewerDownload').css('display','none');
				$('#viewerAdhoc').css('display','none');
			}
			
			compMoreMenuUi();
		}
//		,	out:function(_event,_ui){
//			var container = $(this).attr('id');
//			var currentItem = $('#'+_ui.placeholder).attr('id');
////			var itemHeight = $('#' + currentItem).height();
////			var itemWidth = $('#' + currentItem).width();
//			if(_ui.position.top > (_ui.originalPosition.top) && Math.abs(_ui.position.left) > (_ui.originalPosition.left)){
//				_ui.placeholder.remove();
//			}
//
//			if($('#'+container).length == 1){
//				$('#'+container).droppable('enable').sortable('disable');
//			}
//

//		}
	}


	this.addSortableOptions = function(_item){
		switch (_item.fieldManager.focusItemType){
		case 'pivotGrid' :
//			_item.fieldManager.panelManager['rowContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			if (_item.fieldManager.panelManager['rowContentPanel'+_item.index].find('.analysis-data').length > 0) {
				_item.fieldManager.panelManager['rowContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['rowContentPanel'+_item.index].droppable('disable');
			}
			if (_item.fieldManager.panelManager['colContentPanel'+_item.index].find('.analysis-data').length > 0) {
				_item.fieldManager.panelManager['colContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['colContentPanel'+_item.index].droppable('disable');
			}
			if (_item.fieldManager.panelManager['datafieldContentPanel'+_item.index].find('.analysis-data').length > 0) {
				_item.fieldManager.panelManager['datafieldContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
			}
//			if (_item.fieldManager.panelManager['deltaValueContentPanel'+_item.index].find('.analysis-data').length > 0) {
//				_item.fieldManager.panelManager['deltaValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//			}
			_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions)
			break;
		case 'dataGrid' :
			_item.fieldManager.panelManager['dataContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'chart' :
			_item.fieldManager.panelManager['chartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['chartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['chartSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['chart_hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'pieChart' :
			_item.fieldManager.panelManager['pieValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['pieParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['pieSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['pie_hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['pie_hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'card' :
			_item.fieldManager.panelManager['cardValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['cardSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['cardSparkLineContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['card_hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		/* DOGFOOT hsshim 2020-02-03 게이지 데이터 항목 UI 및 기능 작업 */
		case 'gauge' :
			_item.fieldManager.panelManager['gaugeValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['gaugeSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['pie_hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'choroplethMap' :
			_item.fieldManager.panelManager['mapValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['mapStateContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['mapCityContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['mapDongContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
			/* DOGFOOT syjin 카카오 지도 추가  20200820 */
		case 'kakaoMap' :
			_item.fieldManager.panelManager['kakaoMapValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['kakaoMapParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['kakaoMapLatitudeContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['kakaoMapLongitudeContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['kakaoMapAddressContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['kakaoMapFieldListContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);

			//_item.fieldManager.panelManager['kakaoMapSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'kakaoMap2' :
			_item.fieldManager.panelManager['kakaoMap2ValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['kakaoMap2ParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			//_item.fieldManager.panelManager['kakaoMap2LatitudeContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			//_item.fieldManager.panelManager['kakaoMap2LongitudeContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			//_item.fieldManager.panelManager['kakaoMapSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'Treemap' :
			_item.fieldManager.panelManager['treemapValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['treemapParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'parallel' :
			_item.fieldManager.panelManager['parallelValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['parallelParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'bubblepackchart' :
			_item.fieldManager.panelManager['bubblepackchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['bubblepackchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'wordcloudv2' :
			_item.fieldManager.panelManager['wordcloudv2ValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['wordcloudv2ParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'dendrogrambarchart' :
			_item.fieldManager.panelManager['dendrogrambarchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['dendrogrambarchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'calendarviewchart' :
			_item.fieldManager.panelManager['calendarviewchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['calendarviewchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'calendarview2chart' :
			_item.fieldManager.panelManager['calendarview2chartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['calendarview2chartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'calendarview3chart' :
			_item.fieldManager.panelManager['calendarview3chartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['calendarview3chartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'collapsibletreechart' :
			_item.fieldManager.panelManager['collapsibletreechartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['collapsibletreechartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'RectangularAreaChart' :
			_item.fieldManager.panelManager['RectangularAreaChartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['RectangularAreaChartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'waterfallchart' :
			_item.fieldManager.panelManager['waterfallchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['waterfallchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'bipartitechart' :
//			_item.fieldManager.panelManager['bipartitechartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['bipartitechartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'sankeychart' :
//			_item.fieldManager.panelManager['sankeychartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['sankeychartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'histogramchart' :
			_item.fieldManager.panelManager['histogramchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
//			_item.fieldManager.panelManager['histogramchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'funnelchart' :
			_item.fieldManager.panelManager['funnelchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['funnelchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'pyramidchart' :
			_item.fieldManager.panelManager['pyramidchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['pyramidchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'bubbleChart' :
			_item.fieldManager.panelManager['bubbleChartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['bubbleChartYContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['bubbleChartXContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'bubbled3' :
			_item.fieldManager.panelManager['bubbled3ValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['bubbled3ParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'Starchart' :
			_item.fieldManager.panelManager['starchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['starchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['starchartSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['starchart_hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['starchart_hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'heatmap' :
			_item.fieldManager.panelManager['heatmapValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['heatmapParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['heatmap_hide_measure_listContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
		case 'heatmap2' :
			_item.fieldManager.panelManager['heatmap2ValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['heatmap2ParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['heatmap2_hide_measure_listContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'heatmap2' :
			_item.fieldManager.panelManager['syncchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['syncchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['syncchart_hide_measure_listContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'wordcloud' :
			_item.fieldManager.panelManager['wordcloudValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['wordcloudParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'adhocItem' :
//			_item.fieldManager.panelManager['rowContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['rowAdHocContentPanel'+_item.adhocIndex].droppable('disable').sortable('enable');
			_item.fieldManager.panelManager['colAdHocContentPanel'+_item.adhocIndex].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['datafieldAdHocContentPanel'+_item.adhocIndex].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+_item.adhocIndex].droppable('disable').sortable(this.sortableOptions)
			break;
		case 'listBox' :
			_item.fieldManager.panelManager['dimfieldContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'treeView' :
			_item.fieldManager.panelManager['tv_dimfieldContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'comboBox' :
			_item.fieldManager.panelManager['cb_dimfieldContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'textBox' : // ymbin
			if(gDashboard.reportType === 'RAnalysis'){
				_item.fieldManager.panelManager['rFieldContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
//				 _item.fieldManager.panelManager['textbox_hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			}else{
				_item.fieldManager.panelManager['textboxValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
//				 _item.fieldManager.panelManager['textbox_hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
				 _item.fieldManager.panelManager['textbox_hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			}
			break;
		case 'hierarchical' :
			_item.fieldManager.panelManager['hierarchicalParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'forceDirect' :
			//_item.fieldManager.panelManager['forceDirectValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['forceDirectParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'forceDirectExpand' :
			//_item.fieldManager.panelManager['forceDirectExpandValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['forceDirectExpandParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'rangebarchart' :
			_item.fieldManager.panelManager['rangebarchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['rangebarchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
//			_item.fieldManager.panelManager['rangebarchartSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			// _item.fieldManager.panelManager['chart_hide_column_list_dimContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'rangeareachart' :
			_item.fieldManager.panelManager['rangeareachartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['rangeareachartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'timelinechart' :
			_item.fieldManager.panelManager['timelinechartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['timelinechartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['timelinechartSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['timelinechartStartDateContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['timelinechartEndDateContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'divergingchart' :
			_item.fieldManager.panelManager['divergingchartValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['divergingchartParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['divergingchartSeriesContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
//			_item.fieldManager.panelManager['divergingchart_hide_column_list_meaContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'dependencywheel' :
//			_item.fieldManager.panelManager['dependencywheelValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['dependencywheelParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'sequencessunburst' :
			_item.fieldManager.panelManager['sequencessunburstValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['sequencessunburstParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'boxplot' :
			_item.fieldManager.panelManager['boxplotValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['boxplotParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'scatterplot' :
			_item.fieldManager.panelManager['scatterplotXContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterplotYContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterplotParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'coordinateline' :
			_item.fieldManager.panelManager['coordinatelineXContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['coordinatelineYContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['coordinatelineParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'coordinatedot' :
			_item.fieldManager.panelManager['coordinatedotXContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['coordinatedotYContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['coordinatedotParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'scatterplot2' :
			_item.fieldManager.panelManager['scatterplot2XContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterplot2YContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterplot2ZContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterplot2ParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'radialtidytree' :
			_item.fieldManager.panelManager['radialTidyTreeParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'arcdiagram' :
			_item.fieldManager.panelManager['arcdiagramParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'scatterplotmatrix' :
			_item.fieldManager.panelManager['scatterPlotMatrixX1ContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterPlotMatrixX2ContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterPlotMatrixY1ContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterPlotMatrixY2ContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['scatterplotMatrixParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'historytimeline' :
			_item.fieldManager.panelManager['historyTimelineParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['historyTimelineStartContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['historyTimelineEndContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'liquidfillgauge' :
			_item.fieldManager.panelManager['liquidfillgaugeValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager['liquidfillgaugeParameterContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
			break;
		/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
		case 'onewayAnova' :
		case 'twowayAnova' :
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'onwayAnova2' :
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ItemContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'pearsonsCorrelation' :
		case 'spearmansCorrelation' :
		/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
		case 'tTest' :
		case 'zTest' :
		case 'chiTest' :
		case 'fTest' :
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			break;
		/* DOGFOOT ktkang 다변량분석 추가  20210215 */
		case 'multivariate' :
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ParameterContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			break;
		case 'simpleRegression' :
		case 'multipleRegression' :
		case 'logisticRegression' :
		case 'multipleLogisticRegression' :
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'IndpnContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'DpndnContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'VectorContentPanel1'].droppable('disable').sortable(this.sortableOptions);
			break;
		}

	};

	this.addDroppableOptions = function(_item) {
		switch (_item.fieldManager.focusItemType){
			case 'pivotGrid' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rowContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['rowContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['colContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['colContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['datafieldContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['datafieldContentPanel'+_item.index].sortable('disable');
				if(gDashboard.reportType == 'Adhoc' || _item.isAdhocItem){
					_item.fieldManager.panelManager['deltaValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					_item.fieldManager.panelManager['deltaValueContentPanel'+_item.index].droppable('disable');
				}

				_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+_item.index].sortable('disable');

//				_item.fieldManager.panelManager['hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				break;
			case 'dataGrid' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['dataContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['dataContentPanel'+_item.index].sortable('disable');

				if(gDashboard.reportType !== 'DSViewer'){
					_item.fieldManager.panelManager['grid_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					_item.fieldManager.panelManager['grid_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
					_item.fieldManager.panelManager['sparkLineContentPanel'+_item.index].droppable(this.droppableOptions);
				}
				break;
			case 'chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['chartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['chartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['chartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['chartParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['chartSeriesContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['chartSeriesContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'pieChart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['pieValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pieValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['pieParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pieParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['pieSeriesContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pieSeriesContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['pie_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pie_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'card' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['cardValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['cardValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['cardSeriesContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['cardSeriesContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['cardSparkLineContentPanel'+_item.index].droppable(this.droppableOptions);
				 _item.fieldManager.panelManager['card_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				 _item.fieldManager.panelManager['card_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			/* DOGFOOT hsshim 2020-02-03 게이지 데이터 항목 UI 및 기능 작업 */
			case 'gauge' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['gaugeValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['gaugeValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['gaugeSeriesContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['gaugeSeriesContentPanel'+_item.index].sortable('disable');
				// _item.fieldManager.panelManager['gauge_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				// _item.fieldManager.panelManager['gauge_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'choroplethMap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['mapValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['mapValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['mapStateContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['mapStateContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['mapCityContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['mapCityContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['mapDongContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['mapDongContentPanel'+_item.index].sortable('disable');
				break;
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
			case 'kakaoMap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['kakaoMapValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['kakaoMapParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['kakaoMapLatitudeContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapLatitudeContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['kakaoMapLongitudeContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapLongitudeContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['kakaoMapAddressContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapAddressContentPanel'+_item.index].sortable('disable');
				break;
			case 'kakaoMap2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['kakaoMap2ValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMap2ValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['kakaoMap2ParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMap2ParameterContentPanel'+_item.index].sortable('disable');
				/*
				_item.fieldManager.panelManager['kakaoMapLatitudeContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapLatitudeContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['kakaoMapLongitudeContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapLongitudeContentPanel'+_item.index].sortable('disable');
				*/
				break;
			case 'Treemap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['treemapValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['treemapValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['treemapParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['treemapParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'parallel' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['parallelValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['parallelValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['parallelParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['parallelParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'bubblepackchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['bubblepackchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubblepackchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['bubblepackchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubblepackchartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'wordcloudv2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['wordcloudv2ValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['wordcloudv2ValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['wordcloudv2ParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['wordcloudv2ParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'dendrogrambarchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['dendrogrambarchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['dendrogrambarchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['dendrogrambarchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['dendrogrambarchartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'calendarviewchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['calendarviewchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarviewchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['calendarviewchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarviewchartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'calendarview2chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['calendarview2chartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarview2chartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['calendarview2chartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarview2chartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'calendarview3chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['calendarview3chartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarview3chartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['calendarview3chartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarview3chartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'collapsibletreechart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['collapsibletreechartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['collapsibletreechartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['collapsibletreechartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['collapsibletreechartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'rangebarchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rangebarchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['rangebarchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['rangebarchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['rangebarchartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['rangebarchartSeriesContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['rangebarchartSeriesContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['rangebarchart_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['rangebarchart_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'rangeareachart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rangeareachartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['rangeareachartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['rangeareachartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['rangeareachartParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'timelinechart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['timelinechartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['timelinechartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['timelinechartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['timelinechartParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['timelinechartSeriesContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['timelinechartSeriesContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['timelinechartStartDateContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['timelinechartStartDateContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['timelinechartEndDateContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['timelinechartEndDateContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['timelinechart_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['timelinechart_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'RectangularAreaChart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['RectangularAreaChartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['RectangularAreaChartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['RectangularAreaChartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['RectangularAreaChartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'waterfallchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['waterfallchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['waterfallchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['waterfallchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['waterfallchartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'bipartitechart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['bipartitechartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['bipartitechartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['bipartitechartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bipartitechartParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'sankeychart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['sankeychartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['sankeychartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['sankeychartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['sankeychartParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'histogramchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['histogramchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['histogramchartValueContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['histogramchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['histogramchartParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'funnelchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['funnelchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['funnelchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['funnelchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['funnelchartParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'pyramidchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['pyramidchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pyramidchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['pyramidchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pyramidchartParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'bubbled3' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['bubbled3ValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbled3ValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['bubbled3ParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbled3ParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'bubbleChart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['bubbleChartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbleChartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['bubbleChartYContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbleChartYContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['bubbleChartXContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbleChartXContentPanel'+_item.index].sortable('disable');
				break;
			case 'Starchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['starchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['starchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['starchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['starchartParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['starchartSeriesContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['starchartSeriesContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['chart_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'heatmap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['heatmapValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmapValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['heatmapParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmapParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['heatmap_hide_measure_listContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmap_hide_measure_listContentPanel'+_item.index].sortable('disable');
				break;
			case 'heatmap2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['heatmap2ValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmap2ValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['heatmap2ParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmap2ParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['heatmap2_hide_measure_listContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmap2_hide_measure_listContentPanel'+_item.index].sortable('disable');
				break;
			case 'syncchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['syncchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['syncchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['syncchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['syncchartParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['syncchart_hide_measure_listContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['syncchart_hide_measure_listContentPanel'+_item.index].sortable('disable');
				break;
			case 'wordcloud' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['wordcloudValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['wordcloudValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['wordcloudParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['wordcloudParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'adhocItem' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rowAdHocContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['rowAdHocContentPanel'+_item.adhocIndex].sortable('disable');
				_item.fieldManager.panelManager['colAdHocContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['colAdHocContentPanel'+_item.adhocIndex].sortable('disable');
				_item.fieldManager.panelManager['datafieldAdHocContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['datafieldAdHocContentPanel'+_item.adhocIndex].sortable('disable');
				_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].droppable('disable');

				_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+_item.adhocIndex].sortable('disable');

				break;
			case 'listBox' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['dimfieldContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['dimfieldContentPanel'+_item.index].sortable('disable');

				_item.fieldManager.panelManager['listbox_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['listbox_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'treeView' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['tv_dimfieldContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['tv_dimfieldContentPanel'+_item.index].sortable('disable');

				_item.fieldManager.panelManager['treeview_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['treeview_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'comboBox' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['cb_dimfieldContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['cb_dimfieldContentPanel'+_item.index].sortable('disable');

				_item.fieldManager.panelManager['combobox_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['combobox_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'textBox' : // ymbin
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				if(gDashboard.reportType === 'RAnalysis'){
					_item.fieldManager.panelManager['rFieldContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					_item.fieldManager.panelManager['rFieldContentPanel'+_item.index].sortable('disable');

				}else{
					_item.fieldManager.panelManager['textboxValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					_item.fieldManager.panelManager['textboxValueContentPanel'+_item.index].sortable('disable');
					_item.fieldManager.panelManager['textbox_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					_item.fieldManager.panelManager['textbox_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				}
				break;
			case 'hierarchical' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['hierarchicalParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['hierarchicalParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'forceDirect' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				//_item.fieldManager.panelManager['forceDirectValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				//_item.fieldManager.panelManager['forceDirectValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['forceDirectParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['forceDirectParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'forceDirectExpand' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				//_item.fieldManager.panelManager['forceDirectExpandValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				//_item.fieldManager.panelManager['forceDirectExpandValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['forceDirectExpandParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['forceDirectExpandParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'divergingchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['divergingchartValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['divergingchartValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['divergingchartParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['divergingchartParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['divergingchartSeriesContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['divergingchartSeriesContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['divergingchart_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['divergingchart_hide_column_list_meaContentPanel'+_item.index].sortable('disable');
				break;
			case 'dependencywheel' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['dependencywheelValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['dependencywheelValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['dependencywheelParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['dependencywheelParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'sequencessunburst' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['sequencessunburstValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['sequencessunburstValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['sequencessunburstParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['sequencessunburstParameterContentPanel'+_item.index].sortable('disable')
				break;
			case 'boxplot' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['boxplotValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['boxplotValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['boxplotParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['boxplotParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'scatterplot' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['scatterplotXContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplotXContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterplotYContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplotYContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterplotParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplotParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'coordinatedot' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['coordinatedotXContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatedotXContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['coordinatedotYContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatedotYContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['coordinatedotParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatedotParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'coordinateline' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['coordinatelineXContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatelineXContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['coordinatelineYContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatelineYContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['coordinatelineParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatelineParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'scatterplot2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['scatterplot2XContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplot2XContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterplot2YContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplot2YContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterplot2ZContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplot2ZContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterplot2ParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplot2ParameterContentPanel'+_item.index].sortable('disable');
//				_item.fieldManager.panelManager['scatterplot2_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['scatterplot2_hide_column_list_meaContentPanel'+_item.index].sortable('disable');

				break;
			case 'liquidfillgauge' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['liquidfillgaugeValueContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['liquidfillgaugeValueContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['liquidfillgaugeParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['liquidfillgaugeParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'arcdiagram' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['arcdiagramParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['arcdiagramParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'radialtidytree' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['radialTidyTreeParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['radialTidyTreeParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'scatterplotmatrix' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixX1ContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixX1ContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixX2ContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixX2ContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixY1ContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixY1ContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixY2ContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixY2ContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixParameterContentPanel'+_item.index].sortable('disable');
				break;
			case 'historytimeline' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['historyTimelineParameterContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['historyTimelineParameterContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['historyTimelineStartContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['historyTimelineStartContentPanel'+_item.index].sortable('disable');
				_item.fieldManager.panelManager['historyTimelineEndContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['historyTimelineEndContentPanel'+_item.index].sortable('disable');
				break;
			/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
			case 'onewayAnova' :
			case 'onewayAnova2' :
			case 'twowayAnova' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].sortable('disable');
				break;
			/*case 'onewayAnova2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ItemContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ItemContentPanel1'].sortable('disable');
				break;*/
			case 'pearsonsCorrelation' :
			case 'spearmansCorrelation' :
			case 'tTest' :
			case 'zTest' :
			case 'chiTest' :
			case 'fTest' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].sortable('disable');
				break;
			/* DOGFOOT ktkang 다변량분석 추가  20210215 */
			case 'multivariate' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ParameterContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ParameterContentPanel1'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].sortable('disable');
				break;
			case 'simpleRegression' :
			case 'multipleRegression' :
			case 'logisticRegression' :
			case 'multipleLogisticRegression' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'IndpnContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'IndpnContentPanel1'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'DpndnContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'DpndnContentPanel1'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'VectorContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'VectorContentPanel1'].sortable('disable');
				break;

		}
		/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
		if(WISE.Constants.editmode == 'viewer') {
			$('.filter-row').droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
			$('.filter-row').sortable('disable');
		} else {
			$('.filter-bar').droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
			$('.filter-bar').sortable('disable');
		}
	};

	this.toggleDroppableOptions = function(_item) {
		switch (_item.fieldManager.focusItemType){
			case 'pivotGrid' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['rowContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['colContentPanel'+_item.index].droppable('enable').sortable('disable');
				if(gDashboard.reportType == 'Adhoc'){
					_item.fieldManager.panelManager['datafieldContentPanel'+_item.index].droppable('enable').sortable('disable');
					_item.fieldManager.panelManager['deltaValueContentPanel'+_item.index].droppable('enable').droppable('disable');
				}

				_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');

//				_item.fieldManager.panelManager['hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				break;
			case 'dataGrid' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['dataContentPanel'+_item.index].droppable('enable').sortable('disable');

				_item.fieldManager.panelManager['grid_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['sparkLineContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['chartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['chartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['chartSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'pieChart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['pieValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['pieParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['pieSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['pie_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'card' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['cardValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['cardSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['cardSparkLineContentPanel'+_item.index].droppable(this.droppableOptions);
				// _item.fieldManager.panelManager['card_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			/* DOGFOOT hsshim 2020-02-03 게이지 데이터 항목 UI 및 기능 작업 */
			case 'gauge' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['gaugeValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['gaugeSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['gaugeSparkLineContentPanel'+_item.index].droppable(this.droppableOptions);
				// _item.fieldManager.panelManager['gauge_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'choroplethMap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['mapValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['mapParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				
				_item.fieldManager.panelManager['mapStateContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['mapCityContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['mapDongContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'Treemap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['treemapValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['treemapParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'parallel' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['parallelValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['parallelParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'bubblepackchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['bubblepackchartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['bubblepackchartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'wordcloudv2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['wordcloudv2ValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['wordcloudv2ParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'dendrogrambarchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['dendrogrambarchartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['dendrogrambarchartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'calendarviewchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['calendarviewchartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['calendarviewchartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'calendarview2chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['calendarview2chartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['calendarview2chartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'calendarview3chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['calendarview3chartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['calendarview3chartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'collapsibletreechart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['collapsibletreechartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['collapsibletreechartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'rangebarchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['rangebarchartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['rangebarchartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['rangebarchartSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['rangebarchart_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'rangeareachart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['rangeareachartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['rangeareachartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['rangeareachartSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['rangeareachart_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'timelinechart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['timelinechartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['timelinechartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['timelinechartSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['timelinechartStartDateContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['timelinechartEndDateContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['timelinechart_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'Starchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['starchartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['starchartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['starchartSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['chart_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'heatmap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['heatmapValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['heatmapParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['heatmap_hide_measure_listContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'heatmap2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['heatmap2ValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['heatmap2ParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['heatmap2_hide_measure_listContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'syncchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['syncchartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['syncchartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['syncchart_hide_measure_listContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'dependencywheel' :
//				_item.fieldManager.panelManager['dependencywheelValueContentPanel'+_item.index].droppable('disable').sortable(this.sortableOptions);
				_item.fieldManager.panelManager['dependencywheelParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'sequencessunburst' :
				_item.fieldManager.panelManager['sequencessunburstValueContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['sequencessunburstParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'boxplot' :
				_item.fieldManager.panelManager['boxplotValueContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['boxplotParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'scatterplot' :
				_item.fieldManager.panelManager['scatterplotXContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterplotYContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterplotParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'coordinateline' :
				_item.fieldManager.panelManager['coordinatelineXContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['coordinatelineYContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['coordinatelineParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'coordinatedot' :
				_item.fieldManager.panelManager['coordinatedotXContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['coordinatedotYContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['coordinatedotParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'scatterplot2' :
				_item.fieldManager.panelManager['scatterplot2XContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterplot2YContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterplot2ZContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterplot2ParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'radialtidytree' :
				_item.fieldManager.panelManager['radialTidyTreeParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'arcdiagram' :
				_item.fieldManager.panelManager['arcdiagramParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'scatterplotmatrix' :
				_item.fieldManager.panelManager['scatterPlotMatrixX1ContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixX2ContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixY1ContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixY2ContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['scatterplotMatrixParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'historytimeline' :
				_item.fieldManager.panelManager['historyTimelineParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['historyTimelineStartContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['historyTimelineEndContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'liquidfillgauge' :
				_item.fieldManager.panelManager['liquidfillgaugeValueContentPanel'+_item.index].droppable('disable').sortable('disable');
				_item.fieldManager.panelManager['liquidfillgaugeParameterContentPanel'+_item.index].droppable('disable').sortable('disable');
				break;
			case 'wordcloud' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['wordcloudValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['wordcloudParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'histogramchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['histogramchartValueContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['histogramchartParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'adhocItem' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['rowAdHocContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['colAdHocContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['datafieldAdHocContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['deltaValueContentPanel'+_item.index].droppable('disable');

				_item.fieldManager.panelManager['hide_column_list_dimAdHocContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['hide_column_list_meaAdHocContentPanel'+_item.index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				break;
			case 'textBox' : // ymbin
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				if(gDashboard.reportType === 'RAnalysis'){
					_item.fieldManager.panelManager['rFieldContentPanel'+_item.index].droppable('enable').sortable('disable');
				}else{
					_item.fieldManager.panelManager['textboxValueContentPanel'+_item.index].droppable('enable').sortable('disable');
					_item.fieldManager.panelManager['textbox_hide_column_list_meaContentPanel'+_item.index].droppable('enable').sortable('disable');
				}
				break;
			case 'hierarchical' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['hierarchicalParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'forceDirect' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['forceDirectValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['forceDirectParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['forceDirectSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['chart_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'forceDirectExpand' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['forceDirectExpandValueContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['forceDirectExpandParameterContentPanel'+_item.index].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['forceDirectExpandSeriesContentPanel'+_item.index].droppable('enable').sortable('disable');
//				_item.fieldManager.panelManager['chart_hide_column_list_dimContentPanel'+_item.index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+_item.index].droppable(this.droppableOptions);
				break;
			case 'onewayAnova' :
			case 'onewayAnova2' :
			case 'twowayAnova' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager['heatmap2_hide_measure_listContentPanel'+_item.index].droppable('enable').sortable('disable');
				break;
			case 'pearsonsCorrelation' :
			case 'spearmansCorrelation' :
			case 'tTest' :
			case 'zTest' :
			case 'chiTest' :
			case 'fTest' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable('enable').sortable('disable');
				break;
			/* DOGFOOT ktkang 다변량분석 추가  20210215 */
			case 'multivariate' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ParameterContentPanel1'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable('enable').sortable('disable');
				break;
			case 'simpleRegression' :
			case 'multipleRegression' :
			case 'logisticRegression' :
			case 'multipleLogisticRegression' :
				_item.fieldManager.panelManager['allContentPanel'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'IndpnContentPanel1'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'DpndnContentPanel1'].droppable('enable').sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'VectorContentPanel1'].droppable('enable').sortable('disable');
				break;
		}

	};

	this.addSortableOptionsForOpenViewer = function(_item){
		switch (_item.fieldManager.focusItemType){
			case 'pivotGrid' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rowContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.rows.length != 0){
					_item.fieldManager.panelManager['rowContentPanel'+_item.adhocIndex].droppable('disable');
				}else{
					_item.fieldManager.panelManager['rowContentPanel'+_item.adhocIndex].sortable('disable');
				}

				_item.fieldManager.panelManager['colContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.columns.length != 0){
					_item.fieldManager.panelManager['colContentPanel'+_item.adhocIndex].droppable('disable');
				}else{
					_item.fieldManager.panelManager['colContentPanel'+_item.adhocIndex].sortable('disable');
				}

				_item.fieldManager.panelManager['datafieldContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.dataFields.length != 0){
					_item.fieldManager.panelManager['datafieldContentPanel'+_item.adhocIndex].droppable('disable');
				}else{
					_item.fieldManager.panelManager['datafieldContentPanel'+_item.adhocIndex].sortable('disable');
				}
				_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(gDashboard.reportType == 'Adhoc'){
					if(_item.dataFields.length != 0){
						_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].droppable('disable');
					}else{
						_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].sortable('disable');
					}
				}
//				_item.fieldManager.panelManager['hide_column_list_dimContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+_item.adhocIndex].droppable('disable');
				}else{
					_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+_item.adhocIndex].sortable('disable');
				}

				break;
			case 'adhocItem' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rowAdHocContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.rows.length != 0){
					_item.fieldManager.panelManager['rowAdHocContentPanel'+_item.adhocIndex].droppable('disable');
				}else{
					_item.fieldManager.panelManager['rowAdHocContentPanel'+_item.adhocIndex].sortable('disable');
				}

				_item.fieldManager.panelManager['colAdHocContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.columns.length != 0){
					_item.fieldManager.panelManager['colAdHocContentPanel'+_item.adhocIndex].droppable('disable');
				}else{
					_item.fieldManager.panelManager['colAdHocContentPanel'+_item.adhocIndex].sortable('disable');
				}

				_item.fieldManager.panelManager['datafieldAdHocContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.dataFields.length != 0){
					_item.fieldManager.panelManager['datafieldAdHocContentPanel'+_item.adhocIndex].droppable('disable');
				}else{
					_item.fieldManager.panelManager['datafieldAdHocContentPanel'+_item.adhocIndex].sortable('disable');
				}
				_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(gDashboard.reportType == 'Adhoc'){
					if(_item.dataFields.length != 0){
						_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].droppable('disable');
					}else{
						_item.fieldManager.panelManager['deltaValueContentPanel'+_item.adhocIndex].sortable('disable');
					}
				}
//				_item.fieldManager.panelManager['hide_column_list_dimContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+_item.adhocIndex].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+_item.adhocIndex].droppable('disable');
				}else{
					_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+_item.adhocIndex].sortable('disable');
				}

				break;
		}
		/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
		if(WISE.Constants.editmode == 'viewer') {
			$('.filter-row').droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
			$('.filter-row').sortable('disable');
		} else {
			$('.filter-bar').droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
			$('.filter-bar').sortable('disable');
		}
	}

	this.addSortableOptionsForOpen = function(_item){
		var index = _item.index;
		if(WISE.Constants.editmode == 'viewer'){
			index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
		}
		switch (_item.fieldManager.focusItemType){
			case 'adhocItem' :
				var rows, columns, dataFields, HiddenMeasures;

				var index = _item.isAdhocItem ? _item.adhocIndex : _item.index;

				if(WISE.Constants.editmode == 'viewer'){
					index = index + '_' + gDashboard.structure.ReportMasterInfo.id;
				}

				switch(_item.type){
					case 'PIVOT_GRID':
						rows = _item.rows;
						columns = _item.columns;
						dataFields = _item.dataFields;
						HiddenMeasures = _item.HiddenMeasures;
						break;
					case 'SIMPLE_CHART':
						rows = _item.arguments;
						columns = _item.seriesDimensions;
						dataFields = _item.measures;
						HiddenMeasures = _item.HiddenMeasures;
						break;
				}


				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rowAdHocContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(rows.length != 0){
					_item.fieldManager.panelManager['rowAdHocContentPanel'+index].droppable('disable');
					_item.fieldManager.panelManager['rowAdHocContentPanel'+index].sortable('enable');
				}else{
					_item.fieldManager.panelManager['rowAdHocContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['colAdHocContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(columns.length != 0){
					_item.fieldManager.panelManager['colAdHocContentPanel'+index].droppable('disable');
					_item.fieldManager.panelManager['colAdHocContentPanel'+index].sortable('enable');
				}else{
					_item.fieldManager.panelManager['colAdHocContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['datafieldAdHocContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(dataFields.length != 0){
					_item.fieldManager.panelManager['datafieldAdHocContentPanel'+index].droppable('disable');
					_item.fieldManager.panelManager['datafieldAdHocContentPanel'+index].sortable('enable');
				}else{
					_item.fieldManager.panelManager['datafieldAdHocContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['deltaValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(dataFields.length != 0){
					_item.fieldManager.panelManager['deltaValueContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['deltaValueContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['adhoc_hide_column_list_meaContentPanel'+index].sortable('disable');
				}

				/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
				if(WISE.Constants.editmode == 'viewer') {
					$('.filter-row').droppable(self.droppableOptions).sortable(self.sortableOptions);
					$('.filter-row').sortable('disable');
				} else {
					$('.filter-bar').droppable(self.droppableOptions).sortable(self.sortableOptions);
					$('.filter-bar').sortable('disable');
				}

				break;
			case 'pivotGrid' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rowContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.rows.length != 0){
					_item.fieldManager.panelManager['rowContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['rowContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['colContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.columns.length != 0){
					_item.fieldManager.panelManager['colContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['colContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['datafieldContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.dataFields.length != 0){
					_item.fieldManager.panelManager['datafieldContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['datafieldContentPanel'+index].sortable('disable');
				}
//				_item.fieldManager.panelManager['hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['pivot_hide_column_list_meaContentPanel'+index].sortable('disable');
				}
				break;
			case 'dataGrid' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['dataContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.columns.length != 0){
					_item.fieldManager.panelManager['dataContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['dataContentPanel'+index].sortable('disable');
				}

				if(gDashboard.reportType !== 'DSViewer'){
					_item.fieldManager.panelManager['sparkLineContentPanel'+index].droppable(this.droppableOptions);
					_item.fieldManager.panelManager['grid_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					if(_item.HiddenMeasures.length != 0){
						_item.fieldManager.panelManager['grid_hide_column_list_meaContentPanel'+index].droppable('disable');
					}else{
						_item.fieldManager.panelManager['grid_hide_column_list_meaContentPanel'+index].sortable('disable');
					}
				}
				break;
			case 'chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['chartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.measures.length != 0){
					_item.fieldManager.panelManager['chartValueContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['chartValueContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['chartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.arguments.length != 0){
					_item.fieldManager.panelManager['chartParameterContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['chartParameterContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['chartSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.seriesDimensions.length != 0){
					_item.fieldManager.panelManager['chartSeriesContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['chartSeriesContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+index].sortable('disable');
				}
				break;
			case 'pieChart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['pieValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.measures.length != 0){
					_item.fieldManager.panelManager['pieValueContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['pieValueContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['pieParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.arguments.length != 0){
					_item.fieldManager.panelManager['pieParameterContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['pieParameterContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['pieSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.seriesDimensions.length != 0){
					_item.fieldManager.panelManager['pieSeriesContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['pieSeriesContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['pie_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['pie_hide_column_list_meaContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['pie_hide_column_list_meaContentPanel'+index].sortable('disable');
				}
				break;
			case 'card' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['cardValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.measures.length != 0){
					_item.fieldManager.panelManager['cardValueContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['cardValueContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['cardSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.seriesDimensions.length != 0){
					_item.fieldManager.panelManager['cardSeriesContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['cardSeriesContentPanel'+index].sortable('disable');
				}

				 //2020.07.31 MKSGON 불러오기 카드 스파크라인 필드 추가 안되는 오류 수정 DOGFOOT
				 _item.fieldManager.panelManager['cardSparkLineContentPanel'+index].droppable(this.droppableOptions);
				 _item.fieldManager.panelManager['card_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				 if(_item.HiddenMeasures.length != 0){
				 	_item.fieldManager.panelManager['card_hide_column_list_meaContentPanel'+index].droppable('disable');
				 }else{
				 	_item.fieldManager.panelManager['card_hide_column_list_meaContentPanel'+index].sortable('disable');
				 }
				break;
			/* DOGFOOT hsshim 2020-02-03 게이지 데이터 항목 UI 및 기능 작업 */
			case 'gauge' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['gaugeValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.measures.length != 0){
					_item.fieldManager.panelManager['gaugeValueContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['gaugeValueContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['gaugeSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.seriesDimensions.length != 0){
					_item.fieldManager.panelManager['gaugeSeriesContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['gaugeSeriesContentPanel'+index].sortable('disable');
				}

				// _item.fieldManager.panelManager['gauge_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				// if(_item.HiddenMeasures.length != 0){
				// 	_item.fieldManager.panelManager['gauge_hide_column_list_meaContentPanel'+index].droppable('disable');
				// }else{
				// 	_item.fieldManager.panelManager['gauge_hide_column_list_meaContentPanel'+index].sortable('disable');
				// }
				break;
			case 'choroplethMap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['mapValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['mapValueContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['mapParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['mapParameterContentPanel'+index].droppable('disable');
				
				_item.fieldManager.panelManager['mapStateContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['mapStateContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['mapCityContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['mapCityContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['mapDongContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['mapDongContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'Treemap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['treemapValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['treemapValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['treemapParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['treemapParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'parallel' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['parallelValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['parallelValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['parallelParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['parallelParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'bubblepackchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['bubblepackchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubblepackchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['bubblepackchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubblepackchartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'wordcloudv2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['wordcloudv2ValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['wordcloudv2ValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['wordcloudv2ParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['wordcloudv2ParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'dendrogrambarchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['dendrogrambarchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['dendrogrambarchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['dendrogrambarchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['dendrogrambarchartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'calendarviewchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['calendarviewchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarviewchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['calendarviewchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarviewchartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'calendarview2chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['calendarview2chartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarview2chartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['calendarview2chartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarview2chartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'calendarview3chart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['calendarview3chartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarview3chartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['calendarview3chartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['calendarview3chartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'collapsibletreechart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['collapsibletreechartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['collapsibletreechartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['collapsibletreechartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['collapsibletreechartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'rangebarchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rangebarchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.measures.length != 0){
					_item.fieldManager.panelManager['rangebarchartValueContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['rangebarchartValueContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['rangebarchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.arguments.length != 0){
					_item.fieldManager.panelManager['rangebarchartParameterContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['rangebarchartParameterContentPanel'+index].sortable('disable');
				}
//				_item.fieldManager.panelManager['rangebarchartSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				if(_item.seriesDimensions.length != 0){
//					_item.fieldManager.panelManager['rangebarchartSeriesContentPanel'+index].droppable('disable');
//				}else{
//					_item.fieldManager.panelManager['rangebarchartSeriesContentPanel'+index].sortable('disable');
//				}
//
//				_item.fieldManager.panelManager['rangebarchart_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				if(_item.HiddenMeasures.length != 0){
//					_item.fieldManager.panelManager['rangebarchart_hide_column_list_meaContentPanel'+index].droppable('disable');
//				}else{
//					_item.fieldManager.panelManager['rangebarchart_hide_column_list_meaContentPanel'+index].sortable('disable');
//				}
				break;
			case 'rangeareachart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['rangeareachartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.measures.length != 0){
					_item.fieldManager.panelManager['rangeareachartValueContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['rangeareachartValueContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['rangeareachartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.arguments.length != 0){
					_item.fieldManager.panelManager['rangeareachartParameterContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['rangeareachartParameterContentPanel'+index].sortable('disable');
				}
//				_item.fieldManager.panelManager['rangeareachartSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				if(_item.seriesDimensions.length != 0){
//					_item.fieldManager.panelManager['rangeareachartSeriesContentPanel'+index].droppable('disable');
//				}else{
//					_item.fieldManager.panelManager['rangeareachartSeriesContentPanel'+index].sortable('disable');
//				}
//
//				_item.fieldManager.panelManager['rangeareachart_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				if(_item.HiddenMeasures.length != 0){
//					_item.fieldManager.panelManager['rangeareachart_hide_column_list_meaContentPanel'+index].droppable('disable');
//				}else{
//					_item.fieldManager.panelManager['rangeareachart_hide_column_list_meaContentPanel'+index].sortable('disable');
//				}
				break;
			case 'timelinechart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['timelinechartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.measures.length != 0){
					_item.fieldManager.panelManager['timelinechartValueContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['timelinechartValueContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['timelinechartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.arguments.length != 0){
					_item.fieldManager.panelManager['timelinechartParameterContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['timelinechartParameterContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['timelinechartSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.seriesDimensions.length != 0){
					_item.fieldManager.panelManager['timelinechartSeriesContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['timelinechartSeriesContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['timelinechartStartDateContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.seriesDimensions.length != 0){
					_item.fieldManager.panelManager['timelinechartStartDateContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['timelinechartStartDateContentPanel'+index].sortable('disable');
				}
				_item.fieldManager.panelManager['timelinechartEndDateContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.seriesDimensions.length != 0){
					_item.fieldManager.panelManager['timelinechartEndDateContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['timelinechartEndDateContentPanel'+index].sortable('disable');
				}
//
//				_item.fieldManager.panelManager['timelinechart_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				if(_item.HiddenMeasures.length != 0){
//					_item.fieldManager.panelManager['timelinechart_hide_column_list_meaContentPanel'+index].droppable('disable');
//				}else{
//					_item.fieldManager.panelManager['timelinechart_hide_column_list_meaContentPanel'+index].sortable('disable');
//				}
				break;
			case 'RectangularAreaChart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['RectangularAreaChartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['RectangularAreaChartValueContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['RectangularAreaChartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['RectangularAreaChartParameterContentPanel'+index].sortable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'waterfallchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['waterfallchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['waterfallchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['waterfallchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['waterfallchartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'bipartitechart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['bipartitechartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['bipartitechartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['bipartitechartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bipartitechartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'sankeychart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['sankeychartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['sankeychartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['sankeychartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['sankeychartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'histogramchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['histogramchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['histogramchartValueContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['histogramchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['histogramchartParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'funnelchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['funnelchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['funnelchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['funnelchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['funnelchartParameterContentPanel'+index].droppable('disable');
				break;
			case 'pyramidchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['pyramidchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pyramidchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['pyramidchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['pyramidchartParameterContentPanel'+index].droppable('disable');
				break;
			case 'bubbled3' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['bubbled3ValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbled3ValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['bubbled3ParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbled3ParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['map_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['map_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'bubbleChart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['bubbleChartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbleChartValueContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['bubbleChartYContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbleChartYContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['bubbleChartXContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['bubbleChartXContentPanel'+index].sortable('disable');

				break;
			case 'Starchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['starchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['starchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['starchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['starchartParameterContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['starchartSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['starchartSeriesContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['chart_hide_column_list_dimContentPanel'+index].droppable(this.droppableOptions);
//				_item.fieldManager.panelManager['chart_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions);
				break;
			case 'heatmap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['heatmapValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmapValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['heatmapParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmapParameterContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['heatmap_hide_measure_listContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmap_hide_measure_listContentPanel'+index].droppable('disable');
				break;
			case 'heatmap2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['heatmap2ValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmap2ValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['heatmap2ParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmap2ParameterContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['heatmap2_hide_measure_listContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['heatmap2_hide_measure_listContentPanel'+index].droppable('disable');
				break;
			case 'syncchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['syncchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['syncchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['syncchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['syncchartParameterContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['syncchart_hide_measure_listContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['syncchart_hide_measure_listContentPanel'+index].droppable('disable');
				break;
			case 'wordcloud' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['wordcloudValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['wordcloudValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['wordcloudParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['wordcloudParameterContentPanel'+index].droppable('disable');
				break;
			case 'listBox' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['dimfieldContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.filterDimensions.length != 0){
					_item.fieldManager.panelManager['dimfieldContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['dimfieldContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['listbox_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['listbox_hide_column_list_meaContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['listbox_hide_column_list_meaContentPanel'+index].sortable('disable');
				}
				break;
			case 'treeView' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['tv_dimfieldContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.filterDimensions.length != 0){
					_item.fieldManager.panelManager['tv_dimfieldContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['tv_dimfieldContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['treeview_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['treeview_hide_column_list_meaContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['treeview_hide_column_list_meaContentPanel'+index].sortable('disable');
				}
				break;
			case 'comboBox' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['cb_dimfieldContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.filterDimensions.length != 0){
					_item.fieldManager.panelManager['cb_dimfieldContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['cb_dimfieldContentPanel'+index].sortable('disable');
				}

				_item.fieldManager.panelManager['combobox_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['combobox_hide_column_list_meaContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['combobox_hide_column_list_meaContentPanel'+index].sortable('disable');
				}
				break;
			case 'textBox' : // ymbin
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');

				if(gDashboard.reportType === 'RAnalysis'){
					_item.fieldManager.panelManager['rFieldContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					_item.fieldManager.panelManager['rFieldContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['textboxValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					if(_item.measures.length != 0){
						_item.fieldManager.panelManager['textboxValueContentPanel'+index].droppable('disable');
					}else{
						_item.fieldManager.panelManager['textboxValueContentPanel'+index].sortable('disable');
					}
					_item.fieldManager.panelManager['textbox_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
					if(_item.HiddenMeasures.length != 0){
						_item.fieldManager.panelManager['textbox_hide_column_list_meaContentPanel'+index].droppable('disable');
					}else{
						_item.fieldManager.panelManager['textbox_hide_column_list_meaContentPanel'+index].sortable('disable');
					}
				}

				break;
			case 'hierarchical' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['hierarchicalParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['hierarchicalParameterContentPanel'+index].droppable('disable');
				break;
			case 'forceDirect' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['forceDirectValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['forceDirectValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['forceDirectParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['forceDirectParameterContentPanel'+index].droppable('disable');
				break;
			case 'forceDirectExpand' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['forceDirectExpandValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['forceDirectExpandValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['forceDirectExpandParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['forceDirectExpandParameterContentPanel'+index].droppable('disable');
				break;
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
			case 'kakaoMap' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['kakaoMapValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['kakaoMapParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapParameterContentPanel'+index].droppable('disable');

				_item.fieldManager.panelManager['kakaoMapLatitudeContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapLatitudeContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['kakaoMapLongitudeContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapLongitudeContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['kakaoMapAddressContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapAddressContentPanel'+index].droppable('disable');
				break;
			case 'kakaoMap2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['kakaoMap2ValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMap2ValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['kakaoMap2ParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['kakaoMap2ParameterContentPanel'+index].droppable('disable');
				/*
				_item.fieldManager.panelManager['kakaoMapLatitudeContentPanel'+index].droppable('disable').sortable(this.sortableOptions);
				_item.fieldManager.panelManager['kakaoMapLongitudeListContentPanel'+index].droppable('disable').sortable(this.sortableOptions);
				*/
				break;
			case 'divergingchart' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['divergingchartValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['divergingchartValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['divergingchartParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['divergingchartParameterContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['divergingchartSeriesContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['divergingchartSeriesContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['divergingchart_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				if(_item.HiddenMeasures.length != 0){
					_item.fieldManager.panelManager['divergingchart_hide_column_list_meaContentPanel'+index].droppable('disable');
				}else{
					_item.fieldManager.panelManager['divergingchart_hide_column_list_meaContentPanel'+index].sortable('disable');
				}
				break;
			case 'liquidfillgauge' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['liquidfillgaugeValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['liquidfillgaugeValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['liquidfillgaugeParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['liquidfillgaugeParameterContentPanel'+index].droppable('disable');
			break;
			case 'dependencywheel' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['dependencywheelValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['dependencywheelValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['dependencywheelParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['dependencywheelParameterContentPanel'+index].droppable('disable');
			break;
			case 'sequencessunburst' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['sequencessunburstValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['sequencessunburstValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['sequencessunburstParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['sequencessunburstParameterContentPanel'+index].droppable('disable');
			break;
			case 'boxplot' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['boxplotValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['boxplotValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['boxplotParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['boxplotParameterContentPanel'+index].droppable('disable');
			break;
			case 'scatterplot' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['scatterplotValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['scatterplotValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['scatterplotXContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplotXContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['scatterplotYContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplotYContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['scatterplotZContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['scatterplotZContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['scatterplotParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplotParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['scatterplot_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				if(_item.HiddenMeasures.length != 0){
//					_item.fieldManager.panelManager['scatterplot_hide_column_list_meaContentPanel'+index].droppable('disable');
//				}else{
//					_item.fieldManager.panelManager['scatterplot_hide_column_list_meaContentPanel'+index].sortable('disable');
//				}
			break;
			case 'coordinateline' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['coordinatelineXContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatelineXContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['coordinatelineYContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatelineYContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['coordinatelineParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatelineParameterContentPanel'+index].droppable('disable');
			break;
			case 'coordinatedot' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['coordinatedotXContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatedotXContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['coordinatedotYContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatedotYContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['coordinatedotParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['coordinatedotParameterContentPanel'+index].droppable('disable');
			break;
			case 'scatterplot2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
//				_item.fieldManager.panelManager['scatterplotValueContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				_item.fieldManager.panelManager['scatterplotValueContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['scatterplot2XContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplot2XContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['scatterplot2YContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplot2YContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['scatterplot2ZContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplot2ZContentPanel'+index].droppable('disable');
				_item.fieldManager.panelManager['scatterplot2ParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterplot2ParameterContentPanel'+index].droppable('disable');
//				_item.fieldManager.panelManager['scatterplot2_hide_column_list_meaContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
//				if(_item.HiddenMeasures.length != 0){
//					_item.fieldManager.panelManager['scatterplot2_hide_column_list_meaContentPanel'+index].droppable('disable');
//				}else{
//					_item.fieldManager.panelManager['scatterplot2_hide_column_list_meaContentPanel'+index].sortable('disable');
//				}
			break;
			case 'radialtidytree' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['radialTidyTreeParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['radialTidyTreeParameterContentPanel'+index].sortable('disable');
				break;
			case 'arcdiagram' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['arcdiagramParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['arcdiagramParameterContentPanel'+index].sortable('disable');
				break;
			case 'scatterplotmatrix' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixX1ContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixX1ContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixX2ContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixX2ContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixY1ContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixY1ContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixY2ContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixY2ContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['scatterPlotMatrixParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['scatterPlotMatrixParameterContentPanel'+index].sortable('disable');
				break;
			case 'historytimeline' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager['historyTimelineParameterContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['historyTimelineParameterContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['historyTimelineStartContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['historyTimelineStartContentPanel'+index].sortable('disable');
				_item.fieldManager.panelManager['historyTimelineEndContentPanel'+index].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['historyTimelineEndContentPanel'+index].sortable('disable');
				break;
			/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
			case 'onewayAnova' :
			case 'onewayAnova2' :
			case 'twowayAnova' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable('disable');
			break;
			/*case 'onewayAnova2' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ObservedContentPanel1'].droppable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'FactorContentPanel1'].droppable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ItemContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ItemContentPanel1'].droppable('disable');
			break;*/
			case 'pearsonsCorrelation' :
			case 'spearmansCorrelation' :
			case 'tTest' :
			case 'zTest' :
			case 'chiTest' :
			case 'fTest' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable('disable');
			break;
			/* DOGFOOT ktkang 다변량분석 추가  20210215 */
			case 'multivariate' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ParameterContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'ParameterContentPanel1'].droppable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'NumericalContentPanel1'].droppable('disable');
			break;
			case 'simpleRegression' :
			case 'multipleRegression' :
			case 'logisticRegression' :
			case 'multipleLogisticRegression' :
				_item.fieldManager.panelManager['allContentPanel'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager['allContentPanel'].sortable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'IndpnContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'IndpnContentPanel1'].droppable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'DpndnContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'DpndnContentPanel1'].droppable('disable');
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'VectorContentPanel1'].droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
				_item.fieldManager.panelManager[_item.fieldManager.focusItemType + 'VectorContentPanel1'].droppable('disable');
			break;

		}
		/* DOGFOOT ktkang 뷰어에서 주제영역 보고서 필터 올리는 기능 추가  20200709 */
		if(WISE.Constants.editmode == 'viewer') {
			$('.filter-row').droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
			$('.filter-row').sortable('disable');
		} else {
			$('.filter-bar').droppable(this.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
			$('.filter-bar').sortable('disable');
		}
	};

	this.addClassToField = function(_target, _field) {
		var popoverid = filedid + '_config';
		var areaIcon = _field.type === 'dimension' ? (_field.meta.isLevelType ? 'dimension-hierarchy' : 'dimension') : (_field.fieldType ? (_field.fieldType === "customed" ? 'measure-customed' : 'measure-delta') : 'measure');
		var field = $('<li'
					+ ' id="' + filedid + '"'
					+ ' class="wise-area-field wise-area-box"'
					+ ' data-field-uname="' + _field.uid + '"'
					+ ' data-field-type="' + _field.type + '"'
					+ ' data-tableName="'+_field.tableName+'"'
					+ '>'
					+ '<span class="wise-area-icon wise-area-icon-' + areaIcon + ' icon-size"></span>'
					+ '<span>&nbsp;</span>'
					+ '<div'
					+ ' class="wise-area-caption"'
					+ ' style="display:inline-block; max-width:88%; text-overflow:ellipsis; overflow:hidden;"'
					+ '>' + _field.caption
					+ '</div>'
					/*## 16.10.03 -> skb에서 format수정 팝업 주석처리
					+ ('dataList' === _target ? '<span id="' + popoverid + '" class="wise-area-icon wise-area-icon-filter"></span>' : '')*/
					+ '</li>');

		switch(_target) {
		case 'allList':
			if (self.reportType === 'cube') field.addClass('wise-field-leaf');
			field.addClass('wise-no-border');
			break;
		default:
			field.addClass('ui-state-default');
			// cube table container일경우
			if (_target.indexOf('_container') > -1) field.addClass('wise-field-leaf').addClass('wise-no-border');
		}

		if (!_.isEmpty(field)) {
			field.draggable(draggableOptions);
		}

		return field;
	};

	this.getImgForSeriesType2 = function(seriestype){
		var result = 'bar2';
		switch(seriestype){
		case 'StackedBar' :
			result = 'bar3';
		break;
		case 'FullStackedBar' :
			result = 'bar4';
		break;
		case 'Scatter' :
		case 'Point' :
			result = 'pointLine1';
		break;
		case 'Line' :
			result = 'pointLine2';
		break;
		case 'StackedLine' :
			result = 'pointLine3';
		break;
		case 'FullStackedLine' :
			result = 'pointLine4';
		break;
		case 'StepLine' :
			result = 'pointLine5';
		break;
		case 'Spline' :
			result = 'pointLine6';
		break;
		case 'Area' :
			result = 'area1';
		break;
		case 'StackedArea' :
			result = 'area2';
		break;
		case 'FullStackedArea' :
			result = 'area3';
		break;
		case 'StepArea' :
			result = 'area4';
		break;
		case 'SplineArea' :
			result = 'area5';
		break;
		case 'StackedSplineArea' :
			result = 'area6';
		break;
		case 'FullStackedSplineArea' :
			result = 'area7';
		break;
		case 'Bubble' :
			result = 'bubble1';
		break;
	}
	return result;
	}

	this.getImgForSeriesType = function(_item){

		var seriestype = '';
		var result = 'bar2';
		var series;
		if(_item.P){
			if(_item.P.length!=0)series = _item.P[0].Series;
		}else if(_item.fieldManager){
			series = {'seriesType' : _item.fieldManager.seriesType}
		}

		if(series == undefined){
			return result;
		}

		if(series.Simple){
			seriestype = series.Simple.SeriesType
		}else if(series.Weighted){
			seriestype = series.Weighted.SeriesType
		}else{
			seriestype = series.seriesType;
		}

		switch(seriestype){
			case 'StackedBar' :
				result = 'bar3';
			break;
			case 'FullStackedBar' :
				result = 'bar4';
			break;
			case 'Scatter' :
			case 'Point' :
				result = 'pointLine1';
			break;
			case 'Line' :
				result = 'pointLine2';
			break;
			case 'StackedLine' :
				result = 'pointLine3';
			break;
			case 'FullStackedLine' :
				result = 'pointLine4';
			break;
			case 'StepLine' :
				result = 'pointLine5';
			break;
			case 'Spline' :
				result = 'pointLine6';
			break;
			case 'Area' :
				result = 'area1';
			break;
			case 'StackedArea' :
				result = 'area2';
			break;
			case 'FullStackedArea' :
				result = 'area3';
			break;
			case 'StepArea' :
				result = 'area4';
			break;
			case 'SplineArea' :
				result = 'area5';
			break;
			case 'StackedSplineArea' :
				result = 'area6';
			break;
			case 'FullStackedSplineArea' :
				result = 'area7';
			break;
			case 'Bubble' :
				result = 'bubble1';
			break;
		}
		return result;
	}

	this.getImgSourceForSeriesType = function(_seriesType){
		switch(_seriesType){
			case 'StackedBar' :
				result = 'bar3';
			break;
			case 'FullStackedBar' :
				result = 'bar4';
			break;
			case 'Scatter' :
			case 'Point' :
				result = 'pointLine1';
			break;
			case 'Line' :
				result = 'pointLine2';
			break;
			case 'StackedLine' :
				result = 'pointLine3';
			break;
			case 'FullStackedLine' :
				result = 'pointLine4';
			break;
			case 'StepLine' :
				result = 'pointLine5';
			break;
			case 'Spline' :
				result = 'pointLine6';
			break;
			case 'Area' :
				result = 'area1';
			break;
			case 'StackedArea' :
				result = 'area2';
			break;
			case 'FullStackedArea' :
				result = 'area3';
			break;
			case 'StepArea' :
				result = 'area4';
			break;
			case 'SplineArea' :
				result = 'area5';
			break;
			case 'StackedSplineArea' :
				result = 'area6';
			break;
			case 'FullStackedSplineArea' :
				result = 'area7';
			break;
			case 'Bubble' :
				result = 'bubble1';
			break;
			default :
				result = 'bar2';
		}
		return result;
	}

	//20200526 ajkim loadItemData 공통부분 처리 dogfoot
	/*dogfoot 통계 분석 추가 shlim 20201102*/
	this.loadItemData = function(_itemMeta,_aysCheck) {
		var dataNumFormatSetting = function(fieldList, xmlList, dataItemNo, index){
			var dataNumFormat;
			dataNumFormat = dataNumFormatSettingNoSuffix(fieldList, dataItemNo);

			if (typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined') {
				$.each(WISE.util.Object.toArray(xmlList), function(_i, _item) {
					if (_itemMeta.ComponentName === _item.CTRL_NM) {
						$.each(WISE.util.Object.toArray(_item[index]), function(_j, _measure) {
							if (dataItemNo === _measure.UNI_NM) {
								dataNumFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
								dataNumFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
								return false;
							}
						});
						return false;
					}
				});
			}
			return dataNumFormat;
		}

		var dataNumFormatSettingNoSuffix = function(fieldList, dataItemNo){
			var dataNumFormat = {};
			$.each(WISE.util.Object.toArray(fieldList),function(_i,_mea){
				if(_mea.UniqueName == dataItemNo){
					//2019.12.26 mksong numericformat undefined 에러 수정 dogfoot
					// if(_mea.NumericFormat == undefined){
					// 	dataNumFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'Unit': "Ones"};
					// }else{
					// 	dataNumFormat = _mea.NumericFormat;
					// }
					dataNumFormat = {'FormatType' : 'Number', 'IncludeGroupSeparator': true, 'Precision': 0, 'PrecisionOption': '반올림', 'Unit': "Ones"};
					if(_mea.NumericFormat !== undefined){
						dataNumFormat = _mea.NumericFormat;
					}

					return false;
				}
			});
			return dataNumFormat;
		}
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 밑으로 cubeUniqueName 부분 전부  20200618 */
		var dataCubeUniqueName = function(fieldList, dataItemNo){
			var cubeUniqueName = '';
			$.each(WISE.util.Object.toArray(fieldList),function(_i,_mea){
				if(_mea.UniqueName == dataItemNo){
					if(WISE.Context.isCubeReport) {
						cubeUniqueName = _mea.CubeUniqueName;
					}
					return false;
				}
			});
			return cubeUniqueName;
		}

		var measureDataItemSetting = function(dataField, index, prevContainer, number, dataNumFormat, fixType, cubeUniqueName){
//			var element = treeView.element().find('.dx-treeview-node[aria-label="' + dataField['name'] + '"]').clone();
//			var dataFieldType = dataField['dataType'] == 'string' ? 'dimension' : 'measure';
			var dataFieldType;
			if(fixType)
				dataFieldType = 'measure';
			else
				dataFieldType = dataField['type'];

			//2020.10.16 mksong 필드 이름 숫자일 경우 오류 수정 dogfoot
			var dataCaption = dataField['caption'].toString().replace('(sum)','');
			if(!dataCaption||dataCaption === '')
				dataCaption = dataField['name'];
			var dataItemNo = dataField.uniqueName;
			var dataUniNm = dataField.UNI_NM == undefined ? dataField.name : dataField.UNI_NM;

			var element = $('<ul class="display-unmove analysis-data" />');
			if(index == 0){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				element.insertAfter($('#'+ prevContainer + number).children().get(index-1));
			}

			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" '+
					'prev-container="'+ prevContainer + number +'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+dataCaption+'" '+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "'+dataCaption+'" '+
					'style="height: 31px; width: 100%">'+
					'<a href="#" class="ico sigma btn neutral" ' + (_itemMeta.type === 'SIMPLE_CHART' || _itemMeta.isAdhocItem || _itemMeta.type === 'RANGE_BAR_CHART' || _itemMeta.type === 'RANGE_AREA_CHART' ? 'style="width: calc(100% - 35px);">': '>') +
					'<div class="fieldName">' + dataCaption + "</div>"
					+ '</a></li>');
			element.append(dataItem);
			//20201112 AJKIM 측정값 메뉴 필요없는 아이템 메뉴 제거 dogfoot
			if(prevContainer && (prevContainer.indexOf("histogram")>-1 || prevContainer.indexOf("wordcloud")>-1)){
				element.append(self.dimensionFieldOptionMenuNoTopNNoSort);
			}else{
				element.append(self.measureFieldOptionMenu);
			}

			self.addFormat(dataItem);
			dataItem.data('formatOptions', dataNumFormat);
			self.setFormatOptionModalForOpen(dataItem);
			compMoreMenuUi();
			if (typeof self.itemFormat !== undefined && _itemMeta.type === 'BUBBLE_CHART') {
				dataItem.data('formatOptions', self.itemFormat);
			}
			self.fieldRename(dataItem);
			//2020-01-14 LSH topN
			self.topNset(dataItem);
			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			$.each(element.find('.summaryType'),function(_i,_summary){
				if(dataField.summaryType == $(_summary).attr('summaryType')){
					$(_summary).trigger('click');
					return false;
				}
			});

			// 시리즈 설정
			if(_itemMeta.type === 'SIMPLE_CHART' || _itemMeta.type === 'BUBBLE_CHART' || _itemMeta.isAdhocItem){
				var dataItemId =prevContainer + _itemMeta.index + '_' + dataItemNo
				if(_itemMeta.type !== 'BUBBLE_CHART')
				/*dogfoot 크롬 다운로드시 아이콘 레이아웃 오류 수정 shlim 20200717 */
					$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(_itemMeta)+'.png" alt></a>').insertAfter(dataItem.children());
				else
					$('<a id="'+ dataItemId +'" href="#seriesOptions" class="chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(_itemMeta)+'.png" alt></a>').insertAfter(dataItem.children());
				var dataItemOptions = dataItem.find('#' + dataItemId);

				if(_itemMeta.isAdhocItem){
					var chart;
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, item){
						if(item.type === 'SIMPLE_CHART' && item.adhocIndex === _itemMeta.adhocIndex)
							chart = item;
					});
				}

				if (typeof self.itemData !== 'undefined') {
					dataItemOptions.data('dataItemOptions', self.itemData);
				} else if(_itemMeta.isAdhocItem && chart){
					self.addChartDataItemOptions(chart, dataItemNo, dataItemOptions);
				} else {
					self.addChartDataItemOptions(_itemMeta, dataItemNo, dataItemOptions);
				}

				if(_itemMeta.type === 'BUBBLE_CHART')
					$('#'+dataItemId).css('display', 'none');
				dataItemOptions.on('click',function(e){
					self.dataItemOptionsWindow(this);
					e.preventDefault();
				});
			}else if(_itemMeta.type === 'RANGE_BAR_CHART'){
                var dataItemId =prevContainer + _itemMeta.index + '_' + dataItemNo
				if(_itemMeta.type !== 'BUBBLE_CHART')
				/*dogfoot 크롬 다운로드시 아이콘 레이아웃 오류 수정 shlim 20200717 */
					$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(_itemMeta)+'.png" alt></a>').insertAfter(dataItem.children());
				else
					$('<a id="'+ dataItemId +'" href="#seriesOptions" class="chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(_itemMeta)+'.png" alt></a>').insertAfter(dataItem.children());
				var dataItemOptions = dataItem.find('#' + dataItemId);

				if(_itemMeta.isAdhocItem){
					var chart;
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, item){
						if(item.type === 'SIMPLE_CHART' && item.adhocIndex === _itemMeta.adhocIndex)
							chart = item;
					});
				}

				if (typeof self.itemData !== 'undefined') {
					dataItemOptions.data('dataItemOptions', self.itemData);
				} else if(_itemMeta.isAdhocItem && chart){
					self.addChartDataItemOptions(chart, dataItemNo, dataItemOptions);
				} else {
					self.addChartDataItemOptions(_itemMeta, dataItemNo, dataItemOptions);
				}

				dataItemOptions.on('click',function(e){
					self.dataItemRangeBarOptionsWindow(this);
					e.preventDefault();
				});
			}else if(_itemMeta.type === 'RANGE_AREA_CHART'){
				 var dataItemId =prevContainer + _itemMeta.index + '_' + dataItemNo
				if(_itemMeta.type !== 'BUBBLE_CHART')
				/*dogfoot 크롬 다운로드시 아이콘 레이아웃 오류 수정 shlim 20200717 */
					$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(_itemMeta)+'.png" alt></a>').insertAfter(dataItem.children());
				else
					$('<a id="'+ dataItemId +'" href="#seriesOptions" class="chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(_itemMeta)+'.png" alt></a>').insertAfter(dataItem.children());
				var dataItemOptions = dataItem.find('#' + dataItemId);

				if(_itemMeta.isAdhocItem){
					var chart;
					$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, item){
						if(item.type === 'SIMPLE_CHART' && item.adhocIndex === _itemMeta.adhocIndex)
							chart = item;
					});
				}

				if (typeof self.itemData !== 'undefined') {
					dataItemOptions.data('dataItemOptions', self.itemData);
				} else if(_itemMeta.isAdhocItem && chart){
					self.addChartDataItemOptions(chart, dataItemNo, dataItemOptions);
				} else {
					self.addChartDataItemOptions(_itemMeta, dataItemNo, dataItemOptions);
				}

				dataItemOptions.on('click',function(e){
					self.dataItemRangeAreaOptionsWindow(this);
					e.preventDefault();
				});
			}

			modalUi();
			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			gDashboard.fieldManager.dataItemNo++;
		}

		var hiddenDataItemSetting =  function(hiddenmeasure, index, prevContainer, number, dataNumFormat, cubeUniqueName){
			var dataFieldType = 'measure';
			var dataCaption = hiddenmeasure['caption'];
			if(!dataCaption||dataCaption === '')
				dataCaption = dataField['name'];
			if(_itemMeta.type === 'SIMPLE_CHART' || _itemMeta.type === 'BUBBLE_CHART') dataCaption = hiddenmeasure['caption'];
			var dataItemNo = hiddenmeasure.uniqueName;
			var dataUniNm = hiddenmeasure.UNI_NM == undefined ? hiddenmeasure.name : hiddenmeasure.UNI_NM;

			var element = $('<ul class="display-unmove analysis-data" />');

			if(index == 0){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				element.insertAfter($('#' + prevContainer + number).children().get(index-1));
			}

			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" '+
					'dataType="' + dataFieldType + '" ' +
					'prev-container="'+ prevContainer + number+'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+dataCaption+'" '+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title= "'+dataCaption+'" '+
					'style="height: 31px; width: 100%;"><a href="#" class="ico sigma btn neutral">' +
					'<div class="fieldName">' + dataCaption + "</div>"
					+ '</a></li>');
			element.append(dataItem);
			/*Format... 메뉴*/
			/*컬럼 값 메뉴*/
			element.append(self.hiddenMeasureFieldOptionMenu);
			if(_itemMeta.type !== 'SIMPLE_CHART' && _itemMeta.type !== 'BUBBLE_CHART')
				dataItem.data('formatOptions', dataNumFormat);
			self.addFormat(dataItem);
			self.setFormatOptionModalForOpen(dataItem);
			compMoreMenuUi();

			/*Rename 메뉴*/
			self.fieldRename(dataItem);
			//2020-01-14 LSH topN
			self.topNset(dataItem);

			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			/*컬럼 값 메뉴 선택*/
			$.each(element.find('.summaryType'),function(_i,_summary){
				if(hiddenmeasure.summaryType == $(_summary).attr('summaryType')){
					$(_summary).trigger('click');
					return false;
				}
			});

			modalUi();

			gDashboard.fieldManager.dataItemNo++;
		}

		var pivotDimensionDataItemSetting = function(dimension, prevContainer, number, index, cubeUniqueName){
			var dataFieldType = dimension['type'];
			var dataItemNo = dimension.uniqueName;
			var SortOrderBy = dimension.sortOrder === undefined ? 'asc' : dimension.sortOrder;
			var dataUniNm = dimension.UNI_NM == undefined ? dimension.name : dimension.UNI_NM;

			var arrayUpDown = "arrayUp";
			if(SortOrderBy === 'asc'){
				arrayUpDown = 'arrayUp';
			}else{
				arrayUpDown = 'arrayDown';
			}

			/*dogfoot 피벗그리드 topN 기능 추가 shlim 20200630*/
			if(dimension.TopNEnabled){
				/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
				var TopNEnabled = dimension.TopNEnabled ?  dimension.TopNEnabled : false;
				var TopNOrder = dimension.TopNOrder ? dimension.TopNOrder : false;
				var TopNCount = dimension.TopNCount == undefined ? 5 : dimension.TopNCount;
				var TopNMeasure = dimension.TopNMeasure == undefined ? "" : dimension.TopNMeasure
				var TopNShowOthers = dimension.TopNShowOthers == undefined ? false : dimension.TopNShowOthers;
			}

			var element = $('<ul class="display-unmove analysis-data" />');

			if(index == 0){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				element.insertAfter($('#' + prevContainer + number).children().get(index-1));
			}

			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" '+
					'prev-container="'+ prevContainer + pivotNum+'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+dimension['caption'] +'" '+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "'+dimension['caption'] +'" '+
					/*dogfoot 피벗그리드 topN 기능 추가 shlim 20200630*/
					'TopNEnabled = "'+TopNEnabled+'" '+
					/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
					'TopNOrder = "'+TopNOrder+'" '+
					'TopNCount = "'+TopNCount+'" '+
					'TopNMeasure = "'+TopNMeasure+'" '+
					'TopNShowOthers = "'+TopNShowOthers+'" '+
					'style="height: 31px;">'+
					'<a href="#" class="ico block btn neutral">' +
					'<div class="fieldName">' + dimension['caption']  + "</div>"
					+ '</a></li>');
			element.append(dataItem);

			self.setDimensionFieldOptionMenu(element);
//			element.append(self.dimensionFieldOptionMenu);
			self.fieldRename(dataItem);
			//2020-01-14 LSH topN
			self.topNset(dataItem);
			compMoreMenuUi();

			self.expandMeasureList(element.find('.other-menu-ico'));

			$.each(element.find('.measureList').children(),function(_k,_j){
				if(dimension.sortByMeasure != undefined){
					// mksong 2019.12.20 sort By 오류 수정 dogfoot
					if($(_j).attr('uni_nm') == dimension.sortByMeasure){
						$(_j).children().trigger('click');
						return false;
					}
				}
			});

			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			self.activeGridOption(dataItem);
			gDashboard.fieldManager.dataItemNo++;
		}

		var argumentDataItemSetting = function(argument, index, prevContainer, number, cubeUniqueName){
			var dataFieldType = 'dimension';
			var element = $('<ul class="display-unmove analysis-data" />');
			var dataItemNo = argument.uniqueName;
			var dataUniNm = argument.UNI_NM == undefined ? argument.name : argument.UNI_NM;

			//20201029 AJKIM SortBy 기능  없는 곳에서 화살표 표시 제거 dogfoot
			var noSort = false;
			if(prevContainer.indexOf("historyTimeline") > -1 || prevContainer.indexOf("plot") > -1 || prevContainer.indexOf("Plot") > -1
					|| prevContainer.indexOf("arc") > -1 || prevContainer.indexOf("bubbled3") > -1 || prevContainer.indexOf("wordcloud") > -1
					|| prevContainer.indexOf("Rectangular") > -1 || prevContainer.indexOf("plot") > -1 || prevContainer.indexOf("waterfall") > -1
					|| prevContainer.indexOf("bipart") > -1 || prevContainer.indexOf("dependency") > -1
					|| prevContainer.indexOf("hierarchical") > -1 || prevContainer.indexOf("forceDirect") > -1 || prevContainer.indexOf("calendarview") > -1
					|| prevContainer.indexOf("calendarview") > -1 || prevContainer.indexOf("sunburst") > -1 || prevContainer.indexOf("dendrogram") > -1
					|| prevContainer.indexOf("collapsibletreechart") > -1 || prevContainer.indexOf("radialTidyTree") > -1 || prevContainer.indexOf("parallel") > -1
					|| prevContainer.indexOf("bubblepackchart") > -1 || prevContainer.indexOf("sankey") > -1 || prevContainer.indexOf("coordinate") > -1){
				noSort = true;
			}

			var SortOrderBy = argument.sortOrder === undefined ? 'asc' : argument.sortOrder;
			var arrayUpDown = "arrayUp";
			if(SortOrderBy === 'asc'){
				arrayUpDown = 'arrayUp';
			}
			else{
				arrayUpDown = 'arrayDown';
			}
			if(noSort){
				arrayUpDown = '';
			}

			//lsh topN 데이터 항목 필드 값 추가
			if(argument.TopNEnabled){
			/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
				var TopNEnabled = argument.TopNEnabled ?  argument.TopNEnabled : false;
				var TopNOrder = argument.TopNOrder ? argument.TopNOrder : false;
				var TopNCount = argument.TopNCount == undefined ? 5 : argument.TopNCount;
				var TopNMeasure = argument.TopNMeasure == undefined ? "" : argument.TopNMeasure
				var TopNShowOthers = argument.TopNShowOthers == undefined ? false : argument.TopNShowOthers;
			}

			/* DOGFOOT ktkang 아진주임이 수정한 부분 다시 수정 차원이 2개 이상이면 저장 후 불러올 때 1개만 불러옴(버블차트2 수정시 오류)  20200706 */
			if(index == 0 || _itemMeta.type === 'BUBBLE_CHART'){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				element.insertAfter($('#' + prevContainer + number).children().get(index-1));
			}

//					var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" prev-container="'+'chartParameterList' + chartNum+'" dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico block btn neutral">' + argument['caption']
//							+ '</a></li>'));
//					element.append(dataItem);
			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" '+
					'prev-container="'+ prevContainer + number+'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+argument['caption'] +'" '+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "'+argument['caption'] +'" '+
					// lsh topN 추가
					'TopNEnabled = "'+TopNEnabled+'" '+
					/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
					'TopNOrder = "'+TopNOrder+'" '+
					'TopNCount = "'+TopNCount+'" '+
					'TopNMeasure = "'+TopNMeasure+'" '+
					'TopNShowOthers = "'+TopNShowOthers+'" '+
					'style="height: 31px;"><a href="#" class="ico block btn neutral">' +
					'<div class="fieldName">'+argument['caption'] + "</div>"
					+ '</a></li>');
			element.append(dataItem);

//					element.find('.btn').append($('<a href="#" class="other-menu-ico"></a>'));

			element.addClass('arrayUp other-menu');
			/*차원 메뉴 추가*/
			self.setDimensionFieldOptionMenu(element);
//			element.append(self.dimensionFieldOptionMenu);
			/*Rename 추가*/
			self.fieldRename(dataItem);
			/*topN 추가*/
			//2020-01-14 LSH topN
			self.topNset(dataItem);
			compMoreMenuUi();
			/*Sort By 메뉴 추가*/
			self.expandMeasureList(element.find('.other-menu-ico'));
			/*Sort By 설정*/
			$.each(element.find('.measureList').children(),function(_k,_j){
				if(argument.sortByMeasure != undefined){
					// mksong 2019.12.20 sort By 오류 수정 dogfoot
					if($(_j).attr('uni_nm') == argument.sortByMeasure){
						$(_j).children().trigger('click');
						return false;
					}
				}
			});

			self.activeGridOption(dataItem);

//					self.expandMeasureList()

			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			gDashboard.fieldManager.dataItemNo++;
		}

		var argumentDataItemSettingNoTopN = function(argument, index, prevContainer, number, cubeUniqueName){
			var dataFieldType = 'dimension';
			if(argument.type) dataFieldType = argument.type;
			var element = $('<ul class="display-unmove analysis-data" />');
			var dataItemNo = argument.uniqueName;
			var dataUniNm = argument.UNI_NM == undefined ? argument.name : argument.UNI_NM;

			var SortOrderBy = argument.sortOrder === undefined ? 'asc' : argument.sortOrder;
			//20201029 AJKIM SortBy 기능  없는 곳에서 화살표 표시 제거 dogfoot
			var noSort = false;
			if(prevContainer.indexOf("historyTimeline") > -1 || prevContainer.indexOf("plot") > -1 || prevContainer.indexOf("Plot") > -1
					|| prevContainer.indexOf("arc") > -1 || prevContainer.indexOf("bubbled3") > -1 || prevContainer.indexOf("wordcloud") > -1
					|| prevContainer.indexOf("Rectangular") > -1 || prevContainer.indexOf("plot") > -1 || prevContainer.indexOf("waterfall") > -1
					|| prevContainer.indexOf("bipart") > -1 || prevContainer.indexOf("dependency") > -1
					|| prevContainer.indexOf("hierarchical") > -1 || prevContainer.indexOf("forceDirect") > -1 || prevContainer.indexOf("calendarview") > -1
					|| prevContainer.indexOf("calendarview") > -1 || prevContainer.indexOf("sunburst") > -1 || prevContainer.indexOf("dendrogram") > -1
					|| prevContainer.indexOf("collapsibletreechart") > -1 || prevContainer.indexOf("radialTidyTree") > -1 || prevContainer.indexOf("parallel") > -1
					|| prevContainer.indexOf("bubblepackchart") > -1 || prevContainer.indexOf("sankey") > -1 || prevContainer.indexOf("coordinate") > -1){
				noSort = true;
			}
			var arrayUpDown = "arrayUp";
			if(SortOrderBy === 'asc'){
				arrayUpDown = 'arrayUp';
			}
			else{
				arrayUpDown = 'arrayDown';
			}

			if(noSort){
				arrayUpDown = '';
			}

			if(index == 0 || prevContainer.indexOf("mapDongList") > -1 || prevContainer.indexOf("mapCityList") > -1 || (index < 3 && prevContainer.indexOf("scatterplot")> -1) || (index < 5 && prevContainer.indexOf("scatterPlot")> -1) || (index < 3 && prevContainer.indexOf("historyTimeline") > -1)||(index < 3 && prevContainer.indexOf("coordinate")> -1)){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				var tIndex = index - 1;

				if(prevContainer.indexOf("scatterplot")> -1){
					tIndex -= 2;
				}else if(prevContainer.indexOf("scatterPlot") > -1){
					tIndex -= 4;
				}else if(prevContainer.indexOf("historyTimeline") > -1){
					tIndex -= 2;
				}
				element.insertAfter($('#' + prevContainer + number).children().get(tIndex));
			}

//					var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" prev-container="'+'chartParameterList' + chartNum+'" dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico block btn neutral">' + argument['caption']
//							+ '</a></li>'));
//					element.append(dataItem);
			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" '+
					'prev-container="'+ prevContainer + number+'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+argument['caption'] +'" '+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "'+argument['caption'] +'" '+
					// lsh topN 추가
					'style="height: 31px;"><a href="#" class="ico block btn neutral">' +
					'<div class="fieldName">'+argument['caption'] + "</div>"
					+ '</a></li>');
			element.append(dataItem);

//					element.find('.btn').append($('<a href="#" class="other-menu-ico"></a>'));

			element.addClass('arrayUp other-menu');
			/*차원 메뉴 추가*/
//			element.append(self.dimensionFieldOptionMenu);
			self.setDimensionFieldOptionMenu(element);
			/*Rename 추가*/
			self.fieldRename(dataItem);
			/*topN 추가*/
			//2020-01-14 LSH topN
			self.topNset(dataItem);
			compMoreMenuUi();
			/*Sort By 메뉴 추가*/
			self.expandMeasureList(element.find('.other-menu-ico'));
			/*Sort By 설정*/
			$.each(element.find('.measureList').children(),function(_k,_j){
				if(argument.sortByMeasure != undefined){
					// mksong 2019.12.20 sort By 오류 수정 dogfoot
					if($(_j).attr('uni_nm') == argument.sortByMeasure){
						$(_j).children().trigger('click');
						return false;
					}
				}
			});

			self.activeGridOption(dataItem);

//					self.expandMeasureList()

			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			gDashboard.fieldManager.dataItemNo++;
		}

		var addressFieldDataItemSettingNoTopN = function(addressField, index, prevContainer, number, cubeUniqueName){
			var dataFieldType = 'dimension';
			var element = $('<ul class="display-unmove analysis-data" />');
			var dataItemNo = addressField.uniqueName;
			var dataUniNm = addressField.UNI_NM == undefined ? addressField.name : addressField.UNI_NM;

			if(index == 0 || (index < 3 && (prevContainer.indexOf("scatterplot")> -1))){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				element.insertAfter($('#' + prevContainer + number).children().get(index-1));
			}

			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" '+
					'prev-container="'+ prevContainer + number+'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+addressField['caption'] +'" '+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "'+addressField['caption'] +'" '+
					// lsh topN 추가
					'style="height: 31px;"><a href="#" class="ico block btn neutral">' +
					'<div class="fieldName">'+addressField['caption'] + "</div>"
					+ '</a></li>');

			element.append(dataItem);
			element.addClass('arrayUp other-menu');
			/*차원 메뉴 추가*/
			element.append(self.addressFieldOptionMenu);
			/*Rename 추가*/
			self.fieldRename(dataItem);
			/*topN 추가*/
			compMoreMenuUi();

			self.synchronizeAddressTypeList(element.find('.other-menu-ico'),addressField.addressType);
			element.find('[addressType="'+ addressField.addressType +'"]').children().trigger('click');

			self.activeGridOption(dataItem);
			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			gDashboard.fieldManager.dataItemNo++;
		}

		/* DOGFOOT ktkang 사용안하는 파라미터 제거  20200706 */
		var seriesDimensionDataItemSetting = function(series, index, prevContainer, number, cubeUniqueName){
			var dataFieldType = 'dimension';
			var element = $('<ul class="display-unmove analysis-data" />');
			var dataItemNo = series.uniqueName;
			var dataUniNm = series.UNI_NM == undefined ? series.name : series.UNI_NM;

			var SortOrderBy = series.sortOrder === undefined ? 'asc' : series.sortOrder;

			//20201029 AJKIM SortBy 기능  없는 곳에서 화살표 표시 제거 dogfoot
			var noSort = false;
			if(prevContainer.indexOf("historyTimeline") > -1 || prevContainer.indexOf("plot") > -1 || prevContainer.indexOf("Plot") > -1
					|| prevContainer.indexOf("arc") > -1 || prevContainer.indexOf("bubbled3") > -1 || prevContainer.indexOf("wordcloud") > -1
					|| prevContainer.indexOf("Rectangular") > -1 || prevContainer.indexOf("plot") > -1 || prevContainer.indexOf("waterfall") > -1
					|| prevContainer.indexOf("bipart") > -1 || prevContainer.indexOf("dependency") > -1
					|| prevContainer.indexOf("hierarchical") > -1 || prevContainer.indexOf("forceDirect") > -1 || prevContainer.indexOf("calendarview") > -1
					|| prevContainer.indexOf("calendarview") > -1 || prevContainer.indexOf("sunburst") > -1 || prevContainer.indexOf("dendrogram") > -1
					|| prevContainer.indexOf("collapsibletreechart") > -1 || prevContainer.indexOf("radialTidyTree") > -1 || prevContainer.indexOf("parallel") > -1
					|| prevContainer.indexOf("bubblepackchart") > -1 || prevContainer.indexOf("sankey") > -1 || prevContainer.indexOf("coordinate") > -1 ){
				noSort = true;
			}

			var arrayUpDown = "arrayUp";
			if(SortOrderBy === 'asc'){
				arrayUpDown = 'arrayUp';
			}
			else{
				arrayUpDown = 'arrayDown';
			}

			if(noSort){
				arrayUpDown = '';
			}


			/*dogfoot 차원그룹 topN 불러오기 안되는 오류 수정 shlim 20200629*/
			if(series.TopNEnabled){
				/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
				var TopNEnabled = series.TopNEnabled ? series.TopNEnabled : false;
				var TopNOrder = series.TopNOrder ? series.TopNOrder : false;
				var TopNCount = series.TopNCount == undefined ? 5 : series.TopNCount;
				var TopNMeasure = series.TopNMeasure == undefined ? "" : series.TopNMeasure
				var TopNShowOthers = series.TopNShowOthers == undefined ? false : series.TopNShowOthers;
			}

			if(index == 0){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				element.insertAfter($('#' + prevContainer + number).children().get(index-1));
			}

			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" '+
					'prev-container="'+ prevContainer + number+'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+series['caption'] +'" '+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "'+series['caption'] +'" '+
					/*dogfoot 차원그룹 topN 불러오기 안되는 오류 수정 shlim 20200629*/
					(series.TopNEnabled? 'TopNEnabled = "'+TopNEnabled+'" '+
					/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
					'TopNOrder = "'+TopNOrder+'" '+
					'TopNCount = "'+TopNCount+'" '+
					'TopNMeasure = "'+TopNMeasure+'" '+
					'TopNShowOthers = "'+TopNShowOthers+'" ': '') +
					'style="height: 31px;"><a href="#" class="ico block btn neutral">' +
					'<div class="fieldName">' + series['caption'] + "</div>"
					+ '</a></li>');
			element.append(dataItem);
			/*컬럼 값 메뉴*/
//			element.append(self.dimensionFieldOptionMenu);
			self.setDimensionFieldOptionMenu(element);
			self.fieldRename(dataItem);
			//2020-01-14 LSH topN
			self.topNset(dataItem);
			compMoreMenuUi();
			self.expandMeasureList(element.find('.other-menu-ico'));

			/*Rename 메뉴*/
			self.fieldRename(dataItem);
			//2020-01-14 LSH topN
			self.topNset(dataItem);

			/*Sort By 설정*/
			$.each(element.find('.measureList').children(),function(_k,_j){
				if(series.sortByMeasure != undefined){
					// mksong 2019.12.20 sort By 오류 수정 dogfoot
					if($(_j).attr('uni_nm') == series.sortByMeasure){
						$(_j).children().trigger('click');
						return false;
					}
				}
			});

			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			self.activeGridOption(dataItem);
			gDashboard.fieldManager.dataItemNo++;
		}

		var gridFieldDeltaDataItemSetting = function(index, column, cubeUniqueName){
			var actualField = {};
			var targetField = {};

			var dataFieldType = column['dataType'] == 'string' ? 'dimension' : 'measure';

			//lsh topN 데이터 항목 필드 값
			if(column.TopNEnabled){
				/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
				var TopNEnabled = column.TopNEnabled ? column.TopNEnabled : false
				var TopNOrder = column.TopNOrder ? column.TopNOrder : false
				var TopNCount = column.TopNCount == undefined ? 5 : column.TopNCount;
				var TopNMeasure = column.TopNMeasure == undefined ? "" : column.TopNMeasure
				var TopNShowOthers = column.TopNShowOthers == undefined ? false : column.TopNShowOthers;
				var topMember = column.topMember == undefined ? "" : column.topMember
			}

			if(dataFieldType == 'measure'){
				dataCaption = column['caption'].replace('(sum)','');
			}

			$.each(_item.meta.DataItems.Measure,function(_i, _measure){
				if(column.actualUniqueName === _measure.UniqueName){
					actualField = _measure;
				}else if(column.targetUniqueName === _measure.UniqueName){
					targetField = _measure;
				}
			});

            var deltaOptions;
            $.each(WISE.util.Object.toArray(_item.meta.GridColumns.GridDeltaColumn), function(_i, _deltaColumn){
            	if(column.actualUniqueName === _deltaColumn.ActualValue.UniqueName && column.targetUniqueName === _deltaColumn.TargetValue.UniqueName){
            		deltaOptions = _deltaColumn.DeltaOptions;
            	}
            });

            var fieldArray = WISE.util.Object.toArray(actualField).concat(targetField);

			var element = $('<ul class="display-unmove analysis-data" />');

			$.each(fieldArray, function(_k, _field){
				var dataUniNm = _field.UNI_NM == undefined ? _field.Name : _field.UNI_NM;
				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu drop-target wise-drag" '+
						'dataType = "delta" '+
						'prev-container="'+'columnList' + gridNum+'" '+
						'data-source-id="' + _itemMeta.dataSourceId + '" '+
						'uni_nm="'+dataUniNm+'" ' +
						'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
						'caption = "'+_field.DataMember +'" '+
						// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
						'title = "'+_field.DataMember +'" '+
						'TopNEnabled = "'+TopNEnabled+'" '+
						/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
						'TopNOrder = "'+TopNOrder+'" '+
						'TopNCount = "'+TopNCount+'" '+
						'TopNMeasure = "'+TopNMeasure+'" '+
						'TopNShowOthers = "'+TopNShowOthers+'" '+
						'topMember = "'+topMember+'" '+
						'style="height: 31px;">'+
						'<a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);">' +
						'<div class="fieldName">'+_field.DataMember +"</div>"
						+ '</a></li>');

				if(_k == 0 && deltaOptions != undefined){
					dataItem.attr('AlwaysShowZeroLevel',deltaOptions.AlwaysShowZeroLevel);
					dataItem.attr('ResultIndicationMode',deltaOptions.ResultIndicationMode);
					dataItem.attr('ResultIndicationThresholdType',deltaOptions.ResultIndicationThresholdType);
					dataItem.attr('ResultIndicationThreshold',deltaOptions.ResultIndicationThreshold);
					dataItem.attr('ValueType',deltaOptions.ValueType);
					dataItem.attr('actualField',dataItem.attr('dataitem'));
					dataItem.attr('target-field-uninm',fieldArray[1].UNI_NM == undefined ? fieldArray[1].Name : fieldArray[1].UNI_NM);
					dataItem.attr('target-field-dataitem','DataItem' + (gDashboard.fieldManager.dataItemNo + 1));
					dataItem.attr('target-field-caption',fieldArray[1].DataMember);
					dataItem.attr('target-field-origintype','measure');

					$('<a id="DataItem'+ gDashboard.fieldManager.dataItemNo  +'" href="#" class="otherBtn delta" style="height: 66px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_triangle.png" alt></a>').insertAfter(dataItem.children());
				}else{
					dataItem.addClass('delta-drop');
					dataItem.attr('drop-type','deltaTarget');
					dataItem.attr('prev-container','deltavalueList');
					dataItem.droppable(gDashboard.dragNdropController.droppableOptions);
				}
				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
				element.append(dataItem);

				if (typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined') {
					$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.DATA_GRID_ELEMENT), function(_i, _item) {
						if (_itemMeta.ComponentName === _item.CTRL_NM) {
							$.each(WISE.util.Object.toArray(_item.MEASURES), function(_j, _measure) {
								if (_field.UniqueName === _measure.UNI_NM) {
									_field.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
									_field.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
									return false;
								}
							});
							return false;
						}
					});
				}

				/*컬럼 값 메뉴*/
				self.appendFieldOptionMenu(dataItem,'delta', false);
//				element.append(self.measureFieldOptionMenu);
				self.addFormat(dataItem);
				dataItem.data('formatOptions', _field.NumericFormat);
				self.setFormatOptionModalForOpen(dataItem);
				compMoreMenuUi();

				/*Rename 메뉴*/
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);

				$.each(element.find('.summaryType'),function(_i,_summary){
					if(column.summaryType == $(_summary).attr('summaryType')){
						$(_summary).trigger('click');
						return false;
					}
				});
				modalUi();

				dataItem.data('dataGridColumnWeight',column.width);
				self.addEventChangeType(dataItem.find(".otherBtn"));
				gDashboard.fieldManager.dataItemNo++;
			});

			if(index == 0){
				element.appendTo($('#columnList' + gridNum));
			}else{
				element.insertAfter($('#columnList' + gridNum).children().get(index-1));
			}
		}

		var rangeBarFieldDeltaDataItemSetting = function(dataField, index, prevContainer, number, dataNumFormat, fixType, cubeUniqueName){

			var valueData;
			var deltaData;
			var dataFieldType;
			$.each(_item.meta.DataItems.Measure,function(_i, _measure){
				    if(typeof _measure.DeltaItem != 'undefined' && _measure.DeltaItem != ''){
			            if(_measure.DeltaItem === dataField.uniqueName){
						    deltaData = _measure;
						}
			        }else{
			        	 if(_measure.UniqueName === dataField.uniqueName){
						    valueData = _measure
						}
			        }
			});

			var fieldArray = WISE.util.Object.toArray(valueData).concat(deltaData);

			var element = $('<ul class="display-unmove analysis-data" />');
			if(index == 0){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				element.insertAfter($('#'+ prevContainer + number).children().get(index-1));
			}
			$.each(fieldArray, function(_k, _field){

				dataFieldType = 'measure';

				var dataCaption = _field.Name;
				if(!dataCaption||dataCaption === '')
					dataCaption = _field.Name;
				var dataItemNo = _field.UniqueName;
				var dataUniNm = _field.UNI_NM == undefined ? _field.Name : _field.UNI_NM;

				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" '+
						'prev-container="'+ prevContainer + number +'" '+
						'data-source-id="' + _itemMeta.dataSourceId + '" '+
						'uni_nm="'+dataUniNm+'" ' +
						'cubeuninm= "' + _field.CubeUniqueName + '" ' +
						'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
						'caption = "'+dataCaption+'" '+
						// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
						'title = "'+dataCaption+'" '+
						'style="height: 31px; width: 100%">'+
						'<a href="#" class="ico sigma btn neutral" ' + (_itemMeta.type === 'SIMPLE_CHART' || _itemMeta.isAdhocItem || _itemMeta.type === 'RANGE_BAR_CHART' || _itemMeta.type === 'RANGE_AREA_CHART' ? 'style="width: calc(100% - 35px);">': '>') +
						'<div class="fieldName">' + dataCaption + "</div>"
						+ '</a></li>');
				element.append(dataItem);
				element.append(self.measureFieldOptionMenu);
				self.addFormat(dataItem);
				dataItem.data('formatOptions', dataNumFormat);
				self.setFormatOptionModalForOpen(dataItem);
				compMoreMenuUi();
				if (typeof self.itemFormat !== undefined && _itemMeta.type === 'BUBBLE_CHART') {
					dataItem.data('formatOptions', self.itemFormat);
				}
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
				$.each(element.find('.summaryType'),function(_i,_summary){
					if(dataField.summaryType == $(_summary).attr('summaryType')){
						$(_summary).trigger('click');
						return false;
					}
				});

				// 시리즈 설정
				if(_k==0){
					dataItem.attr('target-field-dataitem','DataItem' + (gDashboard.fieldManager.dataItemNo + 1));

					var dataItemId =prevContainer + _itemMeta.index + '_' + dataItemNo
					if(_itemMeta.type !== 'BUBBLE_CHART')
					/*dogfoot 크롬 다운로드시 아이콘 레이아웃 오류 수정 shlim 20200717 */
						$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(_itemMeta)+'.png" alt></a>').insertAfter(dataItem.children());
					else
						$('<a id="'+ dataItemId +'" href="#seriesOptions" class="chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(_itemMeta)+'.png" alt></a>').insertAfter(dataItem.children());
					var dataItemOptions = dataItem.find('#' + dataItemId);

					if(_itemMeta.isAdhocItem){
						var chart;
						$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, item){
							if(item.type === 'SIMPLE_CHART' && item.adhocIndex === _itemMeta.adhocIndex)
								chart = item;
						});
					}

					if (typeof self.itemData !== 'undefined') {
						dataItemOptions.data('dataItemOptions', self.itemData);
					} else if(_itemMeta.isAdhocItem && chart){
						self.addChartDataItemOptions(chart, dataItemNo, dataItemOptions);
					} else {
						self.addChartDataItemOptions(_itemMeta, dataItemNo, dataItemOptions);
					}

					if(prevContainer.indexOf('rangebarchart') > -1){
                        dataItemOptions.on('click',function(e){
							self.dataItemRangeBarOptionsWindow(this);
							e.preventDefault();
						});
				    }else if(prevContainer.indexOf('rangeareachart') > -1){
				    	dataItemOptions.on('click',function(e){
							self.dataItemRangeAreaOptionsWindow(this);
							e.preventDefault();
						});
				    }

					if(dataItem.parent().hasClass('display-move-wrap')){
						thisItem = dataItem.children('li');
					}else{
						thisItem = dataItem;
					}

					thisItem.removeClass('arrayUp');
					thisItem.removeClass('arrayDown');
					thisItem.attr('dataType','delta');
					thisItem.addClass('drop-target');

					thisItem.find('.otherBtn').addClass('delta');
					thisItem.attr('detailtype','value');


					//thisItem.parent().append($('<li id="delta-drop' + self.item.index + '_'+ ($('.delta-drop').length + 1) + '" class="drop-target delta-drop" style="margin-top: 0px;height: 31px;margin-bottom: 4px;" drop-type="deltaTarget"><a href="#" class="btn neutral" style="width: calc(100% - 35px); margin-bottom: 4px;">' + gMessage.get('WISE.message.page.widget.drop.target') + '</a></li>'));
					thisItem.find('.otherBtn').height('66px');
					//thisItem.find('.otherBtn').append('<img src="' + WISE.Constants.context + '/resources/main/images/ico_triangle.png" alt>');

					$('.delta-drop').droppable(this.droppableOptions);
				}else{
					dataItem.addClass('delta-drop');
					dataItem.attr('drop-type','deltaTarget');
					dataItem.attr('prev-container','delta-drop');
					dataItem.droppable(gDashboard.dragNdropController.droppableOptions);
				}
				modalUi();
				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
				gDashboard.fieldManager.dataItemNo++;


			});
		}

		var gridFieldDataItemSetting = function(index, column, cubeUniqueName){
			var dataFieldType = column['dataType'] == 'string' ? 'dimension' : 'measure';
			var dataType = dataFieldType;
			var dataCaption = column['caption'];
			var SortOrderBy;
			var dataUniNm = column.UNI_NM == undefined ? column.name : column.UNI_NM;
			var arrayUpDown;
			if(dataFieldType == 'dimension'){
				SortOrderBy = column.sortOrder === undefined ? 'asc' : column.sortOrder;
				if(SortOrderBy == 'desc'){
					arrayUpDown = 'arrayDown';
				}else{
					arrayUpDown = 'arrayUp';
				}
			}
			//lsh topN 데이터 항목 필드 값
			if(column.TopNEnabled){
				/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
				var TopNEnabled = column.TopNEnabled ? column.TopNEnabled : false;
				var TopNOrder = column.TopNOrder ? column.TopNOrder : false;
				var TopNCount = column.TopNCount == undefined ? 5 : column.TopNCount;
				var TopNMeasure = column.TopNMeasure == undefined ? "" : column.TopNMeasure
				var TopNShowOthers = column.TopNShowOthers == undefined ? false : column.TopNShowOthers;
				var topMember = column.topMember == undefined ? "" : column.topMember
			}

			if(dataFieldType == 'measure'){
				dataCaption = column['caption'].toString().replace('(sum)','');
			}

			var displayMode = '';
            $.each(WISE.util.Object.toArray(_item.meta.GridColumns.GridMeasureColumn), function(_i, _dataItem){
            	if(column.uniqueName === _dataItem.Measure.UniqueName)
            	    displayMode = _dataItem.DisplayMode;
            });


            var sparklineOptions;
            $.each(WISE.util.Object.toArray(_item.meta.GridColumns.GridSparklineColumn), function(_i, _dataItem){
            	if(column.uniqueName === _dataItem.SparklineValue.UniqueName){
            		displayMode = 'sparkline';
            		dataType = displayMode;
            		sparklineOptions = _dataItem.SparklineOptions;
            	}
            });
            /*dogfoot 사용자 정의 데이터 불러오기시 relation check 하는 오류 수정 shlim 20210402*/
            var isCustomField = false;
            $.each(_itemMeta.dataSources,function(_x,_ds){
            	if(_ds.CalculatedFields){
            		$.each(_ds.CalculatedFields.CalculatedField,function(_y,_calcfield){
            			if(_calcfield.Name == dataUniNm) isCustomField = true;
            		})
            	}
            })

			var element = $('<ul class="display-unmove analysis-data" />');

			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" '+
					'dataType = "'+dataType+'" '+
					'prev-container="'+'columnList' + gridNum+'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+column['caption'] +'" '+
					'detailtype = "' + displayMode + '"'+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "'+column['caption'] +'" '+
					'TopNEnabled = "'+TopNEnabled+'" '+
					/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
					'TopNOrder = "'+TopNOrder+'" '+
					'TopNCount = "'+TopNCount+'" '+
					'TopNMeasure = "'+TopNMeasure+'" '+
					'TopNShowOthers = "'+TopNShowOthers+'" '+
					'topMember = "'+topMember+'" '+
					'style="height: 31px;">'+
					'<a href="#" class="ico ' + column['dataType'] + ' btn neutral" style="width: calc(100% - 35px);">' +
					'<div class="fieldName">'+dataCaption +"</div>"
					+ '</a></li>');

			if(sparklineOptions != undefined){
				dataItem.attr('highlightstartendpoints',sparklineOptions.HighlightStartEndPoints);
				dataItem.attr('highlightminmaxpoints',sparklineOptions.HighlightMinMaxPoints);
			}

			element.append(dataItem);
//					element.find('.btn').append($('<a href="#" class="other-menu-ico"></a>'));

			if(index == 0){
				element.appendTo($('#columnList' + gridNum));
			}else{
				element.insertAfter($('#columnList' + gridNum).children().get(index-1));
			}

			if(dataType == 'dimension'){
			/*dogfoot 크롬 다운로드시 데이터항목 아이콘 레이아웃 깨지는 오류 수정 shlim 20200717*/
				$('<a id="DataItem'+ gDashboard.fieldManager.dataItemNo  +'" href="#" class="otherBtn" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_axis.png" alt></a>').insertAfter(dataItem.children());
			}else if (dataType == 'sparkline'){
				$('<a id="DataItem'+ gDashboard.fieldManager.dataItemNo  +'" href="#" class="otherBtn sparkline" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_graph.png" alt></a>').insertAfter(dataItem.children());
			}else{
				$('<a href="#" class="otherBtn" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_sigma.png" alt></a>').insertAfter(dataItem.children());
			}

			if(dataFieldType == 'dimension'){
				element.addClass('other-menu');
				/*컬럼 값 메뉴*/
//				element.append(self.dimensionFieldOptionMenu);
				self.setDimensionFieldOptionMenu(element);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				compMoreMenuUi();
				self.expandMeasureList(element.find('.other-menu-ico'));

				/*Rename 메뉴*/
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);

				self.activeGridOption(dataItem);

				self.expandMeasureList(element.find('.other-menu-ico'));

				$.each(element.find('.measureList').children(),function(_k,_j){
					if(column.sortByMeasure != undefined){
						// mksong 2019.12.20 sort By 오류 수정 dogfoot
						if($(_j).attr('uni_nm') == column.sortByMeasure){
							$(_j).children().trigger('click');
							return false;
						}
					}
				});
			}else{
				var dataNumFormat = {};
				var uniqueName = 'DataItem'+gDashboard.fieldManager.dataItemNo;
				$.each(WISE.util.Object.toArray(_itemMeta.meta.DataItems.Measure),function(_i,_mea){
					if(_mea.UniqueName == column.uniqueName){
						dataNumFormat = _mea.NumericFormat;
						return false;
					}
				});
				if (typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined') {
					$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.DATA_GRID_ELEMENT), function(_i, _item) {
						if (_itemMeta.ComponentName === _item.CTRL_NM) {
							$.each(WISE.util.Object.toArray(_item.MEASURES), function(_j, _measure) {
								if (column.uniqueName === _measure.UNI_NM) {
									dataNumFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
									dataNumFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
									return false;
								}
							});
							return false;
						}
					});
				}

				/*컬럼 값 메뉴*/
				element.append(self.measureFieldOptionMenu);
				self.addFormat(dataItem);
				dataItem.data('formatOptions', dataNumFormat);
				self.setFormatOptionModalForOpen(dataItem);
				compMoreMenuUi();

				/*Rename 메뉴*/
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);

				$.each(element.find('.summaryType'),function(_i,_summary){
					if(column.summaryType == $(_summary).attr('summaryType')){
						$(_summary).trigger('click');
						return false;
					}
				});
				modalUi();
			}
			dataItem.data('dataGridColumnWeight',column.width);
			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			self.addEventChangeType(dataItem.find(".otherBtn"));
			gDashboard.fieldManager.dataItemNo++;
		}

		var sparkLineDataItemSetting = function(sparkline, prevContainer, number, index, dataFieldType, cubeUniqueName){
			var dataCaption = sparkline.caption;
			var element = $('<ul class="display-unmove analysis-data" />');
			if(index == 0){
				$('#' + prevContainer + number).empty();
				element.appendTo($('#' + prevContainer + number));
			}else{
				element.insertAfter($('#' + prevContainer + number).children().get(index-1));
			}

			var arrayUpDown;
			var SortOrderBy = sparkline.sortOrder === undefined ? 'asc' : sparkline.sortOrder;

			if(SortOrderBy === 'asc'){
				arrayUpDown = 'arrayUp';
			}else if(SortOrderBy === 'desc'){
				arrayUpDown = 'arrayDown';
			}else{
				arrayUpDown = 'arrayNone';
			}

			var fieldType = sparkline.dataType? sparkline.dataType : sparkline.type;

			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" '+
					'dataType = "sparklineArgument" '+
					'prev-container="' + prevContainer + number + '" ' +
					'data-source-id="' + _itemMeta.dataSourceId + '" ' +
					'uni_nm="' + sparkline.name + '" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="' + 'DataItem' + gDashboard.fieldManager.dataItemNo  + '" ' +
					'caption = "' + dataCaption + '" ' +
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "' + dataCaption + '" ' +
					'style="height: 31px;">' +
					'<a href="#" class="ico ' + fieldType + ' btn neutral">' +
					'<div class="fieldName">' + dataCaption + '</div>' +
					'</a></li>');
			element.append(dataItem);

			element.appendTo($('#'+ prevContainer + number));

			/*컬럼 값 메뉴*/
//			element.append(self.dimensionFieldOptionMenu);
//			self.setDimensionFieldOptionMenu(element);
			self.fieldRename(dataItem);
			//2020-01-14 LSH topN
			self.topNset(dataItem);
			compMoreMenuUi();
//			self.expandMeasureList(element.find('.other-menu-ico'));

			/*Rename 메뉴*/
			self.fieldRename(dataItem);
			//2020-01-14 LSH topN
			self.topNset(dataItem);

			self.activeGridOption(dataItem);
			gDashboard.fieldManager.dataItemNo++;
			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
		}

		/*dogfoot 통계 분석 레이아웃 불러오기 shlim 20201102*/
		var gridAysFieldDataItemSetting = function(index, column, cubeUniqueName){
			var dataFieldType = column['dataType'] == 'string' ? 'dimension' : 'measure';
			var dataType = dataFieldType;
			var dataCaption = column['caption'];
			var SortOrderBy,focusItemType;
			var dataUniNm = column.UNI_NM == undefined ? column.name : column.UNI_NM;
			var prevContainerNm = column.ContainerType != undefined ? column.ContainerType : "";
			var arrayUpDown;
			if(dataFieldType == 'dimension'){
				SortOrderBy = column.sortOrder === undefined ? 'asc' : column.sortOrder;
				if(SortOrderBy == 'desc'){
					arrayUpDown = 'arrayDown';
				}else{
					arrayUpDown = 'arrayUp';
				}
			}
			//lsh topN 데이터 항목 필드 값
			if(column.TopNEnabled){
				/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
				var TopNEnabled = column.TopNEnabled ? column.TopNEnabled : false;
				var TopNOrder = column.TopNOrder ? column.TopNOrder : false;
				var TopNCount = column.TopNCount == undefined ? 5 : column.TopNCount;
				var TopNMeasure = column.TopNMeasure == undefined ? "" : column.TopNMeasure
						var TopNShowOthers = column.TopNShowOthers == undefined ? false : column.TopNShowOthers;
				var topMember = column.topMember == undefined ? "" : column.topMember
			}

			if(dataFieldType == 'measure'){
				dataCaption = column['caption'].replace('(sum)','');
			}

			var displayMode = '';
			$.each(WISE.util.Object.toArray(_item.meta.GridColumns.GridMeasureColumn), function(_i, _dataItem){
				if(column.uniqueName === _dataItem.Measure.UniqueName)
					displayMode = _dataItem.DisplayMode;
			});


			var sparklineOptions;
			$.each(WISE.util.Object.toArray(_item.meta.GridColumns.GridSparklineColumn), function(_i, _dataItem){
				if(column.uniqueName === _dataItem.SparklineValue.UniqueName){
					displayMode = 'sparkline';
					dataType = displayMode;
					sparklineOptions = _dataItem.SparklineOptions;
				}
			});



			var element = $('<ul class="display-unmove analysis-data" />');

			switch(gDashboard.analysisType) {
				case 'insertOnewayAnova':
					focusItemType = 'onewayAnova';
					break;
				case 'insertTwowayAnova':
					focusItemType = 'twowayAnova';
					break;
				case 'insertOnewayAnova2':
					focusItemType = 'onewayAnova2';
					break;
				case 'insertSimpleRegression':
					focusItemType = 'simpleRegression';
					break;
				case 'insertMultipleRegression':
					focusItemType = 'multipleRegression';
					break;
				case 'insertLogisticRegression':
					focusItemType = 'logisticRegression';
					break;
				case 'insertMultipleLogisticRegression':
					focusItemType = 'multipleLogisticRegression';
					break;
				case 'insertPearsonsCorrelation':
					focusItemType = 'pearsonsCorrelation';
					break;
				case 'insertSpearmansCorrelation':
					focusItemType = 'spearmansCorrelation';
					break;
				/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
				case 'insertTtest':
					focusItemType = 'tTest';
					break;
				case 'insertZtest':
					focusItemType = 'zTest';
					break;
				case 'insertChitest':
					focusItemType = 'chiTest';
					break;
				case 'insertFtest':
					focusItemType = 'fTest';
					break;
				/* DOGFOOT ktkang 다변량분석 추가  20210215 */
				case 'insertMultivariate':
					focusItemType = 'multivariate';
					break;
				default:
					break;
			}

			var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" '+
					'dataType = "'+dataType+'" '+
					'prev-container="'+ prevContainerNm + 1+'" '+
					'data-source-id="' + _itemMeta.dataSourceId + '" '+
					'uni_nm="'+dataUniNm+'" ' +
					'cubeuninm= "' + cubeUniqueName + '" ' +
					'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
					'caption = "'+column['caption'] +'" '+
					'detailtype = "' + displayMode + '"'+
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					'title = "'+column['caption'] +'" '+
					'TopNEnabled = "'+TopNEnabled+'" '+
					/*dogfoot topN 정렬 설정 추가 shlim 20201112*/
					'TopNOrder = "'+TopNOrder+'" '+
					'TopNCount = "'+TopNCount+'" '+
					'TopNMeasure = "'+TopNMeasure+'" '+
					'TopNShowOthers = "'+TopNShowOthers+'" '+
					'topMember = "'+topMember+'" '+
					'containerType ="'+prevContainerNm+'"'+
					'style="height: 31px;">'+
					'<a href="#" class="ico ' + column['dataType'] + ' btn neutral" style="width: 100%;">' +
					'<div class="fieldName">'+dataCaption +"</div>"
					+ '</a></li>');

			if(sparklineOptions != undefined){
				dataItem.attr('highlightstartendpoints',sparklineOptions.HighlightStartEndPoints);
				dataItem.attr('highlightminmaxpoints',sparklineOptions.HighlightMinMaxPoints);
			}

			element.append(dataItem);
//					element.find('.btn').append($('<a href="#" class="other-menu-ico"></a>'));

			if($('#'+ prevContainerNm + 1).children().length == 0){
				element.appendTo($('#'+ prevContainerNm + 1));
			}else{
				element.insertAfter($('#'+ prevContainerNm + 1).children().get($('#'+ prevContainerNm + 1).children().length-1));
			}

			//20201112 통게분석 그리드 오른쪽 아이콘 제거 dogfoot
			if(gDashboard.reportType !== 'StaticAnalysis' && gDashboard.reportType !== 'RAnalysis'  && gDashboard.reportType !== 'DSViewer'){
				if(dataType == 'dimension'){
					/*dogfoot 크롬 다운로드시 데이터항목 아이콘 레이아웃 깨지는 오류 수정 shlim 20200717*/
					$('<a id="DataItem'+ gDashboard.fieldManager.dataItemNo  +'" href="#" class="otherBtn" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_axis.png" alt></a>').insertAfter(dataItem.children());
				}else if (dataType == 'sparkline'){
					$('<a id="DataItem'+ gDashboard.fieldManager.dataItemNo  +'" href="#" class="otherBtn sparkline" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_graph.png" alt></a>').insertAfter(dataItem.children());
				}else{
					$('<a href="#" class="otherBtn" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_sigma.png" alt></a>').insertAfter(dataItem.children());
				}
			}


			if(dataFieldType == 'dimension'){
				element.addClass('other-menu');
				/*컬럼 값 메뉴*/
//				element.append(self.dimensionFieldOptionMenu);
				self.setDimensionFieldOptionMenu(element);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				compMoreMenuUi();
				self.expandMeasureList(element.find('.other-menu-ico'));

				/*Rename 메뉴*/
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);

				self.activeGridOption(dataItem);

				self.expandMeasureList(element.find('.other-menu-ico'));

				$.each(element.find('.measureList').children(),function(_k,_j){
					if(column.sortByMeasure != undefined){
						// mksong 2019.12.20 sort By 오류 수정 dogfoot
						if($(_j).attr('uni_nm') == column.sortByMeasure){
							$(_j).children().trigger('click');
							return false;
						}
					}
				});
			}else{
				var dataNumFormat = {};
				var uniqueName = 'DataItem'+gDashboard.fieldManager.dataItemNo;
				$.each(WISE.util.Object.toArray(_itemMeta.meta.DataItems.Measure),function(_i,_mea){
					if(_mea.UniqueName == column.uniqueName){
						dataNumFormat = _mea.NumericFormat;
						return false;
					}
				});
				if (typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined') {
					$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.DATA_GRID_ELEMENT), function(_i, _item) {
						if (_itemMeta.ComponentName === _item.CTRL_NM) {
							$.each(WISE.util.Object.toArray(_item.MEASURES), function(_j, _measure) {
								if (column.uniqueName === _measure.UNI_NM) {
									dataNumFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
									dataNumFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
									return false;
								}
							});
							return false;
						}
					});
				}

				/*컬럼 값 메뉴*/
				element.append(self.measureFieldOptionMenu);
				self.addFormat(dataItem);
				dataItem.data('formatOptions', dataNumFormat);
				self.setFormatOptionModalForOpen(dataItem);
				compMoreMenuUi();

				/*Rename 메뉴*/
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);

				$.each(element.find('.summaryType'),function(_i,_summary){
					if(column.summaryType == $(_summary).attr('summaryType')){
						$(_summary).trigger('click');
						return false;
					}
				});
				modalUi();
			}
			//20201112 AJKIM 통계 분석일 경우 필드 메뉴 제거 dogfoot
			if(gDashboard.reportType === 'StaticAnalysis' || gDashboard.reportType == 'DSViewer'){
				dataItem.parent().find('.divide-menu').remove();
			}
			dataItem.data('dataGridColumnWeight',column.width);
			dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			//20201112 통게분석 그리드 오른쪽 아이콘 제거 dogfoot
			if(gDashboard.reportType !== 'StaticAnalysis' && gDashboard.reportType !== 'RAnalysis' && gDashboard.reportType !== 'DSViewer')
				self.addEventChangeType(dataItem.find(".otherBtn"));
			gDashboard.fieldManager.dataItemNo++;
		}

		switch (_itemMeta.type) {
			case 'PIVOT_GRID':
//				var treeView = $('#allList').dxTreeView('instance');
//				var pivotNum = _itemMeta.ComponentName.replace('pivotDashboardItem', '');
				var pivotNum = _itemMeta.isAdhocItem == true ? _itemMeta.adhocIndex : _itemMeta.index;
				if(WISE.Constants.editmode == 'viewer'){
					pivotNum = pivotNum + '_' + gDashboard.structure.ReportMasterInfo.id;
				}
				// retrieve data fields

				$.each(_itemMeta.dataFields, function(index, dataField) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.PIVOT_GRID_ELEMENT, dataField.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, dataField.uniqueName);

					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, dataField.uniqueName);
					if(_itemMeta.isAdhocItem){
						measureDataItemSetting(dataField, index, 'dataAdHocList', pivotNum, dataNumFormat, false, cubeUniqueName);
					}else{
						measureDataItemSetting(dataField, index, 'dataList', pivotNum, dataNumFormat, false, cubeUniqueName);
					}

				});

				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.PIVOT_GRID_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					if(_itemMeta.isAdhocItem){
						hiddenDataItemSetting(hiddenmeasure, index, 'adhoc_hide_measure_list', pivotNum, dataNumFormat, cubeUniqueName);
					}else{
						hiddenDataItemSetting(hiddenmeasure, index, 'pivot_hide_measure_list', pivotNum, dataNumFormat, cubeUniqueName);
					}
				});

				// retrieve rows
				$.each(_itemMeta.rows, function(index, row) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, row.uniqueName);
					if(_itemMeta.isAdhocItem){
						pivotDimensionDataItemSetting(row, 'rowAdHocList', pivotNum, index, cubeUniqueName);
					}else{
						pivotDimensionDataItemSetting(row, 'rowList', pivotNum, index, cubeUniqueName);
					}
				});
				// retrieve columns
				$.each(_itemMeta.columns, function(index, column) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, column.uniqueName);
					if(_itemMeta.isAdhocItem){
						pivotDimensionDataItemSetting(column, 'colAdHocList', pivotNum, index, cubeUniqueName);
					}else{
						pivotDimensionDataItemSetting(column, 'colList', pivotNum, index, cubeUniqueName);
					}
				});
				break;
			case 'DATA_GRID':
				var gridNum = _itemMeta.ComponentName.replace('gridDashboardItem', '');
				// retrieve columns
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				if(!_aysCheck){
					$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.DATA_GRID_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
						var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
						hiddenDataItemSetting(hiddenmeasure, index, 'grid_hide_measure_list', gridNum, dataNumFormat, cubeUniqueName);
					});
					$.each(_itemMeta.columns, function(index, column) {
						var cubeUniqueName = dataCubeUniqueName(_itemMeta.columns, column.uniqueName);
						if(column.dataField.indexOf('DELTA_CELL_COLOR') != -1){
							gridFieldDeltaDataItemSetting(index, column);
						}else{
							gridFieldDataItemSetting(index, column, cubeUniqueName);
						}
					});
					// retrieve sparklines
					$.each(_itemMeta.sparklineElements, function(index, sparkline) {
						var cubeUniqueName = dataCubeUniqueName(_itemMeta.sparklineElements, sparkline.uniqueName);
						sparkLineDataItemSetting(sparkline, 'sparkLine', gridNum, index, sparkline.type, cubeUniqueName);
					});
				}else{
					$.each(_itemMeta.columns, function(index, column) {
						var cubeUniqueName = dataCubeUniqueName(_itemMeta.columns, column.uniqueName);
						if(column.dataField.indexOf('DELTA_CELL_COLOR') != -1){
							gridFieldDeltaDataItemSetting(index, column);
						}else{
							gridAysFieldDataItemSetting(index, column, cubeUniqueName,_itemMeta.focusItemType);
						}
					});
				}


				break;
			case 'SIMPLE_CHART':
//				var treeView = $('#allList').dxTreeView('instance');
				var chartNum = _itemMeta.ComponentName.replace('chartDashboardItem', '');
				
				/* DOGFOOT syjin 뷰어 불러오기 수정  20211118*/
				if(WISE.Constants.editmode == 'viewer'){
					chartNum += ("_" + gDashboard.structure.ReportMasterInfo.id)
				}
				
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					if(_itemMeta.isAdhocItem){
						measureDataItemSetting(measure, index, 'dataAdHocList', chartNum, dataNumFormat, false, cubeUniqueName);
					}else{
						measureDataItemSetting(measure, index, 'chartValueList', chartNum, dataNumFormat, false, cubeUniqueName);
					}
				});

				// retrieve hidden measures
				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					if(_itemMeta.isAdhocItem){
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
						hiddenDataItemSetting(hiddenmeasure, index, 'adhoc_hide_measure_list', chartNum, dataNumFormat);
					}else{
						hiddenDataItemSetting(hiddenmeasure, index, 'chart_hide_measure_list', chartNum, undefined, cubeUniqueName);
					}
				});
				// retrieve arguments
				$.each(_itemMeta.arguments, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);
					if(_itemMeta.isAdhocItem){
						argumentDataItemSetting(argument, index, 'rowAdHocList', chartNum, cubeUniqueName);
					}else{
						argumentDataItemSetting(argument, index, 'chartParameterList', chartNum, cubeUniqueName);
					}
				});
				// retrieve dimensions
				$.each(_itemMeta.seriesDimensions, function(index, series) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
					if(_itemMeta.isAdhocItem){
					/* DOGFOOT ktkang 사용안하는 파라미터 제거  20200706 */
						seriesDimensionDataItemSetting(series, index, 'colAdHocList', chartNum, cubeUniqueName);
					}else{
						seriesDimensionDataItemSetting(series, index, 'chartSeriesList', chartNum, cubeUniqueName);
					}
				});
				break;
			case 'BUBBLE_CHART':
				var chartNum = _itemMeta.ComponentName.replace('bubbleChartDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES')
					measureDataItemSetting(measure, index, 'bubbleChartValueList', chartNum, dataNumFormat, true, cubeUniqueName);
				});

				// retrieve hidden measures
//				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
//					var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
//					hiddenDataItemSetting(hiddenmeasure, index, 'chart_hide_measure_list', chartNum, dataNumFormat, cubeUniqueName);
//				});
				// retrieve arguments
				$.each(_itemMeta.arguments, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);
					var position = 'Y';
                    if(index == 0){
                    	position = 'X';
                    }
					argumentDataItemSetting(argument, index, 'bubbleChart' + position + 'List', chartNum, cubeUniqueName);
				});

				break;
			case 'PIE_CHART':
//				var treeView = $('#allList').dxTreeView('instance');
				var pieNum = _itemMeta.ComponentName.replace('pieDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.PIE_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'pieValueList', pieNum, dataNumFormat, true, cubeUniqueName);
				});
				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.PIE_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'pie_hide_measure_list', pieNum, dataNumFormat, cubeUniqueName);
				});
				// retrieve arguments
				$.each(_itemMeta.arguments, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);
					argumentDataItemSetting(argument, index, 'pieParameterList', pieNum, cubeUniqueName);
				});
				// retrieve dimensions
				$.each(_itemMeta.seriesDimensions, function(index, series) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
					seriesDimensionDataItemSetting(series, index, 'pieSeriesList', pieNum, cubeUniqueName);
				});
				break;
			case 'CARD_CHART':
				var cardNum = _itemMeta.ComponentName.replace('cardDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CARD_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'cardValueList', cardNum, dataNumFormat, true, cubeUniqueName);
				});
				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CARD_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'card_hide_measure_list', cardNum, dataNumFormat, cubeUniqueName);
				});
// 				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
// 					var dataFieldType = 'measure';
// 					var dataCaption = hiddenmeasure['caption'];
// 					var dataItemNo = hiddenmeasure.uniqueName;
// 					var dataUniNm = hiddenmeasure.UNI_NM == undefined ? hiddenmeasure.name : hiddenmeasure.UNI_NM;

// 					/*Format... 메뉴*/
// 					var dataNumFormat = {};
// 					$.each(WISE.util.Object.toArray(_itemMeta.meta.DataItems.Measure),function(_i,_mea){
// 						if(_mea.UniqueName == hiddenmeasure.uniqueName){
// 							dataNumFormat = _mea.NumericFormat;
// 							return false;
// 						}
// 					});
// 					if (typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined') {
// 						$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CARD_DATA_ELEMENT), function(_i, _item) {
// 							if (_itemMeta.ComponentName === _item.CTRL_NM) {
// 								$.each(WISE.util.Object.toArray(_item.MEASURES), function(_j, _measure) {
// 									if (dataItemNo === _measure.UNI_NM) {
// 										dataNumFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
// 										dataNumFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
// 										return false;
// 									}
// 								});
// 								return false;
// 							}
// 						});
// 					}

// 					var element = $('<ul class="display-unmove analysis-data" />');

// 					if(index == 0){
// 						element.appendTo($('#card_hide_measure_list' + cardNum));
// 					}else{
// 						element.insertAfter($('#card_hide_measure_list' + cardNum).children().get(index-1));
// 					}

// //					var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" prev-container="'+'chartValueList' + chartNum+'" dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px; width: 100%;"><a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);">' + dataCaption
// //							+ '</a></li>'));
// //					element.append(dataItem);
// 					var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" '+
// 							'prev-container="'+'pie_hide_measure_list' + cardNum+'" '+
// 							'data-source-id="' + _itemMeta.dataSourceId + '" '+
// 							'uni_nm="'+dataUniNm+'" ' +
// 							'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
// 							'caption = "'+dataCaption+'" '+
// 							'style="height: 31px; width: 100%;"><a href="#" class="ico sigma btn neutral">' +
// 							'<div class="fieldName">' + dataCaption + "</div>"
// 							+ '</a></li>');
// 					element.append(dataItem);

// 					/*컬럼 값 메뉴*/
// 					element.append(self.hiddenMeasureFieldOptionMenu);
// 					dataItem.data('formatOptions', dataNumFormat);
// 					self.addFormat(dataItem);
// 					self.setFormatOptionModalForOpen(dataItem);
// 					compMoreMenuUi();

// 					/*Rename 메뉴*/
// 					self.fieldRename(dataItem);


// 					dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
// 					/*컬럼 값 메뉴 선택*/
// 					$.each(element.find('.summaryType'),function(_i,_summary){
// 						if(hiddenmeasure.summaryType == $(_summary).attr('summaryType')){
// 							$(_summary).trigger('click');
// 							return false;
// 						}
// 					});

// 					// $('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption"><img src="' + WISE.Constants.context + '/resources/main/images/ico_bar1.png" alt></a>').insertAfter(dataItem.children());
// 					// var dataItemOptions = dataItem.find('#' + dataItemId);
// 					// self.addChartDataItemOptions(_itemMeta, dataItemNo, dataItemOptions);
// 					// dataItemOptions.on('click',function(e){
// 					// 	self.item.initDataItemOptionsWindow(this);
// 					// 	e.preventDefault();
// 					// });
// 					modalUi();

// 					gDashboard.fieldManager.dataItemNo++;
// 				});
				// retrieve dimensions
				$.each(_itemMeta.seriesDimensions, function(index, series) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
					seriesDimensionDataItemSetting(series, index, 'cardSeriesList', cardNum, cubeUniqueName);
				});
				// retrieve sparklines
				$.each(_itemMeta.sparklineElements, function(index, sparkline) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, sparkline.uniqueName);
					sparkLineDataItemSetting(sparkline, 'cardSparkLine', cardNum, index, 'measure', cubeUniqueName);
				});
				break;
			/* DOGFOOT hsshim 2020-02-03 게이지 데이터 항목 UI 및 기능 작업 */
			case 'GAUGE_CHART':
				var gaugeNum = _itemMeta.ComponentName.replace('gaugeDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.GAUGE_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'gaugeValueList', gaugeNum, dataNumFormat, true, cubeUniqueName);
				});
// 				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
// 					var dataFieldType = 'measure';
// 					var dataCaption = hiddenmeasure['caption'];
// 					var dataItemNo = hiddenmeasure.uniqueName;
// 					var dataUniNm = hiddenmeasure.UNI_NM == undefined ? hiddenmeasure.name : hiddenmeasure.UNI_NM;

// 					/*Format... 메뉴*/
// 					var dataNumFormat = {};
// 					$.each(WISE.util.Object.toArray(_itemMeta.meta.DataItems.Measure),function(_i,_mea){
// 						if(_mea.UniqueName == hiddenmeasure.uniqueName){
// 							dataNumFormat = _mea.NumericFormat;
// 							return false;
// 						}
// 					});
// 					if (typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined') {
// 						$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.WEB.GAUGE_DATA_ELEMENT), function(_i, _item) {
// 							if (_itemMeta.ComponentName === _item.CTRL_NM) {
// 								$.each(WISE.util.Object.toArray(_item.MEASURES), function(_j, _measure) {
// 									if (dataItemNo === _measure.UNI_NM) {
// 										dataNumFormat.SuffixEnabled = _measure.NUMERIC_FORMAT.SUFFIX_ENABLED === 'Y';
// 										dataNumFormat.Suffix = _measure.NUMERIC_FORMAT.SUFFIX;
// 										return false;
// 									}
// 								});
// 								return false;
// 							}
// 						});
// 					}

// 					var element = $('<ul class="display-unmove analysis-data" />');

// 					if(index == 0){
// 						element.appendTo($('#gauge_hide_measure_list' + gaugeNum));
// 					}else{
// 						element.insertAfter($('#gauge_hide_measure_list' + gaugeNum).children().get(index-1));
// 					}

// //					var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" prev-container="'+'chartValueList' + chartNum+'" dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px; width: 100%;"><a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);">' + dataCaption
// //							+ '</a></li>'));
// //					element.append(dataItem);
// 					var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" '+
// 							'prev-container="'+'pie_hide_measure_list' + gaugeNum+'" '+
// 							'data-source-id="' + _itemMeta.dataSourceId + '" '+
// 							'uni_nm="'+dataUniNm+'" ' +
// 							'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
// 							'caption = "'+dataCaption+'" '+
// 							'style="height: 31px; width: 100%;"><a href="#" class="ico sigma btn neutral">' +
// 							'<div class="fieldName">' + dataCaption + "</div>"
// 							+ '</a></li>');
// 					element.append(dataItem);

// 					/*컬럼 값 메뉴*/
// 					element.append(self.hiddenMeasureFieldOptionMenu);
// 					dataItem.data('formatOptions', dataNumFormat);
// 					self.addFormat(dataItem);
// 					self.setFormatOptionModalForOpen(dataItem);
// 					compMoreMenuUi();

// 					/*Rename 메뉴*/
// 					self.fieldRename(dataItem);


// 					dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
// 					/*컬럼 값 메뉴 선택*/
// 					$.each(element.find('.summaryType'),function(_i,_summary){
// 						if(hiddenmeasure.summaryType == $(_summary).attr('summaryType')){
// 							$(_summary).trigger('click');
// 							return false;
// 						}
// 					});

// 					// $('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption"><img src="' + WISE.Constants.context + '/resources/main/images/ico_bar1.png" alt></a>').insertAfter(dataItem.children());
// 					// var dataItemOptions = dataItem.find('#' + dataItemId);
// 					// self.addChartDataItemOptions(_itemMeta, dataItemNo, dataItemOptions);
// 					// dataItemOptions.on('click',function(e){
// 					// 	self.item.initDataItemOptionsWindow(this);
// 					// 	e.preventDefault();
// 					// });
// 					modalUi();

// 					gDashboard.fieldManager.dataItemNo++;
// 				});
				// retrieve dimensions
				$.each(_itemMeta.seriesDimensions, function(index, series) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
					seriesDimensionDataItemSetting(series, index, 'gaugeSeriesList', gaugeNum, cubeUniqueName);
				});
				break;
			case 'CHOROPLETH_MAP':
				var MapNum = _itemMeta.ComponentName.replace('choroplethMapDashboardItem', '');
				
				//20210419 AJKIM 뷰어 대시보드 데이터 항목 추가 dogfoot
				if(WISE.Constants.editmode == 'viewer'){
					MapNum += ("_" + gDashboard.structure.ReportMasterInfo.id)
				}
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHOROPLETH_MAP_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'mapValueList', MapNum, dataNumFormat, true, cubeUniqueName);
				});

				// retrieve arguments
				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					if(index == 0){
						if(_itemMeta.customShapefile.url[0] == ""){
							if(_itemMeta.customShapefile.url[1] == ""){
								argumentDataItemSettingNoTopN(dimension, index, 'mapDongList', MapNum, cubeUniqueName);
							}else{
								argumentDataItemSettingNoTopN(dimension, index, 'mapCityList', MapNum, cubeUniqueName);
							}
						}else{
							argumentDataItemSettingNoTopN(dimension, index, 'mapStateList', MapNum, cubeUniqueName);
						}
					}else if(index == 1){
						if(_itemMeta.customShapefile.url[0] == ""){
						    argumentDataItemSettingNoTopN(dimension, index, 'mapDongList', MapNum, cubeUniqueName);
						}
						else{
							argumentDataItemSettingNoTopN(dimension, index, 'mapCityList', MapNum, cubeUniqueName);
						}
					}else{
						argumentDataItemSettingNoTopN(dimension, index, 'mapDongList', MapNum, cubeUniqueName);						
					}					
				});
				// retrieve dimensions
				break;
			case 'TREEMAP':
				var TreemapNum = _itemMeta.ComponentName.replace('treemapDashboardItem', '');
				// retrieve measures

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
					/*dogfoot 트리맵 툴팁 오류 수정 shlim 20200715*/
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.TREEMAP_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'treemapValueList', TreemapNum, dataNumFormat, true, cubeUniqueName);
				});

				// retrieve arguments
				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'treemapParameterList', TreemapNum, cubeUniqueName);
				});
				break;
			case 'RECTANGULAR_ARAREA_CHART':

				var RectangularAreaChartNum = _itemMeta.ComponentName.replace('RectangularAreaChartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.RECTANGULAR_ARAREA_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'RectangularAreaChartValueList', RectangularAreaChartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'RectangularAreaChartParameterList', RectangularAreaChartNum, cubeUniqueName);
				});
				break;
			case 'WATERFALL_CHART':
				var waterfallchartNum = _itemMeta.ComponentName.replace('waterfallchartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.WATERFALL_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'waterfallchartValueList', waterfallchartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'waterfallchartParameterList', waterfallchartNum, cubeUniqueName);
				});
				break;
			case 'BIPARTITE_CHART':
				var bipartitechartNum = _itemMeta.ComponentName.replace('bipartitechartDashboardItem', '');

//				$.each(_itemMeta.measures, function(index, measure) {
//					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
//						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.BIPARTITE_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
//					else
//						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
//					measureDataItemSetting(measure, index, 'bipartitechartValueList', bipartitechartNum, dataNumFormat, true, cubeUniqueName);
//				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'bipartitechartParameterList', bipartitechartNum, cubeUniqueName);
				});
				break;
			case 'SANKEY_CHART':
				var sankeychartNum = _itemMeta.ComponentName.replace('sankeychartDashboardItem', '');

//				$.each(_itemMeta.measures, function(index, measure) {
//					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
//						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.SANKEY_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
//					else
//						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
//					measureDataItemSetting(measure, index, 'sankeychartValueList', sankeychartNum, dataNumFormat, true, cubeUniqueName);
//				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'sankeychartParameterList', sankeychartNum, cubeUniqueName);
				});
				break;
			case 'HISTOGRAM_CHART':

				var histogramchartNum = _itemMeta.ComponentName.replace('histogramchartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.HISTOGRAM_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'histogramchartValueList', histogramchartNum, dataNumFormat, true, cubeUniqueName);
				});

//				$.each(_itemMeta.dimensions, function(index, dimension) {
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
//					argumentDataItemSettingNoTopN(dimension, index, 'histogramchartParameterList', histogramchartNum, cubeUniqueName);
//				});
				break;
			case 'DIVERGING_CHART':
				var chartNum = _itemMeta.ComponentName.replace('divergingchartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.DIVERGING_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'divergingchartValueList', chartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'divergingchartParameterList', chartNum, cubeUniqueName);
				});

				$.each(_itemMeta.seriesDimensions, function(index, series) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
					seriesDimensionDataItemSetting(series, index, 'divergingchartSeriesList', chartNum, cubeUniqueName);
				});

				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'divergingchart_hide_measure_list', chartNum, undefined, cubeUniqueName);
				});
				break;
			case 'SCATTER_PLOT':
				var chartNum = _itemMeta.ComponentName.replace('scatterplotDashboardItem', '');

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					if(cubeUniqueName === "")
						cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, dimension.uniqueName);
					if(index === 0){
						argumentDataItemSettingNoTopN(dimension, index, 'scatterplotXList', chartNum, cubeUniqueName);
					} else if(index === 1){
						argumentDataItemSettingNoTopN(dimension, index, 'scatterplotYList', chartNum, cubeUniqueName);
					} else{
						argumentDataItemSettingNoTopN(dimension, index, 'scatterplotParameterList', chartNum, cubeUniqueName);
					}
				});

				break;
			case 'COORDINATE_LINE':
				var chartNum = _itemMeta.ComponentName.replace('coordinatelineDashboardItem', '');

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					if(cubeUniqueName === "")
						cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, dimension.uniqueName);
					if(index === 0){
						argumentDataItemSettingNoTopN(dimension, index, 'coordinatelineXList', chartNum, cubeUniqueName);
					} else if(index === 1){
						argumentDataItemSettingNoTopN(dimension, index, 'coordinatelineYList', chartNum, cubeUniqueName);
					} else{
						argumentDataItemSettingNoTopN(dimension, index, 'coordinatelineParameterList', chartNum, cubeUniqueName);
					}
				});

				break;
			case 'COORDINATE_DOT':
				var chartNum = _itemMeta.ComponentName.replace('coordinatedotDashboardItem', '');

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					if(cubeUniqueName === "")
						cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, dimension.uniqueName);
					if(index === 0){
						argumentDataItemSettingNoTopN(dimension, index, 'coordinatedotXList', chartNum, cubeUniqueName);
					} else if(index === 1){
						argumentDataItemSettingNoTopN(dimension, index, 'coordinatedotYList', chartNum, cubeUniqueName);
					} else{
						argumentDataItemSettingNoTopN(dimension, index, 'coordinatedotParameterList', chartNum, cubeUniqueName);
					}
				});

				break;
			case 'SCATTER_PLOT2':
				var chartNum = _itemMeta.ComponentName.replace('scatterplot2DashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.SCATTER_PLOT2_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'scatterplot2ZList', chartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					if(cubeUniqueName === "")
						cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, dimension.uniqueName);
					if(index === 0){
						argumentDataItemSettingNoTopN(dimension, index, 'scatterplot2XList', chartNum, cubeUniqueName);
					} else if(index === 1){
						argumentDataItemSettingNoTopN(dimension, index, 'scatterplot2YList', chartNum, cubeUniqueName);
					} else{
						argumentDataItemSettingNoTopN(dimension, index, 'scatterplot2ParameterList', chartNum, cubeUniqueName);
					}
				});

//				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
//					hiddenDataItemSetting(hiddenmeasure, index, 'scatterplot2_hide_measure_list', chartNum, undefined, cubeUniqueName);
//				});
				break;
			case 'RADIAL_TIDY_TREE':
				var chartNum = _itemMeta.ComponentName.replace('radialtidytreeDashboardItem', '');

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'radialTidyTreeParameterList', chartNum, cubeUniqueName);
				});
				break;
			case 'ARC_DIAGRAM':
				var chartNum = _itemMeta.ComponentName.replace('arcdiagramDashboardItem', '');

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'arcdiagramParameterList', chartNum, cubeUniqueName);
				});
				break;
			case 'SCATTER_PLOT_MATRIX':
				var chartNum = _itemMeta.ComponentName.replace('scatterplotmatrixDashboardItem', '');

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					if(cubeUniqueName === "")
						cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, dimension.uniqueName);
					if(index === 0){
						argumentDataItemSettingNoTopN(dimension, index, 'scatterPlotMatrixX1List', chartNum, cubeUniqueName);
					} else if(index === 1){
						argumentDataItemSettingNoTopN(dimension, index, 'scatterPlotMatrixY1List', chartNum, cubeUniqueName);
					} else if(index === 2){
						argumentDataItemSettingNoTopN(dimension, index, 'scatterPlotMatrixX2List', chartNum, cubeUniqueName);
					} else if(index === 3){
						argumentDataItemSettingNoTopN(dimension, index, 'scatterPlotMatrixY2List', chartNum, cubeUniqueName);
					} else{
						argumentDataItemSettingNoTopN(dimension, index, 'scatterPlotMatrixParameterList', chartNum, cubeUniqueName);
					}
				});
				break;
			case 'HISTORY_TIMELINE':
				var chartNum = _itemMeta.ComponentName.replace('historytimelineDashboardItem', '');

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					if(index === 0){
						argumentDataItemSettingNoTopN(dimension, index, 'historyTimelineStartList', chartNum, cubeUniqueName);
					} else if(index === 1){
						argumentDataItemSettingNoTopN(dimension, index, 'historyTimelineEndList', chartNum, cubeUniqueName);
					} else{
						argumentDataItemSettingNoTopN(dimension, index, 'historyTimelineParameterList', chartNum, cubeUniqueName);
					}
				});
				break;
			case 'BOX_PLOT':
				var chartNum = _itemMeta.ComponentName.replace('boxplotDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.BOX_PLOT_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'boxplotValueList', chartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					if(cubeUniqueName === "")
						cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'boxplotParameterList', chartNum, cubeUniqueName);
				});
				break;
			case 'DEPENDENCY_WHEEL':
				var chartNum = _itemMeta.ComponentName.replace('dependencywheelDashboardItem', '');

//				$.each(_itemMeta.measures, function(index, measure) {
//					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
//						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.DEPENDENCY_WHEEL_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
//					else
//						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
//					measureDataItemSetting(measure, index, 'dependencywheelValueList', chartNum, dataNumFormat, true, cubeUniqueName);
//				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'dependencywheelParameterList', chartNum, cubeUniqueName);
				});
				break;
			case 'SEQUENCES_SUNBURST':
				var chartNum = _itemMeta.ComponentName.replace('sequencessunburstDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.SEQUENCES_SUNBURST_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'sequencessunburstValueList', chartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'sequencessunburstParameterList', chartNum, cubeUniqueName);
				});
				break;
			case 'LIQUID_FILL_GAUGE':
				var chartNum = _itemMeta.ComponentName.replace('liquidfillgaugeDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.LIQUID_FILL_GAUGE_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'liquidfillgaugeValueList', chartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'liquidfillgaugeParameterList', chartNum, cubeUniqueName);
				});
				break;
			case 'PYRAMID_CHART':
				var pyramidchartNum = _itemMeta.ComponentName.replace('pyramidchartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.PYRAMID_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'pyramidchartValueList', pyramidchartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'pyramidchartParameterList', pyramidchartNum, cubeUniqueName);
				});
				break;
			case 'FUNNEL_CHART':
				var FunnelChartNum = _itemMeta.ComponentName.replace('funnelchartDashboardItem', '');
				// retrieve measures

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
					/*dogfoot 트리맵 툴팁 오류 수정 shlim 20200715*/
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.FUNNEL_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'funnelchartValueList', FunnelChartNum, dataNumFormat, true, cubeUniqueName);
				});

				// retrieve arguments
				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'funnelchartParameterList', FunnelChartNum, cubeUniqueName);
				});
				break;
			case 'BUBBLE_D3':

				var bubbled3Num = _itemMeta.ComponentName.replace('bubbled3DashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
						if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
							var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.BUBBLE_D3_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
						else
							var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
						var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
						measureDataItemSetting(measure, index, 'bubbled3ValueList', bubbled3Num, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'bubbled3ParameterList', bubbled3Num, cubeUniqueName);
				});
				break;
			case 'PARALLEL_COORDINATE':

				var parallelNum = _itemMeta.ComponentName.replace('parallelDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.PARALLEL_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'parallelValueList', parallelNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'parallelParameterList', parallelNum, cubeUniqueName);
				});
				break;
			case 'BUBBLE_PACK_CHART':

				var bubblepackchartNum = _itemMeta.ComponentName.replace('bubblepackchartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.BUBBLE_PACK_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'bubblepackchartValueList', bubblepackchartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'bubblepackchartParameterList', bubblepackchartNum, cubeUniqueName);
				});
				break;
			case 'WORD_CLOUD_V2':

				var wordcloudv2Num = _itemMeta.ComponentName.replace('wordcloudv2DashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.WORD_CLOUD_V2_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'wordcloudv2ValueList', wordcloudv2Num, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'wordcloudv2ParameterList', wordcloudv2Num, cubeUniqueName);
				});
				break;
			case 'DENDROGRAM_BAR_CHART':

				var dendrogrambarchartNum = _itemMeta.ComponentName.replace('dendrogrambarchartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.DENDROGRAM_BAR_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'dendrogrambarchartValueList', dendrogrambarchartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'dendrogrambarchartParameterList', dendrogrambarchartNum, cubeUniqueName);
				});
				break;
			case 'CALENDAR_VIEW_CHART':

				var calendarviewchartNum = _itemMeta.ComponentName.replace('calendarviewchartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'calendarviewchartValueList', calendarviewchartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'calendarviewchartParameterList', calendarviewchartNum, cubeUniqueName);
				});
				break;
			case 'CALENDAR_VIEW2_CHART':

				var calendarview2chartNum = _itemMeta.ComponentName.replace('calendarview2chartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'calendarview2chartValueList', calendarview2chartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'calendarview2chartParameterList', calendarview2chartNum, cubeUniqueName);
				});
				break;
			case 'CALENDAR_VIEW3_CHART':

				var calendarview3chartNum = _itemMeta.ComponentName.replace('calendarview3chartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'calendarview3chartValueList', calendarview3chartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'calendarview3chartParameterList', calendarview3chartNum, cubeUniqueName);
				});
				break;
			case 'COLLAPSIBLE_TREE_CHART':

				var collapsibletreechartNum = _itemMeta.ComponentName.replace('collapsibletreechartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CALENDAR_VIEW_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'collapsibletreechartValueList', collapsibletreechartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'collapsibletreechartParameterList', collapsibletreechartNum, cubeUniqueName);
				});
				break;
			case 'RANGE_BAR_CHART':

				var rangebarchartNum = _itemMeta.ComponentName.replace('rangebarchartDashboardItem', '');
				var rangebarindex = 0;
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.RANGE_BAR_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);

					$.each(_item.meta.DataItems.Measure,function(_i, _measure){
							if(typeof _measure.DeltaItem == 'undefined' && _measure.UniqueName === measure.uniqueName){
								rangeBarFieldDeltaDataItemSetting(measure, rangebarindex, 'rangebarchartValueList', rangebarchartNum, dataNumFormat, false, cubeUniqueName);
								rangebarindex++;
							}
					});
//					measureDataItemSetting(measure, index, 'rangebarchartValueList', rangebarchartNum, dataNumFormat, false, cubeUniqueName);
				});

//				// retrieve hidden measures
//				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
//					if(_itemMeta.isAdhocItem){
//						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
//						hiddenDataItemSetting(hiddenmeasure, index, 'adhoc_hide_measure_list', rangebarchartNum, dataNumFormat);
//					}else{
//						hiddenDataItemSetting(hiddenmeasure, index, 'rangebarchart_hide_measure_list', rangebarchartNum, undefined, cubeUniqueName);
//					}
//				});
				// retrieve arguments
				$.each(_itemMeta.arguments, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);

					argumentDataItemSetting(argument, index, 'rangebarchartParameterList', rangebarchartNum, cubeUniqueName);

				});
//				// retrieve dimensions
//				$.each(_itemMeta.seriesDimensions, function(index, series) {
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
//					if(_itemMeta.isAdhocItem){
//					/* DOGFOOT ktkang 사용안하는 파라미터 제거  20200706 */
//						seriesDimensionDataItemSetting(series, index, 'colAdHocList', rangebarchartNum, cubeUniqueName);
//					}else{
//						seriesDimensionDataItemSetting(series, index, 'rangebarchartSeriesList', rangebarchartNum, cubeUniqueName);
//					}
//				});
				break;
			case 'RANGE_AREA_CHART':

				var rangeareachartNum = _itemMeta.ComponentName.replace('rangeareachartDashboardItem', '');
				var rangeareaindex = 0;
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.RANGE_AREA_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					$.each(_item.meta.DataItems.Measure,function(_i, _measure){
							if(typeof _measure.DeltaItem == 'undefined' && _measure.UniqueName === measure.uniqueName){
								rangeBarFieldDeltaDataItemSetting(measure, index, 'rangeareachartValueList', rangeareachartNum, dataNumFormat, false, cubeUniqueName);
								rangeareaindex++;
							}
					});
					//measureDataItemSetting(measure, index, 'rangeareachartValueList', rangeareachartNum, dataNumFormat, false, cubeUniqueName);

				});

//				// retrieve hidden measures
//				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
//					if(_itemMeta.isAdhocItem){
//						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
//						hiddenDataItemSetting(hiddenmeasure, index, 'adhoc_hide_measure_list', rangeareachartNum, dataNumFormat);
//					}else{
//						hiddenDataItemSetting(hiddenmeasure, index, 'rangeareachart_hide_measure_list', rangeareachartNum, undefined, cubeUniqueName);
//					}
//				});
				// retrieve arguments
				$.each(_itemMeta.arguments, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);

					argumentDataItemSetting(argument, index, 'rangeareachartParameterList', rangeareachartNum, cubeUniqueName);

				});
//				// retrieve dimensions
//				$.each(_itemMeta.seriesDimensions, function(index, series) {
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
//					if(_itemMeta.isAdhocItem){
//					/* DOGFOOT ktkang 사용안하는 파라미터 제거  20200706 */
//						seriesDimensionDataItemSetting(series, index, 'colAdHocList', rangeareachartNum, cubeUniqueName);
//					}else{
//						seriesDimensionDataItemSetting(series, index, 'rangeareachartSeriesList', rangeareachartNum, cubeUniqueName);
//					}
//				});
				break;
			case 'TIME_LINE_CHART':

				var timelinechartNum = _itemMeta.ComponentName.replace('timelinechartDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.TIME_LINE_CHART_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);

					measureDataItemSetting(measure, index, 'timelinechartValueList', timelinechartNum, dataNumFormat, false, cubeUniqueName);

				});

//				// retrieve hidden measures
//				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
//					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
//					if(_itemMeta.isAdhocItem){
//						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.CHART_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
//						hiddenDataItemSetting(hiddenmeasure, index, 'adhoc_hide_measure_list', timelinechartNum, dataNumFormat);
//					}else{
//						hiddenDataItemSetting(hiddenmeasure, index, 'timelinechart_hide_measure_list', timelinechartNum, undefined, cubeUniqueName);
//					}
//				});
				// retrieve arguments
				$.each(_itemMeta.arguments, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);

					argumentDataItemSetting(argument, index, 'timelinechartParameterList', timelinechartNum, cubeUniqueName);

				});
//				// retrieve dimensions
				$.each(_itemMeta.seriesDimensions, function(index, series) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
					if(_itemMeta.isAdhocItem){
					/* DOGFOOT ktkang 사용안하는 파라미터 제거  20200706 */
						seriesDimensionDataItemSetting(series, index, 'colAdHocList', timelinechartNum, cubeUniqueName);
					}else{
						seriesDimensionDataItemSetting(series, index, 'timelinechartSeriesList', timelinechartNum, cubeUniqueName);
					}
				});

				$.each(_itemMeta.startDateDimensions, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);

					argumentDataItemSetting(argument, index, 'timelinechartStartDateList', timelinechartNum, cubeUniqueName);

				});

				$.each(_itemMeta.endDateDimensions, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);

					argumentDataItemSetting(argument, index, 'timelinechartEndDateList', timelinechartNum, cubeUniqueName);

				});
				break;
			case 'STAR_CHART':
				var starchartNum = _itemMeta.ComponentName.replace('starchartDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.STAR_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'starchartValueList', starchartNum, dataNumFormat, true, cubeUniqueName);
				});

				// retrieve arguments
				$.each(_itemMeta.arguments, function(index, argument) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, argument.uniqueName);
					argumentDataItemSettingNoTopN(argument, index, 'starchartParameterList', starchartNum, cubeUniqueName);
				});
				// retrieve dimensions
				$.each(_itemMeta.seriesDimensions, function(index, series) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, series.uniqueName);
					seriesDimensionDataItemSetting(series, index, 'starchartSeriesList', starchartNum, cubeUniqueName);
				});
				break;
			case 'HEATMAP':

				var heatmapNum = _itemMeta.ComponentName.replace('heatmapDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.HEATMAP_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'heatmapValueList', heatmapNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'heatmapParameterList', heatmapNum, cubeUniqueName);
				});

				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.HEATMAP_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'heatmap_hide_measure_list', pieNum, dataNumFormat, cubeUniqueName);
				});
				break;

			case 'HEATMAP2':
				var heatmapNum = _itemMeta.ComponentName.replace('heatmap2DashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.HEATMAP2_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'heatmap2ValueList', heatmapNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'heatmap2ParameterList', heatmapNum, cubeUniqueName);
				});

				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.HEATMAP2_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'heatmap2_hide_measure_list', pieNum, dataNumFormat, cubeUniqueName);
				});
				break;
			case 'SYNCHRONIZED_CHARTS':
				var syncchartNum = _itemMeta.ComponentName.replace('syncchartDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.SYNCHRONIZED_CHARTS_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'syncchartValueList', syncchartNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'syncchartParameterList', syncchartNum, cubeUniqueName);
				});

				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.SYNCHRONIZED_CHARTS_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'syncchart_hide_measure_list', pieNum, dataNumFormat, cubeUniqueName);
				});
				break;
			case 'WORD_CLOUD':

				var wordcloudNum = _itemMeta.ComponentName.replace('WordCloudDashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.WORD_CLOUD_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'wordcloudValueList', wordcloudNum, dataNumFormat, true, cubeUniqueName);
				});

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'wordcloudParameterList', wordcloudNum, cubeUniqueName);
				});
				break;
			case 'LISTBOX':
				var listBoxNum = _itemMeta.ComponentName.replace('listBoxDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.LISTBOX_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'listbox_hide_measure_list', listBoxNum, dataNumFormat, cubeUniqueName);
				});
				// retrieve arguments
				$.each(_itemMeta.filterDimensions, function(index, filterDimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, filterDimension.uniqueName);
					argumentDataItemSettingNoTopN(filterDimension, index, 'dimList', listBoxNum, cubeUniqueName);
				});
				break;
			case 'TREEVIEW':
				var treeViewNum = _itemMeta.ComponentName.replace('treeViewDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.TREEVIEW_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'treeview_hide_measure_list', treeViewNum, dataNumFormat, cubeUniqueName);
				});
				// retrieve arguments
				$.each(_itemMeta.filterDimensions, function(index, filterDimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, filterDimension.uniqueName);
					argumentDataItemSettingNoTopN(filterDimension, index, 'tv_dimList', treeViewNum, cubeUniqueName);
				});
				break;
			case 'COMBOBOX':
				var comboBoxNum = _itemMeta.ComponentName.replace('comboBoxDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.COMBOBOX_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'combobox_hide_measure_list', comboBoxNum, dataNumFormat, cubeUniqueName);
				});
				// retrieve arguments
				$.each(_itemMeta.filterDimensions, function(index, filterDimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, filterDimension.uniqueName);
					argumentDataItemSettingNoTopN(filterDimension, index, 'cb_dimList', comboBoxNum, cubeUniqueName);
				});
				break;
			case 'TEXTBOX': // ymbin
//				var treeView = $('#allList').dxTreeView('instance');
				var textboxNum = _itemMeta.ComponentName.replace('textBoxDashboardItem', '');
				// retrieve measures
				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.TEXTBOX_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'textboxValueList', textboxNum, dataNumFormat, true, cubeUniqueName);
				});
				$.each(_itemMeta.HiddenMeasures, function(index, hiddenmeasure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.TEXTBOX_DATA_ELEMENT, hiddenmeasure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, hiddenmeasure.uniqueName);
					hiddenDataItemSetting(hiddenmeasure, index, 'textbox_hide_measure_list', textboxNum, dataNumFormat, cubeUniqueName);
				});
				/* DOGFOOT ktkang 대시보드 주제영역 기능 추가 밑으로 cubeUniqueName 부분 끝  20200618 */
				break;
			case 'HIERARCHICAL_EDGE':

				var hierarchicalNum = _itemMeta.ComponentName.replace('hierarchicalDashboardItem', '');

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'hierarchicalParameterList', hierarchicalNum, cubeUniqueName);
				});
				break;
			case 'FORCEDIRECT':

				var forceDirectNum = _itemMeta.ComponentName.replace('forceDirectDashboardItem', '');

				/*
				$.each(_itemMeta.measures, function(index, measure) {
						if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
							var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.FORCEDIRECT_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
						else
							var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
						var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
						measureDataItemSetting(measure, index, 'forceDirectValueList', forceDirectNum, dataNumFormat, true, cubeUniqueName);
				});
				*/

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'forceDirectParameterList', forceDirectNum, cubeUniqueName);
				});
				break;
			case 'FORCEDIRECTEXPAND':

				var forceDirectExpandNum = _itemMeta.ComponentName.replace('forceDirectExpandDashboardItem', '');

				/*
				$.each(_itemMeta.measures, function(index, measure) {
						if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
							var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.FORCEDIRECTEXPAND_DATA_ELEMENT, measure.uniqueName, 'MEASURES');
						else
							var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
						var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
						measureDataItemSetting(measure, index, 'forceDirectExpandValueList', forceDirectExpandNum, dataNumFormat, true, cubeUniqueName);
				});
				*/

				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'forceDirectExpandParameterList', forceDirectExpandNum, cubeUniqueName);
				});
				break;
			/* DOGFOOT syjin 카카오 지도 추가  20200820 */
			case 'KAKAO_MAP':
				var kakaoMapNum = _itemMeta.ComponentName.replace('kakaoMapDashboardItem', '');
				//2020.09.18 syjin 카카오맵 불러오기 수정 dogfoot
				$.each(_itemMeta.latitudes, function(index, latitude) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, latitude.uniqueName);
					argumentDataItemSettingNoTopN(latitude, index, 'kakaoMapLatitudeList', kakaoMapNum, cubeUniqueName);
				});

				$.each(_itemMeta.longitudes, function(index, longitude) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, longitude.uniqueName);
					argumentDataItemSettingNoTopN(longitude, index, 'kakaoMapLongitudeList', kakaoMapNum, cubeUniqueName);
				});

				//2020.09.22 mksong dogfoot 카카오지도 주소필드 추가
				$.each(_itemMeta.addresses, function(index, address) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, address.uniqueName);
					addressFieldDataItemSettingNoTopN(address, index, 'kakaoMapAddressList', kakaoMapNum, cubeUniqueName);
				});

				$.each(_itemMeta.markerDimensions, function(index, markerDimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, markerDimension.uniqueName);
					argumentDataItemSettingNoTopN(markerDimension, index, 'kakaoMapParameterList', kakaoMapNum, cubeUniqueName);
				});

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'kakaoMapValueList', kakaoMapNum, dataNumFormat, true, cubeUniqueName);
				});

				//2020.09.18 syjin 카카오맵 불러오기 수정 dogfoot
				// retrieve arguments
				/*$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'kakaoMapParameterList', kakaoMapNum, cubeUniqueName);
				});*/
				break;
			case 'KAKAO_MAP2':
				var kakaoMapNum = _itemMeta.ComponentName.replace('kakaoMap2DashboardItem', '');

				$.each(_itemMeta.measures, function(index, measure) {
					if(typeof gDashboard.structure.MapOption.DASHBOARD_XML.WEB !== 'undefined')
						var dataNumFormat = dataNumFormatSetting(_itemMeta.meta.DataItems.Measure, gDashboard.structure.MapOption.DASHBOARD_XML.WEB.KAKAO_MAP2_ELEMENT, measure.uniqueName, 'MEASURES');
					else
						var dataNumFormat = dataNumFormatSettingNoSuffix(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Measure, measure.uniqueName);
					measureDataItemSetting(measure, index, 'kakaoMap2ValueList', kakaoMapNum, dataNumFormat, true, cubeUniqueName);
				});

				// retrieve arguments
				$.each(_itemMeta.dimensions, function(index, dimension) {
					var cubeUniqueName = dataCubeUniqueName(_itemMeta.meta.DataItems.Dimension, dimension.uniqueName);
					argumentDataItemSettingNoTopN(dimension, index, 'kakaoMap2ParameterList', kakaoMapNum, cubeUniqueName);
				});
				break;
			}

			$('.other-menu-ico').draggable(gDashboard.dragNdropController.draggableOptions2);
		}

	/**
	 * Add chart data item attributes to its associated element.
	 * @param {WISE.libs.Dashboard.item.ChartGenerator} chart
	 * @param {string} dataItemNo
	 * @param {jQuery} dataItemOptions
	 */
	this.addChartDataItemOptions = function(chart, dataItemNo, dataItemOptions) {
		var isNewDataItem = true;
		var options = {};
		// if data item has been initialized, load its previous options
		$.each(chart.P, function(pIndex, pane) {
			if (pane.Series.Simple) {
				$.each(WISE.util.Object.toArray(pane.Series.Simple), function(vIndex, value) {
					if (value.Value.UniqueName === dataItemNo) {
						// get CHART_XML measure data
						var chartDataElement = {};
						if (gDashboard.structure.MapOption.DASHBOARD_XML) {
							$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.CHART_DATA_ELEMENT), function(cIndex, chartData) {
								if (chartData.PANE_ELEMENT && chart.ComponentName === chartData.CTRL_NM) {
									$.each(WISE.util.Object.toArray(chartData.PANE_ELEMENT.SERIES_ELEMENT), function(sIndex, series) {
										if (series.UNI_NM === dataItemNo) {
											chartDataElement = series;
											return false;
										}
									});
									return false;
								}
							});
						}
						// set point options
						options = {
							seriesType: value.SeriesType ? value.SeriesType : 'Bar',
							plotOnSecondaryAxis: value.PlotOnSecondaryAxis ? true : false,
							ignoreEmptyPoints: value.IgnoreEmptyPoints ? true : false,
							showPointMarkers: value.ShowPointMarkers ? true : false,
							//2020.12.24 mksong 차트 y축 역순으로 보기 dogfoot
							inverted: chartDataElement.INVERTED == 'Y' ? true : false
						}
						var pointLabelOptions = {};
						if (!(value.PointLabelOptions)) {
							value.PointLabelOptions = {
								orientation: '',
								contentType: 'Value',
								overlappingMode: 'Reposition',
								showForZeroValues: false,
								position: 'Outside',
								fillBackground: false,
								showBorder: false,
								showCustomTextColor: false,
								customTextColor: '#000000'
							};
						}
						pointLabelOptions = {
							orientation: value.PointLabelOptions.Orientation ? value.PointLabelOptions.Orientation : '',
							contentType: typeof value.PointLabelOptions.ContentType !== 'undefined' ? value.PointLabelOptions.ContentType : 'Value',
							overlappingMode: value.PointLabelOptions.OverlappingMode ? value.PointLabelOptions.OverlappingMode : 'Hide',
							showForZeroValues: value.PointLabelOptions.ShowForZeroValues ? true : false,
							position: value.PointLabelOptions.Position ? value.PointLabelOptions.Position : 'Outside',
							fillBackground: value.PointLabelOptions.FillBackground ? value.PointLabelOptions.FillBackground : false,
							showBorder: value.PointLabelOptions.ShowBorder ? value.PointLabelOptions.ShowBorder : false,
							showCustomTextColor: value.PointLabelOptions.ShowCustomTextColor ? value.PointLabelOptions.ShowCustomTextColor : false,
							customTextColor: chartDataElement.SERIES_FONT_COLOR ? gDashboard.itemColorManager.getHexColor(chartDataElement.SERIES_FONT_COLOR) : '#000000'
						}
						options.pointLabelOptions = pointLabelOptions;

						isNewDataItem = false;
						return false;
					}
				});
			}
			if (pane.Series.Weighted) {
				$.each(WISE.util.Object.toArray(pane.Series.Weighted), function(vIndex, value) {
					if (value.Value.UniqueName === dataItemNo) {
						// get CHART_XML measure data
						var chartDataElement = {};
						if (gDashboard.structure.MapOption.DASHBOARD_XML) {
							$.each(WISE.util.Object.toArray(gDashboard.structure.MapOption.DASHBOARD_XML.CHART_DATA_ELEMENT), function(cIndex, chartData) {
								if (chartData.PANE_ELEMENT && chart.ComponentName === chartData.CTRL_NM) {
									$.each(WISE.util.Object.toArray(chartData.PANE_ELEMENT.SERIES_ELEMENT), function(sIndex, series) {
										if (series.UNI_NM === dataItemNo) {
											chartDataElement = series;
											return false;
										}
									});
									return false;
								}
							});
						}
						options = {
							seriesType: value.SeriesType ? value.SeriesType : 'Bubble',
							plotOnSecondaryAxis: value.PlotOnSecondaryAxis ? true : false,
							ignoreEmptyPoints: value.IgnoreEmptyPoints ? true : false,
							showPointMarkers: value.ShowPointMarkers ? true : false,
							//2020.12.24 mksong 차트 y축 역순으로 보기 dogfoot
							inverted: chartDataElement.INVERTED == 'Y' ? true : false
						}
						var pointLabelOptions = {};
						if (!(value.PointLabelOptions)) {
							value.PointLabelOptions = {
								orientation: '',
								contentType: 'Value',
								overlappingMode: 'Reposition',
								showForZeroValues: false,
								position: 'Outside',
								fillBackground: false,
								showBorder: false,
								showCustomTextColor: false,
								customTextColor: '#ffffff'
							};
						}
						pointLabelOptions = {
							orientation: value.PointLabelOptions.Orientation ? value.PointLabelOptions.Orientation : '',
							contentType: typeof value.PointLabelOptions.ContentType !== 'undefined' ? value.PointLabelOptions.ContentType : 'Value',
							overlappingMode: value.PointLabelOptions.OverlappingMode ? value.PointLabelOptions.OverlappingMode : 'Hide',
							showForZeroValues: value.PointLabelOptions.ShowForZeroValues ? true : false,
							position: value.PointLabelOptions.Position ? value.PointLabelOptions.Position : 'Outside',
							fillBackground: chartDataElement.SERIES_BACK_COLOR_VISIBLE === 'Y' ? true : false,
							showBorder: chartDataElement.SERIES_BORDER_VISIBLE === 'Y' ? true : false,
							showCustomTextColor: chartDataElement.SERIES_FONT_COLOR_YN === 'Y',
							customTextColor: chartDataElement.SERIES_FONT_COLOR ? gDashboard.itemColorManager.getHexColor(chartDataElement.SERIES_FONT_COLOR) : '#000000'
						}
						options.pointLabelOptions = pointLabelOptions;

						isNewDataItem = false;
						return false;
					}
				});
			}
		});
		// if data item is new, set default options
		if (isNewDataItem) {
			var newItemSeriesType = chart.fieldManager.seriesType ? chart.fieldManager.seriesType : 'Bar';
			options = {
				seriesType: newItemSeriesType,
				plotOnSecondaryAxis: false,
				ignoreEmptyPoints: false,
				showPointMarkers: true,
				pointLabelOptions: {
					orientation: '',
					contentType: 'Value',
					overlappingMode: 'Reposition',
					showForZeroValues: false,
					position: 'Outside',
					fillBackground: false,
					showBorder: false,
					showCustomTextColor: false,
					customTextColor: '#000000'
				}
			};
		}
		// add options to element
		dataItemOptions.children()[0].src = WISE.Constants.context + '/resources/main/images/ico_' + self.getImgForSeriesType2(options.seriesType) + '.png';
		dataItemOptions.data('dataItemOptions', options);
	}

	/**
	 * Add adhoc chart data item attributes to its associated element.
	 * @param {number} dataItemNo
	 * @param {jQuery} dataItemOptions
	 */
	this.addAdhocChartDataItemOptions = function(dataItemNo, dataItemOptions) {
		var options = {};
		/* goyong ktkang 차트 시리즈 옵션 오류 수정  20210521 */
		var	chartXml2;
		var chartDataItemLength = 0;
		if(typeof gDashboard.structure.ReportMasterInfo.chartJson !== 'undefined') {
			chartXml2 = gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML;
			if(typeof chartXml2.WEB != 'undefined') {
				chartDataItemLength = chartXml2.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.length;
			}
		}
		
		if (typeof gDashboard.structure.ReportMasterInfo.chartJson === 'undefined' || chartDataItemLength < dataItemNo) {
			/* DOGFOOT ktkang 비정형 주제영역 오류 수정  20200922 */
			var newItemSeriesType = (typeof chart !== 'undefined' && typeof chart.fieldManager != 'undefined' && chart.fieldManager.seriesType) ? chart.fieldManager.seriesType : 'Bar';
			options = {
				seriesType: newItemSeriesType,
				plotOnSecondaryAxis: false,
				ignoreEmptyPoints: false,
				showPointMarkers: true,
				pointLabelOptions: {
					orientation: '',
					contentType: 'Value',
					overlappingMode: 'Reposition',
					showForZeroValues: false,
					position: 'Outside',
					fillBackground: false,
					showBorder: false,
					showCustomTextColor: false,
					customTextColor: '#000000'
				}
			};
		} else {
			var CU = WISE.libs.Dashboard.item.ChartUtility,
				chartXml = gDashboard.structure.ReportMasterInfo.chartJson.CHART_XML,
				chartType = 'Bar',
				chartTypeNum = chartXml['SERIES' + (dataItemNo + 1).toString() + '_CHART_TYPE'],
				y2Enabled = chartXml['SERIES' + (dataItemNo + 1).toString() + '_AXISY2'],
				showZero = false,
				customTextColor = '#000000';
			
			if (typeof chartTypeNum === 'number') {
				chartType = CU.Series.Simple.getChartName(chartTypeNum);
			}
			if (chartXml.EMPTY_POINT_STYLE !== 'Empty') {
				showZero = true;
			}

			if(chartXml.WEB != undefined) {
				if(chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.length != undefined){
					if(dataItemNo < chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.length) {
						if(typeof chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].SERIES_FONT_COLOR !== 'undefined') {
							customTextColor = gDashboard.itemColorManager.getHexColor(chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].SERIES_FONT_COLOR);
						}
						options = {
								seriesType: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].SERIES_TYPE,
								plotOnSecondaryAxis: y2Enabled,
								ignoreEmptyPoints: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].IGNORE_EMPTY_POINTS,
								showPointMarkers: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].SHOW_POINT_MARKER,
								pointLabelOptions: {
									orientation: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].ORIENTATION,
									contentType: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].CONTENT_TYPE,
									overlappingMode: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].OVERLAPPING_MODE,
									showForZeroValues: showZero,
									position: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].POSITION,
									fillBackground: (chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].SERIES_BACK_COLOR_VISIBLE=='Y')?true:false,
									showBorder: (chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].SERIES_BORDER_VISIBLE=='Y')?true:false,
									showCustomTextColor: (chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT[dataItemNo].SERIES_FONT_COLOR_YN =='Y')?true:false,
									customTextColor: customTextColor
								}
							};
					}
				}else{
//					if(dataItemNo < chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.length) {
						if(typeof chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.SERIES_FONT_COLOR !== 'undefined') {
							customTextColor = gDashboard.itemColorManager.getHexColor(chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.SERIES_FONT_COLOR);
						}
						options = {
								seriesType: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.SERIES_TYPE,
								plotOnSecondaryAxis: y2Enabled,
								ignoreEmptyPoints: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.IGNORE_EMPTY_POINTS,
								showPointMarkers: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.SHOW_POINT_MARKER,
								pointLabelOptions: {
									orientation: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.ORIENTATION,
									contentType: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.CONTENT_TYPE,
									overlappingMode: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.OVERLAPPING_MODE,
									showForZeroValues: showZero,
									position: chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.POSITION,
									fillBackground: (chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.SERIES_BACK_COLOR_VISIBLE=='Y')?true:false,
									showBorder: (chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.SERIES_BORDER_VISIBLE=='Y')?true:false,
									showCustomTextColor: (chartXml.WEB.CHART_DATA_ELEMENT.PANE_ELEMENT.SERIESE_ELEMENT.SERIES_FONT_COLOR_YN == 'Y')?true:false,
									customTextColor: customTextColor
								}
							};
//					}
				}
			}
		}
		// add options to element
		dataItemOptions.children()[0].src = WISE.Constants.context + '/resources/main/images/ico_' + self.getImgForSeriesType2(options.seriesType) + '.png';
		dataItemOptions.data('dataItemOptions', options);
	}

	this.getCaptionName = function(_fldNm){
		var dataCaption = _fldNm;
		var GRID_ELEMENT = gDashboard.structure.ReportMasterInfo.reportJson.GRID_ELEMENT.GRID;
		$.each(GRID_ELEMENT, function(_i, _d){

			if(WISE.Context.isCubeReport){
				if(_d.FLD_NM == _fldNm){
					dataCaption = _d.CAPTION;
				}
			}else{
				if(_d.UNI_NM == _fldNm){
					dataCaption = _d.CAPTION;
				}
			}
		});

		return dataCaption;
	}

	this.loadAdhocItemData = function(_itemMeta){
		var rows = gDashboard.structure.ReportMasterInfo.reportJson.ROW_ELEMENT.ROW;
		var cols = gDashboard.structure.ReportMasterInfo.reportJson.COL_ELEMENT.COL;
		var datas = gDashboard.structure.ReportMasterInfo.reportJson.DATA_ELEMENT.DATA;
		//2020.04.09 mksong 비정형 사용자정의데이터 불러오기 오류 수정 dogfoot
		var colulatedDatas = gDashboard.structure.ReportMasterInfo.reportJson.CALCDATA_ELEMENT.CALC_DATA;
		var sorts = WISE.util.Object.toArray(gDashboard.structure.ReportMasterInfo.reportJson.DATASORT_ELEMENT.DATA_SORT);

		var allFieldList =  WISE.util.Object.toArray(datas);
		if(cols != undefined){
			allFieldList = allFieldList.concat(WISE.util.Object.toArray(cols));
		}
		if(rows != undefined){
			allFieldList = allFieldList.concat(WISE.util.Object.toArray(rows));
		}

		var hiddenFields = [];
		/* DOGFOOT hsshim 2020-01-15 주제영역 뷰어 불러오기 오류 수정 */
		gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id', _itemMeta.dataSourceId);

		var itemNum = _itemMeta.adhocIndex;
		if(WISE.Constants.editmode === 'viewer'){
			var tempIdx = _itemMeta.index.split('_');
			itemNum = itemNum + '_' + tempIdx[1];
		}
		// retrieve data fields
		_itemMeta.dataFields = [];
		_itemMeta.rows = [];
		_itemMeta.columns = [];

		if(datas != undefined){
			datas = WISE.util.Object.toArray(datas);
			if(datas.length == undefined){
				_itemMeta.dataFields.push(datas);
//				var dataFieldType = datas['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
				var dataFieldType = 'measure';
				var dataCaption = self.getCaptionName(datas['FLD_NM']);
				var dataUninm = datas['UNI_NM'];
				var dataItemNo = gDashboard.fieldManager.dataItemNo;
				var summaryType = WISE.libs.Dashboard.item.DataUtility.AdHoc.getSummaryType(datas.SUMMARY_TYPE);

				var element = $('<ul class="display-unmove analysis-data" />');
				element.appendTo($('#dataAdHocList' + itemNum));
				$('#dataAdHocList' + itemNum).children('.unsortable').remove();

				//2020.04.09 mksong 비정형 사용자정의데이터 불러오기 오류 수정 dogfoot
				var isCustomField = false;
				$.each(WISE.util.Object.toArray(colulatedDatas), function(_k, _colulatedData){
					if(_colulatedData.FLD_NM == dataUninm){
						isCustomField = true;
					}
				});

				var dataItem;
				if(isCustomField){
					dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" prev-container="'
						/* DOGFOOT ktkang 대소문자 구분 수정 ~ 앞으로 나오는 cubeuninm은 전부 다 20200305 */
							+ 'dataAdHocList' + itemNum + '" isCustomField="' + isCustomField + '" cubeuninm="' + dataUninm + '" uni_nm="'+datas['FLD_NM']+'" dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
							// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
							+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);">'
							+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
				}else{
					dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" prev-container="'
						/* DOGFOOT ktkang 대소문자 구분 수정 ~ 앞으로 나오는 cubeuninm은 전부 다 20200305 */
							+ 'dataAdHocList' + itemNum+'" cubeuninm="' + dataUninm + '" uni_nm="'+datas['FLD_NM']+'" dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
							// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
							+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);">'
							+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
				}

				element.append(dataItem);
				element.append(self.measureFieldOptionMenu);
				// set summary class
				element.find('.summaryType').parent().removeClass('on');
				element.find('.summaryType[summarytype="' + summaryType + '"]').parent().addClass('on');
				self.addFormat(dataItem);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				compMoreMenuUi();
				if (typeof self.itemFormat !== undefined) {
					dataItem.data('formatOptions', self.itemFormat);
				}

				var dataItemId = 'dataAdHocList'  + itemNum + '_' + dataItemNo;
				/*dogfoot 크롬 다운로드시 데이터항목 아이콘 레이아웃 깨지는 오류 수정 shlim 20200717*/
				$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_bar1.png" alt></a>').insertAfter(element.find('a.btn'));
				var dataItemOptions = element.find('#' + dataItemId);
				if (typeof self.itemData !== 'undefined') {
					dataItemOptions.data('dataItemOptions', self.itemData);
				} else {
					self.addAdhocChartDataItemOptions(dataItemNo, dataItemOptions);
				}
				dataItemOptions.on('click',function(e){
					self.dataItemOptionsWindow(this);
					e.preventDefault();
				});

				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//				$('<a href="#" class="otherBtn sigma"></a>').insertAfter(element);
				gDashboard.fieldManager.dataItemNo++;
			}else{
				$.each(datas, function(_i, _d){
					if(_d.HIDDEN){
						_d.dataType = 'measure';
						hiddenFields.push(_d);
					}
				});

				$.each(WISE.util.Object.toArray(datas), function(index, dataField) {
					/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */
					if(dataField.HIDDEN || dataField['FLD_NM'].indexOf('DELTA_FIELD') != -1 || dataField['UNI_NM'].indexOf('DELTA_FIELD') != -1 ){
						return false;
					}
//					var element = treeView.element().find('.dx-treeview-node[aria-label="' + dataField['name'] + '"]').clone();
//					var dataFieldType = dataField['dataType'] == 'string' ? 'dimension' : 'measure';
//					var dataFieldType = dataField['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
					var dataFieldType = 'measure';
					var dataCaption = self.getCaptionName(dataField['FLD_NM']);
					var dataUninm = dataField['UNI_NM'];
					var dataItemNo = gDashboard.fieldManager.dataItemNo;
					var summaryType = WISE.libs.Dashboard.item.DataUtility.AdHoc.getSummaryType(dataField.SUMMARY_TYPE);

					var element = $('<ul class="display-unmove analysis-data" />');
					if(index == 0){
						element.appendTo($('#dataAdHocList' + itemNum));
						$('#dataAdHocList' + itemNum).children('.unsortable').remove();
					}else{
						element.insertAfter($('#dataAdHocList' + itemNum).children().get(index-1));
					}

					var isCustomField = false;
					$.each(WISE.util.Object.toArray(colulatedDatas), function(_k, _colulatedData){
						if(_colulatedData.FLD_NM == dataUninm){
							isCustomField = true;
						}
					});

					var dataItem;
					if(isCustomField){
						dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" prev-container="'
							/* DOGFOOT ktkang 대소문자 구분 수정 ~ 앞으로 나오는 cubeuninm은 전부 다 20200305 */
								+ 'dataAdHocList' + itemNum + '" isCustomField="' + isCustomField + '" cubeuninm="' + dataUninm + '" uni_nm="'+dataField['FLD_NM']+'" dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
								// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
								+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);">'
								+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
					}else{
						dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" prev-container="'
							/* DOGFOOT ktkang 대소문자 구분 수정 ~ 앞으로 나오는 cubeuninm은 전부 다 20200305 */
								+ 'dataAdHocList' + itemNum+'" cubeuninm="' + dataUninm + '" uni_nm="'+dataField['FLD_NM']+'" dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
								// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
								+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);">'
								+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
					}
					//2020.04.09 mksong 비정형 사용자정의데이터 불러오기 오류 수정 끝 dogfoot
					element.append(dataItem);
					element.append(self.measureFieldOptionMenu);
					// set summary class
					element.find('.summaryType').parent().removeClass('on');
					element.find('.summaryType[summarytype="' + summaryType + '"]').parent().addClass('on');
//					self.addFormat(dataItem);
					self.addFormat(dataItem,dataField);
					self.fieldRename(dataItem);
					 //2020-01-14 LSH topN
					self.topNset(dataItem);
					compMoreMenuUi();

					var dataItemId = 'dataAdHocList' + itemNum + '_' + dataItemNo;
					/*dogfoot 크롬 다운로드시 데이터항목 아이콘 레이아웃 깨지는 오류 수정 shlim 20200717*/
					$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_bar1.png" alt></a>').insertAfter(element.find('a.btn'));
					var dataItemOptions = element.find('#' + dataItemId);
					if (typeof self.itemData !== 'undefined') {
						dataItemOptions.data('dataItemOptions', self.itemData);
					} else {
						self.addAdhocChartDataItemOptions(dataItemNo, dataItemOptions);
					}
					dataItemOptions.on('click',function(e){
						self.dataItemOptionsWindow(this);
						e.preventDefault();
					});

					dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//					$('<a href="#" class="otherBtn sigma"></a>').insertAfter(element);
					dataField.dataItem = 'DataItem'+gDashboard.fieldManager.dataItemNo;
					_itemMeta.dataFields.push(dataField);
					gDashboard.fieldManager.dataItemNo++;
				});
			}
		}

		if(rows != undefined){
			/* goyong ktkang 정렬기준항목이 행이나 열로 가는 오류 수정  20210521 */
			if(typeof rows.length != 'undefined'){
				$.each(rows, function(_i, _row){
					if(_row.HIDDEN){
						_row.dataType = 'dimension';
						hiddenFields.push(_row);
					}
				});
			} else {
				if(rows.HIDDEN){
					rows.dataType = 'dimension';
					hiddenFields.push(rows);
					rows = [];
				}
			}
		}

		if(cols != undefined){
			/* goyong ktkang 정렬기준항목이 행이나 열로 가는 오류 수정  20210521 */
			if(typeof cols.length != 'undefined'){
				$.each(cols, function(_i, _column){
					if(_column.HIDDEN){
						_column.dataType = 'dimension';
						hiddenFields.push(_column);
					}
				});
			} else {
				if(cols.HIDDEN){
					cols.dataType = 'dimension';
					hiddenFields.push(cols);
					cols = [];
				}
			}
		}

		if(hiddenFields.length > 0){
			$.each(hiddenFields, function(index, hiddenField) {
				var dataFieldType = hiddenField.dataType;
				var dataCaption = self.getCaptionName(hiddenField['FLD_NM']);
				var dataUninm = hiddenField['UNI_NM'];
				var dataItemNo = gDashboard.fieldManager.dataItemNo;
				var summaryType;
				if(dataFieldType == 'measure'){
					summaryType = WISE.libs.Dashboard.item.DataUtility.AdHoc.getSummaryType(hiddenField.SUMMARY_TYPE);
				}
				var element = $('<ul class="display-unmove analysis-data" />');

				if(index == 0){
					element.appendTo($('#adhoc_hide_measure_list' + itemNum));
					$('#adhoc_hide_measure_list' + itemNum).children('.unsortable').remove();
				}else{
					element.insertAfter($('#adhoc_hide_measure_list' + itemNum).children().get(index-1));
				}

				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" '+
						'prev-container="'+'adhoc_hide_measure_list' + itemNum+'" '+
						'data-source-id="' + _itemMeta.dataSourceId + '" '+
						'cubeuninm="' + dataUninm + '" ' +
						'uni_nm="'+hiddenField['FLD_NM']+'" ' +
						'dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo  +'" '+
						'caption = "'+dataCaption+'" '+
						// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
						'title="' + dataCaption +'" '+
						'style="height: 31px; width: 100%;"><a href="#" class="ico sigma btn neutral">' +
						'<div class="fieldName">' + dataCaption + "</div>"
						+ '</a></li>');
				element.append(dataItem);
				/*컬럼 값 메뉴*/
				if(dataFieldType == 'measure'){
					element.append(self.hiddenMeasureFieldOptionMenu);
					element.find('.summaryType').parent().removeClass('on');
					element.find('.summaryType[summarytype="' + summaryType + '"]').parent().addClass('on');
					self.addFormat(dataItem);
				}
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				self.setFormatOptionModalForOpen(dataItem);
				compMoreMenuUi();

				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
				hiddenField.dataItem = 'DataItem'+gDashboard.fieldManager.dataItemNo;
				_itemMeta.HiddenMeasures.push(hiddenField);
				gDashboard.fieldManager.dataItemNo++;
			});
		}

		var datalist = _itemMeta.dataFields.concat(_itemMeta.HiddenMeasures);

		// retrieve rows
		if(rows != undefined){
			if(rows.length == undefined){
				_itemMeta.rows.push(rows);
//				var dataFieldType = rows['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
				var dataFieldType = 'dimension';
				var dataCaption = self.getCaptionName(rows['FLD_NM']);
				var dataUninm = rows['UNI_NM'];
				var dataItemNo = gDashboard.fieldManager.dataItemNo++;

				$.each(sorts, function(_i,_sort){
					if(_sort.SORT_FLD_NM == rows.FLD_NM || _sort.SORT_FIELD_NM == rows.FLD_NM){
						$.each(allFieldList, function(_k,_field){
							if(_field.FLD_NM == _sort.BASE_FLD_NM || _field.FLD_NM == _sort.BASE_FIELD_NM){
								rows.sortByMeasure = _field.FLD_NM;
								rows.sortOrder = _sort.SORT_MODE == 'ASC' ? 'asc' : 'desc';
							}
						});
					}
				});

				var SortOrderBy = rows.sortOrder === undefined ? 'asc' : rows.sortOrder;
				var arrayUpDown = "arrayUp";
				if(SortOrderBy === 'asc'){
					arrayUpDown = 'arrayUp';
				}else{
					arrayUpDown = 'arrayDown';
				}

//				if(dataFieldType == 'measure'){
//					var dataCaption = column['caption'].replace('(sum)','');
//				}
				var element = $('<ul class="display-unmove analysis-data" />');
				element.appendTo($('#rowAdHocList' + itemNum));
				$('#rowAdHocList' + itemNum).children('.unsortable').remove();

				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" prev-container="'
					+ 'rowAdHocList' + itemNum+'" cubeuninm="' + dataUninm + '" uni_nm="'+rows['FLD_NM']+'"  dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico block btn neutral">'
					+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
				element.append(dataItem);
//				element.append(self.dimensionFieldOptionMenu);
				self.setDimensionFieldOptionMenu(element);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				compMoreMenuUi();
				self.expandMeasureList(element.find('.other-menu-ico'));
				$.each(element.find('.measureList').children(),function(_k,_j){
					if(rows.sortByMeasure != undefined){
						// mksong 2019.12.20 sort By 오류 수정 dogfoot
						if($(_j).attr('uni_nm') == rows.sortByMeasure){
							$(_j).children().trigger('click');
							return false;
						}
					}
				});

				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//				$('<a href="#" class="otherBtn axis"></a>').insertAfter(element);
				self.activeGridOption(dataItem);
				gDashboard.fieldManager.dataItemNo++;
			}else{
				$.each(rows, function(index, row) {
					if(row.HIDDEN){
						return false;
					}

					_itemMeta.rows.push(row);
//					var element = treeView.element().find('.dx-treeview-node[aria-label="' + row['name'] + '"]').clone();
//					element
//						.attr('prev-container', 'rowAdHocList' + pivotNum)
//						.attr('style','position: relative;')
//						.attr('dataitem','DataItem' + gDashboard.fieldManager.dataItemNo)
//						.draggable(gDashboard.dragNdropController.draggableOptions)
//						.appendTo('#rowAdHocList' + pivotNum);
//					gDashboard.fieldManager.dataItemNo++;
//					var dataFieldType = row['dataType'] == 'string' ? 'dimension' : 'measure';
//					var dataFieldType = row['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
					var dataFieldType = 'dimension';
					var dataCaption = self.getCaptionName(row['FLD_NM']);
					var dataUninm = row['UNI_NM'];
					var dataItemNo = gDashboard.fieldManager.dataItemNo++;

					$.each(sorts, function(_i,_sort){
						if(_sort.SORT_FLD_NM == row.FLD_NM || _sort.SORT_FIELD_NM == row.FLD_NM){
							$.each(allFieldList, function(_k,_field){
								if(_field.FLD_NM == _sort.BASE_FLD_NM || _field.FLD_NM == _sort.BASE_FIELD_NM){
									row.sortByMeasure = _field.FLD_NM;
									row.sortOrder = _sort.SORT_MODE == 'ASC' ? 'asc' : 'desc';
								}
							});
						}
					});
					var SortOrderBy = row.sortOrder === undefined ? 'asc' : row.sortOrder;
					var arrayUpDown = "arrayUp";
					if(SortOrderBy === 'asc'){
						arrayUpDown = 'arrayUp';
					}else{
						arrayUpDown = 'arrayDown';
					}

//					if(dataFieldType == 'measure'){
//						var dataCaption = column['caption'].replace('(sum)','');
//					}
					var element = $('<ul class="display-unmove analysis-data" />');
					if(index == 0){
						element.appendTo($('#rowAdHocList' + itemNum));
						$('#rowAdHocList' + itemNum).children('.unsortable').remove();
					}else{
						element.insertAfter($('#rowAdHocList' + itemNum).children().get(index-1));
					}

					var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" prev-container="'
						+ 'rowAdHocList' + itemNum+'" cubeuninm="' + dataUninm + '" uni_nm="'+row['FLD_NM']+'"  dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
						// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
						+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico block btn neutral">'
						+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
					element.append(dataItem);
//					element.append(self.dimensionFieldOptionMenu);
					self.setDimensionFieldOptionMenu(element);
					self.fieldRename(dataItem);
					 //2020-01-14 LSH topN
					self.topNset(dataItem);
					compMoreMenuUi();
					self.expandMeasureList(element.find('.other-menu-ico'));
					$.each(element.find('.measureList').children(),function(_k,_j){
						if(row.sortByMeasure != undefined){
							// mksong 2019.12.20 sort By 오류 수정 dogfoot
							if($(_j).attr('uni_nm') == row.sortByMeasure){
								$(_j).children().trigger('click');
								return false;
							}
						}
					});

					dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//					$('<a href="#" class="otherBtn axis"></a>').insertAfter(element);
					self.activeGridOption(dataItem);
					gDashboard.fieldManager.dataItemNo++;

				});
			}
		}

		// retrieve columns
		if(cols != undefined){
			if(cols.length == undefined){
				_itemMeta.columns.push(cols);
//				var dataFieldType = cols['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
				var dataFieldType = 'dimension';
				var dataCaption = self.getCaptionName(cols['FLD_NM']);
				var dataUninm = cols['UNI_NM'];
				var dataItemNo = gDashboard.fieldManager.dataItemNo++;

				$.each(sorts, function(_i,_sort){
					if(_sort.SORT_FLD_NM == cols.FLD_NM || _sort.SORT_FIELD_NM == cols.FLD_NM){
						$.each(allFieldList, function(_k,_field){
							if(_field.FLD_NM == _sort.BASE_FLD_NM || _field.FLD_NM == _sort.BASE_FIELD_NM){
								cols.sortByMeasure = _field.FLD_NM;
								cols.sortOrder = _sort.SORT_MODE == 'ASC' ? 'asc' : 'desc';
							}
						});
					}
				});

				var SortOrderBy = cols.sortOrder === undefined ? 'asc' : cols.sortOrder;
				var arrayUpDown = "arrayUp";
				if(SortOrderBy === 'asc'){
					arrayUpDown = 'arrayUp';
				}else{
					arrayUpDown = 'arrayDown';
				}

				var element = $('<ul class="display-unmove analysis-data" />');
				element.appendTo($('#colAdHocList' + itemNum));
				$('#colAdHocList' + itemNum).children('.unsortable').remove();

				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" prev-container="'
					+ 'colAdHocList' + itemNum+'" cubeuninm="' + dataUninm + '" uni_nm="'+cols['FLD_NM']+'"  dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico block btn neutral">'
					+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
				element.append(dataItem);
//				element.append(self.dimensionFieldOptionMenu);
				self.setDimensionFieldOptionMenu(element);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);

				compMoreMenuUi();
				self.expandMeasureList(element.find('.other-menu-ico'));
				$.each(element.find('.measureList').children(),function(_k,_j){
					if(cols.sortByMeasure != undefined){
						// mksong 2019.12.20 sort By 오류 수정 dogfoot
						if($(_j).attr('uni_nm') == cols.sortByMeasure){
							$(_j).children().trigger('click');
							return false;
						}
					}
				});

				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//				$('<a href="#" class="otherBtn axis"></a>').insertAfter(element);
				self.activeGridOption(dataItem);
				gDashboard.fieldManager.dataItemNo++;
			}else{
				$.each(cols, function(index, column) {
					if(column.HIDDEN){
						return false;
					}

					_itemMeta.columns.push(column);
//					var element = treeView.element().find('.dx-treeview-node[aria-label="' + column['name'] + '"]').clone();
//					element
//						.attr('prev-container', 'colAdHocList' + pivotNum)
//						.attr('style','position: relative;')
//						.attr('dataitem','DataItem' + gDashboard.fieldManager.dataItemNo)
//						.draggable(gDashboard.dragNdropController.draggableOptions)
//						.appendTo('#colAdHocList' + pivotNum);
//					gDashboard.fieldManager.dataItemNo++;
//					var dataFieldType = column['dataType'] == 'string' ? 'dimension' : 'measure';
//					var dataFieldType = column['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
					var dataFieldType = 'dimension';
					var dataCaption = self.getCaptionName(column['FLD_NM']);
					var dataUninm = column['UNI_NM'];
					var dataItemNo = gDashboard.fieldManager.dataItemNo++;

					$.each(sorts, function(_i,_sort){
						if(_sort.SORT_FLD_NM == column.FLD_NM || _sort.SORT_FIELD_NM == column.FLD_NM){
							$.each(allFieldList, function(_k,_field){
								if(_field.FLD_NM == _sort.BASE_FLD_NM || _field.FLD_NM == _sort.BASE_FIELD_NM){
									column.sortByMeasure = _field.FLD_NM;
									column.sortOrder = _sort.SORT_MODE == 'ASC' ? 'asc' : 'desc';
								}
							});
						}
					});

					var SortOrderBy = column.sortOrder === undefined ? 'asc' : column.sortOrder;
					var arrayUpDown = "arrayUp";
					if(SortOrderBy === 'asc'){
						arrayUpDown = 'arrayUp';
					}else{
						arrayUpDown = 'arrayDown';
					}


					var element = $('<ul class="display-unmove analysis-data" />');

					if(index == 0){
						element.appendTo($('#colAdHocList' + itemNum));
						$('#colAdHocList' + itemNum).children('.unsortable').remove();
					}else{
						element.insertAfter($('#colAdHocList' + itemNum).children().get(index-1));
					}

					var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" prev-container="'
						+ 'colAdHocList' + itemNum+'" cubeuninm="' + dataUninm + '" uni_nm="'+column['FLD_NM']+'"  dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
						// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
						+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico block btn neutral">'
						+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
					element.append(dataItem);
//					element.append(self.dimensionFieldOptionMenu);
					self.setDimensionFieldOptionMenu(element);
					self.fieldRename(dataItem);
					 //2020-01-14 LSH topN
					self.topNset(dataItem);

					dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//					$('<a href="#" class="otherBtn axis"></a>').insertAfter(element);

					compMoreMenuUi();
					self.expandMeasureList(element.find('.other-menu-ico'));
					$.each(element.find('.measureList').children(),function(_k,_j){
						if(column.sortByMeasure != undefined){
							// mksong 2019.12.20 sort By 오류 수정 dogfoot
							if($(_j).attr('uni_nm') == column.sortByMeasure){
								$(_j).children().trigger('click');
								return false;
							}
						}
					});

					self.activeGridOption(dataItem);
					gDashboard.fieldManager.dataItemNo++;
				});
			}
		}

		if(sorts.length != 0){
			$.each($(_itemMeta.fieldManager.stateFieldChooser).find('.analysis-data'),function(_i,_field){
				self.expandMeasureList($(_field).find('.other-menu-ico'));
				$.each(sorts, function(_i,_sort){
					if(_sort.SORT_FLD_NM == $(_field).children('li').attr('caption') || _sort.SORT_FIELD_NM == $(_field).children('li').attr('caption')){
						var sortByMeasure = _sort.BASE_FLD_NM == undefined ? _sort.BASE_FIELD_NM : _sort.BASE_FLD_NM;
						$.each($(_field).find('.measureList').children(),function(_k,_j){
							if(sortByMeasure != undefined){
								// mksong 2019.12.20 sort By 오류 수정 dogfoot
								if($(_j).attr('uni_nm') == sortByMeasure){
									$(_j).children().trigger('click');
									return false;
								}
							}
						});
					}
				});
			});
		}
		/* DOGFOOT ktkang 주제영역 관계 표시 부분 오류 수정  20200305 */
		if(WISE.Context.isCubeReport) {
		/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
			if(WISE.Constants.editmode == 'designer'){
			/* DOGFOOT 20201021 ajkim setTimeout 제거*/
//				setTimeout(function () {
					self.cubeRelationCheck(_itemMeta);
//				}, 500);
			}
		}
		$('.other-menu-ico').draggable(gDashboard.dragNdropController.draggableOptions2);
	}

	this.loadAdhocItemDataForViewer = function(_itemMeta){
		var rows = _itemMeta.rows;
		var cols = _itemMeta.columns;
		var datas = _itemMeta.dataFields;
		var sorts = [];
		var hiddenFields = _itemMeta.HiddenMeasures;

		var itemNum = _itemMeta.adhocIndex != undefined ? _itemMeta.adhocIndex : 1;
		// retrieve data fields
		_itemMeta.dataFields = [];
		_itemMeta.rows = [];
		_itemMeta.columns = [];
		_itemMeta.HiddenMeasures = [];

		$.each(hiddenFields, function(_i,_hidmea){
			$.each(datas, function(_k, _data){
				if(_hidmea.uniqueName == _data.uniqueName){
					datas.splice(_k,1);
					return false;
				}
			});
		});

		if(hiddenFields != undefined){
			$.each(hiddenFields, function(index, hiddenField) {
				var dataFieldType = 'measure';
				var dataCaption = self.getCaptionName(hiddenField['FLD_NM']);
				var dataItemNo = hiddenField.uniqueName ? Number(hiddenField.uniqueName.substr(hiddenField.uniqueName.lastIndexOf('m')+1)) : gDashboard.fieldManager.dataItemNo;
				var summaryType = hiddenField.summaryType ? hiddenField.summaryType : WISE.libs.Dashboard.item.DataUtility.AdHoc.getSummaryType(hiddenField.summaryType);

				var element = $('<ul class="display-unmove analysis-data" />');
				if(index == 0){
					element.appendTo($('#adhoc_hide_measure_list' + itemNum));
					$('#adhoc_hide_measure_list' + itemNum).children('.unsortable').remove();
				}else{
					element.insertAfter($('#adhoc_hide_measure_list' + itemNum).children().get(index-1));
				}

				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" prev-container="'
					+ 'dataAdHocList' + itemNum+'" uni_nm="'+hiddenField['UNI_NM']+'"  dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico sigma btn neutral">'
					+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
				element.append(dataItem);
				element.append(self.hiddenMeasureFieldOptionMenu);
				// set summary class
				element.find('.summaryType').parent().removeClass('on');
				element.find('.summaryType[summarytype="' + summaryType + '"]').parent().addClass('on');
				self.addFormat(dataItem);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				compMoreMenuUi();

				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
				hiddenField.dataItem = 'DataItem'+gDashboard.fieldManager.dataItemNo;
				_itemMeta.HiddenMeasures.push(hiddenField);
				gDashboard.fieldManager.dataItemNo++;
			});
		}

		if(datas != undefined){
			$.each(datas, function(index, dataField) {
				if(dataField['caption'].indexOf('DELTA_FIELD') != -1){
					return false;
				}
//					var element = treeView.element().find('.dx-treeview-node[aria-label="' + dataField['name'] + '"]').clone();
//					var dataFieldType = dataField['dataType'] == 'string' ? 'dimension' : 'measure';
//					var dataFieldType = dataField['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
				var dataFieldType = 'measure';
				var dataCaption = dataField['caption'];
				var dataItemNo = dataField.uniqueName ? Number(dataField.uniqueName.substr(dataField.uniqueName.lastIndexOf('m')+1)) : gDashboard.fieldManager.dataItemNo;
				var summaryType = dataField.summaryType ? dataField.summaryType : WISE.libs.Dashboard.item.DataUtility.AdHoc.getSummaryType(dataField.summaryType);

				var element = $('<ul class="display-unmove analysis-data" />');
				if(index == 0){
					element.appendTo($('#dataAdHocList' + itemNum));
					$('#dataAdHocList' + itemNum).children('.unsortable').remove();
				}else{
					element.insertAfter($('#dataAdHocList' + itemNum).children().get(index-1));
				}

				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field other-menu" prev-container="'
					+ 'dataAdHocList' + itemNum+'" uni_nm="'+dataField['UNI_NM']+'"  dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);">'
					+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
				element.append(dataItem);
				element.append(self.measureFieldOptionMenu);
				// set summary class
				element.find('.summaryType').parent().removeClass('on');
				element.find('.summaryType[summarytype="' + summaryType + '"]').parent().addClass('on');
				self.addFormat(dataItem);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				compMoreMenuUi();

				var dataItemId = 'dataAdHocList' + itemNum + '_' + dataItemNo;
				/*dogfoot 크롬 다운로드시 데이터항목 아이콘 레이아웃 깨지는 오류 수정 shlim 20200717*/
				$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_bar1.png" alt></a>').insertAfter(element.find('a.btn'));
				var dataItemOptions = element.find('#' + dataItemId);
				if (typeof self.itemData !== 'undefined') {
					dataItemOptions.data('dataItemOptions', self.itemData);
				} else {
					self.addAdhocChartDataItemOptions(dataItemNo, dataItemOptions);
				}
				dataItemOptions.on('click',function(e){
					self.dataItemOptionsWindow(this);
					e.preventDefault();
				});

				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//					$('<a href="#" class="otherBtn sigma"></a>').insertAfter(element);
				dataField.dataItem = 'DataItem'+gDashboard.fieldManager.dataItemNo;
				_itemMeta.dataFields.push(dataField);
				gDashboard.fieldManager.dataItemNo++;
			});
		}

		var datalist = _itemMeta.dataFields;
		// retrieve rows
		if(rows != undefined){
			$.each(rows, function(index, row) {
				_itemMeta.rows.push(row);
//					var element = treeView.element().find('.dx-treeview-node[aria-label="' + row['name'] + '"]').clone();
//					element
//						.attr('prev-container', 'rowAdHocList' + pivotNum)
//						.attr('style','position: relative;')
//						.attr('dataitem','DataItem' + gDashboard.fieldManager.dataItemNo)
//						.draggable(gDashboard.dragNdropController.draggableOptions)
//						.appendTo('#rowAdHocList' + pivotNum);
//					gDashboard.fieldManager.dataItemNo++;
//					var dataFieldType = row['dataType'] == 'string' ? 'dimension' : 'measure';
//					var dataFieldType = row['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
				var dataFieldType = 'dimension';
				var dataCaption = row['caption'];
				var dataItemNo = row.uniqueName ? Number(row.uniqueName.substr(row.uniqueName.lastIndexOf('m')+1)): gDashboard.fieldManager.dataItemNo++;

				var SortOrderBy = row.sortDirection === undefined ? (row.sortOrder === undefined ? 'asc' : row.sortOrder) : row.sortDirection;
				var arrayUpDown = "arrayUp";
				if(SortOrderBy === 'asc'){
					arrayUpDown = 'arrayUp';
				}else{
					arrayUpDown = 'arrayDown';
				}

//					if(dataFieldType == 'measure'){
//						var dataCaption = column['caption'].replace('(sum)','');
//					}
				var element = $('<ul class="display-unmove analysis-data" />');
				if(index == 0){
					element.appendTo($('#rowAdHocList' + itemNum));
					$('#rowAdHocList' + itemNum).children('.unsortable').remove();
				}else{
					element.insertAfter($('#rowAdHocList' + itemNum).children().get(index-1));
				}

				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" prev-container="'
					+ 'rowAdHocList' + itemNum+'" uni_nm="'+row['UNI_NM']+'"  dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico block btn neutral">'
					+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
				element.append(dataItem);
//				element.append(self.dimensionFieldOptionMenu);
				self.setDimensionFieldOptionMenu(element);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				compMoreMenuUi();
				self.expandMeasureList(element.find('.other-menu-ico'));
				$.each(element.find('.measureList').children(),function(_k,_j){
					if(row.sortByField != undefined || row.sortByMeasure != undefined){
						// mksong 2019.12.20 sort By 오류 수정 dogfoot
						if($(_j).attr('uni_nm') == row.sortByField || $(_j).attr('uni_nm') == row.sortByMeasure){
							$(_j).children().trigger('click');
							return false;
						}
					}
				});
				if(row.sortByField != undefined || row.sortByMeasure != undefined){
					var sort = {'BASE_FLD_NM':row.sortByField == undefined ? (row.sortByMeasure == undefined ? undefined : row.sortByMeasure) : row.sortByField, 'SORT_FLD_NM' : row.UNI_NM, 'SORT_MODE': SortOrderBy};
					sorts.push(sort);
				}

				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//					$('<a href="#" class="otherBtn axis"></a>').insertAfter(element);
				self.activeGridOption(dataItem);
				gDashboard.fieldManager.dataItemNo++;

			});
		}

		// retrieve columns
		if(cols != undefined){
			$.each(cols, function(index, column) {
				_itemMeta.columns.push(column);
//					var element = treeView.element().find('.dx-treeview-node[aria-label="' + column['name'] + '"]').clone();
//					element
//						.attr('prev-container', 'colAdHocList' + pivotNum)
//						.attr('style','position: relative;')
//						.attr('dataitem','DataItem' + gDashboard.fieldManager.dataItemNo)
//						.draggable(gDashboard.dragNdropController.draggableOptions)
//						.appendTo('#colAdHocList' + pivotNum);
//					gDashboard.fieldManager.dataItemNo++;
//					var dataFieldType = column['dataType'] == 'string' ? 'dimension' : 'measure';
//					var dataFieldType = column['FORMAT_TYPE'] == 'Numeric' ? 'measure' : 'dimension';
				var dataFieldType = 'dimension';
				var dataCaption = column['caption'];
				var dataItemNo = column.uniqueName ? Number(column.uniqueName.substr(column.uniqueName.lastIndexOf('m')+1)): gDashboard.fieldManager.dataItemNo++;

				var SortOrderBy = column.sortDirection === undefined ? (column.sortOrder === undefined ? 'asc' : column.sortOrder) : column.sortDirection;

				var arrayUpDown = "arrayUp";
				if(SortOrderBy === 'asc'){
					arrayUpDown = 'arrayUp';
				}else{
					arrayUpDown = 'arrayDown';
				}

				var element = $('<ul class="display-unmove analysis-data" />');

				if(index == 0){
					element.appendTo($('#colAdHocList' + itemNum));
					$('#colAdHocList' + itemNum).children('.unsortable').remove();
				}else{
					element.insertAfter($('#colAdHocList' + itemNum).children().get(index-1));
				}

				var dataItem = $('<li data-field-type="'+ dataFieldType +'" class="wise-column-chooser wise-area-field '+arrayUpDown+' other-menu" prev-container="'
					+ 'colAdHocList' + itemNum+'" uni_nm="'+column['UNI_NM']+'"  dataitem="'+ 'DataItem' + gDashboard.fieldManager.dataItemNo + '" caption="' + dataCaption
					// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
					+ '" title="' + dataCaption + '" data-source-id="' + _itemMeta.dataSourceId + '" style="height: 31px;"><a href="#" class="ico block btn neutral">'
					+ '<div class="fieldName">' + dataCaption + '</div></a></li>');
				element.append(dataItem);
//				element.append(self.dimensionFieldOptionMenu);
				self.setDimensionFieldOptionMenu(element);
				self.fieldRename(dataItem);
				//2020-01-14 LSH topN
				 self.topNset(dataItem);

				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
//					$('<a href="#" class="otherBtn axis"></a>').insertAfter(element);

				compMoreMenuUi();
				self.expandMeasureList(element.find('.other-menu-ico'));
				$.each(element.find('.measureList').children(),function(_k,_j){
					if(column.sortByField != undefined || column.sortByMeasure != undefined){
						// mksong 2019.12.20 sort By 오류 수정 dogfoot
						if($(_j).attr('uni_nm') == column.sortByField || $(_j).attr('uni_nm') == column.sortByMeasure){
							$(_j).children().trigger('click');
							return false;
						}
					}
				});

				if(column.sortByField != undefined || column.sortByMeasure != undefined){
					var sort = {'BASE_FLD_NM':column.sortByField == undefined ? (column.sortByMeasure == undefined ? undefined : column.sortByMeasure) : column.sortByField, 'SORT_FLD_NM' : column.UNI_NM, 'SORT_MODE': SortOrderBy};
					sorts.push(sort);
				}

				self.activeGridOption(dataItem);
				gDashboard.fieldManager.dataItemNo++;
			});
		}

		if(sorts.length != 0){
			$.each($(_itemMeta.fieldManager.stateFieldChooser).find('.analysis-data'),function(_i,_field){
				self.expandMeasureList($(_field).find('.other-menu-ico'));
				$.each(sorts, function(_i,_sort){
					if(_sort.SORT_FLD_NM == $(_field).children('li').attr('caption') || _sort.SORT_FIELD_NM == $(_field).children('li').attr('caption')){
						var sortByMeasure = _sort.BASE_FLD_NM == undefined ? _sort.BASE_FIELD_NM : _sort.BASE_FLD_NM;
						$.each($(_field).find('.measureList').children(),function(_k,_j){
							if(sortByMeasure != undefined){
								// mksong 2019.12.20 sort By 오류 수정 dogfoot
								if($(_j).attr('uni_nm') == sortByMeasure){
									$(_j).children().trigger('click');
									return false;
								}
							}
						});
					}
				});
			});
		}
	}

	//2020.02.13 MKSONG 필드 삭제시 기본으로 복원 DOGFOOT
	this.recovery = function ($o){
		var type;
		if($o.length === 0) return;
		if($o == 'delta-drop'){
			type = $o;
		}else{
			type = $o.attr('id').substring(0,$o.attr('id').lastIndexOf('t')+1);
		}

		if(type != ""){
			$o.droppable("enable").sortable('disable');
		}else{
			type = $o.attr('id').substring(0,$o.attr('id').lastIndexOf('e')+1);
		}

		if(gDashboard.fieldManager.stateFieldChooser.children().find('.other-menu-ico').length == 0){
			gDashboard.fieldManager.stateFieldChooser.children().removeAttr('data-source-id');
		}

		var message;
		if(type != 'deltavalueList'){
			switch(type){
				case 'dataAdHocList':
				case 'dataList':
				case 'chartValueList':
				case 'pieValueList':
				case 'parallelValueList':
				case 'bubblepackchartValueList':
				case 'wordcloudv2ValueList':
				case 'dendrogrambarchartValueList':
				case 'calendarviewchartValueList':
				case 'calendarview2chartValueList':
				case 'calendarview3chartValueList':
				case 'collapsibletreechartValueList':
				case 'rangebarchartValueList':
				case 'rangeareachartValueList':
				case 'timelinechartValueList':
				case 'RectangularAreaChartValueList':
				case 'waterfallchartValueList':
				case 'bipartitechartValueList':
				case 'funnelchartValueList':
				case 'pyramidchartValueList':
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case 'kakaoMapValueList':
				case 'kakaoMap2ValueList':
				case 'sankeychartValueList':
				case 'histogramchartValueList':
				case 'bubbled3ValueList':
				case 'treemapValueList':
				case 'starchartValueList':
				case 'heatmapValueList':
				case 'heatmap2ValueList':
				case 'syncchartValueList':
				case 'wordcloudValueList':
				case 'textboxValueList':
				case 'cardValueList':
				case 'mapValueList':
				case 'forceDirectValueList':
				case 'forceDirectExpandValueList':
				case 'bubbleChartValueList':
				case 'divergingchartValueList':
				case 'dependencywheelValueList':
				case 'scatterplotValueList':
				case 'scatterplot2ZList':
				case 'sequencessunburstValueList':
				case 'boxplotValueList':
				case 'liquidfillgaugeValueList':
				case 'coordinatelineXList':
				case 'coordinatelineYList':
				case 'coordinatedotXList':
				case 'coordinatedotYList':
					/* DOGFOOT hsshim 2020-02-03 게이지 데이터 항목 UI 및 기능 작업 */
					message = gMessage.get('WISE.message.page.widget.drop.newdatafiled');
					break;
				case 'kakaoMapLatitudeList':
					message = gMessage.get('WISE.message.page.widget.drop.newlattitude');
					break;
				case 'kakaoMapLongitudeList':
					message = gMessage.get('WISE.message.page.widget.drop.newlongtitude');
					break;
				case 'kakaoMapAddressList':
					message = gMessage.get('WISE.message.page.widget.drop.newaddress');
					break;
				case 'kakaoMapFieldList':
					message = gMessage.get('WISE.message.page.widget.drop.newfield');
					break;
				case 'mapStateList':
					message = gMessage.get('WISE.message.page.widget.drop.newstate');
					break;
				case 'mapCityList':
					message = gMessage.get('WISE.message.page.widget.drop.newcity');
					break;
				case 'mapDongList':
					message = gMessage.get('WISE.message.page.widget.drop.newdong');
					break;
				case 'colList':
				case 'columnList':
				case 'colAdHocList':
				case 'bubbleChartXList':
				case 'bubbleChartYList':
				case 'scatterplotXList':
				case 'scatterplotYList':
				case 'scatterplot2XList':
				case 'scatterplot2YList':
				case 'scatterPlotMatrixX1List':
				case 'scatterPlotMatrixX2List':
				case 'scatterPlotMatrixY1List':
				case 'scatterPlotMatrixY2List':
				case 'rFieldList':
					message = gMessage.get('WISE.message.page.widget.drop.newcolumnfiled');
					break;
				case 'rowList':
				case 'rowAdHocList':
					message = gMessage.get('WISE.message.page.widget.drop.newrowfiled');
					break;
				case 'chartParameterList':
				case 'pieParameterList':
				case 'parallelParameterList':
				case 'bubblepackchartParameterList':
				case 'wordcloudv2ParameterList':
				case 'dendrogrambarchartParameterList':
				case 'calendarviewchartParameterList':
				case 'calendarview2chartParameterList':
				case 'calendarview3chartParameterList':
				case 'collapsibletreechartParameterList':
				case 'rangebarchartParameterList':
				case 'rangeareachartParameterList':
				case 'timelinechartParameterList':
				case 'timelinechartStartDateList':
				case 'timelinechartEndDateList':
				case 'RectangularAreaChartParameterList':
				case 'waterfallchartParameterList':
				case 'bipartitechartParameterList':
				case 'pyramidchartParameterList':
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
				case 'kakaoMapParameterList':
				case 'kakaoMap2ParameterList':
				case 'funnelchartParameterList':
				case 'sankeychartParameterList':
				case 'histogramchartParameterList':
				case 'bubbled3ParameterList':
				case 'treemapParameterList':
				case 'starchartParameterList':
				case 'wordcloudParameterList':
				case 'heatmapParameterList':
				case 'heatmap2ParameterList':
				case 'syncchartParameterList':
				case 'mapParameterList':
				case 'hierarchicalParameterList':
				case 'forceDirectParameterList':
				case 'forceDirectExpandParameterList':
				case 'divergingchartParameterList':
				case 'dependencywheelParameterList':
				case 'scatterplotParameterList':
				case 'scatterplot2ParameterList':
				case 'sequencessunburstParameterList':
				case 'boxplotParameterList':
				case 'liquidfillgaugeParameterList':
				case 'scatterPlotMatrixParameterList':
				case 'radialTidyTreeParameterList':
				case 'historyTimelineParameterList':
				case 'historyTimelineStartList':
				case 'historyTimelineEndList':
				case 'arcdiagramParameterList':
					message = gMessage.get('WISE.message.page.widget.drop.newparameter');
					break;
				case 'chartSeriesList':
				case 'timelinechartSeriesList':
				case 'pieSeriesList':
				case 'starchartSeriesList':
				case 'cardSeriesList':
				/* DOGFOOT hsshim 2020-02-03 게이지 데이터 항목 UI 및 기능 작업 */
				case 'gaugeSeriesList':
					message = gMessage.get('WISE.message.page.widget.drop.newseries');
					break;
					/* DOGFOOT ktkang undefined표기 오류 수정  20200130 */
				case 'adhoc_hide_measure_list':
				case 'pivot_hide_measure_list':
				case 'grid_hide_measure_list':
				case 'chart_hide_measure_list':
				case 'pie_hide_measure_list':
				case 'textbox_hide_measure_list':
				//2020.02.07 mksong listbox_hide_measure_list 추가 dogfoot
				case 'listbox_hide_measure_list':
				case 'combobox_hide_measure_list':
				case 'card_hide_measure_list':
				case 'divergingchartSeriesList':
				case 'divergingchart_hide_measure_list':
				case 'scatterplot_hide_measure_list':
				case 'scatterplot2_hide_measure_list':
				case 'heatmap_hide_measure_list':
				case 'heatmap2_hide_measure_list':
				case 'syncchart_hide_measure_list':
					message = gMessage.get('WISE.message.page.widget.drop.newitem');
					break;
				case 'dimList':
				case 'cb_dimList':
				case 'tv_dimList':
					message = gMessage.get('WISE.message.page.widget.drop.newparameter');
					break;
				case 'sparkLine':
				case 'cardSparkLine':
					message = "인수";
					break;
				case 'kakaoMapLatitude':
					message = '위도';
					break;
				case 'kakaoMapLongitude':
					message = '경도';
					break;
				/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
				case 'onewayAnovaObservedList':
				case 'onewayAnova2ObservedList':
				case 'twowayAnovaObservedList':
					message = gMessage.get('WISE.message.page.widget.analysis.observed');
					break;
				case 'onewayAnovaFactorList':
				case 'onewayAnova2FactorList':
				case 'twowayAnovaFactorList':
					message = gMessage.get('WISE.message.page.widget.analysis.factor');
					break;
				case 'onewayAnova2ItemList':
					message = gMessage.get('WISE.message.page.widget.analysis.item');
					break;
				case 'pearsonsCorrelationNumericalList':
				case 'spearmansCorrelationNumericalList':
				case 'tTestNumericalList':
				case 'zTestNumericalList':
				case 'chiTestNumericalList':
				case 'fTestNumericalList':
				/* DOGFOOT ktkang 다변량분석 추가  20210215 */
				case 'multivariateNumericalList':
					message = gMessage.get('WISE.message.page.widget.analysis.numerical');
					break;
				case 'multivariateParameterList':
					message = gMessage.get('WISE.message.page.widget.analysis.dimension');
					break;
				case 'simpleRegressionIndpnList':
				case 'multipleRegressionIndpnList':
				case 'logisticRegressionIndpnList':
				case 'multipleLogisticRegressionIndpnList':
					message = gMessage.get('WISE.message.page.widget.analysis.independent');
					break;
				case 'simpleRegressionDpndnList':
				case 'multipleRegressionDpndnList':
				case 'logisticRegressionDpndnList':
				case 'multipleLogisticRegressionDpndnList':
					message = gMessage.get('WISE.message.page.widget.analysis.dependent');
					break;
				case 'simpleRegressionVectorList':
				case 'multipleRegressionVectorList':
				case 'logisticRegressionVectorList':
				case 'multipleLogisticRegressionVectorList':
					message = gMessage.get('WISE.message.page.widget.analysis.vector');
					break;
			}

			$('<ul class="display-unmove unsortable"><li><a href="#" class="btn neutral">' + message + '</a></li></ul>').appendTo($o);
		}
	};

	this.recoveryDataGridDelta = function($o){
		$o.wrap('<ul class="display-unmove more analysis-data sortable"/>');
		var targetField = $('<li id="delta-drop' + self.item.index + '_'+ ($('.delta-drop').length + 1) + '" class="drop-target delta-drop" style="margin-top: 0px;height: 31px;margin-bottom: 4px;" drop-type="deltaTarget"><a href="#" class="btn neutral" style="width: calc(100% - 35px); margin-bottom: 4px;">' + gMessage.get('WISE.message.page.widget.drop.target') + '</a></li>');
		self.appendFieldOptionMenu($o,'measure',false);
		$o.parent().append(targetField);

		$o.attr('target-field-uninm',undefined);
		$o.attr('target-field-dataitem',undefined);
		$o.attr('target-field-caption',undefined);
		$o.attr('target-field-origintype',undefined);

		$('.delta-drop').droppable(self.droppableOptions);
	}

	//2020.03.02 MKSONG 주제영역 중복 항목 제거 함수화 DOGFOOT
	//2020.03.02 MKSONG 주제영역 중복 항목 제거 함수화 DOGFOOT
	this.duplicatedCheck = function(container,_fieldItem, prevContainer){
		/* DOGFOOT ktkang 주제영역 데이터 항목에 중복되어 들어가지 못하도록 수정 시작   20200225 */
		var duple = false;
		if(WISE.Context.isCubeReport && (!prevContainer || container != prevContainer)){
			if(container !== 'downloadexpand_colList'){
				$.each(gDashboard.fieldManager.stateFieldChooser.children().find('.drop-panel'),function(_i, _o){
					var dataList = $(_o).children('ul');
	//				if($(_o).attr('id').indexOf('hide_measure') == -1) {
						$.each(dataList,function(_ii, _oo){
						/* DOGFOOT mksong IE innerText오류 수정 20200309 */
							if($(_oo).children().attr('uni_nm')  == _fieldItem.attr('uni_nm')) {
								WISE.alert('같은 이름의 데이터 항목을 중복으로 사용하실 수 없습니다.');
								/*dogfoot 중복체크 후 드래그한 데이터항목이 안사라지는 오류 수정 shlim 20200715*/
								_fieldItem.remove();
								duple = true;
							}
						});
	//				}
				});
			}else {
				_o = $('#downloadexpand_colList')
				var dataList = $(_o).children('ul');
				$.each(dataList,function(_ii, _oo){
				/* DOGFOOT mksong IE innerText오류 수정 20200309 */
					if($(_oo).children().attr('uni_nm')  == _fieldItem.attr('uni_nm')) {
						WISE.alert('같은 이름의 데이터 항목을 중복으로 사용하실 수 없습니다.');
						/*dogfoot 중복체크 후 드래그한 데이터항목이 안사라지는 오류 수정 shlim 20200715*/
						_fieldItem.remove();
						duple = true;
					}
				});
			}
			
		}
		
		if(!duple){
			_fieldItem.removeClass("wise-field-leaf");
			_fieldItem.removeClass("wise-no-border");
		}
		
		return duple;
	}

	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
	this.cubeRelationCheck = function(_item) {
		var valueList = [];
		var columnList = [];
		var rowList = [];
		var hiddenList = [];
		/* DOGFOOT ktkang 주제영역 관계 오류 수정  20200525 */
		var itemParameter;
		var itemParameter2;
		var itemParameter3;
		var itemSeries;
		var itemHidden;
		/*dogfoot shlim 비정형 관계 없는 차원 삭제시 새행 추가 2020512*/
		var itemNum ;
		if(_item){
           itemNum = _item.index != undefined ? _item.index : _item.adhocIndex;
		}
		if(typeof _item != 'undefined') {
			/*dogfoot 통계 분석 추가 shlim 20201102*/
			if(_item.type === 'SIMPLE_CHART' && ((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis'))) {
				valueList = $('#chartValueList' + _item.index).children().children('li');
				columnList = $('#chartParameterList' + _item.index).children().children('li');
				rowList = $('#chartSeriesList' + _item.index).children().children('li');
				hiddenList = $('#chart_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#chartParameterList';
				itemSeries = '#chartSeriesList';
				itemHidden = '#chart_hide_measure_list';
				/* DOGFOOT ktkang 주제영역 관계부분 오류 수정  20200704 */
			} else if((_item.type === 'SIMPLE_CHART' || _item.type === 'PIVOT_GRID') && (gDashboard.reportType == 'AdHoc')) {
				valueList = $('#dataAdHocList' + _item.index).children().children('li');
				columnList = $('#colAdHocList' + _item.index).children().children('li');
				rowList = $('#rowAdHocList' + _item.index).children().children('li');
				hiddenList = $('#adhoc_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#colAdHocList';
				itemSeries = '#rowAdHocList';
				itemHidden = '#adhoc_hide_measure_list';
			}  else if(_item.type === 'PIVOT_GRID' && (gDashboard.reportType == 'DashAny')) {
				valueList = $('#dataList' + _item.index).children().children('li');
				columnList = $('#colList' + _item.index).children().children('li');
				rowList = $('#rowList' + _item.index).children().children('li');
				hiddenList = $('#pivot_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#colList';
				itemSeries = '#rowList';
				itemHidden = '#pivot_hide_measure_list';
			} else if(_item.type === 'PIE_CHART') {
				valueList = $('#pieValueList' + _item.index).children().children('li');
				columnList = $('#pieParameterList' + _item.index).children().children('li');
				rowList = $('#pieSeriesList' + _item.index).children().children('li');
				hiddenList = $('#pie_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#pieParameterList';
				itemSeries = '#pieSeriesList';
				itemHidden = '#pie_hide_measure_list';
			} else if(_item.type === 'DATA_GRID') {
				/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
				if(_item.fieldManager.focusItemType !== _item.kind && _item.fieldManager.focusItemType !== _item.kind) {
					var measures = [];
					var dimensions = [];

					if(_item.fieldManager.focusItemType.indexOf('Anova') > -1) {
						$.each($('#' + _item.fieldManager.focusItemType +'ObservedList' + _item.index).children().children('li'), function(_j, _k){
							if($(_k).attr('data-field-type') == 'measure') {
								measures.push($(_k));
							} else {
								dimensions.push($(_k));
							}
						});
						$.each($('#' + _item.fieldManager.focusItemType + 'FactorList' + _item.index).children().children('li'), function(_j, _k){
							if($(_k).attr('data-field-type') == 'measure') {
								measures.push($(_k));
							} else {
								dimensions.push($(_k));
							}
						});
						itemParameter = '#' + _item.fieldManager.focusItemType + 'ObservedList';
						itemParameter2 = '#' + _item.fieldManager.focusItemType + 'FactorList';

						/*if(_item.fieldManager.focusItemType === 'onewayAnova2') {
							$.each($('#' + _item.fieldManager.focusItemType + 'ItemList' + _item.index).children().children('li'), function(_j, _k){
								if($(_k).attr('data-field-type') == 'measure') {
									measures.push($(_k));
								} else {
									dimensions.push($(_k));
								}
							});
							itemParameter3 = '#' + _item.fieldManager.focusItemType + 'ItemList';
						}*/
					/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
					} else if(_item.fieldManager.focusItemType.indexOf('Correlation') > -1 || _item.fieldManager.focusItemType.indexOf('Test') > -1) {
						$.each($('#' + _item.fieldManager.focusItemType +'NumericalList1').children().children('li'), function(_j, _k){
							if($(_k).attr('data-field-type') == 'measure') {
								measures.push($(_k));
							} else {
								dimensions.push($(_k));
							}
						});
						itemParameter = '#' + _item.fieldManager.focusItemType + 'NumericalList';
					} else if(_item.fieldManager.focusItemType.indexOf('Regression') > -1) {
						$.each($('#' + _item.fieldManager.focusItemType +'IndpnList' + _item.index).children().children('li'), function(_j, _k){
							if($(_k).attr('data-field-type') == 'measure') {
								measures.push($(_k));
							} else {
								dimensions.push($(_k));
							}
						});
						$.each($('#' + _item.fieldManager.focusItemType +'DpndnList' + _item.index).children().children('li'), function(_j, _k){
							if($(_k).attr('data-field-type') == 'measure') {
								measures.push($(_k));
							} else {
								dimensions.push($(_k));
							}
						});
						$.each($('#' + _item.fieldManager.focusItemType +'VectorList' + _item.index).children().children('li'), function(_j, _k){
							if($(_k).attr('data-field-type') == 'measure') {
								measures.push($(_k));
							} else {
								dimensions.push($(_k));
							}
						});
						itemParameter = '#' + _item.fieldManager.focusItemType + 'IndpnList';
						itemParameter2 = '#' + _item.fieldManager.focusItemType + 'DpndnList';
						itemParameter3 = '#' + _item.fieldManager.focusItemType + 'VectorList';
					/* DOGFOOT ktkang 다변량분석 추가  20210215 */
					} else if(_item.fieldManager.focusItemType.indexOf('multivariate') > -1) {
						$.each($('#' + _item.fieldManager.focusItemType +'NumericalList1').children().children('li'), function(_j, _k){
							if($(_k).attr('data-field-type') == 'measure') {
								measures.push($(_k));
							} else {
								dimensions.push($(_k));
							}
						});
						$.each($('#' + _item.fieldManager.focusItemType + 'ParameterList1').children().children('li'), function(_j, _k){
							if($(_k).attr('data-field-type') == 'measure') {
								measures.push($(_k));
							} else {
								dimensions.push($(_k));
							}
						});
						itemParameter = '#' + _item.fieldManager.focusItemType + 'NumericalList';
						itemParameter2 = '#' + _item.fieldManager.focusItemType + 'ParameterList';
					}
					/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */

					valueList = measures;
					columnList = dimensions;
					hiddenList = $('#hide_measure_list' + _item.index).children().children('li');

					itemHidden = '#hide_measure_list';
				} else {
					var measures = [];
					var dimensions = [];
					$.each($('#columnList' + _item.index).children().children('li'), function(_j, _k){
						if($(_k).attr('data-field-type') == 'measure') {
							measures.push($(_k));
						} else {
							dimensions.push($(_k));
						}
					});

					valueList = measures;
					columnList = dimensions;
					hiddenList = $('#hide_measure_list' + _item.index).children().children('li');

					itemParameter = '#columnList';
					itemHidden = '#hide_measure_list';
				}
			} else if(_item.type === 'STAR_CHART') {
				valueList = $('#starchartValueList' + _item.index).children().children('li');
				columnList = $('#starchartParameterList' + _item.index).children().children('li');
				rowList = $('#starchartSeriesList' + _item.index).children().children('li');

				itemParameter = '#starchartParameterList';
				itemSeries = '#starchartSeriesList';
			} else if(_item.type === 'TREEMAP') {
				valueList = $('#treemapValueList' + _item.index).children().children('li');
				columnList = $('#treemapParameterList' + _item.index).children().children('li');

				itemParameter = '#treemapParameterList';
			} else if(_item.type === 'WORD_CLOUD') {
				valueList = $('#wordcloudValueList' + _item.index).children().children('li');
				columnList = $('#wordcloudParameterList' + _item.index).children().children('li');

				itemParameter = '#wordcloudParameterList';
			} else if(_item.type === 'WATERFALL_CHART') {
				valueList = $('#waterfallchartValueList' + _item.index).children().children('li');
				columnList = $('#waterfallchartParameterList' + _item.index).children().children('li');

				itemParameter = '#waterfallchartParameterList';
			} else if(_item.type === 'BIPARTITEL_CHART') {
				valueList = $('#bipartitechartValueList' + _item.index).children().children('li');
				columnList = $('#bipartitechartParameterList' + _item.index).children().children('li');

				itemParameter = '#bipartitechartParameterList';
			} else if(_item.type === 'PYRAMID_CHART') {
				valueList = $('#pyramidchartValueList' + _item.index).children().children('li');
				columnList = $('#pyramidchartParameterList' + _item.index).children().children('li');

				itemParameter = '#pyramidchartParameterList';
			} else if(_item.type === 'FUNNEL_CHART') {
				valueList = $('#funnelchartValueList' + _item.index).children().children('li');
				columnList = $('#funnelchartParameterList' + _item.index).children().children('li');

				itemParameter = '#funnelchartParameterList';
			} else if(_item.type === 'SANKEY_CHART') {
				valueList = $('#sankeychartValueList' + _item.index).children().children('li');
				columnList = $('#sankeychartParameterList' + _item.index).children().children('li');

				itemParameter = '#sankeychartParameterList';
			} else if(_item.type === 'TEXTBOX') {
				if(gDashboard.reportType === 'RAnalysis'){
					var measures = [];
					var dimensions = [];
					$.each($('#rFieldList' + _item.index).children().children('li'), function(_j, _k){
						if($(_k).attr('data-field-type') == 'measure') {
							measures.push($(_k));
						} else {
							dimensions.push($(_k));
						}
					});

					valueList = measures;
					columnList = dimensions;

					itemParameter = '#rFieldList';
				}else{
					valueList = $('#textboxValueList' + _item.index).children().children('li');
					hiddenList = $('#textbox_measure_list' + _item.index).children().children('li');

					itemHidden = '#textbox_measure_list';
				}
			} else if(_item.type === 'RECTANGULAR_ARAREA_CHART') {
				valueList = $('#RectangularAreaChartValueList' + _item.index).children().children('li');
				columnList = $('#RectangularAreaChartParameterList' + _item.index).children().children('li');

				itemParameter = '#RectangularAreaChartParameterList';
			} else if(_item.type === 'DIVERGING_CHART') {
				valueList = $('#divergingchartValueList' + _item.index).children().children('li');
				columnList = $('#divergingchartParameterList' + _item.index).children().children('li');
				rowList = $('#divergingchartSeriesList' + _item.index).children().children('li');
				hiddenList = $('#divergingchart_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#divergingchartParameterList';
				itemSeries = '#divergingchartSeriesList';
				itemHidden = '#divergingchart_hide_measure_list';
			} else if(_item.type === 'DEPENDENCY_WHEEL') {
//				valueList = $('#dependencywheelValueList' + _item.index).children().children('li');
				columnList = $('#dependencywheelParameterList' + _item.index).children().children('li');

				itemParameter = '#dependencywheelParameterList';
			} else if(_item.type === 'SEQUENCES_SUNBURST') {
				valueList = $('#sequencessunburstValueList' + _item.index).children().children('li');
				columnList = $('#sequencessunburstParameterList' + _item.index).children().children('li');

				itemParameter = '#sequencessunburstParameterList';
			} else if(_item.type === 'LIQUID_FILL_GAUGE') {
				valueList = $('#liquidfillgaugeValueList' + _item.index).children().children('li');
				columnList = $('#liquidfillgaugeParameterList' + _item.index).children().children('li');

				itemParameter = '#liquidfillgaugeParameterList';
			} else if(_item.type === 'BOX_PLOT') {
				/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
				if(_item.fieldManager.focusItemType !== _item.kind && _item.fieldManager.focusItemType !== _item.kind) {
					if(_item.fieldManager.focusItemType.indexOf('Anova') > -1) {
						valueList = $('#' + _item.fieldManager.focusItemType + 'AnovaObservedList' + _item.index).children().children('li');
						columnList = $('#' + _item.fieldManager.focusItemType + 'AnovaFactorList' + _item.index).children().children('li');
					} else if(_item.fieldManager.focusItemType.indexOf('Correlation') > -1) {

					} else if(_item.fieldManager.focusItemType.indexOf('Regression') > -1) {

					}
				} else {
					valueList = $('#boxplotValueList' + _item.index).children().children('li');
					columnList = $('#boxplotParameterList' + _item.index).children().children('li');
				}
				itemParameter = '#boxplotParameterList';
			} else if(_item.type === 'SCATTER_PLOT') {
//				valueList = $('#scatterplotZList' + _item.index).children().children('li');
				columnList = $('#scatterplotParameterList' + _item.index).children().children('li');
//				hiddenList = $('#scatterplot_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#scatterplotParameterList';
//				itemHidden = '#scatterplot_hide_measure_list';
			} else if(_item.type === 'COORDINATE_LINE') {
				columnList = $('#coordinatelineParameterList' + _item.index).children().children('li');

				itemParameter = '#coordinatelineParameterList';
//				itemHidden = '#scatterplot_hide_measure_list';
			} else if(_item.type === 'COORDINATE_DOT') {
				columnList = $('#coordinatedotParameterList' + _item.index).children().children('li');

				itemParameter = '#coordinatedotParameterList';
//				itemHidden = '#scatterplot_hide_measure_list';
			} else if(_item.type === 'SCATTER_PLOT2') {
				valueList = $('#scatterplot2ZList' + _item.index).children().children('li');
				columnList = $('#scatterplot2ParameterList' + _item.index).children().children('li');
//				hiddenList = $('#scatterplot2_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#scatterplot2ParameterList';
//				itemHidden = '#scatterplot2_hide_measure_list';
			} else if(_item.type === 'RADIAL_TIDY_TREE') {
				columnList = $('#radialTidyTreeParameterList' + _item.index).children().children('li');
				itemParameter = '#radialTidyTreeParameterList';
			} else if(_item.type === 'ARC_DIAGRAM') {
				columnList = $('#arcdiagramParameterList' + _item.index).children().children('li');
				itemParameter = '#arcdiagramParameterList';
			}else if(_item.type === 'SCATTER_PLOT_MATRIX') {
				columnList = $('#scatterPlotMatrixParameterList' + _item.index).children().children('li');

				itemParameter = '#scatterPlotMatrixParameterList';
			} else if(_item.type === 'HISTORY_TIMELINE') {
				columnList = $('#historyTimelineParameterList' + _item.index).children().children('li');

				itemParameter = '#historyTimelineParameterList';
			}else if(_item.type === 'PARALLEL_COORDINATE') {
				valueList = $('#parallelValueList' + _item.index).children().children('li');
				columnList = $('#parallelParameterList' + _item.index).children().children('li');

				itemParameter = '#parallelParameterList';
			} else if(_item.type === 'BUBBLE_PACK_CHART') {
				valueList = $('#bubblepackchartValueList' + _item.index).children().children('li');
				columnList = $('#bubblepackchartParameterList' + _item.index).children().children('li');

				itemParameter = '#bubblepackchartParameterList';
			} else if(_item.type === 'WORD_CLOUD_V2') {
				valueList = $('#wordcloudv2ValueList' + _item.index).children().children('li');
				columnList = $('#wordcloudv2ParameterList' + _item.index).children().children('li');

				itemParameter = '#wordcloudv2ParameterList';
			} else if(_item.type === 'DENDROGRAM_BAR_CHART') {
				valueList = $('#dendrogrambarchartValueList' + _item.index).children().children('li');
				columnList = $('#dendrogrambarchartParameterList' + _item.index).children().children('li');

				itemParameter = '#dendrogrambarchartParameterList';
			} else if(_item.type === 'CALENDAR_VIEW_CHART') {
				valueList = $('#calendarviewchartValueList' + _item.index).children().children('li');
				columnList = $('#calendarviewchartParameterList' + _item.index).children().children('li');

				itemParameter = '#calendarviewchartParameterList';
			} else if(_item.type === 'CALENDAR_VIEW2_CHART') {
				valueList = $('#calendarview2chartValueList' + _item.index).children().children('li');
				columnList = $('#calendarview2chartParameterList' + _item.index).children().children('li');

				itemParameter = '#calendarview2chartParameterList';
			} else if(_item.type === 'CALENDAR_VIEW3_CHART') {
				valueList = $('#calendarview3chartValueList' + _item.index).children().children('li');
				columnList = $('#calendarview3chartParameterList' + _item.index).children().children('li');

				itemParameter = '#calendarview3chartParameterList';
			} else if(_item.type === 'COLLAPSIBLE_TREE_CHART') {
				valueList = $('#collapsibletreechartValueList' + _item.index).children().children('li');
				columnList = $('#collapsibletreechartParameterList' + _item.index).children().children('li');

				itemParameter = '#collapsibletreechartParameterList';
			} else if(_item.type === 'RANGE_BAR_CHART') {
				valueList = $('#rangebarchartValueList' + _item.index).children().children('li');
				columnList = $('#rangebarchartParameterList' + _item.index).children().children('li');
//				rowList = $('#rangebarchartSeriesList' + _item.index).children().children('li');
//				hiddenList = $('#rangebarchart_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#rangebarchartParameterList';
//				itemSeries = '#rangebarchartSeriesList';
//				itemHidden = '#rangebarchart_hide_measure_list';
			}  else if(_item.type === 'RANGE_AREA_CHART') {
				valueList = $('#rangeareachartValueList' + _item.index).children().children('li');
				columnList = $('#rangeareachartParameterList' + _item.index).children().children('li');

				itemParameter = '#rangeareachartParameterList';
			}else if(_item.type === 'TIME_LINE_CHART') {
				valueList = $('#timelinechartValueList' + _item.index).children().children('li');
				columnList = $('#timelinechartParameterList' + _item.index).children().children('li');
				rowList = $('#timelinechartSeriesList' + _item.index).children().children('li');
				startList = $('#timelinechartStartDateList' + _item.index).children().children('li');
				endList = $('#timelinechartEndDateList' + _item.index).children().children('li');
//				hiddenList = $('#timelinechart_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#timelinechartParameterList';
				itemSeries = '#timelinechartSeriesList';
				itemStart = '#timelinechartParameterList';
				itemEnd = '#timelinechartParameterList';
//				itemHidden = '#timelinechart_hide_measure_list';
			}  else if(_item.type === 'CHOROPLETH_MAP') {
				valueList = $('#mapValueList' + _item.index).children().children('li');
				columnList = $('#mapParameterList' + _item.index).children().children('li');

				itemParameter = '#mapParameterList';
			} else if(_item.type === 'KAKAO_MAP') {
				valueList = $('#kakaoMapValueList' + _item.index).children().children('li');
				columnList = $('#kakaoMapParameterList' + _item.index).children().children('li');

				itemParameter = '#kakaoMapParameterList';
			} else if(_item.type === 'KAKAO_MAP2') {
				valueList = $('#kakaoMap2ValueList' + _item.index).children().children('li');
				columnList = $('#kakaoMap2ParameterList' + _item.index).children().children('li');

				itemParameter = '#kakaoMap2ParameterList';
			} else if(_item.type === 'HISTOGRAM_CHART') {
				valueList = $('#histogramchartValueList' + _item.index).children().children('li');
//				columnList = $('#histogramchartParameterList' + _item.index).children().children('li');

//				itemParameter = '#histogramchartParameterList';
			} else if(_item.type === 'HEATMAP') {
				valueList = $('#heatmapValueList' + _item.index).children().children('li');
				columnList = $('#heatmapParameterList' + _item.index).children().children('li');
				hiddenList = $('#heatmap_hide_measure_list' + _item.index).children().children('li');

				itemParameter = '#heatmapParameterList';
				itemHidden = '#heatmap_hide_measure_list';
			} else if(_item.type === 'HEATMAP2') {
				valueList = $('#heatmap2ValueList' + _item.index).children().children('li');
				columnList = $('#heatmap2ParameterList' + _item.index).children().children('li');
				hiddenList = $('#heatmap2_hide_measure_list' + _item.index).children().children('li');


				itemParameter = '#heatmap2ParameterList';
				itemHidden = '#heatmap2_hide_measure_list';
			} else if(_item.type === 'SYNCHRONIZED_CHARTS') {
				valueList = $('#syncchartValueList' + _item.index).children().children('li');
				columnList = $('#syncchartParameterList' + _item.index).children().children('li');
				hiddenList = $('#syncchart_hide_measure_list' + _item.index).children().children('li');


				itemParameter = '#syncchartParameterList';
				itemHidden = '#syncchart_hide_measure_list';
			}else if(_item.type === 'GAUGE_CHART') {
				valueList = $('#gaugeValueList' + _item.index).children().children('li');
				columnList = $('#gaugeSeriesList' + _item.index).children().children('li');

				itemParameter = '#gaugeSeriesList';
			} else if(_item.type === 'CARD_CHART') {
				valueList = $('#cardValueList' + _item.index).children().children('li');
				columnList = $('#cardSeriesList' + _item.index).children().children('li');
				rowList = $('#cardSparkline' + _item.index).children().children('li');

				itemParameter = '#cardSeriesList';
				itemSeries = '#cardSparkline';
				//20200728 ajkim 카드 정렬 기준 항목 추가 dogfoot
				hiddenList = $('#card_hide_measure_list' + _item.index).children().children('li');
			} else if(_item.type === 'BUBBLE_D3') {
				valueList = $('#bubbled3ValueList' + _item.index).children().children('li');
				columnList = $('#bubbled3ParameterList' + _item.index).children().children('li');

				itemParameter = '#bubbled3ParameterList';
			} else if(_item.type === 'HIERARCHICAL_EDGE') {
				columnList = $('#hierarchicalParameterList' + _item.index).children().children('li');

				itemParameter = '#hierarchicalParameterList';
			} else if(_item.type === 'FORCEDIRECT') {
				valueList = $('#forceDirectValueList' + _item.index).children().children('li');
				columnList = $('#forceDirectParameterList' + _item.index).children().children('li');

				itemParameter = '#forceDirectParameterList';
			} else if(_item.type === 'FORCEDIRECTEXPAND') {
				valueList = $('#forceDirectExpandValueList' + _item.index).children().children('li');
				columnList = $('#forceDirectExpandParameterList' + _item.index).children().children('li');

				itemParameter = '#forceDirectExpandParameterList';
			/* DOGFOOT ktkang 버블차트2 추가  20200716  */
			} else if(_item.type === 'BUBBLE_CHART') {
				valueList = $('#bubbleChartValueList' + _item.index).children().children('li');
				columnList = $('#bubbleChartXList' + _item.index).children().children('li');
				rowList = $('#bubbleChartYList' + _item.index).children().children('li');

				itemParameter = '#bubbleChartXList';
				itemSeries = '#bubbleChartYList';
			}
		//2020.04.09 mksong 비정형 사용자정의데이터 추가일 경우 관계체크 오류 수정 dogfoot
		var $dataSetLookUp = $("#dataSetLookUp");
		
		if(WISE.Constants.editmode == "viewer" && $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp").length > 0){
			$dataSetLookUp = $("#dataArea_"+WISE.Constants.pid+" #dataSetLookUp");
		}
		var lookUpIns = $dataSetLookUp.dxLookup('instance');
		var dsId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(lookUpIns.option('value'));
		var regExp = /[\[\]]/gi;

		if(valueList.length == 0) {
			gDashboard.dataSetCreate.cubeRelationTable = [];
			if(typeof $("#cubeRelation").dxCheckBox('instance') != 'undefined') {
				$("#cubeRelation").dxCheckBox('instance').option('tabIndex', 1);
			}
		} else if(valueList.length > 0) {
			gDashboard.dataSetCreate.cubeRelationTable = [];
			var uni_nmList = [];
			$.each(valueList, function(_j, _k){
				var itemValue = $(_k);
				if(!itemValue.attr('isCustomField') && itemValue.attr('data-field-type') == 'measure' && !itemValue.hasClass('delta-drop')){
					if(typeof itemValue.attr('cubeuninm') != 'undefined') {
						/* DOGFOOT ktkang 주제영역에서 항목 추가시 오류 수정  20200404 */
						var measureDuple = [];
						$.each(valueList, function(_i, _e){
							if(!$(_e).hasClass('delta-drop')){
								if(measureDuple.indexOf($(_e).attr('cubeuninm').split('.')[0]) == -1) {
									measureDuple.push($(_e).attr('cubeuninm').split('.')[0]);
									var duplicatedCheck = false;
									$.each(uni_nmList, function(_ii, _uni_nm){
										if(_uni_nm == itemValue.attr('cubeuninm').split('.')[0].replace(regExp, "")){
											duplicatedCheck = true;
										}
									});
									if(!duplicatedCheck){
										/* DOGFOOT ktkang 주제영역 관계 오류 수정  20200909 */
										if(itemValue.attr('cubeuninm').split('.')[0].indexOf('[') > -1) {
											uni_nmList.push(itemValue.attr('cubeuninm').split('.')[0].replace(regExp, ""));
										}
									}
								}
							}
						});
						if(measureDuple.length < 2) {
							gDashboard.dataSetCreate.cubeRelationTable.push(itemValue.attr('cubeuninm').split('.')[0]);
						}
					}
				}
			});

			/* DOGFOOT ktkang 주제영역 연결 정렬기준 항목 체크 추가  20201125 */
			if(hiddenList.length > 0) {
				$.each(hiddenList, function(_j, _k){
					var itemValue = $(_k);
					if(!itemValue.attr('isCustomField') && itemValue.attr('data-field-type') == 'measure' && !itemValue.hasClass('delta-drop')){
						if(typeof itemValue.attr('cubeuninm') != 'undefined') {
							/* DOGFOOT ktkang 주제영역에서 항목 추가시 오류 수정  20200404 */
							var measureDuple = [];
							$.each(hiddenList, function(_i, _e){
								if(!$(_e).hasClass('delta-drop')){
									if(measureDuple.indexOf($(_e).attr('cubeuninm').split('.')[0]) == -1) {
										measureDuple.push($(_e).attr('cubeuninm').split('.')[0]);
										var duplicatedCheck = false;
										$.each(uni_nmList, function(_ii, _uni_nm){
											if(_uni_nm == itemValue.attr('cubeuninm').split('.')[0].replace(regExp, "")){
												duplicatedCheck = true;
											}
										});
										if(!duplicatedCheck){
											/* DOGFOOT ktkang 주제영역 관계 오류 수정  20200909 */
											if(itemValue.attr('cubeuninm').split('.')[0].indexOf('[') > -1) {
												uni_nmList.push(itemValue.attr('cubeuninm').split('.')[0].replace(regExp, ""));
											}
										}
									}
								}
							});
							if(measureDuple.length < 2) {
								gDashboard.dataSetCreate.cubeRelationTable.push(itemValue.attr('cubeuninm').split('.')[0]);
							}
						}
					}
				});
			}

			$.each(uni_nmList,function(_j, _uni_nm){
				$.ajax({
					type : 'post',
					/* DOGFOOT ktkang 주제영역 관계 오류 수정  20200310 */
					async: false,
					url : WISE.Constants.context + '/report/cubeRelationList.do',
					data:{
						'cube_id': gDashboard.dataSourceManager.datasetInformation[dsId].DATASRC_ID,
						'uni_nm' : _uni_nm
					},
					success : function(data) {
						var newRelationList = [];
						if(_j == 0) {
							gDashboard.dataSetCreate.cubeRelationTable = gDashboard.dataSetCreate.cubeRelationTable.concat(data.relationTableList);
						} else {
							$.each(data.relationTableList, function(_i, _e){
								$.each(gDashboard.dataSetCreate.cubeRelationTable, function(_ii, _ee){
									if(_e == _ee) {
										newRelationList.push(_e);
										return false;
									}
								});
							});
							
							/* DOGFOOT syjin 주제엉역 불러오기 오류 수정  20210303 */
							gDashboard.dataSetCreate.cubeRelationTable = gDashboard.dataSetCreate.cubeRelationTable.concat(newRelationList);
						}
						/* DOGFOOT ktkang 주제영역에서 항목 추가시 오류 수정  20200404 */
						var removeList = [];

						$.each(columnList, function(_i, _col){
							if(typeof $(_col).attr('cubeuninm') != 'undefined' && !(gDashboard.dataSetCreate.cubeRelationTable.indexOf($(_col).attr('cubeuninm').split('.')[0]) != -1)) {
								removeList.push($(_col).attr('title'));
								$(_col).parent().remove();
								if($(itemParameter + itemNum).children().length == 0){
									self.recovery($(itemParameter + itemNum));
								}
								/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
								if(itemParameter2 !== undefined) {
									if($(itemParameter2 + itemNum).children().length == 0){
										self.recovery($(itemParameter2 + itemNum));
									}
								}
								if(itemParameter3 !== undefined) {
									if($(itemParameter3 + itemNum).children().length == 0){
										self.recovery($(itemParameter3 + itemNum));
									}
								}
							}
						});

						$.each(rowList, function(_i, _row){
							if(typeof $(_row).attr('cubeuninm') != 'undefined' && !(gDashboard.dataSetCreate.cubeRelationTable.indexOf($(_row).attr('cubeuninm').split('.')[0]) != -1)) {
								removeList.push($(_row).attr('title'));
								$(_row).parent().remove();
								if($(itemSeries + itemNum).children().length == 0){
									self.recovery($(itemSeries + itemNum));
								}
							}
						});

						$.each(hiddenList, function(_i, _hie){
							if(typeof $(_hie).attr('cubeuninm') != 'undefined' && !(gDashboard.dataSetCreate.cubeRelationTable.indexOf($(_hie).attr('cubeuninm').split('.')[0]) != -1)) {
								removeList.push($(_hie).attr('title'));
								$(_hie).parent().remove();
								if($(itemHidden + itemNum).children().length == 0){
									self.recovery($(itemHidden));
								}
							}
						});


						$.each(gDashboard.parameterFilterBar.parameterInformation, function(_i, _o) {
							if(!(gDashboard.dataSetCreate.cubeRelationTable.indexOf(_o['UNI_NM'].split('.')[0]) != -1)) {
								delete gDashboard.parameterFilterBar.parameterInformation[_o.PARAM_NM];
								var paramList = [];
								gDashboard.structure.ReportMasterInfo.paramJson = [];
								$.each(gDashboard.parameterFilterBar.parameterInformation,function(_i,_items){
									paramList.push(_items);
									gDashboard.structure.ReportMasterInfo.paramJson.push(_items);
								});

								var paramNm;
								if(typeof _o.BASKET != 'undefined') {
									paramNm = _o.BASKET.replace(':dxTextBox', '');
								} else {
									paramNm = 'param_' + _o.PARAM_NM.replace('@', '');
								}
								$('#' + paramNm).parent().remove();
								removeList.push(_o.PARAM_CAPTION);
							}
						});

						if(removeList.length > 0) {
							compMoreMenuUi();
							if(removeList.length > 3) {
								WISE.alert('해당 측정값에 연결이 되어있지 않은<br/>' + removeList[0] + '' + removeList[1] + '' + removeList[2] + '등의 차원들은 데이터 항목 및 필터에서 삭제되었습니다.');
							} else {
								WISE.alert('해당 측정값에 연결이 되어있지 않은<br/>' + removeList + ' 차원들은 데이터 항목 및 필터에서 삭제되었습니다.');
							}
						}
					}
				});
			});

			/* DOGFOOT ktkang 주제영역 관계 오류 수정  20200407 */
			if(typeof $("#cubeRelation").dxCheckBox('instance') != 'undefined') {
				$("#cubeRelation").dxCheckBox('instance').option('tabIndex', 1);
			}
			//2020.04.09 mksong 비정형 사용자정의데이터 추가일 경우 관계체크 오류 수정 끝 dogfoot
		}
		}
		/* DOGFOOT ktkang 주제영역 관계 표시 부분 오류 수정 끝  20200308 */
	}

	this.dataItemSetting = function(dropType, _fieldItem, dataItem , container, prevContainer, targetContainer, _item, dropQuantity){
		var containerType;
		if (container == 'delta-drop') {
			containerType = 'delta-drop';
		} else if (container.toLowerCase().indexOf('sparkline') !== -1) {
			containerType = 'sparkline';
		} else {
			containerType = container.substring(0,container.lastIndexOf('t')+1);
		}

		if(containerType != 'allList'){
			if((containerType == 'bubbleChartXList' || containerType == 'bubbleChartYList') && $('#'+container+' .other-menu').length > 1){
				WISE.alert('X축과 Y축에는 각각 하나의 필드만 넣을 수 있습니다.');
				$(dataItem).remove();
				return;
			}

			if((containerType == 'onewayAnovaObservedList' || containerType == 'onewayAnovaFactorList1') && $('#'+container+' .analysis-data').length > 0){
				WISE.alert('해당 영역에 데이터 항목을 <br> 더이상 넣을 수 없습니다.');
				$(dataItem).remove();
				return;
			}

			var prevContainerType = prevContainer.substring(0,prevContainer.lastIndexOf('t')+1);

//			var dataItem = _fieldItem;

			if(dropType == 'drop'){
				dataItem = dataItem.clone();
			}

			var divideMenu = $(dataItem).children('.divide-menu');
			dataItem.removeClass('btn neutral');

			var dataItemNo;
			var dataItemNum;
			if(prevContainerType == 'allList'){
				dataItemNum = gDashboard.fieldManager.dataItemNo;
				dataItemNo = 'DataItem'+dataItemNum;
				dataItem.attr('dataitem',dataItemNo);
				dataItem.attr('caption',dataItem.text());
				// 2020.01.07 mksong 필드에 타이틀 추가 dogfoot
				dataItem.attr('title',dataItem.text());
				gDashboard.fieldManager.dataItemNo++;
			}else{
				dataItemNo = dataItem.attr('dataitem');
				//20200720 ajkim 변동측정값 오류 수정 dogfoot
				if(!dataItemNo){
					dataItemNum = gDashboard.fieldManager.dataItemNo
				}else
					/* DOGFOOT ktkang IE 에서 오류 수정  20201112 */
					dataItemNum = parseInt(dataItemNo.substr(dataItemNo.lastIndexOf('m')+1));
				if(container.indexOf('hide_measure') === -1 && prevContainer.indexOf('hide_measure') !== -1){
					dataItem.attr('data-field-type', dataItem.attr('originType'))
				}
			}

//			if(prevContainerType == 'chartValueList' || prevContainerType == 'columnList'){
//				var currentIndex = $("#"+prevContainer).children().index(dataItem);
//				if(currentIndex > 0){
//					$("#"+prevContainer).children().get(currentIndex+1).remove();
//				}
//
//				$(dataItem).width('100%');
//				dataItem.addClass('arrayUp other-menu');
//			}

			if(containerType == 'delta-drop'){
				dataItem.draggable(gDashboard.dragNdropController.draggableOptions);
			}else{
				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);
			}
			dataItem.removeClass('btn neutral');
			dataItem.width('100%');
			dataItem.children('.ico').addClass('btn neutral')
			if(typeof dataItem.attr('originType') === 'undefined'){
				if(dataItem.attr('data-field-type') == 'dimension'){
					dataItem.attr('originType','dimension');
//					dataItem.find('.more-link').children('.on').toggleClass('on');
//					dataItem.find('.more-link').find('.summaryType').parent().removeClass('on');
//					dataItem.find('.more-link').find('[summaryType|="count"]').parent().toggleClass('on');
				}else{
					dataItem.attr('originType','measure');
				}
			}

			dataItem.attr('prev-container', container)
			.attr('style','position: relative;')
			.removeClass('wise-drag');

			var insertTarget;
			if(containerType != 'delta-drop' && containerType != 'sparkline' && containerType != 'cardSparkline'){
				if(dropType == 'drop'){
					if(dropQuantity == 'single'){
						insertTarget = targetContainer.children().get(targetContainer.find(dataItem.parent()).index());
						dataItem.insertBefore(insertTarget);
					}else{
						insertTarget = targetContainer.children().get(targetContainer.find(dataItem).index());
						dataItem.insertAfter(insertTarget);
					}
				}else{
					if(targetContainer.is('ul')){
						insertTarget = targetContainer;
						dataItem.insertBefore(insertTarget);
					}else{
						insertTarget = targetContainer.children('li');
						dataItem.insertBefore(insertTarget);
					}
				}
			}else{
				if(containerType != 'delta-drop'){
					targetContainer.children().empty();
				}
			}

			if(container != 'delta-drop')
				dataItem.wrap('<ul class="display-unmove more analysis-data sortable"/>');

			if(dataItem.hasClass("wise-area-field-de"))
				dataItem.draggable(gDashboard.dragNdropController.draggableOptionsDE2);
			else
				dataItem.draggable(gDashboard.dragNdropController.draggableOptions2);


			var isRemoved = false;
			/* DOGFOOT ktkang 주제영역에서 항목 추가시 오류 수정  20200404 */
			if ((WISE.Context.isCubeReport && containerType != 'pivot_hide_measure_list' && dropQuantity != 'multiple') || (WISE.Context.isCubeReport && containerType != 'adhoc_hide_measure_list' && dropQuantity != 'multiple') ){
				if((containerType == 'dataList' && dataItem.attr('data-field-type') != 'measure') || ((containerType == 'rowList' || containerType == 'colList') && dataItem.attr('data-field-type') != 'dimension')){
					WISE.alert('주제영역을 사용하실 때 측정값은 측정값 부분에 차원은 행이나 열 부분에 넣으셔야 합니다.');
					dataItem.parent().remove();
					isRemoved = true;
				}
			}else{
				var fType = dataItem.attr('data-field-type');

				if((container.indexOf("rowList") >= 0 || container.indexOf("colList") >= 0 || container.indexOf("Parameter") > 0) &&
					fType === 'measure' && gDashboard.reportType === 'AdHoc')
				{
					dataItem.parent().remove();
					WISE.alert('비정형 보고서에서는 측정값을 측정값 항목에 넣으셔야 합니다.');
					return;
				}else if((container.indexOf("Value") >= 0 || container.indexOf("data") >= 0) && fType === 'dimension' && gDashboard.reportType === 'AdHoc'){
					dataItem.parent().remove();
					WISE.alert('비정형 보고서에서는 차원을 차원(행/열) 항목에 넣으셔야 합니다.');
					return;
				}
			}

			if(!isRemoved){
				switch(containerType){
					case 'delta-drop':
						dataItem.children('.btn').width('calc(100% - 35px)');
						dataItem.insertAfter(targetContainer);
						targetContainer.remove();

						var actualField = $(dataItem.parent().children('li').get(0));
						actualField.attr('target-field-uninm',dataItem.attr('uni_nm'));
						actualField.attr('target-field-dataitem',dataItem.attr('dataitem'));
						actualField.attr('target-field-caption',dataItem.attr('caption'));
						actualField.attr('target-field-origintype',dataItem.attr('origintype'));

						dataItem.attr('actualField', actualField.attr('dataitem'));

						self.appendFieldOptionMenu(dataItem,'delta',false);
						self.addFormat(dataItem);
						self.fieldRename(dataItem);

						dataItem.attr('dataType','delta');
						dataItem.attr('originType',dataItem.attr('data-field-type'));
						dataItem.attr('data-field-type','measure');
						dataItem.attr('dataType','measure');
						dataItem.attr('detailType','value');
						dataItem.addClass('drop-target delta-drop');
						break;
					case 'sparkline':
					case 'cardSparkline':
						dataItem.attr('dataType','sparklineArgument');
						dataItem.children('.btn').width('100%');
						dataItem.appendTo(targetContainer.children());
						targetContainer.children().addClass('analysis-data');
						dataItem.addClass('arrayUp');
//						self.appendFieldOptionMenu(dataItem,'dimension',false);
						dataItem.attr('dataType','sparklineArgument');
						break;
					case 'columnList':
					/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
					case 'onewayAnovaObservedList':
					case 'onewayAnovaFactorList':
					case 'onewayAnova2ObservedList':
					case 'onewayAnova2FactorList':
					case 'onewayAnova2ItemList':
					case 'twowayAnovaObservedList':
					case 'twowayAnovaFactorList':
					case 'pearsonsCorrelationNumericalList':
					case 'spearmansCorrelationNumericalList':
					case 'simpleRegressionIndpnList':
					case 'simpleRegressionDpndnList':
					case 'simpleRegressionVectorList':
					case 'multipleRegressionIndpnList':
					case 'multipleRegressionDpndnList':
					case 'multipleRegressionVectorList':
					case 'logisticRegressionIndpnList':
					case 'logisticRegressionDpndnList':
					case 'logisticRegressionVectorList':
					case 'multipleLogisticRegressionIndpnList':
					case 'multipleLogisticRegressionDpndnList':
					case 'multipleLogisticRegressionVectorList':
					case 'rFieldList':
					case 'tTestNumericalList':
					case 'zTestNumericalList':
					case 'chiTestNumericalList':
					case 'fTestNumericalList':
					/* DOGFOOT ktkang 다변량분석 추가  20210215 */
					case 'multivariateParameterList':
					case 'multivariateNumericalList':
						//20201112 ajkim 통게분석 그리드 오른쪽 아이콘 제거 dogfoot
						if(gDashboard.reportType !== 'StaticAnalysis' && gDashboard.reportType !== 'RAnalysis'  && gDashboard.reportType !== 'DSViewer'){
							dataItem.children('.btn').width('calc(100% - 35px)');
						}
						var insertOtherBtn = dataItem.children('a.btn');

						if(dataItem.attr('dataType') == 'sparkline'){
							self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
							dataItem.attr('originType','sparkline');
							dataItem.attr('dataType','sparkline');
							dataItem.attr('detailType','sparkline');
							/*dogfoot 크롬 다운로드시 데이터항목 아이콘 레이아웃 깨지는 오류 수정 shlim 20200717*/
							//20201112 통게분석 그리드 오른쪽 아이콘 제거 dogfoot
							if(gDashboard.reportType !== 'StaticAnalysis' && gDashboard.reportType !== 'RAnalysis' && gDashboard.reportType !== 'DSViewer'){
								$('<a id="'+ dataItemNo +'" href="#" class="otherBtn" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_graph.png" alt></a>').insertAfter(insertOtherBtn);
								self.addEventChangeType(dataItem.find('.otherBtn'));
							}
						}else if(dataItem.attr('dataType') == 'delta'){
							self.appendFieldOptionMenu(dataItem,'delta',false);

							//20201112 통게분석 그리드 오른쪽 아이콘 제거 dogfoot
							if(gDashboard.reportType !== 'StaticAnalysis' && gDashboard.reportType !== 'RAnalysis' && gDashboard.reportType !== 'DSViewer'){
								$('<a id="'+ dataItemNo +'" href="#" class="otherBtn delta" style="height: 66px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_triangle.png" alt></a>').insertAfter(insertOtherBtn);
								self.addEventChangeType(dataItem.find('.otherBtn'));
							}

							if(dataItem.attr('target-field-uninm') != undefined){
								var targetField = $('<li class="drop-target delta-drop other-menu wise-area-field wise-column-chooser" style="margin-top: 0px; height: 31px;" drop-type="deltaTarget"><a href="#" class="ico sigma btn neutral" style="width: calc(100% - 35px);"><div class="fieldName">'+ dataItem.attr('target-field-caption') +'</div></a></li>');
								dataItem.parent().append(targetField);

								targetField.attr('UNI_NM',dataItem.attr('target-field-uninm'));
								targetField.attr('dataitem',dataItem.attr('target-field-dataitem'));
								targetField.attr('caption',dataItem.attr('target-field-caption'));
								targetField.attr('origintype',dataItem.attr('target-field-origintype'));
								targetField.attr('dataType','delta');
								targetField.attr('originType',dataItem.attr('data-field-type'));
								targetField.attr('detailType','value');
								targetField.attr('data-field-type',dataItem.attr('data-field-type'));
								targetField.attr('prev-container','delta-drop');

								self.appendFieldOptionMenu(targetField,'delta',false);
								self.addFormat(targetField);
								self.fieldRename(targetField);
								if(dataItem.hasClass("wise-area-field-de"))
									targetField.draggable(gDashboard.dragNdropController.draggableOptionsDE2);
								else
									targetField.draggable(gDashboard.dragNdropController.draggableOptions2);
							}else{
								var targetField = $('<li id="delta-drop' + self.item.index + '_'+ ($('.delta-drop').length + 1) + '" class="drop-target delta-drop" style="margin-top: 0px;height: 31px;margin-bottom: 4px;" drop-type="deltaTarget"><a href="#" class="btn neutral" style="width: calc(100% - 35px); margin-bottom: 4px;">' + gMessage.get('WISE.message.page.widget.drop.target') + '</a></li>');
								dataItem.parent().append(targetField);
							}
							$('.delta-drop').droppable(self.droppableOptions);
						}else{
							if(dataItem.attr('data-field-type') == 'dimension'){
								self.appendFieldOptionMenu(dataItem,'dimension',divideMenu);
								if(gDashboard.reportType !== 'DSViewer')
									dataItem.addClass('arrayUp');
								dataItem.attr('originType','dimension');
								dataItem.attr('dataType','dimension');
								dataItem.attr('data-field-type','dimension');
								/*dogfoot 통계 분석 추가 shlim 20201103*/
								dataItem.attr('containerType',containerType);
								/*dogfoot 크롬 다운로드시 데이터항목 아이콘 레이아웃 깨지는 오류 수정 shlim 20200717*/
								//20201112 통게분석 그리드 오른쪽 아이콘 제거 dogfoot
								if(gDashboard.reportType !== 'StaticAnalysis' && gDashboard.reportType !== 'RAnalysis' && gDashboard.reportType !== 'DSViewer'){
									$('<a id="'+ dataItemNo +'" href="#" class="otherBtn" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_axis.png" alt></a>').insertAfter(insertOtherBtn);
									self.addEventChangeType(dataItem.find('.otherBtn'));
								}
								self.activeGridOption(dataItem);
							}else if(dataItem.attr('data-field-type') == 'measure'){
								self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
								dataItem.attr('originType','measure');
								dataItem.attr('dataType','measure');
								dataItem.attr('data-field-type','measure');
								dataItem.attr('detailType','value');
								/*dogfoot 통계 분석 추가 shlim 20201103*/
								dataItem.attr('containerType',containerType);
								/*dogfoot 크롬 다운로드시 데이터항목 아이콘 레이아웃 깨지는 오류 수정 shlim 20200717*/
								//20201112 통게분석 그리드 오른쪽 아이콘 제거 dogfoot
								if(gDashboard.reportType !== 'StaticAnalysis' && gDashboard.reportType !== 'RAnalysis'  && gDashboard.reportType !== 'DSViewer'){
									$('<a id="'+ dataItemNo +'" href="#" class="otherBtn" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_sigma.png" alt></a>').insertAfter(insertOtherBtn);
									self.addEventChangeType(dataItem.find('.otherBtn'));
								}
							}
						}
						break;
					case 'chartValueList':
						dataItem.children('.btn').width('calc(100% - 35px)');
						self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
						if (typeof self.itemFormat !== undefined) {
							dataItem.data('formatOptions', self.itemFormat);
						}
						var dataItemId = container + '_' + dataItemNo;
						if(dropType !='drop' && self.itemData != undefined){
							$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgSourceForSeriesType(self.itemData.seriesType)+'.png" alt></a>').insertAfter(dataItem.children('a.btn'));
						}else{
							$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(self.item)+'.png" alt></a>').insertAfter(dataItem.children('a.btn'));
						}

						var dataItemOptions = dataItem.find('#' + dataItemId);
						if (typeof self.itemData !== 'undefined') {
							dataItemOptions.data('dataItemOptions', self.itemData);
						} else {
							self.addChartDataItemOptions(self.item, dataItemNo, dataItemOptions);
						}
						dataItemOptions.on('click',function(e){
							self.dataItemOptionsWindow(this);
							e.preventDefault();
						});
						break;
					case 'rangebarchartValueList':
						dataItem.children('.btn').width('calc(100% - 35px)');
						self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
						if (typeof self.itemFormat !== undefined) {
							dataItem.data('formatOptions', self.itemFormat);
						}
						var dataItemId = container + '_' + dataItemNo;
						if(dropType !='drop' && self.itemData != undefined){
							$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgSourceForSeriesType(self.itemData.seriesType)+'.png" alt></a>').insertAfter(dataItem.children('a.btn'));
						}else{
							$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(self.item)+'.png" alt></a>').insertAfter(dataItem.children('a.btn'));
						}

						var dataItemOptions = dataItem.find('#' + dataItemId);
						if (typeof self.itemData !== 'undefined') {
							dataItemOptions.data('dataItemOptions', self.itemData);
						} else {
							self.addChartDataItemOptions(self.item, dataItemNo, dataItemOptions);
						}
						dataItemOptions.on('click',function(e){
							self.dataItemRangeBarOptionsWindow(this);
							e.preventDefault();
						});

						if(dataItem.parent().hasClass('display-move-wrap')){
							thisItem = dataItem.children('li');
						}else{
							thisItem = dataItem;
						}

						thisItem.removeClass('arrayUp');
						thisItem.removeClass('arrayDown');
						thisItem.attr('dataType','delta');
						thisItem.addClass('drop-target');

						thisItem.find('.otherBtn').addClass('delta');
						thisItem.attr('detailtype','value');

						if(thisItem.parent().find('.drop-target').length == 1){
							thisItem.parent().append($('<li id="delta-drop' + self.item.index + '_'+ ($('.delta-drop').length + 1) + '" class="drop-target delta-drop" style="margin-top: 0px;height: 31px;margin-bottom: 4px;" drop-type="deltaTarget"><a href="#" class="btn neutral" style="width: calc(100% - 35px); margin-bottom: 4px;">' + gMessage.get('WISE.message.page.widget.drop.target') + '</a></li>'));
							thisItem.find('.otherBtn').height('66px');
							//thisItem.find('.otherBtn').append('<img src="' + WISE.Constants.context + '/resources/main/images/ico_triangle.png" alt>');
						}
						$('.delta-drop').droppable(this.droppableOptions);
						break;
					case 'rangeareachartValueList':
						dataItem.children('.btn').width('calc(100% - 35px)');
						self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
						if (typeof self.itemFormat !== undefined) {
							dataItem.data('formatOptions', self.itemFormat);
						}
						var dataItemId = container + '_' + dataItemNo;
						if(dropType !='drop' && self.itemData != undefined){
							$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgSourceForSeriesType(self.itemData.seriesType)+'.png" alt></a>').insertAfter(dataItem.children('a.btn'));
						}else{
							$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(self.item)+'.png" alt></a>').insertAfter(dataItem.children('a.btn'));
						}

						var dataItemOptions = dataItem.find('#' + dataItemId);
						if (typeof self.itemData !== 'undefined') {
							dataItemOptions.data('dataItemOptions', self.itemData);
						} else {
							self.addChartDataItemOptions(self.item, dataItemNo, dataItemOptions);
						}
						dataItemOptions.on('click',function(e){
							self.dataItemRangeAreaOptionsWindow(this);
							e.preventDefault();
						});

						if(dataItem.parent().hasClass('display-move-wrap')){
							thisItem = dataItem.children('li');
						}else{
							thisItem = dataItem;
						}

						thisItem.removeClass('arrayUp');
						thisItem.removeClass('arrayDown');
						thisItem.attr('dataType','delta');
						thisItem.addClass('drop-target');

						thisItem.find('.otherBtn').addClass('delta');
						thisItem.attr('detailtype','value');

						if(thisItem.parent().find('.drop-target').length == 1){
							thisItem.parent().append($('<li id="delta-drop' + self.item.index + '_'+ ($('.delta-drop').length + 1) + '" class="drop-target delta-drop" style="margin-top: 0px;height: 31px;margin-bottom: 4px;" drop-type="deltaTarget"><a href="#" class="btn neutral" style="width: calc(100% - 35px); margin-bottom: 4px;">' + gMessage.get('WISE.message.page.widget.drop.target') + '</a></li>'));
							thisItem.find('.otherBtn').height('66px');
							//thisItem.find('.otherBtn').append('<img src="' + WISE.Constants.context + '/resources/main/images/ico_triangle.png" alt>');
						}
						$('.delta-drop').droppable(this.droppableOptions);
						break;
					case 'bubbleChartValueList':
//						dataItem.children('.btn').width('calc(100% - 35px)');
						self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
						if (typeof self.itemFormat !== undefined) {
							dataItem.data('formatOptions', self.itemFormat);
						}
						var dataItemId = container + '_' + dataItemNo;
						$('<a id="'+ dataItemId +'" href="#seriesOptions" class="chart seriesoption"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgForSeriesType(self.item)+'.png" alt></a>').insertAfter(dataItem.children('a.btn'));
						var dataItemOptions = dataItem.find('#' + dataItemId);
						if (typeof self.itemData !== 'undefined') {
							dataItemOptions.data('dataItemOptions', self.itemData);
						} else {
							self.addChartDataItemOptions(self.item, dataItemNo, dataItemOptions);
						}
						$('#'+dataItemId).css('display', 'none');
						dataItemOptions.on('click',function(e){
							self.dataItemOptionsWindow(this);
							e.preventDefault();
						});
						break;
					case 'dataList':
					case 'dataAdHocList':
						if(gDashboard.reportType == 'AdHoc' || _item.isAdhocItem){
							dataItem.children('.btn').width('calc(100% - 35px)');
							self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
							if (typeof self.itemFormat !== undefined) {
								dataItem.data('formatOptions', self.itemFormat);
							}
							var dataItemId = container + '_' + dataItemNum;
							if(dropType !='drop' && self.itemData != undefined){
								$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_'+self.getImgSourceForSeriesType(self.itemData.seriesType)+'.png" alt></a>').insertAfter(dataItem.children('a.btn'));
							}else{
								$('<a id="'+ dataItemId +'" href="#seriesOptions" class="otherBtn chart seriesoption" style="height:30px;"><img src="' + WISE.Constants.context + '/resources/main/images/ico_bar1.png" alt></a>').insertAfter(dataItem.children('a.btn'));
							}

							var dataItemOptions = dataItem.find('#' + dataItemId);
							if (typeof self.itemData !== 'undefined') {
								dataItemOptions.data('dataItemOptions', self.itemData);
							} else {
								self.addAdhocChartDataItemOptions(dataItemNum, dataItemOptions);
							}
							dataItemOptions.on('click',function(e){
								self.dataItemOptionsWindow(this);
								e.preventDefault();
							});
						}else{
							self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
						}
						/* DOGFOOT ktkang 측정값에 차원 올렸을 때 오류 수정  20200318 */
						dataItem.attr('data-field-type','measure');
						/* DOGFOOT ktkang 빠져있는 부분 추가  20200619 */
						break;
					case 'pieValueList':
					case 'mapValueList':
					case 'treemapValueList':
					case 'textboxValueList':
					case 'cardValueList':
					case 'gaugeValueList':
					case 'parallelValueList':
					case 'bubblepackchartValueList':
					case 'wordcloudv2ValueList':
					case 'dendrogrambarchartValueList':
					case 'calendarviewchartValueList':
					case 'calendarview2chartValueList':
					case 'calendarview3chartValueList':
					case 'collapsibletreechartValueList':
//					case 'rangebarchartValueList':
//					case 'rangeareachartValueList':
					case 'timelinechartValueList':
					case 'RectangularAreaChartValueList':
					case 'wordcloudValueList':
					case 'histogramchartValueList':
					case 'bubbled3ValueList':
					case 'waterfallchartValueList':
					case 'bipartitechartValueList':
					case 'pyramidchartValueList':
					case 'funnelchartValueList':
					case 'sankeychartValueList':
					case 'starchartValueList':
					case 'heatmapValueList':
					case 'syncchartValueList':
					case 'heatmap2ValueList':
					case 'forceDirectValueList':
					/* DOGFOOT syjin 카카오 지도 추가  20200820 */
					case 'kakaoMapValueList':
					case 'kakaoMap2ValueList':
					case 'kakaoMapLatitudeList':
					case 'kakaoMapLongitudeList':
					case 'forceDirectExpandValueList':
					case 'divergingchartValueList':
					case 'scatterplot2ZList':
//					case 'scatterplotValueList':
					case 'liquidfillgaugeValueList':
					case 'boxplotValueList':
//					case 'dependencywheelValueList':
					case 'sequencessunburstValueList':
						if(gDashboard.reportType != 'AdHoc'){
							self.appendFieldOptionMenu(dataItem,'measure',divideMenu);
							dataItem.attr('dataType','measure');
							dataItem.attr('data-field-type','measure');
						}
						//2020.07.22 mksong 카드 측정값 최대 2개 가능하도록 수정 dogfoot
						if(containerType == 'cardValueList' && dropType == 'receive'){
							if(targetContainer.children().length > 2){
								$(targetContainer.children().get(targetContainer.children().length-2)).remove();
								WISE.alert('해당 영역에 데이터 항목을 <br> 더이상 넣을 수 없습니다.');
							}
						}

						//DOGFOOT syjin 2020-12-04 카카오 지도 측정값 최대 1개 가능하도록 수정
						if(containerType == 'kakaoMapValueList' && dropType == 'receive'){
							if(targetContainer.children().length > 1){
								$(targetContainer.children().get(targetContainer.children().length-2)).remove();
								WISE.alert('해당 영역에 데이터 항목을 <br> 더이상 넣을 수 없습니다.');
							}
						}
						break;
					case 'pivot_hide_measure_list':
					case 'adhoc_hide_measure_list':
						if(gDashboard.reportType == 'AdHoc' || _item.isAdhocItem){
							if(dataItem.attr('data-field-type') == 'dimension'){
//								self.appendFieldOptionMenu(dataItem,'dimension',divideMenu);
								dataItem.removeClass('arrayUp');
								dataItem.removeClass('arrayDown');
								dataItem.attr('originType','dimension');
								dataItem.attr('dataType','dimension');
							}else if(dataItem.attr('data-field-type') == 'measure'){
								self.appendFieldOptionMenu(dataItem,'hiddenMeasure',divideMenu);
								dataItem.attr('originType','measure');
								dataItem.attr('dataType','measure');
							}
						}
					case 'grid_hide_measure_list':
					case 'chart_hide_measure_list':
					case 'pie_hide_measure_list':
					case 'textbox_hide_measure_list':
					case 'listbox_hide_measure_list':
					case 'combobox_hide_measure_list':
					case 'treeview_hide_measure_list':
					case 'card_hide_measure_list':
					case 'scatterplot_hide_measure_list':
					case 'scatterplot2_hide_measure_list':
					case 'divergingchart_hide_measure_list':
					case 'heatmap_hide_measure_list':
					case 'heatmap2_hide_measure_list':
					case 'syncchart_hide_measure_list':
						dataItem.children('a').width('');
						if(gDashboard.reportType != 'AdHoc'){
							self.appendFieldOptionMenu(dataItem,'hiddenMeasure',divideMenu);
							dataItem.attr('dataType','measure');
							dataItem.attr('originType', dataItem.data('field-type'));
							dataItem.attr('data-field-type','measure');
						}

						break;
					case 'deltavalueList':
						dataItem.children('a').width('');

						break;
					case 'kakaoMapAddressList':
						dataItem.children('a').width('');
						self.appendFieldOptionMenu(dataItem,'address',divideMenu);
						self.synchronizeAddressTypeList(dataItem.find('.other-menu-ico'));
						self.activeGridOption(dataItem);
						break;
					default:
						dataItem.children('a').width('');
						if(container != 'downloadexpand_colList')
							self.appendFieldOptionMenu(dataItem,'dimension',divideMenu);
						//20201029 AJKIM SortBy 기능  없는 곳에서 화살표 표시 제거 dogfoot
						var noSort = false;
						if(containerType.indexOf("historyTimeline") > -1 || containerType.indexOf("plot") > -1 || containerType.indexOf("Plot") > -1
								|| containerType.indexOf("arc") > -1 || containerType.indexOf("bubbled3") > -1 || containerType.indexOf("wordcloud") > -1
								|| containerType.indexOf("Rectangular") > -1 || containerType.indexOf("plot") > -1 || containerType.indexOf("waterfall") > -1
								|| containerType.indexOf("bipart") > -1 || containerType.indexOf("dependency") > -1
								|| containerType.indexOf("hierarchical") > -1 || containerType.indexOf("forceDirect") > -1 || containerType.indexOf("calendarview") > -1
								|| containerType.indexOf("calendarview") > -1 || containerType.indexOf("sunburst") > -1 || containerType.indexOf("dendrogram") > -1
								|| containerType.indexOf("collapsibletreechart") > -1 || containerType.indexOf("radialTidyTree") > -1 || containerType.indexOf("parallel") > -1
								|| containerType.indexOf("bubblepackchart") > -1 || containerType.indexOf("sankey") > -1 || prevContainer.indexOf("coordinate") > -1 || container == 'downloadexpand_colList'){
							noSort = true;
						}

						if(!noSort){
							if(gDashboard.reportType !== 'DSViewer')
							dataItem.addClass('arrayUp');
						}

						self.activeGridOption(dataItem);
						break;
				}

				dataItem.height('31px');
				dataItem.addClass('other-menu wise-area-field wise-column-chooser');
				//2020-01-14 LSH topN
				self.topNset(dataItem);
				self.fieldRename(dataItem);
				compMoreMenuUi();
				modalUi();

				if(dropType == 'drop'){
					if(containerType != 'sparkline' && containerType != 'cardSparkline' && containerType != 'delta-drop'){
						$('#'+container).droppable("option", "disabled", true );
						$('#'+container).sortable('enable');

						if(!$(targetContainer.children().get(targetContainer.children().length-1)).hasClass('analysis-data')){
							$(targetContainer.children().get(targetContainer.children().length-1)).remove();
						}
					}
				}

				if(WISE.Constants.editmode !== 'viewer'){
					if(gDashboard.reportType == 'AdHoc' || (_item && _item.isAdhocItem)){
						$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_adhocItem){
							/*dogfoot 뷰어 컬럼선택기 오류 수정 shlim 20200717*/
							if(WISE.Constants.editmode === 'viewer'){
								if(dataItem.attr('data-source-id') !== undefined){
									_adhocItem.dataSourceId = dataItem.attr('data-source-id');
								}
							}else{
								if(_item.adhocIndex == _adhocItem.adhocIndex && dataItem.attr('data-source-id') !== undefined){
									_adhocItem.dataSourceId = dataItem.attr('data-source-id');
								}
							}
						});
					}else{
						gDashboard.itemGenerateManager.focusedItem.dataSourceId = dataItem.attr('data-source-id');

					}
				}
				
				
				if(dropType == 'drop'){
					gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id',(_item? _item.dataSourceId : gDashboard.dataSourceDE));
				}

				//2020.03.09 MKSONG 그룹별 이동시 측정값그룹에 차원 컬럼이 첫번째로 위치한 경우 오류 수정 DOGFOOT
				if(targetContainer.children().length > 1){
					targetContainer.find('.unsortable').remove();
				}

				//검색10
				dataItem
					.children("div.wise-area-caption")
					.text(dataItem.children("div.wise-area-caption").text());
				//검색10

				/* update chart options in real time */
//				2019.12.16 mksong preferences config undefined 오류 수정 dogfoot
				if (gDashboard.preferences.config != undefined){
					if (gDashboard.preferences.config.autoUpdate) {
						var currentItem = gDashboard.itemGenerateManager.focusedItem;
						if (currentItem.dxItem && currentItem.type === 'SIMPLE_CHART') {
							currentItem.setChart();
							currentItem.bindData(currentItem.globalData, true);
						} else if (_item.type === 'SIMPLE_CHART') {
							gDashboard.itemGenerateManager.clearTrackingConditionAll();
							gDashboard.query();
						}
					}
				}

				if(prevContainerType != 'allList'){
					if(prevContainerType == 'sparkline'|| prevContainerType == 'cardSparkline' || prevContainerType == 'delta-drop'){
						$("#"+prevContainer).empty();
						self.recovery($("#"+prevContainer));
					}else{
						var isChild = $("#"+prevContainer).children().find(_fieldItem) == undefined;
						if(isChild){
							_fieldItem.remove();
							/* DOGFOOT ktkang 주제영역 관계 표시 부분 오류 수정  20200305 */
//						}else{
//							if(prevContainer == 'columnList'+_item.index || prevContainer == 'chartValueList'+_item.index){
//								$("#"+prevContainer).children().get(currentIndex).remove();
//							}
						}

						if(_fieldItem.attr('deltaid') != undefined && containerType !== "deltavalueList"){
							var deltaId  = _fieldItem.attr('deltaid');
							$.each(_item.deltaItems,function(_i,_delta){
								if(_delta.ID == deltaId){
									_item.deltaItems.splice(_i, 1);
									_item.deltaItemlength = _item.deltaItems.length;
									return false;
								}
							});
							if(_item.deltaItemlength === 0){
								$('#deltavalueList'+_item.adhocIndex).parent().css('display', 'none')
							}
						}else if(containerType !== "deltavalueList"){
							if(_fieldItem.parent().hasClass('display-unmove analysis-data')){
								_fieldItem.parent().remove();
								if($('#'+prevContainer).children().length == 0){
									self.recovery($('#'+prevContainer));
								}
//							} else {
//								_fieldItem.remove();
//								if($('#'+prevContainer).children().length == 0){
//									self.recovery($('#'+prevContainer));
//								}
							}
						}

						if($('#'+prevContainer).children().length == 0 && prevContainer != 'deltavalueList'){
							self.recovery($('#'+prevContainer));
						}else if(prevContainer == 'deltavalueList'){
							//2020.03.02 MKSONG recovery 부분 함수화 DOGFOOT
							var actualfield = gDashboard.fieldManager.panelManager["dataContentPanel"+gDashboard.fieldManager.stateFieldChooser.attr('id').substr(gDashboard.fieldManager.stateFieldChooser.attr('id').lastIndexOf('fieldManager')-1,1)].find('li[target-field-dataitem="'+$(dataItem).attr('dataitem')+'"]');
							self.recoveryDataGridDelta(actualfield);
						}

						if($("#"+prevContainer).children('.unsortable').length ==1){
							if(prevContainer.indexOf('sparkLine') == -1 && prevContainer.indexOf('cardSpark') == -1 ){
								$('#'+prevContainer).sortable('disable').droppable('enable');
							}
						}
					}
				}
			}
		}
	};

	this.appendFieldOptionMenu = function(dataItem, type, divideMenu){
		var prevContainer = dataItem.parent().attr("id")||dataItem.parent().parent().attr("id");
		var tempDiv = ''
			+'<div class="divide-menu other-menu">'
			+'<a href="#" class="other-menu-ico"></a>'
			+'<ul class="more-link right-type">'
				+'<li class="on"><a href="#" class="summaryType" summaryType="count">카운트</a></li>'
				+'<li><a href="#" class="summaryType" summaryType="countdistinct">고유 카운트</a></li>'
				+'<li><a href="#formatOptions" class="setFormat">Format...</a></li>'
				+'<li><a href="#" class="fieldRename">Rename...</a></li>'
				+'</ul>'
			+'</div>';
		
		/*dogfoot 포멧 정보를 레포트 마스터에서 가져오기 shlim 20210813 */
		var datas = [],dataField=undefined;
        if(gDashboard.reportType == 'AdHoc' && typeof gDashboard.structure.ReportMasterInfo.reportJson != 'undefined'){
           datas = gDashboard.structure.ReportMasterInfo.reportJson.DATA_ELEMENT.DATA;	

           $.each(datas,function(_i,_d){
           	    if(dataItem.attr('uni_nm') == _d.UNI_NM){
           	    	dataField = _d
           	    }
           })
        }

		if(dataItem.parent().find('.other-menu-ico').length == 0){
			if(type == 'measure'){
				/* 2020.05.13 tbchoi 대시보드에서 측정값이 아닌 차원을 필드 > 측정값 항목에 대입하면 합계,평균,최소/최대값은 사용할 수 없음 (CS참조)*/
				if(dataItem.attr('originType') == 'measure'){
					/*dogfoot 사용자정의 데이터  구분자 추가 shlim 20200716*/
					if(dataItem.attr('custom_data') == 'Y'){
					/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
//                        dataItem.parent().append(self.customMeasureFieldOptionMenu);
						/* DOGFOOT syjin 사용자 정의 데이터 필드 옵션 추가  20210305 */
						if(prevContainer && (prevContainer.indexOf("histogram")>-1 || prevContainer.indexOf("wordcloud")>-1)){
							 dataItem.parent().append(self.dimensionFieldOptionMenuNoTopNNoSort);
							 $(dataItem.parent().find(".fieldRename")).css('display', 'none');
						}else{
							 dataItem.parent().append(self.measureFieldOptionMenu);
							 /*dogfoot shlim 20210416*/
//							 $(dataItem.parent().find(".fieldRename")).css('display', 'none');
						}
					}else{
						//20201112 AJKIM 측정값 메뉴 필요없는 아이템 메뉴 제거 dogfoot
						if(prevContainer && (prevContainer.indexOf("histogram")>-1 || prevContainer.indexOf("wordcloud")>-1)){
							 dataItem.parent().append(self.dimensionFieldOptionMenuNoTopNNoSort);
						}else{
							 dataItem.parent().append(self.measureFieldOptionMenu);
						}
//					    dataItem.parent().append(self.measureFieldOptionMenu);
					}
				}else{
					if(prevContainer && (prevContainer.indexOf("histogram")>-1 || prevContainer.indexOf("wordcloud")>-1)){
						 dataItem.parent().append(self.dimensionFieldOptionMenuNoTopNNoSort);
					}else{
						dataItem.parent().append(tempDiv);
					}
				}
				self.addFormat(dataItem,dataField);
			}else if(type == 'dimension'){
				self.setDimensionFieldOptionMenu(dataItem.parent());
//				dataItem.parent().append(self.dimensionFieldOptionMenu);
			}else if(type == 'delta'){
				if(dataItem.attr('originType') == 'measure'){
					dataItem.parent().append(self.measureFieldOptionMenu);
				}else{
					dataItem.parent().append(tempDiv);
				}
			}else if(type == 'hiddenMeasure'){
				dataItem.parent().append(self.hiddenMeasureFieldOptionMenu);
				self.addFormat(dataItem,dataField);
			}else if(type == 'address'){
				dataItem.parent().append(self.addressFieldOptionMenu);
			}
		}else{
			if(type == 'delta'){
				if (!divideMenu) {
					if($($(dataItem).parent().children().get(dataItem.parent().children().index(dataItem)+1)).hasClass('divide-menu')){
						$($(dataItem).parent().children().get(dataItem.parent().children().index(dataItem)+1)).remove();
					}else{
						if(dataItem.attr('originType') == 'measure'){
							dataItem.parent().append(self.measureFieldOptionMenu);
						}else{
							dataItem.parent().append(tempDiv);
						}
					}
				}
				
			}else{
				if(divideMenu){
					dataItem.parent().find('.divide-menu').remove();
//					dataItem.parent().append(divideMenu);
					if(type == 'measure'){
						/* 2020.05.13 tbchoi 대시보드에서 측정값이 아닌 차원을 필드 > 측정값 항목에 대입하면 합계,평균,최소/최대값은 사용할 수 없음 (CS참조)*/
						if(dataItem.attr('originType') == 'measure'){
							dataItem.parent().append(self.measureFieldOptionMenu);
						}else{
							dataItem.parent().append(tempDiv);
						}
						self.addFormat(dataItem,dataField);
					}else if(type == 'dimension'){
						self.setDimensionFieldOptionMenu(dataItem.parent());
//						dataItem.parent().append(self.dimensionFieldOptionMenu);
					}else if(type == 'delta'){
						if(dataItem.attr('originType') == 'measure'){
							dataItem.parent().append(self.measureFieldOptionMenu);
						}else{
							dataItem.parent().append(tempDiv);
						}
					}else if(type == 'hiddenMeasure'){
						dataItem.parent().append(self.hiddenMeasureFieldOptionMenu);
						self.addFormat(dataItem,dataField);
					}else if(type == 'address'){
						dataItem.parent().append(self.addressFieldOptionMenu);
					}
				}
			}

			if(type != 'dimension' && type != 'address'){
				self.addFormat(dataItem);
			}
		}

		$('.other-menu-ico').draggable(gDashboard.dragNdropController.draggableOptions2);
		//20201112 AJKIM 통계 분석일 경우 필드 메뉴 제거 dogfoot
		if(gDashboard.reportType === 'StaticAnalysis' || gDashboard.reportType == 'DSViewer'){
			dataItem.parent().find('.divide-menu').remove();
		}
	};

	this.dataItemOptionsWindow = function(target){
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, _item) {
			if (_item.type === 'SIMPLE_CHART' && self.item.adhocIndex == _item.adhocIndex) {
				_item.initDataItemOptionsWindow(target);
			}
		});
	}
	this.dataItemRangeBarOptionsWindow = function(target){
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, _item) {
			if (_item.type === 'RANGE_BAR_CHART') {
				_item.initDataItemOptionsWindow(target);
			}
		});
	}
	this.dataItemRangeAreaOptionsWindow = function(target){
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, _item) {
			if (_item.type === 'RANGE_AREA_CHART') {
				_item.initDataItemOptionsWindow(target);
			}
		});
	}
}

