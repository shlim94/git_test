WISE.libs.Dashboard.item.InsertItemManager = function() {
	var self = this;
	
	this.init = function() {
		$('.insertItem').on('click', function(e) {
			e.preventDefault();

			var insertkind = e.currentTarget.id;
			var seriesType;
			if (insertkind == 'insertChart') {
				seriesType = $(e.currentTarget).attr('seriestype');
			}
			
			/* DOGFOOT ktkang 통계 변경 시 리프레시 제거  20201028 */
			if(gDashboard.reportType == "StaticAnalysis") {
				$.each($('.lm_close_tab'), function(i, e) {
					e.click();
				});
			}
			
			gDashboard.insertItemManager.insertItem(insertkind, seriesType);
		});
		/* DOGFOOT hsshim 2020-01-23 텝 컨테이너 추가하는 기능 개선 */
		$('#insertContainer').hover(function(e) {
			$('.tab_cont_box.selected').children('.lm_header').addClass('highlighted');
		}, function(e) {
			$('.tab_cont_box.selected').children('.lm_header').removeClass('highlighted');
		});
	};

	this.insertItem = function(_itemkind, _seriesType, _copyItem) {
		var item;
		var copyItem = _copyItem;
		var copy = false;

		if (_itemkind == 'copyItem') {
			copy = true;
			_itemkind = 'insert' + copyItem.kind.charAt(0).toUpperCase()
					+ copyItem.kind.slice(1);

			if (_itemkind == 'insertParallel') {
				_itemkind = 'insertParallelCoordinate';
			}
		}

		switch (_itemkind) {
			case 'insertPivotGrid':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','PivotGrid');
				item = new WISE.libs.Dashboard.item.PivotGridGenerator();
	
				item.kind = 'pivotGrid';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '피벗 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'pivotDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.columns = copyItem.columns;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.dataFields = copyItem.dataFields;
					item.rows = copyItem.rows;
					item.deltaItems = copyItem.deltaItems;
					item.highlightItems = copyItem.highlightItems;
					item.HiddenMeasures = copyItem.HiddenMeasures;
					item.CUSTOMIZED = copyItem.CUSTOMIZED;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PivotGridFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertDataGrid':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','DataGrid');
				item = new WISE.libs.Dashboard.item.DataGridGenerator();
	
				item.kind = 'dataGrid';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '그리드 ' + gDashboard.itemQuantity[item.kind];
				if(gDashboard.reportType === 'DSViewer') item.Name = "상세데이터";
				item.ComponentName = 'gridDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.columns = copyItem.columns;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.HiddenMeasures = copyItem.HiddenMeasures;
					item.CUSTOMIZED = copyItem.CUSTOMIZED;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','Chart');
				item = new WISE.libs.Dashboard.item.ChartGenerator();
	
				item.kind = 'chart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'chartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				var seriesType = _seriesType;
				if (copy) {
					seriesType = 'bar';
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					item.HiddenMeasures = copyItem.HiddenMeasures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
						seriesType = copyItem.meta.SeriesType;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				item.fieldManager.seriesType = seriesType;
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertBubbleChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','BubbleChart');
				item = new WISE.libs.Dashboard.item.BubbleChartGenerator();	
				item.kind = 'bubble';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '버블차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'bubbleChartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				var seriesType = _seriesType;
				if (copy) {
					seriesType = 'bubble';
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					item.HiddenMeasures = copyItem.HiddenMeasures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
						seriesType = copyItem.meta.SeriesType;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubbleChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				item.fieldManager.seriesType = seriesType;
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertPieChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','Pie');
				item = new WISE.libs.Dashboard.item.PieGenerator();
	
				item.kind = 'pieChart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '파이 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'pieDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					item.HiddenMeasures = copyItem.HiddenMeasures;
					item.values = copyItem.values;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PieFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertGauge':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','Gauge');
				/* DOGFOOT hsshim 2020-02-03 게이지 아이템 만드는 기능 작업 */
				item = new WISE.libs.Dashboard.item.GaugeGenerator();
	
				item.kind = 'gauge';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '게이지 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'gaugeDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.GaugeFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setGaugeAnalysisFieldArea(item);
				/* DOGFOOT hsshim 2020-02-03 끝 */
				break;
			case 'insertCard':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','Card');
				item = new WISE.libs.Dashboard.item.CardGenerator();
	
				item.kind = 'card';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '카드 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'cardDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CardFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertWordCloud' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','WordCloud');
				item = new WISE.libs.Dashboard.item.WordCloud();
				
				item.kind = 'wordcloud';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '워드클라우드 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'WordCloudDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				if(copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if(copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}

				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WordCloudFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertHeatMap':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','HeatMap');
				item = new WISE.libs.Dashboard.item.HeatMapGenerator();
	
				item.kind = 'heatmap';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '히트맵 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'heatmapDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HeatMapFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertHeatMap2':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','HeatMap2');
				item = new WISE.libs.Dashboard.item.HeatMap2Generator();
	
				item.kind = 'heatmap2';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '히트맵 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'heatmap2DashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HeatMap2FieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertSynchronizedChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','SynchronizedChart');
				item = new WISE.libs.Dashboard.item.SynchronizedChartGenerator();
	
				item.kind = 'syncchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '동기화 라인 차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'syncchartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SynchronizedChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertHistogramChart' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','HistogramChart');
				item = new WISE.libs.Dashboard.item.HistogramChartGenerator();
				
				item.kind = 'histogramchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '히스토그램 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'histogramchartDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				if(copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if(copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}

				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HistogramChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertParallelCoordinate':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ParallelCoordinate');
				item = new WISE.libs.Dashboard.item.ParallelCoorGenerator();
	
				item.kind = 'parallel';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '평행좌표계 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'parallelDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ParallelFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertBubblePackChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','BubblePackChart');
				item = new WISE.libs.Dashboard.item.BubblePackChartGenerator();
	
				item.kind = 'bubblepackchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '버블 팩 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'bubblepackchartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubblePackChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertWordCloudV2':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','WordCloudv2');
				item = new WISE.libs.Dashboard.item.WordCloudV2Generator();
	
				item.kind = 'wordcloudv2';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '워드클라우드2 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'wordcloudv2DashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WordCloudV2FieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertDendrogramBarChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','DendrogramBarChart');
				item = new WISE.libs.Dashboard.item.DendrogramBarChartGenerator();
	
				item.kind = 'dendrogrambarchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '신경망바차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'dendrogrambarchartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DendrogramBarChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertCalendarViewChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','CalendarView');
				item = new WISE.libs.Dashboard.item.CalendarViewChartGenerator();
	
				item.kind = 'calendarviewchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '캘린더뷰 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'calendarviewchartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarViewChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertCalendarView2Chart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','CalendarView2chart');
				item = new WISE.libs.Dashboard.item.CalendarView2ChartGenerator();
				
				item.kind = 'calendarview2chart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '캘린더2뷰 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'calendarview2chartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];
				
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarView2ChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertCalendarView3Chart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','CalendarView3chart');
				item = new WISE.libs.Dashboard.item.CalendarView3ChartGenerator();
				
				item.kind = 'calendarview3chart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '캘린더3뷰 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'calendarview3chartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];
				
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarView3ChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertCollapsibleTreeChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','CollapsibleTree');
				item = new WISE.libs.Dashboard.item.CollapsibleTreeChartGenerator();
				
				item.kind = 'collapsibletreechart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '신경망트리 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'collapsibletreechartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];
				
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CollapsibleTreeChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertRangeBarChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','RangeBar');
				item = new WISE.libs.Dashboard.item.RangeBarChartGenerator();
	
				item.kind = 'rangebarchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '레인지 바 차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'rangebarchartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				var seriesType = _seriesType;
				if (copy) {
					seriesType = 'rangeBar';
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					item.HiddenMeasures = copyItem.HiddenMeasures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
						seriesType = copyItem.meta.SeriesType;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RangeBarChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				item.fieldManager.seriesType = seriesType;
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertRangeAreaChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','RangeAreaChart');
				item = new WISE.libs.Dashboard.item.RangeAreaChartGenerator();
				
				item.kind = 'rangeareachart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '레인지 영역 차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'rangeareachartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];
				
				var seriesType = _seriesType;
				if (copy) {
					seriesType = 'rangearea';
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					item.HiddenMeasures = copyItem.HiddenMeasures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
						seriesType = copyItem.meta.SeriesType;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RangeAreaChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				item.fieldManager.seriesType = seriesType;
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertTimeLineChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','TimeLineChart');
				item = new WISE.libs.Dashboard.item.TimeLineChartGenerator();
	
				item.kind = 'timelinechart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '타임라인 차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'timelinechartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				var seriesType = _seriesType;
				if (copy) {
					seriesType = 'timeline';
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					item.HiddenMeasures = copyItem.HiddenMeasures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
						seriesType = copyItem.meta.SeriesType;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TimeLineChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				item.fieldManager.seriesType = seriesType;
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertChoroplethMap':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','Map.Choropleth');
				item = new WISE.libs.Dashboard.item.ChoroplethMapGenerator();
				item.kind = 'choroplethMap';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '지도 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'choroplethMapDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ChoroplethMapFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertTreemap':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','TreeMap');
				item = new WISE.libs.Dashboard.item.TreeMapGenerator();
				item.kind = 'Treemap';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '트리맵 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'treemapDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TreeMapFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertStarchart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','StarChart');
				item = new WISE.libs.Dashboard.item.StarChartGenerator();
				item.kind = 'Starchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '스타차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'starchartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.StarChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertImage': // ymbin
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','Image');
				item = new WISE.libs.Dashboard.item.ImageGenerator();
	
				item.kind = 'image';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '이미지 ' + gDashboard.itemQuantity[item.kind]; // WISE itemQuantity에 image 추가해야한다.
				item.ComponentName = 'imageDashboardItem' + gDashboard.itemQuantity[item.kind]; // ComponentName : // 이미지1, 이미지2, ...
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ImageFieldManager(); // slide_menu and field_menu manager
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				// Drag 하여 Data를 분석하는 부분?? -> 데이터 가져오고 데이터 드레그 시 오류 AnalysisFieldArea -> DragNDrop 고려
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertTextBox':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','TextBox');
				item = new WISE.libs.Dashboard.item.TextBoxGenerator();
	
				item.kind = 'textBox';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '텍스트 상자 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'textBoxDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TextBoxFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertListBox' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ListBox');
				item = new WISE.libs.Dashboard.item.ListBoxGenerator();
				
				item.kind = 'listBox';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '목록 상자 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'listBoxDashboardItem' + gDashboard.itemQuantity[item.kind];

				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ListBoxFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertTreeView' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','TreeView');
				item = new WISE.libs.Dashboard.item.TreeViewGenerator();
				
				item.kind = 'treeView';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '트리 보기 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'treeViewDashboardItem' + gDashboard.itemQuantity[item.kind];

				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TreeViewFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertComboBox' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ComboBox');
				item = new WISE.libs.Dashboard.item.ComboBoxGenerator();
				
				item.kind = 'comboBox';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '콤보 상자 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'comboBoxDashboardItem' + gDashboard.itemQuantity[item.kind];

				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ComboBoxFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertRectangularAreaChart' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','RectangularAreaChart');
				item = new WISE.libs.Dashboard.item.RectangularAreaChartGenerator();
				
				item.kind = 'RectangularAreaChart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '네모차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'RectangularAreaChartDashboardItem' + gDashboard.itemQuantity[item.kind];

				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RectangularAreaChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertWaterfallchart' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','WaterfallChart');
				item = new WISE.libs.Dashboard.item.WaterfallChartGenerator();
				
				item.kind = 'waterfallchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '폭포수차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'waterfallchartDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				if(copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if(copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WaterfallChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertBipartitechart' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','BipartiteChart');
				item = new WISE.libs.Dashboard.item.BipartiteChartGenerator();
				
				item.kind = 'bipartitechart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '이분법차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'bipartitechartDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				if(copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if(copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BipartiteChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertFunnelChart' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','FunnelChart');
				item = new WISE.libs.Dashboard.item.FunnelChartGenerator();
				
				item.kind = 'funnelchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '퍼널차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'funnelchartDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				if(copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if(copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.FunnelChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertPyramidChart' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','PyramidChart');
				item = new WISE.libs.Dashboard.item.PyramidChartGenerator();
				
				item.kind = 'pyramidchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '피라미드차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'pyramidchartDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				if(copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if(copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PyramidChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertSankeychart' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','SankeyChart');
				item = new WISE.libs.Dashboard.item.SankeyChartGenerator();
				
				item.kind = 'sankeychart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '샌키차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'sankeychartDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				if(copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if(copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SankeyChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertBubbleD3' :
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','BubbleD3');
				item = new WISE.libs.Dashboard.item.BubbleD3Generator();
				
				item.kind = 'bubbled3';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = 'D3버블차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'bubbled3DashboardItem' + gDashboard.itemQuantity[item.kind];
				
				if(copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if(copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubbleD3FieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertForceDirect':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ForceDirect');
				item = new WISE.libs.Dashboard.item.ForceDirectGenerator();
	
				item.kind = 'forceDirect';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '네트워크-축소 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'forceDirectDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ForceDirectFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertDivergingChart':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','DivergingChart');
				item = new WISE.libs.Dashboard.item.DivergingChartGenerator();
	
				item.kind = 'divergingchart';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '긍정/부정비교 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'divergingchartDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DivergingChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;	
			case 'insertScatterPlot':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ScatterPlot');
				item = new WISE.libs.Dashboard.item.ScatterPlotGenerator();
	
				item.kind = 'scatterplot';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '산점도 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'scatterplotDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ScatterPlotFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;	
			case 'insertScatterPlot2':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ScatterPlot2');
				item = new WISE.libs.Dashboard.item.ScatterPlot2Generator();
	
				item.kind = 'scatterplot2';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '버블차트2 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'scatterplot2DashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ScatterPlot2FieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertRadialTidyTree':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','RadialTidyTree');
				item = new WISE.libs.Dashboard.item.RadialTidyTreeGenerator();
	
				item.kind = 'radialtidytree';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '방사형 신경망 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'radialtidytreeDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RadialTidyTreeFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertScatterPlotMatrix':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ScatterPlotMatrix');
				item = new WISE.libs.Dashboard.item.ScatterPlotMatrixGenerator();
	
				item.kind = 'scatterplotmatrix';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '산점도 행렬 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'scatterplotmatrixDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ScatterPlotMatrixFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertHistoryTimeline':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','HistoryTimeline');
				item = new WISE.libs.Dashboard.item.HistoryTimelineGenerator();
	
				item.kind = 'historytimeline';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '타임라인 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'historytimelineDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HistoryTimelineFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertArcDiagram':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ArcDiagram');
				item = new WISE.libs.Dashboard.item.ArcDiagramGenerator();
	
				item.kind = 'arcdiagram';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '아크 다이어그램 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'arcdiagramDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ArcDiagramFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertDependencyWheel':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','DependencyWheel');
				item = new WISE.libs.Dashboard.item.DependencyWheelGenerator();
	
				item.kind = 'dependencywheel';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '의존성 휠 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'dependencywheelDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DependencyWheelFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;	
			case 'insertSequencesSunburst':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','SequencesSunburst');
				item = new WISE.libs.Dashboard.item.SequencesSunburstGenerator();
	
				item.kind = 'sequencessunburst';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '선버스트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'sequencessunburstDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SequencesSunburstFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;	
			case 'insertBoxPlot':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','BoxPlot');
				item = new WISE.libs.Dashboard.item.BoxPlotGenerator();
	
				item.kind = 'boxplot';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '박스플롯' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'boxplotDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BoxPlotFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;	
			case 'insertCoordinateLine':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','CoordinateLine');
				item = new WISE.libs.Dashboard.item.CoordinateLineGenerator();
	
				item.kind = 'coordinateline';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '평면좌표라인 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'coordinatelineDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CoordinateLineFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;	
			case 'insertCoordinateDot':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','CoordinateDot');
				item = new WISE.libs.Dashboard.item.CoordinateDotGenerator();
	
				item.kind = 'coordinatedot';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '평면좌표점 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'coordinatedotDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CoordinateDotFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertLiquidFillGauge':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','LiquidFillGauge');
				item = new WISE.libs.Dashboard.item.LiquidFillGaugeGenerator();
	
				item.kind = 'liquidfillgauge';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '액체게이지' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'liquidfillgaugeDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.LiquidFillGaugeFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;	
			case 'insertForceDirectExpand':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','ForceDirectExpand');
				item = new WISE.libs.Dashboard.item.ForceDirectExpandGenerator();
	
				item.kind = 'forceDirectExpand';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '네트워크-확대 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'forceDirectExpandDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					item.seriesDimensions = copyItem.seriesDimensions;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ForceDirectExpandFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;								
			// KERIS 수정
			case 'insertContainer':
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				if ((gDashboard.reportType === 'DashAny' || gDashboard.reportType == 'StaticAnalysis')) {
					gDashboard.insertItemManager.generateItemContainer('container');
				}
				return;
			case 'insertAdHocItem':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','AdhocItem');
				var isAdhocItem = false;
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i,_item){
					if(_item.isAdhocItem){
						isAdhocItem = true;
					}
				});
				
				if(isAdhocItem){
					WISE.alert('보고서에 비정형 아이템은 1개만 존재할 수 있습니다.');
				}else{
					var fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();

					gDashboard.itemQuantity[fieldManager.focusItemType]++;
					
					//chart 넣기
					//2020.11.06 mksong resource Import 동적 구현 dogfoot
					WISE.loadedSourceCheck('itemJS','Chart');
					var item = new WISE.libs.Dashboard.item.ChartGenerator();
					item.kind = 'chart';
					gDashboard.fieldManager = item.fieldManager = fieldManager;
					item.fieldManager.focusItemType = 'adhocItem';					
					gDashboard.itemQuantity[item.kind]++;
					item.Name = '차트 '+ gDashboard.itemQuantity[item.kind];
					item.ComponentName = 'chartDashboardItem' + gDashboard.itemQuantity[item.kind];
					item.isAdhocItem = true;
					item.adhocIndex = gDashboard.itemQuantity[gDashboard.fieldManager.focusItemType];
					
					item.index = gDashboard.itemQuantity[item.kind];
					item.fieldManager.index = item.adhocIndex;
					item.fieldManager.seriesType = 'Bar';
					item.itemid = item.ComponentName + '_item';
					
					//피벗 생성
					//2020.11.06 mksong resource Import 동적 구현 dogfoot
					WISE.loadedSourceCheck('itemJS','PivotGrid');
					var item2 = new WISE.libs.Dashboard.item.PivotGridGenerator();
					item2.kind = 'pivotGrid';
					gDashboard.fieldManager = item2.fieldManager = fieldManager;
					item2.fieldManager.focusItemType = 'adhocItem';
					gDashboard.itemQuantity[item2.kind]++;
					item2.Name = '피벗 '+ gDashboard.itemQuantity[item2.kind];
					item2.ComponentName = 'pivotDashboardItem' + gDashboard.itemQuantity[item2.kind];
					item2.isAdhocItem = true;
					item2.adhocIndex = gDashboard.itemQuantity[gDashboard.fieldManager.focusItemType];

					item2.index = gDashboard.itemQuantity[item2.kind];
					item2.fieldManager.index = item2.adhocIndex;
					
					gDashboard.fieldChooser.setAnalysisFieldArea(item2, true);
					item2.itemid = item2.ComponentName + '_item';
					
					// initialize chart and pivot
					gDashboard.itemGenerateManager.dxItemBasten.push(item2);
					gDashboard.itemGenerateManager.dxItemBasten.push(item);
					
					gDashboard.insertItemManager.generateItemContainer(item, true);
					gDashboard.insertItemManager.generateItemContainer(item2, true);
					gDashboard.itemGenerateManager.init();
					item2.dragNdropController = new WISE.widget.DragNDropController(item2);
					item2.dragNdropController.addDroppableOptions(item2);
					item.dragNdropController = item2.dragNdropController;	
				}
				return;
			case 'insertHierarchicalEdge':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','HierarchicalEdge');
				item = new WISE.libs.Dashboard.item.HierarchicalEdgeGenerator();
	
				item.kind = 'hierarchical';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '계층차트 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'hierarchicalDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HierarchicalFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			/* DOGFOOT syjin 카카오 지도 widget 추가 20200820 */		
			case 'insertKakaoMap':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','Map.KakaoMap');
				item = new WISE.libs.Dashboard.item.KakaoMapGenerator();
				item.kind = 'kakaoMap';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '카카오 지도 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'kakaoMapDashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.KakaoMapFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'insertKakaoMap2':
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				WISE.loadedSourceCheck('itemJS','Map.KakaoMap2');
				item = new WISE.libs.Dashboard.item.KakaoMap2Generator();
				item.kind = 'kakaoMap2';
				gDashboard.itemQuantity[item.kind]++;
				item.Name = '카카오 지도 ' + gDashboard.itemQuantity[item.kind];
				item.ComponentName = 'kakaoMap2DashboardItem'
						+ gDashboard.itemQuantity[item.kind];
	
				if (copy) {
					item.arguments = copyItem.arguments;
					item.dimensions = copyItem.dimensions;
					item.measures = copyItem.measures;
					if (copyItem.meta) {
						item.meta = copyItem.meta;
						item.meta.ComponentName = item.ComponentName;
						item.meta.Name = item.Name;
					}
				}
	
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.KakaoMap2FieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
			case 'insertOnewayAnova':
			case 'insertOnewayAnova2':
			case 'insertTwowayAnova':
				WISE.loadedSourceCheck('itemJS','DataGrid');
				WISE.loadedSourceCheck('itemJS','BoxPlot');
				gDashboard.itemGenerateManager.dxItemBasten = [];
				gDashboard.analysisType = _itemkind;
				
				var focusItemType;
				if(gDashboard.analysisType === 'insertOnewayAnova') {
					focusItemType = 'onewayAnova';
				} else if(gDashboard.analysisType === 'insertTwowayAnova') {
					focusItemType = 'twowayAnova';
				} else {
					focusItemType = 'onewayAnova2';
				}
				
				var fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
				
				item = new WISE.libs.Dashboard.item.DataGridGenerator();
				item.kind = 'dataGrid';
				gDashboard.fieldManager = item.fieldManager = fieldManager;
				gDashboard.itemQuantity[item.kind]++;
				item.index = gDashboard.itemQuantity[item.kind];
				item.Name = '데이터';
				item.fieldManager.focusItemType = focusItemType;
				item.focusItemType = focusItemType;
				
				gDashboard.itemQuantity[item.fieldManager.focusItemType]++;
				item.fieldManager.index = 1;
				
				item.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item.kind];

				item2 = new WISE.libs.Dashboard.item.DataGridGenerator();
				item2.kind = 'dataGrid';
				gDashboard.fieldManager = item2.fieldManager = fieldManager;
				gDashboard.itemQuantity[item2.kind]++;
				item2.index = gDashboard.itemQuantity[item2.kind];
				item2.Name = '분석결과표';
				item2.fieldManager.focusItemType = focusItemType;
				item2.focusItemType = focusItemType;
				item2.fieldManager.index = 1;
				
				item2.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item2.kind];

				if(focusItemType == 'onewayAnova') {
					item4 = new WISE.libs.Dashboard.item.DataGridGenerator();
					item4.kind = 'dataGrid';
					gDashboard.fieldManager = item4.fieldManager = fieldManager;
					gDashboard.itemQuantity[item4.kind]++;
					item4.index = gDashboard.itemQuantity[item4.kind];
					item4.Name = '기술통계';
					item4.fieldManager.focusItemType = focusItemType;
					item4.focusItemType = focusItemType;
					item4.fieldManager.index = 1;
					
					item4.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item4.kind];
					
					
					item5 = new WISE.libs.Dashboard.item.DataGridGenerator();
					item5.kind = 'dataGrid';
					gDashboard.fieldManager = item5.fieldManager = fieldManager;
					gDashboard.itemQuantity[item5.kind]++;
					item5.index = gDashboard.itemQuantity[item5.kind];
					item5.Name = '그룹별 기술통계';
					item5.fieldManager.focusItemType = focusItemType;
					item5.focusItemType = focusItemType;
					item5.fieldManager.index = 1;
					
					item5.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item5.kind];
					
					
					item6 = new WISE.libs.Dashboard.item.DataGridGenerator();
					item6.kind = 'dataGrid';
					gDashboard.fieldManager = item6.fieldManager = fieldManager;
					gDashboard.itemQuantity[item6.kind]++;
					item6.index = gDashboard.itemQuantity[item6.kind];
					item6.Name = '도수분포표';
					item6.fieldManager.focusItemType = focusItemType;
					item6.focusItemType = focusItemType;
					item6.fieldManager.index = 1;
					
					item6.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item6.kind];
				} else {
					item4 = new WISE.libs.Dashboard.item.DataGridGenerator();
					item4.kind = 'dataGrid';
					gDashboard.fieldManager = item4.fieldManager = fieldManager;
					gDashboard.itemQuantity[item4.kind]++;
					item4.index = gDashboard.itemQuantity[item4.kind];
					item4.Name = '기술통계';
					item4.fieldManager.focusItemType = focusItemType;
					item4.focusItemType = focusItemType;
					item4.fieldManager.index = 1;
					
					item4.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item4.kind];
					
					
					item5 = new WISE.libs.Dashboard.item.DataGridGenerator();
					item5.kind = 'dataGrid';
					gDashboard.fieldManager = item5.fieldManager = fieldManager;
					gDashboard.itemQuantity[item5.kind]++;
					item5.index = gDashboard.itemQuantity[item5.kind];
					item5.Name = '교차분석';
					item5.fieldManager.focusItemType = focusItemType;
					item5.focusItemType = focusItemType;
					item5.fieldManager.index = 1;
					
					item5.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item5.kind];
				}
				
				item3 = new WISE.libs.Dashboard.item.BoxPlotGenerator();
				item3.kind = 'boxplot';
				gDashboard.fieldManager = item3.fieldManager = fieldManager;
				gDashboard.itemQuantity[item3.kind]++;
				item3.index = gDashboard.itemQuantity[item3.kind];
				item3.Name = '분석전 시각화';
				item3.fieldManager.focusItemType = focusItemType;
				item3.focusItemType = focusItemType;
				item3.fieldManager.index = 1;
				
				item3.ComponentName = 'boxplotDashboardItem' + gDashboard.itemQuantity[item3.kind];

				gDashboard.itemGenerateManager.dxItemBasten.push(item);
				gDashboard.itemGenerateManager.dxItemBasten.push(item2);
				gDashboard.itemGenerateManager.dxItemBasten.push(item3);
				if(focusItemType == 'onewayAnova') {
					gDashboard.itemGenerateManager.dxItemBasten.push(item4);
					gDashboard.itemGenerateManager.dxItemBasten.push(item5);
					gDashboard.itemGenerateManager.dxItemBasten.push(item6);
				} else {
					gDashboard.itemGenerateManager.dxItemBasten.push(item4);
					gDashboard.itemGenerateManager.dxItemBasten.push(item5);
				}
				

				/*dogfoot 통계 화면 초기 아이템 설정 shlim 20201012*/
				
//				gDashboard.insertItemManager.generateItemContainer(item, false);
//				gDashboard.insertItemManager.generateItemContainer(item2, false);				
//    			gDashboard.insertItemManager.generateItemContainer(item3, false);
				
				/*dogfoot 컨테이너에 담을 아이템 리스트 생성 shlim 20201021*/
				var itemList = [];
				
				/*dogfoot 컨테이너에 담을 아이템 생성 shlim 20201021*/
				itemList.push(item)
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"데이터셋");
				
				/*dogfoot 컨테이너에 담을 아이템 생성 shlim 20201021*/
				itemList=[]
				itemList.push(item2);
				if(focusItemType == 'onewayAnova') {
					itemList.push(item4);
					itemList.push(item5);
					itemList.push(item6);
				} else {
					itemList.push(item4);
					itemList.push(item5);
				}
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"통계분석");
				
				itemList=[]
				itemList.push(item3);
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"시각화");
				
//				진짜
//				gDashboard.insertItemManager.generateAysItemContainer(item,false,"AysItem");
//				gDashboard.insertItemManager.generateAysItemContainer(item2,false,"AysItem");
//				gDashboard.insertItemManager.generateAysItemContainer(item3,false,"AysItem");
				
				gDashboard.fieldChooser.setAnalysisFieldArea(item, false);
				gDashboard.itemGenerateManager.init();
				
				item.dragNdropController = new WISE.widget.DragNDropController(item); 
				item.dragNdropController.addDroppableOptions(item); 
				item2.dragNdropController = item.dragNdropController;
				item3.dragNdropController = item2.dragNdropController;
			
				return;
			case 'insertPearsonsCorrelation':
			case 'insertSpearmansCorrelation':
				WISE.loadedSourceCheck('itemJS','DataGrid');
				WISE.loadedSourceCheck('itemJS','ScatterPlotMatrix');
				WISE.loadedSourceCheck('itemJS','HeatMap2');
				gDashboard.itemGenerateManager.dxItemBasten = [];
				/*dogfoot 통계 분석 추가 shlim 20201102*/
				gDashboard.analysisType = _itemkind;
				var focusItemType;
				
				switch(_itemkind) {
					case 'insertPearsonsCorrelation':
						focusItemType = 'pearsonsCorrelation';
						break;
					case 'insertSpearmansCorrelation':
						focusItemType = 'spearmansCorrelation';
						break;
					default:
						break;
				}
				
				var fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
				
				item = new WISE.libs.Dashboard.item.DataGridGenerator();
				item.kind = 'dataGrid';
				gDashboard.fieldManager = item.fieldManager = fieldManager;
				gDashboard.itemQuantity[item.kind]++;
				item.index = gDashboard.itemQuantity[item.kind];
				item.Name = '데이터';
				item.fieldManager.focusItemType = focusItemType;
				item.focusItemType = focusItemType;
				gDashboard.itemQuantity[item.fieldManager.focusItemType]++;
				item.fieldManager.index = 1;
				
				item.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				item2 = new WISE.libs.Dashboard.item.DataGridGenerator();
				item2.kind = 'dataGrid';
				gDashboard.fieldManager = item2.fieldManager = fieldManager;
				gDashboard.itemQuantity[item2.kind]++;
				item2.index = gDashboard.itemQuantity[item2.kind];
				item2.Name = '분석결과표';
				item2.fieldManager.focusItemType = focusItemType;
				item2.focusItemType = focusItemType;
				item2.fieldManager.index = 1;
				
				item2.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item2.kind];
				
				item4 = new WISE.libs.Dashboard.item.DataGridGenerator();
				item4.kind = 'dataGrid';
				gDashboard.fieldManager = item4.fieldManager = fieldManager;
				gDashboard.itemQuantity[item4.kind]++;
				item4.index = gDashboard.itemQuantity[item4.kind];
				item4.Name = '기술통계';
				item4.fieldManager.focusItemType = focusItemType;
				item4.focusItemType = focusItemType;
				item4.fieldManager.index = 1;
				
				item4.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item4.kind];
				
								
				
				
				item3 = new WISE.libs.Dashboard.item.ScatterPlotMatrixGenerator();
				item3.kind = 'scatterplotmatrix';
				gDashboard.fieldManager = item3.fieldManager = fieldManager;
				gDashboard.itemQuantity[item3.kind]++;
				item3.index = gDashboard.itemQuantity[item3.kind];
				item3.Name = '분석전 시각화';
				item3.fieldManager.focusItemType = focusItemType;
				item3.focusItemType = focusItemType;
				item3.fieldManager.index = 1;
				
				item3.ComponentName = 'scatterplotmatrixDashboardItem' + gDashboard.itemQuantity[item3.kind];
				
				item5 = new WISE.libs.Dashboard.item.HeatMap2Generator();
				item5.kind = 'heatmap2';
				gDashboard.fieldManager = item5.fieldManager = fieldManager;
				
				gDashboard.itemQuantity[item5.kind] = 0;
				gDashboard.itemQuantity[item5.kind]++;
				item5.index = gDashboard.itemQuantity[item5.kind];
				item5.Name = '분석후 시각화';
				item5.fieldManager.focusItemType = focusItemType;
				item5.focusItemType = focusItemType;
				item5.fieldManager.index = 1
				
				item5.ComponentName = 'heatmap2DashboardItem' + gDashboard.itemQuantity[item5.kind];
				
				gDashboard.itemGenerateManager.dxItemBasten.push(item);
				gDashboard.itemGenerateManager.dxItemBasten.push(item2);
				gDashboard.itemGenerateManager.dxItemBasten.push(item3);
				gDashboard.itemGenerateManager.dxItemBasten.push(item4);
				gDashboard.itemGenerateManager.dxItemBasten.push(item5);
				
				/*dogfoot 컨테이너에 담을 아이템 리스트 생성 shlim 20201021*/
				var itemList = [];
				
				/*dogfoot 컨테이너에 담을 아이템 생성 shlim 20201021*/
				itemList.push(item)
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"데이터셋");
				
				/*dogfoot 컨테이너에 담을 아이템 생성 shlim 20201021*/
				itemList=[]
				itemList.push(item2);
				itemList.push(item4);
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"통계분석");
				
				itemList=[]
				itemList.push(item3);
				itemList.push(item5);
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"시각화");
				
				gDashboard.fieldChooser.setAnalysisFieldArea(item, false);
				gDashboard.itemGenerateManager.init();
				
				item.dragNdropController = new WISE.widget.DragNDropController(item); 
				item.dragNdropController.addDroppableOptions(item); 
				item2.dragNdropController = item.dragNdropController;
				item3.dragNdropController = item2.dragNdropController;
				
				return;
			case 'insertSimpleRegression':
			case 'insertMultipleRegression':
			case 'insertLogisticRegression':
			case 'insertMultipleLogisticRegression':
				WISE.loadedSourceCheck('itemJS','DataGrid');
				WISE.loadedSourceCheck('itemJS','ScatterPlot');
				WISE.loadedSourceCheck('itemJS','HeatMap2');
				gDashboard.itemGenerateManager.dxItemBasten = [];
				gDashboard.analysisType = _itemkind;
				var focusItemType;
				
				switch(_itemkind) {
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
					default:
						break;
				}
				
				var fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
				
				item = new WISE.libs.Dashboard.item.DataGridGenerator();
				item.kind = 'dataGrid';
				gDashboard.fieldManager = item.fieldManager = fieldManager;
				
				gDashboard.itemQuantity[item.kind] = 0;
				gDashboard.itemQuantity[item.kind]++;
				item.index = gDashboard.itemQuantity[item.kind];
				item.Name = '데이터';
				item.fieldManager.focusItemType = focusItemType;
				item.focusItemType = focusItemType;
				gDashboard.itemQuantity[item.fieldManager.focusItemType]++;
				item.fieldManager.index = 1;
				
				item.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item.kind];

				switch(_itemkind) {
					case 'insertSimpleRegression':
					case 'insertMultipleRegression':
						item2 = new WISE.libs.Dashboard.item.DataGridGenerator();
						item2.kind = 'dataGrid';
						gDashboard.fieldManager = item2.fieldManager = fieldManager;
						gDashboard.itemQuantity[item2.kind]++;
						item2.index = gDashboard.itemQuantity[item2.kind];
						item2.Name = '회귀분석 통계량';
						item2.fieldManager.focusItemType = focusItemType;
						item2.focusItemType = focusItemType;
						item2.fieldManager.index = 1;
						
						item2.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item2.kind];
	
						item3 = new WISE.libs.Dashboard.item.ScatterPlotGenerator();
						item3.kind = 'scatterplot';
						gDashboard.fieldManager = item3.fieldManager = fieldManager;
						
						gDashboard.itemQuantity[item3.kind] = 0;
						gDashboard.itemQuantity[item3.kind]++;
						item3.index = gDashboard.itemQuantity[item3.kind];
						item3.Name = '분석 후 시각화'
						item3.fieldManager.focusItemType = focusItemType;
						item3.focusItemType = focusItemType;
						item3.fieldManager.index = 1;

						item3.ComponentName = 'scatterplotDashboardItem' + gDashboard.itemQuantity[item3.kind];

						item4 = new WISE.libs.Dashboard.item.DataGridGenerator();
						item4.kind = 'dataGrid';
						gDashboard.fieldManager = item4.fieldManager = fieldManager;
						gDashboard.itemQuantity[item4.kind]++;
						item4.index = gDashboard.itemQuantity[item4.kind];
						item4.Name = '분산분석';
						item4.fieldManager.focusItemType = focusItemType;
						item4.focusItemType = focusItemType;
						item4.fieldManager.index = 1;
						
						item4.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item4.kind];
		                
	
		                item5 = new WISE.libs.Dashboard.item.DataGridGenerator();
						item5.kind = 'dataGrid';
						gDashboard.fieldManager = item5.fieldManager = fieldManager;
						gDashboard.itemQuantity[item5.kind]++;
						item5.index = gDashboard.itemQuantity[item5.kind];
						item5.Name = '분석 결과';
						item5.fieldManager.focusItemType = focusItemType;
						item5.focusItemType = focusItemType;
						item5.fieldManager.index = 1;
						
						item5.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item5.kind];
						
						item6 = new WISE.libs.Dashboard.item.DataGridGenerator();
						item6.kind = 'dataGrid';
						gDashboard.fieldManager = item6.fieldManager = fieldManager;
						gDashboard.itemQuantity[item6.kind]++;
						item6.index = gDashboard.itemQuantity[item6.kind];
						item6.Name = '기술통계';
						item6.fieldManager.focusItemType = focusItemType;
						item6.focusItemType = focusItemType;
						item6.fieldManager.index = 1;
						
						item6.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item6.kind];
						
						gDashboard.itemGenerateManager.dxItemBasten.push(item);
						gDashboard.itemGenerateManager.dxItemBasten.push(item2);
						gDashboard.itemGenerateManager.dxItemBasten.push(item4);
						gDashboard.itemGenerateManager.dxItemBasten.push(item3);
						gDashboard.itemGenerateManager.dxItemBasten.push(item5);
						gDashboard.itemGenerateManager.dxItemBasten.push(item6);
						
						
						
						gDashboard.insertItemManager.generateAysItemContainer(item,false,"AysItem",undefined,"데이터셋");
						
						itemList=[],inItemList=[];
						inItemList.push(item2);
						inItemList.push(item4);
						inItemList.push(item5);
						itemList.push(inItemList);
						itemList.push(item6);
						
						gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem","inContainer","통계분석");
						
						
						gDashboard.insertItemManager.generateAysItemContainer(item3,false,"AysItem",undefined,"시각화");
						
						gDashboard.fieldChooser.setAnalysisFieldArea(item, false);
						gDashboard.itemGenerateManager.init();
						
						item.dragNdropController = new WISE.widget.DragNDropController(item); 
						item.dragNdropController.addDroppableOptions(item); 
						item2.dragNdropController = item.dragNdropController;
						item3.dragNdropController = item2.dragNdropController;
						item4.dragNdropController = item3.dragNdropController;
						item5.dragNdropController = item4.dragNdropController;
						item6.dragNdropController = item5.dragNdropController;
						break;
					case 'insertLogisticRegression':
					case 'insertMultipleLogisticRegression':
						item2 = new WISE.libs.Dashboard.item.DataGridGenerator();
						item2.kind = 'dataGrid';
						gDashboard.fieldManager = item2.fieldManager = fieldManager;
						gDashboard.itemQuantity[item2.kind]++;
						item2.index = gDashboard.itemQuantity[item2.kind];
						item2.Name = '분석결과표';
						item2.fieldManager.focusItemType = focusItemType;
						item2.focusItemType = focusItemType;
						item2.fieldManager.index = 1;
						
						item2.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item2.kind];
						
						
						item4 = new WISE.libs.Dashboard.item.DataGridGenerator();
						item4.kind = 'dataGrid';
						gDashboard.fieldManager = item4.fieldManager = fieldManager;
						gDashboard.itemQuantity[item4.kind]++;
						item4.index = gDashboard.itemQuantity[item4.kind];
						item4.Name = '로지스틱회귀계수';
						item4.fieldManager.focusItemType = focusItemType;
						item4.focusItemType = focusItemType;
						item4.fieldManager.index = 1;
						
						item4.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item4.kind];
						
						if(_itemkind != "insertMultipleLogisticRegression"){
							item3 = new WISE.libs.Dashboard.item.ScatterPlotGenerator();
							item3.kind = 'scatterplot';
							gDashboard.fieldManager = item3.fieldManager = fieldManager;
							
							gDashboard.itemQuantity[item3.kind] = 0;
							gDashboard.itemQuantity[item3.kind]++;
							item3.index = gDashboard.itemQuantity[item3.kind];
							item3.Name = '예측 결과 시각화';
							item3.fieldManager.focusItemType = focusItemType;
							item3.focusItemType = focusItemType;
							item3.fieldManager.index = 1;
							
							item3.ComponentName = 'scatterplotDashboardItem' + gDashboard.itemQuantity[item3.kind];
						}
						
	
						
						item6 = new WISE.libs.Dashboard.item.DataGridGenerator();
						item6.kind = 'dataGrid';
						gDashboard.fieldManager = item6.fieldManager = fieldManager;
						gDashboard.itemQuantity[item6.kind]++;
						item6.index = gDashboard.itemQuantity[item6.kind];
						item6.Name = '기술통계';
						item6.fieldManager.focusItemType = focusItemType;
						item6.focusItemType = focusItemType;
						item6.fieldManager.index = 1;
						
						item6.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item6.kind];
						
						gDashboard.itemGenerateManager.dxItemBasten.push(item);
						gDashboard.itemGenerateManager.dxItemBasten.push(item2);
						gDashboard.itemGenerateManager.dxItemBasten.push(item4);
						if(_itemkind != "insertMultipleLogisticRegression"){
							gDashboard.itemGenerateManager.dxItemBasten.push(item3);
						}
						gDashboard.itemGenerateManager.dxItemBasten.push(item6);
						
						
						
						
						gDashboard.insertItemManager.generateAysItemContainer(item,false,"AysItem",undefined,"데이터셋");
						
						itemList=[],inItemList=[];
						inItemList.push(item2);
						inItemList.push(item4);
						itemList.push(inItemList);
						itemList.push(item6);
						
						gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem","inContainer","통계분석");
						
						if(_itemkind != "insertMultipleLogisticRegression"){
							gDashboard.insertItemManager.generateAysItemContainer(item3,false,"AysItem",undefined,"시각화");
						}
						
						gDashboard.fieldChooser.setAnalysisFieldArea(item, false);
						gDashboard.itemGenerateManager.init();
						
						item.dragNdropController = new WISE.widget.DragNDropController(item); 
						item.dragNdropController.addDroppableOptions(item); 
						item2.dragNdropController = item.dragNdropController;
						if(_itemkind != "insertMultipleLogisticRegression"){
							item3.dragNdropController = item2.dragNdropController;
							item4.dragNdropController = item3.dragNdropController;
							item6.dragNdropController = item3.dragNdropController;
						}else{
							item4.dragNdropController = item2.dragNdropController;
							item6.dragNdropController = item4.dragNdropController;
						}
						
						break;
					default:
						break;
				}
				return;
			/* DOGFOOT ktkang 가설검정 T-test 추가  20210204 */
			case 'insertTtest':
			case 'insertZtest':
			case 'insertChitest':
			case 'insertFtest':
				WISE.loadedSourceCheck('itemJS','DataGrid');
				gDashboard.itemGenerateManager.dxItemBasten = [];
				gDashboard.analysisType = _itemkind;
				var focusItemType;
				
				switch(_itemkind) {
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
					default:
						break;
				}
				
				var fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
				
				item = new WISE.libs.Dashboard.item.DataGridGenerator();
				item.kind = 'dataGrid';
				gDashboard.fieldManager = item.fieldManager = fieldManager;
				gDashboard.itemQuantity[item.kind]++;
				item.index = gDashboard.itemQuantity[item.kind];
				item.Name = '데이터';
				item.fieldManager.focusItemType = focusItemType;
				item.focusItemType = focusItemType;
				gDashboard.itemQuantity[item.fieldManager.focusItemType]++;
				item.fieldManager.index = 1;
				
				item.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				item2 = new WISE.libs.Dashboard.item.DataGridGenerator();
				item2.kind = 'dataGrid';
				gDashboard.fieldManager = item2.fieldManager = fieldManager;
				gDashboard.itemQuantity[item2.kind]++;
				item2.index = gDashboard.itemQuantity[item2.kind];
				item2.Name = '분석결과표';
				item2.fieldManager.focusItemType = focusItemType;
				item2.focusItemType = focusItemType;
				item2.fieldManager.index = 1;
				
				item2.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item2.kind];
				
				item4 = new WISE.libs.Dashboard.item.DataGridGenerator();
				item4.kind = 'dataGrid';
				gDashboard.fieldManager = item4.fieldManager = fieldManager;
				gDashboard.itemQuantity[item4.kind]++;
				item4.index = gDashboard.itemQuantity[item4.kind];
				item4.Name = '기술통계';
				item4.fieldManager.focusItemType = focusItemType;
				item4.focusItemType = focusItemType;
				item4.fieldManager.index = 1;
				
				item4.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item4.kind];
				
								
				gDashboard.itemGenerateManager.dxItemBasten.push(item);
				gDashboard.itemGenerateManager.dxItemBasten.push(item2);
				gDashboard.itemGenerateManager.dxItemBasten.push(item4);
				
				/*dogfoot 컨테이너에 담을 아이템 리스트 생성 shlim 20201021*/
				var itemList = [];
				
				/*dogfoot 컨테이너에 담을 아이템 생성 shlim 20201021*/
				itemList.push(item)
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"데이터셋");
				
				/*dogfoot 컨테이너에 담을 아이템 생성 shlim 20201021*/
				itemList=[]
				itemList.push(item2);
				itemList.push(item4);
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"통계분석");
				
				gDashboard.fieldChooser.setAnalysisFieldArea(item, false);
				gDashboard.itemGenerateManager.init();
				
				item.dragNdropController = new WISE.widget.DragNDropController(item); 
				item.dragNdropController.addDroppableOptions(item); 
				item2.dragNdropController = item.dragNdropController;
				item3.dragNdropController = item2.dragNdropController;
				
				return;
			/* DOGFOOT ktkang 다변량분석 추가  20210215 */
			case 'insertMultivariate' :
				WISE.loadedSourceCheck('itemJS','DataGrid');
				gDashboard.itemGenerateManager.dxItemBasten = [];
				gDashboard.analysisType = _itemkind;
				var focusItemType = 'multivariate';
				
				var fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
				
				item = new WISE.libs.Dashboard.item.DataGridGenerator();
				item.kind = 'dataGrid';
				gDashboard.fieldManager = item.fieldManager = fieldManager;
				gDashboard.itemQuantity[item.kind]++;
				item.index = gDashboard.itemQuantity[item.kind];
				item.Name = '데이터';
				item.fieldManager.focusItemType = focusItemType;
				item.focusItemType = focusItemType;
				gDashboard.itemQuantity[item.fieldManager.focusItemType]++;
				item.fieldManager.index = 1;
				
				item.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item.kind];
				
				item2 = new WISE.libs.Dashboard.item.DataGridGenerator();
				item2.kind = 'dataGrid';
				gDashboard.fieldManager = item2.fieldManager = fieldManager;
				gDashboard.itemQuantity[item2.kind]++;
				item2.index = gDashboard.itemQuantity[item2.kind];
				item2.Name = '분석결과표';
				item2.fieldManager.focusItemType = focusItemType;
				item2.focusItemType = focusItemType;
				item2.fieldManager.index = 1;
				
				item2.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item2.kind];
				
				item4 = new WISE.libs.Dashboard.item.DataGridGenerator();
				item4.kind = 'dataGrid';
				gDashboard.fieldManager = item4.fieldManager = fieldManager;
				gDashboard.itemQuantity[item4.kind]++;
				item4.index = gDashboard.itemQuantity[item4.kind];
				item4.Name = '기술통계';
				item4.fieldManager.focusItemType = focusItemType;
				item4.focusItemType = focusItemType;
				item4.fieldManager.index = 1;
				
				item4.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item4.kind];
				
								
				gDashboard.itemGenerateManager.dxItemBasten.push(item);
				gDashboard.itemGenerateManager.dxItemBasten.push(item2);
				gDashboard.itemGenerateManager.dxItemBasten.push(item4);
				
				/*dogfoot 컨테이너에 담을 아이템 리스트 생성 shlim 20201021*/
				var itemList = [];
				
				/*dogfoot 컨테이너에 담을 아이템 생성 shlim 20201021*/
				itemList.push(item)
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"데이터셋");
				
				/*dogfoot 컨테이너에 담을 아이템 생성 shlim 20201021*/
				itemList=[]
				itemList.push(item2);
				itemList.push(item4);
				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem",undefined,"통계분석");
				
				gDashboard.fieldChooser.setAnalysisFieldArea(item, false);
				gDashboard.itemGenerateManager.init();
				
				item.dragNdropController = new WISE.widget.DragNDropController(item); 
				item.dragNdropController.addDroppableOptions(item); 
				item2.dragNdropController = item.dragNdropController;
				item3.dragNdropController = item2.dragNdropController;
				
				return;
//			case 'insertSimpleRegression':
//			case 'insertMultipleRegression':
//			case 'insertLogisticRegression':
//				WISE.loadedSourceCheck('itemJS','DataGrid');
//				WISE.loadedSourceCheck('itemJS','ScatterPlot');
//				WISE.loadedSourceCheck('itemJS','HeatMap2');
//				gDashboard.itemGenerateManager.dxItemBasten = [];
//				gDashboard.analysisType = _itemkind;
//				var focusItemType;
//				
//				switch(_itemkind) {
//					case 'insertSimpleRegression':
//						focusItemType = 'simpleRegression';
//						break;
//					case 'insertMultipleRegression':
//						focusItemType = 'multipleRegression';
//						break;
//					case 'insertLogisticRegression':
//						focusItemType = 'logisticRegression';
//						break;
//					default:
//						break;
//				}
//				
//				var fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
//				
//				item = new WISE.libs.Dashboard.item.DataGridGenerator();
//				item.kind = 'dataGrid';
//				gDashboard.fieldManager = item.fieldManager = fieldManager;
//				
//				gDashboard.itemQuantity[item.kind] = 0;
//				gDashboard.itemQuantity[item.kind]++;
//				item.index = gDashboard.itemQuantity[item.kind];
//				item.Name = '데이터';
//				item.fieldManager.focusItemType = focusItemType;
//				
//				gDashboard.itemQuantity[item.fieldManager.focusItemType]++;
//				item.fieldManager.index = 1;
//				
//				item.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item.kind];
//
//				item2 = new WISE.libs.Dashboard.item.DataGridGenerator();
//				item2.kind = 'dataGrid';
//				gDashboard.fieldManager = item2.fieldManager = fieldManager;
//				gDashboard.itemQuantity[item2.kind]++;
//				item2.index = gDashboard.itemQuantity[item2.kind];
//				item2.Name = '분석결과표';
//				item2.fieldManager.focusItemType = focusItemType;
//				
//				item2.fieldManager.index = 1;
//				
//				item2.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item2.kind];
//				
//				item4 = new WISE.libs.Dashboard.item.DataGridGenerator();
//				item4.kind = 'dataGrid';
//				gDashboard.fieldManager = item4.fieldManager = fieldManager;
//				gDashboard.itemQuantity[item4.kind]++;
//				item4.index = gDashboard.itemQuantity[item4.kind];
//				item4.Name = '기술통계';
//				item4.fieldManager.focusItemType = focusItemType;
//				
//				item4.fieldManager.index = 1;
//				
//				item4.ComponentName = 'gridDashboardItem' + gDashboard.itemQuantity[item4.kind];
//				
//				
//				
//				
//				switch(_itemkind) {
//					case 'insertSimpleRegression':
//						item3 = new WISE.libs.Dashboard.item.ScatterPlotGenerator();
//						item3.kind = 'scatterplot';
//						gDashboard.fieldManager = item3.fieldManager = fieldManager;
//						
//						gDashboard.itemQuantity[item3.kind] = 0;
//						gDashboard.itemQuantity[item3.kind]++;
//						item3.index = gDashboard.itemQuantity[item3.kind];
//						item3.Name = '산점도' + gDashboard.itemQuantity[item3.kind];
//						item3.fieldManager.focusItemType = focusItemType;
//						
//						item3.fieldManager.index = 1;
//						
//						item3.ComponentName = 'scatterplotDashboardItem' + gDashboard.itemQuantity[item3.kind];
//						break;
//					case 'insertMultipleRegression':
//						item3 = new WISE.libs.Dashboard.item.ScatterPlotGenerator();
//						item3.kind = 'scatterplot';
//						gDashboard.fieldManager = item3.fieldManager = fieldManager;
//						
//						gDashboard.itemQuantity[item3.kind] = 0;
//						gDashboard.itemQuantity[item3.kind]++;
//						item3.index = gDashboard.itemQuantity[item3.kind];
//						item3.Name = '산점도' + gDashboard.itemQuantity[item3.kind];
//						item3.fieldManager.focusItemType = focusItemType;
//						
//						item3.fieldManager.index = 1;
//						
//						item3.ComponentName = 'scatterplotDashboardItem' + gDashboard.itemQuantity[item3.kind];
//						break;
//					case 'insertLogisticRegression':
//						item3 = new WISE.libs.Dashboard.item.ScatterPlotGenerator();
//						item3.kind = 'scatterplot';
//						gDashboard.fieldManager = item3.fieldManager = fieldManager;
//						
//						gDashboard.itemQuantity[item3.kind] = 0;
//						gDashboard.itemQuantity[item3.kind]++;
//						item3.index = gDashboard.itemQuantity[item3.kind];
//						item3.Name = '예측 결과 시각화';
//						item3.fieldManager.focusItemType = focusItemType;
//						
//						item3.fieldManager.index = 1;
//						
//						item3.ComponentName = 'scatterplotDashboardItem' + gDashboard.itemQuantity[item3.kind];
//						break;
//					default:
//						break;
//				}
//				
//				gDashboard.itemGenerateManager.dxItemBasten.push(item);
//				gDashboard.itemGenerateManager.dxItemBasten.push(item2);
//				gDashboard.itemGenerateManager.dxItemBasten.push(item4);
//				gDashboard.itemGenerateManager.dxItemBasten.push(item3);
//				
//				gDashboard.insertItemManager.generateAysItemContainer(item,false,"AysItem");
//				
//				itemList=[]
//				itemList.push(item2);
//				itemList.push(item4);
//				gDashboard.insertItemManager.generateAysItemContainer(itemList,false,"AysItem");
//				
//				gDashboard.insertItemManager.generateAysItemContainer(item3,false,"AysItem");
//				
//				gDashboard.fieldChooser.setAnalysisFieldArea(item, false);
//				gDashboard.itemGenerateManager.init();
//				
//				item.dragNdropController = new WISE.widget.DragNDropController(item); 
//				item.dragNdropController.addDroppableOptions(item); 
//				item2.dragNdropController = item.dragNdropController;
//				item3.dragNdropController = item2.dragNdropController;
//			
//				return;
			default:
				return;
			// KERIS 수정 끝
		}

		item.itemid = item.ComponentName + '_item';
		// item.dataSourceId = 'dataSource1';
		if (copy) {
			item.dataSourceId = copyItem.dataSourceId;
		}

		// KERIS 수정
		gDashboard.itemGenerateManager.dxItemBasten.push(item);
		gDashboard.itemGenerateManager.init();
		
		gDashboard.insertItemManager.generateItemContainer(item);
		// KERIS 수정 끝

		if (copy) {
			item.dragNdropController = new WISE.widget.DragNDropController(item);
			item.dragNdropController.loadItemData(item);
			item.dragNdropController.addSortableOptionsForOpen(item);

			gDashboard.query();
		} else {
			item.dragNdropController = new WISE.widget.DragNDropController(item);
			item.dragNdropController.addDroppableOptions(item);
		}

//		KERIS
		if (gDashboard.reportType != 'AdHoc') {
			this.contextMenuItem(item);
		}
//		KERIS 주석 끝
	};

	this.generateItemContainer = function(item, isAdhoc,type) {
		gDashboard.goldenLayoutManager.render(item, isAdhoc,undefined,type);

		// render textbox immediately
		if(item){
			if (!isNull(gDashboard.structure.ReportMasterInfo.reportJson)) {
				if (isAdhoc) {
					if (gDashboard.structure.ReportMasterInfo.layout != 'C') {
						var pivotItemBasten = gDashboard.itemGenerateManager.dxItemBasten.filter(function (item, idx) {
							return item.type == 'PIVOT_GRID';
						});
						
						if (!isNull(pivotItemBasten)) {
							var bChk = false;
							if (Array.isArray(pivotItemBasten)) {
								pivotItemBasten = pivotItemBasten[0];
							}
							if (!isNull(pivotItemBasten.dxItem)) {
								var dataSrc = pivotItemBasten.dxItem.getDataSource();
								
								if (!isNull(dataSrc) && ds._data.values.length > 0) {
									bChk = false;
								}
								else {
									bChk = true;
								}
							}
							else {
								bChk = true;
							}
							
							if (bChk) {
								gDashboard.itemGenerateManager.renderButtons(pivotItemBasten, pivotItemBasten.isAdhocItem, true);
							}
							else {
								gDashboard.itemGenerateManager.renderButtons(pivotItemBasten);
							}
						}
					}
				}
				else {
					switch(item.type) {
						case "PIVOT_GRID":
							if (!isNull(item.dxItem)) {
								var dataSrc = item.dxItem.getDataSource();
								
								if (!isNull(dataSrc) && dataSrc._data.values.length > 0) {
									bChk = false;
								}
								else {
									bChk = true;
								}
							}
							else {
								bChk = true;
							}
							
							if (bChk) {
								gDashboard.itemGenerateManager.renderButtons(item, item.isAdhocItem, true);
							}
							else {
								gDashboard.itemGenerateManager.renderButtons(item);
							}
						break;
					}
				}
			}
			
		    if (item.kind === 'textBox') gDashboard.itemGenerateManager.renderButtons(item);
		}
//		item.renderButtons();
	};
	/* DOGFOOT ktkang 통계 분석 부분 추가  20201102 */
	this.generateAysItemContainer = function(item, isAdhoc,type,itemType,_tabTitle) {
		
		/*
		 * gDashboard.goldenLayoutManager.setAysItem()
		 * 여러개의 아이템 리스트를 컨테이너 하나에 생성하기 위한 Function
		 */
		gDashboard.goldenLayoutManager.aysRender(gDashboard.goldenLayoutManager.setAysItem(item,itemType), isAdhoc,undefined,type,_tabTitle);

		// render textbox immediately
		if (item.kind === 'textBox') gDashboard.itemGenerateManager.renderButtons(item);
//		item.renderButtons();
	};
	this.clearCanvasLayout = function() {
		gDashboard.goldenLayoutManager.clear();
	};
	
	this.generateAdhocFieldManagerForViewer = function(item){
		var focusItem = item;
		if(item.isAdhocItem && item.type != 'PIVOT_GRID'){
			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
				if(_item.isAdhocItem && _item.type == 'PIVOT_GRID' && item.adhocIndex == _item.adhocIndex){
					focusItem = _item;
				}
			});	
		}
		
		switch (item.type) {
			case "PIVOT_GRID":
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
				item.fieldManager.focusItemType = 'adhocItem';
				gDashboard.itemQuantity[item.fieldManager.focusItemType] = item.adhocIndex;
				item.fieldManager.index = item.adhocIndex;
				gDashboard.fieldChooser.setAnalysisFieldArea(item, true);
				item.dragNdropController = new WISE.widget.DragNDropController(item);
				break;
			case "SIMPLE_CHART":
				if(item != focusItem){
					item.fieldManager = focusItem.fieldManager;	
				}else{
					gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
					item.fieldManager.focusItemType = 'adhocItem';
					gDashboard.itemQuantity[item.fieldManager.focusItemType] = item.adhocIndex;
					item.fieldManager.index = item.adhocIndex;
					gDashboard.fieldChooser.setAnalysisFieldArea(item, true);
				}
				break;
		}
	};
	
	this.openItem = function(_itemMeta) {
		var item = _itemMeta;
		if (typeof _itemMeta.meta.ShowCaption != 'undefined') {
			$('#' + _itemMeta.itemid + '_title').parent().hide();
		}
		
		var focusItem = item;
		if(item.isAdhocItem && item.type != 'PIVOT_GRID'){
			$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
				if(_item.isAdhocItem && _item.type == 'PIVOT_GRID' && item.adhocIndex == _item.adhocIndex){
					focusItem = _item;
				}
			});	
		}
		
		if(_itemMeta.meta.MemoText)
			item.memoText = _itemMeta.meta.MemoText;
		
		switch (item.type) {
		case "PIVOT_GRID":
			item.kind = 'pivotGrid';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('pivotDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			item.index = gDashboard.itemQuantity[item.kind];
			
			if(item.isAdhocItem){
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
				item.fieldManager.focusItemType = 'adhocItem';
				gDashboard.itemQuantity[item.fieldManager.focusItemType] = item.adhocIndex;
				item.fieldManager.index = item.adhocIndex;
				gDashboard.fieldChooser.setAnalysisFieldArea(item, true);
			}else{
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PivotGridFieldManager(
						_itemMeta.meta);
				item.fieldManager.index = gDashboard.itemQuantity[item.kind];
				// gDashboard.fieldChooser.openPivotAnalysisFieldArea(item,_itemMeta);
				
				gDashboard.fieldChooser.setAnalysisFieldArea(item);	
			}
			
			break;
		case 'DATA_GRID':
			item.kind = 'dataGrid';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('gridDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DataGridFieldManager(
					_itemMeta.meta);
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			// gDashboard.fieldChooser.openGridAnalysisFieldArea(item,_itemMeta);
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'SIMPLE_CHART':
			item.kind = 'chart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('chartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			if(item.isAdhocItem){
				if(item != focusItem){
					item.fieldManager = focusItem.fieldManager;	
				}else{
					gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
					item.fieldManager.focusItemType = 'adhocItem';
					gDashboard.itemQuantity[item.fieldManager.focusItemType] = item.adhocIndex;
					item.fieldManager.index = item.adhocIndex;
					gDashboard.fieldChooser.setAnalysisFieldArea(item, true);
				}
			}else{
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				// gDashboard.fieldChooser.openChartAnalysisFieldArea(item,_itemMeta);
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
			}
			break;
		case 'PIE_CHART':
			item.kind = 'pieChart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('pieDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PieFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		/* DOGFOOT hsshim 2020-02-03 게이지 불러오기 기능 작업 */
		case 'GAUGE_CHART':
			item.kind = 'gauge';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('gaugeDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.GaugeFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setGaugeAnalysisFieldArea(item);
			break;
		/* DOGFOOT hsshim 2020-02-03 끝 */
		case 'CARD_CHART':
			item.kind = 'card';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('cardDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CardFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'PARALLEL_COORDINATE':
			item.kind = 'parallel';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('parallelDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ParallelFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'BUBBLE_PACK_CHART':
			item.kind = 'bubblepackchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('bubblepackchartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubblePackChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'WORD_CLOUD_V2':
			item.kind = 'wordcloudv2';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('wordcloudv2DashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WordCloudV2FieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'DENDROGRAM_BAR_CHART':
			item.kind = 'dendrogrambarchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('dendrogrambarchartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DendrogramBarChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'CALENDAR_VIEW_CHART':
			item.kind = 'calendarviewchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('calendarviewchartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarViewChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'CALENDAR_VIEW2_CHART':
			item.kind = 'calendarview2chart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('calendarview2chartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarView2ChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'CALENDAR_VIEW3_CHART':
			item.kind = 'calendarview3chart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('calendarview3chartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarView3ChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'COLLAPSIBLE_TREE_CHART':
			item.kind = 'collapsibletreechart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('collapsibletreechartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CollapsibleTreeChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'RANGE_BAR_CHART':
			item.kind = 'rangebarchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('rangebarchartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

	
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RangeBarChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);

			break;
		case 'RANGE_AREA_CHART':
			item.kind = 'rangeareachart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('rangeareachartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RangeAreaChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			
			break;
		case 'TIME_LINE_CHART':
			item.kind = 'timelinechart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('timelinechartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

	
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TimeLineChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);

			break;
		case 'CHOROPLETH_MAP':
			item.kind = 'choroplethMap';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('choroplethMapDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ChoroplethMapFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;

		case 'TREEMAP':
			item.kind = 'Treemap';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('treemapDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TreeMapFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'WORD_CLOUD' :
			item.kind = 'wordcloud';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('WordCloudDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WordCloudFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'HEATMAP':
			item.kind = 'heatmap';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('heatmapDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HeatMapFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'HEATMAP2':
			item.kind = 'heatmap2';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('heatmap2DashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HeatMap2FieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'SYNCHRONIZED_CHARTS':
			item.kind = 'syncchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('syncchartDashboardItem', ''));
			item.Name = item.itemNm;
			item.ComponentName = item.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SynchronizedChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'HISTOGRAM_CHART' :
			item.kind = 'histogramchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('histogramchartDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HistogramChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'IMAGE': // ymbin
			item.kind = 'image';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('imageDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ImageFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'TEXTBOX': // ymbin
			item.kind = 'textBox';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('textBoxDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TextBoxFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'STAR_CHART':
			item.kind = 'Starchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('starchartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.StarChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'LISTBOX':
			item.kind ='ListBox';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('listBoxDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ListBoxFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'TREEVIEW':
			item.kind ='TreeView';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('treeViewDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TreeViewFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'COMBOBOX':
			item.kind ='ComboBox';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('comboBoxDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ComboBoxFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'RECTANGULAR_ARAREA_CHART' :
			item.kind = 'RectangularAreaChart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('RectangularAreaChartDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RectangularAreaChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'WATERFALL_CHART' :
			item.kind = 'waterfallchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('waterfallchartDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WaterfallChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'BIPARTITE_CHART' :
			item.kind = 'bipartitechart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('bipartitechartDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BipartiteChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'SANKEY_CHART' :
			item.kind = 'sankeychart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('sankeychartDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SankeyChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
			break;
		case 'DIVERGING_CHART' :
			item.kind = 'divergingchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('divergingchartDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DivergingChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'SCATTER_PLOT' :
			item.kind = 'scatterplot';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('scatterplotDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ScatterPlotFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'SCATTER_PLOT2' :
			item.kind = 'scatterplot2';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('scatterplot2DashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ScatterPlot2FieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'RADIAL_TIDY_TREE':
			item.kind = 'radialtidytree';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('radialtidytreeDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RadialTidyTreeFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'SCATTER_PLOT_MATRIX':
			item.kind = 'scatterplotmatrix';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('scatterplotmatrixDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ScatterPlotMatrixFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'HISTORY_TIMELINE':
			item.kind = 'historytimeline';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('historytimelineDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HistoryTimelineFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'ARC_DIAGRAM':
			item.kind = 'arcdiagram';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('arcdiagramDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ArcDiagramFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'BOX_PLOT':
			item.kind = 'boxplot';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('boxplotDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BoxPlotFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'COORDINATE_LINE':
			item.kind = 'coordinateline';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('coordinatelineDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CoordinateLineFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'COORDINATE_DOT':
			item.kind = 'coordinatedot';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('coordinatedotDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CoordinateDotFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'DEPENDENCY_WHEEL':
			item.kind = 'dependencywheel';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('dependencywheelDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DependencyWheelFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'SEQUENCES_SUNBURST' :
			item.kind = 'sequencessunburst';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('sequencessunburstDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SequencesSunburstFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'LIQUID_FILL_GAUGE' :
			item.kind = 'liquidfillgauge';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('liquidfillgaugeDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.LiquidFillGaugeFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'BUBBLE_D3' :
			item.kind = 'bubbled3';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('bubbled3DashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubbleD3FieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'HIERARCHICAL_EDGE':
			item.kind = 'hierarchical';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('hierarchicalDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HierarchicalFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'FORCEDIRECT' :
			item.kind = 'forceDirect';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('forceDirectDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ForceDirectFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'FORCEDIRECTEXPAND' :
			item.kind = 'forceDirectExpand';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('forceDirectExpandDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ForceDirectExpandFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'BUBBLE_CHART' :
			item.kind = 'bubble';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('bubbleChartDashboardItem', ''));
			item.Name = _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubbleChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'FUNNEL_CHART' :
			item.kind = 'funnelchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('funnelchartDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.FunnelChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'PYRAMID_CHART' :
			item.kind = 'pyramidchart';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('pyramidchartDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PyramidChartFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		/* DOGFOOT syjin 카카오 지도 추가  20200820 */
		case 'KAKAO_MAP' :
			item.kind = 'kakaoMap';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('kakaoMapDashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.KakaoMapFieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'KAKAO_MAP2' :
			item.kind = 'kakaoMap2';
			gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('kakaoMap2DashboardItem', ''));
			item.Name =  _itemMeta.itemNm;
			item.ComponentName = _itemMeta.meta.ComponentName;
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.KakaoMap2FieldManager(); 
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		}

		$('#column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity).attr('data-source-id',item.dataSourceId);
		$('#'+item.ComponentName).on('click',function(){
			gDashboard.fieldManager = focusItem.fieldManager;
			gDashboard.itemGenerateManager.focusItem(item,focusItem);
			gDashboard.fieldChooser.resetAnalysisFieldArea(focusItem);
		});

		item.itemid = item.ComponentName + "_item";
		item.dataSourceId = _itemMeta.dataSourceId;
		gDashboard.itemGenerateManager.focusItem(item,focusItem);

		gDashboard.itemGenerateManager.init();

		if(!item.isAdhocItem || item.type == 'PIVOT_GRID' || item == focusItem){
			item.dragNdropController = new WISE.widget.DragNDropController(item);
			item.dragNdropController.loadItemData(item);
			item.dragNdropController.addSortableOptionsForOpen(item);
		}else{
			item.dragNdropController = focusItem.dragNdropController;
		}

//		KERIS
		if (gDashboard.reportType != 'AdHoc') {
			this.contextMenuItem(item);
		}
//		KERIS 주석 끝
	};
	
	/*dogfoot shlim 통계 분석 불러오기 부분 추가 20201030 */
	this.openAysItem = function(_itemMeta) {
		var item
			,focusItemType
			,focusItem
			,setFieldManager
			,setFieldItem
			,setDragNdropController;
			
		var fieldManager,setFieldItem;
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
		 $.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
			if(_item.Name == '데이터'){
				setFieldManager =  new WISE.libs.Dashboard.DataGridFieldManager();
				setFieldItem = _item;
				gDashboard.fieldManager = _item.fieldManager = setFieldManager
				_item.fieldManager.focusItemType = focusItemType;
				gDashboard.fieldChooser.setAnalysisFieldArea(_item, false);
				_item.dragNdropController = setDragNdropController = new WISE.widget.DragNDropController(_item);
				_item.dragNdropController.loadItemData(_item,true);
				_item.dragNdropController.addDroppableOptions(_item); 
				
			}
		});	
		
		$.each(gDashboard.itemGenerateManager.dxItemBasten,function(_i,_item){
			focusItem = item = _item;
			
			switch (item.type) {
			case "PIVOT_GRID":
				item.kind = 'pivotGrid';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('pivotDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				item.index = gDashboard.itemQuantity[item.kind];
				
				if(item.isAdhocItem){
					gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
					item.fieldManager.focusItemType = 'adhocItem';
					gDashboard.itemQuantity[item.fieldManager.focusItemType] = item.adhocIndex;
					item.fieldManager.index = item.adhocIndex;
					gDashboard.fieldChooser.setAnalysisFieldArea(item, true);
				}else{
					gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PivotGridFieldManager(
							item.meta);
					item.fieldManager.index = gDashboard.itemQuantity[item.kind];
					// gDashboard.fieldChooser.openPivotAnalysisFieldArea(item,item);
					
					gDashboard.fieldChooser.setAnalysisFieldArea(item);	
				}
				
				break;
			case 'DATA_GRID':
				item.kind = 'dataGrid';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('gridDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = setFieldManager
				item.fieldManager.index = 1;
				item.fieldManager.focusItemType = focusItemType;
				// gDashboard.fieldChooser.openGridAnalysisFieldArea(item,item);
				
				break;
			case 'SIMPLE_CHART':
				item.kind = 'chart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('chartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				if(item.isAdhocItem){
					if(item != focusItem){
						item.fieldManager = focusItem.fieldManager;	
					}else{
						gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();
						item.fieldManager.focusItemType = 'adhocItem';
						gDashboard.itemQuantity[item.fieldManager.focusItemType] = item.adhocIndex;
						item.fieldManager.index = item.adhocIndex;
						gDashboard.fieldChooser.setAnalysisFieldArea(item, true);
					}
				}else{
					gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ChartFieldManager();
					item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
					// gDashboard.fieldChooser.openChartAnalysisFieldArea(item,item);
					gDashboard.fieldChooser.setAnalysisFieldArea(item);
				}
				break;
			case 'PIE_CHART':
				item.kind = 'pieChart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('pieDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PieFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
				/* DOGFOOT hsshim 2020-02-03 게이지 불러오기 기능 작업 */
			case 'GAUGE_CHART':
				item.kind = 'gauge';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('gaugeDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.GaugeFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setGaugeAnalysisFieldArea(item);
				break;
				/* DOGFOOT hsshim 2020-02-03 끝 */
			case 'CARD_CHART':
				item.kind = 'card';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('cardDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CardFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'PARALLEL_COORDINATE':
				item.kind = 'parallel';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('parallelDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ParallelFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'BUBBLE_PACK_CHART':
				item.kind = 'bubblepackchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('bubblepackchartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubblePackChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'WORD_CLOUD_V2':
				item.kind = 'wordcloudv2';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('wordcloudv2DashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WordCloudV2FieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'DENDROGRAM_BAR_CHART':
				item.kind = 'dendrogrambarchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('dendrogrambarchartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DendrogramBarChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'CALENDAR_VIEW_CHART':
				item.kind = 'calendarviewchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('calendarviewchartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarViewChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'CALENDAR_VIEW2_CHART':
				item.kind = 'calendarview2chart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('calendarview2chartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarView2ChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'CALENDAR_VIEW3_CHART':
				item.kind = 'calendarview3chart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('calendarview3chartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarView3ChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'COLLAPSIBLE_TREE_CHART':
				item.kind = 'collapsibletreechart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('collapsibletreechartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CollapsibleTreeChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'RANGE_BAR_CHART':
				item.kind = 'rangebarchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('rangebarchartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RangeBarChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				
				break;
			case 'RANGE_AREA_CHART':
				item.kind = 'rangeareachart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('rangeareachartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RangeAreaChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				
				break;
			case 'TIME_LINE_CHART':
				item.kind = 'timelinechart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('timelinechartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TimeLineChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				
				break;
			case 'CHOROPLETH_MAP':
				item.kind = 'choroplethMap';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('choroplethMapDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ChoroplethMapFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
				
			case 'TREEMAP':
				item.kind = 'Treemap';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('treemapDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TreeMapFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'WORD_CLOUD' :
				item.kind = 'wordcloud';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('WordCloudDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WordCloudFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'HEATMAP':
				item.kind = 'heatmap';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('heatmapDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HeatMapFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'HEATMAP2':
				item.kind = 'heatmap2';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('heatmap2DashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = setFieldManager
				item.fieldManager.index = 1;
				item.fieldManager.focusItemType = focusItemType;
				item.dragNdropController = setDragNdropController;
				break;
			case 'SYNCHRONIZED_CHARTS':
				item.kind = 'syncchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('syncchartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SynchronizedChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'HISTOGRAM_CHART' :
				item.kind = 'histogramchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('histogramchartDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HistogramChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'IMAGE': // ymbin
				item.kind = 'image';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('imageDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ImageFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'TEXTBOX': // ymbin
				item.kind = 'textBox';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('textBoxDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TextBoxFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'STAR_CHART':
				item.kind = 'Starchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('starchartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.StarChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'LISTBOX':
				item.kind ='ListBox';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('listBoxDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ListBoxFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'TREEVIEW':
				item.kind ='TreeView';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('treeViewDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TreeViewFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'COMBOBOX':
				item.kind ='ComboBox';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('comboBoxDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ComboBoxFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'RECTANGULAR_ARAREA_CHART' :
				item.kind = 'RectangularAreaChart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('RectangularAreaChartDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RectangularAreaChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'WATERFALL_CHART' :
				item.kind = 'waterfallchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('waterfallchartDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WaterfallChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'BIPARTITE_CHART' :
				item.kind = 'bipartitechart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('bipartitechartDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BipartiteChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'SANKEY_CHART' :
				item.kind = 'sankeychart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('sankeychartDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SankeyChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
				break;
			case 'DIVERGING_CHART' :
				item.kind = 'divergingchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('divergingchartDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DivergingChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'SCATTER_PLOT' :
				item.kind = 'scatterplot';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('scatterplotDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = setFieldManager
				item.fieldManager.index = 1;
				item.fieldManager.focusItemType = focusItemType;
				item.dragNdropController = setDragNdropController;
				break;
			case 'SCATTER_PLOT2' :
				item.kind = 'scatterplot2';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('scatterplot2DashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ScatterPlot2FieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'SCATTER_PLOT_MATRIX':
				item.kind = 'scatterplotmatrix';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('scatterplotmatrixDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = setFieldManager
				item.fieldManager.index = 1;
				item.fieldManager.focusItemType = focusItemType;
				item.dragNdropController = setDragNdropController;
				break;
			case 'BOX_PLOT':
				item.kind = 'boxplot';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('boxplotDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = setFieldManager
				item.fieldManager.index = 1;
				item.fieldManager.focusItemType = focusItemType;
				item.dragNdropController = setDragNdropController;
//				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'COORDINATE_LINE':
				item.kind = 'coordinateline';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('coordinatelineDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = setFieldManager
				item.fieldManager.index = 1;
				item.fieldManager.focusItemType = focusItemType;
				item.dragNdropController = setDragNdropController;
//				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'COORDINATE_DOT':
				item.kind = 'coordinatedot';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('coordinatedotDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = setFieldManager
				item.fieldManager.index = 1;
				item.fieldManager.focusItemType = focusItemType;
				item.dragNdropController = setDragNdropController;
//				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'DEPENDENCY_WHEEL':
				item.kind = 'dependencywheel';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('dependencywheelDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DependencyWheelFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'SEQUENCES_SUNBURST' :
				item.kind = 'sequencessunburst';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('sequencessunburstDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SequencesSunburstFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'LIQUID_FILL_GAUGE' :
				item.kind = 'liquidfillgauge';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('liquidfillgaugeDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.LiquidFillGaugeFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'BUBBLE_D3' :
				item.kind = 'bubbled3';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('bubbled3DashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubbleD3FieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'HIERARCHICAL_EDGE':
				item.kind = 'hierarchical';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('hierarchicalDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HierarchicalFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'FORCEDIRECT' :
				item.kind = 'forceDirect';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('forceDirectDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ForceDirectFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'FORCEDIRECTEXPAND' :
				item.kind = 'forceDirectExpand';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('forceDirectExpandDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ForceDirectExpandFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'BUBBLE_CHART' :
				item.kind = 'bubble';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('bubbleChartDashboardItem', ''));
				item.Name = item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubbleChartFieldManager();
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'FUNNEL_CHART' :
				item.kind = 'funnelchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('funnelchartDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.FunnelChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'PYRAMID_CHART' :
				item.kind = 'pyramidchart';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('pyramidchartDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PyramidChartFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
				/* DOGFOOT syjin 카카오 지도 추가  20200820 */
			case 'KAKAO_MAP' :
				item.kind = 'kakaoMap';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('kakaoMapDashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.KakaoMapFieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			case 'KAKAO_MAP2' :
				item.kind = 'kakaoMap2';
				gDashboard.itemQuantity[item.kind] = parseInt(item.itemid.replace('kakaoMap2DashboardItem', ''));
				item.Name =  item.itemNm;
				item.ComponentName = item.meta.ComponentName;
				
				gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.KakaoMap2FieldManager(); 
				item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
				gDashboard.fieldChooser.setAnalysisFieldArea(item);
				break;
			}
			
			$('#column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity).attr('data-source-id',item.dataSourceId);
			$('#'+item.ComponentName).on('click',function(){
				gDashboard.fieldManager = focusItem.fieldManager;
				gDashboard.itemGenerateManager.focusItem(item,focusItem);
				gDashboard.fieldChooser.resetAnalysisFieldArea(focusItem);
			});
			
			$('#column-drop-body'+gDashboard.fieldChooser.fieldChooserQuantity).attr('data-source-id',item.dataSourceId);
			$('#'+item.ComponentName).on('click',function(){
				gDashboard.fieldManager = focusItem.fieldManager;
				gDashboard.itemGenerateManager.focusItem(item,focusItem);
				gDashboard.fieldChooser.resetAnalysisFieldArea(focusItem);
			});

			item.itemid = item.ComponentName + "_item";
			item.dataSourceId = item.dataSourceId;
			gDashboard.itemGenerateManager.focusItem(item,focusItem);

			gDashboard.itemGenerateManager.init();

//			KERIS
			if (gDashboard.reportType != 'AdHoc') {
				self.contextMenuItem(item);
			}
			
			
			if(!item.isAdhocItem || item.type == 'PIVOT_GRID' || item == focusItem){
				item.dragNdropController = setDragNdropController;
				//item.dragNdropController.addSortableOptionsForOpen(item);
			}else{
				item.dragNdropController = focusItem.dragNdropController;
			}
			
//			KERIS
//			KERIS 주석 끝
		});	
		
		
//		gDashboard.itemGenerateManager.focusItem(item,focusItem);
//		gDashboard.fieldChooser.setAnalysisFieldArea(item, false);
//		gDashboard.itemGenerateManager.init();
//		
//		item.dragNdropController = new WISE.widget.DragNDropController(item); 
//		item.dragNdropController.addDroppableOptions(item); 
//		item2.dragNdropController = item.dragNdropController;
//		item3.dragNdropController = item2.dragNdropController;
		
	};

//	KERIS
	this.contextMenuItem = function(item) {
		
		//20201112 AJKIM 통계 분석 서브 연결 보고서 삭제 dogfoot
		if(gDashboard.reportType == "StaticAnalysis") return;
		var html = '<div id="' + item.ComponentName + '_contextMenu"></div>';
		$(document.body).append(html);
//		var contextMenuItems = [ {
//			text : '아이템 복제'
//		}, {
//			text : '아이템 변경',
//			items : [ {
//				text : '차트'
//			}, {
//				text : '파이 차트'
//			}, {
//				text : '그리드'
//			}, {
//				text : '피벗 그리드'
//			}, {
//				text : '트리맵'
//			}, {
//				text : '스타 차트'
//			}, {
//				text : '히트맵'
//			}, {
//				text : '평행좌표계'
//			}, {
//				text : '코로플레스 지도'
//			}, {
//				text : '네모영역차트'
//			}, {
//				text : '폭포수차트'
//			}, {
//				text : 'D3버블차트'
//			}, {
//				text : '히스토그램'
//			} ]
//		} ];
		
		var contextMenuItems = [];
		var page = window.location.pathname.split('/');
		if(gDashboard.structure && gDashboard.structure.subLinkReport) {
			if(!(page[page.length - 1] === 'viewer.do')) {
				contextMenuItems = [{
					text : '서브 연결 보고서 설정'
				}];
			}
			
			$.each(gDashboard.structure.subLinkReport,function(_i,_linkMeta){
				if(item.ComponentName == _linkMeta.target_item || item.ComponentName == _linkMeta.target_item + '_' + _linkMeta.arg_id) {
					var targetNm = {"text" : _linkMeta.target_nm, "item" : _linkMeta.target_item};
					contextMenuItems.push(targetNm);
				}
			});
		} else {
			contextMenuItems = [{
				text : '서브 연결 보고서 설정'
			}];
		}
		
		var clickNum = 0;
		$("#" + item.ComponentName + "_contextMenu").dxContextMenu(
				{
					dataSource : contextMenuItems,
					width : 200,
					target : "#" + item.ComponentName + '_item',
					onShowing : function(e) {
						clickNum = 0;
					},
					onItemClick : function(e) {
						if (!e.itemData.items && clickNum == 0) {
							if (e.itemData.text == '차트') {
								gDashboard.insertItemManager
										.changeItemComponent('changeChart',
												item);
							} else if (e.itemData.text == '파이 차트') {
								gDashboard.insertItemManager
										.changeItemComponent('changePieChart',
												item);
							} else if (e.itemData.text == '그리드') {
								gDashboard.insertItemManager
										.changeItemComponent('changeDataGrid',
												item);
							} else if (e.itemData.text == '피벗 그리드') {
								gDashboard.insertItemManager
										.changeItemComponent('changePivotGrid',
												item);
							} else if (e.itemData.text == '트리맵') {
								gDashboard.insertItemManager
										.changeItemComponent('changeTreemap',
												item);
							} else if (e.itemData.text == '스타 차트') {
								gDashboard.insertItemManager
										.changeItemComponent('changeStarchart',
												item);
							} else if (e.itemData.text == '히트맵') {
								gDashboard.insertItemManager
										.changeItemComponent('changeHeatMap',
												item);
								
							} else if (e.itemData.text == '워드클라우드') {
								gDashboard.insertItemManager
								.changeItemComponent('changeWordCloud',
										item);
						
							} else if (e.itemData.text == '히스토그램') {
								gDashboard.insertItemManager
								.changeItemComponent('changeHistogramChart',
										item);
							}  else if (e.itemData.text == '평행좌표계') {
								gDashboard.insertItemManager
										.changeItemComponent(
												'changeParallelCoordinate',
												item);
								
							} else if (e.itemData.text == '버블팩차트') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeBubblePackChart',
										item);
						
							} else if (e.itemData.text == '워드클라우드2') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeWordCloudV2',
										item);
						
							} else if (e.itemData.text == '신경망바차트') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeDendrogramBarChart',
										item);
						
							} else if (e.itemData.text == '캘린더뷰') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeCalendarViewChart',
										item);
						
							} else if (e.itemData.text == '캘린더2뷰') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeCalendarView2Chart',
										item);
						
							} else if (e.itemData.text == '캘린더3뷰') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeCalendarView3Chart',
										item);
						
							} else if (e.itemData.text == '신경망트리') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeCollapsibleTreeChart',
										item);
						
							} else if (e.itemData.text == '레인지 바 차트') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeRangeBarChart',
										item);
						
							} else if (e.itemData.text == '레인지 영역 차트') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeRangeAreaChart',
										item);
						
							}  else if (e.itemData.text == '타임라인 차트') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeTimeLineChart',
										item);
						
							} else if (e.itemData.text == '피라미드 차트') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changePyramidChart',
										item);
							} else if (e.itemData.text == '카카오 지도') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeKakaoMap',
										item);	
							} else if (e.itemData.text == '카카오 지도2') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeKakaoMap2',
										item);	
							} else if (e.itemData.text == '퍼널 차트') {
								gDashboard.insertItemManager
								.changeItemComponent(
										'changeFunnelChart',
										item);
						
							} else if(e.itemData.text == '네모영역차트') {
			            		gDashboard.insertItemManager.changeItemComponent('changeRectangularAreaChart', item);
			            	} else if(e.itemData.text == '폭포수차트') {
			            		gDashboard.insertItemManager.changeItemComponent('changeWaterfallchart', item);
			            	} else if(e.itemData.text == '이분법차트') {
			            		gDashboard.insertItemManager.changeItemComponent('changeBipartitechart', item);
			            	} else if(e.itemData.text == '샌키차트') {
			            		gDashboard.insertItemManager.changeItemComponent('changeSankeychart', item);
			            	} else if(e.itemData.text == '긍정/부정 비교') {
			            		gDashboard.insertItemManager.changeItemComponent('changeDivergingChart', item);
			            	}  else if(e.itemData.text == 'D3버블차트') {
			            		gDashboard.insertItemManager.changeItemComponent('changeBubbleD3', item);
			            	} else if(e.itemData.text == '네트워크-축소') {
			            		gDashboard.insertItemManager.changeItemComponent('changeForceDirect', item);
			            	} else if(e.itemData.text == '네트워크-확대') {
			            		gDashboard.insertItemManager.changeItemComponent('changeForceDirectExpand', item);
			            	} else if (e.itemData.text == '코로플레스 지도') {
								gDashboard.insertItemManager
										.changeItemComponent(
												'changeChoroplethMap', item);
							} else if (e.itemData.text == '아이템 복제') {
								gDashboard.insertItemManager.insertItem(
										'copyItem', item, item);
							} else if (e.itemData.text == '서브 연결 보고서 설정') {
								if(!gDashboard.isNewReport) {
									gDashboard.reportUtility.addLinkedReport(true, item);
								} else {
									WISE.alert("보고서를 저장 한 후 연결보고서를 등록 할 수 있습니다.");
								}
							} else {
								
								/*dogfoot 서브 연결 보고서 데이터 - 필터 바인딩 임시 shlim 20210124*/
								var onData = {
                                    'rowPathData' : item.rowData,
                                    'colPathData' : item.colData
								}
//								gDashboard.layoutManager.openLink(e.itemData.item + '_item_link', e.itemData.text);
								gDashboard.layoutManager.openLink(e.itemData.item + '_item_link', e.itemData.text, onData);
							}
							clickNum++;
						}
					}
				});
	};
//	KERIS 주석 끝

	this.changeItemComponent = function(_itemkind, afterItem) {
		var item;
		var itemkind;

		var afterValueList, afterParameterList, afterSeriesList, afterAnalysisData;

		if (_itemkind == 'copyItem') {
			itemkind = afterItem;
		} else {
			itemkind = _itemkind;
		}

		// afterValueList = gDashboard.fieldManager.stateFieldChooser.find('#' +
		// afterItem.kind + 'ValueList' +
		// gDashboard.itemQuantity[afterItem.kind]);
		// afterParameterList =
		// gDashboard.fieldManager.stateFieldChooser.find('#' + afterItem.kind +
		// 'ParameterList' + gDashboard.itemQuantity[afterItem.kind]);
		// afterSeriesList = gDashboard.fieldManager.stateFieldChooser.find('#'
		// + afterItem.kind + 'SeriesList' +
		// gDashboard.itemQuantity[afterItem.kind]);
		// afterAnalysisData =
		// gDashboard.fieldManager.stateFieldChooser.find('.analysis-data');

		$(
				'#' + afterItem.kind + 'DashboardItem'
						+ gDashboard.itemQuantity[afterItem.kind]
						+ 'fieldManager').remove();

		$("#" + afterItem.ComponentName + '_item').empty();
		$("#" + afterItem.ComponentName + '_item_topicon').empty();

		switch (itemkind) {
		case 'changePivotGrid':
			item = new WISE.libs.Dashboard.item.PivotGridGenerator();

			item.kind = 'pivotGrid';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '피벗 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'pivotDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PivotGridFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeDataGrid':
			item = new WISE.libs.Dashboard.item.DataGridGenerator();

			item.kind = 'dataGrid';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '그리드 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'gridDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DataGridFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeChart':
			item = new WISE.libs.Dashboard.item.ChartGenerator();

			item.kind = 'chart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'chartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			item.fieldManager.seriesType = "Bar";
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changePieChart':
			item = new WISE.libs.Dashboard.item.PieGenerator();

			item.kind = 'pieChart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '파이 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'pieDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PieFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeGage':
			break;
		case 'changeCard':
			break;
		case 'changeHeatMap':
			item = new WISE.libs.Dashboard.item.HeatMapGenerator();

			item.kind = 'heatmap';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '히트맵 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'heatmapDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HeatMapFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeWordCloud' :
			item = new WISE.libs.Dashboard.item.WordCloud();

			item.kind = 'wordcloud';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '워드클라우드 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'WordCloudDashboardItem' + gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WordCloudFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeHistogramChart':
			item = new WISE.libs.Dashboard.item.HistogramChartGenerator();

			item.kind = 'histogramchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '히스토그램 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'histogramchartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HistogramChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeParallelCoordinate':
			item = new WISE.libs.Dashboard.item.ParallelCoorGenerator();

			item.kind = 'parallel';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '평행좌표계 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'parallelDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ParallelFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeBubblePackChart':
			item = new WISE.libs.Dashboard.item.BubblePackChartGenerator();
			
			item.kind = 'bubblepackchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '평행좌표계 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'bubblepackchartDashboardItem'
				+ gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubblePackChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeWordCloudV2':
			item = new WISE.libs.Dashboard.item.WordCloudV2Generator();
			
			item.kind = 'wordcloudv2';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '평행좌표계 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'wordcloudv2DashboardItem'
				+ gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WordCloudV2FieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeDendrogramBarChart':
			item = new WISE.libs.Dashboard.item.DendrogramBarChartGenerator();
			
			item.kind = 'dendrogrambarchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '신경망바 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'dendrogrambarchartDashboardItem'
				+ gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DendrogramBarChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeCalendarViewChart':
			item = new WISE.libs.Dashboard.item.CalendarViewChartGenerator();
			
			item.kind = 'calendarviewchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '캘린더뷰 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'calendarviewchartDashboardItem'
				+ gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarViewChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeCalendarView2Chart':
			item = new WISE.libs.Dashboard.item.CalendarView2ChartGenerator();
			
			item.kind = 'calendarview2chart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '캘린더2뷰 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'calendarview2chartDashboardItem'
				+ gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarView2ChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeCalendarView3Chart':
			item = new WISE.libs.Dashboard.item.CalendarView3ChartGenerator();
			
			item.kind = 'calendarview3chart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '캘린더3뷰 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'calendarview3chartDashboardItem'
				+ gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CalendarView3ChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeCollapsibleTreeChart':
			item = new WISE.libs.Dashboard.item.CollapsibleTreeChartGenerator();
			
			item.kind = 'collapsibletreechart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '신경망트리 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'collapsibletreechartDashboardItem'
				+ gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.CollapsibleTreeChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeRangeBarChart':
			item = new WISE.libs.Dashboard.item.RangeBarChartGenerator();

			item.kind = 'rangebarchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '레인지 바 차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'rangebarchartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RangeBarChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			item.fieldManager.seriesType = "rangeBar";
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeRangeAreaChart':
			item = new WISE.libs.Dashboard.item.RangeBarChartGenerator();
			
			item.kind = 'rangeareachart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '레인지 영역 차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'rangeareachartDashboardItem'
				+ gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RangeAreaChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			item.fieldManager.seriesType = "rangeArea";
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeTimeLineChart':
			item = new WISE.libs.Dashboard.item.TimeLineChartGenerator();

			item.kind = 'timelinechart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '타임라인 차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'timelinechartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TimeLineChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			item.fieldManager.seriesType = "timeline";
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeChoroplethMap':
			item = new WISE.libs.Dashboard.item.ChoroplethMapGenerator();
			item.kind = 'choroplethMap';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '지도 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'choroplethMapDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ChoroplethMapFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeTreemap':
			item = new WISE.libs.Dashboard.item.TreeMapGenerator();
			item.kind = 'Treemap';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '트리맵 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'treemapDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.TreeMapFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeStarchart':
			item = new WISE.libs.Dashboard.item.StarChartGenerator();
			item.kind = 'Starchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '스타차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'starchartDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.StarChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeRectangularAreaChart' :
			item = new WISE.libs.Dashboard.item.RectangularAreaChartGenerator();
			
			item.kind = 'RectangularAreaChart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '네모차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'RectangularAreaChartDashboardItem' + gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.RectangularAreaChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeWaterfallchart' :
			item = new WISE.libs.Dashboard.item.WaterfallChartGenerator();
			
			item.kind = 'waterfallchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '폭포수차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'waterfallchartDashboardItem' + gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.WaterfallChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeBipartitechart' :
			item = new WISE.libs.Dashboard.item.BipartiteChartGenerator();
			
			item.kind = 'bipartitechart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '이분법차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'bipartitechartDashboardItem' + gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BipartiteChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changePyramidChart' :
			item = new WISE.libs.Dashboard.item.PyramidChartGenerator();
			
			item.kind = 'pyramidchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '피라미드차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'pyramidchartDashboardItem' + gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.PyramidChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		/* DOGFOOT syjin 카카오 지도 추가  20200820 */
		case 'changeKakaoMap' :
			item = new WISE.libs.Dashboard.item.KakaoMapGenerator();
			
			item.kind = 'kakaoMap';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '카카오지도 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'kakaoMapDashboardItem' + gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.KakaoMapFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeKakaoMap2' :
			item = new WISE.libs.Dashboard.item.KakaoMap2Generator();
			
			item.kind = 'kakaoMap2';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '카카오지도 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'kakaoMap2DashboardItem' + gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.KakaoMap2FieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeFunnelChart' :
			item = new WISE.libs.Dashboard.item.FunnelChartGenerator();
			
			item.kind = 'funnelchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '퍼널차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'funnelchartDashboardItem' + gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.FunnelChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeSankeychart' :
			item = new WISE.libs.Dashboard.item.SankeyChartGenerator();
			
			item.kind = 'sankeychart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '샌키차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'sankeychartDashboardItem' + gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.SankeyChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeDivergingChart' :
			item = new WISE.libs.Dashboard.item.DivergingChartGenerator();
			
			item.kind = 'divergingchart';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '긍정/부정비교 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'divergingchartDashboardItem' + gDashboard.itemQuantity[item.kind];
			
			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.DivergingChartFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeBubbleD3' :
			item = new WISE.libs.Dashboard.item.BubbleD3();

			item.kind = 'bubbled3';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = 'D3버블차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'bubbled3DashboardItem' + gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.BubbleD3FieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeHierarchicalEdge':
			item = new WISE.libs.Dashboard.item.HierarchicalGenerator();

			item.kind = 'hierarchical';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '계층차트 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'hierarchicalDashboardItem'
					+ gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.HierarchicalFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setlAnalysisFieldArea(item);
			break;
		case 'changeForceDirect' :
			item = new WISE.libs.Dashboard.item.ForceDirect();

			item.kind = 'forceDirect';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '네트워크-축소 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'forceDirectDashboardItem' + gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ForceDirectFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		case 'changeForceDirectExpand' :
			item = new WISE.libs.Dashboard.item.ForceDirectExpand();

			item.kind = 'forceDirectExpand';
			gDashboard.itemQuantity[item.kind]++;
			item.Name = '네트워크-확대 ' + gDashboard.itemQuantity[item.kind];
			item.ComponentName = 'forceDirectExpandDashboardItem' + gDashboard.itemQuantity[item.kind];

			gDashboard.fieldManager = item.fieldManager = new WISE.libs.Dashboard.ForceDirectExpandFieldManager();
			item.fieldManager.index = item.index = gDashboard.itemQuantity[item.kind];
			gDashboard.fieldChooser.setAnalysisFieldArea(item);
			break;
		}

		$('#' + afterItem.ComponentName + '_item').off();

		$('#' + item.ComponentName).on('click', function() {
			gDashboard.fieldManager = item.fieldManager;
			gDashboard.itemGenerateManager.focusItem(item,item);
			gDashboard.fieldChooser.resetAnalysisFieldArea(item);
		});

		item.itemid = item.ComponentName + '_item';

		gDashboard.itemGenerateManager.focusItem(item,item);
		// item.dataSourceId = 'dataSource1';
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _o) {
			if (_o.itemid == afterItem.itemid) {
				gDashboard.itemGenerateManager.dxItemBasten[_i] = item;
			}
		});

		// if(item.kind == 'dataGrid' && afterAnalysisData.length != 0) {
		// $('#columnList' + gDashboard.itemQuantity[item.kind]).empty();
		// gDashboard.fieldManager.stateFieldChooser.find('#columnList' +
		// gDashboard.itemQuantity[item.kind]).append(afterValueList.children());
		// gDashboard.fieldManager.stateFieldChooser.find('#columnList' +
		// gDashboard.itemQuantity[item.kind]).append(afterParameterList.children());
		// gDashboard.fieldManager.stateFieldChooser.find('#columnList' +
		// gDashboard.itemQuantity[item.kind]).append(afterSeriesList.children());
		// } else if(item.kind == 'pivotGrid' && afterAnalysisData.length != 0)
		// {
		// $('#dataList' + gDashboard.itemQuantity[item.kind]).empty();
		// $('#rowList' + gDashboard.itemQuantity[item.kind]).empty();
		// $('#colList' + gDashboard.itemQuantity[item.kind]).empty();
		// gDashboard.fieldManager.stateFieldChooser.find('#dataList' +
		// gDashboard.itemQuantity[item.kind]).append(afterValueList.children());
		// gDashboard.fieldManager.stateFieldChooser.find('#rowList' +
		// gDashboard.itemQuantity[item.kind]).append(afterParameterList.children());
		// gDashboard.fieldManager.stateFieldChooser.find('#colList' +
		// gDashboard.itemQuantity[item.kind]).append(afterSeriesList.children());
		// $('.seriesoption').remove();
		// $('#dataList' +
		// gDashboard.itemQuantity[item.kind]).find('a').css('width', '100%');
		//			
		// item.dragNdropController = new
		// WISE.widget.DragNDropController(item);
		// item.dragNdropController.loadItemData(item);
		// item.dragNdropController.addSortableOptionsForOpen(item);
		// gDashboard.dragNdropController.addSortableOptions(item);
		//			
		// }

		// gDashboard.itemGenerateManager.dxItemBasten.push(item);
		gDashboard.itemGenerateManager.init();

		$("#" + afterItem.ComponentName).attr('id', item.ComponentName);
		$("#" + afterItem.ComponentName + '_item').attr('id',
				item.ComponentName + '_item');
		$("#" + afterItem.ComponentName + '_item_title').attr('id',
				item.ComponentName + '_item_title');
		$("#" + afterItem.ComponentName + '_item_topicon').attr('id',
				item.ComponentName + '_item_topicon');
		$("#" + item.ComponentName + '_item_topicon').children('.lm_close')
				.attr('item', item.ComponentName);
		var goldenLayout = gDashboard.goldenLayoutManager;
		goldenLayout.changeTitle(item.ComponentName + '_item', item.Name,
				goldenLayout.canvasLayout.root.contentItems);

		item.dragNdropController = new WISE.widget.DragNDropController(item);
		item.dragNdropController.addDroppableOptions(item);

//		KERIS
		if (gDashboard.reportType != 'AdHoc') {
			this.contextMenuItem(item);
		}
//		KERIS 주석 끝
	};

	this.openAdHocItem = function(layout) {
		$("[id$='contextMenu']").remove();
		var fieldManager = new WISE.libs.Dashboard.AdhoceItemFieldManager();

		// chart 넣기
		//2020.11.06 mksong resource Import 동적 구현 dogfoot
		WISE.loadedSourceCheck('itemJS','Chart');
		var item = new WISE.libs.Dashboard.item.ChartGenerator();
		item.kind = 'chart';
		gDashboard.itemQuantity[item.kind]++;
		//2020.04.09 mksong 비정형 아이템 이름 변경 저장 및 불러오기 dogfoot
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
		item.ComponentName = 'chartDashboardItem' + gDashboard.itemQuantity[item.kind];
		item.isAdhocItem = true;
		/*dogfoot 비정형 주제영역보고서 열었을때 데이터 항목 index 오류 수정 shlim 20200715*/
		item.adhocIndex = 1;
		gDashboard.fieldManager = item.fieldManager = fieldManager;
		item.fieldManager.focusItemType = 'adhocItem';
		gDashboard.itemQuantity[item.fieldManager.focusItemType] = item.adhocIndex;
		
		item.index = gDashboard.itemQuantity[item.kind];
		item.fieldManager.index = item.adhocIndex;
		item.fieldManager.seriesType = 'Bar';
		item.itemid = item.ComponentName + '_item';
		var chartXml = gDashboard.structure.chartXml;
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
				PrecisionOption: '반올림',
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

		// 피벗 생성
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
		
		//2020.11.13 mksong 비정형 보고서 showCaption 기능 추가 dogfoot
		if(gDashboard.structure.ReportMasterInfo.reportJson.DISP_PIVOT_CAPTION_ELEMENT != undefined){
			item2['ShowCaption'] = gDashboard.structure.ReportMasterInfo.reportJson.DISP_PIVOT_CAPTION_ELEMENT;
			if(WISE.Constants.editmode != 'viewer'){
				gDashboard.structure.ReportMasterInfo.reportJson.DISP_PIVOT_CAPTION_ELEMENT = undefined;
			}	
		}
		
		item2.ComponentName = 'pivotDashboardItem' + gDashboard.itemQuantity[item2.kind];
		item2.isAdhocItem = true;
		/*dogfoot 비정형 주제영역보고서 열었을때 데이터 항목 index 오류 수정 shlim 20200715*/
		item2.adhocIndex = 1;
		gDashboard.fieldManager = item2.fieldManager = fieldManager;
		item2.index = gDashboard.itemQuantity[item2.kind];
		item2.fieldManager.index = item2.adhocIndex;
		gDashboard.fieldChooser.setAnalysisFieldArea(item2, true);
		item2.itemid = item2.ComponentName + '_item';

		/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
		var dataSrcName = gDashboard.structure.ReportMasterInfo.cube_nm;
		var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(dataSrcName);
		gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id', dataSrcId);

		// initialize chart and pivot
		gDashboard.itemGenerateManager.dxItemBasten.push(item);
		gDashboard.itemGenerateManager.dxItemBasten.push(item2);
		gDashboard.insertItemManager.generateItemContainer('adhoc', true);
		gDashboard.itemGenerateManager.init();
		item.dragNdropController = new WISE.widget.DragNDropController(item);
		item2.dragNdropController = new WISE.widget.DragNDropController(item2);
		/* DOGFOOT hjkim 주제영역 필터 추가되게 20200704 */
		$('.filter-bar').droppable(item.dragNdropController.droppableOptions).sortable(gDashboard.dragNdropController.sortableOptions);
		$('.filter-bar').sortable('disable');
		self.contextMenuItem(item);
		self.contextMenuItem(item2);
		// 2019.12.16 수정자 : mksong 뷰어 비정형 ui 수정 반영 dogfoot
		gDashboard.changeReportTypeManager.activeAdhocLayout();
	}
};
