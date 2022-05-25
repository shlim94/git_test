/**
 * 
 */

WISE.libs.Dashboard.item.ItemFactory = function() {
	var self = this;
	
	//2020.11.03 mksong resource Import 동적 구현 dogfoot
	this.getInstance = function(_type) {
		var instance;
		switch(_type) {
		case 'Image':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ImageGenerator();
			break;
		case 'TextBox':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.TextBoxGenerator();
			break;
		case 'Pivot':
			WISE.loadedSourceCheck('itemJS','PivotGrid');
			instance = new WISE.libs.Dashboard.item.PivotGridGenerator();
			instance.child = new WISE.libs.Dashboard.item.PivotGridGenerator();
			break;
		case 'Grid':
			WISE.loadedSourceCheck('itemJS','DataGrid');
			instance = new WISE.libs.Dashboard.item.DataGridGenerator();
			instance.child = new WISE.libs.Dashboard.item.DataGridGenerator();
			break;
		case 'Card': 
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.CardGenerator();
			instance.child = new WISE.libs.Dashboard.item.CardGenerator();
			break;
		case 'Chart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ChartGenerator();
			instance.child = new WISE.libs.Dashboard.item.ChartGenerator();
			break;
		case 'Pie':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.PieGenerator();
			instance.child = new WISE.libs.Dashboard.item.PieGenerator();
			break;
		case 'Gauge':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.GaugeGenerator();
			instance.child = new WISE.libs.Dashboard.item.GaugeGenerator();
			break;
		case 'PieMap':
		case 'BubbleMap':
		case 'GeoPointMap':
			WISE.loadedSourceCheck('itemJS','GeoPointMap');
			instance = new WISE.libs.Dashboard.item.GeoPointMapGenerator(_type);
			break;
		case 'ChoroplethMap':
			WISE.loadedSourceCheck('itemJS', 'Map.Choropleth');
			instance = new WISE.libs.Dashboard.item.ChoroplethMapGenerator();
			break;
		case 'ComboBox':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ComboBoxGenerator();
			break;
		case 'ListBox':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ListBoxGenerator();
			break;
		case 'TreeView':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.TreeViewGenerator();
			break;
		case 'HeatMap':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.HeatMapGenerator();
			break;
		case 'HeatMap2':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.HeatMap2Generator();
			break;
		case 'SynchronizedChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.SynchronizedChartGenerator();
			break;
		case 'CoordinateDot':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.CoordinateDotGenerator();
			break;
		case 'WordCloud':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.WordCloud();
			break;	
		case 'Parallel':
			WISE.loadedSourceCheck('itemJS', 'ParallelCoordinate');
			instance = new WISE.libs.Dashboard.item.ParallelCoorGenerator();
			break;
		case 'BubblePackChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.BubblePackChartGenerator();
			break;
		case 'WordCloudV2':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.WordCloudV2Generator();
			break;
		case 'DendrogramBarChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.DendrogramBarChartGenerator();
			break;
		case 'CalendarViewChart':
			WISE.loadedSourceCheck('itemJS', 'CalendarView');
			instance = new WISE.libs.Dashboard.item.CalendarViewChartGenerator();
			break;
		case 'CalendarView2Chart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.CalendarView2ChartGenerator();
			break;
		case 'CalendarView3Chart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.CalendarView3ChartGenerator();
			break;
		case 'CollapsibleTreeChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.CollapsibleTreeChartGenerator();
			break;
		case 'RangeBarChart':
			WISE.loadedSourceCheck('itemJS','RangeBar');
			instance = new WISE.libs.Dashboard.item.RangeBarChartGenerator();
			instance.child = new WISE.libs.Dashboard.item.RangeBarChartGenerator();
			break;
		case 'RangeAreaChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.RangeAreaChartGenerator();
			instance.child = new WISE.libs.Dashboard.item.RangeAreaChartGenerator();
			break;
		case 'TimeLineChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.TimeLineChartGenerator();
			instance.child = new WISE.libs.Dashboard.item.TimeLineChartGenerator();
			break;
		case 'RectangularAreaChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.RectangularAreaChartGenerator();
			break;
		case 'Waterfallchart':
			WISE.loadedSourceCheck('itemJS', 'WaterfallChart');
			instance = new WISE.libs.Dashboard.item.WaterfallChartGenerator();
			break;
		case 'Bipartitechart':
			WISE.loadedSourceCheck('itemJS','BipartiteChart');
			instance = new WISE.libs.Dashboard.item.BipartiteChartGenerator();
			break;
		case 'Sankeychart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.SankeyChartGenerator();
			break;
		case 'DivergingChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.DivergingChartGenerator();
			break;
		case 'DependencyWheel':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.DependencyWheelGenerator();
			break;
		case 'SequencesSunburst':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.SequencesSunburstGenerator();
			break;
		case 'BoxPlot':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.BoxPlotGenerator();
			break;
		case 'CoordinateLine':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.CoordinateLineGenerator();
			break;
		case 'ScatterPlot':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ScatterPlotGenerator();
			break;
		case 'ScatterPlot2':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ScatterPlot2Generator();
			break;
		case 'RadialTidyTree':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.RadialTidyTreeGenerator();
			break;
		case 'ScatterPlotMatrix':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ScatterPlotMatrixGenerator();
			break;
		case 'HistoryTimeline':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.HistoryTimelineGenerator();
			break;
		case 'ArcDiagram':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ArcDiagramGenerator();
			break;
		case 'LiquidFillGauge':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.LiquidFillGaugeGenerator();
			break;
		case 'HistogramChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.HistogramChartGenerator();
			break;
		case 'BubbleD3':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.BubbleD3Generator();
			break;
		case 'BubbleChart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.BubbleChartGenerator();
			break;
		case 'Treemap':
			WISE.loadedSourceCheck('itemJS','TreeMap');
			instance = new WISE.libs.Dashboard.item.TreeMapGenerator();
			break;
		case 'Starchart':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.StarChartGenerator();
			break;
//		case 'RangeFilter':
//			WISE.loadedSourceCheck('itemJS',_type);
//			instance = new WISE.libs.Dashboard.item.RangeFilterGenerator();
//			break;
		case 'Hierarchical':
			WISE.loadedSourceCheck('itemJS','HierarchicalEdge');
			instance = new WISE.libs.Dashboard.item.HierarchicalEdgeGenerator();
			break;
		case 'ForceDirect':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ForceDirectGenerator();
			break;
		case 'ForceDirectExpand':
			WISE.loadedSourceCheck('itemJS',_type);
			instance = new WISE.libs.Dashboard.item.ForceDirectExpandGenerator();
			break;
		case 'Funnelchart':
			WISE.loadedSourceCheck('itemJS', 'FunnelChart');
			instance = new WISE.libs.Dashboard.item.FunnelChartGenerator();
			break;
		case 'Pyramidchart':
			WISE.loadedSourceCheck('itemJS', 'PyramidChart');
			instance = new WISE.libs.Dashboard.item.PyramidChartGenerator();
			break;
		/* DOGFOOT syjin 카카오 지도 추가  20200820 */
		case 'KakaoMap':
			WISE.loadedSourceCheck('itemJS', 'Map.KakaoMap');
			instance = new WISE.libs.Dashboard.item.KakaoMapGenerator();
			break;
		case 'KakaoMap2':
			WISE.loadedSourceCheck('itemJS', 'Map.KakaoMap2');
			instance = new WISE.libs.Dashboard.item.KakaoMap2Generator();
			break;
		default:
			WISE.loadedSourceCheck('itemJS',_type);
			instance = undefined;
		}
		return instance;
	};
};