/** DataGridUtility */
WISE.libs.Dashboard.item.DataGridUtility = {
	Constants: {
		'SUFFIX_INTERVAL_FOR_BAR_CHART':'_interval',
		'SUFFIX_COL_NM_FOR_BAR_CHART': '_for_barchart',
		'SUFFIX_COL_NM_MIN_FOR_BAR_CHART': '_min_for_barchart',
		'SUFFIX_COL_NM_FOR_SPARKLINE_CHART': '_for_sparkline'
	},
	Graph: {		
		/**
		 * @Param _opts (columnConfig, dataMember)
		 * */
		'bar': function(_opts) {
			delete _opts.columnConfig.calculateDisplayValue;
			_opts.columnConfig.cellTemplate = function(_container, _options) {
				var Palette = _opts.item.Grid.Palette
				if(typeof Palette === "string")
					Palette = getPaletteValue(_opts.item.Grid.Palette);
				if(!Palette)
					var Palette = getPaletteValue(userJsonObject.defaultPalette);
				var DGU = WISE.libs.Dashboard.item.DataGridUtility;
				var tempOrigin,tempMax,interval,tempMin;
				var barValue = _options.data[_opts.dataMember.nameBySummaryType];
				var maxValue = _options.data[_opts.dataMember.nameBySummaryType+'_maxValue'];
				var chartWidth = _container.width() - 2;
				//_container.addClass("chart-cell");
				var color = Palette[_options.component.option('dataSource').store()._array.indexOf(_options.data) % Palette.length];
				if(typeof color === "string")
					color = gDashboard.itemColorManager.hexToRgb(color);
				var configs = {
						color: "rgb(" + color.r + ", " + color.g + ", " + color.b + ")",
						onIncidentOccurred: null,
				        size: {
//				            width: Math.floor(chartWidth)
				        },
				        margin: {
				            top: 5,
				            bottom: 0,
				            left: 5
				        },
				        showTarget: false,
				        showZeroLevel: false,
				        value:barValue,
				        startScaleValue: 0,
				        endScaleValue: maxValue,
				        tooltip: {
				            enabled: true,				           
				            paddingTopBottom: 2,
				            customizeTooltip: function(_arg) {
				                return { text: _options.text };
				            },
				            zIndex: 5
				        }
				};
				//20200731 ajkim 그리드 바 측정값 라벨 추가 dogfoot
				
				var $bullet = $('<div class="gridBar" style="width:100%; display:inline-block; position:relative; float:left"/>').dxBullet(configs).appendTo(_container);
				var $label = $('<div class="gridBarLabel"style="width:auto; display:inline-block; margin: 0 auto; position:absolute; color: ' + "rgb(" + (color.r - 70) + ", " + (color.g - 70) + ", " + (color.b - 70) + ")" + ';">' // background-color: rgb(255, 255, 255, .5);
						+ WISE.util.Number.unit(_options.value, _opts.dataMember.formatType, _opts.dataMember.unit, _opts.dataMember.precision, _opts.dataMember.includeGroupSeparator, undefined, _opts.dataMember.suffix, _opts.dataMember.suffixEnabled, _opts.dataMember.precisionOption) +
						'</div>').appendTo(_container); 
				setTimeout(function(){
					$label.css("top", $bullet.position().top + $bullet.height()/2 - $label.height()/2);
	                $label.css("left", $bullet.position().left + $bullet.width() - $label.width());
					//라벨을 그릴 수 있는 크기가 아닐 땐 보이지 않음
					if($label.width() > $bullet.width())
	                	$label.css('display', 'none');
	                else
	                	$label.css('display', 'inline-block');
				}, 100)
            };
		},
		
		/**
		 * @Param _opts (columnConfig, dataMember, dimensions)
		 * */
		'sparkline': function(_opts) {			
			_opts.columnConfig.cellTemplate = function(_container, _options) {				
				var sparklineOpts = _opts.dataMember.sparkline.sparklineOptions;				
				$.extend(sparklineOpts);	
				
				//_container.addClass("chart-cell");
				var time = 0;
				
				//그리드 넓비조정 자동 맞춤일 경우 width값을 가져오지 못하기 때문에 아래와 같이 비동기호출로 맞춰야함
				if(_options.component.option('columnAutoWidth')){
					time = 100;
				}
				setTimeout(function () {
					var chartWidth = _container.width();						
					// type: line, area, bar, winloss
					var configs = {
						dataSource: _options.data.sparkLineData,
						argumentField: 'TimeLine',
						valueField: 'Volumne',
					    type: sparklineOpts.ViewType.toLowerCase(),
					    lineColor: "#a6a6a6",
					    size : {
					    	width:Math.floor(chartWidth)
					    },
//						firstLastColor: '#4641d9',
					    showMinMax: sparklineOpts.HighlightMinMaxPoints,
					    showFirstLast: sparklineOpts.HighlightStartEndPoints,
					    tooltip: {opacity:1, zIndex: 5}
					};
					
					$('<div style="width:100%; height:50px; display: inline-block;"/>').dxSparkline(configs).appendTo(_container);
				},time);
				
			};
		},
		
		/**
		 * @Param _opts (columnConfig, dataMember, deltaOptions)
		 * */
		'delta-value': function(_opts) {
			
		}
	}
}; // end of WISE.libs.Dashboard.item.DataGridUtility
