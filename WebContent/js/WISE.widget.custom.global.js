WISE.widget.configured('common', {
	'Config': {
		debug: true,
//		searchOnStart: false,
		searchOnStart: true,
		useNativeScrolling: false,
		parameter: {
			showButton: false
		},
		message: {
			datasource: {
				connected: false
			},
			search: {
				manyData: false
			}
		},
		download: {
			maxRow: 1000
		}
	},
	
	'CONDITION': {
		gap: 15,
		datasource: {
			list: {
				pageSize: 9999
			}
		},
//		hiding:{
//			validate:true,
//			paramCode:[
//				{
//					paramKey:'@DPTCD',
//					hidingWhenAll:false,
//					paramValue:['@All']
//				},
//				{
//					paramKey:'@hhh',
//					hidingWhenAll:false,
//					paramValue:['골프','농구']
//				}
//			],
//		},
		mandatory: ['@COURT_CD'] // ['@COURT_CD', '@IROF_CD','@TEST_CD']
	},
	'SIMPLE_CHART': {
		axisX: {
			label: {
				font: {
					weight:400 // 기본 400 100~900까지 100단위로 조정
				},
				overlappingBehavior: {
					mode: 'stagger' //stagger 또는 rotate로 설정
				}
			},
			title:{
				font:{
					weight:400 //  기본 400 100~900까지 100단위로 조정
				}
			}
		},
		axisY: {
			label:{
				font:{
					weight:400 //  기본 400 100~900까지 100단위로 조정
				},
			},
			title:{
				font:{
					weight:400 //  기본 400 100~900까지 100단위로 조정
				},
			}
		},
		secondaxisY: {
			label:{
				font:{
					weight:400 //  기본 400 100~900까지 100단위로 조정
				},
			},
			title:{
				font:{
					weight:400 //  기본 400 100~900까지 100단위로 조정
				},
			}
		},
		valueGrid:{
			visible:false // x축 그리드 표시 기본 false
		},
		series: {
			change: {
				type: 'imagetext', /* text, image, imagetext (default: image) */
				list: ['bar','stackedbar','fullstackedbar','scatter','line','stackedline',
				       'fullstackedline','stepline','spline','area','stackedarea',
				       'fullstackedarea','steparea','stackedsplinearea','fullstackedsplinearea']
			}
		},
		
		/**
	     * 사용자 커스터마이징 설정
	     * 개발자는 적용하고자하는 dxChart configurations를 기술
	     * 
	     * @UnChangableOptions
	     *     rotated
	     *     dataSource
	     *     commonSeriesSettings.argumentField -> 'arg'
	     *     series
	     *     argumentAxis
	     *     valueAxis
	     *     panes
	     *     tooltip
	     *     legend
	     *     onPointClick
	     */
		dx: {
			// equalBarWidth: true,
			// barWidth: 0.97,
			ignoreEmptyPoints: true,
			barPadding: 0.97,
//			resolveLabelOverlapping: 'stack', // range series가 포함 될 경우 resolveLabelOverlapping은 'none'으로 강제 설정 됨(devextreme bug)
//			palette: ['rgb(199, 21, 133)','rgb(100, 149, 237)','rgb(34, 139, 34)','rgb(250, 128, 114)','rgb(255, 69, 0)','rgb(176, 224, 230)']
			palette: "Default" //Default, Soft Pastel, Harmony Light, Pastel, Bright, Soft, Ocean, Vintage, Violet
		}
	},
	'PIE_CHART': {
		/**
	     * 사용자 커스터마이징 설정
	     * 개발자는 적용하고자하는 dxPie configurations를 기술 
	     * 
	     * @UnChangableOptions
	     *     series
	     *     tooltip
	     *     legend
	     *     adaptiveLayout.keepLabels -> true
	     *     redrawOnResize -> true
	     *     onPointClick
	     */
		dx: {
			title: {
				font: {
					size: 22
				}
			},
			loadingIndicator: {
				backgroundColor: '#eaeaea',
				font: {
					weight: 700
				},
				show: true
			},
			resolveLabelOverlapping: 'shift',
			palette: "Default" //Default, Soft Pastel, Harmony Light, Pastel, Bright, Soft, Ocean, Vintage, Violet
		}
	},
	'CARD_CHART': {
		widthSize: 470,
		fontSize: 45  // pixel
	},
	'DATA_GRID': {
		summaryEnabled: false,
		
		/**
		 * 사용자 커스터마이징 설정
	     * 개발자는 적용하고자하는 dxPie configurations를 기술 
	     * 
	     * @UnChangableOptions
	     *     columns
	     *     sorting.mode -> 'multiple'
	     *     selection.mode -> 'single'
	     *     selection.showCheckBoxesMode -> 'always'
	     *     rowAlternationEnabled
	     *     showColumnHeaders
	     *     wordWrapEnabled
	     *     noDataText
	     *     export
	     *     onSelectionChanged
	     *     onRowClick
	     *     onContentReady
	     */
		dx: {
			allowColumnReordering: true,
			allowColumnResizing: false,
			columnAutoWidth:true,
			hoverStateEnabled: true,
			showColumnLines: true,
			showRowLines: true,
			pager: {
				showPageSizeSelector: true,
				allowedPageSizes: [10,25,50]
			},
			paging: {
				enabled: false,
				pageSize: 30
			}
		}
	},
	'PIVOT_GRID': {
		dataSource: {
			row: {
				width: 125
			},
			column: {
				width: 125
			},
			data: {
				width: 50
			}
		},
		
		/**
		 * 사용자 커스터마이징 설정
	     * 개발자는 적용하고자하는 dxPie configurations를 기술 
	     * 
		 * @UnChangableOptions
		 *     dataSource
		 *     useNativeScrolling -> CUSTOMIZED('useNativeScrolling','Config'),
		 *     export -> true
		 *     fieldChooser.enabled -> false
		 */
		dx: {
			allowSortingBySummary: true,
			allowSorting: true,
			allowFiltering: true,
			allowExpandAll: true
		}
	},
	
	/**
	 * map은 dx option을 적용할 수 없음
	 */
	'CHOROPLETH_MAP': {
		useShapeFile: false,
//		data: 'state.geojson',
		data: 'KOR_adm1_edit_kor.geojson',
//		palette: ['rgb(199, 21, 133)','rgb(100, 149, 237)','rgb(34, 139, 34)','rgb(250, 128, 114)','rgb(255, 69, 0)','rgb(176, 224, 230)'],
		rangeStopMaxValue: 10000000000000000000000,
	//	CustomScale_RangeStop: [0,50,100,200,300,400,600,700,800,900] // default Range Stop
	},
	'GEOPOINT_MAP': {
		rangeStopMaxValue: 10000000000000000000000,
	}
});
