/**
 * @Param _pageid 
 * 		report_mstr의 report_id 
 */
WISE.widget.configured('15337', {
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
		'dx-신규계좌_내역조회': {
			pager: {
				showPageSizeSelector: true,
				allowedPageSizes: [15,25,50]
			},
			paging: {
				enabled: true,
				pageSize: 30
			}
		}
	}
});

WISE.widget.configured('15021', {
	'DATA_GRID': {
		summaryEnabled: true,
		
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
		'dx-그리드_2': {
			pager: {
				showPageSizeSelector: true,
				allowedPageSizes: [15,25,50]
			},
			paging: {
				enabled: true,
				pageSize: 15
			}
		}
	},
	'CONDITION': {
		gap: 15,
		datasource: {
			list: {
				pageSize: 9999
			}
		},
		mandatory: ['@COURT_CD', '@IROF_CD'] // ['@COURT_CD', '@IROF_CD','@TEST_CD']
	},
	'SIMPLE_CHART': {
		dx: {
			palette: 'Default'
		}
	},
	'PIE_CHART': {
		dx: {
			title: {
				font: {
					size: 14
				}
			},
			palette: 'Default'
		}
	},
	'CHOROPLETH_MAP': {
//		'CustomScale_RangeStop': [0,100,150,200,300,400,600,700,800,900]
	}
});
WISE.widget.configured('17159',{
	'CHOROPLETH_MAP': {
		data: 'city.geojson'
	}
});
WISE.widget.configured('17152_choroplethMapDashboardItem2',{
	'CHOROPLETH_MAP': {
		data: 'city.geojson'
	}
});