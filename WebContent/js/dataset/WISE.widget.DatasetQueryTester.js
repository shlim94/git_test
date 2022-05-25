/**
 * 데이터집합 쿼리 실행 팝업 컴포넌트 클래스
 * Dataset query tester popup component class.
 */
WISE.libs.Dashboard.DatasetQueryTester = function() {
    var self = this;
    this.paramFilterBar = new WISE.libs.Dashboard.ParameterBar();

    this.state = {
        dsId: null,
        dsType: '',
        queryText: '',
        params: [],
        paramValues: {},
        queryResult: [],
		dsMultiTblList: [],
    };
    this.container = null;
    this.components = {
        queryTextViewer: null,
        queryStartBtn: null,
        downloadResultBtn: null,
        resultCounter: null,
        queryResultGrid: null,
        queryBackBtn: null,
    };

    /**
     * Update component state.
     */
    this.setState = function(state, action) {
        switch (action) {
            case 'PARAM_VALUES':
                $.extend(self.state.paramValues, state);
                break;
            default:
                $.extend(self.state, state);
        }
    }

    /**
     * Close query tester popup.
     */
    function onPopupClose() {
        self.container.hide();
    }

    /**
     * query text field component (ace)
     */
    function queryTextViewer() {
        return ace.edit(
            'queryTextViewer', 
            {
                mode: 'ace/mode/sql',
                theme: 'ace/theme/crimson_editor',
                value: self.state.queryText,
                readOnly: true,
                showPrintMargin: false,
            }
        );
    }

    /**
     * query start component (button)
     */
    function queryStartBtn() {
        return $('#queryStartBtn').dxButton({
            text: 'SQL 실행',
			icon: 'refresh',
            type: 'normal',
            onClick: function(e) {
            	/* DOGFOOT ktkang 쿼리보기 오류 수정 20200716 */
            	gDashboard.parameterFilterBar.setState(self.paramFilterBar.state.listValues,'LIST_VALUES');
            	gDashboard.parameterFilterBar.setState(self.paramFilterBar.state.paramValues,'PARAM_VALUES');
                $.ajax({
                    method: 'POST',
                    url: WISE.Constants.context + '/report/directSql.do',
                    data: {
                        dsid: self.state.dsId,
                        dstype: self.state.dsType,
                        sql: self.state.queryText,
						tbllist: $.toJSON(self.state.dsMultiTblList),
                        params: $.toJSON(WISE.libs.Dashboard.item.DatasetUtility.getCurrentParamValues())
                    },
                    beforeSend: function() {
                        gProgressbar.show();
                    },
                    complete: function() {
                        gProgressbar.hide();
                    },
                    success: function(data) {
                        self.setState({ queryResult: data.data });
                        /* DOGFOOT ktkang 테스트 쿼리보기용 쿼리 수정  20200629 */
						WISE.alert('테스트 데이터는 100건만 보여집니다.');
//                        self.components.resultCounter.text('총 건수 : ' + self.state.queryResult.length + ' 건');
                        self.components.queryResultGrid.option('dataSource', self.state.queryResult);            
                    },
                    error: function(_response) {/*dogfoot 쿼리 보기 sql 오류 표시 shlim 20200715*/
                        //WISE.alert('쿼리가 부적합 합니다.');
                        //2020.09.18 mksong 검색제한시간 초과 오류 문구 수정 dogfoot
						if (_response.error) {
							if(_response.error == 422){
								WISE.alert('검색제한시간을 초과하였습니다.');							
							}else{
								WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
							}
                    	}
                        
                    },
                });
            }
        }).dxButton('instance');
    }

    /**
     * query result download component (button)
     */
    function downloadResultBtn() {
        return $('#downloadResultBtn').dxButton({
            text: '내려받기',
			icon: 'export',
            type: 'normal',
            onClick: function() {
				if(self.components.queryResultGrid.totalCount()>0) {
                	self.components.queryResultGrid.exportToExcel();
				}
            }
        }).dxButton('instance');
    }

    /**
     * query result row counter component
     */
    function resultCounter() {
        return $('#resultCounter');
    }

    /**
     * parameter filter bar component
     */
    function paramFilterBar() {
        return self.paramFilterBar.render({
            element: $('#paramFieldBar'),
            params: self.state.params,
            paramValues: self.state.paramValues,
            onQuery: function(paramValues) {
                self.setState(paramValues, 'PARAM_VALUES');
            }
        });
    }

    /**
     * query result data component (dataGrid)
     */
    function queryResultGrid() {
        return $('#queryResultGrid').dxDataGrid({
        	columnAutoWidth: true,
            height: 'calc(100% - 100px)',
            showColumnLines: true,
            filterRow: { visible: false },
            filterPanel: { visible: false },
            headerFilter: { visible: false },
            scrolling: {
                mode: 'virtual'
            },
            showBorders: true,
        }).dxDataGrid('instance');
    }

    /**
     * back button component (button)
     */
    function queryBackBtn() {
        return $('#queryBackBtn').dxButton({
            text: '뒤로',
            type: 'normal',
            onClick: onPopupClose
        }).dxButton('instance');
    }

    /**
     * Renders query tester component.
     * @param props { dsId: number, dsType: string, queryText: string, queryResult: object[] }
     */
    this.render = function(props) {
        self.setState(props);

        $('body').remove('#dsQueryTesterPopup').append('<div id="dsQueryTesterPopup" />');
        self.container = $('#dsQueryTesterPopup').dxPopup({
            showCloseButton: false,
            showTitle: true,
            title: '쿼리 실행 결과보기',
            visible: true,
            closeOnOutsideClick: false,
            width: '90vw',
            height: '90vh',
            maxWidth: 1300,
            maxHeight: 900,
            onShowing: function () {
                // query tab container component (tabPanel)
                $('#queryTabPanel').dxTabPanel({
                    height: 'calc(100% - 85px)',
                    selectedIndex: 0,
                    loop: false,
                    animationEnabled: false,
                    swipeEnabled: false,
                    dataSource: [{
                        title: 'SQL',
                    }, {
                        title: 'SQL Data',
                    }],
                    itemTemplate: function(item) {
                        switch (item.title) {
                            case 'SQL':
                                return $(
                                    '<div style="height: 100%;">' +
                                        '<div id="queryTextViewer" style="height: 97%; width: 100%; margin-top: 10px"></div>' + 
                                    '</div>'
                                );
                            case 'SQL Data':
                                return $(
                                    '<div style="height: 100%;">' +
                                        '<div id="sqlButtonArea" style="height: 40px;">' +
                                            '<div id="queryStartBtn" class="btn crud neutral" style="margin-left:5px; margin-top:5px;"></div>' +
                                            '<div id="downloadResultBtn" class="btn crud neutral" style="margin-top:5px;"></div>' +
                                            '<span id="resultCounter" style="margin-top:19px; margin-left:20px; display: inline-block;"></span>' +
                                        '</div>' +
                                        '<div id="paramFieldBar" style="overflow: auto; padding-top: 10px; padding-bottom: 10px;"></div>' +
                                        '<div id="queryResultGrid"><div>' +
                                    '</div>'
                                );
                            default:
                                return $('<p>').text('No template specified.');
                        }
                    },
                    onItemRendered: function(e) {
                        switch (e.itemData.title) {
                            case 'SQL':
                                self.components.queryTextViewer = queryTextViewer();
                                break;
                            case 'SQL Data':
                                self.components.queryStartBtn = queryStartBtn();
                                self.components.downloadResultBtn = downloadResultBtn();
                                self.components.resultCounter = resultCounter();
                                self.components.paramFilterBar = paramFilterBar();
                                self.components.queryResultGrid = queryResultGrid();
                                break;
                            default:
                        }
                    }
                });

                self.components.queryBackBtn = queryBackBtn();
            },
            contentTemplate: function() {
                return  '<div style="height: 100%; width: 100%;">' +
                            // query tab container component (tabPanel)
                            '<div id="queryTabPanel"></div>' +
                            '<div class="modal-footer" style="height: 45px; padding-bottom: 0;">' + 
                                '<div class="row center">' + 
                                    // back button component (button)
                                    '<a id="queryBackBtn" class="btn positive ok-hide" href="#">뒤로</a>' + 
                                '</div>' + 
                            '</div>' + 
                        '</div>';
            },
        }).dxPopup('instance');
    }
}