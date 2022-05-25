/**
 * 데이터소스 선택 팝업 컴포넌트 클래스
 * Datasource selector popup component class.
 */
WISE.libs.Dashboard.DatasourceSelector = function() {
    var self = this;

    this.state = {
        userId: '',
        userNo: null,
        dsType: '',
        dsList: [],
        selectedDs: {}
    };
    this.container = null;
    this.components = {
        datasourceList: null,
        datasourceInfo: null,
        dsSelectOkBtn: null,
        dsSelectCancelBtn: null
    };

    /**
     * Update component state.
     */
    this.setState = function(state) {
        $.extend(self.state, state);
    }

    /**
     * Open and pass information to dataset designer window.
     */
    function onConfirm() {
        switch(self.state.dsType) {
            case 'DS_SINGLE':
                // TODO
                break;
            default:
                gDashboard.datasetDesigner.render({
                    datasource: self.state.selectedDs,
					dslist: self.state.dsList,
                    dataset: {
                        DATASET_SEQ: '',
                        DATASET_NM: '데이터집합' + (gDashboard.dataSourceQuantity + 1),
                        DATASET_TYPE: generateDatasetType(),
                        DATASRC_ID: self.state.selectedDs.DS_ID,
                        DATASRC_TYPE: self.state.dsType,
                        DATASET_QUERY: '',
                        SQL_QUERY: '',
                        DATASET_XML: '',
                        SHEET_ID: 'Sheet1',
                        data: [],
                        mapid: 'dataSource' + (gDashboard.dataSourceQuantity + 1),
                        // required by DataSetDs and DataSetCube
                        SEL_CLAUSE: [],
                        FROM_CLAUSE: [],
                        WHERE_CLAUSE: [],
                        ORDER_CLAUSE: [],
                        PARAM: [],
                        CHANGE_COND: '',
                        /* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
                        JOIN_TYPE: self.state.joinType
                    },
                    params: [],
                    onPopupClose: onPopupClose
                });
        }
        //onPopupClose();
    }

    /**
     * Load datasource data into state and components.
     */
    function loadDatasourceList() {
        $.ajax({
            method: 'GET',
            url: requestUrl(self.state.dsType),
            data: {
                userId: self.state.userId,
                userNo: self.state.userNo,
                dsType: self.state.dsType
            },
            beforeSend: function() {
                gProgressbar.show();
            },
            complete: function() {
                gProgressbar.hide();
            },
            success: function(result) {
                if (result.status === 200) {
                    self.setState({ dsList: result.data });
                    self.components.datasourceList.option('dataSource', self.state.dsList);
                } else {
                    WISE.alert(result.status);
                }
            },
            error: function() {
                WISE.alert(gMessage.get('WISE.message.page.500.m1'));
            }
        });
    }

    /**
     * Close datasource selector popup.
     */
    function onPopupClose() {
        self.components.datasourceList.dispose();
        self.components.datasourceInfo.dispose();
        self.components.dsSelectOkBtn.dispose();
        self.components.dsSelectCancelBtn.dispose();
        self.container.hide();
    }

    /**
     * Fetch the corresponding AJAX request URL by datasource type.
     * @param {string} dsType
     */
    function requestUrl(dsType) {
        switch (dsType) {
            case 'DS':
            case 'DS_SQL':
            case 'DS_SINGLE':
                return WISE.Constants.context + '/report/datasourceList.do';
            case 'CUBE':
                return WISE.Constants.context + '/report/cubeDatasourceList.do';
            // case 'CUBE':
            //     return WISE.Constants.context + '/report/subjectViewAndCube.do';
            default:
                return null;
        }
    }

    /**
     * Return the corresponding dataset type.
     * @param {string} datasourceType 
     */
    function generateDatasetType() {
        switch (self.state.dsType) {
            case 'DS':
                return 'DataSetDs';
            case 'DS_SQL':
                return 'DataSetSQL';
            case 'DS_SINGLE':
                return 'DataSetSingleDs';
            case 'CUBE':
                return 'DataSetCube';
            default:
                return '';
        }
    }

    /**
     * Return datasource list's column format.
     */
    function generateDatasourceListColumns() {
        switch (self.state.dsType) {
            case 'CUBE':
                return [{
                    dataField: 'CUBE_NM',
                    caption: '주제영역 명',
                    width: '40%',
                }, {
                    dataField: 'DS_NM',
                    caption: '데이터 원본 명',
                    width: '35%',
                }, {
                    dataField: 'IP',
                    caption: '서버 주소(명)', 
                    width: '25%',
                }];
            default:
                return [{
                    dataField: 'DS_NM',
                    caption: '데이터 원본 명', 
                    width: '40%',
                }, {
                    dataField: 'DBMS_TYPE',
                    caption: 'DB 유형',
                    width: '15%',
                }, {
                    dataField: 'IP',
                    caption: '서버 주소(명)',
                    width: '25%',
                }, {
                    dataField: 'USER_AREA_YN',
                    caption: '사용자 데이터',
                    width: '10%',
                }];
        }
    }

    /**
     * datasource list component (grid)
     */
    function datasourceList() {
        return $("#datasourceList").dxDataGrid({
            width: "100%",
            //height: "calc(100% - 80px)",
            height: "95%",
            showBorders: true,
            paging: {
                pageSize: 20
            },
            visible : true,
            columnAutoWidth: true,
            allowColumnResizing: true,
            selection: {
                mode:'single'
            },
            onSelectionChanged: function (selectedItems) {
                self.setState({ selectedDs: selectedItems.selectedRowsData[0] || {} });
                self.components.datasourceInfo.option("formData", self.state.selectedDs);
            },
            columns: generateDatasourceListColumns(),
            onContentReady: function(){
            	$("#datasourceList .dx-freespace-row").css('display', 'none');
            },
            headerFilter: {
                visible: true,
                allowSearch: true
            },            
        }).dxDataGrid('instance');
    }

    /**
     * datasource info component (form)
     */
    function datasourceInfo() {
        return $("#datasourceInfo").dxForm({
            width: "100%",
            height: 600,
            readOnly: true,
            formData: {},
            items: [{
                dataField: 'CUBE_NM',
                label: {
                    text: '주제영역 명'
                },
                editorOptions: {
                    readOnly: true
                },
                visible: self.state.dsType === 'CUBE'
            }, {
                dataField: 'DS_NM',
                label: {
                    text: "데이터 원본 명",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'IP',
                label: {
                    text: "서버 주소(명)",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'DB_NM',
                label: {
                    text: "DB 명",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'DBMS_TYPE',
                label: {
                    text: "DB 유형",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'PORT',
                label: {
                    text: "Port",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'OWNER_NM',
                label: {
                    text: "소유자",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'USER_ID',
                label: {
                    text: "접속 ID",
                },
                editorOptions: {
                    readOnly: true
                }
            }, {
                dataField: 'DS_DESC',
                label: {
                    text: "설명",
                },
                editorType: "dxTextArea",
                editorOptions: {
                    readOnly: true,
                    height: 130
                }
            }],
        }).dxForm('instance');
    }

    /**
     * confirm button component (button)
     */
    function dsSelectOkBtn() {
        return $("#dsSelectOkBtn").dxButton({
            text: "확인",
            type: "normal",
            onClick: function() {
                if (!$.isEmptyObject(self.state.selectedDs)) {
                    onConfirm();
                }
            },
        }).dxButton('instance');
    }
    
    /**
     * cancel button component (button)
     */
    function dsSelectCancelBtn() {
        return $("#dsSelectCancelBtn").dxButton({
            text: "취소",
            type: "normal",
            onClick: function() {
                onPopupClose();
            },
        }).dxButton('instance');
    }

    /**
     * Render datasource selector popup page.
     * @param self.state { userId: string, userNo: number, dsType: string }
     */
    this.render = function(props) {
        self.setState(props);
        // datasource selector container component (popup)
        $('body').remove('#dsSelectorPopup').append('<div id="dsSelectorPopup" />');
        self.container = $('#dsSelectorPopup').dxPopup({
            showCloseButton: false,
			showTitle: true,
			title:"데이터 원본 선택",
			visible: true,
            closeOnOutsideClick: false,
            width: '90vw',
            height: '90vh',
            maxWidth: 1300,
            maxHeight: 900,
            onContentReady: function(){
            	gDashboard.fontManager.setFontConfigForListPopup('dsSelectorPopup')
            },
            contentTemplate: function(element) {
                element.append(
                    '<div class="modal-inner" style="height: 100%; width: 100%;">' + 
                        '<div class="modal-body" style="height: calc(100% - 85px);">' + 
                            '<div class="row" style="height: 100%;">' + 
                                '<div class="column" style="width:50%; height: 100%">' + 
                                    '<div class="modal-article" style="height: 100%">' + 
                                        '<div class="modal-tit">' + 
                                            '<span>데이터원본 목록</span>' + 
                                        '</div>' + 
                                        // datasource list component (grid)
                                        //'<div id="datasourceList" style="height: calc(100% - 80px)"/>' + 
                                        '<div id="datasourceList" style="height: 95%"/>' +
                                    '</div>' + 
                                '</div>' + 
                                '<div class="column" style="width:50%; height: 100%">' + 
                                    '<div class="modal-article">' + 
                                        '<div class="modal-tit">' + 
                                            '<span>데이터원본 정보</span>' + 
                                        '</div>' + 
                                        // datasource info component (form)
                                        '<div id="datasourceInfo"></div>' + 
                                    '</div>' + 
                                '</div>' + 
                            '</div>' + 
                        '</div>' + 
                        '<div class="modal-footer" style="height: 45px; padding-bottom: 0;">' + 
                            '<div class="row center">' + 
                                // confirm button component (button)
                                '<a id="dsSelectOkBtn" class="btn positive ok-hide">확인</a>' + 
                                // cancel button component (button)
                                '<a id="dsSelectCancelBtn" class="btn neutral close">취소</a>' + 
                            '</div>' + 
                        '</div>' + 
                    '</div>'
                );
                self.components = {
                    datasourceList: datasourceList(),
                    datasourceInfo: datasourceInfo(),
                    dsSelectOkBtn: dsSelectOkBtn(),
                    dsSelectCancelBtn: dsSelectCancelBtn()
                };
                loadDatasourceList();
            },
        }).dxPopup('instance');
    }
}