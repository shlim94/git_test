/**
 * 데이터집합 디자이너에 쿼리 직접 입력 컴포넌트 클래스
 * Dataset query designer component class.
 */
WISE.libs.Dashboard.DatasetQueryDesigner = function() {
    var self = this;

    this.state = {
        element: null,
        initialQueryText: '',
        initialParams: [],
        onChange: null,
        onParamSearch: null,
        onParamEdit: null,
        onParamDelete: null,
        onParamSelect: null,
    };
    this.container = null;
    this.components = {
        dsQueryTextArea: null,
        paramSearchBtn: null,
        paramEditBtn: null,
        paramDeleteBtn: null,
        dsParamList: null
    };

    /**
     * Update component state.
     */
    this.setState = function(state) {
        $.extend(self.state, state);
    };

        /**
     * Renders query designer component.
     * @param props { element: HTMLElement, onChange: function, onParamSearch: function }
     */
    this.render = function(props) {
        self.setState(props);
        self.state.element.append(
            '<div class="row horizen" style="height: 100%;">' + 
                '<div class="column" style="height: 60%;">' +
                    '<div class="modal-article" style="height: 100%;">' +
                        '<div class="modal-tit" style="height: 37px;"><span>쿼리</span></div>' +
                        // query input component (textArea)
                        '<div id="dsQueryTextArea"' + 
                            'style="position: relative; height: calc(100% - 47px); width: 100%;" />' +
                    '</div>' +
                '</div>' +
                '<div class="column" style="padding-bottom:0px; height: 40%; padding-bottom: 0;">' +
                    '<div class="modal-article" style="height: 100%;">' +
                        '<div id="param_area" class="param_area modal-tit" style="height: 40px;">' + 
                            '<span>매개변수<em class="red">*매개변수는 영문만 가능합니다.</em></span>' + 
                            '<div class="right-item">' +
                                // param button components
                                '<a id="paramSearchBtn" class="btn crud positive">생성</a>' +
                                '<a id="paramEditBtn" class="btn crud neutral">편집</a>' +
                                '<a id="paramDeleteBtn" class="btn crud negative">삭제</a>' +
                            '</div>' +
                        '</div>' +
                        // param list component (dataGrid)
                        '<div id="dsParamList"></div>' +
                    '</div>' +
                '</div>' +
            '</div>'
        );

        self.components = {
            dsQueryTextArea: dsQueryTextArea(),
            paramSearchBtn: paramSearchBtn(),
            paramEditBtn: paramEditBtn(),
            paramDeleteBtn: paramDeleteBtn(),
            dsParamList: dsParamList()
        };

        addEditorDropListener();
    };

    /**
     * Update param grid component with new set of params.
     * @param {object[]} params 
     */
    this.updateParamList = function(params) {
        self.components.dsParamList.option('dataSource', params);
    };

    /**
     * Add a drop listener for table columns.
     */
    function addEditorDropListener() {
        $('#dsQueryTextArea').droppable({
            drop: function(e, ui) {                
            	var data = ui.draggable.data('column');
            	var str = "";
            	if (data && data.TYPE === 'COLUMN') {
            		str = data.TBL_NM+"."+data.COL_NM;
            	}else if (data && data.TYPE === 'TABLE') {
            		str = data.TBL_NM;
            	}
                self.components.dsQueryTextArea.insert(str);
                self.components.dsQueryTextArea.focus();
			}
        });
    }

    /**
     * query input component (ace)
     */
    function dsQueryTextArea() {
        var editor = ace.edit(
            'dsQueryTextArea',
            {
                mode: 'ace/mode/sql',
                theme: 'ace/theme/crimson_editor',
                value: self.state.initialQueryText,
                showPrintMargin: false,
            }
        );

        editor.on('change', function() {
            self.state.onChange(editor.getValue());
        });

        return editor;
    }

    /**
     * param search button component (button)
     */
    function paramSearchBtn() {
        return $('#paramSearchBtn').dxButton({
            type: 'normal',
            onClick: function() {
                self.state.onParamSearch();
            }
        }).dxButton('instance');
    }

    /**
     * param edit button component (button)
     */
    function paramEditBtn() {
        return $('#paramEditBtn').dxButton({
            type: 'normal',
            onClick: function() {
                self.state.onParamEdit();
            }
        }).dxButton('instance');
    }

    /**
     * param delete button component (button)
     */
    function paramDeleteBtn() {
        return $('#paramDeleteBtn').dxButton({
            type: 'normal',
            onClick: function() {
                self.state.onParamDelete(self.components.dsParamList.getSelectedRowKeys());
            }
        }).dxButton('instance');
    }

    /**
     * param list component (dataGrid)
     */
    function dsParamList() {
    	
        return $('#dsParamList').dxDataGrid({
            dataSource: self.state.initialParams,
            height: 'calc(100% - 35px)',
            width: '100%',
            columnAutoWidth: true,
            selection: {
                allowSelectAll: true,
                mode: 'multiple',
                showCheckBoxesMode: 'onClick',
            },
            editing: {
            	mode: 'cell',
            	allowUpdating: true
            },
            onSelectionChanged: function(e) {
                self.state.onParamSelect(e.selectedRowKeys[0] || '');
            },
            keyExpr: 'PARAM_NM',
            columns: [{
                dataField: 'PARAM_NM',
                caption: '매개변수 명',
            	allowEditing:false
            }, {
                dataField: 'PARAM_CAPTION',
                caption: '매개변수 Caption',
            	allowEditing:false
            }, {
                dataField: 'DATA_TYPE',
                caption: '데이터 유형',
            	allowEditing:false
            }, {
                dataField: 'PARAM_TYPE',
                caption: '매개변수 유형',
            	allowEditing:false
            }, {
                dataField: 'VISIBLE',
                caption: 'Visible',
            	allowEditing:false
            }, {
                dataField: 'MULTI_SEL',
                caption: '다중선택',
            	allowEditing:false
            }, {
                dataField: 'ORDER',
                caption: '순서',
            	allowEditing:false
            }, {
                dataField: 'OPER',
                caption: '조건 명',
                lookup: {
                    dataSource: [
                		{
                			caption:'In',
                			value:'In'
                		},
                		{
                		/* DOGFOOT ktkang 필터 Not In 조건 추가  20200717 */
                			caption:'NotIn',
                			value:'NotIn'
                		},
                		{
                			caption:'Between',
                			value:'Between'
                		},
                		{
                			caption:'Equals',
                			value:'Equals'
                		}
                		
                	],
                    displayExpr: "caption",
                    valueExpr: "value"
                }
           
            }],
        }).dxDataGrid('instance');
    }
}