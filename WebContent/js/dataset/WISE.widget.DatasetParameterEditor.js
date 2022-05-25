/**
 * 데이터집합 매개변수 편집 팝업 컴포넌트 클래스
 * Dataset parameter editor popup component class.
 */
WISE.libs.Dashboard.DatasetParameterEditor = function() {
    var self = this;
    this.tableColumnPicker = new WISE.libs.Dashboard.TableColumnPicker();
    this.state = {
        dsId: '',
        dsType: '',
        params: [],
        selectedParam: '',
        selectedParamIndex: null,
        selectedTable: '',
        onConfirm: null,
        showSearchBindCheckBoxes: false,
        showSearchButtons: false
    };
    this.container = null;
    this.components = {
        parameterList: null,
        parameterForm: null,
        parameterDetailsForm: null,
        paramConfimBtn: null,
        paramCancelBtn: null,
    };
    this.trackUserInput = false;

    /**
     * Update component state.
     */
    this.setState = function(state, paramState) {
        if (paramState) {
            $.extend(
                self.state.params[self.state.selectedParamIndex],
                paramState
            );
        } else {
            $.extend(self.state, state);
        }
    }

    /**
     * Close popup component.
     */
    function onPopupClose() {
        self.components.parameterList.dispose();
        self.components.parameterForm.dispose();
        self.components.parameterDetailsForm.dispose();
        self.container.hide();
    }

    /**
     * Update forms with selected parameter info.
     * @param {object} e 
     */
    function onParamSelected(e) {
        self.trackUserInput = false;
        var selected = e.selectedRowKeys[0] || '';
        self.setState({
            selectedParam: selected,
            selectedParamIndex: getParamIndex(selected)
        });
        if (e.selectedRowsData[0]) {
            self.components.parameterForm.itemOption('general', 'visible', true);
            self.components.parameterForm.updateData(e.selectedRowsData[0]);
            self.components.parameterDetailsForm.updateData(e.selectedRowsData[0]);
            // render search buttons
            if (e.selectedRowsData[0].PARAM_TYPE === 'LIST' && e.selectedRowsData[0].DATASRC_TYPE === 'TABLE') {
                toggleTableSearch('on');
            }
        } else {
            self.components.parameterForm.resetValues();
            self.components.parameterForm.itemOption('general', 'visible', false);
            hideFormDetails();
        }
        self.trackUserInput = true;
    }

    function onParamFormChange(e) {
        if (self.trackUserInput && self.state.selectedParam.length > 0) {
            var paramState = {};
            paramState[e.dataField] = e.value;
            self.setState(null, paramState);
        }
    }

    /**
     * Change parameter input types according to operator type.
     * @param {object} e 
     */
    function onOperatorChange(e) {
        switch (e.value) {
            case 'Between':
                self.components.parameterForm
                    .getEditor('PARAM_TYPE')
                    .option('items', [
                        { key:'BETWEEN_LIST', caption:'Between 리스트' },
                        { key:'BETWEEN_INPUT', caption:'Between 입력' },
                        { key:'BETWEEN_CAND', caption:'Between 달력' }
                    ]);
                break;
            default:
                self.components.parameterForm
                    .getEditor('PARAM_TYPE')
                    .option('items', [
                        { key:'LIST', caption:'리스트' },
                        { key:'INPUT', caption:'입력' },
                        { key:'CAND', caption:'달력' }
                    ]);
        }
    }

    /**
     * Hide and show forms according to parameter type.
     * @param {object} e 
     */
    function onParamTypeChange(e) {
        var formName = '';
        switch (e.value) {
            case 'INPUT':
                formName = 'input-details';
                toggleSearchBindCheck('off');
                break;
            case 'LIST':
                formName = 'list-details';
                toggleSearchBindCheck('on');
                break;
            case 'CAND':
                formName = 'calendar-details';
                toggleSearchBindCheck('off');
                break;
            default:
                return;
        }

        hideFormDetails();
        self.components.parameterDetailsForm.itemOption(formName, 'visible', true);
        // render search buttons
        if (e.value === 'LIST' && self.state.showSearchButtons) {
            toggleTableSearch('on');
        }
    }

    /**
     * Hide and show forms according to calendar type.
     * @param {string} action
     */
    function onCalendarTypeChange(action) {
        hideCalendarFormValueComponents();
        switch (action) {
            case 'NOW':
                self.components.parameterDetailsForm.itemOption('calendar-details.CAND_PERIOD_BASE', 'visible', true);
                self.components.parameterDetailsForm.itemOption('calendar-details.CAND_DEFAULT_BASE_DESC', 'visible', true);
                self.components.parameterDetailsForm.itemOption('calendar-details.CAND_PERIOD_VALUE', 'visible', true);
                self.components.parameterDetailsForm.itemOption('calendar-details.CAND_DEFAULT_VALUE_DESC', 'visible', true);
                self.components.parameterDetailsForm.itemOption('calendar-details.CAND_DEFAULT_COMMENT_ONE', 'visible', true);
                self.components.parameterDetailsForm.itemOption('calendar-details.CAND_DEFAULT_COMMENT_TWO', 'visible', true);
                break;
            case 'QUERY':
                self.components.parameterDetailsForm.itemOption('calendar-details.DEFAULT_VALUE', 'visible', false);
                self.components.parameterDetailsForm.itemOption('calendar-details.DEFAULT_VALUE_USE_SQL_SCRIPT', 'visible', false);
                break;
            default:
                return;
        }
    }

    function onTableSearch() {
        self.tableColumnPicker.render({ 
            id: self.state.dsId, 
            type: self.state.dsType,
            request: 'TABLE',
            table: '',
            onConfirm: function(tableName) {
                self.components.parameterDetailsForm.getEditor('DATASRC').option('value', tableName);
            }
        });
    }

    function onTableNameChange(e) {
        self.setState({ selectedTable: e.value });
    } 

    function onColumnSearch(componentName) {
        self.tableColumnPicker.render({
            id: self.state.dsId,
            type: self.state.dsType,
            request: 'COLUMN',
            table: self.state.selectedTable,
            onConfirm: function(columnName) {
                self.components.parameterDetailsForm.getEditor(componentName).option('value', columnName);
            }
        })
    }

    function hideFormDetails() {
        self.components.parameterDetailsForm.itemOption('input-details', 'visible', false);
        self.components.parameterDetailsForm.itemOption('list-details', 'visible', false);
        self.components.parameterDetailsForm.itemOption('calendar-details', 'visible', false);
    }

    function hideCalendarFormValueComponents() {
        self.components.parameterDetailsForm.itemOption('calendar-details.CAND_PERIOD_BASE', 'visible', false);
        self.components.parameterDetailsForm.itemOption('calendar-details.CAND_DEFAULT_BASE_DESC', 'visible', false);
        self.components.parameterDetailsForm.itemOption('calendar-details.CAND_PERIOD_VALUE', 'visible', false);
        self.components.parameterDetailsForm.itemOption('calendar-details.CAND_DEFAULT_VALUE_DESC', 'visible', false);
        self.components.parameterDetailsForm.itemOption('calendar-details.CAND_DEFAULT_COMMENT_ONE', 'visible', false);
        self.components.parameterDetailsForm.itemOption('calendar-details.CAND_DEFAULT_COMMENT_TWO', 'visible', false);
        self.components.parameterDetailsForm.itemOption('calendar-details.DEFAULT_VALUE', 'visible', false);
        self.components.parameterDetailsForm.itemOption('calendar-details.DEFAULT_VALUE_USE_SQL_SCRIPT', 'visible', false);
    }

    function toggleSearchBindCheck(action) {
        switch (action) {
            case 'on':
                self.setState({ showSearchBindCheckBoxes: true });
                self.components.parameterForm.getEditor('SEARCH_YN').option('visible', true);
                self.components.parameterForm.getEditor('BIND_YN').option('visible', true);
                break;
            case 'off':
                self.setState({ showSearchBindCheckBoxes: true });
                self.components.parameterForm.getEditor('SEARCH_YN').option('visible', false);
                self.components.parameterForm.getEditor('BIND_YN').option('visible', false);
                break;
            default:
        }
    }

    function toggleTableSearch(action) {
        switch (action) {
            case 'on':
                self.setState({ showSearchButtons: true });
                self.components.parameterDetailsForm.getEditor('DATASRC_BTN').option('visible', true);
                self.components.parameterDetailsForm.getEditor('CAPTION_VALUE_ITEM_BTN').option('visible', true);
                self.components.parameterDetailsForm.getEditor('SORT_VALUE_ITEM_BTN').option('visible', true);
                self.components.parameterDetailsForm.getEditor('KEY_VALUE_ITEM_BTN').option('visible', true);
                break;
            case 'off':
                self.setState({ showSearchButtons: false });
                self.components.parameterDetailsForm.getEditor('DATASRC_BTN').option('visible', false);
                self.components.parameterDetailsForm.getEditor('CAPTION_VALUE_ITEM_BTN').option('visible', false);
                self.components.parameterDetailsForm.getEditor('SORT_VALUE_ITEM_BTN').option('visible', false);
                self.components.parameterDetailsForm.getEditor('KEY_VALUE_ITEM_BTN').option('visible', false);
                break;
            default:
        }
    }

    function getParamIndex(key) {
        for (var i = 0; i < self.state.params.length; i++) {
            if (self.state.params[i].PARAM_NM === key) {
                return i;
            }
        }
        return null;
    }

    /**
     * parameter list component (dataGrid)
     */
    function parameterList() {
        return $('#parameterList').dxDataGrid({
            dataSource: self.state.params,
            height: 'calc(100% - 55px)',
            showBorders: true,
            columnAutoWidth: true,
            keyExpr: 'PARAM_NM',
            columns:[
                {
                    dataField: 'PARAM_NM',
                    caption: '매개변수 명',
                    alignment: 'center',
                },
                {
                    dataField: 'PARAM_CAPTION',
                    caption: '매개변수 캡션',
                    alignment: 'center',
                },
                {
                    dataField: 'ORDER',
                    caption: '순서',
                    alignment: 'center',
                },
            ],
            selection: {
                mode: 'single'
            },
            onSelectionChanged: onParamSelected,
        }).dxDataGrid('instance');
    }

    /**
     * parameter form component (form)
     */
    function parameterForm() {
        return $('#parameterForm').dxForm({
            height: 'calc(100% - 55px)',
            width: '100%',
            scrollingEnabled: true,
            onFieldDataChanged: onParamFormChange,
            items: [{
                itemType: 'group',
                name: 'general',
                caption: 'general',
                colCount: 16,
                visible: false,
                items: [{
                    // 매개변수 명 필드
                    dataField: 'PARAM_NM',
                    label: {
                        text: '매개변수 명',
                    },
                    colSpan: 8,
                    editorType: 'dxTextBox',
                    editorOptions: {
                        readOnly: true
                    }
                }, {
                    itemType: 'empty',
                    colSpan: 8,
                    // template: function(data, element) {
                    //     element.append('<span>Test 1234 안녕하세요</span>');
                    // }
                }, {
                    // 매개변수 캡션 필드
                    dataField: 'PARAM_CAPTION',
                    label: {
                        text: '매개변수 캡션',
                    },
                    colSpan: 8,
                    editorType: 'dxTextBox',
                }, {
                    // 데이터 검색 필드
                    dataField: 'SEARCH_YN',
                    label: {
                        text: ' ',
                        showColon: false,
                    },
                    colSpan: 8,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: '데이터 검색',
                        visible: self.state.showSearchBindCheckBoxes
                    }
                }, {
                    // 데이터 유형 필드
                    dataField: 'DATA_TYPE',
                    label: {
                        text: '데이터 유형',
                    },
                    colSpan: 8,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        items: [
                            { key: 'STRING', caption: 'String' },
                            { key: 'NUMERIC', caption: 'Numeric' },
                            { key: 'DATETIME', caption: 'DateTime' }
                        ],
                        displayExpr: 'caption',
                        valueExpr: 'key'
                    }
                }, {
                    // 데이터 바인딩 필드
                    dataField: 'BIND_YN',
                    label: {
                        text: ' ',
                        showColon: false,
                    },
                    colSpan: 8,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: '데이터 바인딩',
                        visible: self.state.showSearchBindCheckBoxes
                    }
                }, {
                    // 매개변수 유형 필드
                    dataField: 'PARAM_TYPE',
                    label: {
                        text: '매개변수 유형',
                    },
                    colSpan: 8,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        displayExpr: 'caption',
                        valueExpr: 'key',
                        onValueChanged: onParamTypeChange
                    }
                }, {
                    itemType: 'empty',
                    colSpan: 8,
                }, {
                    // 순서 필드
                    dataField: 'ORDER',
                    label: {
                        text: '순서',
                    },
                    colSpan: 4,
                    editorType: 'dxNumberBox',
                    editorOptions: {
                        showSpinButtons: true
                    }
                }, {
                    // 넓이 필드
                    dataField: 'WIDTH',
                    label: {
                        text: '넓이',
                    },
                    colSpan: 4,
                    editorType: 'dxNumberBox',
                    editorOptions: {
                        showSpinButtons: true
                    }
                }, {
                    // Visible 필드
                    dataField: 'VISIBLE',
                    label: {
                        text: ' ',
                        showColon: false,
                    },
                    colSpan: 4,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: 'Visible',
                    }
                }, {
                    // 조건 명 필드
                    dataField: 'OPER',
                    label: {
                        text: '조건 명',
                    },
                    colSpan: 4,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        items: ['In', 'Between', 'Equals'],
                        readOnly: true,
                        onValueChanged: onOperatorChange,
                        onContentReady: onOperatorChange
                    }
                }]
            }]
        }).dxForm('instance');
    }

    /**
     * parameter details form component (form)
     */
    function parameterDetailsForm() {
        return $('#parameterDetailsForm').dxForm({
            height: '100%',
            width: '100%',
            scrollingEnabled: true,
            onFieldDataChanged: onParamFormChange,
            items: [{
                // 입력 설정
                itemType: 'group',
                name: 'input-details',
                caption: 'input',
                colCount: 16,
                items: [{
                    // 매개변수 기본 값 필드
                    dataField: 'DEFAULT_VALUE',
                    label: {
                        text: '매개변수 기본 값',
                    },
                    colSpan: 12,
                    editorType: 'dxTextArea',
                }, {
                    // 매개변수 기본 값 SQL 사용 필드
                    dataField: 'DEFAULT_VALUE_USE_SQL_SCRIPT',
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    colSpan: 4,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: 'Use SQL Script'
                    }
                }, {
                    // 조건절 필드
                    dataField: 'WHERE_CLAUSE',
                    label: {
                        text: '조건절',
                    },
                    colSpan: 8,
                    editorType: 'dxTextBox'
                }, {
                    // 기본 값 유지 필드
                    dataField: 'DEFAULT_VALUE_MAINTAIN',
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    colSpan: 4,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: '기본 값 유지'
                    }
                }, {
                    itemType: 'empty',
                    colSpan: 4
                }]
            }, {
                // 리스트 설정
                itemType: 'group',
                name: 'list-details',
                caption: 'list',
                colCount: 16,
                items: [{
                    // 데이터원본 유형 필드
                    dataField: 'DATASRC_TYPE',
                    label: {
                        text: '데이터원본 유형',
                    },
                    colSpan: 8,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        items: [
                            { key: 'TABLE', caption: '테이블' },
                            { key: 'QUERY', caption: '쿼리' },
                        ],
                        displayExpr: 'caption',
                        valueExpr: 'key',
                        onValueChanged: function(e) {
                            switch (e.value) {
                                case 'TABLE':
                                    toggleTableSearch('on');
                                    break;
                                case 'QUERY':
                                    toggleTableSearch('off');
                                    break;
                                default:
                            }
                        }
                    }
                }, {
                    itemType: 'empty',
                    colSpan: 8,
                }, {
                    // 데이터원본 필드
                    dataField: 'DATASRC',
                    label: {
                        text: '데이터원본',
                    },
                    colSpan: 15,
                    editorType: 'dxTextArea',
                    editorOptions: {
                        onValueChanged: onTableNameChange
                    }
                }, {
                    // 데이터원본 검색 버튼
                    name: 'DATASRC_BTN',
                    colSpan: 1,
                    editorType: 'dxButton',
                    editorOptions: {
                        visible: self.state.showSearchButtons,
                        icon: 'find',
                        onClick: onTableSearch,
                    }
                }, {
                    // 캡션 항목 필드
                    dataField: 'CAPTION_VALUE_ITEM',
                    label: {
                        text: 'Caption 항목',
                    },
                    colSpan: 8,
                    editorType: 'dxTextBox'
                }, {
                    // 캡션 항목 검색 버튼
                    name: 'CAPTION_VALUE_ITEM_BTN',
                    colSpan: 1,
                    editorType: 'dxButton',
                    editorOptions: {
                        visible: self.state.showSearchButtons,
                        icon: 'find',
                        onClick: function() {
                            onColumnSearch('CAPTION_VALUE_ITEM');
                        }
                    }
                }, {
                    // 정렬 항목 필드
                    dataField: 'SORT_VALUE_ITEM',
                    label: {
                        text: '정렬',
                    },
                    colSpan: 6,
                    editorType: 'dxTextBox'
                }, {
                    // 정렬 항목 검색 버튼
                    name: 'SORT_VALUE_ITEM_BTN',
                    colSpan: 1,
                    editorType: 'dxButton',
                    editorOptions: {
                        visible: self.state.showSearchButtons,
                        icon: 'find',
                        onClick: function() {
                            onColumnSearch('SORT_VALUE_ITEM');
                        }
                    }
                }, {
                    // key 항목 필드
                    dataField: 'KEY_VALUE_ITEM',
                    label: {
                        text: 'Key 항목',
                    },
                    colSpan: 8,
                    editorType: 'dxTextBox'
                }, {
                    // key 항목 검색 버튼
                    name: 'KEY_VALUE_ITEM_BTN',
                    colSpan: 1,
                    editorType: 'dxButton',
                    editorOptions: {
                        visible: self.state.showSearchButtons,
                        icon: 'find',
                        onClick: function() {
                            onColumnSearch('KEY_VALUE_ITEM');
                        }
                    }
                }, {
                    // 정렬 순서 필드
                    dataField: 'SORT_TYPE',
                    label: {
                        text: '정렬 순서',
                    },
                    colSpan: 6,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        items: [
                            { key: 'ASC', caption: '오름차순' },
                            { key: 'DESC', caption: '내림차순' },
                        ],
                        displayExpr: 'caption',
                        valueExpr: 'key'
                    }
                }, {
                    itemType: 'empty',
                    colSpan: 1
                }, {
                    // 매개변수 기본 값 필드
                    dataField: 'DEFAULT_VALUE',
                    label: {
                        text: '매개변수 기본 값',
                    },
                    colSpan: 12,
                    editorType: 'dxTextArea',
                }, {
                    // 매개변수 기본 값 SQL 사용 필드
                    dataField: 'DEFAULT_VALUE_USE_SQL_SCRIPT',
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    colSpan: 4,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: 'Use SQL Script'
                    }
                }, {
                    // 조건절 필드
                    dataField: 'WHERE_CLAUSE',
                    label: {
                        text: '조건절',
                    },
                    colSpan: 8,
                    editorType: 'dxTextBox'
                }, {
                    itemType: 'empty',
                    colSpan: 8,
                }, {
                    itemType: 'empty',
                    colSpan: 2,
                }, {
                    // "전체" 항목 표시 필드
                    dataField: 'ALL_YN',
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    colSpan: 6,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: '[전체] 항목 표시'
                    }
                }, {
                    // 다중 선택 필드
                    dataField: 'MULTI_SEL',
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    colSpan: 4,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: '다중 선택'
                    }
                }, {
                    // 기본 값 유지 필드
                    dataField: 'DEFAULT_VALUE_MAINTAIN',
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    colSpan: 4,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: '기본 값 유지'
                    }
                }]
            }, {
                itemType: 'group',
                name: 'calendar-details',
                caption: 'calendar',
                colCount: 16,
                items: [{
                    dataField: 'CAND_DEFAULT_TYPE',
                    label: {
                        text: '기본 값 유형'
                    },
                    colSpan: 8,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        items: [
                            { key: 'NOW', caption: '현재' },
                            { key: 'QUERY', caption: '쿼리' },
                        ],
                        displayExpr: 'caption',
                        valueExpr: 'key',
                        onValueChanged: function(e) {
                            onCalendarTypeChange(e.value);
                        }
                    },
                }, {
                    itemType: 'empty',
                    colSpan: 8,
                }, {
                    dataField: 'CAND_DEFAULT_BASE',
                    label: {
                        text: '기본 값 계산'
                    },
                    colSpan: 6,
                    visible: false,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        items: [
                            { key: 'YEAR', caption: '년도' },
                            { key: 'MONTH', caption: '월' },
                            { key: 'DAY', caption: '일' },
                        ],
                        displayExpr: 'caption',
                        valueExpr: 'key'
                    }
                }, {
                    name: 'CAND_DEFAULT_BASE_DESC',
                    colSpan: 2,
                    visible: false,
                    template: function(data, element) {
                        element.append('<span>을 기준으로</span>');
                    }
                }, {
                    dataField: 'CAND_DEFAULT_VALUE',
                    label: {
                        text: ' ',
                        showColon: false,
                    },
                    colSpan: 4,
                    visible: false,
                    editorType: 'dxNumberBox',
                    editorOptions: {
                        showSpinButtons: true
                    }
                }, {
                    name: 'CAND_DEFAULT_VALUE_DESC',
                    colSpan: 4,
                    visible: false,
                    template: function(data, element) {
                        element.append('<span>이동 값을 기본 값으로 합니다.</span>');
                    }
                }, {
                    name: 'CAND_DEFAULT_COMMENT_ONE',
                    colSpan: 16,
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    visible: false,
                    template: function(data, element) {
                        element.append(
                            '<p>' +
                                '* 기본 계산 값 계산 앞 부분을 [년도]를 선택하고 뒤 부분의 숫자를 -1로 설정하면 ' +
                                '매개변수 기본 값 유형에서 선택 한 기본 값을 기준으로 전년도 값을 자동으로 가져옵니다.' +
                            '</p>'
                        );
                    }
                }, {
                    name: 'CAND_DEFAULT_COMMENT_TWO',
                    colSpan: 16,
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    visible: false,
                    template: function(data, element) {
                        element.append(
                            '<p>' +
                                '년도, 월, 주, 일을 기준으로 기간을 설정할 수 있습니다.' +
                            '</p>'
                        );
                    }
                }, {
                    // 매개변수 기본 값 필드
                    dataField: 'DEFAULT_VALUE',
                    label: {
                        text: '매개변수 기본 값',
                    },
                    colSpan: 12,
                    visible: false,
                    editorType: 'dxTextArea',
                }, {
                    // 매개변수 기본 값 SQL 사용 필드
                    dataField: 'DEFAULT_VALUE_USE_SQL_SCRIPT',
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    colSpan: 4,
                    visible: false,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: 'Use SQL Script'
                    }
                }, {
                    dataField: 'CAPTION_FORMAT',
                    label: {
                        text: 'Caption Value 형식',
                    },
                    colSpan: 8,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        items: ['yyyy', 'yyyyMM', 'yyyyMMdd', 'yyyy-MM', 'yyyy-MM-dd'],
                    }
                }, {
                    // 기본 값 유지 필드
                    dataField: 'DEFAULT_VALUE_MAINTAIN',
                    label: {
                        text: ' ',
                        showColon: false
                    },
                    colSpan: 8,
                    editorType: 'dxCheckBox',
                    editorOptions: {
                        text: '기본 값 유지'
                    }
                }, {
                    dataField: 'KEY_FORMAT',
                    label: {
                        text: 'Key Value 형식',
                    },
                    colSpan: 8,
                    editorType: 'dxSelectBox',
                    editorOptions: {
                        items: ['yyyy', 'yyyyMM', 'yyyyMMdd', 'yyyy-MM', 'yyyy-MM-dd'],
                    }
                }]
            }]
        }).dxForm('instance');
    }

    /**
     * parameter confirm component (button)
     */
    function paramConfirmBtn() {
        return $('#paramConfirmBtn').dxButton({
            type: 'normal',
            onClick: function() {
                self.state.onConfirm(self.state.params);
                onPopupClose();
            }
        }).dxButton('instance');
    }

    /**
     * parameter cancel component (button)
     */
    function paramCancelBtn() {
        return $('#paramCancelBtn').dxButton({
            type: 'normal',
            onClick: onPopupClose
        }).dxButton('instance');
    }

    /**
     * Renders dataset parameter editor component.
     * @param props { dsId: string, dsType: string, params: object[] }
     */
    this.render = function(props) {
        self.setState(props);

        if (self.state.params.length === 0) {
            WISE.alert('매개변수 생성후 편집 하시기 바랍니다.');
            return;
        }
        
        $('body').remove('#paramEditorPopup').append('<div id="paramEditorPopup" />');
        self.container = $('#paramEditorPopup').dxPopup({
            showCloseButton: false,
            showTitle: true,
            title: '매개변수 편집',
            visible: true,
            closeOnOutsideClick: false,
            width: '90vw',
            height: '90vh',
            maxWidth: 1300,
            maxHeight: 900,
            onShowing: function() {
                self.components = {
                    parameterList: parameterList(),
                    parameterForm: parameterForm(),
                    parameterDetailsForm: parameterDetailsForm(),
                    paramConfirmBtn: paramConfirmBtn(),
                    paramCancelBtn: paramCancelBtn(),
                };
                hideFormDetails();
                if (self.state.selectedParam.length > 0) {
                    self.components.parameterList.selectRows([self.state.selectedParam]);
                }
                self.trackUserInput = true;
            },
            contentTemplate:function() {
                return $(
                    '<div class="modal-body" style="height: calc(100% - 85px);">' + 
                        '<div class="row" style="height:100%">' + 
                            '<div class="column" style="width:30%">' + 
                                '<div class="modal-article" style="height: 100%; margin-top:0px;">' + 
                                    '<div class="modal-tit" style="height: 40px;">' + 
                                        '<span>매개변수 목록</span>' +
                                    '</div>' +
                                    // parameter list component (dataGrid)
                                    '<div id="parameterList"></div>' + 
                                '</div>' + 
                            '</div>' +
                            '<div class="column" style="width:70%">' +
                                '<div class="row" style="height: 43%; width: 100%;">' +
                                    '<div class="modal-article" style="width: 100%;">' +
                                        '<div class="modal-tit" style="height: 40px;">' + 
                                            '<span>매개변수 정보</span>' + 
                                        '</div>' +
                                        // parameter form component (form)
                                        '<div id="parameterForm"></div>' +
                                    '</div>' +
                                '</div>' +
                                '<div class="row" style="height: 57%; width: 100%;">' +
                                    // parameter details form component (form)
                                    '<div id="parameterDetailsForm"></div>' +
                                '</div>' +
                            '</div>' +
                        '</div>' +
                    '</div>' +
                    '<div class="modal-footer" style="height: 45px; padding-botton: 0;">' + 
                        '<div class="row center">' + 
                            // button components (button)
                            '<a id="paramConfirmBtn" class="btn positive ok-hide">확인</a>' + 
                            '<a id="paramCancelBtn" class="btn neutral close">취소</a>' + 
                        '</div>' +
                    '</div>'
                );
            },
        }).dxPopup('instance');
    }
}