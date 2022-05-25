/**
 * Database table/column selector popup component.
 */
WISE.libs.Dashboard.TableColumnPicker = function() {
    var self = this;
    this.components = {
        tableColumnList: null,
        tableColumnConfirmBtn: null,
        tableColumnCancelBtn: null,
    };
    this.container = null;

    /**
     * Render the component.
     */
    this.render = function(props) {
        $.ajax({
            method: 'POST',
            url: WISE.Constants.context + '/report/getDatasetTableColumns2.do',
            data:{
                id: props.id,
                type: props.type,
                table: props.table,
                request: props.request
            },
            beforeSend: function() {
                gProgressbar.show();
            },
            complete: function() {
                gProgressbar.hide();
            },
            success: function(data) {
                $('body').remove('#paramTableSearchPopup').append('<div id="paramTableSearchPopup" />');
                self.container = $('#paramTableSearchPopup').dxPopup({
                    visible: true,
                    width:600,
                    height:700,
                    contentTemplate: function() {
                        return $(
                            '<div class="modal-body" style="height: calc(100% - 85px);">' + 
                                // result grid component (dataGrid)
                                '<div id="tableColumnList"></div>' +
                            '</div>' +
                            '<div class="modal-footer" style="height: 45px; padding-botton: 0;">' + 
                                '<div class="row center">' + 
                                    // button components (button)
                                    '<a id="tableColumnConfirmBtn" class="btn positive ok-hide">확인</a>' + 
                                    '<a id="tableColumnCancelBtn" class="btn neutral close">취소</a>' + 
                                '</div>' +
                            '</div>'
                        );
                    },
                    onShowing: function() {
                        self.components = {
                            tableColumnList: tableColumnList(data, props.request),
                            tableColumnConfirmBtn: tableColumnConfirmBtn(props.onConfirm),
                            tableColumnCancelBtn: tableColumnCancelbtn(),
                        };
                    }
                }).dxPopup('instance');
            }
        });
    }

    /**
     * Table/column search result list component
     * @param {object[]} data 
     * @param {string} request 
     */
    function tableColumnList(data, request) {
        return $('#tableColumnList').dxDataGrid({
            height: '100%',
            dataSource: data,
            keyExpr: 'text',
            columns: [{
                dataField: 'id',
                caption: '물리명',
                visible: request === 'TABLE'
            },{
                dataField: 'text',
                caption: request === 'TABLE' ? '논리명' : '컬럼명'
            }],
            paging: {
                enabled: false
            },
            selection: {
                mode: 'single'
            }
        }).dxDataGrid('instance');
    }

    /**
     * Table/column select confirm button component
     * @param {function} onConfirm 
     */
    function tableColumnConfirmBtn(onConfirm) {
        return $('#tableColumnConfirmBtn').dxButton({
            onClick:function(){
                var selected = grid.getSelectedRowKeys();
                if (selected[0]) {
                    onConfirm(selected[0]);
                    self.container.hide();
                }
            }
        }).dxButton('instance');
    }

    /**
     * Table/column select cancel button component
     */
    function tableColumnCancelBtn() {
        return $('#tableColumnCancelBtn').dxButton({
            onClick:function(){
                self.container.hide();
            }
        }).dxButton('instance');
    }
}