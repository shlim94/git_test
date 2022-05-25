/**
 * 데이터집합 이름 편집 컴포넌트 클래스
 * Dataset name editor component class.
 */
 WISE.libs.Dashboard.DatasetNameEditor = function() {
    var self = this;

    this.state = {
        element: null,
        target: null,
        name: '',
        onNameChangeConfirm: null,
        onNameChangeCancel: null,
    };

    this.components = {
        dsNameTextEditor: null,
        dsNameChangeOkBtn: null,
        dsNameChangeCancelBtn: null,
    };

    /**
     * Update component state.
     */
    this.setState = function(state) {
        $.extend(self.state, state);
    }

    /**
     * dataset name text editor component (textBox)
     */
    function dsNameTextEditor() {
        return $("#dsNameTextEditor").dxTextBox({
            width: 350,
            value: self.state.name,
        }).dxTextBox('instance');
    }

    /**
     * dataset name confirm component (button)
     */
    function dsNameChangeOkBtn() {
        return $("#dsNameChangeOkBtn").dxButton({
            text: "확인",
            type: "normal",
            onClick: function(e) {
            	if(self.components.dsNameTextEditor.option('value')==='') {
            		WISE.alert('데이터집합명을 입력해주세요.');
            	} else {
	                self.setState({ name: self.components.dsNameTextEditor.option('value') });
	                self.state.onNameChangeConfirm(self.state.name);
            	}
            }
        }).dxButton('instance');
    }

    /**
     * dataset name cancel component (button)
     */
    function dsNameChangeCancelBtn() {
        return $("#dsNameChangeCancelBtn").dxButton({
            text: "취소",
            type: "normal",
            onClick: function(e) {
                self.state.onNameChangeCancel();
            }
        }).dxButton('instance');
    }

    /**
     * Renders dataset name editor component.
     * @param props { element: DOMElement, target: DOMElement, name: string, onNameChangeConfirm: function, onNameChangeCancel: function }
     */
    this.render = function(props) {
        self.setState(props);

        return self.state.element.dxPopover({
            target: self.state.target,
            contentTemplate: function() {
                return  '<div><em class="primary">데이터 집합 명 변경</em></div>'+
                        // dataset name text editor component (textBox)
                        '<div id="dsNameTextEditor"></div>'+
                        '<div class="row center">' +
                            '<div style="margin-top: 20px;">' +
                                // dataset name confirm component (button)
                                '<a id="dsNameChangeOkBtn" class="btn crud positive" href="#">변경</a>' +
                                // dataset name cancel component (button)
                                '<a id="dsNameChangeCancelBtn" class="btn crud neutral" href="#">취소</a>' +
                            '</div>' +
                        '</div>';
                
            },
            onShowing: function() {
                self.components = {
                    dsNameTextEditor: dsNameTextEditor(),
                    dsNameChangeOkBtn: dsNameChangeOkBtn(),
                    dsNameChangeCancelBtn: dsNameChangeCancelBtn(),
                };
            }
        }).dxPopover('instance');
    }
 }