/**
 * 데이터 집합 선택 팝오버 컴포넌트 클래스
 * Dataset designer popover component class.
 */
WISE.libs.Dashboard.DatasetDesignerSelector = function() {
    var self = this;
    this.datasourceSelector = new WISE.libs.Dashboard.DatasourceSelector();
    /* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
    this.state = {
        userId: '',
        userNo: null,
        reportType: 'DashAny',
        joinType: '' 
    };
    this.container = null;
    this.components = {
        selectDsTypeList: null
    };

    /**
     * Update component state.
     */
    this.setState = function(state) {
        $.extend(self.state, state);
    }

    /**
     * Renders dataset designer selector component.
     * @param props { userId: string, userNo: number, reportType: string }
     */
    this.render = function(props) {
        self.setState(props);

        $('body').remove('#newDatasetPopover').append('<div id="newDatasetPopover" />');
        self.container = $('#newDatasetPopover').dxPopover({
            height: 'auto',
            width: 310,
            position: 'left',
            visible: false,
            target: $('.db'),
            contentTemplate: function() {
                return '<div id="selectDsTypeList"></div>';
            },
            onShowing: function() {
                self.components = {
                    selectDsTypeList: selectDsTypeList()
                };
            },
        }).dxPopover('instance');

        addPopupToggleListener();
    }

    function addPopupToggleListener() {
        // add popover show/hide action to click event
        $('.db').off('click').on('click', function() {
            // self.container.option('visible', !(self.container.option('visible')));
            // aa();
        });
    }

    /**
     * dataset designer list component (list)
     */
    function selectDsTypeList() {
    	var menuConfigJson = menuConfigManager.getMenuConfig.Menu;	
		
        var dataSource = [];
        if (self.state.reportType === 'AdHoc') {
            dataSource = [
				{caption: '주제 영역 데이터', value:'OPEN_CUBE', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.CUBE},
				{caption: '신규 데이터 집합(주제 영역 기준)', value:'CUBE', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetCube},
				{caption: '신규 데이터 집합(데이터 원본 기준)', value:'DS', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDs},
				{caption: '신규 데이터 집합(이기종 조인)', value:'DSJOIN', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDsJoin},
				{caption: '신규 데이터 집합(쿼리 직접 입력)', value:'DS_SQL', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_sqlInput.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSQL},
				{caption: '신규 데이터 집합(단일 테이블)', value:'DS_SINGLE', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_singleTable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSingleDs},
				{caption: '사용자 데이터 업로드', value:'DS_USER', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exceltable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetUser},
				{caption: '기존 데이터 집합', value:'DS_OLD', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exist.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetLoad},
            ];
        } else {
            dataSource = [
            	/* DOGFOOT ktkang 대시보드 주제영역 기능 추가  20200618 */
            	{caption: '주제 영역 데이터', value:'OPEN_CUBE', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.CUBE},
            	{caption: '신규 데이터 집합(주제 영역 기준)', value:'CUBE', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_subject.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetCube},
				{caption: '신규 데이터 집합(데이터 원본 기준)', value:'DS', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDs},
				{caption: '신규 데이터 집합(이기종 조인)', value:'DSJOIN', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_dataSource.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetDsJoin},
				{caption: '신규 데이터 집합(쿼리 직접 입력)', value:'DS_SQL', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_sqlInput.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSQL},
				{caption: '신규 데이터 집합(단일 테이블)', value:'DS_SINGLE', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_new_singleTable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetSingleDs},
				{caption: '사용자 데이터 업로드', value:'DS_USER', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exceltable.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetUser},
				{caption: '기존 데이터 집합', value:'DS_OLD', ImageSrc:WISE.Constants.context + '/resources/main/images/ico_exist.png', visible: menuConfigJson.DATASET_MENU_TYPE.DataSetLoad},
            ];
        }
        
        return $('#selectDsTypeList').dxList({
            dataSource: dataSource,
            displayExpr:'caption',
            keyExpr:'value',
            width: 270,
            itemTemplate: function(data) {
                return  $('<div>')
                    .append(
                        $('<img>').attr('src', data.ImageSrc).css('width', '32px')
                    )
                    .append(
                        $('<span>').text(data.caption).css('padding-left', '5px')
                    );
            },
            onItemClick: function(e) {
                switch (e.itemData.value) {
                    case 'DS_OLD':
                        gDashboard.datasetMaster.openDataset();
                        break;
                    case 'DS':
                    	self.datasourceSelector.render({ userId: self.state.userId, userNo: self.state.userNo, dsType: e.itemData.value, joinType: 'N'  });
                    case 'DSJOIN':
                    	self.datasourceSelector.render({ userId: self.state.userId, userNo: self.state.userNo, dsType: e.itemData.value, joinType: 'Y'  });
                    default:
                        self.datasourceSelector.render({ userId: self.state.userId, userNo: self.state.userNo, dsType: e.itemData.value });
                }
                self.container.hide();
            },
        }).dxList('instance');
    }
}