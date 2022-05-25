/**
 * 2020.05.12 MKSON DOGFOOT
 * 모든 아이템의 데이터 항목 영역은 이곳에서 관리
 */

WISE.libs.Dashboard.item.ColumnChooserManager = function() {
	this.column_chooser = function(){
		var fieldChooser = new WISE.libs.Dashboard.item.FieldChooser();
//		fieldChooser.datasetType = WISE.Context.isCubeDataset ? 'cube' : 'common';
//		fieldChooser.fieldManager = self.fieldManager;
		gDashboard.fieldChooser = fieldChooser;
		fieldChooser.show();
	}
};