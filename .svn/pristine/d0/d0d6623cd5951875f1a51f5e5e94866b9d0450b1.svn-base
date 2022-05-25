var menuConfigManager = (function() {
	
	this.configJsonData = {};

	function initMenu() {
		var configData = getDataDB();
		
		$.ajax({
			url: WISE.Constants.context + '/report/getMenuConfig.do',
			dataType: "json",
			method: 'GET',
			async: false,
			success: function(_data){
				if(_data.data){
					configData = JSON.stringify(_data.data);
				}				
			}
		});
		this.configJsonData = JSON.parse(configData);
		return this.configJsonData;
	}
	
	function getDataDB(){
		var data =
			'{"Menu" :'+
		    '{'+
		        '"PROG_MENU_TYPE" : {' +
		            '"AdHoc" : {"visible":true, "popup":false},' +
		            '"DashAny" : {"visible":true, "popup":false},' +
		            '"Excel": {"visible":false, "popup":true},' +
		            '"DataSet": {"visible":true, "popup":false},' +
		            '"Config":{"visible":true, "popup":true}' +
		        '},' +
		        '"TOP_MENU_TYPE" : {' +
		            '"Scheduler" : { "visible" : false},' +
		            '"Container" : { "visible" : false},' +
		            '"InsertAdHoc" : { "visible" : true}' +
		            /* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
		            '"QueryView" : { "visible" : true}' +
	            '},'+
		        '"DATASET_MENU_TYPE" : {' +
		            '"CUBE" : true,' +
		            '"DataSetCube" : false,' +
		            '"DataSetDs" : true,' + 
		            /* DOGFOOT ktkang 데이터 원본 기준에서 이기종 조인 분리  20201014 */
		            '"DataSetDsJoin" : false,' +
		            '"DataSetSQL" : true,' +
		            '"DataSetSingleDs" : false,' +
		            '"DataSetUser" : true,' +
		            '"DataSetLoad" : true' +
		        '},' +
		        '"SPREAD_MENU_TYPE" : {' +
	            	'"Print" : true,' +
	            	'"BindType" : sheetBind' +
	            '},'+
		        '"DOWNLOAD_MENU_TYPE" : {' +
		            '"Office" : { "visible" : true, "xlsx": true, "xls": true, "doc": false, "ppt": false},' +
		            '"Hancom" : { "visible" : false, "hwp": true, "cell": true, "show": true},' +
		            '"Etc" : { "visible" : true, "img": true, "html": true, "pdf": true}' +
	            '}'+	          	            
		    '}}';

		return data;
	}
	
	return {
		getMenuConfig : initMenu()
	}
	
})();