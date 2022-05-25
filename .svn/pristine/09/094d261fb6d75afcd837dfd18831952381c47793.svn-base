var fontConfigManager = (function() {
	
	this.configJsonData = {};

	function initMenu() {
		var configData = getData();
		
		$.ajax({
			url: WISE.Constants.context + '/report/getFontConfig.do',
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
	
	function getData(){
		var data = '{"FONT_FAMILY":"Basic","FONT_SIZE":9,"FONT_COVERAGE":{"Menu":false,"Item":true}}'
		return data;
	}
	
	return {
		getFontConfig : initMenu()
	}
	
})();