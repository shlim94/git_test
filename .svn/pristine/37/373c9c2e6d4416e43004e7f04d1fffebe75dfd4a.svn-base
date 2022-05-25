var gConsole, gMessage, gDashboard;

$(document).ready(function() {
	gConsole = new WISE.Console();
	gMessage = new WISE.lang.Message();
	if (!$('#progress_box').length) {
		gProgressbar = new WISE.libs.Progressbar();
	}
	gDashboard = new WISE.libs.Dashboard('gDashboard', 'contentContainer');
	gDashboard.init();

	$(document).on("dblclick","#licenceInfo",function(){ 
		 var url = WISE.Constants.domain + WISE.Constants.context + '/monitoring';
		  window.open(url);
	 });
	

});