//2020.01.22 KERIS MKSONG 서버 연결 확인 테스트 DOGFOOT
var gConsole, gProgressbar, gMessage, gDashboard, gDictionary;

$(document).ready(function() {
	//Globalize.culture(navigator.language || navigator.browserLanguage);
	
	Globalize.locale(navigator.language || navigator.browserLanguage); // 반드시 gDashboard보다 상위에 설정

	gConsole = new WISE.Console();
	gMessage = new WISE.lang.Message();
	if (!$('#progress_box').length) {
		gProgressbar = new WISE.libs.Progressbar();
	}
	/*dogfoot 속도 테스트 속도테스트 shlim 20201209*/
	console.log("-----------------------------------------------------------------------");
	console.log("속도 테스트 시작");
	console.log("-----------------------------------------------------------------------");
	window.startGenTime = window.performance.now();
	window.startQueryTime={};
	window.endQueryTime={};
	window.startDrawItemTime={};
	window.endDrawItemTime={};
	
	gDashboard = new WISE.libs.Dashboard('gDashboard', 'contentContainer');
	gDashboard.button.printScreen = 'btn_print';
	gDashboard.init();
	
	gDictionary = DevExpress.localization.message.getDictionary();
//	var json = JSON.stringify(DevExpress.localization.getDictionary());

//	$("#reloadButton").click(function(){
//		window.location.reload();
//	})
	var page = window.location.pathname.split('/');
//	if (page[page.length - 1] != 'viewer.do') {
//		var scheduler = new WISE.libs.Dashboard.Scheduler();
//		scheduler.init();
//	}
	// 개인 설정 적용
	gDashboard.applyUserSettings();
	//2020.11.03 mksong resource Import 동적 테스트 dogfoot
//	console.log('완료 타임 : ' + new Date());
});