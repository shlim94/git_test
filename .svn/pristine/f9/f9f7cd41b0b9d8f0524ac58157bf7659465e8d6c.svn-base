
WISE.libs.Dashboard.util.PanelResizer = function(){
	var self = this;
	
	this.render = function(){
		var collapseHeight = $('#tab-content').height();
		
		//2020.02.18 MKSONG 컬럼선택기 영역 리사이즈 기능 추가 DOGFOOT
		$(".panel.tree.active").resize_panel({
		   handleSelector: "#splitter",
		   resizeHeight: false,
		   target: ".panel.data.active"
		 });

		
		 //20201209 AJKIM R 분석 기능 추가 dogfoot
		 if(gDashboard.reportType === 'RAnalysis'){
			 $(".panel.data.active").resize_panel({
			   handleSelector: "#splitter2",
			   resizeHeight: false,
			   target: ".panel.r"
			 });
			 
			 $(".panel.r.active").resize_panel({
			   handleSelector: "#splitter6",
			   resizeHeight: false,
			   target: ".panel.cont"
			 });
		 }else{
			//2020.02.19 MKSONG 데이터 항목 영역 리사이즈 기능 추가 DOGFOOT
			 $(".panel.data.active").resize_panel({
			   handleSelector: "#splitter2",
			   resizeHeight: false,
			   target: ".panel.cont"
			 });
		 }
		 
		$(".panel.tree.active.viewer1").resize_panel({
		   handleSelector: "#splitter3",
		   resizeHeight: false,
		   target: ".panel.data.active"
		 });
		 
		 $("#container_top").resize_panel({
		   handleSelector: "#splitter-horizontal",
		   resizeWidth: false,
		   target: "#container_bottom"
		 });
		 
		 $('#menu-collapse').on('click',function(){
			if($('#tab-content').hasClass('in')){
				$('.menu-bottom').height($('.menu-bottom').height() + collapseHeight);
				$('#container_bottom').height($('#container_bottom').height() + 12);
			}else{
				$('.menu-bottom').height($('.menu-bottom').height() - collapseHeight);
				$('#container_bottom').height($('#container_bottom').height() - 12);
			}
		 });
	}
};
