WISE.libs.Dashboard.util.WindowSet = function(){
	var self = this;
	this.render = function(){
		$('body').height('100%');
		$('body').width('100%');
		
		if($('body').width() < 1920 && $('body').width() > 1200){
			$('.panel-column-selector').width($('#column-selector-set').width() * 0.5 - $('#splitter').width()-3);
			$('.right-side').width($('.menu-bottom').width() * 0.752039 - $('#splitter2').width() * 0.5);
		}
		
		$('.column-set').height($('.panel-column-selector').height()-$('.panel-heading').height());
		$('#home > a').text(gMessage.get('WISE.message.page.widget.nav.home'));
		$('#insert > a').text(gMessage.get('WISE.message.page.widget.nav.insert'));
		$('#datasource > a').text(gMessage.get('WISE.message.page.widget.nav.propertiessource'));
//		$('#data > a').text(gMessage.get('WISE.message.page.widget.nav.properties'));
//		$('#design > a').text(gMessage.get('WISE.message.page.widget.nav.design'));
		
		$('.filter').text(gMessage.get('WISE.message.page.widget.drop.filter'));
		$('.drop-column').text(gMessage.get('WISE.message.page.widget.drop.column'));
		$('.drop-row').text(gMessage.get('WISE.message.page.widget.drop.row'));
		$('.drop-data').text(gMessage.get('WISE.message.page.widget.drop.data-field'));
		
		$('.chart-panel > div').text(gMessage.get('WISE.message.page.widget.panel.chart'));
		$('.grid-panel > div').text(gMessage.get('WISE.message.page.widget.panel.grid'));
		$('.column-drop-head').text(gMessage.get('WISE.message.page.widget.panel.drop'));
		$('.column-selector-head').text(gMessage.get('WISE.message.page.widget.panel.columnSelect'));
		
		/* focusing Test*/
		var zoomWin = null;
		$('#portal').on('click',function(){
			if (zoomWin != null && !zoomWin.closed) 
		     {
		          zoomWin.focus(); 
		          return false;
		     } 
		     zoomWin = window.open("","parent");
		     zoomWin.focus();
		});
		
	}
};
