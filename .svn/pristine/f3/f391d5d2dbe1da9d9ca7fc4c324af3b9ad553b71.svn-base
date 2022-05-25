/**
 * 
 */

WISE.libs.Progressbar = function() {
	var self = this;
	this.progressBox;
	this.stopngo = true;
	this.cancelDelay = false;
	/* DOGFOOT hsshim 2020-02-06 마스터 필터 속도 개선 (DEBUG 기능) */
	this.startTime;
	this.endTime;
	
	this.cancelQuery = function(){
		// 20200731 ajkim 작업 취소 시 5초간 로딩바가 뜨지 않도록 수정 dogfoot
		// ktkang 1초로 줄임
		this.cancelDelay = true;
		setTimeout(function(){
			self.cancelDelay = false;
		}, 1000);
	}
	
	this.setStopngoProgress = function(value){
		self.stopngo = value;
	};
	
	//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
	this.show = function(_queryCancelDel) {
		if(this.cancelDelay) return;
		$(this.progressBox).css({'display' : 'block'});
		if(!_queryCancelDel){
			$('#queryCancel').css({'display' : 'block'});	
		}else{
			$('#queryCancel').css({'display' : 'none'});
		}
	};
	
	this.hide = function() {
		if(self.stopngo){
			$(this.progressBox).css({'display' : 'none'});
		}
	};

	/**
	 * After progress bar shows, trigger custom function.
	 */
	this.showThen = function(customFunction) {
		$(this.progressBox).show(0, customFunction);
	};

	/* DOGFOOT hsshim 2020-02-06 마스터 필터 렌더링 표시 추가 */
	this.resetListeners = function() {
		self.listenerCount = 0;
		self.doneListenerCount = 0;
		self.startTime = 0;
		self.endTime = 0;
	};

	this.beginListening = function(count) {
		self.resetListeners();
		self.listenerCount = count;
		self.show();
		self.startTime = performance.now();

	};

	this.finishListening = function() {
		if (self.listenerCount > 0) {
			self.doneListenerCount++;
			if(self.listenerCount <= self.doneListenerCount){
				self.endTime = performance.now();
				console.log('마스터 필터 실행 시간: ' + (self.endTime - self.startTime) + ' ms');
				self.resetListeners();
				self.hide();
			}
		}
	};
	/* DOGFOOT hsshim 2020-02-06 끝 */
	
	(function() {
		//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
		var html = '<div class="img_progress"></div><div class="queryCancel progress-btn-type" id="queryCancel" style="display:none;"></div><div class="progress_back_panel"></div>';
		
		self.progressBox = $('<div></div>', {
			'id' : 'progress_box',
			'class' : 'progress_box'
		});
		self.progressBox.html(html);
		
		$(document.body).append(self.progressBox);
		// 2020.01.16 mksong 작업 취소 문구 처음부터 보이도록 수정 dogfoot
		$('#queryCancel').dxButton({
			text:"작업 취소",
			type:'default',
			onClick:function(_e){
				//2020.02.12 mksong 프로그레스바 작업취소 최적화 dogfoot
				gProgressbar.setStopngoProgress(true);
				gProgressbar.hide();
				$.ajax({
					type : 'post',
					cache : false,
					async: false,
					url : WISE.Constants.context + '/report/cancelqueries.do',
					complete: function(_e) {
						gProgressbar.cancelQuery();
//						gProgressbar.hide();
					}
				});
			}
		});
	})();
};