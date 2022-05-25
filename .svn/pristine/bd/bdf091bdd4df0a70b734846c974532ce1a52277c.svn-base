// Global Apprise variables
var $Alert = null,
	$AlertPopup = null,
//	$overlay = null,
	$body = null,
	$window = null,
	$alertStrong = null,
	$alertContent = null,
	$cA = null,
	// 2020.01.16 mksong confirm 기능 추가위한 변수 변경 dogfoot	
	$ok = null,
	$exit = null,
	$btnDetail = null,
	AlertQueue = [];

// Add overlay and set opacity for cross-browser compatibility
$(function() {
	var html = '<div id="alert-container" class="alert-container" style="width:330px">';
		html += '</div>';
	
//	$overlay = $('<div class="alert-overlay">');
	$body = $('body');
	$window = $(window);
	
//	$body.append( $overlay.css('opacity', '.70')).append($Alert);
	$body.append(html);
	
	$Alert = $('#alert-container');
	
	var contentHtml = '	<div class="modal-inner">';
	contentHtml += '		<div class="modal-body">';
	contentHtml += '			<div class="alert-inner">';
	contentHtml += '				<strong class="alert-strong"></strong>';
	contentHtml += '				<p class="alertContent" style="width:100%"></p>';
	contentHtml += '			</div>';
	contentHtml += '		</div>';
	contentHtml += '		<div class="modal-footer">';
	contentHtml += '			<div class="row center">';
	// 2020.01.16 mksong confirm 기능 추가 dogfoot	
	contentHtml += '				<a href="#" class="btn close ok">확인</a>';
	contentHtml += '				<a href="#" class="btn close exit negative" style="margin-left:0px; margin-top:10px;">취소</a>';
	contentHtml += '			</div>';
	contentHtml += '		</div>';
//	contentHtml += '		<a href="#" class="btn-detail">상세보기</a>';
	contentHtml += '	</div>';
//	contentHtml += '	<div class="detail-cont">';
//	contentHtml += '		<p>상세보기 영역</p>';
	contentHtml += '	</div>';
	
	$('#alert-container').dxPopup({
		width:300,
		// 2020.01.16 mksong 경고창 높이 자동 조정 dogfoot
		height:'auto',
		visible:false,
		showTitle:false,
		onContentReady: function(){
			gDashboard.fontManager.setFontConfigForEditText('alert-container');
		},
		contentTemplate: function() {
            return contentHtml;
        }
	});
	
	$AlertPopup = $('#alert-container').dxPopup('instance');
});

//2020.01.22 KERIS MKSONG 경고창 옵션 설정 기능 추가 DOGFOOT
function Alert(text, state, _options){
	// Restrict blank modals
	if(text===undefined || !text) {
		return false;
	}
	$Alert.removeClass("success");
	$Alert.removeClass("error");
	/* DOGFOOT ktkang alert 색상 오류 수정  20200214 */
	$Alert.removeClass("alert");

	// 2020.01.16 mksong confirm 기능 추가 위한 수정 dogfoot	
	$AlertPopup.option('onShowing', function(){
    	$alertStrong = $('.alert-strong');
//        	$btnDetail = $('.btn-detail');
    	$alertContent = $('.alertContent');
    	$ok = $Alert.find('.ok');
    	$exit = $Alert.find('.exit');
    });
	

	$AlertPopup.option('onShown', function(){
		//2020.01.22 KERIS MKSONG 경고창 옵션 설정 기능 추가 DOGFOOT
		
		$alertContent.off('dblclick').on('dblclick',function(e){
		   var text = $alertContent[0].textContent;	  
		   var tempElem = document.createElement('textarea');
		   tempElem.value = text;  
		   document.body.appendChild(tempElem);
		   tempElem.select();
		   document.execCommand("copy");
		   document.body.removeChild(tempElem);
		   
		});
		
		
		if(_options != undefined){
			if(_options.buttons != undefined){
				if(_options.buttons.confirm != undefined){
					$ok.off('click').on('click',_options.buttons.confirm.action);
					$exit.off('click').on('click',function(e){
						e.preventDefault();
						$AlertPopup.hide();
					});
				}
				if(_options.buttons.cancel != undefined){
					$exit.off('click').on('click',_options.buttons.cancel.action);
				}else{
					$exit.off('click').on('click',function(e){
						e.preventDefault();
						$AlertPopup.hide();
					});
				}
			}else{
				/* DOGFOOT ktkang click 이벤트 겹침 오류 수정  20200214 */
				$ok.off('click').on('click',function(e){
			      e.preventDefault();
			      $AlertPopup.hide();
		    	});
				
				/* DOGFOOT ktkang click 이벤트 겹침 오류 수정  20200214 */
				$exit.off('click').on('click',function(e){
			      e.preventDefault();
			      $AlertPopup.hide();
				});
			}
		}else{
			/* DOGFOOT ktkang click 이벤트 겹침 오류 수정  20200214 */
			$ok.off('click').on('click',function(e){
		      e.preventDefault();
		      $AlertPopup.hide();
	    	});
			
			/* DOGFOOT ktkang click 이벤트 겹침 오류 수정  20200214 */
			$exit.off('click').on('click',function(e){
		      e.preventDefault();
		      $AlertPopup.hide();
			});
		}
    });
			//2020.01.22 KERIS MKSONG 경고창 옵션 설정 기능 추가 수정 끝 DOGFOOT
	
	$AlertPopup.show();
	
	$ok.removeClass('positive');
	$ok.removeClass('red');
	/* DOGFOOT ktkang alert 색상 오류 수정  20200214 */
	$ok.removeClass('green');
	
	$exit.css('display','none');
	
	$alertStrong.empty();
	if(state == 'success'){
		$Alert.addClass("success");
		$ok.addClass('positive');
		$alertStrong.append('성공 !');
	}else if(state == 'error'){
		$Alert.addClass("error");
		$ok.addClass('red');
		$alertStrong.append('에러발생');
	}else{
		$Alert.addClass("alert");
		$ok.addClass('green');
		$alertStrong.append('알림 !');
	}
	
	$alertContent.empty();
	$alertContent.append(text);
}

function Confirm(text, _options){
	// Restrict blank modals
	if(text===undefined || !text) {
		return false;
	}
	$Alert.removeClass("success");
	$Alert.removeClass("error");
	
	$AlertPopup.option('onShowing', function(){
    	$alertStrong = $('.alert-strong');
//        	$btnDetail = $('.btn-detail');
    	$alertContent = $('.alertContent');
    	$ok = $Alert.find('.ok');
    	$exit = $Alert.find('.exit');
    	
    	$ok.removeClass('positive');
    	$ok.removeClass('red');
    	
    	$exit.css('display','block');
    	
    	$alertStrong.empty();
    	$Alert.addClass("alert");
    	$ok.addClass('green');
    	$alertStrong.append('알림 !');
    	
    	$alertContent.empty();
    	$alertContent.append(text);
    });
	
	$AlertPopup.option('onShown', function(){
		if(_options.buttons != undefined){
			if(_options.buttons.confirm != undefined){
				$ok.text(_options.buttons.confirm.text);
				$ok.off('click').on('click',_options.buttons.confirm.action);
				$exit.off('click').on('click',function(e){
					e.preventDefault();
					$AlertPopup.hide();
				});
			}
			if(_options.buttons.cancel != undefined){
				$exit.off('click').on('click',_options.buttons.cancel.action);
			}else{
				$exit.off('click').on('click',function(e){
					e.preventDefault();
					$AlertPopup.hide();
				});
			}
		}
    });
	
	$AlertPopup.show();
}

	// 2020.01.16 mksong confirm 기능 추가 위한 수정 끝 dogfoot	