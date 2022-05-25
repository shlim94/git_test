$(document).ready(function(){
//    // check func
//    userAgentCheck();
//    languageCheck();
//    $('.scrollbar').scrollbar();

//    // top bar util menu UI
//    utilUi();
//    menuItemUi();
//    menuItemSlideUi();

//    // common layout UI
//    tabUi();
//    boxColumn();
//    tabColumnClass();

//    // panel UI
//    panelUi();
//    panelLayout();

//    panelDataUi();
//    containerBoxUi();

//    compMoreMenuUi();
//    designMenuUi();

//    // modal UI
//    miniPop();
//    modalUi();



//    // input UI
//    btnswitch();
//    treeMenuUi();
// 	  treeTableUi(); // 0723 추가
//    customSelect();
//    fileUploadUi();


//    // media UI
//    resizeUi();
//    mediaTab();

// 	// 0729 모바일반응형 탭 ui 추가
//    preferencesTabMo();
});

var pressKey = {};
$(document).on('keydown', function(e){
	pressKey[e.key] = true;
});

$(document).on('keyup', function(e){
	pressKey[e.key] = false;
});


function displayBtnMoreUi(){
    $('.display-move-wrap').find('.arrayDown').each(function(){
        var dvbtnOffsetT = $(this).offset().top;
        var dvbtnOffsetL = $(this).offset().left;
        var dvWidth = $(this).width();
        var dvHeight = $(this).height();

        $(this).next('.divide-menu').offset({left: dvbtnOffsetL + dvWidth - 18, top: dvbtnOffsetT});
        $(this).next('.divide-menu').height(dvHeight);
    });
}

function preferencesTabMo(){
    var tabOnText = $('.panel-head.on a').text();
    if($('.mo-slt').length){
        $('.mo-slt a').text(tabOnText);
        $('.mo-slt a').off('click').on('click', function(){
            $(this).parent().toggleClass('active');
            $(this).parent().siblings().toggleClass('show');
        });
    }

}

//0701 소스추가
$(window).scroll(function(){
    if($('.other-menu-ico').length){
        $('.other-menu-ico').removeClass('on');
    }
});

$(window).resize(function() {
	/* DOGFOOT ktkang 뷰어 window resize 오류 수정  20200221 */
	if(typeof WISE.Constants != 'undefined' && WISE.Constants.editmode == 'viewer'){
		if($('#reportContainer').length != 0){
			/* DOGFOOT ktkang KERIS portal뷰어에서 빈공간 삭제   20200228 */
			if(gDashboard.portalView) {
				$('#reportContainer').height($('.content').height() - 10);
			} else {
				$('#reportContainer').height($('.content').height()-$('.filter-bar').height() - 15);
			}
			if(gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id] != undefined){
        		gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id].canvasLayout.updateSize($('#reportContainer').width(),$('#reportContainer').height());
        	}
		}
	}
	//2020.02.13 mksong resize 느리게 동작해서 주석 dogfoot
//    if(this.resizeTO) {
//        clearTimeout(this.resizeTO);
//    }
//    this.resizeTO = setTimeout(function() {
//        $(this).trigger('resizeEnd');
//    }, 400);
});
$(window).on('resize', function(){
    btnswitch();
    resizeUi();
    panelLayout();
    modalUi();
    lnbResponsive(); // 0701;

    // 0528 소스추가
    if($('.other-menu-ico').length){
        $('.other-menu-ico').removeClass('on');
    }

    // 1203
    panelDataUi();
    displayBtnMoreUi();
    /* mksong 2020.01.21 불필요한 부분 삭제 dogfoot */
    if(WISE.Constants != undefined){
    	if(WISE.Constants.editmode == 'viewer'){
        	var height = $('#treeopen').height() * 0.87;
        	if($('#reportList').children().length != 0){
        		$('#reportList').dxTreeView('instance').option('height',height);
        	}
        	if(gDashboard != undefined){
            	if(gDashboard.parameterFilterBar != undefined){
            		gDashboard.parameterFilterBar.resize();
            	}
            }
        }else{
        	if(gDashboard != undefined){
            	if(gDashboard.parameterFilterBar != undefined){
            		gDashboard.parameterFilterBar.resize();
            	}
            }
        }
    }
}).resize();

//수정
$(window).resize(function() {
    if(this.resizeTO) {
        clearTimeout(this.resizeTO);
    }
    this.resizeTO = setTimeout(function() {
        $(this).trigger('resizeEnd');
    }, 400);
});

function lnbResponsive(){
  /*  2020.01.07 mksong 수정사항반영 dogfoot */
//	 // 슬라이드 lnb 너비는 100% - 고정값 lnb
//    var lnbFixW = $('.fix-menu').outerWidth();
//    var customMius = lnbFixW+76;
//    $('.custom-menu').css({width : 'calc(100% - '+ customMius +'px)'});
//
//    var globalSlideL = $('.custom-menu').find('.slide-ui-item').length;
//
//    $('.slide-ui').find('.slide-ui-list').each(function(_i,_o){
//    	var slideL = $(this).find('.slide-ui-item').length;
//        var lnbWindW = $(window).width();
//    	if(_i == 1){
//    		var thisWidth = $(this).width() - 6 - $(this).find('.slide-ui-item').length * 12;
//    		if(thisWidth/$(this).find('.slide-ui-item').length < 42.3){
//    			$(this).parent().addClass('ui-active');
//    		}else{
//    			$(this).parent().removeClass('ui-active');
//    		}
//    	}else if(_i == 0){
//    		if(lnbWindW < 1460){
//    			$(this).parent().addClass('ui-active');
//    			var width = $('#tab5primary').parent().width() + 300;
//    			$(this).parent().width('calc(100% - '+ width +'px)');
//    		}else{
//    			$(this).parent().removeClass('ui-active');
//    			$(this).parent().width('304px');
//    		}
//    	}
//    });
    // 1212 해상리소스로원복
    // 슬라이드 lnb 너비는 100% - 고정값 lnb
    var lnbFixW = $('.fix-menu').outerWidth();
    var customMius = lnbFixW+76;
    $('.custom-menu').css({width : 'calc(100% - '+ customMius +'px)'});

	  /*  2020.01.07 mksong 수정사항반영 dogfoot */
    $('.slide-ui').find('.slide-ui-list').each(function(){
        var slideL = $(this).find('.slide-ui-item').length;
        var lnbWindW = $(window).width();

        if(slideL <= 5 && lnbWindW <= 1510){
            // 갯수가 5개 이하거나 해상도가 1510 이하인 경우 화살표 생성
            $(this).parent().addClass('ui-active');
        }
        /*DOGFOOT 20200206 cshan - 대시보드 항목 추가 아이콘에 슬라이드 추가*/
        if(slideL <= 3 && lnbWindW <= 1724){
        	//고급시각화쪽
        	$(this).parent().addClass('ui-active');
        }

        if(slideL >= 6 && lnbWindW <= 1700){
            // 갯수가 6개 이상이거나 해상도가 1700 이하인 경우 화살표 생성
            $(this).parent().addClass('ui-active');
        }
        /*DOGFOOT 20200206 cshan - 대시보드 항목 추가 아이콘에 슬라이드 추가*/
        if(slideL < 3 || lnbWindW > 1700){
            // 갯수가 4개 미만이거나 해상도가 1700 초과인경우 화살표 삭제
            $(this).parent().removeClass('ui-active');

        }
    });
}



//0530 선택 이외 요소 클릭시 팝업 닫히기 공통 스크립트 추가
//팝업여는버튼 click-btn 팝업 클래스 click-pop
function clickPopupUi(){
    $('.click-btn').off('click').on('click', function(e){
        e.stopPropagation();
        $('.click-pop').toggleClass('click-show');
    });
    $('.click-pop').off('click').on('click', function(e){
        e.stopPropagation();
    });

    $('body').off('click', bodyClickEvent).on('click', bodyClickEvent);
}

function bodyClickEvent(e) {
    var $tgPoint = $(e.target);
    var $popCallBtn = $tgPoint.hasClass('click-btn');
    var $popArea = $tgPoint.hasClass('click-pop');

    if ( !$popCallBtn && !$popArea ) {
        $('.click-pop').removeClass('click-show');
    }
    if($tgPoint.attr('id') != 'viewerAdhoc'){
    	if($("#viewerAdhoc").hasClass("on")){
    	    $("#viewerAdhoc").toggleClass('on')	
    	    $("#singleView_layout").css("display","none");
            $("#singleView_layout").css("display","none");	
    	}
    }
}

function userAgentCheck(){
    var ua = window.navigator.userAgent;
    var other = 999;
    var msie = ua.indexOf('MSIE ');

    // check Mobile
    if(ua.indexOf('Mobile') != -1){
        $('html').addClass('mobile');
    }

    // check Browser
    if(ua.toLowerCase().indexOf('safari') != -1){

        if(ua.toLowerCase().indexOf('chrome') != -1){
            $('html').addClass('chrome');

        } else {
            $('html').addClass('safari');
        }

    } else if(ua.toLowerCase().indexOf('firefox') != -1){
        $('html').addClass('firefox');

    } else if(ua.toLowerCase().indexOf('msie 10.0') != -1){
        $('html').addClass('ie ie10');

    } else if(ua.toLowerCase().indexOf('rv:11.0') != -1){
        $('html').addClass('ie ie11');
    }

}

function languageCheck(){
      var $html = $('html');
      var lang = $html.attr('lang');

      switch(lang){
        case 'ko' :
          $html.addClass('ko');
          break;
        case 'en' :
          $html.addClass('en');
          break;
      }
}

function miniPop(){
    $('.minPop-btn').off('click').on('click', function(e){
        $(this).toggleClass('on');
    });
}

/* 0919 수정: "off" 이벤트 추가 */
function menuItemUi(){
    $('.lnb-lst-tab .arrow').off('click').on('click',function(e){
        e.preventDefault();
        $(this).toggleClass('on').parent('li').siblings().find('.arrow').removeClass('on');
        $(this).parents('.slide-ui').siblings().find('.arrow').removeClass('on');
        $(this).parents('.menu-comp').siblings().find('.arrow').removeClass('on');

        if($(this).hasClass('on')){
            $('html').click(function(e) {
//              if(!$(e.target).hasClass("on")) {
				/*dogfoot 고급 시각화 레이아웃 수정 shlim 20201202*/
                if(!$(e.target).hasClass("on") && !$(e.target).hasClass("add-item-head")) {
                    $('.lnb-lst-tab .arrow').removeClass('on');
                }
            });
        }

     // 0604 추가
     //20201015 ajkim 다운로드 메뉴 오류 수정 dogfoot
        $('.lnb-lst-tab .right-type').find('.more-link').each(function(){
            var lnbthisW = $('.lnb-lst-tab .right-type').outerWidth();
            $(this).css({'left' : lnbthisW});
            // var lnbbtnOffsetT = $(this).offset().top;
            // $(this).offset( { top: lnbbtnOffsetT } );
        });
    });

    // hover title
    $('.add-item-body > li a,.menu-item-box-list > li a,.desing-menu-list > li a').find('span').each(function(){
        var menuName = $(this).text();
        $(this).parent('a').attr('title', menuName);
    });
    $('.menu-item-more').find('span').each(function(){
        var menuNameMore = $(this).text();
        $(this).parents('a').attr('title', menuNameMore);
    });

    $('.add-item-head').off('click').on('click', function(e){
        e.preventDefault();
        $(this).toggleClass('on');
    });

}

function menuItemSlideUi(){
    var slideUi = $('.slide-ui.responsive');
    slideUi.each(function(){
        var slideUiList = $(this).find('.slide-ui-list');
        var slideUiItem = $(this).find('.slide-ui-item');
        var slideItemWidth = slideUiItem.outerWidth();
        $(this).find('.slide-ui-prev').off('click').on('click',function(e) {
            slideUiList.animate({
                left: + slideItemWidth
            }, 0, function () {
                $(this).find('.slide-ui-item:last').prependTo(slideUiList);
                slideUiList.css('left', '');
            });
            e.preventDefault();
        });

        $(this).find('.slide-ui-next').off('click').on('click',function(e) {
            slideUiList.animate({
                left: - slideItemWidth
            }, 0, function () {
                $(this).find('.slide-ui-item:first').appendTo(slideUiList);
                slideUiList.css('left', '');
            });
            e.preventDefault();
        });
    });
}

function fileUploadUi(){
    $('.file-ui').each(function(){
        var realFileBtn = $(this).find(".real-file");
        var customBtn = $(this).find(".custom-button");
        var customTxt = $(this).find(".custom-text");
        customBtn.on("click", function() {
            realFileBtn.click();
        });

        realFileBtn.on("change", function() {
            if (realFileBtn.val()) {
                customTxt.html(realFileBtn.val().match(
                  /[\/\\]([\w\d\s\.\-\(\)]+)$/
                )[1])
            } else {
                customTxt.html("No file chosen, yet.");
            }
        });
    });
}

function compMoreMenuUi(){
	setTimeout(function() {
		$('.display-unmove').find('.wise-area-field').each(function(){
            var dvbtnOffsetT = $(this).offset().top;
            var dvbtnOffsetL = $(this).offset().left;
            var dvWidth = $(this).width();
            var dvHeight = $(this).height();

            if(WISE.Constants.editmode == 'viewer'){
            	if($(this).find('.otherBtn').length == 1){
					/* 2019.12.16 수정자 : mksong 디자인 수정 적용 dogfoot */
//                	$(this).next('.divide-menu').offset({left: dvbtnOffsetL + dvWidth + 35, top: dvbtnOffsetT-7});
            		$(this).next('.divide-menu').css({left: '175px', top: '-35px'});
                    $(this).next('.divide-menu').height(dvHeight);
                }else{
					/* 2019.12.16 수정자 : mksong 디자인 수정 적용 dogfoot */
//                	$(this).next('.divide-menu').offset({left: dvbtnOffsetL + dvWidth + 42, top: dvbtnOffsetT-7});
                	$(this).next('.divide-menu').css({left: '210px', top: '-35px'});
                    $(this).next('.divide-menu').height(dvHeight);
                }
            }else{
            	if($(this).find('.otherBtn').length == 1){
                	$(this).next('.divide-menu').offset({left: dvbtnOffsetL + dvWidth - 54, top: dvbtnOffsetT});
                    $(this).next('.divide-menu').height(dvHeight);
                }else{
                	if($(this).hasClass('delta-drop')){
                		$(this).next('.divide-menu').offset({left: dvbtnOffsetL + dvWidth - 54, top: dvbtnOffsetT});
                        $(this).next('.divide-menu').height(dvHeight);
                	}else{
                		$(this).next('.divide-menu').offset({left: dvbtnOffsetL + dvWidth - 18, top: dvbtnOffsetT});
                        $(this).next('.divide-menu').height(dvHeight);
                	}

                }
            }
        });
    }, 4);

    //0530 함수수정
    $('.other-menu-ico').off('click').on('click',function(e){
        e.preventDefault();
        /*dogfoot 데이터 항목 옵션 버튼 위치 조정 20210329 */
        $(this).parents('.display-move-wrap').siblings().siblings().find('.other-menu-ico').removeClass('on');
        $(this).toggleClass('on');
        // 0729 추가
//        $(this).parents('.display-move-wrap').siblings().find('.other-menu-ico').removeClass('on');

        if($(e.target).hasClass('dimensionFieldMenu')){
        	gDashboard.dragNdropController.expandMeasureList(e.target);
        }

        $('.right-type').find('.more-link').each(function(){
            var thisW = $(this).outerWidth();
            $(this).css({'right' : - thisW});
        });

        $('.left-type').find('.more-link').each(function(){
            var thisW = $(this).outerWidth();
            $(this).css({'left' : - thisW});
        });

        var btnOffsetT = $(this).offset().top;
        var btnOffsetL = $(this).offset().left;
        var rightPos = $(this).next('.left-type').width();
        /*dogfoot 데이터 항목 옵션 버튼 위치 조정 20210329 */
        if(window.innerHeight-10 > $(this).next('.right-type').height()+$(this).offset().top){
            $(this).next('.right-type').offset( { left: btnOffsetL, top: btnOffsetT+19 } );
            $(this).next('.left-type').offset( { left: btnOffsetL- rightPos +19, top: btnOffsetT+19 } );
        }else{
        	if(gDashboard.isSingleView && $(this).attr("id") == 'viewerAdhoc'){
        		rightPos = 100;
        		if($(this).hasClass("on")){
        		    $("#singleView_layout").css("display","block");
        		    $("#singleView_layout").css("display","block")	;
        		}else{
        			$("#singleView_layout").css("display","none");
        		    $("#singleView_layout").css("display","none");
        		}
        		
        		$("#singleView_layout").offset( { left: btnOffsetL, top: (btnOffsetT - $(this).next('.right-type').height()) } );
               $("#singleView_layout").offset( { left: btnOffsetL - rightPos*1.5 , top: (btnOffsetT) } );	
			}else{
				$(this).next('.right-type').offset( { left: btnOffsetL, top: (btnOffsetT - $(this).next('.right-type').height()) } );
                $(this).next('.left-type').offset( { left: btnOffsetL- rightPos +19, top: (btnOffsetT - $(this).next('.left-type').height()) } );	
			}	
        }
     // 1015 추가
        var btnOffsetB = $(this).next('.right-bottom-type').height();
        $(this).next('.right-bottom-type').offset( { left: btnOffsetL, top: btnOffsetT-btnOffsetB+19 } );

        // 0701 추가
        if($(this).hasClass('export')){
            $(this).next('.more-link').offset( { left: btnOffsetL- rightPos +19, top: btnOffsetT+29 } );
	    /*  2020.01.07 mksong ui 위치 변경 dogfoot */
        }else if($(this).hasClass('download')){
            $(this).next('.more-link').offset( { top: btnOffsetT+55 } );
            var po = $('#dl_popover').dxPopover('instance');
			if (po) po.option('visible', !po.option('visible'));
       	/*  2020.01.22 MKSONG 연결보고서 링크 위치 변경 DOGFOOT */
        }else if($(this).hasClass('connectR')){
        	$(this).next('.more-link').offset( { left: btnOffsetL- rightPos +19, top: btnOffsetT+56 } );
        }

        if($(this).hasClass('on')){
            $('html').click(function(e) {
                if(!$(e.target).hasClass("on")) {
                    $('.other-menu-ico').removeClass('on');
                }
            });
        }
    });

    $('.design-more-ico').off('click').on('click', function(e){
        e.preventDefault();
        $(this).toggleClass('on');
    });
}

function containerBoxUi(){
    $('.cont-box').off('click').on('click',function(){
        $(this).find('.cont-box-head .tab-title').addClass('focus').parents('.cont-box').siblings().find('.tab-title').removeClass('focus');
    });

	/* 20210212 AJKIM 다운로드 확장 기능 추가 dogfoot*/
    $('.container-inner .filter-more').off('click').on('click',function(e){
        e.preventDefault();
        /* DOGFOOT ktkang 뷰어에서 필터 접기 펼치기 안되는 오류 수정  20200705 */
        /*dogfoot 보고서 레이아웃 불러오기 리사이즈 수정 shlim 20200821*/
        if($(this).parents('.filter-bar').hasClass('on') && (WISE.Constants.editmode === 'viewer' ||WISE.Constants.editmode === 'designer')) {
        	if(WISE.Constants.editmode === 'viewer'){
        		if(typeof gDashboard.layoutConfig[WISE.Constants.pid]!='undefined' && gDashboard.layoutConfig[WISE.Constants.pid] !=""
					&& gDashboard.layoutConfig[WISE.Constants.pid] !="\"\"" && Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0){

        			$("#filter-bar").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig[WISE.Constants.pid].FILTER_HEIGHT_SETTING+"px"
					});
					$(".condition-item-container").css({
						"max-height" : "1000px",
//						"height" : gDashboard.layoutConfig[WISE.Constants.pid].FILTER_HEIGHT_SETTING+"px",
						"padding-bottom" : "0px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

					$("#"+WISE.Constants.pid+"_paramContainer").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig[WISE.Constants.pid].FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

        		}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){

        			$("#filter-bar").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px"
					});
					$(".condition-item-container").css({
						"max-height" : "1000px",
//						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"padding-bottom" : "0px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

					$("#"+WISE.Constants.pid+"_paramContainer").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

        		}

        	}else{

        		if(typeof gDashboard.layoutConfig!='undefined' && gDashboard.layoutConfig !=""
        			&& gDashboard.layoutConfig !="\"\"" && Object.keys(gDashboard.layoutConfig).length != 0){
        			$("#filter-bar").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig.FILTER_HEIGHT_SETTING+"px"
					});
					$(".condition-item-container").css({
						"max-height" : "1000px",
//						"height" : gDashboard.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"padding-bottom" : "0px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

					$(".filter-item").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});
				}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){
					$("#filter-bar").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px"
					});
					$(".condition-item-container").css({
						"max-height" : "1000px",
//						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"padding-bottom" : "0px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

					$(".filter-item").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});
				}
        	}
        } else if((WISE.Constants.editmode === 'viewer' ||WISE.Constants.editmode === 'designer')){
        	if(WISE.Constants.editmode === 'viewer'){
        		if(typeof gDashboard.layoutConfig[WISE.Constants.pid]!='undefined' && gDashboard.layoutConfig[WISE.Constants.pid] !=""
					&& gDashboard.layoutConfig[WISE.Constants.pid] !="\"\"" && Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0){

        			$("#filter-bar").css({
						"max-height" : "1000px",
						"height" : "auto"
					});
					$(".condition-item-container").css({
						"max-height" : "1000px",
//						"height" : gDashboard.layoutConfig[WISE.Constants.pid].FILTER_HEIGHT_SETTING+"px",
						"padding-bottom" : "0px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});
					$("#"+WISE.Constants.pid+"_paramContainer").css({
						"max-height" : "1000px",
						"height" : "auto",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

        		}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){

        			$("#filter-bar").css({
						"max-height" : "1000px",
						"height" : "auto"
					});
					$(".condition-item-container").css({
						"max-height" : "1000px",
//						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"padding-bottom" : "0px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});
					$("#"+WISE.Constants.pid+"_paramContainer").css({
						"max-height" : "1000px",
						"height" : "auto",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

        		}
        	}else{
        		if(typeof gDashboard.layoutConfig!='undefined' && gDashboard.layoutConfig !=""
        			&& gDashboard.layoutConfig !="\"\"" && Object.keys(gDashboard.layoutConfig).length != 0){
        			$("#filter-bar").css({
    					"max-height" : "1000px",
    					"height" : "auto"
    				});
    				$(".condition-item-container").css({
    					"max-height" : "1000px",
//    					"height" : gDashboard.layoutConfig.FILTER_HEIGHT_SETTING+"px",
    					"padding-bottom" : "0px",
    					"display" : "flex",
    					"flex-wrap" : "wrap",
    					"align-items" : "center"
    				});
    				$(".filter-item").css({
    					"max-height" : "1000px",
    					"height" : "auto",
    					"display" : "flex",
    					"flex-wrap" : "wrap",
    					"align-items" : "center"
    				});
				}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){
					$("#filter-bar").css({
    					"max-height" : "1000px",
    					"height" : "auto"
    				});
    				$(".condition-item-container").css({
    					"max-height" : "1000px",
//    					"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
    					"padding-bottom" : "0px",
    					"display" : "flex",
    					"flex-wrap" : "wrap",
    					"align-items" : "center"
    				});
    				$(".filter-item").css({
    					"max-height" : "1000px",
    					"height" : "auto",
    					"display" : "flex",
    					"flex-wrap" : "wrap",
    					"align-items" : "center"
    				});
				}

        	}


        }
        $(this).parents('.filter-bar').toggleClass('on');
		/* 2020.01.21 수정자 : mksong 뷰어 리사이즈 오류 수정 dogfoot */
        if(gDashboard.hasTab){
        	$('#reportContainer').height($('.content').height()-$('.filter-bar').height()-$('.tab_cont_box_top_tit').height());
        }else{
        	$('#reportContainer').height($('.content').height()-$('.filter-bar').height());
        }
        

        /*  2020.01.22 MKSONG 뷰어 UI 오류 수정 DOGFOOT */

        if(!_.isEmpty(gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id])){
        	$('#contentContainer'+gDashboard.structure.ReportMasterInfo.id).css('height', 'calc(100vh - ' + (84 + ($('.filter-bar').height() < 40? 40 : $('.filter-bar').height())) + 'px)')
            gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id].canvasLayout.updateSize($('#reportContainer').width(),$('#reportContainer').height());
        	 gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id].resize();
        }else if(gDashboard.goldenLayoutManager.canvasLayout){
            $('.panel.cont').css('height', 'calc(100vh - ' + (84 + ($('.filter-bar').height() < 40? 40 : $('.filter-bar').height())) + 'px)')
            gDashboard.goldenLayoutManager.canvasLayout.updateSize($('.panel.cont').width());
            gDashboard.goldenLayoutManager.resize();
        }
        $(".download-designer .panel.cont").css('height', 'calc(85vh - ' + (84 + ($('.filter-bar').height() < 40? 40 : $('.filter-bar').height())) + 'px)')


    });

    $('.download-designer .filter-more').off('click').on('click',function(e){
        e.preventDefault();


        if($(this).parents('.download-designer .filter-bar').hasClass('on')) {
        	if(WISE.Constants.editmode === 'viewer'){
        		if(typeof gDashboard.layoutConfig[WISE.Constants.pid]!='undefined' && gDashboard.layoutConfig[WISE.Constants.pid] !=""
					&& gDashboard.layoutConfig[WISE.Constants.pid] !="\"\"" && Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0){

        			$(".download-designer #filter-bar").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig[WISE.Constants.pid].FILTER_HEIGHT_SETTING+"px"
					});
					$(".download-designer .condition-item-container").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig[WISE.Constants.pid].FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

					$(".download-designer #"+WISE.Constants.pid+"_paramContainer").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig[WISE.Constants.pid].FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

        		}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){

        			$(".download-designer #filter-bar").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px"
					});
					$(".download-designer .condition-item-container").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

					$(".download-designer #"+WISE.Constants.pid+"_paramContainer").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

        		}

        	}else{

        		if(typeof gDashboard.layoutConfig!='undefined' && gDashboard.layoutConfig !=""
        			&& gDashboard.layoutConfig !="\"\"" && Object.keys(gDashboard.layoutConfig).length != 0){
        			$(".download-designer #filter-bar").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig.FILTER_HEIGHT_SETTING+"px"
					});
					$(".download-designer .condition-item-container").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

					$(".download-designer .filter-item").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});
				}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){
					$(".download-designer #filter-bar").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px"
					});
					$(".download-designer .condition-item-container").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

					$(".download-designer .filter-item").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});
				}
        	}
        } else if((WISE.Constants.editmode === 'viewer' ||WISE.Constants.editmode === 'designer')){
        	if(WISE.Constants.editmode === 'viewer'){
        		if(typeof gDashboard.layoutConfig[WISE.Constants.pid]!='undefined' && gDashboard.layoutConfig[WISE.Constants.pid] !=""
					&& gDashboard.layoutConfig[WISE.Constants.pid] !="\"\"" && Object.keys(gDashboard.layoutConfig[WISE.Constants.pid]).length != 0){

        			$(".download-designer #filter-bar").css({
						"max-height" : "1000px",
						"height" : "auto"
					});
					$(".download-designer .condition-item-container").css({
						"max-height" : "1000px",
						"height" : gDashboard.layoutConfig[WISE.Constants.pid].FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});
					$(".download-designer #"+WISE.Constants.pid+"_paramContainer").css({
						"max-height" : "1000px",
						"height" : "auto",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

        		}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){

        			$(".download-designer #filter-bar").css({
						"max-height" : "1000px",
						"height" : "auto"
					});
					$(".download-designer .condition-item-container").css({
						"max-height" : "1000px",
						"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});
					$(".download-designer #"+WISE.Constants.pid+"_paramContainer").css({
						"max-height" : "1000px",
						"height" : "auto",
						"display" : "flex",
						"flex-wrap" : "wrap",
						"align-items" : "center"
					});

        		}
        	}else{
        		if(typeof gDashboard.layoutConfig!='undefined' && gDashboard.layoutConfig !=""
        			&& gDashboard.layoutConfig !="\"\"" && Object.keys(gDashboard.layoutConfig).length != 0){
        			$(".download-designer #filter-bar").css({
    					"max-height" : "1000px",
    					"height" : "auto"
    				});
    				$(".download-designer .condition-item-container").css({
    					"max-height" : "1000px",
    					"height" : gDashboard.layoutConfig.FILTER_HEIGHT_SETTING+"px",
    					"display" : "flex",
    					"flex-wrap" : "wrap",
    					"align-items" : "center"
    				});
    				$(".download-designer .filter-item").css({
    					"max-height" : "1000px",
    					"height" : "auto",
    					"display" : "flex",
    					"flex-wrap" : "wrap",
    					"align-items" : "center"
    				});
				}else if (typeof userJsonObject.layoutConfig!='undefined' && userJsonObject.layoutConfig!=""){
					$(".download-designer #filter-bar").css({
    					"max-height" : "1000px",
    					"height" : "auto"
    				});
    				$(".download-designer .condition-item-container").css({
    					"max-height" : "1000px",
    					"height" : userJsonObject.layoutConfig.FILTER_HEIGHT_SETTING+"px",
    					"display" : "flex",
    					"flex-wrap" : "wrap",
    					"align-items" : "center"
    				});
    				$(".download-designer .filter-item").css({
    					"max-height" : "1000px",
    					"height" : "auto",
    					"display" : "flex",
    					"flex-wrap" : "wrap",
    					"align-items" : "center"
    				});
				}

        	}


        }
        $(this).parents('.download-designer .filter-bar').toggleClass('on');

        $('.download-designer #reportContainer').height($('.content').height()-$('.filter-bar').height());



        if(!_.isEmpty(gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id])){
        	$('.download-designer #contentContainer'+gDashboard.structure.ReportMasterInfo.id).css('height', 'calc(100vh - ' + (84 + ($('.download-designer .filter-bar').height() < 40? 40 : $('.download-designer .filter-bar').height())) + 'px)')
        }else if(gDashboard.goldenLayoutManager.canvasLayout){
            $('.download-designer .panel.cont').css('height', 'calc(100vh - ' + (84 + ($('.download-designer .filter-bar').height() < 40? 40 : $('.download-designer .filter-bar').height())) + 'px)')
        }


    });

    if(gDashboard.parameterFilterBar)
    	gDashboard.parameterFilterBar.resize();
}

function panelLayout(){
    var headerH = $('header').outerHeight();
    var lnbH = $('#lnb').outerHeight();
    var contminusH = headerH + lnbH;

    var panelTreeW = $('.panel.tree').outerWidth();
    var panelDataW = $('.panel.data').outerWidth();
    //20201209 AJKIM R 분석 기능 추가 dogfoot
    var panelDataR = ($('.panel.r').length > 0? $('.panel.r').outerWidth() : 0)
        panelContW = panelTreeW + panelDataW + panelDataR;

    $('.panel.cont').css({width:"calc(100% - " + panelContW + "px)"});
    // 20200730 ajkim 디자이너 모드에서 필터 펼칠 때 아이템 밀리는 오류 수정 dogfoot
    // jhseo 고용정보원09 기존 개인설정과 달리 개인 보고서 및 폴더 관리말곤 다 빼버려서 디자인 오류가 나기에 height 조정해야함
	if(WISE.Constants.editmode == 'account'){
		$('.panel').css({height:"calc(80vh - " + contminusH + "px)"});
		$('.panel-inner ').css({height:"calc(80vh - " + (contminusH + 45) + "px)"});
	}else{
		$('.panel').css({height:"calc(100vh - " + contminusH + "px)"});
	}
	
	$('.download-designer .panel').css({height:"calc(85vh - " + contminusH + "px)"});
	$('.panel.grid').css('height', 'calc(85vh - ' + (contminusH - 39 + $('.filter-bar').height()) + 'px)')
	$('.panel.grid').css({width:"calc(100% - " + panelContW + "px)"});

	if(WISE.Constants && WISE.Constants.editmode === 'designer')
    	$('.panel.cont').css('height', 'calc(100vh - ' + (contminusH - 39 + $('.filter-bar').height()) + 'px)')

}

function panelUi(){
    var reportTabLi= $('.report-tab ul').find('li');
    var reportTabLiL = reportTabLi.length;

    // report
    // $('.report').on("click", function(e){
    //     e.preventDefault();
    //     window.open(window.document.location.href);

//        var reportTab = $(this).next('.report-tab');
//        var reportTabUl = $(this).next('.report-tab ul');
//            reportTabLiL = reportTabLiL +1;
//
//        var createTab='';
//            createTab+='<li><span><em>reportName</em> <a href="#" class="gui close">close</a></span></li>';
//
//        reportTab.find('ul').append(createTab);
//        reportTab.find('li').last().addClass('on').siblings().removeClass('on');
//        reportTab.find('li').width(100 / reportTabLiL + '%');
//
//        $('.report-tab ul').find('li').each(function(){
//            var createTabCustomData = $(this).find('em').text();
//            // $(this).attr('data-name', createTabCustomData);
//        });
//
//        // mobile slectbox text
//        reportTab.find('li').not('li.now-slt').on('click',function(e){
//            e.preventDefault();
//            var reportClickSlt = $(this).find('em').text();
//            console.log(reportClickSlt);
//            $(this).parent('ul').removeClass('m-open').find('li.now-slt a').text(reportClickSlt);
//        });
//
//        // mobile arrow show
//        if(reportTab.find('li').length > 0){
//            reportTab.find('.now-slt').addClass('use');
//        }
//
//        $(document).on('click', '.report-tab li', function(e){
//            $(this).addClass('on').siblings().removeClass('on');
//        });
    // });

    $(document).off('click','.report-tab .close').on('click', '.report-tab .close', function(e){
        // $('.report-tab .close').off('click').on('click', '.report-tab .close', function(e){
//    	reportTabLiL = reportTabLiL -1;

        e.preventDefault();
        var reportId = $(this).parents('li').attr('report_id');
        var focusId =  $('.report-tab').find('li:last').attr('report_id');
        if(focusId === reportId) var focusId =  $('.report-tab').find('li:nth-last-of-type(2)').attr('report_id');
        /*dogfoot shlim 20210414*/
//        $('#dataArea_'+ gDashboard.structure.ReportMasterInfo.id).remove();
		/*dogfoot shlim 20210415*/
        $('#dataArea_'+ reportId).remove();
    	$('.data-view').css('display','none');
    	gDashboard.itemGenerateManager.dxItemBasten = [];
    	WISE.Constants.pid = focusId;
        $('.report-tab li').each(function(_i,_e){
			if($(_e).attr('report_id') == focusId){
				$(_e).click();
			}
    	});

        $(this).parents('li').remove();
        $('.report-tab').find('li:last').addClass('on');
        $('#reportContainer').removeClass('on');
//        $('.report-tab ul').find('li').width(100 / reportTabLiL + '%');
        $('.report-tab ul').find('li').width(100 /  ($('.report-tab ul').find('li').length) + '%');
        // mobile arrow show
        if($('.report-tab').find('li').length === 1){
            $('.report-tab').find('.now-slt').removeClass('use');
        }
        if(gDashboard != undefined){
        	$.each($('#reportContainer').children('.contentContainer'),function(_i,_container){
        		if($(_container).attr('report_id') == reportId){
        			$(_container).remove();
        			return false;
        		}
        	});
        	$('.filter-item').each(function(_i,_e){
        		if($(_e).attr('report_id') == reportId){
        			$(_e).remove();
        			return false;
        		}
        	});
        	$.each(gDashboard.structureBuffer,function(_i,_structure){
        		if(_structure.reportId == reportId){
        			gDashboard.structureBuffer.splice(_i,1);
        			return false;
        		}
        	});
        	$.each(gDashboard.totalConditionBuffer,function(_i,_totalCondition){
        		if(_totalCondition.reportId == reportId){
        			gDashboard.totalConditionBuffer.splice(_i,1);
        			return false;
        		}
        	});
        	$.each(gDashboard.itemGenerateBuffer,function(_i,_itemGenerate){
        		if(_itemGenerate.reportId == reportId){
        			gDashboard.itemGenerateBuffer.splice(_i,1);
        			return false;
        		}
        	});

        	gDashboard.contentReadyParamList = [];
        	/* 2020.01.21 수정자 : mksong 뷰어 보고서 삭제 후 열기 오류 수정 dogfoot */
        	/*dogfoot shlim 20210414*/
        	gDashboard.tabN--;
        	$.each($('#reportContainer').children('.contentContainer'),function(_i,_container){
	    		if($(_container).attr('report_id') == focusId){
	    			$(_container).css('display','block');
	    			return false;
	    		}
	    	});
//        	$('.filter-item').each(function(_i,_e){
//				if($(_e).attr('report_id') == focusId){
//					$(_e).trigger('click');
//					$(_e).css('display','block');
//					$.each(gDashboard.structureBuffer,function(_i,_e){
//						gDashboard.structure = _e.structure;
//						gDashboard.reportType = _e.reportType;
//						WISE.Constants.pid = focusId;
//						gDashboard.parameterHandler.init();
//						gDashboard.dataSourceManager.init();
//						gDashboard.itemGenerateManager.dxItemBasten= [];
//						gDashboard.itemGenerateManager.init();
//						$.each(gDashboard.itemGenerateBuffer,function(_j,_generate){
//							if(_generate.reportId == focusId){
//								gDashboard.itemGenerateManager.dxItemBasten = _generate.dxItemBasten;
//								return false;
//							}
//						})
//						gDashboard.parameterHandler.toggleParameter(focusId);
//						return false;
//					});
//				}
//			});
//        	$.each($('#reportContainer').children('.contentContainer'),function(_i,_container){
//        		if($(_container).attr('report_id') == focusId){
//        			$(_container).css('display','block');
//        			return false;
//        		}
//        	});
//        	$.each(gDashboard.structureBuffer,function(_i,_e){
//				if(_e.reportId == focusId){
//
//				}
//			});

        }
    });

    // $('.util-cont.left .next').on('click', function(e){
    //     var reportTabW = $('.report-tab li').width();
    //     $('.report-tab ul').css({marginLeft:-reportTabW});
    // });

    // viewerMode tree btn
//    $('.tree-view').off('click').on('click', function(e){
//        $('.tree-area').toggleClass('on');
//        $('#reportContainer').toggleClass('on');
//        // if($(window).width() <= 720){
//        // 	if($('.tree-area').hasClass('on')){
//        //     	$('.filter-bar').css('width','calc(100% - 300px)');
//        //     }else{
//        //     	$('.filter-bar').css('width','calc(100%)');
//        //     }
//        // }
//        if(gDashboard.parameterHandler != undefined){
//        	gDashboard.parameterHandler.resize();
//        }
//    });

 // viewerMode tree btn 1203 함수로 대체
    if($('.viewer').length){
        viewrUiOptionBtn();
    }
}

function viewrUiOptionBtn(){
    // 1205 viewrUiOptionBtn 함수변경
    var viewrBtns = $('.viewr-ui-option').find('a');
    var treeViewBtn = $('.tree-view');
    var dataViewBtn = $('.data-view');
	/* 2019.12.16 수정자 : mksong 디자인 수정 적용 dogfoot */
    var movePanelSet = $('#reportContainer, .filter-bar');

	/* 2019.12.16 수정자 : mksong 디자인 수정 적용 dogfoot */
//    dataViewBtn.on('click', function(){
//        $('.dataAttrArea').toggleClass('on').siblings().removeClass('on');
//    });
//
//    treeViewBtn.on('click', function(){
//        $('.reportListArea').toggleClass('on').siblings().removeClass('on');
//    });

    viewrBtns.off('click').on('click', function(e){
        e.preventDefault();
        gDashboard.clickedfolderList = true;

        var self = $(this);
        setTimeout(function () {
        	if(self.hasClass('data-view')){
        		$('.dataAttrArea').toggleClass('on').siblings().removeClass('on');
        		setTimeout(function () {
        			if($('.data-view').hasClass('on')){
        				$('.dx-page-sizes').css('display', 'none');
        			}else{
        				$('.dx-page-sizes').css('display', 'block');
        			}
        		}, 100);
        	}else if(self.hasClass('tree-view')){
                /* DOGFOOT ktkang 보고서 목록 열 때 로딩바 나오도록 수정  20200110 */
        		$('.reportListArea').toggleClass('on').siblings().removeClass('on');
        		// 2021-09-02 jhseo 고용정보원09 보고서 펼칠때 개인보고서 펼치고 나면 on이 안꺼질때가 있음 이때 삭제
        		$("#treeopen > div.reportListArea.on > div > div.tab-title.rowColumn > ul > li:nth-child(2)").removeClass('on');

                /* goyong ktkang 로딩바 오류 수정  20210513 */
//        		if($('.reportListArea').hasClass('on')){
//        			gProgressbar.show();
//        		}
        	}

        	self.toggleClass('on').siblings().removeClass('on');
        	var areaWid = $('.tree-area').outerWidth();

        	if($('.tree-view').hasClass('on')){
        		movePanelSet.css({
        			paddingLeft:areaWid+5
        		});
        		/* 2020.01.21 수정자 : mksong 뷰어 리사이즈 오류 수정 dogfoot */
        		$('.lm_goldenlayout').width($('.lm_goldenlayout').width());
        	} else if($('.data-view').hasClass('on')){
        		var movingPx = gDashboard.isSingleView ? 0 : 5
        		
    			movePanelSet.css({
        			paddingLeft:areaWid+ movingPx
        		});
        		
        		/*dogfoot shlim 20210702*/
        		$('.contentContainer').css('height', 'calc(101% + 20px)');
        	} else {
        		/* 2019.12.24 수정자 : mksong 뷰어 필터바 패딩 크기 최적화 dogfoot */
        		var paddingLeft;
        		if($('.data-view').css('display') == 'none'){
        			paddingLeft = 40;
        		}else{
        			paddingLeft = 79;
        		}

        		/* 2019.12.16 수정자 : mksong 디자인 수정 적용 dogfoot */
        		$('#reportContainer').css({
        			paddingLeft:0
        		});

        		/* DOGFOOT ktkang 뷰어 필터 바 데이터 뷰 없을 때 수정  20200110 */
        		if($('.data-view').css('display') == 'none'){
        			$('.filter-bar').css({
        				paddingLeft:40
        			});
        			$('.dx-page-sizes').css('display', 'block');
        		}else{
        			$('.filter-bar').css({
        				/*dogfoot shlim 20210415*/
        				paddingLeft: gDashboard.isSingleView ? 39:79
        			});
        			$('.dx-page-sizes').css('display', 'none');
        			/*dogfoot shlim 20210702*/
        			$('.contentContainer').css('height', '102%');
        		}

        		/* 2019.12.24 수정자 : mksong 뷰어 필터바 패딩 크기 최적화 수정 끝 dogfoot */
        	}
        	/* 2020.01.22 수정자 : mksong 뷰어 리사이즈 오류 수정 dogfoot */
        	/* DOGFOOT ktkang KERIS portal뷰어에서 빈공간 삭제   20200228 */
        	if(gDashboard.portalView) {
				$('#reportContainer').height($('.content').height() - 10);
			} else {
				$('#reportContainer').height($('.content').height()-$('.filter-bar').height());
			}
        	/* DOGFOOT mksong 뷰어 보고서 목록 열기 오류 수정  20200210 */
        	if(gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id] != undefined){
        		gDashboard.goldenLayoutManager[gDashboard.structure.ReportMasterInfo.id].canvasLayout.updateSize($('#reportContainer').width(),$('#reportContainer').height());
        	}

        	panelDataUi();
        	displayBtnMoreUi();
        	/* 2019.12.16 수정자 : mksong 디자인 수정 적용 dogfoot */
        	itemsResize();

			/* DOGFOOT ktkang 보고서 목록 열 때 리스트 필터 깨지는 오류 수정  20200110 */
        	gDashboard.parameterFilterBar.resize();

        	/* DOGFOOT ktkang 보고서를 열면 보고서 목록이 닫히는데 보고서 목록을 다시 열면 현재 선택 되어 있는 보고서에 포커스가 가도록 수정  20200110 */
        	$('#reportList').dxTreeView('instance').focus();

        	gProgressbar.hide();
        }, 100);
    });
    	/* 2019.12.16 수정자 : mksong 디자인 수정 적용 수정 끝 dogfoot */
}


function treeMenuUi(){
    var dropAnc = $('.drop-down li > a');
    dropAnc.each(function(){
        // 드롭다운 할 내용이 있는 item
        var dataUse = $(this).next('.dep');

        // 0708 focus 추가
        $(this).off('click').on('click',function(){
            $(this).addClass('on').parents('li').siblings().find('a').removeClass('on');
            $(this).parents('li').find('>a').addClass('on');
        });


        if(dataUse.length){
            $(this).addClass('arrow');
            $(this).on("click", function(e){
                e.preventDefault();
                $(this).parent().find('>.dep').slideToggle().parent('li');
                $(this).parent().find('>.dep').parent('li').toggleClass('active');
            });
        }
    });
}

function treeTableUi(){
    var treeAnc = $('.tree-table li > a');
    treeAnc.each(function(){
        // 드롭다운 할 내용이 있는 item
        var treeUse = $(this).next('.dep');

        // 0708 focus 추가
        $(this).off('click').on('click',function(){
            $(this).addClass('on').parents('li').siblings().find('a').removeClass('on');
            $(this).parents('li').find('>a').addClass('on');
        });


        if(treeUse.length){
            $(this).addClass('arrow');
            $(this).on("click", function(){
                $(this).parent().find('>.dep').toggleClass('open');
                $(this).parent().find('>.dep').parent('li').toggleClass('active');
            });
        }
    });
}

function panelDataUi(){
    $('.display-move-wrap').each(function(){
        var boxH = $(this).find('ul').height();
        $(this).find('.otherBtn').height(boxH);
    });
}

function resizeUi(){
    var utilMinuW = $('.util-cont.right').outerWidth() + 58; // 0729 수정
    if($(window).width() <= 720){
        utilMinuW += 20;
    }
    $('.util-cont.left').css({width:"calc(100% - " + utilMinuW + "px)"});
}

function utilUi(){
    var textSize = 15;
    var gnbW = $('#gnb').width();
    var headerH = $('header').height();

    $('.ico-language').on("click", function(e){
        e.preventDefault();
        $('.language-inner').toggleClass('active');
        if($('.language-inner').hasClass('active')){
            $(this).addClass('on');
        } else {
            $(this).removeClass('on');
        }
    });

    if(!gDashboard.fontManager.fontCoverage)
    	gDashboard.fontManager.init();
    if(gDashboard.fontManager.fontCoverage.Menu){
    	textSize = 15 + gDashboard.fontManager.fontSize;
    	$('html').css('font-size', textSize);
        $('html').css('font-family', gDashboard.fontManager.fontFamily);
    }

    $('.text-zoom-plus').off('click').on('click', function(){
        textSize ++;
        $('html').css('font-size', textSize);
    });
    $('.text-zoom-minus').off('click').on('click', function(){
        textSize --;
        $('html').css('font-size', textSize);
    });


    // var textSize = 1/10;
    // var gnbW = $('#gnb').width();
    // var headerH = $('header').height();
    //
    // $('.ico-language').on("click", function(e){
    //     e.preventDefault();
    //     $('.language-inner').toggleClass('active');
    //     if($('.language-inner').hasClass('active')){
    //         $(this).addClass('on');
    //     } else {
    //         $(this).removeClass('on');
    //     }
    // });
    //
    //
    //
    // $('.text-zoom-plus').off('click').on('click', function(){
    //     textSize ++;
    //     $('html').css('transform', 'scale(' + textSize +')');
    // });
    // $('.text-zoom-minus').off('click').on('click', function(){
    //     textSize --;
    //     $('html').css('transform', 'scale(' + textSize +')');
    // });



//    $('.user-name >a').off('click').on('click', function(e){
//        e.preventDefault();
//        $('.user-util').toggleClass('on');
//    })

    $('.language-select .lang-item').off('click').on('click',function(e){
        var langThisText = $(this).text();
        $(this).parent('.language-select').removeClass('on');
        $('.language-select-status a').html(langThisText);
    });
    $('.language-select-status').off('click').on('click', function(e){
        e.preventDefault();
        $(this).parents('.language-select').toggleClass('on');
    });

}

function customSelect(){
    $('.like-select').each(function(){
        $(this).find('.like-item').off('click').on('click',function(e){
            var langThisText = $(this).find('a').html();
            $(this).parent('.like-select').removeClass('on');
            $(this).siblings('.like-status').find('a').html(langThisText);
        });

        $(this).find('.like-status').off('click').on('click',function(e){
            e.preventDefault();
            $(this).parents('.like-select').toggleClass('on');
        });
    });
}

function boxColumn(){
    $('.box-ui').each(function(){
        var boxColumnL = $(this).find('>.box-ui-item').length;
        if($(this).find('>.box-ui-item').length){
            $(this).find('>.box-ui-item').css({width: 100 / boxColumnL + '%'});
        }
    });

    $('.layout-row').each(function(){
        var layoutColumnL = $(this).find('>.layout-col').length;
        if($(this).find('>.layout-col').length){
            $(this).find('>.layout-col').css({width: 100 / layoutColumnL + '%'});
        }
    });
}

function tabColumnClass(){
    // column layout
    var layoutCountNum = $('.row, .tab-title.rowColumn ul, .design-menu.rowColumn .desing-menu-list'),
        layoutClassNum = layoutCountNum.length;
    for (var i = 0; i < layoutClassNum; i++) {
    	if(layoutCountNum.eq(i).attr("class") && layoutCountNum.eq(i).attr("class").indexOf('col-') > -1){
    		continue;
    	}
        var layoutClassCount = 'col-' + layoutCountNum.eq(i).find('>.column, >li').length;
        layoutCountNum.eq(i).addClass(layoutClassCount);
    }
}

function designMenuUi(){
    $('.item-more').off('click').on('click', function(e){
        e.preventDefault();
        $(this).toggleClass('on');
    })
}

/* 0919 수정: "off" 이벤트 추가 */
function tabUi(){
	var tabTit = $('.tab-title,.report-tab-viewr');
    var tabNum = tabTit.length;
    var tabBtn = tabTit.find('li');

    var tabCnt = $('.tab-content');
    var tabIdx = tabCnt.index();

    // load style settings
    tabCnt.hide();

    // ymbin
    // image item 선택 시 필드 숨기고 속성 보여줌

    $('.tab-title ul li:first-child').addClass('on');
    $('.tab-component .tab-content:first-child').show();

    tabBtn.off('click').on('click', function(e){
        e.preventDefault();
        var $this = $(this);
        var thisRel = $this.attr('rel');
        var thisClass = $('.'+ thisRel);
        var target = thisClass.parent('.tab-component').attr('id');

            if(thisRel === 'panelDataA-2'){
                $('.panel.cont').addClass('padding');
            } else {
                $('.panel.cont').removeClass('padding');
            }

        // content connect
        $('#' + target +  '>.tab-content').hide().removeClass('on');
		$('#' + target + ' .' + thisRel).show().addClass('on');
		$(this).addClass('on').siblings().removeClass('on');
    });

    // ymbin: image에서 hide한 필드 부분 다시 보이게 하기
    $('#menulist:first-child').find('li').show();
}

// ymbin : field가 필요 없는 item 클릭 시 focus를 속성으로
function tabPropertyUi(){
	var tabTit = $('.tab-title,.report-tab-viewr');
    var tabNum = tabTit.length;
    var tabBtn = tabTit.find('li');

    var tabCnt = $('.tab-content');
    var tabIdx = tabCnt.index();

    // load style settings
    tabCnt.hide();
    // first -> last
    $('.tab-title ul li:last-child').addClass('on'); // 속성
    $('.tab-component .tab-content:last-child').show();

    tabBtn.off('click').on('click', function(e){
        e.preventDefault();
        var $this = $(this);
        var thisRel = $this.attr('rel');
        var thisClass = $('.'+ thisRel);
        var target = thisClass.parent('.tab-component').attr('id');

            if(thisRel === 'panelDataA-2'){
                $('.panel.cont').addClass('padding');
            } else {
                $('.panel.cont').removeClass('padding');
            }

        // content connect
        $('#' + target +  '>.tab-content').hide().removeClass('on');
		$('#' + target + ' .' + thisRel).show().addClass('on');
		$(this).addClass('on').siblings().removeClass('on');
    });
}

function modalUi(){
    modalSizing();
    function modalSizing(){
        $('.modal').each(function(){
            var layerResize = $(window).height();
            var layerHeight = $(this).outerHeight();
            var layerWidth = $(this).outerWidth();
            $(this).css({
                //marginLeft : -layerWidth/2,
                //marginTop : -layerHeight/2
            });

            $(this).find('.modal-body').css({
                // maxHeight : layerResize/2
            });
        });
    }

     $('.modalLoad').off('click').on('click',function(e){
         e.preventDefault();
         var $self = $(this);
         var $target = $($(this).attr('href'));
         var $targetId = $target.attr('id');


         if($(this).attr('href') == '#formatOptions'){
         	gDashboard.dragNdropController.setFormatOptionModal($self.parent().parent().parent().parent());

			$target.fadeIn(400);
			// close and focusout
			var isVisible = $target.is(':visible');
			var modalLength = $('.modal:visible').length;

			$target.find(".close").off('click').on('click',function(e){
				e.preventDefault();
				$target.fadeOut(250);
				$self.focus();
				$(this).off('click');
				if (isVisible) {
					if (modalLength > 1) {
						$target.fadeOut(250);
					} else {

					}
				}
			});

			$target.find(".ok-hide").off('click').on('click',function(_e){
				_e.preventDefault();
				$target.fadeOut(250);
				$self.focus();

				if($(_e.target).attr('id') == 'formatOptionsOk'){
					gDashboard.dragNdropController.setFormatOption($self.parent().parent().parent().parent());
				}

				if (isVisible) {
					if (modalLength > 1) {
						$target.fadeOut(250);
					} else {

					}
				}
			});

         }
     });
}

function mediaTab(){
    $('.tab-title').find('ul').each(function(){
        var nowSlt = $(this).find('li:first em').text();
        if($(this).find('li').length > 2){
            $(this).addClass('tab-m');
            $(this).prepend('<li class="now-slt"><a href="#">'+ nowSlt +'</a></li>');
            $(this).find('li.now-slt').off('click').on('click', function(e){
                e.preventDefault();
                $(this).parent('ul').toggleClass('m-open');
            });
            $(this).find('li').not('li.now-slt').off('click').on('click',function(e){
                e.preventDefault();
                var clickSlt = $(this).find('em').text();
                $(this).parent('ul').removeClass('m-open').find('li.now-slt a').text(clickSlt);
            });
        }
    });

    $('.report-tab,.report-tab-viewr').find('ul').each(function(){
        // 0802 선택자 및 소스 추가
        $(this).addClass('tab-m');
        // $(this).prepend('<li class="now-slt"><a href="#">Please Report Add</a></li>');
        $(this).find('li.now-slt').off('click').on('click', function(e){
            e.preventDefault();
            $(this).parent('ul').toggleClass('m-open');
        });
        $(this).find('li.now-slt').siblings().off('click').on('click', function(){
            $(this).parents('.tab-m').removeClass('m-open');
        });
    });
//    $('.report-tab').find('ul').each(function(){
//        $(this).addClass('tab-m');
//        $(this).prepend('<li class="now-slt"><a href="#">Please Report Add</a></li>');
//        $(this).find('li.now-slt').off('click').on('click', function(e){
//            e.preventDefault();
//            $(this).parent('ul').toggleClass('m-open');
//        });
//    });

}

function btnswitch() {
    $('.switch').each(function(){
        $(this).off('click').on('click', function(){
            if ($(this).hasClass('on')) {
                $(this).removeClass('on');
                $(this).find('input').attr('checked', false);
                return false;
            }else {
                $(this).addClass('on');
                $(this).find('input').attr('checked', true);
                return false;
            }
        });
    });

    $('.cell-ctl').each(function(){
        $(this).find('.switch').off('click').on('click', function(){
            if($(this).hasClass('on')){
                $(this).prev('.ctl-ipt').find('input').attr('disabled', false);
            } else{
                $(this).prev('.ctl-ipt').find('input').attr('disabled', true);
            };
        });
    });
}

function reportSearch(){
	$('.reportSearch').off('keydown').on('keydown',function(key){
		key.preventDefault();
		if(key.keyCode == 13){
			alert('검색기능은 준비중입니다.');
		}
	});

	$('#report_search_btn').off('click').on('click',function(e){
		e.preventDefault();
		alert('검색기능은 준비중입니다.');
	});

}

/* 2019.12.16 수정자 : mksong 아이템 리사이즈 함수 dogfoot */
function itemsResize(){
	/* 2020.01.21 수정자 : mksong 뷰어 리사이즈 오류 수정 dogfoot */
	if(gDashboard.itemGenerateManager != undefined){
		if(gDashboard.itemGenerateManager.dxItemBasten.length != 0){
	    	$('.cont_box_cont').css('width', '100%');
	        $('.cont_box_cont').css('height', '93%');

	        if (gDashboard.itemGenerateManager.dxItemBasten[0].dxItem != undefined) {
	            var itemList = gDashboard.itemGenerateManager.dxItemBasten;
	            for (var i = 0; i < itemList.length; i++) {
	                if (itemList[i].dxItem != undefined) {
	                    switch (itemList[i].type) {
	                        case 'PIVOT_GRID':
//	                            	itemList[i].dxItem._options.width = $('#' + itemList[i].itemid).parent().width();
								/* 2020.01.16 수정자 : mksong 피벗 리사이즈 수정 dogfoot */
	                        	itemList[i].dxItem.option('width',$('#' + itemList[i].itemid).parent().innerWidth());
	                    		itemList[i].dxItem.option('height',$('#' + itemList[i].itemid).parent().innerHeight());
	                            break;
	                        case 'DATA_GRID':
	                            itemList[i].dxItem.repaint();
	                            break;
	                        case 'SIMPLE_CHART':
	                            itemList[i].dxItem.render();
	                            break;
	                        case 'PIE_CHART':
	                            if (itemList[i].dxItem.length == 1) {
	                                var size = { 'height': $('#' + itemList[i].itemid).height(), 'width': $('#' + itemList[i].itemid).width() };
	                                itemList[i].dxItem[0].option('size', size);
	                                itemList[i].dxItem[0].render();
	                            } else {
	                                itemList[i].resize();
	                            }
	                            break;
	                        case 'TREEMAP':
	                        	itemList[i].dxItem.option('size',{'height': $('#'+itemList[i].itemid).height(),'width': $('#'+itemList[i].itemid).width()});
	                        	break;
	                        case 'HEATMAP':
	                        case 'HEATMAP2':
	                        	itemList[i].resize();
	                            break;
	                        case 'WORD_CLOUD':
	                        	itemList[i].resize();
	                        	break;
	                        case 'HISTOGRAM_CHART':
	                        	itemList[i].resize();
	                            break;
	                        case 'PARALLEL_COORDINATE':
	                        	itemList[i].resize();
	                            break;
	                        case 'STAR_CHART':
	                        	itemList[i].dxItem.render();
	                        	break;
	                        case 'HIERARCHICAL_EDGE':
	                        	itemList[i].resize();
	                            break;
	                    }
	                }
	            }
	        }

	        $('.cont_box_cont').css('width', '100%');
	        $('.cont_box_cont').css('height', '100%');

		}
	}
	/* 2020.01.21 수정자 : mksong 뷰어 리사이즈 오류 수정 끝 dogfoot */
}

// 공통 null 체크
// undefined, null, '', nan 등등 체크(trim 적용됨)
function isNull(sValue)
{
	if(new String(sValue).valueOf() == "undefined" || new String(sValue).valueOf() == "[Undefined]") return true;
	if(sValue == null || sValue == "null") return true;
	if(("x"+sValue == "xNaN") && (String(sValue.length).valueOf() == "undefined"))
		return true;
	if(String(sValue).length == 0) return true;

    //Trim 기능 추가
    var sArg = new String(sValue);
	if (sArg.replace(/(^\s*)|(\s*$)/g, "").length == 0 ) return true;

 	return false;
}
