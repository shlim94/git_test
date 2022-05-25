/// <reference path="../bower_components/jquery/dist/jquery.js" />
/*
jquery-resizable
Version 0.27 - 1/10/2018
© 2015-2017 Rick Strahl, West Wind Technologies
www.west-wind.com
Licensed under MIT License
*/

(function(factory, undefined) {
	if (typeof define === 'function' && define.amd) {
		// AMD
		define(['jquery'], factory);
	} else if (typeof module === 'object' && typeof module.exports === 'object') {
		// CommonJS
		module.exports = factory(require('jquery'));
	} else {
		// Global jQuery
		factory(jQuery);
	}
}(function($, undefined) {
    
    if ($.fn.resize_panel)
        return;

    $.fn.resize_panel = function fnResize_panel(options) {
        var defaultOptions = {
            // selector for handle that starts dragging
            handleSelector: null,
            // resize the width
            resizeWidth: true,
            // resize the height
            resizeHeight: true,
            // the side that the width resizing is relative to
            resizeWidthFrom: 'right',
            // the side that the height resizing is relative to
            resizeHeightFrom: 'bottom',
            // hook into start drag operation (event passed)
            onDragStart: null,
            // hook into stop drag operation (event passed)
            onDragEnd: null,
            // hook into each drag operation (event passed)
            onDrag: null,
            // disable touch-action on $handle
            // prevents browser level actions like forward back gestures
            touchActionNone: true,
            // instance id
            instanceId: null,
    };
        if (typeof options == "object")
            defaultOptions = $.extend(defaultOptions, options);

        return this.each(function () {
            var opt = $.extend({}, defaultOptions);
            if (!opt.instanceId)
                opt.instanceId = "rsz_" + new Date().getTime();            

            var startPos, startTransition;

            // get the element to resize 
            var $el = $(this);
            var $handle;

            if (options === 'destroy') {
                opt = $el.data('resize_panel');
                if (!opt)
                    return;

                $handle = getHandle(opt.handleSelector, $el);
                $handle.off("mousedown." + opt.instanceId + " touchstart." + opt.instanceId);
                if (opt.touchActionNone)
                    $handle.css("touch-action", "");
                $el.removeClass("resize_panel");
                return;
            }
          
            $el.data('resize_panel', opt);
            
            var $target = getTarget(opt.target);

            // get the drag handle

            $handle = getHandle(opt.handleSelector, $el);

            if (opt.touchActionNone)
                $handle.css("touch-action", "none");

            $el.addClass("resize_panel");
            $handle.on("mousedown." + opt.instanceId + " touchstart." + opt.instanceId, startDragging);

            function noop(e) {
                e.stopPropagation();
                e.preventDefault();
            };

            function startDragging(e) {
                // Prevent dragging a ghost image in HTML5 / Firefox and maybe others    
                if ( e.preventDefault ) {
                  e.preventDefault();
                }
                
                startPos = getMousePos(e);
                startPos.width = parseInt($el.width(), 10);
                startPos.height = parseInt($el.height(), 10);

                startTransition = $el.css("transition");
                $el.css("transition", "none");

                if (opt.onDragStart) {
                    if (opt.onDragStart(e, $el, opt) === false)
                        return;
                }
                
                $(document).on('mousemove.' + opt.instanceId, doDrag);
                $(document).on('mouseup.' + opt.instanceId, stopDragging);
                
                if (window.Touch || navigator.maxTouchPoints) {
                    $(document).on('touchmove.' + opt.instanceId, doDrag);
                    $(document).on('touchend.' + opt.instanceId, stopDragging);
                }
                $(document).on('selectstart.' + opt.instanceId, noop); // disable selection
                
                //2020.02.18 MKSONG 필드 메뉴 아이콘 hide DOGFOOT
                if(WISE.Constants.editmode !== 'viewer')
                	$('.divide-menu .other-menu-ico').css('display','none');
            }

            function doDrag(e) {
                
                var pos = getMousePos(e);
                var changeableWidth = true;
                var changeableWidth2 = false;
                var changeableWidth3 = false;
                var changeableHeight = true;
                
                if(opt.handleSelector == '#splitter' && pos.x <= $el.position().left + 20){
                	return;
                }

                if (opt.resizeWidthFrom === 'left'){
                	var changedWidth = startPos.x - pos.x;
                }
                else{
                	var changedWidth = pos.x - startPos.x;
                }

                if (opt.resizeHeightFrom === 'top')
                    var changedHeight = startPos.y - pos.y; 
                else
                	var changedHeight = pos.y - startPos.y;

                if (!opt.onDrag || opt.onDrag(e, $el, changedWidth, changedHeight, opt) !== false) {
                	//2020.02.20 MKSONG 불필요한 부분 주석 DOGFOOT
//                	if (opt.resizeHeight){
//                		if($el.height() < $('#chart-grid-filter-set').height() * 0.277 && changedHeight < 0){
//                    		changeableHeight = false;
//                    	}
//                    	if($el.height() >= $('#chart-grid-filter-set').height() * 0.277 || changedHeight > 0){
//                    		changeableHeight = true;
//                    	}
//                    	if($target.height() < $('#chart-grid-filter-set').height() * 0.34 && changedHeight > 0){
//                    		changeableHeight = false;
//                    	}
//                    	if(changeableHeight){
//                			$el.height(startPos.height + changedHeight);
////                			$('#chart-grid-filter-set').height($('#chart-grid-filter-set').height() - changedHeight);
////                			$target.height($('#chart-grid-filter-set').height() - $el.height() - $('#splitter-horizontal').height() - $('#panel-filter').height());
//                			$target.height($('#chart-grid-filter-set').height() - (startPos.height + changedHeight) - $('#splitter-horizontal').height() - $('#panel-filter').height()-37);
//                    	}
//                		
//                    }

                    if (opt.resizeWidth){
                    	//2020.02.20 MKSONG 변화가 있을 때만 로직을 타도록 수정 DOGFOOT
                    	if(changedWidth != 0){
                    		if(opt.handleSelector == '#splitter'){
                        		//2020.02.18 MKSONG 컬럼선택기 영역 리사이즈 기능 추가 DOGFOOT
                        		//최소 사이즈보다 감소 방지
                        		if($el.width() < 200 && changedWidth < 0){
                        			changeableWidth = false;
                        		}
                        		//사이즈 변경
                            	if($el.width() >= 200 || changedWidth > 0){
                            		changeableWidth = true;
                            	}
                            	//최대 사이즈보다 증가 방지
                            	if($target.width() < 202 && changedWidth > 0){
                            		changeableWidth = false;
                            	}
                        		if(changeableWidth){
                        			$el.width((startPos.width + changedWidth)<200? 200: (startPos.width + changedWidth));
                            		var width = $('.panel-tab').width() - $el.width() - ($('.panel.r').length > 0? $('.panel.r').width() : 0) - $('.panel.cont').width() - $('#splitter').width();
                            		$target.width(width);
                            	}
                        	} else if(opt.handleSelector == '#splitter2' && gDashboard.reportType === 'RAnalysis'){
                        		//2020.02.18 MKSONG 컬럼선택기 영역 리사이즈 기능 추가 DOGFOOT
                        		//최소 사이즈보다 감소 방지
                        		if($el.width() < 200 && changedWidth < 0){
                        			changeableWidth = false;
                        		}
                        		//사이즈 변경
                            	if($el.width() >= 200 || changedWidth > 0){
                            		changeableWidth = true;
                            	}
                            	//최대 사이즈보다 증가 방지
                            	if($target.width() < 202 && changedWidth > 0){
                            		changeableWidth = false;
                            	}
                        		if(changeableWidth){
                        			$el.width((startPos.width + changedWidth)<200? 200: (startPos.width + changedWidth));
                            		var width = $('.panel-tab').width() - $el.width() - $('.panel.tree').width() - $('.panel.cont').width() - $('#splitter2').width();
                            		$target.width(width);
                            	}
                        	}           	
                        	else if(opt.handleSelector == '#splitter2' || opt.handleSelector == '#splitter6'){
                        		if(changedWidth > 0){
                        			changeableWidth = true;
                        		} 
                        		//2020.02.19 MKSONG 데이터 항목 영역 리사이즈 기능 추가 DOGFOOT
                        		if($target.width() < $('body').width() * 0.59 && changedWidth > 0){
                            		changeableWidth = false;
                            	}else{
                            		changeableWidth = true;
                            		//2020.02.21 MKSONG 영역 리사이즈 범위 수정 DOGFOOT
                            		if($el.width() < 200 && changedWidth < 0){
                                        changeableWidth = false;
                                    }
                                }
                        		
                        		if(changeableWidth){
                        			$el.width(startPos.width + changedWidth);
                        			         			
                    				$target.width('calc(100% - ' + ($('.panel.tree').width() + $('.panel.data').width()+3 + ($('.panel.r').length > 0? $('.panel.r').width() : 0)) + 'px)');
                    				var panelContW = $('.panel.cont').width();
                    	            var panelContWM = panelContW - 42;
                    	            gDashboard.goldenLayoutManager.canvasLayout.updateSize(panelContWM);
                    	            gDashboard.goldenLayoutManager.resize();
                    	            //2020.02.19 MKSONG 데이터 항목 영역 리사이즈 기능 추가 수정 끝 DOGFOOT
                        		}
                        		
                        	}else if(opt.handleSelector == '#splitter3' || opt.handleSelector == '#splitter4' || opt.handleSelector == '#splitter5'){
                        	    
                        		if(changedWidth > 0){
                        			changeableWidth = true;
                        		} 
                        		//2020.02.19 MKSONG 데이터 항목 영역 리사이즈 기능 추가 DOGFOOT
                        		if($el.width() > $('body').width() * 0.25 && changedWidth > 0){
                            		changeableWidth = false;
                            	}else{
                            		changeableWidth = true;
                            		//2020.02.21 MKSONG 영역 리사이즈 범위 수정 DOGFOOT
                            		if($el.width() < 200 && changedWidth < 0){
                                        changeableWidth = false;
                                    }
                                }
                        		
                        		if(changeableWidth){
                        			var movePanelSet = $('#reportContainer, .filter-bar');
                        			$el.width((startPos.width + changedWidth)<200? 200: (startPos.width + changedWidth));
                        			         			
                        			$el.attr('style', $el.attr('style').slice(0, $el.attr('style').indexOf("width")) + 'width:'+(startPos.width + changedWidth)+'px !important');
                    	            movePanelSet.css({
                            			paddingLeft:$('.tree-area').outerWidth()+5
                            		});
                    	            $('.lm_goldenlayout').width($('.lm_goldenlayout').width());
                    	            if(Object.keys(gDashboard.goldenLayoutManager).length > 0)
                    	            	gDashboard.goldenLayoutManager[gDashboard.reportUtility.reportInfo.ReportMasterInfo.id].canvasLayout.updateSize($('#reportContainer').width(),$('#reportContainer').height());
                    	            //2020.02.19 MKSONG 데이터 항목 영역 리사이즈 기능 추가 수정 끝 DOGFOOT
                        		}
                        		
                        	}
                    		
                        	//2020.02.20 MKSONG 불필요한 부분 제거 DOGFOOT
                    	}
                    	
                    }
                }
            }

            function stopDragging(e) {
                e.stopPropagation();
                e.preventDefault();
                
                $(document).off('mousemove.' + opt.instanceId);
                $(document).off('mouseup.' + opt.instanceId);

                if (window.Touch || navigator.maxTouchPoints) {
                    $(document).off('touchmove.' + opt.instanceId);
                    $(document).off('touchend.' + opt.instanceId);
                }
                $(document).off('selectstart.' + opt.instanceId, noop);                

                // reset changed values
                $el.css("transition", startTransition);

                if (opt.onDragEnd)
                    opt.onDragEnd(e, $el, opt);
               
               //2020.02.19 MKSONG 데이터 항목 영역 리사이즈 기능 추가 불필요한 부분 주석 DOGFOOT
//                sizeSet(opt);
                
                //2020.02.18 MKSONG 필드 메뉴 아이콘 show 및 위치 조정 DOGFOOT
                if(WISE.Constants.editmode !== 'viewer')
                	$('.other-menu-ico').css('display','block');
                compMoreMenuUi();
                
                return false;
            }

            function getMousePos(e) {
                var pos = { x: 0, y: 0, width: 0, height: 0 };
                if (typeof e.clientX === "number") {
                    pos.x = e.clientX;
                    pos.y = e.clientY;
                } else if (e.originalEvent.touches) {
                    pos.x = e.originalEvent.touches[0].clientX;
                    pos.y = e.originalEvent.touches[0].clientY;
                } else
                    return null;

                return pos;
            }

            function getHandle(selector, $el) {
                if (selector && selector.trim()[0] === ">") {
                    selector = selector.trim().replace(/^>\s*/, "");
                    return $el.find(selector);
                }

                // Search for the selector, but only in the parent element to limit the scope
                // This works for multiple objects on a page (using .class syntax most likely)
                // as long as each has a separate parent container. 
                return selector ? $el.parent().find(selector) : $el;
            }
            
            function sizeSet(opt){
            	if(opt.handleSelector == '#splitter-horizontal' || opt.handleSelector == '#splitter-horizontal2'){
                	$('.cont_box').height('100%');
                    $('#CHART_CONTENT_PANEL').height($('#CHART_CONTENT_PANEL').parent().height()-$('.cont_box_top').height()-30);
                    $('#CHART_CONTENT_PANEL').dxChart('instance').render();
                    $('#GRID_CONTENT_PANEL').height($('#GRID_CONTENT_PANEL').parent().height()-$('.cont_box_top').height());
                    $('#GRID_CONTENT_PANEL').dxPivotGrid('instance').repaint();
                }
                
            	else if((opt.handleSelector == '#splitter2' && gDashboard.reportType !== 'RAnaylsis') || (opt.handleSelector == '#splitter6' && gDashboard.reportType === 'RAnaylsis')){
                    $('.cont_box').width('100%');
                    $('#CHART_CONTENT_PANEL').width($('#CHART_CONTENT_PANEL').parent().width()-30);
                    $('#CHART_CONTENT_PANEL').dxChart('instance').render();
                    $('#GRID_CONTENT_PANEL').width($('#GRID_CONTENT_PANEL').parent().width());
                    $('#GRID_CONTENT_PANEL').dxPivotGrid('instance').repaint();
                }
            	
            }
            
            function getTarget(target){
            	var $target = null;
            	if(target != null){
            		$target = $(target);
            	}
            	return $target;
            }   
            
        });
    };
}));
