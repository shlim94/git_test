/**
 * package name : WISE.resources
 * @desc : 3-rd party javascript library wrapper package
 * @author : jylee
 * @since : 2015.06.10
 */
WISE.namespace('WISE.resources');
WISE.resources.dx = {
	exports: {
		image: function(_code, _options) {
			if ($.type(_options) === 'object') {
				switch(_options.type) {
				case 'canvas':
					this.canvas(_code); break;
				default:
					this.svg(_code);
				}
			}
			else {
				this.svg(_code);
			}
		},
		canvas: function(_canvas) {
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
			_canvas.toBlob(function(_blob) {
        	    saveAs(_blob, "image-" + new Date().valueOf() + ".png");
        	});
		},
		svg: function(_svgCode) {
			var canvas = document.createElement('canvas');
			document.body.appendChild(canvas);
			
			//2020.11.03 mksong resource Import 동적 구현 dogfoot
			canvg(canvas, _svgCode,{ ignoreMouse: true, ignoreAnimation: true });
			
			/**
			 * 2016.01.01 : DevExtreme 버전은 IE9 이하는 지원하지 않음
			 * 하위 코드 (IE7,IE8 코드)는 history로 남겨둠
			 * */
//			if (WISE.Constants.browser === 'IE7' || WISE.Constants.browser === 'IE8') {
////				gProgressbar.show();
//				
//				var png = canvas.toDataURL('image/png');
//				png = png.replace(/^data:image\/png;base64,/, '');
//				
//				var iframe = document.createElement('iframe');
//				var iframeName = 'iframeDL_IMG_' + new Date().valueOf();
////				iframe.setAttribute('id', iframeName);
//				iframe.setAttribute('name', iframeName);
//				iframe.setAttribute('style', 'width: 0; height: 0; border: none;');
////				iframe.onload = (function() {
////					if (gProgressbar) {
////						gProgressbar.hide();
////					} 
////				})();
//				document.body.appendChild(iframe);
//				
//				var form = document.createElement('form');
//				form.setAttribute('name', 'frmDL_IMG_' + new Date().valueOf());
//				form.setAttribute('target', iframeName);
//				form.setAttribute('method', 'post');
//				form.setAttribute('action', WISE.Constants.context + '/file/down/base64/png.do');
//				document.body.appendChild(form);
//				
//				var input = document.createElement('input');
//				input.setAttribute('type', 'hidden');
//				input.setAttcribute('name', 'base64');
//				input.setAttribute('value', png);
////				input.setAttribute('value', encodeURIComponent(png));
//				form.appendChild(input);
//				
//				form.submit();
//				
//				form.removeChild(input);
//				document.body.removeChild(form);
//				document.body.removeChild(iframe);
//			} else {
				//2020.11.03 mksong resource Import 동적 구현 dogfoot
				canvas.toBlob(function(_blob) {
            	    saveAs(_blob, "image-" + new Date().valueOf() + ".png");
            	});
//			}
			
			document.body.removeChild(canvas);
		},
		excel: function(_dimensions, _measures, _data, _meta) {
			var postData = {
				'fileName': _meta['Name'],
				'dimensions': _dimensions,
				'measures': _measures,
				'data': _data
			};
			
			var postDataStr = $.toJSON(postData);
			
			gProgressbar.show();
			
			var iframe = document.createElement('iframe');
			var iframeName = 'iframeDL_G_' + new Date().valueOf();
//			iframe.setAttribute('id', iframeName);
			iframe.setAttribute('name', iframeName);
			iframe.setAttribute('style', 'width: 0; height: 0; border: none;');
			iframe.onload = (function() {
				if (gProgressbar) {
					gProgressbar.hide();
				} 
			})();
			document.body.appendChild(iframe);
			
			var form = document.createElement('form');
			form.setAttribute('name', 'frmDL_G_' + new Date().valueOf());
			form.setAttribute('target', iframeName);
			form.setAttribute('method', 'post');
			form.setAttribute('action', WISE.Constants.context + '/file/down/excel.do');
			document.body.appendChild(form);
			
			var input = document.createElement('input');
			input.setAttribute('type', 'hidden');
			input.setAttribute('name', 'gd');
			input.setAttribute('value', postDataStr);
//			input.setAttribute('value', encodeURIComponent(postDataStr));
			form.appendChild(input);
			
			form.submit();
			
			var remove = function() {
				form.removeChild(input);
				document.body.removeChild(form);
				document.body.removeChild(iframe);
			};
			
			setTimeout(remove, 60000);
		}
	}
};