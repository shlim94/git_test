(function() {
   var out$ = typeof exports != 'undefined' && exports || this;
 
   var doctype = '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">';
 
   function isExternal(url) {
     return url && url.lastIndexOf('http',0) == 0 && url.lastIndexOf(window.location.host) == -1;
   }
 
   function inlineImages(el, callback) {
     var images = el.querySelectorAll('image');
     var left = images.length;
     if (left == 0) {
       callback();
     }
     for (var i = 0; i < images.length; i++) {
       (function(image) {
         var href = image.getAttributeNS("http://www.w3.org/1999/xlink", "href");
         if (href) {
           if (isExternal(href.value)) {
             console.warn("Cannot render embedded images linking to external hosts: "+href.value);
             return;
           }
         }
         var canvas = document.createElement('canvas');
         var ctx = canvas.getContext('2d');
         var img = new Image();
         href = href || image.getAttribute('href');
         img.src = href;
         img.onload = function() {
           canvas.width = img.width;
           canvas.height = img.height;
           ctx.drawImage(img, 0, 0);
           image.setAttributeNS("http://www.w3.org/1999/xlink", "href", canvas.toDataURL('image/png'));
           left--;
           if (left == 0) {
             callback();
           }
         }
         img.onerror = function() {
           console.log("Could not load "+href);
           left--;
           if (left == 0) {
             callback();
           }
         }
       })(images[i]);
     }
   }
 
   function styles(el, selectorRemap) {
     var css = "";
     var sheets = document.styleSheets;
     for (var i = 0; i < sheets.length; i++) {
       try {
         var rules = sheets[i].cssRules;
       } catch (e) {
         console.warn("Stylesheet could not be loaded: "+sheets[i].href);
         continue;
       }
 
       if (rules != null) {
         for (var j = 0; j < rules.length; j++) {
           var rule = rules[j];
           if (typeof(rule.style) != "undefined") {
             var match = null;
             try {
               match = el.querySelector(rule.selectorText);
             } catch(err) {
               console.warn('Invalid CSS selector "' + rule.selectorText + '"', err);
             }
             if (match) {
               var selector = selectorRemap ? selectorRemap(rule.selectorText) : rule.selectorText;
               css += selector + " { " + rule.style.cssText + " }\n";
             } else if(rule.cssText.match(/^@font-face/)) {
               css += rule.cssText + '\n';
             }
           }
         }
       }
     }
     return css;
   }
 
   function getDimension(el, clone, dim) {
     var v = (el.viewBox.baseVal && el.viewBox.baseVal[dim]) ||
       (clone.getAttribute(dim) !== null && !clone.getAttribute(dim).match(/%$/) && parseInt(clone.getAttribute(dim))) ||
       el.getBoundingClientRect()[dim] ||
       parseInt(clone.style[dim]) ||
       parseInt(window.getComputedStyle(el).getPropertyValue(dim));
     return (typeof v === 'undefined' || v === null || isNaN(parseFloat(v))) ? 0 : v;
   }
 
   function reEncode(data) {
     data = encodeURIComponent(data);
     data = data.replace(/%([0-9A-F]{2})/g, function(match, p1) {
       var c = String.fromCharCode('0x'+p1);
       return c === '%' ? '%25' : c;
     });
     return decodeURIComponent(data);
   }
 
   out$.svgAsDataUri = function(el, options, cb,total) {
     options = options || {};
     options.scale = options.scale || 1;
     var xmlns = "http://www.w3.org/2000/xmlns/";
 
     inlineImages(el, function() {
       var outer = document.createElement("div");
       var clone = el.cloneNode(true);
       var width, height;
       if(el.tagName == 'svg') {
         width = options.width || getDimension(el, clone, 'width');
         height = options.height || getDimension(el, clone, 'height');
       } else if(el.getBBox) {
         var box = el.getBBox();
         width = box.x + box.width;
         height = box.y + box.height;
         clone.setAttribute('transform', clone.getAttribute('transform').replace(/translate\(.*?\)/, ''));
 
         var svg = document.createElementNS('http://www.w3.org/2000/svg','svg')
         svg.appendChild(clone)
         clone = svg;
       } else {
         console.error('Attempted to render non-SVG element', el);
         return;
       }
 
       clone.setAttribute("version", "1.1");
       clone.setAttributeNS(xmlns, "xmlns", "http://www.w3.org/2000/svg");
       clone.setAttributeNS(xmlns, "xmlns:xlink", "http://www.w3.org/1999/xlink");
       clone.setAttribute("width", width * options.scale);
       clone.setAttribute("height", height * options.scale);
       clone.setAttribute("viewBox", [
         options.left || 0,
         options.top || 0,
         width,
         height
       ].join(" "));
 
       outer.appendChild(clone);
 
       var css = styles(el, options.selectorRemap);
       var s = document.createElement('style');
       s.setAttribute('type', 'text/css');
       s.innerHTML = "<![CDATA[\n" + css + "\n]]>";
       var defs = document.createElement('defs');
       defs.appendChild(s);
       clone.insertBefore(defs, clone.firstChild);
 
       var svg = doctype + outer.innerHTML;
       var uri = 'data:image/svg+xml;base64,' + window.btoa(reEncode(svg));
       if (cb) {
         cb(uri,total);
       }
     });
   }
 
//   out$.svgAsPngUri = function(el, options, cb) {
//	     out$.svgAsDataUri(el, options, function(uri) {
//	       var image = new Image();
//	       image.onload = async function() {
//	         var canvas = document.createElement('canvas');
//	         canvas.width = image.width;
//	         canvas.height = image.height;
//	         var context = canvas.getContext('2d');
//	         if(options && options.backgroundColor){
//	           context.fillStyle = options.backgroundColor;
//	           context.fillRect(0, 0, canvas.width, canvas.height);
//	         }
////	         v = await canvg.from(context, './svgs/1.svg');
//	         v = await canvg(context, './svgs/1.svg')
//
//	   
//			v.start();
//	       }
//	       image.src = uri;
//	     });
//	   }
   
   out$.svgAsPngUri = function(el, options, cb, total) {
     out$.svgAsDataUri(el, options, function(uri,total) {
       var image = new Image();
       image.crossOrigin = 'anonymous';
       if(total){
		image.onload =  function() {
			 var canvas = document.createElement("canvas");
		     canvas.width = image.width;
		     canvas.height = image.height;
		     var context = canvas.getContext('2d');
		     context.drawImage(image, 0, 0,image.width, image.height);
		    try {
		         var a = document.createElement('a');
		//         a.append("<img src='"+canvas.toDataURL('image/png')+"'/>")
		         
		         a.download = fileName + ".png";
		         a.href = canvas.toDataURL("image/png"); 
		         a.click(); 
		         console.log("a.click()");
	    	 }catch(error) { 
	    	     
	    		 var d = openNewWindowTotal(image); 
//	    		 cb(image.src);
	    	 }
       }	 
       }else{
       	image.onload =  function() {
			 var canvas = document.createElement("canvas");
		     canvas.width = image.width;
		     canvas.height = image.height;
		     var context = canvas.getContext('2d');
		     context.drawImage(image, 0, 0,image.width, image.height);
		    try {
		         var a = document.createElement('a');
		//         a.append("<img src='"+canvas.toDataURL('image/png')+"'/>")
		         
		         a.download = fileName + ".png";
		         a.href = canvas.toDataURL("image/png"); 
		         a.click(); 
		         console.log("a.click()");
	    	 }catch(error) { 
	    	     
	    		 var d = openNewWindow(image); 
//	    		 cb(image.src);
	    	 }
       }	 
       }
       
       image.src = uri;
//       gDashboard.itemGenerateManager.saveImg(image)
     },total);
   }
   
   function openNewWindow(img) { 
//	   var d = img.src; 
//	   document.getElementById("d3_image").src = img.src;
	   var imgData = img.src.split(',')[1];
	 
	   gDashboard.itemGenerateManager.saveImg(imgData);

   }
     function openNewWindowTotal(img) { 
//	   var d = img.src; 
//	   document.getElementById("d3_image").src = img.src;
	   var imgData = img.src.split(',')[1];
	 
	  gDashboard.downloadManager.saveImg(imgData);

   }
 
   out$.saveSvgAsPng = function(el, name, options, total) {
     options = options || {};
     out$.svgAsPngUri(el, options, function(uri) {
//       var a = document.createElement('a');
//       a.download = name;
//       a.href = uri;
//       document.body.appendChild(a);
//       a.addEventListener("click", function(e) {
//         a.parentNode.removeChild(a);
//       });
//       a.click();
    	 return el;
     },total);
   }
   
   
   out$.getSVGString = function( svgNode ) {
		svgNode.setAttribute('xlink', 'http://www.w3.org/1999/xlink');
		var cssStyleText = getCSSStyles( svgNode );
		appendCSS( cssStyleText, svgNode );

		var serializer = new XMLSerializer();
		var svgString = serializer.serializeToString(svgNode);
		svgString = svgString.replace(/(\w+)?:?xlink=/g, 'xmlns:xlink='); // Fix root xlink without namespace
		svgString = svgString.replace(/NS\d+:href/g, 'xlink:href'); // Safari NS namespace fix

//		return svgString;
		return svgNode;

		function getCSSStyles( parentElement ) {
			var selectorTextArr = [];

			// Add Parent element Id and Classes to the list
			selectorTextArr.push( '#'+parentElement.id );
			// Add Children element Ids and Classes to the list
			var nodes = parentElement.getElementsByTagName("*");
			for (var i = 0; i < nodes.length; i++) {
				var id = nodes[i].id;
				if ( !contains('#'+id, selectorTextArr) )
					selectorTextArr.push( '#'+id );
				var classes = nodes[i].className;
				if(typeof classes.animVal != 'undefined'){
				
						if ( !contains('.'+classes.animVal, selectorTextArr) )
							selectorTextArr.push( '.'+classes.animVal );
				}
			}

			// Extract CSS Rules
			var extractedCSSText = "";
			for (var i = 0; i < document.styleSheets.length; i++) {
				var s = document.styleSheets[i];
				
				try {
				    if(!s.cssRules) continue;
				} catch( e ) {
			    		if(e.name !== 'SecurityError') throw e; // for Firefox
			    		continue;
			    	}

				var cssRules = s.cssRules;
				for (var r = 0; r < cssRules.length; r++) {
					if ( contains( cssRules[r].selectorText, selectorTextArr ) )
						extractedCSSText += cssRules[r].cssText;
				}
			}
			

			return extractedCSSText;

			function contains(str,arr) {
				return arr.indexOf( str ) === -1 ? false : true;
			}

		}

		function appendCSS( cssText, element ) {
			var styleElement = document.createElement("style");
			styleElement.setAttribute("type","text/css"); 
			styleElement.innerHTML = cssText;
			var refNode = element.hasChildNodes() ? element.childNodes[0] : null;
			element.insertBefore( styleElement, refNode );
		}
	}


   out$.svgString2Image = function( svgString, width, height, format, callback, id,svgNode) {
		var format = 'png';

		var imgsrc = 'data:image/svg+xml;base64,'+ btoa( unescape( encodeURIComponent( svgString ) ) ); // Convert SVG string to data URL
		
		var canvas = document.getElementById("tutorial");
//		var canvas = document.createElement("canvas");
		var context = canvas.getContext("2d");
		
		canvas.width = width;
		canvas.height = height;

		var image = new Image();
		image.onload = function() {
			context.clearRect ( 0, 0, width, height );
			context.drawImage(image, 0, 0, width, height);
			
		
			
			
			html2canvas(svgNode, {letterRendering:true}).then(function(canvas) {
				
				var png_dataurl = canvas.toDataURL('image/' + format);
				
				var image = document.getElementById("d3_image");
				image.src = png_dataurl;
				canvas.toBlob(function(blob){
					gDashboard.itemGenerateManager.saveImg(blob)
				});
			});
			
//			html2canvas(svgNode, {letterRendering:true}).then(function(canvas22) {
//				canvas.toBlob(function(blob){
//					gDashboard.itemGenerateManager.saveImg(blob)
//				});
//				canvas.toBlob( function(blob) {
//					var filesize = Math.round( blob.length/1024 ) + ' KB';
//					if ( callback ) callback( blob, filesize );
//				});
//			});
						
		};

		image.src = imgsrc;
		image.crossOrigin = "Anonymous";
			
//		image.setAttribute('crossOrigin', 'anonymous');
	}
   
   out$.toDataURL = function(svgdata,type, options) {
		var _svg = svgdata;
		
		function debug(s) {
			console.log("SVG.toDataURL:", s);
		}

		function exportSVG() {
			var svg_xml = XMLSerialize(_svg);
			var svg_dataurl = base64dataURLencode(svg_xml);
			debug(type + " length: " + svg_dataurl.length);

			// NOTE double data carrier
			if (options.callback) options.callback(svg_dataurl);
			return svg_dataurl;
		}

		function XMLSerialize(svg) {

			// quick-n-serialize an SVG dom, needed for IE9 where there's no XMLSerializer nor SVG.xml
			// s: SVG dom, which is the <svg> elemennt
			function XMLSerializerForIE(s) {
				var out = "";
				
				out += "<" + s.nodeName;
				for (var n = 0; n < s.attributes.length; n++) {
					out += " " + s.attributes[n].name + "=" + "'" + s.attributes[n].value + "'";
				}
				
				if (s.hasChildNodes()) {
					out += ">\n";

					for (var n = 0; n < s.childNodes.length; n++) {
						out += XMLSerializerForIE(s.childNodes[n]);
					}

					out += "</" + s.nodeName + ">" + "\n";

				} else out += " />\n";

				return out;
			}

			
			if (window.XMLSerializer) {
				debug("using standard XMLSerializer.serializeToString")
				return (new XMLSerializer()).serializeToString(svg);
			} else {
				debug("using custom XMLSerializerForIE")
				return XMLSerializerForIE(svg);
			}
		
		}

		function base64dataURLencode(s) {
			var b64 = "data:image/svg+xml;base64,";

			// https://developer.mozilla.org/en/DOM/window.btoa
			if (window.btoa) {
				debug("using window.btoa for base64 encoding");
				b64 += btoa(s);
			} else {
				debug("using custom base64 encoder");
				b64 += Base64.encode(s);
			}
			
			return b64;
		}

		function exportPNG() {
			var canvas = document.createElement("canvas");
			var ctx = canvas.getContext('2d');

			// TODO: if (options.keepOutsideViewport), do some translation magic?

			var svg_img = new Image();
			var svg_xml = XMLSerialize(_svg);
			svg_img.src = base64dataURLencode(svg_xml);

			svg_img.onload = function() {
				debug("exported image size: " + [svg_img.width, svg_img.height])
				canvas.width = svg_img.width;
				canvas.height = svg_img.height;
				ctx.drawImage(svg_img, 0, 0);

				// SECURITY_ERR WILL HAPPEN NOW
				var png_dataurl = canvas.toDataURL();
				debug(type + " length: " + png_dataurl.length);

				if (options.callback) options.callback( png_dataurl );
				else debug("WARNING: no callback set, so nothing happens.");
			}
			
			svg_img.onerror = function() {
				console.log(
					"Can't export! Maybe your browser doesn't support " +
					"SVG in img element or SVG input for Canvas drawImage?\n" +
					"http://en.wikipedia.org/wiki/SVG#Native_support"
				);
			}

			// NOTE: will not return anything
		}

		function exportPNGcanvg() {
			var canvas = document.createElement("canvas");
			var ctx = canvas.getContext('2d');
			var svg_xml = XMLSerialize(_svg);

			// NOTE: canvg gets the SVG element dimensions incorrectly if not specified as attributes
			//debug("detected svg dimensions " + [_svg.clientWidth, _svg.clientHeight])
			//debug("canvas dimensions " + [canvas.width, canvas.height])

			var keepBB = options.keepOutsideViewport;
			if (keepBB) var bb = _svg.getBBox();

			// NOTE: this canvg call is synchronous and blocks
			canvg(canvas, svg_xml, { 
				ignoreMouse: true, ignoreAnimation: true,
				offsetX: keepBB ? -bb.x : undefined, 
				offsetY: keepBB ? -bb.y : undefined,
				scaleWidth: keepBB ? bb.width+bb.x : undefined,
				scaleHeight: keepBB ? bb.height+bb.y : undefined,
				renderCallback: function() {
					debug("exported image dimensions " + [canvas.width, canvas.height]);
					var png_dataurl = canvas.toDataURL();
					debug(type + " length: " + png_dataurl.length);
		
					if (options.callback) options.callback( png_dataurl );
				}
			});

			// NOTE: return in addition to callback
			return canvas.toDataURL();
		}

		// BEGIN MAIN

		if (!type) type = "image/svg+xml";
		if (!options) options = {};

		if (options.keepNonSafe) debug("NOTE: keepNonSafe is NOT supported and will be ignored!");
		if (options.keepOutsideViewport) debug("NOTE: keepOutsideViewport is only supported with canvg exporter.");
		
		switch (type) {
			case "image/svg+xml":
				return exportSVG();
				break;

			case "image/png":

				if (!options.renderer) {
					if (window.canvg) options.renderer = "canvg";
					else options.renderer="native";
				}

				switch (options.renderer) {
					case "canvg":
						debug("using canvg renderer for png export");
						return exportPNGcanvg();
						break;

					case "native":
						debug("using native renderer for png export. THIS MIGHT FAIL.");
						return exportPNG();
						break;

					default:
						debug("unknown png renderer given, doing noting (" + options.renderer + ")");
				}

				break;

			default:
				debug("Sorry! Exporting as '" + type + "' is not supported!")
		}
	}

   
 })();