/*  @preserve
 *  Project: jQuery plugin Watermark
 *  Description: Add watermark on images use HTML5 and Javascript.
 *  Author: Zzbaivong (devs.forumvi.com)
 *  Version: 0.2
 *  License: MIT
 */

/*
 *  jquery-boilerplate - v3.4.0
 *  A jump-start for jQuery plugins development.
 *  http://jqueryboilerplate.com
 *
 *  Made by Zeno Rocha
 *  Under MIT License
 */
;(function ($, window, document, undefined) {

    'use strict';

    var pluginName = 'watermark',
        defaults = {
            path: 'watermark.png',
            dataPath: false,

            text: '',
            textWidth: 130,
            textSize: 13,
            textColor: 'white',
            textBg: 'rgba(0, 0, 0, 0.4)',

            gravity: 'se', // nw | n | ne | w | e | sw | s | se
            opacity: 0.7,
            margin: 0,
            fullOverlay: false,

            outputWidth: 'auto',
            outputHeight: 'auto',
            outputType: 'jpeg', // jpeg | png | webp

            done: function (imgURL) {
                this.src = imgURL;
            },
            fail: function ( /*imgURL*/ ) {
                // console.error(imgURL, 'image error!');
            },
            always: function ( /*imgURL*/ ) {
                // console.log(imgURL, 'image URL!');
            }
        };

    function Plugin(element, options) {
        this.element = element;
        this.settings = $.extend({}, defaults, options);
        this._defaults = defaults;
        this._name = pluginName;
        this.init();
    }

    $.extend(Plugin.prototype, {
        init: function () {

            var _this = this,
                ele = _this.element,
                set = _this.settings,
                actualPath = set.dataPath ? $(ele).data(set.dataPath) : set.path,

                wmData = {
                    imgurl: actualPath,
                    type: 'png',
                    cross: true
                },

                imageData = {
                    imgurl: ele.src,
                    cross: true,
                    type: set.outputType,
                    width: set.outputWidth,
                    height: set.outputHeight
                };

            // Watermark d???ng base64
            if (actualPath.search(/data:image\/(png|jpg|jpeg|gif);base64,/) === 0) {
                wmData.cross = false;
            }

            // ???nh ??ang duy???t d???ng base64
            if (ele.src.search(/data:image\/(png|jpg|jpeg|gif);base64,/) === 0) {
                imageData.cross = false;
            }

            var defer = $.Deferred();

            $.when(defer).done(function (imgObj) {
                imageData.wmObj = imgObj;
                _this.imgurltodata(imageData, function (dataURL) {
                    set.done.call(ele, dataURL);
                    set.always.call(ele, dataURL);
                });
            });

            if (set.text !== '') {
                wmData.imgurl = _this.textwatermark();
                wmData.cross = false;
            }

            _this.imgurltodata(wmData, function (imgObj) {
                defer.resolve(imgObj);
            });
        },

        /**
         * Chuy???n text sang ???nh ????? l??m watermark
         * @returns {String} URL ???nh d???ng base64
         */
        textwatermark: function () {
            var _this = this,
                set = _this.settings,

                canvas = document.createElement('CANVAS'),
                ctx = canvas.getContext('2d'),

                w = set.textWidth,
                h = set.textSize + 8;

            canvas.width = w;
            canvas.height = h;

            ctx.fillStyle = set.textBg;
            ctx.fillRect(0, 0, w, h);

            ctx.fillStyle = set.textColor;
            ctx.textAlign = 'center';
            ctx.font = '500 ' + set.textSize + 'px Sans-serif';

            ctx.fillText(set.text, (w / 2), (set.textSize + 2));

            return canvas.toDataURL();
        },

        /**
         * Chuy???n ???nh sang d???ng base64
         * @param   {Object}  data     C??c th??ng s??? thi???t l???p ????? ph??n bi???t lo???i ???nh v?? v???i watermark
         * @param   {String}  callback URL ???nh d???ng base64
         */
        imgurltodata: function (data, callback) {

            var _this = this,
                set = _this.settings,
                ele = _this.element;

            var img = new Image();

            if (data.cross) {
                img.crossOrigin = 'Anonymous';
            }

            img.onload = function () {
                var canvas = document.createElement('CANVAS');
                var ctx = canvas.getContext('2d');

                var w = this.width, // image height
                    h = this.height, // image width
                    ctxH;

                if (data.wmObj) {

                    if (data.width !== 'auto' && data.height === 'auto' && data.width < w) {
                        h = h / w * data.width;
                        w = data.width;
                    } else if (data.width === 'auto' && data.height !== 'auto' && data.height < h) {
                        w = w / h * data.height;
                        h = data.height;
                    } else if (data.width !== 'auto' && data.height !== 'auto' && data.width < w && data.height < h) {
                        w = data.width;
                        h = data.height;
                    }

                }

                // Xoay d???c watermark s??? d???ng text, khi ??? v??? tr?? gi???a m??p d???c
                if ((set.gravity === 'w' || set.gravity === 'e') && !data.wmObj) {
                    canvas.width = h;
                    canvas.height = w;
                    ctxH = -h;
                    ctx.rotate(90 * Math.PI / 180);
                } else {
                    canvas.width = w;
                    canvas.height = h;
                    ctxH = 0;
                }

                // T?? n???n tr???ng cho ???nh xu???t ra d???ng jpeg
                if (data.type === 'jpeg') {
                    ctx.fillStyle = '#ffffff';
                    ctx.fillRect(0, 0, w, h);
                }

                ctx.drawImage(this, 0, ctxH, w, h);

                // X??? l?? watermark ???????c ch??n v??o
                if (data.wmObj) {

                    // ????? trong su???t
                    var op = set.opacity;
                    if (op > 0 && op < 1) {
                        ctx.globalAlpha = set.opacity;
                    }

                    // V??? tr?? ch??n, g???i theo h?????ng tr??n b???n ?????
                    var wmW = set.fullOverlay ? w : data.wmObj.width,
                        wmH = set.fullOverlay ? h : data.wmObj.height,
                        pos = set.margin,
                        gLeft, gTop;

                    switch (set.gravity) { // nw | n | ne | w | e | sw | s | se
                        case 'nw': // T??y b???c
                            gLeft = pos;
                            gTop = pos;
                            break;
                        case 'n': // B???c
                            gLeft = w / 2 - wmW / 2;
                            gTop = pos;
                            break;
                        case 'ne': // ????ng B???c
                            gLeft = w - wmW - pos;
                            gTop = pos;
                            break;
                        case 'w': // T??y
                            gLeft = pos;
                            gTop = h / 2 - wmH / 2;
                            break;
                        case 'e': // ????ng
                            gLeft = w - wmW - pos;
                            gTop = h / 2 - wmH / 2;
                            break;
                        case 'sw': // T??y Nam
                            gLeft = pos;
                            gTop = h - wmH - pos;
                            break;
                        case 's': // Nam
                            gLeft = w / 2 - wmW / 2;
                            gTop = h - wmH - pos;
                            break;
                        default: // ????ng Nam
                            gLeft = w - wmW - pos;
                            gTop = h - wmH - pos;
                    }
                    ctx.drawImage(data.wmObj, gLeft, gTop, wmW, wmH);
                }

                // Xu???t ra url ???nh d???ng base64
                var dataURL = canvas.toDataURL('image/' + data.type);

                if (typeof callback === 'function') {

                    if (data.wmObj) { // ???? c?? watermark
                        callback(dataURL);

                    } else { // watermark
                        var wmNew = new Image();
                        wmNew.src = dataURL;
                        callback(wmNew);
                    }
                }

                canvas = null;
            };

            // X??? l?? ???nh t???i l???i ho???c c?? th??? do t??? ch???i CORS headers
            img.onerror = function () {
                set.fail.call(this, this.src);
                set.always.call(ele, this.src);
                return false;
            };

            img.src = data.imgurl;
        }
    });

    $.fn[pluginName] = function (options) {
        return this.each(function () {
            if (!$.data(this, 'plugin_' + pluginName)) {
                $.data(this, 'plugin_' + pluginName, new Plugin(this, options));
            }
        });
    };

}(jQuery, window, document));
