(function () {
    'use strict';

    var designer = GC.Spread.Sheets.Designer;
    GC.Spread.Sheets.LicenseKey ="intelligence.wise.co.kr,525832174497429#B0LBNVoR5YzNWUKRjVWp5SxpFdoFGc4kWeLdTTyVWV6pFRTVjQIdEVnlDVZpVTOh7Qzo4KUFGcal6ZFd6c934ZjlkQ6w4QKJUZ4ZjSJlVRYR4MStyN9A7S9MUMJRzR4p6VJBjZEV4L5NkSSl5b88kd7w4YGRFU8EnY5R7RrYEOIhWMJhTemtyLYRTVUh7N5sCb6ImSF54ZJRzarZ4U7plUElGVTh5ZGBHMXlnZEd6djJUQ8Fmc4VGWad6Ui3GSmlUeLNXRvAnMTVXUuN6dol5S4Imd8kGdlRkR7YEd5ATdRB5UGBnVNFEbsJkdHpHS5hVQCJiOiMlIsISM5QEMwkTMiojIIJCLxYzM8gTNyUzN0IicfJye35XX3JSVPNjNiojIDJCLiMTMuYHITpEIkFWZyB7UiojIOJyebpjIkJHUiwiIxIDMzgDMgkDMzADMyAjMiojI4J7QiwiIytmLvNmLlNXa79SZj9WZnlGbsVGdulmI0IyctRkIsISjF6OtdyOhVyOuEyOhcyuI0ISYONkIsISOyQzN9QDN7EjMzgTNyUjI0ICZJJCL3V6csFmZ0IiczRmI1pjIs9WQisnOiQkIsISP3cXTThjNsZkS696bBNDb5YDb6RUR9RXNNdkWGFzclVlbklTTMRnW4JDavZHaMh4RZFHemFWO7YFRYhUYnN6Y8h5Z7AleONUb4hGdP9Ud6A7QNtiSDFWepZTWwtWZytCTIBVQvoVR";

    var needSuspend;
    var tipWidth = designer.res.ribbon.accessBar.tipWidth || 600;

    function updateLayout() {
        $(".content").css('height', $(".content").children('.fill-spread-content').height());
        $(".header").css("width", $(window).width() + "px");
        if ($(".ribbon-bar").data("gcui-gcuiribbon")) {
            $(".ribbon-bar").data("gcui-gcuiribbon").updateRibbonSize();
        }
        var spread = designer.wrapper.spread;
        if (spread && spread.isPaintSuspended()) {
            spread.resumePaint();
            spread.refresh();
            needSuspend = true;
        }
    }

    var _windowResizeTimer = null;

    function _doWindowResize() {
        if (_windowResizeTimer) {
            window.clearTimeout(_windowResizeTimer);
        }
        _windowResizeTimer = window.setTimeout(function () {
            updateLayout();
            _windowResizeTimer = null;
            if (needSuspend) {
                needSuspend = false;
                window.setTimeout(function () {
                    designer.wrapper.spread.suspendPaint();
                }, 300);
            }
        }, 100); //now delay 100ms to resize designer
    }

    $(document).ready(function () {
        designer.loader.loadContent();
        $(window).resize(_doWindowResize);
        $(window).resize();

        $("#verticalSplitter").draggable({
            axis: "y",
            containment: ".container",
            scroll: false,
            zIndex: 100,
            stop: function (event, ui) {
                var $this = $(this), top = $this.offset().top, offset = top - $(".header").height(), $content = $(".content .fill-spread-content");

                // adjust size of related items
                var oldHeight = $("#formulaBarText").height();
                var newHeight = oldHeight + offset;
                var ORIGINAL_FORMULABARTEXT_HEIGHT = 20;
                var MAX_FORMULABAETEXT_HEIGHT = 100; // 100: max height of formulaBarText
                if (newHeight < ORIGINAL_FORMULABARTEXT_HEIGHT) { // 20: original height of formulaBarText
                    // reset to default
                    $("#formulaBarText").css({ height: ORIGINAL_FORMULABARTEXT_HEIGHT });
                    top = top + ORIGINAL_FORMULABARTEXT_HEIGHT - newHeight;
                } else if (newHeight > MAX_FORMULABAETEXT_HEIGHT) {
                    $("#formulaBarText").css({ height: MAX_FORMULABAETEXT_HEIGHT });
                    top = top + MAX_FORMULABAETEXT_HEIGHT - newHeight;
                } else {
                    $("#formulaBarText").css({ height: newHeight });
                }
                $content.css({ top: top + 10 }); // 10: height of the space for verticalSplitter
                $content.parent().css({ height: $content.height() });
                $(".header").css({ height: top });
                $this.css({ top: 0 });
                designer.wrapper.spread.refresh();
            }
        });

        function disableDragDrop(dataTransfer) {
            if (dataTransfer) {
                dataTransfer.effectAllowed = "none";
                dataTransfer.dropEffect = "none";
            }
        }

        window.addEventListener("dragenter", function (e) {
            e = e || event;
            e.preventDefault();
            disableDragDrop(e.dataTransfer);
        }, false);
        window.addEventListener("dragover", function (e) {
            e = e || event;
            e.preventDefault();
            disableDragDrop(e.dataTransfer);
        }, false);
        window.addEventListener("drop", function (e) {
            e = e || event;
            e.preventDefault();
            disableDragDrop(e.dataTransfer);
        }, false);
    });

    designer.loader.ready(function () {
        //To Fix the designer resize performance issues.
        $(window).unbind("resize.gcuiribbon");
        $("#verticalSplitter").show();
        updateLayout();
    });

})();

