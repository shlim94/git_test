/**
 * 
 */

WISE.libs.Dashboard.MessageHandler = {
	showMessage: true,
	type: 'toast',
	success: function (_config) {
		if (this.showMessage) {
			
			if (this.type === 'alert') {
				alert(_config.msg);
			} else {
				var toastOption = {
					animation: {
						show: { type: "slide", from: { opacity: 1, top: $(window).height() }, to: { top: $(window).height() - 100 } },
					    hide: { type: "slide", from: { top: $(window).height() - 100 }, to: { top: $(window).height() } }
					},
					message: _config.msg,
					type: 'success',
					displayTime: 1500
				};
				DevExpress.ui.notify(toastOption);
			}
		}
	},
	error: function (_config) {
		gProgressbar.hide();
		
		if (this.showMessage) {
			var msg = _config.msg || 'Error Occurred While Generating Report';
//			var msg = gMessage.get('WISE.message.page.error.occurred');
			
			if (this.type === 'alert') {
				alert(msg);
			} else {
				var toastOption = {
					animation: {
						show: { type: "slide", from: { opacity: 1, top: $(window).height() }, to: { top: $(window).height() - 100 } },
					    hide: { type: "slide", from: { top: $(window).height() - 100 }, to: { top: $(window).height() } }
					},
					message: msg,
					type: 'error',
					displayTime: 5000
				};
				DevExpress.ui.notify(toastOption);
			}
			
		}
	},
	info: function (_config) {
		gProgressbar.hide();
		
		if (this.showMessage) {
			var msg = _config.msg || 'Report Information';
			
			if (this.type === 'alert') {
				alert(msg);
			} else {
				var toastOption = {
					animation: {
						show: { type: "slide", from: { opacity: 1, top: $(window).height() }, to: { top: $(window).height() - 100 } },
					    hide: { type: "slide", from: { top: $(window).height() - 100 }, to: { top: $(window).height() } }
					},
					message: msg,
					type: 'info',
					displayTime: 5000
				};
				DevExpress.ui.notify(toastOption);
			}
			
		}
	}
};