/* dashboard & adhoc item report utility */
WISE.libs.Dashboard.item.ItemUtility = {
	/**
	 * get ItemGenerator instance.
	 */
	getItem: function(itemType) {
		var result = null;
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
			if (item.kind === itemType) {
				result = item;
				return false;
			}
		});
		return result;
	},
	/**
	 * Get ItemGenerator instance by given id.
	 */
	getItemById: function(id) {
		var result = null;
		$.each(gDashboard.itemGenerateManager.dxItemBasten, function(i, item) {
			if (item.ComponentName === id) {
				result = item;
				return false;
			}
		});
		return result;
	}
};
