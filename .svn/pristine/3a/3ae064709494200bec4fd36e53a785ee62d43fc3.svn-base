/**
 * 
 */

WISE.util.Object = {
	toArray: function (_o) {
		if (_o) {
			return $.type(_o) === 'array' ? _o : [_o];
		} else {
			return [];
		}
	},
	extend: function(_parent) {
		var child = function() {
			_parent.call(this);
		};
		
		child.prototype = Object.create(_parent.prototype);
		child.prototype.constructor = child;
		
		return child;
	},
	overrideExtend: function(_child, _parent) {
		$.each(_parent, function(_p, _o) {
			if (!_.has(_child, _p)) {
				_child[_p] = _o;
			}
		});
	}
};