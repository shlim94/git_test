/** QueryUtility */
WISE.libs.Dashboard.util.QueryUtility = {
	cartesianProductOf: function() {
//		return Array.prototype.reduce.call(arguments[0], function(a, b) {
//		    var ret = [];
//		    a.forEach(function(a) {
//		    	b.forEach(function(b) {
//		    		ret.push(a.concat([b]));
//		    	});
//		    });
//		    return ret;
//		}, [[]]);
		return _.reduce(arguments[0], function(a, b) {
	        return _.flatten(_.map(a, function(x) {
	            return _.map(b, function(y) {
	                return x.concat([y]);
	            });
	        }), true);
	    }, [ [] ]);
	},
	doCatesianProduct: function(_distinctDataBasten) {
		var bastenn = [];
		$.each(_distinctDataBasten, function(_i0, _r0) {
			var elemm = []
			$.each(_r0, function(_i1, _r1) {
				$.each(_r1, function(_k, _v){
					elemm.push(_r1[_k]);
				});
			});
			bastenn.push(elemm);
		});
//		alert($.toJSON(bastenn));
		return this.cartesianProductOf(bastenn);
	},
	makeWhere: function(_seriesDimensions, _bastenn) { // this is for chart, pie
		var where = [];
		$.each(_bastenn, function(_i, _a) {
			var name = [];
			var and = [];
			$.each(_a, function(_i0, _a0) {
				var val = (typeof _a0 !== 'number') ? '\'' + _a0 + '\'' : _a0;
				and.push('this.' + _seriesDimensions[_i0].name + '==' + val); 
				name.push(_a0);
			});
			if (name.length > 0 && and.length > 0) {
                where.push({
                    name: name.join('-'),
                    and: and.join(' && ')
                });
            }
		});
		return where;
	},
	queryWhere: function(_seriesDimensions, _bastenn, _data) {
		var where = this.makeWhere(_seriesDimensions, _bastenn);
		var whereResult = [];
		$.each(where, function(_i, _w) {
			var tempResult = WISE.libs.Dashboard.Query.likeSql.fromJson('*', '', _data, {'where': function() {return eval(_w.and);}});
			whereResult.push.apply(whereResult, tempResult);
		});
		return whereResult;
	},
	
	/**
	 * @Param _data: dataset raw data
	 * @Param _afo: sparkline-column info
	 * @Param _vfo: actual-column info
	 * @Param _dim: dimension list
	 * */
	querySparklineData: function(_afo, _vfo, _dimensions, _item) {
		var SQLikeUtil = WISE.libs.Dashboard.Query.likeSql;
		
		var sqlConfig = {
			Select: [_afo.name],
//			From: _data,
			OrderBy: [_afo.name, '|asc|'],
			GroupBy: [_afo.name]
		};
		
		if (_vfo.summaryType === 'countdistinct') {
			var distinctCount = function(_columName, _dimensions) {
				var rowData = this, whereClause = [];
				$.each(_dimensions, function(_xx, _oo) {
					whereClause.push('this["'+_oo.name+'"] == rowData["'+_oo.name+'"]');
				});
				return function() {
					var sc = {
						'Select': [_columName],
//						'From': _data,
						'GroupBy': [_columName]
					};
					if (whereClause.length > 0) {
						sc.Where = function(_a) {
							return eval(whereClause.join(' && '));
						};
					}
					return SQLike.q(sc).length;
				};
			};
			
			sqlConfig.Select.push(distinctCount(_vfo.name, _dimensions));
			sqlConfig.Select.push('|as|');
			sqlConfig.Select.push('countdistinct_' + _vfo.name);
		}
		else {
			sqlConfig.Select.push('|' + _vfo.summaryType + '|');
			sqlConfig.Select.push(_vfo.name);
			sqlConfig.Select.push('|as|');
			sqlConfig.Select.push(_vfo.nameBySummaryType);
			$.each(_dimensions, function(index, dimension){
				sqlConfig.Select.push(dimension.name);
				sqlConfig.Select.push('|as|');
				sqlConfig.Select.push(dimension.caption);
				sqlConfig.GroupBy.push(dimension.name);
			})
		}
		
		/* DOGFOOT ktkang 쿼리보기 기능 구현  20200804 */
		var QD = SQLikeUtil.doSqlLike(_item.dataSourceId, sqlConfig, _item);
//		var QD = SQLike.q(sqlConfig);
		
		// adding sequence number
		var n = 0;
		_.map(QD, function(_do) {
			_do['seq'] = n++;
			return _do;
		});
		
		return {
//			argumentField: _afo.name,
			argumentField: 'seq',
			valueField: _vfo.nameBySummaryType,
			dataSource: QD
		};
	} // end of querySparklineData function
	
}; // end of WISE.libs.Dashboard.util.QueryUtility
