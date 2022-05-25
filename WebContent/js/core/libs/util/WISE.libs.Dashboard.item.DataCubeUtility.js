/** DataCubeUtility */
WISE.libs.Dashboard.item.DataCubeUtility = {
	setPrecision: function(_member) {
		var fs = _member['FORMAT_STRING'];
		if(fs == 0)
			_member.precision = 1;
		else
			_member.precision = 0;
		// set default


		if (!!fs && (fs.indexOf('.') > -1)) {
			var ps = fs.split('.');
			ps = ps[ps.length - 1];
			ps = ps.replace(/\'/g,'').replace(/\%/g,'');
			_member.precision = ps.length;
		}
		return _member;
	},
	setFormat: function(_member) {

		if (_member.type === 'measure') {
			var fs = _member['FORMAT_STRING'];
			if (!!fs && (fs.indexOf('%') > -1)) {
				_member.format = 'percent';
			}
			else {
				_member.format = 'fixedPoint';
			}
		}
		else {
			_member.format = undefined;
		}
		return _member;
	},
	setSummaryType: function(_member) {
		var fs = _member['FORMAT_TYPE'];
		if (_member.type === 'measure') {
			_member.summaryType = 'sum';
		}
		else {
			_member.summaryType = 'count';
		}
		return _member;
	},
	toDimension: function(_member) { // chart에서 사용됨
		return {
			type: 'dimension',
			name: _member['UNI_NM'],
			caption: _member['CAPTION'],
			sortOrder: _member.ssssss
		};
	},
	toMeasure: function(_member) { // chart에서 사용됨

		return {
			type: 'measure',
			name: _member['UNI_NM'],
			caption: _member['CAPTION'],
			summaryType: _member.summaryType,
			format: _member.format,
			format_string: _member['FORMAT_STRING'],
			precision: _member.precision,
			precisionOption: _member.precisionOption,
			nameBySummaryType: _member.summaryType + '_' + _member['UNI_NM'],
			captionBySummaryType: _member.summaryType + '_' + _member['CAPTION']
		};

	},
	getMember: function(_o, _grids, _calcs, _deltas) {
		var member;
		_.each(_grids, function(_grid) {
			if (_o['UNI_NM'] === _grid['UNI_NM']) {
				member = $.extend({}, _o);
				$.extend(member, _grid);
				member.name = member.CAPTION;
				member.isCCF = _o['FORMAT_TYPE'] === 'Custom' && _grid['TYPE'] === 'USER'; // C/S 화면에서 추가된 계산필드 (주제영역 계산필드 구분여부가 아님)
				member.isDTF = _o['FORMAT_TYPE'] === 'Custom' && _grid['TYPE'] === 'DELTA'; // C/S 화면에서 추가된 delta field
				return false;
			}
		});

		if (_calcs && member) {
			_.each(_calcs, function(_calc) {
				if (_o['UNI_NM'] === _calc['FLD_NM']) {
					member.CAPTION = _calc['CAPTION'];
					member.name = member.CAPTION;
					return false;
				}
			});
		}
		if (_deltas && member) {
			_.each(_deltas, function(_delta) {
				if (_o['UNI_NM'] === _delta['FLD_NM']) {
					member.CAPTION = _delta['CAPTION'];
					member.name = member.CAPTION;
					return false;
				}
			});
		}
		return member;
	},
	/* DOGFOOT ktkang 주제영역 정렬기준 항목 추가  20200305 */
	getCubeSortMember: function(_o, _grids) {
		var member;
		var BASE_FLD_NM = _o['BASE_FLD_NM'];		
		if(BASE_FLD_NM === undefined){
			BASE_FLD_NM = _o['BASE_FIELD_NM']
		}
		
		_.each(_grids, function(_grid) {
			if (BASE_FLD_NM === _grid['FLD_NM'] || BASE_FLD_NM.split('_K')[0] === _grid['FLD_NM']){
				member = $.extend({}, _o);
				$.extend(member, _grid);
				member.name = member.CAPTION;
				return false;
			}
		});
		
		return member;
	},
	getRowMember: function(_row, _grids, _rows) {
		var member = this.getMember(_row, _grids);
		if (!!member) member.type = 'dimension', (_rows||[]).push(member);
		return member;
	},
	getSortMember: function(_row, _grids, _rows) {
		var member = this.getMember(_row, _grids);
		if (!!member) member.type = 'dimension', (_rows||[]).push(member);
		return member;
	},
	getColumnMember: function(_column, _grids, _columns) {
		return this.getRowMember(_column, _grids, _columns);
	},
	getDataMember: function(_data, _grids, _datas, _calcs, _deltas) {
		var member = this.getMember(_data, _grids, _calcs, _deltas);
		if (!!member) {
			member.type = 'measure';
			this.setPrecision(member); 
			this.setFormat(member);
			this.setSummaryType(member);
			(_datas||[]).push(member);
		}
		return member;
	},
	Delta: {
		getDeltaValueType: function(_c) {
			var type;
			switch(_c) {
			case 'Absolute Variation': // 변화량
				type = 'absoluteVariation'; break;
			case 'Percent Variation': // 변화비율
				type = 'percentVariation'; break;
			case 'Percent Of Column': // 열기준비율
				type = 'percentOfColumnTotal'; break;
			case 'Percent Of Row': // 행기준비율
				type = 'percentOfRowTotal'; break;
			case 'Percent Of Column GrandTotal': // 열 총합계 기준비율
				type = 'percentOfColumnGrandTotal'; break;
			case 'Percent Of Row GrandTotal': // 행 총합계 기준비율
				type = 'percentOfRowGrandTotal'; break;
			case 'Percent Of GrandTotal': // 총합계 기준비율
				type = 'percentOfGrandTotal'; break;
			};
			return type;
		}
	},
	/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
	/**
	 * Return a data source's non-numeric unique identifier by data source name.
	 * @param {string} dataSrcName 
	 */
	getDataSourceIdByName: function(dataSrcName) {
		var dataSrcId = 'dataSource1';
		$.each(gDashboard.dataSourceManager.datasetInformation, function(id, ds) {
			if (ds.DATASET_NM === dataSrcName) {
				dataSrcId = id;
				return false;
			}
		});
		return dataSrcId;
	},
	/**
	 * Return a data source's non-numeric unique identifier by current data field.
	 */
	getDataSourceIdByField: function() {
		var dataSrcId = 'dataSource1';
		if (gDashboard.fieldManager && gDashboard.fieldManager.stateFieldChooser) {
			dataSrcId = gDashboard.fieldManager.stateFieldChooser.children().attr('data-source-id');
		}
		return dataSrcId;
	}
	/* DOGFOOT hsshim 2020-01-15 끝 */
}; // end of WISE.libs.Dashboard.item.DataUtility 
