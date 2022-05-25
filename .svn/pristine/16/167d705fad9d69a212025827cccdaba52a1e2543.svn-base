WISE.libs.Dashboard.DataSourceManager = function() {
	var self = this;
	var dataSources; //report datasource
	
	this.dashboardid;
//	this.datasetInformation = []; //DATASET_ELEMENT
	this.datasetInformation = {};
	
	this.init = function() {
		if(!gDashboard.isNewReport){
			dataSources = WISE.util.Object.toArray(window[this.dashboardid].structure.DataSources.DataSource);
			this.setDataSetInformation(window[this.dashboardid].structure.ReportMasterInfo.datasetJson);

		}
		
		else{
//			this.dataSource = gDashboard.structure.ReportMasterInfo.dataSource;
//			this.dataSet = gDashboard.structure.ReportMasterInfo.dataSet;

		}

	};
	
	this.setDataSetInformation = function(_information) {
		var getDataSourceName = function(_dataSetName) {
			var componentName;
			
			$.each(dataSources, function(_i, _o) {
				if (_o['Name'] == _dataSetName) {
					componentName = _o['ComponentName'];
					return false;
				}
			});
			
			return componentName;
		};
		
		try {			
			if(dataSources.length == 0) return;			
			var datsetElementList = _information['DATASET_ELEMENT'];
			this.datasetInformation = {};
			$.each(datsetElementList, function(_i, _ds) {
				//self.datasetInformation[getDataSourceName(_ds['DATASET_NM'])] = _ds;
				self.datasetInformation["dataSource"+(_i+1)] = _ds;
			});
			
		} catch (e) {
			this.datasetInformation = undefined;
			WISE.alert('has no dataset information - ' + e);
		}
	};
	
	this.connect = function() {
		$.each(this.datasetInformation, function(_id, _ds) {
			
			if(_ds['DATASRC_ID'] == "0") return; // tbchoi 데이터집합이 없어도 열수 있도록 예외처리 200330
			
			var runnable = function() {
				$.ajax({
					type : 'post',
					async : false,
					data : {'dsid' : _ds['DATASRC_ID'], 'dstype' : _ds['DATASRC_TYPE']},
					url : WISE.Constants.context + '/report/connect.do',
					success : function(_data) {
						var __CONFIG = WISE.widget.getCustom('common','Config');
						if (__CONFIG.message.datasource.connected) {
							var msg = 'Conneted Datasource(' + _ds['DATASRC_TYPE'] + ':' + _ds['DATASRC_ID'] + ') completely';
							WISE.libs.Dashboard.MessageHandler.success({msg: msg});
						}
					},
					error:function(error){
						WISE.alert('error'+ajax_error_message(error),'error');
					}
				});
			};
			
			var __CONFIG = WISE.widget.getCustom('common', 'Config');
			if (__CONFIG.debug) {
				runnable();
			} else {
				try {
					runnable();
				}
				catch(e) {
					var msg = '';
//					switch(e) {
//					case 910: msg = 'Error Occured While Connecting DataBase, See Server Log File'; break;
//					case 911: msg = 'Not Found Datasource Type'; break;
//					case 912: msg = 'None-Register Dataset Information'; break;
//					case 913: msg = 'Not Found Database Connector'; break;
//					}
					
					msg += ' - id : ' + _ds['DATASRC_ID'] + ', type : ' + _ds['DATASRC_TYPE'];
					
					throw {status: e, msg: msg};
				}
			}

		});
	};
};