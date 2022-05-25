var currentThread;
var tossCode, tossTbl;
$('document').ready(function(){
	$('#tableInput').dxTextBox({
		placeholder:'테이블 이름 입력',
		width:400
	});
	$('#executor').dxSelectBox({
		dataSource:['sh','bat'],
		value:'sh'
	})
	$('#executeBatch').dxButton({
		text:'배치실행',
		onClick:function(){
			var param = {
				'tableNm': $('#tableInput').dxTextBox('option','value'),
				'runType': $('#executor').dxSelectBox('option','value')
			}

			var location = window.location.href.replace("execToss.do",'execBatch.do');
			$.ajax({
				type : 'post',
				data : param,
				async: false,
				dataType:"json",
				cache : false,
				url : location,
				complete: function(_e) {
					var tossInfo = JSON.parse(_e.responseText);
					tossCode = tossInfo.CODE;
					tossTbl = tossInfo.TBL_NM;
//					currentThread = setInterval(getTossResult(tossCode,tossTbl),1000);
					currentThread = setInterval(function(){
						 getTossResult(tossCode,tossTbl)
					 } ,1000);
				}
			});
		}
	});
});

function getTossResult(_code,_tableName){
	var tossParam = {
		'CODE':_code,
		'TBL_NM':_tableName
	};
	var location = window.location.href.replace("execToss.do",'getBatchStatus.do');

	$.ajax({
		type : 'post',
		data : tossParam,
		async: false,
		dataType:"json",
		cache : false,
		url : location,
		complete: function(_e) {

			var tossInfo = JSON.parse(_e.responseText);
//			$("<span>" + tossInfo.STATUS + ", " + "</span>").appendTo("#resultArea");
			if(tossInfo.STATUS_CD === "50"){
				$("#resultArea").text(tossInfo.STATUS_NM);
			}else{
				$("<br><span>" + tossInfo.STATUS_NM + "<br>총 소요 시간: "+ tossInfo.interval + "</span>").appendTo("#resultArea");
				clearInterval(currentThread);
			}
		}
	})
	
}