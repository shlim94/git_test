/**
 * Manage and calcuate custom field inputs.
 */
WISE.libs.Dashboard.CustomFieldManager = function() {
    /*
     * Variables
     */
	var self = this;
	this.editLayout;
    this.calcLayout;
    /* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
    this.paramLayout
    this.functionList;
	this.dataSource;
	this.dataSourceName;
    this.customFieldNumber;
	this.fieldInfo;
	this.originalFieldInfo;
	this.fieldNameList;
	/* DOGFOOT hsshim 1231
	 * variable를 CustomFieldManager 클레스 안으로 이동
	 */
	var editTemplate = 	'<div class="modal-body" style="height:87%">' + 
							'<div class="row" style="height:100%">' + 
								'<div class="column" style="width:60%">' + 
									'<div class="modal-article" style="margin-top:0px;">' + 
										'<div class="modal-tit">' + 
											'<span style="font-size:1.5rem;">사용자 정의 데이터</span>' + 
											'<div style="float:right;">' +
												'<a id="saveField"><img src="' + WISE.Constants.context + '/resources/main/images/ico_zoom.png" style="height:30px; width:30px;"/></a>' +
											'</div>' +
										'</div>' + 
										'<div id="customFieldList" />' + 
									'</div>' +
								'</div>' + 
								'<div class="column" style="width:40%">' + 
									'<div class="modal-article" style="margin-top:0px;">' + 
										'<div class="modal-tit">' + 
											'<span style="font-size:1.5rem;">사용자 정의 데이터 정보</span>' + 
										'</div>' +
										'<div class="tbl data-form">' +
											'<table>' +
												'<colgroup <col="" style="width: 120px;">' +
													'<col style="width: auto">' +
												'</colgroup>' +
												'<tbody>' +
												'<tr>' +
														'<th style="vertical-align: middle; padding: 0; font-size: 1.25rem;">필드 이름</th>' +
														'<td class="ipt">' +
															'<input id="fieldName" type="text" class="wise-text-input" style="font-size:1.25rem; height: 42px;">' +
														'</td>' +
													'</tr>' +
													'<tr>' +
														'<th style="vertical-align: middle; padding: 0; font-size: 1.25rem;">계산식</th>' +
														'<td class="ipt">' +
															'<div class="relative-item">' +
															/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
																'<input id="fieldCalc" type="text" class="wise-text-input search" readonly style="font-size:1.25rem; height: 42px; width: 175px;">' +
																'<a id="toCalcView" style="background-image: url(../resources/main/images/ico_sigma.png); background-size: cover; background-position: center; width: 30px; height: 30px;"></a>' +
															'</div>' +
														'</td>' +
													'</tr>' +
												'</tbody>' +
											'</table>' +
										'</div>' + 
									'</div>' +
								'</div>' + 
							'</div>' +
						'</div>' +
						'<div class="modal-footer" style="padding-top:15px;">' + 
							'<div class="row center">' + 
								'<a class="btn positive edit-ok-hide">확인</a>' + 
								'<a class="btn neutral edit-close">취소</a>' +
							'</div>' + 
						'</div>';

	var calcTemplate =  '<div class="math-edit">' +
							/* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
							'<div id="calcParam_area" class="param_area modal-tit" style="height: 40px;">' + 
	                            '<div class="right-item-calc">' +
	                            	'<a id="createCalcParamBtn" class="btn crud positive">매개변수 생성</a>' +
	                            '</div>' +
	                        '</div>' +
							'<textarea id="calcTextArea" class="wise-text-input" style="width:100%; height:160px;"></textarea>' +
							'<div class="filter-bar-sub">' +
								'<div class="filter-center">' +
									'<div class="filter-inline">' +
										'<ul class="math-gui-list">' +
											'<li><a class="operator-button" title="add" symbol="+"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_plus.png" alt=""><span>더하기</span></a></li>' +
											'<li><a class="operator-button" title="subtract" symbol="-"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_minus.png" alt=""><span>빼기</span></a></li>' +
											'<li><a class="operator-button" title="multiply" symbol="*"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_multiple.png" alt=""><span>곱하기</span></a></li>' +
											'<li><a class="operator-button" title="divide" symbol="/"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_div.png" alt=""><span>나누기</span></a></li>' +
											'<li><a class="operator-button" title="modulo" symbol="%"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_percent.png" alt=""><span>퍼센트</span></a></li>' +
										'</ul>' +
										// '<ul class="math-gui-list">' +
										// 	'<li><a class="operator-button"title="more operators..."><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_etc1.png" alt=""><span>?</span></a></li>' +
										// '</ul>' +
										'<ul class="math-gui-list">' +
											'<li><a class="operator-button" title="equals"  symbol="=="><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_same.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="not equals" symbol="!="><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_nosame.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="less than" symbol="<"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_right.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="less than or equal to" symbol="<="><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_rightfull.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="greater than or equal to" symbol=">="><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_leftfull.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="greater than" symbol=">"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_left.png" alt=""><span>?</span></a></li>' +
										'</ul>' +
										'<ul class="math-gui-list ctl">' +
											'<li><a class="operator-button" title="A and B" symbol="and"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_etc2.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="A or B" symbol="or"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_etc3.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="not B" symbol="not"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_etc4.png" alt=""><span>?</span></a></li>' +
										'</ul>' +
									'</div>' +
								'</div>' +
							'</div>' +
							'<div class="layout-row">' +
								'<div class="layout-col" style="width: 33.3333%; border:1px solid #e7e7e7;">' +
									'<div class="select-list">' +
										'<ul>' +
											//2020.04.06 MKSONG mouse-icon 수정 DOGFOOT
											'<li><a class="select-type" href="#">열</a></li>' +
											/* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
											'<li><a class="select-type" href="#">매개변수</a></li>' +
											'<li><a class="select-type" href="#">상수</a></li>' +
											'<li><a class="select-type" href="#">연산자</a></li>' +
											'<li><a class="select-type" href="#">함수</a></li>' +
										'</ul>' +
									'</div>' +
								'</div>' +
								'<div class="layout-col" style="width: 33.3333%; border:1px solid #e7e7e7;">' +
									'<select id="selectCategory" style="display:none; width:100%;"></select>' +
									//2020.04.06 MKSONG 사용자정의데이터 열 검색기능 추가 DOGFOOT
									'<div id="fieldSearch" style="width:calc(100%); display:none;"></div>' +
									'<div style="position: relative; height:240px;">' +
										/* DOGFOOT hsshim 2020-02-13 jQuery scrollbar -> dxScrollView 변경 */
										'<div id="scroll-content" class="h240">' +
											'<div class="field-list select-list input-list"></div>' +
										'</div>' +
									'</div>' +
								'</div>' +
//								'<div class="layout-col" style="width: 33.3333%; border:1px solid #e7e7e7;">' +
//									'<div class="scrollbar h240">' +
//										'<select id="selectCategory" style="display:none; width:100%;"></select>' +
//										'<div class="select-list input-list"></div>' +
//									'</div>' +
//								'</div>' +
								'<div class="layout-col" style="width: 33.3333%; border:1px solid #e7e7e7;">' +
									'<textarea id="descriptionText" rows="8" cols="80" style="height:100%" disabled></textarea>' +
								'</div>' +
							'</div>' +
						'</div>'+
						'<div class="modal-footer">' +
							'<div class="row center">' +
								'<a class="btn positive calc-ok-hide">확인</a>' +
								'<a class="btn neutral calc-close">취소</a>' +
							'</div>' +
						'</div>';
	/* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
	var paramTemplate = "<div class=\"modal-body\" style='height:93%'>\r\n" + 
	"                      <div class=\"row\" style='height:100%'>\r\n" + 
	"                            <div class=\"column\" style='width:40%'>\r\n" + 
	"                                <div class=\"modal-article\" style=\"margin-top:0px;\">\r\n" + 
	"                                   <div class=\"modal-tit\">\r\n" + 
	"                                   <span>매개변수 목록</span>\r\n" +
	"									<div id=\"removeCalcParam\" style=\"float: right\"></div>\r\n"+
	"									<div id=\"addCalcParam\" style=\"float: right\"></div>\r\n"+
	"                                   </div>\r\n" +
	"									<div id=\"paramCalcListArea\" />\r\n" + 
	"                                </div>\r\n" +
//	"                                <button class=\"btn-drag\" type=\"button\">Drag</button>\r\n" + 
	"                            </div>\r\n" + 
	"                            <div class=\"column\" style=\"width:60%\">\r\n" +
	"                            	<div class=\"row horizen\">\r\n" + 
	" 		                            <div class=\"column\" style=\"padding-bottom:0px; height:100%\">\r\n" +
	'										<div class="modal-article" style="height:100%;">' +
	"											<div id=\"calcParam_area\" class=\"param_area modal-tit\">\r\n" + 
	"   		                                     <span>매개변수 정보</span>" + 
	"       	                	            </div>\r\n" +
	"											<div id=\"calcParamItemDescArea\" style='height: calc(100% - 30px);padding-bottom:30px;overflow:auto;'></div>\r\n" +
	"       	                	        </div>\r\n" +
	" 									</div>" + //column 끝
    " 								 </div>" + //row horizon 끝
	"                            </div>\r\n" +  //column 끝 
	"                        </div>\r\n" + //row 끝
	"                    </div>\r\n" + //modal-body 끝
	"                    <div class=\"modal-footer\" style=\"padding-top:15px;\">\r\n" + 
	"                        <div class=\"row center\">\r\n" + 
	"                            <a class='btn positive paramCalc-ok-hide'>확인</a>" +
	"							<a class='btn neutral paramCalc-close'>취소</a>" +
	"                        </div>\r\n" + 
	"                    </div>\r\n" + 
	"                </div>";

	//20210122 AJKIM 단일테이블 계산된 컬럼 추가 DOGFOOT
	
	var editTemplateDS = 	'<div class="modal-body" style="height:100%">' + 
							'<div class="row" style="height:100%">' + 
								'<div class="column" style="width:40%">' + 
									'<div class="modal-article" style="margin-top:0px;height:100%">' + 
										'<div class="modal-tit">' + 
											'<span style="font-size:1.5rem;">계산된 항목</span>' + 
											'<div style="float:right;">' +
												'<a id="saveField"><img src="' + WISE.Constants.context + '/resources/main/images/ico_zoom.png" style="height:30px; width:30px;"/></a>' +
											'</div>' +
										'</div>' + 
										'<div id="customFieldList" />' + 
									'</div>' +
								'</div>' + 
								'<div class="column" style="width:60%">' + 
									'<div class="modal-article" style="margin-top:0px;height:100%">' + 
										'<div class="modal-tit">' + 
											'<span style="font-size:1.5rem;">계산된 항목 정보</span>' + 
										'</div>' +
										'<div class="tbl data-form">' +
											'<table>' +
												'<colgroup <col="" style="width: 120px;">' +
													'<col style="width: auto">' +
												'</colgroup>' +
												'<tbody>' +
												'<tr>' +
													'<th style="vertical-align: middle; padding: 0; font-size: 1.25rem;">항목 이름</th>' +
													'<td class="ipt">' +
														'<input id="fieldName" type="text" class="wise-text-input" style="font-size:1.25rem; height: 42px;">' +
													'</td>' +
												'</tr>' +
											'</tbody>' +
										'</table>' +
									'</div>' + 
									'<div class="tbl data-form">' +
									'<table>' +
										'<colgroup <col="" style="width: 50%;">' +
											'<col style="width: 50%">' +
										'</colgroup>' +
										'<tbody>' +
										'<tr>' +
											'<th style="vertical-align: middle; padding: 0; font-size: 1.25rem;">함수 리스트</th>' +
											'<th style="vertical-align: middle; padding: 0; font-size: 1.25rem;">항목 리스트</th>' +
										'</tr>' +
										'<tr>' +
										'<td class="ipt">' +
											'<div id="function_list" style="border: 1px solid #d5d6d8;">'+
										'</td>' +
										'<td class="ipt">' +
											'<div id="column_list" style="border: 1px solid #d5d6d8;">'+
										'</td>' +
									'</tr>' +
									'</tbody>' +
								'</table>' +
							'</div>' + 
							'<div class="tbl data-form">' +
							'<table>' +
								'<colgroup <col="" style="width: 100px;">' +
									'<col style="width: auto">' +
								'</colgroup>' +
								'<tbody>' +
								'<tr>' +
									'<th style="vertical-align: middle; padding: 0; font-size: 1.25rem;">계산식</th>' +
									'<th style="vertical-align: middle; padding: 0; font-size: 1.25rem;"></th>' +
								'</tr>' +
							'</tbody>' +
						'</table>' +
					'</div>' + 
									'<div class="tbl data-form">' +
									'<table>' +
										'<colgroup <col="" style="width: 120px;">' +
											'<col style="width: auto">' +
										'</colgroup>' +
										'<tbody>' +
										'<tr>' +
											'<td class="ipt">' +
												'<div class="relative-item">' +
												/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
													'<textarea id="fieldCalc" type="text" class="wise-text-input search" style="font-size:1.25rem; height: 100%;"/>' +
												'</div>' +
											'</td>' +
										'</tr>' +
									'</tbody>' +
								'</table>' +
							'</div>' +
								'</div>' +
							'</div>' + 
						'</div>' +
					'</div>' +
					'<div class="modal-footer" style="padding-top:15px;">' + 
						'<div class="row center">' + 
							'<a class="btn positive edit-ok-hide">확인</a>' + 
							'<a class="btn neutral edit-close">취소</a>' +
						'</div>' + 
					'</div>';
	var editTemplateGrp = 	'<div class="modal-body" style="height:100%">' + 
		'<div class="row" style="height:100%">' + 
			'<div class="column" style="width:33%">' + 
				'<div class="modal-article" style="margin-top:0px; height: 100%;">' + 
					'<div class="modal-tit">' + 
						'<span style="font-size:1.5rem;">그룹명</span>' + 
						'<div style="float:right;">' +
							'<a id="create_grp"><img src="' + WISE.Constants.context + '/resources/main/images/ico_zoom.png" style="height:30px; width:30px;"/></a>' +
						'</div>' +
					'</div>' + 
					'<div id="grpList" />' + 
				'</div>' +
			'</div>' + 
			'<div class="column" style="width:33%">' + 
				'<div class="modal-article" style="margin-top:0px; height: 100%;">' + 
					'<div class="modal-tit">' + 
						'<span style="font-size:1.5rem;">항목 그룹명</span>' + 
						'<div style="float:right;">' +
							'<a id="create_grp_field"><img src="' + WISE.Constants.context + '/resources/main/images/ico_zoom.png" style="height:30px; width:30px;"/></a>' +
						'</div>' +
					'</div>' + 
					'<div id="grpFieldList" />' + 
				'</div>' +
			'</div>' + 
			'<div class="column" style="width:43%">' + 
				'<div class="modal-article" style="margin-top:0px; height: 100%;">' + 
					'<div class="modal-tit">' + 
						'<span style="font-size:1.5rem;">항목 데이터 정보</span>' + 
					'</div>' +
					'<div class="tbl data-form">' +
						'<table>' +
							'<colgroup <col="" style="width: 120px;">' +
								'<col style="width: auto">' +
							'</colgroup>' +
							'<tbody>' +
							'<tr>' +
								'<th style="vertical-align: middle; padding: 0; font-size: 1.25rem;">항목 이름</th>' +
								'<td class="ipt">' +
									'<input id="fieldName" type="text" class="wise-text-input" style="font-size:1.25rem; height: 42px;">' +
								'</td>' +
							'</tr>' +
							'</tbody>' +
						'</table>' +
					'</div>' + 
					'<div id="grp_dim_list" style="border: 1px solid #d5d6d8;"/>'+
			'</div>' +
			'</div>' +
			'</div>' +
			'<div class="modal-footer" style="padding-top:15px;">' + 
			'<div class="row center">' + 
				'<a class="btn positive edit-ok-hide">확인</a>' + 
				'<a class="btn neutral edit-close">취소</a>' +
			'</div>' + 
		'</div>';
					
						var calcTemplateDS =  '<div class="math-edit">' +
							'<textarea id="calcTextArea" class="wise-text-input" style="width:100%; height:160px;"></textarea>' +
							'<div class="filter-bar-sub">' +
								'<div class="filter-center">' +
									'<div class="filter-inline">' +
										'<ul class="math-gui-list">' +
											'<li><a class="operator-button" title="add" symbol="+"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_plus.png" alt=""><span>더하기</span></a></li>' +
											'<li><a class="operator-button" title="subtract" symbol="-"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_minus.png" alt=""><span>빼기</span></a></li>' +
											'<li><a class="operator-button" title="multiply" symbol="*"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_multiple.png" alt=""><span>곱하기</span></a></li>' +
											'<li><a class="operator-button" title="divide" symbol="/"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_div.png" alt=""><span>나누기</span></a></li>' +
											'<li><a class="operator-button" title="modulo" symbol="%"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_percent.png" alt=""><span>퍼센트</span></a></li>' +
										'</ul>' +
										// '<ul class="math-gui-list">' +
										// 	'<li><a class="operator-button"title="more operators..."><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_etc1.png" alt=""><span>?</span></a></li>' +
										// '</ul>' +
										'<ul class="math-gui-list">' +
											'<li><a class="operator-button" title="equals"  symbol="=="><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_same.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="not equals" symbol="!="><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_nosame.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="less than" symbol="<"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_right.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="less than or equal to" symbol="<="><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_rightfull.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="greater than or equal to" symbol=">="><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_leftfull.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="greater than" symbol=">"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_left.png" alt=""><span>?</span></a></li>' +
										'</ul>' +
										'<ul class="math-gui-list ctl">' +
											'<li><a class="operator-button" title="A and B" symbol="and"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_etc2.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="A or B" symbol="or"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_etc3.png" alt=""><span>?</span></a></li>' +
											'<li><a class="operator-button" title="not B" symbol="not"><img src="' + WISE.Constants.context + '/resources/main/images/ico_math_etc4.png" alt=""><span>?</span></a></li>' +
										'</ul>' +
									'</div>' +
								'</div>' +
							'</div>' +
							'<div class="layout-row">' +
								'<div class="layout-col" style="width: 33.3333%; border:1px solid #e7e7e7;">' +
									'<div class="select-list">' +
										'<ul>' +
											//2020.04.06 MKSONG mouse-icon 수정 DOGFOOT
											'<li><a class="select-type" href="#">열</a></li>' +
											'<li><a class="select-type" href="#">함수</a></li>' +
										'</ul>' +
									'</div>' +
								'</div>' +
								'<div class="layout-col" style="width: 33.3333%; border:1px solid #e7e7e7;">' +
									'<select id="selectCategory" style="display:none; width:100%;"></select>' +
									//2020.04.06 MKSONG 사용자정의데이터 열 검색기능 추가 DOGFOOT
									'<div id="fieldSearch" style="width:calc(100%); display:none;"></div>' +
									'<div style="position: relative; height:240px;">' +
										/* DOGFOOT hsshim 2020-02-13 jQuery scrollbar -> dxScrollView 변경 */
										'<div id="scroll-content" class="h240">' +
											'<div class="field-list select-list input-list"></div>' +
										'</div>' +
									'</div>' +
								'</div>' +
						//		'<div class="layout-col" style="width: 33.3333%; border:1px solid #e7e7e7;">' +
						//			'<div class="scrollbar h240">' +
						//				'<select id="selectCategory" style="display:none; width:100%;"></select>' +
						//				'<div class="select-list input-list"></div>' +
						//			'</div>' +
						//		'</div>' +
								'<div class="layout-col" style="width: 33.3333%; border:1px solid #e7e7e7;">' +
									'<textarea id="descriptionText" rows="8" cols="80" style="height:100%" disabled></textarea>' +
								'</div>' +
							'</div>' +
						'</div>'+
						'<div class="modal-footer">' +
							'<div class="row center">' +
								'<a class="btn positive calc-ok-hide">확인</a>' +
								'<a class="btn neutral calc-close">취소</a>' +
							'</div>' +
						'</div>';
	/* DOGFOOT hsshim 1231 끝 */
	/* DOGFOOT hsshim 1231
	 * 사용자 정의 데이터 함수 개선
	 */
	var functionList = {
		'열': {
			'DataItem': 'Description'
		},
		'매개변수': {
		},
		'상수': {
			'True': '부울 True 값을 나타냅니다.',
			'False': '부울 False 값을 나타냅니다.',
			'?': '한 개체를 참조 하지 않는 null 참조를 나타냅니다.'
		},
		'연산자': {
			'+': 'Add',
			'-': 'Subtract',
			'*': 'Multiply',
			'/': 'Divide',
			'%': 'Modulus',
			'^': 'Power',
			'!': 'Factorial',
			'&': 'Bitwise and',
			'|': 'Bitwise or',
			'^|': 'Bitwise xor',
			'<<': 'Left shift',
			'>>': 'Right arithmetic shift',
			'>>>': 'Right logical shift',
			'and': 'Logical and',
			'or': 'Logical or',
			'xor': 'Logical xor',
			'=': 'Assignment',
			'? :': 'Conditional expression',
			':': 'Range',
			'to': 'Unit conversion',
			'==': 'Equal',
			'!=': 'Unequal',
			'<': 'Smaller',
			'>': 'Larger',
			'<=': 'Smallereq',
			'>=': 'Largereq'
		},
		'함수': {
			/* DOGFOOT hsshim 200103
			 * 사용자 정의 데이터 집계 함수 추가
			 */
			'집계': {
				'Avg()': 'Avg(Value)\n\n컬렉션에 있는 값의 평균을 계산 합니다.',
				'Count()': 'Count()\n\n컬렉션의 개체 수를 반환 합니다.',
				'Max()': 'Max(Value)\n\n컬렉션의 최대 표현 값을 반환 합니다.',
				'Median()': 'Median(Value)\n\n컬렉션에 있는 값 들의 중간 값을 반환합니다.',
				'Min()': 'Min(Value)\n\n컬렉션에서 최소 식 값을 반환 합니다.',
				'Mode()': 'Mode(Value)\n\n값의 모드입니다. 모드는 다른 것보다 더 자주 반복되는 값입니다.',
				'StdDev()': 'StdDev(Value)\n\n모집단의 표준 편차에 대한 추정치를 반환합니다. 여기서 샘플은 전체 모집단의 하위 집합입니다.',
				'Sum()': 'Sum(Value)\n\n컬렉션에서 모든 식 값의 합계를 반환 합니다.',
				'Var()': 'Var(Value)\n\n모집단의 분산에 대한 추정치를 반환하며, 여기서 샘플은 전체 모집단의 하위 집합이다.'
			},
			/* DOGFOOT hsshim 200103 끝 */
			'논리': {
				'Iif()': 'Iif (식, 참, FalsePart)\n\n부울 식의 평가 따라 참 또는 FalsePart를 반환 합니다.',
				'IsNull()': 'IsNull(Value)\n\n지정된 된 값이 NULL 경우 True를 반환 합니다.',
				'IsNullOrEmpty()': 'IsNullOrEmpty(String)\n\n지정 된 String 개체는 NULL 또는 빈 문자열; 하는 경우 True를 반환 합니다. 그렇지 않은 경우 False가 반환 됩니다.',
				'ToBoolean()': 'ToBoolean(Value)\n\nValue를 등가의 부울 값으로 변환합니다.'
			},
			'수학': {
				'Abs()': 'Abs(Value)\n\n지정된 된 숫자 식의 절대, 양수 값을 반환 합니다.',
				'Acos()': 'Acos(Value)\n\n(코사인은 주어진된 float 식 라디안에서 각도) 숫자의 아크코사인 값을 반환 합니다.',
				'Asin()': 'Asin(Value)\n\n(각도, 라디안, 사인 주어진된 float 식) 숫자의 아크사인 값을 반환 합니다.',
				'Atn()': 'Atn(Value1, [Value2])\n\n각도 탄젠트는 라디안에서 2 개의 지정 된 수의 몫을 반환 합니다.',
				'BigMul()': 'BigMul(Value1, Value2)\n\nInt64 반환 합니다 두 개의 완전 한 제품을 포함 하는 32 비트 숫자를 지정 합니다.',
				'Ceiling()': 'Ceiling(Value)\n\n지정된 된 숫자 식 보다 크거나 같은 최소 정수를 반환 합니다.',
				'Cos()': 'Cos(Value)\n\n라디안에서 정의 된 각도의 코사인을 반환 합니다.',
				'Cosh()': 'Cosh(Value)\n\n라디안에서 정의 된 각도의 하이퍼볼릭 코사인 값을 반환 합니다.',
				'Exps()': 'Exp(Value)\n\n지정된 된 float 식의 지 수 값을 반환 합니다.',
				'Floor()': 'Floor(Value)\n\n지정된 된 숫자 식 보다 작거나 같은 가장 큰 정수를 반환 합니다.',
				'Log()': 'Log(Value, [Base])\n\n지정된 된 밑에서 지정된 된 숫자의 로그를 반환 합니다.',
				'Log10()': 'Log10(Value)\n\n지정 된 숫자의 반환 기본 10 로그.',
				'Power()': 'Power(Value, Power)\n\n지정 된 수를 지정 된 거듭제곱을 반환 합니다.',
				'Rnd()': 'Rnd()\n\n하지만 0 보다 크거나 1 보다 작은 난수를 반환 합니다.',
				'Round()': 'Round(Value, [Presicison])\n\n가장 가까운 정수 또는 소수 자릿수가 지정된 된 지정된 된 값을 반올림합니다.',
				'Sign()': 'Sign(Value)\n\n양수 (+1), 영 (0), 또는 지정된 된 식의 음수 (-1) 기호를 반환 합니다.',
				'Sin()': 'Sin(Value)\n\n라디안에서 정의 된 각도의 사인을 반환 합니다.',
				'Sinh()': 'Sinh(Value)\n\n라디안에서 정의 된 각도의 하이퍼볼릭 사인을 반환 합니다.',
				'Sqr()': 'Sqr(Value)\n\n지정 된 숫자의 제곱근을 반환 합니다.',
				'Tan()': 'Tan(Value)\n\n라디안에서 정의 된 각도의 탄젠트를 반환 합니다.',
				'Tanh()': 'Tanh(Value)\n\n라디안에서 정의 된 각도의 하이퍼볼릭 탄젠트를 반환 합니다.'
			},
			'문자열': {
				'Ascii()': 'Ascii(String)\n\n문자 식에서 가장 왼쪽 문자의 ASCII 코드 값을 반환 합니다.',
				'Char()': 'Char(Number)\n\n문자는 integerASCIICode로 변환 합니다.',
				'CharIndex()': 'CharIndex (String1, String2, [StartLocation])\n\nString1 내에서 String2, StartLocation 문자 위치에서 시작 하는 문자열의 끝에 시작 위치를 반환 합니다.',
				'Concat()': 'Concat(문자열 1,..., StringN)\n\n어떤 추가 문자열 사용 하 여 현재 문자열의 연결을 포함 하는 문자열 값을 반환 합니다.',
				'Contains()': 'Contains(문자열, 문자열)\n\n(문자열, 문자열)을 포함 부분 문자열 문자열; 내에서 발생 하는 경우 True를 반환 합니다. 그렇지 않은 경우 False가 반환 됩니다.',
				'EndsWith()': 'EndsWith(String, EndString)\n\n문자열의 끝 EndString; 일치 하는 경우 True를 반환 합니다. 그렇지 않은 경우 False가 반환 됩니다.',
				'Insert()': 'Insert(문자열 1, StartPosition, 문자열 2)\n\nStartPositon로 지정 된 위치에서 문자열 1 문자열 2 삽입',
				'Len()': 'Len(Value)\n\n문자열 또는 변수를 저장 하는 데 필요한 바이트의 명목상 수 문자 수 중 하나를 포함 하는 정수를 반환 합니다.',
				'Lower()': 'Lower(String)\n\n소문자 문자열을 반환 합니다.',
				'PadLeft()': 'PadLeft(문자열, 길이, [Char])\n\n정의 된 문자열을 지정한 길이까지 지정 된 Char와 그것의 왼쪽 여백에 문자 왼쪽에 정렬 합니다.',
				'PadRight()': 'PadRight(문자열, 길이, [Char])\n\n지정한 길이 만큼까지 지정 된 Char와 그것의 왼쪽 패딩 정의 문자열의 문자 오른쪽에 정렬 합니다.',
				'Remove()': 'Remove(String, StartPosition, [Length])\n\n지정된 StartPosition에서 시작하여 지정된 문자열에서 지정된 길이의 문자를 삭제합니다.',
				'Replace()': 'Replace(문자열, SubString2, String3)\n\n문자열 1에서 SubString2 String3로 대체 되었습니다의 복사본을 반환 합니다.',
				'Reverse()': 'Reverse(String)\n\n문자열 내에서 요소 순서를 반대로 바꿉니다.',
				'StartsWith()': 'StartsWith(String, StartString)\n\n문자열의 시작 부분과 일치 StartString; 경우 True를 반환 합니다. 그렇지 않은 경우 False가 반환 됩니다.',
				'Substring()': 'Substring(문자열, StartPosition, 길이)\n\n문자열에서 부분 문자열을 검색합니다. 부분 문자열 StartPosition에서 시작 하 고 지정 된 길이 있다.',
				'ToStr()': 'ToStr(Value)\n\n개체의 문자열 표현을 반환 합니다.',
				'Trim()': 'Trim(String)\n\n문자열에서 모든 선행 및 후행 공백 문자를 제거 합니다.',
				'Upper()': 'Upper(String)\n\n대문자 문자열을 반환 합니다.',
				/* DOGFOOT ktkang 사용자 정의 데이터 함수 추가  20200730*/
				'StringAdd()': 'StringAdd(String1, String2, String3...)\n\n문자열1 뒤에 문자열2, 문자열2 뒤에 문자열3 뒤에...를 더해서 반환됩니다.'
			}
		}
	};
	/* DOGFOOT hsshim 1231 끝 */
    
   /* DOGFOOT hsshim 1231
	* 사용자 정의 데이터 함수 개선
	*/
	/**
	 * Custom expression calculator
	 */
    var secureEval = math.evaluate;
    math.import({
        'import': function () { throw new Error('Function import is disabled') },
        'createUnit': function () { throw new Error('Function createUnit is disabled') },
        'eval': function () { throw new Error('Function eval is disabled') },
        'parse': function () { throw new Error('Function parse is disabled') },
        'simplify': function () { throw new Error('Function simplify is disabled') },
		'derivative': function () { throw new Error('Function derivative is disabled') },
		// 상수
		'True': true,
		'False': false,
		// 집계 함수
		/* DOGFOOT hsshim 200103
		 * 사용자 정의 데이터 집계 함수 추가
		 */
		'Avg': function(_vals) {
			return math.mean(_vals);
		},
		'Count': function(_vals) {
			return _vals.length;
		},
		'Max': function(_vals) {
			return math.max(_vals);
		},
		'Median': function(_vals) {
			return math.median(_vals);
		},
		'Min': function(_vals) {
			return math.min(_vals);
		},
		'Mode': function(_vals) {
			return math.mode(_vals);
		},
		'StdDev': function(_vals) {
			return math.std(_vals);
		},
		'Sum': function(_vals) {
			return math.sum(_vals);
		},
		'Var': function(_vals) {
			return math.variance(vals);
		},
		/* DOGFOOT hsshim 200103 끝 */
		// 논리 함수
		'Iif': function(_condition, _ifTrue, _ifFalse) {
			return _condition ? _ifTrue : _ifFalse;
		},
		'IsNull': function(_val) {
			return typeof _val === 'undefined' || _val === null;
		},
		'IsNullOrEmpty': function(_str) {
			return typeof _str === 'undefined' || _str === null || _str.length === 0;
		},
		'ToBoolean': function(_val) {
			return Boolean(_val);
		},
		// 수학 함수
		'Abs': function(_val) {
			return math.abs(_val);
		},
		'Acos': function(_val) {
			return math.acos(_val);
		},
		'Asin': function(_val) {
			return math.asin(_val);
		},
		'Atn': function(_val1, _val2) {
			if (_val2) {
				return math.atan2(_val1, _val2);
			}
			return math.atan(_val1);
		},
		'BigMul': function(_val1, _val2) {
			return math.string(math.bignumber(_val1 * _val2));
		},
		'Ceiling': function(_val) {
			return math.ceil(_val);
		},
		'Cos': function(_val) {
			return math.cos(_val);
		},
		'Cosh': function(_val) {
			return math.cosh(_val);
		},
		'Exps': function(_val) {
			return math.exp(_val);
		},
		'Floor': function(_val) {
			return math.floor(_val);
		},
		'Log': function(_val, _base) {
			if (_base) {
				return math.log(_val, _base);
			}
			return math.log(_val);
		},
		'Log10': function(_val) {
			return math.log10(_val);
		},
		'Power': function(_val, _exp) {
			return math.pow(_val, _exp);
		},
		'Rnd': function() {
			return math.random(0, 1);
		},
		'Round': function(_val, _pos) {
			if (!_pos) {
				_pos = 0;
			} else if (_pos < 0) {
				var base = math.pow(10, math.abs(_pos)); 
				return math.multiply(math.round(math.divide(_val, base), 0), base);
			}
			return math.round(_val, _pos);
		},
		'Sign': function(_val) {
			return math.sign(_val);
		},
		'Sin': function(_val) {
			return math.sin(_val);
		},
		'Sinh': function(_val) {
			return math.sinh(_val);
		},
		'Sqr': function(_val) {
			return math.square(_val);
		},
		'Tan': function(_val) {
			return math.tan(_val);
		},
		'Tanh': function(_val) {
			return math.tanh(_val);
		},
		// 문자열 함수
		'Ascii': function(_char) {
			return _char.charCodeAt(0);
		},
		'Char': function(_ascii) {
			return String.fromCharCode(_ascii);
		},
		'CharIndex': function(_str1, _str2, _start) {
			if (_start) {
				return _str2.indexOf(_str1, _start);
			}
			return _str2.indexOf(_str1);
		},
		'Concat': function() {
			var result = '';
			for (var i = 0; i < arguments.length; i++) {
				result = result.concat(arguments[i]);
			}
			return result;
		},
		'Contains': function(_val, _sub) {
			return _val.indexOf(_sub) !== -1;
		},
		'EndsWith': function(_str1, _str2) {
			var len = _str1.length;
			return _str1.substring(len - _str2.length, len) === _str2;
		},
		'Insert': function(_str1, _index, _str2) {
			return _str1.slice(0, _index) + _str2 + _str1.slice(_index);
		},
		'Len': function(_str) {
			return _str.length;
		},
		'Lower': function(_str) {
			return _str.toLowerCase();
		},
		'PadLeft': function(_str, _targetLength, _padding) {
			_targetLength = _targetLength >> 0;
			_padding = String(_padding !== undefined ? _padding : ' ');
			if (_str.length >= _targetLength) {
				return _str;
			} else {
				_targetLength = _targetLength - _str.length;
				if (_targetLength > _padding.length) {
					_padding += _padding.repeat(_targetLength / _padding.length);
				}
				return _padding.slice(0, _targetLength) + _str;
			}
		},
		'PadRight': function(_str, _targetLength, _padding) {
			_targetLength = _targetLength >> 0;
			_padding = String(_padding !== undefined ? _padding : ' ');
			if (_str.length >= _targetLength) {
				return _str;
			} else {
				_targetLength = _targetLength - _str.length;
				if (_targetLength > _padding.length) {
					_padding += _padding.repeat(_targetLength / _padding.length);
				}
				return _str + _padding.slice(0, _targetLength);
			}
		},
		'Remove': function(_str, _start, _length) {
			var strLen = _str.length;
			if (_start < strLen) {
				if (_length !== undefined) {
					var first = _str.substring(0, _start);
					if (first.length + _length < strLen) {
						return first + _str.substring(first.length + _length, strLen);
					}
				}
				return _str.substring(0, _start);
			}
			return _str;
		},
		'Replace': function(_str, _substr, _replace) {
			return _str.replace(_substr, _replace);
		},
		'Reverse': function(_str) {
			return Array.from(_str).reverse().join('');
		},
		'StartsWith': function(_str1, _str2) {
			return _str1.substring(0, _str2.length) === _str2;
		},
		'Substring': function(_str, _start, _length) {
			var strLen = _str.length;
			if (_start < strLen) {
				if (_length !== undefined) {
					if (_start + _length < strLen) {
						return _str.substring(_start, _start + _length);
					}
				}
				return _str.substring(_start, strLen);
			}
			return _str;
		},
		'ToStr': function(_val) {
			return _val.toString();
		},
		'Trim': function(_str) {
			return _str.trim();
		},
		'Upper': function(_str) {
			return _str.toUpperCase();
		},
		/* DOGFOOT ktkang 사용자 정의 데이터 함수 추가  20200730*/
		'StringAdd': function() {
			var stringAdd = "";
			for( var i in arguments){
				stringAdd += arguments[i].toString();
			}
			return stringAdd;
		}
	}, { override: true });
	// DOGFOOT hsshim 1231 끝

	/**
	 * Initialize CustomFieldManager instance.
	 */
    this.init = function() {
		this.editLayout = editTemplate;
        this.calcLayout = calcTemplate;
        /* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
        this.paramLayout = paramTemplate;
        this.functionList = functionList;
        this.customFieldNumber = 1;
		this.fieldInfo = self.getCustomFieldInfo();
		this.originalFieldInfo = [];

		$('#createCustomField').on('click', function() {
        	//2020.04.09 mksong 비정형 사용자정의데이터 열 불러오기 수정 dogfoot
//        	if(WISE.Context.isCubeReport){
        		if(gDashboard.fieldManager.stateFieldChooser.find('.analysis-data').length !=0){
        			/* DOGFOOT hsshim 비정형 사용자 정의 데이터 오류 수정 2020-01-13 */
    				self.setDataSourceInfo();
    				self.setOriginalFieldInfo();
                    self.initLayout();
        		}
//        	}else{
//        		if ($('#allList').text().length !== 0) {
//              		/* DOGFOOT hsshim 비정형 사용자 정의 데이터 오류 수정 2020-01-13 */
//    				self.setDataSourceInfo();
//    				self.setOriginalFieldInfo();
//                    self.initLayout();
//                }	
//        	}
        });
		/* dogfoot WHATIF 분석 매개변수 생성 버튼 shlim 20201022 */
		$('#createCalcParamBtn').dxButton({
            type: 'normal',
            onClick: function() {
            	
            }
        }).dxButton('instance');
    }
    
    this.createCustomField = function (columnList, dsInfo, type) {
		if ($('#allList').text().length !== 0) {
			if(!$.isEmptyObject(gDashboard.datasetMaster.state.datasets)) {
	      		/* DOGFOOT hsshim 비정형 사용자 정의 데이터 오류 수정 2020-01-13 */
				self.setDataSourceInfo();
				self.setOriginalFieldInfo();
	            self.initLayout();
			}
        }
		
		if(type && type === 'dscal'){
			self.setDSSingleInfo(columnList, dsInfo);
            self.initLayoutDSSingle(columnList, dsInfo);
		}else if(type && type === 'dsgrp'){
			self.setDSGrpInfo(columnList, dsInfo);
            self.initLayoutDSGrp(columnList, dsInfo);
		}
		
		
    }

    /**
     * Initialize the popup calculator layout. 
     */
    this.initLayout = function() {
        $('body').append('<div id="customFieldPopup"></div>');
        $('#customFieldPopup').dxPopup({
            height: 'auto',
            width: 1000,
            visible: true,
            showCloseButton: false,
            title: '사용자 정의 데이터',
            onContentReady: function() {
            	gDashboard.fontManager.setFontConfigForOption('customFieldPopup')
            },
            contentTemplate: function(contentElement) {
				contentElement.append('<div id="multiView"/>');
				$('#multiView').dxMultiView({
					items: [
						{
							template: $('<div id="editView"/>')
						},
						{
							template: $('<div id="calcView"/>')
						},
						/* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
						{
							template: $('<div id="paramView"/>')
						}
					],
					deferRendering: false,
					height: '100%',
					width: '100%',
					selectedIndex: 0,
					loop: false,
					swipeEnabled: false,
					onContentReady: function()  {
						$('#editView').append(self.editLayout);
						$('#calcView').append(self.calcLayout);
						/* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
						$('#paramView').append(self.paramLayout);
						//2020.04.06 MKSONG 사용자정의데이터 열 검색기능 추가 DOGFOOT
						$("#fieldSearch").dxTextBox({
							visible:true,
							readOnly: false,
							placeholder: '검색어를 입력하세요.',
							onKeyUp: function(e) {
								self.fieldSearchText(e.event.target.value);
							}
						});
						self.initEditComponents();
						self.initCalcComponents();
						gDashboard.fontManager.setFontConfigForEditText('multiView');
					}
				});
            }
        }).appendTo('#tab6primary');
	};

	//2020.04.06 MKSONG 사용자정의데이터 열 검색기능 추가 DOGFOOT
    this.fieldSearchText = function(searchText){
		var treeList = $('.field-list').find('li');
		
		if(searchText) {
			$.each(treeList, function(_i,_e){
				if($(_e).text().indexOf(searchText) > -1) {
					$(_e).css('display', 'block');
				} else {
					$(_e).css('display', 'none');
				}
			});
		}else{
			$.each(treeList, function(_i,_e){
				$(_e).css('display', 'block');	
			});
		}
	};
    
	/**
	 * Initialize field editor widgets and button events.
	 */
	this.initEditComponents = function() {
		// copy of current list of custom fields
		var customFields = self.fieldInfo[self.dataSource.mapid];
		if (!customFields) customFields = [];

		// list of variables names to change
		var changedNames = [];

		// popup instance
		var popup = $('#customFieldPopup').dxPopup('instance');

		// multiview instance
		var multiView = $('#multiView').dxMultiView('instance');

		// list of custom fields
		var fieldList = $('#customFieldList').dxDataGrid({
			height: 200,
			columns: [
				{
					caption: '필드명',
					dataField: 'Name'
				},
				{
					caption: '계산식',
					dataField: 'Expression'
				},
				{
					caption: '데이터 형식',
					dataField: 'DataType',
					width: '20%'
				}
			],
			dataSource: customFields,
			editing: {
				mode: 'row',
				allowDeleting: true,
				useIcons: true,
				texts: {
					confirmDeleteMessage: ''
				}
			},
			keyExpr: 'Name',
			// selection: {
			// 	mode:'single'
			// },
			onContentReady: function(){
				gDashboard.fontManager.setFontConfigForEditText('customFieldList')
			},
			onSelectionChanged: function(e) {
				var selectedField = e.selectedRowsData[0];
				if (selectedField) {
					$('#fieldName').val(selectedField.Name);
					$('#fieldCalc').val(selectedField.Expression);
				} else {
					$('#fieldName').val('');
					$('#fieldCalc').val('');
				}
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			}
		}).dxDataGrid('instance');

		// link view to calculation page
		$('#toCalcView').on('click', function() {
			var expression = $('#fieldCalc').val();
			$('#calcTextArea').val(expression);
			self.setCalcParameterList();
			popup.option('title', '계산식 편집');
			multiView.option('selectedIndex', 1);
		});
		/* dogfoot WHATIF 분석 매개변수 생성 버튼 클릭동작 shlim 20201022 */
		$('#createCalcParamBtn').on('click', function() {
			gDashboard.customParameterHandler.init()
			popup.option('title', '매개변수 생성');
			multiView.option('selectedIndex', 2);
		});

		// save field info to list
		$('#saveField').on('click', function() {
			self.addFieldToList(customFields, changedNames);
		});

		// confirm and cancel buttons
		$('a.edit-ok-hide').on('click', function() {
			var name = $('#fieldName').val();
			var expression = $('#fieldCalc').val();
			// case where field list is empty but field name and calcualtion exists
			if (name.length > 0 && expression.length > 0) {
				var success = self.addFieldToList(customFields, changedNames);
				if (!success) {
					return;
				}
			}
			var fields = fieldList.option('dataSource');
			self.fieldInfo[self.dataSource.mapid] = fields;
			self.updateFieldInfo(fields, true);
			self.updateChangedFields(changedNames);
			gDashboard.itemGenerateManager.clearTrackingConditionAll();
			/* DOGFOOT ktkang 주제영역 데이터 사용자정의 데이터 수정  20191212 */
			if(WISE.Context.isCubeReport) {
				gDashboard.queryByGeneratingSql = true;
			}
			/* dogfoot WHATIF 분석 매개변수 필터 버튼생성 shlim 20201022 */
			gDashboard.customParameterHandler.setCalcFilterButton(fields);
			
			gDashboard.query();
			popup.hide();
		});
		$('a.edit-close').on('click', function() {
			popup.hide();
		});
	}

    /**
     * Initialize calculator widgets and button events.
     */
    this.initCalcComponents = function() {
		// popup instance
		var popup = $('#customFieldPopup').dxPopup('instance');

		// multiview instance
		var multiView = $('#multiView').dxMultiView('instance');

        // selecting category type creates input list
        $('.select-type').on('click', function() {
            var inputList = $('.select-list.input-list');
            inputList.empty();
            var nameList = $('<ul />');
            var selectedType = $(this).text();
            var typeSet = self.functionList[selectedType];

            // case for functions list
            if (selectedType === '함수') {
            	//2020.04.06 MKSONG 사용자정의데이터 열 검색기능 추가 DOGFOOT
            	$('#fieldSearch').css('display', 'none');
                $('#selectCategory').empty();
                $('#selectCategory').css('display', 'inline-block');
                $.each(typeSet, function(category) {
                    $('#selectCategory').append('<option value="' + category + '">' + category + '</option>');
                });
                // set first category as default selected
                $('#selectCategory option[value="Arithmetic"]').prop('selected', true);

                var subTypeSet = typeSet[$('#selectCategory :selected').text()];
                $.each(subTypeSet, function(name) {
                    nameList.append('<li><a class="select-input">' + name + '</a></li>');
                });
				inputList.append(nameList);

				self.setInputClickEvents(subTypeSet);
				self.setInputDragEvents();

                // category changed
                $('#selectCategory').on('change', function() {
                    inputList.empty();
                    nameList.empty();
                    subTypeSet = typeSet[$(this).val()];
                    $.each(subTypeSet, function(name) {
                    	//2020.04.06 MKSONG mouse-icon 수정 DOGFOOT
                        nameList.append('<li><a class="select-input" href="#">' + name + '</a></li>');
                    });
					inputList.append(nameList);

					self.setInputClickEvents(subTypeSet);
					self.setInputDragEvents();
                });
            } 
            // case for everything else
            else {
            	//2020.04.06 MKSONG 사용자정의데이터 열 검색기능 추가 DOGFOOT
            	if (selectedType === '열') {
            		$('#fieldSearch').css('display', 'block');
            	}else{
            		$('#fieldSearch').css('display', 'none');
            	}
                $('#selectCategory').css('display', 'none');
                $.each(typeSet, function(name) {
                	//2020.04.06 MKSONG mouse-icon 수정 DOGFOOT
                    nameList.append('<li><a class="select-input" href="#">' + name + '</a></li>');
                });
				inputList.append(nameList);

				self.setInputClickEvents(typeSet);
				self.setInputDragEvents();
            }
        });

        // operator buttons
        $('.operator-button').on('click', function() {
            var input = $(this).attr('symbol');
            var inputArea = $('#calcTextArea');
			var position = 0;
			var el = inputArea.get(0);
			if('selectionStart' in el) {
				position = el.selectionStart;
			} else if('selection' in document) {
				el.focus();
				var Sel = document.selection.createRange();
				var SelLength = document.selection.createRange().text.length;
				Sel.moveStart('character', -el.value.length);
				position = Sel.text.length - SelLength;
			}
			inputArea.val(function(idx, txt) {
				return txt.substr(0, position) + input + txt.substr(position);
			});
			inputArea.prop('selectionStart', position + input.length);
            inputArea.prop('selectionEnd', position + input.length);
            inputArea.focus();
		});
		
		// confirm and cancel buttons
		$('a.calc-ok-hide').on('click', function() {
			$('#fieldCalc').val($('#calcTextArea').val());
			popup.option('title', '사용자 정의 데이터');
			multiView.option('selectedIndex', 0);         
		});
		$('a.calc-close').on('click', function() {
			popup.option('title', '사용자 정의 데이터');
			multiView.option('selectedIndex', 0);
		});
        /* dogfoot WHATIF 분석 매개변수 생성 확인 shlim 20201022 */
        $('a.paramCalc-ok-hide').on('click', function() {
			popup.option('title', '계산식 편집');
			if(gDashboard.customParameterHandler.setCalcParaminfomation()){
				self.setCalcParameterList();
				multiView.option('selectedIndex', 1);
			}else{
				WISE.alert('매개변수 명이 중복 되었습니다.');
			}
			         
		});
		/* dogfoot WHATIF 분석 매개변수 생성 취소 shlim 20201022 */
		$('a.paramCalc-close').on('click', function() {
			$('#calcParamItemDescArea').empty();
			self.setCalcParameterList();
			popup.option('title', '계산식 편집');
			multiView.option('selectedIndex', 1);
		});
		
		

		/* DOGFOOT hsshim 2020-02-13 jQuery scrollbar -> dxScrollView 변경 */
		$('#scroll-content').dxScrollView();
    }

	/**
	 * Initialize on-click events for the field calculator.
	 */
    this.setInputClickEvents = function(typeSet) {
        // input single-click
        $('.select-input').on('click', function() {
            var description = typeSet[$(this).text()];
            $('#descriptionText').text(description);
        });
        // input double-click
        $('.select-input').on('dblclick', function() {
            var input = $(this).text();
            var inputArea = $('#calcTextArea');
			var position = 0;
			var el = inputArea.get(0);
			if('selectionStart' in el) {
				position = el.selectionStart;
			} else if('selection' in document) {
				el.focus();
				var Sel = document.selection.createRange();
				var SelLength = document.selection.createRange().text.length;
				Sel.moveStart('character', -el.value.length);
				position = Sel.text.length - SelLength;
			}
			inputArea.val(function(idx, txt) {
				return txt.substr(0, position) + input + txt.substr(position);
			});
			inputArea.prop('selectionStart', position + input.length);
            inputArea.prop('selectionEnd', position + input.length);
            inputArea.focus();
        });
	}
	
	this.setInputDragEvents = function() {
		$('.select-input').draggable({
			connectToSortable: '#calcTextArea',
			appendTo: 'body',
			zIndex: 9999,
			scroll: false,
			revert: 'invalid',
			helper: 'clone',
		});
		// $('.select-input').on('mousedown', function(e) {
		// 	e.dataTransfer.setData("text", $(this).text());
		// });
		$('#calcTextArea').droppable({
			drop: function(e, ui) {
				var el = $(this).get(0);
				var position = 0;
				if('selectionStart' in el) {
					position = el.selectionStart;
				} else if('selection' in document) {
					el.focus();
					var Sel = document.selection.createRange();
					var SelLength = document.selection.createRange().text.length;
					Sel.moveStart('character', -el.value.length);
					position = Sel.text.length - SelLength;
				}
				$(this).val(function(idx, txt) {
					return txt.substr(0, position) + ui.draggable.text() + txt.substr(position);
				});
			}
		});
	}

	/* DOGFOOT hsshim 200103 사용자 정의 데이터 집합 기능 개선 */
	/**
	 * Get data source object under dataSourceId and load it to CustomFieldManager.
	 * If undefined, get the currently selected data source object.
	 */
    this.setDataSourceInfo = function(dataSourceId) {
//        var dsInfoList = gDashboard.dataSourceManager.datasetInformation;
        var dsInfoList = (WISE.Context.isCubeReport)?gDashboard.dataSourceManager.datasetInformation:gDashboard.datasetMaster.getState('dataset').datasets;
        /* DOGFOOT ktkang 지도 오류 수정  20200923 */
        if(Object.keys(dsInfoList).length == 0 || dsInfoList.length === 0) {
        	return;
        }
		
        if(WISE.Constants.editmode == 'spreadsheet') return;
        
        if (dataSourceId) {
			self.dataSourceName = dsInfoList[dataSourceId].DATASET_NM;
		} else {
			if(WISE.Constants.editmode != 'viewer'){
				self.dataSourceName = $('#dataSetLookUp').dxLookup('instance').option('text');	
			}
        }
        /* DOGFOOT hsshim 2020-01-15 끝 */
        
        //2020.04.09 mksong 비정형 사용자정의데이터 열 불러오기 수정 dogfoot
        if(WISE.Context.isCubeReport){
        	  $.each(dsInfoList, function(dsName, dsInfo) {
                  if (self.dataSourceName === dsInfo.DATASET_NM) {
                	  self.functionList['열'] = {};
                      self.dataSource = dsInfo;
                      $.each(gDashboard.fieldManager.stateFieldChooser.find('.analysis-data'), function(_i,_field){
                    	 var field = $(_field);
                    	 /* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
                    	 var agg = field.find('.more-link').children('.on');
                		 if(field.children().attr('data-field-type') == 'measure' && (agg.text() == '합계' || agg.text() == '')){
                			 self.functionList['열']['['+ (field.find('li').attr('uni_nm') || field.text())  + ']'] = '필드 형식: decimal';	 
                		 }else if(field.children().attr('data-field-type') == 'dimension'){
                			 self.functionList['열']['['+ field.find('li').attr('uni_nm')  + ']'] = '필드 형식: varchar';
                		 }
                		 /*20200916 ajkim 사용자 정의 데이터 오류 수정*/
                		 else if(field.children().attr('data-field-type') == 'measure' && field.parent().attr("id").indexOf("Value") === -1){
                			 self.functionList['열']['['+ field.find('li').attr('uni_nm')  + ']'] = '필드 형식: decimal';
                		 }
                      });
                  }
              });
        }else{
        	  $.each(dsInfoList, function(dsName, dsInfo) {
                  if (self.dataSourceName === dsInfo.DATASET_NM) {
                      self.dataSource = dsInfo;
                      var dsTreeInfo = gDashboard.dataSetCreate.infoTreeList[self.dataSourceName];
                      /* DOGFOOT hsshim 1231
      				 * "필드" -> "열" 
      				 */
                      self.functionList['열'] = {};
                      // new report
                      $.each(gDashboard.fieldManager.stateFieldChooser.find('.analysis-data'), function(_i,_field){
                    	  	var field = $(_field);
                    	  	/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
	                       	 var agg = field.find('.more-link').children('.on');
	                       	 if(agg.length > 1){
	                             $.each(field.find('.wise-column-chooser'),function(_i,_ag){
	                             	var added = [];
	                             	added.push(_ag);
	                             	if(field.find('.wise-column-chooser').attr('data-search-flag') == 'Y') {
	 									 if(field.find('.wise-column-chooser').attr('data-field-type') == 'measure' && (agg[_i].innerText == '합계' || agg[_i].innerText == '')){
	 										 self.functionList['열']['['+ _ag.innerText  + ']'] = '필드 형식: decimal';	 
	 									 }else if(field.children().attr('data-field-type') == 'dimension'){
	 										 self.functionList['열']['['+ _ag.innerText  + ']'] = '필드 형식: varchar';
	 									 } /*20200916 ajkim 사용자 정의 데이터 오류 수정*/
	 			                		 else if(field.children().attr('data-field-type') == 'measure' && field.parent().attr("id").indexOf("Value") === -1){
	 			                			 self.functionList['열']['['+ field.find('.fieldName').text()  + ']'] = '필드 형식: varchar';
	 			                		 }
	 								 }
	                             })
	                       	 }else{
	                       	 	if(field.children().attr('data-search-flag') == 'Y') {
	 								 if(field.children().attr('data-field-type') == 'measure' && (agg.text() == '합계' || agg.text() == '')){
	 									 self.functionList['열']['['+ (field.find('li').attr('uni_nm') || field.text()) + ']'] = '필드 형식: decimal';	 
	 								 }else if(field.children().attr('data-field-type') == 'dimension'){
	 									 self.functionList['열']['['+ field.find('li').attr('uni_nm')  + ']'] = '필드 형식: varchar';
	 								 } /*20200916 ajkim 사용자 정의 데이터 오류 수정*/
	 		                		 else if(field.children().attr('data-field-type') == 'measure' && field.parent().attr("id").indexOf("Value") === -1){
	 		                			 self.functionList['열']['['+ field.find('li').attr('uni_nm')  + ']'] = '필드 형식: varchar';
	 		                		 }
	 							 }
	                       	 }
                      });
                  }
              });
        }
      
	}

	/* DOGFOOT hsshim 200103 끝 */
	
	/**
	 * Get the data set's original fields (ie. without custom fields).
	 */
	this.setOriginalFieldInfo = function() {
		var fieldInfo = gDashboard.dataSetCreate.infoTreeList[self.dataSourceName];
		if (typeof fieldInfo === 'undefined') {
			return;
		}
		var retFieldInfo = JSON.parse(JSON.stringify(fieldInfo));
		var customFieldInfo = self.fieldInfo[self.dataSource.mapid] ? self.fieldInfo[self.dataSource.mapid] : [];
		if((gDashboard.reportType == "DashAny" && userJsonObject.menuconfig.Menu.DASH_DATA_FIELD)  || gDashboard.reportType == 'DSViewer'){
			if(typeof self.fieldInfo[self.dataSource.mapid] == 'undefined')
			    self.fieldInfo[self.dataSource.mapid] = [];
		}
		var noMoreCustomValues = customFieldInfo.length > 0 ? false : true;
		for (var i = retFieldInfo.length - 1; i > 0; i--) {
			for (var j = 0; j < customFieldInfo.length; j++) {
				if (retFieldInfo[i]['CAPTION'] === customFieldInfo[j]['Name']) {
					retFieldInfo.pop();
					break;
				}
				if (j === customFieldInfo.length - 1) {
					noMoreCustomValues = true;
				}
			}
			if (noMoreCustomValues) {
				break;
			}
		}
		self.originalFieldInfo = retFieldInfo;
	}
	
	this.setOriginalFieldInfo = function() {
		var fieldInfo = gDashboard.dataSetCreate.infoTreeList[self.dataSourceName];
		if (typeof fieldInfo === 'undefined') {
			return;
		}
		var retFieldInfo = JSON.parse(JSON.stringify(fieldInfo));
		var customFieldInfo = self.fieldInfo[self.dataSource.mapid] ? self.fieldInfo[self.dataSource.mapid] : [];
		var noMoreCustomValues = customFieldInfo.length > 0 ? false : true;
		for (var i = retFieldInfo.length - 1; i > 0; i--) {
			for (var j = 0; j < customFieldInfo.length; j++) {
				if (retFieldInfo[i]['CAPTION'] === customFieldInfo[j]['Name']) {
					retFieldInfo.pop();
					break;
				}
				if (j === customFieldInfo.length - 1) {
					noMoreCustomValues = true;
				}
			}
			if (noMoreCustomValues) {
				break;
			}
		}
		self.originalFieldInfo = retFieldInfo;
	}

	/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 리스트 겹치는 오류 수정 */
	/**
	 * Helper function for updateFieldInfo(). Return the highest parent node order in a dataset tree.
	 */
	this.getHighestDatasetTreeNodeOrder = function(dataTree) {
		var max = -1;
		for (var node in dataTree) {
			if ((node.TYPE == undefined || node.TYPE === '') && max < node.ORDER ) {
				max = node.ORDER;
			}
		}
		return max;
	}

	/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 리스트 겹치는 오류 수정 */
	/**
	 * Function for cube datasets.
	 * Add the currently generated field to the list of fields for drag & drop operations.
	 */
    this.updateCubeFieldInfo = function(newFields, saveToLayout) {
		var dataSet = gDashboard.dataSetCreate,
			dataSetName = self.dataSource.DATASET_NM,
			dataSourceId = self.dataSource.mapid;
		var dataSources = gDashboard.structure.DataSources.DataSource;
		//2020.04.09 MKSONG 신규보고서 사용자정의데이터 추가 기능 수정 DOGFOOT
		if(!gDashboard.isNewReport && gDashboard.reportType == 'AdHoc'){
			for (var i = 0; i < dataSources.length; i++) {
				if (dataSourceId === dataSources[i].ComponentName) {
					// clear previous custom field info from dashboard layout info
					if (saveToLayout) {
						dataSources[i].CalculatedFields = { CalculatedField: [] };
					}

					if (newFields.length > 0) {
						var customFieldParentNode = {
							CAPTION: '계산된 필드',
							ORDER: this.getHighestDatasetTreeNodeOrder(dataSet.infoTreeList[dataSetName]) + 1,
							expanded: true,
							DATASOURCE: dataSourceId,
						}
						/* DOGFOOT ktkang 비정형 사용자 정의 데이터 오류 수정  20201013 */
						if(typeof self.originalFieldInfo[self.originalFieldInfo.length-1] != 'undefined' && 
								self.originalFieldInfo[self.originalFieldInfo.length-1].CAPTION != customFieldParentNode.CAPTION){
							self.originalFieldInfo.push(customFieldParentNode)	
						}

						$.each(newFields, function(j, field) {
							var fld_type = "";
							if(WISE.Context.isCubeReport) {
								fld_type = 'CUBE';
							}
							var fieldInfo = {
								CAPTION: field.Name,
								DATA_TYPE: field.DataType,
								ORDER: self.originalFieldInfo.length,
								PARENT_ID: 0,
								TYPE: (field.DataType === 'Decimal') ? 'MEA' : 'DIM',
								UNI_NM: field.Name,
								CUBE_UNI_NM: field.Name,
								icon: '',
								//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
								FLD_TYPE: fld_type,
								isCustomField: true
							};
							self.originalFieldInfo.push(fieldInfo);
							// save calculation field to dashboard layout info
							if (saveToLayout) {
								dataSources[i].CalculatedFields.CalculatedField.push(field);
							}
						});
					}
					break;
				}
			}
		}else{
			if (newFields.length > 0) {
				var customFieldParentNode = {
					CAPTION: '계산된 필드',
					ORDER: this.getHighestDatasetTreeNodeOrder(dataSet.infoTreeList[dataSetName]) + 1,
					expanded: true,
					DATASOURCE: dataSourceId,
				}
				/* DOGFOOT ktkang 비정형 사용자 정의 데이터 오류 수정  20201023 */
				if(typeof self.originalFieldInfo[self.originalFieldInfo.length-1] != 'undefined' && self.originalFieldInfo[self.originalFieldInfo.length-1].CAPTION != customFieldParentNode.CAPTION){
					self.originalFieldInfo.push(customFieldParentNode)	
				}

				$.each(newFields, function(j, field) {
					var fld_type = "";
					if(WISE.Context.isCubeReport) {
						fld_type = 'CUBE';
					}
					var fieldInfo = {
						CAPTION: field.Name,
						DATA_TYPE: field.DataType,
						ORDER: self.originalFieldInfo.length,
						PARENT_ID: 0,
						TYPE: (field.DataType === 'Decimal') ? 'MEA' : 'DIM',
						UNI_NM: field.Name,
						CUBE_UNI_NM: field.Name,
						icon: '',
						//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
						FLD_TYPE: fld_type,
						isCustomField: true
					};
					self.originalFieldInfo.push(fieldInfo);
				});
			}
		}
		//2020.04.09 MKSONG 신규보고서 사용자정의데이터 추가 기능 수정 끝 DOGFOOT
		
		// save field info tree to dataset info
		if (WISE.Constants.editmode === 'designer') {
			dataSet.infoTreeList[dataSetName] = self.originalFieldInfo;
			//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
			$('.drop-down.tree-menu ul').empty();
			var cubeDs = new WISE.libs.CubeData();
			cubeDs.insertDataSet(dataSet.infoTreeList[dataSetName], dataSourceId);
			//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
			gDashboard.dragNdropController.cubeRelationCheck();
			compMoreMenuUi();
			/*dogfoot 비정형 주제영역 뷰어 사용자 정의 데이터 항목 나오도록 수정 shlim 20210408*/
		}else if(WISE.Constants.editmode === 'viewer'){
			$('#dataArea_'+gDashboard.structure.ReportMasterInfo.id).find('.drop-down.tree-menu ul').empty();
			dataSet.infoTreeList[dataSetName] = self.originalFieldInfo;
			var cubeDs = new WISE.libs.CubeData();
			cubeDs.insertDataSet(dataSet.infoTreeList[dataSetName], dataSourceId);
		}
	}

	/**
	 * Add the currently generated field to the list of fields for drag & drop operations.
	 */
    this.updateFieldInfo = function(newFields, saveToLayout) {
		/* DOGFOOT hsshim 2020-01-13 주제영역 사용자 정의 데이터 리스트 겹치는 오류 수정 */
		// redirect to cube field info updater if report uses OLAP database
		if (WISE.Context.isCubeReport) {
			return self.updateCubeFieldInfo(newFields, saveToLayout);
		}
		var dataSet = gDashboard.dataSetCreate,
			dataSetName = self.dataSource.DATASET_NM,
			/* DOGFOOT hsshim 2020-01-13 사용자 정의 데이터 개선 */
			dataSourceId = self.dataSource.mapid,
			dataSources = gDashboard.structure.DataSources.DataSource;

		for (var i = 0; i < dataSources.length; i++) {
			/* DOGFOOT hsshim 2020-01-13 사용자 정의 데이터 개선 */
			if (dataSourceId === dataSources[i].ComponentName) {
				// clear previous custom field info from dashboard layout info
				if (saveToLayout) {
					dataSources[i].CalculatedFields = { CalculatedField: [] };
				}

				$.each(newFields, function(j, field) {
					/* DOGFOOT ktkang 주제영역 데이터 사용자정의 데이터 수정  20191212 */
					var fld_type = "";
					if(WISE.Context.isCubeReport) {
						fld_type = 'CUBE';
					}
					var fieldInfo = {
						CAPTION: field.Name,
						DATA_TYPE: field.DataType,
						ORDER: self.originalFieldInfo.length,
						PARENT_ID: 0,
						TYPE: (field.DataType === 'Decimal') ? 'MEA' : 'DIM',
						/* DOGFOOT hsshim 2020-01-13 사용자 정의 데이터 개선 */
						UNI_NM: field.Name,
						icon: '',
						/*dogfoot 사용자정의 데이터  구분자 추가 shlim 20200716*/
						FLD_TYPE: fld_type,
						CUSTOM_DATA: true
					};
					
					/* goyong ktkang 사용자 정의 데이터 똑같은 이름 추가 시 오류 수정  20210518 */
					var dupleNumber = [];
					$.each(self.originalFieldInfo, function(_i, _e) {
						if(typeof _e.CAPTION != 'undefined' && field.Name == _e.CAPTION) {
							dupleNumber.push(_i);
						}
					});
					
					if(dupleNumber.length > 0) {
						$.each(dupleNumber, function(_i, _e) {
							self.originalFieldInfo.splice(_e, 1);
						});
					}
					
					self.originalFieldInfo.push(fieldInfo);
					// save calculation field to dashboard layout info
					if (saveToLayout) {
						dataSources[i].CalculatedFields.CalculatedField.push(field);
					}
				});
				break;
			}
		}
		// save field info tree to dataset info
		/* DOGFOOT hsshim 2020-01-13 'editor' -> 'designer' 변경 */
		if (WISE.Constants.editmode === 'designer') {
			dataSet.infoTreeList[dataSetName] = self.originalFieldInfo;
			//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
			$('.drop-down.tree-menu ul').empty();
			/* DOGFOOT hsshim 2020-01-13 사용자 정의 데이터 개선 */
			dataSet.insertDataSet(dataSet.infoTreeList[dataSetName], dataSourceId);
		}
	}
	
	/**
	 * Return a newly generated custom field object.
	 * If calculation is invalid, return false.
	 */
	this.createNewField = function(name, input, data) {
		try {
			// parse fields from input
            var re  = /\[([^\]]*)]/g,
                matches = [],
                scope = {},
                mapping = {},
                mapCount = 0,
				newInput = input,
				/* DOGFOOT hsshim 1231
				 * 사용자 정의 데이터 개선
				 */
                newFieldType,
                newFieldName = name,
                newFieldInfo = { 
					Name: newFieldName, 
					Expression: input, 
					DataType: '' 
				},
				result;
			/* dogfoot WHATIF 분석 매개변수 사용 계산식 치환 shlim 20201022 */	
            input = self.repCalcParam(input);
            newInput = input;
				/* DOGFOOT hsshim 1231 끝 */
            while (m = re.exec(input)) {
                var swap = new RegExp('\\[' + m[1]  + ']', 'g');
                if (!mapping[m[1]]) {
                    var newVar = '_v' + mapCount++;
                    matches.push(m[1]);
                    mapping[m[1]] = newVar;
                    // required because Math.js doesn't support Korean characters
                    newInput = newInput.replace(swap, newVar);
                    newInput = WISE.util.String.replaceAll(newInput, m[0], newVar);
                }
            /* DOGFOOT hsshim 1231
			 * 사용자 정의 데이터 집계 함수 확인하는 기능 추가
			 */
			}
			// if input has summary type, set value to 0
			if (self.hasSummaryTypeFunction(newInput)) {
				$.each(matches, function(fIndex, field) {
					scope[mapping[field]] = _.map(data, field);
				});
			} else {
				// add new values to data
				var sample = data[0];
				var keys = Object.keys(sample);
				$.each(keys, function(i, k) {
				    if (k.indexOf('sum_') > -1) {
				        sample[k.replace('sum_','')] = sample[k];
				        delete sample[k];
				    } else if(k.indexOf('count_') > -1) {
				        sample[k.replace('count_','')] = sample[k];
				        delete sample[k];
				    } else if(k.indexOf('countdistinct_') > -1) {
				        sample[k.replace('countdistinct_','')] = sample[k];
				        delete sample[k];
				    } else if(k.indexOf('min_') > -1) {
				        sample[k.replace('min_','')] = sample[k];
				        delete sample[k];
				    } else if(k.indexOf('max_') > -1) {
				        sample[k.replace('max_','')] = sample[k];
				        delete sample[k];
				    } else if(k.indexOf('avg_') > -1) {
				        sample[k.replace('avg_','')] = sample[k];
				        delete sample[k];
				    }
				});
				
				$.each(matches, function(fIndex, field) {
					if(typeof sample[field] == 'string'){
						scope[mapping[field]] = 0;
					}else{
						scope[mapping[field]] = sample[field];
					}
				});
			}
			/* DOGFOOT hsshim 1231 끝 */
			result = secureEval(newInput, scope);
			// set field type
			switch(typeof result) {
				case 'number':
					newFieldType = 'Decimal';
					break;
				case 'string':
					newFieldType = 'Varchar';
					break;
				case 'boolean':
					newFieldType = 'Boolean';
					break;
				default:
					/* DOGFOOT hsshim 1231
					 * 사용자 정의 데이터 개선
					 */
					newFieldType = 'Auto';
					break;
			}
			newFieldInfo.DataType = newFieldType;
		} catch(e) {
			console.error(e);
			return false;
		}
		return newFieldInfo;
	}

	/**
	 * If name and calculation fields make a valid non-duplicate field, add it to the list of custom fields. Returns true if successful, otherwise returns false.
	 */
	this.addFieldToList = function(customFields, changedNames) {
		var fieldList = $('#customFieldList').dxDataGrid('instance');
		var popup = $('#customFieldPopup').dxPopup('instance');
		var name = $('#fieldName').val();
		var expression = $('#fieldCalc').val();
		var data = self.dataSource.data && self.dataSource.data.length>0 ? self.dataSource.data : gDashboard.itemGenerateManager.focusedItem.globalData;
		/* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730*/
		if(typeof data == 'undefined' || data.length === 0) {
			if(gDashboard.reportType == 'AdHoc') {
				$.each(gDashboard.itemGenerateManager.dxItemBasten, function(_i, _e) {
					if(_e.kind == 'pivotGrid') {
						data = _e.filteredData;
					}
				});
			} else {
				data = gDashboard.itemGenerateManager.focusedItem.filteredData;
			}
		}
		// check for null values
		if (name !== '' && expression !== '') {
			var newFieldInfo = self.createNewField(name, expression, data);
			// check for duplicate names from original fields
			if (self.equalsOriginalFieldName(name)) {
				/* goyong ktkang 사용자 정의 데이터 똑같은 이름 추가 시 오류 수정  20210518 */
				var message = '같은 이름의 사용자 정의 데이터가 존재합니다.\n';
				message += '계산식을 변경하시겠습니까?';
				var options = {
					buttons: {
						confirm: {
							id: 'confirm',
							className: 'blue',
							text: '확인',
							action: function() {
								if (data == undefined || data.length === 0) {
									WISE.alert('조회된 데이터가 부족합니다.');
									$AlertPopup.hide();
									return false;
								} else {
									WISE.alert('계산식이 잘못 되어 있습니다.');
									$AlertPopup.hide();
									return false;
								}
								
								var selected = fieldList.getSelectedRowsData();
								var selectedIndex = -1;
								// check for field selection
								if (selected.length > 0) {
									selectedIndex = fieldList.getRowIndexByKey(selected[0].Name);
								}
								// check for duplicate custom names
								var listSize = customFields.length;
								for (var i = 0; i <= listSize; i++) {
									if (i === listSize) {
										if (selectedIndex >= 0) {
											// update selected field
											var oldName = customFields[selectedIndex].Name,
												newName = newFieldInfo.Name;
											var temp = {};
											temp[oldName] = newName;
											changedNames.push(temp);
											customFields[selectedIndex] = newFieldInfo;
											fieldList.option('dataSource', customFields);
											fieldList.clearSelection();
											$('#fieldName').val('');
											$('#fieldCalc').val('');
										} else {
											// add new field
											customFields.push(newFieldInfo);
											fieldList.option('dataSource', customFields);
											fieldList.clearSelection();
											$('#fieldName').val('');
											$('#fieldCalc').val('');
										}
									}
								}
								$AlertPopup.hide();
							}
						},
						cancel: {
							id: 'cancel',
							className: 'negative',
							text: '취소',
							action: function() {
								$AlertPopup.hide();
							}
						}
					}
				};
					
				WISE.confirm(message, options);
			} else if (newFieldInfo) {
				var selected = fieldList.getSelectedRowsData();
				var selectedIndex = -1;
				// check for field selection
				if (selected.length > 0) {
					selectedIndex = fieldList.getRowIndexByKey(selected[0].Name);
				}
				// check for duplicate custom names
				var listSize = customFields.length;
				for (var i = 0; i <= listSize; i++) {
					if (i === listSize) {
						if (selectedIndex >= 0) {
							// update selected field
							var oldName = customFields[selectedIndex].Name,
								newName = newFieldInfo.Name;
							var temp = {};
							temp[oldName] = newName;
							changedNames.push(temp);
							customFields[selectedIndex] = newFieldInfo;
							fieldList.option('dataSource', customFields);
							fieldList.clearSelection();
							$('#fieldName').val('');
							$('#fieldCalc').val('');
						} else {
							// add new field
							customFields.push(newFieldInfo);
							fieldList.option('dataSource', customFields);
							fieldList.clearSelection();
							$('#fieldName').val('');
							$('#fieldCalc').val('');
						}
					}
					else if (i !== selectedIndex && customFields[i].Name === name) {
						WISE.alert('중복이름 입니다. 이름 다시 선택해주세요.');
						return false;
					}
				}
			} else {
				/* DOGFOOT hsshim 2020-01-13 데이터 없는 경우 알림 추가 */
				if (data == undefined || data.length === 0) {
					WISE.alert('조회된 데이터가 부족합니다.');
				} else {
					WISE.alert('계산식이 잘못 되어 있습니다.');
				}
				return false;
			}
		} else {
			WISE.alert('이름이나 계산필드가 비어있습니다.');
			return false;
		}
		return true;
	}
	
	//2020.02.04 mksong SQLLIKE doSqlLike 사용자정의데이터 적용 dogfoot
	this.trackingDatafields = function(fieldInfo) {
        try {
            // parse fields from input
            var re  = /\[([^\]]*)]/g,
                matches = [],
                scope = {},
                mapping = {},
                mapCount = 0,
                input = fieldInfo.Expression,
                newInput = input,
                /* DOGFOOT hsshim 1231
				 * 사용자 정의 데이터 개선
				 */
				fieldName = fieldInfo.Name,
				result;
            /* dogfoot WHATIF 분석 매개변수 사용 계산식 치환 shlim 20201022 */	
            input = self.repCalcParam(input);
            newInput = input;
            while (m = re.exec(input)) {
                var swap = new RegExp('\\[' + m[1]  + ']', 'g');
                if (!mapping[m[1]]) {
                    var newVar = '_v' + mapCount++;
                    matches.push(m[1]);
                }
            }
            // add new values to data
        } catch(error) {
       		/* DOGFOOT hsshim 2020-01-13 사용자 정의 데이터 개선 */
			console.error(error.stack);
			//2020.01.31 MKSONG 오타 수정 DOGFOOT
			WISE.alert('사용자 정의 데이터 계산을 실패 했습니다.');
        }
        return matches;
	}
	
    /**
     * Add custom field data to the item's data source.
     */
    this.addCustomFieldsToDataSource = function(fieldInfo, data, calculatedFields) {
        try {
            // parse fields from input
            var re  = /\[([^\]]*)]/g,
                matches = [],
                scope = {},
                mapping = {},
                mapCount = 0,
                input = fieldInfo.Expression,
                newInput = input,
                /* DOGFOOT hsshim 1231
				 * 사용자 정의 데이터 개선
				 */
				fieldName = fieldInfo.Name,
				result;
			/* dogfoot WHATIF 분석 매개변수 사용 계산식 치환 shlim 20201022 */	
            input = self.repCalcParam(input);
            newInput = input;
            while (m = re.exec(input)) {
                var swap = new RegExp('\\[' + m[1]  + ']', 'g');
                if (!mapping[m[1]]) {
                    var newVar = '_v' + mapCount++;
                    matches.push(m[1]);
                    mapping[m[1]] = newVar;
                    // required because Math.js doesn't support Korean characters
                    newInput = newInput.replace(swap, newVar);
                    newInput = WISE.util.String.replaceAll(newInput, m[0], newVar);
                }
            }
            // add new values to data
            var unmappingField = [];
            $.each(data, function(i, e) {
            	/* DOGFOOT hsshim 1231
				 * 사용자 정의 데이터 집계 함수 확인하는 기능 추가
				 */
				if (self.hasSummaryTypeFunction(newInput)) {
					result = 0;
				} else {
					/* goyong ktkang 사용자정의데이터에 매핑안되어있는 차원 알림창에 추가  20210607 */
					$.each(matches, function(fIndex, field) {
						var fieldNm = field
							.replace('sum_', '')
							.replace('count_', '')
							.replace('countdistinct_', '')
							.replace('min_', '')
							.replace('max_', '')
							.replace('avg_', '');
						/* goyong ktkang 사용자정의데이터에 매핑안되어있는 차원 알림창에 추가  20210607 */
						if(typeof e[fieldNm] === 'undefined') {
							if(unmappingField.indexOf(fieldNm) < 0) {
								unmappingField.push(fieldNm);
							}
						}
						/*dogfoot null value 들어올때 계산 오류 수정 shlim 20210421*/
						if(typeof e[fieldNm] == 'string'){
							scope[mapping[fieldNm]] = 0;
						}else{
							scope[mapping[fieldNm]] = e[fieldNm];
						}
					});
					/* goyong ktkang 사용자정의데이터에 매핑안되어있는 차원 알림창에 추가  20210607 */
					if(unmappingField.length > 0){
						return false;
					}else{
						result = secureEval(newInput, scope);
					}
				}
				if(result)
					e[fieldName] = result;
				/* DOGFOOT hsshim 1231 끝 */
            });
            
            if(unmappingField.length > 0 && (gDashboard.reportType == 'DashAny' && !WISE.Context.isCubeReport)){
				var unmapString = '(';
				$.each(unmappingField, function(_ii, _ee) {
					unmapString += _ee + ',';
				});
				unmapString = unmapString.substring(0, unmapString.length -1);
				unmapString += ')';
				gProgressbar.hide();
				WISE.alert("사용자 정의 데이터에 참조되어 있는 필드가 존재하지 않습니다." + unmapString);
            }
        } catch(error) {
       		/* DOGFOOT hsshim 2020-01-13 사용자 정의 데이터 개선 */
			console.error(error.stack);
			//2020.01.31 MKSONG 오타 수정 DOGFOOT
			WISE.alert('사용자 정의 데이터 계산을 실패 했습니다.');
        }
	}
    
    this.addCustomTotalFieldsToDataSource = function(fieldInfo, data) {
        try {
            // parse fields from input
            var re  = /\[([^\]]*)]/g,
                matches = [],
                scope = {},
                mapping = {},
                mapCount = 0,
                input = fieldInfo.Expression,
                newInput = input,
                /* DOGFOOT hsshim 1231
				 * 사용자 정의 데이터 개선
				 */
				fieldName = fieldInfo.Name,
				result;
			/* dogfoot WHATIF 분석 매개변수 사용 계산식 치환 shlim 20201022 */	
            input = self.repCalcParam(input);
            newInput = input;
            while (m = re.exec(input)) {
                var swap = new RegExp('\\[' + m[1]  + ']', 'g');
                if (!mapping[m[1]]) {
                    var newVar = '_v' + mapCount++;
                    matches.push(m[1]);
                    mapping[m[1]] = newVar;
                    // required because Math.js doesn't support Korean characters
                    newInput = newInput.replace(swap, newVar);
                    newInput = WISE.util.String.replaceAll(newInput, m[0], newVar);
                }
            }
            // add new values to data
            $.each(data, function(i, e) {
            	/* DOGFOOT hsshim 1231
				 * 사용자 정의 데이터 집계 함수 확인하는 기능 추가
				 */
				if (self.hasSummaryTypeFunction(newInput)) {
					result = 0;
				} else {
					/* goyong ktkang 사용자정의데이터에 매핑안되어있는 차원 알림창에 추가  20210607 */
					var unmappingField = [];
					$.each(matches, function(fIndex, field) {
						var fieldNm = field
							.replace('sum_', '')
							.replace('count_', '')
							.replace('countdistinct_', '')
							.replace('min_', '')
							.replace('max_', '')
							.replace('avg_', '');
						if(typeof e[fieldNm] === 'undefined') {
							unmappingField.push(fieldNm);
							return false;
						}
						scope[mapping[fieldNm]] = e[fieldNm];
					});
					if(unmappingField.length > 0){
						return false;
					}else{
						result = secureEval(newInput, scope);
					}
				}
				if(result)
					e[fieldName] = result;
				/* DOGFOOT hsshim 1231 끝 */
            });
        } catch(error) {
       		/* DOGFOOT hsshim 2020-01-13 사용자 정의 데이터 개선 */
			console.error(error.stack);
			//2020.01.31 MKSONG 오타 수정 DOGFOOT
			WISE.alert('사용자 정의 데이터 계산을 실패 했습니다.');
        }
	}
    
    /* DOGFOOT ktkang 사용자 정의 데이터 오류 수정  20200730 */
    /* DOGFOOT shlim 사용자 정의 데이터 정렬기준항목으로 생성 가능하도록 수정  20210121 */
    this.addCustomFieldsToDataSourceForSummaryValue = function(fieldInfo, data, fieldOption, measures, dimensions,hiddenMeasure) {
        try {
            // parse fields from input
            var re  = /\[([^\]]*)]/g,
                matches = [],
                scope = {},
                mapping = {},
                mapCount = 0,
                input = fieldInfo.Expression,
                newInput = input,
                /* DOGFOOT hsshim 1231
				 * 사용자 정의 데이터 개선
				 */
				fieldName = fieldInfo.Name,
				result;
			/* dogfoot WHATIF 분석 매개변수 사용 계산식 치환 shlim 20201022 */	
            input = self.repCalcParam(input);
            newInput = input;
            /*dogfoot shlim 20210419*/
            var fieldNameBySummary = fieldOption.nameBySummaryType2;
            if(typeof fieldNameBySummary == 'undefined') {
            	fieldNameBySummary = fieldOption.caption;
            }
            while (m = re.exec(input)) {
                var swap = new RegExp('\\[' + m[1]  + ']', 'g');
                if (!mapping[m[1]]) {
                	var newVar = '_v' + mapCount++;
                	$.each(measures, function(_i,_measure){
	                	/*dogfoot shlim 20210419*/
                		if(m[1] == _measure.name){
                			/*dogfoot shlim 20210419*/
                			var autoCustom = false;
                			var autoCustomName = '';
                			$.each(gDashboard.customFieldManager.fieldNameList, function(_ii, _ee){
                				if(typeof data[0][_measure.nameBySummaryType2] != 'undefined') {
                					autoCustom = false;
                				} else {
                					var measureName = _measure.nameBySummaryType2.replace(_measure.summaryType + '_', '');
                					if(measureName == _ee) {
                						autoCustom = true;
                						autoCustomName = _ee;
                					}
                				}
                			});
                			if(autoCustom) {
                				matches.push(autoCustomName);
                				if(mapping[autoCustomName] == undefined){
                    				mapping[autoCustomName] = newVar;	
                    			}
                			} else {
                				matches.push(_measure.nameBySummaryType2);
                    			//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
                    			if(mapping[_measure.nameBySummaryType2] == undefined){
                    				mapping[_measure.nameBySummaryType2] = newVar;	
                    			}
                			}
                		}
                	});
                	
                	$.each(dimensions, function(_i,_dimension){
                		if(m[1] == _dimension.caption){
                			matches.push(_dimension.caption);
                			//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
                			if(mapping[_dimension.caption] == undefined){
                				mapping[_dimension.caption] = newVar;	
                			}
                		}
                	});
                	
                	$.each(hiddenMeasure, function(_i,_hiddenMeasure){
                		if(m[1] == _hiddenMeasure.caption){
		               		/* dogfoot 사용자정의 데이터 정렬기준항목에 있을때도 적용되도록 수정  20210201*/
                			matches.push(_hiddenMeasure.nameBySummaryType);
                			//2020.04.09 mksong 비정형 사용자정의데이터 오류 수정 dogfoot
                			if(mapping[_hiddenMeasure.nameBySummaryType] == undefined){
                				mapping[_hiddenMeasure.nameBySummaryType] = newVar;	
                			}
                		}
                	});
                	
                    // required because Math.js doesn't support Korean characters
                    newInput = newInput.replace(swap, newVar);
                    newInput = WISE.util.String.replaceAll(newInput, m[0], newVar);
                }
            }
            // add new values to data
            $.each(data, function(i, e) {
            	/* DOGFOOT hsshim 1231
				 * 사용자 정의 데이터 집계 함수 확인하는 기능 추가
				 */
				if (self.hasSummaryTypeFunction(newInput)) {
					result = 0;
				} else {
					/*
					var keys = Object.keys(e);
					$.each(keys, function(i, k) {
					    if (k.indexOf('sum_') > -1) {
					        e[k.replace('sum_','')] = e[k];
					        delete e[k];
					    } else if(k.indexOf('count_') > -1) {
					        e[k.replace('count_','')] = e[k];
					        delete e[k];
					    } else if(k.indexOf('countdistinct_') > -1) {
					        e[k.replace('countdistinct_','')] = e[k];
					        delete e[k];
					    } else if(k.indexOf('min_') > -1) {
					        e[k.replace('min_','')] = e[k];
					        delete e[k];
					    } else if(k.indexOf('max_') > -1) {
					        e[k.replace('max_','')] = e[k];
					        delete e[k];
					    } else if(k.indexOf('avg_') > -1) {
					        e[k.replace('avg_','')] = e[k];
					        delete e[k];
					    }
					});					
					*/
					$.each(matches, function(fIndex, field) {
						scope[mapping[field]] = e[field];
						/*
						var fieldNm = field
							.replace('sum_', '')
							.replace('count_', '')
							.replace('countdistinct_', '')
							.replace('min_', '')
							.replace('max_', '')
							.replace('avg_', '');
						scope[mapping[fieldNm]] = e[fieldNm];
						*/
					});
					
					if(_.isEmpty(scope)){
						WISE.alert("사용자 정의 데이터에 참조되어 있는 필드가 존재하지 않습니다.");
						return false;
					}else{
						result = secureEval(newInput, scope);
					}
					
				}
				if(result)
					e[fieldNameBySummary] = result;
				/* DOGFOOT hsshim 1231 끝 */
            });
        } catch(error) {
       		/* DOGFOOT hsshim 2020-01-13 사용자 정의 데이터 개선 */
			console.error(error.stack);
			//2020.01.31 MKSONG 오타 수정 DOGFOOT
			WISE.alert('사용자 정의 데이터 계산을 실패 했습니다.');
        }
	}
    //2020.02.07 mksong SUMMARYTYPE 기준 사용자정의데이터 추가 수정 끝 dogfoot
    
	/**
	 * Return an empty list if the current dashboard is a new report.
	 * Else, get the saved custom field info from Dashboard structure.
	 */
	this.getCustomFieldInfo = function() {
		var customFieldInfo = {};
		/* DOGFOOT hsshim 2020-01-13 비정형 사용자 정의 데이터 저장 기능 작업 */
		/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
		/*dogfoot 통계 분석 추가 shlim 20201102*/
		if (gDashboard.reportType === 'DashAny' || gDashboard.reportType === 'StaticAnalysis') {
			var dataSources = gDashboard.structure.DataSources.DataSource;
			if (dataSources.length === 0) {
				return customFieldInfo;
			}
			$.each(dataSources, function(i, dataSource) {
				if (dataSource.CalculatedFields) {
					customFieldInfo[dataSource.ComponentName] = [];
					var fields = WISE.util.Object.toArray(dataSource.CalculatedFields.CalculatedField);
					$.each(fields, function(j, field) {
						customFieldInfo[dataSource.ComponentName].push(field);
					});
				}
			});
		} else if (gDashboard.reportType === 'AdHoc') {
			var reportJson = gDashboard.structure.ReportMasterInfo.reportJson;
			if (reportJson == undefined) {
				return customFieldInfo;
			}
			var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByName(gDashboard.structure.ReportMasterInfo.cube_nm);
			customFieldInfo[dataSrcId] = [];
			if (reportJson.CALCDATA_ELEMENT) {
				$.each(WISE.util.Object.toArray(reportJson.CALCDATA_ELEMENT.CALC_DATA), function(i, calcData) {
					var expression = calcData.EXP_SCRIPT;
					/* DOGFOOT hsshim 2020-01-17 비정형 사용자 정의 데이터 불러오기 오류 수정 */
					var re = /NM_\[([^\]]*)]/g;
					while (m = re.exec(calcData.EXP_SCRIPT)) {
						expression = expression.replace(m[0], m[0].substring(3));
					}
					/* DOGFOOT hsshim 2020-01-17 끝 */
					customFieldInfo[dataSrcId].push({
						Name: calcData.FLD_NM,
						//2020.04.09 mksong 비정형 사용자정의데이터 불러오기 오류 수정 dogfoot
						DataType: 'Decimal',
						Expression: expression
					});
				});
			}
		}
		/* DOGFOOT hsshim 2020-01-13 끝 */
		/* DOGFOOT hsshim 2020-01-15 끝 */
		return customFieldInfo;
	}

	/**
	 * Returns true iff name is the same as that of an already existing field.
	 */
	this.isDuplicateName = function(name) {
		var dataSetName = self.dataSource.DATASET_NM;
		var fieldList = gDashboard.dataSetCreate.infoTreeList[dataSetName];
		for (var i = 0; i < fieldList.length; i++) {
			if (name === fieldList[i].CAPTION) return true; 
		}
		return false;
	}

	/**
	 * Initialize custom fields directly. Used for opening reports.
	 */
	this.setCustomFieldsForOpen = function(dataSourceId) {
		/* DOGFOOT hsshim 200103
		 * 사용자 정의 데이터 집합 기능 개선
		 */
		self.setDataSourceInfo(dataSourceId);
		self.setOriginalFieldInfo();
		if (self.fieldInfo[dataSourceId]) {
			self.updateFieldInfo(self.fieldInfo[dataSourceId], false);
		}
	}

	/**
	 * Return true if name is not equal to that of an original field.
	 */
	this.equalsOriginalFieldName = function(name) {
		for (var i = 0; i < self.originalFieldInfo.length; i++) {
			if (name === self.originalFieldInfo[i].CAPTION) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Return true if field with name no longer exists.
	 */
	this.fieldIsDeleted = function(name) {
		var currentFields = gDashboard.dataSetCreate.infoTreeList[self.dataSourceName];
		for (var i = 0; i < currentFields.length; i++) {
			if (name === currentFields[i].CAPTION) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Change the names of edited custom fields.
	 */
	this.updateChangedFields = function(changedNames) {
		var dataSourceFields = $('#panelDataA').find('.wise-column-chooser[data-source-id="' + self.dataSource.mapid + '"]');
		$.each(dataSourceFields, function(index, field) {
			/* DOGFOOT hsshim 2020-01-13 항목 이름 변경 후 사용자 정의 데이터 사용시 이름 변경된 항목이 모두 사라지는 오류 수정 */
			var fieldName = $(field).attr('uni_nm');
			$.each(changedNames, function(nIndex, name) {
				if (name[fieldName]) {
					$(field).attr('uni_nm', name[fieldName]);
					$(field).attr('caption', name[fieldName]);
					$(field).attr('title', name[fieldName]);
					$(field).children('a.btn.neutral')[0].text = name[fieldName];
					fieldName = name[fieldName];
				}
			});
			/* DOGFOOT hsshim 2020-01-13 끝 */
			if (self.fieldIsDeleted(fieldName)) {
				$(field).parent().remove();
			}
		});
	}
	
	/* DOGFOOT hsshim 1231
	 * 사용자 정의 데이터 집계 함수 확인하는 기능 추가
	 */
	/**
	 * Return true if given expression contains a summary type function.
	 */
	this.hasSummaryTypeFunction = function(expression) {
		var summaryTypePatterns = [/Avg\(/, /Count\(/, /Max\(/, /Median\(/, /Min\(/, /Mode\(/, /StdDev\(/, /Sum\(/, /Var\(/];
		return summaryTypePatterns.some(function(regex) { 
			return regex.test(expression) 
			});
	}
	/* DOGFOOT hsshim 1231 끝 */
	
	/* DOGFOOT hsshim 200103
	 * 사용자 정의 데이터 집계 함수 추가
	 */
	/**
	 * Add summary field data to csvData and queryData.
	 */
	this.addSummaryFieldData = function(item, queryData) {
		if (self.fieldInfo[item.dataSourceId]) {
			$.each(self.fieldInfo[item.dataSourceId], function(i, field) {
				if (self.hasSummaryTypeFunction(field.Expression)) {
					var dims = _.map(item.dimensions, function(dim) { return dim.name; });
					/* DOGFOOT hsshim 2020-01-13 집계 사용자 정의 데이터 오류 수정 */
					var series = _.map(item.seriesDimensions, function(series) { return series.name; });
					dims = dims.concat(series);
					$.each(item.csvData, function(j, csvDataItem) {
						/* DOGFOOT hsshim 200109
						 * 차원 없는 경우에 계산 잘못되는 오류 수정
						 */
						// filter data by dimension values
						var vals = [];
						if (dims.length === 0) {
							vals = _.clone(item.filteredData);
						} else {
							vals = item.filteredData.filter(function(dataItem) {
								for (var k = 0; k < dims.length; k++) {
									if (dataItem[dims[k]] !== csvDataItem[dims[k]]) {
										return false;
									} else if (k === dims.length - 1) {
										return true;
									}
								}
							});
						}
						/* DOGFOOT hsshim 200109 끝 */
						// calculate summary data then put into csvData
						try {
							// parse fields from input
							var re = /\[([^\]]*)]/g,
								matches = [],
								scope = {},
								mapping = {},
								mapCount = 0,
								input = field.Expression,
								newInput = input,
								fieldName = field.Name,
								result;
							/* dogfoot WHATIF 분석 매개변수 사용 계산식 치환 shlim 20201022 */	
							input = self.repCalcParam(input);
							newInput = input;
							while (m = re.exec(input)) {
								var swap = new RegExp('\\[' + m[1] + ']', 'g');
								if (!mapping[m[1]]) {
									var newVar = '_v' + mapCount++;
									matches.push(m[1]);
									mapping[m[1]] = newVar;
									// required because Math.js doesn't support Korean characters
									newInput = newInput.replace(swap, newVar);
								}
							}
							// add new values to data
							$.each(matches, function(fIndex, _field) {
								scope[mapping[_field]] = _.map(vals, function(_val) { return _val[_field]; });
							});
							result = secureEval(newInput, scope);
							csvDataItem[field.Name] = result;
							// add to queryData if provided
							if (queryData !== undefined) {
								for (key in queryData[j]) {
									if (key.indexOf('_' + field.Name) !== -1) {
										queryData[j][key] = result;
									}
								}
							}
						} catch(error) {
							console.error(error.stack);
							WISE.alert('사용자 정의 데이터 계산을 실패했습니다.');
						}
					});
					/* DOGFOOT hsshim 2020-01-13 끝 */
				}
			});
		}
	}
	/* DOGFOOT hsshim 200103 끝 */

	/* DOGFOOT hsshim 2020-01-13 비정형 사용자 정의 데이터 저장 기능 작업 */
	/* DOGFOOT hsshim 2020-01-15 주제영역 집합 여러개 적용되개 수정 */
	/**
	 * Return a JSON element with custom field information for adhoc reports.
	 */
	this.getAdhocCalcDataElement = function() {
		var dataSrcId = WISE.libs.Dashboard.item.DataCubeUtility.getDataSourceIdByField();
		if (self.fieldInfo[dataSrcId] == undefined) {
			return '';
		}
		var result = { CALC_DATA: [] };
		$.each(self.fieldInfo[dataSrcId], function(i, field) {
			var adhocExpression = field.Expression;
			/* DOGFOOT hsshim 2020-01-17 비정형 사용자 정의 데이터 저장 오류 수정 */
			adhocExpression = adhocExpression.replace(/\[([^\]]*)]/g, 'NM_[$1]');
			result.CALC_DATA.push({
				FLD_NM: field.Name,
				CAPTION: field.Name,
				EXP_SCRIPT: adhocExpression
			});
		});
		return result;
	}
	/* dogfoot WHATIF 분석 매개변수 계산식 편집용 리스트 생성 shlim 20201022 */	
	this.setCalcParameterList = function(){
    	if(Object.keys(gDashboard.customParameterHandler.calcParameterInformation).length >= 0){
    		self.functionList['매개변수'] = {};
    		
    		$.each(gDashboard.customParameterHandler.calcParameterInformation,function(_key,_info){
    			self.functionList['매개변수']['['+ _info.PARAM_CAPTION+']'] = '필드 형식: decimal';
    		})
    	}
    }
	/* dogfoot WHATIF 분석 매개변수 사용 계산식 치환 기능  shlim 20201022 */	
	this.repCalcParam = function(_expression){
		var returnVal = _expression;
		
    	if(Object.keys(gDashboard.customParameterHandler.calcParameterInformation).length >= 0){
    		$.each(gDashboard.customParameterHandler.calcParameterInformation,function(_key,_info){
    			if(returnVal.indexOf('['+ _info.PARAM_CAPTION+']') > -1){
    				returnVal = returnVal.replace('['+ _info.PARAM_CAPTION+']',_info.SET_VALUE);
    			}
    		})
    	}
    	return returnVal
    }
	
    
    /* 20210122 AJKIM 계산된 컬럼 단일 테이블 적용 DOGFOOT*/
    this.setDSSingleInfo = function(columnList) {
    	self.functionList['열'] = {};
        
    	$.each(columnList, function(i, c){
    		if(c.DATA_TYPE !== 'cal'){
    			self.functionList['열'][c.COL_CAPTION] = '데이터 타입: ' + c.DATA_TYPE;
    		}
    	})
	}
    
    this.initLayoutDSSingle = function(columnList, dsInfo) {
        $('body').append('<div id="customFieldPopup"></div>');
        $('#customFieldPopup').dxPopup({
            height: '66%',
            width: 1000,
            visible: true,
            showCloseButton: false,
            title: '계산된 컬럼',
            onContentReady: function() {
            	gDashboard.fontManager.setFontConfigForOption('customFieldPopup')
            },
            contentTemplate: function(contentElement) {
				contentElement.append('<div id="multiView"/>');
				$('#multiView').dxMultiView({
					items: [
						{
							template: $('<div id="editView" style="height:87%"/>')
						},
						{
							template: $('<div id="calcView"/>')
						},
						/* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
						{
							template: $('<div id="paramView"/>')
						}
					],
					deferRendering: false,
					height: '100%',
					width: '100%',
					selectedIndex: 0,
					loop: false,
					swipeEnabled: false,
					onContentReady: function()  {
						$('#editView').append(editTemplateDS);
//						$('#calcView').append(calcTemplateDS);
						//2020.04.06 MKSONG 사용자정의데이터 열 검색기능 추가 DOGFOOT
						$("#fieldSearch").dxTextBox({
							visible:true,
							readOnly: false,
							placeholder: '검색어를 입력하세요.',
							onKeyUp: function(e) {
								self.fieldSearchText(e.event.target.value);
							}
						});
						
						self.initEditComponentsDSSingle(columnList, dsInfo);
						self.initCalcComponents();
						gDashboard.fontManager.setFontConfigForEditText('multiView');
					}
				});
            }
        }).appendTo('#tab6primary');
	};
    
    this.initEditComponentsDSSingle = function(columnList, dsInfo) {
    	// list of variables names to change
		var changedNames = [];

		var calColumn = columnList.filter(function(c){
			return c.DATA_TYPE === 'cal';
		})
		
		var nonCalCol = columnList.filter(function(c){
			return c.DATA_TYPE !== 'cal' && c.DATA_TYPE !== 'grp';
		})
		
		var functionList = ["ASCII()", "SUBSTRING()", "LEFT()", "RIGHT()", "CONCAT()", "TRIM()", "MID()", "REPLACE()", "REVERSE()", "LTRIM()", "RTRIM()", "INSERT()"];
		
		var addString = function(e){
			var component = e.component;  

		    function initialClick() {  
		        console.log('initial click for key ' + e.key);  
		        component.clickCount = 1;  
		        component.clickKey = e.key;  
		        component.clickDate = new Date();  
		    }  

		    function doubleClick() {  
		    	var str = typeof e.itemData == "string"? e.itemData : e.itemData.COL_NM;
		    	$("#fieldCalc").val($("#fieldCalc").val() + str)
		        component.clickCount = 0;  
		        component.clickKey = 0;  
		        component.clickDate = null;  
		    }  

		    if ((!component.clickCount) || (component.clickCount != 1) || (component.clickKey != e.key) ) {  
		        initialClick();  
		    }  
		    else if (component.clickKey == e.key) {  
		        if (((new Date()) - component.clickDate) <= 300)  
		            doubleClick();  
		        else  
		            initialClick();  
		    }  
		}
		
		$("#column_list").dxList({
	        dataSource: nonCalCol,
	        height: 200,
	        searchEnabled: true,
	        allowItemDeleting: false,
	        itemTemplate: function(data) {
	            return $("<div>").text(data.COL_NM);
	        },
	        onItemClick: addString
	    }).dxList("instance");
		
		$("#function_list").dxList({
	        dataSource: functionList,
	        height: 200,
	        searchEnabled: true,
	        allowItemDeleting: false,
	        onItemClick: addString
	    }).dxList("instance");
		// popup instance
		var popup = $('#customFieldPopup').dxPopup('instance');

		// multiview instance
		var multiView = $('#multiView').dxMultiView('instance');

		// list of custom fields
		var fieldList = $('#customFieldList').dxDataGrid({
			height: "calc(100% - 50px)",
			columns: [
				{
					caption: '필드명',
					dataField: 'COL_CAPTION'
				}
			],
			dataSource: calColumn,
			editing: {
				mode: 'row',
				allowDeleting: true,
				useIcons: true,
				texts: {
					confirmDeleteMessage: ''
				}
			},
			keyExpr: 'COL_CAPTION',
			// selection: {
			// 	mode:'single'
			// },
			onContentReady: function(){
				gDashboard.fontManager.setFontConfigForEditText('customFieldList')
			},
			onSelectionChanged: function(e) {
				var selectedField = e.selectedRowsData[0];
				if (selectedField) {
					$('#fieldName').val(selectedField.COL_CAPTION);
					$('#fieldCalc').val(selectedField.COL_NM);
				} else {
					$('#fieldName').val('');
					$('#fieldCalc').val('');
				}
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			}
		}).dxDataGrid('instance');

		// link view to calculation page
//		$('#toCalcView').on('click', function() {
//			var expression = $('#fieldCalc').val();
//			$('#calcTextArea').val(expression);
//			self.setCalcParameterList();
//			popup.option('title', '계산식 편집');
//			multiView.option('selectedIndex', 1);
//		});

		var addCalColumn = function(){
			var name = $('#fieldName').val();
			var expression = $('#fieldCalc').val();
			
			var dupleCheck = false;
			
			var maxOrder = 0;
			$.each(calColumn, function(i, c){
				if(name === c.COL_CAPTION){
					dupleCheck = true;
					return false;
				}
				if(maxOrder < c.COL_ID * 1) maxOrder = c.COL_ID * 1;
			});
			
			$.each(nonCalCol, function(i, c){
				if(name === c.COL_CAPTION){
					dupleCheck = true;
					return false;
				}
				if(maxOrder < c.COL_ID * 1) maxOrder = c.COL_ID * 1;
			});
			
			if(dupleCheck){
				WISE.alert("같은 이름의 컬럼은 추가할 수 없습니다.");
				return false;
			}
			
			var temp = {
					TBL_NM: dsInfo.TBL_NM,
					COL_NM: expression,
					COL_CAPTION: name,
					DATA_TYPE: "cal",
                    AGG: "",
                    PK_YN: "",
                    TYPE: "DIM",
                    VISIBLE: true,
                    COL_ID: ++maxOrder
				};
			
			var param = {
					'dsid' : dsInfo.DS_ID,
					'dstype' : 'DS_SQL',
					'sql' : "SELECT  TOP 1 "+ temp.COL_NM +" AS ["+ temp.COL_CAPTION +"] FROM " + dsInfo.TBL_NM,
					'params' :{}
			};
			
			gProgressbar.show();
			
			$.ajax({
				type : 'post',
				data: param,
				url : WISE.Constants.context + '/report/directSql.do',
				async : false,
				success : function(data) {
					var result = data.data;
					
					if(result){
						calColumn.push(temp);
						$('#customFieldList').dxDataGrid('instance').refresh();
						$('#fieldName').val('');
						$('#fieldCalc').val('');
						gProgressbar.hide();
					}
					
				},error: function(_response) {
					gProgressbar.hide();
					WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
					return false;
				}
			});
			
			return true;
		}
		// save field info to list
		$('#saveField').on('click', function() {
			var selectedData = $('#customFieldList').dxDataGrid('instance').getSelectedRowsData();
			var name = $('#fieldName').val();
			var expression = $('#fieldCalc').val();
			
			if(selectedData.length > 0){
				$.each(calColumn, function(i, c){
					if(c.COL_CAPTION === selectedData[0].COL_CAPTION){
						c.COL_CAPTION = name;
						c.COL_NM = expression;
					}
				})
				$('#customFieldList').dxDataGrid('instance').refresh();
			}else{
				addCalColumn();
			}
		});

		// confirm and cancel buttons
		$('a.edit-ok-hide').on('click', function() {
			var selectedData = $('#customFieldList').dxDataGrid('instance').getSelectedRowsData();
			var name = $('#fieldName').val();
			var expression = $('#fieldCalc').val();
			
			if(name !== ""){
				if(selectedData.length > 0){
					$.each(calColumn, function(i, c){
						if(c.COL_CAPTION === selectedData[0].COL_CAPTION){
							c.COL_CAPTION = name;
							c.COL_NM = expression;
						}
					})
					$('#customFieldList').dxDataGrid('instance').refresh();
				}else{
					if(!addCalColumn()) return;
				}
			}
			
			
			for(j = 0; j < columnList.length; j++){
				if(columnList[j].DATA_TYPE === 'cal'){
					columnList.splice(j, 1);
					j--;
				}
			}
			
			for(j = 0; j < calColumn.length; j++){
				columnList.push(calColumn[j]);
			}
			
			$('#ExpressArea').dxDataGrid('instance').option('dataSource', columnList);
			$('#ExpressArea').dxDataGrid('instance').refresh()
//			$('#customFieldList').dxDataGrid('option').dataSource
			gProgressbar.hide();
			popup.hide();
		});
		$('a.edit-close').on('click', function() {
			popup.hide();
		});
	}
    
    /* 20210122 AJKIM 계산된 컬럼 단일 테이블 적용 DOGFOOT*/
    this.setDSGrpInfo = function(columnList) {
    	self.functionList['열'] = {};
        
    	$.each(columnList, function(i, c){
    		if(c.DATA_TYPE !== 'cal'){
    			self.functionList['열'][c.COL_CAPTION] = '데이터 타입: ' + c.DATA_TYPE;
    		}
    	})
	}
    
    this.initLayoutDSGrp = function(columnList, dsInfo) {
        $('body').append('<div id="customFieldPopup"></div>');
        $('#customFieldPopup').dxPopup({
            height: '66%',
            width: 1000,
            visible: true,
            showCloseButton: false,
            title: '항목 그룹화 관리',
            onContentReady: function() {
            	gDashboard.fontManager.setFontConfigForOption('customFieldPopup')
            },
            contentTemplate: function(contentElement) {
				contentElement.append('<div id="multiView"/>');
				$('#multiView').dxMultiView({
					items: [
						{
							template: $('<div id="editView" style="height: 87%"/>')
						},
						{
							template: $('<div id="calcView"/>')
						},
						/* dogfoot WHATIF 분석 매개변수 생성 레이아웃 shlim 20201022 */
						{
							template: $('<div id="paramView"/>')
						}
					],
					deferRendering: false,
					height: '100%',
					width: '100%',
					selectedIndex: 0,
					loop: false,
					swipeEnabled: false,
					onContentReady: function()  {
						$('#editView').append(editTemplateGrp);
//						$('#calcView').append(calcTemplateDS);
						//2020.04.06 MKSONG 사용자정의데이터 열 검색기능 추가 DOGFOOT
						$("#fieldSearch").dxTextBox({
							visible:true,
							readOnly: false,
							placeholder: '검색어를 입력하세요.',
							onKeyUp: function(e) {
								self.fieldSearchText(e.event.target.value);
							}
						});
						
						self.initEditComponentsDSGrp(columnList, dsInfo);
						self.initCalcComponents();
						gDashboard.fontManager.setFontConfigForEditText('multiView');
					}
				});
            }
        }).appendTo('#tab6primary');
	};
    
    this.initEditComponentsDSGrp = function(columnList, dsInfo) {
    	// list of variables names to change
		var changedNames = [];
		
		var nameList = [];

		var grpColumn = columnList.filter(function(c){
			return c.DATA_TYPE === 'grp';
		})
		
		var grpList = {};
		var grpName = [];
		
		var selectedGrp = "";
		var selectedGrpField = "";
		
		var originData = [];
		var currentData = [];
		
		$.each(grpColumn, function(i, c){
			grpList[c.COL_CAPTION] = self.getGroupList(c.COL_NM);
			grpName.push({grp : c.COL_CAPTION})
		})
		
		var nonGrpCol = columnList.filter(function(c){
			return c.DATA_TYPE !== 'grp';
		})

		// popup instance
		var popup = $('#customFieldPopup').dxPopup('instance');

		// multiview instance
		var multiView = $('#multiView').dxMultiView('instance');

		// list of custom fields
		var grpListGrid = $('#grpList').dxDataGrid({
			height:  "calc(100% - 50px)",
			columns: [
				{
					caption: '그룹명',
					dataField: 'grp'
				},
				{
					type: "buttons",
					buttons: ["delete"],
					width: 48
				}
			],
			dataSource: grpName,
			editing: {
				mode: 'row',
				allowDeleting: true,
				useIcons: true,
				texts: {
					confirmDeleteMessage: ''
				}
			},
			keyExpr: 'grp',
			// selection: {
			// 	mode:'single'
			// },
			onContentReady: function(e){
//				e.component.columnOption("command:edit", {
//					width : 35
//				});
				gDashboard.fontManager.setFontConfigForEditText('customFieldList');
			},
			onSelectionChanged: function(e) {
				var select = e.selectedRowsData[0];
				if (select) {
					select = grpList[select.grp];
					selectedGrp = e.selectedRowsData[0].grp;
					selectedGrpField = "";
					
					var temp = select.groupList;
					var dataSource = [];
					var tempList = [];
					$.each(temp, function(name, list){
						dataSource.push({grp_field : name});
						if(name !== selectedGrpField)
							tempList = tempList.concat(list);
					})
					$("#grpFieldList").dxDataGrid('instance').option('dataSource', dataSource);
					$("#grpFieldList").dxDataGrid('instance').refresh();
					
					var param = {
							'dsid' : dsInfo.DS_ID,
							'dstype' : 'DS_SQL',
							'sql' : "SELECT " + select.groupTarget  + " FROM " + dsInfo.TBL_NM + " GROUP BY " + select.groupTarget,
							'params' :{}
					};

					gProgressbar.show();

					$.ajax({
						type : 'post',
						data: param,
						url : WISE.Constants.context + '/report/directSql.do',
						async : false,
						success : function(data) {
							var result = data.data;
							
							if(result){
								originData = result;
								
								if(tempList.length == 0){
									currentData = originData;
								} else{
									currentData = [];
									for(var j = 0; j < originData.length; j++){
										$.each(originData[j], function(name, data){
											for(var i = 0; i < tempList.length; i++){
												if(data == tempList[i])
													return true;
											}
											var tempData = {};
											tempData[name] = data;
											currentData.push(tempData);
									    })
									}
								}
								
								
								$("#grp_dim_list").dxDataGrid('instance').option('columns[1].dataField', select.groupTarget);
								$("#grp_dim_list").dxDataGrid('instance').option('keyExpr', select.groupTarget);
								$("#grp_dim_list").dxDataGrid('instance').option('dataSource', currentData);
								$("#grp_dim_list").dxDataGrid('instance').refresh();
							}else{
								$("#grp_dim_list").dxDataGrid('instance').option('dataSource', []);
							}
							
							gProgressbar.hide();

						},error: function(_response) {
							gProgressbar.hide();
							WISE.alert('쿼리가 부적합 합니다.'+ajax_error_message(_response));
						}
					});
				} else {
					selectedGrp = "";
					selectedGrpField = "";
					$("#grpFieldList").dxDataGrid('instance').option('dataSource', [])
					$("#grpFieldList").dxDataGrid('instance').refresh();
					$("#grp_dim_list").dxDataGrid('instance').option('dataSource', []);
					$("#grp_dim_list").dxDataGrid('instance').refresh();
				}
			},
			onRowRemoved : function(e){
				delete grpList[e.key];
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			}
		}).dxDataGrid('instance');
		
		var grpFieldListGrid = $('#grpFieldList').dxDataGrid({
			height: "calc(100% - 50px)",
			columns: [
				{
					caption: '항목 그룹명',
					dataField: 'grp_field'
				},
				{
					type: "buttons",
					buttons: ["delete"],
					width: 48
				}
			],
			dataSource: [],
			editing: {
				mode: 'row',
				allowDeleting: true,
				useIcons: true,
				texts: {
					confirmDeleteMessage: ''
				}
			},
			keyExpr: 'grp_field',
			onContentReady: function(){
//				e.component.columnOption("command:edit", {
//					width : 35
//				});
				gDashboard.fontManager.setFontConfigForEditText('customFieldList')
			},
			onRowRemoved : function(e){
				delete grpList[selectedGrp].groupList[e.key];
				
				var tempList = [];
				
				$.each(grpList[selectedGrp].groupList, function(name, data){
					if(name !== selectedGrpField){
						tempList = tempList.concat(data);
					}
				});
				if(tempList.length == 0){
					currentData = originData;
				}else{
					currentData = [];
					for(var j = 0; j < originData.length; j++){
						$.each(originData[j], function(name, data){
							for(var i = 0; i < tempList.length; i++){
								if(data == tempList[i])
									return true;	
							}
							var tempData = {};
							tempData[name] = data;
							currentData.push(tempData);
					    })
					}
				}
				
				$("#grp_dim_list").dxDataGrid('instance').option('dataSource', currentData);
				$("#grp_dim_list").dxDataGrid('instance').refresh();
			},
			onSelectionChanged: function(e) {
				
				var select = e.selectedRowsData[0];
				if (select) {
					select = grpList[selectedGrp].groupList[e.selectedRowsData[0].grp_field]
					selectedGrpField = e.selectedRowsData[0].grp_field;
					$("#fieldName").val(selectedGrpField);
					$("#grp_dim_list").dxDataGrid('instance').selectRows(select);
				} else {
					selectedGrpField = "";
					$("#fieldName").val('');
				}
				
				var tempList = [];
				
				$.each(grpList[selectedGrp].groupList, function(name, data){
					if(name !== selectedGrpField){
						tempList = tempList.concat(data);
					}
				});
				if(tempList.length == 0){
					currentData = originData;
				}else{
					currentData = [];
					for(var j = 0; j < originData.length; j++){
						$.each(originData[j], function(name, data){
							for(var i = 0; i < tempList.length; i++){
								if(data == tempList[i])
									return true;	
							}
							var tempData = {};
							tempData[name] = data;
							currentData.push(tempData);
					    })
					}
				}
				
				
				$("#grp_dim_list").dxDataGrid('instance').option('dataSource', currentData);
				$("#grp_dim_list").dxDataGrid('instance').refresh();
				if (select) {
					$("#grp_dim_list").dxDataGrid('instance').selectRows(select);
				}
				
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			}
		}).dxDataGrid('instance');
		
		var grpDimList = $('#grp_dim_list').dxDataGrid({
			height: "calc(100% - 100px)",
			columns: [
				{
					width: 48,
					type: "selection"
				},
				{
					caption: '항목명',
					dataField: 'COL_CAPTION'
				}
			],
			selection: {
				mode: 'multiple'
			},
			dataSource: [],
			keyExpr: 'COL_CAPTION',
			paging : {
				enabled: false
			},
			onContentReady: function(){
				gDashboard.fontManager.setFontConfigForEditText('customFieldList')
			},
			onRowClick: function(e) {
				if (e.isSelected) {
					e.component.deselectRows([e.key]);
				} else {
					e.component.selectRows([e.key]);
				}
			}
		}).dxDataGrid('instance');

		$('#create_grp').on('click', function(){
			var p = $('#editPopup').dxPopup('instance');
			p.option({
				title: '새 그룹 추가',
				onContentReady: function() {
					gDashboard.fontManager.setFontConfigForEditText('editPopup');
				},
				contentTemplate: function(contentElement) {
					// initialize title input box
					var html = 	'<p>그룹 이름</p><div id="grpInput"></div>' +
								'<div style="padding-bottom:20px;"></div>' +
								'<div class="modal-footer" style="padding-bottom:0px;">' +
									'<div class="row center">' +
										'<a id="ok-hide" href="#" class="btn positive ok-hide">확인</a>' +
										'<a id="close" href="#" class="btn neutral close">취소</a>' +
									'</div>' +
								'</div>';
					contentElement.append(html);
					
					$('#grpInput').dxTextBox({
						text: ""
					});
                    
                    // confirm and cancel
					contentElement.find('#ok-hide').on('click', function() {
						var newName = $('#grpInput').dxTextBox('instance').option('text');
						var dupleCheck = false;
            			
            			$.each(nonGrpCol, function(i, c){
            				if(newName === c.COL_CAPTION){
            					dupleCheck = true;
            					return false;
            				}
            			});
                        if(newName.trim() == '') {
                        	WISE.alert('그룹 이름에 빈 값을 넣을 수 없습니다.');
                        } else if(typeof grpList[newName] !== 'undefined'){
                        	WISE.alert('이미 존재하는 그룹명입니다.');
                        } else if(dupleCheck){
                        	WISE.alert('이미 존재하는 컬럼명입니다.');
                        }else {
                        	grpName.push({grp : newName});
                        	grpList[newName] = self.createGroupListJson();
                        	$('#grpList').dxDataGrid('instance').refresh();
                        	p.hide();
                        }
					});
					contentElement.find('#close').on('click', function() {
						p.hide();
					});
				}
			});
			
			p.show();
		});
		
		$('#create_grp_field').on('click', function(){
			var selected = $("#grp_dim_list").dxDataGrid("instance").getSelectedRowKeys();
			var name = $("#fieldName").val();
			if(selected.length == 0){
				WISE.alert("최소 하나의 항목을 체크해야 합니다.");
				return;
			}
			if(name.trim() == ""){
				WISE.alert("이름을 지정해주십시오.");
				return;
			}
			
			//신규 추가
			if(selectedGrpField == ""){
				if(typeof grpList[selectedGrp].groupList[name] !== 'undefined'){
					WISE.alert("동일한 항목 이름은 지정할 수 없습니다.");
					return
				}
				grpList[selectedGrp].groupList[name] = selected;
			}else{
				//수정
				if(typeof grpList[selectedGrp].groupList[name] !== 'undefined' && selectedGrpField !== name){
					WISE.alert("동일한 항목 이름은 지정할 수 없습니다.");
					return;
				}
				
				grpList[selectedGrp].groupList[selectedGrpField] = selected;
				
				if(selectedGrpField !== name){
					var t = grpList[selectedGrp].groupList[selectedGrpField];
					delete grpList[selectedGrp].groupList[selectedGrpField];
					grpList[selectedGrp].groupList[name] = t;
				}
			}
			var dataSource = [];
			$.each(grpList[selectedGrp].groupList, function(name, list){
				dataSource.push({grp_field : name});
			})
			
			var tempList = [];
			
			$.each(grpList[selectedGrp].groupList, function(name, data){
				if(name !== selectedGrpField){
					tempList = tempList.concat(data);
				}
			});
			if(tempList.length == 0){
				currentData = originData;
			}else{
				currentData = [];
				for(var j = 0; j < originData.length; j++){
					$.each(originData[j], function(name, data){
						for(var i = 0; i < tempList.length; i++){
							if(data == tempList[i])
								return true;	
						}
						var tempData = {};
						tempData[name] = data;
						currentData.push(tempData);
				    })
				}
			}
			selectedGrpField = "";
			$("#fieldName").val('');
			$("#grp_dim_list").dxDataGrid('instance').option('dataSource', currentData);
			$("#grpFieldList").dxDataGrid('instance').option('dataSource', dataSource);
			$("#grpFieldList").dxDataGrid('instance').deselectAll();
			$("#grpFieldList").dxDataGrid('instance').refresh();
			
		});

		// confirm and cancel buttons
		$('a.edit-ok-hide').on('click', function() {
			var success = true;
			$.each(grpList, function(grp, content){
				var name = grp;
				var expression = self.createGroupQuery(content.groupList, content.groupTarget, content.etc);
				
				if(!expression){
					success = false;
				}
			});
			
			if(!success){
				WISE.alert("항목이 없는 그룹은 생성할 수 없습니다.");
				return false;
			}
			

			var maxOrder = 0;
			for(j = 0; j < columnList.length; j++){
				if(maxOrder < columnList[j].COL_ID * 1) maxOrder = columnList[j].COL_ID * 1;
				if(columnList[j].DATA_TYPE === 'grp'){
					columnList.splice(j, 1);
					j--;
				}
			}
			
			var grpColumn = [];
			$.each(grpList, function(grp, content){
				var name = grp;
				var expression = self.createGroupQuery(content.groupList, content.groupTarget, content.etc);

				var temp = {
					TBL_NM: dsInfo.TBL_NM,
					COL_NM: expression,
					COL_CAPTION: name,
					DATA_TYPE: "grp",
                    AGG: "",
                    PK_YN: "",
                    TYPE: "DIM",
                    VISIBLE: true,
                    COL_ID: ++maxOrder
				};
				
				columnList.push(temp);
			})

			$('#ExpressArea').dxDataGrid('instance').option('dataSource', columnList);
			$('#ExpressArea').dxDataGrid('instance').refresh()
//			$('#customFieldList').dxDataGrid('option').dataSource
			gProgressbar.hide();
			popup.hide();
		});
		$('a.edit-close').on('click', function() {
			popup.hide();
		});
    }
    
    this.createGroupQuery = function(groupList, groupTarget, etc){
    	
    	
    	var query = "CASE ";
    	$.each(groupList, function(groupNm, groupDim){
    		query += "WHEN "
    		for(var i = 0; i < groupDim.length; i++){
    			if(i !== 0) query += "OR "
    			query +=	(groupTarget + " = '" + groupDim[i]+"' ")
    		}
    		query += ("THEN '" + groupNm + "' ");
    	});
    	
    	if(query.indexOf("WHEN ") === -1){
    		return false;
    	}
    	
    	if(etc)
    		query += "ELSE '기타' END"
    	else
    		query += "ELSE " + groupTarget + " END";
    	return query;
    }
    
    this.createGroupListJson = function(){
    	var grp = {
        		groupTarget : $("#ExpressArea").dxDataGrid("instance").getSelectedRowKeys()[0].COL_NM,
        		groupList : {},
        		etc : false
        	}
    	
    	return grp;
    }

    this.getGroupList = function(grpQuery){
    	var grp = {
    		groupTarget : "",
    		groupList : {},
    		etc : false
    	}
    	var tempQuery = grpQuery.slice(4).split("WHEN ");

    	if(grpQuery.indexOf("WHEN") == -1){
    		grp.grpTarget = tempQuery[0]
    		return grp;
    	}
    	
    	grp.groupTarget = tempQuery[1].split(' = ')[0];

    	if(grpQuery.indexOf("ELSE '기타' END") > -1) grp.etc = true;
    	
    	for(var i = 1; i < tempQuery.length ; i++){
    		var temp = tempQuery[i].split(' THEN ')
    		var grpName = temp[1].split('ELSE')[0];
    		grpName = grpName.slice(1, grpName.lastIndexOf("'"));
    		grp.groupList[grpName] = [];
    		var listItem = temp[0].split(grp.groupTarget+' = ')
    		console.log(listItem)
    		for(var j = 0; j < listItem.length; j++){
    			if(listItem[j] !== ""){
    				grp.groupList[grpName].push(listItem[j].slice(listItem[j].indexOf("'") + 1, listItem[j].lastIndexOf("'")));
    			} 
    		}
    	} 

    	return grp;
    }
}