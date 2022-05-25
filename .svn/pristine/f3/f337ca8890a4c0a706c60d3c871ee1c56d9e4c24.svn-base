<%@ page language="java" contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<div id="preferencesPage" class="scrollbar">
	<!-- 일반 설정 탭 -->
	<div class="tab-container" id="configGeneralTab">
		<div class="panel-inner scrollbar">
			<h4 id="licenceInfo" class="tit-level3 pre">라이센스 정보</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>라이센스 정보</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">OLAP 라이센스 키</th>
							<td class="ipt" colspan="5"><input class="wise-text-input" id="licenseKey" type="text"></td>
						</tr>
						<tr id="spreadLicenseKeyTr">
							<th class="left">SpreadJS<br>라이센스 키</th>
							<td class="ipt" colspan="5"><input class="wise-text-input" id="spreadJsLicenseKey" type="text"></td>
						</tr>
						<!-- DOGFOOT syjin kakao map 설정 추가  20200716 -->
						<tr id="kakaoApiKeyTr">
							<th class="left">카카오 지도 API 키</th>
							<td class="ipt" colspan="5"><input class="wise-text-input" id="kakaoApiKey" type="text"></td>
						</tr>
					</tbody>
				</table>
			</div>

			<h4 class="tit-level3 pre">솔루션 제목</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>솔루션 제목</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">제목</th>
							<td class="ipt"><input class="wise-text-input" type="text" id="solutionTitle">
							</td>
						</tr>
					</tbody>
				</table>
			</div>

			<h4 class="tit-level3 pre">기본 URL</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>기본 URL</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">URL</th>
							<td class="ipt">
								<input class="wise-text-input" type="text" id="defaultUrl">
							</td>
						</tr>
					</tbody>
				</table>
			</div>

			<h4 class="tit-level3 pre">이미지 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>로그인 화면 이미지</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">로그인 화면</th>
							<td class="ipt">
								<img id="loginImage">
								<div id="uploadLoginImage"></div>
								<div id="resetLoginImage"></div>
							</td>
							<th class="left">아이콘</th>
							<td class="ipt">
								<img id="logo"> 
								<div id="uploadLogo"></div>
								<div id="resetLogo"></div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">초기화면</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>디자이너 초기화면 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">초기화면</th>
							<td class="ipt">
							    <select id="defaultPage">
							        <option value="DashAny">대시보드</option>
							        <option value="AdHoc">비정형</option>
							    </select>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">글꼴 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>글꼴 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: 400px">
						<col style="width: 150px">
						<col style="width: 200px">
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">글꼴</th>
							<td class="ipt">
								<select id="fontFamily">
							        <option value="Basic">기본</option>
							        <option value="Noto Sans KR">Noto Sans KR</option>
							        <option value="Nanum Square">Nanum Square</option>
							        <option value="Roboto">Roboto</option>
							        <option value="Georgia, serif">Georgia</option>
							        <option value="sans-serif">sans-serif</option>
							        <option value="monospace">monospace</option>
							        <option value="cursive">cursive</option>
						         	<option value="맑은 고딕">맑은 고딕</option>
						         	<option value="굴림">굴림</option>
							    </select>
							</td>
							<th class="left">글꼴 크기</th>
							<td class="ipt">
								<input class="wise-text-input" type="number" id="fontSize">
							</td>
							<th class="left">적용 영역</th>
							<td class="ipt">
								<div>
									<input class="check" id="FONT_COVERAGE-Menu" type="checkbox">
									<label id="FONT_COVERAGE-MenuLabel" for="FONT_COVERAGE-Menu">메뉴</label>
									<input class="check" id="FONT_COVERAGE-Item" type="checkbox">
									<label id="FONT_COVERAGE-ItemLabel" for="FONT_COVERAGE-Item">아이템</label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
	</div>
	
	<!-- 고급 설정 탭 -->
	<div class="tab-container" id="configAdvancedTab">
		<div class="panel-inner scrollbar">
			<h4 class="tit-level3 pre">데이터 관리</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>데이터 관리</caption>
					<colgroup>
						<col style="width: 200px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">검색 제한 시간(초)</th>
							<td class="ipt"><input id="searchLimitTime" class="wise-text-input" type="number"></td>
						</tr>
						<tr>
							<th class="left">검색 제한 크기(Row)</th>
							<td class="ipt"><input id="searchLimitRow" class="wise-text-input" type="number"></td>
						</tr>
						<tr>
							<th class="left">동시 작업 제한 수</th>
							<td class="ipt"><input id="limitWorks" class="wise-text-input" type="number"></td>
						</tr>
						<tr>
							<th class="left">보고서 로그 정제 시간</th>
							<td class="ipt"><input id="reportLogCleanHour" class="wise-text-input" type="number"></td>
						</tr>
						<tr>
							<th class="left">엑셀 다운로드 서버 처리 건수</th>
							<td class="ipt"><input id="excelDownloadServerCount" class="wise-text-input" type="number"></td>
						</tr>
						<tr>
							<th class="left">보고서 바로 조회</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="reportDirectView" type="checkbox">
									<label id="reportDirectViewLabel" for="reportDirectView"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>			
			</div>
    			
			<h4 class="tit-level3 pre">사용자 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>사용자 설정</caption>
					<colgroup>
						<col style="width: 200px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">미사용 제한 일자</th>
							<td class="ipt"><input id="useTerm" class="wise-text-input" type="number"></td>
						</tr>
						<tr>
							<th class="left">동시접속 제한 수</th>
							<td class="ipt"><input id="limitConnections" class="wise-text-input" type="number"></td>
						</tr>
						<tr>
							<th class="left">비밀번호 변경 주기</th>
							<td class="ipt"><input id="pwChangePeriod" class="wise-text-input" type="number"></td>
						</tr>
						<tr>
							<th class="left">로그인 실패시 잠김</th>
							<td class="ipt"><input id="loginLockCnt" class="wise-text-input" type="number"></td>
						</tr>
					</tbody>
				</table>
			</div>
			<!--  DOGFOOT syjin JAVA R 분기처리 ui 설정 20210218 -->
			<h4 id="analysisTitle" class="tit-level3 pre">통계분석</h4>
			<div class="tbl data-form preferences-tbl" id="statisticalAnalysis">
				<table>
					<caption>통계분석</</caption>
					<colgroup>
						<col style="width: 200px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">통계분석 방식 설정</th>
							<td class="ipt">
								<input id="analR" class="wise-text-input" type="radio" name="anal" value="0">
								<label for="analR">R</label>
								
								<input id="analJava" class="wise-text-input" type="radio" name="anal" value="1">
								<label for="analJava">JAVA</label>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
	</div>
	
	<!-- 보고서 설정 탭 -->
	<div class="tab-container" id="configReportTab">
		<div class="panel-inner scrollbar">

			<h4 class="tit-level3 pre">메인 레이아웃 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>메인 레이아웃 설정</caption>
					<colgroup>
						<col style="width: 150px;">
						<col style="width: auto;">
						<col style="width: 150px;">
						<col style="width: auto;">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">메인 레이아웃</th>
							<td class="ipt">
							    <select id="mainLayout">
							        <option value="Bar">막대 차트</option>
							        <option value="Line">선 차트</option>
							        <option value="Area">영역 차트</option>
							        <option value="Bubble">버블 차트</option>
							        <option value="PivotGrid">피벗 그리드</option>
							        <option value="DataGrid">일반 그리드</option>
							        <option value="PieChart">파이 차트</option>
							        <option value="Card">카드</option>
							        <option value="ChoroplethMap">코로플레스 지도</option>
							        <option value="ParallelCoordinate">평행 좌표계</option>
							        <option value="BubblePackChart">버블팩</option>
							        <option value="WordCloudV2">워드클라우드</option>
							        <option value="DendrogramBarChart">신경망 바</option>
							        <option value="CalendarViewChart">캘린더 뷰</option>
							        <option value="CalendarView2Chart">캘린더 뷰2</option>
							        <option value="CalendarView3Chart">캘린더 뷰3</option>
							        <option value="CollapsibleTreeChart">신경망 트리</option>
							        <option value="Waterfallchart">폭포수 차트</option>
							        <option value="HistogramChart">히스토그램</option>
							        <option value="RectangularAreaChart">네모영역</option>
							        <option value="SynchronizedChart">동기화 라인 차트</option>
							        <option value="TreeMap">트리 맵</option>
							        <option value="StarChart">스타 차트</option>
							        <option value="HeatMap2">히트 맵</option>
							        <option value="HierarchicalEdge">계층 차트</option>
							        <option value="PyramidChart">피라미드 차트</option>
							        <option value="FunnelChart">퍼널 차트</option>
							        <option value="CoordinateDot">평면좌표 점</option>
							        <option value="CoordinateLine">평면좌표 라인</option>
							        <option value="HierarchicalEdge">계층 차트</option>
							        <option value="ForceDirect">네트워크-축소</option>
							        <option value="ForceDirectExpand">네트워크-확대</option>
							        <option value="RangeBarChart">바 분포</option>
							        <option value="RangeAreaChart">영역 분포</option>
							        <option vlaue="TimeLineChart">타임라인 차트</option>
							    </select>
							</td>
						</tr>
						<tr>
							<th class="left">보고서 권한</th>
							<td class="ipt">
							    <select id="reportAuthDetail">
							        <option value="N">폴더별 권한</option>
							        <option value="Y">보고서별 권한</option>
							    </select>
							</td>
						</tr>
						<tr>
							<th class="left">Null 값 표기</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="showNullValue" type="checkbox">
									<label id="showNullValueLabel" for="showNullValue"></label>
									<input class="wise-text-input" type="text" id="nullValue">
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">다운로드 조건 포함</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="downloadFilter" type="checkbox">
									<label id="downloadFilterLabel" for="downloadFilter"></label>
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">과거 스케줄 보고서 형식 사용</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="oldSchedule" type="checkbox">
									<label id="oldScheduleLabel" for="oldSchedule"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">비정형 보고서 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>비정형 보고서 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">비정형 레이아웃</th>
							<td class="ipt">
							    <select id="adhocLayout">
							        <option value="CTGB">차트와 그리드 동시에 보기</option>
							        <option value="C">차트만 보기</option>
							        <option value="G">그리드만 보기</option>
							    </select>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">차트 기본색상 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>차트 기본색상 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">기본 파레트</th>
							<td class="ipt">
							    <select id="defaultPalette">
							        <option value="Bright">밝음</option>
							        <option value="Harmony Light">발광체</option>
							        <option value="Ocean">바다</option>
							        <option value="Pastel">파스텔</option>
							        <option value="Soft">부드러움</option>
							        <option value="Soft Pastel">연한 파스텔</option>
							        <option value="Vintage">나무</option>
							        <option value="Violet">포도</option>
							        <option value="Carmine">단색</option>
							        <option value="Dark Moon">우주</option>
							        <option value="Dark Violet">진보라</option>
							        <option value="Green Mist">안개숲</option>
							        <option value="Soft Blue">연파랑</option>
							        <option value="Material">기본값</option>
							        <option value="Office">사무실 테마</option>
							        <option value="Sunset">노을</option>
							    </select>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			<h4 class="tit-level3 pre">피벗 그리드 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>피벗 그리드 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">데이터 가운데 정렬</th>
							<td class="ipt" style="width: 200px;">
								<div class="check-and-text">
									<input class="check" id="pivotAlignCenter" type="checkbox">
									<label id="pivotAlignCenterLabel" for="pivotAlignCenter"></label>
								</div>
							</td>
							<th class="left" style="width: 180px;">드릴 업/다운 사용</th>
							<td class="ipt" style="width: 200px">
								<div class="check-and-text">
									<input class="check" id="pivotDrillUpDown" type="checkbox">
									<label id="pivotDrillUpDownLabel" for="pivotDrillUpDown"></label>
								</div>
							</td>
							<th class="left" style="width: 180px;">정렬 기준 행열 별도 사용</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="pivotSortingOption" type="checkbox">
									<label id="pivotSortingOptionLabel" for="pivotSortingOption"></label>
								</div>
							</td>
							<th class="left" style="width: 180px;">피벗 페이징 옵션</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="pivotPagingOption" type="checkbox">
									<label id="pivotPagingOptionLabel" for="pivotPagingOption"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			<h4 class="tit-level3 pre">일반 그리드 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>일반 그리드 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">헤더 자동 정렬</th>
							<!-- DOGFOOT ktkang 그리드 페이징 해당 페이지 데이터만 가져오기 기능 구현  20200903 -->
							<td class="ipt" style="width: 200px;">
								<div class="check-and-text">
									<input class="check" id="gridAutoAlign" type="checkbox">
									<label id="gridAutoAlignLabel" for="gridAutoAlign"></label>
								</div>
							</td>
							<th class="left" style="width: 180px;">서버 데이터 페이징</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="gridDataPaging" type="checkbox">
									<label id="gridDataPagingLabel" for="gridDataPaging"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			<h4 class="tit-level3 pre">뷰어 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>뷰어 설정</caption>
					<colgroup>
						<col style="width: 180px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">대시보드 데이터 항목</th>
							<td class="ipt" style="width: 160px;">
								<div class="check-and-text">
									<input class="check" id="dashDataField" type="checkbox">
									<label id="dashDataFieldLabel" for="dashDataField"></label>
								</div>
							</td>
							<!-- 2021-04-20 Jhseo 뷰어(URL, 연결보고서 포함) 다운로드 레이아웃 활성화 -->
							<th class="left" style="width: 345px;">뷰어(URL, 연결보고서 포함) 다운로드 레이아웃 활성화</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="dashboardDownloadOption" type="checkbox">
									<label id="dashboardDownloadOptionLabel" for="dashboardDownloadOption"></label>
								</div>
							</td>
							<th class="left" style="width: 370px;">뷰어(URL, 연결보고서 포함) 데이터 항목 자동 노출 활성화</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="viewerDataFieldOption" type="checkbox">
									<label id="viewerDataFieldOptionLabel" for="viewerDataFieldOption"></label>
								</div>
							</td>
						</tr>
						<!-- dogfoot shlim 뷰어 디자이너 바로가기 기능 구현 20210614 -->
						<tr>
							<th class="left">디자이너 바로가기 활성화</th>
							<td class="ipt" style="width: 160px;">
								<div class="check-and-text">
									<input class="check" id="directDesigner" type="checkbox">
									<label id="directDesignerLabel" for="directDesigner"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			<h4 class="tit-level3 pre">보고서 레이아웃 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>보고서 레이아웃 설정</caption>
					<colgroup>
						<col style="width : 150px">
						<col style="width : auto"> 
					</colgroup>
					<tbody>
						<tr>
							<th class="left">보고서 레이아웃</th>
							<td class="ipt">
								<div id="report-layout-btn"></div>
								<div id="report-layout-pop"></div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			<h4 class="tit-level3 pre">데이터 집합 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>데이터 집합 설정</caption>
					<colgroup>
						<col style="width : 190px">
						<col style="width : auto"> 
					</colgroup>
					<tbody>
						<tr>
							<th class="left">데이터 집합 저장여부 체크</th>
							<td class="left">
								<div class="check-and-text">
									<input class="check" id="dsSaveChk" type="checkbox">
									<label id="dsSaveChkLabel" for="dsSaveChk"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">쿼리 관련 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>쿼리 관련 설정</caption>
					<colgroup>
						<col style="width : 190px">
						<col style="width : auto"> 
					</colgroup>
					<tbody>
						<tr>
							<th class="left">쿼리 에러 로그 공개</th>
							<td class="ipt" style="width: 200px;">
								<div class="check-and-text">
									<input class="check" id="SQLErrorLogVisible" type="checkbox">
									<label id="SQLErrorLogVisibleLabel" for="SQLErrorLogVisible"></label>
								</div>
							</td>
							
							<th class="left" style="width: 180px;">쿼리 캐시기능 사용</th>
							<td class="ipt">
								<div class="check-and-text">
									<input class="check" id="qryCashUse" type="checkbox">
									<label id="qryCashUseLabel" for="qryCashUse"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">데이터 항목 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>데이터 항목 설정</caption>
					<colgroup>
						<col style="width : 190px">
						<col style="width : auto"> 
					</colgroup>
					<tbody>
						<tr>
							<th class="left">측정값 위치 아래로 변경</th>
							<td class="left">
								<div class="check-and-text">
									<input class="check" id="measurePositionBottom" type="checkbox">
									<label id="measurePositionBottomLabel" for="measurePositionBottom"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
	</div>
	
	<!-- 메뉴 설정 탭 -->
	<div class="tab-container" id="configMenuTab">
		<div class="panel-inner scrollbar">

			<h4 class="tit-level3 pre">왼쪽 메뉴 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>왼쪽 메뉴 설정</caption>
					<colgroup>
						<col style="width: 150px;">
						<col style="width: auto;">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">표시 여부</th>
							<td class="ipt">
								<div>
									<input class="check" id="PROG_MENU_TYPE-AdHocVisible" type="checkbox">
									<label id="PROG_MENU_TYPE-AdHocVisibleLabel" for="PROG_MENU_TYPE-AdHocVisible">비정형 보고서</label>
									<input class="check" id="PROG_MENU_TYPE-DashAnyVisible" type="checkbox">
									<label id="PROG_MENU_TYPE-DashAnyVisibleLabel" for="PROG_MENU_TYPE-DashAnyVisible">대시보드</label>
									<input class="check" id="PROG_MENU_TYPE-ExcelVisible" type="checkbox">
									<label id="PROG_MENU_TYPE-ExcelVisibleLabel" for="PROG_MENU_TYPE-ExcelVisible">스프레드 시트</label>
									<input class="check" id="PROG_MENU_TYPE-AnalysisVisible" type="checkbox">
									<label id="PROG_MENU_TYPE-AnalysisVisibleLabel" for="PROG_MENU_TYPE-AnalysisVisible">통계분석</label>
									<input class="check" id="PROG_MENU_TYPE-DataSetVisible" type="checkbox">
									<label id="PROG_MENU_TYPE-DataSetVisibleLabel" for="PROG_MENU_TYPE-DataSetVisible">데이터 집합</label>
									<input class="check" id="PROG_MENU_TYPE-ConfigVisible" type="checkbox">
									<label id="PROG_MENU_TYPE-ConfigVisibleLabel" for="PROG_MENU_TYPE-ConfigVisible">환경설정</label>
									<input class="check" id="PROG_MENU_TYPE-DSViewerVisible" type="checkbox">
									<label id="PROG_MENU_TYPE-DSViewerVisibleLabel" for="PROG_MENU_TYPE-DSViewerVisible">데이터 집합 뷰어</label>
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">팝업 설정</th>
							<td class="ipt">
								<div>
									<input class="check" id="PROG_MENU_TYPE-AdHocPopup" type="checkbox">
									<label id="PROG_MENU_TYPE-AdHocPopupLabel" for="PROG_MENU_TYPE-AdHocPopup">비정형 보고서</label>
									<input class="check" id="PROG_MENU_TYPE-DashAnyPopup" type="checkbox">
									<label id="PROG_MENU_TYPE-DashAnyPopupLabel" for="PROG_MENU_TYPE-DashAnyPopup">대시보드</label>
									<input class="check" id="PROG_MENU_TYPE-ExcelPopup" type="checkbox">
									<label id="PROG_MENU_TYPE-ExcelPopupLabel" for="PROG_MENU_TYPE-ExcelPopup">스프레드 시트</label>
									<input class="check" id="PROG_MENU_TYPE-AnalysisPopup" type="checkbox">
									<label id="PROG_MENU_TYPE-AnalysisPopupLabel" for="PROG_MENU_TYPE-AnalysisPopup">통계분석</label>
									<!-- <input class="check" id="PROG_MENU_TYPE-DataSetPopup" type="checkbox">
									<label id="PROG_MENU_TYPE-DataSetPopupLabel" for="PROG_MENU_TYPE-DataSetPopup">데이터 집합</label> -->
									<input class="check" id="PROG_MENU_TYPE-ConfigPopup" type="checkbox">
									<label id="PROG_MENU_TYPE-ConfigPopupLabel" for="PROG_MENU_TYPE-ConfigPopup">환경설정</label>
									<input class="check" id="PROG_MENU_TYPE-DSViewerPopup" type="checkbox">
									<label id="PROG_MENU_TYPE-DSViewerPopupLabel" for="PROG_MENU_TYPE-DSViewerPopup">데이터 집합 뷰어</label>
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">메뉴 권한</th>
							<td class="ipt">
								<div>
									<input class="check" id="USE_MENU_AUTH" type="checkbox">
									<label id="USE_MENU_AUTHLabel" for="USE_MENU_AUTH">메뉴 권한 사용</label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>			
			
			<h4 class="tit-level3 pre">상단 메뉴 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>상단 메뉴 설정</caption>
					<colgroup>
						<col style="width: 150px;">
						<col style="width: auto;">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">표시 여부</th>
							<td class="ipt">
								<div>
									<input class="check" id="TOP_MENU_TYPE-SchedulerVisible" type="checkbox">
									<label id="TOP_MENU_TYPE-SchedulerVisible" for="TOP_MENU_TYPE-SchedulerVisible">스케줄러</label>
									<input class="check" id="TOP_MENU_TYPE-ContainerVisible" type="checkbox">
									<label id="TOP_MENU_TYPE-ContainerVisible" for="TOP_MENU_TYPE-ContainerVisible">컨테이너 추가</label>
									<input class="check" id="TOP_MENU_TYPE-InsertAdHocVisible" type="checkbox">
									<label id="TOP_MENU_TYPE-InsertAdHocVisible" for="TOP_MENU_TYPE-InsertAdHocVisible">비정형 아이템 추가</label>
									<input class="check" id="TOP_MENU_TYPE-QueryViewVisible" type="checkbox">
									<label id="TOP_MENU_TYPE-QueryViewVisible" for="TOP_MENU_TYPE-QueryViewVisible">쿼리보기</label>
								</div>
							</td>
						</tr>	
						<!-- MEIS 아닌곳은 주석처리 -->
						<!-- <tr>
							<th class="left">뷰어 설정</th>
							<td class="ipt">
								<div>
									<input class="check" id="TOP_MENU_TYPE-ViewerHomeVisible" type="checkbox">
									<label id="TOP_MENU_TYPE-ViewerHomeVisible" for="TOP_MENU_TYPE-ViewerHomeVisible">뷰어 홈 버튼</label>
								</div>
							</td>
						</tr> -->		
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">데이터 집합 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>데이터 집합 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">표시 여부</th>
							<td class="ipt">
								<div>
									<ul>
										<li>
											<input class="check" id="DATASET_MENU_TYPE-CUBE" type="checkbox">
											<label id="DATASET_MENU_TYPE-CUBELabel" for="DATASET_MENU_TYPE-CUBE">주제 영역 데이터</label>
										</li>
									</ul>
									<ul>
										<li>
											<input class="check" id="DATASET_MENU_TYPE-DataSetCube" type="checkbox">
											<label id="DATASET_MENU_TYPE-DataSetCubeLabel" for="DATASET_MENU_TYPE-DataSetCube">신규 데이터 집합(주제 영역 기준)</label>
										</li>
									</ul>
									<ul>
										<li>
											<input class="check" id="DATASET_MENU_TYPE-DataSetDs" type="checkbox">
											<label id="DATASET_MENU_TYPE-DataSetDsLabel" for="DATASET_MENU_TYPE-DataSetDs">신규 데이터 집합(데이터 원본 기준)</label>
										</li>
									</ul>
									<ul>
										<li>
											<input class="check" id="DATASET_MENU_TYPE-DataSetDsJoin" type="checkbox">
											<label id="DATASET_MENU_TYPE-DataSetDsJoinLabel" for="DATASET_MENU_TYPE-DataSetDsJoin">신규 데이터 집합(이기종 조인)</label>
										</li>
									</ul>
									<ul>
										<li>
											<input class="check" id="DATASET_MENU_TYPE-DataSetSQL" type="checkbox">
											<label id="DATASET_MENU_TYPE-DataSetSQLLabel" for="DATASET_MENU_TYPE-DataSetSQL">신규 데이터 집합(쿼리 직접 입력)</label>
										</li>
									</ul>
									<ul>
										<li>
											<input class="check" id="DATASET_MENU_TYPE-DataSetSingleDs" type="checkbox">
											<label id="DATASET_MENU_TYPE-DataSetSingleDsLabel" for="DATASET_MENU_TYPE-DataSetSingleDs">신규 데이터 집합(단일 테이블)</label>
										</li>
									</ul>
									<ul>
										<li>
											<input class="check" id="DATASET_MENU_TYPE-DataSetUser" type="checkbox">
											<label id="DATASET_MENU_TYPE-DataSetUserLabel" for="DATASET_MENU_TYPE-DataSetUser">사용자 데이터 업로드</label>
										</li>
									</ul>
									<ul>
										<li>
											<input class="check" id="DATASET_MENU_TYPE-DataSetLoad" type="checkbox">
											<label id="DATASET_MENU_TYPE-DataSetLoadLabel" for="DATASET_MENU_TYPE-DataSetLoad">기존 데이터 집합</label>
										</li>
									</ul>
								</div>
							</td>
						</tr>
						<tr>
						<th class="left">기능 사용 여부</th>
							<td class="ipt">
								<div>
									<ul>
										<li>
											<input class="check" id="IN_MEMORY" type="checkbox">
											<label id="IN_MEMORYLabel" for="IN_MEMORY">인메모리</label>
										</li>
									</ul>
									<ul>
										<li>
											<input class="check" id="MODIFY_EXCEPT_FIELD" type="checkbox">
											<label id="MODIFY_EXCEPT_FIELDLabel" for="MODIFY_EXCEPT_FIELD">필드 제외 수정 허용(쿼리 직접 입력)</label>
										</li>
									</ul>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">Spread Sheet 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>Spread Sheet 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">표시여부</th>
							<td class="ipt">
								<div>
									<input class="check" id="SPREAD_MENU_TYPE-Print" type="checkbox">
									<label id="SPREAD_MENU_TYPE-PrintLabel" for="SPREAD_MENU_TYPE-Print">프린트</label>
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">데이터 연결 유형</th>
							<td class="ipt">
								<div>
									<input class="check" id="SPREAD_MENU_TYPE-BindSheet" type="radio" name="bind_type" value="sheetBind">
									<label id="SPREAD_MENU_TYPE-BindSheetLabel" for="SPREAD_MENU_TYPE-BindSheet">시트</label>
									<input class="check" id="SPREAD_MENU_TYPE-BindTable" type="radio" name="bind_type" value="tableBind">
									<label id="SPREAD_MENU_TYPE-BindTableLabel" for="SPREAD_MENU_TYPE-BindTable">테이블</label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">다운로드 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>다운로드 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">Office</th>
							<td class="ipt">
								<div>
									<input class="check" id="DOWNLOAD_MENU_TYPE-OfficeVisible" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-OfficeVisibleLabel" for="DOWNLOAD_MENU_TYPE-OfficeVisible">표시</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-OfficeXlsx" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-OfficeXlsxLabel" for="DOWNLOAD_MENU_TYPE-OfficeXlsx">xlsx</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-OfficeXls" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-OfficeXlsLabel" for="DOWNLOAD_MENU_TYPE-OfficeXls">xls</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-OfficeDoc" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-OfficeDocLabel" for="DOWNLOAD_MENU_TYPE-OfficeDoc">doc</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-OfficePpt" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-OfficePptLabel" for="DOWNLOAD_MENU_TYPE-OfficePpt">ppt</label>
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">Hancom</th>
							<td class="ipt">
								<div>
									<input class="check" id="DOWNLOAD_MENU_TYPE-HancomVisible" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-HancomVisibleLabel" for="DOWNLOAD_MENU_TYPE-HancomVisible">표시</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-HancomHwp" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-HancomHwpLabel" for="DOWNLOAD_MENU_TYPE-HancomHwp">hwp</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-HancomCell" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-HancomCellLabel" for="DOWNLOAD_MENU_TYPE-HancomCell">cell</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-HancomShow" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-HancomShowLabel" for="DOWNLOAD_MENU_TYPE-HancomShow">show</label>
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">기타</th>
							<td class="ipt">
								<div>
									<input class="check" id="DOWNLOAD_MENU_TYPE-EtcVisible" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-EtcVisibleLabel" for="DOWNLOAD_MENU_TYPE-EtcVisible">표시</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-EtcImg" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-EtcImgLabel" for="DOWNLOAD_MENU_TYPE-EtcImg">img</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-EtcHtml" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-EtcHtmlLabel" for="DOWNLOAD_MENU_TYPE-EtcHtml">html</label>
									<input class="check" id="DOWNLOAD_MENU_TYPE-EtcPdf" type="checkbox">
									<label id="DOWNLOAD_MENU_TYPE-EtcPdfLabel" for="DOWNLOAD_MENU_TYPE-EtcPdf">pdf</label>
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">다운로드(아이템별)</th>
							<td class="ipt">
								<div>
									<input class="check" id="ITEM_DOWNLOAD-Expand" type="checkbox">
									<label id="ITEM_DOWNLOAD-ExpandLabel" for="ITEM_DOWNLOAD-Expand">다운로드 확장</label>
								</div>
							</td>
						</tr>
						<tr>
							<th class="left">다운로드 타입</th>
							<td class="ipt">
							    <select id="reportDownloadType">
							        <option value="Default">기본 다운로드</option>
							        <option value="Dev_nonExcelJs">DEV</option>
							        <option value="Dev_ExcelJs">DEV.ExcelJs</option>
							    </select>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
			
			<h4 class="tit-level3 pre">분석항목 폴더 그룹 설정</h4>
			<div class="tbl data-form preferences-tbl">
				<table>
					<caption>분석항목 폴더 그룹 설정</caption>
					<colgroup>
						<col style="width: 150px">
						<col style="width: auto">
					</colgroup>
					<tbody>
						<tr>
							<th class="left">폴더 그룹화</th>
							<td class="ipt">
								<div>
									<input class="check" id="GROUP_FOLDER_YN" type="checkbox">
									<label id="GROUP_FOLDER_YN_CHK" for="GROUP_FOLDER_YN"></label>
								</div>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
		</div>
	</div>
</div>