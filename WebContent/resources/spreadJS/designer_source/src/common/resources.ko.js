(function () {
    'use strict';
    var designer = GC.Spread.Sheets.Designer;
    var ko_res = {};


    ko_res.title = "스프레드시트 디자이너";
    ko_res.defaultFont = "11pt Calibri";
    ko_res.ok = "확인";
    ko_res.yes = "예";
    ko_res.no = "아니요";
    ko_res.apply = "적용";
    ko_res.cancel = "취소";
    ko_res.close = "닫기";
    ko_res.fileAPINotSupported = "브라우저가 File API를 지원하지 않습니다.";
    ko_res.blobNotSupported = "브라우저가 Blob 객체를 지원하지 않습니다.";

    ko_res.saveFileDialogTitle = "다른 이름으로 저장";
    ko_res.openFileDialogTitle = "열기";
    ko_res.allSpreadFileFilter = '모든 스프레드시트 파일(*.ssjson *.xlsx *.csv)';
    ko_res.spreadFileFilter = 'SpreadJS 파일(*.ssjson)';
    ko_res.ssJSONToJSFilter = 'Javascript 파일(*.js)';
    ko_res.allExcelFilter = "모든 Excel 파일(*.xlsx)";
    ko_res.excelFileFilter = 'Excel 통합 문서(*.xlsx)';
    ko_res.csvFileFilter = "CSV 파일(*.csv)";
    ko_res.pdfFileFilter = "PDF 파일(*.pdf)";
    ko_res.allFileFilter = '모든 파일(*.*)';
    ko_res.importFileDialogTitle = "가져오기";
    ko_res.exportFileDialogTitle = "내보내기";

    ko_res.insertCellInSheet = "전체 시트에서 셀을 이동할 수 없습니다.";
    ko_res.insertCellInMixtureRange = "전체 행이나 열 또는 다른 셀을 포함하는 선택 범위에서는 실행할 수 없는 명령입니다. 전체 행만 또는 열만 선택하거나 셀 그룹을 선택하세요.";
    ko_res.NotExecInMultiRanges = "다중 선택 범위에서는 사용할 수 없는 명령입니다. 한 번에 한 범위만 선택한 다음 명령을 다시 실행하세요.";
    ko_res.unsavedWarning = "파일을 저장할 수 없습니다. 저장하시겠습니까?";
    ko_res.errorGroup = "시트에 아웃라인 열이 있습니다. 작업을 계속하시겠습니까?";

    ko_res.requestTempalteFail = "템플릿 파일 요청 오류입니다.";
    ko_res.requestTemplateConfigFail = "템플릿 구성 파일 요청 오류입니다.";
    ko_res.openFileFormatError = "파일 형식이 올바르지 않습니다.";

    ko_res.closingNotification = "경고: 현재 파일이 수정되었습니다.\n변경 내용을 이 파일에 저장하시겠습니까?";


    ko_res.sameSlicerName = "이 슬라이서 이름은 이미 사용되고 있습니다. 고유한 이름을 입력하세요.";
    ko_res.nullSlicerName = "슬라이서 이름이 잘못되었습니다.";

    ko_res.changePartOfArrayWarning = "배열 수식의 일부를 변경할 수 없습니다.";
    ko_res.changePartOfTableWarning = "워크시트의 표에 있는 셀이 이동될 수 있으므로 이 작업은 수행되지 않습니다.";
    ko_res.exportCsvSheetIndexError = "시트 인덱스가 잘못되었습니다.";

    ko_res.fontPicker = {
        familyLabelText: '글꼴:',
        styleLabelText: '글꼴 스타일:',
        sizeLabelText: '크기:',
        weightLabelText: '두께:',
        colorLabelText: '색상:',
        normalFontLabelText: '기본 글꼴',
        previewLabelText: '미리 보기',
        previewText: 'AaBbCcYyZz',
        effects: "효과",
        underline: "밑줄",
        doubleUnderline: "이중 밑줄",
        strikethrough: "취소선",
        //
        // Fonts shown in font selector.
        //
        // the property's name means the font family name.
        // the property's value means the text shown in drop down list.
        //
        fontFamilies: {
            "Arial": "Arial",
            "'Arial Black'": "Arial Black",
            "Calibri": "Calibri",
            "Cambria": "Cambria",
            "Candara": "Candara",
            "Century": "Century",
            "'Courier New'": "Courier New",
            "'Comic Sans MS'": "Comic Sans MS",
            "Garamond": "Garamond",
            "Georgia": "Georgia",
            "'맑은 고딕'": "맑은 고딕",
            "Mangal": "Mangal",
            "Tahoma": "Tahoma",
            "Times": "Times",
            "'Times New Roman'": "Times New Roman",
            "'Trebuchet MS'": "Trebuchet MS",
            "Verdana": "Verdana",
            "Wingdings": "Wingdings",
            "Meiryo": "Meiryo",
            "'MS Gothic'": "MS Gothic",
            "'MS Mincho'": "MS Mincho",
            "'MS PGothic'": "MS PGothic",
            "'MS PMincho'": "MS PMincho"
        },
        fontStyles: {
            'normal': '보통',
            'italic': '기울임꼴',
            'oblique': '오블리크'
        },
        fontWeights: {
            'normal': '보통',
            'bold': '굵게',
            'bolder': '더 굵게',
            'lighter': '더 얇게'
        },
        alternativeFonts: "Arial,'Segoe UI',Thonburi,Verdana,Sans-Serif",
        defaultSize: '10'
    };

    ko_res.commonFormats = {
        Number: {
            format: "0.00",
            label: "숫자"
        },
        Currency: {
            format: "$#,##0.00",
            label: "통화"
        },
        Accounting: {
            format: "_($* #,##0.00_);_($* (#,##0.00);_($* \"-\"??_);_(@_)",
            label: "회계"
        },
        ShortDate: {
            format: "m/d/yyyy",
            label: "간단한 날짜"
        },
        LongDate: {
            format: "dddd, mmmm dd, yyyy",
            label: "자세한 날짜"
        },
        Time: {
            format: "h:mm:ss AM/PM",
            label: "시간"
        },
        Percentage: {
            format: "0%",
            label: "백분율"
        },
        Fraction: {
            format: "# ?/?",
            label: "분수"
        },
        Scientific: {
            format: "0.00E+00",
            label: "지수"
        },
        Text: {
            format: "@",
            label: "텍스트"
        },
        Comma: {
            format: '_(* #,##0.00_);_(* (#,##0.00);_(* "-"??_);_(@_)',
            label: "쉼표"
        }
    };
    ko_res.customFormat = "사용자 지정";
    ko_res.generalFormat = "일반";

    ko_res.colorPicker = {
        themeColorsTitle: "테마 색",
        standardColorsTitle: "표준 색",
        noFillText: "색 없음",
        moreColorsText: "추가 색...",
        colorDialogTitle: "색",
        red: "빨강: ",
        green: "녹색: ",
        blue: "파랑: ",
        newLabel: "새로 만들기",
        currentLabel: "현재"
    };

    ko_res.formatDialog = {
        title: "셀 서식",
        number: '번호',
        alignment: '맞춤',
        fonts: "글꼴",
        font: '글꼴',
        border: '테두리',
        padding: '안쪽 여백',
        label: '레이블',
        cellContent: "셀 내용",
        labelContent: "레이블 내용",
        text: "텍스트",
        margin: "여백",
        fill: '테두리',
        protection: '보호',
        category: '범주:',
        backColor: '배경색',
        textAlignment: '텍스트 맞춤',
        horizontalAlignment: '가로:',
        verticalAlignment: '세로:',
        indent: '들여쓰기:',
        degrees: "도",
        rotateText: "텍스트",
        orientation: "방향",
        textControl: '텍스트 조정',
        wrapText: '텍스트 줄 바꿈',
        shrink: '셀에 맞춤',
        merge: '셀 병합',
        top: '위쪽',
        bottom: '아래쪽',
        left: '왼쪽',
        right: '오른쪽',
        center: '가운데',
        general: '일반',
        sampleText: '텍스트',
        cantMergeMessage: '겹쳐져 있는 범위는 병합할 수 없습니다.',
        lock: "잠금",
        lockComments: "워크시트를 보호하지 않으면 셀을 잠가도 아무 효과가 없습니다(서식 드롭다운 목록에서 홈 탭, 셀 그룹, '시트 보호' 단추 선택).",
        backGroundColor: "배경색:",
        moreColorsText: "추가 색",
        sample: "보기",
        preview: "미리 보기",
        paddingPreviewText: "내용",
        visibility: "표시 여부",
        labelVisibility: {
            visible: "표시 가능",
            hidden: "숨김",
            auto: "자동"
        },
        vertical: "세로 텍스트",
        cellButton: "셀 버튼",
        addButton: "추가",
        deleteButton: "삭제",
        cellButtonImageType: "이미지 유형",
        cellButtonCommand: "명령",
        cellButtonUserButtonStyle: "버튼 스타일 사용",
        cellButtonVisibility: "표시 여부",
        cellButtonPosition: "위치",
        cellButtonEnable: "활성화",
        cellButtonWidth: "너비",
        cellButtonCaption: "캡션",
        cellButtonImageSrc: "이미지 Src",
        cellButtonImageLoad: "로드",
        cellButtonCaptionAlign: "캡션 정렬",
        cellButtonImageWidth: "이미지 너비",
        cellButtonImageHeight: "이미지 높이",
        cellButtonCommands: {
            openColorPicker: "색상 선택 도구",
            openDateTimePicker: "시간날짜 선택 도구",
            openTimePicker: "시간 선택 도구",
            openCalculator: "계산기",
            openMonthPicker: "월 선택 도구",
            openList: "목록",
            openSlider: "슬라이더",
            openWorkflowList: "워크플로 목록",
        },
        cellButtonImageTypes: {
            custom: "사용자 정의",
            clear: "지우기",
            cancel: "취소",
            ok: "확인",
            dropdown: "드롭다운",
            ellipsis: "줄임표",
            left: "왼쪽",
            right: "오른쪽",
            plus: "더하기",
            minus: "빼기",
            undo: "실행 취소",
            redo: "다시 실행",
            search: "검색",
            separator: "구분 기호",
            spinLeft: "왼쪽 스핀",
            spinRight: "오른쪽 스핀",
        },
        cellButtonVisibilitys: {
            always: "항상",
            onseleciton: "선택",
            onedit: "편집"
        },
    };
    ko_res.dropdownDialog = {
        width: "너비",
        height: "높이",
        value: "값",
        text: "텍스트",
        min: "최소값",
        max: "최대값",
        step: "단계",
        direction: "방향",
        horizontal: "가로",
        vertical: "세로",
        list: {
            title: "목록",
            hasChild: "하위 있음",
            wrap: "줄 바꿈",
            displayAs: "표시",
            inline: "인라인",
            popup: "팝업",
            tree: "트리",
            collapsible: "축소 가능",
            icon: "아이콘",
            isBigIcon: "큰 아이콘",
        },
        datetimepicker: {
            title: "시간날짜 선택 도구",
            startDay: "시작 요일",
            monday: "월요일",
            tuesday: "화요일",
            wednesday: "수요일",
            thursday: "목요일",
            friday: "금요일",
            saturday: "토요일",
            sunday: "일요일",
            calendarPage: "달력 페이지",
            day: "일",
            year: "년",
            month: "월",
            showTime: "시간 표시"
        },
        timepicker: {
            title: "시간 선택 도구",
            hour: "시",
            minute: "분",
            second: "초",
            format: "서식",
            formatters: [
                "[$-409]h:mm:ss AM/PM",
                "h:mm;@",
                "[$-409]h:mm AM/PM;@",
                "h:mm:ss;@",
                "[$-409]h:mm:ss AM/PM;@",
                "mm:ss.0;@",
                "[h]:mm:ss;@",
                "[$-409]m/d/yy h:mm AM/PM;@",
                "m/d/yy h:mm;@",
                'h"时"mm"分";@',
                'h"时"mm"分"ss"秒";@',
                '[$-804]AM/PM h"时"mm"分";;@',
                '[$-804]AM/PM h"时"mm"分"ss"秒";@',
                '[DBNum1][$-804]h"时"mm"分";@',
                '[DBNum1][$-804]AM/PM h"时"mm"分";@',
                'h"時"mm"分";@',
                'h"時"mm"分"ss"秒";@',
                "[$-412]AM/PM h:mm;@",
                "[$-412]AM/PM h:mm:ss;@",
                "[$-409]h:mm AM/PM;@",
                "[$-409]h:mm:ss AM/PM;@",
                'yyyy"-"m"-"d h:mm;@',
                '[$-412]yyyy"-"m"-"d AM/PM h:mm;@',
                '[$-409]yyyy"-"m"-"d h:mm AM/PM;@',
                'h"시" mm"분";@',
                'h"시" mm"분" ss"초";@',
                '[$-412]AM/PM h"시" mm"분";@',
                '[$-412]AM/PM h"시" mm"분" ss"초";@'
            ]
        },
        monthpicker: {
            title: "월 선택 도구",
            startYear: "시작 연도",
            stopYear: "마침 연도",
        },
        slider: {
            title: "슬라이더",
            scaleVisible: "스케일 표시",
            tooltipVisible: "툴팁 표시",
            marks: "눈금",
            formatter: "서식",
            formatters: [
                "0",
                "0.00",
                "#,##0",
                "#,##0.00",
                "#,##0;(#,##0)",
                "#,##0.00;(#,##0.00)",
                "$#,##0;($#,##0)",
                "$#,##0.00;($#,##0.00)",
                "0%",
                "0.00%",
                "0.00E+00",
                "##0.0E+0",
                ' $* #,##0.00 ; $* #,##0.00 ; $* "-" ; @ ',
                '_-[$¥-804]* #,##0.00_-;-[$¥-804]* #,##0.00_-;_-[$¥-804]* "-"_-;_-@_-',
                '_-[$¥-411]* #,##0.00_-;-[$¥-411]* #,##0.00_-;_-[$¥-411]* "-"_-;_-@_-',
                '_-[$₩-412]* #,##0.00_-;-[$₩-412]* #,##0.00_-;_-[$₩-412]* "-"_-;_-@_-'
            ]
        },
        workflowlist: {
            title: "워크플로 목록",
            transitions: "전환",
            statusSetting: "상태 설정",
            processFlow: "진행 흐름"
        },
        colorpicker: {
            title: "색상 선택 도구",
            colorWidth: "블록 너비",
            themeColor: "테마 색상",
            stardardColor: "표준 색상"
        }
    };

    ko_res.formatComment = {
        title: "메모 서식",
        protection: "보호",
        commentLocked: "잠금",
        commentLockText: "텍스트 잠금",
        commentLockComments: "시트를 보호하지 않으면 개체를 잠가도 아무 효과가 없습니다. 시트를 보호하려면 [홈] 탭에서 서식을 선택한 다음 [시트 보호]를 선택하세요.",
        properties: "속성",
        positioning: "개체 위치 지정",
        internalMargin: "안쪽 여백",
        moveSize: "위치와 크기 변함",
        moveNoSize: "위치만 변함",
        noMoveSize: "변하지 않음",
        automatic: "자동",
        autoSize: "자동 크기",
        colors: "색 및 선",
        size: "크기",
        fill: "채우기",
        line: "선",
        height: "높이",
        width: "너비",
        lockRatio: "가로 세로 비율 고정",
        color: "색",
        transparency: "투명도",
        style: "스타일",
        dotted: "점선",
        dashed: "파선",
        solid: "단색",
        double: "실수(Double)",
        none: "없음",
        groove: "오목",
        ridge: "볼록",
        inset: "넣기",
        outset: "빼기",
        px: "px"
    };

    ko_res.categories = {
        general: "일반",
        numbers: "숫자",
        currency: "통화",
        accounting: "회계",
        date: "날짜",
        time: "시간",
        percentage: "백분율",
        fraction: "분수",
        scientific: "지수",
        text: "텍스트",
        special: "기타",
        custom: "사용자 지정"
    };

    ko_res.formatNumberComments = {
        generalComments: "일반 셀 서식에서는 특정 서식을 지정하지 않습니다.",
        numberComments: "숫자 서식은 일반적인 숫자를 나타내는 데 사용합니다. 통화 및 회계 표시 형식에는 화폐 가치에 대한 특수 서식이 있습니다.",
        currencyComments: "통화 서식은 일반 통화 수치에 사용합니다. 회계 서식을 사용하면 소수점에 맞추어 열이 정렬됩니다.",
        accountingComments: "회계 서식을 사용하면 통화 기호와 소수점에 맞추어 열이 정렬됩니다.",
        dateComments: "날짜 서식으로 날짜와 시간에 해당하는 일련의 숫자를 날짜값으로 나타낼 수 있습니다.",
        timeComments: "시간 서식으로 날짜와 시간에 해당하는 일련의 숫자를 날짜값으로 나타낼 수 있습니다.",
        percentageComments: "백분율 서식을 사용하면 셀 값에 100을 곱한 값이 백분율 기호와 함께 나타납니다.",
        textComments: "텍스트 서식으로 지정된 셀에 있는 숫자는 텍스트로 처리되므로 입력한 대로 표시됩니다.",
        specialComments: "기타 서식은 목록 및 데이터베이스 값을 찾을 때에 사용합니다.",
        customComments: "기존의 형식 중 하나를 선택한 후 변형시킵니다."
    };

    ko_res.formatNumberPickerSetting = {
        type: "유형:",
        decimalPlaces: "소수 자릿수:",
        symbol: "기호:",
        negativeNumber: "음수:",
        separator: "1000 단위 구분 기호(,) 사용",
        deleted: "삭제",
        locale: "로캘(위치):",
        calendar: "달력 종류:"
    };

    ko_res.localeType = {
        en_us: "영어(미국)",
        ja_jp: "일본어",
        zh_cn: "중국말",
        ko_kr: "한국어"
    };

    ko_res.calendarType = {
        western: "서유럽/미국 영문자",
        JER: "일본 연호"
    };

    ko_res.fractionFormats = [
        "# ?/?",
        "# ??/??",
        "# ???/???",
        "# ?/2",
        "# ?/4",
        "# ?/8",
        "# ??/16",
        "# ?/10",
        "# ??/100"
    ];

    ko_res.numberFormats = [
        "0",
        "0;[Red]0",
        "0_);(0)",
        "0_);[Red](0)",
        "#,##0",
        "#,##0;[Red]#,##0",
        "#,##0_);(#,##0)",
        "#,##0_);[Red](#,##0)"
    ];

    ko_res.dateFormats = [
        "m/d/yyyy",
        "[$-409]dddd, mmmm dd, yyyy",
        "m/d;@",
        "m/d/yy;@",
        "mm/dd/yy;@",
        "[$-409]d-mmm;@",
        "[$-409]d-mmm-yy;@",
        "[$-409]dd-mmm-yy;@",
        "[$-409]mmm-yy;@",
        "[$-409]mmmm-yy;@",
        "[$-409]mmmm d, yyyy;@",
        "[$-409]m/d/yy h:mm AM/PM;@",
        "m/d/yy h:mm;@",
        "[$-409]mmmmm;@",
        "[$-409]mmmmm-yy;@",
        "m/d/yyyy;@",
        "[$-409]d-mmm-yyyy;@"
    ];

    ko_res.chinaDateFormat = [
        "yyyy-mm-dd;@",
        '[DBNum1][$-804]yyyy"年"m"月"d"日";@',
        '[DBNum1][$-804]yyyy"年"m"月";@',
        '[DBNum1][$-804]m"月"d"日";@',
        "[$-409]yyyy/m/d h:mm AM/PM;@",
        'yyyy"年"m"月"d"日";@',
        'yyyy"年"m"月";@',
        'm"月"d"日";@',
        "mm/dd/yy;@",
        "m/d/yy;@",
        "yyyy/m/d h:mm AM/PM;@",
        "yyyy/m/d h:mm;@",
        "[$-409]d-mmm;@",
        "[$-409]d-mmm-yy;@",
        "[$-409]dd-mmm-yy;@",
        "[$-409]mmm-yy;@",
        "[$-409]m",
        "[$-409]m-d;@"
    ];
    ko_res.koreanDateFormat = [
        "yyyy-mm-dd;@",
        'yyyy"년" m"월" d"일";@',
        'yy"年" m"月" d"日";@',
        'yyyy"년" m"월";@',
        'm"월" d"일";@',
        "yy-m-d;@",
        "yy-m-d h:mm;@",
        'm"月"d"日";@',
        "[$-412]yy-m-d AM/PM h:mm;@",
        "yy/m/d;@",
        "yyyy/m/d h:mm;@",
        "m/d;@",
        "m/d/yy;@",
        "mm/dd/yy;@",
        "[$-409]d-mmm;@",
        "[$-409]d-mmm-yy;@",
        "[$-409]dd-mmm-yy;@",
        "[$-409]mmm-yy;@",
        "[$-409]m",
        "[$-409]m-d;@"
    ];
    ko_res.japanWesternDateFormat = [
        'yyyy"年"m"月"d"日";@',
        'yyyy"年"m"月";@',
        'm"月"d"日";@',
        "yyyy/m/d;@",
        "[$-409]yyyy/m/d h:mm AM/PM;@",
        "yyyy/m/d h:mm;@",
        "m/d;@",
        "m/d/yy;@",
        "mm/dd/yy;@",
        "[$-409]d-mmm;@",
        "[$-409]d-mmm-yy;@",
        "[$-409]dd-mmm-yy;@",
        "[$-409]mmm-yy;@",
        "[$-409]mmmm-yy;@",
        "[$-409]mmmmm;@",
        "[$-409]mmmmm-yy;@"
    ];

    ko_res.japanEmperorReignDateFormat = [
        "[$-411]ge.m.d;@",
        '[$-411]ggge"年"m"月"d"日";@'
    ];

    ko_res.timeFormats = [
        "[$-409]h:mm:ss AM/PM",
        "h:mm;@",
        "[$-409]h:mm AM/PM;@",
        "h:mm:ss;@",
        "[$-409]h:mm:ss AM/PM;@",
        "mm:ss.0;@",
        "[h]:mm:ss;@",
        "[$-409]m/d/yy h:mm AM/PM;@",
        "m/d/yy h:mm;@"
    ];

    ko_res.chinaTimeFormats = [
        "h:mm;@",
        "[$-409]h:mm AM/PM;@",
        "h:mm:ss;@",
        'h"时"mm"分";@',
        'h"时"mm"分"ss"秒";@',
        '[$-804]AM/PM h"时"mm"分";;@',
        '[$-804]AM/PM h"时"mm"分"ss"秒";@',
        '[DBNum1][$-804]h"时"mm"分";@',
        '[DBNum1][$-804]AM/PM h"时"mm"分";@'
    ];
    ko_res.koreanTimeFormats = [
        "h:mm;@",
        "h:mm:ss;@",
        "[$-412]AM/PM h:mm;@",
        "[$-412]AM/PM h:mm:ss;@",
        "[$-409]h:mm AM/PM;@",
        "[$-409]h:mm:ss AM/PM;@",
        'yyyy"-"m"-"d h:mm;@',
        '[$-412]yyyy"-"m"-"d AM/PM h:mm;@',
        '[$-409]yyyy"-"m"-"d h:mm AM/PM;@',
        'h"시" mm"분";@',
        'h"시" mm"분" ss"초";@',
        '[$-412]AM/PM h"시" mm"분";@',
        '[$-412]AM/PM h"시" mm"분" ss"초";@'
    ];
    ko_res.japanTimeFormats = [
        "h:mm;@",
        "[$-409]h:mm AM/PM;@",
        "h:mm:ss;@",
        "[$-409]h:mm:ss AM/PM;@",
        "[$-409]yyyy/m/d h:mm AM/PM;@",
        "yyyy/m/d h:mm;@",
        'h"時"mm"分";@',
        'h"時"mm"分"ss"秒";@'
    ];

    ko_res.textFormats = [
        "@"
    ];

    ko_res.specialFormats = [
        "00000",
        "00000-0000",
        "[<=9999999]###-####;(###) ###-####",
        "000-00-0000"
    ];

    ko_res.specialJapanFormats = [
        "[<=999]000;[<=9999]000-00;000-0000",
        "[<=99999999]####-####;(00) ####-####",
        "'△' #,##0;'▲' #,##0",
        "[DBNum1][$-411]General",
        "[DBNum2][$-411]General",
        "[DBNum3][$-411]0",
        "[DBNum3][$-411]#,##0"
    ];

    ko_res.specialKoreanFormats = [
        "000-000",
        "[<=999999]####-####;(0##) ####-####",
        "[<=9999999]###-####;(0##) ###-####",
        "000000-0000000",
        "[DBNum1][$-412]General",
        "[DBNum2][$-412]General",
        "[$-412]General"
    ];
    ko_res.specialChinaFormats = [
        "000000",
        "[DBNum1][$-804]General",
        "[DBNum2][$-804]General"
    ];
    ko_res.currencyFormats = [
        "#,##0",
        "#,##0;[Red]#,##0",
        "#,##0;-#,##0",
        "#,##0;[Red]-#,##0"
    ];

    ko_res.percentageFormats = [
        "0%"
    ];

    ko_res.scientificFormats = [
        "0E+00"
    ];

    ko_res.accountingFormats = [
        '_(* #,##0_);_(* (#,##0);_(* \"-\"?_);_(@_)',
        '_($* #,##0_);_($* (#,##0);_($* \"-\"?_);_(@_)',
        '_ [$¥-804]* #,##0_ ;_ [$¥-804]* \\-#,##0_ ;_ [$¥-804]* "-"?_ ;_ @_ ',
        '_-[$¥-411]* #,##0_-;\\-[$¥-411]* #,##0_-;_-[$¥-411]* "-"?_-;_-@_-',
        '_-[$₩-412]* #,##0_-;\\-[$₩-412]* #,##0_-;_-[$₩-412]* "-"?_-;_-@_-'
    ];

    ko_res.customFormats = [
        "일반",
        "0",
        "0.00",
        "#,##0",
        "#,##0.00",
        "#,##0;(#,##0)",
        "#,##0;[Red](#,##0)",
        "#,##0.00;(#,##0.00)",
        "#,##0.00;[Red](#,##0.00)",
        "$#,##0;($#,##0)",
        "$#,##0;[Red]($#,##0)",
        "$#,##0.00;($#,##0.00)",
        "$#,##0.00;[Red]($#,##0.00)",
        "0%",
        "0.00%",
        "0.00E+00",
        "##0.0E+0",
        "# ?/?",
        "# ??/??",
        "m/d/yyyy",
        "d-mmm-yy",
        "d-mmm",
        "mmm-yy",
        "h:mm AM/PM",
        "h:mm:ss AM/PM",
        "hh:mm",
        "hh:mm:ss",
        "m/d/yyyy hh:mm",
        "mm:ss",
        "mm:ss.0",
        "@",
        "[h]:mm:ss",
        "$ #,##0;$ (#,##0);$ \"-\";@",
        " #,##0; (#,##0); \"-\";@",
        "$ #,##0.00;$ (#,##0.00);$ \"-\"??;@",
        " #,##0.00; (#,##0.00); \"-\"??;@",
        "hh:mm:ss",
        "00000",
        "# ???/???",
        "000-00-0000",
        "dddd, mmmm dd, yyyy",
        "m/d;@",
        "[<=9999999]###-####;(###) ###-####",
        "# ?/8"
    ];

    ko_res.accountingSymbol = [
        ["없음", null, null],
        ["$", "$", "en-US"],
        ["¥(Chinese)", "¥", "zh-cn"],
        ["¥(Japanese)", "¥", "ja-jp"],
        ["₩(Korean)", "₩", "ko-kr"]
    ];

    ko_res.specialType = [
        "우편 번호",
        "우편 번호 + 4",
        "전화 번호",
        "주민 등록 번호"
    ];

    ko_res.specialJapanType = [
        "郵便番号",
        "電話番号（東京)",
        "正負記号 （+ = △; - = ▲)",
        "漢数字（十二万三千四百）",
        "大字 (壱拾弐萬参阡四百)",
        "全角 (１２３４５)",
        "全角 桁区切り（１２,３４５）"
    ];
    ko_res.specialKoreanType = [
        "우편 번호",
        "전화 번호 (국번 4자리)",
        "전화 번호 (국번 3자리)",
        "주민등록번호",
        "숫자(한자)",
        "숫자(한자-갖은자)",
        "숫자(한글)"
    ];
    ko_res.specialChinaType = [
        "邮政编码",
        "中文小写字母",
        "中文大写字母"
    ];

    ko_res.fractionType = [
        "한 자릿수 분모(1/4)",
        "두 자릿수 분모(21/25)",
        "세 자릿수 분모(312/943)",
        "분모를 2로(1/2)",
        "분모를 4로(2/4)",
        "분모를 8로(4/8)",
        "분모를 16으로(8/16)",
        "분모를 10으로(3/10)",
        "분모를 100으로(30/100)"
    ];

    ko_res.negativeNumbers = {
        "-1234.10": "-1234.10",
        "red:1234.10": "1234.10",
        "(1234.10)": "(1234.10)",
        "red:(1234.10)": "(1234.10)"
    };

    ko_res.currencyNegativeNumbers = {
        "number1": "-1,234.10",
        "red:number2": "1,234.10",
        "number3": "-1,234.10",
        "red:number4": "-1,234.10"
    };

    ko_res.passwordDialog = {
        title: "암호",
        passwordLabel: "암호:"
    };
    ko_res.rowHeightDialog = {
        title: "행 높이",
        rowHeight: "행 높이:",
        exception: "행 높이는 숫자 또는동적 크기(3*처럼 숫자에 별표시가 있음)여야 합니다..",
        exception2: "행 높이는 0과 9999999 사이여야 합니다."
    };
    ko_res.chart = {
        formatChartArea: "서식",
        properties: '속성',
        moveAndSizeWithCells: '위치와 크기 변함',
        moveButDoNotSizeWithCells: '위치만 변함',
        locked: '잠김',
        color: "색",
        transparency: '투명도',
        selectedOption: {
            series: '계열 옵션',
            dataPoints: "계열 옵션",
            chartArea: '차트 옵션',
            chartTitle: '제목 옵션',
            legend: '범례 옵션',
            label: "레이블 옵션",
            errorBar: "오류 바 옵션",
            trendline: "추세선 옵션",
            plotArea: '플롯 영역 옵션',
            dataLabels: '레이블 옵션',
            primaryCategory: '축 옵션',
            primaryValue: '축 옵션',
            primaryCategoryTitle: '제목 옵션',
            primaryValueTitle: '제목 옵션',
            primaryCategoryMajorGridLine: '주요 눈금선 옵션',
            primaryValueMajorGridLine: '주요 눈금선 옵션',
            primaryCategoryMinorGridLine: '보조 눈금선 옵션',
            primaryValueMinorGridLine: '보조 눈금선 옵션',
            primaryValueUnitsLabel: "레이블 옵션",
            secondaryCategory: '축 옵션',
            secondaryValue: '축 옵션',
            secondaryCategoryTitle: '제목 옵션',
            secondaryValueTitle: '제목 옵션',
            secondaryCategoryMajorGridLine: '주요 눈금선 옵션',
            secondaryValueMajorGridLine: '주요 눈금선 옵션',
            secondaryCategoryMinorGridLine: '보조 눈금선 옵션',
            secondaryValueMinorGridLine: '보조 눈금선 옵션',
            secondaryValueUnitsLabel: "레이블 옵션"
        },
        selectedText: {
            series: '계열',
            errorBar: "오차 막대",
            trendline: "추세선",
            dataPoints: '데이터 요소',
            chartArea: '차트 영역',
            chartTitle: '차트 제목',
            legend: '범례',
            dataLabels: '데이터 레이블',
            plotArea: '그림 영역',
            primaryCategory: '가로(범주) 축',
            primaryValue: '세로(값) 축',
            primaryCategoryTitle: '가로(범주) 축 제목',
            primaryValueTitle: '세로(값) 축 제목',
            primaryCategoryMajorGridLine: '가로(범주) 축 주요 눈금선',
            primaryValueMajorGridLine: '세로(값) 축 주요 눈금선',
            primaryCategoryMinorGridLine: '가로(범주) 축 보조 눈금선',
            primaryValueMinorGridLine: '세로(값) 축 보조 눈금선',
            primaryValueUnitsLabel: "세로(값) 축 표시 단위 레이블",
            secondaryCategory: '보조 가로(범주) 축',
            secondaryValue: '보조 세로(값) 축',
            secondaryCategoryTitle: '보조 가로(범주) 축 제목',
            secondaryValueTitle: '보조 세로(값) 축 제목',
            secondaryCategoryMajorGridLine: '보조 가로(범주) 축 주요 눈금선',
            secondaryValueMajorGridLine: '보조 세로(값) 축 주요 눈금선',
            secondaryCategoryMinorGridLine: '보조 가로(범주) 축 보조 눈금선',
            secondaryValueMinorGridLine: '보조 세로(값) 축 보조 눈금선',
            secondaryValueUnitsLabel: "보조 세로(값) 축 표시 단위 레이블"
        },
        selectedRadarChartText: {
            primaryCategory: '항목 레이블',
        },
        selectedBarChartText: {
            primaryCategory: '세로(범주) 축',
            primaryValue: '가로(값) 축',
            primaryCategoryTitle: '세로(범주) 축 제목',
            primaryValueTitle: '가로(값) 축 제목',
            primaryCategoryMajorGridLine: '세로(범주) 축 주요 눈금선',
            primaryValueMajorGridLine: '가로(값) 축 주요 눈금선',
            primaryCategoryMinorGridLine: '세로(범주) 축 보조 눈금선',
            primaryValueMinorGridLine: '가로(값) 축 보조 눈금선',
            primaryValueUnitsLabel: "가로(값) 축 표시 단위 레이블",
            secondaryCategory: '보조 세로(범주) 축',
            secondaryValue: '보조 가로(값) 축',
            secondaryCategoryTitle: '보조 세로(범주) 축 제목',
            secondaryValueTitle: '보조 가로(값) 축 제목',
            secondaryCategoryMajorGridLine: '보조 세로(범주) 축 주요 눈금선',
            secondaryValueMajorGridLine: '보조 가로(값) 축 주요 눈금선',
            secondaryCategoryMinorGridLine: '보조 세로(범주) 축 보조 눈금선',
            secondaryValueMinorGridLine: '보조 가로(값) 축 보조 눈금선',
            secondaryValueUnitsLabel: "보조 가로(값) 축 표시 단위 레이블"
        },
        formatChart: {
            dataSeries: ' 데이터 계열:',
            errorBar: ' 오차 막대',
            trendline: ' 추세선',
            dataPoints: ' 데이터 요소',
            axis: ' 축',
            legend: ' 범례',
            dataLable: ' 데이터 레이블',
            chartTitle: ' 차트 제목',
            plotArea: ' 그림 영역',
            chartArea: ' 차트 영역',
            unitsLabel: ' 표시 단위 레이블'
        }
    };

    ko_res.chartSliderPanel = {
        tick: {
            cross: "교차",
            inside: '내부',
            none: '없음',
            outSide: '외부'
        },
        axisFormat: {
            General: "일반",
            Number: "숫자",
            Currency: "통화",
            Accounting: "회계",
            Date: "날짜",
            Time: "시간",
            Percentage: "백분율",
            Fraction: "분수",
            Scientific: "지수",
            Text: "텍스트",
            Special: "특수",
            Custom: "사용자 정의",
            Add: "추가",
            formatCode: "형식 코드",
            category: "범주"
        },
        noLine: '선 없음',
        solidLine: "실선",
        width: "너비",
        fontFamily: "글꼴 패밀리",
        fontSize: "글꼴 크기",
        noFill: '채우기 없음',
        solidFill: "단색 채우기",
        auto: '자동',
        reset: '다시 놓기',
        automatic: '자동',
        custom: "사용자 정의",
        color: '색',
        text: '텍스트',
        majorType: '주요 유형',
        minorType: '보조 유형',
        textAxis: '텍스트 축',
        dateAxis: '날짜 축',
        unitsMajor: '주 단위',
        unitsMinor: '보조 단위',
        maximum: '최대값',
        minimum: '최소값',
        height: '높이',
        top: '위쪽',
        bottom: '아래쪽',
        left: '왼쪽',
        right: '오른쪽',
        topRight: "오른쪽 위",
        primaryAxis: '기본 축',
        secondaryAxis: '보조 축',
        tickMarks: '눈금 표시',
        axisOptions: '축 옵션',
        line: '선',
        font: '글꼴',
        textFill: '텍스트 채우기',
        textEditor: '텍스트 편집기',
        size: '크기',
        fill: '채우기',
        legendPosition: '범례 위치',
        seriesOptions: '계열 옵션',
        border: '테두리',
        transparency: '투명도',
        none: "없음",
        builtIn: "기본 제공",
        shape: "셰이프",
        lintType: "파선 유형",
        markOptions: "표식 옵션",
        markFill: "표식 채우기",
        markBorder: "표식 테두리",
        logarithmicScale: "로그 눈금",
        logBase: "기본",
        dashStyle: "파선 유형",
        exponential: "지수",
        linear: "선형",
        logarithmic: "로그",
        polynomial: "다항식",
        power: "거듭제곱",
        movingAverage: "이동 평균",
        verticalErroeBar: "세로 오류 바",
        horizontalErrorBar: "가로 오류 바",
        both: "둘 다",
        minus: "빼기",
        plus: "더하기",
        noCap: "캡 없음",
        cap: "캡",
        fixed: "고정 값",
        percentage: "백분율",
        standardDev: "표준 편차",
        standardErr: "표준 오류",
        specifyValue: "값 지정",
        direction: "방향",
        endStyle: "끝 스타일",
        errorAmount: "오차량",
        bounds: "범위",
        units: "유닛(Units)",
        displayUnits: "표시 단위",
        displayUnit: {
            none: "없음",
            hundreds: "백",
            thousands: "천",
            tenThousands: "10,000",
            hundredThousands: "100,000",
            millions: "백만",
            tenMillions: "10,000,000",
            hundredMillions: "100,000,000",
            billions: "십억",
            trillions: "조",
        },
        showDisplayUnitsLabel: "차트에 표시 단위 레이블 표시",
        trendline: {
            exponential: "지수",
            linear: "선형",
            logarithmic: "로그",
            polynomial: "다항식",
            power: "거듭제곱",
            movingAverage: "이동 평균",
            name: "추세선 이름",
            forecast: "예측",
            forward: "앞으로",
            backward: "뒤로",
            intercept: "개입 설정",
            displayEquation: "차트에 수식 표시",
            displayRSquared: "차트에 분산 값 표시",
        }
    };

    ko_res.moveChartDialog = {
        title: "차트 이동",
        description: "차트 위치 선택:",
        newSheet: "새 시트:",
        existingSheet: "개체 위치:",
        errorPrompt: {
            sameSheetNameError: "이 시트가 있고 차트가 포함되어 있습니다. 다른 시트 이름을 지정하십시오."
        }
    };

    ko_res.selectChartDialog = {
        title: "차트 삽입",
        insertChart: "차트 삽입",
        changeChartType: "차트 유형 변경",
        defaultRowColumn: "기본 행 열 레이아웃",
        switchedRowColumn: "전환된 행 열 레이아웃",
        column: "열",
        columnClustered: "클러스터된 열",
        columnStacked: "누적 막대형",
        columnStacked100: "100% 기준 누적 막대형",
        line: "선",
        lineStacked: "누적 꺾은선형",
        lineStacked100: '100% 기준 누적 꺾은선형',
        lineMarkers: "표식이 있는 꺾은선형",
        lineMarkersStacked: "표식이 있는 누적 꺾은선형",
        lineMarkersStacked100: "표식이 있는 100% 기준 누적 꺾은선형",
        pie: "원형",
        doughnut: "도넛형",
        bar: "가로 막대형",
        area: "영역",
        XYScatter: "XY(분산형)",
        stock: "주식형",
        combo: "혼합형",
        radar: "방사형",
        sunburst: "선버스트",
        treemap: "트리맵",
        barClustered: "묶은 가로 막대형",
        barStacked: "누적 막대형",
        barStacked100: "100% 기준 누적 막대형",
        areaStacked: "누적 영역형",
        areaStacked100: "100% 기준 누적 영역형",
        xyScatter: "분산형",
        xyScatterSmooth: "곡선 및 표식이 있는 분산형",
        xyScatterSmoothNoMarkers: "곡선이 있는 분산형",
        xyScatterLines: "직선 및 표식이 있는 분산형",
        xyScatterLinesNoMarkers: "직선이 있는 분산형",
        bubble: "거품형",
        stockHLC: "고가-저가-종가",
        stockOHLC: "시가-고가-저가-종가",
        stockVHLC: "거래량-고가-저가-종가",
        stockVOHLC: "거래량-시가-고가-저가-종가",
        columnClusteredAndLine: "묶은 세로 막대형 - 꺾은선형",
        columnClusteredAndLineOnSecondaryAxis: "묶은 세로 막대형 - 꺾은선형, 보조 축",
        stackedAreaAndColumnClustered: "누적 영역형 - 묶은 세로 막대형",
        customCombination: "사용자 정의 혼합형",
        radarMarkers: "표식이 있는 방사형",
        radarFilled: "채워진 방사형",
        seriesModifyDescription: "데이터 계열의 차트 유형과 축 선택:",
        seriesName: "계열 이름",
        chartType: "차트 유형",
        secondaryAxis: "보조 축",
        errorPrompt: {
            stockHLCErrorMsg: "이 주식형 차트를 만들려면 주식의 고가, 저가, 종가의 순서로 시트에 데이터를 정리합니다. 날짜를 레이블로 사용하십시오.",
            stockOHLCErrorMsg: "이 주식형 차트를 만들려면 주식의 시가, 고가, 저가, 종가의 순서로 시트에 데이터를 정리합니다. 날짜를 레이블로 사용하십시오.",
            stockVHLCErrorMsg: "이 주식형 차트를 만들려면 주식의 일일 거래량, 주식의 고가, 저가, 종가의 순서로 시트에 데이터를 정리합니다. 날짜를 레이블로 사용하십시오.",
            stockVOHLCErrorMsg: "이 주식형 차트를 만들려면 주식의 일일 거래량, 주식의 시가, 고가, 저가, 종가 등의 순서로 시트에 데이터를 정리합니다. 날짜를 레이블로 사용하십시오.",
            emptyDataErrorMsg: "차트를 만들려면 사용할 데이터가 포함된 셀을 선택합니다. 행과 열 이름이 있고 이를 레이블로 사용하려면 선택 항목에 포함하십시오.",
            unexpectedErrorMsg: "몇 가지 알 수 없는 오류가 발생했습니다. 다시 시도하십시오. 다시 발생하면 지원 부서에 문의하십시오."
        }
    };

    ko_res.columnWidthDialog = {
        title: "열 너비",
        columnWidth: "열 너비:",
        exception: "열 너비는 숫자 또는 동적 크기(“3*”처럼 별표 표시가 있는 숫자)여야 합니다.",
        exception2: "열 너비는 0과 9999999 사이여야 합니다."
    };
    ko_res.standardWidthDialog = {
        title: "표준 너비",
        columnWidth: "표준 열 너비:",
        exception: "잘못된 값을 입력했습니다. 정수나 실수를 입력해야 합니다."
    };
    ko_res.standardHeightDialog = {
        title: "표준 높이",
        rowHeight: "표준 행 높이:",
        exception: "잘못된 값을 입력했습니다. 정수나 실수를 입력해야 합니다."
    };
    ko_res.insertCellsDialog = {
        title: "삽입",
        shiftcellsright: "셀을 오른쪽으로 밀기",
        shiftcellsdown: "셀을 아래로 밀기",
        entirerow: "전체 행",
        entirecolumn: "전체 열"
    };
    ko_res.deleteCellsDialog = {
        title: "삭제",
        shiftcellsleft: "셀을 왼쪽으로 밀기",
        shiftcellsup: "셀을 위로 밀기",
        entirerow: "전체 행",
        entirecolumn: "전체 열"
    };
    ko_res.groupDialog = {
        title: "그룹",
        rows: "행",
        columns: "열"
    };
    ko_res.ungroupDialog = {
        title: "그룹 해제"
    };
    ko_res.subtotalDialog = {
        title: "부분합",
        remove: "제거",
        groupNameSelectionLabel: "그룹화할 항목:",
        subtotalFormulaItemLabel: "사용할 함수:",
        subtotalFormulaSum: "합계",
        subtotalFormulaCount: "개수",
        subtotalFormulaAverage: "평균",
        subtotalFormulaMax: "최대값",
        subtotalFormulaMin: "최소값",
        subtotalFormulaProduct: "제품",
        addSubtotalColumnItem: "부분합 계산 항목:",
        replaceCurrent: "새로운 값으로 대치",
        breakPageByGroups: "그룹 사이에서 페이지 나누기",
        summaryBelowData: "데이터 아래에 요약 표시"
    };
    ko_res.findDialog = {
        title: "찾기",
        findwhat: "찾을 내용:",
        within: "범위:",
        matchcase: "대/소문자 구분",
        search: "검색:",
        matchexactly: "정확히 일치",
        lookin: "찾는 위치:",
        usewildcards: "와일드카드 사용",
        option: "옵션",
        findall: "모두 찾기",
        findnext: "다음 찾기",
        exception: "검색하는 항목을 찾지 못했습니다."
    };
    ko_res.gotoDialog = {
        title: "이동",
        goto: "이동:",
        reference: "참조:",
        exception: "입력한 내용은 올바른 참조나 정의된 이름이 아닙니다.",
        wrongName: "작업을 실행하지 못했습니다."
    };
    ko_res.richTextDialog = {
        title: '서식 있는 텍스트 대화 상자',
        fontFamilyTitle: '글꼴 패밀리',
        fontSizeTitle: '글꼴 크기',
        boldTitle: '굵게',
        italicTitle: '기울임꼴',
        underlineTitle: '밑줄',
        strikethroughTitle: '취소선',
        colorPickerTitle: '글꼴 색',
        superScriptTitle: '위 첨자',
        subScriptTitle: '아래 첨자'
    };
    ko_res.nameManagerDialog = {
        title: "이름 관리자",
        newName: "새로 만들기...",
        edit: "편집...",
        deleteName: "삭제",
        filterWith: {
            title: "필터링 기준:",
            clearFilter: "필터 지우기",
            nameScopedToWorkbook: "통합 문서로 범위 지정된 이름",
            nameScopedToWorksheet: "워크시트로 범위 지정된 이름",
            nameWithErrors: "오류가 있는 이름",
            nameWithoutErrors: "오류가 없는 이름"
        },
        nameColumn: "이름",
        valueColumn: "값",
        refersToColumn: "참조 대상",
        scopeColumn: "범위",
        commentColumn: "메모",
        exception1: "입력한 이름이 올바르지 않습니다.",
        exception2: "입력한 이름이 이미 있습니다. 고유한 이름을 입력하세요.",
        deleteAlert: "이름 {0}을(를) 삭제하시겠습니까?"
    };
    ko_res.newNameDialog = {
        titleNew: "새 이름",
        titleEdit: "이름 편집",
        name: "이름:",
        scope: {
            title: "범위:",
            workbook: "통합 문서"
        },
        referTo: "참조:",
        comment: "메모:",
        wrongName: "작업을 실행하지 못했습니다."
    };
    ko_res.insertFunctionDialog = {
        title: "함수 삽입",
        functionCategory: "함수 범주:",
        functionList: "함수 목록:",
        formula: "수식:",
        functionCategorys: "모두,데이터베이스,날짜 및 시간,엔지니어링,재무,정보,논리적,조회 및 참조,수학 및 삼각 함수,통계,텍스트"
    };
    ko_res.buttonCellTypeDialog = {
        title: "단추 셀 유형",
        marginGroup: "여백:",
        left: "왼쪽:",
        top: "위쪽:",
        right: "오른쪽:",
        bottom: "아래쪽:",
        text: "텍스트:",
        backcolor: "배경색",
        other: "기타:"
    };
    ko_res.checkBoxCellTypeDialog = {
        title: "확인란 셀 유형",
        textGroup: "텍스트:",
        "true": "True:",
        indeterminate: "비활성화 상태:",
        "false": "False:",
        align: "맞춤:",
        other: "기타:",
        caption: "캡션:",
        isThreeState: "세 가지 상태 여부",
        checkBoxTextAlign: {
            top: "위쪽",
            bottom: "아래쪽",
            left: "왼쪽",
            right: "오른쪽"
        }
    };
    ko_res.comboBoxCellTypeDialog = {
        title: "콤보 상자 셀 유형",
        editorValueTypes: "편집기 값 유형:",
        items: "항목:",
        itemProperties: "항목 속성:",
        text: "텍스트:",
        value: "값:",
        add: "추가",
        remove: "제거",
        editorValueType: {
            text: "텍스트",
            index: "인덱스",
            value: "값"
        },
        editable: "편집 가능",
        itemHeight: "항목 높이"
    };
    ko_res.hyperLinkCellTypeDialog = {
        title: "하이퍼링크 셀 유형",
        link: "링크:",
        visitedlink: "열어 본 링크:",
        text: "텍스트:",
        linktooltip: "링크 도구 설명:",
        color: "색:",
        other: "기타:"
    };
    ko_res.checkListCellTypeDialog = {
        title1: "체크박스 목록 셀 유형",
        title2: "라디오 목록 셀 유형",
        direction: "방향:",
        horizontal: "가로",
        vertical: "세로",
        items: "항목:",
        itemProperties: "항목 속성:",
        text: "텍스트:",
        value: "값:",
        add: "추가",
        remove: "제거",
        isWrap: "너비에 맞게 배열",
        rowCount: "행 수:",
        colCount: "열 수:",
        vSpace: "세로 간격:",
        hSpace: "가로 간격:",
        textAlign: "텍스트 맞춤:",
        checkBoxTextAlign: {
            left: "왼쪽",
            right: "오른쪽"
        },
        exception: "셀 유형의 항목을 추가하십시오."
    };
    ko_res.buttonListCellTypeDialog = {
        title: "버튼 목록 셀 유형",
        backColor: "배경색:",
        foreColor: "전경색:",
        marginGroup: "여백:",
        left: "왼쪽:",
        top: "위쪽:",
        right: "오른쪽:",
        bottom: "아래쪽:",
        selectMode: "선택 모드:",
        singleSelect: "실선",
        multiSelect: "다중",
        exception: "셀 유형 아이템을 추가하십시오."
    };
    ko_res.headerCellsDialog = {
        title: "머리글 셀",
        rowHeader: "행 머리글",
        columnHeader: "열 머리글",
        backColor: "배경색",
        borderBottom: "아래쪽 테두리",
        borderLeft: "왼쪽 테두리",
        borderRight: "오른쪽 테두리",
        borderTop: "위쪽 테두리",
        diagonalUp: "오른쪽 대각선",
        diagonalDown: "왼쪽 대각선",
        font: "글꼴",
        foreColor: "전경색",
        formatter: "포맷터",
        hAlign: "가로 맞춤",
        height: "높이",
        locked: "잠금",
        resizable: "크기 조정 가능",
        shrinkToFit: "축소 맞춤",
        value: "값",
        textIndent: "텍스트 들여쓰기",
        vAlign: "세로 맞춤",
        visible: "표시",
        width: "너비",
        wordWrap: "자동 줄 바꿈",
        popUp: "...",
        merge: "병합",
        unmerge: "분할",
        insertRows: "행 삽입",
        addRows: "행 추가",
        deleteRows: "행 삭제",
        insertColumns: "열 삽입",
        addColumns: "열 추가",
        deleteColumns: "열 삭제",
        clear: "지우기",
        top: '위쪽',
        bottom: '아래쪽',
        left: '왼쪽',
        right: '오른쪽',
        center: '가운데',
        general: '일반',
        verticalText: "세로 텍스트",
        exception: "설정이 잘못되었습니다. 빨간색 부분을 확인하세요."
    };
    ko_res.fontPickerDialog = {
        title: "글꼴"
    };
    ko_res.fillDialog = {
        title: "계열"
    };

    ko_res.zoomDialog = {
        title: "확대/축소",
        double: "200%",
        normal: "100%",
        threeFourths: "75%",
        half: "50%",
        quarter: "25%",
        fitSelection: "선택 영역에 맞춤",
        custom: "사용자 지정:",
        exception: "잘못된 값을 입력했습니다. 정수나 실수를 입력해야 합니다.",
        magnification: "배율",
        percent: "%"
    };
    ko_res.contextMenu = {
        cut: "잘라내기",
        copy: "복사",
        paste: "붙여넣기 옵션:",
        pasteAll: '모두 붙여넣기',
        pasteFormula: '수식 붙여넣기',
        pasteValue: '값 붙여넣기',
        pasteFormatting: '서식 붙여넣기',
        insertDialog: "삽입...",
        deleteDialog: "삭제...",
        clearcontents: "내용 지우기",
        filter: "필터",
        totalRow: "총 행",
        toTange: "범위로 변환",
        sort: "정렬",
        table: "표",
        sortAToZ: "오름차순 정렬",
        sortZToA: "내림차순 정렬",
        customSort: "사용자 지정 정렬...",
        formatCells: "셀 서식...",
        editCellType: "셀 유형 편집...",
        editCellDropdows: "셀 드롭다운 편집...",
        richText: "서식 있는 텍스트...",
        defineName: "이름 정의...",
        tag: "태그...",
        rowHeight: "행 높이...",
        columnWidth: "열 너비...",
        hide: "숨기기",
        unhide: "숨기기 취소",
        headers: "머리글...",
        insert: "삽입",
        delete: "삭제",
        tableInsert: "삽입",
        tableInsertRowsAbove: "위쪽에 표 행 삽입",
        tableInsertRowsBelow: "아래쪽에 표 행 삽입",
        tableInsertColumnsLeft: "왼쪽에 표 열 삽입",
        tableInsertColumnsRight: "오른쪽에 표 열 삽입",
        tableDelete: "삭제",
        tableDeleteRows: "표 행 삭제",
        tableDeleteColumns: "표 열 삭제",
        protectsheet: "시트 보호...",
        unprotectsheet: "시트 보호 해제...",
        comments: "통합 문서에는 화면에 보이는 시트가 적어도 하나는 있어야 합니다.",
        insertComment: "메모 삽입",
        editComment: "메모 편집",
        deleteComment: "메모 삭제",
        hideComment: "메모 숨기기",
        editText: "텍스트 편집",
        exitEditText: "텍스트 편집 끝내기",
        formatComment: "메모 서식",
        unHideComment: "메모 표시/숨기기",
        sheetTabColor: "탭 색",
        remove: "제거",
        slicerProperty: "크기 및 속성...",
        slicerSetting: "슬라이서 설정...",
        changeChartType: "차트 유형 변경...",
        selectData: "데이터 선택...",
        moveChart: "차트 이동...",
        resetChartColor: "일치 스타일로 다시 설정",
        formatChart: {
            chartArea: "차트 영역 서식...",
            series: "데이터 계열 서식...",
            axis: "축 서식...",
            legend: "범례 서식...",
            dataLabels: "데이터 레이블 서식...",
            chartTitle: "차트 제목 서식...",
            trendline: "추세선 서식...",
            errorBar: "오류 바 서식...",
            unitsLabel: "표시 단위 서식...",
        },
        groupShapes: "그룹",
        ungroupShapes: "그룹 해제",
        pasteShape: "붙여넣기",
        formatShapes: "도형 서식 지정...",
        pasteValuesFormatting: "값 및 서식",
        pasteFormulaFormatting: "수식 및 서식",
        outlineColumn: "아웃라인 열..."
    };
    ko_res.tagDialog = {
        cellTagTitle: "셀 태그 대화 상자",
        rowTagTitle: "행 태그 대화 상자",
        columnTagTitle: "열 태그 대화 상자",
        sheetTagTitle: "시트 태그 대화 상자",
        tag: "태그:"
    };
    ko_res.borderPicker = {
        lineStyleTitle: "선:",
        borderColorTitle: "색:",
        none: "없음"
    };
    ko_res.borderDialog = {
        border: "테두리",
        presets: "미리 설정",
        none: "없음",
        outline: "윤곽선",
        inside: "내부",
        line: "선",
        text: "텍스트",
        comments: "미리 설정, 미리 보기 다이어그램 또는 위의 단추를 클릭하면 선택한 테두리 스타일이 적용됩니다."
    };

    ko_res.conditionalFormat = {
        highlightCellsRules: "셀 강조 규칙",
        topBottomRules: "상위/하위 규칙",
        dataBars: "데이터 막대",
        colorScales: "색조",
        iconSets: "아이콘 집합",
        newRule: "새 규칙...",
        clearRules: "규칙 지우기...",
        manageRules: "규칙 관리...",
        greaterThan: "보다 큼...",
        lessThan: "보다 작음...",
        between: "다음 값의 사이에 있음...",
        equalTo: "같음...",
        textThatContains: "텍스트 포함...",
        aDateOccurring: "발생 날짜...",
        duplicateValues: "중복 값...",
        moreRules: "기타 규칙...",
        top10Items: "상위 10개 항목...",
        bottom10Items: "하위 10개 항목...",
        aboveAverage: "평균 초과...",
        belowAverage: "평균 미만...",
        gradientFill: "그라데이션 채우기",
        solidFill: "단색 채우기",
        directional: "방향",
        shapes: "도형",
        indicators: "표시기",
        ratings: "등급",
        clearRulesFromSelectedCells: "선택한 셀의 규칙 지우기",
        clearRulesFromEntireSheet: "시트 전체에서 규칙 지우기"
    };

    ko_res.fileMenu = {
        new: "새로 만들기",
        open: "열기",
        save: "저장",
        saveAs: "다른 이름으로 저장",
        export: "내보내기",
        import: "가져오기",
        exit: "닫기",
        recentWorkbooks: "최근 통합 문서",
        computer: "컴퓨터",
        currentFolder: "현재 폴더",
        recentFolders: "최근 폴더",
        browse: "찾아보기",
        spreadSheetJsonFile: "스프레드시트 파일(JSON)",
        excelFile: "Excel 파일",
        csvFile: "CSV 파일",
        pdfFile: "PDF 파일",
        importSpreadSheetFile: "SSJSON 파일 가져오기",
        importExcelFile: "Excel 파일 가져오기",
        importCsvFile: "CSV 파일 가져오기",
        exportSpreadSheetFile: "SSJSON 파일 내보내기",
        exportExcelFile: "Excel 파일 내보내기",
        exportCsvFile: "CSV 파일 내보내기",
        exportPdfFile: "PDF 파일 내보내기",
        exportJSFile: "Javascript 파일 내보내기",
        openFlags: "플래그 열기",
        importIgnoreStyle: '데이터만',
        importIgnoreFormula: '데이터와 수식만',
        importDoNotRecalculateAfterLoad: "가져온 후 수식 자동 재계산 안 함",
        importRowAndColumnHeaders: "고정된 열과 행을 모두 머리글로 가져오기",
        importRowHeaders: "고정된 행을 열 머리글로 가져오기",
        importColumnHeaders: "고정된 열을 행 머리글로 가져오기",
        importPassword: "암호",
        importIncludeRowHeader: "행 머리글 가져오기",
        importIncludeColumnHeader: "열 머리글 가져오기",
        importUnformatted: "서식 없는 데이터 유지",
        importImportFormula: "셀 수식 가져오기",
        importRowDelimiter: "행 구분 기호",
        importColumnDelimiter: "열 구분 기호",
        importCellDelimiter: "셀 구분 기호",
        importEncoding: "파일 인코딩",
        saveFlags: "플래그 저장",
        exportIgnoreStyle: "스타일을 내보내지 않음",
        exportIgnoreFormulas: "수식을 내보내지 않음",
        exportAutoRowHeight: "행 높이 자동 맞춤",
        exportSaveAsFiltered: "필터링된 항목으로 내보내기",
        exportSaveAsViewed: "본 항목으로 내보내기",
        exportSaveBothCustomRowAndColumnHeaders: "행 머리글을 Excel 고정 열로 내보내고 열 머리글을 Excel 고정 행으로 내보내기",
        exportSaveCustomRowHeaders: "행 머리글을 Excel 고정 열로 내보내기",
        exportSaveCustomColumnHeaders: "열 머리글을 Excel 고정 행으로 내보내기",
        exportPassword: "암호",
        exportIncludeRowHeader: "행 머리글 포함",
        exportIncludeColumnHeader: "열 머리글 포함",
        exportUnFormatted: "스타일 정보 포함 안 함",
        exportFormula: "수식 포함",
        exportAsViewed: "본 항목으로 내보내기",
        exportSheetIndex: "시트 인덱스",
        exportEncoding: "인코딩",
        exportRow: "행 인덱스",
        exportColumn: "열 인덱스",
        exportRowCount: "행 수",
        exportColumnCount: "열 수",
        exportRowDelimiter: "행 구분 기호",
        exportColumnDelimiter: "열 구분 기호",
        exportCellDelimiter: "셀 구분 기호",
        exportVisibleRowCol: "보이는 행과 열만 포함",
        pdfBasicSetting: "기본 설정",
        pdfTitle: "제목:",
        pdfAuthor: "작성자:",
        pdfApplication: "응용 프로그램:",
        pdfSubject: "제목:",
        pdfKeyWords: "키워드:",
        pdfExportSetting: "설정 내보내기",
        exportSheetLabel: "내보낼 시트 선택:",
        allSheet: "모두",
        pdfDisplaySetting: "표시 설정",
        centerWindowLabel: "가운데 창",
        showTitleLabel: "제목 표시",
        showToolBarLabel: "도구 모음 표시",
        fitWindowLabel: "창 맞추기",
        showMenuBarLabel: "메뉴 모음 표시",
        showWindowUILabel: "창 UI 표시",
        destinationTypeLabel: "대상 유형:",
        destinationType: {
            autoDestination: "자동",
            fitPageDestination: "페이지에 맞추기",
            fitWidthDestination: "너비에 맞추기",
            fitHeightDestination: "높이에 맞추기",
            fitBoxDestination: "상자에 맞추기"
        },
        openTypeLabel: "열기 형식:",
        openType: {
            autoOpen: "자동",
            useNoneOpen: "사용하지 않음",
            useOutlinesOpen: "윤곽선 사용",
            useThumbsOpen: "미리 보기 사용",
            fullScreenOpen: "전체 화면",
            useOCOpen: "OC 사용",
            useAttachmentsOpen: "첨부 파일 사용"
        },
        pdfPageSetting: "페이지 설정",
        openPageNumberLabel: "페이지 번호 열기:",
        pageLayoutLabel: "페이지 레이아웃:",
        pageLayout: {
            autoLayout: "자동",
            singlePageLayout: "단일 페이지",
            oneColumnLayout: "하나의 열",
            twoColumnLeftLayout: "왼쪽 두 개의 열",
            twoColumnRightLayout: "오른쪽 두 개의 열",
            twoPageLeftLayout: "왼쪽 두 개의 페이지",
            twoPageRight: "오른쪽 두 개의 페이지"
        },
        pageDurationLabel: "페이지 지속 기간:",
        pageTransitionLabel: "페이지 전환:",
        pageTransition: {
            defaultTransition: "기본값",
            splitTransition: "분할",
            blindsTransition: "블라인드",
            boxTransition: "상자",
            wipeTransition: "닦아내기",
            dissolveTransition: "흩어뿌리기",
            glitterTransition: "반짝이기",
            flyTransition: "날기",
            pushTransition: "밀어넣기",
            coverTransition: "덮기",
            uncoverTransition: "당기기",
            fadeTransition: "밝기 변화"
        },
        printerSetting: "프린터 설정...",
        printerSettingDialogTitle: "프린터 설정",
        copiesLabel: "인쇄 매수:",
        scalingTypeLabel: "배율 유형:",
        scalingType: {
            appDefaultScaling: "앱 기본값",
            noneScaling: "없음"
        },
        duplexModeLabel: "이중 모드:",
        duplexMode: {
            defaultDuplex: "기본값",
            simplexDuplex: "단면",
            duplexFlipShortEdge: "이중 대칭 짧은 가장자리",
            duplexFlipLongEdge: "이중 대칭 긴 가장자리"
        },
        choosePaperSource: "PDF 페이지 크기별 페이지 원본 선택",
        printRanges: "인쇄 범위",
        indexLabel: "인덱스",
        countLabel: "개수",
        addRange: "추가",
        removeRange: "제거",
        addRangeException: "잘못된 값입니다. 인덱스는 0보다 크거나 같고 개수는 0보다 커야 합니다.",
        noRecentWorkbooks: "최근에 사용한 통합 문서가 없습니다. 먼저 통합 문서를 여세요.",
        noRecentFolders: "최근에 사용한 폴더가 없습니다. 먼저 통합 문서를 여세요.",
    };

    ko_res.formatTableStyle = {
        name: "이름:",
        tableElement: "표 요소:",
        preview: "미리 보기",
        format: "형식",
        tableStyle: "표 스타일",
        clear: "지우기",
        stripeSize: "줄무늬 크기",
        light: "밝게",
        medium: "보통",
        dark: "어둡게",
        newTableStyle: "새 표 스타일...",
        clearTableStyle: "지우기",
        custom: "사용자 지정",
        exception: "이 스타일 이름이 이미 있습니다.",
        title: "SpreadJS 디자이너"
    };
    ko_res.tableElement = {
        wholeTableStyle: "전체 표",
        firstColumnStripStyle: "첫 열 줄무늬",
        secondColumnStripStyle: "둘째 열 줄무늬",
        firstRowStripStyle: "첫 행 줄무늬",
        secondRowStripStyle: "둘째 행 줄무늬",
        highlightLastColumnStyle: "마지막 열",
        highlightFirstColumnStyle: "첫째 열",
        headerRowStyle: "머리글 행",
        footerRowStyle: "전체 행",
        firstHeaderCellStyle: "첫 머리글 셀",
        lastHeaderCellStyle: "마지막 머리글 셀",
        firstFooterCellStyle: "첫 바닥글 셀",
        lastFooterCellStyle: "마지막 바닥글 셀"
    };
    ko_res.conditionalFormatting = {
        common: {
            'with': "포함",
            selectedRangeWith: "적용할 서식",
            and: "및"
        },
        greaterThan: {
            title: "보다 큼",
            description: "다음 값보다 큰 셀의 서식 지정:"
        },
        lessThan: {
            title: "보다 작음",
            description: "다음 값보다 작은 셀의 서식 지정:"
        },
        between: {
            title: "해당 범위",
            description: "다음 값 사이에 있는 셀 서식 지정:"
        },
        equalTo: {
            title: "같음",
            description: "다음 값과 같은 셀의 서식 지정:"
        },
        textThatCotains: {
            title: "텍스트 포함",
            description: "다음 텍스트를 포함하는 셀의 서식 지정:"
        },
        dateOccurringFormat: {
            title: "발생 날짜",
            description: "다음 발생 날짜를 포함하는 셀의 서식 지정:",
            date: {
                yesterday: "어제",
                today: "오늘",
                tomorrow: "내일",
                last7days: "지난 7일",
                lastweek: "지난 주",
                thisweek: "이번 주",
                nextweek: "다음 주",
                lastmonth: "지난 달",
                thismonth: "이번 달",
                nextmonth: "다음 달"
            }
        },
        duplicateValuesFormat: {
            title: "중복 값",
            description: "다음 값을 포함하는 셀의 서식 지정:",
            type: {
                duplicate: "중복",
                unique: "고유"
            },
            valueswith: "적용할 서식"
        },
        top10items: {
            title: "상위 10개 항목",
            description: "다음 상위 순위에 속하는 셀의 서식 지정:"
        },
        bottom10items: {
            title: "하위 10개 항목",
            description: "다음 하위 순위에 속하는 셀의 서식 지정:"
        },
        aboveAverage: {
            title: "평균 초과",
            description: "선택한 범위에서 평균 초과인 셀의 서식 지정:"
        },
        belowAverage: {
            title: "평균 미만",
            description: "선택한 범위에서 평균 미만인 셀의 서식 지정:"
        },
        newFormattingRule: {
            title: "새 서식 규칙",
            title2: "서식 규칙 편집",
            description1: "규칙 유형 선택:",
            description2: "규칙 설명 편집:",
            ruleType: {
                formatOnValue: "►셀 값을 기준으로 모든 셀의 서식 지정",
                formatContain: "►다음을 포함하는 셀만 서식 지정",
                formatRankedValue: "►상위 또는 하위 값만 서식 지정",
                formatAbove: "►평균보다 크거나 작은 값만 서식 지정",
                formatUnique: "►고유 또는 중복 값만 서식 지정",
                useFormula: "►수식을 사용하여 서식을 지정할 셀 결정"
            },
            formatOnValue: {
                description: "셀 값을 기준으로 모든 셀의 서식 지정:",
                formatStyle: "서식 스타일:",
                formatStyleSelector: {
                    color2: "2가지 색조",
                    color3: "3가지 색조",
                    dataBar: "데이터 막대",
                    iconSets: "아이콘 집합"
                },
                color2: {
                    min: "최소값",
                    max: "최대값",
                    type: "유형:",
                    value: "값:",
                    color: "색:",
                    preview: "미리 보기",
                    minSelector: {
                        lowest: "최소값"
                    },
                    maxSelector: {
                        highest: "최대값"
                    }
                },
                color3: {
                    mid: "중간값"
                },
                dataBar: {
                    showBarOnly: "막대만 표시",
                    auto: "자동",
                    description2: "막대 모양:",
                    fill: "채우기",
                    color: "색",
                    border: "테두리",
                    fillSelector: {
                        solidFill: "단색 채우기",
                        gradientFill: "그라데이션 채우기"
                    },
                    borderSelector: {
                        noBorder: "테두리 없음",
                        solidBorder: "실선 테두리"
                    },
                    negativeBtn: "음수 값 및 축...",
                    barDirection: "막대 방향:",
                    barDirectionSelector: {
                        l2r: "왼쪽에서 오른쪽",
                        r2l: "오른쪽에서 왼쪽"
                    },
                    preview: "미리 보기",
                    negativeDialog: {
                        title: "음수 값 및 축 설정",
                        group1: {
                            title: "음수 막대 채우기 색",
                            fillColor: "채우기 색:",
                            apply: "양수 막대와 동일한 채우기 색 적용"
                        },
                        group2: {
                            title: "음수 막대 테두리 색",
                            borderColor: "테두리 색:",
                            apply: "양수 막대와 동일한 채우기 색 적용"
                        },
                        group3: {
                            title: "축 설정",
                            description: "음수 값에 대한 막대 모양을 변경하려면 셀에서 축 위치를 선택합니다.",
                            radio: {
                                auto: "자동(음수 값을 사용하여 변수 위치에 표시)",
                                cell: "셀 중간값 ",
                                none: "없음(양수와 같은 방향으로 음수 값 막대 표시)"
                            },
                            axisColor: "축 색:"
                        }
                    }
                },
                iconSets: {
                    iconStyle: "아이콘 스타일:",
                    showIconOnly: "아이콘만 표시",
                    reverseIconOrder: "아이콘 순서 거꾸로",
                    display: "다음 규칙에 따라 각 아이콘 표시:",
                    icon: "아이콘",
                    value: "값",
                    type: "유형",
                    description1: "값",
                    description2: "<",
                    operator: {
                        largeOrEqu: "> =",
                        large: ">"
                    },
                    customIconSet: "사용자 정의",
                    noCellIcon: "셀 아이콘 없음"
                },
                commonSelector: {
                    num: "숫자",
                    percent: "백분율",
                    formula: "수식",
                    percentile: "백분위수"
                }
            },
            formatContain: {
                description: "다음을 포함하는 셀만 서식 지정:",
                type: {
                    cellValue: "셀 값",
                    specificText: "특정 텍스트",
                    dateOccurring: "발생 날짜",
                    blanks: "빈 셀",
                    noBlanks: "내용 있는 셀",
                    errors: "오류",
                    noErrors: "오류 없음"
                },
                operator_cellValue: {
                    between: "해당 범위",
                    notBetween: "제외 범위",
                    equalTo: "같음",
                    notEqualTo: "같지 않음",
                    greaterThan: "보다 큼",
                    lessThan: "보다 작음",
                    greaterThanOrEqu: "보다 크거나 같음",
                    lessThanOrEqu: "보다 작거나 같음"
                },
                operator_specificText: {
                    containing: "포함",
                    notContaining: "포함하지 않음",
                    beginningWith: "시작 문자",
                    endingWith: "끝 문자"
                }
            },
            formatRankedValue: {
                description: "다음 순위에 속하는 셀의 서식 지정:",
                type: {
                    top: "위쪽",
                    bottom: "아래쪽"
                }
            },
            formatAbove: {
                description: "셀 서식 지정 조건:",
                type: {
                    above: "초과",
                    below: "미만",
                    equalOrAbove: "이상",
                    equalOrBelow: "이하",
                    std1Above: "> 1 표준 편차",
                    std1Below: "< 1 표준 편차",
                    std2Above: "> 2 표준 편차",
                    std2Below: "< 2 표준 편차",
                    std3Above: "> 3 표준 편차",
                    std3Below: "< 3 표준 편차"
                },
                description2: "선택한 범위의 평균"
            },
            formatUnique: {
                description: "선택한 범위에 있는 다음 값에 모두 서식 지정:",
                type: {
                    duplicate: "중복",
                    unique: "고유"
                },
                description2: "선택된 범위의 값"
            },
            useFormula: {
                description: "다음 수식이 참인 값의 서식 지정:"
            },
            preview: {
                description: "미리 보기:",
                buttonText: "서식...",
                noFormat: "설정된 서식 없음",
                hasFormat: "AaBbCcYyZz"
            }
        },
        withStyle: {
            lightRedFill_DarkRedText: "진한 빨강 텍스트가 있는 연한 빨강 채우기",
            yellowFill_DrakYellowText: "진한 노랑 텍스트가 있는 노랑 채우기",
            greenFill_DarkGreenText: "진한 녹색 텍스트가 있는 녹색 채우기",
            lightRedFill: "연한 빨강 채우기",
            redText: "빨강 텍스트",
            redBorder: "빨강 테두리",
            customFormat: "사용자 지정 서식..."
        },
        exceptions: {
            e1: "입력한 값이 유효한 숫자, 날짜, 시간 또는 문자열이 아닙니다.",
            e2: "값을 입력하세요.",
            e3: "1에서 1,000 사이의 정수를 입력하세요.",
            e4: "입력한 값을 비워 둘 수 없습니다.",
            e5: "조건부 서식 수식에서는 이 유형의 참조를 사용할 수 없습니다.\n참조를 하나의 셀로 바꾸거나 워크시트 함수(예:=SUM(A1:E5))를 참조로 사용하세요.",
            e6: "수식 규칙의 원본 범위에는 단일 범위만 사용할 수 있습니다."
        }
    };

    ko_res.formattingRulesManagerDialog = {
        title: "조건부 서식 규칙 관리자",
        rulesScopeLabel: "이 워크시트에 대한 서식 규칙: ",
        rulesScopeForSelection: "현재 선택 영역",
        rulesScopeForWorksheet: "이 워크시트",
        newRule: "새 규칙...",
        editRule: "규칙 편집...",
        deleteRule: "규칙 삭제...",
        gridTitleRule: "규칙(표시 순서대로 적용)",
        gridTitleFormat: "형식",
        gridTitleAppliesTo: "적용 대상",
        gridTitleStopIfTrue: "True일 경우 중지",
        ruleDescriptions: {
            valueBetween: '{0}에서 {1} 사이의 셀 값',
            valueNotBetween: '{0}에서 {1} 사이에 없는 셀 값',
            valueEquals: '셀 값 = {0}',
            valueNotEquals: '셀 값 <> {0}',
            valueGreateThan: '셀 값 > {0}',
            valueGreateThanOrEquals: '셀 값 >= {0}',
            valueLessThan: '셀 값 < {0}',
            valueLessThanOrEquals: '셀 값 <= {0}',
            valueContains: '"{0}"을(를) 포함하는 셀 값',
            valueNotContains: '"{0}"을(를) 포함하지 않는 셀 값',
            valueBeginsWith: '"{0}"(으)로 시작하는 셀 값',
            valueEndsWith: '"{0}"(으)로 끝나는 셀 값',
            last7Days: '지난 7일',
            lastMonth: '지난달',
            lastWeek: '지난주',
            nextMonth: '다음 달',
            nextWeek: '다음 주',
            thisMonth: '이번 달',
            thisWeek: '이번 주',
            today: '오늘',
            tomorrow: '내일',
            yesterday: '어제',
            duplicateValues: '중복 값',
            uniqueValues: '고유 값',
            top: '위쪽 {0}',
            bottom: '아래쪽 {0}',
            above: '평균 초과',
            above1StdDev: '> 1 표준 편차 평균',
            above2StdDev: '> 2 표준 편차 평균',
            above3StdDev: '> 3 표준 편차 평균',
            below: '평균 미만',
            below1StdDev: '< 1 표준 편차 평균',
            below2StdDev: '< 2 표준 편차 평균',
            below3StdDev: '< 3 표준 편차 평균',
            equalOrAbove: '평균 이상',
            equalOrBelow: '평균 이하',
            dataBar: '데이터 막대',
            twoScale: '다양한 색조',
            threeScale: '다양한 색조',
            iconSet: '아이콘 집합',
            formula: '수식: {0}'
        },
        previewText: 'AaBbCcYyZz'
    };

    ko_res.cellStylesDialog = {
        cellStyles: "셀 스타일",
        custom: "사용자 지정",
        cellButtonStyleTitle: "색, 날짜 시간 및 다른 셀 유형 스타일",
        goodBadAndNeutral: "좋음, 나쁨 및 보통",
        dataAndModel: "데이터 및 모델",
        titlesAndHeadings: "제목 및 머리글",
        themedCellStyle: "테마 셀 스타일",
        numberFormat: "표시 형식",
        cellButtonsStyles: {
            "colorpicker-cellbutton": "색",
            "datetimepicker-cellbutton": "날짜 시간",
            "timepicker-cellbutton": "시간",
            "calculator-cellbutton": "계산기",
            "monthpicker-cellbutton": "월",
            "slider-cellbutton": "슬라이더",
            "okcancel-cellbutton": "확인 취소",
            "clear-cellbutton": "지우기"
        },
        goodBadAndNeutralContent: {
            "Normal": "보통",
            "Bad": "나쁨",
            "Good": "좋음",
            "Neutral": "보통"
        },
        dataAndModelContent: {
            "Calculation": "계산",
            "Check Cell": "셀 확인",
            "Explanatory Text": "설명...",
            "Input": "입력",
            "Linked Cell": "연결된 셀",
            "Note": "참고",
            "Output": "출력",
            "Warning Text": "경고문"
        },
        titlesAndHeadingsContent: {
            "Heading 1": "머리글 1",
            "Heading 2": "머리글 2",
            "Heading 3": "머리글 3",
            "Heading 4": "머리글 4",
            "Title": "제목",
            "Total": "합계"
        },
        themedCellStyleContent: {
            "20% - Accent1": "20% - 강조색1",
            "20% - Accent2": "20% - 강조색2",
            "20% - Accent3": "20% - 강조색3",
            "20% - Accent4": "20% - 강조색4",
            "20% - Accent5": "20% - 강조색5",
            "20% - Accent6": "20% - 강조색6",
            "40% - Accent1": "40% - 강조색1",
            "40% - Accent2": "40% - 강조색2",
            "40% - Accent3": "40% - 강조색3",
            "40% - Accent4": "40% - 강조색4",
            "40% - Accent5": "40% - 강조색5",
            "40% - Accent6": "40% - 강조색6",
            "60% - Accent1": "60% - 강조색1",
            "60% - Accent2": "60% - 강조색2",
            "60% - Accent3": "60% - 강조색3",
            "60% - Accent4": "60% - 강조색4",
            "60% - Accent5": "60% - 강조색5",
            "60% - Accent6": "60% - 강조색6",
            "Accent1": "강조색1",
            "Accent2": "강조색2",
            "Accent3": "강조색3",
            "Accent4": "강조색4",
            "Accent5": "강조색5",
            "Accent6": "강조색6"
        },
        numberFormatContent: {
            "Comma": "쉼표",
            "Comma [0]": "쉼표 [0]",
            "Currency": "통화",
            "Currency [0]": "통화 [0]",
            "Percent": "백분율"
        },
        newCellStyle: "새 셀 스타일..."
    };

    ko_res.newCellStyleDialog = {
        style: "스타일",
        styleName: "스타일 이름:",
        defaultStyleName: "스타일 1",
        format: "서식...",
        message: "이 스타일 이름이 이미 있습니다."
    };

    ko_res.cellStyleContextMenu = {
        "delete": "삭제",
        modify: "수정"
    };

    ko_res.insertPictureDialogTitle = "그림 삽입";
    ko_res.pictureFormatFilter = {
        jpeg: "JPEG 파일 교환 형식(*.jpg;*.jpeg)",
        png: "이동식 네트워크 그래픽(*.png)",
        bmp: "Windows 비트맵(*.bmp)",
        allFiles: "모든 파일(*.*)"
    };

    ko_res.ribbon = {
        accessBar: {
            undo: "실행 취소",
            redo: "다시 실행",
            save: "저장",
            New: "새로 만들기",
            open: "열기",
            active: "활성",
            tipWidth: 660
        },
        home: {
            file: "파일",
            home: "홈",
            clipboard: "클립보드",
            fonts: "글꼴",
            alignment: "맞춤",
            numbers: "숫자",
            cellType: "표시 유형",
            styles: "스타일",
            cells: "셀",
            editing: "편집",
            paste: "붙여넣기",
            all: "모두",
            formulas: "수식",
            values: "값",
            formatting: "서식",
            valuesAndFormatting: "값 및 서식",
            formulasAndFormatting: "수식 및 서식",
            cut: "잘라내기",
            copy: "복사",
            fontFamily: "글꼴 패밀리",
            fontSize: "글꼴 크기",
            increaseFontSize: "글꼴 크기 크게",
            decreaseFontSize: "글꼴 크기 작게",
            bold: "굵게",
            italic: "기울임꼴",
            underline: "밑줄",
            doubleUnderline: "이중 밑줄",
            border: "테두리",
            bottomBorder: "아래쪽 테두리",
            topBorder: "위쪽 테두리",
            leftBorder: "왼쪽 테두리",
            rightBorder: "오른쪽 테두리",
            noBorder: "테두리 없음",
            allBorder: "모든 테두리",
            outsideBorder: "바깥쪽 테두리",
            thickBoxBorder: "굵은 상자 테두리",
            bottomDoubleBorder: "아래쪽 이중 테두리",
            thickBottomBorder: "굵은 아래쪽 테두리",
            topBottomBorder: "위쪽/아래쪽 테두리",
            topThickBottomBorder: "위쪽/굵은 아래쪽 테두리",
            topDoubleBottomBorder: "위쪽/아래쪽 이중 테두리",
            moreBorders: "추가 테두리...",
            backColor: "배경색",
            fontColor: "글꼴 색",
            topAlign: "위쪽 맞춤",
            middleAlign: "가운데 맞춤",
            bottomAlign: "아래쪽 맞춤",
            leftAlign: "왼쪽 맞춤",
            centerAlign: "가운데 맞춤",
            rightAlign: "오른쪽 맞춤",
            increaseIndent: "들여쓰기",
            decreaseIndent: "내어쓰기",
            wrapText: "텍스트 줄 바꿈",
            mergeCenter: "병합하고 가운데 맞춤",
            mergeAcross: "전체 병합",
            mergeCells: "셀 병합",
            unMergeCells: "셀 병합 취소",
            numberFormat: "표시 형식",
            general: "일반",
            Number: "숫자",
            currency: "통화",
            accounting: "회계",
            shortDate: "간단한 날짜",
            longDate: "자세한 날짜",
            time: "시간",
            percentage: "백분율",
            fraction: "분수",
            scientific: "지수",
            text: "텍스트",
            moreNumberFormat: "기타 번호 서식...",
            percentStyle: "백분율 스타일",
            commaStyle: "쉼표 스타일",
            increaseDecimal: "자릿수 늘림",
            decreaseDecimal: "자릿수 줄임",
            buttonCellType: "단추 셀 유형",
            checkboxCellType: "확인란 셀 유형",
            comboBoxCellType: "콤보 상자 셀 유형",
            hyperlinkCellType: "하이퍼링크 셀 유형",
            checkboxListCellType: "체크박스 목록",
            radioListCellType: "라디오 버튼 목록",
            buttonList: "버튼 목록",
            list: "목록",
            buttonListCellType: "버튼 목록",
            clearCellType: "셀 유형 지우기",
            clearCellButton: "셀 유형 지우기",
            cellDropdowns: "셀 드롭다운",
            conditionFormat: "조건 형식",
            conditionFormat1: "조건 형식",
            formatTable: "표 서식",
            formatTable1: "표 서식",
            insert: "삽입",
            insertCells: "셀 삽입...",
            insertSheetRows: "시트 행 삽입",
            insertSheetColumns: "시트 열 삽입",
            insertSheet: "시트 삽입",
            Delete: "삭제",
            deleteCells: "셀 삭제...",
            deleteSheetRows: "시트 행 삭제",
            deleteSheetColumns: "시트 열 삭제",
            deleteSheet: "시트 삭제",
            format: "형식",
            rowHeight: "행 높이...",
            autofitRowHeight: "행 높이 자동 맞춤",
            defaultHeight: "기본 높이...",
            columnWidth: "열 너비...",
            autofitColumnWidth: "열 너비 자동 맞춤",
            defaultWidth: "기본 너비...",
            hideRows: "행 숨기기",
            hideColumns: "열 숨기기",
            unHideRows: "행 숨기기 취소",
            unHideColumns: "열 숨기기 취소",
            protectSheet: "시트 보호...",
            unProtectSheet: "시트 보호 해제...",
            lockCells: "셀 잠금",
            unLockCells: "셀 잠금 해제",
            autoSum: "자동 합계",
            sum: "합계",
            average: "평균",
            countNumbers: "숫자 개수",
            max: "최대값",
            min: "최소값",
            fill: "채우기",
            down: "아래로",
            right: "오른쪽",
            up: "위로",
            left: "왼쪽",
            series: "계열...",
            clear: "지우기",
            clearAll: "모두 지우기",
            clearFormat: "서식 지우기",
            clearContent: "내용 지우기",
            clearComments: "메모 지우기",
            sortFilter: "정렬 및 필터",
            sortFilter1: "정렬 및 필터",
            sortAtoZ: "오름차순 정렬",
            sortZtoA: "내림차순 정렬",
            customSort: "사용자 지정 정렬...",
            filter: "필터",
            clearFilter: "필터 지우기",
            reapply: "다시 적용",
            find: "찾기",
            find1: "찾기...",
            goto: "이동...",
            rotateText: "텍스트 회전",
            orientation: "방향",
            angleCounterclockwise: "시계 반대 방향 각도",
            angleClockwise: "시계 방향 각도",
            verticalText: "세로 텍스트",
            rotateTextUp: "텍스트 위로 회전",
            rotateTextDown: "텍스트 아래로 회전",
            formatCellAlignment: "서식 셀 정렬",
        },
        insert: {
            insert: "삽입",
            table: "표",
            chart: "차트",
            sparklines: "스파크라인",
            line: "선",
            column: "열",
            winloss: "승패",
            insertTable: "표 삽입",
            insertChart: "차트 삽입",
            insertShapes: "도형 삽입",
            insertBarcode: "바코드 삽입",
            insertPicture: "그림 삽입",
            insertLineSparkline: "선 스파크라인 삽입",
            insertColumnSparkline: "열 스파크라인 삽입",
            insertWinlossSparkline: "승패 스파크라인 삽입",
            picture: "그림",
            //illustrations: "일러스트레이션..", // SJS-3435
            illustrations: "그림",
            shapes: "도형",
            barcode: "바코드",
            insertPieSparkline: "원형 스파크라인 삽입",
            insertAreaSparkline: "영역 스파크라인 삽입",
            insertScatterSparkline: "분산형 스파크라인 삽입",
            pie: "원형",
            area: "영역",
            scatter: "분산형",
            insertBulletSparkline: "글머리 기호 스파크라인 삽입",
            bullet: "글머리 기호",
            insertSpreadSparkline: "분배 스파크라인 삽입",
            spread: "분배",
            insertStackedSparkline: "누적형 스파크라인 삽입",
            stacked: "누적형",
            insertHbarSparkline: "가로 막대형 스파크라인 삽입",
            hbar: "가로 막대형",
            insertVbarSparkline: "세로 막대형 스파크라인 삽입",
            vbar: "세로 막대형",
            insertVariSparkline: "분산 스파크라인 삽입",
            variance: "분산",
            insertBoxPlotSparkline: "상자 그림 스파크라인 삽입",
            boxplot: "상자 그림",
            insertCascadeSparkline: "계단식 배열 스파크라인 삽입",
            cascade: "계단식 배열",
            insertParetoSparkline: "파레토 스파크라인 삽입",
            pareto: "파레토",
            insertMonthSparkline: "월 스파크라인 삽입",
            month: "월",
            insertYearSparkline: "년 스파크라인 삽입",
            year: "년"
        },
        formulas: {
            formulas: "수식",
            insertFunction: "함수 삽입",
            insertFunction1: "함수 삽입",
            functions: "함수",
            names: "이름",
            nameManager: "이름 관리자",
            nameManager1: "이름 관리자",
            text: "텍스트",
            text1: "텍스트",
            financial: "재무",
            logical: "논리",
            datetime: "날짜 및 시간",
            lookupreference: "찾기/참조",
            mathtrig: "수학/삼각",
            more: "함수 더 보기",
            statistical: "통계",
            engineering: "공학",
            information: "정보",
            database: "데이터베이스",
            autoSum: "자동 합계",
            functionsLibrary: "함수 라이브러리"
        },
        data: {
            data: "데이터",
            sortFilter: "정렬 및 필터",
            dataTools: "데이터 도구",
            outline: "윤곽선",
            sortAtoZ: "오름차순 정렬",
            sortZtoA: "내림차순 정렬",
            sort: "정렬",
            customSort: "사용자 지정 정렬...",
            filter: "필터",
            clear: "지우기",
            clearFilter: "필터 지우기",
            reapply: "다시 적용",
            dataValidation: "데이터 유효성 검사",
            dataValidation1: "데이터 유효성 검사",
            circleInvalidData: "잘못된 데이터",
            clearInvalidCircles: "잘못된 원 지우기",
            group: "그룹",
            unGroup: "그룹 해제",
            subtotal: "부분합",
            showDetail: "하위 수준 표시",
            hideDetail: "하위 수준 숨기기",
            designMode: "디자인 모드",
            enterTemplate: "템플릿 디자인 모드 입력",
            template: "템플릿",
            bindingPath: "바인딩 경로",
            loadSchemaTitle: "트리 보기를 가져올 스키마 로드",
            loadSchema: "스키마 로드",
            loadDataSourceFilter: {
                json: "JSON 파일(*.json)",
                txt: "일반 텍스트 파일(*.txt)"
            },
            saveDataSourceFilter: {
                json: "JSON 파일(*.json)"
            },
            saveSchemaTitle: "json 파일로 스키마 저장",
            saveSchema: "스키마 저장",
            autoGenerateColumns: "열 자동 생성",
            columns: "열",
            name: "이름",
            details: "세부 정보",
            ok: "확인",
            cancel: "취소",
            loadDataError: "json 파일을 로드하세요.",
            addNode: "노드 추가",
            remove: "제거",
            rename: "이름 바꾸기",
            table: "표",
            selectOptions: "옵션 선택",
            clearBindingPath: "바인딩 경로 지우기",
            dataField: "데이터 필드",
            warningTable: "표의 열 개수가 변경됩니다. 계속하시겠습니까?",
            warningDataField: "\"autoGenerateColumns\"를 'false'로 변경하고 데이터 필드를 설정하시겠습니까?",
            checkbox: "확인란",
            hyperlink: "하이퍼링크",
            combox: "콤보 상자",
            button: "단추",
            text: "텍스트",
            autoGenerateLabel: "레이블 자동 생성",
            autoGenerateLabelTip: "데이터 레이블 자동 생성",
            unallowableTableBindingTip: "데이터 필드는 표에서만 설정할 수 있습니다. 표를 선택하세요.",
            overwriteCellTypeWarning: "시트의 일부 셀 유형을 덮어쓰거나 변경합니다. 계속하시겠습니까?",
            removeNodeWarning: "제거하려는 노드에 하위 노드가 있습니다. 제거하시겠습니까?",
            unallowComboxBindingTip: "콤보 상자 항목은 콤보 상자에서만 설정할 수 있습니다. 콤보 상자를 선택하세요.",
            rowOutline: "행 아웃라인",
            unallowOneRowSubtotal: "선택한 범위에 적용할 수 없습니다. 범위에 1개 이상의 행을 선택하고 다시 시도하십시오.",
            unallowTableSubtotal: "부분합은 표에서 지원되지 않습니다.",
            canNotAppliedRange: "선택한 범위에 적용할 수 없습니다. 범위에서 단일 셀을 선택하고 다시 시도하십시오."
        },
        view: {
            view: "보기",
            showHide: "표시/숨기기",
            zoom: "확대/축소",
            viewport: "보기 포트",
            rowHeader: "행 머리글",
            columnHeader: "열 머리글",
            verticalGridline: "세로 눈금선",
            horizontalGridline: "가로 눈금선",
            tabStrip: "연속 탭",
            newTab: "새 탭",
            rowHeaderTip: "행 머리글 표시/숨기기",
            columnHeaderTip: "열 머리글 표시/숨기기",
            verticalGridlineTip: "세로 눈금선 표시/숨기기",
            horizontalGridlineTip: "가로 눈금선 표시/숨기기",
            tabStripTip: "연속 탭 표시/숨기기",
            newTabTip: "새 탭 표시/숨기기",
            zoomToSelection: "선택 항목으로 확대/축소",
            zoomToSelection1: "선택 항목으로 확대/축소",
            freezePane: "틀 고정",
            freezePane1: "틀 고정",
            freezeTopRow: "첫 행 고정",
            freezeFirstColumn: "첫 열 고정",
            freezeBottomRow: "끝 행 고정",
            freezeLastColumn: "마지막 열 고정",
            unFreezePane: "틀 고정 취소",
            unFreezePane1: "틀 고정 취소"
        },
        setting: {
            setting: "설정",
            spreadSetting: "분배 설정",
            sheetSetting: "시트 설정",
            general: "일반",
            generalTip: "일반 설정",
            scrollBars: "스크롤 막대",
            tabStrip: "연속 탭",
            gridLines: "눈금선",
            calculation: "계산",
            headers: "머리글"
        },
        sparkLineDesign: {
            design: "디자인",
            type: "유형",
            show: "표시",
            style: "스타일",
            groups: "그룹",
            line: "선",
            column: "열",
            winLoss: "승패",
            lineTip: "선 스파크라인",
            columnTip: "열 스파크라인",
            winLossTip: "승패 스파크라인",
            highPoint: "높은 점",
            lowPoint: "낮은 점",
            negativePoint: "음수 점",
            firstPoint: "첫 점",
            lastPoint: "마지막 점",
            markers: "표식",
            highPointTip: "스파크라인 높은 점 설정/해제",
            lowPointTip: "스파크라인 낮은 점 설정/해제",
            negativePointTip: "스파크라인 음수 점 설정/해제",
            firstPointTip: "스파크라인 첫 점 설정/해제",
            lastPointTip: "스파크라인 마지막 점 설정/해제",
            markersTip: "스파크라인 표식 점 설정/해제",
            sparklineColor: "스파크라인 색",
            markerColor: "표식 색",
            sparklineWeight: "스파크라인 두께",
            customWeight: "사용자 지정 두께...",
            group: "그룹",
            groupTip: "선택한 스파크라인 그룹화",
            unGroupTip: "선택한 스파크라인 그룹 해제",
            unGroup: "그룹 해제",
            clear: "지우기",
            clearSparkline: "선택한 스파크라인 지우기",
            clearSparklineGroup: "선택한 스파크라인 그룹 지우기"
        },
        formulaSparklineDesign: {
            design: "디자인",
            argument: "인수",
            settings: "설정"
        },
        tableDesign: {
            design: "디자인",
            tableName: "표 이름",
            resizeTable: "표 크기 조정",
            reszieHandler: "크기 조정 처리기",
            tableOption: "표 스타일 옵션",
            property: "속성",
            headerRow: "머리글 행",
            totalRow: "전체 행",
            bandedRows: "줄무늬 행",
            firstColumn: "첫째 열",
            lastColumn: "마지막 열",
            bandedColumns: "줄무늬 열",
            filterButton: "필터 단추",
            tableStyle: "표 스타일",
            style: "스타일",
            tools: "도구",
            insertSlicer: "슬라이서 삽입",
            toRange: "범위로 변환",
            totalRowList: "합계 행 목록",
            moreFunctions: "함수 더 보기..."
        },
        chartDesign: {
            design: "디자인",
            chartLayouts: "차트 레이아웃",
            addChartElement: "차트 요소 추가",
            addChartElement1: "차트 요소 추가",
            quickLayout: "빠른 레이아웃",
            changeColors: "색 변경",
            axes: "축",
            chartStyles: "차트 스타일",
            switchRowColumn: "행/열 전환",
            selectData: "데이터 선택",
            data: "데이터",
            changeChartType: "차트 유형 변경",
            changeChartType1: "차트 유형 변경",
            type: "유형",
            moveChart: "차트 이동",
            location: "위치",
            chartTemplate: "차트 서식 파일"
        },
        shapeDesign: {
            design: "디자인",
            shape: "도형",
            changeShapeStyle: "도형 스타일",
            changeShapeType: "도형 변경",
            insertShape: "도형 삽입",
            backColor: "도형 채우기",
            fontColor: "텍스트 채우기",
            color: "색",
            themeStyle: "테마 스타일",
            presets: "미리 설정",
            size: "크기",
            width: "너비",
            height: "높이",
            rotate: "회전",
            arrange: "정렬",
            group: "그룹",
            regroup: "다시 그룹",
            ungroup: "그룹 해제",
            rotateright90: "오른쪽으로 90° 회전",
            rotateleft90: "왼쪽으로 90° 회전"
        },
        insertShapeDialog: {
            errorPrompt: {
                unexpectedErrorMsg: "오류",
            }
        },
        fontFamilies: {
            ff1: { name: "Arial", text: "Arial" },
            ff2: { name: "Arial Black", text: "Arial Black" },
            ff3: { name: "Calibri", text: "Calibri" },
            ff4: { name: "Cambria", text: "Cambria" },
            ff5: { name: "Candara", text: "Candara" },
            ff6: { name: "Century", text: "Century" },
            ff7: { name: "Courier New", text: "Courier New" },
            ff8: { name: "Comic Sans MS", text: "Comic Sans MS" },
            ff9: { name: "Garamond", text: "Garamond" },
            ff10: { name: "Georgia", text: "Georgia" },
            ff11: { name: "맑은 고딕", text: "맑은 고딕" },
            ff12: { name: "Mangal", text: "Mangal" },
            ff13: { name: "Meiryo", text: "Meiryo" },
            ff14: { name: "MS Gothic", text: "MS Gothic" },
            ff15: { name: "MS Mincho", text: "MS Mincho" },
            ff16: { name: "MS PGothic", text: "MS PGothic" },
            ff17: { name: "MS PMincho", text: "MS PMincho" },
            ff18: { name: "Tahoma", text: "Tahoma" },
            ff19: { name: "Times", text: "Times" },
            ff20: { name: "Times New Roman", text: "Times New Roman" },
            ff21: { name: "Trebuchet MS", text: "Trebuchet MS" },
            ff22: { name: "Verdana", text: "Verdana" },
            ff23: { name: "Wingdings", text: "Wingdings" }
        },
        slicerOptions: {
            options: "옵션",
            slicerCaptionShow: "슬라이서 캡션:",
            slicerCaption: "슬라이서 캡션",
            slicerSettings: "슬라이서 설정",
            slicer: "슬라이서",
            styles: "스타일",
            slicerStyles: "슬라이서 스타일",
            columnsShow: "열:",
            heightShow: "높이:",
            widthShow: "너비:",
            columns: "열",
            height: "높이",
            width: "너비",
            buttons: "단추",
            size: "크기",
            shapeHeight: "도형 높이",
            shapeWidth: "도형 너비"
        }
    };
    ko_res.shapeSliderPanel = {
        fillAndLine: "채우기 및 선",
        formatShape: "도형 서식",
        shapeOptions: "도형 옵션",
        textOptions: "텍스트 옵션",
        textFill: "텍스트 채우기",
        textbox: "텍스트 상자",
        fill: "채우기",
        noFill: "채우기 없음",
        solidFill: "단색 채우기",
        color: "색",
        transparency: "투명도",
        line: "선",
        noLine: "선 없음",
        solidLine: "실선",
        dashType: "파선 유형",
        capType: "캡 유형",
        joinType: "조인 유형",
        beginArrowType: "시작 화살표 유형",
        beginArrowSize: "시작 화살표 크기",
        endArrowType: "끝 화살표 유형",
        endArrowSize: "끝 화살표 크기",
        width: "너비",
        height: "높이",
        size: "크기",
        rotation: "회전",
        moveSizeWithCells: "위치와 크기 변함",
        moveNoSizeWithCells: "위치만 변함",
        noMoveNoSizeWithCells: "변하지 않음",
        printObject: "객체 인쇄",
        locked: "잠김",
        vAlign: "세로 맞춤",
        hAlign: "가로 맞춤",
        flat: "기본",
        square: "정사각형",
        round: "원형",
        miter: "이음매",
        bevel: "3D 가장자리",
        solid: "단색",
        squareDot: "사각 점선",
        dash: "파선",
        longDash: "긴 파선",
        dashDot: "파선-점선",
        longDashDot: "긴 파선-점선",
        longDashDotDot: "긴 파선-점선-점선",
        sysDash: "SysDash",
        sysDot: "SysDot",
        sysDashDot: "SysDashDot",
        dashDotDot: "파선-점선-점선",
        roundDot: "둥근 점선",
        center: "가운데",
        bottom: "아래쪽",
        top: "위쪽",
        left: "왼쪽",
        right: "오른쪽",
        textEditor: "텍스트 편집기",
        text: "텍스트",
        font: "글꼴",
        properties: "속성",
        normal: "기본",
        italic: "기울임꼴",
        oblique: "오블리크",
        bold: "굵게",
        bolder: "더 굵게",
        lighter: '더 얇게',
        fontSize: '글꼴 크기',
        fontFamily: '글꼴 패밀리',
        fontStyle: '글꼴 스타일',
        fontWeight: '글꼴 두께',
    };
    ko_res.insertShapeDialog = {
        lines: "선",
        rectangles: "사각형",
        basicShapes: "기본 도형",
        blockArrows: "블록 화살표",
        equationShapes: "수식 도형",
        flowChart: "순서도",
        starsAndBanners: "별 및 배너",
        callouts: "설명선"
    };
    ko_res.shapeType = {
        actionButtonBackorPrevious: "뒤로 또는 이전 작업 버튼",
        actionButtonBeginning: "시작 작업 버튼",
        actionButtonCustom: "사용자 정의 작업 버튼",
        actionButtonDocument: "문서 작업 버튼",
        actionButtonEnd: "종료 작업 버튼",
        actionButtonForwardorNext: "앞으로 또는 다음 작업 버튼",
        actionButtonHelp: "도움말 작업 버튼",
        actionButtonHome: "홈 작업 버튼",
        actionButtonInformation: "정보 작업 버튼",
        actionButtonMovie: "동영상 작업 버튼",
        actionButtonReturn: "반환 작업 버튼",
        actionButtonSound: "소리 작업 버튼",
        arc: "호",
        balloon: "풍선",
        bentArrow: "굽은 화살표",
        bentUpArrow: "굽은 위쪽 화살표",
        bevel: "3D 가장자리",
        blockArc: "막힌 원호",
        can: "원통",
        chartPlus: "더하기 차트",
        chartStar: "별 차트",
        chartX: "X 차트",
        chevron: "펼침",
        chord: "현",
        circularArrow: "원형 화살표",
        cloud: "구름 모양",
        cloudCallout: "구름 모양 설명선",
        corner: "모서리",
        cornerTabs: "모서리 탭",
        cross: "교차",
        cube: "큐브",
        curvedDownArrow: "아래로 구부러진 화살표",
        curvedDownRibbon: "아래로 구부러진 리본",
        curvedLeftArrow: "왼쪽으로 구부러진 화살표",
        curvedRightArrow: "오른쪽으로 구부러진 화살표",
        curvedUpArrow: "위로 구부러진 화살표",
        curvedUpRibbon: "위로 구부러진 리본",
        decagon: "십각형",
        diagonalStripe: "대각선 줄",
        diamond: "다이아몬드",
        dodecagon: "십이각형",
        donut: "도넛",
        doubleBrace: "양쪽 중괄호",
        doubleBracket: "양쪽 대괄호",
        doubleWave: "이중 물결",
        downArrow: "아래쪽 화살표",
        downArrowCallout: "아래쪽 화살표 설명선",
        downRibbon: "아래쪽 리본",
        explosion1: "폭발 1",
        explosion2: "폭발 2",
        flowchartAlternateProcess: "순서도: 대체 처리",
        flowchartCard: "순서도: 카드",
        flowchartCollate: "순서도: 정렬/분류",
        flowchartConnector: "순서도: 연결선",
        flowchartData: "순서도: 데이터",
        flowchartDecision: "순서도: 의사 결정",
        flowchartDelay: "순서도: 지연",
        flowchartDirectAccessStorage: "순서도: 직접 액세스 저장소",
        flowchartDisplay: "순서도: 표시",
        flowchartDocument: "순서도: 문서",
        flowchartExtract: "순서도: 추출",
        flowchartInternalStorage: "순서도: 내부 저장소",
        flowchartMagneticDisk: "순서도: 자기 디스크",
        flowchartManualInput: "순서도: 수동 입력",
        flowchartManualOperation: "순서도: 수동 작업",
        flowchartMerge: "순서도: 병합",
        flowchartMultidocument: "순서도: 다중 문서",
        flowchartOfflineStorage: "순서도: 오프라인 저장소",
        flowchartOffpageConnector: "순서도: 페이지 연결선",
        flowchartOr: "순서도: 또는",
        flowchartPredefinedProcess: "순서도: 종속 처리",
        flowchartPreparation: "순서도: 준비",
        flowchartProcess: "순서도: 프로세스",
        flowchartPunchedTape: "순서도: 천공 테이프",
        flowchartSequentialAccessStorage: "순서도: 순차적 액세스 저장소",
        flowchartSort: "순서도: 정렬",
        flowchartStoredData: "순서도: 저장 데이터",
        flowchartSummingJunction: "순서도: 가산 접합",
        flowchartTerminator: "순서도: 수행의 시작/종료",
        foldedCorner: "모서리가 접힌 도형",
        frame: "액자",
        funnel: "퍼널형",
        gear6: "톱니 6",
        gear9: "톱니 9",
        halfFrame: "1/2 액자",
        heart: "하트",
        heptagon: "칠각형",
        hexagon: "육각형",
        horizontalScroll: "가로 스크롤",
        isoscelesTriangle: "이등변 삼각형",
        leftArrow: "왼쪽 화살표",
        leftArrowCallout: "왼쪽 화살표 설명선",
        leftBrace: "왼쪽 중괄호",
        leftBracket: "왼쪽 대괄호",
        leftCircularArrow: "왼쪽 원형 화살표",
        leftRightArrow: "왼쪽/오른쪽 화살표",
        leftRightArrowCallout: "왼쪽/오른쪽 화살표 설명선",
        leftRightCircularArrow: "왼쪽/오른쪽 원형 화살표",
        leftRightRibbon: "왼쪽/오른쪽 리본",
        leftRightUpArrow: "왼쪽/오른쪽/위쪽 화살표",
        leftUpArrow: "왼쪽/위쪽 화살표",
        lightningBolt: "번개",
        lineCallout1: "설명선 1",
        lineCallout1AccentBar: "설명선 1(강조선)",
        lineCallout1BorderandAccentBar: "설명선 1(테두리 및 강조선)",
        lineCallout1NoBorder: "설명선1(테두리 없음)",
        lineCallout2: "설명선 2",
        lineCallout2AccentBar: "설명선 2(강조선)",
        lineCallout2BorderandAccentBar: "설명선 2(테두리 및 강조선)",
        lineCallout2NoBorder: "설명선 2(테두리 없음)",
        lineCallout3: "설명선3",
        lineCallout3AccentBar: "설명선 3(강조선)",
        lineCallout3BorderandAccentBar: "설명선 3(테두리 및 강조선)",
        lineCallout3NoBorder: "설명선 3(테두리 없음)",
        lineCallout4: "설명선 4",
        lineCallout4AccentBar: "설명선 4(강조선)",
        lineCallout4BorderandAccentBar: "설명선 4(테두리 및 강조선)",
        lineCallout4NoBorder: "설명선 4(테두리 없음)",
        lineInverse: "역 선",
        mathDivide: "나누기",
        mathEqual: "같음",
        mathMinus: "빼기",
        mathMultiply: "곱하기",
        mathNotEqual: "같지 않음",
        mathPlus: "더하기",
        moon: "달",
        noSymbol: "기호 \"없음\"",
        nonIsoscelesTrapezoid: "이등변 사다리꼴 아님",
        notchedRightArrow: "톱니 모양의 오른쪽 화살표",
        octagon: "팔각형",
        oval: "타원",
        ovalCallout: "타원형 설명선",
        parallelogram: "평행 사변형",
        pentagon: "오각형",
        pie: "원형",
        pieWedge: "원형 쐐기",
        plaque: "액자",
        plaqueTabs: "액자 탭",
        quadArrow: "왼쪽/오른쪽/위쪽/아래쪽 화살표",
        quadArrowCallout: "왼쪽/오른쪽/위쪽/아래쪽 화살표 설명선",
        rectangle: "직사각형",
        rectangularCallout: "사각형 설명선",
        regularPentagon: "정오각형",
        rightArrow: "오른쪽 화살표",
        rightArrowCallout: "오른쪽 화살표 설명선",
        rightBrace: "오른쪽 중괄호",
        rightBracket: "오른쪽 대괄호",
        rightTriangle: "직각 삼각형",
        round1Rectangle: "한쪽 모서리가 둥근 사각형",
        round2DiagRectangle: "대각선 방향의 모서리가 둥근 사각형",
        round2SameRectangle: "양쪽 모서리가 둥근 사각형",
        roundedRectangle: "모서리가 둥근 직사각형",
        roundedRectangularCallout: "모서리가 둥근 사각형 설명선",
        shape4pointStar: "포인트가 4개인 별",
        shape5pointStar: "포인트가 5개인 별",
        shape8pointStar: "포인트가 8개인 별",
        shape16pointStar: "포인트가 16개인 별",
        shape24pointStar: "포인트가 24개인 별",
        shape32pointStar: "포인트가 32개인 별",
        smileyFace: "웃는 얼굴",
        snip1Rectangle: "한쪽 모서리가 잘린 사각형",
        snip2DiagRectangle: "대각선 방향의 모서리가 잘린 사각형",
        snip2SameRectangle: "양쪽 모서리가 잘린 사각형",
        snipRoundRectangle: "한쪽 모서리는 잘리고 다른 쪽 모서리는 둥근 사각형",
        squareTabs: "정사각형 탭",
        star6Point: "포인트가 6개인 별",
        star7Point: "포인트가 7개인 별",
        star10Point: "포인트가 10개인 별",
        star12Point: "포인트가 12개인 별",
        stripedRightArrow: "줄무늬가 있는 오른쪽 화살표",
        sun: "해",
        swooshArrow: "날아가는 화살표",
        tear: "눈물",
        trapezoid: "사다리꼴",
        uTurnArrow: "U자형 화살표",
        upArrow: "위쪽 화살표",
        upArrowCallout: "위쪽 화살표 설명선",
        upDownArrow: "위쪽/아래쪽 화살표",
        upDownArrowCallout: "위쪽/아래쪽 화살표 설명선",
        upRibbon: "위쪽 리본",
        verticalScroll: "세로 스크롤",
        wave: "물결",
        line: "선",
        lineArrow: "선 화살표",
        lineArrowDouble: "양방향 화살표",
        elbow: "꺾인 연결선",
        elbowArrow: "꺾인 화살표 연결선",
        elbowArrowDouble: "꺾인 양쪽 화살표 연결선"
    };
    ko_res.seriesDialog = {
        series: "계열",
        seriesIn: "방향",
        rows: "행",
        columns: "열",
        type: "유형",
        linear: "선형",
        growth: "급수",
        date: "날짜",
        autoFill: "자동 채우기",
        dateUnit: "날짜 단위",
        day: "일",
        weekday: "평일",
        month: "월",
        year: "년",
        trend: "추세",
        stepValue: "단계 값",
        stopValue: "종료 값"
    };

    ko_res.customSortDialog = {
        sort: "정렬",
        addLevel: "기준 추가",
        deleteLevel: "기준 삭제",
        copyLevel: "기준 복사",
        options: "옵션...",
        sortBy: "정렬 기준",
        sortBy2: "정렬 기준",
        thenBy: "다음 기준",
        sortOn: "정렬 기준",
        sortOrder: "정렬 순서",
        sortOptions: "정렬 옵션",
        orientation: "방향",
        sortTopToBottom: "위쪽에서 아래쪽",
        sortLeftToRight: "왼쪽에서 오른쪽",
        column: "열 ",
        row: "행 ",
        values: "값",
        ascending: "오름차순",
        descending: "내림차순"
    };

    ko_res.createTableDialog = {
        createTable: "표 만들기",
        whereYourTable: "표에 사용할 데이터를 지정하세요."
    };

    ko_res.createSparklineDialog = {
        createSparkline: "스파크라인 만들기",
        dataRange: "데이터 범위",
        locationRange: "위치 범위",
        chooseData: "원하는 데이터 선택",
        chooseWhere: "스파크라인을 배치할 위치 선택",
        warningText: "셀이 모두 같은 열 또는 행에 있지 않으므로 위치 참조가 잘못되었습니다. 모두 단일 열 또는 행에 있는 셀을 선택하세요.",
        notSingleCell: "위치 참조는 셀 범위를 지원하지 않으므로 단일 셀이어야 합니다."
    };

    ko_res.dataValidationDialog = {
        dataValidation: "데이터 유효성 검사",
        settings: "설정",
        validationCriteria: "유효성 조건",
        allow: "허용",
        anyValue: "모든 값",
        wholeNumber: "정수",
        decimal: "소수점",
        list: "목록",
        date: "날짜",
        textLength: "텍스트 길이",
        custom: "사용자 지정",
        data: "데이터",
        dataLabel: "데이터:",
        between: "해당 범위",
        notBetween: "제외 범위",
        equalTo: "같음",
        notEqualTo: "같지 않음",
        greaterThan: "보다 큼",
        lessThan: "보다 작음",
        greaterEqual: "보다 크거나 같음",
        lessEqual: "보다 작거나 같음",
        minimum: "최소값:",
        maximum: "최대값:",
        value: "값:",
        startDate: "시작 날짜:",
        endDate: "종료 날짜:",
        dateLabel: "날짜:",
        length: "길이:",
        source: "원본:",
        formula: "수식:",
        ignoreBlank: "공백 무시",
        inCellDropDown: "드롭다운 표시",
        inputMessage: "설명 메시지",
        highlightStyle: "강조 표시 스타일",
        errorAlert: "오류 메시지",
        showMessage: "셀을 선택하면 설명 메시지 표시",
        showMessage2: "셀을 선택하면 나타낼 설명 메시지: ",
        title: "제목",
        showError: "유효하지 않은 데이터를 입력하면 오류 메시지 표시",
        showError2: "유효하지 않은 데이터를 입력하면 나타낼 오류 메시지:",
        style: "스타일:",
        stop: "중지",
        warning: "경고",
        information: "정보",
        errorMessage: "오류 메시지",
        clearAll: "모두 지우기",
        valueEmptyMessage: "값은 비워둘 수 없습니다.",
        minimumMaximumMessage: "최대값은 최소값보다 크거나 같아야 합니다.",
        errorMessage1: "입력한 값이 잘못되었습니다.\r\n 이 셀에 입력할 수 있는 값은 제한되어 있습니다.",
        errorMessage2: "입력한 값이 잘못되었습니다.\r\n 이 셀에 입력할 수 있는 값은 제한되어 있습니다.\r\n계속하시겠습니까?",
        circle: "원",
        dogear: "모서리",
        icon: "아이콘",
        topLeft: "왼쪽 위",
        topRight: "오른쪽 위",
        bottomRight: "오른쪽 아래",
        bottomLeft: "왼쪽 아래",
        outsideRight: "바깥쪽 오른쪽",
        outsideLeft: "바깥쪽 왼쪽",
        color: "색",
        position: "위치",
        selectIcon: "아이콘 선택",
        selectIcons: "아이콘 추가"
    };
    ko_res.outlineColumnDialog = {
        collapsed: "축소됨",
        expanded: "확장된",
        custom: "사용자 정의",
        maxLevel: "최고 수준",
        showIndicator: "표시기 표시",
        customImage: "사용자 정의 표시기 이미지",
        showImage: "이미지 표시",
        showCheckBox: "체크박스 표시",
        title: "아웃라인 열",
        indicatorImage: "표시기 이미지:",
        itemImages: "항목 이미지:",
        icon: "아이콘"
    };

    ko_res.spreadSettingDialog = {
        spreadSetting: "분배 설정",
        general: "일반",
        settings: "설정",
        allowDragMerge: "끌어서 병합 허용",
        allowDragDrop: "끌어서 놓기 허용",
        allowFormula: "사용자의 수식 입력 허용",
        allowDragFill: "끌어서 채우기 허용",
        allowZoom: "확대/축소 허용",
        allowUndo: "실행 취소 허용",
        allowOverflow: "오버플로 허용",
        scrollBars: "스크롤 막대",
        visibility: "표시 여부",
        verticalScrollBar: "세로 스크롤 막대",
        horizontalScrollBar: "가로 스크롤 막대",
        scrollbarShowMax: "스크롤 막대 최대값 표시",
        scrollbarMaxAlign: "스크롤 막대 최대값 맞춤",
        tabStrip: "탭 스트립",
        tabStripVisible: "탭 스트립 표시",
        tabStripEditable: "탭 스트립 편집 가능",
        newTabVisible: "새 탭 표시",
        tabStripRatio: "탭 스트립 비율(백분율)",
        clipboard: "클립보드",
        allowCopyPasteExcelStyle: "Excel 스타일 복사 및 붙여넣기 허용",
        allowExtendPasteRange: "확장 범위 붙여넣기 허용",
        headerOptions: "머리글 옵션",
        noHeaders: "머리글 없음",
        rowHeaders: " 행 머리글",
        columnHeaders: "열 머리글",
        allHeaders: "모든 머리글",
        customListsTitle: "사용자 정의 목록",
        customLists: "사용자 정의 목록:",
        listEntries: "목록 항목:",
        add: "추가",
        delete: "삭제",
        newList: "새로운 목록",
        deleteNotification: "목록이 영구적으로 삭제됩니다.",
        scrollByPixel: "픽셀 스크롤",
        scrollPixel: "<pixels> 스크롤",
        allowDynamicArray: "동적 배열 허용",
        normalResizeMode: "기본",
        splitResizeMode: "분할",
        rowResizeMode: "행 크기 조정 모드",
        columnResizeMode: "열 크기 조정 모드"
    };

    ko_res.sheetSettingDialog = {
        sheetSetting: "시트 설정",
        general: "일반",
        columnCount: "열 수",
        rowCount: "행 수",
        frozenColumnCount: "고정된 열 수",
        frozenRowCount: "고정된 행 수",
        trailingFrozenColumnCount: "후행 고정된 열 수",
        trailingFrozenRowCount: "후행 고정된 행 수",
        selectionPolicy: "선택 정책",
        singleSelection: "단일 선택",
        rangeSelection: "범위 선택",
        multiRangeSelection: "여러 범위 선택",
        protect: "보호",
        gridlines: "눈금선",
        horizontalGridline: "가로 눈금선",
        verticalGridline: "세로 눈금선",
        gridlineColor: "눈금선 색",
        calculation: "계산",
        referenceStyle: "참조 스타일",
        a1: "A1",
        r1c1: "R1C1",
        headers: "머리글",
        columnHeaders: "열 머리글",
        rowHeaders: "행 머리글",
        columnHeaderRowCount: "열 머리글 행 수",
        columnHeaderAutoText: "열 머리글 자동 텍스트",
        columnHeaderAutoIndex: "열 머리글 자동 인덱스",
        defaultRowHeight: "기본 행 높이",
        columnHeaderVisible: "열 머리글 표시",
        blank: "공백",
        numbers: "숫자",
        letters: "문자",
        rowHeaderColumnCount: "행 머리글 열 수",
        rowHeaderAutoText: "행 머리글 자동 텍스트",
        rowHeaderAutoIndex: "행 머리글 자동 인덱스",
        defaultColumnWidth: "기본 열 너비",
        rowHeaderVisible: "행 머리글 표시",
        sheetTab: "시트 탭",
        sheetTabColor: "시트 탭 색:"
    };

    ko_res.groupDirectionDialog = {
        settings: "설정",
        direction: "방향",
        rowDirection: "아래 행에 정리",
        columnDirection: "오른쪽 열에 정리",
        showrow: "행 개요 표시",
        showcol: "열 개요 표시"
    };

    ko_res.insertSparklineDialog = {
        createSparklines: "스파크라인 만들기",
        dataRange: "데이터 범위:",
        dataRangeTitle: "원하는 데이터 선택",
        locationRange: "위치 범위",
        locationRangeTitle: "스파크라인을 배치할 위치 선택",
        errorDataRangeMessage: "유효한 범위를 입력하세요.",
        isFormulaSparkline: "수식 스파크라인 여부"
    };
    ko_res.cellStates = {
        cellStates: "셀 상태",
        cellStates1: "셀 상태",
        add: "셀 상태 추가",
        remove: "셀 상태 제거",
        manage: "셀 상태 관리",
        selectStateType: "셀 상태 유형 선택",
        normal: "기본",
        hover: "일반",
        invalid: "사용 불가능",
        edit: "편집",
        readonly: "읽기 전용",
        active: "활성화",
        selected: "선택됨",
        selectRange: "범위 선택",
        range: "범위:",
        selectStyle: "스타일 선택",
        formatStyle: "서식...",
        headRange: "범위",
        headStyle: "스타일",
        headState: "상태 유형",
        title: "셀 상태 만들기",
        list: "셀 상태 목록:",

        forbidCorssSheet: "시트에서 범위를 선택하십시오",
        errorStateType: "유효한 셀 상태를 선택하십시오.",
        errorStyle: "선택한 범위의 유효한 스타일을 설정하십시오.",
        errorDataRangeMessage: "유효한 범위를 입력하십시오."
    };

    ko_res.sparklineWeightDialog = {
        sparklineWeight: "스파크라인 두께",
        inputWeight: "스파크라인 두께(pt) 입력",
        errorMessage: "유효한 두께를 입력하세요."
    };

    ko_res.sparklineMarkerColorDialog = {
        sparklineMarkerColor: "스파크라인 표식 색:",
        negativePoints: "음수 점:",
        markers: "표식:",
        highPoint: "높은 점:",
        lowPoint: "낮은 점:",
        firstPoint: "첫 점:",
        lastPoint: "마지막 점:"
    };

    ko_res.resizeTableDialog = {
        title: "표 크기 조정",
        dataRangeTitle: "표의 새 데이터 범위 선택:",
        note: "참고: 머리글은 동일한 행에 유지되고\r\n결과 표 범위는 원래 표 범위와 \r\n일치해야 합니다."
    };

    ko_res.saveAsDialog = {
        title: "파일을 저장",
        fileNameLabel: "파일 이름:"
    };

    ko_res.statusBar = {
        zoom: "확대/축소",
        toolTipZoomPanel: "확대/축소 수준입니다. 확대/축소 대화 상자를 열려면 클릭하십시오."
    };

    ko_res.calendarSparklineDialog = {
        calendarSparklineDialog: "달력 스파크라인 대화 상자",
        monthSparklineDialog: "월 스파크라인 대화 상자",
        yearSparklineDialog: "년 스파크라인 대화 상자",
        emptyColor: "빈 색",
        startColor: "시작 색",
        middleColor: "중간 색",
        endColor: "마지막 색",
        rangeColor: "범위 색",
        year: "년",
        month: "월"
    };
    ko_res.barcodeDialog = {
        barcodeDialog: "바코드 대화 상자",
        locationReference: "위치 참조",
        showLabel: "레이블 표시",
        barcodetype: "바코드 유형",
        value: "값",
        color: "색",
        errorCorrectionLevel: "오류 수정 수준",
        backgroudColor: "배경색",
        version: "버전",
        model: "모델",
        mask: "마스크",
        connection: "연결",
        charCode: "문자 코드",
        connectionNo: "연결 번호",
        charset: "문자 집합",
        quietZoneLeft: "왼쪽 자동 영역",
        quietZoneRight: "오른쪽 자동 영역",
        quietZoneTop: "위쪽 자동 영역",
        quietZoneBottom: "아래쪽 자동 영역",
        labelPosition: "레이블 위치",
        addOn: "AddOn",
        addOnLabelPosition: "AddOn 레이블 위치",
        fontFamily: "글꼴 패밀리",
        fontStyle: "글꼴 스타일",
        fontWeight: "글꼴 두께",
        fontTextDecoration: "글꼴 텍스트 장식",
        fontTextAlign: "글꼴 텍스트 맞춤",
        fontSize: "글꼴 크기",
        fileIdentifier: "파일 식별자",
        structureNumber: "구조 번호",
        structureAppend: "구조 추가",
        ecc00_140Symbole: "Ecc000_140 기호 크기",
        ecc200EndcodingMode: "Ecc200 인코딩 모드",
        ecc200SymbolSize: "Ecc200 기호 크기",
        eccMode: "Ecc 모드",
        compact: "컴팩트",
        columns: "열",
        rows: "행",
        groupNo: "그룹 번호",
        grouping: "그룹화",
        codeSet: "코드 집합",
        fullASCII: "전체 ASCII",
        checkDigit: "검사 숫자",
        nwRatio: "전각 및 반각 비율",
        labelWithStartAndStopCharacter: "시작 및 끝 문자가 있는 레이블"
    };
    ko_res.pieSparklineDialog = {
        percentage: "백분율",
        color: "색",
        addColor: "색 추가",
        pieSparklineSetting: "원형 스파크라인 설정"
    };

    ko_res.areaSparklineDialog = {
        title: "영역 스파크라인 수식",
        points: "점",
        min: "최소값",
        max: "최대값",
        line1: "선 1",
        line2: "선 2",
        positiveColor: "양수 색",
        negativeColor: "음수 색",
        areaSparklineSetting: "영역 스파크라인 설정"
    };

    ko_res.scatterSparklineDialog = {
        points1: "점1",
        points2: "점2",
        minX: "최소 X",
        maxX: "최대 X",
        minY: "최소 Y",
        maxY: "최대 Y",
        hLine: "가로 선",
        vLine: "세로 선",
        xMinZone: "X 최소 영역",
        yMinZone: "Y 최소 영역",
        xMaxZone: "X 최대 영역",
        yMaxZone: "Y 최대 영역",
        tags: "태그",
        drawSymbol: "기호 그리기",
        drawLines: "선 그리기",
        color1: "색 1",
        color2: "색 2",
        dash: "파선",
        scatterSparklineSetting: "분산형 스파크라인 설정"
    };

    ko_res.compatibleSparklineDialog = {
        title: "호환되는 스파크라인 수식",
        style: "스타일",
        show: "표시",
        group: "그룹",
        data: "데이터",
        dataOrientation: "데이터 방향",
        dateAxisData: "날짜 축 데이터",
        dateAxisOrientation: "날짜 축 방향",
        settting: "설정",
        axisColor: "축",
        firstMarkerColor: "첫 표식",
        highMarkerColor: "높은 표식",
        lastMarkerColor: "마지막 표식",
        lowMarkerColor: "낮은 표식",
        markersColor: "표식",
        negativeColor: "음수",
        seriesColor: "계열",
        displayXAxis: "X축 표시",
        showFirst: "첫 항목 표시",
        showHigh: "높은 항목 표시",
        showLast: "마지막 항목 표시",
        showLow: "낮은 항목 표시",
        showNegative: "음수 표시",
        showMarkers: "표식 표시",
        lineWeight: "선 두께",
        displayHidden: "숨겨진 행 및 열에 데이터 표시",
        displayEmptyCellsAs: "빈 셀로 표시할 항목",
        rightToLeft: "오른쪽에서 왼쪽",
        minAxisType: "최소 축 유형",
        maxAxisType: "최대 축 유형",
        manualMax: "수동 최대값",
        manualMin: "수동 최소값",
        gaps: "간격",
        zero: "0",
        connect: "연결",
        vertical: "세로",
        horizontal: "가로",
        stylesetting: "스타일 설정",
        individual: "개인",
        custom: "사용자 지정",
        compatibleSparklineSetting: "호환되는 스파크라인 설정",
        styleSetting: "스타일 설정",
        errorMessage: "유효한 범위를 입력하세요."
    };

    ko_res.bulletSparklineDialog = {
        bulletSparklineSetting: "글머리 기호 스파크라인 설정",
        measure: "측정",
        target: "대상",
        maxi: "최대값",
        good: "좋음",
        bad: "나쁨",
        forecast: "예측",
        tickunit: "눈금 단위",
        colorScheme: "색 구성표",
        vertical: "세로"
    };

    ko_res.spreadSparklineDialog = {
        spreadSparklineSetting: "분산형 스파크라인 설정",
        points: "점",
        showAverage: "평균 표시",
        scaleStart: "첫 점",
        scaleEnd: "마지막 점",
        style: "스타일",
        colorScheme: "색 구성표",
        vertical: "세로",
        stacked: "누적형",
        spread: "분배",
        jitter: "지터",
        poles: "기둥",
        stackedDots: "누적된 점",
        stripe: "줄무늬"
    };

    ko_res.stackedSparklineDialog = {
        stackedSparklineSetting: "누적형 스파크라인 설정",
        points: "점",
        colorRange: "색 범위",
        labelRange: "레이블 범위",
        maximum: "최대값",
        targetRed: "대상 빨강",
        targetGreen: "대상 녹색",
        targetBlue: "대상 파랑",
        targetYellow: "대상 노랑",
        color: "색",
        highlightPosition: "강조 표시 위치",
        vertical: "세로",
        textOrientation: "텍스트 방향",
        textSize: "텍스트 크기",
        textHorizontal: "가로",
        textVertical: "세로",
        px: "px"
    };

    ko_res.barbaseSparklineDialog = {
        hbarSparklineSetting: "가로 막대 스파크라인 설정",
        vbarSparklineSetting: "세로 막대 스파크라인 설정",
        value: "값",
        colorScheme: "색 구성표"
    };

    ko_res.variSparklineDialog = {
        variSparklineSetting: "분산 스파크라인 설정",
        variance: "분산",
        reference: "참조",
        mini: "최소값",
        maxi: "최대값",
        mark: "표시",
        tickunit: "눈금 단위",
        legend: "범례",
        colorPositive: "양수 색",
        colorNegative: "음수 색",
        vertical: "세로"
    };
    ko_res.boxplotSparklineDialog = {
        boxplotSparklineSetting: "상자 그림 스파크라인 설정",
        points: "점",
        boxPlotClass: "상자 그림 클래스",
        showAverage: "평균 표시",
        scaleStart: "크기 조정 시작",
        scaleEnd: "크기 조정 종료",
        acceptableStart: "허용 가능한 시작",
        acceptableEnd: "허용 가능한 끝",
        colorScheme: "색 구성표",
        style: "스타일",
        vertical: "세로",
        fiveNS: "5NS",
        sevenNS: "7NS",
        tukey: "Tukey",
        bowley: "Bowley",
        sigma: "Sigma3",
        classical: "클래식",
        neo: "Neo"
    };
    ko_res.cascadeSparklineDialog = {
        cascadeSparklineSetting: "계단식 스파크라인 배열 설정",
        pointsRange: "점 범위",
        pointIndex: "점 인덱스",
        labelsRange: "레이블 범위",
        minimum: "최소값",
        maximum: "최대값",
        colorPositive: "양수 색",
        colorNegative: "음수 색",
        vertical: "세로"
    };

    ko_res.multiCellFormula = {
        warningText: "선택한 범위에 다른 수식 유형이 있을 수 있습니다. 새 범위를 선택하세요."
    };

    ko_res.paretoSparklineDialog = {
        paretoSparklineSetting: "파레토 스파크라인 설정",
        points: "점",
        pointIndex: "점 인덱스",
        colorRange: "색 범위",
        target: "대상",
        target2: "대상2",
        highlightPosition: "강조 표시 위치",
        label: "레이블",
        vertical: "세로",
        none: "없음",
        cumulated: "누적",
        single: "단일"
    };

    ko_res.sliderPanel = {
        title: "필드 목록"
    };

    ko_res.protectionOptionDialog = {
        title: "시트 보호",
        label: "워크시트에서 허용할 내용:",
        allowSelectLockedCells: "잠긴 셀 선택",
        allowSelectUnlockedCells: "잠기지 않은 셀 선택",
        allowSort: "정렬",
        allowFilter: "자동 필터 사용",
        allowResizeRows: "행 크기 조정",
        allowResizeColumns: "열 크기 조정",
        allowEditObjects: "개체 편집",
        allowDragInsertRows: "끌어서 행 삽입",
        allowDragInsertColumns: "끌어서 열 삽입",
        allowInsertRows: "행 삽입",
        allowInsertColumns: "열 삽입",
        allowDeleteRows: "행 삭제",
        allowDeleteColumns: "열 삭제"
    };

    ko_res.insertSlicerDialog = {
        insertSlicer: "슬라이서 삽입"
    };

    ko_res.formatSlicerStyle = {
        custom: "사용자 지정",
        light: "밝게",
        dark: "어둡게",
        other: "기타",
        newSlicerStyle: "새 슬라이서 스타일...",
        slicerStyle: "슬라이서 스타일",
        name: "이름",
        slicerElement: "슬라이서 요소",
        format: "형식",
        clear: "지우기",
        preview: "미리 보기",
        exception: "이 스타일 이름이 이미 있습니다."
    };

    ko_res.slicerElement = {
        wholeSlicer: "전체 슬라이서",
        header: "머리글",
        selectedItemWithData: "선택된 항목(데이터 있음)",
        selectedItemWithNoData: "선택된 항목(데이터 없음)",
        unselectedItemWithData: "선택되지 않은 항목(데이터 있음)",
        unselectedItemWithNoData: "선택되지 않은 항목(데이터 없음)",
        hoveredSelectedItemWithData: "마우스가 가리키는 선택된 항목(데이터 있음)",
        hoveredSelectedItemWithNoData: "마우스가 가리키는 선택된 항목(데이터 없음)",
        hoveredUnselectedItemWithData: "마우스가 가리키는 선택되지 않은 항목(데이터 있음)",
        hoveredUnselectedItemWithNoData: "마우스가 가리키는 선택되지 않은 항목(데이터 없음)"
    };

    ko_res.slicerSettingDialog = {
        slicerSetting: "슬라이서 설정",
        sourceName: "원본 이름:",
        name: "이름:",
        header: "머리글",
        display: "머리글 표시",
        caption: "캡션:",
        items: "항목 정렬 및 필터링",
        ascending: "오름차순 기준",
        descending: "내림차순 기준",
        customList: "정렬할 때 사용자 지정 목록 사용",
        hideItem: "데이터가 없는 항목 숨기기",
        visuallyItem: "데이터가 없는 항목을 시각적으로 표시",
        showItem: "마지막 데이터가 없는 항목 표시"
    };

    ko_res.slicerPropertyDialog = {
        formatSlicer: "서식 슬라이서",
        position: "위치 및 레이아웃",
        size: "크기",
        properties: "속성",
        pos: "위치",
        horizontal: "가로:",
        vertial: "세로:",
        disableResizingMoving: "크기 조정 및 이동 사용 안 함",
        layout: "레이아웃",
        numberColumn: "열 개수:",
        buttonHeight: "단추 높이:",
        buttonWidth: "단추 너비:",
        height: "높이:",
        width: "너비:",
        scaleHeight: "높이 조절:",
        scaleWidth: "너비 조절:",
        moveSize: "위치와 크기 변함",
        moveNoSize: "위치만 변함",
        noMoveSize: "변하지 않음",
        locked: "잠금"
    };
    ko_res.errorGroupDialog = {
        errorGroup: "오류 그룹/그룹 해제",
        errorGroupMessage: "시트에 아웃라인 열이 있습니다. 작업을 계속하시겠습니까?"
    };
    ko_res.tableErrDialog = {
        tableToRange: "표를 일반 범위로 변환하시겠습니까?",
        insertTableInArrayFormula: "다중 셀 배열 수식은 표에서 사용할 수 없습니다."
    };

    ko_res.selectData = {
        changeDataRange: '차트 데이터 범위:',
        switchRowColumn: '행/열 전환',
        legendEntries: '범례 항목(계열)',
        moveUp: '위로 이동',
        moveDown: '아래로 이동',
        horizontalAxisLabels: '가로(범주) 축 레이블',
        add: '추가',
        edit: '편집',
        remove: '제거',
        selectDataSource: '데이터 원본 선택',
        addSeries: '계열 추가',
        editSeries: '계열 편집',
        editSeriesName: '계열 이름 편집',
        editSeriesValue: '계열 값 편집',
        seriesName: '계열 이름',
        seriesYValue: 'y 값 계열',
        seriesXValue: 'x 값 ​​계열',
        seriesSize: '계열 크기',
        errorPrompt: {
            cantRemoveLastSeries: "마지막 계열을 제거할 수 없습니다.",
            seriesValueIsIllegal: '잘못된 계열 값',
            cantSwitchRowColumn: "행/열을 전환 할 수 없음",
            categoryValueIsIllegal: "잘못된 범주 값",
            connectorShapeChangeShapeType: "선 도형 유형은 변경할 수 없습니다."
        },
        noDataRange: '데이터 범위가 너무 복잡해서 표시할 수 없습니다. 새 범위를 선택하면 계열 패널의 모든 계열이 바뀝니다.',
        hiddenEmptyButton: "숨겨진 셀 및 빈 셀",
        gaps: "간격",
        zero: "0",
        connectData: "선으로 데이터 요소 연결",
        showEmptyCell: "다음으로 빈 셀 표시:",
        chartHiddenEmptyCell: "숨겨진 셀 및 빈 셀 설정",
        positive: "양의 오류 값",
        negative: "음의 오류 값"
    };

    ko_res.addChartElement = {
        axes: {
            axes: '축',
            moreAxisOption: '추가 축 옵션'
        },
        axisTitles: {
            axisTitles: '축 제목',
            moreAxisTitlesOption: '추가 축 제목 옵션'
        },
        chartTitle: {
            chartTitle: '차트 제목',
            moreChartTitleOption: '추가 차트 제목 옵션'
        },
        gridLines: {
            gridLines: '눈금선',
            moreGridLinesOption: '추가 눈금선 옵션'
        },
        dataLabels: {
            dataLabels: '데이터 레이블',
            moreDataLabelsOption: '추가 데이터 레이블 옵션'
        },
        legend: {
            legend: '범례',
            moreLegendOption: '추가 범례 옵션'
        },
        trendline: {
            trendline: "추세선",
            moreTrendlineOption: "추세선 옵션 더 보기"
        },
        errorBar: {
            errorBar: "오차 막대"
        },
        primaryHorizontal: '기본 가로',
        primaryVertical: '기본 세로',
        secondaryHorizontal: '보조 가로',
        secondaryVertical: '보조 세로',
        none: '없음',
        aboveChart: '차트 위',
        primaryMajorHorizontal: '기본 주 가로',
        primaryMajorVertical: '기본 주 세로',
        primaryMinorHorizontal: '기본 부 가로',
        primaryMinorVertical: '기본 부 세로',
        secondaryMajorHorizontal: '보조 주 가로',
        secondaryMajorVertical: '보조 주 세로',
        secondaryMinorHorizontal: '보조 부 가로',
        secondaryMinorVertical: '보조 부 세로',
        center: '가운데',
        insideEnd: '안쪽 끝',
        outsideEnd: '바깥쪽 끝',
        bestFit: '자동 맞춤',
        above: '초과',
        below: '미만',
        show: '표시',
        right: '오른쪽',
        top: '위쪽',
        left: '왼쪽',
        bottom: '아래쪽',
        errorBarStandardError: "표준 오류",
        errorBarPercentage: "백분율",
        errorBarStandardDeviation: "표준 편차",
        moreErrorBarOption: "오차 막대 옵션 더 보기...",
        trendlineLinear: "선형",
        trendlineExponential: "지수",
        trendlineLinearForecast: "선형 예측",
        trendlineMovingAverage: "이동 평균"
    };
    ko_res.InsertFunctionsChildrenDialog = {
        title: '함수 인수',
        formula: '함수'
    };
    ko_res.chartErrorBar = {
        title: '사용자 정의 오차 막대'
    };
    ko_res.chartErrorBarsDialog = {
        title: '오차 막대 추가',
        label: '계열을 기반으로 오차 막대 추가:'
    };
    ko_res.chartTrendlineDialog = {
        title: '추세선 추가',
        label: '계열을 기반으로 추세선 추가:'
    };
    ko_res.selectionError = {
        selectEmptyArea: "영역 선택 오류"
    };

    ko_res.name = "ko";
    designer.res = ko_res;

})();
