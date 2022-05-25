# 피벗그리드 조회 배치 프로그램 가이드

해당 프로그램은 pivotSummaryMatrix.do 를 기준으로 작성되었습니다.

## CSRF 회피 방법

 CSRF 보안취약점을 우회하기 위해 가장먼저 security-context에 id="csrfMatcher"부분에 /report/pivotSummaryMatrix.do를 추가한다(현재(2021-10-03) CSRF는 get방식은 모두 적용X이나 POST방식의 경우 CSRF필터링에 걸리지 않도록해야하기 떄문)

## 해당 보고서의 조회 요청 네트워크 패킷을 복사

 크롬 개발자 도구 Network 창에서 pivotSummaryMatrix.do의 curl을 카피한다.

`-H` 부분이 많은데 그 중 필요한 정보를 제외하고 나머지를 제거한다

예를 들면,

```
  -H "Proxy-Connection: keep-alive" ^
  -H "Pragma: no-cache" ^
  -H "Cache-Control: no-cache" ^
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36" ^
  -H "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" ^
  -H "Accept: */*" ^
  -H "Referer: http://localhost:8080/olap/report/edit.do" ^
  -H "Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7" ^
```

※ 위의 기준은 WINDOW이며 리눅스 " -> ', ^(줄내림) -> \
  
4. curl의 --data-row는 압축되어서 표시되기 떄문에 크롬개발자 도구 Network 창에서 pivotSummaryMatrix.do의 copy to node.js를 복사한 후 body 부분만 가져온다

5. curl의 --data-row는 길이제한이 있어 body부분을 txt파일 등으로 저장한다 이떄 "(리눅스=')는 저장하지 않는다.

6. curl의 --data-row 부분을 -d @폴더경로/파일명으로 변경하여 입력한다.

 EX)

```

  -d @test1_data.txt
  
```  
7. 실행한다.
