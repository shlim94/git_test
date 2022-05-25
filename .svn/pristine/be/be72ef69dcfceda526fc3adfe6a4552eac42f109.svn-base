for i in data/*.txt
do
        curl -i 'http://10.99.9.131:7100/olap/report/pivotSummaryMatrix.do' \
			-H 'Connection: keep-alive' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' \
			-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.54 Safari/537.36' \
			-H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' -H 'Accept: */*' -H 'Referer: http://10.99.9.131:7100/olap/report/edit.do' \
			-H 'Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7' \
			-d @"${i}" 1> logs/${i}.log 2>&1
			
done


