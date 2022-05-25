package com.wise.ds.query.util;

public class SqlForEachMartDbType {
	public String SqlForEachDbType(String aDbmsType, String aObjType, String aOwnerNm, String aDbNm, String aTblNmByCol, String aFilterStr) {
		String sql = null;
		
		/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
		if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
			int tblCnt = 0;
			String selectTableListStr = "";
			for(String selectedTable:aFilterStr.split(",")) {
				selectTableListStr += "'"+ selectedTable.toUpperCase() +"'";
				if(tblCnt < aFilterStr.split(",").length -1) {
					selectTableListStr +=",";
				}
				tblCnt++;
			}
			selectTableListStr+="";
			aFilterStr = selectTableListStr;
		}
		
		
		if(aObjType.equals("TABLE")) {
			if(aDbmsType.equals("MS-SQL")) {
				/* DOGFOOT ktkang 데이터 원본으로 테이블 가져오는 쿼리 수정  20201117 */
				sql = "";
				sql += "SELECT  CAST(A.NAME AS NVARCHAR(200)) AS TBL_NM, CAST(B.VALUE AS NVARCHAR(200)) AS TBL_CAPTION ";
				sql += "FROM	SYSOBJECTS A LEFT JOIN ::FN_LISTEXTENDEDPROPERTY(DEFAULT, N'USER', N'dbo', N'TABLE',DEFAULT,DEFAULT,DEFAULT) B ";
				sql += "ON A.name = B.objname collate Latin1_General_CI_AI ";
				sql += "LEFT JOIN SYS.schemas C ";
				sql += "ON A.uid = C.schema_id ";
				sql += "WHERE	A.xtype IN ('U', 'V') ";
				sql += "AND A.NAME NOT IN ('sysdiagrams') ";
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND UPPER(CAST(A.NAME AS NVARCHAR(200))) IN (" + aFilterStr.toUpperCase() + ") ";
				}else {
					sql += "AND UPPER(CAST(A.NAME AS NVARCHAR(200))) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				if(aOwnerNm != null) {
					sql += "AND  C.name = '" + aOwnerNm + "' ";
				}
				sql += "ORDER BY 1 ";
			} 
			else if(aDbmsType.equals("ORACLE")) {
				sql = "";
				sql += "SELECT  A.TABLE_NAME TBL_NM, B.COMMENTS TBL_CAPTION ";
				sql += "FROM	ALL_TABLES A, ALL_TAB_COMMENTS B ";
				sql += "WHERE	A.OWNER = B.OWNER ";
				sql += "AND     A.TABLE_NAME = B.TABLE_NAME ";
				sql += "AND     A.OWNER = '" + aOwnerNm + "' ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND     UPPER(A.TABLE_NAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND     UPPER(A.TABLE_NAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";					
				}
				sql += "UNION ALL ";
				sql += "SELECT  A.VIEW_NAME TBL_NM, B.COMMENTS TBL_CAPTION ";
				sql += "FROM	ALL_VIEWS A, ALL_TAB_COMMENTS B ";
				sql += "WHERE	A.OWNER = B.OWNER ";
				sql += "AND     A.VIEW_NAME = B.TABLE_NAME ";
				sql += "AND     A.OWNER = '" + aOwnerNm + "' ";
				sql += "UNION ALL ";
				sql += "SELECT A.MVIEW_NAME TBL_NM, B.COMMENTS TBL_CAPTION ";
				sql += "FROM ALL_MVIEWS A, USER_MVIEW_COMMENTS B ";
				sql += "WHERE  A.MVIEW_NAME = B.MVIEW_NAME ";
				sql += "AND     A.OWNER = '" + aOwnerNm + "' ";
				sql += "UNION ALL ";
				sql += "SELECT  A.SYNONYM_NAME TBL_NM, B.COMMENTS TBL_CAPTION ";
				sql += "FROM	ALL_SYNONYMS A, ALL_TAB_COMMENTS B ";
				sql += "WHERE	A.TABLE_OWNER = B.OWNER ";
				sql += "AND     A.TABLE_NAME = B.TABLE_NAME ";
				sql += "AND     A.OWNER = '" + aOwnerNm + "' ";
				sql += "ORDER BY 1  ";
			}
			else if(aDbmsType.equals("TIBERO")) {
				sql = "";
				sql += "SELECT  A.TABLE_NAME TBL_NM, B.COMMENTS TBL_CAPTION ";
				sql += "FROM	ALL_TABLES A, ALL_TAB_COMMENTS B ";
				sql += "WHERE	A.OWNER = B.OWNER ";
				sql += "AND     A.TABLE_NAME = B.TABLE_NAME ";
				sql += "AND     A.OWNER = '" + aOwnerNm + "' ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND     UPPER(A.TABLE_NAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND     UPPER(A.TABLE_NAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";					
				}
				sql += "UNION ALL ";
				sql += "SELECT  A.VIEW_NAME TBL_NM, B.COMMENTS TBL_CAPTION ";
				sql += "FROM	ALL_VIEWS A, ALL_TAB_COMMENTS B ";
				sql += "WHERE	A.OWNER = B.OWNER ";
				sql += "AND     A.VIEW_NAME = B.TABLE_NAME ";
				sql += "AND     A.OWNER = '" + aOwnerNm + "' ";
				sql += "ORDER BY 1  ";
			}
			else if(aDbmsType.equals("TBIN")) {
				sql = "";
				sql += "SELECT  A.TABLE_NAME TBL_NM, B.COMMENTS TBL_CAPTION ";
				sql += "FROM	ALL_TABLES A, ALL_TAB_COMMENTS B ";
				sql += "WHERE	A.OWNER = B.OWNER ";
				sql += "AND     A.TABLE_NAME = B.TABLE_NAME ";
				sql += "AND     A.OWNER = '" + aOwnerNm + "' ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND     UPPER(A.TABLE_NAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND     UPPER(A.TABLE_NAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";					
				}
				sql += "UNION ALL ";
				sql += "SELECT  A.VIEW_NAME TBL_NM, B.COMMENTS TBL_CAPTION ";
				sql += "FROM	ALL_VIEWS A, ALL_TAB_COMMENTS B ";
				sql += "WHERE	A.OWNER = B.OWNER ";
				sql += "AND     A.VIEW_NAME = B.TABLE_NAME ";
				sql += "AND     A.OWNER = '" + aOwnerNm + "' ";
				sql += "ORDER BY 1  ";
			}
			else if(aDbmsType.equals("VERTICA")) {
				sql = "";
				sql += "SELECT  A.TABLE_NAME TBL_NM, B.COMMENT TBL_CAPTION ";
				sql += "FROM    TABLES A LEFT OUTER JOIN COMMENTS B ";
				sql += "ON      A.TABLE_NAME = B.OBJECT_NAME ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "WHERE   UPPER(A.TABLE_NAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "WHERE   UPPER(A.TABLE_NAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += "ORDER BY 1  ";
			}
			else if(aDbmsType.equals("MSPDW")) {
				//                sql += "SELECT  CAST(A.TABLE_NAME AS NVARCHAR(200)) AS TBL_NM, CAST(A.TABLE_NAME AS NVARCHAR(200)) AS TBL_CAPTION ";
				//                sql += "FROM	[" + aDbNm + "].INFORMATION_SCHEMA.TABLES A ";
				//                sql += "WHERE	A.TABLE_TYPE IN ('VIEW', 'BASE TABLE') ";
				//                sql += "ORDER BY 1  ";

				sql = "";
				sql += "SELECT CAST(A.NAME AS NVARCHAR(200)) AS TBL_NM, CAST(A.NAME AS NVARCHAR(200)) AS TBL_CAPTION ";
				sql += "FROM	 SYSOBJECTS A ";
				sql += "WHERE	A.xtype IN ('U', 'V') ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND     UPPER(CAST(A.NAME AS NVARCHAR(200))) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND     UPPER(CAST(A.NAME AS NVARCHAR(200))) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += "ORDER BY 1  ";
			}
			else if(aDbmsType.equals("MYSQL") || aDbmsType.equals("MYIDB") || aDbmsType.equals("MARIA")) {
				sql = "";
				sql += "SELECT TABLE_NAME AS TBL_NM, TABLE_COMMENT AS TBL_CAPTION  ";
				sql += "FROM INFORMATION_SCHEMA.TABLES  ";
				sql += "WHERE TABLE_SCHEMA = '" + aDbNm + "' ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND UPPER(TABLE_NAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND UPPER(TABLE_NAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
			}
			else if(aDbmsType.equals("DB2BLU")) {
				sql = "";
				sql += "SELECT  TABNAME TBL_NM, COALESCE(REMARKS, TABNAME) TBL_CAPTION  ";
				sql += "FROM    SYSCAT.TABLES  ";
				sql += "WHERE   TYPE IN ('T', 'V') AND OWNERTYPE = 'U'  ";
				sql += "AND     TABSCHEMA = '" + aOwnerNm + "' ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND     UPPER(TABNAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND     UPPER(TABNAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += "ORDER BY 1 ";
			}
			else if(aDbmsType.equals("POSTGRES")) {
				sql = "";

				////                cjs_20180316 서울시청 테이블에 권한 적용 
				//                if(m_clsSolutionProperty.GetSiteNm().equals("SEOULCITYHALL")) {
				//                    sql += " SELECT A.table_name TBL_NM ";
				//                    sql += "        , pg_catalog.obj_description(B.oid, 'pg_class') as TBL_CAPTION ";
				//                    sql += " FROM information_schema.tables A ";
				//                    sql += "    LEFT OUTER JOIN pg_catalog.pg_class B  ";
				//                    sql += "        ON A.table_name = substr(B.relname,1,300) ";
				//                    sql += "    LEFT OUTER JOIN INFORMATION_SCHEMA.ROLE_TABLE_GRANTS C  "; // 사용자 권한 테이블 조회
				//                    sql += "        ON A.TABLE_NAME = substr(C.TABLE_NAME,1,300) ";
				//                    sql += " WHERE A.table_type IN ('BASE TABLE', 'VIEW') ";
				//                    sql += "    AND A.table_schema NOT IN ('pg_catalog', 'information_schema') ";
				//                    sql += "    AND C.PRIVILEGE_TYPE = 'SELECT' ";
				////                    'sql += "    AND A.table_schema = 'bdw_dm' ";
				////                    'sql += "    AND C.GRANTEE = '" + m_clsUserProperty.GetUserId + "' ";
				//                    sql += "    AND A.table_schema = '" + aOwnerNm + "' ";
				//                    sql += "    AND C.GRANTEE = '" + aUserId + "' ";
				//                    sql += " ORDER BY 1 ";
				//                }
				//                else {
				sql += " SELECT A.table_name TBL_NM, pg_catalog.obj_description(B.oid, 'pg_class') as TBL_CAPTION ";
				sql += " FROM information_schema.tables A ";
				sql += " INNER JOIN pg_catalog.pg_class B ON A.table_name = B.relname ";
				sql += " WHERE A.table_type IN ('BASE TABLE', 'VIEW')  ";
				sql += " AND A.table_schema NOT IN ('pg_catalog', 'information_schema') ";
				sql += " AND pg_catalog.pg_table_is_visible(B.oid) ";
				sql += " AND A.table_schema = '" + aOwnerNm + "' ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND UPPER(A.table_name) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND UPPER(A.table_name) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += " ORDER BY 1 ";
				//                }
			}
			else if(aDbmsType.equals("NETEZZA")) {
				/*dogfoot NETEZZA DB 오류 로 인한 임시작업 shlim 20210427*/
				//sql = "SELECT 1 AS TBL_NM, 1 AS TBL_CAPTION";
				
				sql = "";
				sql += " SELECT TABLENAME AS TBL_NM, ";
				sql += " 	    DESCRIPTION AS TBL_CAPTION  ";
				sql += " FROM _v_table WHERE OWNER = '" + aOwnerNm + "' ";
//				dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND   UPPER(TABLENAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND   UPPER(TABLENAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += " UNION ALL ";
				sql += " SELECT VIEWNAME AS TBL_NM, ";
				sql += " 	    DESCRIPTION AS TBL_CAPTION ";
				sql += " FROM _v_VIEW WHERE OWNER = '" + aOwnerNm + "' ";
				sql += " ORDER BY TBL_NM ";
			}
			else if(aDbmsType.equals("SAPIQ")) {
				sql = "";
				sql += "SELECT  TRIM(A.TABLE_NAME) TBL_NM, CASE WHEN LENGTH(TRIM(A.REMARKS)) >= 100 THEN ' ' ELSE COALESCE(TRIM(A.REMARKS),' ') END TBL_CAPTION  ";
				sql += "FROM	SYSTABLE A  ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "WHERE   UPPER(TRIM(A.TABLE_NAME)) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "WHERE   UPPER(TRIM(A.TABLE_NAME)) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += "ORDER BY 1  ";
				//                '' psc_2018.12.18 Sybase ASE v16
				//                'sql = ""
				//                'sql += " SELECT name TBL_NM, ' ' AS TBL_CAPTION "
				//                'sql += " FROM sysobjects"
				//                'sql += " WHERE type IN ('U', 'V') "
				//                'sql += " AND name NOT IN ('sysquerymetrics') "
				//                'sql += " ORDER BY 1 "
			}
			else if(aDbmsType.equals("CUBRID")) {
				//9.x _cub_schema_comments 있는 경우
				/*
				sql = "";
				sql += "SELECT A.class_name AS TBL_NM, NVL(B.description,'') AS TBL_CAPTION ";
				sql += "FROM db_class A ";
				sql += "LEFT JOIN _cub_schema_comments B ON A.class_name = B.table_name AND B.column_name = '*' ";
				sql += "WHERE 1=1 ";
				sql += "AND A.is_system_class = 'NO' ";
				//                'sql += "AND A.class_type = 'CLASS'"
				sql += "AND A.class_name <> '_cub_schema_comments' ";
				if (aFilterStr != null) {
					sql += "AND     UPPER(A.class_name) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += "ORDER BY 1  ";
				*/
				//10.x
				sql = "";
				sql += "SELECT A.class_name AS TBL_NM, NVL(A.comment,'') AS TBL_CAPTION ";
				sql += "FROM db_class A ";
				sql += "WHERE 1=1 ";
				sql += "AND A.is_system_class = 'NO' ";
				//                'sql += "AND A.class_type = 'CLASS'"
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND     UPPER(A.class_name) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND     UPPER(A.class_name) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += "ORDER BY 1  ";
			}
			else if(aDbmsType.equals("ALTIBASE")) {
				sql = "";
				sql += "SELECT B.TABLE_NAME AS TBL_NM, C.COMMENTS AS TBL_CAPTION ";
				sql += "FROM SYSTEM_.SYS_USERS_ A ";
				sql += "INNER JOIN SYSTEM_.SYS_TABLES_ B   ";
				sql += "ON A.USER_ID = B.USER_ID AND A.USER_NAME = UPPER('" + aOwnerNm + "') ";
				sql += "LEFT OUTER JOIN SYSTEM_.SYS_COMMENTS_ C ";
				sql += "ON B.TABLE_NAME = C.TABLE_NAME AND C.COLUMN_NAME IS NULL ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "WHERE   UPPER(B.TABLE_NAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "WHERE   UPPER(B.TABLE_NAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
				sql += "ORDER BY B.TABLE_NAME  ";
			}
			else if(aDbmsType.equals("TERADATA")) {
				sql = "";
				sql += "SELECT TABLENAME AS TBL_NM, ";
				sql += "COMMENTSTRING AS TBL_CAPTION ";
				sql += "FROM dbc.TABLESV ";
				sql += "WHERE 1=1 ";
				sql += "AND DATABASENAME = '" + aDbNm + "' ";
				/*dogfoot ERD 전체 테이블 불러오기 -> 필요한 테이블만 불러오기로 수정 shlim 20210402*/
				if (aFilterStr != null && !aFilterStr.isEmpty() && aFilterStr.split(",").length > 1) {
					sql += "AND UPPER(TABLENAME) IN (" + aFilterStr.toUpperCase() + ") ";
				}else if (aFilterStr != null){
					sql += "AND UPPER(TABLENAME) LIKE '%" + aFilterStr.toUpperCase() + "%' ";
				}
			}
			else if(aDbmsType.equals("IMPALA")) {
				sql = "";
				if(aFilterStr!=null) {
					sql += "SHOW TABLES LIKE '*" + aFilterStr.toLowerCase() + "*'";
				} else {
					sql += "SHOW TABLES LIKE '*'";
				}
			}
		}
		else if(aObjType.equals("COLUMN")) {
			if(aDbmsType.equals("MS-SQL")) {
				sql = "";
				sql += "SELECT CAST(A.[name] AS NVARCHAR(200)) AS 'TBL_NM', ";
				sql += "       CAST(B.[name] AS NVARCHAR(200))  AS 'COL_NM', ";
				sql += "       CAST(C.[name] AS NVARCHAR(200))  AS 'DATA_TYPE', ";
				sql += "       CAST(B.[length] AS NVARCHAR(200))  AS 'LENGTH', ";
				sql += "       CAST(B.[colid] AS NVARCHAR(200))  AS 'COL_ID', ";
				sql += "       CAST(E.[indid] AS NVARCHAR(200))  AS 'PK_YN', ";
				sql += "       CAST(F.value AS NVARCHAR(200))  AS 'COL_CAPTION', ";
				sql += "       CAST(G.value AS NVARCHAR(200)) AS 'TBL_CAPTION' ";
				sql += " FROM  SYSOBJECTS A INNER JOIN SYSCOLUMNS B ON A.id = B.id INNER JOIN SYSTYPES C ON B.xusertype = C.xusertype ";
				sql += "       LEFT JOIN SYSINDEXKEYS E ON E.id = A.id AND B.colid = E.colid  ";
				sql	+= "       LEFT JOIN SYS.extended_properties F ON B.ID = F.major_id AND B.colid = F.minor_id ";
				sql	+= "       LEFT JOIN SYS.extended_properties G ON A.ID = G.major_id AND G.minor_id = 0 ";
				sql += " WHERE 1 = 1 ";
				sql += " AND   A.xtype IN ('U', 'V') ";

				if(!aTblNmByCol.equalsIgnoreCase("")) {
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(A.name) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(A.name) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY B.colorder ";
			}

			//                else if(aDbmsType.equals("ORACLE")) {
			//                    sql = "";
			//                    sql += "SELECT DISTINCT * FROM ";
			//                    sql += " ( ";
			//
			//                    sql += "select  a.table_name as TBL_NM, a.column_name AS COL_NM ";
			//                    sql += "     	,data_type as DATA_TYPE ";
			//                    sql += "     	,CAST(data_length as VARCHAR(50)) as LENGTH ";
			//                    sql += "     	,CAST(a.column_id AS VARCHAR(50)) as COL_ID ";
			//                    sql += "     	,CAST(c.position AS VARCHAR(50)) as PK_YN ";
			//                    sql += "     	,b.comments as COL_CAPTION ";
			//                    sql += " from 	all_tab_columns a ";
			//                    sql += "      	,all_col_comments b  ";
			//                    sql += "   		, ";
			//                    sql += "   		( ";
			//                    sql += "   		select 	a.table_name  ";
			//                    sql += "           		,a.column_name ";
			//                    sql += "           		,a.position ";
			//                    sql += "      	from 	all_cons_columns a, all_constraints b ";
			//                    sql += "      	where  	a.table_name = b.table_name ";
			//                    sql += "        and  	b.constraint_type = 'P' ";
			//                    sql += "        and  	a.constraint_name = b.constraint_name ";
			//                    sql += "       	) c ";
			//
			//                    if(aTblNmByCol != "") {
			//                        sql += " where 	a.table_name  = upper('" + aTblNmByCol + "') ";
			//                    } else {
			//                        sql += " where 	1 = 1 ";
			//                    }
			//
			//                    sql += "   and 	a.table_name  = b.table_name(+) ";
			//                    sql += "   and 	a.column_name = b.column_name(+) ";
			//                    sql += "   and 	a.table_name  = c.table_name(+) ";
			//                    sql += "   and 	a.column_name = c.column_name(+) ";
			//                    sql += " order 	by PK_YN, column_id ";
			//
			//                    sql += " ) ";
			////                synonyms 추가(기정원) : JKJ_20180320
			else if(aDbmsType.equals("ORACLE")) {
				sql = "SELECT DISTINCT * FROM\r\n" + 
						"                (\r\n" + 
						"\r\n" + 
						"select  a.table_name as TBL_NM, a.column_name AS COL_NM\r\n" + 
						"       ,data_type as DATA_TYPE\r\n" + 
						"       ,CAST(data_length as VARCHAR(50)) as LENGTH\r\n" + 
						"       ,CAST(a.column_id AS VARCHAR(50)) as COL_ID\r\n" + 
						"       ,CAST(c.position AS VARCHAR(50)) as PK_YN\r\n" + 
						"       ,b.comments as COL_CAPTION\r\n" + 
						"       ,d.comments as TBL_CAPTION\r\n" + 
						"from    all_tab_columns a\r\n" + 
						"        ,all_col_comments b \r\n" + 
						"        ,all_tab_comments d \r\n" + 
						"        ,\r\n" + 
						"        (\r\n" + 
						"        select    a.table_name \r\n" + 
						"                ,a.column_name\r\n" + 
						"                ,a.position\r\n" + 
						"        from    all_cons_columns a, all_constraints b\r\n" + 
						"        where     a.table_name = b.table_name\r\n" + 
						"       and     b.constraint_type = 'P'\r\n" + 
						"       and     a.constraint_name = b.constraint_name\r\n" + 
						"         ) c\r\n" + 
						"where    1 = 1\r\n";
				
				if(!aTblNmByCol.equalsIgnoreCase("")) {
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "and UPPER(a.table_name) IN " + aTblNmByCol.toUpperCase() + " ";
						sql += "and UPPER(b.table_name) IN " + aTblNmByCol.toUpperCase() + " ";
						sql += "and UPPER(d.table_name) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "and UPPER(a.table_name) = '" + aTblNmByCol.toUpperCase() + "' ";
						sql += "and UPPER(b.table_name) = '" + aTblNmByCol.toUpperCase() + "' ";
						sql += "and UPPER(d.table_name) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}				
						
				sql +=	"and   a.owner = UPPER('" + aOwnerNm + "')\r\n" +
						"and   b.owner = UPPER('" + aOwnerNm + "')\r\n" +
						"and   d.owner = UPPER('" + aOwnerNm + "')\r\n" +
						"and    a.table_name  = b.table_name(+)\r\n" + 
						"and    a.column_name = b.column_name(+)\r\n" + 
						"and    a.table_name  = c.table_name(+)\r\n" + 
						"and    a.column_name = c.column_name(+)\r\n" + 
						"and    a.table_name  = d.table_name(+)\r\n" + 
						"order    by PK_YN, column_id\r\n" + 
						")";
			}
			else if(aDbmsType.equals("TIBERO") || aDbmsType.equals("TBIN")) {
				sql = "";
				sql += "SELECT A.TABLE_NAME AS TBL_NM ";
				sql += "     	,A.COLUMN_NAME AS COL_NM ";
				sql += "     	,DATA_TYPE AS DATA_TYPE ";
				sql += "     	,CAST(DATA_LENGTH AS VARCHAR(50)) AS LENGTH ";
				sql += "     	,CAST(A.COLUMN_ID AS VARCHAR(50)) AS COL_ID ";
				sql += "     	,CAST(PK.POSITION AS VARCHAR(50)) AS PK_YN ";
				sql += " 		,B.COMMENTS AS COL_CAPTION ";
				sql += " 		,C.COMMENTS AS TBL_CAPTION ";
				sql += "FROM ALL_TAB_COLUMNS A  ";
				sql += "INNER JOIN ALL_COL_COMMENTS B ";
				sql += "ON  A.OWNER = B.OWNER ";
				sql += "AND A.TABLE_NAME  = B.TABLE_NAME ";
				sql += "AND A.COLUMN_NAME = B.COLUMN_NAME ";
				sql += "INNER JOIN ALL_TAB_COMMENTS C ";
				sql += "ON  A.OWNER = C.OWNER ";
				sql += "AND A.TABLE_NAME  = C.TABLE_NAME ";
				sql += "LEFT JOIN ";
				sql += "( ";
				sql += "	SELECT DISTINCT A.TABLE_NAME  ";
				sql += "        ,A.COLUMN_NAME ";
				sql += "        ,A.POSITION ";
				sql += "    FROM ALL_CONS_COLUMNS A ";
				sql += "    INNER JOIN ALL_CONSTRAINTS B ";
				sql += "    ON A.TABLE_NAME = B.TABLE_NAME ";
				sql += "    AND A.CONSTRAINT_NAME = B.CONSTRAINT_NAME ";
				sql += "    AND A.OWNER = B.OWNER ";
				sql += "    AND B.CONSTRAINT_TYPE = 'P' ";
				sql += ") PK ";
				sql += "ON  A.TABLE_NAME  = PK.TABLE_NAME ";
				sql += "AND A.COLUMN_NAME = PK.COLUMN_NAME ";
				sql += "WHERE 1=1 ";

				if(!aTblNmByCol.equals("")) {
					if (aTblNmByCol.charAt(0) == '(') {
						sql += " AND UPPER(A.TABLE_NAME) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += " AND UPPER(A.TABLE_NAME) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += "AND A.OWNER = UPPER('" + aOwnerNm + "') ";
				sql += "ORDER BY A.TABLE_NAME, PK_YN, A.COLUMN_ID ";
			}
			else if(aDbmsType.equals("VERTICA")) {
				sql = "";
				sql += "SELECT  A.TABLE_NAME AS TBL_NM ";
				sql += "        ,B.COLUMN_NAME AS COL_NM ";
				sql += "        ,CASE WHEN INSTR(B.DATA_TYPE, '(') > 0 THEN SUBSTR(B.DATA_TYPE, 1, INSTR(B.DATA_TYPE, '(')-1) ELSE B.DATA_TYPE END AS DATA_TYPE ";
				sql += "        ,CAST(B.DATA_TYPE_LENGTH AS VARCHAR(50)) AS LENGTH ";
				sql += "        ,CAST(B.ORDINAL_POSITION AS VARCHAR(20)) AS COL_ID ";
				sql += "        ,CAST(C.ORDINAL_POSITION AS VARCHAR(20)) AS PK_YN ";
				sql += "        ,D.COMMENT AS COL_CAPTION ";
				sql += "        ,'' AS TBL_CAPTION ";
				sql += " FROM  TABLES A ";
				sql += "        INNER JOIN COLUMNS B ON A.TABLE_SCHEMA = B.TABLE_SCHEMA AND A.TABLE_NAME = B.TABLE_NAME ";
				sql += "        LEFT OUTER JOIN PRIMARY_KEYS C ON A.TABLE_SCHEMA = C.TABLE_SCHEMA AND A.TABLE_NAME = C.TABLE_NAME AND B.COLUMN_NAME = C.COLUMN_NAME AND C.CONSTRAINT_TYPE = 'p' ";
				sql += "        LEFT OUTER JOIN ";
				sql += "        ( ";
				sql += "        SELECT B.TABLE_SCHEMA, B.TABLE_NAME, B.TABLE_COLUMN_NAME, MIN(C.COMMENT) AS COMMENT ";
				sql += "        FROM PROJECTION_COLUMNS B  ";
				sql += "                INNER JOIN COMMENTS C ON B.COLUMN_ID = C.OBJECT_ID AND C.OBJECT_TYPE = 'COLUMN' ";
				sql += "        WHERE C.COMMENT <> '' ";
				sql += "        GROUP BY B.TABLE_SCHEMA, B.TABLE_NAME, B.TABLE_COLUMN_NAME ";
				sql += "        ) D ON B.TABLE_SCHEMA = D.TABLE_SCHEMA AND B.TABLE_NAME = D.TABLE_NAME AND B.COLUMN_NAME = D.TABLE_COLUMN_NAME ";

				if(!aTblNmByCol.equals("")) {
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "WHERE UPPER(A.TABLE_NAME) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "WHERE UPPER(A.TABLE_NAME) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				} else {
					sql += " WHERE 	1 = 1 ";
				}

				sql += " ORDER BY B.ORDINAL_POSITION ";
			}
			else if(aDbmsType.equals("MSPDW")) {
				sql = "";
				sql += "SELECT CAST(A.[name] AS NVARCHAR(100))  AS 'TBL_NM', ";
				sql += "       CAST(B.[name] AS NVARCHAR(50))   AS 'COL_NM', ";
				sql += "       CAST(C.[name] AS NVARCHAR(50))   AS 'DATA_TYPE', ";
				sql += "       CAST(B.[length] AS NVARCHAR(10))   AS 'LENGTH', ";
				sql += "       CAST(B.[colid] AS NVARCHAR(10))   AS 'COL_ID', ";
				sql += "       ''N''   AS 'PK_YN', ";
				sql += "      CAST(B.[name] AS NVARCHAR(50))   AS 'COL_CAPTION', ";
				sql += "      CAST('' AS NVARCHAR(50))   AS 'TBL_CAPTION' ";
				sql += " FROM  SYSOBJECTS A INNER JOIN SYSCOLUMNS B ON A.id = B.id INNER JOIN SYSTYPES C ON B.xusertype = C.xusertype ";

				if(aTblNmByCol != "") {
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "WHERE UPPER(A.name) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "WHERE UPPER(A.name) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY B.colorder ";
			}
			else if(aDbmsType.equals("MYSQL") || aDbmsType.equals("MYIDB") || aDbmsType.equals("MARIA")) {
				sql = "";
				sql += "SELECT A.TABLE_NAME AS 'TBL_NM' ";
				sql += "     , B.COLUMN_NAME AS 'COL_NM' ";
				sql += "     , B.DATA_TYPE AS 'DATA_TYPE' ";
				sql += "     , case DATA_TYPE when 'int' then CAST(NUMERIC_PRECISION AS char(50)) ";
				sql += "                      when 'float' then CAST(NUMERIC_PRECISION AS char(50)) ";
				sql += "                      else  CAST(CHARACTER_MAXIMUM_LENGTH AS char(50)) ";
				sql += "       end AS 'LENGTH' ";
				sql += "     , CAST(B.ORDINAL_POSITION AS char(50)) AS 'COL_ID' ";
				sql += "     , case B.COLUMN_KEY when 'PRI' then CAST(1 AS char(10))  ";
				sql += "                         when 'MUL' then CAST(2 AS char(10))  ";
				sql += "       end AS 'PK_YN' ";
				sql += "     , B.COLUMN_COMMENT AS 'COL_CAPTION' ";
				sql += "     , A.TABLE_COMMENT AS 'TBL_CAPTION' ";
				sql += " FROM INFORMATION_SCHEMA.TABLES A  ";
				sql += " INNER JOIN INFORMATION_SCHEMA.COLUMNS B ";
				sql += "         ON A.TABLE_NAME = B.TABLE_NAME ";

				if(aTblNmByCol != "") {
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "WHERE UPPER(A.TABLE_NAME) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "WHERE UPPER(A.TABLE_NAME) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY B.ORDINAL_POSITION ";
			}
			else if(aDbmsType.equals("DB2BLU")) {
				sql = "";
				sql += "SELECT A.TABNAME TBL_NM ";
				sql += " , B.COLNAME COL_NM ";
				sql += " , B.TYPENAME DATA_TYPE ";
				sql += " , B.LENGTH LENGTH ";
				sql += " , B.COLNO COL_ID ";
				sql += " , CASE WHEN B.KEYSEQ > 0 THEN 1 ELSE 0 END PK_YN ";
				sql += " , NVL(B.REMARKS, B.COLNAME) COL_CAPTION ";
				sql += " , NVL(A.REMARKS, A.TABNAME) TBL_CAPTION ";
				sql += " FROM SYSCAT.TABLES A  ";
				//                sql += "  INNER JOIN SYSCAT.COLUMNS B ON  A.TABNAME = B.TABNAME  ";
				//                _20160510_cjs 시스템쿼리 수정 (데이터 디자이너에서 차원속성값 2개씩 나오는현상)
				sql += "  INNER JOIN SYSCAT.COLUMNS B ON A.TABSCHEMA = B.TABSCHEMA AND A.TABNAME = B.TABNAME  ";
				sql += " WHERE A.TYPE IN ('T', 'V')  ";
				sql += " AND A.OWNERTYPE = 'U'  ";

				if(aTblNmByCol != ""){
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(A.TABNAME) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(A.TABNAME) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY B.COLNO ";
			}
			else if(aDbmsType.equals("POSTGRES")) {

				sql = "";
				sql += " SELECT A.table_name AS TBL_NM ";
				sql += "    , A.column_name AS COL_NM ";
				sql += "    , A.data_type AS DATA_TYPE ";
				sql += "    , CASE WHEN A.character_maximum_length IS NULL THEN numeric_precision ELSE character_maximum_length END AS LENGTH ";
				sql += "    , A.ordinal_position AS COL_ID ";
				sql += "    , CASE WHEN D.column_name IS NOT NULL THEN CAST('1' AS VARCHAR) ELSE NULL END AS PK_YN ";
				sql += "    , pg_catalog.col_description(C.attrelid, C.attnum) AS COL_CAPTION ";
				sql += "    , '' AS TBL_CAPTION ";
				sql += " FROM information_schema.columns A ";
				sql += " INNER JOIN pg_catalog.pg_class B ON A.table_name = B.relname ";
				sql += " INNER JOIN pg_catalog.pg_attribute C ON B.oid = C.attrelid AND A.column_name = C.attname ";
				sql += " LEFT JOIN (SELECT D.table_schema, D.table_name, D.column_name ";
				sql += "                FROM information_schema.key_column_usage D  ";
				sql += "            INNER JOIN information_schema.table_constraints E ON D.table_schema = E.table_schema AND D.table_name = E.table_name AND E.constraint_type = 'PRIMARY KEY' ";
				sql += " ) D ON A.table_schema = D.table_schema AND A.table_name = D.table_name AND A.column_name = D.column_name ";

				sql += " WHERE attnum > 0  ";
				sql += " AND NOT attisdropped ";

				if(aTblNmByCol != ""){
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(A.table_name) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(A.table_name) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY A.ordinal_position ";
			}
			else if(aDbmsType.equals("NETEZZA")) {

				sql = "";
				sql += " SELECT A.NAME AS TBL_NM ";
				sql += "       ,A.ATTNAME AS COL_NM ";
				sql += "       ,B.DATATYPE AS DATA_TYPE ";
				sql += "       ,A.ATTCOLLENG AS LENGTH ";
				sql += "       ,A.ATTNUM AS COL_ID ";
				sql += "       ,CASE WHEN C.CONTYPE = 'p' THEN '1' ELSE C.CONTYPE END AS PK_YN ";
				sql += "       ,A.DESCRIPTION AS COL_CAPTION ";
				sql += "       ,'' AS TBL_CAPTION ";
				sql += " FROM _v_relation_column A ";
				sql += " INNER JOIN _V_DATATYPE B ON A.ATTTYPID = B.OBJID  ";
				sql += " LEFT OUTER JOIN _V_RELATION_KEYDATA C ON A.NAME = C.RELATION AND A.ATTNAME = C. ATTNAME AND C.CONTYPE = 'p' ";
				sql += " WHERE A.OWNER = '" + aOwnerNm + "' ";

				if(aTblNmByCol != ""){
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(A.NAME) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(A.NAME) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY COL_ID ";
			}
			else if(aDbmsType.equals("SAPIQ")) {
				sql = "";
				sql += "SELECT TRIM(A.TABLE_NAME) AS 'TBL_NM', ";
				sql += "       TRIM(B.COLUMN_NAME) AS 'COL_NM', ";
				sql += "       TRIM(C.DOMAIN_NAME) AS 'DATA_TYPE', ";
				sql += "       B.WIDTH AS 'LENGTH', ";
				sql += "       B.COLUMN_ID AS 'COL_ID', ";
				sql += "       CASE B.PKEY WHEN 'Y' THEN 1 WHEN 'N' THEN 2 END AS 'PK_YN', ";
				sql += "       CASE WHEN LENGTH(TRIM(A.REMARKS)) >= 100 THEN ' ' ELSE COALESCE(TRIM(A.REMARKS), ' ') END AS 'COL_CAPTION', ";
				sql += "       '' AS 'TBLL_CAPTION' ";
				sql += " FROM  SYSTABLE A ";
				sql += "       INNER JOIN SYSCOLUMN B ON A.table_id = B.table_id  ";
				sql += "       INNER JOIN SYSDOMAIN C ON B.domain_id = C.domain_id  ";
				sql += " WHERE 1 = 1 ";

				if(aTblNmByCol != ""){
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(A.TABLE_NAME) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(A.TABLE_NAME) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY B.PKEY DESC, B.COLUMN_ID ";

				//                 psc_2018.12.18 Sybase ASE v16
				//                sql = ""
				//                sql += " SELECT A.name AS TBL_NM, B.name AS COL_NM, C.name AS DATA_TYPE, "
				//                sql += " B.length AS LENGTH, B.colid AS COL_ID, "
				//                sql += " CASE WHEN ( "
				//                sql += " B.colid = D.key1 "
				//                sql += " OR B.colid = D.key2 "
				//                sql += " OR B.colid = D.key3 "
				//                sql += " OR B.colid = D.key4 "
				//                sql += " OR B.colid = D.key5 "
				//                sql += " OR B.colid = D.key6 "
				//                sql += " OR B.colid = D.key7 "
				//                sql += " OR B.colid = D.key8 "
				//                sql += " ) THEN 'Y' ELSE 'N' "
				//                sql += " END AS PK_YN, ' ' AS COL_CAPTION "
				//                sql += " FROM sysobjects A, syscolumns B, systypes C, syskeys D "
				//                sql += " WHERE 1=1 "
				//                sql += " AND A.id = B.id "
				//                sql += " AND B.usertype = C.usertype "
				//                sql += " AND A.type = 'U' "
				//                sql += " AND A.id = D.id "
				//                sql += " AND D.type in (1,2) "
				//                sql += " ORDER BY A.name, B.colid "
				//                
				//                if(aTblNmByCol != ""){
				//                    sql += " AND A.name = '" + aTblNmByCol + "'"
				//                }
				//                
				//                sql += " ORDER BY A.name, B.colid "
			}
			else if(aDbmsType.equals("CUBRID")) {
				// 9.x _cub_schema_comments 있는 경우
				/*
				sql = "";
				sql += " Select  ";
				sql += "    a.class_name AS TBL_NM,  ";
				sql += "    b.attr_name As COL_NM,  ";
				sql += "    b.data_type AS DATA_TYPE,  ";
				sql += "    b.prec As LENGTH,  ";
				sql += "    b.def_order AS COL_ID,  ";
				sql += "    d.index_name,  ";
				sql += "    CASE WHEN d.index_name Is Not NULL THEN '1' ELSE '0' END AS PK_YN,  ";
				sql += "    c.description AS COL_CAPTION,  ";
				sql += "    '' AS TBL_CAPTION  ";
				sql += " From db_class a  ";
				sql += "    INNER Join db_attribute b  ";
				sql += "        On a.class_name = b.class_name  ";
				sql += "    Left Join _cub_schema_comments c  ";
				sql += "        On b.class_name = c.table_name And  b.attr_name = c.column_name  ";
				sql += "    Left Join(  ";
				sql += "            SELECT   ";
				sql += "                  a.index_name,  ";
				sql += "                  a.key_count,  ";
				sql += "                  b.class_name,  ";
				sql += "                  b.key_attr_name,  ";
				sql += "                  b.key_order  ";
				sql += "            From db_index a  ";
				sql += "            INNER Join db_index_key b  ";
				sql += "            On a.index_name = b.index_name  ";
				sql += "            WHERE a.is_primary_key = 'YES'  ";
				sql += "    ) d  ";
				sql += "        On a.class_name = d.class_name And b.attr_name = d.key_attr_name  ";
				sql += "WHERE 1 = 1  ";
				//                sql += "    And a.class_type = 'CLASS'"

				if(aTblNmByCol != ""){
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(a.class_name) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(a.class_name) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY B.def_order  ";
				*/
				//10.x
				sql = "";
				sql += " Select  ";
				sql += "    a.class_name AS TBL_NM,  ";
				sql += "    b.attr_name As COL_NM,  ";
				sql += "    b.data_type AS DATA_TYPE,  ";
				sql += "    b.prec As LENGTH,  ";
				sql += "    b.def_order AS COL_ID,  ";
				sql += "    d.index_name,  ";
				sql += "    CASE WHEN d.index_name Is Not NULL THEN '1' ELSE '0' END AS PK_YN,  ";
				sql += "    b.comment AS COL_CAPTION,  ";
				sql += "    a.comment AS TBL_CAPTION  ";
				sql += " From db_class a  ";
				sql += "    INNER Join db_attribute b  ";
				sql += "        On a.class_name = b.class_name  ";
				sql += "    Left Join(  ";
				sql += "            SELECT   ";
				sql += "                  a.index_name,  ";
				sql += "                  a.key_count,  ";
				sql += "                  b.class_name,  ";
				sql += "                  b.key_attr_name,  ";
				sql += "                  b.key_order  ";
				sql += "            From db_index a  ";
				sql += "            INNER Join db_index_key b  ";
				sql += "            On a.index_name = b.index_name  ";
				sql += "            WHERE a.is_primary_key = 'YES'  ";
				sql += "    ) d  ";
				sql += "        On a.class_name = d.class_name And b.attr_name = d.key_attr_name  ";
				sql += "WHERE 1 = 1  ";
				//                sql += "    And a.class_type = 'CLASS'"

				if(aTblNmByCol != ""){
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(a.class_name) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(a.class_name) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += " ORDER BY B.def_order  ";
			}
			else if(aDbmsType.equals("ALTIBASE")) {
				sql = "";
				sql += "SELECT B.TABLE_NAME AS TBL_NM, ";
				sql += "    C.COLUMN_NAME AS COL_NM, ";
				sql += "    CASE C.DATA_TYPE ";
				sql += "        WHEN '1' THEN 'CHAR' ";
				sql += "        WHEN '12' THEN 'VARCHAR' ";
				sql += "        WHEN '-8' THEN 'NCHAR' ";
				sql += "        WHEN '-9' THEN 'NVARCHAR' ";
				sql += "        WHEN '2' THEN 'NUMERIC' ";
				//                sql += "       --WHEN '2' THEN 'DECIMAL'"
				//                sql += "       --WHEN '6' THEN 'FLOAT'"
				sql += "        WHEN '6' THEN 'NUMBER' ";
				sql += "        WHEN '8' THEN 'DOUBLE' ";
				sql += "        WHEN '7' THEN 'REAL' ";
				sql += "        WHEN '-5' THEN 'BIGINT' ";
				sql += "        WHEN '4' THEN 'INTEGER' ";
				sql += "        WHEN '5' THEN 'SMALLINT' ";
				sql += "        WHEN '9' THEN 'DATE' ";
				sql += "        WHEN '30' THEN 'BLOB' ";
				sql += "        WHEN '40' THEN 'CLOB' ";
				sql += "        WHEN '20001' THEN 'BYTE' ";
				sql += "        WHEN '20002' THEN 'NIBBLE' ";
				sql += "        WHEN '-7' THEN 'BIT' ";
				sql += "        WHEN '-100' THEN 'VARBIT' ";
				sql += "        WHEN '10003' THEN 'GEOMETRY' ";
				sql += "    END  AS DATA_TYPE, ";
				sql += "    C.PRECISION AS LENGTH, ";
				sql += "    C.COLUMN_ORDER + 1 AS COL_ID, ";
				sql += "    D.COMMENTS AS COL_CAPTION, ";
				sql += "    '' AS TBL_CAPTION, ";
				sql += "    DECODE(F.CONSTRAINT_TYPE, 3,'Y') AS PK_YN ";
				sql += "FROM SYSTEM_.SYS_USERS_ A ";
				sql += "    INNER JOIN SYSTEM_.SYS_TABLES_ B ";
				sql += "        ON A.USER_ID = B.USER_ID AND A.USER_NAME = UPPER('" + aOwnerNm + "') ";
				sql += "    INNER JOIN SYSTEM_.SYS_COLUMNS_ C ";
				sql += "        ON B.USER_ID = C.USER_ID AND B.TABLE_ID = C.TABLE_ID AND B.TABLE_TYPE = 'T' ";
				sql += "    LEFT OUTER JOIN SYSTEM_.SYS_COMMENTS_ D ";
				sql += "        ON B.TABLE_NAME = D.TABLE_NAME AND C.COLUMN_NAME = D.COLUMN_NAME ";
				sql += "    LEFT OUTER JOIN SYSTEM_.SYS_CONSTRAINT_COLUMNS_ E ";
				sql += "        ON C.COLUMN_ID = E.COLUMN_ID ";
				sql += "    LEFT OUTER JOIN SYSTEM_.SYS_CONSTRAINTS_ F ";
				sql += "        ON E.CONSTRAINT_ID = F.CONSTRAINT_ID And F.CONSTRAINT_TYPE = '3' ";

				sql += "WHERE 1=1 ";

				if(aTblNmByCol != ""){
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(B.TABLE_NAME) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(B.TABLE_NAME) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += "ORDER BY B.TABLE_NAME, C.COLUMN_ORDER ";
			}
			else if(aDbmsType.equals("TERADATA")) {
				sql = "";
				sql += "SELECT A.DatabaseName, ";
				sql += "A.TABLENAME AS TBL_NM, ";
				sql += "A.COLUMNNAME AS COL_NM, ";
				sql += "CASE WHEN A.COLUMNTYPE IN ('A1','AN') THEN 'ARRAY' ";
				sql += "WHEN A.COLUMNTYPE ='I8' THEN 'BIGINT' ";
				sql += "WHEN A.COLUMNTYPE ='BO' THEN 'BINARY' ";
				sql += "WHEN A.COLUMNTYPE ='BF' THEN 'BYTE' ";
				sql += "WHEN A.COLUMNTYPE='BV' THEN 'BYTE' ";
				sql += "WHEN A.COLUMNTYPE='I1' THEN 'BYTEINT' ";
				sql += "WHEN A.COLUMNTYPE IN ('CF','CV','CO') THEN 'CHARACTER' ";
				sql += "WHEN A.COLUMNTYPE = 'D' THEN 'DECIMAL' ";
				sql += "WHEN A.COLUMNTYPE = 'DA' THEN 'DATE' ";
				sql += "WHEN A.COLUMNTYPE = 'F' THEN 'FLOAT' ";
				sql += "WHEN A.COLUMNTYPE = 'I'  THEN 'INTEGER' ";
				sql += "WHEN A.COLUMNTYPE ='N'  THEN 'NUMBER' ";
				sql += "WHEN A.COLUMNTYPE ='D'  THEN 'NUMERIC' ";
				sql += "WHEN A.COLUMNTYPE = 'I2' THEN 'SMALLINT' ";
				sql += "WHEN A.COLUMNTYPE = 'AT' THEN 'TIME' ";
				sql += "WHEN A.COLUMNTYPE = 'TS' THEN 'TIMESTAMP' ";
				sql += "WHEN A.COLUMNTYPE = 'XM' THEN 'XML' ELSE A.COLUMNTYPE END AS DATA_TYPE, ";
				sql += "A.COLUMNLENGTH As LENGTH, ";
				sql += "A.COLUMNID As COL_ID, ";
				sql += "A.COMMENTSTRING As COL_CAPTION, ";
				sql += "'' As TBL_CAPTION, ";
				sql += "Case When B.ColumnPosition = 1 Then 1 Else 0 End As PK_YN ";
				sql += "FROM DBC.ColumnsV As A  ";
				sql += "LEFT JOIN DBC.indicesV As B  ";
				sql += "On  A.DatabaseName = B.DatabaseName  ";
				sql += "And A.TableName = B.TableName ";
				sql += "And A.ColumnName = B.ColumnName ";
				sql += "And B.ColumnPosition = '1' ";

				sql += "WHERE 1=1 ";
				if(aDbNm != ""){
					sql += "AND A.DatabaseName = '" + aDbNm + "' ";
				}
						
				if(aTblNmByCol != ""){
					if (aTblNmByCol.charAt(0) == '(') {
						sql += "AND UPPER(B.TABLE_NAME) IN " + aTblNmByCol.toUpperCase() + " ";
					} else {
						sql += "AND UPPER(B.TABLE_NAME) = '" + aTblNmByCol.toUpperCase() + "' ";
					}
				}

				sql += "ORDER BY TBL_NM,PK_YN ";
			}
			else if(aDbmsType.equals("IMPALA")) {
				sql = "";
				sql += "DESCRIBE ";
				if(aDbNm != ""){
					sql += "" + aDbNm + ".";
				}
						
				if(aTblNmByCol != ""){
						sql += aTblNmByCol.toLowerCase();
				}
			}
		}
		else if(aObjType.equals("CONSTRAINT")) {
			if(aDbmsType.equals("MS-SQL")) {

				//                ' cjs_20170323 릴레이션 구하는거 변경 (복합키2개인경우 릴레이션이 4개로 나옴)
				sql = "";;
				sql += "SELECT CAST(FK.CONSTRAINT_NAME AS NVARCHAR(500)) AS CONST_NM, ";
				sql += "       CAST(FK.TABLE_NAME AS NVARCHAR(500))  AS FK_TBL_NM, ";
				sql += "       CAST(FK_COLS.COLUMN_NAME AS NVARCHAR(500))  AS FK_COL_NM, ";
				sql += "       CAST(PK.TABLE_NAME AS NVARCHAR(500))  AS PK_TBL_NM, ";
				sql += "       CAST(PK_COLS.COLUMN_NAME AS NVARCHAR(500))  AS PK_COL_NM, ";
				sql += "       'INNER JOIN' AS JOIN_TYPE, ";
				sql += "       'SYSTEM' AS JOIN_SET_OWNER ";
				sql += "FROM   INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS REF_CONST ";
				sql += "       INNER JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS FK ";
				sql += "       ON REF_CONST.CONSTRAINT_CATALOG = FK.CONSTRAINT_CATALOG ";
				sql += "       AND REF_CONST.CONSTRAINT_SCHEMA = FK.CONSTRAINT_SCHEMA ";
				sql += "       AND REF_CONST.CONSTRAINT_NAME = FK.CONSTRAINT_NAME ";
				sql += "       AND FK.CONSTRAINT_TYPE = 'FOREIGN KEY' ";
				sql += "       INNER JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS PK ON REF_CONST.UNIQUE_CONSTRAINT_CATALOG = PK.CONSTRAINT_CATALOG ";
				sql += "       AND REF_CONST.UNIQUE_CONSTRAINT_SCHEMA = PK.CONSTRAINT_SCHEMA ";
				sql += "       AND REF_CONST.UNIQUE_CONSTRAINT_NAME = PK.CONSTRAINT_NAME ";
				sql += "       AND PK.CONSTRAINT_TYPE = 'PRIMARY KEY' ";
				sql += "       INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE FK_COLS ON REF_CONST.CONSTRAINT_NAME = FK_COLS.CONSTRAINT_NAME ";
				sql += "       INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE PK_COLS ON PK.CONSTRAINT_NAME = PK_COLS.CONSTRAINT_NAME ";

				//                '' 우주 쿼리 
				//                sql = ""
				//                sql += "SELECT  CAST(B.CONSTRAINT_NAME As NVARCHAR(500)) As CONST_NM,"
				//                sql += "        CAST(B.TABLE_NAME As NVARCHAR(500))  As FK_TBL_NM,"
				//                sql += "        CAST(B.COLUMN_NAME As NVARCHAR(500))  As FK_COL_NM,"
				//                sql += "        CAST(C.TABLE_NAME As NVARCHAR(500))  As PK_TBL_NM,"
				//                sql += "        CAST(C.COLUMN_NAME As NVARCHAR(500))  As PK_COL_NM,"
				//                sql += "        'INNER JOIN' AS JOIN_TYPE,"
				//                sql += "        'SYSTEM' AS JOIN_SET_OWNER"
				//                sql += "From    INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS A -- 릴레이션 정보"
				//                sql += "        INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE B"
				//                sql += "            On A.CONSTRAINT_NAME = B.CONSTRAINT_NAME -- FK 키컬럼확인"
				//                sql += "        INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE C"
				//                sql += "            On A.UNIQUE_CONSTRAINT_NAME = C.CONSTRAINT_NAME  -- PK 키컬럼확인"
				//                sql += "            AND B.ORDINAL_POSITION = C.ORDINAL_POSITION"
			}
			else if(aDbmsType.equals("ORACLE")) {
				sql = "";
				sql += "Select     FK.CONSTRAINT_NAME As CONST_NM,  ";
				sql += "               FK.TABLE_NAME As FK_TBL_NM,  ";
				sql += "               FK.COLUMN_NAME As FK_COL_NM, ";
				sql += "               PK.TABLE_NAME As PK_TBL_NM,  ";
				sql += "               PK.COLUMN_NAME As PK_COL_NM, ";
				sql += "               'INNER JOIN' AS JOIN_TYPE, ";
				sql += "               'SYSTEM' AS JOIN_SET_OWNER ";
				sql += "FROM      USER_CONSTRAINTS REF_CONST JOIN USER_CONS_COLUMNS FK ";
				sql += "               ON REF_CONST.CONSTRAINT_NAME = FK.CONSTRAINT_NAME ";
				sql += "               JOIN USER_CONS_COLUMNS PK on REF_CONST.R_CONSTRAINT_NAME = PK.CONSTRAINT_NAME ";
				sql += "               AND FK.POSITION = PK.POSITION ";
				sql += "WHERE      1=1 ";
				sql += "AND        REF_CONST.CONSTRAINT_TYPE = 'R' ";
			}
			else if(aDbmsType.equals("TIBERO") || aDbmsType.equals("TBIN")) {
				sql = "";
				sql += "SELECT     FK.CONSTRAINT_NAME AS CONST_NM,  ";
				sql += "               FK.TABLE_NAME as FK_TBL_NM,  ";
				sql += "               FK.COLUMN_NAME AS FK_COL_NM, ";
				sql += "               PK.TABLE_NAME as PK_TBL_NM,  ";
				sql += "               PK.COLUMN_NAME AS PK_COL_NM, ";
				sql += "               'INNER JOIN' AS JOIN_TYPE, ";
				sql += "               'SYSTEM' AS JOIN_SET_OWNER ";
				sql += "FROM      USER_CONSTRAINTS REF_CONST JOIN USER_CONS_COLUMNS FK ";
				sql += "               ON REF_CONST.CONSTRAINT_NAME = FK.CONSTRAINT_NAME ";
				sql += "               JOIN USER_CONS_COLUMNS PK on REF_CONST.R_CONSTRAINT_NAME = PK.CONSTRAINT_NAME ";
				sql += "               AND FK.POSITION = PK.POSITION ";
				sql += "WHERE      1=1 ";
				sql += "AND        REF_CONST.CONSTRAINT_TYPE = 'R' ";
			}
			else if(aDbmsType.equals("VERTICA")) {
				sql = "";
				sql += "SELECT     FK.CONSTRAINT_NAME AS CONST_NM,  ";
				sql += "               FK.TABLE_NAME AS FK_TBL_NM,  ";
				sql += "               FK.COLUMN_NAME AS FK_COL_NM, ";
				sql += "               FK.REFERENCE_TABLE_NAME AS PK_TBL_NM,  ";
				sql += "               FK.REFERENCE_COLUMN_NAME AS PK_COL_NM, ";
				sql += "                'INNER JOIN' AS JOIN_TYPE, ";
				sql += "                'SYSTEM' AS JOIN_SET_OWNER ";
				sql += "FROM      FOREIGN_KEYS FK ";
			}
			else if(aDbmsType.equals("MSPDW")) {
				sql = "";
				sql += "SELECT CAST(FK.CONSTRAINT_NAME AS NVARCHAR(500)) AS CONST_NM, ";
				sql += "       CAST(FK.TABLE_NAME AS NVARCHAR(500))  AS FK_TBL_NM, ";
				sql += "       CAST(FK_COLS.COLUMN_NAME AS NVARCHAR(500))  AS FK_COL_NM, ";
				sql += "       CAST(PK.TABLE_NAME AS NVARCHAR(500))  AS PK_TBL_NM, ";
				sql += "       CAST(PK_COLS.COLUMN_NAME AS NVARCHAR(500))  AS PK_COL_NM, ";
				sql += "       'INNER JOIN' AS JOIN_TYPE, ";
				sql += "       'SYSTEM' AS JOIN_SET_OWNER ";
				sql += "FROM   INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS REF_CONST ";
				sql += "       INNER JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS FK ";
				sql += "       ON REF_CONST.CONSTRAINT_CATALOG = FK.CONSTRAINT_CATALOG ";
				sql += "       AND REF_CONST.CONSTRAINT_SCHEMA = FK.CONSTRAINT_SCHEMA ";
				sql += "       AND REF_CONST.CONSTRAINT_NAME = FK.CONSTRAINT_NAME ";
				sql += "       AND FK.CONSTRAINT_TYPE = 'FOREIGN KEY' ";
				sql += "       INNER JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS PK ON REF_CONST.UNIQUE_CONSTRAINT_CATALOG = PK.CONSTRAINT_CATALOG ";
				sql += "       AND REF_CONST.UNIQUE_CONSTRAINT_SCHEMA = PK.CONSTRAINT_SCHEMA ";
				sql += "       AND REF_CONST.UNIQUE_CONSTRAINT_NAME = PK.CONSTRAINT_NAME ";
				sql += "       AND PK.CONSTRAINT_TYPE = 'PRIMARY KEY' ";
				sql += "       INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE FK_COLS ON REF_CONST.CONSTRAINT_NAME = FK_COLS.CONSTRAINT_NAME ";
				sql += "       INNER JOIN INFORMATION_SCHEMA.KEY_COLUMN_USAGE PK_COLS ON PK.CONSTRAINT_NAME = PK_COLS.CONSTRAINT_NAME ";
			}
			else if(aDbmsType.equals("MYSQL") || aDbmsType.equals("MYIDB") || aDbmsType.equals("MARIA")) {
				sql = "";
				sql += "SELECT  CONSTRAINT_NAME AS CONST_NM,  ";
				sql += "        TABLE_NAME as FK_TBL_NM,  ";
				sql += "        COLUMN_NAME AS FK_COL_NM, ";
				sql += "        REFERENCED_TABLE_NAME as PK_TBL_NM,  ";
				sql += "        REFERENCED_COLUMN_NAME AS PK_COL_NM, ";
				sql += "        'INNER JOIN' AS JOIN_TYPE, ";
				sql += "        'SYSTEM' AS JOIN_SET_OWNER  ";
				sql += "FROM    (INFORMATION_SCHEMA.KEY_COLUMN_USAGE) ";
				sql += "WHERE   constraint_name like 'FK_%' ";
			}
			else if(aDbmsType.equals("DB2BLU")) {
				sql = "";
				sql += "SELECT  A.CONSTNAME CONST_NM ";
				sql += "        , A.REFTABNAME FK_TBL_NM ";
				sql += "        , A.REFKEYNAME FK_COL_NM ";
				sql += "        , A.TABNAME PK_TBL_NM ";
				sql += "        , A.PK_COLNAMES PK_COL_NM ";
				sql += "        ,'INNER JOIN' JOIN_TYPE  ";
				sql += "        ,'SYSTEM' JOIN_SET_OWNER  ";
				sql += "FROM    SYSCAT.REFERENCES A ";
				sql += "        INNER JOIN SYSCAT.TABLES B ON A.TABNAME = B.TABNAME ";
				sql += "WHERE   B.OWNERTYPE = 'U' ";
			}
			else if(aDbmsType.equals("POSTGRES")) {
				sql = "";
				sql += " SELECT tc.constraint_name AS CONST_NM, ";
				sql += "             tc.table_name AS FK_TBL_NM, ";
				sql += "             kcu.column_name AS FK_COL_NM, ";
				sql += "             ccu.table_name AS PK_TBL_NM, ";
				sql += "             ccu.column_name AS PK_COL_NM, ";
				sql += "            'INNER JOIN' AS JOIN_TYPE, ";
				sql += "            'SYSTEM' AS JOIN_SET_OWNER  ";
				sql += "        FROM information_schema.table_constraints tc ";
				sql += "   LEFT JOIN information_schema.key_column_usage kcu ";
				sql += "          ON tc.constraint_catalog = kcu.constraint_catalog ";
				sql += "         AND tc.constraint_schema = kcu.constraint_schema ";
				sql += "         AND tc.constraint_name = kcu.constraint_name ";
				sql += "   LEFT JOIN information_schema.referential_constraints rc ";
				sql += "          ON tc.constraint_catalog = rc.constraint_catalog ";
				sql += "         AND tc.constraint_schema = rc.constraint_schema ";
				sql += "         AND tc.constraint_name = rc.constraint_name ";
				sql += "   LEFT JOIN information_schema.constraint_column_usage ccu ";
				sql += "          ON rc.unique_constraint_catalog = ccu.constraint_catalog ";
				sql += "         AND rc.unique_constraint_schema = ccu.constraint_schema ";
				sql += "         AND rc.unique_constraint_name = ccu.constraint_name ";
				sql += " WHERE constraint_type = 'FOREIGN KEY' ";
			}
			else if(aDbmsType.equals("NETEZZA")) {
				sql = "";
				sql += " SELECT  CONSTRAINTNAME AS CONST_NM ";
				sql += "        ,RELATION AS FK_TBL_NM  ";
				sql += "        ,ATTNAME AS FK_COL_NM ";
				sql += "        ,PKRELATION AS PK_TBL_NM ";
				sql += "        ,PKATTNAME AS PK_COL_NM ";
				sql += "        ,'INNER JOIN' AS JOIN_TYPE ";
				sql += "        ,PKOWNER AS JOIN_SET_OWNER ";
				sql += "   FROM _V_RELATION_KEYDATA  ";
				sql += " WHERE OWNER = '" + aOwnerNm + "' ";
				sql += "  AND CONTYPE = 'f' ";
			}
			else if(aDbmsType.equals("SAPIQ")) {
				sql = "";
				sql += "SELECT TRIM(foreign_tname + '_' + primary_tname + '_' + columns)  CONST_NM, ";
				sql += "       TRIM(foreign_tname) FK_TBL_NM, ";
				sql += "       TRIM(columns) AS FK_COL_NM, ";
				sql += "       TRIM(primary_tname) AS PK_TBL_NM, ";;
				sql += "       TRIM(columns) AS PK_COL_NM, ";
				sql += "       'INNER JOIN' AS JOIN_TYPE, ";
				sql += "       TRIM(foreign_creator) AS JOIN_SET_OWNER ";
				sql += "FROM   SYSFOREIGNKEYS ";

				//                '' psc_2018.12.18 Sybase ASE v16
				//                sql = ""
				//                sql += " SELECT D.name AS CONST_NM, B.name AS FK_TBL_NM, "
				//                sql += " E.name AS FK_COL_NM, C.name AS PK_TBL_NM, F.name AS PK_COL_NM, "
				//                sql += " 'INNER JOIN' AS JOIN_TYPE, 'SYSTEM' AS JOIN_SET_OWNER "
				//                sql += " FROM sysreferences A "
				//                sql += " LEFT JOIN sysobjects B ON A.tableid = B.id "
				//                sql += " LEFT JOIN sysobjects C ON A.reftabid = C.id "
				//                sql += " LEFT JOIN sysobjects D ON A.constrid = D.id "
				//                sql += " INNER JOIN syscolumns E ON A.fokey1 = E.colid AND A.tableid = E.id "
				//                sql += " INNER JOIN syscolumns F ON A.refkey1 = F.colid AND A.reftabid = F.id "
			}
			else if(aDbmsType.equals("CUBRID")) {
				//                sql = ""
				//                sql += "SELECT     FK.CONSTRAINT_NAME As CONST_NM, "
				//                sql += "               FK.TABLE_NAME As FK_TBL_NM, "
				//                sql += "               FK.COLUMN_NAME As FK_COL_NM,"
				//                sql += "               PK.TABLE_NAME As PK_TBL_NM, "
				//                sql += "               PK.COLUMN_NAME As PK_COL_NM,"
				//                sql += "               'INNER JOIN' AS JOIN_TYPE,"
				//                sql += "               'SYSTEM' AS JOIN_SET_OWNER"
				//                sql += "FROM      USER_CONSTRAINTS REF_CONST JOIN USER_CONS_COLUMNS FK"
				//                sql += "               ON REF_CONST.CONSTRAINT_NAME = FK.CONSTRAINT_NAME"
				//                sql += "               JOIN USER_CONS_COLUMNS PK on REF_CONST.R_CONSTRAINT_NAME = PK.CONSTRAINT_NAME"
				//                sql += "               AND FK.POSITION = PK.POSITION"
				//                sql += "WHERE      1=1"
				//                sql += "AND        REF_CONST.CONSTRAINT_TYPE = 'R'"

				sql = "";
				sql += "SELECT  ";
				sql += "    x.index_name As CONST_NM,  ";
				sql += "    x.class_name AS FK_TBL_NM,  ";
				sql += "    x.key_attr_name  AS FK_COL_NM,  ";
				sql += "    y.class_name AS PK_TBL_NM,  ";
				sql += "    y.key_attr_name AS PK_COL_NM,  ";
				sql += "    'INNER JOIN' AS JOIN_TYPE,  ";
				sql += "    'SYSTEM' AS JOIN_SET_OWNER  ";
				sql += " FROM (  ";
				sql += "         SELECT  ";
				sql += "            a.index_name,  ";
				sql += "            a.key_count,  ";
				sql += "            b.class_name,  ";
				sql += "            b.key_attr_name,  ";
				sql += "            b.key_order  ";
				sql += "         FROM db_index a  ";
				sql += "            INNER JOIN db_index_key b  ";
				sql += "            ON a.index_name = b.index_name  ";
				sql += "         WHERE a.is_foreign_key = 'YES'  ";
				sql += "    ) x  ";
				sql += "    INNER JOIN (  ";
				sql += "         SELECT  ";
				sql += "             a.index_name,  ";
				sql += "             a.key_count,  ";
				sql += "             b.class_name,  ";
				sql += "             b.key_attr_name,  ";
				sql += "             b.key_order  ";
				sql += "         FROM db_index a  ";
				sql += "             INNER JOIN db_index_key b  ";
				sql += "             ON a.index_name = b.index_name  ";
				sql += "         WHERE a.is_primary_key = 'YES'  ";
				sql += "    ) y  ";
				sql += "    ON x.key_attr_name = y.key_attr_name AND x.key_count = y.key_count ";
			}
			else if(aDbmsType.equals("ALTIBASE")) {
				sql = "";
				sql += "SELECT CONST.CONSTRAINT_NAME AS CONST_NM  ";
				sql += "       ,FK_TBL.TABLE_NAME AS FK_TBL_NM  ";
				sql += "       ,FK_COL.COLUMN_NAME AS FK_COL_NM  ";
				sql += "       ,PK_TBL.TABLE_NAME AS PK_TBL_NM  ";
				sql += "       ,PK_COL.COLUMN_NAME AS PK_COL_NM  ";
				sql += "       ,'INNER JOIN' AS JOIN_TYPE  ";
				sql += "       ,'SYSTEM' AS JOIN_SET_OWNER  ";
				sql += "FROM SYSTEM_.SYS_CONSTRAINTS_ CONST  ";
				sql += "INNER JOIN SYSTEM_.SYS_CONSTRAINT_COLUMNS_ FK_CON_COL ON CONST.CONSTRAINT_ID = FK_CON_COL.CONSTRAINT_ID  ";
				sql += "INNER JOIN SYSTEM_.SYS_COLUMNS_ FK_COL ON FK_CON_COL.COLUMN_ID = FK_COL.COLUMN_ID  ";
				sql += "INNER JOIN SYSTEM_.SYS_TABLES_ FK_TBL ON CONST.TABLE_ID = FK_TBL.TABLE_ID  ";
				sql += "INNER JOIN SYSTEM_.SYS_TABLES_ PK_TBL ON CONST.REFERENCED_TABLE_ID = PK_TBL.TABLE_ID  ";
				sql += "INNER JOIN SYSTEM_.SYS_INDEX_COLUMNS_ IDX_COL ON IDX_COL.INDEX_ID = CONST.REFERENCED_INDEX_ID AND IDX_COL.TABLE_ID = PK_TBL.TABLE_ID  ";
				sql += "INNER JOIN SYSTEM_.SYS_COLUMNS_ PK_COL  ON PK_COL.COLUMN_ID = IDX_COL.COLUMN_ID  ";
			}
			else if(aDbmsType.equals("TERADATA")) {
				sql = "";
				sql += "SELECT CONST.REFERENCEIDXNAME AS CONST_NM, ";
				sql += "FK_TBL.TABLENAME AS FK_TBL_NM, ";
				sql += "FK_COL.COLUMNNAME AS FK_COL_NM, ";
				sql += "PK_TBL.TABLENAME AS PK_TBL_NM, ";
				sql += "PK_COL.COLUMNNAME AS PK_COL_NM, ";
				sql += "'INNER JOIN' AS JOIN_TYPE, ";
				sql += "'SYSTEM' AS JOIN_SET_OWNER ";
				sql += "FROM DBC.ReferencedTbls CONST ";
				sql += "INNER JOIN DBC.RI_Distinct_ParentsV IDX ON CONST.REFERENCEIDXNAME = IDX.INDEXNAME  ";
				sql += "INNER JOIN DBC.COLUMNSV PK_COL ON CONST.PARENTKEYFID = PK_COL.COLUMNID AND IDX.PARENTDB = PK_COL.DATABASENAME ";
				sql += "INNER JOIN DBC.COLUMNSV FK_COL ON CONST.FOREIGNKEYFID = FK_COL.COLUMNID AND IDX.CHILDDB = FK_COL.DATABASENAME ";
				sql += "INNER JOIN DBC.TABLESV PK_TBL ON PK_COL.TABLENAME = PK_TBL.TABLENAME AND IDX.PARENTTABLE = PK_TBL.TABLENAME ";
				sql += "INNER JOIN DBC.TABLESV FK_TBL ON FK_COL.TABLENAME = FK_TBL.TABLENAME AND IDX.CHILDTABLE = FK_TBL.TABLENAME ";
			}
			else if(aDbmsType.equals("IMPALA")) {
				sql = "";
				sql += "SELECT '' AS CONST_NM, ";
				sql += "'' AS FK_TBL_NM, ";
				sql += "'' AS FK_COL_NM, ";
				sql += "'' AS PK_TBL_NM, ";
				sql += "'' AS PK_COL_NM, ";
				sql += "'' AS JOIN_TYPE, ";
				sql += "'' AS JOIN_SET_OWNER ";
			}
		}
		return sql;
	}
}
