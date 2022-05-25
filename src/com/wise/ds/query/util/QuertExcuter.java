package com.wise.ds.query.util;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.time.StopWatch;
import org.json.JSONObject;

import com.wise.ds.repository.dataset.NotFoundDatabaseConnectorException;

public class QuertExcuter {
	public JSONObject executeCsvImport(String FileNm, String tblNm, ArrayList<String> header, char seprator,
			ArrayList<HashMap<String, String>> colInfo, Connection conn,String realpath, String ckutf) {
		String reval = "";
		Statement stmt = null;
		Statement metaStmt = null;
		ResultSet rs = null;
		ResultSet metaRs = null;

		StringBuilder query = new StringBuilder();
		String uploadId = "";
		Boolean dataClearChk = false;
		JSONObject result = new JSONObject();

		try {
			StopWatch sw = new StopWatch();
			sw.start();
			sw.split();

//			metaStmt = conn.createStatement();
//			metaRs = metaStmt.executeQuery("SELECT WEB_URL FROM CONFIG_MSTR");
			// request.getRealPath("/UploadFiles/DataFile");
			String webUrl = "";
//			while (metaRs.next()) {
//				webUrl = metaRs.getString(1).toString();
//			}

//			int b = webUrl.lastIndexOf("/");

//			URL gwtServlet = new URL(webUrl + "config.do");
//			HttpURLConnection servletConnection = (HttpURLConnection) gwtServlet.openConnection();
//			servletConnection.setRequestMethod("GET");
//
//			InputStream response = servletConnection.getInputStream();

			String ext = "";
			int index = FileNm.lastIndexOf(".");
			if (index != -1) {
				ext = FileNm.substring(index + 1);
			}

			if (ext.equalsIgnoreCase("csv")) {
				CSVLoader csv = new CSVLoader(conn, seprator, header);

//				if (FILE_FIRSTROW_HD.equalsIgnoreCase("CP_CUST"))
//					uploadId = csv.loadCSVCpCust(realpath, tblNm);
//				else
				try {
					csv.loadCSV(realpath, tblNm, dataClearChk, colInfo,
							"True",ckutf);
				} catch (IOException | NotFoundDatabaseConnectorException e) {
					e.printStackTrace();
				}

			} else {
				if (ext.equalsIgnoreCase("cell"))
					FileNm = FileNm.substring(0, index) + ".xlsx";
				ExcelLoader excel = new ExcelLoader(conn, "", header);
				try {
					excel.loadExcel(realpath, tblNm, dataClearChk, colInfo,
							"True");
				} catch (IOException e) {
					e.printStackTrace();
				}
				// 국방부
				// excel.loadExcel("/opt/hpws22/tomcat_olap/webapps/WISE.BI.AUDI.WEB.SVC.v4/UploadFiles/DataFile/"
				// + FileNm, tblNm, true,colInfo,FILE_FIRSTROW_HD);

			}

			sw.split();

			stmt = conn.createStatement();
//			if (FILE_FIRSTROW_HD.equalsIgnoreCase("CP_CUST")) {
//				query.append("SELECT '" + uploadId + "' AS GUID ").append(" , COUNT(*) AS RE_CNT")
//						.append(" FROM " + tblNm).append(" WHERE UP_ID = '" + uploadId + "'");
//			} else {
				query.append("SELECT '" + tblNm + "' AS TABLE_NAME ").append(" , '" + tblNm + "' AS TABLE_CAPTION ")
						.append(" , COUNT(*) AS RE_CNT").append(" FROM " + tblNm);
//			}

			rs = stmt.executeQuery(query.toString());

			sw.stop();
			String s ="";
			ResultSetMetaData rsmd = rs.getMetaData();
			while (rs.next()) {
				result.put("REC_CNT", rs.getString("RE_CNT"));
			}
			// log.debug(new Date(sw.getTime());
		} catch (SQLException e) {
			e.printStackTrace();
			if (rs != null) {
				try {
					if (rs.isClosed() == false) {
						rs.close();
					}
				} catch (SQLException se) {
					se.printStackTrace();
					rs = null;
				}
			}

			if (stmt != null) {
				try {
					if (stmt.isClosed() == false) {
						stmt.close();
					}
				} catch (SQLException se) {
					se.printStackTrace();
					stmt = null;
				}
			}

		} finally {
			if (rs != null) {
				try {
					//if (rs.isClosed() == false) {
						rs.close();
					//}
				} catch (SQLException se) {
					se.printStackTrace();
					rs = null;
				}
			}

			if (stmt != null) {
				try {
					//if (stmt.isClosed() == false) {
						stmt.close();
					//}
				} catch (SQLException se) {
					se.printStackTrace();
					se = null;
				}
			}

			if (metaStmt != null) {
				try {
					//if (metaStmt.isClosed() == false) {
						metaStmt.close();
					//}
				} catch (SQLException se) {
					se.printStackTrace();
					metaStmt = null;
				}
			}
			
		}
		return result;

	}

}
