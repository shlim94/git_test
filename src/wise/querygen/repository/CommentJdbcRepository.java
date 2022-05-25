package wise.querygen.repository;


import java.io.StringReader;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import oracle.jdbc.OracleTypes;
import oracle.jdbc.internal.OracleCallableStatement;

public class CommentJdbcRepository {
	static Properties pt;
	private static final Logger logger = Logger.getLogger(CommentJdbcRepository.class);
	public Connection getConnection() {
		PropertiesLoader  pl = new PropertiesLoader();
		pt = pl.Read();
		Connection result = null;
		try {
			Class.forName(pt.getProperty("jdbc.driver").toString()).newInstance();
			result = DriverManager.getConnection(pt.getProperty("jdbc.url").toString(), 
					pt.getProperty("jdbc.username").toString(), pt.getProperty("jdbc.password").toString());
		} catch (InstantiationException | IllegalAccessException | ClassNotFoundException | SQLException e) {
			e.printStackTrace();
		}
		return result;
	}
	
	public int UpdateComment(String query) {
		Connection conn = null;
		PreparedStatement cstmt= null;
		int result = 0;
		
		try {
			conn = this.getConnection();
			StringBuilder sql = new StringBuilder("");
			sql.append(query);
			cstmt = conn.prepareStatement(sql.toString());
			result = cstmt.executeUpdate();	
			conn.commit();
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				cstmt.close();
			} catch (SQLException se) {
				se.printStackTrace();
				cstmt = null;
			}
			try {
				conn.close();
			} catch (SQLException se) {
				se.printStackTrace();
				conn = null;
			}
		}
		return result;
		
	}
	
	public ResultSet selectComment(String query) {
		Connection conn = null;
		PreparedStatement cstmt = null;
		ResultSet rs = null;
	
		try {
			conn = this.getConnection();
			StringBuilder sql = new StringBuilder("");
			sql.append(query);
			cstmt = conn.prepareStatement(sql.toString());
			rs = cstmt.executeQuery();
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException se) {
					se.printStackTrace();
					rs = null;
				}
			}
			try {
				cstmt.close();
			} catch (SQLException se) {
				se.printStackTrace();
				cstmt = null;
			}
			try {
				conn.close();
			} catch (SQLException se) {
				se.printStackTrace();
				conn = null;
			}
		}
		return rs;
	}
	
	
	public int CallProcMdDmGapAct(String extr_dt, String extr_seq) {
		Connection conn = null;
		CallableStatement cstmt = null;
		ResultSet rs = null;
		OracleCallableStatement ocstmt = null;
		PropertiesLoader  pl = new PropertiesLoader();
		pt = pl.Read();
		String dbtype = "";
//		String dbtype = pt.getProperty("jdbc.dbtype").toString();
		if(pt.getProperty("jdbc.dbtype").toString() != null) {
			dbtype = pt.getProperty("jdbc.dbtype").toString();
		}
		
		int rst=0;
		try {
			if(dbtype != null) {
				conn = this.getConnection();
				
				StringBuilder sql = new StringBuilder("");
				if(dbtype.equals("ORACLE"))
					cstmt = conn.prepareCall("call UP_MD_DM_DB_GAP_ACT(?,?,?,?,?)");
				else
					cstmt = conn.prepareCall("EXEC dbo.UP_CAMP_CUSTCLS_MSTR_ACT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'',''");
				
				cstmt.setString(1,"0");
				cstmt.setString(2,extr_dt);
				cstmt.setString(3,extr_seq);
				
				if(dbtype.equals("ORACLE"))
				{
					cstmt.registerOutParameter(4, OracleTypes.CURSOR);
					cstmt.registerOutParameter(5, OracleTypes.CURSOR);
					cstmt.executeQuery();
					ocstmt = (OracleCallableStatement)cstmt;
					
					rs = (ResultSet) ocstmt.getObject(4);

				}
				else
				{
					boolean tmp = cstmt.execute();
					
				}
				if (rs != null) {
					rst =1;
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException se) {
					se.printStackTrace();
					rs = null;
				}
			}
			try {
				cstmt.close();
			} catch (SQLException se) {
				se.printStackTrace();
				cstmt = null;
			}
			try {
				conn.close();
			} catch (SQLException se) {
				se.printStackTrace();
				conn = null;
			}
		}
		return rst;
	}
	
	public int  CallProcCampCustclsMstrAct(String Custcls_id, String query) {
		Connection conn = null;
		CallableStatement cstmt = null;
		ResultSet rs = null;
		OracleCallableStatement ocstmt = null;
		PropertiesLoader  pl = new PropertiesLoader();
		pt = pl.Read();
//		String dbtype  = pt.getProperty("jdbc.dbtype").toString();
		String dbtype = "";
		if(pt.getProperty("jdbc.dbtype").toString() != null) {
			dbtype = pt.getProperty("jdbc.dbtype").toString();
		}
		
		int rst=0;
		try {
			if(dbtype != null) {
				conn = this.getConnection();
				
				StringBuilder sql = new StringBuilder("");
				if(dbtype.equals("oracle"))
					cstmt = conn.prepareCall("call UP_CAMP_CUSTCLS_MSTR_ACT(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
				else
					cstmt = conn.prepareCall("EXEC dbo.UP_CAMP_CUSTCLS_MSTR_ACT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'',''");
				
				cstmt.setString(1,"CUSTCLS_EXT");
				cstmt.setString(2,"");
				cstmt.setString(3,"");
				cstmt.setString(4,"");
				cstmt.setString(5,Custcls_id);
				cstmt.setString(6,"");
				cstmt.setString(7,"");
				cstmt.setString(8,"");
				cstmt.setString(9,"");
				cstmt.setString(10,"");
				cstmt.setString(11,"");
				cstmt.setString(12,"");
				cstmt.setString(13,"");
				cstmt.setString(14,"");
				cstmt.setString(15,"");
				cstmt.setClob(16,new StringReader(query));
				cstmt.setString(17,"");
				cstmt.setString(18,"");
				cstmt.setString(19,"");
				cstmt.setString(20,"");
				if(dbtype.equals("oracle"))
				{
					cstmt.registerOutParameter(21, OracleTypes.CURSOR);
					cstmt.registerOutParameter(22, OracleTypes.CURSOR);
					cstmt.executeQuery();
					ocstmt = (OracleCallableStatement)cstmt;
					
					rs = (ResultSet) ocstmt.getObject(21);

				}
				else
				{
					boolean tmp = cstmt.execute();
					
				}
				if (rs != null) {
					rst =1;
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException se) {
					se.printStackTrace();
					rs = null;
				}
			}
			try {
				cstmt.close();
			} catch (SQLException se) {
				se.printStackTrace();
				cstmt = null;
			}
			try {
				conn.close();
			} catch (SQLException se) {
				se.printStackTrace();
				conn = null;
			}
		}
		return rst;
	}

	public int  CallProcCampCmsCampaignAct(Map<String, Object> paramMap) {
		Connection conn = null;
		CallableStatement cstmt = null;
		OracleCallableStatement ocstmt = null;
		PropertiesLoader  pl = new PropertiesLoader();
		pt = pl.Read();
//		String dbtype  = pt.getProperty("jdbc.dbtype").toString();
		String dbtype = "";
		if(pt.getProperty("jdbc.dbtype").toString() != null) {
			dbtype = pt.getProperty("jdbc.dbtype").toString();
		}
		
		int rst=0;
		try {
			if(dbtype != null) {
				conn = this.getConnection();
				
				StringBuilder sql = new StringBuilder("");
				
				cstmt = conn.prepareCall("call UP_CAMP_CMS_CAMPAIGN_ACT(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
				
				cstmt.setString(1,paramMap.get("CMS_ID").toString());
				cstmt.setString(2,paramMap.get("DESCRIPTION").toString());
				cstmt.setString(3,paramMap.get("END_DATE").toString());
				cstmt.setString(4,paramMap.get("BOOKING_DATE").toString().substring(0,19));
				cstmt.setString(5,paramMap.get("SUBJECT").toString());
				cstmt.setString(6,paramMap.get("MSGCODE").toString());
				cstmt.setString(7,paramMap.get("SENDER").toString());
				cstmt.setString(8,paramMap.get("SENDER_EMAIL").toString());
				cstmt.setInt(9,Integer.parseInt(paramMap.get("COUNT").toString()));
				cstmt.setString(10,paramMap.get("STATUS").toString());
				cstmt.setString(11,paramMap.get("WORKDAY").toString());
				cstmt.setInt(12,0);
				cstmt.setInt(13,0);
				if(dbtype.equals("oracle"))
				{
					cstmt.registerOutParameter(14, OracleTypes.NUMBER);
					cstmt.executeQuery();
					ocstmt = (OracleCallableStatement)cstmt;
					
					rst = ocstmt.getInt(14);
					logger.debug("CMS_CAMPAIGN RESULT=>" + rst);
				}
//				else
//				{
//
//				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				cstmt.close();
			} catch (SQLException se) {
				se.printStackTrace();
				cstmt = null;
			}
			try {
				conn.close();
			} catch (SQLException se) {
				se.printStackTrace();
				conn = null;
			}
		}
		return rst;
	}
	public int  CallProcCampCmsTargetAct(Map<String, Object> paramMap) {
		Connection conn = null;
		CallableStatement cstmt = null;
		OracleCallableStatement ocstmt = null;
		PropertiesLoader  pl = new PropertiesLoader();
		pt = pl.Read();
//		String dbtype  = pt.getProperty("jdbc.dbtype").toString();
		String dbtype = "";
		if(pt.getProperty("jdbc.dbtype").toString() != null) {
			dbtype = pt.getProperty("jdbc.dbtype").toString();
		}
		
		int rst=0;
		try {
			if(dbtype != null) {
				conn = this.getConnection();
				
				StringBuilder sql = new StringBuilder("");
				
				cstmt = conn.prepareCall("call UP_CAMP_CMS_TARGET_ACT(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
				
				cstmt.setString(1,paramMap.get("CMS_ID").toString());
				cstmt.setString(2,paramMap.get("TARGET_ID").toString());
				cstmt.setString(3,paramMap.get("EMAIL").toString());
				cstmt.setString(4,paramMap.get("NAME").toString());
				cstmt.setString(5,paramMap.get("EXT01").toString());
				cstmt.setString(6,paramMap.get("EXT02").toString());
				cstmt.setString(7,paramMap.get("EXT03").toString());
				cstmt.setString(8,paramMap.get("EXT04").toString());
				cstmt.setString(9,paramMap.get("EXT05").toString());
				cstmt.setString(10,paramMap.get("EXT06").toString());
				cstmt.setString(11,paramMap.get("EXT07").toString());
				cstmt.setString(12,paramMap.get("EXT08").toString());
				cstmt.setString(13,paramMap.get("EXT09").toString());
				cstmt.setString(14,paramMap.get("EXT10").toString());
				
				if(dbtype.equals("oracle"))
				{
					cstmt.registerOutParameter(15, OracleTypes.NUMBER);
					cstmt.executeQuery();
					ocstmt = (OracleCallableStatement)cstmt;
					
					rst = ocstmt.getInt(15);

				}
//				else
//				{
//
//				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			try {
				cstmt.close();
			} catch (SQLException se) {
				se.printStackTrace();
				cstmt = null;
			}
			try {
				conn.close();
			} catch (SQLException se) {
				se.printStackTrace();
				conn = null;
			}
		}
		return rst;
	}
	public int  CallprocUpCampSegclsAct(Map paramMap) {
		Connection conn = null;
		CallableStatement cstmt = null;
		ResultSet rs = null;
		OracleCallableStatement ocstmt = null;
		PropertiesLoader  pl = new PropertiesLoader();
		pt = pl.Read();
//		String dbtype  = pt.getProperty("jdbc.dbtype").toString();
		String dbtype = "";
		if(pt.getProperty("jdbc.dbtype").toString() != null) {
			dbtype = pt.getProperty("jdbc.dbtype").toString();
		}
		
		int rst=0;
		try {
			if(dbtype != null) {
				conn = this.getConnection();
				
				StringBuilder sql = new StringBuilder("");
				if(dbtype.equals("oracle"))
					cstmt = conn.prepareCall("call UP_CAMP_SEGCLS_ACT(?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?,?, ?,?,?,?)");
				else
					cstmt = conn.prepareCall("EXEC dbo.UP_CAMP_SEGCLS_ACT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'' ");
				
				cstmt.setString(1,"CAMPTARG_EXT");
				cstmt.setString(2,paramMap.get("CAMP_ID")+"");
				cstmt.setString(3,paramMap.get("CUSTCLS_ID")+"");
				cstmt.setString(4,paramMap.get("SEGCLS_ID")+"");
				cstmt.setString(5,"");
				cstmt.setString(6,"");
				cstmt.setString(7,"");
				cstmt.setString(8,"");
				cstmt.setString(9,"");
				cstmt.setString(10,"");
				cstmt.setString(11,"");
				cstmt.setString(12,"");
				cstmt.setString(13,"");
				cstmt.setString(14,"");
				cstmt.setString(15,"");
				cstmt.setString(16,"");
				cstmt.setString(17,"");
				cstmt.setString(18,paramMap.get("SCHD_RECNT")+""  );
				cstmt.setString(19,paramMap.get("SCHD_ID")+"" );
				cstmt.setString(20,paramMap.get("CHTYP_ID")+"" );
				cstmt.setString(21,paramMap.get("MSG_ID" )+"");
				cstmt.setString(22,"");
				cstmt.setString(23,"");
				cstmt.setString(24,"");
				cstmt.setString(25,"");
				cstmt.setString(26,"");
				cstmt.setString(27,"");
				
				if(dbtype.equals("oracle"))
				{
					cstmt.registerOutParameter(28, OracleTypes.CURSOR);
					cstmt.registerOutParameter(29, OracleTypes.CURSOR);
					cstmt.executeQuery();
					ocstmt = (OracleCallableStatement)cstmt;
					
					rs = (ResultSet) ocstmt.getObject(29);

				}
				else
				{
					boolean tmp = cstmt.execute();
					
				}
				
		 	 
				if (rs != null) {
					rst =1;
					 
				}
			}
		} catch (SQLException e) {
			e.printStackTrace();
		} finally {
			if (rs != null) {
				try {
					rs.close();
				} catch (SQLException se) {
					se.printStackTrace();
					rs = null;
				}
			}
			try {
				cstmt.close();
			} catch (SQLException se) {
				se.printStackTrace();
				cstmt = null;
			}
			try {
				conn.close();
			} catch (SQLException se) {
				se.printStackTrace();
				conn = null;
			}
		}
		return rst;
	}


}