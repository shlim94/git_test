package com.wise.ds.repository.controller;

import java.io.PrintWriter;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import com.wise.common.secure.SecureUtils;
import com.wise.ds.query.util.SqlStorage;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 *     수정일                 수정자             수정내용   
 *  ----------    --------    ---------------------------
 *  2015.06.08      DOGFOOT             최초 생성
 * </pre>
 */

@Controller
@RequestMapping(value = "/sql/storage")
public class SqlDiagnosticeController {
	private static final Logger logger = LoggerFactory.getLogger(SqlDiagnosticeController.class);
	
    @Resource(name = "sqlStorage")
    private SqlStorage sqlStorage;
	
	@RequestMapping(value = {"/report.do"})
    public void diagnostic(HttpServletResponse response) throws Exception {
	    response.setCharacterEncoding("UTF-8");
        response.setContentType("text/html");
	    
        PrintWriter out = response.getWriter();
        out.write(this.sqlStorage.diagnostic());
        out.flush();
        out.close();
    }
	
	@RequestMapping(value = {"/clear.do"})
    public void clear(HttpServletResponse response) throws Exception {
        this.sqlStorage.clear();
        
        PrintWriter out = response.getWriter();
        out.write("SQL Cache Cleared.");
        out.flush();
        out.close();
    }
	@RequestMapping(value = {"/clearSqlId.do"})
	 public void clearSqlId(HttpServletRequest request,HttpServletResponse response) throws Exception {
		String sqlId = SecureUtils.getParameter(request, "wise_sql_id");
		String refer = (String)request.getHeader("REFERER");
		PrintWriter out = response.getWriter();
		if(refer.indexOf("editds") > 0 || refer.indexOf("ds") > 0 || refer.indexOf("olap") > 0) {
			this.sqlStorage.clearSqlById(sqlId);
	        out.write("SQL Cache Cleared. target : "+sqlId);
		}
        out.flush();
        out.close();
    }
}
