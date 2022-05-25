package com.wise.common.view;

import java.io.PrintWriter;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import org.springframework.web.servlet.View;

import com.wise.context.config.Configurator;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 * 
 *     수정일         수정자               수정내용
 *  --------------    ------------    ---------------------------
 *  2015.06.08        DOGFOOT              최초 생성
 * </pre>
 */

public class PrintWriterView implements View {

	private String contentType;

	void setContentType(String contentType) {
		this.contentType = contentType;
	}

	public String getContentType() {
		return this.contentType == null ? "text/html; charset=UTF-8" : this.contentType;
	}

	public void render(Map<String, ?> model, HttpServletRequest request, HttpServletResponse response) throws Exception {
	    String encoding = Configurator.getInstance().getConfig("encoding");
	    response.setCharacterEncoding(encoding);
	    response.setContentType(this.contentType);
		
		PrintWriter out = response.getWriter();
		
		String json;
		Object data = model.get("OUT_DATA");
		
		if (data instanceof JSONArray) {
		    json = ((JSONArray) data).toString();
		} else if (data instanceof JSONObject) {
		    json = ((JSONObject) data).toString();
		} else {
		    json = (String) data;
		}
		
		out.print(json);

		out.flush();
		out.close();
	}

}
