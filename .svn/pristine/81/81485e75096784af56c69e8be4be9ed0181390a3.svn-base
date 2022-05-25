package com.wise.common.csrf;

import java.io.ByteArrayOutputStream; 
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import org.apache.commons.lang.StringUtils;
import org.springframework.security.web.csrf.CsrfToken;
/**
 * [CsrfTokenAdder.java, 서블릿필터]
 * - HttpServletRequest(일반 JSP요청), XMLHttpRequest(AJAX) 요청이든 Csrf 히든테그 삽입
 * - CSRF Protection을 위한 Text/Html Response에 히든태그 Xsrf Token 삽입
 * - AJAX JSON Response는 히든태그 Csrf Token 삽입할 필요없다.
 */
public class CsrfTokenAdder implements Filter {
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String url = ((HttpServletRequest)request).getRequestURL().toString();
		String responseText = null;
		HtmlResponseWrapper  newResponse = null;
		CsrfToken token = null;
		
		// 필터대상 에서 제외할 목록
		final String[] EXCLUDE_URL_LIST = {"/favicon.ico","/css", "/css.min", "/DataFiles", "/images", "/js", "/js.min", "/resources", "/test", "/UploadFiles", "/WEB-INF" };
		String paramName = null;
		String strToken = null; 
		String tokenStr = null;
		String csrfTokenInput = null;
		String replacedText = null;	
		boolean excludeState = false;

		//-------------------------------------
		// 필터 제외 URI SKIP
		//-------------------------------------
		for (String target:EXCLUDE_URL_LIST)
		{
			if (url.indexOf(target) > -1) {
				excludeState = true;
				break;
			}
		}

		if (excludeState) {
			chain.doFilter(request, response);
			return;
		}
		//-------------------------------------

		//-------------------------------------------------------------
		// AJAX APPLICATION/JSON RESPONSE, NON TEXT/HTML
		// 화면 콤보 초기화 등에서 AJAX CALL 하는 경우
		// 이 경우는 CSRF 태그를 삽입할 필요없다.
		//-------------------------------------------------------------
        if (((HttpServletResponse)response).getContentType() != null 
        		&& "XMLHttpRequest".equals(((HttpServletRequest) request).getHeader("X-Requested-With"))
        		&& ((HttpServletResponse)response).getContentType().contains("application/json")) {  
			response.getWriter().write(responseText);
        } 
		//-------------------------------------------------------------
        // 응답이 text/html인 경우 Csrf 히든 태그를 응답 </form> 앞에 삽입한다. 
        // 일반 JSP로 보내는 응답, AJAX TEXT/HTML 응답인 팝업 화면로딩 등
        //-------------------------------------------------------------
		else if (((HttpServletResponse)response).getContentType() != null         		
        		&& ((HttpServletResponse)response).getContentType().contains("text/html")) {
        	newResponse = new HtmlResponseWrapper ((HttpServletResponse) response);	
    		chain.doFilter(request, newResponse);
    		responseText = newResponse.getCaptureAsString();  
        	token = (CsrfToken) request.getAttribute("_csrf");
            paramName = token.getParameterName();
            strToken = token.getToken();
			if (token != null) {
				tokenStr = String.format("<input type=\"hidden\" name=\"%s\" id=\"%s\" value=\"%s\" />",
						paramName, paramName, strToken);
			}

			// 일반 JSP로 응답을 보내는 경우(HttpServletRequest, TEXT/HTML응답)
			if (!StringUtils.contains(responseText, "_csrf.parameterName")
				&& StringUtils.contains(responseText, "<form>")) {
				 csrfTokenInput = tokenStr + "</form>";
			     replacedText = StringUtils.replace(responseText, "</form>", csrfTokenInput);
			} 

			// 팝업창 로딩(XMLHttpRequest요청,AJAX TEXT/HTML응답)
			else {
				csrfTokenInput = "<form>" + tokenStr + "</form></body>";
				replacedText = StringUtils.replace(responseText, "</body>", csrfTokenInput);
			}	
			response.getWriter().write(replacedText);
		}
		else {	
			chain.doFilter(request, response);
		}
	}

	@Override
	public void init(FilterConfig arg0) throws ServletException {

	}

	@Override
	public void destroy() {

	}
}

//----------------------------------------------------------
// Response에 Csrf 히든 테그를 삽입하기 위한 Wrapper
//----------------------------------------------------------
class HtmlResponseWrapper extends HttpServletResponseWrapper {
    private final ByteArrayOutputStream capture;
    private ServletOutputStream output;
    private PrintWriter writer;

    public HtmlResponseWrapper(HttpServletResponse response) {
        super(response);
        capture = new ByteArrayOutputStream(response.getBufferSize());
    }

    @Override
    public ServletOutputStream getOutputStream() {
        if (writer != null) {
            throw new IllegalStateException(
                    "getWriter() has already been called on this response.");
        }

        if (output == null) {
            output = new ServletOutputStream() {
                @Override
                public void write(int b) throws IOException {
                    capture.write(b);
                }

                @Override
                public void flush() throws IOException {
                    capture.flush();
                }

                @Override
                public void close() throws IOException {
                    capture.close();
                }

				@Override
				public boolean isReady() {
					// TODO Auto-generated method stub
					return false;
				}

				@Override
				public void setWriteListener(WriteListener arg0) {
					// TODO Auto-generated method stub
					
				}
            };
        }

        return output;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (output != null) {
            throw new IllegalStateException(
                    "getOutputStream() has already been called on this response.");
        }

        if (writer == null) {
            writer = new PrintWriter(new OutputStreamWriter(capture,
                    getCharacterEncoding()));
        }

        return writer;
    }

    @Override
    public void flushBuffer() throws IOException {
        super.flushBuffer();

        if (writer != null) {
            writer.flush();
        }
        else if (output != null) {
            output.flush();
        }
    }

    public byte[] getCaptureAsBytes() throws IOException {
        if (writer != null) {
            writer.close();
        }
        else if (output != null) {
            output.close();
        }

        return capture.toByteArray();
    }

    public String getCaptureAsString() throws IOException {
        return new String(getCaptureAsBytes(), getCharacterEncoding());
    }
}