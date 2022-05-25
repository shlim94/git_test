package com.wise.common.web.controller;

import java.io.PrintWriter;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

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

@Controller
@RequestMapping(value = "/css")
public class CssStylsheetController {
	private Logger logger = Logger.getLogger(this.getClass());
	
	@RequestMapping(value = "/WISE.custom.css", method = RequestMethod.GET)
    public void custom(HttpServletRequest request, HttpServletResponse response) throws Exception {
	    String encoding = Configurator.getInstance().getConfig("encoding");
        response.setCharacterEncoding(encoding);
        response.setContentType("text/css");
        
        String script = "";
        
        if (Configurator.getInstance().getConfigKeySet().contains("WISE.libs.Dashboard.CSS.widget.font.size")) {
            script += "html, body, div, span, applet, object, iframe, h1, h2, h3, h4, h5, h6, p, blockquote, pre, abbr, acronym, address, big, cite, code, del, dfn, em, font, img, ins, kbd, q, s, samp, small, strike, strong, sub, sup, tt, var, b, u, i, center, dl, dt, dd, ol, ul, li, fieldset, form, label, legend, table, caption, tbody, tfoot, thead, tr, th, td {font-size: " + Configurator.getInstance().getConfig("WISE.libs.Dashboard.CSS.widget.font.size") + ";} ";
        }
        
        if (Configurator.getInstance().getConfigKeySet().contains("WISE.libs.Dashboard.CSS.widget.font.family")) {
            script += ".dx-widget {font-family: ";
            String fontFamilyValues = "";
            List<String> widgetFontFamilyElements = Configurator.getInstance().getListConfig("WISE.libs.Dashboard.CSS.widget.font.family");
            for (String fontFamily : widgetFontFamilyElements) {
                if (fontFamily.indexOf(" ") > -1) {
                    fontFamilyValues += "'" + fontFamily + "',";
                }
                else {
                    fontFamilyValues += fontFamily + ",";
                }
            }
            
            if (fontFamilyValues.length() > 0) {
                fontFamilyValues = fontFamilyValues.substring(0, fontFamilyValues.length() - 1);
            }
            
            script += fontFamilyValues;
            script += ";} ";
        }
        
        if (Configurator.getInstance().getConfigKeySet().contains("WISE.libs.Dashboard.CSS.condition.font.size")) {
            script += ".cont_query .condition-item.condition-caption {font-size: " + Configurator.getInstance().getConfig("WISE.libs.Dashboard.CSS.condition.font.size") + ";} ";
        }
        if (Configurator.getInstance().getConfigKeySet().contains("WISE.libs.Dashboard.CSS.condition.font.padding")) {
            script += ".cont_query .condition-item.condition-caption {padding: " + Configurator.getInstance().getConfig("WISE.libs.Dashboard.CSS.condition.font.padding") + ";} ";
        }
        
        if (Configurator.getInstance().getConfigKeySet().contains("WISE.libs.Dashboard.CSS.widget.grid.header.color")) {
            script += ".dx-datagrid-headers {background-color: " + Configurator.getInstance().getConfig("WISE.libs.Dashboard.CSS.widget.grid.header.color") + ";} ";
        }
        
        if (Configurator.getInstance().getConfigKeySet().contains("WISE.libs.Dashboard.CSS.widget.pivot.horizontal.header.color")) {
            script += "thead.dx-pivotgrid-horizontal-headers {background-color: " + Configurator.getInstance().getConfig("WISE.libs.Dashboard.CSS.widget.pivot.horizontal.header.color") + ";} ";
        }
        if (Configurator.getInstance().getConfigKeySet().contains("WISE.libs.Dashboard.CSS.widget.pivot.vertical.header.color")) {
            script += "thead.dx-pivotgrid-vertical-headers {background-color: " + Configurator.getInstance().getConfig("WISE.libs.Dashboard.CSS.widget.pivot.vertical.header.color") + ";} ";
        }
        
        List<String> cssElements = Configurator.getInstance().getListConfig("WISE.libs.Dashboard.CSS.custom.elements");
        for (String css : cssElements) {
            script += css + " ";
        }
        
        this.logger.debug("added css - " + script);
        
        PrintWriter out = response.getWriter();
        out.write(script);
        
        out.flush();
        out.close();
    }
}