package com.wise.ds.util;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import net.sf.json.JSON;
import net.sf.json.JSONObject;
import net.sf.json.xml.XMLSerializer;

import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.wise.context.config.Configurator;

@Service("CopyOfXml2Json")
public class CopyOfXml2Json {
    private static final Logger logger = LoggerFactory.getLogger(CopyOfXml2Json.class);
    
    private String xmlBodyText = "";
    
    public void readXml(String xmlReqId) {
        int xmlId = Integer.valueOf(xmlReqId).intValue();
        this.readXml(xmlId);
    }
    public void readXml(int xmlReqId) {
        String dashboardRepositoryXmlUrl = Configurator.getInstance().getDashboardRepositoryXmlURL();
        String url = dashboardRepositoryXmlUrl + "/" + Integer.toString(xmlReqId) + ".xml";
        
        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(url);
        
        logger.debug("call url : " + url);
        
        method.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, new DefaultHttpMethodRetryHandler(3, false));

        try {
          int statusCode = client.executeMethod(method);
          switch (statusCode) {
              case HttpStatus.SC_OK:
                  logger.debug("call url success");
                  byte[] responseBody = method.getResponseBody();

                  this.xmlBodyText = new String(responseBody);
                  this.xmlBodyText = this.xmlBodyText.substring(1);
                  
                  InputSource is = new InputSource(new StringReader(this.xmlBodyText));
                  Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
                  
                  XPath xpath = XPathFactory.newInstance().newXPath();
                  NodeList itemList = (NodeList) xpath.evaluate("/Dashboard/Items[1]", document, XPathConstants.NODESET);
                  
                  if (itemList.getLength() > 0) {
                      Node items = itemList.item(0);
                      
                      // add empty node child to items, so let make items-node Object, NOT Array
                      Element emptyNode = document.createElement("Empty");
                      items.appendChild(emptyNode);
                      
                      TransformerFactory tf = TransformerFactory.newInstance();
                      Transformer transformer = tf.newTransformer();
                      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
                      StringWriter writer = new StringWriter();
                      transformer.transform(new DOMSource(document), new StreamResult(writer));
                      
                      this.xmlBodyText = writer.getBuffer().toString().replaceAll("\n|\r", "");
                  }
                  
                  break;
//              case HttpStatus.SC_NOT_FOUND:
//                  break;
              default:
                  logger.error("call url failed");
                  String message = "xml parse error(" + statusCode + ") : " + url;
                  XmlParseException e = new XmlParseException(message);
                  e.setHttpStatusCode(statusCode);
                  throw e;
          }
        } 
        catch (IOException | XmlParseException | TransformerException | SAXException | ParserConfigurationException | XPathExpressionException e) {
          e.printStackTrace();
        }
        finally {
          method.releaseConnection();
        }  
    }
    
    public JSONObject parseJSON() throws SAXException, IOException, ParserConfigurationException, XPathExpressionException, TransformerException {
        
        int PRETTY_PRINT_INDENT_FACTOR = 4;
        org.json.JSONObject xmlJSONObj = org.json.XML.toJSONObject(this.xmlBodyText);
        String jsonPrettyPrintString = xmlJSONObj.toString(PRETTY_PRINT_INDENT_FACTOR);
//        System.out.println(jsonPrettyPrintString);
        
        
        
        
        XMLSerializer xmlSerializer = new XMLSerializer();  
        xmlSerializer.setForceTopLevelObject(true);
        xmlSerializer.setSkipNamespaces(false);
        
        JSON json =   xmlSerializer.read(this.xmlBodyText);
        JSONObject jsonObject = JSONObject.fromObject(json);
        
        int toIndex = this.xmlBodyText.indexOf("<LayoutTree>");
        int frIndex = this.xmlBodyText.indexOf("</LayoutTree>");
        String layoutTreeString = this.xmlBodyText.substring(toIndex, frIndex);
        layoutTreeString += "</LayoutTree>";
        
        InputSource is = new InputSource(new StringReader(layoutTreeString));
        Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
        
        XPath xpath = XPathFactory.newInstance().newXPath();
        
        NodeList layoutGroup = (NodeList) xpath.evaluate("//*[@Orientation='Vertical']", document, XPathConstants.NODESET);
        for( int idx = 0; idx < layoutGroup.getLength(); idx++ ){
            Node layout = layoutGroup.item(idx);
            NodeList childLayoutList = layout.getChildNodes();
            
            // add Vertical css class to chilid layout
            for (int x0 = 0; x0 < childLayoutList.getLength(); x0++) {
                Node child = childLayoutList.item(x0);
                
                if (child.getNodeType() == Node.ELEMENT_NODE) {
                    Element elem = (Element) child;
                    elem.setAttribute("class", "horizontal");
                }
            }
            
            // remove Orientation attribute
            if (layout.getNodeType() == Node.ELEMENT_NODE) {
                Element elem = (Element) layout;
                elem.removeAttribute("Orientation");
            }
        }
        
        
        //////////////////////////////////////////////
        // background-color 
        //////////////////////////////////////////////
//        int colorIdx = 0;
//        String[] colors = new String[]{"red", "blue", "green", "yellow", "pink", "silver", "orange", "gray", "black", "#b0c4de", "purple", "#6495ed", "#b0c4de", "#e0ffff", "white"};
//        String backgroundColor = " background-color: ";
        //////////////////////////////////////////////
        // background-color 
        //////////////////////////////////////////////
        
        
        double weight;
        String weightStr;
        String cssClass;
        String style;
        NodeList weightGroup = (NodeList) xpath.evaluate("//*[@Weight]", document, XPathConstants.NODESET);
        for( int idx = 0; idx < weightGroup.getLength(); idx++ ){
            Node layout = weightGroup.item(idx);
            
            // remove Orientation attribute
            if (layout.getNodeType() == Node.ELEMENT_NODE) {
                Element elem = (Element) layout;
                weightStr = elem.getAttribute("Weight");
                cssClass = elem.getAttribute("class");
                
                weight = Double.valueOf(weightStr).doubleValue();
                if (weightStr.indexOf("0.") == 0) {
                    weight = weight * 100;
                }
                
                if ("horizontal".equals(cssClass)) {
                    style = "height: ";
                } else {
                    style = "width: ";
                }
                
                String bgColorStyle = "";
//                String bgColorStyle = backgroundColor + colors[colorIdx++] + ";";
                
                elem.setAttribute("style", style + Double.toString(weight) + "%;" + bgColorStyle);
                elem.removeAttribute("Weight");
            }
        }
        
        String id;
        NodeList dashboardItemGroup = (NodeList) xpath.evaluate("//*[@DashboardItem]", document, XPathConstants.NODESET);
        for( int idx = 0; idx < dashboardItemGroup.getLength(); idx++ ) {
            Node layout = dashboardItemGroup.item(idx);
            
            // remove Orientation attribute
            if (layout.getNodeType() == Node.ELEMENT_NODE) {
                Element elem = (Element) layout;
                id = elem.getAttribute("DashboardItem");
                elem.setAttribute("id", id);
                
                elem.removeAttribute("DashboardItem");
            }
        }
        
        DOMSource domSource = new DOMSource(document);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.transform(domSource, result);
        
        String documentXmlString = writer.toString();
        writer.close();
        
        documentXmlString = documentXmlString.replaceAll("<\\?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"\\?>", "");
        documentXmlString = documentXmlString.replaceAll("<LayoutTree>", "");
        documentXmlString = documentXmlString.replaceAll("</LayoutTree>", "");
        documentXmlString = documentXmlString.replaceAll("LayoutGroup", "div");
        documentXmlString = documentXmlString.replaceAll("LayoutItem", "div");
        documentXmlString = documentXmlString.replaceAll("<div>", "<div class=\"no-bpm\">");
        
        logger.debug(documentXmlString);
        
        documentXmlString = documentXmlString.replaceAll("\r", "");
        documentXmlString = documentXmlString.replaceAll("\n", "");
        
        jsonObject.getJSONObject("Dashboard").put("LayoutTreeHtml", documentXmlString);
        
        logger.debug(jsonObject.toString());  
          
        return jsonObject;
    }
    
    public String getXmlBodyText() {
        return xmlBodyText;
    }
    
}
