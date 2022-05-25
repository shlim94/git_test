package com.wise.sso.controller;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;

/**
* @package kr.or.keis.system.web.crypt;
* @className CryptoUtil.java
* @description 프로그램적으로 스트링을 Base64 방식으로 인코딩 및 디코딩하는 클래스 
* @author 개발팀
* @since 2020.12.01
* @version 1.0
* 
* @Copyright (c) 2020 한국고용정보원, 메타넷대우정보컨소시엄 All rights reserved.
* @see
* <pre>
*  == 개정이력(Modification Information) ==
*  수정일         	수정자       	수정내용
*  -----------  	--------  		----------------------
*  2020.02.22		한윤수			최초 생성
* 
 */
public class CryptoUtil {
    
    private final static Log logger = LogFactory.getLog(CryptoUtil.class);
    
    @Value("#{sysProp['sys.system.salt.string']}")
	private static String saltString;

    public static String encodeBinary(byte[] data) throws Exception {
    	if (data == null) return "";
    	return new String(Base64.encodeBase64(data));
    }
    
    /**
     * 데이터를 암호화하는 기능
     * 
     * @param String data 암호화할 데이터
     * @return String result 암호화된 데이터
     * @exception Exception
     */
    public static String encode(String data) throws Exception {
    	return encodeBinary(data.getBytes());
    }
    
    /**
     * 데이터를 복호화하는 기능
     * 
     * @param String data 복호화할 데이터
     * @return String result 복호화된 데이터
     * @exception Exception
     */
    public static byte[] decodeBinary(String data) throws Exception {
    	if(data == null){
    		return null;
    	}else{
    		return Base64.decodeBase64(data.getBytes());
    	}
    }

    /**
     * 데이터를 복호화하는 기능
     * 
     * @param String data 복호화할 데이터
     * @return String result 복호화된 데이터
     * @exception Exception
     */
    public static String decode(String data) throws Exception {
    	if(data == null){
    		return null;
    	}else{
    		return new String(decodeBinary(data));
    	}
    }
    
    /**
     * 데이터를 암호화하는 기능URLEncoder.encode을 한번 더 함 
     * 
     * @param String data 암호화할 데이터
     * @return String result 암호화된 데이터
     * @exception Exception
     */
    public static String encodeURL(String data){
    	try {
			return URLEncoder.encode( encodeBinary(data.getBytes()), "UTF-8" );
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage(), e.getCause());
		} catch (Exception e) {
			throw new RuntimeException(e.getMessage(), e.getCause());
		}
    }
	
    /**
     * SALT 문자와 SHA-256 방식을 이용하여 단방향 패스워드 생성한다.
     *
     * @param str 패스워드 문자열
     * @return String
     */
    public static String getOneWayPassword(String password){
    	if (password == null || password.equals("")) return password;
	
    	MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.getMessage(), e.getCause());
		}
    	md.update((saltString+password).getBytes());
    	byte byteData[] = md.digest();

    	//convert the byte to hex format method 1
    	StringBuffer sb = new StringBuffer();
    	for (int i = 0; i < byteData.length; i++) {
    		sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
    	}
    	return sb.toString();
    }
}