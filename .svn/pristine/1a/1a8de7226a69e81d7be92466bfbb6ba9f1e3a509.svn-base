package com.wise.common.secure;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class AES256Cipher {
    private static volatile AES256Cipher INSTANCE;

    final static String secretKey = "wiseitech_witeam"; // 32bit
    static String IV = ""; // 16bit

    public static AES256Cipher getInstance() {
        if (INSTANCE == null) {
            synchronized (AES256Cipher.class) {
                if (INSTANCE == null)
                    INSTANCE = new AES256Cipher();
            }
        }
        return INSTANCE;
    }

    private AES256Cipher() {
        IV = secretKey.substring(0, 16);
    }

    // 암호화
    public static String AES_Encode(String str)
            throws java.io.UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] keyData = secretKey.getBytes();

        SecretKey secureKey = new SecretKeySpec(keyData, "AES");

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, secureKey, new IvParameterSpec(IV.getBytes()));

        byte[] encrypted = c.doFinal(str.getBytes("UTF-8"));
        String enStr = new String(Base64.encodeBase64(encrypted));

        return enStr;
    }

    public static String encryptAESMD5(String keyStr, String strText) {
    	String retVal = "";
    	Key key;
    	try {
    		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

    		MessageDigest md5 = MessageDigest.getInstance("MD5");
    		key = new SecretKeySpec(md5.digest(keyStr.getBytes("UTF-8")), "AES");
    		cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(md5.digest(keyStr.getBytes("UTF-8"))));

    		byte[] encrypted = cipher.doFinal(strText.getBytes("UTF-8"));
    		retVal = new String(Base64.encodeBase64(encrypted));
    	} catch (Exception e) {
    		retVal = "";
    	}
    	
    	return retVal;
    }
    
    public static String decryptAESMD5(String strText) {
    	String retVal = "";
    	Key key;
    	try {
    		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

    		MessageDigest md5 = MessageDigest.getInstance("MD5");
    		key = new SecretKeySpec(md5.digest(secretKey.getBytes("UTF-8")), "AES");
    		cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(md5.digest(IV.getBytes("UTF-8"))));

    		byte[] decrypted = cipher.doFinal(Base64.decodeBase64(strText));
    		retVal = new String(decrypted);
    	} catch (Exception e) {
    		retVal = "";
    	}
    	
    	return retVal;
    }
    
    // 복호화
    public static String AES_Decode(String str)
            throws java.io.UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] keyData = secretKey.getBytes();
        SecretKey secureKey = new SecretKeySpec(keyData, "AES");
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, secureKey, new IvParameterSpec(IV.getBytes("UTF-8")));

        byte[] byteStr = Base64.decodeBase64(str.getBytes());

        return new String(c.doFinal(byteStr), "UTF-8");
    }
    
    public static void main(String[] args) throws InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    	AES256Cipher a256 = AES256Cipher.getInstance();
		String userId = a256.decryptAESMD5("nHK7cqYzZgD94Y8REejXTw==");
		System.out.println(userId);
	}	
}