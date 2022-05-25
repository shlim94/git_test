package com.wise.sso.controller;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.CharEncoding;
import org.apache.commons.codec.binary.Base64;

public class AesCrypto {

	public static String encrypt(int keySize, String key, String str) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			byte[] encKey = null;
			if(keySize==128) encKey = encMD(key, "MD5");
			else encKey = encMD(key, "SHA-256");

			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(encKey));
			
			byte[] encrypted = cipher.doFinal(str.getBytes(CharEncoding.UTF_8));
			byte[] base64Encoded = Base64.encodeBase64(encrypted);
			String result = new String(base64Encoded, CharEncoding.UTF_8);

			return result;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static String decrypt(int keySize, String key, String str) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			byte[] encKey = null;
			if(keySize==128) encKey = encMD(key, "MD5");
			else encKey = encMD(key, "SHA-256");
			
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(encKey));

			byte[] base64Decoded = Base64.decodeBase64(str.getBytes(CharEncoding.UTF_8));
			byte[] decrypted = cipher.doFinal(base64Decoded);

			String result = new String(decrypted, CharEncoding.UTF_8);

			return result;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	public static byte[] encMD(String str, String type) {
		byte byteData[] = null; 
		try{
			MessageDigest md = MessageDigest.getInstance(type); 
			md.update(str.getBytes()); 
			byteData = md.digest();
		}catch(Exception e){
			e.printStackTrace(); 
		}
		return byteData;
	}

	public static void main(String[] args) {
		System.out.println(encrypt(256, "wiseitech_witeam", "bskim"));
		//System.out.println(decrypt(128, "wiseitech_ftc", "trsn0y+0VSfI8EynHzAD+A=="));
		//System.out.println(encrypt(256, "wiseitech_ftc", "g552"));
		//System.out.println(decrypt(256, "wiseitech_ftc", "6PONH4cRzF2bsK7QOCL8kfJ1Trfk9+aRtnw1LWrHHkc="));
	}	
}
