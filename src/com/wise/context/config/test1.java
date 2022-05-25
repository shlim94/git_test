//package com.wise.context.config;
//
//import java.io.UnsupportedEncodingException;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//
//import javax.crypto.BadPaddingException;
//import javax.crypto.Cipher;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.spec.IvParameterSpec;
//import javax.crypto.spec.SecretKeySpec;
//
//import com.wise.common.exception.InvalidBase64Exception;
//
//public class test1 {
//	private static String keyStr = "12345";
//	private static Cipher cipher = null;
//	private static SecretKeySpec key = null;
//	private static IvParameterSpec iniVec = null;
//	
//	public static void main(String[] args) {
//		// TODO Auto-generated method stub
//		
////		System.out.println(encrypt("admin1111"));
//	}
//	
//	public test1(String keyStr) {
////		// Create a AES algorithm.
//		
//	}
//
//	/**
//	 * Encrypts a string.
//	 * 
//	 * @param value A string to encrypt. It is converted into UTF-8 before being encrypted.
//	 *              Null is regarded as an empty string.
//	 * @return An encrypted string.
//	 * @throws NoSuchPaddingException 
//	 * @throws NoSuchAlgorithmException 
//	 * @throws UnsupportedEncodingException 
//	 * @throws InvalidAlgorithmParameterException 
//	 * @throws InvalidKeyException 
//	 * @throws BadPaddingException 
//	 * @throws IllegalBlockSizeException 
//	 */
//	public static String encrypt(String value) throws 
//		NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, 
//		InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
//		
//		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//
//		// Initialize an encryption key and an initial vector.
//		MessageDigest md5 = MessageDigest.getInstance("MD5");
//		key = new SecretKeySpec(md5.digest(keyStr.getBytes("UTF8")), "AES");
//		iniVec = new IvParameterSpec(md5.digest(keyStr.getBytes("UTF8")));
////		System.out.println(new String (md5.digest(keyStr.getBytes("UTF8"))));
////		System.out.println(new String (key.getAlgorithm()));
//		//System.out.println(Base64Coder.encode(iniVec.getIV()));
//		
//		if (value == null)
//			value = "";
//
//		// Initialize the cryptography algorithm.
//		cipher.init(Cipher.ENCRYPT_MODE, key, iniVec);
//
//		// Get a UTF-8 byte array from a unicode string.
//		byte[] utf8Value = value.getBytes("UTF8");
//
//		// Encrypt the UTF-8 byte array.
//		byte[] encryptedValue = cipher.doFinal(utf8Value);
//
//		// Return a base64 encoded string of the encrypted byte array.
//		//return new  String( Base64Coder.encode(encryptedValue));	
//		return Base64Encoder.encode(encryptedValue);		
//	}
//
//	/**
//	 * Decrypts a string which is encrypted with the same key and initial vector. 
//	 * 
//	 * @param value A string to decrypt. It must be a string encrypted with the same key and initial vector.
//	 *              Null or an empty string is not allowed.
//	 * @return A decrypted string
//	 * @throws InvalidAlgorithmParameterException 
//	 * @throws InvalidKeyException 
//	 * @throws InvalidBase64Exception 
//	 * @throws BadPaddingException 
//	 * @throws IllegalBlockSizeException 
//	 * @throws UnsupportedEncodingException 
//	 */
//	public String decrypt(String value) throws 
//		IllegalArgumentException, InvalidKeyException, InvalidAlgorithmParameterException, 
//		InvalidBase64Exception, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
//		if (value == null || value.equals(""))
//			throw new IllegalArgumentException("The cipher string can not be null or an empty string.");
//
//		// Initialize the cryptography algorithm.
//		cipher.init(Cipher.DECRYPT_MODE, key, iniVec);
//
//		// Get an encrypted byte array from a base64 encoded string.
//		byte[] encryptedValue = Base64Encoder.decode(value);
//
//		// Decrypt the byte array.
//		byte[] decryptedValue = cipher.doFinal(encryptedValue);
//
//		// Return a string converted from the UTF-8 byte array.
//		return new String(decryptedValue, "UTF8");
//	}
//}
//
//
