package com.wise.common.secure;

import org.bouncycastle.util.encoders.Base64;

import com.wise.context.config.Configurator;


public class SecureUtilsTestor {
    
    public static void testEncriptModule() throws Exception {
        Configurator.Constants.SEED_CBC_ENCRIPTION_KEY_ROUND = 5;
        
        // 1) 랜덤으로 user key를 생성하는 예제
        SecureKeyGenerator keyGenerator = new SecureKeyGenerator(Configurator.Constants.SEED_CBC_ENCRIPTION_KEY_ROUND);
        keyGenerator.generateRandomUserKey(); // 1) 사용자 키를 랜덤 생성
        keyGenerator.generateSecureKey(); // 2) 1)에서 생성된 사용자 키를 이용하여 secure key 생성
        String userKey = keyGenerator.getUserKey();
        String secureKey = keyGenerator.getSecureKey();
        System.out.println("user key : " + userKey);
        System.out.println("secure key : " + secureKey);
        System.out.println();
        
        // 2) 1)에서 생성된 user key와 secure key를 이용한 암/복호화 예제
        String plainText = "jdbc:sqlserver://14.63.168.64:31433;DatabaseName=WISE.BI.R4";
//        String plainText = "jdbc:sqlserver://14.63.168.64:31433;DatabaseName=WISE.BI.R4.T";
        String cipherText = SecureUtils.encSeed(secureKey, plainText);
        System.out.println("plain text : " + plainText);
        System.out.println("cipher text : " + cipherText);
        
        String decText = SecureUtils.decSeed(secureKey, cipherText);
        System.out.println("decode text : " + decText);
        System.out.println();
        
        // 3) web-application.xml 에 등록되어 있는 secure key를 이용한 예제
        System.out.println("---------------------------------------------------------------------------");
        keyGenerator = new SecureKeyGenerator(Configurator.Constants.SEED_CBC_ENCRIPTION_KEY_ROUND);
//        keyGenerator.setUserKey("8074212aa995900a");
//        keyGenerator.generateSecureKey();
        keyGenerator.setSecureKey("Vm10UzNRMVV4Um5KTlNHUlBWbFphVlZZd1pHOVVNV3h6Vm0xR2FVMVdSalJXVnpWTFZHeGFWV0pHV2xaV2JXaHlWako0WVZKdFJYcGlSbFpYWVRGVk1WWlZXa1pQVmtKU1VGUXdQUT09");
        secureKey = keyGenerator.getSecureKey();
        System.out.println("user key : " + keyGenerator.getUserKey());
        System.out.println("secure key : " + secureKey);
        System.out.println();
        
        plainText = "jdbc:sqlserver://14.63.168.64:31433;DatabaseName=WISE.BI.R4";
        plainText = "jdbc:jtds:sqlserver://14.63.168.64:31433/WISE.BI.R4";
//        plainText = "jdbc:sqlserver://14.63.168.64:31433;DatabaseName=WISE.BI.R4.T";
        cipherText = SecureUtils.encSeed(secureKey, plainText);
        System.out.println("plain text : " + plainText);
        System.out.println("cipher text : " + cipherText);
        
        decText = SecureUtils.decSeed(secureKey, cipherText);
        System.out.println("decode text : " + decText);
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
      
//        SecureUtilsTestor.testEncriptModule();
        
        String base64 = "GPfKA1t6bDzvI5uSH01nE4m57c+wEzILwEJHVAytFMGdv2xkQbWczT47o4jhJ6KMLB0F9TlpI1ibPYJgbQECh+cPA++4PwndnF6Y6DeqFKujQaZr2nlGF3EOTJyheaSJEcp332XZwdTRNffCPDjuwwnDkNMD1dV8HjtwELQCDYg=";
        System.out.println(new String(Base64.decode(base64)));
      
    }

}
