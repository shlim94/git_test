package com.wise.common.secure;

import java.util.Random;

import javaxt.utils.Date;

public class SecureKeyGenerator {
    private int round;
    private String userKey; // 16bit 문자열  
    private String secureKey;
    
    public SecureKeyGenerator() {
    }
    
    public SecureKeyGenerator(int round) {
        this.round = round;
    }
    
    public void generateSecureKey() {
        this.secureKey = SecureUtils.encode(this.userKey, this.round);
    }

    public void generateRandomUserKey() {
        this.userKey = "";
        Random r = new Random();
        r.setSeed(new Date().getTime());
        for (int i = 0; i < 16; i++) {
            this.userKey += Long.toHexString(Math.round((r.nextInt()%6+1) * 15));
        }
    }
    
    public int getRound() {
        return round;
    }

    public void setRound(int round) {
        this.round = round;
    }

    public String getUserKey() {
        return userKey;
    }

    public void setUserKey(String userKey) {
        this.userKey = userKey;
    }

    public String getSecureKey() {
        return secureKey;
    }

    public void setSecureKey(String secureKey) {
        this.secureKey = secureKey;
    }

}
