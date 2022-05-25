package com.wise.common.util;

import java.io.Serializable;
import java.sql.Date;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.concurrent.TimeUnit;



public class Timer implements Serializable {
    private static final long serialVersionUID = 2094259851827019547L;
    
    private String interval; // 04:11:15 등의 경과 시간 문자열이 저장될 버퍼 정의
    private long startTime; // 타이머가 ON 되었을 때의 시각을 기억하고 있는 변수
    private long finishTime;
    private int difference;
    
    private String intervalLong; //길게 세팅 04:11:15.1111
    private long differenceLong; 
    
    public void start() {
        this.stopwatch(1);
    }
    
    public void stop() {
        this.stopwatch(0);
    }

    private void stopwatch(int onOff) {
        if (onOff == 1) // 타이머 켜기
            this.startTime = System.currentTimeMillis();

        if (onOff == 0) {
            this.finishTime = System.currentTimeMillis();
            this.difference = ((int) this.finishTime / 1000) - ((int) this.startTime / 1000);
//            secToHHMMSS(((int) this.finishTime / 1000) - ((int) this.startTime / 1000));
            this.differenceLong = this.finishTime - this.startTime;
            secToHHMMSS(this.difference);
        }
    }

    // 정수로 된 시간을 초단위(sec)로 입력 받아, "04:11:15" 등의 형식의 문자열로 시분초를 저장
    public void secToHHMMSS(int secs) {
        int hour, min, sec;

        sec = secs % 60;
        min = secs / 60 % 60;
        hour = secs / 3600;
        
        this.interval = String.format("%02d:%02d:%02d", hour, min, sec);
    }
//    public void secToHHMMSS(long elapseTime) {
//        long hours = elapseTime / 3600;
//        long minute = elapseTime % 3600 / 60;
//        long second = elapseTime % 3600 % 60;
//
//        this.interval = String.format("%02d:%02d:%02d", hours, minute, second);
//    }

    public String getInterval() {
    	int seconds = (int) (this.differenceLong / 1000) % 60 ;
    	int minutes = (int) ((this.differenceLong / (1000*60)) % 60);
    	int hours   = (int) ((this.differenceLong / (1000*60*60)) % 24);
    	
    	String intervalLong = String.format("%02d:%02d:%02d.%03d", hours, minutes, seconds,(this.differenceLong%1000));
        return intervalLong;
    }
    
    public int getInterval(String checker) {
        return ((int) this.finishTime / 1000) - ((int) this.startTime / 1000);
    }
    
    public void interval() {
        System.out.format("Timer OFF! 경과 시간: [%s]%n", this.interval); // 경과 시간 화면에 출력
    }
    
    public long getStartTime() {
        return startTime;
    }

    public long getFinishTime() {
        return finishTime;
    }

    public int getDifference() {
        return difference;
    }

    public static Timestamp formatTime(long timestamp) {
        return new Timestamp(timestamp);
//        Calendar c = Calendar.getInstance();
//        c.setTimeInMillis(timestamp);
//        return (c.get(Calendar.HOUR_OF_DAY) + "시 " + c.get(Calendar.MINUTE) + "분 " + c.get(Calendar.SECOND) + "." + c.get(Calendar.MILLISECOND) + "초");
    }
    
    public static void main(String[] s) {
        Timer timer = new Timer();
        timer.secToHHMMSS(1330/1000);
        System.out.println(timer.getInterval());
    }

}
