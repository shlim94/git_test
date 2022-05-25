package com.wise.ds.query.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class TossExecutor extends Thread{
	public String execPath;
	public String returnLine = "";
	public long startTime;
	
	public TossExecutor(String execPath) {
		this.execPath = execPath;
	}

	@Override
	public void run() {
		Process p;
		String line = "";
		try {
			p = Runtime.getRuntime().exec(execPath);
			p.getInputStream().close();
			p.getOutputStream().close();
			
			BufferedReader processRun = new BufferedReader(new InputStreamReader(p.getErrorStream()));
			p.waitFor();
			while((line = processRun.readLine()) != null){
				returnLine = line;
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException ie) {
			ie.printStackTrace();
		}
	}

	public String getReturnLine() {
		return returnLine;
	}
}
