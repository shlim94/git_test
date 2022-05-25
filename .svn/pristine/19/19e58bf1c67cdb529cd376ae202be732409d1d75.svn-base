package com.wise.ds.util;

import net.sf.json.JSONObject;

import org.hyperic.sigar.CpuPerc;
import org.hyperic.sigar.FileSystemUsage;
import org.hyperic.sigar.Mem;
import org.hyperic.sigar.OperatingSystem;
import org.hyperic.sigar.Sigar;

import javax.servlet.http.HttpServletRequest;

public class WiseResource {
	public JSONObject showOS() {
		JSONObject obj = new JSONObject();
		JSONObject OSobj = new JSONObject();
		
		Sigar sigar = null;
		try {
			sigar = new Sigar();
			OperatingSystem sys = OperatingSystem.getInstance();
			CpuPerc cpu = sigar.getCpuPerc();
			Mem mem = sigar.getMem();
			String os = sys.getName();
			FileSystemUsage disk = sigar.getFileSystemUsage((os.equals("Win32"))?"C:\\":"/");

			OSobj.put("OS Name", os);
	
			OSobj.put("cpu", (1-cpu.getIdle()));
			OSobj.put("TotalMem", toGB(mem.getTotal()));
			OSobj.put("FreeMem", toGB(mem.getFree()));
			OSobj.put("PerMem", mem.getUsedPercent());
	
			OSobj.put("TotalSpace", toDiskGB(disk.getTotal()));
			OSobj.put("UsingSpace", toDiskGB(disk.getUsed()));
			OSobj.put("FreeSpace", toDiskGB(disk.getAvail()));
			OSobj.put("PerSpace", disk.getUsePercent());
			
			OSobj.put("IO Read", Sigar.formatSize(disk.getDiskReadBytes()));
			OSobj.put("IO Write", Sigar.formatSize(disk.getDiskWriteBytes()));
			
			obj.put("OSobj", OSobj);
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if(sigar!=null) sigar.close();
		}
		return obj;
	}

	private String toGB(long size) {
		return String.format("%.1f (GB)", (float) size / (1024 * 1024 * 1024));
	}
	
	private String toDiskGB(long size) {
		return String.format("%.1f (GB)", (float) size / (1024 * 1024));
	}
	

	public String getClientIP(HttpServletRequest request) {
//		String ip = request.getHeader("X-Forwarded-For");
//        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
//            ip = request.getHeader("Proxy-Client-IP"); 
//        } 
//        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
//            ip = request.getHeader("WL-Proxy-Client-IP"); 
//        } 
//        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
//            ip = request.getHeader("HTTP_CLIENT_IP"); 
//        } 
//        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
//            ip = request.getHeader("HTTP_X_FORWARDED_FOR"); 
//        } 
//        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) { 
//            ip = request.getRemoteAddr(); 
//        }
		String ip = request.getHeader("X-FORWARDED-FOR");
		if (ip == null)
			ip = request.getRemoteAddr();
		return ip;
	}
}
