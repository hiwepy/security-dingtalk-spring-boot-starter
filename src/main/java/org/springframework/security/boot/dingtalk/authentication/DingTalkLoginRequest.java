package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class DingTalkLoginRequest {
	
	/**
	 * 	应用的唯一标识key
	 */
	private String appId;
	private String code;
    private String loginTmpCode;
    
    @JsonCreator
    public DingTalkLoginRequest(@JsonProperty("appId") String appId, @JsonProperty("code") String code,  @JsonProperty("loginTmpCode") String loginTmpCode) {
        this.appId = appId;
        this.code = code;
        this.loginTmpCode = loginTmpCode;
    }

	public String getAppId() {
		return appId;
	}

	public void setAppId(String appId) {
		this.appId = appId;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getLoginTmpCode() {
		return loginTmpCode;
	}

	public void setLoginTmpCode(String loginTmpCode) {
		this.loginTmpCode = loginTmpCode;
	}
	
}
