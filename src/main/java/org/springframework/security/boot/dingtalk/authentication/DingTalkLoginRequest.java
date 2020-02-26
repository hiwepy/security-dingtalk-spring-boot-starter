package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class DingTalkLoginRequest {
	
	private String code;
    private String loginTmpCode;
    
    @JsonCreator
    public DingTalkLoginRequest(@JsonProperty("code") String code, @JsonProperty("loginTmpCode") String loginTmpCode) {
        this.code = code;
        this.loginTmpCode = loginTmpCode;
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
