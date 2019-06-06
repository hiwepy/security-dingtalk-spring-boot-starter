package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class DingTalkLoginRequest {
	
    private String loginTmpCode;

    @JsonCreator
    public DingTalkLoginRequest(@JsonProperty("loginTmpCode") String loginTmpCode) {
        this.loginTmpCode = loginTmpCode;
    }

	public String getLoginTmpCode() {
		return loginTmpCode;
	}

	public void setLoginTmpCode(String loginTmpCode) {
		this.loginTmpCode = loginTmpCode;
	}
	
}
