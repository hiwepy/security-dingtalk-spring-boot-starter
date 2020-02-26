package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class DingTalkLoginRequest {
	
    private String code;
    
    @JsonCreator
    public DingTalkLoginRequest(@JsonProperty("code") String code) {
        this.code = code;
    }

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}
	
}
