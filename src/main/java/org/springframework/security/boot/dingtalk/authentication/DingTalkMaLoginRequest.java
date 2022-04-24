package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DingTalkMaLoginRequest {
	
	/**
	 * 	应用的唯一标识key
	 */
	protected String key;
	/**
	 * 临时登录凭证code
	 */
	protected String code;
	
	@JsonIgnoreProperties(ignoreUnknown = true)
    @JsonCreator
    public DingTalkMaLoginRequest(@JsonProperty("key") String key,
    		@JsonProperty("code") String code) {
        this.key = key;
        this.code = code;
    }

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}
	
}
