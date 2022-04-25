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
	protected String authCode;
	/**
	 * Access Token
	 */
	protected String accessToken;
	
	@JsonIgnoreProperties(ignoreUnknown = true)
    @JsonCreator
    public DingTalkMaLoginRequest(@JsonProperty("key") String key,
    		@JsonProperty("authCode") String authCode) {
        this.key = key;
        this.authCode = authCode;
    }

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getAuthCode() {
		return authCode;
	}

	public void setAuthCode(String authCode) {
		this.authCode = authCode;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	
}
