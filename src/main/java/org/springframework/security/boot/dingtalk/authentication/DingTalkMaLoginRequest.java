package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DingTalkMaLoginRequest {
	
	/**
	 * 应用的唯一标识key
	 */
	protected String key;
	/**
	 * 临时登录凭证code
	 */
	protected String authCode;
	/**
	 * 	当前请求使用的token，用于绑定用户
	 */
	protected String token;
	/**
	 * Access Token
	 */
	protected String accessToken;
	
	@JsonIgnoreProperties(ignoreUnknown = true)
    @JsonCreator
    public DingTalkMaLoginRequest(@JsonProperty("key") String key,
								  @JsonProperty("token") String token,
								  @JsonProperty("authCode") String authCode) {
        this.key = key;
		this.token = token;
        this.authCode = authCode;
    }

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
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
