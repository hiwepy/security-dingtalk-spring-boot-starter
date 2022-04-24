package org.springframework.security.boot.dingtalk.authentication;

import com.dingtalk.api.response.OapiUserGetResponse;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 企业内部应用免登、第三方企业应用免登、应用管理后台免登
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DingTalkTmpCodeLoginRequest {
	
	/**
	 * 	应用的唯一标识key
	 */
	protected String key;
	/**
	 * 临时登录凭证code
	 */
	protected String code;
	/**
	 * Access Token
	 */
	protected String accessToken;
    
	@JsonIgnoreProperties(ignoreUnknown = true)
    @JsonCreator
    public DingTalkTmpCodeLoginRequest(@JsonProperty("key") String key, 
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

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
