package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 *	 微应用免登授权
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class DingTalkMpLoginRequest {
	
	/**
	 * 	应用的唯一标识key
	 */
	private String key;
	private String code;
    private String loginTmpCode;
    
    @JsonCreator
    public DingTalkMpLoginRequest(@JsonProperty("key") String key, @JsonProperty("code") String code,  @JsonProperty("loginTmpCode") String loginTmpCode) {
        this.key = key;
        this.code = code;
        this.loginTmpCode = loginTmpCode;
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

	public String getLoginTmpCode() {
		return loginTmpCode;
	}

	public void setLoginTmpCode(String loginTmpCode) {
		this.loginTmpCode = loginTmpCode;
	}
	
}
