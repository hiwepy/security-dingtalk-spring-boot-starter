package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 第三方系统钉钉扫码登录授权
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class DingTalkTmpCodeLoginRequest {
	
	/**
	 * 	应用的唯一标识key
	 */
	private String key;
    private String loginTmpCode;
    
    @JsonCreator
    public DingTalkTmpCodeLoginRequest(@JsonProperty("key") String key, @JsonProperty("loginTmpCode") String loginTmpCode) {
        this.key = key;
        this.loginTmpCode = loginTmpCode;
    }

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getLoginTmpCode() {
		return loginTmpCode;
	}

	public void setLoginTmpCode(String loginTmpCode) {
		this.loginTmpCode = loginTmpCode;
	}
	
}
