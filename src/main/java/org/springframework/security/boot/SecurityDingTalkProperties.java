package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkAuthcProperties;

@ConfigurationProperties(prefix = SecurityDingTalkProperties.PREFIX)
public class SecurityDingTalkProperties {

	public static final String PREFIX = "spring.security.dingtalk";

	/** Whether Enable JWT Authentication. */
	private boolean enabled = false;
	
	private String accessKey;
	private String accessSecret;
	private String accessToken;
	
	/**
	 * 扫描登陆通过临时授权码获取用基本信息的接口地址
	 * https://open-doc.dingtalk.com/microapp/serverapi2/kymkv6
	 */
	private String userInfoURL = "https://oapi.dingtalk.com/sns/getuserinfo_bycode";
	/**
	 * 获取用户详情的接口地址
	 * https://open-doc.dingtalk.com/microapp/serverapi2/ege851
	 */
	private String userDetailURL = "https://oapi.dingtalk.com/user/get";
	
	
	@NestedConfigurationProperty
	private SecurityDingTalkAuthcProperties authc = new SecurityDingTalkAuthcProperties();
	
	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public SecurityDingTalkAuthcProperties getAuthc() {
		return authc;
	}

	public void setAuthc(SecurityDingTalkAuthcProperties authc) {
		this.authc = authc;
	}

	public String getAccessKey() {
		return accessKey;
	}

	public void setAccessKey(String accessKey) {
		this.accessKey = accessKey;
	}

	public String getAccessSecret() {
		return accessSecret;
	}

	public void setAccessSecret(String accessSecret) {
		this.accessSecret = accessSecret;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

	public String getUserInfoURL() {
		return userInfoURL;
	}

	public void setUserInfoURL(String userInfoURL) {
		this.userInfoURL = userInfoURL;
	}

	public String getUserDetailURL() {
		return userDetailURL;
	}

	public void setUserDetailURL(String userDetailURL) {
		this.userDetailURL = userDetailURL;
	}
	
}
