package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityRedirectProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkAuthcProperties;

@ConfigurationProperties(prefix = SecurityDingTalkProperties.PREFIX)
public class SecurityDingTalkProperties {

	public static final String PREFIX = "spring.security.dingtalk";

	/** Whether Enable DingTalk Authentication. */
	private boolean enabled = false;

	/**
	 * 移动接入应用-扫码登录应用的appId
	 */
	private String accessKey;
	/**
	 * 移动接入应用-扫码登录应用的appSecret
	 */
	private String accessSecret;
	/**
	 * 企业内部开发：程序客户端ID
	 */
	private String agentId;
	/**
	 * 企业内部开发：应用的唯一标识key
	 */
	private String appKey;
	/**
	 * 企业内部开发：应用的密钥
	 */
	private String appSecret;
	/**
	 * 企业ID
	 */
	private String corpId;

	@NestedConfigurationProperty
	private SecurityDingTalkAuthcProperties authc = new SecurityDingTalkAuthcProperties();
	@NestedConfigurationProperty
	private SecurityRedirectProperties redirect = new SecurityRedirectProperties();

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

	/**
	 * 移动接入应用-扫码登录应用的appId
	 */
	public String getAccessKey() {
		return accessKey;
	}

	/**
	 * 移动接入应用-扫码登录应用的appSecret
	 */
	public String getAccessSecret() {
		return accessSecret;
	}

	public void setAccessKey(String accessKey) {
		this.accessKey = accessKey;
	}

	public void setAccessSecret(String accessSecret) {
		this.accessSecret = accessSecret;
	}

	public String getAgentId() {
		return agentId;
	}

	/**
	 * 企业内部开发：应用的唯一标识key
	 */
	public String getAppKey() {
		return appKey;
	}

	/**
	 * 企业内部开发：应用的密钥
	 */
	public String getAppSecret() {
		return appSecret;
	}

	public String getCorpId() {
		return corpId;
	}

	public void setAgentId(String agentId) {
		this.agentId = agentId;
	}

	public void setAppKey(String appKey) {
		this.appKey = appKey;
	}

	public void setAppSecret(String appSecret) {
		this.appSecret = appSecret;
	}

	public void setCorpId(String corpId) {
		this.corpId = corpId;
	}

	public SecurityRedirectProperties getRedirect() {
		return redirect;
	}

	public void setRedirect(SecurityRedirectProperties redirect) {
		this.redirect = redirect;
	}

}
