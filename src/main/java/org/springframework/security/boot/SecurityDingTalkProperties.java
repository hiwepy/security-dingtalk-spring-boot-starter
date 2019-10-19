package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityRedirectProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkAuthcProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityDingTalkProperties.PREFIX)
@Getter
@Setter
@ToString
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

}
