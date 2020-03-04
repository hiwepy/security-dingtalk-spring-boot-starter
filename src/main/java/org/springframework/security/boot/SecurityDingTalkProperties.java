package org.springframework.security.boot;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkCropAppProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkLoginProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkPersonalMiniAppProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkSuiteProperties;

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
	 * 	企业ID
	 */
	private String corpId;
	
	/**
	 *    企业内部开发：小程序、H5配置
	 */
	private List<SecurityDingTalkCropAppProperties> cropApps;
	/**
	 *    第三方个人应用：小程序配置
	 */
	private List<SecurityDingTalkPersonalMiniAppProperties> apps;
	/**
	 * 	第三方企业应用：小程序、H5配置
	 */
	private List<SecurityDingTalkSuiteProperties> suites;
	/**
	 *	 移动接入应用：扫码登录配置
	 */
	private List<SecurityDingTalkLoginProperties> logins;
	
}
