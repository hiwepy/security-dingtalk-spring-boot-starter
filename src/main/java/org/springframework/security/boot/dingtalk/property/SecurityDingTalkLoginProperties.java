package org.springframework.security.boot.dingtalk.property;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * 	移动接入应用：扫码登录配置
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class SecurityDingTalkLoginProperties {

	/**
	 * 	移动接入应用-扫码登录应用的appId
	 */
	private String appId;
	/**
	 * 	移动接入应用-扫码登录应用的appSecret
	 */
	private String appSecret;

}
