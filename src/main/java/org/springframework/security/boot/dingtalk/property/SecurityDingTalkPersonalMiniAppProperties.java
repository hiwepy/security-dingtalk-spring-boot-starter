package org.springframework.security.boot.dingtalk.property;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 *	第三方个人应用：小程序配置
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class SecurityDingTalkPersonalMiniAppProperties {

	/**
	 * 	AppId：每一个个人应用都会分配一个AppId，该AppId是个人应用开发过程中的唯一性标识，用来获取登录用户授权的access_token
	 */
	private String appId;
	/**
	 * 	AppSecret：每一个个人应用都会分配一个AppSecret，AppSecret可用来获取登录用户授权的access_token
	 */
	private String appSecret;

}
