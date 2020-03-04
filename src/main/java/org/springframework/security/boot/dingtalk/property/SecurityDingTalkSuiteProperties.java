package org.springframework.security.boot.dingtalk.property;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * 	第三方企业应用：小程序、H5配置
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class SecurityDingTalkSuiteProperties {

	/**
	 * 	第三方企业应用：程序客户端ID
	 */
	private String suiteId;
	/**
	 * 	第三方企业应用：应用的唯一标识key
	 */
	private String appId;
	/**
	 * 	第三方企业应用：应用的唯一标识key
	 */
	private String suiteKey;
	/**
	 *	第三方企业应用：应用的密钥
	 */
	private String suiteSecret;

}
