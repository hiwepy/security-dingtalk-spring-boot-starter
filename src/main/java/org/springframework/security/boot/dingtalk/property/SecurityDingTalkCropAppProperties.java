package org.springframework.security.boot.dingtalk.property;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 *	 企业内部开发：小程序、H5配置
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@Getter
@Setter
@ToString
public class SecurityDingTalkCropAppProperties {

	/**
	 * 	企业内部开发：程序客户端ID
	 */
	private String agentId;
	/**
	 * 	企业内部开发：应用的唯一标识key
	 */
	private String appKey;
	/**
	 * 	企业内部开发：应用的密钥
	 */
	private String appSecret;

}
