package org.springframework.security.boot;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.userdetails.AuthcUserDetailsService;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationEntryPoint;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationFailureHandler;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationProvider;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityDingTalkProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityDingTalkProperties.class })
public class SecurityDingTalkAutoConfiguration{

	@Autowired
	private SecurityDingTalkProperties dingtalkProperties;
	
	@Bean("dingtalkSessionAuthenticationStrategy")
	@ConditionalOnMissingBean(name = "dingtalkSessionAuthenticationStrategy")
	public SessionAuthenticationStrategy dingtalkSessionAuthenticationStrategy() {
		return new NullAuthenticatedSessionStrategy();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DingTalkAuthenticationEntryPoint idcAuthenticationEntryPoint() {
		return new DingTalkAuthenticationEntryPoint(dingtalkProperties.getAuthc().getLoginUrl());
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DingTalkAuthenticationFailureHandler idcAuthenticationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners) {
		return new DingTalkAuthenticationFailureHandler(authenticationListeners, dingtalkProperties.getAuthc().getLoginUrl());
	}
	
	@Bean
	public DingTalkAuthenticationProvider idcCodeAuthenticationProvider(
			AuthcUserDetailsService authcUserDetailsService) {
		return new DingTalkAuthenticationProvider(authcUserDetailsService, dingtalkProperties);
	}

	@Bean
	@ConditionalOnMissingBean
	public DingTalkAuthenticationSuccessHandler idcAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners) {
		return new DingTalkAuthenticationSuccessHandler(authenticationListeners, dingtalkProperties.getAuthc().getLoginUrl());
	}

}
