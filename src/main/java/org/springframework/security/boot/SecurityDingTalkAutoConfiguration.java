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
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationProvider;
import org.springframework.security.boot.dingtalk.authentication.DingTalkMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.dingtalk.authentication.DingTalkMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.dingtalk.authentication.DingTalkTemplate;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityDingTalkProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityDingTalkProperties.class })
public class SecurityDingTalkAutoConfiguration{

	@Autowired
	private SecurityBizProperties bizProperties;
	@Autowired
	private SecurityDingTalkProperties dingtalkProperties;
	
	@Bean("dingTalkAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler dingTalkAuthenticationSuccessHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers) {
		
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		
		successHandler.setDefaultTargetUrl(dingtalkProperties.getAuthc().getSuccessUrl());
		successHandler.setStateless(bizProperties.isStateless());
		successHandler.setTargetUrlParameter(dingtalkProperties.getAuthc().getTargetUrlParameter());
		successHandler.setUseReferer(dingtalkProperties.getAuthc().isUseReferer());
		
		return successHandler;
	}
	
	@Bean("dingTalkAuthenticationFailureHandler")
	public PostRequestAuthenticationFailureHandler dingTalkAuthenticationFailureHandler(
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationFailureHandler> failureHandlers) {
		
		PostRequestAuthenticationFailureHandler failureHandler = new PostRequestAuthenticationFailureHandler(
				authenticationListeners, failureHandlers);
		
		failureHandler.setAllowSessionCreation(bizProperties.getSessionMgt().isAllowSessionCreation());
		failureHandler.setDefaultFailureUrl(dingtalkProperties.getAuthc().getFailureUrl());
		failureHandler.setStateless(bizProperties.isStateless());
		failureHandler.setUseForward(dingtalkProperties.getAuthc().isUseForward());
		
		return failureHandler;
	}
	
	@Bean
	public DingTalkMatchedAuthenticationEntryPoint dingTalkMatchedAuthenticationEntryPoint() {
		return new DingTalkMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public DingTalkMatchedAuthenticationFailureHandler dingTalkMatchedAuthenticationFailureHandler() {
		return new DingTalkMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DingTalkTemplate dingTalkTemplate() {
		return new DingTalkTemplate();
	}
	
	@Bean
	public DingTalkAuthenticationProvider dingTalkAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService, 
			DingTalkTemplate dingTalkTemplate) {
		return new DingTalkAuthenticationProvider(userDetailsService, dingTalkTemplate, dingtalkProperties);
	}

}
