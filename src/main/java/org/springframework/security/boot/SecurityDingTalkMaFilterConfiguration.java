package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.biz.web.servlet.i18n.LocaleContextFilter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.authentication.DingTalkMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.dingtalk.authentication.DingTalkMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.dingtalk.authentication.DingTalkTmpCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.dingtalk.authentication.DingTalkTmpCodeAuthenticationProvider;
import org.springframework.security.boot.utils.WebSecurityUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.dingtalk.spring.boot.DingTalkTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityDingTalkProperties.class, SecurityDingTalkTmpCodeAuthcProperties.class })
public class SecurityDingTalkMaFilterConfiguration {
	
	@Bean
	public DingTalkMatchedAuthenticationEntryPoint dingtalkMatchedAuthenticationEntryPoint() {
		return new DingTalkMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public DingTalkMatchedAuthenticationFailureHandler dingtalkMatchedAuthenticationFailureHandler() {
		return new DingTalkMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	public DingTalkTmpCodeAuthenticationProvider dingtalkAuthenticationProvider(
			UserDetailsServiceAdapter userDetailsService, 
			DingTalkTemplate dingtalkTemplate) {
		return new DingTalkTmpCodeAuthenticationProvider(userDetailsService, dingtalkTemplate);
	}
	
    @Configuration
    @ConditionalOnProperty(prefix = SecurityDingTalkProperties.PREFIX, value = "enabled", havingValue = "true")
    @EnableConfigurationProperties({ SecurityBizProperties.class, SecuritySessionMgtProperties.class, SecurityDingTalkProperties.class, SecurityDingTalkTmpCodeAuthcProperties.class })
    @Order(SecurityProperties.DEFAULT_FILTER_ORDER + 5)
   	static class DingTalkMaWebSecurityConfigurerAdapter extends WebSecurityBizConfigurerAdapter {
    	
    	private final SecurityDingTalkTmpCodeAuthcProperties authcProperties;
    	
    	private final LocaleContextFilter localeContextFilter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final ObjectMapper objectMapper;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
   		
   		public DingTalkMaWebSecurityConfigurerAdapter(
   			
   				SecurityBizProperties bizProperties,
   				SecuritySessionMgtProperties sessionMgtProperties,
   				SecurityDingTalkTmpCodeAuthcProperties authcProperties,
   				
   				ObjectProvider<LocaleContextFilter> localeContextProvider,
   				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider
   				
			) {
   			
   			super(bizProperties, sessionMgtProperties, authenticationProvider.stream().collect(Collectors.toList()));
   			
   			this.authcProperties = authcProperties;

			this.localeContextFilter = localeContextProvider.getIfAvailable();
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = WebSecurityUtils.authenticationEntryPoint(authcProperties, sessionMgtProperties, authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = WebSecurityUtils.authenticationSuccessHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = WebSecurityUtils.authenticationFailureHandler(authcProperties, sessionMgtProperties, authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
   		}
   		
   	    public DingTalkTmpCodeAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
   	    	
   			DingTalkTmpCodeAuthenticationProcessingFilter authenticationFilter = new DingTalkTmpCodeAuthenticationProcessingFilter(objectMapper);
   			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(getSessionMgtProperties().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(authcProperties.getTmpCodeParameter()).to(authenticationFilter::setTmpCodeParameter);
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
   			
   	        return authenticationFilter;
   	    }
   	    
   	    @Override
		public void configure(HttpSecurity http) throws Exception {
	    	
   	    	http.antMatcher(authcProperties.getPathPattern())
				.exceptionHandling()
	        	.authenticationEntryPoint(authenticationEntryPoint)
	        	.and()
	        	.httpBasic()
	        	.disable()
   	        	.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
   	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 
   	    	
   	    	super.configure(http, authcProperties.getCros());
   	    	super.configure(http, authcProperties.getCsrf());
   	    	super.configure(http, authcProperties.getHeaders());
	    	super.configure(http);
   	    }
   	    
   	    @Override
	    public void configure(WebSecurity web) throws Exception {
	    	super.configure(web);
	    }

   	}

}



