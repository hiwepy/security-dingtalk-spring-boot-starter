package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.captcha.CaptchaResolver;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.authentication.DingTalkTmpCodeAuthenticationProcessingFilter;
import org.springframework.security.boot.dingtalk.authentication.DingTalkTmpCodeAuthenticationProvider;
import org.springframework.security.boot.dingtalk.authentication.DingTalkMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.dingtalk.authentication.DingTalkMatchedAuthenticationFailureHandler;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

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
    @EnableConfigurationProperties({ SecurityBizProperties.class, SecurityDingTalkProperties.class, SecurityDingTalkTmpCodeAuthcProperties.class })
    @Order(SecurityProperties.DEFAULT_FILTER_ORDER + 5)
   	static class DingTalkMaWebSecurityConfigurerAdapter extends AbstractSecurityConfigurerAdapter {
    	
    	private final SecurityDingTalkTmpCodeAuthcProperties authcProperties;
    	
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final InvalidSessionStrategy invalidSessionStrategy;
	    private final LogoutSuccessHandler logoutSuccessHandler;
	    private final LogoutHandler logoutHandler;
	    private final ObjectMapper objectMapper;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
    	private final SessionRegistry sessionRegistry;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
   		
   		public DingTalkMaWebSecurityConfigurerAdapter(
   			
   				SecurityBizProperties bizProperties,
   				SecurityDingTalkTmpCodeAuthcProperties authcProperties,
   				
   				ObjectProvider<DingTalkTmpCodeAuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<CaptchaResolver> captchaResolverProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider
   				
			) {
   			
   			super(bizProperties, authcProperties, authenticationProvider.stream().collect(Collectors.toList()),
					authenticationManagerProvider.getIfAvailable());
   			
   			this.authcProperties = authcProperties;
   			
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
   			this.invalidSessionStrategy = super.invalidSessionStrategy();
   			this.logoutSuccessHandler = super.logoutSuccessHandler();
   			this.logoutHandler = super.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.requestCache = super.requestCache();
   			this.rememberMeServices = super.rememberMeServices();
   			this.sessionRegistry = super.sessionRegistry();
   			this.sessionAuthenticationStrategy = super.sessionAuthenticationStrategy();
   			this.sessionInformationExpiredStrategy = super.sessionInformationExpiredStrategy();
   			
   		}
   		
   	    public DingTalkTmpCodeAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
   	    	
   			DingTalkTmpCodeAuthenticationProcessingFilter authenticationFilter = new DingTalkTmpCodeAuthenticationProcessingFilter(objectMapper);
   			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(authcProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
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
   	    	
   	    	// Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = authcProperties.getSessionMgt();
   	    	// Session 注销配置参数
   	    	SecurityLogoutProperties logout = authcProperties.getLogout();
   	    	
   	    	http.csrf().disable(); // We don't need CSRF for JWT based authentication
	    	http.headers().cacheControl(); // 禁用缓存
	    	
   		    // Session 管理器配置
   	    	http.sessionManagement()
   	    		.enableSessionUrlRewriting(sessionMgt.isEnableSessionUrlRewriting())
   	    		.invalidSessionStrategy(invalidSessionStrategy)
   	    		.invalidSessionUrl(logout.getLogoutUrl())
   	    		.maximumSessions(sessionMgt.getMaximumSessions())
   	    		.maxSessionsPreventsLogin(sessionMgt.isMaxSessionsPreventsLogin())
   	    		.expiredSessionStrategy(sessionInformationExpiredStrategy)
   				.expiredUrl(logout.getLogoutUrl())
   				.sessionRegistry(sessionRegistry)
   				.and()
   	    		.sessionAuthenticationErrorUrl(sessionMgt.getFailureUrl())
   	    		.sessionAuthenticationFailureHandler(authenticationFailureHandler)
   	    		.sessionAuthenticationStrategy(sessionAuthenticationStrategy)
   	    		.sessionCreationPolicy(sessionMgt.getCreationPolicy())
   	    		// Session 注销配置
   	    		.and()
   	    		.logout()
   	    		.logoutUrl(logout.getPathPatterns())
   	    		.logoutSuccessHandler(logoutSuccessHandler)
   	    		.addLogoutHandler(logoutHandler)
   	    		.clearAuthentication(logout.isClearAuthentication())
   	    		.invalidateHttpSession(logout.isInvalidateHttpSession())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	// 异常处理
   	        	.and()
   	        	.exceptionHandling()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.httpBasic()
   	        	.authenticationEntryPoint(authenticationEntryPoint)
   	        	.and()
   	        	.antMatcher(authcProperties.getPathPattern())
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



