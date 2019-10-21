package org.springframework.security.boot;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.PropertyMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.PostRequestAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecurityCsrfProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationProcessingFilter;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationProvider;
import org.springframework.security.boot.dingtalk.authentication.DingTalkMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.dingtalk.authentication.DingTalkMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.dingtalk.authentication.DingTalkTemplate;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityDingTalkProperties.class, SecurityDingTalkAuthcProperties.class })
public class SecurityDingTalkFilterConfiguration {

	@Bean("dingtalkAuthenticationSuccessHandler")
	public PostRequestAuthenticationSuccessHandler dingtalkAuthenticationSuccessHandler(
			SecurityBizProperties bizProperties,
			SecurityDingTalkAuthcProperties dingtalkAuthcProperties,
			@Autowired(required = false) List<AuthenticationListener> authenticationListeners,
			@Autowired(required = false) List<MatchedAuthenticationSuccessHandler> successHandlers) {
		
		PostRequestAuthenticationSuccessHandler successHandler = new PostRequestAuthenticationSuccessHandler(
				authenticationListeners, successHandlers);
		
		successHandler.setDefaultTargetUrl(dingtalkAuthcProperties.getSuccessUrl());
		successHandler.setStateless(bizProperties.isStateless());
		successHandler.setTargetUrlParameter(dingtalkAuthcProperties.getTargetUrlParameter());
		successHandler.setUseReferer(dingtalkAuthcProperties.isUseReferer());
		
		return successHandler;
	}
	
	@Bean
	public DingTalkMatchedAuthenticationEntryPoint dingtalkMatchedAuthenticationEntryPoint() {
		return new DingTalkMatchedAuthenticationEntryPoint();
	}
	
	@Bean
	public DingTalkMatchedAuthenticationFailureHandler dingtalkMatchedAuthenticationFailureHandler() {
		return new DingTalkMatchedAuthenticationFailureHandler();
	}
	
	@Bean
	@ConditionalOnMissingBean
	public DingTalkTemplate dingtalkTemplate() {
		return new DingTalkTemplate();
	}
	
	@Bean
	public DingTalkAuthenticationProvider dingtalkAuthenticationProvider(
			SecurityDingTalkProperties dingtalkProperties,
			UserDetailsServiceAdapter userDetailsService, 
			DingTalkTemplate dingtalkTemplate) {
		return new DingTalkAuthenticationProvider(userDetailsService, dingtalkTemplate, dingtalkProperties);
	}
	
	@Bean("dingtalkLogoutSuccessHandler")
	public LogoutSuccessHandler dingtalkLogoutSuccessHandler() {
		return new HttpStatusReturningLogoutSuccessHandler();
	}
	
	
    @Configuration
    @ConditionalOnProperty(prefix = SecurityDingTalkProperties.PREFIX, value = "enabled", havingValue = "true")
    @EnableConfigurationProperties({ SecurityBizProperties.class, SecurityDingTalkProperties.class, SecurityDingTalkAuthcProperties.class })
    @Order(104)
   	static class DingTalkWebSecurityConfigurerAdapter extends SecurityBizConfigurerAdapter {
    	
	    private final SecurityBizProperties bizProperties;
    	private final SecurityDingTalkAuthcProperties dingtalkAuthcProperties;
    	
    	private final AuthenticationManager authenticationManager;
	    private final DingTalkAuthenticationProvider authenticationProvider;
	    private final PostRequestAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final PostRequestAuthenticationFailureHandler authenticationFailureHandler;
	    private final CsrfTokenRepository csrfTokenRepository;
	    private final InvalidSessionStrategy invalidSessionStrategy;
	    private final LogoutSuccessHandler logoutSuccessHandler;
	    private final List<LogoutHandler> logoutHandlers;
	    private final ObjectMapper objectMapper;
    	private final RequestCache requestCache;
    	private final RememberMeServices rememberMeServices;
    	private final SessionRegistry sessionRegistry;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
		private final SessionInformationExpiredStrategy sessionInformationExpiredStrategy;
	    
   		
   		public DingTalkWebSecurityConfigurerAdapter(
   			
   				SecurityBizProperties bizProperties,
   				SecurityDingTalkAuthcProperties dingtalkAuthcProperties,
   				
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<DingTalkAuthenticationProvider> authenticationProvider,
   				ObjectProvider<PostRequestAuthenticationFailureHandler> authenticationFailureHandler,
   				@Qualifier("dingtalkAuthenticationSuccessHandler") ObjectProvider<PostRequestAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<CsrfTokenRepository> csrfTokenRepositoryProvider,
   				ObjectProvider<InvalidSessionStrategy> invalidSessionStrategyProvider,
   				@Qualifier("dingtalkLogoutSuccessHandler") ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
   				ObjectProvider<LogoutHandler> logoutHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionRegistry> sessionRegistryProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider,
				ObjectProvider<SessionInformationExpiredStrategy> sessionInformationExpiredStrategyProvider
			) {
   			
   			super(bizProperties);
   			
   			this.bizProperties = bizProperties;
   			this.dingtalkAuthcProperties = dingtalkAuthcProperties;
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.csrfTokenRepository = csrfTokenRepositoryProvider.getIfAvailable();
   			this.invalidSessionStrategy = invalidSessionStrategyProvider.getIfAvailable();
   			this.logoutSuccessHandler = logoutSuccessHandlerProvider.getIfAvailable();
   			this.logoutHandlers = logoutHandlerProvider.stream().collect(Collectors.toList());
   			this.objectMapper = objectMapperProvider.getIfAvailable();
   			this.requestCache = requestCacheProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			this.sessionRegistry = sessionRegistryProvider.getIfAvailable();
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategyProvider.getIfAvailable();
   			
   		}
   		
		@Override
		protected AuthenticationManager authenticationManager() throws Exception {
			return authenticationManager == null ? super.authenticationManager() : authenticationManager;
		}
		
   	    public DingTalkAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {
   	    	
   			DingTalkAuthenticationProcessingFilter authenticationFilter = new DingTalkAuthenticationProcessingFilter(objectMapper);
   			
			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();
			
			map.from(bizProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);
			
			map.from(authenticationManager()).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);
			
			map.from(dingtalkAuthcProperties.getCodeParameter()).to(authenticationFilter::setCodeParameter);
			map.from(dingtalkAuthcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(dingtalkAuthcProperties.isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(dingtalkAuthcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);
   			
   	        return authenticationFilter;
   	    }
   		
   		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
   	        auth.authenticationProvider(authenticationProvider);
   	        super.configure(auth);
   	    }

   	    @Override
		public void configure(HttpSecurity http) throws Exception {
   	    	
   	  // Session 管理器配置参数
   	    	SecuritySessionMgtProperties sessionMgt = bizProperties.getSessionMgt();
   	    	// Session 注销配置参数
   	    	SecurityLogoutProperties logout = dingtalkAuthcProperties.getLogout();
   	    	
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
   	    		.addLogoutHandler(new CompositeLogoutHandler(logoutHandlers))
   	    		.clearAuthentication(logout.isClearAuthentication())
   	    		.invalidateHttpSession(logout.isInvalidateHttpSession())
   	        	// Request 缓存配置
   	        	.and()
   	    		.requestCache()
   	        	.requestCache(requestCache)
   	        	.and()
   	        	.antMatcher(dingtalkAuthcProperties.getPathPattern())
   	        	.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class); 
   	    	
   	    	// CSRF 配置
   	    	SecurityCsrfProperties csrf = dingtalkAuthcProperties.getCsrf();
   	    	if(csrf.isEnabled()) {
   	       		http.csrf()
   				   	.csrfTokenRepository(csrfTokenRepository)
   				   	.ignoringAntMatchers(StringUtils.tokenizeToStringArray(csrf.getIgnoringAntMatchers()))
   					.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
   	        } else {
   	        	http.csrf().disable();
   	        }
	    	super.configure(http);
	    	
   	    	http.csrf().disable(); // We don't need CSRF for DingTalk LoginTmpCode based authentication
   	    	
   	    	http.antMatcher(dingtalkAuthcProperties.getPathPattern())
   	    		.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
   	    	
   	        super.configure(http);
   	    }
   	    
   	    @Override
	    public void configure(WebSecurity web) throws Exception {
	    	super.configure(web);
	    }

   	}

}



