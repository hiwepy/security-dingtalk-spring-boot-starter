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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.authentication.AuthenticationListener;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.property.SecuritySessionMgtProperties;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.authentication.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import com.dingtalk.spring.boot.DingTalkTemplate;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.web.savedrequest.RequestCache;

@Configuration
@ConditionalOnProperty(prefix = SecurityDingTalkProperties.PREFIX, value = "enabled", havingValue = "true")
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityBizProperties.class, SecurityDingTalkProperties.class, SecurityDingTalkMaAuthcProperties.class })
public class SecurityDingTalkMaFilterConfiguration {

	@Bean
	public DingTalkMaAuthenticationProvider dingTalkMaAuthenticationProvider(
			ObjectProvider<UserDetailsServiceAdapter> userDetailsServiceProvider,
			ObjectProvider<DingTalkTemplate> dingtalkTemplateProvider) {
		return new DingTalkMaAuthenticationProvider(userDetailsServiceProvider.getIfAvailable(), dingtalkTemplateProvider.getIfAvailable());
	}

    @Configuration
	@ConditionalOnProperty(prefix = SecurityDingTalkProperties.PREFIX, value = "enabled", havingValue = "true")
    @EnableConfigurationProperties({ SecurityBizProperties.class, SecuritySessionMgtProperties.class, SecurityDingTalkProperties.class, SecurityDingTalkMaAuthcProperties.class })
   	static class DingTalkMaWebSecurityConfigurerAdapter extends SecurityFilterChainConfigurer {

		private final SecurityBizProperties bizProperties;
    	private final SecurityDingTalkMaAuthcProperties authcProperties;

		private final AuthenticationEntryPoint authenticationEntryPoint;
		private final AuthenticationSuccessHandler authenticationSuccessHandler;
		private final AuthenticationFailureHandler authenticationFailureHandler;
		private final AuthenticationManager authenticationManager;
		private final LocaleContextFilter localeContextFilter;
		private final LogoutHandler logoutHandler;
		private final LogoutSuccessHandler logoutSuccessHandler;
		private final ObjectMapper objectMapper;
		private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;

   		public DingTalkMaWebSecurityConfigurerAdapter(

   				SecurityBizProperties bizProperties,
   				SecurityDingTalkMaAuthcProperties authcProperties,

				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
				ObjectProvider<LocaleContextFilter> localeContextProvider,
				ObjectProvider<LogoutHandler> logoutHandlerProvider,
				ObjectProvider<LogoutSuccessHandler> logoutSuccessHandlerProvider,
				ObjectProvider<ObjectMapper> objectMapperProvider,
				ObjectProvider<RedirectStrategy> redirectStrategyProvider,
				ObjectProvider<RequestCache> requestCacheProvider,
				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider

			) {

   			super(bizProperties, redirectStrategyProvider.getIfAvailable(), requestCacheProvider.getIfAvailable());

   			this.authcProperties = authcProperties;
			this.bizProperties = bizProperties;

			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
			this.authenticationEntryPoint = super.authenticationEntryPoint(authcProperties.getPathPattern(), authenticationEntryPointProvider.stream().collect(Collectors.toList()));
			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authcProperties, authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
			this.localeContextFilter = localeContextProvider.getIfAvailable();
			this.logoutHandler = super.logoutHandler(logoutHandlerProvider.stream().collect(Collectors.toList()));
			this.logoutSuccessHandler = logoutSuccessHandlerProvider.getIfAvailable();
			this.objectMapper = objectMapperProvider.getIfAvailable();
			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();

   		}

   	    public DingTalkMaAuthenticationProcessingFilter authenticationProcessingFilter() throws Exception {

			DingTalkMaAuthenticationProcessingFilter authenticationFilter = new DingTalkMaAuthenticationProcessingFilter(objectMapper);

			/**
			 * 批量设置参数
			 */
			PropertyMapper map = PropertyMapper.get().alwaysApplyingWhenNonNull();

			map.from(bizProperties.getSession().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);

			map.from(authenticationManager).to(authenticationFilter::setAuthenticationManager);
			map.from(authenticationSuccessHandler).to(authenticationFilter::setAuthenticationSuccessHandler);
			map.from(authenticationFailureHandler).to(authenticationFilter::setAuthenticationFailureHandler);

			map.from(authcProperties.getTokenParameter()).to(authenticationFilter::setTokenParameter);
			map.from(authcProperties.getAuthCodeParameter()).to(authenticationFilter::setAuthCodeParameter);
			map.from(authcProperties.getPathPattern()).to(authenticationFilter::setFilterProcessesUrl);
			map.from(authcProperties.isPostOnly()).to(authenticationFilter::setPostOnly);
			map.from(rememberMeServices).to(authenticationFilter::setRememberMeServices);
			map.from(sessionAuthenticationStrategy).to(authenticationFilter::setSessionAuthenticationStrategy);
			map.from(authcProperties.isContinueChainBeforeSuccessfulAuthentication()).to(authenticationFilter::setContinueChainBeforeSuccessfulAuthentication);

   	        return authenticationFilter;
   	    }

		@Bean
		@Order(SecurityProperties.DEFAULT_FILTER_ORDER + 11)
		public SecurityFilterChain dingTalkMaSecurityFilterChain(HttpSecurity http) throws Exception {
			// new DefaultSecurityFilterChain(new AntPathRequestMatcher(authcProperties.getPathPattern()), localeContextFilter, authenticationProcessingFilter());
			http.antMatcher(authcProperties.getPathPattern())
					// 请求鉴权配置
					.authorizeRequests(this.authorizeRequestsCustomizer())
					// 异常处理
					.exceptionHandling((configurer) -> configurer.authenticationEntryPoint(authenticationEntryPoint))
					// 请求头配置
					.headers(this.headersCustomizer(bizProperties.getHeaders()))
					// Request 缓存配置
					.requestCache(this.requestCacheCustomizer())
					// Session 注销配置
					.logout(this.logoutCustomizer(bizProperties.getLogout(), logoutHandler, logoutSuccessHandler))
					// 禁用 Http Basic
					.httpBasic((basic) -> basic.disable())
					// Filter 配置
					.addFilterBefore(localeContextFilter, UsernamePasswordAuthenticationFilter.class)
					.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

			return http.build();
		}

   	}

}



