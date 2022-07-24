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
    @Order(SecurityProperties.DEFAULT_FILTER_ORDER + 11)
   	static class DingTalkMaWebSecurityConfigurerAdapter extends WebSecurityBizConfigurerAdapter {

    	private final SecurityDingTalkMaAuthcProperties authcProperties;

    	private final LocaleContextFilter localeContextFilter;
	    private final AuthenticationEntryPoint authenticationEntryPoint;
	    private final AuthenticationSuccessHandler authenticationSuccessHandler;
	    private final AuthenticationFailureHandler authenticationFailureHandler;
	    private final ObjectMapper objectMapper;
    	private final RememberMeServices rememberMeServices;
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;

   		public DingTalkMaWebSecurityConfigurerAdapter(

   				SecurityBizProperties bizProperties,
   				SecurityDingTalkMaAuthcProperties authcProperties,

   				ObjectProvider<LocaleContextFilter> localeContextProvider,
   				ObjectProvider<AuthenticationProvider> authenticationProvider,
   				ObjectProvider<AuthenticationListener> authenticationListenerProvider,
				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<MatchedAuthenticationEntryPoint> authenticationEntryPointProvider,
   				ObjectProvider<MatchedAuthenticationSuccessHandler> authenticationSuccessHandlerProvider,
   				ObjectProvider<MatchedAuthenticationFailureHandler> authenticationFailureHandlerProvider,
   				ObjectProvider<ObjectMapper> objectMapperProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider

			) {

   			super(bizProperties, authcProperties, authenticationProvider.stream().collect(Collectors.toList()), authenticationManagerProvider.getIfAvailable());

   			this.authcProperties = authcProperties;

			this.localeContextFilter = localeContextProvider.getIfAvailable();
   			List<AuthenticationListener> authenticationListeners = authenticationListenerProvider.stream().collect(Collectors.toList());
   			this.authenticationEntryPoint = super.authenticationEntryPoint(authenticationEntryPointProvider.stream().collect(Collectors.toList()));
   			this.authenticationSuccessHandler = super.authenticationSuccessHandler(authenticationListeners, authenticationSuccessHandlerProvider.stream().collect(Collectors.toList()));
   			this.authenticationFailureHandler = super.authenticationFailureHandler(authenticationListeners, authenticationFailureHandlerProvider.stream().collect(Collectors.toList()));
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

			map.from(authcProperties.getSessionMgt().isAllowSessionCreation()).to(authenticationFilter::setAllowSessionCreation);

			map.from(authenticationManagerBean()).to(authenticationFilter::setAuthenticationManager);
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



