package org.springframework.security.boot;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.servlet.SecurityFilterAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationFailureHandler;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationProcessingFilter;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationProvider;
import org.springframework.security.boot.dingtalk.authentication.DingTalkAuthenticationSuccessHandler;
import org.springframework.security.boot.utils.StringUtils;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@AutoConfigureBefore({ SecurityFilterAutoConfiguration.class })
@EnableConfigurationProperties({ SecurityDingTalkProperties.class })
public class SecurityDingTalkFilterConfiguration {
    
    @Configuration
    @ConditionalOnProperty(prefix = SecurityDingTalkProperties.PREFIX, value = "enabled", havingValue = "true")
   	@EnableConfigurationProperties({ SecurityDingTalkProperties.class, SecurityBizProperties.class })
    @Order(104)
   	static class DingTalkWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter implements ApplicationEventPublisherAware {
    	
    	private ApplicationEventPublisher eventPublisher;
    	
        private final AuthenticationManager authenticationManager;
	    private final RememberMeServices rememberMeServices;
		
    	private final SecurityDingTalkProperties dingtalkProperties;
    	private final DingTalkAuthenticationProvider authenticationProvider;
	    private final DingTalkAuthenticationSuccessHandler authenticationSuccessHandler;
	    private final DingTalkAuthenticationFailureHandler authenticationFailureHandler;
	    
		private final SessionAuthenticationStrategy sessionAuthenticationStrategy;
   		
   		public DingTalkWebSecurityConfigurerAdapter(
   			
   				ObjectProvider<AuthenticationManager> authenticationManagerProvider,
   				ObjectProvider<RememberMeServices> rememberMeServicesProvider,
   				
   				SecurityDingTalkProperties dingtalkProperties,
   				ObjectProvider<DingTalkAuthenticationProvider> authenticationProvider,
   				ObjectProvider<DingTalkAuthenticationProcessingFilter> authenticationProcessingFilter,
   				ObjectProvider<DingTalkAuthenticationSuccessHandler> authenticationSuccessHandler,
   				ObjectProvider<DingTalkAuthenticationFailureHandler> authenticationFailureHandler,
   				
				@Qualifier("dingtalkSessionAuthenticationStrategy") ObjectProvider<SessionAuthenticationStrategy> sessionAuthenticationStrategyProvider
				) {
   			
   			this.authenticationManager = authenticationManagerProvider.getIfAvailable();
   			this.rememberMeServices = rememberMeServicesProvider.getIfAvailable();
   			
   			this.dingtalkProperties = dingtalkProperties;
   			this.authenticationProvider = authenticationProvider.getIfAvailable();
   			this.authenticationSuccessHandler = authenticationSuccessHandler.getIfAvailable();
   			this.authenticationFailureHandler = authenticationFailureHandler.getIfAvailable();
   			
   			this.sessionAuthenticationStrategy = sessionAuthenticationStrategyProvider.getIfAvailable();
   			
   		}
   		
   		@Bean
   	    public DingTalkAuthenticationProcessingFilter authenticationProcessingFilter() {
   	    	
   			DingTalkAuthenticationProcessingFilter authcFilter = new DingTalkAuthenticationProcessingFilter();
   			
   			authcFilter.setAllowSessionCreation(dingtalkProperties.getAuthc().isAllowSessionCreation());
   			authcFilter.setApplicationEventPublisher(eventPublisher);
   			authcFilter.setAuthenticationFailureHandler(authenticationFailureHandler);
   			authcFilter.setAuthenticationManager(authenticationManager);
   			authcFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
   			authcFilter.setContinueChainBeforeSuccessfulAuthentication(dingtalkProperties.getAuthc().isContinueChainBeforeSuccessfulAuthentication());
   			if (StringUtils.hasText(dingtalkProperties.getAuthc().getLoginUrlPatterns())) {
   				authcFilter.setFilterProcessesUrl(dingtalkProperties.getAuthc().getLoginUrlPatterns());
   			}
   			//authcFilter.setMessageSource(messageSource);
   			authcFilter.setCodeParameter(dingtalkProperties.getAuthc().getCodeParameter());
   			authcFilter.setPostOnly(dingtalkProperties.getAuthc().isPostOnly());
   			authcFilter.setRememberMeServices(rememberMeServices);
   			authcFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
   			
   	        return authcFilter;
   	    }
   		
   		@Override
   	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
   	        auth.authenticationProvider(authenticationProvider);
   	    }

   	    @Override
   	    protected void configure(HttpSecurity http) throws Exception {
   	    	
   	    	http.csrf().disable(); // We don't need CSRF for DingTalk LoginTmpCode based authentication
   	    	http.addFilterBefore(authenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class);
   	        
   	    }
   	    
   	    @Override
	    public void configure(WebSecurity web) throws Exception {
	    	web.ignoring().antMatchers(dingtalkProperties.getAuthc().getLoginUrlPatterns());
	    }
   	    
   		@Override
   		public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
   			this.eventPublisher = applicationEventPublisher;
   		}

   	}

}
