package org.springframework.security.boot.dingtalk.authentication;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;
import com.dingtalk.api.response.OapiUserGetResponse;
import com.dingtalk.api.response.OapiUserGetuserinfoResponse;
import com.dingtalk.spring.boot.DingTalkTemplate;
import com.taobao.api.ApiException;

public class DingTalkMaAuthenticationProvider implements AuthenticationProvider, InitializingBean {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final UserDetailsServiceAdapter userDetailsService;
    private final DingTalkTemplate dingTalkTemplate;
    
    public DingTalkMaAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService,
    		final DingTalkTemplate dingTalkTemplate) {
        this.userDetailsService = userDetailsService;
        this.dingTalkTemplate = dingTalkTemplate;
    }

	@Override
	public void afterPropertiesSet() throws Exception {
		
	}
    
    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link DingTalkTmpCodeAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
    	DingTalkMaLoginRequest loginRequest = (DingTalkMaLoginRequest) authentication.getPrincipal();

    	if ( !StringUtils.hasText(loginRequest.getUserid()) && !StringUtils.hasText(loginRequest.getCode())) {
			logger.debug("No Code found in request.");
			throw new DingTalkCodeNotFoundException("No Code found in request.");
		}
    	
		try {

			if(!dingTalkTemplate.hasAppKey(loginRequest.getKey())) {
				logger.debug("Invalid App Key {} .", loginRequest.getKey());
				throw new DingTalkCodeNotFoundException("Invalid App Key.");
			}
			
			String appKey = loginRequest.getKey();
			String appSecret = dingTalkTemplate.getAppSecret(loginRequest.getKey());
			// 获取access_token
			String accessToken = dingTalkTemplate.getAccessToken(appKey, appSecret);
			
			if(StringUtils.hasText(loginRequest.getCode()) && !StringUtils.hasText(loginRequest.getUserid()) ) {
				
				OapiUserGetuserinfoResponse response = dingTalkTemplate.getUserinfoBycode(loginRequest.getCode(), accessToken);
				/*{
				    "userid": "****",
				    "sys_level": 1,
				    "errmsg": "ok",
				    "is_sys": true,
				    "errcode": 0
				}*/
				if (logger.isDebugEnabled()) {
					logger.debug(response.getBody());
				}
				
				if(!response.isSuccess()) {
					logger.error(JSONObject.toJSONString(AuthResponse.of(response.getErrorCode(), response.getErrmsg())));
					throw new DingTalkAuthenticationServiceException(response.getErrmsg());
				}
				
				loginRequest.setUserid(response.getUserid());
				
			}
			
			DingTalkTmpCodeAuthenticationToken dingTalkToken = (DingTalkTmpCodeAuthenticationToken) authentication;
			
			if(Objects.isNull(loginRequest.getUserInfo()) && !Objects.isNull(loginRequest.getUserid()) ) {
				OapiUserGetResponse userInfoResponse = dingTalkTemplate.getUserByUserid(loginRequest.getUserid(), accessToken);
				if(!userInfoResponse.isSuccess()) {
					logger.error(JSONObject.toJSONString(AuthResponse.of(userInfoResponse.getErrorCode(), userInfoResponse.getErrmsg())));
					throw new DingTalkAuthenticationServiceException(userInfoResponse.getErrmsg());
				}
				dingTalkToken.setUserInfo(userInfoResponse);
				dingTalkToken.setUnionid(userInfoResponse.getUnionid());
				dingTalkToken.setOpenid(userInfoResponse.getOpenId());
				loginRequest.setUnionid(userInfoResponse.getUnionid());
				loginRequest.setOpenid(userInfoResponse.getOpenId());
			}
			
			UserDetails ud = getUserDetailsService().loadUserDetails(dingTalkToken);
	        
	        // User Status Check
	        getUserDetailsChecker().check(ud);
	        
	        DingTalkTmpCodeAuthenticationToken authenticationToken = null;
	        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
	        	authenticationToken = new DingTalkTmpCodeAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
	        } else {
	        	authenticationToken = new DingTalkTmpCodeAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
			}
	        authenticationToken.setDetails(authentication.getDetails());
	        
	        return authenticationToken;
		} catch (ApiException e) {
			throw new DingTalkAuthenticationServiceException(e.getErrMsg(), e);
		}
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return (DingTalkTmpCodeAuthenticationToken.class.isAssignableFrom(authentication));
    }

	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}
