package org.springframework.security.boot.dingtalk.authentication;

import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.SecurityDingTalkProperties;
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
import com.taobao.api.ApiException;

public class DingTalkAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final UserDetailsServiceAdapter userDetailsService;
    private final SecurityDingTalkProperties dingtalkProperties;
    private final DingTalkTemplate dingTalkTemplate;
 
    public DingTalkAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService,
    		final DingTalkTemplate dingTalkTemplate,
    		final SecurityDingTalkProperties dingtalkProperties) {
        this.userDetailsService = userDetailsService;
        this.dingTalkTemplate = dingTalkTemplate;
        this.dingtalkProperties = dingtalkProperties;
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link DingTalkAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
        String loginTmpCode = (String) authentication.getCredentials();

		if (!StringUtils.hasLength(loginTmpCode)) {
			logger.debug("No loginTmpCode found in request.");
			throw new DingTalkCodeNotFoundException("No loginTmpCode found in request.");
		}
		
		try {
			
			
			// 获取access_token
			String accessToken = dingTalkTemplate.getAccessToken(dingtalkProperties.getAppKey(), dingtalkProperties.getAppSecret());
						
			// 企业内部应用免登录：通过免登授权码和access_token获取用户信息
			OapiUserGetuserinfoResponse response = dingTalkTemplate.getUserinfoBycode(loginTmpCode, accessToken);
			/*{
			    "userid": "****",
			    "sys_level": 1,
			    "errmsg": "ok",
			    "is_sys": true,
			    "errcode": 0
			}*/
			if (logger.isDebugEnabled()) {
				logger.debug(response.getCode());
			}

			if(!response.isSuccess()) {
				logger.error(JSONObject.toJSONString(AuthResponse.of(response.getErrorCode(), response.getErrmsg())));
				throw new DingTalkAuthenticationServiceException(response.getErrmsg());
			}
			
			OapiUserGetResponse userInfoResponse = dingTalkTemplate.getUserByUserid(response.getUserid(), accessToken);
			if(!userInfoResponse.isSuccess()) {
				logger.error(JSONObject.toJSONString(AuthResponse.of(userInfoResponse.getErrorCode(), userInfoResponse.getErrmsg())));
				throw new DingTalkAuthenticationServiceException(userInfoResponse.getErrmsg());
			}
			
			DingTalkAuthenticationToken dingTalkToken = (DingTalkAuthenticationToken) authentication;
			
			dingTalkToken.setAvatar(userInfoResponse.getAvatar());
			dingTalkToken.setName(userInfoResponse.getName());
			dingTalkToken.setNick(userInfoResponse.getNickname());
			dingTalkToken.setMobile(userInfoResponse.getMobile());
			dingTalkToken.setEmail(userInfoResponse.getEmail());
			dingTalkToken.setJobnumber(userInfoResponse.getJobnumber());
			dingTalkToken.setUnionid(userInfoResponse.getUnionid());
			dingTalkToken.setPrincipal(userInfoResponse.getUserid());
			
			UserDetails ud = getUserDetailsService().loadUserDetails(dingTalkToken);
	        
	        // User Status Check
	        getUserDetailsChecker().check(ud);
	        
	        DingTalkAuthenticationToken authenticationToken = null;
	        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
	        	SecurityPrincipal principal = (SecurityPrincipal) ud;
	        	if(!StringUtils.hasText(principal.getAlias())) {
	        		principal.setAlias(userInfoResponse.getNickname());
	        	}
	        	authenticationToken = new DingTalkAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
	        } else {
	        	authenticationToken = new DingTalkAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
			}
	        authenticationToken.setDetails(authentication.getDetails());
	        
	        return authenticationToken;
		} catch (ApiException e) {
			throw new DingTalkAuthenticationServiceException(e.getErrMsg(), e);
		} catch (ExecutionException e) {
			throw new InternalAuthenticationServiceException(e.getMessage(), e);
		}
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (DingTalkAuthenticationToken.class.isAssignableFrom(authentication));
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
