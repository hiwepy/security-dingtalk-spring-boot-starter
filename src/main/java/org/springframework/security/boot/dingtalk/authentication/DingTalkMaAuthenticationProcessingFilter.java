/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.dingtalk.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

public class DingTalkMaAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
    public static final String SPRING_SECURITY_FORM_APP_KEY = "key";
    public static final String SPRING_SECURITY_FORM_CODE_KEY = "code";
    public static final String SPRING_SECURITY_FORM_USERID_KEY = "userid";
    public static final String SPRING_SECURITY_FORM_UNIONID_KEY = "unionid";
    public static final String SPRING_SECURITY_FORM_OPENID_KEY = "openid";
    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "username";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "password";
    
    private String keyParameter = SPRING_SECURITY_FORM_APP_KEY;
    private String codeParameter = SPRING_SECURITY_FORM_CODE_KEY;
    private String useridParameter = SPRING_SECURITY_FORM_USERID_KEY;
    private String unionidParameter = SPRING_SECURITY_FORM_UNIONID_KEY;
    private String openidParameter = SPRING_SECURITY_FORM_OPENID_KEY;
    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;
    
    private ObjectMapper objectMapper = new ObjectMapper();
    
    public DingTalkMaAuthenticationProcessingFilter(ObjectMapper objectMapper) {
    	super(new AntPathRequestMatcher("/login/dingtalk"));
		this.objectMapper = objectMapper;
	}
	
	public DingTalkMaAuthenticationProcessingFilter(ObjectMapper objectMapper, AntPathRequestMatcher requestMatcher) {
		super(requestMatcher);
		this.objectMapper = objectMapper;
	}
	
    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        
        AbstractAuthenticationToken authRequest;
        
        // Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			
			if (logger.isDebugEnabled()) {
				logger.debug("Post && JSON");
			}
			
			DingTalkMaLoginRequest loginRequest = objectMapper.readValue(request.getReader(), DingTalkMaLoginRequest.class);
			
			if ( !StringUtils.hasText(loginRequest.getKey())) {
				logger.debug("No key (appId or appKey) found in request.");
				throw new DingTalkCodeNotFoundException("No key (appId or appKey) found in request.");
			}
			if ( !StringUtils.hasText(loginRequest.getUserid()) && !StringUtils.hasText(loginRequest.getCode())) {
				logger.debug("No Code found in request.");
				throw new DingTalkCodeNotFoundException("No Code found in request.");
			}
			
			authRequest = this.authenticationToken( loginRequest );
			
		} else {
			
			/**
			 * 	应用的唯一标识key
			 */
			String appId = obtainKey(request);;
			String code = obtainCode(request);
			String userId = obtainUserId(request);
			String unionid = obtainUnionid(request);
	        String openid = obtainOpenid(request);
	        String username = obtainUsername(request); 
	        String password = obtainPassword(request); 
	        
			if ( !StringUtils.hasText(appId)) {
				logger.debug("No appId found in request.");
				throw new DingTalkCodeNotFoundException("No appId found in request.");
			}
			if ( !StringUtils.hasText(userId) && !StringUtils.hasText(code)) {
				logger.debug("No Code found in request.");
				throw new DingTalkCodeNotFoundException("No Code found in request.");
			}
			if (userId == null) {
				userId = "";
	        }
			if (unionid == null) {
	        	unionid = "";
	        }
	        if (openid == null) {
	        	openid = "";
	        }
	        if (username == null) {
	        	username = "";
	        }
	        if (password == null) {
	        	password = "";
	        }
	        
			DingTalkMaLoginRequest loginRequest = new DingTalkMaLoginRequest(appId, userId, code, 
	        		unionid, openid, username, password, null);
	        
	        authRequest = this.authenticationToken( loginRequest);
	        
		}
        

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);

    }

    protected String obtainKey(HttpServletRequest request) {
        return request.getParameter(keyParameter);
    }
    
    protected String obtainUserId(HttpServletRequest request) {
        return request.getParameter(useridParameter);
    }
    
    protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }
    
    protected String obtainUnionid(HttpServletRequest request) {
        return request.getParameter(unionidParameter);
    }
    
    protected String obtainOpenid(HttpServletRequest request) {
        return request.getParameter(openidParameter);
    }
    
    protected String obtainUsername(HttpServletRequest request) {
        return request.getParameter(usernameParameter);
    }
    
    protected String obtainPassword(HttpServletRequest request) {
        return request.getParameter(passwordParameter);
    }
    
    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	protected AbstractAuthenticationToken authenticationToken(DingTalkMaLoginRequest loginRequest) {
		return new DingTalkMaAuthenticationToken(loginRequest);
	}
	
	public String getKeyParameter() {
		return keyParameter;
	}

	public void setKeyParameter(String keyParameter) {
		this.keyParameter = keyParameter;
	}

	public String getCodeParameter() {
		return codeParameter;
	}

	public void setCodeParameter(String codeParameter) {
		this.codeParameter = codeParameter;
	}
	
	public String getUseridParameter() {
		return useridParameter;
	}

	public void setUseridParameter(String useridParameter) {
		this.useridParameter = useridParameter;
	}

	public String getUnionidParameter() {
		return unionidParameter;
	}

	public void setUnionidParameter(String unionidParameter) {
		this.unionidParameter = unionidParameter;
	}

	public String getOpenidParameter() {
		return openidParameter;
	}

	public void setOpenidParameter(String openidParameter) {
		this.openidParameter = openidParameter;
	}

	public String getUsernameParameter() {
		return usernameParameter;
	}

	public void setUsernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
	}

	public String getPasswordParameter() {
		return passwordParameter;
	}

	public void setPasswordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

}