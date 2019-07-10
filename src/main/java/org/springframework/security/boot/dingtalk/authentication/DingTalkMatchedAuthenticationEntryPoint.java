/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationEntryPoint;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeExpiredException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeIncorrectException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

import com.alibaba.fastjson.JSONObject;

public class DingTalkMatchedAuthenticationEntryPoint implements MatchedAuthenticationEntryPoint {
	
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), DingTalkAuthenticationServiceException.class,
				DingTalkCodeIncorrectException.class, DingTalkCodeExpiredException.class);
	}
	
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
		if (e instanceof DingTalkAuthenticationServiceException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE.getCode(), e.getMessage()));
		} else if (e instanceof DingTalkCodeNotFoundException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_DINGTALK_REQUIRED.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_DINGTALK_REQUIRED.getMsgKey(), e.getMessage())));
		} else if (e instanceof DingTalkCodeExpiredException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_DINGTALK_EXPIRED.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_DINGTALK_EXPIRED.getMsgKey(), e.getMessage())));
		} else if (e instanceof DingTalkCodeIncorrectException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_DINGTALK_INCORRECT.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_DINGTALK_INCORRECT.getMsgKey(), e.getMessage())));
		} else {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_FAIL.getCode(),
					messages.getMessage(AuthResponseCode.SC_AUTHC_FAIL.getMsgKey())));
		}
		
	}
	
}
