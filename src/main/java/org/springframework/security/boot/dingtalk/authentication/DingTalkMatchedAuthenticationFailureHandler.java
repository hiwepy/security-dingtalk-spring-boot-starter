package org.springframework.security.boot.dingtalk.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeExpiredException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeIncorrectException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

import com.alibaba.fastjson.JSONObject;

/**
 * DingTalk认证请求失败后的处理实现
 */
public class DingTalkMatchedAuthenticationFailureHandler implements MatchedAuthenticationFailureHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	 
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.supports(e.getClass(), DingTalkAuthenticationServiceException.class,
				DingTalkCodeIncorrectException.class, DingTalkCodeExpiredException.class);
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {
		
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
		
		if (e instanceof DingTalkAuthenticationServiceException) {
			JSONObject.writeJSONString(response.getWriter(), AuthResponse.of(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE.getCode(), 
					messages.getMessage(AuthResponseCode.SC_AUTHZ_THIRD_PARTY_SERVICE.getMsgKey(), e.getMessage())));
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
