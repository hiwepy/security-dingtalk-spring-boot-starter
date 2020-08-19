package org.springframework.security.boot.dingtalk.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationFailureHandler;
import org.springframework.security.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeExpiredException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeIncorrectException;
import org.springframework.security.boot.utils.SecurityResponseUtils;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.AuthenticationException;

/**
 * DingTalk认证请求失败后的处理实现
 */
public class DingTalkMatchedAuthenticationFailureHandler implements MatchedAuthenticationFailureHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	 
	@Override
	public boolean supports(AuthenticationException e) {
		return SubjectUtils.isAssignableFrom(e.getClass(), DingTalkAuthenticationServiceException.class,
				DingTalkCodeIncorrectException.class, DingTalkCodeExpiredException.class);
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException, ServletException {
		
		SecurityResponseUtils.handleException(request, response, e);
		
	}

}
