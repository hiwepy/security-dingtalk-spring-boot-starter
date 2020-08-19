package org.springframework.security.boot.dingtalk.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

@SuppressWarnings("serial")
public class DingTalkCodeExpiredException extends AuthenticationExceptionAdapter {

	public DingTalkCodeExpiredException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_DINGTALK_EXPIRED, msg);
	}
	
	public DingTalkCodeExpiredException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_DINGTALK_EXPIRED, msg, t);
	}

}
