package org.springframework.security.boot.dingtalk.exception;

import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationExceptionAdapter;

@SuppressWarnings("serial")
public class DingTalkCodeIncorrectException extends AuthenticationExceptionAdapter {

	public DingTalkCodeIncorrectException(String msg) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT, msg);
	}
	
	public DingTalkCodeIncorrectException(String msg, Throwable t) {
		super(AuthResponseCode.SC_AUTHZ_CODE_INCORRECT, msg, t);
	}
	
}
