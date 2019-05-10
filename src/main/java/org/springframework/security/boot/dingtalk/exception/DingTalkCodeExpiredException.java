package org.springframework.security.boot.dingtalk.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class DingTalkCodeExpiredException extends AuthenticationException {

	public DingTalkCodeExpiredException(String msg) {
		super(msg);
	}
	
	public DingTalkCodeExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
