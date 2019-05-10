package org.springframework.security.boot.dingtalk.exception;

import org.springframework.security.core.AuthenticationException;

@SuppressWarnings("serial")
public class DingTalkCodeIncorrectException extends AuthenticationException {

	public DingTalkCodeIncorrectException(String msg) {
		super(msg);
	}
	
	public DingTalkCodeIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
	
}
