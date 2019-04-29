package org.springframework.security.boot.dingtalk.exception;

import org.springframework.security.core.AuthenticationException;

public class DingTalkCodeIncorrectException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public DingTalkCodeIncorrectException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeIncorrectException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public DingTalkCodeIncorrectException(String msg, Throwable t) {
		super(msg, t);
	}
}
