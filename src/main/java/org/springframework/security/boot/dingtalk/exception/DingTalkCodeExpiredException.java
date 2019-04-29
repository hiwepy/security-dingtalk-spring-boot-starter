package org.springframework.security.boot.dingtalk.exception;

import org.springframework.security.core.AuthenticationException;

public class DingTalkCodeExpiredException extends AuthenticationException {

	// ~ Constructors
	// ===================================================================================================

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message.
	 *
	 * @param msg the detail message
	 */
	public DingTalkCodeExpiredException(String msg) {
		super(msg);
	}

	/**
	 * Constructs an <code>IdentityCodeExpiredException</code> with the specified
	 * message and root cause.
	 *
	 * @param msg the detail message
	 * @param t   root cause
	 */
	public DingTalkCodeExpiredException(String msg, Throwable t) {
		super(msg, t);
	}

}
