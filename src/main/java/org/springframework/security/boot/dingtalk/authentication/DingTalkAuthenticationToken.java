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
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@SuppressWarnings("serial")
public class DingTalkAuthenticationToken extends AbstractAuthenticationToken {

	private final Object principal;
	private Object credentials;

	/**
	 * 用户在钉钉上面的昵称
	 */
	protected String nick;
	/**
	 * 用户在当前开放应用内的唯一标识
	 */
	protected String openid;
	/**
	 * 用户在当前开放应用所属企业内的唯一标识
	 */
	protected String unionid;

	public DingTalkAuthenticationToken(String credentials) {
		super(null);
		this.principal = null;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	public DingTalkAuthenticationToken(Object principal, String credentials) {
		super(null);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	public DingTalkAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}

	// ~ Methods
	// ========================================================================================================

	public Object getCredentials() {
		return this.credentials;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (isAuthenticated) {
			throw new IllegalArgumentException(
					"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		}

		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		credentials = null;
	}

	public String getNick() {
		return nick;
	}

	public String getOpenid() {
		return openid;
	}

	public String getUnionid() {
		return unionid;
	}

	public void setNick(String nick) {
		this.nick = nick;
	}

	public void setOpenid(String openid) {
		this.openid = openid;
	}

	public void setUnionid(String unionid) {
		this.unionid = unionid;
	}

}