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

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.dingtalk.api.DefaultDingTalkClient;
import com.dingtalk.api.request.OapiGettokenRequest;
import com.dingtalk.api.response.OapiGettokenResponse;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

/**
 * https://open-doc.dingtalk.com/microapp/serverapi2/eev437
 * @author ： <a href="https://github.com/vindell">wandl</a>
 */
public class DingTalkAccessTokenProvider {

	public static String ACCESS_TOKEN_URL = "https://oapi.dingtalk.com/gettoken";
	public static DefaultDingTalkClient client = new DefaultDingTalkClient(ACCESS_TOKEN_URL);
	
	public static class KeySecret {

		private String accessKey;
		private String accessSecret;

		public KeySecret(String accessKey, String accessSecret) {
			this.accessKey = accessKey;
			this.accessSecret = accessSecret;
		}

		public String getAccessKey() {
			return accessKey;
		}

		public String getAccessSecret() {
			return accessSecret;
		}

		public void setAccessKey(String accessKey) {
			this.accessKey = accessKey;
		}

		public void setAccessSecret(String accessSecret) {
			this.accessSecret = accessSecret;
		}

	}
	
	// 缓存接口这里是LoadingCache，LoadingCache在缓存项不存在时可以自动加载缓存
	private final LoadingCache<KeySecret, String> ACCESS_TOKEN_CACHE
			// CacheBuilder的构造函数是私有的，只能通过其静态方法newBuilder()来获得CacheBuilder的实例
			= CacheBuilder.newBuilder()
					// 设置并发级别为8，并发级别是指可以同时写缓存的线程数
					.concurrencyLevel(8)
					// 设置写缓存后600秒钟过期
					.expireAfterWrite(6000, TimeUnit.SECONDS)
					// 设置缓存容器的初始容量为10
					.initialCapacity(2)
					// 设置缓存最大容量为100，超过100之后就会按照LRU最近虽少使用算法来移除缓存项
					.maximumSize(10)
					// 设置要统计缓存的命中率
					.recordStats()
					// 设置缓存的移除通知
					.removalListener(new RemovalListener<Object, Object>() {
						@Override
						public void onRemoval(RemovalNotification<Object, Object> notification) {
							System.out.println( notification.getKey() + " was removed, cause is " + notification.getCause());
						}
					})
					// build方法中可以指定CacheLoader，在缓存不存在时通过CacheLoader的实现自动加载缓存
					.build(new CacheLoader<KeySecret, String>() {

						@Override
						public String load(KeySecret keys) throws Exception {

							OapiGettokenRequest request = new OapiGettokenRequest();

							request.setAppkey(keys.getAccessKey());
							request.setAppsecret(keys.getAccessSecret());

							request.setHttpMethod("GET");
							OapiGettokenResponse response = client.execute(request);

							return response.getAccessToken();
						}
					});

	public String getAccessToken(KeySecret keySecret) throws ExecutionException {
		return ACCESS_TOKEN_CACHE.get(keySecret);
	}

}
