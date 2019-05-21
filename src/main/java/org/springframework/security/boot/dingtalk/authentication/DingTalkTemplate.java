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

import com.alibaba.fastjson.JSONObject;
import com.dingtalk.api.DefaultDingTalkClient;
import com.dingtalk.api.DingTalkClient;
import com.dingtalk.api.request.OapiDepartmentGetRequest;
import com.dingtalk.api.request.OapiGettokenRequest;
import com.dingtalk.api.request.OapiSnsGetPersistentCodeRequest;
import com.dingtalk.api.request.OapiSnsGetSnsTokenRequest;
import com.dingtalk.api.request.OapiSnsGettokenRequest;
import com.dingtalk.api.request.OapiSnsGetuserinfoBycodeRequest;
import com.dingtalk.api.request.OapiSnsGetuserinfoRequest;
import com.dingtalk.api.request.OapiUserGetRequest;
import com.dingtalk.api.request.OapiUserGetUseridByUnionidRequest;
import com.dingtalk.api.response.OapiDepartmentGetResponse;
import com.dingtalk.api.response.OapiGettokenResponse;
import com.dingtalk.api.response.OapiSnsGetPersistentCodeResponse;
import com.dingtalk.api.response.OapiSnsGetSnsTokenResponse;
import com.dingtalk.api.response.OapiSnsGettokenResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoResponse;
import com.dingtalk.api.response.OapiUserGetResponse;
import com.dingtalk.api.response.OapiUserGetUseridByUnionidResponse;
import com.google.common.base.Optional;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;
import com.taobao.api.ApiException;

/**
 * https://open-doc.dingtalk.com/microapp/serverapi2/eev437
 * https://blog.csdn.net/yangguosb/article/details/79762565
 * 
 * @author ： <a href="https://github.com/vindell">wandl</a>
 */
public class DingTalkTemplate {

	private final String SDINGTALKSERVICE = "https://oapi.dingtalk.com";
	private final String METHOD_GET = "GET";

	private final LoadingCache<String, Optional<String>> ACCESS_TOKEN_CACHES = CacheBuilder.newBuilder()
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
			.removalListener(new RemovalListener<String, Optional<String>>() {
				@Override
				public void onRemoval(RemovalNotification<String, Optional<String>> notification) {
					System.out.println(notification.getKey() + " was removed, cause is " + notification.getCause());
				}
			})
			// build方法中可以指定CacheLoader，在缓存不存在时通过CacheLoader的实现自动加载缓存
			.build(new CacheLoader<String, Optional<String>>() {

				@Override
				public Optional<String> load(String keySecret) throws Exception {

					OapiGettokenRequest request = new OapiGettokenRequest();

					JSONObject key = JSONObject.parseObject(keySecret);
					//request.setCorpid(key.getString("corpId"));
					//request.setCorpsecret(key.getString("corpSecret"));
					request.setAppkey(key.getString("appKey"));
					request.setAppsecret(key.getString("appSecret"));
					
					request.setHttpMethod(METHOD_GET);
					
					DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/gettoken");
					OapiGettokenResponse response = client.execute(request);

					if (response.isSuccess()) {
						String token = response.getAccessToken();
						return Optional.fromNullable(token);
					}
					return Optional.fromNullable(null);
				}
			});

	private final LoadingCache<String, Optional<String>> SNS_ACCESS_TOKEN_CACHES = CacheBuilder.newBuilder()
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
			.removalListener(new RemovalListener<String, Optional<String>>() {
				@Override
				public void onRemoval(RemovalNotification<String, Optional<String>> notification) {
					System.out.println(notification.getKey() + " was removed, cause is " + notification.getCause());
				}
			})
			// build方法中可以指定CacheLoader，在缓存不存在时通过CacheLoader的实现自动加载缓存
			.build(new CacheLoader<String, Optional<String>>() {

				@Override
				public Optional<String> load(String keySecret) throws Exception {

					OapiSnsGettokenRequest request = new OapiSnsGettokenRequest();

					JSONObject key = JSONObject.parseObject(keySecret);

					request.setAppid(key.getString("appId"));
					request.setAppsecret(key.getString("appSecret"));
					request.setHttpMethod(METHOD_GET);

					DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/sns/gettoken");

					OapiSnsGettokenResponse response = client.execute(request);

					if (response.isSuccess()) {
						String token = response.getAccessToken();
						return Optional.fromNullable(token);
					}
					return Optional.fromNullable(null);

				}
			});

	/**
	 * 
	 * 	企业内部开发获取access_token 先从缓存查，再到钉钉查
	 * https://open-doc.dingtalk.com/microapp/serverapi2/eev437
	 * @param appKey    企业Id
	 * @param appSecret 企业应用的凭证密钥
	 * @return
	 * @throws ExecutionException
	 */
	public String getAccessToken(String appKey, String appSecret) throws ExecutionException {

		JSONObject key = new JSONObject();
		key.put("appKey", appKey);
		key.put("appSecret", appSecret);

		Optional<String> opt = ACCESS_TOKEN_CACHES.get(key.toJSONString());
		return opt.isPresent() ? opt.get() : null;

	}
	
	/**
	 * 获取钉钉开放应用的ACCESS_TOKEN
	 * 
	 * @param appKey
	 * @param appSecret
	 * @return
	 * @throws ExecutionException
	 */
	public String getOpenToken(String appId, String appSecret) throws ExecutionException {

		JSONObject key = new JSONObject();
		key.put("appId", appId);
		key.put("appSecret", appSecret);

		Optional<String> opt = SNS_ACCESS_TOKEN_CACHES.get(key.toJSONString());
		return opt.isPresent() ? opt.get() : null;

	}
	
	/**
	 * 	通过临时授权码Code获取用户信息，临时授权码只能使用一次。
	 * https://open-doc.dingtalk.com/microapp/serverapi2/kymkv6
	 * @throws ApiException 
	 */
	public OapiSnsGetuserinfoBycodeResponse getSnsGetuserinfoBycode( String code, String accessKey, String accessSecret) throws ApiException {
		DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/sns/getuserinfo_bycode");
		OapiSnsGetuserinfoBycodeRequest request = new OapiSnsGetuserinfoBycodeRequest();
		request.setTmpAuthCode(code);
		return client.execute(request, accessKey, accessSecret);
	}
	
	/**
	 * 根据unionid获取userid
	 * https://open-doc.dingtalk.com/microapp/serverapi2/ege851#-5
	 * @throws ApiException 
	 */
	public OapiUserGetUseridByUnionidResponse getUseridByUnionid( String unionid, String accessToken) throws ApiException {
		
		DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/user/getUseridByUnionid");
		OapiUserGetUseridByUnionidRequest request = new OapiUserGetUseridByUnionidRequest();
		request.setUnionid(unionid);
		request.setHttpMethod(METHOD_GET);
		
		return client.execute(request, accessToken);
	}
	
	/**
	 * 获取用户授权的持久授权码
	 * 
	 * @param accessToken
	 * @return
	 */
	public String get_persistent_code(String accessToken, String code) {
		OapiSnsGetPersistentCodeResponse response = null;
		try {
			DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/sns/get_persistent_code");
			OapiSnsGetPersistentCodeRequest request = new OapiSnsGetPersistentCodeRequest();
			request.setTmpAuthCode(code);
			response = client.execute(request, accessToken);
		} catch (ApiException e) {
			e.printStackTrace();
		}
		return response.getBody();
	}

	/**
	 * 获取用户授权的SNS_TOKEN
	 * 
	 * @param openId
	 * @param persistentCode
	 * @param accessToken    开放应用的token
	 * @return
	 */
	public String get_sns_token(String openId, String persistentCode, String accessToken) {
		OapiSnsGetSnsTokenResponse response = null;
		try {
			DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/sns/get_sns_token");
			OapiSnsGetSnsTokenRequest request = new OapiSnsGetSnsTokenRequest();
			request.setOpenid(openId);
			request.setPersistentCode(persistentCode);
			response = client.execute(request, accessToken);
		} catch (ApiException e) {
			e.printStackTrace();
		}
		return response.getSnsToken();
	}

	/**
	 * 获取用户授权的个人信息
	 * 
	 * @param snsToken
	 * @return
	 */
	public String get_sns_userinfo_unionid(String snsToken) {
		OapiSnsGetuserinfoResponse response = null;
		try {
			DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/sns/getuserinfo");
			OapiSnsGetuserinfoRequest request = new OapiSnsGetuserinfoRequest();
			request.setSnsToken(snsToken);
			request.setHttpMethod(METHOD_GET);
			response = client.execute(request);
		} catch (ApiException e) {
			e.printStackTrace();
		}
		return response.getBody();
	}

	

	/**
	 * 获取用户授权的个人信息
	 * 
	 * @param accessToken
	 * @param uid
	 * @return
	 */
	public String getUserGetOne(String accessToken, String uid) {
		OapiUserGetResponse response = null;
		try {
			DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/user/get");
			OapiUserGetRequest request = new OapiUserGetRequest();
			request.setUserid(uid);
			request.setHttpMethod(METHOD_GET);
			response = client.execute(request, accessToken);
		} catch (ApiException e) {
			e.printStackTrace();
		}
		return response.getBody();
	}

	/**
	 * 获取部门详情（根据部门id查询）
	 * 
	 * @param accessToken
	 * @param deptid
	 * @return
	 * @throws ApiException
	 */
	public OapiDepartmentGetResponse getDepartmentInfo(String accessToken, String deptid) throws ApiException {
		DingTalkClient client = new DefaultDingTalkClient(SDINGTALKSERVICE + "/department/get");
		OapiDepartmentGetRequest request = new OapiDepartmentGetRequest();
		request.setId(deptid);
		request.setHttpMethod(METHOD_GET);
		return client.execute(request, accessToken);
	}

}
