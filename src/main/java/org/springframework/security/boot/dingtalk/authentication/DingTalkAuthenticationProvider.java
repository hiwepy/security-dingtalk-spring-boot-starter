package org.springframework.security.boot.dingtalk.authentication;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.SecurityDingTalkProperties;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkCropAppProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkLoginProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkPersonalMiniAppProperties;
import org.springframework.security.boot.dingtalk.property.SecurityDingTalkSuiteProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse.UserInfo;
import com.dingtalk.api.response.OapiUserGetResponse;
import com.dingtalk.api.response.OapiUserGetUseridByUnionidResponse;
import com.dingtalk.api.response.OapiUserGetuserinfoResponse;
import com.taobao.api.ApiException;

public class DingTalkAuthenticationProvider implements AuthenticationProvider, InitializingBean {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final UserDetailsServiceAdapter userDetailsService;
    private final SecurityDingTalkProperties dingtalkProperties;
    private final DingTalkTemplate dingTalkTemplate;
    private Map<String, String> appKeySecret = new ConcurrentHashMap<>();
    
    public DingTalkAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService,
    		final DingTalkTemplate dingTalkTemplate,
    		final SecurityDingTalkProperties dingtalkProperties) {
        this.userDetailsService = userDetailsService;
        this.dingTalkTemplate = dingTalkTemplate;
        this.dingtalkProperties = dingtalkProperties;
    }

	@Override
	public void afterPropertiesSet() throws Exception {
		
		if(!CollectionUtils.isEmpty(this.dingtalkProperties.getCropApps())) {
			for (SecurityDingTalkCropAppProperties properties : this.dingtalkProperties.getCropApps()) {
				appKeySecret.put(properties.getAppKey(), properties.getAppSecret());
			}
		}
		if(!CollectionUtils.isEmpty(this.dingtalkProperties.getApps())) {
			for (SecurityDingTalkPersonalMiniAppProperties properties : this.dingtalkProperties.getApps()) {
				appKeySecret.put(properties.getAppId(), properties.getAppSecret());
			}
		}
		if(!CollectionUtils.isEmpty(this.dingtalkProperties.getSuites())) {
			for (SecurityDingTalkSuiteProperties properties : this.dingtalkProperties.getSuites()) {
				appKeySecret.put(properties.getAppId(), properties.getSuiteSecret());
			}
		}
		if(!CollectionUtils.isEmpty(this.dingtalkProperties.getLogins())) {
			for (SecurityDingTalkLoginProperties properties : this.dingtalkProperties.getLogins()) {
				appKeySecret.put(properties.getAppId(), properties.getAppSecret());
			}
		}
		
		logger.debug(appKeySecret.toString());
		
	}
    
    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link DingTalkAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
    	DingTalkLoginRequest loginRequest = (DingTalkLoginRequest) authentication.getPrincipal();

		if ( !StringUtils.hasText(loginRequest.getCode()) && !StringUtils.hasText(loginRequest.getLoginTmpCode())) {
			logger.debug("No loginTmpCode or Code found in request.");
			throw new DingTalkCodeNotFoundException("No loginTmpCode or Code found in request.");
		}
		
		try {

			if(!appKeySecret.containsKey(loginRequest.getKey())) {
				logger.debug("Invalid App Key {} .", loginRequest.getKey());
				throw new DingTalkCodeNotFoundException("Invalid App Key.");
			}
			
			String appKey = loginRequest.getKey();
			String appSecret = appKeySecret.get(loginRequest.getKey());
			// 获取access_token
			String accessToken = dingTalkTemplate.getAccessToken(appKey, appSecret);
			
			DingTalkAuthenticationToken dingTalkToken = (DingTalkAuthenticationToken) authentication;
			
			// 企业内部应用免登录：通过免登授权码和access_token获取用户信息
			if(StringUtils.hasText(loginRequest.getCode())) {
				dingTalkToken = doAuthenticationByCode(authentication, accessToken, loginRequest.getCode());
			}
			// 第三方应用钉钉扫码登录：通过临时授权码Code获取用户信息，临时授权码只能使用一次
			else if(StringUtils.hasText(loginRequest.getLoginTmpCode())) {
				dingTalkToken = doAuthenticationByTmpCode(authentication, accessToken, loginRequest.getLoginTmpCode(), appKey, appSecret);
			}
			
			UserDetails ud = getUserDetailsService().loadUserDetails(dingTalkToken);
	        
	        // User Status Check
	        getUserDetailsChecker().check(ud);
	        
	        DingTalkAuthenticationToken authenticationToken = null;
	        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
	        	SecurityPrincipal principal = (SecurityPrincipal) ud;
	        	if(!StringUtils.hasText(principal.getAlias())) {
	        		principal.setAlias(dingTalkToken.getNick());
	        	}
	        	authenticationToken = new DingTalkAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
	        } else {
	        	authenticationToken = new DingTalkAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
			}
	        authenticationToken.setDetails(authentication.getDetails());
	        
	        return authenticationToken;
		} catch (ApiException e) {
			throw new DingTalkAuthenticationServiceException(e.getErrMsg(), e);
		} catch (ExecutionException e) {
			throw new InternalAuthenticationServiceException(e.getMessage(), e);
		}
    }

    protected DingTalkAuthenticationToken doAuthenticationByCode(Authentication authentication, String accessToken, String code) throws ApiException{


		DingTalkAuthenticationToken dingTalkToken = (DingTalkAuthenticationToken) authentication;
			
		OapiUserGetuserinfoResponse response = dingTalkTemplate.getUserinfoBycode(code, accessToken);
		/*{
		    "userid": "****",
		    "sys_level": 1,
		    "errmsg": "ok",
		    "is_sys": true,
		    "errcode": 0
		}*/
		if (logger.isDebugEnabled()) {
			logger.debug(response.getCode());
		}

		if(!response.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthResponse.of(response.getErrorCode(), response.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(response.getErrmsg());
		}
		
		OapiUserGetResponse userInfoResponse = dingTalkTemplate.getUserByUserid(response.getUserid(), accessToken);
		if(!userInfoResponse.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthResponse.of(userInfoResponse.getErrorCode(), userInfoResponse.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(userInfoResponse.getErrmsg());
		}
		
		// 解析钉钉用户信息到Token对象
		this.extractRespone(dingTalkToken, userInfoResponse);
		
		return dingTalkToken;
    }
    
	protected DingTalkAuthenticationToken doAuthenticationByTmpCode(Authentication authentication, String accessToken, String loginTmpCode, String appId, String appSecret) throws ApiException{
    	
    	// 第三方应用钉钉扫码登录：通过临时授权码Code获取用户信息，临时授权码只能使用一次
		OapiSnsGetuserinfoBycodeResponse response = dingTalkTemplate.getSnsGetuserinfoBycode(loginTmpCode, appId, appSecret);
		/*{ 
		    "errcode": 0,
		    "errmsg": "ok",
		    "user_info": {
		        "nick": "张三",
		        "openid": "liSii8KCxxxxx",
		        "unionid": "7Huu46kk"
		    }
		}*/
		if (logger.isDebugEnabled()) {
			logger.debug(response.getCode());
		}

		if(!response.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthResponse.of(response.getErrorCode(), response.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(response.getErrmsg());
		}
			
		UserInfo userInfo = response.getUserInfo();
		
		DingTalkAuthenticationToken dingTalkToken = (DingTalkAuthenticationToken) authentication;
		
		dingTalkToken.setNick(userInfo.getNick());
		dingTalkToken.setOpenid(userInfo.getOpenid());
		dingTalkToken.setUnionid(userInfo.getUnionid());
		
		// 根据unionid获取userid
		OapiUserGetUseridByUnionidResponse unionidResponse = dingTalkTemplate.getUseridByUnionid(userInfo.getUnionid(), accessToken);
		if(!unionidResponse.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthResponse.of(unionidResponse.getErrorCode(), unionidResponse.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(unionidResponse.getErrmsg());
		}
		
		// 根据UserId 获取用户信息
		OapiUserGetResponse userInfoResponse = dingTalkTemplate.getUserByUserid(unionidResponse.getUserid(), accessToken);
		if(!userInfoResponse.isSuccess()) {
			logger.error(JSONObject.toJSONString(AuthResponse.of(userInfoResponse.getErrorCode(), userInfoResponse.getErrmsg())));
			throw new DingTalkAuthenticationServiceException(userInfoResponse.getErrmsg());
		}
		// 解析钉钉用户信息到Token对象
		this.extractRespone(dingTalkToken, userInfoResponse);
		return dingTalkToken;
    }

    /*    
	 {
	    "active":true,
	    "avatar":"https://static.dingtalk.com/media/lADPBbCc1dSekr_NAczNAcw_460_460.jpg",
	    "body":"{"errcode":0,"unionid":"DhoiSf4ug6KuOpAY95CytZwiEiE","userid":"061955121419944345","isLeaderInDepts":"{110421538:false}","isBoss":false,"isSenior":false,"department":[110421538],"orderInDepts":"{110421538:176362815343598512}","errmsg":"ok","active":true,"avatar":"https://static.dingtalk.com/media/lADPBbCc1dSekr_NAczNAcw_460_460.jpg","isAdmin":false,"tags":{},"isHide":false,"jobnumber":"","name":"万大龙","position":"高级JAVA开发"}",
	    "department":[
	        110421538
	    ],
	    "errcode":0,
	    "errmsg":"ok",
	    "errorCode":"0",
	    "isAdmin":false,
	    "isBoss":false,
	    "isHide":false,
	    "isLeaderInDepts":"{110421538:false}",
	    "isSenior":false,
	    "jobnumber":"",
	    "msg":"ok",
	    "name":"",
	    "orderInDepts":"{110421538:176362815343598512}",
	    "params":{
	        "userid":"061955121419944345"
	    },
	    "position":"高级JAVA开发",
	    "success":true,
	    "unionid":"DhoiSf4ug6KuOpAY95CytZwiEiE",
	    "userid":"061955121419944345"
	} 
	*/
    @SuppressWarnings("unchecked")
	protected void extractRespone(DingTalkAuthenticationToken dingTalkToken, OapiUserGetResponse userInfoResponse) {

		dingTalkToken.setActive(userInfoResponse.getActive());
		dingTalkToken.setAdmin(userInfoResponse.getIsAdmin());
		dingTalkToken.setAvatar(userInfoResponse.getAvatar());
		dingTalkToken.setBoss(userInfoResponse.getIsBoss());
		dingTalkToken.setDepts(userInfoResponse.getDepartment());
		dingTalkToken.setEmail(userInfoResponse.getEmail());
		if(StringUtils.hasText(userInfoResponse.getExtattr())) {
			dingTalkToken.setExtattr(JSONObject.parseObject(userInfoResponse.getExtattr(), Map.class));
		}
		dingTalkToken.setHide(userInfoResponse.getIsHide());
		dingTalkToken.setHiredDate(userInfoResponse.getHiredDate());
		dingTalkToken.setInviteMobile(userInfoResponse.getInviteMobile());
		dingTalkToken.setJobnumber(userInfoResponse.getJobnumber());
		dingTalkToken.setMobile(userInfoResponse.getMobile());
		dingTalkToken.setName(userInfoResponse.getName());
		dingTalkToken.setNick(userInfoResponse.getNickname());
		dingTalkToken.setOrgEmail(userInfoResponse.getOrgEmail());
		dingTalkToken.setPosition(userInfoResponse.getPosition());
		dingTalkToken.setPrincipal(userInfoResponse.getUserid());
		dingTalkToken.setRemark(userInfoResponse.getRemark());
		dingTalkToken.setRoles(userInfoResponse.getRoles());
		dingTalkToken.setSenior(userInfoResponse.getIsSenior());
		dingTalkToken.setStateCode(userInfoResponse.getStateCode());
		dingTalkToken.setTel(userInfoResponse.getTel());
		dingTalkToken.setWorkPlace(userInfoResponse.getWorkPlace());
		
	}
    
    
    @Override
    public boolean supports(Class<?> authentication) {
        return (DingTalkAuthenticationToken.class.isAssignableFrom(authentication));
    }

	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}
