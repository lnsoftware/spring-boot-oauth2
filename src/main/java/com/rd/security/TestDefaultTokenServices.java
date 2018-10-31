package com.rd.security;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

/**
 * 描述：重写父类方法，添加线程锁,同步执行创建token、刷新token，解决token高并发问题
 *
 * @Auth yang.m.zhang
 * @Date 10/31/2018 4:27 PM
 * @Version 1.0
 */
public class TestDefaultTokenServices extends DefaultTokenServices {

    @Override
    public synchronized OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
        return super.createAccessToken(authentication);
    }

    @Override
    public synchronized OAuth2AccessToken refreshAccessToken(String refreshTokenValue, TokenRequest tokenRequest) throws AuthenticationException {
        return super.refreshAccessToken(refreshTokenValue, tokenRequest);
    }
}