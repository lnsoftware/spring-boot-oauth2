package com.rd.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;

/**
 * -@EnableWebSecurity注解以及WebSecurityConfigurerAdapter一起配合提供基于web的security
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new StandardPasswordEncoder();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder());

    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web
                .ignoring()
                .antMatchers("/h2console/**")
                .antMatchers("/api/register")
                .antMatchers("/api/activate")
                .antMatchers("/api/lostpassword")
                .antMatchers("/api/resetpassword")
                .antMatchers("/api/hello");

    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     * #@EnableGlobalMethodSecurity注解，来判断用户对某个控制层的方法是否具有访问权限
     * Spring Security默认是禁用注解的，要想开启注解，需要在继承WebSecurityConfigurerAdapter的类上加该注解
     *
     *   @EnableGlobalMethodSecurity(securedEnabled=true)
     *   开启@Secured 注解过滤权限
     *
     *   @EnableGlobalMethodSecurity(jsr250Enabled=true)
     *   开启@RolesAllowed 注解过滤权限
     *
     *   @EnableGlobalMethodSecurity(prePostEnabled=true)
     *   使用表达式时间方法级别的安全性 4个注解可用
     *   -@PreAuthorize 在方法调用之前,基于表达式的计算结果来限制对方法的访问
     *   -@PostAuthorize 允许方法调用,但是如果表达式计算结果为false,将抛出一个安全性异常
     *   -@PostFilter 允许方法调用,但必须按照表达式来过滤方法的结果
     *   -@PreFilter 允许方法调用,但必须在进入方法之前过滤输入值
     */
    @EnableGlobalMethodSecurity(prePostEnabled = true, jsr250Enabled = true)
    private static class GlobalSecurityConfiguration extends GlobalMethodSecurityConfiguration {
        @Override
        protected MethodSecurityExpressionHandler createExpressionHandler() {
            return new OAuth2MethodSecurityExpressionHandler();
        }

    }

}

