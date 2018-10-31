package com.rd.config;

import com.rd.security.Authorities;
import com.rd.security.CustomAuthenticationEntryPoint;
import com.rd.security.CustomLogoutSuccessHandler;
import com.rd.security.TestDefaultTokenServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.encoding.PasswordEncoder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.JdbcApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.sql.DataSource;

/**
 * OAuth2配置 目前是基于内存的演示【可以修改成基于数据库的】
 * 参考：https://blog.csdn.net/wuzhiwei549/article/details/79815491
 *      http://www.cnblogs.com/charlypage/p/9383420.html
 */
@Configuration
public class OAuth2Configuration {

    /**
     * <b>ResourceServerConfigurerAdapter资源服务器配置</b>
     * <p>
     *  内部关联了ResourceServerSecurityConfigurer和HttpSecurity。前者与资源安全配置相关，后者与http安全配置相关
     * </p>
     */
    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Autowired
        private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

        @Autowired
        private CustomLogoutSuccessHandler customLogoutSuccessHandler;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .exceptionHandling()
                    .authenticationEntryPoint(customAuthenticationEntryPoint)

                    .and()
                    .logout()
                    .logoutUrl("/oauth/logout")
                    .logoutSuccessHandler(customLogoutSuccessHandler)

                    .and()
                    .csrf()
                    .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
                    .disable()
                    .headers()
                    .frameOptions().disable()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                    .and()
                    .authorizeRequests()
                    .antMatchers("/hello/").permitAll()
                    .antMatchers("/secure/**").authenticated();

        }

    }

    /**
     * <b>AuthorizationServerConfigurerAdapter认证服务器配置</b>
     * <p>
     *
     * </p>
     */
    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter implements EnvironmentAware {

        private static final String ENV_OAUTH = "authentication.oauth.";
        private static final String PROP_CLIENTID = "clientid";
        private static final String PROP_SECRET = "secret";
        private static final String PROP_TOKEN_VALIDITY_SECONDS = "tokenValidityInSeconds";

        private RelaxedPropertyResolver propertyResolver;

//      private static String REALM = "OAUTH_REALM";

//      /**
//       * 获取用户信息
//       */
//      @Autowired
//      private UserDetailsService userDetailsService;

//      /**
//       * 加密方式
//       */AuthorizationServerSecurityConfigurer
//      @Autowired
//      private PasswordEncoder passwordEncoder;

//      /**
//       * 声明 ClientDetails实现
//       * Load a client by the client id. This method must not return null.
//       *
//       * @return clientDetails
//       */
//      @Bean
//      public ClientDetailsService clientDetails() {
//          return new JdbcClientDetailsService(dataSource);
//      }

        /**
         * 数据源
         */
        @Autowired
        private DataSource dataSource;

        /**
         * 声明TokenStore实现
         *
         * @return TokenStore
         */
        @Bean
        public TokenStore tokenStore() {
            return new JdbcTokenStore(dataSource);
        }

//      @Bean
//      public AuthorizationCodeServices authorizationCodeServices() {
//          return new JdbcAuthorizationCodeServices(dataSource);
//      }

//      @Bean
//      public ApprovalStore approvalStore(){
//          return new JdbcApprovalStore(dataSource);
//      }

        /**
         * 认证管理器
         */
        @Autowired
        @Qualifier("authenticationManagerBean")
        private AuthenticationManager authenticationManager;

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints)
                throws Exception {
            endpoints.tokenStore(tokenStore());
            endpoints.authenticationManager(authenticationManager);

//          endpoints.userDetailsService(userDetailsService);
//          endpoints.authorizationCodeServices(authorizationCodeServices());
//          endpoints.approvalStore(approvalStore());
//
//            // 为解决获取token并发问题
//          DefaultTokenServices tokenServices = new TestDefaultTokenServices();
//          tokenServices.setTokenStore(endpoints.getTokenStore());
//          tokenServices.setSupportRefreshToken(true);
//          tokenServices.setClientDetailsService(endpoints.getClientDetailsService());
//          tokenServices.setTokenEnhancer(endpoints.getTokenEnhancer());
//
//          endpoints.tokenServices(tokenServices);
        }

        /**
         * 配置令牌端点(Token Endpoint)的安全约束.
         *
         * @param oauthServer oauthServer
         * @throws Exception
         */
        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
//          oauthServer.realm(REALM);
//          oauthServer.passwordEncoder(passwordEncoder);
//          oauthServer.allowFormAuthenticationForClients();
            oauthServer
                    .tokenKeyAccess("permitAll()")
                    .checkTokenAccess("isAuthenticated()");
        }

        /**
         * 配置客户端详情服务（ClientDetailsService）
         * 客户端详情信息在这里进行初始化
         * 通过数据库来存储调取详情信息
         *
         * @param clients
         * @throws Exception
         */
        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            // 1. 数据库方式
//          clients.withClientDetails(clientDetails());
            // 2. 基于内存的方式
            clients
                    .inMemory()
                    .withClient(propertyResolver.getProperty(PROP_CLIENTID))
                    .scopes("bar", "read", "write")
                    .authorities(Authorities.ROLE_ADMIN.name(), Authorities.ROLE_USER.name())
                    .authorizedGrantTypes("password", "refresh_token", "authorization_code")
                    .secret(propertyResolver.getProperty(PROP_SECRET))
                    .accessTokenValiditySeconds(propertyResolver.getProperty(PROP_TOKEN_VALIDITY_SECONDS, Integer.class, 1800));
        }

        /**
         * 读取配置文件
         *
         * @param environment
         */
        @Override
        public void setEnvironment(Environment environment) {
            this.propertyResolver = new RelaxedPropertyResolver(environment, ENV_OAUTH);
        }

    }

}
