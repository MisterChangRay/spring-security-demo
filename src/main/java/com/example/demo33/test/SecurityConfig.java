package com.example.demo33.test;

import com.example.demo33.test.filter.RequestTokenFilter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

import java.io.IOException;
import java.util.ArrayList;


@Configuration
@EnableMethodSecurity(securedEnabled = true)
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 这里有提供一个是账号密码登录使用的provider
     * @param userDetailService
     * @return
     */
    @Bean()
        public ProviderManager ProviderManager(MyUserDetailService userDetailService) {
            return new ProviderManager(new ArrayList<>(){{
                DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
                daoAuthenticationProvider.setUserDetailsService(userDetailService);
                daoAuthenticationProvider.setPasswordEncoder( NoOpPasswordEncoder.getInstance());
                this.add(daoAuthenticationProvider);
            }});
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http, RequestTokenFilter mf1) throws Exception {
            http.csrf((t) -> t.disable())
                    .authorizeHttpRequests((authorize) -> authorize
                            .requestMatchers("/public/**").permitAll()
                            .anyRequest().authenticated()
                    )
                    .addFilterBefore(mf1, AuthorizationFilter.class)
                    .sessionManagement((session) -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    )
                    .exceptionHandling(exceptionHandlingConfigurer -> {
                        exceptionHandlingConfigurer
                                // 这里处理所有 AccessDeniedException, 也就是权限校验异常
                                .accessDeniedHandler((request, response, accessDeniedException) -> {
                                    accessDeniedException.printStackTrace();
                                    response.setContentType("application/json;charset=utf-8");
                                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                                    response.getWriter().write("没有权限访问");
                                    response.getWriter().flush();
                                })
                                // 这里处理所有 AuthenticationException, 也就是登录验证异常， 这里直接返回异常消息
                                .authenticationEntryPoint((request, response, authException) -> {
                                    authException.printStackTrace();
                                    response.setContentType("application/json;charset=utf-8");
                                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                                    response.getWriter().write(authException.getMessage());
                                    response.getWriter().flush();
                        });
                    })
                    .httpBasic().disable()
                    .formLogin().disable();

            DefaultSecurityFilterChain build = http.build();
            return build;
        }



}
