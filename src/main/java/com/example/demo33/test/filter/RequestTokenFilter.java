package com.example.demo33.test.filter;

import com.example.demo33.test.Cache;
import com.example.demo33.test.User;
import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Objects;

@Component
@WebFilter
public class RequestTokenFilter implements Filter {
    ProviderManager authenticationManager;

    public RequestTokenFilter(ProviderManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
        System.out.println(httpRequest.getRequestURI());
        if(httpRequest.getRequestURI().startsWith("/public")) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        String token = httpRequest.getHeader("token");

        User user = Cache.loginedUserMap.get(token);

        // 这里拿token到redis取用户数据, 然后构造上下文,
        // 我这里直接判断固定的token
        if(Objects.nonNull(user)) {
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(usernamePasswordAuthenticationToken);
            SecurityContextHolder.setContext(context);
        } else {
            // 这里直接抛出异常即可, 也可以自己实现异常 ，继承 AuthenticationException
            throw new CredentialsExpiredException("无效token");
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}

