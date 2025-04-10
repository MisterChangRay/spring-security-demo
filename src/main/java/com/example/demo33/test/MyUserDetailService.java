package com.example.demo33.test;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.UUID;

@Component
public class MyUserDetailService implements UserDetailsService {
    /**
     * 这里根据用户名加载用户
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println(username + "==========");
        User user = new User();
        user.setPwd("bbb");
        user.setUsername("aaa");
        user.setCredentialsNonExpired(true);
        user.setToken(UUID.randomUUID().toString());
        user.setPermissions(new ArrayList<>(){{
            // 为用户增加权限 permission:read
            this.add(new SimpleGrantedAuthority("permission:read"));
            // 增加admin角色
            this.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }});

        // 缓存登录数据
        Cache.loginedUserMap.put(user.getToken(), user);
        return user;
    }
}
