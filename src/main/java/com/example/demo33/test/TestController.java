package com.example.demo33.test;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping
public class TestController {
    @Autowired
    ProviderManager authenticationManager;


    /**
     * 需要权限访问
     * @return
     */
    @ResponseBody
    @RequestMapping("/test")
    public String test() {
        return "aaa";
    }


    /**
     * 获取登录用户信息
     * @return
     */
    @ResponseBody
    @RequestMapping("/user")
    public User user() {
        User principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return principal;
    }

    /**
     * 获取登录用户信息
     * 验证权限 有角色admin 或者 admin2 才能访问
     *
     * https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html#use-preauthorize
     * @return
     */
    @PreAuthorize(value = "hasRole('ADMIN') || hasRole('ADMIN2')")
    @ResponseBody
    @RequestMapping("/admin")
    public User admin() {
        User principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return principal;
    }


    /**
     * 这里需要有 permission:read 才能访问
     * @return
     */
    @PreAuthorize(value = "hasAuthority('permission:read') ")
    @ResponseBody
    @RequestMapping("/permission1")
    public User permission1() {
        User principal = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return principal;
    }


    /**
     * 登录接口
     * @param name
     * @param pwd
     * @return
     */
    @ResponseBody
    @PostMapping("/public/login")
    public User login(@RequestParam("name") String name, @RequestParam("pwd") String pwd) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(name, pwd);
        Authentication authenticate = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        User principal = (User) authenticate.getPrincipal();

        return principal;
    }


    /**
     * 这里是公共测试函数, 访问这个不需要登录
     * @return
     */
    @ResponseBody
    @RequestMapping("/public")
    public String public1() {
        return "public";
    }
}
