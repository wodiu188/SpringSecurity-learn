# SpringSecurity-learn
springsecurity深入浅出--王松 2021年出版学习笔记

# SpringSecurity啦啦啦

### 认证与授权

#### 认证

用户的信息主要用Authentication来保存

```java
public interface Authentication extends Principal, Serializable {
    Collection<? extends GrantedAuthority> getAuthorities();//获取权限

    Object getCredentials();//获取用户凭证

    Object getDetails();//携带参数

    Object getPrincipal();//获取当前用户

    boolean isAuthenticated();//是否认证成功

    void setAuthenticated(boolean var1) throws IllegalArgumentException;
}
```

当用户使用用户名／密码登录或使用Remember-me登录时，都会对应一个不同的Authentication实例



Spring Security中的认证工作主要由AuthenticationManager接口来负责

```java
public interface AuthenticationManager {
    Authentication authenticate(Authentication var1) throws AuthenticationException;
}
```

如果返回Authentication代表认证成功

抛出异常则认证失败

返回null则不能断定

> AuthenticationManager最主要的实现类是ProviderManager,而他用来管理AuthenticationProvider,在这个类中有一个supports方法用来检测是否支持给定的Authentication类型。而Authentication有着众多的实现类，但不是每个项目都支持所以菜肴进行检测，例如有的项目需要短信认证登录认证

ProviderManager具有一个可选的parent，如果所有的认证都失败就会调用parent进行认证



#### 授权

认证结束后就进行授权了

两个关键的接口:

- AccessDecisionManager
- AccessDecisionVoter

AccessDecisionVoter是个投票器,检查用户是否具有该角色然后进行投票进行赞成,反对或者弃票

AccessDecisionManager则会根据投票结果来判断用户是否有权利访问,会对AccessDecisionVoter进行遍历访问

用户请求的资源所需要的角色会被封装成ConfigAttribute对象,角色名称都带有一个ROLE_前缀，投票器AccessDecisionVoter所做的事情，其实就是比较用户所具备的角色和请求某个资源所需的ConfigAttribute之间的关系。





#### 默认不做配置开启的过滤器

认证授权都是基于过滤器

![Figure-T21_111015](D:\package_and_data\Book\JdReaderEBooks\jd_4657302ffcbc3\30712708_dir_img\OEBPS\Images\Figure-T21_111015.jpg)

@Order注解去调整自定义过滤器在过滤器链中的位置。

默认过滤器并不是直接放在Web项目的原生过滤器链中，而是通过一个FilterChainProxy来统一管理,不仅仅只有一个，可能会有多个,FilterChainProxy通过DelegatingFilterProxy整合到原生过滤器链中

Spring Security会将登录成功的用户信息保存到SecurityContextHolder中



### 基本的过滤配置



基本所有的配置类都需要继承WebSecurityConfigurerAdapter



```java
package com.yh.code.springcode.Config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //.anyRequest().authenticated()代表所有请求认证后才能访问
        http.authorizeRequests().anyRequest().authenticated()
                //and代表将将原来的http返回
                .and()
                //开启表单配置
                .formLogin()
                //设置登录页
                .loginPage("/index.html")
                //设置认证地址
                .loginProcessingUrl("/doLogin")
                //成功跳转
                .defaultSuccessUrl("/index")
                //失败跳转
                .failureUrl("/index.html")
                //接收前端表单的用户名
                .usernameParameter("uname")
                //接收前端表单的密码
                .passwordParameter("passwd")
                //代表跟登录相关的接口认证不做拦截
                .permitAll()
                //表单配置完毕后进行返回
                .and()
                //进行csrf配置
                .csrf()
                //关闭csrf防御功能
                .disable();

    }
}

```

#### defaultSuccessUrl与successForwardUrl

- successForwardUrl:

  - 用户验证成功后强行跳转到该方法设置的页面

  - > 例如请求/user,successForwardUrl设置为/index
    >
    > 用户验证成功后跳向/index

- defaultSuccessUrl:

  - 用户验证成功后如果有自己请求的地址则调向请求地址,如果没有则跳向请求地址

  - >例如请求/user,defaultSuccessUrl设置为/index
    >
    >用户验证成功后跳向/user



