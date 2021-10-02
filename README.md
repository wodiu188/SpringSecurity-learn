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

  - 源码实际就是创建了一个SavedRequestAwareAuthenticationSuccessHandler

  - ```java
        public final T defaultSuccessUrl(String defaultSuccessUrl, boolean alwaysUse) {
            SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
            handler.setDefaultTargetUrl(defaultSuccessUrl);
            handler.setAlwaysUseDefaultTargetUrl(alwaysUse);
            this.defaultSuccessHandler = handler;
            return this.successHandler(handler);
        }
    ```





这两个配置的都是AuthenticationSuccessHandler接口的实例并且该接口才是security用来处理登录成功的事项

其中AuthenticationSuccessHandler有两个方法一个是在处理特定的认证请求Authentication Filter中会用到;另一个用来进行处理登录成功的.

前两个参数很常见,而Authentication则用来传递登陆成功的用户信息

```java
public interface AuthenticationSuccessHandler {
    default void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        this.onAuthenticationSuccess(request, response, authentication);
        chain.doFilter(request, response);
    }

    void onAuthenticationSuccess(HttpServletRequest var1, HttpServletResponse var2, Authentication var3) throws IOException, ServletException;
}
```

AuthenticationSuccessHandler有三个实现类

- SimpleUrlAuthenticationSuccessHandler:通过handle方法实现请求重定向
- SavedRequestAwareAuthenticationSuccessHandler:在SimpleUrlAuthenticationSuccess Handler的基础上增加了请求缓存的功能，可以记录之前请求的地址，进而在登录成功后重定向到一开始访问的地址。
- ForwardAuthenticationSuccessHandler:的实现则比较容易，就是一个服务端跳转。



请求失败和请求成功差不多



#### 注销

注销需要使用注销类所以要使用and()进行切换

```java
 @Override
    protected void configure(HttpSecurity http) throws Exception {
        //.anyRequest().authenticated()代表所有请求认证后才能访问
        http.authorizeRequests()
             
                .and()
                //开启表单配置
                .formLogin()
              
                .and()
                .logout()
                .logoutUrl("/logout")
                //是否清除认证
                .clearAuthentication(true)
                //是否注销session
                .invalidateHttpSession(true)
                .logoutSuccessUrl("/mylogin")
                //表单配置完毕后进行返回
            	.logoutRequestMatcher(new OrRequestMatcher(
                        new AntPathRequestMatcher("/logout1","GET"),
                        new AntPathRequestMatcher("/logout3","POST")
                ))
            
                .and()
                //进行csrf配置
                .csrf()
                //关闭csrf防御功能
                .disable();

    }
```

可以指定多个登出路径并且可以设置请求方法

如果使用的是前后分离则可以自定义.logoutSuccessHandler()

```java
       .logoutSuccessHandler(( req,resp,auth)->{
                    resp.setContentType("application/json;charset=utf-8");
                    Map<String, Object> respH = new HashMap<>();
                    respH.put("status", 200);
                    respH.put("msg", "登出成功!");
                    ObjectMapper om = new ObjectMapper();
                    String s = om.writeValueAsString(resp);
                    resp.getWriter().write(s);
                })
           
                .defaultLogoutSuccessHandlerFor(( req,resp,auth)->{
                    resp.setContentType("application/json;charset=utf-8");
                    Map<String, Object> respH = new HashMap<>();
                    respH.put("status", 200);
                    respH.put("msg", "登出成功!");
                    ObjectMapper om = new ObjectMapper();
                    String s = om.writeValueAsString(resp);
                    resp.getWriter().write(s);
                },new AntPathRequestMatcher("/logout3","POST"))
```

有这两个方法进行自定义一个是设置登出地址的另一个是设置默认的

#### 总结

> 用户的登录成功或失败,注销都差不多
>
> 都可以设置页面只不过登录的表单与注销的表单之间需要用and来切换
>
> 都可以自定义handle(使用lamda表达式更简单)



### 登录的用户数据获取

使用了security后会对httpSession数据进行封装所以我们想要获取用户数据可以获取

- SecurityContextHolder
- HttpSession

但是这两个方法都要用到[认证类Authentication](#认证)

该类有四个信息

>（1）principal：定义认证的用户。如果用户使用用户名／密码的方式登录，principal通常就是一个UserDetails对象。
>（2）credentials：登录凭证，一般就是指密码。当用户登录成功之后，登录凭证会被自动擦除，以防止泄漏。
>（3）authorities：用户被授予的权限信息。
>（4）isAuthenticated()：是否认证



Authentication有很多实现类

> UsernamePasswordAuthenticationToken
>
> JaasAuthenticationToken
>
> TestingAuthenticationToken
>
> PreAuthenticatedAuthenticationToken
>
> RememberMeAuthenticationToken
>
> RunAsUserToken
>
> 等认证最常用的是UsernamePasswordAuthenticationToken和RememberMeAuthenticationToken

emmmm上面这么多认证我们要用的时候要怎么取呢<-_->:dog:看下面

```java
    @RequestMapping("/hello2")
    public String hello2(){
        //获取当前用户信息
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        //获取角色
        Collection<? extends GrantedAuthority> authorities =
                authentication.getAuthorities();
        System.out.println("authorities" + authorities);
        
        //获取用户名
        String name = authentication.getName();
        System.out.println(name);
        return name;
    }
```

从上面可以看出通过SecurityContextHolder的静态方法就可以获取对象了,那为啥能获取呢?

![image-20211002195222829](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211002195222829.png)

根据图可以看出SecurityContextHolder中的内容

SecurityContextHolder的三种数据存储模式:

- MODE_THREADLOCAL:将SecurityContext存到ThreadLocal(那个线程存进去的那个线程才能取,所以一个请求无论经过多少filter和servlet都是一个线程处理的)这种方法如果用子线程取就会取不到,==默认的==
- MODE_INHERITABLETHREADLOCAL：这种存储模式适用于多线程环境，如果希望在==子线程中也能够获取到登录用户数据==，那么可以使用这种存储模式。
- MODE_GLOBAL：这种存储模式实际上是将数据保存在一个静态变量中，在Java Web开发中，这种模式很少使用到。



```java
    public interface SecurityContextHolderStrategy {
        //清理SecurityContext对象。
        void clearContext();
        //获取SecurityContext对象。
        SecurityContext getContext();
        //设置SecurityContext对象。
        void setContext(SecurityContext context);
        //创建一个空的SecurityContext对象。
        SecurityContext createEmptyContext();
    }
```

莫名奇妙给你个这个接口你一定莫名奇妙:dog:,其实这个接口有三个实现类这三个实现类就对应着上面三种模式

![image-20211002201040742](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211002201040742.png)

