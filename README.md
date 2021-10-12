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

#### 第一种数据获取方式



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

##### SecurityContextHolder的三种数据存储模式



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



源码：

```java
final class ThreadLocalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();

	@Override
	public void clearContext() {
		contextHolder.remove();
	}

	@Override
	public SecurityContext getContext() {
		SecurityContext ctx = contextHolder.get();
		if (ctx == null) {
			ctx = createEmptyContext();
			contextHolder.set(ctx);
		}
		return ctx;
	}

	@Override
	public void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		contextHolder.set(context);
	}

	@Override
	public SecurityContext createEmptyContext() {
		return new SecurityContextImpl();
	}

}

final class InheritableThreadLocalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private static final ThreadLocal<SecurityContext> contextHolder = new InheritableThreadLocal<>();

	@Override
	public void clearContext() {
		contextHolder.remove();
	}

	@Override
	public SecurityContext getContext() {
		SecurityContext ctx = contextHolder.get();
		if (ctx == null) {
			ctx = createEmptyContext();
			contextHolder.set(ctx);
		}
		return ctx;
	}

	@Override
	public void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		contextHolder.set(context);
	}

	@Override
	public SecurityContext createEmptyContext() {
		return new SecurityContextImpl();
	}

}

```

从ThreadLocalSecurityContextHolderStrategy该源码可知new ThreadLocal<>();

而InheritableThreadLocalSecurityContextHolderStrategy的源码可知 new InheritableThreadLocal<>();

其他基本都是一样的,InheritableThreadLocal对比ThreadLocal的最大特点是==子线程创建的时候会将父线程的数据复制到子线程==

```java
final class GlobalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private static SecurityContext contextHolder;

```

对于GlobalSecurityContextHolderStrategy只是一个普通的static类



##### SecurityContextHolder

聊完了三种模式我们再回头看看SecurityContextHolder这个可以获取用户数据的类

```java
public class SecurityContextHolder {

	public static final String MODE_THREADLOCAL = "MODE_THREADLOCAL";

	public static final String MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL";

	public static final String MODE_GLOBAL = "MODE_GLOBAL";

	public static final String SYSTEM_PROPERTY = "spring.security.strategy";

	private static String strategyName = System.getProperty(SYSTEM_PROPERTY);

	private static SecurityContextHolderStrategy strategy;

	private static int initializeCount = 0;
    
    private static void initialize() {
		if (!StringUtils.hasText(strategyName)) {
			// Set default
			strategyName = MODE_THREADLOCAL;
		}
		if (strategyName.equals(MODE_THREADLOCAL)) {
			strategy = new ThreadLocalSecurityContextHolderStrategy();
		}
		else if (strategyName.equals(MODE_INHERITABLETHREADLOCAL)) {
			strategy = new InheritableThreadLocalSecurityContextHolderStrategy();
		}
		else if (strategyName.equals(MODE_GLOBAL)) {
			strategy = new GlobalSecurityContextHolderStrategy();
		}
		else {
			// Try to load a custom strategy
			try {
				Class<?> clazz = Class.forName(strategyName);
				Constructor<?> customStrategy = clazz.getConstructor();
				strategy = (SecurityContextHolderStrategy) customStrategy.newInstance();
			}
			catch (Exception ex) {
				ReflectionUtils.handleReflectionException(ex);
			}
		}
		initializeCount++;
	}
```

可以看到上面三个常量代表的就是三个模式,第四个变量代表从配置文件如何获取配置

第五个才是确定要用的模式,可以看出默认是从配置文件中获取的



我们不同的请求是通过不同的线程处理的那为啥那为什么每一次请求都还能从SecurityContextHolder中获取到登录用户信息呢？

这就得看:SecurityContextPersistenceFilter的了



##### SecurityContextPersistenceFilter

这个实例主要做两个事情:

>（1）当一个请求到来时，从HttpSession中获取SecurityContext并存入SecurityContext Holder中，这样在同一个请求的后续处理过程中，开发者始终可以通过SecurityContextHolder获取到当前登录用户信息。
>（2）当一个请求处理完毕时，从SecurityContextHolder中获取SecurityContext并存入HttpSession中（主要针对异步Servlet），方便下一个请求到来时，再从HttpSession中拿出来使用，同时擦除SecurityContextHolder中的登录用户信息。

而上面这两个事情是由SecurityContextPersistence来做的

SecurityContextRepository:

```java
public interface SecurityContextRepository {
    //这个方法用来加载SecurityContext对象出来，对于没有登录的用户，这里会返回一个空的SecurityContext对象，注意空的SecurityContext对象是指SecurityContext中不存在Authentication对象，而不是该方法返回null。
    SecurityContext loadContext(HttpRequestResponseHolder var1);

    //该方法用来保存一个SecurityContext对象。
    void saveContext(SecurityContext var1, HttpServletRequest var2, HttpServletResponse var3);

    //该方法可以判断SecurityContext对象是否存在。
    boolean containsContext(HttpServletRequest var1);
}

```

而该接口有三个实现类:

![image-20211003122105142](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211003122105142.png)

NullSecurityContextRepository对数据的操作没有任何实现

TestSecurityContextRepository用于单元测试

HttpSeesionSecurityContextRepository默认的其中实现类数据的存储与读取



在HttpSeesionSecurityContextRepository中定义了SaveToSessionRequestWrapper与SaveToSessionResponseWrapper



###### 首先来看SaveToSessionResponseWrapper:

![image-20211003122321618](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211003122321618.png)

从上图可知该类实现了HttpServletResponse并且还继承了三个类:

- HttpServletResponseWrapper:利用该类可以方便地操作参数和输出流等。
- OnCommittedResponseWrapper:对上面的类进行了增强,最重要的增强在于可以获取HttpServletResponse的提交行为。不过onResponseCommitted方法只是一个抽象方法
- SaveContextOnUpdateOrErrorResponseWrapper:该类实现了onResponseCommitted方法,但是定义了一个saveContext的抽象方法用来获取SecurityContext,只有是否存储成功用声明的contextSaved变量，表示SecuirtyContext是否已经存储成功。



回到SaveToSessionResponseWrapper该类继承SaveContextOnUpdateOrErrorResponseWrapper并实现了saveContext这个抽象方法,除了这个还有该类定义的另两个方法,下面呈现主要的三个定义方法:

- saveContext:==该方法主要是用来保存SecurityContext，==如果authentication对象为null或者它是一个匿名对象，则不需要保存SecurityContext（参见SEC-776：https://github.com/spring-projects/spring-security/issues/1036）；同时，如果==httpSession不为null并且authBefore Execution也不为null，就从httpSession中将保存的登录用户数据移除，这个主要是为了防止开发者在注销成功的回调中继续调用chain.doFilter方法，进而导致原始的登录信息无法清除的问题==（参见SEC-1587：https://github.com/spring-projects/spring-security/issues/1826）；如果httpSession为null，则去创建一个HttpSession对象；最后，如果SecurityContext发生了变化，或者httpSession中没有保存SecurityContext，则调用httpSession中的setAttribute方法将SecurityContext保存起来。
- contextChanged：该方法主要用来判断SecurityContext是否发生变化
- createNewSessionIfAllowed：该方法用来创建一个HttpSession对象。



SaveToSessionRequestWrapper类这个可比上面这个简单多了



###### SaveToSessionRequestWrapper

封装的SaveToSession RequestWrapper类主要作用是禁止在异步Servlet提交时，自动保存SecurityContext。

为啥要禁止呢?还记得前面讲的子线程无法从TreadLocal中获取父线程的SecurityContext吗,所以当异步保存时会报错.

所以SaveToSessionRequestWrapper会将自动保存禁止掉所以这一功能在SecurityContextPersistenceFilter过滤器中完成SecurityContext保存操作。



###### HttpSeesionSecurityContextRepository

聊完该类里面定义的两个类来聊聊这个大类

首先时开头几个定义

```java
	//定义了SecurityContext在HttpSession中存储的key
	public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";
	
    protected final Log logger = LogFactory.getLog(this.getClass());
    private final Object contextObject = SecurityContextHolder.createEmptyContext();
	//allowSessionCreation用来设置是否允许创建HttpSession，默认是true。
    private boolean allowSessionCreation = true;

	//disableUrlRewriting表示是否禁用URL重写，默认是false。
    private boolean disableUrlRewriting = false;

	//springSecurityContextKey可以用来配置HttpSession中存储SecurityContext的key
    private String springSecurityContextKey = "SPRING_SECURITY_CONTEXT";

	//用来获取是rememberMe认证还是匿名用户
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	//获取SecurityContext,如果发现为空则创建一个并保存在HttpRequestResponseHolder对象中
 	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder){...};

	//用来保存SecurityContext,正常情况下在HttpServletResponse提交时就会被保存但是异步就由该方法保存
	public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {...};
	//用来判断当前请求中是否存在SecurityContext
	public boolean containsContext(HttpServletRequest request){...};

	//实现了如果从HttpSession中读取并存储为SecurityContext后返回,loadContext方法就调用了该方法
    private SecurityContext readSecurityContextFromSession(HttpSession httpSession){...};

	//该方法用来生成一个不包含Authentication的空的SecurityContext对象,loadContext方法就调用了该方法
	protected SecurityContext generateNewContext() {
        return SecurityContextHolder.createEmptyContext();
    }
	
	//判断当前Authentication是否免于存储。
	private boolean isTransientAuthentication(Authentication authentication)
        
	//    setTrustResolver方法用来配置身份评估器。
    public void setTrustResolver(AuthenticationTrustResolver trustResolver)
```



解决完HttpSeesionSecurityContextRepository就可以回到主体：

doFilter()

```java
 private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request.getAttribute("__spring_security_scpf_applied") != null) {
            chain.doFilter(request, response);
        } else {
            request.setAttribute("__spring_security_scpf_applied", Boolean.TRUE);
            if (this.forceEagerSessionCreation) {
                HttpSession session = request.getSession();
                if (this.logger.isDebugEnabled() && session.isNew()) {
                    this.logger.debug(LogMessage.format("Created session %s eagerly", session.getId()));
                }
            }

            HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
            SecurityContext contextBeforeChainExecution = this.repo.loadContext(holder);
            boolean var10 = false;

            try {
                var10 = true;
                SecurityContextHolder.setContext(contextBeforeChainExecution);
                if (contextBeforeChainExecution.getAuthentication() == null) {
                    this.logger.debug("Set SecurityContextHolder to empty SecurityContext");
                } else if (this.logger.isDebugEnabled()) {
                    this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", contextBeforeChainExecution));
                }

                chain.doFilter(holder.getRequest(), holder.getResponse());
                var10 = false;
            } finally {
                if (var10) {
                    SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
                    SecurityContextHolder.clearContext();
                    this.repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
                    request.removeAttribute("__spring_security_scpf_applied");
                    this.logger.debug("Cleared SecurityContextHolder to complete request");
                }
            }

            SecurityContext contextAfterChainExecution = SecurityContextHolder.getContext();
            SecurityContextHolder.clearContext();
            this.repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
            request.removeAttribute("__spring_security_scpf_applied");
            this.logger.debug("Cleared SecurityContextHolder to complete request");
        }
    }
```

1. 首先从request中取出变量如果不是空就继续执行后面的,这里应该是防止异步
2. 接下来对上面提到的那个变量设置为true之后判断forceEagerSessionCreation默认为false如果为true则要进行确会话有效操作,但是比较耗费资源
3. 使用构造方法来构造出[HttpRequestResponseHolder](#SecurityContextHolder)并将request和response存进去
4. 然后加载一个SecurityContext并存入刚刚构造的HttpRequestResponseHolder实例里面
5. 判断是否为匿名用户或无效用户
6. finally的作用是如果没有正常保存则进行保存
7. 最后进行清空操作



#### 第二种数据获取方式

```java
  @RequestMapping("/authentication")
    public void authentication(Authentication authentication) {
       System.out.println("authentication = " + authentication);
    }
    @RequestMapping("/principal")
    public void principal(Principal principal) {
       System.out.println("principal = " + principal);
    }
```

经过验证上面两个的结果一样但是这些数据和springMVC一样都是由HttpServletRequest来提供的

一个普通的web项目不使用任何框架，请求是由tomcat提供RequestFacade来填充HttpServletRequest，由名字可以看出使用的是外观模式（Facade）这样防止使用者直接调用Tomcat的内部方法，但是如果使用了springSecurity则提供SecurityContextHolderAwareRequestWrapper来进行填充



> principal和authentication的数据都是由HttpServletRequest带来的,而在
>
> 不用框架则是RequestFacade实现
>
> 使用了springsecurity则是由Servlet3SecurityContextHolderAwareRequestWrapper来实现的并且实现类servlet3.0规范
>
> 他的上层实现了servlet3.0之前的规范
>
> (讲道理我观察到的HttpServletRequest是SecurityContextHolderAwareRequestWrapper即该层实现了servlet3.0之前的规范)



并且我们观察SecurityContextHolderAwareRequestWrapper类

![image-20211008095855652](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211008095855652.png)

- getAuthentication():获取Authentication对象,和SpringContextHolder中获取的一样

- getRemoteUser():获取用户名

- getUserPrincipal():该方法当前登录用户对象

- isGranted():判断用户是否具有具体指定的某一用户

- isUserInRole():判断用户是否具有某功能的用户

==所以可以看出第一种方法也可以直接使用HttpServletRequest获取==



至于如何将请求转化为Servlet3SecurityContextHolderAware RequestWrapper呢,这就是SecurityContextHolderAwareRequestFilter的工作,详细代码如下(只留重点非全部代码)

```java
public class SecurityContextHolderAwareRequestFilter extends GenericFilterBean {
    private String rolePrefix = "ROLE_";
    private HttpServletRequestFactory requestFactory;


    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        chain.doFilter(this.requestFactory.create((HttpServletRequest)req, (HttpServletResponse)res), res);
    }


    private void updateFactory() {
        String rolePrefix = this.rolePrefix;
        this.requestFactory = this.createServlet3Factory(rolePrefix);
    }
}
```

可以看出doFilter是直接创建了一个HttpServletRequset并且是通过createServlet3Factory()来创建该方法会创建一个,HttpServlet3RequestFactory而这个方法就是用来创建Servlet3SecurityContextHolderAwareRequestWrapper



### 用户自定义数据获取

我们可以重写WebSecurityConfigurerAdapter类的configure(AuthenticationManagerBuilder)方法

```java
   @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
       manager.createUser(User.withUsername("javaboy")
                                 .password("{noop}123").roles("admin").build());
       manager.createUser(User.withUsername("sang")
                                  .password("{noop}123").roles("user").build());
       auth.userDetailsService(manager);
}
```

{noop}代表不加密

而InMemoryUserDetailsManager内部是使用HashMap来实现的



#### 基于JdbcUserDetailsManager

JdbcUserDetailsManager提供了数据库脚本

```mysql
create table `users`(
	`username` varchar(500) primary key,
    `password` varchar(500) not null,
    `enabled` boolean not null
);
create table `authorities` (
	`username` varchar(50) not null,
    `authority` varchar(50) not null,
    constraint fk_authorities_users foreign key(username) references users(username)
);
create unique index ix_auth_username on authorities (username,authority);
```



准备依赖

```xml
 <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-jdbc</artifactId>
    </dependency>
    <dependency>
       <groupId>mysql</groupId>
       <artifactId>mysql-connector-java</artifactId>
    </dependency>
```

数据源配置

```yaml
spring:
  datasource:
    password: 123456
    username: root
    url: jdbc:mysql://localhost:3306/security_authority?serverTimezone=UTC
```

然后就可以在前一小节的config方法中进行数据的控制

```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);

        if(!manager.userExists("YH")){
            manager.createUser(User.withUsername("YH").password("{noop}123456").roles("admin").build());
        }

        if(!manager.userExists("ZZ")){
            manager.createUser(User.withUsername("ZZ").password("{noop}123456").roles("user").build());
        }

        auth.userDetailsService(manager);
    }
```



- 创建数据库
- 导入依赖
- 配置连接参数
- 将数据写入获取对象的方法中

这里使用的是JdbcUserDetailsManager类,因为该类继承了UserDetailsService,在系统中获取用户数据是调用该接口的loadUserByUsername方法



> JDBC默认调用的是users表和authorities表
>
> JdbcUserDetailsManager则继承自JdbcDaoImpl，同时完善了数据库操作，又封装了用户的增删改查方法。



#### 基于Mybatis

首先是三表关系

![image-20211008163428372](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211008163428372.png)

首先建表

```mysql
 CREATE TABLE `role` (
     `id` int(11) NOT NULL AUTO_INCREMENT,
     `name` varchar(32) DEFAULT NULL,
     `nameZh` varchar(32) DEFAULT NULL,
     PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
 
    CREATE TABLE `user` (
     `id` int(11) NOT NULL AUTO_INCREMENT,
     `username` varchar(32) DEFAULT NULL,
     `password` varchar(255) DEFAULT NULL,
     `enabled` tinyint(1) DEFAULT NULL,
     `accountNonExpired` tinyint(1) DEFAULT NULL,
     `accountNonLocked` tinyint(1) DEFAULT NULL,
     `credentialsNonExpired` tinyint(1) DEFAULT NULL,
     PRIMARY KEY (`id`)
   ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
 
    CREATE TABLE `user_role` (
     `id` int(11) NOT NULL AUTO_INCREMENT,
     `uid` int(11) DEFAULT NULL,
     `rid` int(11) DEFAULT NULL,
     PRIMARY KEY (`id`),
     KEY `uid` (`uid`),
     KEY `rid` (`rid`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
    
    #插入数据
     INSERT INTO `role` (`id`, `name`, `nameZh`)
    VALUES
       (1,'ROLE_dba','数据库管理员'),
       (2,'ROLE_admin','系统管理员'),
       (3,'ROLE_user','用户');
 
    INSERT INTO `user` (`id`, `username`, `password`, `enabled`,
           `accountNonExpired`, `accountNonLocked`, `credentialsNonExpired`)
    VALUES
       (1,'root','{noop}123',1,1,1,1),
       (2,'admin','{noop}123',1,1,1,1),
       (3,'sang','{noop}123',1,1,1,1);
 
    INSERT INTO `user_role` (`id`, `uid`, `rid`)
    VALUES
       (1,1,1),
       (2,1,2),
       (3,2,2),
       (4,3,3);
```

首先导入依赖

```xml
 <dependency>
       <groupId>org.mybatis.spring.boot</groupId>
       <artifactId>mybatis-spring-boot-starter</artifactId>
       <version>2.1.3</version>
    </dependency>
    <dependency>
       <groupId>mysql</groupId>
       <artifactId>mysql-connector-java</artifactId>
    </dependency>
```

数据库连接配置

```yaml
spring:
  datasource:
    password: 123456
    username: root
    url: jdbc:mysql://localhost:3306/security_authority?serverTimezone=UTC
```



创建用户类和角色类(角色类需要继承UserDetails)

```java
@Data
public class User implements UserDetails {

    private int id;
    private String username;
    private String password;
    //是否可用
    private Boolean enabled;
    //是否过期
    private Boolean accountNonExpired;
    //是否被锁定
    private Boolean accountNonLocked;
    //凭证是否过期
    private Boolean credentialsNonExpired;

    private List<Role> roles = new ArrayList<>();

    //系统获取用户角色权限
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return authorities;

    }

    @Override
    public boolean isAccountNonExpired() {
        return this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }
}

@Data
public class Role {
    private Integer id;
    private String name;
    private String nameZh;

}
```

创建UserMapper

```java
@Mapper
@Repository
public interface UserMapper {

    List<Role> getRolesByUid(Integer id);

    User loadUserByUsername(String username);

}
```

创建UserMapper.xml

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.yh.code.springcode.Mapper.UserMapper">
    <select id="loadUserByUsername"
            resultType="com.yh.code.springcode.Entity.User">
           select * from security_authority.user where username=#{username};
       </select>
    <select id="getRolesByUid" resultType="com.yh.code.springcode.Entity.Role">
           select r.* from security_authority.role r,security_authority.user_role ur where r.`id`=ur.`rid`
       </select>

</mapper>
```

在pom.xml文件中设置打包不过滤

```xml
   <build>
       <resources>
           <resource>
               <directory>src/main/java</directory>
               <includes>
                   <include>**/*.xml</include>
               </includes>
           </resource>
           <resource>
               <directory>src/main/resources</directory>
           </resource>
       </resources>
    </build>
```

创建服务类

```java
   @Service
    public class MyUserDetailsService implements UserDetailsService {
       @Autowired
       UserMapper userMapper;
       @Override
       public UserDetails loadUserByUsername(String username)
                                                 throws UsernameNotFoundException {
           User user = userMapper.loadUserByUsername(username);
           if (user == null) {
               throw new UsernameNotFoundException("用户不存在");
           }
           user.setRoles(userMapper.getRolesByUid(user.getId()));
           return user;
       }
    }
```

以上操作都是Mybatis的常规操作



首先在SecurityConfig中的config(上面两节的那个类的相同方法)

```java
 @Configuration
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
       @Autowired
       MyUserDetailsService myUserDetailsService;
       @Override
       protected void configure(AuthenticationManagerBuilder auth)throws Exception {
           auth.userDetailsService(myUserDetailsService);
       }
       @Override
       protected void configure(HttpSecurity http) throws Exception {
           http.authorizeRequests()
                   //省略
       }
    }
```

- 建库插入测试数据
- 导入以来
- 配置连接数据库参数
- 根据表创建类(用户类需要实现UserDetails接口)
- 创建mapper
- 创建mapper.xml
- 创建服务类实现UserDetailsService接口(为了让系统调用loadUserByUsername方法)
- config方法中传递数据源



#### 基于SpringDataJPA

与mybatis相似但是可见区别在于不用建表不用写sql

```xml
  <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
       <groupId>mysql</groupId>
       <artifactId>mysql-connector-java</artifactId>
    </dependency>
```

配置连接数据库

JPA的配置则主要配置了数据库平台，数据表更新方式、是否打印SQL以及对应的数据库方言。

```properties
 spring.datasource.username=root
    spring.datasource.password=123
    spring.datasource.url=jdbc:mysql:///security03?useUnicode=true&characterEncod
ing=UTF-8&serverTimezone=Asia/Shanghai
  
    spring.jpa.database=mysql
    spring.jpa.database-platform=mysql
    spring.jpa.hibernate.ddl-auto=update
    spring.jpa.show-sql=true
    spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.MySQL8D
```



创建实体类

```java
  @Entity(name = "t_user")
    public class User implements UserDetails {
       @Id
       @GeneratedValue(strategy = GenerationType.IDENTITY)
       private Long id;
       private String username;
   private String password;
       private boolean accountNonExpired;
       private boolean accountNonLocked;
       private boolean credentialsNonExpired;
       private boolean enabled;
       @ManyToMany(fetch = FetchType.EAGER,cascade = CascadeType.PERSIST)
       private List<Role> roles;
       @Override
       public Collection<? extends GrantedAuthority> getAuthorities() {
           List<SimpleGrantedAuthority> authorities = new ArrayList<>();
           for (Role role : getRoles()) {
               authorities.add(new SimpleGrantedAuthority(role.getName()));
           }
           return authorities;
       }
       @Override
       public String getPassword() {
           return password;
       }
       @Override
       public String getUsername() {
           return username;
       }
       @Override
       public boolean isAccountNonExpired() {
           return accountNonExpired;
       }
       @Override
       public boolean isAccountNonLocked() {
           return accountNonLocked;
       }
       @Override
       public boolean isCredentialsNonExpired() {
           return credentialsNonExpired;
       }
       @Override
       public boolean isEnabled() {
           return enabled;
       }
       //省略getter/setter
    }
    @Entity(name = "t_role")
    public class Role {
       @Id
       @GeneratedValue(strategy = GenerationType.IDENTITY)
       private Long id;
       private String name;
       private String nameZh;
       //省略getter/setter
    }
```

配置service

![image-20211008170937801](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211008170937801.png)

方法config()的配置与mybatis一样



### 三个基本组件以及登录认证过滤器

##### AuthenticationManager

```java
public interface AuthenticationManager {
	Authentication authenticate(Authentication authentication) throws AuthenticationException;
}
```

定义了security如何去认证,成功后会返回Authentication并将它存到SecurityContextHolder中通过传入用户名和密码的简单信息的Authentication对其进行验证与填充并返回保存



对于该实现类最常见的时ProviderManager

----------------------------

##### ProviderManager

多个AuthenticationProvider将组成一个列表，这个列表将由ProviderManager代理。而==ProviderManager本身也可以再配置一个AuthenticationManager作为parent==，这样当ProviderManager认证失败之后，就可以进入到parent中再次进行认证。

理论上来说，ProviderManager的parent可以是任意类型的AuthenticationManager，但是通常都是由ProviderManager来扮演parent的角色，也就是==ProviderManager是ProviderManager的parent。==
ProviderManager本身也可以有多个，==多个ProviderManager共用同一个parent==，当存在多个过滤器链的时候非常有用。当存在多个过滤器链时，不同的路径可能对应不同的认证方式，但是不同路径可能又会同时存在一些共有的认证方式，这些共有的认证方式可以在parent中统一处理。



![image-20211009102918119](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211009102918119.png)



##### AuthenticationProvider

该方法提供对不同的身份进行具体的身份认证

> 例如，常见的DaoAuthenticationProvider用来支持用户名／密码登录认证，RememberMeAuthenticationProvider用来支持“记住我”的认证。

源码

```java
public interface AuthenticationProvider {
	
	Authentication authenticate(Authentication authentication) throws AuthenticationException;

	boolean supports(Class<?> authentication);

}
```

- authenticate()方法用来执行具体的认证方法
- supports()用来检测该实例是否支持对应的身份检查

举个简单的例子

AbstractUserDetailsAuthenticationProvider该抽象类实现了AuthenticationProvider:部分源代码如下

```java
	//首先创建一个空的用户缓存
	private UserCache userCache = new NullUserCache();
	//principal是否从对象转化为字符串
	private boolean forcePrincipalAsString = false;
	//是否隐藏用户名查找失败即大部分的异常都会被隐藏起来并且重新抛出BadCredentialsException异常,来方式黑客才猜测攻击
	protected boolean hideUserNotFoundExceptions = true;
	//用户状态的认证,例如是否被锁定,冻结等
	private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
	//用于验证密码是否过期
	private UserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
				() -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
						"Only UsernamePasswordAuthenticationToken is supported"));
		String username = determineUsername(authentication);
        
        //随用随开
		boolean cacheWasUsed = true;
		UserDetails user = this.userCache.getUserFromCache(username);
		if (user == null) {
            
            //随用随关
			cacheWasUsed = false;
			try {
				user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
			}
			catch (UsernameNotFoundException ex) {
				this.logger.debug("Failed to find user '" + username + "'");
				if (!this.hideUserNotFoundExceptions) {
					throw ex;
				}
				throw new BadCredentialsException(this.messages
						.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
			}
			Assert.notNull(user, "retrieveUser returned null - a violation of the interface contract");
		}
		try {
			this.preAuthenticationChecks.check(user);
			additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
		}
		catch (AuthenticationException ex) {
			if (!cacheWasUsed) {
				throw ex;
			}
			// There was a problem, so try again after checking
			// we're using latest data (i.e. not from the cache)
			cacheWasUsed = false;
			user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
			this.preAuthenticationChecks.check(user);
			additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
		}
		this.postAuthenticationChecks.check(user);
		if (!cacheWasUsed) {
			this.userCache.putUserInCache(user);
		}
		Object principalToReturn = user;
		if (this.forcePrincipalAsString) {
			principalToReturn = user.getUsername();
		}
		return createSuccessAuthentication(principalToReturn, authentication, user);
	}
```

authenticate()主要的认证方法:

> 首先determineUsername获取用户名,并在缓存中根据用户名进行查找对象如果不存在就使用retrieveUser从数据库中查找
>
> 找到之后首先进行用户状态的认证再进行密码的认证,最后认证是否过期
>
> 上面都通过会创建一个UsernamePasswordAuthenticationToken对象并返回，认证后的对象中包含了认证主体、凭证以及角色等信息。



而该抽象方法的实现类DaoAuthenticationProvider,部分源码如下:

```java
	//如果认证失败的情况下使用的加密字符串
	private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";
	//认证的加密方式等
	private PasswordEncoder passwordEncoder;
	//保存认证失败后USER_NOT_FOUND_PASSWORD的加密字符串
	private volatile String userNotFoundEncodedPassword;
	//用于查询用户的类
	private UserDetailsService userDetailsService;
	//进行密码认证的类
	private UserDetailsPasswordService userDetailsPasswordService;
```

- DaoAuthenticationProvider的构造方法中，默认就会指定PasswordEncoder，当然开发者也可以通过set方法自定义PasswordEncoder。

- additionalAuthenticationChecks方法主要进行密码校验，该方法第一个参数userDetails是从数据库中查询出来的用户对象，第二个参数authentication则是登录用户输入的参数。从这两个参数中分别提取出来用户密码，然后调用passwordEncoder.matches方法进行密码比对。

- retrieveUser方法则是获取用户对象的方法，具体做法就是调用UserDetailsService#loadUserByUsername方法去数据库中查询。

  - >）在retrieveUser方法中，有一个值得关注的地方。在该方法一开始，首先会调用prepareTimingAttackProtection方法，该方法的作用是使用PasswordEncoder对常量USER_NOT_FOUND_PASSWORD进行加密，将加密结果保存在userNotFoundEncoded Password变量中。当根据用户名查找用户时，如果抛出了UsernameNotFoundException异常，则调用mitigateAgainstTimingAttack方法进行密码比对。有读者会说，用户都没查找到，怎么比对密码？需要注意，在调用mitigateAgainstTimingAttack方法进行密码比对时，使用了userNotFoundEncodedPassword变量作为默认密码和登录请求传来的用户密码进行比对。这是一个一开始就注定要失败的密码比对，那么为什么还要进行比对呢？这主要是为了避免旁道攻击（Side-channel attack）。如果根据用户名查找用户失败，就直接抛出异常而不进行密码比对，那么黑客经过大量的测试，就会发现有的请求耗费时间明显小于其他请求，那么进而可以得出该请求的用户名是一个不存在的用户名（因为用户名不存在，所以不需要密码比对，进而节省时间），这样就可以获取到系统信息。为了避免这一问题，所以当用户查找失败时，也会调用mitigateAgainstTimingAttack方法进行密码比对，这样就可以迷惑黑客。

- createSuccessAuthentication方法则是在登录成功后，创建一个全新的UsernamePasswordAuthenticationToken对象，同时会判断是否需要进行密码升级，如果需要进行密码升级，就会在该方法中进行加密方案升级。



##### ProviderManager和AuthenticationProvider的关系

在Spring Security中，由于系统可能同时支持多种不同的认证方式，例如同时支持用户名／密码认证、RememberMe认证、手机号码动态认证等，而不同的认证方式对应了不同的AuthenticationProvider，所以一个完整的认证流程可能由多个AuthenticationProvider来提供。
多个AuthenticationProvider将组成一个列表，这个列表将由ProviderManager代理。换句话说，在ProviderManager中存在一个AuthenticationProvider列表，在ProviderManager中遍历列表中的每一个AuthenticationProvider去执行身份认证，最终得到认证结果。



##### AbstractAuthenticationProcessingFilter

任何登录请求都会经过该过滤链他的实现类为UsernamePasswordAuthenticationFilter



### 过滤器分析



### 配置多数据源

![image-20211009150724088](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211009150724088.png)



### 验证码

##### 通过自定义过滤器

emmmm.....等着!!!



##### 通过自定义认证逻辑

> 如果通过重写DaoAuthenticationProvider类的additionalAuthenticationChecks方法来完成验证码的校验，这个从技术上来说是没有问题的，但是这会让验证码失去存在的意义，因为当additionalAuthenticationChecks方法被调用时，数据库查询已经做了，仅仅剩下密码没有校验，此时，通过验证码来拦截恶意登录的功能就已经失效了。

首先导入依赖

```xml
        <dependency>
            <groupId>com.github.penggle</groupId>
            <artifactId>kaptcha</artifactId>
            <version>2.3.2</version>
        </dependency>
```

创建配置文件

```java
@Configuration
public class KaptchaConfig {
    @Bean
    Producer kaptcha() {
        Properties properties = new Properties();
        properties.setProperty("kaptcha.image.width", "150");
        properties.setProperty("kaptcha.image.height", "50");
        properties.setProperty("kaptcha.textproducer.char.string",
                "0123456789");

        properties.setProperty("kaptcha.textproducer.char.length", "4");
        Config config = new Config(properties);
        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
        defaultKaptcha.setConfig(config);
        return defaultKaptcha;
    }
}
```

创建一个类继承DaoAuthenticationProvider

```java
public class KaptchaAuthenticationProvider extends DaoAuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        HttpServletRequest req = ((ServletRequestAttributes) RequestContextHolder
                .getRequestAttributes()).getRequest();
        String image = req.getParameter("image");
        String kaptcha = (String) req.getSession().getAttribute("kaptcha");

        if(kaptcha==null && image==null && kaptcha.equals(image)){
            throw new AuthenticationServiceException("验证码输入错误");
        }

        return super.authenticate(authentication);
    }
}
```

在SecurityConfig中注册添加到Bean中

```java
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {

        KaptchaAuthenticationProvider provider = new KaptchaAuthenticationProvider();
        provider.setUserDetailsService(service);
        ProviderManager providerManager = new ProviderManager(provider);
        return providerManager;
    }
```

创建Controller

```java
    @Autowired
    Producer producer;

    @RequestMapping("/cv.jpg")
    public void pTest(HttpServletResponse resp, HttpSession session){

        resp.setContentType("image/jpeg");
        String text = producer.createText();
        session.setAttribute("kaptcha",text);
        BufferedImage image = producer.createImage(text);
        try (ServletOutputStream outputStream = resp.getOutputStream()) {

            ImageIO.write(image,"jpg",outputStream);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

```

在SecurityConfig中不对该请求过滤

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //.anyRequest().authenticated()代表所有请求认证后才能访问
        http.authorizeRequests()
                .antMatchers("/cv.jpg")
                .permitAll()
                .anyRequest()
                .authenticated()
                //and代表将将原来的http返回
                .and()
            //......等等
    }
```



### 基础组件

由于Spring Security中大量采用了Java配置，许多过滤器都是直接new出来的，这些直接new出来的对象并不会自动注入到Spring容器中。所以第一个组件是用来注册到容器中

#### ObjectPostProcessor:对一个成功创建的实例使用这个类进行补充

```java
public interface ObjectPostProcessor<T> {
	<O extends T> O postProcess(O object);
}
```

该接口有两个实现类:

- AutowireBeanFactoryObjectPostProcessor:使用该类的postProcess方法将类加载进去
- CompositeObjectPostProcessor:是ObjectPostProcessor的集合,里面有一个关于该接口的List对象调用实现方法实际就是遍历List并使用postProcess方法进行处理,Security使用的后置对象就是这个方法,但默认只有一个AutowireBeanFactoryObjectPostProcessor

每个过滤器都有一个configurer的配置器,这些过滤器就是在配置器中new出来并使用postProcess进行处理



#### SecurityFilterChain:过滤器链对象

该接口的代码

```java
public interface SecurityFilterChain {
    boolean matches(HttpServletRequest var1);

    List<Filter> getFilters();
}
```

- matches:用来处理是否能够被该过滤器链处理
- getFilters:返回所有的过滤器

该接口只有一个实现类DefaultSecurityFilterChain

该过滤器链可能会有多个



#### SecurityBuilder:构建所有需要的对象

![image-20211011093037215](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211011093037215.png)



##### HttpSecurityBuilder：

```java

public interface HttpSecurityBuilder<H extends HttpSecurityBuilder<H>> extends SecurityBuilder<DefaultSecurityFilterChain> {
    //获取配置器
    <C extends SecurityConfigurer<DefaultSecurityFilterChain, H>> C getConfigurer(Class<C> var1);
	//移除配置器
    <C extends SecurityConfigurer<DefaultSecurityFilterChain, H>> C removeConfigurer(Class<C> var1);
	//设置一个可以在各个配置器间共享的对象
    <C> void setSharedObject(Class<C> var1, C var2);
	//获取一个可以在各个配置器间共享的对象
    <C> C getSharedObject(Class<C> var1);
	//配置认证器
    H authenticationProvider(AuthenticationProvider var1);
	//配置数据源
    H userDetailsService(UserDetailsService var1) throws Exception;
	//之后添加一个过滤器
    H addFilterAfter(Filter var1, Class<? extends Filter> var2);
	//之前添加一个过滤器
    H addFilterBefore(Filter var1, Class<? extends Filter> var2);
	//添加一个过滤器
    H addFilter(Filter var1);
}
```



##### AbstractSecurityBuilder:

该确保Build方法只Build一次

```java
public final O build() throws Exception {
    if (this.building.compareAndSet(false, true)) {
        this.object = this.doBuild();
        return this.object;
    } else {
        throw new AlreadyBuiltException("This object has already been built");
    }
}
```

关于方法被设为finalhttps://www.cnblogs.com/frankyou/p/6022959.html

- 第一,防止后续的继承修改该方法
- 第二,对应程序较少的方法提升效率

该类虽然实现了只build一次但是没有实现具体的build而是交给他的doBuild抽象方法



##### AbstractConfiguredSecurityBuilder:

首先该类定义了一个枚举类:

```java
private static enum BuildState {
    UNBUILT(0),//配置前
    INITIALIZING(1),//初始化中
    CONFIGURING(2),//配置中
    BUILDING(3),//构件中
    BUILT(4);//构建完成
    //....省略
}
```

首先声明了一个configurers变量用来保存所有的配置类,关于该类的方法:

- apply:添加配置类(调用add方法实现)
- add:方法用来将所有的配置类保存到configurers中，在添加的过程中，如果==allowConfigurersOfSameType变量为true，则表示允许相同类型的配置类存在==，也就是List集合中可以存在多个相同类型的配置类。默认情况下，如果是普通配置类，allowConfigurersOfSameType是false，所以List集合中的配置类始终只有一个配置类；如果在AuthenticationManagerBuilder中设置allowConfigurersOfSameType为true，此时相同类型的配置类可以有多个
- getConfigurers:方法可以从configurers中返回某一个配置类对应的所有实例
- removeConfigurers:可以移除某一个配置类的所有实例
- getConfigurer方法也是获取配置类实例，但是只获取集合中第一项。
- removeConfigurer方法可以从configurers中移除某一个配置类对应的所有配置类实例，并返回被移除掉的配置类实例中的第一项。



由于该类继承了AbstractSecurityBuilder所有需要实现onBuild

```java
protected final O doBuild() throws Exception {
    synchronized(this.configurers) {
        this.buildState = AbstractConfiguredSecurityBuilder.BuildState.INITIALIZING;
        this.beforeInit();
        this.init();
        this.buildState = AbstractConfiguredSecurityBuilder.BuildState.CONFIGURING;
        this.beforeConfigure();
        this.configure();
        this.buildState = AbstractConfiguredSecurityBuilder.BuildState.BUILDING;
        O result = this.performBuild();
        this.buildState = AbstractConfiguredSecurityBuilder.BuildState.BUILT;
        return result;
    }
}
```

可以看出这个方法是synchronized并且还是final的

首先init();是遍历所有配置类,并完成初始化

configure();完成所有配置类的配置

performBuild();最终完成构建操作



##### ProviderManagerBuilder

该接口是继承SecurityBuilder类并新增了一个Authentication authenticate(Authentication authentication)方法



##### AuthenticationManagerBuilder

继承自[AbstractConfiguredSecurityBuilder](#AbstractConfiguredSecurityBuilder)并实现了ProviderManagerBuilder接口

- 构造方法

  - ```java
        public AuthenticationManagerBuilder(ObjectPostProcessor<Object> objectPostProcessor) {
            super(objectPostProcessor, true);
        }
    ```

    可以看出调用了父类的构造方法也就是AbstractConfiguredSecurityBuilder的构造并且传递了true(允许相同类型的配置类同时存在)

- parentAuthenticationManager:给一个AuthenticationManager设置parent在[ProviderManager](#ProviderManager)中提到如果认证失败就去父类再次认证

- inMemoryAuthentication、jdbcAuthentication以及userDetailsService:配置数据源

- authenticationProvider:该方法用来向authenticationProviders集合中添加AuthenticationProvider对象

- performBuild:执行具体的构建工作



#### HttpSecurity

构建一条过滤器链并反应到代码上,用于构建DefaultSecurityFilterChain

DefaultSecurityFilterChain包含一个路径匹配器和多个SpringSecurity过滤器,HttpSecurity会收集各种xxxconfigurers并将其放入父类的configurers中,要构建的时候再用这些configurer进行构建同时添加到HttpSecurity的filters

由于很多重复的源码所以这里以form表单登录配置为例

```java
public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
    return (FormLoginConfigurer)this.getOrApply(new FormLoginConfigurer());
}

public HttpSecurity formLogin(Customizer<FormLoginConfigurer<HttpSecurity>> formLoginCustomizer) throws Exception {
    formLoginCustomizer.customize((FormLoginConfigurer)this.getOrApply(new FormLoginConfigurer()));
    return this;
}
```

可以看出一个有参一个无参,无参的返回FormLoginConfigurer对象然后可以继续配置,对于有参来说直接传递一个配置类即可完成配置然后返回HttpSecurity来继续进行其他配置,还记得SecurityConfig这个自己的配置文件吗

![image-20211011165450240](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211011165450240.png)

可以看出and后返回的就是HttpSecurity



并且有参和无参方法都调用了:

```java
private <C extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> C getOrApply(C configurer) throws Exception {
    C existingConfig = (SecurityConfigurerAdapter)this.getConfigurer(configurer.getClass());
    return existingConfig != null ? existingConfig : this.apply(configurer);
}
```

该方法就是调用父类的getConfigurer方法查看是否存在配置类有的话直接返回没有则使用父类的apply调用添加



其他的配置都和这个类似



- 每一套过滤器链都会有一个AuthenticationManager对象来进行认证操作（如果认证失败，则会调用AuthenticationManager的parent再次进行认证），主要是通过authentication Provider方法配置执行认证的authenticationProvider对象，通过userDetailsService方法配置UserDetailsService，最后在beforeConfigure方法中触发AuthenticationManager对象的构建。

- performBuild方法则是进行DefaultSecurityFilterChain对象的构建，传入请求匹配器和过滤器集合filters，在构建之前，会先按照既定的顺序对filters进行排序。

- 通过addFilterAfter、addFilterBefore两个方法，我们可以在某一个过滤器之后或者之前添加一个自定义的过滤器（该方法已在HttpSecurityBuilder中声明，此处是具体实现）。
- addFilter方法可以向过滤器链中添加一个过滤器，这个过滤器必须是Spring Security框架提供的过滤器的一个实例或者其扩展。实际上，在每一个xxxConfigurer的configure方法中，都会调用addFilter方法将构建好的过滤器添加到HttpSecurity中的filters集合中（addFilter方法已在HttpSecurityBuilder中声明，此处是具体实现）。
- addFilterAt方法可以在指定位置添加一个过滤器。需要注意的是，在同一个位置添加多个过滤器并不会覆盖现有的过滤器。



#### WebSecurity

HttpSecurity是装配了DefaultSecurityFilterChain,但可能存在多个HttpSecurity也就是存在多个DefaultSecurityFilterChain,这个类的作用是将这些整合成一个FilterChainProxy对象

- 变量ignoredRequests:保存了所有被忽略的请求
- 变量securityFilterChainBuilders:该集合用来保存所有的HttpSecurity对象
- 变量httpFirewall:用来配置请求防火墙
- performBuild:该方法首先统计过滤总数,创建一个securityFilterChains,遍历被忽略的请求并分别构建成DefaultSecurityFilterChain对象保存到securityFilterChains集合中但是只有请求匹配器没有过滤链,这样就可以不用过滤直接放行了,然后securityFilterChain Builders集合，调用每个对象的build方法构建DefaultSecurityFilterChain并存入securityFilter Chains集合中，然后传入securityFilterChains集合构建FilterChainProxy对象，最后再设置HTTP防火墙。所有设置完成之后，最后返回filterChainProxy对象。



#### FilterChainProxy

- 变量filterChains:用来保存过滤链
- 变量filterChainValidator:过滤器配置链完成后的认证器
- 变量firewall:防火墙



主要运行方法doFilter:

>首先该方法会先定义一个变量,检查是否为第一次执行是的话会在过滤链结束后清空SecurityContextHolder,这是防止没有配置SecurityContextPersistenceFilter,关键的过滤处理在doFilterInternal中

doFilterInternal源码:

```java
 private void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        FirewalledRequest firewallRequest = this.firewall.getFirewalledRequest((HttpServletRequest)request);
        HttpServletResponse firewallResponse = this.firewall.getFirewalledResponse((HttpServletResponse)response);
        List<Filter> filters = this.getFilters((HttpServletRequest)firewallRequest);
        if (filters != null && filters.size() != 0) {
            if (logger.isDebugEnabled()) {
                logger.debug(LogMessage.of(() -> {
                    return "Securing " + requestLine(firewallRequest);
                }));
            }

            FilterChainProxy.VirtualFilterChain virtualFilterChain = new FilterChainProxy.VirtualFilterChain(firewallRequest, chain, filters);
            virtualFilterChain.doFilter(firewallRequest, firewallResponse);
        } else {
            if (logger.isTraceEnabled()) {
                logger.trace(LogMessage.of(() -> {
                    return "No security for " + requestLine(firewallRequest);
                }));
            }

            firewallRequest.reset();
            chain.doFilter(firewallRequest, firewallResponse);
        }
    }
```

首先会通过防火墙类来创建firewallRequest和firewallResponse

再从getFilters中获取到适合的filters过滤链如果为空就跳回WebFilter(最外层过滤链,相当于过滤结束),否则就根据获得的过滤链进行变量,并且对每个链都创建一个virtualFilterChain然后继续过滤

再来看virtualFilterChain(部分源代码):

```java
 private static final class VirtualFilterChain implements FilterChain {
        private final FilterChain originalChain;
        private final List<Filter> additionalFilters;
        private final FirewalledRequest firewalledRequest;
        private final int size;
        private int currentPosition;
public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (this.currentPosition == this.size) {
                if (FilterChainProxy.logger.isDebugEnabled()) {
                    FilterChainProxy.logger.debug(LogMessage.of(() -> {
                        return "Secured " + FilterChainProxy.requestLine(this.firewalledRequest);
                    }));
                }

                this.firewalledRequest.reset();
                this.originalChain.doFilter(request, response);
            } else {
                ++this.currentPosition;
                Filter nextFilter = (Filter)this.additionalFilters.get(this.currentPosition - 1);
                if (FilterChainProxy.logger.isTraceEnabled()) {
                    FilterChainProxy.logger.trace(LogMessage.format("Invoking %s (%d/%d)", nextFilter.getClass().getSimpleName(), this.currentPosition, this.size));
                }

                nextFilter.doFilter(request, response, this);
            }
        }
     }
```

- 变量originalChain:用来跳回WebFilter
- 变量additionalFilters:本次要进行过滤的过滤器链
- 变量firewalledRequest:用户请求
- 变量size:请求链大小
- 变量currentPosition:当前请求链位置

在doFilter方法中，会首先判断当前执行的下标是否等于过滤器链的大小，如果相等，则说明整个过滤器链中的所有过滤器都已经挨个走一遍了，此时先对Http防火墙中的属性进行重置，然后调用originalChain.doFilter方法跳出Spring Security Filter，回到Web Filter；如果不相等，则currentPosition自增，然后从过滤器链集合中取出一个过滤器去执行，注意执行的时候第三个参数this表示当前对象（即VirtualFilterChain），这样在每一个过滤器执行完之后，最后的chain.doFilter方法又会回到当前doFilter方法中，继续下一个过滤器的调用。



#### SecurityConfigurer

![image-20211011200219902](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211011200219902.png)

从名字上面看就大概知道该接口是用来初始化和配置类的配置

因为有很多的过滤器,而每个过滤器都有一个XXXconfigurer所以子类很多

下图为一小部分

![image-20211011200608279](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211011200608279.png)

首先我们来看最开始配置的,目前位置最熟悉的配置类的父类的兄弟类:dog:

##### SecurityConfigurerAdapter

- 为每个配置类都提供了一个SecurityBuilder,使用build创建对象使用and返回对象,这里就和前面的一样

- 定义了内部类CompositeObjectPostProcessor，这是一个复合的对象后置处理器

- 提供了一个addObjectPostProcessor方法，通过该方法可以向复合的对象后置处理器中添加新的ObjectPostProcessor实例



##### UserDetailsAwareConfigurer

他的子类主要用于认证配置的相关组件,例如UserDetailsService,但是获取UserDetailsService的方法为抽象方法需要在子类中实现

![image-20211012091022619](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211012091022619.png)

- AbstractDaoAuthenticationConfigurer:完成对DaoAuthenticationProvider的配置
- UserDetailsServiceConfigurer:完成对UserDetailsService的配置
- UserDetailsManagerConfigurer:使用UserDetailsManager构建用户对象，完成对AuthenticationManagerBuilder的填充
- JdbcUserDetailsManagerConfigurer:配置JdbcUserDetailsManager并填充到Authentication ManagerBuilder中
- InMemoryUserDetailsManagerConfigurer:配置InMemoryUserDetailsManager
- DaoAuthenticationConfigurer:完成对DaoAuthenticationProvider的配置



##### AbstractHttpConfigurer

主要是为了给在HttpSecurity中使用的配置类添加一个方便的父类，提取出共同的操作

- disable表示禁用某一个配置（第2章中我们配置的.csrf().disable()），本质上就是从构建器的configurers集合中移除某一个配置类，这样在将来构建的时候就不存在该配置类，那么对应的功能也就不存在（被禁用）

- withObjectPostProcessor表示给某一个对象添加一个对象后置处理器，由于该方法的返回值是当前对象，所以该方法可以用在链式配置中。

下面是他的子类

![Figure-T138_115736](D:\package_and_data\Book\JdReaderEBooks\jd_4657302ffcbc3\30712708_dir_img\OEBPS\Images\Figure-T138_115736.jpg)



##### GlobalAuthenticationConfigurerAdapter

用于配置全局AuthenticationManagerBuilder

在介绍ProviderManager时曾经提到过，默认情况下ProviderManager有一个parent，这个parent就是通过这里的全局AuthenticationManagerBuilder来构建的

![image-20211012093313969](C:\Users\lll\AppData\Roaming\Typora\typora-user-images\image-20211012093313969.png)

他的继承关系为上图

- InitializeAuthenticationProviderBeanManagerConfigurer：初始化全局的AuthenticationProvider对象
- InitializeAuthenticationProviderManagerConfigurer：配置全局的AuthenticationProvider对象，配置过程就是从Spring容器中查找AuthenticationProvider并设置给全局的AuthenticationManagerBuilder对象。
- InitializeUserDetailsBeanManagerConfigurer：初始化全局的UserDetailsService对象。
- InitializeUserDetailsManagerConfigurer：配置全局的UserDetailsService对象，配置过程就是从Spring容器中查找
- UserDetailsService，并设置给全局的AuthenticationManagerBuilder对象。
- EnableGlobalAuthenticationAutowiredConfigurer：从Spring容器中加载被@EnableGlobal Authentication注解标记的Bean。



##### WebSecurityConfigurer

空接口



##### WebSecurityConfigurerAdapter

大多数情况下我们继承他来创建securityConfig

有两个AuthenticationManagerBuilder对象用来构建AuthenticationManager

- private AuthenticationManagerBuilder authenticationBuilder
  - 用于配置局部他和每个HttpSecurity进行绑定
- private AuthenticationManagerBuilder localConfigureAuthenticationBldr
  - 是所有局部AuthenticationManager的parent,但是如果没有重写configure(AuthenticationManagerBuilder)方法全局的AuthenticationManager对象是由AuthenticationConfiguration类中的getAuthenticationManager方法提供的，如果用户重写了configure(AuthenticationManagerBuilder)方法，则全局的AuthenticationManager就由localConfigureAuthenticationBldr负责构建

