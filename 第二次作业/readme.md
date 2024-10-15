# 《实验二：Filter练习》



##### 学院：省级示范性软件学院



##### 题目：《实验二：Filter练习》



##### 姓名：王承宸



##### 学号：2100a60134



##### 班级：软工2202



##### 日期：2024-10-11



##### 实验环境：IntelliJ IDEA 2024.2.1、Apache Tomcat10.1.28



## 实验内容：

**题目:** 实现一个登录验证过滤器

**目标:** 创建一个 Servlet的 过滤器,用于验证用户是否已登录。对于未登录的用户,将其**重定向**到登录页面。

**要求:** 

1. 创建一个名为 `LoginFilter` 的类, 实现 `javax.servlet.Filter` 接口。
2. 使用 `@WebFilter` 注解配置过滤器,使其应用于所有 URL 路径 ("/*")。
3. 在 `doFilter` 方法中实现以下逻辑: 

1. 检查当前请求是否是对登录页面、注册页面或公共资源的请求。如果是,则允许请求通过。 
2. 如果不是上述情况,检查用户的 session 中是否存在表示已登录的属性(如 "user" 属性)。
3. 如果用户已登录,允许请求继续。 
4. 如果用户未登录,将请求重定向到登录页面。

1. 创建一个排除列表,包含不需要登录就能访问的路径(如 "/login", "/register", "/public")。
2. 实现一个方法来检查当前请求路径是否在排除列表中。
3. 添加适当的注释,解释代码的主要部分。

**提交要求:**

1. 项目打zip交上来，不要target中的内容；
2. 先执行mvn -clean 清除掉target文件再打zip；
3. 一个简短的文档,解释你的实现和任何额外的功能。

**评分标准:**

- 正确实现基本的过滤器功能 (70%)
- 代码质量和组织结构 (20%)
- 注释的质量和清晰度 (10%)



### Filter实现：

##### 1、通过定义List\<String>对象来实现对指定页面的放行

##### 2、获取当前页面URI之后，及逆行判断是否放行，若非可放行的页面，进行登录判断：若session中有username说明已经通过了Servlet中设置的账号密码匹配，即登陆成功。登陆成功则跳转到欢迎界面，登陆失败则重定向到登录界面。

### Servlet：

##### 1、通过HttpServletRequest类中的getParameter获得用户输入的账号密码

##### 2、获得之后，进行账号密码匹配，若匹配成功，就写入session并存入user中

##### 3、在控制台输出（用户名+“正在登录”）

### 额外功能：

##### 1、定义了User类来记录用户的账号和密码，为后续可能的开发提供可拓展性

##### 2、在html文件中实现了form表格，为用户输入账号密码提供便捷



### Filter代码：

```Java
package org.example.demo;

import jakarta.servlet.*;
import jakarta.servlet.annotation.WebFilter;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@WebFilter(filterName ="loginfilter",urlPatterns = "/*")
public class LoginFilter implements Filter {
    //添加可放行的项
    private static final List<String> STATIC_EXTENSIONS = Arrays.asList(
            "/login","/hello-servlet",".html"
    );

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        Filter.super.init(filterConfig);
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpSession session = request.getSession();//获取session

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestURI = httpRequest.getRequestURI().toLowerCase();//得到URI来进行后续的匹配

        //匹配
        boolean isStaticResource = STATIC_EXTENSIONS.stream()
                .anyMatch(extension -> requestURI.endsWith(extension));

        //如果是可放行的项
        if(isStaticResource) {
            filterChain.doFilter(servletRequest, servletResponse);//放行
            return;
        }
        else{//否则进行登录判断
            String username = (String) session.getAttribute("username");
            if(username!=null || "".equals(username)) {
                System.out.println("登陆成功");
                HttpServletResponse response = (HttpServletResponse) servletResponse;
                response.sendRedirect("hello.html");//登录成功则重定向到hello界面
            }
            else {
                System.out.println("请登录！");
                HttpServletResponse response = (HttpServletResponse) servletResponse;
                response.sendRedirect("login.html");//登录失败则重定向到登录界面
            }
        }
    }

    @Override
    public void destroy() {
        Filter.super.destroy();
    }
}

```

