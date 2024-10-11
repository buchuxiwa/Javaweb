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

