# 《实验三：Listener练习》



##### 学院：省级示范性软件学院



##### 题目：《实验二：Listener练习》



##### 姓名：王承宸



##### 学号：2100a60134



##### 班级：软工2202



##### 日期：2024-10-11



##### 实验环境：IntelliJ IDEA 2024.2.1、Apache Tomcat10.1.28



## 实验内容：

**题目：**完成请求日志记录（ServletRequestListener）功能

**要求：**

1. 实现一个 ServletRequestListener 来记录每个 HTTP 请求的详细信息。
2. 记录的信息应包括但不限于：

- 请求时间
- 客户端 IP 地址
- 请求方法（GET, POST 等）
- 请求 URI
- 查询字符串（如果有）
- User-Agent
- 请求处理时间（从请求开始到结束的时间）

1. 在请求开始时记录开始时间，在请求结束时计算处理时间。
2. 使用适当的日志格式，确保日志易于阅读和分析。
3. 实现一个简单的测试 Servlet，用于验证日志记录功能。
4. 提供简要说明，解释你的实现方式和任何需要注意的事项。

**评分标准:**

- 正确实现基本的过滤器功能 (70%)
- 代码质量和组织结构 (20%)
- 注释的质量和清晰度 (10%)

**提交要求:**

1. 项目打zip交上来，不要target中的内容；
2. 先执行mvn -clean 清除掉target文件再打zip；
3. 一个简短的文档,解释你的实现和任何额外的功能。



### Listener实现：

##### 1、实现listener接口，重写两方法

##### 2、在初始化和结束时，都要请求一次当前时间并做记录，来方便之后计算请求处理时间

##### 3、请求的详细信息，可以通过HttpServletRequest类中的各get方法得到

##### 4、将格式整理好后打印

### 测试类实现：

##### 1、首先要标记为Servlet

##### 2、在doGet方法中，使用PrintWriter来向浏览器传递数据

### Listener代码：

```java
package org.example.listenerpractice;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;



public class ServletRequestListener implements jakarta.servlet.ServletRequestListener {
    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        HttpServletRequest request = (HttpServletRequest) sre.getServletRequest();

        long startTime = System.currentTimeMillis();//请求初始化时的时间
        request.setAttribute("startTime", startTime);//记录时间
    }

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {
        HttpServletRequest request = (HttpServletRequest) sre.getServletRequest();
        long startTime = (Long) request.getAttribute("startTime");
        long endTime = System.currentTimeMillis();//请求结束时的时间

        //计算请求处理时间
        long processingTime = endTime - startTime;

        //记录请求的详细信息
        String logMessage = String.format("本次访问的请求信息：\nTime: %s\n Client IP: %s\n Method: %s\n URI: %s\n Query String: %s\n User-Agent: %s\n Processing Time: %d ms\n",
                new java.util.Date(),
                request.getRemoteAddr(),
                request.getMethod(),
                request.getRequestURI(),
                request.getQueryString(),
                request.getHeader("User-Agent"),
                processingTime);
        System.out.println(logMessage);
    }
}

```

