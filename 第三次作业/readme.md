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

