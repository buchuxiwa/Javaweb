# 《Javaweb第一次作业》



##### 学院：省级示范性软件学院



##### 题目：《JAVAweb第一次作业》



##### 姓名：王承宸



##### 学号：2100a60134



##### 班级：软工2202



##### 日期：2024-09-14



## 一、会话安全性

### （1）会话劫持和防御

##### 		会话劫持是指攻击者在用户和服务器之间的会话过程中，通过窃取、伪造或劫持会话标识（如会话Cookie、令牌等）来冒充合法用户，从而获得未经授权的访问权限。常见的会话劫持攻击方式包括会话固定、会话侧信道攻击（如旁路监听）和跨站脚本（XSS）攻击等。

##### 	防御：

##### 	**1、使用安全的会话标识符**: 生成随机、不可预测的会话标识符，避免使用易猜测的标识符。

**2、加密传输**: 使用HTTPS加密会话标识符的传输，防止会话标识符被窃取。

**3、HttpOnly和Secure标志**: 设置会话Cookie的`HttpOnly`和`Secure`属性，防止客户端脚本访问Cookie以及在非加密通道传输。

**4、定期更新会话标识符**: 登录成功后或其他敏感操作后，重新生成会话标识符，以防止会话劫持。

**5、验证会话的有效性**: 结合IP地址、用户代理信息等进行会话验证，发现异常及时终止会话。

**6、会话过期策略**: 设置会话的过期时间和闲置超时时间，防止长时间未操作的会话被滥用。

##### 以下给出JavaScript中的HttpOnly和Secure部分代码实现：

```java
import javax.servlet.http.Cookie;
const session = require('express-session');
const app = express();

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,  // 禁止客户端脚本访问Cookie
    secure: true,    // 只在HTTPS下传输Cookie
    maxAge: 30 * 60 * 1000  // 30分钟后过期
  }
}));

app.get('/', (req, res) => {
  if (req.session.username) {
    res.send(`Hello, ${req.session.username}!`);
  } else {
    res.send('You are not logged in.');
  }
});

app.post('/login', (req, res) => {
  req.session.username = req.body.username;
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy();  // 销毁会话
  res.redirect('/');
});

app.listen(3000, () => {
  console.log('Server is running on https://localhost:3000');
});
```

### （2）跨站脚本攻击（XSS）和防御

##### 			跨站脚本攻击（XSS）是一种代码注入攻击，攻击者通过向网站输入恶意脚本代码，使得当用户访问网站时，这些恶意代码会在用户的浏览器中执行。XSS 攻击可以被用来窃取用户的会话信息、伪造用户操作、劫持用户账户等。XSS分为反射型XSS、存储型XSS、DOM型XSS

##### 	防御：

**1、输入验证与过滤 ：**即在所有用户输入进入系统之前，严格验证和过滤。避免输入直接注入到HTML、JavaScript、URL等上下文中。

**2、输出编码：**在将用户输入输出到HTML、JavaScript、URL、CSS等不同上下文时，进行适当的编码，防止恶意脚本执行。

**3、使用安全的库和框架：**使用能自动处理XSS防护的库和框架，例如Django（Python）、Ruby on Rails、Angular等（内置过滤机制）。

**4、内容安全策略：**CSP 可以限制页面加载的资源，防止恶意脚本的执行。

**5、HttpOnly Cookie：**将敏感的会话Cookie标记为HttpOnly，防止JavaScript通过`document.cookie`访问，从而减少XSS对会话的劫持风险。

**6、避免使用危险的JavaScript方法：**尽量避免使用`eval()`、`document.write()`、`innerHTML`等容易导致XSS漏洞的API。



##### 以下是JAVA实现自定义XSS过滤器实现XSS防御的部分代码:

```java
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class XSSFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        chain.doFilter(new XSSRequestWrapper(req), response);
    }

    @Override
    public void destroy() {
    }
}
```

### （3） 跨站请求伪造（CSRF）和防御

##### 	跨站请求伪造（Cross-Site Request Forgery, CSRF）是一种攻击形式，攻击者诱导用户在登录状态下访问一个恶意网站，从而利用用户的身份在被攻击的网站执行未授权的操作。CSRF攻击通常依赖于用户在多个网站之间共享的身份认证信息（如Cookie），并利用受害者当前已登录的身份发起恶意请求。CSRF攻击的典型流程为：1、用户登录到受信任的网站，2、用户未登出，3、用户访问恶意网站，4、**浏览器携带着有效的Cookie**向受信任的网站发送请求，受信任的网站在未验证请求来源的情况下执行了请求。

##### 防御：

**1、CSRF Token 验证：**在每个需要身份验证的请求中，附加一个唯一的、不可预测的令牌（Token）。服务器验证令牌的有效性以确保请求来自合法用户。令牌可以作为隐藏字段放在表单中，或者通过HTTP头（如`X-CSRF-Token`）发送。

**2、Referer 验证：**服务器检查请求的`Referer`或`Origin`头是否来自受信任的域，但容易被用户代理（如浏览器插件）禁用或修改。

**3、双重提交 Cookie：**服务器将CSRF Token存储在Cookie中，并要求客户端在请求中同时提供该Token（如在表单中或HTTP头中）。服务器验证Cookie中的Token和请求中的Token是否匹配。

**4、SameSite Cookie 属性：**设置Cookie的`SameSite`属性为`Strict`或`Lax`，以防止浏览器在跨站请求中发送Cookie，从而减少CSRF风险。

**5、使用自定义请求头：**通过JavaScript添加自定义请求头（如`X-Requested-With`），并在服务器端验证是否存在该头部信息。恶意网站无法设置自定义请求头，因此可以减少CSRF攻击。

##### 以下是在servlet中配置SameSite属性，确保浏览器不会再跨站请求中发送敏感Cookie：

```java
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class CookieUtils {

    public static void setSameSiteCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("JSESSIONID", "value");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(3600);
        cookie.setComment("SameSite=strict"); // 设置SameSite属性
        response.addCookie(cookie);
    }
}
```

## 二、分布式会话管理

### （1）分布式环境下的会话同步问题

#####  		分布式环境下的会话同步问题指的是在多台服务器（节点）共同处理用户请求的情况下，如何保证用户会话数据的一致性、可用性和持久性。会话同步问题通常在多台服务器间出现，因为用户的请求可能被路由到不同的服务器，而每个服务器通常会维护自己的会话数据（例如登录信息、购物车数据等）。

##### 	具体问题包括：1、会话不一致问题，2、会话丢失问题，3、负载均衡导致的会话丢失问题，4、性能和可扩展性问题，5、数据一致性与冲突问题。

### （2）Session集群解决方案

##### 	Session 集群解决方案用于在多个应用服务器之间共享和管理用户会话数据，确保用户请求在不同服务器之间切换时，会话数据的一致性和可用性。常见的 Session 集群解决方案有多种选择：

**1、粘性会话：**负载均衡器（如 Nginx、HAProxy）将同一用户的所有请求都转发到同一台服务器上，从而避免会话数据在多台服务器之间共享和同步的问题。通常通过设置 Cookie（如 `JSESSIONID`）或基于 IP 地址来实现。

**2、集中式会话存储：**将会话数据存储在一个集中式的存储中，所有的应用服务器都访问这个共享存储来获取和更新会话数据。常见的集中式存储包括数据库、分布式缓存（如 Redis、Memcached）。

```java
// Spring Session JDBC 配置
@Bean
public JdbcOperationsSessionRepository sessionRepository(DataSource dataSource) {
    JdbcOperationsSessionRepository sessionRepository = new JdbcOperationsSessionRepository(dataSource);
    sessionRepository.setDefaultMaxInactiveInterval(1800); // 设置会话过期时间
    return sessionRepository;
}
```

**3、会话复制：**在应用服务器集群之间，采用会话复制机制。每台服务器上的会话数据都会复制到其他服务器上，所有服务器都拥有相同的会话数据。

```xml
<Context>
	<Manager className="org.apache.catalina.ha.session.DeltaManager"
             expireSessionsOnShutdown="false"
             notifyListenersOnReplication="true"/>
</Context>
```

**4、客户端会话存储：**将会话数据存储在客户端（如浏览器）的 Cookie 或 LocalStorage 中。每次请求时，客户端会将会话数据发送到服务器。

```Java
String token = Jwts.builder()        
.setSubject(username)
        .signWith(SignatureAlgorithm.HS512, secretKey)
        .compact();

// 将 token 发送给客户端，并存储在客户端的 Cookie 或 LocalStorage 中。
```

**5、无状态会话管理：**通过无状态的会话管理，所有用户状态都不存储在服务器上，而是每次请求都传递所有状态信息。这种方式本质上是将会话管理转移到客户端。

### （3）使用Redis等缓存技术实现分布式会话

##### 	使用Redis等缓存技术实现分布式会话通过集中存储会话数据，使得分布式环境中的所有应用服务器都能够访问相同的会话数据，从而实现会话共享。

#####  使用Spring Boot配置类：

```java
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@Configuration
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800)  // 设置会话过期时间，单位：秒
public class RedisSessionConfig {
}
```

## 三、会话状态的序列化和反序列化

### （1）会话状态的序列化和反序列化

##### 	会话状态的序列化和反序列化是指将用户会话数据从内存对象转换为可存储或传输的格式（序列化），以及将存储或传输的格式转换回内存对象（反序列化）的过程。

##### 	**序列化**：是将对象转换为字节流或其他格式（如JSON、XML），以便将对象的数据持久化到磁盘、存储到数据库、缓存（如Redis）或通过网络传输。

```java
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public class SessionData implements Serializable {
    private String username;
    private int userId;

    public SessionData(String username, int userId) {
        this.username = username;
        this.userId = userId;
    }

    public static void main(String[] args) {
        SessionData session = new SessionData("user123", 1);
        try (FileOutputStream fileOut = new FileOutputStream("session.ser");
             ObjectOutputStream out = new ObjectOutputStream(fileOut)) {
            out.writeObject(session);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

##### 	反序列化：是将存储或传输的字节流或其他格式（如JSON、XML）还原为内存中的对象，恢复对象的状态，以便在系统中使用。

```Java
import java.io.FileInputStream;
import java.io.ObjectInputStream;

public class SessionDeserialization {
    public static void main(String[] args) {
        try (FileInputStream fileIn = new FileInputStream("session.ser");
             ObjectInputStream in = new ObjectInputStream(fileIn)) {
            SessionData session = (SessionData) in.readObject();
            System.out.println("Username: " + session.username);
            System.out.println("UserId: " + session.userId);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### （2）为什么需要序列化会话状态

##### 	进行序列化会话状态时为了实现：1、跨服务器共享会话，2、会话持久化，3、数据传输，3、跨语言或跨平台

##### 	通过序列化，将会话数据存储到数据库、Redis或文件系统中，确保分布式环境中的每个服务器都可以访问到相同的会话数据。

### （3） Java对象序列化

##### 	Java对象序列化是指将Java对象的状态转换为字节流的过程，以便可以将该对象保存到文件、数据库、内存中，或者通过网络传输给其他系统。通过序列化，Java对象的完整状态（包括其数据和结构）可以被保存并在需要时恢复。

### （4）自定义序列化策略

##### 	自定义序列化策略可以让开发者控制对象序列化和反序列化的过程，以满足特殊要求。通常用于：

**1、需要对敏感数据进行加密或掩码处理**。

**2、需要对序列化格式进行优化，减少数据体积**。

**3、需要动态控制某些字段的序列化行为**。

##### 以下是java实现Externalizable接口来控制序列化和反序列化过程的部分实现代码：

```java
import java.io.*;
class CustomPerson implements Externalizable {
    private String name;
    private int age;

    // 必须有无参构造方法，否则反序列化会失败
    public CustomPerson() {
    }

    public CustomPerson(String name, int age) {
        this.name = name;
        this.age = age;
    }

    // 自定义序列化逻辑
    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeObject(name);  // 序列化 name
        out.writeInt(age);      // 序列化 age
    }

    // 自定义反序列化逻辑
    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        this.name = (String) in.readObject(); // 反序列化 name
        this.age = in.readInt();              // 反序列化 age
    }

    @Override
    public String toString() {
        return "CustomPerson{name='" + name + "', age=" + age + '}';
    }
}

public class ExternalizableDemo {
    public static void main(String[] args) {
        CustomPerson person = new CustomPerson("Alice", 25);

        // 序列化
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("customPerson.ser"))) {
            out.writeObject(person);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 反序列化
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream("customPerson.ser"))) {
            CustomPerson deserializedPerson = (CustomPerson) in.readObject();
            System.out.println("Deserialized CustomPerson: " + deserializedPerson);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
```



