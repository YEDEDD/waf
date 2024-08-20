# WAF 
- 使用Nginx+Lua实现自定义WAF（Web application firewall）

## 项目背景介绍

### 需求产生

由于原生态的Nginx的一些安全防护功能有限，就研究能不能自己编写一个WAF，本文根据 unixhot 写的基础上做二次开发，增加了一些功能。：

### 功能列表：

1.	支持IP白名单。
2.	支持黑名单。
3.	支持URL白名单，将不需要过滤的URL进行定义。
4.	支持域名黑名单，注域名黑名单和URL白名单不同，URL匹配域名后缀包括端口。
5.	支持User-Agent的过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
6.	支持CC攻击防护，单个URL指定时间的访问次数，超过设定值，直接返回403。
7.	支持Cookie过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
8.	支持URL过滤，匹配自定义规则中的条目，如果用户请求的URL包含这些，返回403。
9.	支持URL参数过滤，原理同上。
10.	支持日志记录，将白名单、拦截日志与未匹配到的日志分开记录。
11.	日志记录为JSON格式，便于日志分析，例如使用ELK进行攻击日志收集、存储、搜索和展示。

### WAF实现

WAF一句话描述，就是解析HTTP请求（协议解析模块），规则检测（规则模块），做不同的防御动作（动作模块），并将防御过程（日志模块）记录下来。所以本文中的WAF的实现由五个模块(配置模块、协议解析模块、规则模块、动作模块、错误处理模块）组成。

## 安装部署

### OpenResty安装

1. docker-compose部署

```
version: '3.8'

services:
  openresty:
    image: zhaolz/openresty-waf:1.25.3.2
    container_name: openresty
    privileged: true
    volumes:
      - ./nginx/conf.d:/usr/local/openresty/nginx/conf/conf.d:rw
      - ./nginx/waf:/usr/local/openresty/nginx/conf/waf:rw
      - ./nginx/nginx.conf:/usr/local/openresty/nginx/conf/nginx.conf:rw
      - ./logs:/tmp/logs
      - /etc/localtime:/etc/localtime:ro
    restart: always
    network_mode: host
```



### WAF部署
```

```

