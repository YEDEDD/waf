# WAF 
- 使用Openresty+Lua实现自定义WAF（Web application firewall）

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
10.	支持日志记录，将白名单、拦截日志与未匹配到的日志分开记录到每个server块下定义的日志目录。
11.	日志记录为JSON格式，便于日志分析，例如使用ELK进行攻击日志收集、存储、搜索和展示。
12.	支持针对每个server的拦截，而不是全部拦截。
    

### WAF实现

WAF一句话描述，就是解析HTTP请求（协议解析模块），规则检测（规则模块），做不同的防御动作（动作模块），并将防御过程（日志模块）记录下来。所以本文中的WAF的实现由五个模块(配置模块、协议解析模块、规则模块、动作模块、错误处理模块）组成。

### 流程图
- 优先级由上到下
- 可配置是否开启未匹配是否拦截，不拦截只记录日志/全部拦截记录日志
![image](https://github.com/user-attachments/assets/dd1564a5-d971-4283-9236-8bfabb417755)

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
[root@waf test]# git clone https://github.com/YEDEDD/waf.git
[root@waf test]# cd waf/
[root@waf waf]# docker-compose up -d
```


### 全局配置
在http块下配置，
```
http {
    include       mime.types;
    default_type  application/octet-stream;
......
    #全局设置，对所有的server进行限制，只使用一套规则
    lua_shared_dict limit 50m;
    lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua";
    init_by_lua_file "/usr/local/openresty/nginx/conf/waf/init.lua";
    access_by_lua_file "/usr/local/openresty/nginx/conf/waf/access.lua";
......
}
```

#### 单个服务配置
针对某个server的拦截
```
server {
    listen       80;
    server_name  localhost;
    
    set $log_dir "xx";

    #设置sever使用的rule规则，如白名单、黑名单等，达到单独限制某个server的waf功能
    set $rule_config_dir "/usr/local/openresty/nginx/conf/waf/rule-config";
    access_by_lua_block {
        config_rule_dir = ngx.var.rule_config_dir
        dofile("/usr/local/openresty/nginx/conf/waf/access.lua")
    }



    location / {
        content_by_lua_block {
            ngx.header.content_type = "text/html"

            -- 获取请求头中的 Host 字段
            local domain = ngx.var.host

            -- 输出域名到浏览器
            if domain then
                ngx.say("Domain: ", domain)
            else
                ngx.say("Domain not found ")
            end
        }
    }
}
```
如果要针对多个server进行单独限制那么就根据上述内容修改，主要为`$rule_config_dir`路径。然后在拷贝一下`rule-config`为对应的`$rule_config_dir`设置路径。

