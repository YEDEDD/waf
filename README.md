# WAF 
- 使用Openresty+Lua实现自定义WAF（Web application firewall）
- 1秒安装，快速启动，极速体验

## 项目背景介绍

### 需求产生

由于公司对安全防护要求，专业的安全设备又巨贵，就研究能不能自己编写一个WAF。

### 功能列表：
1.	容器化，快速部署。
2.	支持IP白名单。
3.	支持黑名单。
4.	支持tcp、udp规则防护。
5.	支持URL白名单，将不需要过滤的URL进行定义。
6.	支持域名黑名单，注域名黑名单和URL白名单不同，URL匹配域名后缀包括端口。
7.	支持针对每个server的拦截，而不是全部拦截。
8.	支持全局及默认某几个server块的未匹配的规则放行。
9.	支持User-Agent的过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
10.	支持CC攻击防护，单个URL指定时间的访问次数，超过设定值，直接返回403。
11.	支持Cookie过滤，匹配自定义规则中的条目，然后进行处理（返回403）。
12.	支持URL过滤，匹配自定义规则中的条目，如果用户请求的URL包含这些，返回403。
13.	支持URL参数过滤，原理同上。
14.	支持日志记录，将白名单、拦截日志与未匹配到的日志分开记录到每个server块下定义的日志目录。
15.	日志记录为JSON格式，便于日志分析，例如使用ELK进行攻击日志收集、存储、搜索和展示。

    

### WAF实现

WAF一句话描述，就是解析HTTP请求（协议解析模块），规则检测（规则模块），做不同的防御动作（动作模块），并将防御过程（日志模块）记录下来。所以本文中的WAF的实现由五个模块(配置模块、协议解析模块、规则模块、动作模块、错误处理模块）组成。
新增TCP/UDP防护拦截。

### 流程图
- 优先级由上到下
- 可配置是否开启未匹配是否拦截，不拦截只记录日志/全部拦截记录日志


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

#### 单个server服务配置
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

### 设置服务日志名称
#### 背景
当waf防护的规则有监控服务，如普罗米修斯会有大量的日志产生，以前日志都在一个文件。现在日志分为三个部分如：
```
[root@waf logs]# ls
blocked_waf_2024-08-21.log   white_waf_2024-08-21.log
```
- `white_waf_xxx` 为白名单日志
- `blocked_waf_xxx` 所有被拦截的日志
针对每个server的日志记录位置配置，可确保每个服务有自己的日志避免搞混。

#### 配置
使用`$log_dir`变量配置服务日志目录名称。
```
server {
    listen       80;
    server_name  localhost;

    #设置80端口的健康日志目录为"xx"目录
    set $log_dir "xx";

    #设置sever使用的rule规则，如白名单、黑名单等，达到单独限制某个server的waf功能
    set $rule_config_dir "/usr/local/openresty/nginx/conf/waf/rule-config";
    access_by_lua_block {
        config_rule_dir = ngx.var.rule_config_dir
        dofile("/usr/local/openresty/nginx/conf/waf/access.lua")
    }
```

#### 特殊配置说明
默认不在规则内的IP或者域名默认访问都是放行的。

#### 场景一 默认全局拒绝
修改配置文件`config.lua`
```
--enable/disable no match   on: 未匹配的都拦截 off: 未匹配都都放行
config_no_match_check = "on"
```
#### 场景二 单个server块进行放行
在server/stream中设置的`server_no_match_check`优先级高于`config_no_match_check`，不设置默认走`config_no_match_check`
```
server {
    listen 9091 ;
    server_name 10.0.1.xxx;

    set $log_dir "n9e";
    # conf.lua中config_no_match_check默认为on是拒绝所有未记录的IP或者其他规则
    # 但是在server中如果配置server_no_match_check为off那么将放行这个server块的所有来源
    set $server_no_match_check "off";  # 单独定义 no match check 的值 

    set $rule_config_dir "/usr/local/openresty/nginx/conf/waf/n9e-rule-config";
    access_by_lua_block {
        config_rule_dir = ngx.var.rule_config_dir
        dofile("/usr/local/openresty/nginx/conf/waf/access.lua")
    }

    location / {
        proxy_pass http://xxx.xxxx.cn:9091/;
    }
}
```
#### 场景三 TPC 代理
```
stream {
    lua_shared_dict tcp_udp_limit 50m;
    lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua";
    init_by_lua_file "/usr/local/openresty/nginx/conf/waf/init.lua";
    server {
        listen 4085;

        set $log_dir "tcp_udp";

        set $server_no_match_check "off";
        set $rule_config_dir "/usr/local/openresty/nginx/conf/waf/rule-config";
        preread_by_lua_block {
            config_rule_dir = ngx.var.rule_config_dir
            dofile("/usr/local/openresty/nginx/conf/waf/access.lua")
        }
        # 定义处理逻辑
        proxy_pass 10.0.10.xx:4085;
    }
```

#### 场景四 UDP 代理
```
stream {
    lua_shared_dict tcp_udp_limit 50m;
    lua_package_path "/usr/local/openresty/nginx/conf/waf/?.lua";
    init_by_lua_file "/usr/local/openresty/nginx/conf/waf/init.lua";

    # 监听端口 4085，并执行 Lua 脚本
    server {
        listen 6789 udp;

        set $log_dir "tcp_udp";
        set $server_no_match_check "off";
        set $rule_config_dir "/usr/local/openresty/nginx/conf/waf/rule-config";
        preread_by_lua_block {
            config_rule_dir = ngx.var.rule_config_dir
            dofile("/usr/local/openresty/nginx/conf/waf/access.lua")
        }
        # 定义处理逻辑
        proxy_pass 10.0.4.xx:6789;
    }
```





