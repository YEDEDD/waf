--waf core lib
require 'config'

--Get the client IP
function get_client_ip()
    CLIENT_IP = ngx.req.get_headers()["X_real_ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = ngx.var.remote_addr
    end
    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown"
    end
    return CLIENT_IP
end

--Get the client user agent
function get_user_agent()
    USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
       USER_AGENT = "unknown"
    end
    return USER_AGENT
end

--Get WAF rule
function get_rule(rulefilename)
    local io = require 'io'
    local RULE_PATH = config_rule_dir
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r")
    if RULE_FILE == nil then
        return
    end
    RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE,line)
    end
    RULE_FILE:close()
    return(RULE_TABLE)
end

--WAF log record for json,(use logstash codec => json)
--[[function log_record(method,url,data,ruletag)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    local log_json_obj = {
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              }
    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME = LOG_PATH..'/'..ngx.today().."_waf.log"

    local file = io.open(LOG_NAME,"a")
    if file == nil then
        return
    end
    file:write(LOG_LINE.."\n")
    file:flush()
    file:close()
end --]]

function log_record_no_match(method, url, data, ruletag)
    log_record(method, url, data, ruletag, "no_match")
end

function log_record_normal(method, url, data, ruletag)
    log_record(method, url, data, ruletag, false)
end

function log_record_blocked(method, url, data, ruletag)
    log_record(method, url, data, ruletag, true)
end

--[[
function log_record(method, url, data, ruletag, status)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    
    local log_json_obj = {
        client_ip = CLIENT_IP,
        local_time = LOCAL_TIME,
        server_name = SERVER_NAME,
        user_agent = USER_AGENT,
        attack_method = method,
        req_url = url,
        req_data = data,
        rule_tag = ruletag,
    }
    
    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME

    if status == "no_match" then
        LOG_NAME = LOG_PATH..'/'.."no_match_waf_"..ngx.today()..".log"
    elseif status == true then
        LOG_NAME = LOG_PATH..'/'.."blocked_waf_"..ngx.today()..".log"
    else
        LOG_NAME = LOG_PATH..'/'.."white_waf_"..ngx.today()..".log"
    end

    local file = io.open(LOG_NAME, "a")
    if file then
        file:write(LOG_LINE.."\n")
        file:flush()
        file:close()
    end
end
--]]

--[[
function log_record(method, url, data, ruletag, status)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()

    -- 获取 conf.d 目录下的文件列表
    local conf_files = {}
    for file in io.popen("ls /usr/local/openresty/nginx/conf/conf.d/"):lines() do
        table.insert(conf_files, file)
    end

    -- 根据文件名创建日志目录
    local log_dir
    for _, file in ipairs(conf_files) do
        local dir_name = file:match("^(.*)%-proxy%.conf$")
        if dir_name then
            log_dir = LOG_PATH..'/'..dir_name..'/'
            break
        end
    end

    if not log_dir then
        log_dir = LOG_PATH..'/'
    end

    -- 创建日志目录
    local cmd = "mkdir -p "..log_dir
    io.popen(cmd):close()

    local log_json_obj = {
        client_ip = CLIENT_IP,
        local_time = LOCAL_TIME,
        server_name = SERVER_NAME,
        user_agent = USER_AGENT,
        attack_method = method,
        req_url = url,
        req_data = data,
        rule_tag = ruletag,
    }

    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME

    if status == "no_match" then
        LOG_NAME = log_dir..'/'.."no_match_waf_"..ngx.today()..".log"
    elseif status == true then
        LOG_NAME = log_dir..'/'.."blocked_waf_"..ngx.today()..".log"
    else
        LOG_NAME = log_dir..'/'.."white_waf_"..ngx.today()..".log"
    end

    local file = io.open(LOG_NAME, "a")
    if file then
        file:write(LOG_LINE.."\n")
        file:flush()
        file:close()
    end
end
--]]

function log_record(method, url, data, ruletag, status)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    local SERVER_PORT = ngx.var.server_port  -- 获取被访问的端口号
    
    -- 获取定义的日志目录名称
    local log_dir = ngx.var.log_dir or "default"

    -- 创建日志目录路径
    local LOG_PATH = config_log_dir .. '/' .. log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()

    -- 创建日志目录
    local cmd = "mkdir -p " .. LOG_PATH
    os.execute(cmd)

    local log_json_obj = {
        client_ip = CLIENT_IP,
        local_time = LOCAL_TIME,
        server_name = SERVER_NAME,
        server_port = SERVER_PORT,  -- 添加端口号到日志对象
        user_agent = USER_AGENT,
        attack_method = method,
        req_url = url,
        req_data = data,
        rule_tag = ruletag,
    }

    local LOG_LINE = cjson.encode(log_json_obj)
    local LOG_NAME

    if status == "no_match" then
        LOG_NAME = LOG_PATH .. '/' .. "no_match_waf_" .. ngx.today() .. ".log"
    elseif status == true then
        LOG_NAME = LOG_PATH .. '/' .. "blocked_waf_" .. ngx.today() .. ".log"
    else
        LOG_NAME = LOG_PATH .. '/' .. "white_waf_" .. ngx.today() .. ".log"
    end

    local file = io.open(LOG_NAME, "a")
    if file then
        file:write(LOG_LINE .. "\n")
        file:flush()
        file:close()
    end
end


--WAF return
function waf_output()
    if config_waf_output == "redirect" then
        ngx.redirect(config_waf_redirect_url, 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(config_output_html)
        ngx.exit(ngx.status)
    end
end

