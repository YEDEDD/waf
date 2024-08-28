--waf core lib
require 'config'

-- 判断是否为 HTTP 请求
local is_http = ngx.req and ngx.req.get_headers

-- Get the client IP
function get_client_ip()
    if is_http then
        CLIENT_IP = ngx.req.get_headers()["X_real_ip"]
        if CLIENT_IP == nil then
            CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
        end
        if CLIENT_IP == nil then
            CLIENT_IP  = ngx.var.remote_addr
        end
    else
        -- 如果是 TCP 流量，直接使用 ngx.var.remote_addr
        CLIENT_IP = ngx.var.remote_addr
    end

    if CLIENT_IP == nil then
        CLIENT_IP  = "unknown"
    end
    return CLIENT_IP
end

-- Get the client user agent
function get_user_agent()
    if is_http then
        USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT == nil then
           USER_AGENT = "unknown"
        end
    else
        -- TCP 流量不支持 user_agent，返回 "N/A"
        USER_AGENT = "N/A"
    end
    return USER_AGENT
end

-- Get WAF rule
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

-- WAF log record for json,(use logstash codec => json)

function log_record_no_match_allow(method, url, data, ruletag)
    log_record(method, url, data, ruletag, false)
end
function log_record_no_match_block(method, url, data, ruletag)
    log_record(method, url, data, ruletag, true)
end

function log_record_normal(method, url, data, ruletag)
    log_record(method, url, data, ruletag, false)
end

function log_record_blocked(method, url, data, ruletag)
    log_record(method, url, data, ruletag, true)
end


function log_record(method, url, data, ruletag, status)
    local cjson = require("cjson")
    local io = require 'io'

    -- 检测协议类型
    local protocol_type
    if ngx.var.protocol then
        protocol_type = ngx.var.protocol
    elseif ngx.req.get_headers() then
        protocol_type = "http"
    else
        protocol_type = "unknown"
    end

    local LOG_PATH = config_log_dir
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = get_user_agent()
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()
    local SERVER_PORT = ngx.var.server_port  -- 获取被访问的端口号

    -- 判断请求是否被拦截或放行
    local request_status = status == true and "Blocked" or "Allowed"

    -- 获取定义的日志目录名称
    local log_dir = ngx.var.log_dir or "default"

    -- 创建日志目录路径
    local LOG_PATH = config_log_dir .. '/' .. log_dir

    -- 创建日志目录
    local cmd = "mkdir -p " .. LOG_PATH
    os.execute(cmd)

    -- 创建有序日志对象
    local log_json_obj = {
        {key = "local_time", value = LOCAL_TIME},
        {key = "client_ip", value = CLIENT_IP},
        {key = "server_port", value = SERVER_PORT},  -- 添加端口号到日志对象
        {key = "attack_method", value = method},
        {key = "request_status", value = request_status},  -- 添加请求状态字段
        {key = "protocol", value = protocol_type},  -- 添加协议类型字段
        {key = "user_agent", value = USER_AGENT},
        {key = "req_url", value = url or "_" },
        {key = "req_data", value = data},
        {key = "rule_tag", value = ruletag},
        {key = "server_name", value = SERVER_NAME}
    }

-- 手动按顺序生成JSON字符串
local log_json_str = "{"
for i, item in ipairs(log_json_obj) do
    -- 检查 item.value 是否为 nil，如果是，将其设为 "unknown"
    local value = item.value or "unknown"
    log_json_str = log_json_str .. '"' .. item.key .. '":"' .. value .. '"'
    if i < #log_json_obj then
        log_json_str = log_json_str .. ","
    end
end
log_json_str = log_json_str .. "}"

    local LOG_NAME
    if status == true then
        LOG_NAME = LOG_PATH .. '/' .. "blocked_waf_" .. ngx.today() .. ".log"
    else
        LOG_NAME = LOG_PATH .. '/' .. "white_waf_" .. ngx.today() .. ".log"
    end

    local file = io.open(LOG_NAME, "a")
    if file then
        file:write(log_json_str .. "\n")
        file:flush()
        file:close()
    end
end


-- WAF return
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
