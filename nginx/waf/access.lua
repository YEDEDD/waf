require 'init'

-- 从 Nginx 变量中获取每个server规则目录路径
config_rule_dir = ngx.var.rule_config_dir

-- 创建日志目录


function waf_main()
    if white_ip_check() then
    elseif black_ip_check() then
    elseif domain_attack_check() then
    elseif white_url_check() then
    elseif user_agent_attack_check() then
    elseif cc_attack_check() then
    elseif cookie_attack_check() then
    elseif url_attack_check() then
    elseif url_args_attack_check() then
    --elseif post_attack_check() then
    elseif waf_deny_no_match() then
    else
        -- 如果没有匹配到任何规则，记录未被拦截的请求
        --log_record_no_match('No_Match', ngx.var.request_uri, "_", "No_Match")
        return
    end
end

waf_main()

