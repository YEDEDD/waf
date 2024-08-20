--WAF config file,enable = "on",disable = "off"

--waf status
config_waf_enable = "on"
--log dir
config_log_dir = "/tmp/logs"
--rule setting
config_rule_dir = "/usr/local/openresty/nginx/conf/waf/rule-config"
--enable/disable white url
config_white_url_check = "on"
--enable/disable domain url
config_domain_check = "on"
--enable/disable white ip
config_white_ip_check = "on"
--enable/disable block ip
config_black_ip_check = "on"
--enable/disable url filtering
config_url_check = "on"
--enalbe/disable url args filtering
config_url_args_check = "on"
--enable/disable user agent filtering
config_user_agent_check = "on"
--enable/disable cookie deny filtering
config_cookie_check = "on"
--enable/disable cc filtering
config_cc_check = "on"
--cc rate the xxx of xxx seconds
config_cc_rate = "10/60"
--enable/disable post filtering
config_post_check = "on"
--enable/disable no match   on: 未匹配的都拦截 off: 未匹配都都放行
config_no_match_check = "off"
--config waf output redirect/html
config_waf_output = "html"
--if config_waf_output ,setting url
config_waf_redirect_url = "https://waf.yuansuan.cn"
config_output_html=[[
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>拒绝访问</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600&display=swap');

        body {
            font-family: 'Montserrat', sans-serif;
            background-color: #ffffff;
            color: #333;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            text-align: center;
        }

        .container {
            background: #f7f9fc;
            border-radius: 12px;
            padding: 50px 40px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 100%;
            text-align: center;
            transition: transform 0.3s ease;
        }

        .container:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.15);
        }

        .icon {
            margin-bottom: 20px;
        }

        .icon svg {
            width: 80px;
            height: 80px;
            fill: #66a6ff;
        }

        h1 {
            font-size: 1.8em;
            margin: 0;
            font-weight: 600;
            color: #333;
            letter-spacing: 1px;
        }

        p {
            font-size: 1em;
            margin: 20px 0 30px;
            color: #666;
            line-height: 1.6;
        }

        a {
            display: inline-block;
            padding: 12px 30px;
            border-radius: 50px;
            background: #66a6ff;
            color: white;
            text-decoration: none;
            font-weight: 600;
            box-shadow: 0 4px 10px rgba(102, 166, 255, 0.3);
            transition: background 0.3s ease, box-shadow 0.3s ease, transform 0.3s ease;
        }

        a:hover {
            background: #5a9ae0;
            box-shadow: 0 6px 15px rgba(102, 166, 255, 0.4);
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-lock">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
        </div>
        <h1>拒绝访问</h1>
        <p>抱歉，您已经被WAF拦截，请检查您的行为规范。如果您认为这是错误，请联系管理员。</p>
        <a href="/">返回首页</a>
    </div>
</body>
</html>
]]
