-- file: query_ip_location.lua (for Lua 5.3)

local xdb = require("xdb_searcher")

local db_path = "/usr/local/openresty/nginx/conf/waf/ip2region-2.11.2/data/ip2region.xdb"

-- Load xdb content and create searcher
local content = xdb.load_content(db_path)
if content == nil then
    print("failed to load xdb content")
    os.exit(1)
end

local searcher, err = xdb.new_with_buffer(content)
if err then
    print(string.format("failed to create searcher: %s", err))
    os.exit(1)
end

-- Read IP address from input
local ip_str = arg[1]
if not ip_str then
    print("IP address is required")
    os.exit(1)
end

-- Search and print result
local region, err = searcher:search(ip_str)
if err then
    print(string.format("failed to search(%s): %s", ip_str, err))
    os.exit(1)
end

print(region)

