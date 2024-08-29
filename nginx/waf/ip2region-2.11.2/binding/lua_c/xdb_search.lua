local xdb = require("xdb_searcher")

local db_path = "../../data/ip2region.xdb"

-- 1、从指定的 db_path 加载整个 xdb 到内存。
-- xdb内容加载一次即可，建议在服务启动的时候加载为全局对象。
content = xdb.load_content(db_path)
if content == nil then
    print(string.format("failed to load xdb content from '%s'", db_path))
    return
end

-- 2、使用全局的 content 创建带完全基于内存的查询对象。
searcher, err = xdb.new_with_buffer(content)
if err ~= nil then
    print(string.format("failed to create content buffer searcher: %s", err))
    return
end

-- 3、调用查询 API 
local ip_str = "1.2.3.4"
local s_time = xdb.now()
region, err = searcher:search(ip_str)
if err ~= nil then
    print(string.format("failed to search(%s): %s", ip_str, err))
    return
end

-- 备注：并发使用，用 xdb 整个缓存创建的查询对象可以安全的用于并发。
-- 建议在服务启动的时候创建好全局的 searcher 对象，然后全局并发使用。

print(string.format("{region: %s, took: %.5f μs}", region, xdb.now() - s_time))
