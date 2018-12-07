local comm = require "comm"
local string = require "string"
local shortport = require "shortport"
local stdnse    = require "stdnse"
local vulns = require "vulns"

description = [[
Check for open remote shells on Android Device Over Android Debug Bridge (adb)
]]

---
-- @output
-- 5555/tcp open  android syn-ack ttl 52
-- | adb:
-- |   product_name: hlteuc
-- |   product_model: SAMSUNG-SM-N900A
-- |_  product_device: hlteatt
---

author = "Hossam Mohamed"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"version","vuln"}

portrule = shortport.portnumber(5555, "tcp")

action = function(host, port)
    local payload = "\x43\x4e\x58\x4e\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1\x68\x6f\x73\x74\x3a\x3a\x00"

    local status, result = comm.exchange(host, port, payload, {proto="tcp"})

    if not status then
        stdnse.debug("Could not get info ")
        return
    end

    if result then
        stdnse.debug("Connection from adb %s ", host.ip)
        local output = stdnse.output_table()
        output.product_name = string.match(result, "product.name=(.*);ro.product.model")
        output.product_model = string.match(result, "ro.product.model=(.*);ro.product.device=")
        output.product_device = string.match(result, ";ro.product.device=(.*);")
        port.version.name = "android"
        port.version.product = "remote-adb"
        nmap.set_port_version(host, port)
        return output
    end
end
