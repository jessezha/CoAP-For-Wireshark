-- A Lua implementation for dissecting udp sockets' payload carrying ieee 802.15.4 frames
-- @Version: 0.1
-- @Author: Jiexi Zha
-- @E-Mail: zhajx@bupt.edu.cn

do	
	local protos = {
        [0] = Dissector.get("ieee 802.15.4"),
        [1] = Dissector.get("6lowpan"),
        [2] = Dissector.get("ipv6"),
        [3] = Dissector.get("data"),
    }
	
	local udp_encap_table = DissectorTable.get("udp.port")
    udp_encap_table:add(13000,protos[0])
end
