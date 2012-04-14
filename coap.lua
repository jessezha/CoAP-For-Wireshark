-- CoAP-For-Wireshark
-- A Lua implementation for coap dissector of wireshark. It currently supports [draft-ietf-core-coap-08].
-- @Version: 0.2
-- @Author: Jiexi Zha
-- @E-Mail: jesse@bupt.edu.cn

do
	require "bitstring"
	
	--Protocol name "CoAP"
	local p_coap = Proto("CoAP_09", "Constrained Application Protocol - CoAP")
	
	--Protocol Fields
	local f_version = ProtoField.uint8("CoAP.version","Version",base.DEC, nil, 0xC0)
	local f_type = ProtoField.uint8("CoAP.type","Type",base.DEC,
		{ [0] = "Confirmable", [1] = "Non-Confirmable", [2] = "Acknowledgement", [3] = "Reset" }, 0x30
	)
	local f_optionCount = ProtoField.uint8("CoAP.optionCount","Option Count",base.DEC, nil, 0x0F)
	local f_code = ProtoField.uint8("CoAP.code","Code",base.DEC,
		{
			[0]   = "Empty",
			[1]   = "GET",
			[2]   = "POST",
			[3]   = "PUT",
			[4]   = "DELETE",
			[65]  = "2.01 Created",
			[66]  = "2.02 Deleted",
			[67]  = "2.03 Valid",
			[68]  = "2.04 Changed",
			[69]  = "2.05 Content",
			[128] = "4.00 Bad Request",
			[129] = "4.01 Unauthorized",
			[130] = "4.02 Bad Option",
			[131] = "4.03 Forbidden",
			[132] = "4.04 Not Found",
			[133] = "4.05 Method Not Allowed",
			[134] = "4.06 Not Acceptable",
			[140] = "4.12 Precondition Failed",
			[141] = "4.13 Request Entity Too Large",
			[143] = "4.15 Unsupported Media Type",
			[160] = "5.00 Internal Server Error",
			[161] = "5.01 Not Implemented",
			[162] = "5.02 Bad Gateway",
			[163] = "5.03 Service Unavailable",
			[164] = "5.04 Gateway Timeout",
			[165] = "5.05 Proxying Not Supported"
		}
	)
	local f_mid = ProtoField.uint16("CoAP.messageID","Message ID",base.HEX)
	
	-- Define Options
	local f_o_contentType   = ProtoField.bytes("CoAP.option.contentType", "Content-Type Option", nil)
	local f_o_maxAge        = ProtoField.bytes("CoAP.option.maxAge", "Max-Age Option", nil)
	local f_o_proxyUri      = ProtoField.bytes("CoAP.option.proxyUri", "Proxy-Uri Option", nil)
	local f_o_eTag          = ProtoField.bytes("CoAP.option.eTag", "ETag Option", nil)
	local f_o_uriHost       = ProtoField.bytes("CoAP.option.uriHost", "Uri-Host Option", nil)
	local f_o_locationPath  = ProtoField.bytes("CoAP.option.locationPath", "Location-Path Option", nil)
	local f_o_uriPort       = ProtoField.bytes("CoAP.option.uriPort", "Uri-Port Option", nil)
	local f_o_locationQuery = ProtoField.bytes("CoAP.option.locationQuery", "Location-Query Option", nil)
	local f_o_uriPath       = ProtoField.bytes("CoAP.option.uriPath", "Uri-Path Option", nil)
	local f_o_observe       = ProtoField.bytes("CoAP.option.observe", "Observe Option", nil)
	local f_o_token         = ProtoField.bytes("CoAP.option.token", "Token Option", nil)
	local f_o_accept        = ProtoField.bytes("CoAP.option.accept", "Accept Option", nil)
	local f_o_ifMatch       = ProtoField.bytes("CoAP.option.ifMatch", "If-Match Option", nil)
	local f_o_uriQuery      = ProtoField.bytes("CoAP.option.uriQuery", "Uri-Query Option", nil)
	local f_o_ifNoneMatch   = ProtoField.bytes("CoAP.option.ifNoneMatch", "If-None-Match Option", nil)
	local f_o_fenceposting  = ProtoField.bytes("CoAP.option.fenceposting", "Fenceposting(Ignored)", nil)
	local f_o_unrecognized  = ProtoField.bytes("CoAP.option.unrecognized", "Unrecognized Option", nil)
	
	local f_options = {
		[1]  = f_o_contentType,
		[2]  = f_o_maxAge,
		[3]  = f_o_proxyUri,
		[4]  = f_o_eTag,
		[5]  = f_o_uriHost,
		[6]  = f_o_locationPath,
		[7]  = f_o_uriPort,
		[8]  = f_o_locationQuery,
		[9]  = f_o_uriPath,
		[10] = f_o_observe,
		[11] = f_o_token,
		[12] = f_o_accept,
		[13] = f_o_ifMatch,
		[15] = f_o_uriQuery,
		[21] = f_o_ifNoneMatch
	}
	
	local f_o_delta = ProtoField.uint8("CoAP.option.delta", "Option Delta", base.DEC, nil, 0xf0)
	local f_o_length = ProtoField.uint8("CoAP.option.length", "Value Length", base.DEC, nil)
	local f_o_value_uint = ProtoField.uint32("CoAP.option.value", "Option Value(uint)", base.DEC)
	local f_o_value_string = ProtoField.string("CoAP.option.value", "Option Value(string)", nil)
	local f_o_value_opaque = ProtoField.bytes("CoAP.option.value", "Option Value(opaque)", nil)
	
	local f_optionvalue_type = {
		[1]  = f_o_value_uint,
		[2]  = f_o_value_uint,
		[3]  = f_o_value_string,
		[4]  = f_o_value_opaque,
		[5]  = f_o_value_string,
		[6]  = f_o_value_string,
		[7]  = f_o_value_uint,
		[8]  = f_o_value_string,
		[9]  = f_o_value_string,
		[10] = f_o_value_uint,
		[11] = f_o_value_opaque,
		[12] = f_o_value_uint,
		[13] = f_o_value_opaque,
		[15] = f_o_value_string,
	}
	
	local f_payload = ProtoField.bytes("CoAP.payload","Payload")
	
	p_coap.fields = { f_version, f_type, f_optionCount, f_code, f_mid, f_o_contentType, f_o_maxAge, f_o_proxyUri, f_o_eTag, f_o_uriHost, f_o_locationPath,f_o_uriPort, f_o_locationQuery, f_o_uriPath, f_o_observe, f_o_token, f_o_accept, f_o_ifMatch, f_o_uriQuery, f_o_ifNoneMatch, f_o_fenceposting, f_o_unrecognized, f_o_delta, f_o_length, f_o_value_uint, f_o_value_string, f_o_value_opaque, f_payload }
	
	local data_dis = Dissector.get("data")
	
	local function coap_dissector( buf, pkt, tree )
		local buf_len = buf:len()
		if buf_len < 4 then return false end
		local subtree = tree:add(p_coap, buf)
		local offset = 0
		
		-- get version,type,oc bit values using bitstring
		local firstByte = buf(offset, 1)
		subtree:add(f_version, firstByte)
		subtree:add(f_type, firstByte)
		local octree = subtree:add(f_optionCount, firstByte)
		offset = offset + 1
		
		local version, mtype, optionCount = bitstring.unpack("2:int, 2:int, 4:int", bitstring.fromhexstream(tostring(firstByte:bytes())))
		
		-- version check
		if version ~= 1 then return false end
		
		pkt.cols.protocol = "CoAP"
		
		-- get code value
		local v_code = buf(offset, 1)
		subtree:add(f_code, v_code)
		offset = offset + 1
		
		-- get message id
		local v_mid = buf(offset, 2)
		subtree:add(f_mid, v_mid)
		subtree:append_text(", Message ID: 0x" .. v_mid)
		offset = offset + 2
		
		-- set notification if option number equals 15
		if optionCount == 15 then
			octree:append_text("(Unlimited)")
		end
		
		-- get options
		local pre_opt_num = 0;
		for i=1, optionCount do
			-- init option's length & option value's length
			local opt_len = 0
			local val_len = 0
			local opt_hd_len = 0;
			
			-- first byte, including option delta & length
			local delta_length = buf(offset,1)
			local v_delta, v_length = bitstring.unpack("4:int, 4:int", bitstring.fromhexstream(tostring(delta_length:bytes())))
			
			-- End-of-options Marker
			if optionCount == 15 then
				i = 1
				if v_delta == 15 and v_length == 0 then
					break
				end
			end
			
			-- get the length of the Option Value & the Option, in bytes
			if v_length == 15 then
				val_len = buf(offset+1,1):uint()
				opt_hd_len = 2
				opt_len = val_len + opt_hd_len
			else
				val_len = v_length
				opt_hd_len = 1
				opt_len = val_len + opt_hd_len
			end
			
			-- get option number
			local opt_num = pre_opt_num + v_delta
			
			local v_option = buf(offset,opt_len)
			local optionTree = nil
			
			if opt_num % 14 == 0 then
				-- fenceposting, ignored
			else
				if f_options[opt_num] ~= nil then
					optionTree = subtree:add(f_options[opt_num],v_option)
				else
					optionTree = subtree:add(f_o_unrecognized, v_option)
				end
			end
			
			optionTree:add(f_o_delta, delta_length)
			optionTree:add(f_o_length, val_len)
			if val_len ~= 0 then
				local v_optionvalue = buf(offset+opt_hd_len, val_len)
				optionTree:add(f_optionvalue_type[opt_num], v_optionvalue)
			else
				-- no option value
			end
			
			offset = offset + opt_len
			pre_opt_num = pre_opt_num + v_delta
		end -- end of options
		
		-- get payload
		if buf(offset):len() == 0 then
			-- no payload
		else
			local v_payload = buf(offset)
			subtree:add(f_payload, v_payload)
		end
		
		return true
	end
	
	function p_coap.dissector(buf, pkt, tree)
		if coap_dissector(buf, pkt, tree) then
			-- a valid coap message
		else
			data_dis:call(buf, pkt, tree)
		end
	end
	
	local udp_encap_table = DissectorTable.get("udp.port")
    --handle udp port 5683
    udp_encap_table:add(5683,p_coap)
end
