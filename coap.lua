-- CoAP-For-Wireshark
-- A Lua implementation for coap dissector of wireshark. It currently supports [draft-ietf-core-coap-08].
-- @Version: 0.2
-- @Author: Jiexi Zha
-- @E-Mail: jesse@bupt.edu.cn

do
	require "bitstring"
	
	--Protocol name "CoAP"
	local p_coap = Proto("CoAP_12", "Constrained Application Protocol - v12")
	
	--Protocol Fields
	local f_version = ProtoField.uint8("CoAP.version","Version",base.DEC, nil, 0xC0)
	local f_type = ProtoField.uint8("CoAP.type","Type",base.DEC,
		{ [0] = "Confirmable", [1] = "Non-Confirmable", [2] = "Acknowledgement", [3] = "Reset" }, 0x30
	)
	local f_optionCount = ProtoField.uint8("CoAP.optionCount","Option Count",base.DEC, nil, 0x0F)
	
	local codeList = {
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
		[143] = "4.15 Unsupported Content-Format",
		[160] = "5.00 Internal Server Error",
		[161] = "5.01 Not Implemented",
		[162] = "5.02 Bad Gateway",
		[163] = "5.03 Service Unavailable",
		[164] = "5.04 Gateway Timeout",
		[165] = "5.05 Proxying Not Supported"
	}
	local f_code = ProtoField.uint8("CoAP.code", "Code", base.DEC, codeList)
	local f_mid = ProtoField.uint16("CoAP.messageID", "Message ID", base.HEX)
	
	-- Define Options
	local f_o_contentFormat = ProtoField.bytes("CoAP.option.contentFormat", "Content-Format Option", nil)
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
	local f_o_block1	    = ProtoField.bytes("CoAP.option.block1", "Block1 Option", nil)
	local f_o_block2	    = ProtoField.bytes("CoAP.option.block2", "Block2 Option", nil)
	local f_o_size		    = ProtoField.bytes("CoAP.option.size", "Size Option", nil)
	local f_o_unrecognized  = ProtoField.bytes("CoAP.option.unrecognized", "Unrecognized Option", nil)
	
	local f_options = {
		[1]  = f_o_ifMatch,
		[3]  = f_o_uriHost,
		[4]  = f_o_eTag,
		[5]  = f_o_ifNoneMatch,
		[6]  = f_o_observe,
		[7]  = f_o_uriPort,
		[8]  = f_o_locationPath,
		[11] = f_o_uriPath,
		[12] = f_o_contentFormat,
		[14] = f_o_maxAge,
		[15] = f_o_uriQuery,
		[16] = f_o_accept,
		[19] = f_o_token,
		[20] = f_o_locationQuery,
		[23] = f_o_block2,
		[27] = f_o_block1,
		[28] = f_o_size,
		[35] = f_o_proxyUri
	}
	
	local f_o_jump = ProtoField.bytes("CoAP.option.delta", "Option Jump", nil)
	local f_o_delta = ProtoField.uint8("CoAP.option.delta", "Option Delta", base.DEC, nil, 0xf0)
	local f_o_length = ProtoField.uint8("CoAP.option.length", "Value Length", base.DEC, nil)
	local f_o_value_uint = ProtoField.uint32("CoAP.option.value", "Option Value(uint)", base.DEC)
	local f_o_value_string = ProtoField.string("CoAP.option.value", "Option Value(string)", nil)
	local f_o_value_opaque = ProtoField.bytes("CoAP.option.value", "Option Value(opaque)", nil)
	local f_o_value_empty = ProtoField.bytes("CoAP.option.value", "Option Value(empty)", nil)
	
	local f_optionvalue_type = {
		[1]  = f_o_value_opaque,
		[3]  = f_o_value_string,
		[4]  = f_o_value_opaque,
		[5]  = f_o_value_empty,
		[6]  = f_o_value_uint,
		[7]  = f_o_value_uint,
		[8]  = f_o_value_string,
		[11] = f_o_value_string,
		[12] = f_o_value_uint,
		[14] = f_o_value_uint,	
		[15] = f_o_value_string,
		[16] = f_o_value_uint,
		[19] = f_o_value_opaque,
		[20] = f_o_value_string,
		[23] = f_o_value_uint,
		[27] = f_o_value_uint,
		[28] = f_o_value_uint,
		[35] = f_o_value_string
	}
	
	local f_payload = ProtoField.string("CoAP.payload","Payload",nil)
	
	p_coap.fields = { f_version, f_type, f_optionCount, f_code, f_mid, f_o_contentFormat, 
						f_o_maxAge, f_o_proxyUri, f_o_eTag, f_o_uriHost, f_o_locationPath,
						f_o_uriPort, f_o_locationQuery, f_o_uriPath, f_o_observe, f_o_block1, f_o_block2, f_o_size, f_o_token, 
						f_o_accept, f_o_ifMatch, f_o_uriQuery, f_o_ifNoneMatch, f_o_unrecognized, 
						f_o_jump, f_o_delta, f_o_length, f_o_value_uint, f_o_value_string, f_o_value_opaque, f_o_value_empty, f_payload}
	
	local data_dis = Dissector.get("data")
	
	local function coap_dissector( buf, pkt, tree )
		local buf_len = buf:len()
		if buf_len < 4 then return false end
		local subtree = tree:add(p_coap, buf)
		local offset = 0
		local infocol = nil;
		
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

		pkt.cols.info = "CoAP " .. mtype .. " " .. v_code   -- this needs to be fixed and expanded
		
		--info col
		infocol = "CoAP "..codeList[v_code:uint()].." "
		if v_code:uint() >= 1 and v_code:uint() <= 31 then
			infocol = infocol.."/"
		end
		
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
		local firstPathOpt = 1
		local firstQueryOpt = 1
		for i=1, optionCount do
			-- init option's length & option value's length
			local opt_len = 0
			local val_len = 0
			local opt_hd_len = 1;
			
			-- first byte
			local delta_length = buf(offset,1)
			local v_delta, v_length = bitstring.unpack("4:int, 4:int", bitstring.fromhexstream(tostring(delta_length:bytes())))
			
			-- End-of-options Marker
			if optionCount == 15 then
				i = 1
				if v_delta == 15 and v_length == 0 then
					offset = offset + 1
					break
				end
			end
			
			-- handle option jump
			if v_delta == 15 and v_length >= 1 and v_length <= 3 then
				if v_length == 1 then
					v_delta = 15
				elseif v_length == 2 then
					local jump_value = buf(offset+1,1):uint()
					v_delta = (jump_value + 2) * 8
				elseif v_length == 3 then
					local jump_value = buf(offset+1,2):uint()
					v_delta = (jump_value + 258) * 8
				end
				
				local v_jump = buf(offset, v_length)
				local ojump = subtree:add(f_o_jump, v_jump)
				ojump:append_text(", delta: " .. v_delta)
				
				pre_opt_num = pre_opt_num + v_delta
				offset = offset + v_length
				delta_length = buf(offset,1)
				v_delta, v_length = bitstring.unpack("4:int, 4:int", bitstring.fromhexstream(tostring(delta_length:bytes())))
			end	
			
			-- get the length of the Option Value & the Option, in bytes
			if v_length < 15 then
				val_len = v_length
				opt_len = val_len + opt_hd_len
			else
				local flag1, flag2, flag3
				flag1 = ( buf(offset+1,1):uint() == 255 )
				flag2 = ( buf(offset+2,1):uint() == 255 )
				flag3 = ( buf(offset+3,1):uint() == 255 )
				
				if flag1 == false then
					val_len = buf(offset+1,1):uint() + 15
					opt_hd_len = 2
				elseif flag2 == false then
					val_len = buf(offset+2,1):uint() + 270
					opt_hd_len = 3
				elseif flag3 == false then
					val_len = buf(offset+3,1):uint() + 525
					opt_hd_len = 4
				else
					val_len = buf(offset+4,1):uint() + 780
					opt_hd_len = 5
				end
				opt_len = val_len + opt_hd_len
			end
			
			-- get option number
			local opt_num = pre_opt_num + v_delta
			
			local v_option = buf(offset,opt_len)
			local optionTree = nil
			local v_optionvalue = nil
			
			if f_options[opt_num] ~= nil then
				optionTree = subtree:add(f_options[opt_num],v_option)
			else
				optionTree = subtree:add(f_o_unrecognized, v_option)
			end
			
			optionTree:add(f_o_delta, delta_length)
			optionTree:add(f_o_length, val_len)
			if val_len ~= 0 then
				v_optionvalue = buf(offset+opt_hd_len, val_len)
				optionTree:add(f_optionvalue_type[opt_num], v_optionvalue)
			else
				-- no option value
			end
			
			--info col
			-- UriPathOption
			if opt_num == 11 then
				if firstPathOpt == 1 then
					infocol = infocol..v_optionvalue:string()
					firstPathOpt = 0
				else
					infocol = infocol.."/"..v_optionvalue:string()
				end
			end
			-- UriQueryOption
			if opt_num == 15 then
				if firstPathOpt == 1 then
					infocol = infocol.."?"..v_optionvalue
					firstQueryOpt = 0
				else
					infocol = infocol.."&"..v_optionvalue
				end
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
		
		-- info col
		pkt.cols.info = infocol
		
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
