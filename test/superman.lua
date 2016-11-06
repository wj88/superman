superman_proto = Proto("superman", "SUPERMAN Protocol")

local superman_hdr_fields = {
	-- Standard header fields
	packet_type = ProtoField.uint8("superman.packet_type", "Packet Type", base.DEC),
	timestamp = ProtoField.uint16("superman.timestamp", "Timestamp", base.DEC),
	payload_len = ProtoField.uint16("superman.payload_len", "Payload Len", base.DEC),
	last_addr = ProtoField.ipv4("superman.last_addr", "Last Address"),

	-- Other fields
	public_key = ProtoField.bytes("superman.public_key", "Public Key", base.HEX),
	encrypted_data = ProtoField.bytes("superman.encrypted_data", "Encrypted Data", base.HEX),
	e2e_hmac = ProtoField.bytes("superman.e2ehmac", "E2E HMAC", base.HEX),
	p2p_hmac = ProtoField.bytes("superman.p2phmac", "P2P HMAC", base.HEX)

	-- Fields we cannot use because they're data is encrypted.
	--certificate_len = ProtoField.uint16("superman.certificate_len", "Certificate Len", base.DESC),
	--broadcast_key_len = ProtoField.uint16("superman.broadcast_key_len", "Broadcast Key Len", base.DESC),
	--original_addr = ProtoField.ipv4("superman.origin_addr", "Origin Address"),
	--target_addr = ProtoField.ipv4("superman.target_addr", "Target Address"),
	--addr = ProtoField.ipv4("superman.addr", "Address"),
	--sk_len = ProtoField.uint16("superman.sk_len", "SK Len", base.DESC),
	
	--certificate = ProtoField.none("superman.certificate", "Certificate"),
	--broadcast_key = ProtoField.none("superman.broadcast_key", "Broadcast Key"),
	--sk = ProtoField.none("superman.sk", "SK"),
	--data = ProtoField.none("superman.data", "Data"),
}

superman_proto.fields = superman_hdr_fields;

function superman_proto.dissector(tvbuf, pktinfo, root)
	pktinfo.cols.protocol = "SUPERMAN"
	local packet_type = tvbuf:range(0,1):uint()
	local payload_len = tvbuf:range(3, 2):uint()
	local packet_type_desc = "unknown"
	local data_packet_type = 0
	local data_packet_type_desc = ""
	if packet_type == 1 then
		packet_type_desc = "Discovery Request"
	elseif packet_type == 2 then
		packet_type_desc = "Certificate Request"
	elseif packet_type == 3 then
		packet_type_desc = "Certificate Exchange"
	elseif packet_type == 4 then
		packet_type_desc = "Certificate Exchange with Broadcast Key"
	elseif packet_type == 5 then
		packet_type_desc = "Authenticated SK Request"
	elseif packet_type == 6 then
		packet_type_desc = "Authenticated SK Response"
	elseif packet_type == 7 then
		packet_type_desc = "SK Invalidate"
	elseif packet_type == 8 then
		packet_type_desc = "Broadcast Key Exchange"
	else
		data_packet_type = packet_type - 8;
		data_packet_type_desc = " "..tostring(DissectorTable.get("ip.proto"):get_dissector(data_packet_type))
		packet_type_desc = "Data Packet:"..data_packet_type..", Encrypted "..data_packet_type_desc
	end

	local subtree = root:add(superman_proto, tvbuf:range(0, tvbuf:len()), "SUPERMAN Packet, "..packet_type_desc)
	subtree:add(superman_hdr_fields.packet_type, tvbuf:range(0, 1)):append_text(" ("..packet_type_desc..")")
	subtree:add(superman_hdr_fields.timestamp, tvbuf:range(1, 2))
	subtree:add(superman_hdr_fields.payload_len, tvbuf:range(3, 2))
	subtree:add(superman_hdr_fields.last_addr, tvbuf:range(5, 4))

	-- We're looking after the header
	local offset = 9
	
	if packet_type == 1 then
		subtree:add(superman_hdr_fields.public_key, tvbuf:range(offset, payload_len)):append_text(" ("..payload_len.." bytes)")
		offset = offset + payload_len
	elseif packet_type == 2 then
		subtree:add(superman_hdr_fields.public_key, tvbuf:range(offset, payload_len)):append_text(" ("..payload_len.." bytes)")
		offset = offset + payload_len
	--elseif packet_type == 3 then
	--	local cert_len = tvbuf:range(offset, 2):uint()
	--	subtree:add(superman_hdr_fields.certificate_len, tvbuf:range(offset, 2))
	--	offset = offset + 2
	--	subtree:add(superman_hdr_fields.certificate, tvbuf:range(offset, cert_len)):append_text(" ("..certificate_len.." bytes)")
	--	offset = offset + cert_len
	--elseif packet_type == 4 then
	--	local cert_len = tvbuf:range(offset, 2):uint()
	--	subtree:add(superman_hdr_fields.certificate_len, tvbuf:range(offset, 2))
	--	offset = offset + 2
	--	local broadcast_key_len = tvbuf:range(offset, 2):uint()
	--	subtree:add(superman_hdr_fields.broadcast_key_len, tvbuf:range(offset, 2))
	--	offset = offset + 2
	--	subtree:add(superman_hdr_fields.certificate, tvbuf:range(offset, cert_len)):append_text(" ("..certificate_len.." bytes)")
	--	offset = offset + cert_len
	--	subtree:add(superman_hdr_fields.broadcast_key, tvbuf:range(offset, broadcast_key_len)):append_text(" ("..broadcast_key_len.." bytes)")
	--	offset = offset + broadcast_key_len
	else
		subtree:add(superman_hdr_fields.encrypted_data, tvbuf:range(offset, payload_len)):append_text(data_packet_type_desc.." ("..payload_len.." bytes)")
		offset = offset + payload_len
	end

	if tvbuf:len() > offset then
		subtree:add(superman_hdr_fields.e2e_hmac, tvbuf:range(offset, 4))
		subtree:add(superman_hdr_fields.p2p_hmac, tvbuf:range(offset + 4, 4))
	--	local hmac_len = tvbuf:len() - offset
	--	subtree:add(superman_hdr_fields.hmac, tvbuf:range(offset, hmac_len)):append_text(" ("..hmac_len.." bytes)")
	--	offset = offset + hmac_len
	end

end

ip_prot = DissectorTable.get("ip.proto")
ip_prot:add(253,superman_proto)

