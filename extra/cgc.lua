--
-- CGC Network Appliance pcap disector
--
-- Copyright (C) 2015 - Brian Caswell <bmc@lungetech.com>
-- 
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
-- 
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
-- 
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--

cgc_proto = Proto("cgc", "CGC Network Appliance")

local CGC_SIDES = {[0] = "SERVER", [1] = "CLIENT"}

local cgc_error_len = ProtoExpert.new("cgc.too_short.expert", "CGC Message is too short", expert.group.MALFORMED, expert.severity.ERROR)

local cgc_csid = ProtoField.uint32("cgc.csid", "Challenge Set")
local cgc_connection_id = ProtoField.uint32("cgc.connection_id", "Connection ID")
local cgc_message_id = ProtoField.uint32("cgc.message_id", "Message ID")
local cgc_message_len = ProtoField.uint16("cgc.message_len", "Message Length")
local cgc_side = ProtoField.uint8("cgc.side", "Side", base.DEC, CGC_SIDES)
local cgc_message = ProtoField.bytes("cgc.message", "Message")

cgc_proto.experts = { cgc_error_len }
cgc_proto.fields = { cgc_csid, cgc_connection_id, cgc_message_id, cgc_message_len, cgc_side, cgc_message}

function cgc_proto.dissector(buffer, pinfo, root)
    pinfo.cols.protocol:set("CGC")

    local pktlen = buffer:reported_length_remaining()

    if pktlen < 15 then
        tree:add_proto_expert_info(cgc_error_len)
        return
    end

    local tree = root:add(cgc_proto, buffer(), "CGC Network Appliance")

    tree:add_le(cgc_csid, buffer:range(0, 4))
    tree:add_le(cgc_connection_id, buffer:range(4, 4))
    tree:add_le(cgc_message_id, buffer:range(8, 4))
    local message_len = buffer:range(12, 2)
    tree:add_le(cgc_message_len, message_len)
    tree:add_le(cgc_side, buffer:range(14, 1))
    tree:add_le(cgc_message, buffer(15, message_len:le_uint()))
end

DissectorTable.get("ethertype"):add(0xFFFF, cgc_proto)
