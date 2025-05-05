-- AlphaTheta PRO DJ LINK Wireshark Dissectors
-- 
-- by David Ng
-- Copyright 2025 Cardinia Electronics
--
-- https://github.com/nudge/wireshark-prodj-dissectors
--
--
-- Install under:
-- (Windows)      %APPDATA%\Wireshark\plugins\
-- (Linux, Mac)   $HOME/.wireshark/plugins
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
-- 
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
--

--------------------------------------------------
-- AlphaTheta PRO DJ LINK Protocol (Announce)
--------------------------------------------------
p_pdj_announce = Proto("pdj_announce", "AlphaTheta PRO DJ LINK Protocol (Announce)")

local pdj_announce_packet_types = {
  [0x00] = "Channel Claim Stage 1",
  [0x01] = "Mixer Assign Intention",
  [0x02] = "Channel Claim Stage 2",
  [0x03] = "Mixer Channel Assign",
  [0x04] = "Channel Claim Stage 3",
  [0x05] = "Mixer Assign Done",
  [0x06] = "Device Keep-alive",
  [0x08] = "Channel Conflict",
  [0x0a] = "Initial Announce"
}

local pdj_announce_device_types = {
  [0x01] = "Player",
  [0x02] = "Mixer Type 2",
  [0x03] = "Mixer Type 3"
}

local pdj_announce_f = p_pdj_announce.fields
pdj_announce_f.preamble = ProtoField.bytes("pdj_announce.preamble", "Preamble")
pdj_announce_f.type = ProtoField.uint8("pdj_announce.type", "Packet Type", base.HEX, pdj_announce_packet_types)
pdj_announce_f.subtype = ProtoField.uint8("pdj_announce.subtype", "Packet Sub-Type", base.HEX)
pdj_announce_f.name = ProtoField.stringz("pdj_announce.name", "Device Name", base.ASCII)

pdj_announce_f.t00_unk0 = ProtoField.uint8("pdj_announce.unk0", "Unknown 0", base.HEX)
pdj_announce_f.t00_unk1 = ProtoField.uint8("pdj_announce.unk1", "Unknown 1", base.HEX)
pdj_announce_f.t00_length = ProtoField.uint16("pdj_announce.length", "Length", base.DEC)
pdj_announce_f.t00_counter = ProtoField.uint8("pdj_announce.counter", "Counter", base.DEC)
pdj_announce_f.t00_unk2 = ProtoField.uint8("pdj_announce.unk2", "Unknown 2", base.HEX)
pdj_announce_f.t00_mac = ProtoField.ether("pdj_announce.mac", "MAC Address")

pdj_announce_f.t02_unk0 = ProtoField.uint8("pdj_announce.unk0", "Unknown 0", base.HEX)
pdj_announce_f.t02_unk1 = ProtoField.uint8("pdj_announce.unk1", "Unknown 1", base.HEX)
pdj_announce_f.t02_length = ProtoField.uint16("pdj_announce.length", "Length", base.DEC)
pdj_announce_f.t02_counter = ProtoField.uint8("pdj_announce.counter", "Counter", base.DEC)
pdj_announce_f.t02_unk2 = ProtoField.uint8("pdj_announce.unk2", "Unknown 2", base.HEX)
pdj_announce_f.t02_device_number = ProtoField.uint8("pdj_announce.unk3", "Device Number", base.DEC)
pdj_announce_f.t02_ip = ProtoField.ipv4("pdj_announce.ip", "IP Address")
pdj_announce_f.t02_mac = ProtoField.ether("pdj_announce.mac", "MAC Address")
pdj_announce_f.t02_autoassign = ProtoField.uint8("pdj_announce.autoassign", "Auto-assign", base.HEX)

pdj_announce_f.t04_unk0 = ProtoField.uint8("pdj_announce.unk0", "Unknown 0", base.HEX)
pdj_announce_f.t04_unk1 = ProtoField.uint8("pdj_announce.unk1", "Unknown 1", base.HEX)
pdj_announce_f.t04_length = ProtoField.uint16("pdj_announce.length", "Length", base.DEC)
pdj_announce_f.t04_device_number = ProtoField.uint8("pdj_announce.device_number", "Device Number", base.DEC)
pdj_announce_f.t04_counter = ProtoField.uint8("pdj_announce.counter", "Counter", base.DEC)

pdj_announce_f.t05_unk0 = ProtoField.uint8("pdj_announce.unk0", "Unknown 0", base.HEX)
pdj_announce_f.t05_unk1 = ProtoField.uint8("pdj_announce.unk1", "Unknown 1", base.HEX)
pdj_announce_f.t05_length = ProtoField.uint16("pdj_announce.length", "Length", base.DEC)
pdj_announce_f.t05_device_number = ProtoField.uint8("pdj_announce.device_number", "Device Number", base.DEC)
pdj_announce_f.t05_unk2 = ProtoField.uint8("pdj_announce.unk2", "Unknown 2", base.DEC)

pdj_announce_f.t06_unk0 = ProtoField.uint8("pdj_announce.unk0", "Unknown 0", base.HEX)
pdj_announce_f.t06_unk1 = ProtoField.uint8("pdj_announce.unk1", "Unknown 1", base.HEX)
pdj_announce_f.t06_length = ProtoField.uint16("pdj_announce.length", "Length", base.DEC)
pdj_announce_f.t06_device_number = ProtoField.uint8("pdj_announce.device_number", "Device Number", base.DEC)
pdj_announce_f.t06_unk2 = ProtoField.uint8("pdj_announce.unk0", "Unknown 2", base.HEX)
pdj_announce_f.t06_mac = ProtoField.ether("pdj_announce.mac", "MAC Address")
pdj_announce_f.t06_ip = ProtoField.ipv4("pdj_announce.ip", "IP Address")
pdj_announce_f.t06_devices_seen = ProtoField.uint8("pdj_announce.devices_seen", "Devices Seen", base.DEC)
pdj_announce_f.t06_unk4 = ProtoField.uint8("pdj_announce.unk4", "Unknown 4", base.HEX)
pdj_announce_f.t06_unk5 = ProtoField.uint8("pdj_announce.unk5", "Unknown 5", base.HEX)
pdj_announce_f.t06_unk6 = ProtoField.uint8("pdj_announce.unk6", "Unknown 6", base.HEX)
pdj_announce_f.t06_unk7 = ProtoField.uint8("pdj_announce.unk7", "Unknown 7", base.HEX)
pdj_announce_f.t06_unk8 = ProtoField.uint8("pdj_announce.unk8", "Unknown 8", base.HEX)

pdj_announce_f.t0a_unk0 = ProtoField.uint8("pdj_announce.unk0", "Unknown 0", base.HEX)
pdj_announce_f.t0a_unk1 = ProtoField.uint8("pdj_announce.unk1", "Unknown 1", base.HEX)
pdj_announce_f.t0a_length = ProtoField.uint16("pdj_announce.length", "Length", base.DEC)
pdj_announce_f.t0a_device_type = ProtoField.uint8("pdj_announce.device_type", "Device Type", base.HEX, pdj_announce_device_types)
pdj_announce_f.t0a_unk2 = ProtoField.uint8("pdj_announce.unk2", "Unknown 2", base.HEX)

-- AlphaTheta PRO DJ LINK Protocol (Announce): Dissector
function p_pdj_announce.dissector (buf, pkt, root)

  if buf:len() == 0 then return end
  end_position = buf:len()

  local preamble_ptr = buf(0,10)
  local packet_type_ptr = buf(0x0a,1)
  local packet_subtype_ptr = buf(0x0b,1)
  local name_ptr = buf(0x0c,20)

  local packet_type = packet_type_ptr:uint()
  local name = name_ptr:stringz()
  local device_number = nil

  local packet_type_description = pdj_announce_packet_types[packet_type]
  if packet_type_description == nil then
    packet_type_description = "Unknown"
  end

  local is_broadcast = is_dest_broadcast(pkt) and '*' or ''

  -- Create subtree
  local subtree = root:add(
    p_pdj_status,
    buf(0,end_position),
    "AlphaTheta PRO DJ LINK Protocol (Announce), Type: " .. packet_type_description .. ", From: " .. name
  )
  pkt.cols.protocol = 'PRODJ Announce'

  -- Preamble
  subtree:add(pdj_announce_f.preamble, preamble_ptr)

  -- Packet type
  subtree:add(pdj_announce_f.type, packet_type_ptr)
  subtree:add(pdj_announce_f.subtype, packet_subtype_ptr)

  -- Device name
  subtree:add(pdj_announce_f.name, name_ptr)

  -- Channel Claim Stage 1
  if packet_type == 0x00 then
    subtree:add(pdj_announce_f.t00_unk0, buf(0x20,1))
    subtree:add(pdj_announce_f.t00_unk1, buf(0x21,1))
    subtree:add(pdj_announce_f.t00_length, buf(0x22,2))
    subtree:add(pdj_announce_f.t00_counter, buf(0x24,1))
    subtree:add(pdj_announce_f.t00_unk2, buf(0x25,1))
    subtree:add(pdj_announce_f.t00_mac, buf(0x26,6))

  -- Channel Claim Stage 2
  elseif packet_type == 0x02 then
    subtree:add(pdj_announce_f.t02_unk0, buf(0x20,1))
    subtree:add(pdj_announce_f.t02_unk1, buf(0x21,1))
    subtree:add(pdj_announce_f.t02_length, buf(0x22,2))
    subtree:add(pdj_announce_f.t02_ip, buf(0x24,4))
    subtree:add(pdj_announce_f.t02_mac, buf(0x28,6))
    subtree:add(pdj_announce_f.t02_device_number, buf(0x2e,1))
    subtree:add(pdj_announce_f.t02_counter, buf(0x2f,1))
    subtree:add(pdj_announce_f.t02_unk2, buf(0x30,1))
    subtree:add(pdj_announce_f.t02_autoassign, buf(0x31,1))
    device_number = buf(0x2e,1):uint()

  -- Channel Claim Stage 3
  elseif packet_type == 0x04 then
    subtree:add(pdj_announce_f.t04_unk0, buf(0x20,1))
    subtree:add(pdj_announce_f.t04_unk1, buf(0x21,1))
    subtree:add(pdj_announce_f.t04_length, buf(0x22,2))
    subtree:add(pdj_announce_f.t04_device_number, buf(0x24,1))
    subtree:add(pdj_announce_f.t04_counter, buf(0x25,1))
    device_number = buf(0x24,1):uint()

  -- Mixer Assign Done
  elseif packet_type == 0x05 then
    subtree:add(pdj_announce_f.t05_unk0, buf(0x20,1))
    subtree:add(pdj_announce_f.t05_unk1, buf(0x21,1))
    subtree:add(pdj_announce_f.t05_length, buf(0x22,2))
    subtree:add(pdj_announce_f.t05_device_number, buf(0x24,1))
    subtree:add(pdj_announce_f.t05_unk2, buf(0x25,1))
    device_number = buf(0x24,1):uint()

  -- Device Keep-alive
  elseif packet_type == 0x06 then
    subtree:add(pdj_announce_f.t06_unk0, buf(0x20,1))
    subtree:add(pdj_announce_f.t06_unk1, buf(0x21,1))
    subtree:add(pdj_announce_f.t06_length, buf(0x22,2))
    subtree:add(pdj_announce_f.t06_device_number, buf(0x24,1))
    subtree:add(pdj_announce_f.t06_unk2, buf(0x25,1))
    subtree:add(pdj_announce_f.t06_mac, buf(0x26,6))
    subtree:add(pdj_announce_f.t06_ip, buf(0x2c,4))
    subtree:add(pdj_announce_f.t06_devices_seen, buf(0x30,1))
    subtree:add(pdj_announce_f.t06_unk4, buf(0x31,1))
    subtree:add(pdj_announce_f.t06_unk5, buf(0x32,1))
    subtree:add(pdj_announce_f.t06_unk6, buf(0x33,1))
    subtree:add(pdj_announce_f.t06_unk7, buf(0x34,1))
    subtree:add(pdj_announce_f.t06_unk8, buf(0x35,1))
    device_number = buf(0x24,1):uint()

  -- Initial Announce
  elseif packet_type == 0x0a then
    subtree:add(pdj_announce_f.t0a_unk0, buf(0x20,1))
    subtree:add(pdj_announce_f.t0a_unk1, buf(0x21,1))
    subtree:add(pdj_announce_f.t0a_length, buf(0x22,2))
    subtree:add(pdj_announce_f.t0a_device_type, buf(0x24,1))
    if end_position == 38 then
      subtree:add(pdj_announce_f.t0a_unk2, buf(0x25,1))
    end

  end

  if device_number ~= nil then
    pkt.cols.info = pkt.dst_port .. ' Len=' .. buf:len() .. ' [' .. packet_type_description .. '] From=' .. name .. ' (' .. device_number .. ') ' .. is_broadcast
  else
    pkt.cols.info = pkt.dst_port .. ' Len=' .. buf:len() .. ' [' .. packet_type_description .. '] From=' .. name .. ' ' .. is_broadcast
  end

end


-- Initialization routines
function p_pdj_announce.init()
end

function is_dest_broadcast(pkt)
  return tostring(pkt.dl_dst) == 'Broadcast'
end

-- Register a chained dissector for port 50000
local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(50000, p_pdj_announce)
