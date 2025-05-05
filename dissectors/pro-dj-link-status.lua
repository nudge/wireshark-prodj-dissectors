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
-- AlphaTheta PRO DJ LINK Protocol (Status)
--------------------------------------------------
p_pdj_status = Proto("pdj_status", "AlphaTheta PRO DJ LINK Protocol (Status)")

local pdj_status_packet_types = {
  [0x05] = "Media Query",
  [0x06] = "Media Response",
  [0x0a] = "CDJ Status",
  [0x19] = "Load Track Command",
  [0x1a] = "Load Track Ack",
  [0x29] = "Mixer Status",
  [0x34] = "Load Settings Command"
}

local pdj_status_f = p_pdj_status.fields
pdj_status_f.preamble = ProtoField.bytes("pdj_status.preamble", "Preamble")
pdj_status_f.type = ProtoField.uint8("pdj_status.type", "Packet Type", base.HEX, pdj_status_packet_types)
pdj_status_f.device = ProtoField.uint8("pdj_status.device", "Device Number", base.DEC)
pdj_status_f.name = ProtoField.stringz("pdj_status.name", "Device Name", base.ASCII)

pdj_status_f.t29_unk0 = ProtoField.uint8("pdj_status.unk0", "Unknown 0", base.HEX)
pdj_status_f.t29_unk1 = ProtoField.uint8("pdj_status.unk1", "Unknown 1", base.HEX)
pdj_status_f.t29_length = ProtoField.uint16("pdj_status.length", "Length", base.DEC)
pdj_status_f.t29_device = ProtoField.uint8("pdj_status.device2", "Device Number 2", base.DEC)
pdj_status_f.t29_unk2 = ProtoField.uint16("pdj_status.unk2", "Unknown 2", base.HEX)
pdj_status_f.t29_pitch = ProtoField.uint32("pdj_status.pitch", "Pitch", base.HEX)
pdj_status_f.t29_unk3 = ProtoField.uint16("pdj_status.unk2", "Unknown 3", base.HEX)
pdj_status_f.t29_bpm = ProtoField.uint16("pdj_status.unk2", "BPM", base.HEX)
pdj_status_f.t29_unk4 = ProtoField.uint16("pdj_status.unk2", "Unknown 4", base.HEX)
pdj_status_f.t29_unk5 = ProtoField.uint16("pdj_status.unk2", "Unknown 5", base.HEX)
pdj_status_f.t29_unk6 = ProtoField.uint16("pdj_status.unk2", "Unknown 6", base.HEX)
pdj_status_f.t29_beat = ProtoField.uint8("pdj_status.mh", "Beat", base.DEC)
pdj_status_f.t29_mh = ProtoField.uint8("pdj_status.mh", "Master Handoff", base.HEX)

pdj_status_f.flags = ProtoField.uint8("pdj_status.flags", "Flags", base.HEX)
pdj_status_f.flags_unk0 = ProtoField.uint8("pdj_status.flags.unk0", "Unknown 0", base.DEC, nil, 0x80)
pdj_status_f.flags_play = ProtoField.uint8("pdj_status.flags.play", "Play", base.DEC, nil, 0x40)
pdj_status_f.flags_master = ProtoField.uint8("pdj_status.flags.master", "Master", base.DEC, nil, 0x20)
pdj_status_f.flags_sync = ProtoField.uint8("pdj_status.flags.sync", "Sync", base.DEC, nil, 0x10)
pdj_status_f.flags_onair = ProtoField.uint8("pdj_status.flags.onair", "On-Air", base.DEC, nil, 0x08)
pdj_status_f.flags_bpm = ProtoField.uint8("pdj_status.flags.bpm", "BPM", base.DEC, nil, 0x02)

-- AlphaTheta PRO DJ LINK Protocol (Status): Dissector
function p_pdj_status.dissector (buf, pkt, root)

  if buf:len() == 0 then return end
  buf_len = buf:len()

  local preamble_ptr = buf(0,10)
  local device_number_ptr = buf(0x21,1)
  local packet_type_ptr = buf(0x0a,1)
  local name_ptr = buf(0x0b,20)

  local packet_type = packet_type_ptr:uint()
  local name = name_ptr:stringz()
  local device_number = device_number_ptr:uint()

  local packet_type_description = pdj_status_packet_types[packet_type]
  if packet_type_description == nil then
    packet_type_description = "Unknown"
  end

  local is_broadcast = is_dest_broadcast(pkt) and '*' or ''

  -- Create subtree
  local subtree = root:add(
    p_pdj_status,
    buf(0,buf_len),
    "AlphaTheta PRO DJ LINK Protocol (Status), Type: " .. packet_type_description .. ", From: " .. name
  )
  pkt.cols.protocol = 'PRODJ Status'
  pkt.cols.info = pkt.dst_port .. ' Len=' .. buf:len() .. ' [' .. packet_type_description .. '] From=' .. name .. ' (' .. device_number .. ') ' .. is_broadcast

  -- Preamble
  subtree:add(pdj_status_f.preamble, preamble_ptr)

  -- Packet type
  subtree:add(pdj_status_f.type, packet_type_ptr)

  -- Device name
  subtree:add(pdj_status_f.name, name_ptr)

  -- Device number
  subtree:add(pdj_status_f.device, device_number_ptr)

  -- Mixer Status
  if packet_type == 0x0a then
    local flags_ptr = buf(0x89,1)
    subtree_flags = subtree:add(pdj_status_f.flags, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_unk0, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_play, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_master, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_sync, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_onair, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_bpm, flags_ptr)

  elseif packet_type == 0x29 then
    subtree_flags = subtree:add(pdj_status_f.t29_unk0, buf(0x1f,1))
    subtree_flags = subtree:add(pdj_status_f.t29_unk1, buf(0x20,1))
    subtree_flags = subtree:add(pdj_status_f.t29_length, buf(0x22,2))
    subtree_flags = subtree:add(pdj_status_f.t29_device, buf(0x24,1))
    subtree_flags = subtree:add(pdj_status_f.t29_unk2, buf(0x25,2))
    
    local flags_ptr = buf(0x27,1)
    subtree_flags = subtree:add(pdj_status_f.flags, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_unk0, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_play, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_master, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_sync, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_onair, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_bpm, flags_ptr)

    subtree_flags = subtree:add(pdj_status_f.t29_pitch, buf(0x28,4))
    subtree_flags = subtree:add(pdj_status_f.t29_unk3, buf(0x2c,2))
    subtree_flags = subtree:add(pdj_status_f.t29_bpm, buf(0x2e,2))
    subtree_flags = subtree:add(pdj_status_f.t29_unk4, buf(0x30,2))
    subtree_flags = subtree:add(pdj_status_f.t29_unk5, buf(0x32,2))
    subtree_flags = subtree:add(pdj_status_f.t29_unk6, buf(0x34,2))
    subtree_flags = subtree:add(pdj_status_f.t29_mh, buf(0x36,1))
    subtree_flags = subtree:add(pdj_status_f.t29_beat, buf(0x37,1))

  end

end


-- Initialization routines
function p_pdj_status.init()
end

function is_dest_broadcast(pkt)
  return tostring(pkt.dl_dst) == 'Broadcast'
end


-- Register a chained dissector for port 50002
local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(50002, p_pdj_status)
