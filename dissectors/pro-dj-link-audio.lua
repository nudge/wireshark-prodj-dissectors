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
-- AlphaTheta PRO DJ LINK Protocol (Audio)
--------------------------------------------------
p_pdj_audio = Proto("pdj_audio", "AlphaTheta PRO DJ LINK Protocol (Audio)")

pdj_audio_packet_types = {
  [0x1e] = "Data",
  [0x1f] = "Handover",
  [0x20] = "Timing"
}

pdj_audio_f = p_pdj_audio.fields
pdj_audio_f.preamble = ProtoField.bytes("pdj_audio.preamble", "Preamble")
pdj_audio_f.type = ProtoField.uint8("pdj_audio.type", "Packet Type", base.HEX, pdj_audio_packet_types)
pdj_audio_f.device = ProtoField.uint8("pdj_audio.device", "Device Number", base.DEC)
pdj_audio_f.name = ProtoField.stringz("pdj_audio.name", "Device Name", base.ASCII)

pdj_audio_f.timing_counter = ProtoField.uint32("pdj_audio.timing_counter", "Counter")
pdj_audio_f.timing_counter_req = ProtoField.framenum("pdj_audio.timing_counter_req", "Request Packet", base.NONE, frametype.REQUEST)
pdj_audio_f.timing_counter_res = ProtoField.framenum("pdj_audio.timing_counter_res", "Response Packet", base.NONE, frametype.RESPONSE)
pdj_audio_f.timing_cue_enabled = ProtoField.uint8("pdj_audio.timing_cue_enabled", "Link Cue Enabled")
pdj_audio_f.timing_elected_player = ProtoField.uint8("pdj_audio.timing_elected_player", "Elected Player Number")

pdj_audio_f.audio_length = ProtoField.uint16("pdj_audio.audio_length", "Audio Length")
pdj_audio_f.audio_payload = ProtoField.bytes("pdj_audio.audio_payload", "Audio Payload")

local pdj_audio_convo = {}

-- AlphaTheta PRO DJ LINK Protocol (Audio): Dissector
function p_pdj_audio.dissector (buf, pkt, root)

  if buf:len() == 0 then return end
  end_position = buf:len()

  local preamble_ptr = buf(0,10)
  local device_number_ptr = buf(0x21,1)
  local packet_type_ptr = buf(0x0a,1)
  local name_ptr = buf(0x0b,20)

  local packet_type = packet_type_ptr:uint()
  local name = name_ptr:stringz()
  local device_number = device_number_ptr:uint()

  local packet_type_description = pdj_audio_packet_types[packet_type]
  if packet_type_description == nil then
    packet_type_description = "Unknown"
  end

  local is_broadcast = is_dest_broadcast(pkt) and '*' or ''

  -- Create subtree
  local subtree = root:add(
    p_pdj_audio,
    buf(0,end_position),
    "AlphaTheta PRO DJ LINK Protocol (Audio), Type: " .. packet_type_description .. ", From: " .. name
  )
  pkt.cols.protocol = 'PRODJ Audio'
  pkt.cols.info = pkt.dst_port .. ' Len=' .. buf:len() .. ' [' .. packet_type_description .. '] From=' .. name .. ' (' .. device_number .. ') ' .. is_broadcast

  -- Preamble
  subtree:add(pdj_audio_f.preamble, preamble_ptr)

  -- Packet type
  subtree:add(pdj_audio_f.type, packet_type_ptr)

  -- Device name
  subtree:add(pdj_audio_f.name, name_ptr)

  -- Device number
  subtree:add(pdj_audio_f.device, device_number_ptr)

  -- Audio Data
  if packet_type == 0x1e then
    audio_len = end_position - 0x2c
    subtree:add(pdj_audio_f.audio_length, buf(0x22,2))

    convo_id = buf(0x28,4):uint()
    subtree:add(pdj_audio_f.timing_counter, convo_id)
    if not pdj_audio_convo[convo_id] then
      pdj_audio_convo[convo_id] = {}
    end
    pdj_audio_convo[convo_id].response = pkt.number
    if pdj_audio_convo[convo_id].request then
      subtree:add(pdj_audio_f.timing_counter_req, pdj_audio_convo[convo_id].request)
    end

    subtree:add(pdj_audio_f.audio_payload, buf(0x2c,audio_len))

  -- Audio Handover
  elseif packet_type == 0x1f then

  -- Audio Timing
  elseif packet_type == 0x20 then
    convo_id = buf(0x24,4):uint()
    subtree:add(pdj_audio_f.timing_counter, convo_id)
    if not pdj_audio_convo[convo_id] then
      pdj_audio_convo[convo_id] = {}
    end
    pdj_audio_convo[convo_id].request = pkt.number
    if pdj_audio_convo[convo_id].response then
      subtree:add(pdj_audio_f.timing_counter_res, pdj_audio_convo[convo_id].response)
    end

    subtree:add(pdj_audio_f.timing_cue_enabled, buf(0x28,1))
    subtree:add(pdj_audio_f.timing_elected_player, buf(0x29,1))

  end
 
end


-- Initialization routines
function p_pdj_audio.init()
end

function is_dest_broadcast(pkt)
  return tostring(pkt.dl_dst) == 'Broadcast'
end

-- Register a chained dissector for port 50004
local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(50004, p_pdj_audio)
