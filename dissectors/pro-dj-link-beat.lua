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
-- AlphaTheta PRO DJ LINK Protocol (Beat)
--------------------------------------------------
p_pdj_beat = Proto("pdj_beat", "AlphaTheta PRO DJ LINK Protocol (Beat)")

local pdj_beat_packet_types = {
  [0x02] = "Fader Start",
  [0x03] = "On-Air",
  [0x0b] = "Absolute Position",
  [0x26] = "Master Handoff Req",
  [0x27] = "Master Handoff Res",
  [0x28] = "Beat",
  [0x2a] = "Sync Control"
}

local pdj_beat_f = p_pdj_beat.fields
pdj_beat_f.preamble = ProtoField.bytes("pdj_beat.preamble", "Preamble")
pdj_beat_f.type = ProtoField.uint8("pdj_beat.type", "Packet Type", base.HEX, pdj_beat_packet_types)
pdj_beat_f.device = ProtoField.uint8("pdj_beat.device", "Device Number", base.DEC)
pdj_beat_f.name = ProtoField.stringz("pdj_beat.name", "Device Name", base.ASCII)
pdj_beat_f.unk0 = ProtoField.uint8("pdj_beat.unk0", "Unknown 0", base.HEX)
pdj_beat_f.unk1 = ProtoField.uint8("pdj_beat.unk1", "Unknown 1", base.HEX)
pdj_beat_f.length = ProtoField.uint16("pdj_beat.length", "Length", base.DEC)

pdj_beat_f.t03_fader1 = ProtoField.uint8("pdj_beat.fader1", "Fader 1", base.DEC)
pdj_beat_f.t03_fader2 = ProtoField.uint8("pdj_beat.fader2", "Fader 2", base.DEC)
pdj_beat_f.t03_fader3 = ProtoField.uint8("pdj_beat.fader3", "Fader 3", base.DEC)
pdj_beat_f.t03_fader4 = ProtoField.uint8("pdj_beat.fader4", "Fader 4", base.DEC)
pdj_beat_f.t03_fader5 = ProtoField.uint8("pdj_beat.fader5", "Fader 5", base.DEC)
pdj_beat_f.t03_fader6 = ProtoField.uint8("pdj_beat.fader6", "Fader 6", base.DEC)

pdj_beat_f.t0b_track_len = ProtoField.uint32("pdj_beat.track_len", "Track Length (sec)", base.DEC)
pdj_beat_f.t0b_playhead = ProtoField.uint32("pdj_beat.playhead", "Playhead (ms)", base.DEC)
pdj_beat_f.t0b_pitch = ProtoField.int32("pdj_beat.pitch", "Pitch", base.DEC)
pdj_beat_f.t0b_bpm = ProtoField.uint32("pdj_beat.bpm", "BPM", base.DEC)

-- AlphaTheta PRO DJ LINK Protocol (Beat): Dissector
function p_pdj_beat.dissector (buf, pkt, root)

  if buf:len() == 0 then return end
  buf_len = buf:len()

  local preamble_ptr = buf(0,10)
  local device_number_ptr = buf(0x21,1)
  local packet_type_ptr = buf(0x0a,1)
  local name_ptr = buf(0x0b,20)
  local length_ptr = buf(0x22,2)

  local packet_type = packet_type_ptr:uint()
  local name = name_ptr:stringz()
  local device_number = device_number_ptr:uint()
  local length = length_ptr:uint()

  local packet_type_description = pdj_beat_packet_types[packet_type]
  if packet_type_description == nil then
    packet_type_description = "Unknown"
  end

  local is_broadcast = is_dest_broadcast(pkt) and '*' or ''

  -- Create subtree
  local subtree = root:add(
    p_pdj_beat,
    buf(0,buf_len),
    "AlphaTheta PRO DJ LINK Protocol (Beat), Type: " .. packet_type_description .. ", From: " .. name
  )
  pkt.cols.protocol = 'PRODJ Beat'
  pkt.cols.info = pkt.dst_port .. ' Len=' .. buf:len() .. ' [' .. packet_type_description .. '] From=' .. name .. ' (' .. device_number .. ') ' .. is_broadcast

  -- Preamble
  subtree:add(pdj_beat_f.preamble, preamble_ptr)

  -- Packet type
  subtree:add(pdj_beat_f.type, packet_type_ptr)

  -- Device name
  subtree:add(pdj_beat_f.name, name_ptr)

  -- Device number
  subtree:add(pdj_beat_f.device, device_number_ptr)

  -- Length
  subtree:add(pdj_beat_f.length, length_ptr)

  -- Unknown
  subtree:add(pdj_beat_f.unk0, buf(0x1f,1))
  subtree:add(pdj_beat_f.unk1, buf(0x20,1))
  
  -- On-Air
  if packet_type == 0x03 then
    subtree:add(pdj_beat_f.t03_fader1, buf(0x24,1))
    subtree:add(pdj_beat_f.t03_fader2, buf(0x25,1))
    subtree:add(pdj_beat_f.t03_fader3, buf(0x26,1))
    subtree:add(pdj_beat_f.t03_fader4, buf(0x27,1))
    if length == 17 then
        subtree:add(pdj_beat_f.t03_fader5, buf(0x2d,1))
        subtree:add(pdj_beat_f.t03_fader6, buf(0x2e,1))
    end

  -- Absolute Position
  elseif packet_type == 0x0b then
    local pitch_ptr = buf(0x2c,4)
    local pitch = pitch_ptr:int()
    local pitch_display = pitch / 100
    
    local bpm_ptr = buf(0x38,4)
    local bpm = bpm_ptr:uint()
    local bpm_display = "Unknown"
    if bpm ~= 0xFFFFFFFF then
      bpm_display = bpm / 10
    end

    subtree:add(pdj_beat_f.t0b_track_len, buf(0x24,4))
    subtree:add(pdj_beat_f.t0b_playhead, buf(0x28,4))
    subtree:add(pdj_beat_f.t0b_pitch, pitch_ptr, pitch, nil, "(" .. pitch_display .. " %)")
    subtree:add(pdj_beat_f.t0b_bpm, bpm_ptr, bpm, nil, "(" .. bpm_display .. " bpm)")

  end
  
end


-- Initialization routines
function p_pdj_beat.init()
end

function is_dest_broadcast(pkt)
  return tostring(pkt.dl_dst) == 'Broadcast'
end


-- Register a chained dissector for port 50001
local udp_dissector_table = DissectorTable.get("udp.port")
udp_dissector_table:add(50001, p_pdj_beat)
