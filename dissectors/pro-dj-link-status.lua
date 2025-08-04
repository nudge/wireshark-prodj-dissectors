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

local pdj_status_activity_values = {
   [0x00] = "Idle",
   [0x01] = "Playing, searching, or loading a track"
}

local pdj_status_slot_values = {
   [0x00] = "no track",
   [0x01] = "CD drive",
   [0x02] = "SD slot",
   [0x03] = "USB slot",
   [0x04] = "rekordbox collection"
}

local pdj_status_track_types = {
   [0x00] = "no track",
   [0x01] = "rekordbox",
   [0x02] = "unanalyzed",
   [0x05] = "audio CD"
}

local pdj_status_slot_states = {
   [0x00] = "Loaded",
   [0x02] = "Stopping",
   [0x03] = "Unloading",
   [0x04] = "Empty"
}

local pdj_status_play1_states = {
   [0x00] = "No track loaded",
   [0x02] = "Track loading",
   [0x03] = "Normal Play",
   [0x04] = "Loop Play",
   [0x05] = "Paused away from cue point",
   [0x06] = "Paused at cue point",
   [0x07] = "Cue Play",
   [0x08] = "Cue Scratch",
   [0x09] = "Searching",
   [0x0e] = "Audio CD spun down",
   [0x11] = "Stopped at end of track"
}

local pdj_status_play3_states = {
   [0x00] = "No track loaded",
   [0x01] = "Paused or playing in reverse mode",
   [0x09] = "Playing forward, jog mode is Vinyl",
   [0x0d] = "Playing forward, jog mode is CDJ"
}

local pdj_status_master_validity_states = {
   [0x0000] = "No: non-rekordbox track loaded",
   [0x8000] = "Yes: rekordbox track loaded",
   [0x7fff] = "No: no track loaded"
}

local pdj_status_master_meaningful_states = {
   [0x00] = "No: not tempo master",
   [0x01] = "Yes: playing rekordbox track as tempo master",
   [0x02] = "No: playing non-rekordbox track"
}

local pdj_status_nexus = {
   [0x05] = "pre-nexus",
   [0x0f] = "nexus",
   [0x1f] = "XDJ-XZ, -AZ, CDJ-3000"
}

local pdj_status_waveform_colors = {
   [0x01] = "Blue",
   [0x03] = "RGB",
   [0x04] = "3-Band"
}

local pdj_status_waveform_positions = {
   [0x01] = "Center",
   [0x02] = "Left"
}

local pdj_status_buffer = {
   [0x00] = "Buffering",
   [0x01] = "Entire track buffered"
}

local pdj_status_off_on = {
   [0x00] = "Off",
   [0x01] = "On"
}

local pdj_status_key = {
   [0x000000] = "Am",
   [0x0100ff] = "B♭m",
   [0x020000] = "Bm",
   [0x030000] = "Cm",
   [0x040001] = "C♯m",
   [0x050000] = "Dm",
   [0x0600ff] = "E♭m",
   [0x070000] = "Em",
   [0x080000] = "Fm",
   [0x090001] = "F♯m",
   [0x0a0000] = "Gm",
   [0x0b00ff] = "A♭m",
   [0x000100] = "C",
   [0x0101ff] = "D♭",
   [0x020100] = "D",
   [0x0301ff] = "E♭",
   [0x040100] = "E",
   [0x050100] = "F",
   [0x060101] = "F♯",
   [0x070100] = "G",
   [0x0801ff] = "A♭",
   [0x090100] = "A",
   [0x0a01ff] = "B♭",
   [0x0b0100] = "B"
}

local pdj_status_f = p_pdj_status.fields
pdj_status_f.preamble = ProtoField.bytes("pdj_status.preamble", "Preamble")
pdj_status_f.type = ProtoField.uint8("pdj_status.type", "Packet Type", base.HEX, pdj_status_packet_types)
pdj_status_f.device = ProtoField.uint8("pdj_status.device", "Device Number", base.DEC)
pdj_status_f.name = ProtoField.stringz("pdj_status.name", "Device Name", base.ASCII)

-- CDJs send these
pdj_status_f.t0a_length = ProtoField.uint16("pdj_status.length", "Length", base.DEC)
pdj_status_f.t0a_device = ProtoField.uint8("pdj_status.device2", "Device Number 2", base.DEC)
pdj_status_f.t0a_activity = ProtoField.uint8("pdj_status.a", "Activity", base.HEX, pdj_status_activity_values)
pdj_status_f.t0a_Dr = ProtoField.uint8("pdj_status.Dr", "Track Source Device", base.DEC)
pdj_status_f.t0a_Sr = ProtoField.uint8("pdj_status.Sr", "Track Source Slot", base.HEX, pdj_status_slot_values)
pdj_status_f.t0a_Tr = ProtoField.uint8("pdj_status.Tr", "Track Type", base.HEX, pdj_status_track_types)
pdj_status_f.t0a_rekordbox = ProtoField.uint32("pdj_status.rekordbox", "rekordbox id", base.HEX)
pdj_status_f.t0a_track = ProtoField.uint16("pdj_status.track", "Track index", base.DEC)
pdj_status_f.t0a_Ul = ProtoField.uint8("pdj_status.Ul", "USB Slot", base.HEX, pdj_status_slot_states)
pdj_status_f.t0a_Sl = ProtoField.uint8("pdj_status.Sl", "SD Slot", base.HEX, pdj_status_slot_states)
pdj_status_f.t0a_P1 = ProtoField.uint8("pdj_status.P1", "Play 1", base.HEX, pdj_status_play1_states)
pdj_status_f.t0a_firmware = ProtoField.stringz("pdj_status.firmware", "Firmware", base.ASCII)
pdj_status_f.t0a_sync_n = ProtoField.uint16("pdj_status.sync_n", "Sync counter", base.DEC)
pdj_status_f.t0a_pitch1 = ProtoField.uint32("pdj_status.pitch1", "Pitch 1", base.HEX)
pdj_status_f.t0a_pitch2 = ProtoField.uint32("pdj_status.pitch2", "Pitch 2", base.HEX)
pdj_status_f.t0a_pitch3 = ProtoField.uint32("pdj_status.pitch3", "Pitch 3", base.HEX)
pdj_status_f.t0a_pitch4 = ProtoField.uint32("pdj_status.pitch4", "Pitch 4", base.HEX)
pdj_status_f.t0a_bpm = ProtoField.uint16("pdj_status.bpm", "Track BPM", base.HEX)
pdj_status_f.t0a_mv = ProtoField.uint16("pdj_status.mv", "Master Valid", base.HEX, pdj_status_master_validity_states)
pdj_status_f.t0a_P3 = ProtoField.uint8("pdj_status.P3", "Play 3", base.HEX, pdj_status_play3_states)
pdj_status_f.t0a_mm = ProtoField.uint8("pdj_status.mm", "Master Meaningful", base.HEX, pdj_status_master_meaningful_states)
pdj_status_f.t0a_mh = ProtoField.uint8("pdj_status.mh", "Master Handoff", base.HEX)
pdj_status_f.t0a_beat = ProtoField.int32("pdj_status.beat", "Beat", base.DEC)
pdj_status_f.t0a_bb = ProtoField.uint8("pdj_status.bb", "Beat in Bar", base.DEC)
pdj_status_f.t0a_cue = ProtoField.uint16("pdj_status.cue", "Cue countdown", base.HEX)
pdj_status_f.t0a_packet = ProtoField.uint32("pdj_status.packet", "Packet #", base.DEC)
pdj_status_f.t0a_nx = ProtoField.uint8("pdj_status.nx", "Nexus?", base.HEX, pdj_status_nexus)

-- Available from newer players only
pdj_status_f.t0a_wc = ProtoField.uint8("pdj_status.wc", "Waveform Color", base.HEX, pdj_status_waveform_colors)
pdj_status_f.t0a_wp = ProtoField.uint8("pdj_status.wp", "Waveform Position", base.HEX, pdj_status_waveform_positions)
pdj_status_f.t0a_buf_f = ProtoField.uint8("pdj_status.buf_f", "Buffered Forward", base.DEC)
pdj_status_f.t0a_buf_b = ProtoField.uint8("pdj_status.buf_b", "Buffered Back", base.DEC)
pdj_status_f.t0a_buf_s = ProtoField.uint8("pdj_status.buf_s", "Buffer Status", base.HEX, pdj_status_buffer)
pdj_status_f.t0a_mt = ProtoField.uint8("pdj_status.mt", "Master Tempo", base.HEX, pdj_status_off_on)
pdj_status_f.t0a_key = ProtoField.uint24("pdj_status.key", "Key", base.HEX, pdj_status_key)
pdj_status_f.t0a_key_shift = ProtoField.int64("pdj_status.key_shift", "Key Shift (cents)", base.DEC)
pdj_status_f.t0a_loop_s  = ProtoField.uint32("pdj_status.loop_s", "Loop Start", base.HEX)
pdj_status_f.t0a_loop_e  = ProtoField.uint32("pdj_status.loop_e", "Loop End", base.HEX)
pdj_status_f.t0a_loop_b  = ProtoField.uint16("pdj_status.loop_b", "Loop Beats", base.DEC)


-- Mixers send these
pdj_status_f.t29_unk0 = ProtoField.uint8("pdj_status.unk0", "Unknown 0", base.HEX)
pdj_status_f.t29_unk1 = ProtoField.uint8("pdj_status.unk1", "Unknown 1", base.HEX)
pdj_status_f.t29_length = ProtoField.uint16("pdj_status.length", "Length", base.DEC)
pdj_status_f.t29_device = ProtoField.uint8("pdj_status.device2", "Device Number 2", base.DEC)
pdj_status_f.t29_unk2 = ProtoField.uint16("pdj_status.unk2", "Unknown 2", base.HEX)
pdj_status_f.t29_pitch = ProtoField.uint32("pdj_status.pitch", "Pitch", base.HEX)
pdj_status_f.t29_unk3 = ProtoField.uint16("pdj_status.unk3", "Unknown 3", base.HEX)
pdj_status_f.t29_bpm = ProtoField.uint16("pdj_status.bpm", "BPM", base.HEX)
pdj_status_f.t29_unk4 = ProtoField.uint16("pdj_status.unk4", "Unknown 4", base.HEX)
pdj_status_f.t29_unk5 = ProtoField.uint16("pdj_status.unk5", "Unknown 5", base.HEX)
pdj_status_f.t29_unk6 = ProtoField.uint16("pdj_status.unk6", "Unknown 6", base.HEX)
pdj_status_f.t29_beat = ProtoField.uint8("pdj_status.beat", "Beat in Bar", base.DEC)
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

  -- CDJ Status
  if packet_type == 0x0a then
    subtree_flags = subtree:add(pdj_status_f.t0a_length, buf(0x22,2))
    subtree:add(pdj_status_f.t0a_device, buf(0x24,1))
    subtree:add(pdj_status_f.t0a_activity, buf(0x27,1))
    subtree:add(pdj_status_f.t0a_Dr, buf(0x28,1))
    subtree:add(pdj_status_f.t0a_Sr, buf(0x29,1))
    subtree:add(pdj_status_f.t0a_Tr, buf(0x2a,1))
    subtree:add(pdj_status_f.t0a_rekordbox, buf(0x2c,4))
    subtree:add(pdj_status_f.t0a_track, buf(0x32,2))
    subtree:add(pdj_status_f.t0a_Ul, buf(0x6f,1))
    subtree:add(pdj_status_f.t0a_Sl, buf(0x73,1))
    subtree:add(pdj_status_f.t0a_P1, buf(0x7b,1))
    subtree:add(pdj_status_f.t0a_P3, buf(0x9d,1))
    subtree:add(pdj_status_f.t0a_firmware, buf(0x7c,4))
    subtree:add(pdj_status_f.t0a_sync_n, buf(0x84,4))

    local flags_ptr = buf(0x89,1)
    subtree_flags = subtree:add(pdj_status_f.flags, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_unk0, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_play, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_master, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_sync, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_onair, flags_ptr)
    subtree_flags:add(pdj_status_f.flags_bpm, flags_ptr)

    local pitch1_ptr = buf(0x8c,4)
    local pitch1 = pitch1_ptr:uint()
    local pitch1_display = ((pitch1 - 0x100000) / 0x100000) * 100
    subtree:add(pdj_status_f.t0a_pitch1, pitch1_ptr, pitch1, nil, "(" .. pitch1_display .. "%)")

    local pitch2_ptr = buf(0x98,4)
    local pitch2 = pitch2_ptr:uint()
    local pitch2_display = ((pitch2 - 0x100000) / 0x100000) * 100
    subtree:add(pdj_status_f.t0a_pitch2, pitch2_ptr, pitch2, nil, "(" .. pitch2_display .. "%)")

    local pitch3_ptr = buf(0xc0,4)
    local pitch3 = pitch3_ptr:uint()
    local pitch3_display = ((pitch3 - 0x100000) / 0x100000) * 100
    subtree:add(pdj_status_f.t0a_pitch3, pitch3_ptr, pitch3, nil, "(" .. pitch3_display .. "%)")

    local pitch4_ptr = buf(0xc4,4)
    local pitch4 = pitch4_ptr:uint()
    local pitch4_display = ((pitch4 - 0x100000) / 0x100000) * 100
    subtree:add(pdj_status_f.t0a_pitch4, pitch4_ptr, pitch4, nil, "(" .. pitch4_display .. "%)")

    local bpm_ptr = buf(0x92,2)
    local bpm = bpm_ptr:uint() 
    local bpm_display = "Unknown"
    if bpm ~= 0xFFFF then
      bpm_display = bpm / 10
    end
    subtree:add(pdj_status_f.t0a_bpm, bpm_ptr, bpm, nil, "(" .. bpm_display .. " bpm)")

    subtree:add(pdj_status_f.t0a_mv, buf(0x90,2))
    subtree:add(pdj_status_f.t0a_mm, buf(0x9e,1))
    subtree:add(pdj_status_f.t0a_mh, buf(0x9f,1))
    subtree:add(pdj_status_f.t0a_beat, buf(0xa0,4))
    subtree:add(pdj_status_f.t0a_bb, buf(0xa6,1))

    local cue_ptr = buf(0xa4,2)
    local cue = cue_ptr:uint();
    local cue_display = "--.-"
    if cue >= 1 and cue <= 256 then
       local cue_bars = (cue - 1) // 4
       local cue_beats = ((cue - 1) % 4) + 1
       cue_display = string.format("%02d.%d", cue_bars, cue_beats);
    elseif cue == 0 then
       cue_display = "00.0"
    end
    subtree:add(pdj_status_f.t0a_cue, cue_ptr, cue, nil, "(" .. cue_display .. " bars)")

    subtree:add(pdj_status_f.t0a_packet, buf(0xc8,4))
    subtree:add(pdj_status_f.t0a_nx, buf(0xcc,1))

    if buf_len > 0xfd then
       subtree:add(pdj_status_f.t0a_wc, buf(0xfa,1))
       subtree:add(pdj_status_f.t0a_wp, buf(0xfd,1))
    end

    if buf_len > 0x11f then
       subtree:add(pdj_status_f.t0a_buf_f, buf(0x11d,1))
       subtree:add(pdj_status_f.t0a_buf_b, buf(0x11e,1))
       subtree:add(pdj_status_f.t0a_buf_s, buf(0x11f,1))
    end

    if buf_len > 0x1cf then
       subtree:add(pdj_status_f.t0a_mt, buf(0x158,1))
       subtree:add(pdj_status_f.t0a_key, buf(0x15c,3))
       local key_shift_ptr = buf(0x164,8);
       local key_shift = key_shift_ptr:int64()
       local key_shift_display = key_shift / 100
       subtree:add(pdj_status_f.t0a_key_shift, key_shift_ptr, key_shift, nil, "(" .. key_shift_display .. " semitones)")

       local loop_s_ptr = buf(0x1b6,4)
       local loop_s = loop_s_ptr:uint()
       local loop_s_display = loop_s * 65536 / 1000
       subtree:add(pdj_status_f.t0a_loop_s, loop_s_ptr, loop_s, nil, "(" .. loop_s_display .. " ms)")

       local loop_e_ptr = buf(0x1be,4)
       local loop_e = loop_e_ptr:uint()
       local loop_e_display = loop_e * 65536 / 1000
       subtree:add(pdj_status_f.t0a_loop_e, loop_e_ptr, loop_e, nil, "(" .. loop_e_display .. " ms)")

       subtree:add(pdj_status_f.t0a_loop_b, buf(0x1c8,2))
    end


  -- Mixer status
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

    local pitch_ptr = buf(0x28,4)
    local pitch = pitch_ptr:uint()
    local pitch_display = ((pitch - 0x100000) / 0x100000) * 100
    subtree_flags = subtree:add(pdj_status_f.t29_pitch, pitch_ptr, pitch, nil, "(" .. pitch_display .. "%)")
    subtree_flags = subtree:add(pdj_status_f.t29_unk3, buf(0x2c,2))

    local bpm_ptr = buf(0x2e,2)
    local bpm = bpm_ptr:uint()
    local bpm_display = bpm / 100
    subtree_flags = subtree:add(pdj_status_f.t29_bpm, bpm_ptr, bpm, nil, "(" .. bpm_display .. " bpm)")
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
