-- AlphaTheta PRO DJ LINK Wireshark Dissectors
--
-- by Shugo Kawamura
-- Copyright 2026
--
-- https://github.com/nudge/wireshark-prodj-dissectors
--
--
-- Install under:
-- (Windows)      %APPDATA%\Wireshark\plugins\
-- (Linux, Mac)   $HOME/.wireshark/plugins
--                (or $HOME/.config/wireshark/plugins)
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
-- Players advertise a dynamic TCP port via :12523; register a heuristic on
-- magic 0x872349AE (and the session greeting) so captures dissect without
-- binding every ephemeral dbserver port by hand.
--

--------------------------------------------------
-- AlphaTheta PRO DJ LINK Protocol (DB Server)
--------------------------------------------------
p_pdj_dbserver = Proto("pdj_dbserver", "AlphaTheta PRO DJ LINK Protocol (DB Server)")

local pdj_dbserver_opcodes = {
  [0x0000] = "Setup",
  [0x0001] = "Cancel",
  [0x0100] = "Teardown",
  [0x1000] = "Root Menu",
  [0x1001] = "Genre Menu (GP)",
  [0x1002] = "Artist Menu",
  [0x1003] = "Album Menu",
  [0x1004] = "Track Menu",
  [0x1006] = "BPM Menu",
  [0x100b] = "Genre Menu",
  [0x1012] = "Key Menu",
  [0x1014] = "History or Key",
  [0x1105] = "Playlist Menu",
  [0x2002] = "Metadata",
  [0x2003] = "Artwork",
  [0x2004] = "Waveform Preview",
  [0x2005] = "Unknown 0x2005",
  [0x2102] = "Track Path",
  [0x2104] = "Cue List",
  [0x2204] = "Beat Grid",
  [0x2504] = "Load Track Info",
  [0x2705] = "Cue Edit",
  [0x2904] = "Waveform Detail",
  [0x2b04] = "Cue List Ext",
  [0x2c04] = "Analysis Tag",
  [0x2d04] = "Analysis Tag Ext",
  [0x3000] = "Render",
  [0x3001] = "Unknown 0x3001",
  [0x3002] = "Tag List",
  [0x3006] = "Post Load Control",
  [0x3007] = "DB Initialized",
  [0x3100] = "Track Select",
  [0x4000] = "Success Ack",
  [0x4001] = "Menu Header",
  [0x4002] = "Artwork Blob",
  [0x4101] = "Menu Item",
  [0x4201] = "Menu Footer",
  [0x4402] = "Waveform Preview Blob",
  [0x4502] = "Load Track Info Blob",
  [0x4602] = "Beat Grid Blob",
  [0x4702] = "Cue Blob",
  [0x4a02] = "Waveform Detail Blob",
  [0x4d02] = "Post Load Control Ack",
  [0x4e02] = "Cue Ext or Edit Ack",
  [0x4f02] = "Analysis Tag Blob",
}

local pdj_dbserver_item_types = {
  [0x00] = "FILE_PATH",
  [0x02] = "ALBUM",
  [0x04] = "TRACK",
  [0x06] = "GENRE",
  [0x07] = "ARTIST",
  [0x08] = "PLAYLIST",
  [0x0a] = "RATING",
  [0x0b] = "DURATION",
  [0x0d] = "TEMPO",
  [0x0e] = "COLOR",
  [0x0f] = "KEY",
  [0x10] = "BITRATE",
  [0x11] = "YEAR",
  [0x13] = "LABEL",
  [0x23] = "COMMENT",
  [0x2e] = "DATE_ADDED",
  [0x2f] = "LOAD_FLAG",
}

local pdj_dbserver_f = p_pdj_dbserver.fields
pdj_dbserver_f.magic = ProtoField.uint32("pdj_dbserver.magic", "Magic", base.HEX)
pdj_dbserver_f.tx_id = ProtoField.uint32("pdj_dbserver.tx_id", "Transaction ID", base.HEX)
pdj_dbserver_f.msg_type = ProtoField.uint16("pdj_dbserver.msg_type", "Message Type", base.HEX, pdj_dbserver_opcodes)
pdj_dbserver_f.argc = ProtoField.uint8("pdj_dbserver.argc", "Argument Count", base.DEC)
pdj_dbserver_f.tag_blob = ProtoField.bytes("pdj_dbserver.tag_blob", "Tag Blob")
pdj_dbserver_f.arg_tag = ProtoField.uint8("pdj_dbserver.arg.tag", "Arg Tag", base.HEX)
pdj_dbserver_f.arg_u32 = ProtoField.uint32("pdj_dbserver.arg.u32", "U32", base.HEX)
pdj_dbserver_f.arg_u16 = ProtoField.uint16("pdj_dbserver.arg.u16", "U16", base.HEX)
pdj_dbserver_f.arg_u8 = ProtoField.uint8("pdj_dbserver.arg.u8", "U8", base.HEX)
pdj_dbserver_f.arg_bin_len = ProtoField.uint32("pdj_dbserver.arg.binary_len", "Binary Length", base.DEC)
pdj_dbserver_f.arg_bin = ProtoField.bytes("pdj_dbserver.arg.binary", "Binary")
pdj_dbserver_f.arg_str = ProtoField.string("pdj_dbserver.arg.string", "String", base.ASCII)
pdj_dbserver_f.item_type = ProtoField.uint32("pdj_dbserver.menu.item_type", "Item Type", base.HEX, pdj_dbserver_item_types)
pdj_dbserver_f.value1 = ProtoField.uint32("pdj_dbserver.menu.value1", "Value1", base.DEC)
pdj_dbserver_f.value2 = ProtoField.uint32("pdj_dbserver.menu.value2", "Value2", base.DEC)
pdj_dbserver_f.loadability = ProtoField.uint32("pdj_dbserver.menu.loadability", "Loadability", base.HEX)
pdj_dbserver_f.greeting = ProtoField.uint32("pdj_dbserver.greeting", "Greeting Value", base.DEC)

local MAGIC = 0x872349AE

local function read_u32_field(tvb, offset, remain)
  if remain < 5 then return nil end
  if tvb(offset, 1):uint() ~= 0x11 then return nil end
  return tvb(offset + 1, 4):uint(), offset + 5
end

local function read_u16_field(tvb, offset, remain)
  if remain < 3 then return nil end
  if tvb(offset, 1):uint() ~= 0x10 then return nil end
  return tvb(offset + 1, 2):uint(), offset + 3
end

local function read_u8_field(tvb, offset, remain)
  if remain < 2 then return nil end
  if tvb(offset, 1):uint() ~= 0x0f then return nil end
  return tvb(offset + 1, 1):uint(), offset + 2
end

local function read_binary_field(tvb, offset, remain)
  if remain < 5 then return nil end
  if tvb(offset, 1):uint() ~= 0x14 then return nil end
  local ln = tvb(offset + 1, 4):uint()
  if remain < 5 + ln then return nil end
  return ln, offset + 5, offset + 5 + ln
end

-- Wire strings are UTF-16; build a short ASCII preview for the tree/Info path.
local function read_string_field(tvb, offset, remain)
  if remain < 5 then return nil end
  if tvb(offset, 1):uint() ~= 0x26 then return nil end
  local units = tvb(offset + 1, 4):uint()
  local nbytes = units * 2
  if remain < 5 + nbytes then return nil end
  local s = ""
  for i = 0, units - 1 do
    local cu = tvb(offset + 5 + i * 2, 2):uint()
    if cu == 0 then break end
    if cu ~= 0xfffa and cu ~= 0xfffb then
      if cu < 128 then
        s = s .. string.char(cu)
      else
        s = s .. "?"
      end
    end
  end
  return s, offset + 5 + nbytes, offset + 5, nbytes
end

-- Keep Info readable when one TCP segment carries a whole menu render.
local function format_type_list(types)
  if #types == 0 then return "Unknown" end
  local parts = {}
  local i = 1
  while i <= #types do
    local j = i
    while j <= #types and types[j] == types[i] do
      j = j + 1
    end
    local n = j - i
    if n > 1 then
      parts[#parts + 1] = types[i] .. "×" .. n
    else
      parts[#parts + 1] = types[i]
    end
    i = j
  end
  return table.concat(parts, ", ")
end

-- Same Info shape as announce/status/beat so the packet list stays scannable.
local function set_cols(pkt, tvb, detail)
  pkt.cols.protocol = "PRODJ DB"
  pkt.cols.info = tostring(pkt.dst_port)
    .. " Len=" .. tvb:len()
    .. " [" .. detail .. "]"
    .. " From=" .. tostring(pkt.src)
end

-- Also return the type name so multi-PDU segments can share one Info line.
local function dissect_message(tvb, offset, tree, pkt)
  local start = offset
  local remain = tvb:len() - offset
  local magic, o1 = read_u32_field(tvb, offset, remain)
  if not magic or magic ~= MAGIC then return nil end
  remain = tvb:len() - o1
  local tx, o2 = read_u32_field(tvb, o1, remain)
  if not tx then return nil end
  remain = tvb:len() - o2
  local mtype, o3 = read_u16_field(tvb, o2, remain)
  if not mtype then return nil end
  remain = tvb:len() - o3
  local argc, o4 = read_u8_field(tvb, o3, remain)
  if not argc then return nil end

  local name = pdj_dbserver_opcodes[mtype] or "Unknown"
  local subtree = tree:add(p_pdj_dbserver, tvb(start, math.min(64, tvb:len() - start)),
    "AlphaTheta PRO DJ LINK Protocol (DB Server), Type: " .. name
      .. string.format(" (0x%04x), tx=0x%08x, argc=%d", mtype, tx, argc))
  subtree:add(pdj_dbserver_f.magic, tvb(start + 1, 4))
  subtree:add(pdj_dbserver_f.tx_id, tvb(o1 + 1, 4))
  subtree:add(pdj_dbserver_f.msg_type, tvb(o2 + 1, 2))
  subtree:add(pdj_dbserver_f.argc, tvb(o3 + 1, 1))

  local pos = o4
  remain = tvb:len() - pos
  if argc > 0 or (remain >= 5 and tvb(pos, 1):uint() == 0x14) then
    local ln, data_off, next_off = read_binary_field(tvb, pos, remain)
    if not ln then return nil end
    if ln > 0 then
      subtree:add(pdj_dbserver_f.tag_blob, tvb(data_off, ln))
    else
      subtree:add(pdj_dbserver_f.tag_blob, tvb(pos, 5)):append_text(" (empty)")
    end
    pos = next_off
  end

  local strs = {}
  local menu_value1_off, menu_value2_off, menu_type_off, menu_load_off

  for i = 0, argc - 1 do
    remain = tvb:len() - pos
    if remain <= 0 then break end
    local tag = tvb(pos, 1):uint()
    -- 3rd arg is the field value; a string label here trips Wireshark's Lua binding.
    local argtree = subtree:add(pdj_dbserver_f.arg_tag, tvb(pos, 1), tag, nil,
      string.format("(arg[%d])", i))

    if tag == 0x11 then
      local v, n = read_u32_field(tvb, pos, remain)
      if not v then break end
      argtree:add(pdj_dbserver_f.arg_u32, tvb(pos + 1, 4))
      if mtype == 0x4101 then
        if i == 0 then menu_value1_off = pos + 1 end
        if i == 1 then menu_value2_off = pos + 1 end
        if i == 6 then menu_type_off = pos + 1 end
        if i == 10 then menu_load_off = pos + 1 end
      end
      pos = n
    elseif tag == 0x10 then
      local v, n = read_u16_field(tvb, pos, remain)
      if not v then break end
      argtree:add(pdj_dbserver_f.arg_u16, tvb(pos + 1, 2))
      pos = n
    elseif tag == 0x0f then
      local v, n = read_u8_field(tvb, pos, remain)
      if not v then break end
      argtree:add(pdj_dbserver_f.arg_u8, tvb(pos + 1, 1))
      pos = n
    elseif tag == 0x14 then
      local ln, data_off, n = read_binary_field(tvb, pos, remain)
      if not ln then break end
      argtree:add(pdj_dbserver_f.arg_bin_len, tvb(pos + 1, 4))
      if ln > 0 then
        argtree:add(pdj_dbserver_f.arg_bin, tvb(data_off, ln))
      end
      pos = n
    elseif tag == 0x26 then
      local s, n, data_off, nbytes = read_string_field(tvb, pos, remain)
      if not n then break end
      if nbytes and nbytes > 0 then
        argtree:add(pdj_dbserver_f.arg_str, tvb(data_off, nbytes))
          :append_text(string.format(" → %s", s ~= "" and s or "(empty)"))
      else
        argtree:append_text(string.format(" string=%s", s or ""))
      end
      strs[#strs + 1] = s or ""
      pos = n
    else
      break
    end
  end

  if mtype == 0x4101 then
    if menu_value1_off then subtree:add(pdj_dbserver_f.value1, tvb(menu_value1_off, 4)) end
    if menu_value2_off then subtree:add(pdj_dbserver_f.value2, tvb(menu_value2_off, 4)) end
    if menu_type_off then subtree:add(pdj_dbserver_f.item_type, tvb(menu_type_off, 4)) end
    if menu_load_off then subtree:add(pdj_dbserver_f.loadability, tvb(menu_load_off, 4)) end
    if strs[1] and strs[1] ~= "" then
      subtree:append_text(string.format(" label1=%s", strs[1]))
    end
    if strs[2] and strs[2] ~= "" then
      subtree:append_text(string.format(" label2=%s", strs[2]))
    end
  end

  if mtype == 0x2904 then
    subtree:add_expert_info(PI_SEQUENCE, PI_NOTE,
      "waveform_detail request (gate full PWV3 until after 0x3100)")
  end
  if mtype == 0x0100 or mtype == 0x0001 then
    subtree:add_expert_info(PI_SEQUENCE, PI_NOTE,
      "cancel/teardown (server typically silent)")
  end

  return pos - start, name
end

function p_pdj_dbserver.dissector(tvb, pkt, tree)
  local offset = 0
  local len = tvb:len()
  if len < 5 then return 0 end

  if len >= 5 and tvb(0, 1):uint() == 0x11 and tvb(1, 4):uint() == 1 and len <= 8 then
    local t = tree:add(p_pdj_dbserver, tvb(),
      "AlphaTheta PRO DJ LINK Protocol (DB Server), Type: Greeting")
    t:add(pdj_dbserver_f.greeting, tvb(1, 4))
    set_cols(pkt, tvb, "Greeting")
    return len
  end

  local consumed = 0
  local types = {}
  while offset + 6 <= len do
    local matched = false
    for i = offset, len - 6 do
      if tvb(i, 1):uint() == 0x11 and tvb(i + 1, 4):uint() == MAGIC then
        local msg_len, type_name = dissect_message(tvb, i, tree, pkt)
        if not msg_len or msg_len <= 0 then
          offset = i + 1
          break
        end
        types[#types + 1] = type_name or "Unknown"
        offset = i + msg_len
        consumed = offset
        matched = true
        break
      end
    end
    if not matched then break end
  end
  if #types > 0 then
    set_cols(pkt, tvb, format_type_list(types))
  end
  return consumed
end

local function heur_dbserver(tvb, pkt, tree)
  local len = tvb:len()
  if len < 6 then return false end
  if len >= 5 and tvb(0, 1):uint() == 0x11 and tvb(1, 4):uint() == 1 then
    p_pdj_dbserver.dissector(tvb, pkt, tree)
    return true
  end
  for i = 0, math.min(len - 6, 512) do
    if tvb(i, 1):uint() == 0x11 and tvb(i + 1, 4):uint() == MAGIC then
      p_pdj_dbserver.dissector(tvb, pkt, tree)
      return true
    end
  end
  return false
end

function p_pdj_dbserver.init()
end

p_pdj_dbserver:register_heuristic("tcp", heur_dbserver)

local tcp_dissector_table = DissectorTable.get("tcp.port")
tcp_dissector_table:add(1051, p_pdj_dbserver)
tcp_dissector_table:add(12523, p_pdj_dbserver)
