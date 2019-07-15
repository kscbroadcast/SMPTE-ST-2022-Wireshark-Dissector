-- Lua Wireshark Dissector of SMPTE ST 2022
-- Author: Kevin Scott (kevin@kscbroadcast.com)
--
-- Please find instructions on how to use this dissector here:
-- https://github.com/kscbroadcast/SMPTE-ST-2022-Wireshark-Dissector
--
-- This Dissector is distributed under the GNU General Public License v2.0
-- in the hope that it will be of use but WITHOUT ANY WARRENTY; without even 
-- the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
--
-- See the GNU General Public License for more details.

ST2022_1 = Proto ("ST2022-1","SMPTE ST 2022-1")
ST2022_5 = Proto ("ST2022-5","SMPTE ST 2022-5")
ST2022_6 = Proto ("ST2022-6","SMPTE ST 2022-6")

-- SMPTE 2022-1 --

local dashOne = ST2022_1.fields

dashOne.SnBase = ProtoField.uint16("smpte_2022_1.SnBase","Minimum Sequence Number Associated with this FEC (SnBase)",base.DEC,nil,0xffff)
dashOne.LenRecovery = ProtoField.uint16("smpte_2022_1.LenRecovery","Length of Media Packets Associsted with this FEC (LenRecovery)",base.DEC,nil,0xffff)
dashOne.e = ProtoField.bool("smpte_2022_1.e","Header Extension (e)",8,{"Extended Header","Standard Header"},0x80)
dashOne.PtRecovery = ProtoField.uint8("smpte_2022_1.PtRecovery","Payload Type of Media Packets Associated with this FEC (PT Recovery)",base.DEC,nil,0x7f)
dashOne.Mask = ProtoField.uint24("smpte_2022_1.Mask","Recovery Mask (Mask)",base.HEX,nil)
dashOne.TsRecovery = ProtoField.uint32("smpte_2022_1.TsRecovery","Recovered Timestamp (TsRecovery)",base.DEC)
dashOne.N = ProtoField.uint8("smpte_2022_1.N","Reserved for Future Header Extensions (N)",base.HEX,nil,0x80)
dashOne.D = ProtoField.uint8("smpte_2022_1.D", "FEC Stream (D)",base.HEX,{[0]="FEC Stream 1",[1]="FEC Stream 2"},0x40)
dashOne.Type = ProtoField.uint8("smpte_2022_1.Type", "Error Correction Code (Type)",base.HEX,nil,0x38)
dashOne.Index = ProtoField.uint8("smpte_2022_1.Index","Complex Error Correction Codes (Index)",base.HEX,nil,0x07)
dashOne.Offset0 = ProtoField.uint8("smpte_2022_1.Offset","Number of FEC Columns [L] (Offset)",base.DEC,nil,0xff)
dashOne.NA0 = ProtoField.uint8("smpte_2022_1.NA","Number of FEC Rows [D] (NA)",base.DEC,nil,0xff)
dashOne.Offset1 = ProtoField.uint8("smpte_2022_1.Offset","FEC Computed Over Rows (Offset)",base.DEC,nil,0xff)
dashOne.NA1 = ProtoField.uint8("smpte_2022_1.NA","Number of FEC Columns [L] (NA)",base.DEC,nil,0xff)
dashOne.SnBaseE = ProtoField.uint8("smpte_2022_1.SnBaseE","Extended Sequence Numbers",base.HEX,nil,0xff)
dashOne.FecPayload = ProtoField.bytes("smpte_2022_1.FecPayload","FEC")

function ST2022_1.dissector (buffer, packet, root)
	if buffer:len() == 0 then return end
	packet.cols.protocol = ST2022_1.name

	header = root:add(ST2022_1, buffer(0))
	header:append_text(" Header")
	
	header:add(dashOne.SnBase, buffer(0,2))
	header:add(dashOne.LenRecovery, buffer(2,2))
	header:add(dashOne.e, buffer(4,1))

	local exentsion=buffer(4,1):bitfield(0,1)

	header:add(dashOne.PtRecovery, buffer(4,1))
	header:add(dashOne.Mask, buffer(5,3))
	header:add(dashOne.TsRecovery, buffer(8,4))

	local headerLength = 12
	local payloadLength = 1352 - 36

	if exentsion > 0 then
		headerLength = headerLength + 4
		payloadLength = payloadLength

		header:add(dashOne.N, buffer(12,1))
		header:add(dashOne.D, buffer(12,1))
		header:add(dashOne.Type, buffer(12,1))

		local stream=buffer(12,1):bitfield(1,1)

		if stream == 1 then
			header:add(dashOne.Offset1, buffer(13,1))
			header:add(dashOne.NA1, buffer(14,1))
		end

		if stream == 0 then
			header:add(dashOne.Offset0, buffer(13,1))
			header:add(dashOne.NA0, buffer(14,1))
		end
		header:add(dashOne.SnBaseE, buffer(15,1))
	end

	payload = root:add(ST2022_1, buffer(0))
	payload:append_text(" Payload")
	payload:add(dashOne.FecPayload, buffer(headerLength))
end

function ST2022_1.init()
end

local rtp_dissector_table = DissectorTable.get("rtp.pt")
dissector = rtp_dissector_table:get_dissector(96)
rtp_dissector_table:add(96, ST2022_1)

-- SMPTE 2022-5 --

local dashFive = ST2022_5.fields

dashFive.E = ProtoField.bool("smpte_2022_5.Extension_Flag", "Extension Flag (e)",8,{"Extended","Standard"},0x80)
dashFive.R = ProtoField.bool("smpte_2022_5.Reserved_Bit", "Reserved (R)",8,{"True","False"},0x40)
dashFive.P = ProtoField.bool("smpte_2022_5.Padding_Recovery", "Padding Field (P)",8,{"True","False"},0x20)
dashFive.X = ProtoField.bool("smpte_2022_5.Extended_Recovery", "Extended Recovery Field (X)",8,{"True","False"},0x10)
dashFive.Csrc = ProtoField.uint8("smpte_2022_5.CSRC_Recovery_Count", "Csrc Recovery Count (CC)",base.DEC,nil,0x0f)
dashFive.M = ProtoField.bool("smpte_2022_5.Marker_Recovery", "Marker Recovery Field (M)",8,{"True","False"},0x80)
dashFive.PtRecovery = ProtoField.uint8("smpte_2022_5.PtRecovery", "Payload Type Recovery",base.HEX)
dashFive.SnBase = ProtoField.uint16("smpte_2022_5.SnBase","Minimum Sequence Number Associated with this FEC (SN Base)",base.DEC)
dashFive.TsRecovery = ProtoField.uint32("smpte_2022_5.TsRecovery","Recovered Timestamp (TS Recovery)",base.HEX)
dashFive.LenRecovery = ProtoField.uint16("smpte_2022_5.LenRecovery", "Length Recovery (LR)",base.HEX)
dashFive.ReservedBytes = ProtoField.uint8("smpte_2022_5.Reserverd_Bytes", "Reservered",base.HEX,nil,0xff)
dashFive.Offset = ProtoField.uint16("smpte_2022_5.Offset","Number of FEC Coloums [L] or Rows [D]",base.DEC,nil,0xffc0)
dashFive.ReservedBits = ProtoField.uint8("smpte_2022_5.ReservedBits", "Reserved Bits",baseHEX,nil,0x3f)
dashFive.Na = ProtoField.uint16("smpte_2022_5.Na","Number of Media Datagrams Associated",baseDEC)
dashFive.FecPayload = ProtoField.bytes("smpte_2022_5.FecPayload","FEC")

function ST2022_5.dissector (buffer, packet, root)
	if buffer:len() == 0 then return end
	packet.cols.protocol = ST2022_5.name

	header = root:add(ST2022_5, buffer(0))
	header:append_text(" Header")

	header:add(dashFive.E,buffer(0,1))
	header:add(dashFive.R,buffer(0,1))
	header:add(dashFive.P,buffer(0,1))
	header:add(dashFive.X,buffer(0,1))
	header:add(dashFive.Csrc,buffer(0,1))
	header:add(dashFive.M,buffer(1,1))
	header:add(dashFive.PtRecovery,buffer(1,1))
	header:add(dashFive.SnBase,buffer(2,2))
	header:add(dashFive.TsRecovery,buffer(4,4))
	header:add(dashFive.LenRecovery,buffer(8,2))
	header:add(dashFive.ReservedBytes,buffer(10,2))
	header:add(dashFive.Offset,buffer(12,2))
	header:add(dashFive.ReservedBits,buffer(13,1))
	header:add(dashFive.Na,buffer(14,2))
	header:add(dashFive.ReservedBits,buffer(15,1))
	
	payload = root:add(ST2022_5, buffer(0))
	payload:append_text(" Payload")
	payload:add(dashFive.FecPayload,buffer(16))
	
end

function ST2022_5.init()
end

local dash5_dissector_table = DissectorTable.get("rtp.pt")
dash5_dissector = dash5_dissector_table:get_dissector(99)
dash5_dissector_table:add(99, ST2022_5)

-- SMPTE 2022-6 --

videoSrcId={
[0x0]="Primary Stream",
[0x1]="Protect Stream",
}

timestampRef={
[0x0]="Not Locked",
[0x1]="Reserved",
[0x2]="Locked To UTC Time/Frequency Reference",
[0x3]="Locked to a Private Time/Frequency Reference"
}

payloadScrambling={
[0x0]="Not Scrambled"
}

fecUsage={
[0x0]="No FEC Stream",
[0x1]="L (Column) FEC Utilized",
[0x2]="L & D (Column & Row) FEC Utilized",
}

clockFrequency={
[0x0]="No Timestamp",
[0x1]="27 MHz",
[0x2]="148.5 MHz",
[0x3]="148.5/1.001 MHz",
[0x4]="297 MHz",
[0x5]="297/1.001 MHz"
}

imageMapping={
[0]="Direct Sample Structure",
[1]="SMPTE ST 425-1 Level B-DL Mapping Of 372 Dual-Link",
[2]="SMPTE ST 425-1 Level B-DS Mapping Of Two ST 292-1 Streams",
}

frameStructure={
[0x00]="Unknown/Unspecified Frame Structure",
[0x10]="720 x 486 - Interlace",
[0x11]="720 x 576 - Interlace",
[0x20]="1920 x 1080 - Interlace",
[0x21]="1920 x 1080 - Progressive",
[0x22]="1920 x 1080 - PsF",
[0x23]="2048 x 1080 - Progressive",
[0x24]="2048 x 1080 - PsF",
[0x30]="1280 x 720 - Progressive"
}

frameRate={
[0x00]="Unknown/Unspecified Frame Rate 2.970 GHz Signal",
[0x01]="Unknown/Unspecified Frame Rate 2.970/1.001 GHz Signal",
[0x02]="Unknown/Unspecified Frame Rate 1.485 GHz Signal",
[0x03]="Unknown/Unspecified Frame Rate 1.485/1.001 GHz Signal",
[0x04]="Unknown/Unspecified Frame Rate 0.270 GHz Signal",
[0x10]="60 fps",
[0x11]="60/1.001 fps",
[0x12]="50 fps",
[0x14]="48 fps",
[0x15]="48/1.001 fps",
[0x16]="30 fps",
[0x17]="30/1.001 fps",
[0x18]="25 fps",
[0x1A]="24 fps",
[0x1B]="24/1.001 fps"
}

pixelSampling={
[0x00]="Unknown/Unspecified",
[0x01]="4:2:2 10 bits",
[0x02]="4:4:4 10 bits",
[0x03]="4:4:4:4 10 bits",
[0x05]="4:2:2 12 bits",
[0x06]="4:4:4 12 bits",
[0x07]="4:4:4:4 12 bits",
[0x08]="4:2:2:4 12 bits",
}

local dashSix = ST2022_6.fields

dashSix.Ext = ProtoField.uint8("smpte_2022_6.Ext","Extension field (Ext)",base.HEX,nil,0xf0)
dashSix.F = ProtoField.bool("smpte_2022_6.F","Video Source Format Flag (F)",8,{"Video Source Format Present","Video Source format Not Present"},0x08)

dashSix.VsId = ProtoField.uint8("smpte_2022_6.VSID","Video Source ID (VSID)",base.HEX,videoSrcId,0x07)
dashSix.VsIdRes = ProtoField.uint8("smpte_2022_6.VSID","Video Source ID (VSID)",base.HEX,nil,0x07)

dashSix.FRCount = ProtoField.uint8("smpte_2022_6.FRCount","Frame Count (FRCount)",base.DEC,nil,0xff)
dashSix.R = ProtoField.uint8("smpte_2022_6.R","Reference for Timestamp (R)",base.Hex,timestampRef,0xc0)

dashSix.S = ProtoField.uint8("smpte_2022_6.S","Video Payload Scrambing (S)",base.HEX,payloadScrambling,0x30)
dashSix.Sfuture = ProtoField.uint8("smpte_2022_6.S","Video Payload Scrambing (S)",base.HEX,nil,0x30)

dashSix.Fec = ProtoField.uint8("smpte_2022_6.FEC","FEC Usage (FEC)",base.HEX,fecUsage,0x0E)
dashSix.FecRes = ProtoField.uint8("smpte_2022_6.FEC","FEC Usage (FEC)",base.HEX,nil,0x0E)

dashSix.ClockFreq = ProtoField.uint16("smpte_2022_6.CF","Clock Frequency (CF)",base.HEX,clockFrequency,0x01E0)
dashSix.ClockFreqRes = ProtoField.uint16("smpte_2022_6.CF","Clock Frequency (CF)",base.HEX,nil,0x01E0)

dashSix.Reserve = ProtoField.uint8("smpte_2022_6.RESERVE","Fields Reservered for Future Use",base.HEX,nil,0x1f)

dashSix.Map = ProtoField.uint8("smpte_2022_6.MAP","Source Image Mapping (MAP)",base.HEX, imageMapping,0xf0)
dashSix.MapRes = ProtoField.uint8("smpte_2022_6.MAP","Source Image Mapping (MAP)",base.HEX,nil,0xf0)

dashSix.Frame = ProtoField.uint16("smpte_2022_6.FRAME","Frame Structure (FRAME)",base.HEX,frameStructure,0x0ff0)
dashSix.FrameRes = ProtoField.uint16("smpte_2022_6.FRAME","Frame Structure (FRAME)",base.HEX,nil,0x0ff0)

dashSix.FrameRate = ProtoField.uint16("smpte_2022_6.Frate","Payload Frame Rate",base.HEX,frameRate,0x0ff0)
dashSix.FrameRateRes = ProtoField.uint16("smpte_2022_6.Frate","Payload Frame Rate",base.HEX,nil,0x0ff0)

dashSix.Sample = ProtoField.uint8("smpte_2022_6.sample","Pixel Sampling Structure (SAMPLE)",base.HEX,pixelSampling,0x0f)
dashSix.SampleRes = ProtoField.uint8("smpte_2022_6.sample","Pixel Sampling Structure (SAMPLE)",base.HEX,nil,0x0f)

dashSix.FMTReserve = ProtoField.uint8("smpte_2022_6.FMT-Reserve","8-Bit Reserved Field",base.HEX,nil,0xff)

dashSix.VideoTimestamp = ProtoField.uint32("smpte_2022_6.Video_Timestamp","Video Timestamp",base.DEC)

dashSix.ExtensionTag = ProtoField.uint8("smpte_2022_6.exentsion.tag", "Header Extension Tag",baseDEC,nil,0xff)
dashSix.ExtensionLength = ProtoField.uint8("smpte_2022_6.exentsion.length", "Header Extension Length",baseHEX,nil,0xff)
dashSix.ExtensionValue = ProtoField.bytes("smpte_2022_6.exentsion.value", "Header Extension Value")
dashSix.ExtensionPad = ProtoField.bytes("smpte_2022_6.exentsion.pad", "Header Extension Padding",baseHEX,nil,0xff)

dashSix.Payload = ProtoField.bytes("smpte_2022_6.HBRM_Payload","High Bit Rate Media Payload")



function ST2022_6.dissector(buffer, packet, root)
	if buffer:len() == 0 then return end
	
	local videoSrcIdValue = buffer(0,1):bitfield(5,3)
	local scramblingValue = buffer(2,1):bitfield(2,2)
	local fecUsageValue = buffer(2,1):bitfield(4,3)
	local clockFrequencyValue = buffer(2,2):bitfield(7,4)
	local imageMappingValue = buffer(4,1):bitfield(0,4)
	local frameStructureValue = buffer(4,2):bitfield(4,8)
	local frameRateValue = buffer(5,2):bitfield(4,8)
	local pixelSamplingValue = buffer(6,1):bitfield(4,4)
	local extensionSize = buffer(0,1):bitfield(0,4) * 4
	local headerLength = 8
	local bufferSize = buffer:len()
	
	packet.cols.protocol = ST2022_6.name
	
	header = root:add(ST2022_6, buffer(0))
	header:append_text(" Header")
	header:add(dashSix.Ext,buffer(0,1))
	header:add(dashSix.F,buffer(0,1))
	
	if (TableHasKey(videoSrcId,videoSrcIdValue)) then
		header:add(dashSix.VsId,buffer(0,1))
	else
		header:add(dashSix.VsIdRes,buffer(0,1)):append_text(" ### Reserverd ###")
	end
	
	header:add(dashSix.FRCount,buffer(1,1))
	header:add(dashSix.R,buffer(2,1))
	
	if (TableHasKey(payloadScrambling,scramblingValue)) then
		header:add(dashSix.S,buffer(2,1))
	else
		header:add(dashSix.Sfuture,buffer(2,1)):append_text(" ### Reserverd For Future Use ###")
	end
	
	if (TableHasKey(fecUsage,fecUsageValue)) then
		header:add(dashSix.Fec,buffer(2,1))
	else
		header:add(dashSix.FecRes,buffer(2,1)):append_text(" ### Reserverd ###")
	end
	
	if (TableHasKey(clockFrequency,clockFrequencyValue)) then
		header:add(dashSix.ClockFreq,buffer(2,2))
	else
		header:add(dashSix.ClockFreqRes,buffer(2,2)):append_text(" ### Reserverd ###")
	end
	
	header:add(dashSix.Reserve,buffer(3,1))
	
	if (TableHasKey(imageMapping,imageMappingValue)) then
		header:add(dashSix.Map,buffer(4,1))
	else
		header:add(dashSix.MapRes,buffer(4,1)):append_text(" ### Reserverd ###")
	end
	
	if (TableHasKey(frameStructure,frameStructureValue)) then
		header:add(dashSix.Frame,buffer(4,2))
	else
		header:add(dashSix.FrameRes,buffer(4,2)):append_text(" ### Reserverd ###")
	end
	
	if (TableHasKey(frameRate,frameRateValue)) then
		header:add(dashSix.FrameRate,buffer(5,2))
	else
		header:add(dashSix.FrameRateRes,buffer(5,2)):append_text(" ### Reserverd ###")
	end
	
	if (TableHasKey(pixelSampling,pixelSamplingValue)) then
		header:add(dashSix.Sample,buffer(6,1))
	else
		header:add(dashSix.SampleRes,buffer(6,1)):append_text(" ### Reserverd ###")
	end
	
	header:add(dashSix.FMTReserve,buffer(7,1))
	
	if clockFrequencyValue > 0 then
		header:add(dashSix.VideoTimestamp,buffer(8,4))
		headerLength = headerLength + 4
	end
	
	local extensionStart = headerLength
	local extensionBytesRemain = extensionSize
	if extensionSize > 0 then
		extensionHeader = root:add(ST2022_6, buffer(0, (bufferSize - headerLength)))
		extensionHeader:append_text(" Header Extension - " .. extensionSize .. " Bytes")
		
		while extensionBytesRemain > 0 do
			local extensionTag = buffer(headerLength,1):uint()
			if extensionTag > 0 then
				
				extensionHeader:add(dashSix.ExtensionTag, buffer(headerLength, 1))
				extensionHeader:add(dashSix.ExtensionLength, buffer(headerLength + 1, 1))
				
				local extensionLength = buffer(headerLength + 1, 1):uint()
				extensionHeader:add(dashSix.ExtensionValue, buffer(headerLength + 2, extensionLength))
				
				headerLength = headerLength + 2 + extensionLength
				extensionBytesRemain = extensionBytesRemain - 2 - extensionLength
			else
				extensionHeader:add(dashSix.ExtensionPad, buffer(headerLength, 1))
				extensionBytesRemain = extensionBytesRemain - 1
				headerLength = headerLength + 1
			end
		end
		headerLength = extensionStart + (extensionSize)		
	end 	

	payload = root:add(ST2022_6, buffer(0, (bufferSize - headerLength)))
	payload:append_text(" Payload")
	payload:add(dashSix.Payload,buffer(headerLength))
	
end

function ST2022_6.init()


end

local dash6_dissector_table = DissectorTable.get("rtp.pt")
dash6_dissector = dash6_dissector_table:get_dissector(98)
dash6_dissector_table:add(98, ST2022_6)

function TableHasKey(table,key)
	return table [key] ~= nil
end	
