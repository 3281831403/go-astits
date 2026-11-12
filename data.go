package astits

import (
	"encoding/binary"
	"fmt"
	"github.com/asticode/go-astikit"
)

// PIDs
const (
	PIDPAT  uint16 = 0x0    // Program Association Table (PAT) contains a directory listing of all Program Map Tables.
	PIDCAT  uint16 = 0x1    // Conditional Access Table (CAT) contains a directory listing of all ITU-T Rec. H.222 entitlement management message streams used by Program Map Tables.
	PIDTSDT uint16 = 0x2    // Transport Stream Description Table (TSDT) contains descriptors related to the overall transport stream
	PIDNull uint16 = 0x1fff // Null Packet (used for fixed bandwidth padding)
)

// DemuxerData represents a data parsed by Demuxer
type DemuxerData struct {
	EIT         *EITData
	FirstPacket *Packet
	NIT         *NITData
	PAT         *PATData
	PES         *PESData
	PID         uint16
	PMT         *PMTData
	SDT         *SDTData
	TOT         *TOTData
}

// MuxerData represents a data to be written by Muxer
type MuxerData struct {
	PID             uint16
	AdaptationField *PacketAdaptationField
	PES             *PESData
}

// parseData parses a payload spanning over multiple packets and returns a set of data
func parseData(ps []*Packet, prs PacketsParser, pm *programMap, esm *elementaryStreamMap) (ds []*DemuxerData, err error) {
	// Use custom parser first
	if prs != nil {
		var skip bool
		if ds, skip, err = prs(ps); err != nil {
			err = fmt.Errorf("astits: custom packets parsing failed: %w", err)
			return
		} else if skip {
			return
		}
	}

	// Get payload length
	var l int
	for _, p := range ps {
		l += len(p.Payload)
	}

	// Get the slice for payload from pool
	payload := bytesPool.get(l)
	defer bytesPool.put(payload)

	// Append payload
	var c int
	for _, p := range ps {
		c += copy(payload.s[c:], p.Payload)
	}

	// Parse PID
	pid := ps[0].Header.PID

	// Parse payload
	if pid == PIDCAT {
		// Information in a CAT payload is private and dependent on the CA system. Use the PacketsParser
		// to parse this type of payload
	} else if isPSIPayload(pid, pm, esm) {
		// Copy first packet headers, so we can safely deallocate original payload
		fp := &Packet{
			Header:          ps[0].Header,
			AdaptationField: ps[0].AdaptationField,
		}

		// Parse PSI data
		var psiData *PSIData
		if psiData, err = parsePSIData(astikit.NewBytesIterator(payload.s)); err != nil {
			err = fmt.Errorf("astits: parsing PSI data failed: %w", err)
			return
		}

		// Append data
		ds = psiData.toData(fp, pid)
	} else if isPESPayload(payload.s) {
		// Parse PES data. A single payload may contain several PES packets back to
		// back (small audio frames are commonly packed that way), so split them
		// according to PES_packet_length instead of only returning the first one.
		ds, err = parsePESDataSequence(payload.s, ps, pid)
	}
	return
}

// parsePESDataSequence parses every PES packet contained in a payload, in order.
// The payload starts with a PES packet (the caller checks it) and may span
// several TS packets. A truncated or malformed tail that follows complete PES
// packets is dropped silently: it can only be the end of a PES packet cut by
// the payload boundary, and reporting it would prevent the complete packets
// from being delivered.
func parsePESDataSequence(payload []byte, ps []*Packet, pid uint16) (ds []*DemuxerData, err error) {
	var pos int
	for pos < len(payload) {
		// A PES packet must start with the packet start code prefix. Anything else
		// left after complete packets is an incomplete tail.
		if !isPESPayload(payload[pos:]) {
			if len(ds) == 0 {
				err = fmt.Errorf("astits: parsing PES data failed: packet start code prefix not found")
			}
			return
		}

		// Parse the PES packet
		var pesData *PESData
		var errParse error
		if pesData, errParse = parsePESData(astikit.NewBytesIterator(payload[pos:])); errParse != nil {
			if len(ds) == 0 {
				// Keep the historical behavior for a payload that contains a single
				// PES packet: report the parsing error.
				err = fmt.Errorf("astits: parsing PES data failed: %w", errParse)
			}
			return
		}

		// Append data
		ds = append(ds, &DemuxerData{
			FirstPacket: firstPacketForPES(ps, pos),
			PES:         pesData,
			PID:         pid,
		})

		// A packet length of zero means the PES packet is of unknown length: its
		// end can only be determined by the next payload unit start, which is the
		// end of the current payload.
		if pesData.Header.PacketLength == 0 {
			return
		}

		// Move to the next PES packet. PES_packet_length excludes the six-byte
		// fixed header.
		pos += pesHeaderLength + int(pesData.Header.PacketLength)
	}
	return
}

// firstPacketForPES returns a copy of the packet in which the PES packet starting
// at the provided payload offset begins. It preserves the historical behavior of
// returning the first packet of the payload for the first PES packet.
func firstPacketForPES(ps []*Packet, offset int) (fp *Packet) {
	if len(ps) == 0 {
		return
	}

	// Find the packet containing the offset
	var pos int
	for _, p := range ps {
		if offset < pos+len(p.Payload) {
			return &Packet{
				Header:          p.Header,
				AdaptationField: p.AdaptationField,
			}
		}
		pos += len(p.Payload)
	}

	// Offset is out of range: fall back to the last packet with a payload.
	for idx := len(ps) - 1; idx >= 0; idx-- {
		if len(ps[idx].Payload) > 0 {
			return &Packet{
				Header:          ps[idx].Header,
				AdaptationField: ps[idx].AdaptationField,
			}
		}
	}
	return &Packet{
		Header:          ps[len(ps)-1].Header,
		AdaptationField: ps[len(ps)-1].AdaptationField,
	}
}

// isPSIPayload checks whether the payload is a PSI one
func isPSIPayload(pid uint16, pm *programMap, esm *elementaryStreamMap) bool {
	return pid == PIDPAT || // PAT
		pm.existsUnlocked(pid) || // PMT
		(((pid >= 0x10 && pid <= 0x14) || (pid >= 0x1e && pid <= 0x1f)) && // DVB
			!esm.existsUnlocked(pid)) // for non-DVB
}

// isPESPayload checks whether the payload is a PES one
func isPESPayload(i []byte) bool {
	// Packet is not big enough
	if len(i) < 3 {
		return false
	}

	// Check prefix
	return uint32(i[0])<<16|uint32(i[1])<<8|uint32(i[2]) == 1
}

// isPSIComplete checks whether we have sufficient amount of packets to parse PSI
func isPSIComplete(ps []*Packet) bool {
	// Get payload length
	var l int
	for _, p := range ps {
		l += len(p.Payload)
	}

	// Get the slice for payload from pool
	payload := bytesPool.get(l)
	defer bytesPool.put(payload)

	// Append payload
	var o int
	for _, p := range ps {
		o += copy(payload.s[o:], p.Payload)
	}

	// Create reader
	i := astikit.NewBytesIterator(payload.s)

	// Get next byte
	b, err := i.NextByte()
	if err != nil {
		return false
	}

	// Pointer filler bytes
	i.Skip(int(b))

	for i.HasBytesLeft() {

		// Get PSI table ID
		b, err = i.NextByte()
		if err != nil {
			return false
		}

		// Check whether we need to stop the parsing
		if shouldStopPSIParsing(PSITableID(b)) {
			break
		}

		// Get PSI section length
		var bs []byte
		bs, err = i.NextBytesNoCopy(2)
		if err != nil {
			return false
		}

		i.Skip(int(binary.BigEndian.Uint16(bs) & 0x0fff))
	}

	return i.Len() >= i.Offset()
}

// isPESComplete checks whether payload fully contains PES packet
func isPESComplete(ps []*Packet) bool {
	_, complete := pesAccumulationStatus(ps)
	return complete
}

// pesAccumulationStatus reports whether the accumulated packets contain PES data
// and whether the accumulator is complete, meaning that no more packets are
// needed, i.e. the payload ends exactly on the boundary of a bounded PES packet.
//
// The payload is only complete when every PES packet it contains can be delimited:
// packets are packed one after the other, so a PES packet that doesn't end exactly
// at the payload boundary may continue in the next packet. An unknown PES packet
// length (PES_packet_length 0) is also incomplete since its end can only be marked
// by the next payload unit start.
func pesAccumulationStatus(ps []*Packet) (hasPES bool, complete bool) {
	var header [6]byte
	var n int
	for _, p := range ps {
		n += copy(header[n:], p.Payload)
		if n == len(header) {
			break
		}
	}
	if n < len(header) || !isPESPayload(header[:]) {
		return false, false
	}
	hasPES = true

	// Get payload length
	var l int
	for _, p := range ps {
		l += len(p.Payload)
	}

	// PES_packet_length excludes the six-byte fixed header. An unknown length can
	// only be ended by the next payload unit start, and a payload that doesn't
	// reach the declared end of the first PES packet is incomplete. Both cases can
	// be decided from the header alone, without assembling the payload.
	packetLength := binary.BigEndian.Uint16(header[4:])
	if packetLength == 0 || l < pesHeaderLength+int(packetLength) {
		return true, false
	}

	// Get the slice for payload from pool
	payload := bytesPool.get(l)
	defer bytesPool.put(payload)

	// Append payload
	var o int
	for _, p := range ps {
		o += copy(payload.s[o:], p.Payload)
	}

	// Walk PES packets
	var pos int
	for pos < len(payload.s) {
		// Fewer than 3 bytes left: this may be the beginning of the next PES
		// packet's start code prefix, which can be split across the packet boundary.
		if len(payload.s)-pos < 3 {
			return true, false
		}

		// A PES packet must start with the packet start code prefix. Since the
		// previous PES packet ended at this offset, a different prefix means a
		// truncated tail that no following packet can complete.
		if !isPESPayload(payload.s[pos:]) {
			return true, true
		}

		// Parse header
		i := astikit.NewBytesIterator(payload.s[pos:])
		i.Seek(3)
		h, _, _, err := parsePESHeader(i)
		if err != nil {
			return true, false
		}

		// Unknown length: the end of this PES packet can only be marked by the next
		// payload unit start.
		if h.PacketLength == 0 {
			return true, false
		}

		// PES_packet_length excludes the six-byte fixed header.
		end := pos + pesHeaderLength + int(h.PacketLength)
		if end > len(payload.s) {
			// The PES packet continues in the next packet
			return true, false
		}
		pos = end
	}
	return true, true
}
