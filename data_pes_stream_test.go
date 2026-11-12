package astits

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildBoundedPES builds a PES packet with a minimal optional header (no PTS/DTS)
// followed by data. PES_packet_length is set accordingly.
func buildBoundedPES(streamID uint8, data []byte) []byte {
	b := []byte{0, 0, 1, streamID, 0, 0, 0x80, 0x00, 0x00}
	length := len(b) - pesHeaderLength + len(data)
	b[4] = uint8(length >> 8)
	b[5] = uint8(length)
	return append(b, data...)
}

// buildTSPacket builds a 188-byte TS packet whose payload is exactly payload.
// Remaining bytes are filled with an adaptation field so that the padding doesn't
// become part of the payload.
func buildTSPacket(pid uint16, cc uint8, pusi bool, payload []byte) []byte {
	h := []byte{
		byte(syncByte),
		byte(pid>>8) & 0x1f,
		byte(pid),
		0x10 | cc&0xf,
	}
	if pusi {
		h[1] |= 0x40
	}

	if len(payload) == MpegTsPacketSize-mpegTsPacketHeaderSize-1 {
		return append(h, payload...)
	}

	// Adaptation field and payload
	h[3] |= 0x20
	room := MpegTsPacketSize - mpegTsPacketHeaderSize - 1 - len(payload)
	p := []byte{byte(room - 1)}
	if room > 1 {
		p = append(p, 0x00)
		p = append(p, bytes.Repeat([]byte{0xff}, room-2)...)
	}
	return append(append(h, p...), payload...)
}

// buildTSStream packs a byte run into TS packets of the provided PID. Only the
// first packet carries the payload unit start indicator.
func buildTSStream(pid uint16, cc uint8, b []byte) (ps [][]byte, nextCC uint8) {
	payloadLen := MpegTsPacketSize - mpegTsPacketHeaderSize - 1
	first := true
	for len(b) > 0 {
		n := payloadLen
		if len(b) < n {
			n = len(b)
		}
		ps = append(ps, buildTSPacket(pid, cc, first, b[:n]))
		b = b[n:]
		first = false
		cc++
	}
	return ps, cc
}

func concatTS(ps ...[][]byte) []byte {
	var b []byte
	for _, p := range ps {
		for _, pkt := range p {
			b = append(b, pkt...)
		}
	}
	return b
}

type demuxedPES struct {
	Data         []byte
	PacketLength uint16
	StreamID     uint8
	CC           uint8
	PID          uint16
}

func demuxPES(t *testing.T, b []byte) (pes []demuxedPES, err error) {
	t.Helper()
	dmx := NewDemuxer(context.Background(), bytes.NewReader(b), DemuxerOptPacketSize(MpegTsPacketSize))
	for {
		d, errD := dmx.NextData()
		if errD != nil {
			if errors.Is(errD, ErrNoMorePackets) {
				return pes, nil
			}
			return pes, errD
		}
		if d.PES == nil {
			continue
		}
		pes = append(pes, demuxedPES{
			Data:         d.PES.Data,
			PacketLength: d.PES.Header.PacketLength,
			StreamID:     d.PES.Header.StreamID,
			CC:           d.FirstPacket.Header.ContinuityCounter,
			PID:          d.PID,
		})
	}
}

func pesTag(p demuxedPES) byte {
	if len(p.Data) == 0 {
		return 0
	}
	return p.Data[0]
}

func pesTags(ps []demuxedPES) []byte {
	var tags []byte
	for _, p := range ps {
		tags = append(tags, pesTag(p))
	}
	return tags
}

// Several small PES fit in a single TS packet, and one of them straddles the
// packet boundary. Every PES must be returned, in order, with its own data.
func TestDemuxerNextDataMultiplePESPerPacket(t *testing.T) {
	var group []byte
	group = append(group, buildBoundedPES(0xc0, []byte{'A'})...)
	group = append(group, buildBoundedPES(0xc0, []byte{'B'})...)
	group = append(group, buildBoundedPES(0xc0, bytes.Repeat([]byte{'C'}, 160))...)
	group = append(group, buildBoundedPES(0xc0, []byte{'D'})...)
	group = append(group, buildBoundedPES(0xc0, []byte{'E'})...)
	require.Greater(t, len(group), MpegTsPacketSize)

	// A last PES on its own payload unit start, so the previous group is flushed
	// by the packet pool.
	next, _ := buildTSStream(0x101, 3, buildBoundedPES(0xc0, []byte{'F'}))

	ps, _ := buildTSStream(0x101, 0, group)
	b := concatTS(ps, next)

	pes, err := demuxPES(t, b)
	require.NoError(t, err)
	require.Len(t, pes, 6)
	assert.Equal(t, []byte("ABCDEF"), pesTags(pes))

	// Every PES must be complete: the payload bytes follow the header.
	assert.Len(t, pes[0].Data, 1)
	assert.Len(t, pes[2].Data, 160)
	assert.Equal(t, bytes.Repeat([]byte{'C'}, 160), pes[2].Data)

	// The PES starting in the first packet reports the first packet.
	assert.Equal(t, uint8(0), pes[0].CC)
	assert.Equal(t, uint8(0), pes[2].CC)
	// Those starting in the second, non-PUSI packet report it as well.
	assert.Equal(t, uint8(1), pes[3].CC)
	assert.Equal(t, uint8(1), pes[4].CC)
	assert.Equal(t, uint16(0x101), pes[0].PID)
}

// A PES packet split over several TS packets must be reassembled per PID even
// when packets of other PIDs are interleaved.
func TestDemuxerNextDataPESContinuesAcrossPacketsByPID(t *testing.T) {
	audio := buildBoundedPES(0xc0, bytes.Repeat([]byte{'A'}, 300))
	audioPS, _ := buildTSStream(0x101, 0, audio)
	require.Len(t, audioPS, 2)

	// Interleaved video PID, itself unbounded and continuing after the audio one.
	video := append([]byte{0, 0, 1, 0xe0, 0, 0, 0x80, 0x00, 0x00}, bytes.Repeat([]byte{'V'}, 400)...)
	videoPS, _ := buildTSStream(0x100, 0, video)
	require.Len(t, videoPS, 3)

	// Flush both PIDs at EOF.
	b := concatTS(audioPS[:1], videoPS[:1], audioPS[1:], videoPS[1:])

	pes, err := demuxPES(t, b)
	require.NoError(t, err)
	require.Len(t, pes, 2)
	assert.Equal(t, []byte{'A', 'V'}, pesTags(pes))
	assert.Len(t, pes[0].Data, 300)
	assert.Equal(t, bytes.Repeat([]byte{'A'}, 300), pes[0].Data)
	assert.Equal(t, uint16(0x101), pes[0].PID)
	assert.Len(t, pes[1].Data, 400)
	assert.Equal(t, uint16(0x100), pes[1].PID)
}

// An unknown PES packet length (0) is closed by the next payload unit start.
func TestDemuxerNextDataUnknownLengthPESEndsAtPUSI(t *testing.T) {
	unbounded := append([]byte{0, 0, 1, 0xe0, 0x00, 0x00, 0x80, 0x00, 0x00}, bytes.Repeat([]byte{'V'}, 250)...)
	unboundedPS, cc := buildTSStream(0x100, 0, unbounded)

	b := concatTS(unboundedPS, func() [][]byte {
		ps, _ := buildTSStream(0x100, cc, buildBoundedPES(0xe0, []byte{'W'}))
		return ps
	}())

	pes, err := demuxPES(t, b)
	require.NoError(t, err)
	require.Len(t, pes, 2)
	assert.Equal(t, uint16(0), pes[0].PacketLength)
	assert.Equal(t, bytes.Repeat([]byte{'V'}, 250), pes[0].Data)
	assert.Equal(t, []byte("VW"), pesTags(pes))
}

// An unknown PES packet length (0) is closed by the next payload unit start, so
// the rest of the payload belongs to it, even if it looks like other PES packets.
func TestDemuxerNextDataUnknownLengthPESAbsorbsRest(t *testing.T) {
	unbounded := append([]byte{0, 0, 1, 0xe0, 0x00, 0x00, 0x80, 0x00, 0x00}, bytes.Repeat([]byte{'V'}, 250)...)
	unbounded = append(unbounded, buildBoundedPES(0xe0, []byte{'Z'})...)

	ps, _ := buildTSStream(0x100, 0, unbounded)
	pes, err := demuxPES(t, concatTS(ps))
	require.NoError(t, err)
	require.Len(t, pes, 1)
	assert.Equal(t, uint16(0), pes[0].PacketLength)
	// The data of the unknown-length PES runs to the end of the payload, including
	// the bytes that look like another PES packet.
	expected := append(bytes.Repeat([]byte{'V'}, 250), buildBoundedPES(0xe0, []byte{'Z'})...)
	assert.Equal(t, expected, pes[0].Data)
}

// A truncated PES tail is dropped without an error, and doesn't prevent the
// complete PES packets of the group from being returned.
func TestDemuxerNextDataTruncatedPESTailDropped(t *testing.T) {
	group := append(buildBoundedPES(0xc0, []byte{'A'}), []byte{0, 0, 1, 0xc0, 0x00, 0x40, 0x80}...)
	require.Less(t, len(group), MpegTsPacketSize)

	ps, _ := buildTSStream(0x101, 0, group)
	pes, err := demuxPES(t, concatTS(ps))
	require.NoError(t, err)
	require.Len(t, pes, 1)
	assert.Equal(t, []byte{'A'}, pes[0].Data)

	// A group made only of a truncated tail yields no data and no error.
	ps, _ = buildTSStream(0x101, 0, []byte{0, 0, 1, 0xc0, 0x00, 0x40, 0x80})
	pes, err = demuxPES(t, concatTS(ps))
	require.NoError(t, err)
	assert.Empty(t, pes)
}

// parseData splits the group it is given without needing a demuxer.
func TestParseDataMultiplePES(t *testing.T) {
	payload := append(buildBoundedPES(0xc0, []byte{'A'}), buildBoundedPES(0xc0, []byte{'B'})...)
	ps := []*Packet{
		{Header: PacketHeader{PID: 0x101, PayloadUnitStartIndicator: true}, Payload: payload},
	}

	ds, err := parseData(ps, nil, newProgramMap(), newElementaryStreamMap())
	require.NoError(t, err)
	require.Len(t, ds, 2)
	assert.Equal(t, []byte{'A'}, ds[0].PES.Data)
	assert.Equal(t, []byte{'B'}, ds[1].PES.Data)
	assert.Equal(t, uint16(0x101), ds[0].PID)
	assert.Equal(t, ps[0].Header, ds[0].FirstPacket.Header)
	assert.Equal(t, ps[0].Header, ds[1].FirstPacket.Header)
}

// A payload that begins mid-PES cannot be credited to any PES packet.
func TestParseDataPESPayloadNotStartingWithPES(t *testing.T) {
	ps := []*Packet{
		{Header: PacketHeader{PID: 0x101}, Payload: []byte{0xff, 0xff, 0xff}},
	}
	ds, err := parseData(ps, nil, newProgramMap(), newElementaryStreamMap())
	require.NoError(t, err)
	assert.Empty(t, ds)
}

// Rewound demuxer must not keep any PES state.
func TestDemuxerRewindClearsPESState(t *testing.T) {
	group := append(buildBoundedPES(0xc0, []byte{'A'}), []byte{0, 0, 1, 0xc0, 0x00, 0x40, 0x80}...)
	ps, _ := buildTSStream(0x101, 0, group)
	b := concatTS(ps)

	dmx := NewDemuxer(context.Background(), bytes.NewReader(b), DemuxerOptPacketSize(MpegTsPacketSize))

	d, err := dmx.NextData()
	require.NoError(t, err)
	assert.Equal(t, []byte{'A'}, d.PES.Data)

	_, err = dmx.Rewind()
	require.NoError(t, err)
	require.Empty(t, dmx.dataBuffer)
	require.Empty(t, dmx.packetPool.b)

	d, err = dmx.NextData()
	require.NoError(t, err)
	assert.Equal(t, []byte{'A'}, d.PES.Data)
	_, err = dmx.NextData()
	assert.EqualError(t, err, ErrNoMorePackets.Error())
}

// The start code prefix of the next PES packet may be split across the packet
// boundary: the accumulator must wait for the next packet instead of dropping it.
func TestDemuxerNextDataPESPrefixSplitAcrossPackets(t *testing.T) {
	// Two PES of 181 bytes: the second one starts exactly at the second packet's
	// payload boundary, so its bytes are split 181/3 and 3/181.
	var group []byte
	for _, tag := range []byte{'A', 'B'} {
		group = append(group, buildBoundedPES(0xc0, bytes.Repeat([]byte{tag}, 172))...)
	}
	require.Len(t, group, 362)

	// Build the packets by hand: the first packet carries all 181 bytes of the first
	// PES plus the first byte only of the second one's start code prefix.
	ps := [][]byte{
		buildTSPacket(0x101, 0, true, group[:182]),
		buildTSPacket(0x101, 1, false, group[182:]),
	}

	pes, err := demuxPES(t, concatTS(ps))
	require.NoError(t, err)
	require.Len(t, pes, 2)
	assert.Equal(t, []byte{'A', 'B'}, pesTags(pes))
	assert.Len(t, pes[0].Data, 172)
	assert.Len(t, pes[1].Data, 172)
}

// A group that ends exactly on a PES boundary is flushed as soon as it is
// complete. When it contains several PES packets, the demuxer must still return
// all of them, one NextData call at a time.
func TestDemuxerNextDataGroupFlushedOnCompleteBoundary(t *testing.T) {
	group := append(buildBoundedPES(0xc0, []byte{'A'}), buildBoundedPES(0xc0, []byte{'B'})...)
	require.Less(t, len(group), MpegTsPacketSize)

	ps, _ := buildTSStream(0x101, 0, group)
	b := concatTS(ps)

	dmx := NewDemuxer(context.Background(), bytes.NewReader(b), DemuxerOptPacketSize(MpegTsPacketSize))
	d, err := dmx.NextData()
	require.NoError(t, err)
	assert.Equal(t, []byte{'A'}, d.PES.Data)
	d, err = dmx.NextData()
	require.NoError(t, err)
	assert.Equal(t, []byte{'B'}, d.PES.Data)
	_, err = dmx.NextData()
	assert.EqualError(t, err, ErrNoMorePackets.Error())
}

// A PES packet continuing in the next TS packet must not be flushed early even
// when the bytes received so far end on a byte that looks like a PES boundary.
func TestDemuxerNextDataNoPrematureFlush(t *testing.T) {
	pes := buildBoundedPES(0xc0, bytes.Repeat([]byte{'A'}, 400))
	ps, _ := buildTSStream(0x101, 0, pes)
	require.Len(t, ps, 3)

	pesData, err := demuxPES(t, concatTS(ps))
	require.NoError(t, err)
	require.Len(t, pesData, 1)
	assert.Len(t, pesData[0].Data, 400)
}

// The audio streams of the repository test data are made of small PES packets.
func TestDemuxerNextDataSilentAudio(t *testing.T) {
	b, err := os.ReadFile("testdata/ts/silent_audio.ts")
	require.NoError(t, err)

	pes, err := demuxPES(t, b)
	require.NoError(t, err)
	require.Len(t, pes, 2)
	assert.Equal(t, uint16(0x101), pes[0].PID)
	assert.Equal(t, uint8(0xc0), pes[0].StreamID)
	assert.Equal(t, uint16(38), pes[0].PacketLength)
	assert.Len(t, pes[0].Data, 30)
	assert.Equal(t, uint16(21), pes[1].PacketLength)
	assert.Len(t, pes[1].Data, 13)
}
