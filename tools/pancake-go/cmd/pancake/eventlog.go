// eventlog.go: TCG event log parser used by `pancake attest` to
// re-derive PCR 11 (and any other PCR systemd-stub measures into).
//
// The kernel exposes the log at /sys/kernel/security/tpm0/binary_bios_measurements.
// Format (TCG PC Client Platform Firmware Profile):
//
//   record[0] = TCG_PCR_EVENT (legacy SHA-1 only):
//     uint32  pcrIndex
//     uint32  eventType
//     byte[20] sha1Digest
//     uint32  eventSize
//     byte[eventSize] event              // for record 0, a Spec ID Event
//
//   record[1..] = TCG_PCR_EVENT2:
//     uint32  pcrIndex
//     uint32  eventType
//     // TPML_DIGEST_VALUES:
//     uint32  count
//     for each: uint16 hashAlg + bytes[len(alg)] digest
//     uint32  eventSize
//     byte[eventSize] event
//
// We only care about the SHA-256 digests for our chosen PCR. Replay
// (sha256(prev || measurement)) for each, compare against the live
// PCR value the TPM reported in the quote. Match → log is authentic
// and pinpoints which content extended the PCR.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	algSHA1   uint16 = 0x0004
	algSHA256 uint16 = 0x000B
	algSHA384 uint16 = 0x000C
	algSHA512 uint16 = 0x000D
)

func algSize(a uint16) int {
	switch a {
	case algSHA1:
		return 20
	case algSHA256:
		return 32
	case algSHA384:
		return 48
	case algSHA512:
		return 64
	}
	return 0
}

// eventLogEntry is one parsed measurement: which PCR was extended,
// the SHA-256 digest used, an event-type tag, and the raw event
// payload (typically a UTF-16 / ASCII description of what was
// measured — useful for human-readable reporting).
type eventLogEntry struct {
	PCR       uint32
	EventType uint32
	SHA256    []byte
	Event     []byte
}

// parseEventLog walks the binary log. Returns the parsed entries
// (skipping the legacy SHA-1-only header record); errors only on
// truncation/malformed records, not on unknown algorithms (those
// are skipped silently).
func parseEventLog(buf []byte) ([]eventLogEntry, error) {
	if len(buf) < 32 {
		return nil, fmt.Errorf("event log too short (%d bytes)", len(buf))
	}
	r := bytes.NewReader(buf)

	// Skip the legacy header record (TCG_PCR_EVENT). It carries the
	// Spec ID event in its payload (telling us which digest algos
	// follow) — we don't strictly need to parse it for sha256-only
	// pancake-os, just advance past it.
	var hdrPCR, hdrType uint32
	var hdrSHA1 [20]byte
	var hdrSize uint32
	if err := binary.Read(r, binary.LittleEndian, &hdrPCR); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &hdrType); err != nil {
		return nil, err
	}
	if _, err := r.Read(hdrSHA1[:]); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &hdrSize); err != nil {
		return nil, err
	}
	if _, err := r.Seek(int64(hdrSize), 1); err != nil {
		return nil, err
	}

	var out []eventLogEntry
	for r.Len() > 0 {
		var pcr, etyp, count uint32
		if err := binary.Read(r, binary.LittleEndian, &pcr); err != nil {
			return out, err
		}
		if err := binary.Read(r, binary.LittleEndian, &etyp); err != nil {
			return out, err
		}
		if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
			return out, err
		}
		var sha256Digest []byte
		for i := uint32(0); i < count; i++ {
			var alg uint16
			if err := binary.Read(r, binary.LittleEndian, &alg); err != nil {
				return out, err
			}
			sz := algSize(alg)
			if sz == 0 {
				return out, fmt.Errorf("unknown alg 0x%x in event %d", alg, i)
			}
			d := make([]byte, sz)
			if _, err := r.Read(d); err != nil {
				return out, err
			}
			if alg == algSHA256 {
				sha256Digest = d
			}
		}
		var eSize uint32
		if err := binary.Read(r, binary.LittleEndian, &eSize); err != nil {
			return out, err
		}
		event := make([]byte, eSize)
		if _, err := r.Read(event); err != nil {
			return out, err
		}
		if sha256Digest != nil {
			out = append(out, eventLogEntry{
				PCR:       pcr,
				EventType: etyp,
				SHA256:    sha256Digest,
				Event:     event,
			})
		}
	}
	return out, nil
}

// replayPCR returns the value of `pcr` derived by extending sha256
// from a 32-byte zero seed using every event-log entry tagged for
// that PCR. Matches what the TPM would compute live.
func replayPCR(entries []eventLogEntry, pcr uint32) []byte {
	cur := make([]byte, 32)
	for _, e := range entries {
		if e.PCR != pcr {
			continue
		}
		buf := make([]byte, 0, 64)
		buf = append(buf, cur...)
		buf = append(buf, e.SHA256...)
		h := sha256.Sum256(buf)
		cur = h[:]
	}
	return cur
}

// summarizeEntries returns a short human-readable string per entry
// for `pancake attest` to print. systemd-stub events tend to encode
// the section name (e.g. ".linux", ".initrd") as ASCII or UTF-16LE
// in the event payload — we strip control/non-printable bytes to
// produce something operators can eyeball.
func summarizeEntries(entries []eventLogEntry, pcr uint32) []string {
	var out []string
	for i, e := range entries {
		if e.PCR != pcr {
			continue
		}
		out = append(out, fmt.Sprintf("  [%2d] PCR%d type=0x%X sha256=%x… event=%q",
			i, e.PCR, e.EventType, e.SHA256[:8], shrinkEvent(e.Event)))
	}
	return out
}

// shrinkEvent collapses NUL-separated UTF-16-LE-ish names from
// systemd-stub event payloads into a printable ASCII guess. Best
// effort — if we can't decode, return a hex preview.
func shrinkEvent(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == 0 {
			continue
		}
		if c < 0x20 || c > 0x7E {
			// Bail to hex preview if there's anything weird.
			max := 16
			if len(b) < max {
				max = len(b)
			}
			return fmt.Sprintf("0x%x…", b[:max])
		}
		sb.WriteByte(c)
		if sb.Len() > 64 {
			sb.WriteString("…")
			break
		}
	}
	return sb.String()
}
