package node

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const HeaderSize = 60
const MaxPacket = 1472

type Capabilities struct {
	Version        int   `json:"version"`
	UDPPort        int   `json:"udp_port"`
	HTTP3          bool  `json:"http3"`
	UDPNoFragment4 bool  `json:"udp_no_fragment_ipv4"`
	UDPNoFragment6 bool  `json:"udp_no_fragment_ipv6"`
	MaxBytes       int64 `json:"max_bytes"`
	MaxSeconds     int   `json:"max_seconds"`
	MaxStreams     int   `json:"max_streams"`
}

type SessionRequest struct {
	MaxBytes int64 `json:"max_bytes"`
	Seconds  int   `json:"seconds"`
}

type Session struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Expires  int64  `json:"expires"`
	MaxBytes int64  `json:"max_bytes"`
	UDPPort  int    `json:"udp_port"`
}

func Packet(id string, key []byte, seq uint64, size int) ([]byte, error) {
	if size < HeaderSize || size > MaxPacket {
		return nil, errors.New("invalid packet size")
	}
	identifier, err := hex.DecodeString(id)
	if err != nil || len(identifier) != 16 {
		return nil, errors.New("invalid session")
	}
	b := make([]byte, size)
	copy(b, "NDG1")
	copy(b[4:20], identifier)
	binary.BigEndian.PutUint64(b[20:28], seq)
	mac := hmac.New(sha256.New, key)
	mac.Write(b[:28])
	mac.Write(b[60:])
	copy(b[28:60], mac.Sum(nil))
	return b, nil
}

func VerifyPacket(b, key []byte) bool {
	if len(b) < HeaderSize || len(b) > MaxPacket || string(b[:4]) != "NDG1" {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b[:28])
	mac.Write(b[60:])
	return hmac.Equal(b[28:60], mac.Sum(nil))
}
