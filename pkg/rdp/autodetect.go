package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

type AutoDetectManager struct {
	client              *Client
	rttEnabled          bool
	bandwidthEnabled    bool
	lastRTTSequence     uint16
	lastBWSequence      uint16
	connectionStartTime time.Time
	networkCharResults  NetworkCharacteristics
}

type NetworkCharacteristics struct {
	BaseRTT          time.Duration
	AverageRTT       time.Duration
	BandwidthKbps    uint32
	LastMeasuredTime time.Time
}

func NewAutoDetectManager(client *Client) *AutoDetectManager {
	return &AutoDetectManager{
		client:              client,
		connectionStartTime: time.Now(),
	}
}

func buildAutoDetectRequestPDU(headerType uint16, sequenceNumber uint16, payload []byte) []byte {
	var buf bytes.Buffer

	shareDataHeader := make([]byte, 18)
	binary.LittleEndian.PutUint32(shareDataHeader[0:], 0)
	binary.LittleEndian.PutUint16(shareDataHeader[4:], PDUTYPE_DATAPDU|0x10)
	binary.LittleEndian.PutUint16(shareDataHeader[6:], 0)
	binary.LittleEndian.PutUint32(shareDataHeader[8:], 0)
	shareDataHeader[12] = 0
	shareDataHeader[13] = 1
	binary.LittleEndian.PutUint16(shareDataHeader[14:], uint16(len(payload)+8))
	shareDataHeader[16] = PDUTYPE2_AUTODETECT_REQUEST
	shareDataHeader[17] = 0

	buf.Write(shareDataHeader)

	binary.Write(&buf, binary.LittleEndian, headerType)
	binary.Write(&buf, binary.LittleEndian, sequenceNumber)
	binary.Write(&buf, binary.LittleEndian, uint16(len(payload)))

	if payload != nil {
		buf.Write(payload)
	}

	result := buf.Bytes()
	binary.LittleEndian.PutUint32(result[0:], uint32(len(result)))

	return result
}

func (adm *AutoDetectManager) buildRTTMeasureRequest(sequenceNumber uint16) []byte {
	return buildAutoDetectRequestPDU(RDP_RTT_REQUEST_TYPE_CONNECTTIME, sequenceNumber, nil)
}

func (adm *AutoDetectManager) buildBandwidthMeasureStart(sequenceNumber uint16) []byte {
	return buildAutoDetectRequestPDU(RDP_BW_START_TYPE_CONNECTTIME, sequenceNumber, nil)
}

func (adm *AutoDetectManager) buildBandwidthMeasurePayload(sequenceNumber uint16, payloadLength uint16) []byte {

	payload := make([]byte, payloadLength)
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	return buildAutoDetectRequestPDU(RDP_BW_PAYLOAD, sequenceNumber, payload)
}

func (adm *AutoDetectManager) buildBandwidthMeasureStop(sequenceNumber uint16, payloadLength uint16) []byte {
	payload := make([]byte, 2)
	binary.LittleEndian.PutUint16(payload, payloadLength)
	return buildAutoDetectRequestPDU(RDP_BW_STOP, sequenceNumber, payload)
}

func (adm *AutoDetectManager) parseAutoDetectResponse(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("auto-detect response too short")
	}

	headerType := binary.LittleEndian.Uint16(data[0:])
	sequenceNumber := binary.LittleEndian.Uint16(data[2:])
	responseLength := binary.LittleEndian.Uint16(data[4:])

	if len(data) < int(6+responseLength) {
		return fmt.Errorf("auto-detect response length mismatch")
	}

	responseData := data[6 : 6+responseLength]

	switch headerType {
	case RDP_RTT_RESPONSE:

		adm.handleRTTResponse(sequenceNumber)

	case RDP_BW_RESULTS:

		if len(responseData) >= 8 {
			timeDelta := binary.LittleEndian.Uint32(responseData[0:])
			byteCount := binary.LittleEndian.Uint32(responseData[4:])
			adm.handleBandwidthResults(timeDelta, byteCount)
		}

	case RDP_NETCHAR_SYNC:

		if len(responseData) >= 8 {
			bandwidth := binary.LittleEndian.Uint32(responseData[0:])
			rtt := binary.LittleEndian.Uint32(responseData[4:])
			adm.handleNetworkCharSync(bandwidth, rtt)
		}
	}

	return nil
}

func (adm *AutoDetectManager) handleRTTResponse(sequenceNumber uint16) {
	if sequenceNumber == adm.lastRTTSequence {

		fmt.Printf("Received RTT response for sequence %d\n", sequenceNumber)
	}
}

func (adm *AutoDetectManager) handleBandwidthResults(timeDelta uint32, byteCount uint32) {
	if timeDelta > 0 {

		bandwidthKbps := (byteCount * 8 * 1000) / timeDelta
		adm.networkCharResults.BandwidthKbps = bandwidthKbps
		adm.networkCharResults.LastMeasuredTime = time.Now()
		fmt.Printf("Measured bandwidth: %d Kbps\n", bandwidthKbps)
	}
}

func (adm *AutoDetectManager) handleNetworkCharSync(bandwidth uint32, rtt uint32) {
	adm.networkCharResults.BandwidthKbps = bandwidth
	adm.networkCharResults.BaseRTT = time.Duration(rtt) * time.Millisecond
	adm.networkCharResults.AverageRTT = adm.networkCharResults.BaseRTT
	fmt.Printf("Network characteristics: Bandwidth=%d Kbps, RTT=%d ms\n", bandwidth, rtt)
}

func (adm *AutoDetectManager) StartConnectionTimeDetection() error {

	adm.lastRTTSequence++
	rttPDU := adm.buildRTTMeasureRequest(adm.lastRTTSequence)
	if err := adm.client.sendEncryptedPDU(rttPDU); err != nil {
		return fmt.Errorf("failed to send RTT request: %w", err)
	}

	adm.lastBWSequence++

	startPDU := adm.buildBandwidthMeasureStart(adm.lastBWSequence)
	if err := adm.client.sendEncryptedPDU(startPDU); err != nil {
		return fmt.Errorf("failed to send bandwidth start: %w", err)
	}

	payloadSize := uint16(8192)
	for i := 0; i < 2; i++ {
		adm.lastBWSequence++
		payloadPDU := adm.buildBandwidthMeasurePayload(adm.lastBWSequence, payloadSize)
		if err := adm.client.sendEncryptedPDU(payloadPDU); err != nil {
			return fmt.Errorf("failed to send bandwidth payload: %w", err)
		}
	}

	adm.lastBWSequence++
	stopPDU := adm.buildBandwidthMeasureStop(adm.lastBWSequence, payloadSize)
	if err := adm.client.sendEncryptedPDU(stopPDU); err != nil {
		return fmt.Errorf("failed to send bandwidth stop: %w", err)
	}

	return nil
}
