















package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)



type HeartbeatManager struct {
	client            *Client
	enabled           bool
	period            time.Duration
	lastHeartbeatTime time.Time
	missedHeartbeats  int
	maxMissedHeartbeats int
	mu                sync.Mutex
	stopChan          chan struct{}
	running           bool
}


func NewHeartbeatManager(client *Client) *HeartbeatManager {
	return &HeartbeatManager{
		client:              client,
		period:              30 * time.Second, 
		maxMissedHeartbeats: 3,               
		stopChan:            make(chan struct{}),
	}
}



func buildHeartbeatPDU() []byte {
	var buf bytes.Buffer
	
	
	shareDataHeader := make([]byte, 18)
	binary.LittleEndian.PutUint32(shareDataHeader[0:], 22) 
	binary.LittleEndian.PutUint16(shareDataHeader[4:], PDUTYPE_DATAPDU|0x10) 
	binary.LittleEndian.PutUint16(shareDataHeader[6:], 0) 
	binary.LittleEndian.PutUint32(shareDataHeader[8:], 0) 
	shareDataHeader[12] = 0 
	shareDataHeader[13] = 1 
	binary.LittleEndian.PutUint16(shareDataHeader[14:], 4) 
	shareDataHeader[16] = PDUTYPE2_HEARTBEAT 
	shareDataHeader[17] = 0 
	
	buf.Write(shareDataHeader)
	
	
	
	heartbeatData := []byte{0, 0, 0, 0}
	buf.Write(heartbeatData)
	
	return buf.Bytes()
}


func (hm *HeartbeatManager) Start() error {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	if hm.running {
		return fmt.Errorf("heartbeat manager already running")
	}
	
	hm.running = true
	hm.enabled = true
	
	
	go hm.heartbeatLoop()
	
	return nil
}


func (hm *HeartbeatManager) Stop() {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	if !hm.running {
		return
	}
	
	hm.running = false
	hm.enabled = false
	close(hm.stopChan)
}


func (hm *HeartbeatManager) heartbeatLoop() {
	ticker := time.NewTicker(hm.period)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if err := hm.sendHeartbeat(); err != nil {
				fmt.Printf("Failed to send heartbeat: %v\n", err)
				hm.mu.Lock()
				hm.missedHeartbeats++
				if hm.missedHeartbeats >= hm.maxMissedHeartbeats {
					fmt.Printf("Too many missed heartbeats (%d), connection may be dead\n", hm.missedHeartbeats)
					hm.mu.Unlock()
					
					return
				}
				hm.mu.Unlock()
			} else {
				hm.mu.Lock()
				hm.missedHeartbeats = 0
				hm.lastHeartbeatTime = time.Now()
				hm.mu.Unlock()
			}
			
		case <-hm.stopChan:
			return
		}
	}
}


func (hm *HeartbeatManager) sendHeartbeat() error {
	if !hm.enabled {
		return nil
	}
	
	heartbeatPDU := buildHeartbeatPDU()
	if err := hm.client.sendEncryptedPDU(heartbeatPDU); err != nil {
		return fmt.Errorf("failed to send heartbeat PDU: %w", err)
	}
	
	return nil
}


func (hm *HeartbeatManager) SetPeriod(period time.Duration) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.period = period
}


func (hm *HeartbeatManager) GetLastHeartbeatTime() time.Time {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	return hm.lastHeartbeatTime
}


func (hm *HeartbeatManager) IsHealthy() bool {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	
	if !hm.enabled {
		return true 
	}
	
	
	if hm.missedHeartbeats >= hm.maxMissedHeartbeats {
		return false
	}
	
	
	if time.Since(hm.lastHeartbeatTime) > hm.period*time.Duration(hm.maxMissedHeartbeats) {
		return false
	}
	
	return true
}




func (hm *HeartbeatManager) HandleHeartbeatResponse(data []byte) error {
	
	
	return nil
}