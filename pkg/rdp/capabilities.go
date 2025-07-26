















package rdp

import (
	"bytes"
	"encoding/binary"
)


func buildConfirmActivePDU(shareID uint32) ([]byte, error) {
	capsBuf := new(bytes.Buffer)

	
	addGeneralCapabilitySet(capsBuf)
	addBitmapCapabilitySet(capsBuf)
	addOrderCapabilitySet(capsBuf)
	addPointerCapabilitySet(capsBuf)

	capsData := capsBuf.Bytes()

	
	pdu := new(bytes.Buffer)
	binary.Write(pdu, binary.LittleEndian, shareID)
	binary.Write(pdu, binary.LittleEndian, uint16(1002)) 
	binary.Write(pdu, binary.LittleEndian, uint16(4))    
	binary.Write(pdu, binary.LittleEndian, uint16(len(capsData)))
	pdu.WriteString("RDP\x00")
	binary.Write(pdu, binary.LittleEndian, uint16(4)) 
	binary.Write(pdu, binary.LittleEndian, uint16(0)) 
	pdu.Write(capsData)

	
	finalPDU := new(bytes.Buffer)
	pduBytes := pdu.Bytes()
	totalLength := uint16(len(pduBytes) + 6)
	binary.Write(finalPDU, binary.LittleEndian, totalLength)
	binary.Write(finalPDU, binary.LittleEndian, uint16(PDUTYPE_CONFIRMACTIVEPDU|0x10))
	binary.Write(finalPDU, binary.LittleEndian, uint16(1002)) 
	finalPDU.Write(pduBytes)

	return finalPDU.Bytes(), nil
}


func addGeneralCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_GENERAL))
	binary.Write(buf, binary.LittleEndian, uint16(24))     
	binary.Write(buf, binary.LittleEndian, uint16(1))      
	binary.Write(buf, binary.LittleEndian, uint16(3))      
	binary.Write(buf, binary.LittleEndian, uint16(0x0200)) 
	buf.Write(make([]byte, 14))                            
}


func addBitmapCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_BITMAP))
	binary.Write(buf, binary.LittleEndian, uint16(28))   
	binary.Write(buf, binary.LittleEndian, uint16(24))   
	binary.Write(buf, binary.LittleEndian, uint16(1))    
	binary.Write(buf, binary.LittleEndian, uint16(1))    
	binary.Write(buf, binary.LittleEndian, uint16(1))    
	binary.Write(buf, binary.LittleEndian, uint16(1024)) 
	binary.Write(buf, binary.LittleEndian, uint16(768))  
	buf.Write(make([]byte, 2))                           
	binary.Write(buf, binary.LittleEndian, uint16(1))    
	binary.Write(buf, binary.LittleEndian, uint16(1))    
	buf.Write(make([]byte, 8))                           
}


func addOrderCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_ORDER))
	binary.Write(buf, binary.LittleEndian, uint16(88)) 
	buf.Write(make([]byte, 84))                        
}


func addPointerCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_POINTER))
	binary.Write(buf, binary.LittleEndian, uint16(10)) 
	binary.Write(buf, binary.LittleEndian, uint16(1))  
	binary.Write(buf, binary.LittleEndian, uint16(20)) 
	binary.Write(buf, binary.LittleEndian, uint16(20)) 
}
