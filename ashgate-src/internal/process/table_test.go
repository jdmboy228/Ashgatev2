package process

import (
	"encoding/binary"
	"testing"
)

func TestPortFromDWORD(t *testing.T) {
	// Port 80 is stored as bytes 00 50 00 00, which is DWORD 0x00005000.
	if portFromDWORD(0x00005000) != 80 {
		t.Fatal(portFromDWORD(0x00005000))
	}
	// 443 is bytes 01 BB, stored little-endian as DWORD 0x0000BB01.
	if portFromDWORD(0x0000BB01) != 443 {
		t.Fatal(portFromDWORD(0x0000BB01))
	}
}

func TestParseTCP4(t *testing.T) {
	buf := make([]byte, 4+24)
	binary.LittleEndian.PutUint32(buf[0:4], 1)
	row := buf[4:]
	binary.LittleEndian.PutUint32(row[0:4], 5)           // established
	binary.LittleEndian.PutUint32(row[4:8], 0x0100007F)  // 127.0.0.1
	binary.LittleEndian.PutUint32(row[8:12], 0x00005000) // port 80
	binary.LittleEndian.PutUint32(row[20:24], 99)
	eps, err := ParseOwnerTable(buf, TableTCP4)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Addr.String() != "127.0.0.1:80" || eps[0].PID != 99 || eps[0].Proto != 6 {
		t.Fatalf("%+v", eps)
	}
}

func TestParseUDP4WildcardAndSkip(t *testing.T) {
	buf := make([]byte, 4+24)
	binary.LittleEndian.PutUint32(buf[0:4], 2)
	// Row 0: 0.0.0.0:53 pid 4.
	binary.LittleEndian.PutUint32(buf[4+4:4+8], 0x00003500)
	binary.LittleEndian.PutUint32(buf[4+8:4+12], 4)
	// Row 1: port 0 is ignored.
	binary.LittleEndian.PutUint32(buf[16+8:16+12], 5)
	eps, err := ParseOwnerTable(buf, TableUDP4)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || !eps[0].Unspecified || eps[0].Addr.Port != 53 || eps[0].PID != 4 || eps[0].Proto != 17 {
		t.Fatalf("%+v", eps)
	}
}

func TestParseTCP6(t *testing.T) {
	buf := make([]byte, 4+56)
	binary.LittleEndian.PutUint32(buf[0:4], 1)
	row := buf[4:]
	row[0] = 0x20
	row[1] = 0x01
	row[2] = 0x0d
	row[3] = 0xb8
	row[15] = 1
	binary.LittleEndian.PutUint32(row[20:24], 0x0000BB01) // port 443
	binary.LittleEndian.PutUint32(row[52:56], 7)
	eps, err := ParseOwnerTable(buf, TableTCP6)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Addr.String() != "[2001:db8::1]:443" || eps[0].PID != 7 {
		t.Fatalf("%+v", eps)
	}
}

func TestParseRejectsShortTable(t *testing.T) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:4], 3)
	if _, err := ParseOwnerTable(buf, TableUDP6); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParseOwnerTable(buf, TableKind(99)); err == nil {
		t.Fatal("expected error for unknown table kind")
	}
}
