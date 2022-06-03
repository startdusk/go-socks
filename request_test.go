package socks

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestNewClientRequestMsg(t *testing.T) {
	cases := []struct {
		name      string
		version   byte
		rsv       byte
		cmd       Command
		addrType  AddressType
		addr      []byte
		port      []byte
		expectMsg ClientRequestMsg
		err       error
		wantErr   bool
	}{
		{
			name:     "normal_success",
			version:  SOCKS5Version,
			rsv:      ReservedField,
			cmd:      CmdBind,
			addrType: IPv4Addr,
			addr:     []byte{192, 168, 168, 201},
			port:     []byte{0x00, 0x80},
			expectMsg: ClientRequestMsg{
				Command:  CmdBind,
				AddrType: IPv4Addr,
				Address:  "192.168.168.201",
				Port:     0x80,
			},
			wantErr: false,
		},
		{
			name:     "invalid_version",
			version:  0x00,
			rsv:      ReservedField,
			cmd:      CmdBind,
			addrType: IPv4Addr,
			addr:     []byte{192, 168, 168, 201},
			port:     []byte{0x00, 0x80},
			expectMsg: ClientRequestMsg{
				Command: CmdBind,
				Address: "192.168.168.201",
				Port:    0x80,
			},
			err:     ErrVersionNotSupported,
			wantErr: true,
		},
		{
			name:     "invalid_rsv",
			version:  SOCKS5Version,
			rsv:      0x10,
			cmd:      CmdBind,
			addrType: IPv4Addr,
			addr:     []byte{192, 168, 168, 201},
			port:     []byte{0x00, 0x80},
			expectMsg: ClientRequestMsg{
				Command: CmdBind,
				Address: "192.168.168.201",
				Port:    0x80,
			},
			err:     ErrInvalidReservedField,
			wantErr: true,
		},
		{
			name:     "invalid_addr_type",
			version:  SOCKS5Version,
			rsv:      ReservedField,
			cmd:      CmdBind,
			addrType: 0,
			addr:     []byte{192, 168, 168, 201},
			port:     []byte{0x00, 0x80},
			expectMsg: ClientRequestMsg{
				Command: CmdBind,
				Address: "192.168.168.201",
				Port:    0x80,
			},
			err:     ErrAddrTypeNotSupported,
			wantErr: true,
		},
		{
			name:     "invalid_command",
			version:  SOCKS5Version,
			rsv:      ReservedField,
			cmd:      0x00,
			addrType: IPv4Addr,
			addr:     []byte{192, 168, 168, 201},
			port:     []byte{0x00, 0x80},
			expectMsg: ClientRequestMsg{
				Command: CmdBind,
				Address: "192.168.168.201",
				Port:    0x80,
			},
			err:     ErrCommandNotSupported,
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			buf.Write([]byte{c.version, c.cmd, c.rsv, c.addrType})
			buf.Write(c.addr)
			buf.Write(c.port)

			msg, err := NewClientRequestMsg(&buf)
			if c.wantErr && err != c.err {
				t.Fatalf("expected want error %v but got %v", c.err, err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected want nil but got error: %+v", err)
			}

			if c.wantErr {
				return
			}

			if msg.Command != c.expectMsg.Command {
				t.Fatalf("expected command %v but got %v", c.expectMsg.Command, msg.Command)
			}
			if msg.AddrType != c.expectMsg.AddrType {
				t.Fatalf("expected address type %v but got %v", c.expectMsg.AddrType, msg.AddrType)
			}
			if msg.Address != c.expectMsg.Address {
				t.Fatalf("expected address %v but got %v", c.expectMsg.Address, msg.Address)
			}
			if msg.Port != c.expectMsg.Port {
				t.Fatalf("expected port %v but got %v", c.expectMsg.Port, msg.Port)
			}
		})
	}
}

func TestWriteReqSuccessMsg(t *testing.T) {
	cases := []struct {
		name      string
		ip        net.IP
		port      uint16
		expectMsg []byte
		wantErr   bool
	}{
		{
			name:      "normal_success",
			ip:        net.IP([]byte{123, 123, 11, 11}),
			port:      1081,
			expectMsg: []byte{SOCKS5Version, ReplySucceeded, ReservedField, IPv4Addr, 123, 123, 11, 11, 0x04, 0x39},
			wantErr:   false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteReqSuccessMsg(&buf, c.ip, c.port)
			if c.wantErr && err == nil {
				t.Fatalf("expected want error but got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected want nil but got error: %+v", err)
			}

			if c.wantErr {
				return
			}

			got := buf.Bytes()
			if !reflect.DeepEqual(c.expectMsg, got) {
				t.Fatalf("expected message %v but got %v", c.expectMsg, got)
			}
		})
	}
}

func FuzzNewClientRequestMsg(f *testing.F) {
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		NewClientRequestMsg(bytes.NewReader(data))
	})
}

func FuzzWriteReqSuccessMsg(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Fuzz(func(t *testing.T, ip []byte, port uint16) {
		var buf bytes.Buffer
		WriteReqSuccessMsg(&buf, net.IP(ip), port)
	})
}
