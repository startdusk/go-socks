package socks

import (
	"io"
	"net"
)

type ClientRequestMsg struct {
	Command Command
	Address string
	Port    uint16
}

type Command = byte

const (
	CmdConnect      Command = 0x01
	CmdBind         Command = 0x02
	CmdUDPAssociate Command = 0x03
)

type AddressType = byte

const (
	IPv4Addr   AddressType = 0x01
	DomainName AddressType = 0x03
	IPv6Addr   AddressType = 0x04
)

const (
	IPv4Len = 4
	IPv6Len = 6
	PortLen = 2
)

func NewClientRequestMsg(conn io.Reader) (*ClientRequestMsg, error) {
	// Read version, command, reserved, address type
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	version, command, reserved, addrType := buf[0], buf[1], buf[2], buf[3]

	// Check if the fields are valid
	if version != SOCKS5Version {
		return nil, ErrVersionNotSupported
	}
	if command != CmdBind && command != CmdConnect && command != CmdUDPAssociate {
		return nil, ErrCommandNotSupported
	}
	if reserved != ReservedField {
		return nil, ErrInvalidReservedField
	}
	if addrType != IPv4Addr && addrType != DomainName && addrType != IPv6Addr {
		return nil, ErrAddrTypeNotSupported
	}

	msg := ClientRequestMsg{
		Command: command,
	}

	// Read address
	switch addrType {
	case IPv6Addr:
		buf = make([]byte, IPv6Len)
		fallthrough
	case IPv4Addr:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		msg.Address = net.IP(buf).String()
	case DomainName:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		domainLen := buf[0]
		if domainLen > IPv4Len {
			buf = make([]byte, domainLen)
		}
		if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
			return nil, err
		}
		msg.Address = string(buf[:domainLen])
	}

	// Read port
	if _, err := io.ReadFull(conn, buf[:PortLen]); err != nil {
		return nil, err
	}
	msg.Port = (uint16(buf[0]) << 8) + uint16(buf[1])

	return &msg, nil
}
