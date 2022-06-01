package socks

import (
	"io"
)

func NewClientAuthMsg(conn io.Reader) (*ClientAuthMsg, error) {
	// Read Version and NMethods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	// Validate version
	if buf[0] != SOCKS5Version {
		return nil, ErrVersionNotSupported
	}

	// Read Methods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return &ClientAuthMsg{
		Version:  SOCKS5Version,
		NMethods: nmethods,
		Methods:  buf,
	}, nil
}

func NewServerAuthMsg(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	return err
}

type ClientAuthMsg struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

func (c ClientAuthMsg) ContainsMethod(method Method) bool {
	for _, m := range c.Methods {
		if m == method {
			return true
		}
	}
	return false
}

type Method = byte

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)
