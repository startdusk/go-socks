package socks

import (
	"io"
)

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

type ClientPasswordMsg struct {
	Username string
	Password string
}

type Method = byte

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)

const PasswordMethodVersion = 0x01

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

func NewClientPasswordMsg(conn io.Reader) (*ClientPasswordMsg, error) {
	// Read version and username length
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	version, usernameLen := buf[0], buf[1]
	if version != PasswordMethodVersion {
		return nil, ErrMethodVersionNotSupported
	}

	// Read username, password length
	buf = make([]byte, usernameLen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	username, passwordLen := string(buf[:len(buf)-1]), buf[len(buf)-1]

	// Read password
	if len(buf) < int(passwordLen) {
		buf = make([]byte, passwordLen)
	}
	if _, err := io.ReadFull(conn, buf[:passwordLen]); err != nil {
		return nil, err
	}

	return &ClientPasswordMsg{
		Username: username,
		Password: string(buf[:passwordLen]),
	}, nil
}
