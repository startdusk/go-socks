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

const (
	PasswordMethodVersion = 0x01
	PasswordAuthSuccess   = 0x00
	PasswordAuthFailure   = 0x01
)

// The client connects to the server, and sends a version
// identifier/method selection message:
//
//         +----+----------+----------+
//         |VER | NMETHODS | METHODS  |
//         +----+----------+----------+
//         | 1  |    1     | 1 to 255 |
//         +----+----------+----------+
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
	//
	// METHODS 1 to 255
	// uint8 is the set of all unsigned 8-bit integers. Range: 0 through 255.
	nmethods := buf[1]
	if nmethods == 0 {
		return nil, ErrMethodsLengthZero
	}
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

// Once the SOCKS V5 server has started, and the client has selected the
// Username/Password Authentication protocol, the Username/Password
// subnegotiation begins.  This begins with the client producing a
// Username/Password request:
//
//         +----+------+----------+------+----------+
//         |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//         +----+------+----------+------+----------+
//         | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//         +----+------+----------+------+----------+
func NewClientPasswordMsg(conn io.Reader) (*ClientPasswordMsg, error) {
	// Read version and username length
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	version, usernameLen := buf[0], buf[1]
	if version != PasswordMethodVersion {
		return nil, ErrMethodVersionNotSupported
	}

	// UNAME 1 to 255
	// uint8 is the set of all unsigned 8-bit integers. Range: 0 through 255.
	if usernameLen == 0 {
		return nil, ErrUsernameLengthZero
	}

	// Read username, password
	buf = make([]byte, int(usernameLen)+1)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	username, passwordLen := string(buf[:len(buf)-1]), buf[len(buf)-1]

	// PASSWD 1 to 255
	// uint8 is the set of all unsigned 8-bit integers. Range: 0 through 255.
	if passwordLen == 0 {
		return nil, ErrPasswordLengthZero
	}

	// Read password
	if len(buf) < int(passwordLen) {
		buf = make([]byte, passwordLen)
	}
	_, err = io.ReadFull(conn, buf[:passwordLen])
	if err != nil {
		return nil, err
	}

	return &ClientPasswordMsg{
		Username: username,
		Password: string(buf[:passwordLen]),
	}, nil
}

func WriteSrvPasswordMsg(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{PasswordMethodVersion, status})
	return err
}
