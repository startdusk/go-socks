package socks

import (
	"errors"
	"io"
	"log"
	"net"
)

const (
	SOCKS5Version = 0x05
	ReservedField = 0x00
)

type Socks interface {
	Run() error
}

type Server struct {
	IP   string
	Port string
}

func (s *Server) Run() error {
	addr := net.JoinHostPort(s.IP, s.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Printf("connection failure from [%s]: %+v", conn.RemoteAddr(), err)
			continue
		}

		go func() {
			defer conn.Close()
			err := handleConn(conn)
			if err != nil {
				log.Printf("handle connection failure from [%s]: %+v", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConn(conn net.Conn) error {
	// 协商过程
	if err := auth(conn); err != nil {
		return err
	}

	// 请求过程
	_, err := request(conn)
	if err != nil {
		return err
	}

	// 转发过程
	return nil
}

func auth(conn io.ReadWriter) error {
	msg, err := NewClientAuthMsg(conn)
	if err != nil {
		return err
	}

	// Only support no-auth
	if !msg.ContainsMethod(MethodNoAuth) {
		NewServerAuthMsg(conn, MethodNoAcceptable)
		return errors.New("method not supported")
	}

	return NewServerAuthMsg(conn, MethodNoAuth)
}

func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	msg, err := NewClientRequestMsg(conn)
	if err != nil {
		return nil, err
	}

	// Check if the command is supported
	if msg.Command != CmdConnect {
		// no supported
		return nil, ErrCommandNotSupported
	}

	// Check if the address type if supported
	if msg.AddrType == IPv6Addr {
		return nil, ErrAddrTypeNotSupported
	}

	return nil, nil
}
