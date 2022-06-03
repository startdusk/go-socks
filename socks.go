package socks

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"time"
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
	// auth
	if err := auth(conn); err != nil {
		return err
	}

	// request
	target, err := request(conn)
	if err != nil {
		return err
	}

	// forward
	return forward(conn, target)
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
		return nil, WriteReqFailureMsg(conn, ReplyCommandNotSupported)
	}

	// Check if the address type is supported
	if msg.AddrType == IPv6Addr {
		return nil, WriteReqFailureMsg(conn, ReplyAddressTypeNotSupported)
	}

	// Access target tcp server
	address := net.JoinHostPort(msg.Address, fmt.Sprintf("%d", msg.Port))
	targetConn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, WriteReqFailureMsg(conn, ReplyConnectionRefused)
	}

	// Send success message
	addrVal := targetConn.LocalAddr()
	addr := addrVal.(*net.TCPAddr)
	return targetConn, WriteReqSuccessMsg(conn, addr.IP, uint16(addr.Port))
}

func forward(server io.ReadWriter, target io.ReadWriteCloser) error {
	defer target.Close()

	go io.Copy(target, server)
	_, err := io.Copy(server, target)
	return err
}
