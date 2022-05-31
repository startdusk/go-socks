package socks

import (
	"errors"
	"io"
	"log"
	"net"
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
