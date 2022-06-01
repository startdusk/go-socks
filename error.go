package socks

import "errors"

var (
	ErrVersionNotSupported  = errors.New("protocol version not supported")
	ErrCommandNotSupported  = errors.New("request command not supported")
	ErrInvalidReservedField = errors.New("protocol reserved invalid")
	ErrAddrTypeNotSupported = errors.New("address type not supported")
)
