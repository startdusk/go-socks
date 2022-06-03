package socks

import "errors"

var (
	ErrVersionNotSupported       = errors.New("protocol version not supported")
	ErrMethodVersionNotSupported = errors.New("sub-negotiation method version not supported")
	ErrCommandNotSupported       = errors.New("request command not supported")
	ErrInvalidReservedField      = errors.New("protocol reserved invalid")
	ErrAddrTypeNotSupported      = errors.New("address type not supported")

	ErrUsernameLengthZero = errors.New("username length 0")
	ErrPasswordLengthZero = errors.New("password length 0")
)
