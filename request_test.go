package socks

import (
	"bytes"
	"testing"
)

func FuzzNewClientRequestMsg(f *testing.F) {
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		NewClientRequestMsg(bytes.NewReader(data))
	})
}
