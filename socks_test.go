package socks

import (
	"bytes"
	"testing"
)

func TestAuth(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "normal_success",
			data:    []byte{SOCKS5Version, 2, MethodNoAuth, MethodGSSAPI},
			wantErr: false,
		},
		{
			name:    "version_not_support",
			data:    []byte{0x04, 2, MethodNoAuth, MethodGSSAPI},
			wantErr: true,
		},
		{
			name:    "nmethod_not_equal_methods",
			data:    []byte{0x04, 2, MethodGSSAPI},
			wantErr: true,
		},
		{
			name:    "method_not_support",
			data:    []byte{SOCKS5Version, 1, MethodGSSAPI},
			wantErr: true,
		},
		{
			name:    "method_not_support",
			data:    []byte{SOCKS5Version, 1, MethodNoAcceptable},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := auth(bytes.NewBuffer(c.data))
			if c.wantErr && err == nil {
				t.Fatalf("expected want error but got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected want nil but got error: %+v", err)
			}
		})
	}
}
