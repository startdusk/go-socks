package socks

import (
	"bytes"
	"reflect"
	"testing"
)

func TestAuth(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		expect  []byte
		wantErr bool
	}{
		{
			name:    "normal_success",
			data:    []byte{SOCKS5Version, 2, MethodNoAuth, MethodGSSAPI},
			expect:  []byte{SOCKS5Version, MethodNoAuth},
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
		{
			name:    "message_invalid",
			data:    []byte{SOCKS5Version, 2, MethodNoAcceptable},
			wantErr: true,
		},
		{
			name:    "message_invalid_no_nmethod",
			data:    []byte{SOCKS5Version, MethodNoAcceptable},
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := bytes.NewBuffer(c.data)
			err := auth(buf)
			if c.wantErr && err == nil {
				t.Fatalf("expected want error but got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected want nil but got error: %+v", err)
			}
			if c.wantErr {
				return
			}
			got := buf.Bytes()
			if !reflect.DeepEqual(got, c.expect) {
				t.Fatalf("expected want %v but got %v", c.expect, got)
			}
		})
	}
}

func FuzzAuth(f *testing.F) {
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		auth(bytes.NewBuffer(data))
	})
}

func FuzzRequest(f *testing.F) {
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		request(bytes.NewBuffer(data))
	})
}
