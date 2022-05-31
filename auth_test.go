package socks

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClientAuthMsg(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		methods []byte
		wantErr bool
	}{
		{
			name:    "normal_success",
			data:    []byte{SOCKS5Version, 2, MethodNoAuth, MethodGSSAPI},
			methods: []byte{MethodNoAuth, MethodGSSAPI},
			wantErr: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg, err := NewClientAuthMsg(bytes.NewReader(c.data))
			if c.wantErr && err == nil {
				t.Fatalf("expected want error but got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected want nil but got error: %+v", err)
			}

			if msg.Version != SOCKS5Version {
				t.Fatalf("expected version %v but got %v", SOCKS5Version, msg.Version)
			}

			if len(msg.Methods) != int(msg.NMethods) {
				t.Fatalf("expected NMethods %v but got %v", int(msg.NMethods), len(msg.Methods))
			}

			if !reflect.DeepEqual(msg.Methods, c.methods) {
				t.Fatalf("expected Methods %v but got %v", int(msg.NMethods), len(msg.Methods))
			}
		})
	}
}

func TestNewServerAuthMsg(t *testing.T) {
	cases := []struct {
		name    string
		expect  []byte
		method  Method
		wantErr bool
	}{
		{
			name:    "normal_success",
			expect:  []byte{SOCKS5Version, MethodNoAuth},
			method:  MethodNoAuth,
			wantErr: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := NewServerAuthMsg(&buf, c.method)
			if c.wantErr && err == nil {
				t.Fatalf("expected want error but got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected want nil but got error: %+v", err)
			}
			got := buf.Bytes()
			if !reflect.DeepEqual(got, c.expect) {
				t.Fatalf("expected Methods %v but got %v", c.expect, got)
			}
		})
	}
}
