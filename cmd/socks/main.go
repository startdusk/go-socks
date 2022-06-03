package main

import (
	"log"

	"github.com/startdusk/go-socks"
)

// test
// run this program
// go run .
//
// and then
//
// no auth
// $ curl -v --proxy socks5://localhost:18080 www.baidu.com
//
// password auth
// $ curl -v --proxy socks5://admin:123456@localhost:18080 www.baidu.com
func main() {
	users := map[string]string{
		"admin":     "123456",
		"startdusk": "abc123",
		"hulu":      "hulubell",
	}
	srv := socks.Server{
		IP:   "localhost",
		Port: "18080",
		Config: &socks.Config{
			AuthMethod: socks.MethodPassword,
			PasswordChecker: func(username string, password string) bool {
				log.Printf("auth username %s, password %s", username, password)
				want, ok := users[username]
				if !ok {
					return false
				}
				return want == password
			},
		},
	}

	err := srv.Run()
	if err != nil {
		log.Fatal(err)
	}
}
