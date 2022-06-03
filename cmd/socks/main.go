package main

import (
	"log"

	"github.com/startdusk/go-socks"
)

// test
// 运行该程序
// 然后执行 curl -v --proxy socks5://localhost:18080 www.baidu.com
func main() {
	srv := socks.Server{
		IP:   "localhost",
		Port: "18080",
	}

	err := srv.Run()
	if err != nil {
		log.Fatal(err)
	}
}
