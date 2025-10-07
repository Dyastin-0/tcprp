package main

import (
	"context"
	"log"
	"net/http"
	"os"

	_ "net/http/pprof"

	"github.com/Dyastin-0/tcprp/cmd"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	command := cmd.New()

	if err := command.Run(context.Background(), os.Args); err != nil {
		panic(err)
	}
}
