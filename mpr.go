package main

import (
	"context"
	"os"

	"github.com/Dyastin-0/mpr/cmd"
)

func main() {
	command := cmd.New()

	if err := command.Run(context.Background(), os.Args); err != nil {
		panic(err)
	}
}
