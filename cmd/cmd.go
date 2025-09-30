package cmd

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/Dyastin-0/mpr/core"
	"github.com/Dyastin-0/mpr/core/proxy"
	"github.com/caddyserver/certmagic"
	"github.com/common-nighthawk/go-figure"
	"github.com/urfave/cli/v3"
)

func New() *cli.Command {
	return &cli.Command{
		Name:    "mpr",
		Usage:   "a reverse proxy service",
		Version: core.VERSION,
		Commands: []*cli.Command{
			startCommand(),
		},
		Action: rpAction,
	}
}

func rpAction(ctx context.Context, cmd *cli.Command) error {
	figure := figure.NewFigure("mpr-cli", "", true)
	figure.Print()
	fmt.Println()

	err := cli.ShowAppHelp(cmd)
	if err != nil {
		panic(err)
	}

	return nil
}

func startCommand() *cli.Command {
	return &cli.Command{
		Name:        "start",
		Description: "start the reverse proxy service",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config",
				Aliases:  []string{"c", "conf"},
				Required: true,
			},
			&cli.StringFlag{
				Name:    "addr",
				Aliases: []string{"a"},
				Value:   ":443",
			},
		},
		Action: startAction,
	}
}

func startAction(ctx context.Context, cmd *cli.Command) error {
	configPath := cmd.String("config")
	addr := cmd.String("addr")

	proxy := proxy.New()
	err := proxy.Config.Load(configPath)
	if err != nil {
		return err
	}

	domains := proxy.Config.Proxies.GetKeysWithVal()
	magic := certmagic.NewDefault()
	magic.ManageAsync(ctx, domains)

	ln, err := tls.Listen("tcp", addr, magic.TLSConfig())
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				continue
			}
			go proxy.Handler(conn)
		}
	}
}
