package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Dyastin-0/mpr/core"
	"github.com/Dyastin-0/mpr/core/proxy"
	"github.com/caddyserver/certmagic"
	"github.com/common-nighthawk/go-figure"
	"github.com/libdns/cloudflare"
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
				Name:     "api",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "email",
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
	api := cmd.String("api")
	email := cmd.String("email")
	addr := cmd.String("addr")

	proxy := proxy.New()
	err := proxy.Config.Load(configPath)
	if err != nil {
		return err
	}

	provider := &cloudflare.Provider{
		APIToken: api,
	}

	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: provider,
		},
	}

	domains := proxy.Config.Proxies.GetKeysWithVal()

	magic := certmagic.NewDefault()
	err = magic.ManageAsync(ctx, domains)
	if err != nil {
		return err
	}

	tlsConfig := magic.TLSConfig()
	tlsConfig.NextProtos = []string{"http/1.1", "h2"}

	proxy.TLSConfig = tlsConfig

	ln, err := net.Listen("tcp", addr)
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
