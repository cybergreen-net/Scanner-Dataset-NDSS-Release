package main

import (
	"Scanner/pkg/config"
	"Scanner/pkg/scanner"
	"log"
	"net"
	"os"
	"time"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:    "scan",
		Version: config.Version,
		Usage:   "Scan hostname TLS endpoints and capture information",
		Commands: []*cli.Command{
			{
				Name:    "tls",
				Aliases: []string{"t"},
				Action:  scanner.HandleTLSScanRequests,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "hostname",
						Usage: "Hostname for the query",
						Value: "google.com",
					},
					&cli.StringFlag{
						Name:    "out-dir",
						Aliases: []string{"o"},
						Value:   "results",
					},
					&cli.StringFlag{
						Name:    "out-file",
						Aliases: []string{"f"},
						Value:   "",
					},
					&cli.BoolFlag{
						Name:  "json",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "pretty",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "noserver",
						Value: false,
					},
				},
			},
			{
				Name:    "mail",
				Aliases: []string{"m"},
				Action:  scanner.HandleMailScanRequests,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "hostname",
						Usage: "Hostname to query and scan mail related infrastructure",
						Value: "gmail.com",
					},
					&cli.StringFlag{
						Name:    "out-dir",
						Aliases: []string{"o"},
						Value:   "results",
					},
					&cli.StringFlag{
						Name:    "out-file",
						Aliases: []string{"f"},
						Value:   "",
					},
					&cli.BoolFlag{
						Name:  "no-cache-mx",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "json",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "pretty",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "noserver",
						Value: false,
					},
				},
			},
			{
				Name:    "dns",
				Aliases: []string{"d"},
				Action:  scanner.HandleDNSScanRequests,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "hostname",
						Usage: "Hostname to query and scan dnssec records",
						Value: "google.com.",
					},
					&cli.StringFlag{
						Name:    "query-type",
						Aliases: []string{"r"},
						Value:   "A",
					},
					&cli.StringFlag{
						Name:    "out-dir",
						Aliases: []string{"o"},
						Value:   "results",
					},
					&cli.StringFlag{
						Name:    "out-file",
						Aliases: []string{"f"},
						Value:   "",
					},
					&cli.BoolFlag{
						Name:  "json",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "pretty",
						Value: false,
					},
					&cli.BoolFlag{
						Name:  "noserver",
						Value: false,
					},
				},
			},
		},
	}

	_, err := net.DialTimeout("tcp", config.GetServerHostnamePort(), time.Second)
	if err != nil {
		useServer := true
		for _, arg := range os.Args {
			if arg == "--noserver" {
				useServer = false
			}
		}
		if useServer {
			log.Fatalf("%s, %s", err, "run again with --noserver flag, or start cache server")
			return
		}
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

}
