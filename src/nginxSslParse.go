package main

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/tufanbarisyildirim/gonginx/parser"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func parserSslFile(cliContext *cli.Context, wg *sync.WaitGroup, sslFile string) {
	defer wg.Done()

	sslRaw, err := os.ReadFile(sslFile)
	if err != nil {
		log.Printf("readSSLFile %s failed %v\n", sslFile, err)
		return
	}

	certDERBlock, _ := pem.Decode(sslRaw)
	if certDERBlock == nil {
		log.Print(err)
		return
	}

	x509Cert, err := x509.ParseCertificate(certDERBlock.Bytes)
	if err != nil {
		log.Print(err)
		return
	}

	if x509Cert.NotAfter.Before(time.Now().Add(time.Hour * 24 * time.Duration(cliContext.Int("day")))) {
		log.Printf("foundSSLFile %s StartAt=%s,EndAt=\u001B[0;31m%s\033[0m \n",
			sslFile,
			x509Cert.NotBefore.String(),
			x509Cert.NotAfter.String(),
		)
	} else {
		log.Printf("foundSSLFile %s StartAt=%s, EndAt=%s\n",
			sslFile,
			x509Cert.NotBefore.String(),
			x509Cert.NotAfter.String(),
		)
	}
}

func hostsScan(cliContext *cli.Context) error {
	folder := cliContext.String("folder")
	suffix := cliContext.String("suffix")

	var wg sync.WaitGroup

	//找到所有符合结尾的文件列表
	allConfFiles, err := filepath.Glob(path.Join(folder, "*."+suffix))
	if err != nil {
		return err
	}
	//读取文件内容找到对应 ssl_certificate 指令文件
	for _, confFile := range allConfFiles {
		confRaw, err := os.ReadFile(confFile)
		if err != nil {
			log.Printf("readConfFile fail %v", err)
			continue
		}

		directives := parser.NewStringParser(string(confRaw)).Parse().FindDirectives("ssl_certificate")
		if len(directives) == 0 {
			continue
		}

		for _, directive := range directives {
			sslFiles := directive.GetParameters()
			if len(sslFiles) == 0 {
				continue
			}

			if tmpFile, err := os.Stat(sslFiles[0]); err != nil || tmpFile.Size() == 0 {
				continue
			}

			wg.Add(1)
			go parserSslFile(cliContext, &wg, sslFiles[0])
		}
	}

	wg.Wait()

	return nil
}

func main() {
	cli.HelpFlag = &cli.BoolFlag{
		Name:               "help",
		Usage:              "show help",
		DisableDefaultText: true,
	}

	app := &cli.App{
		Name:  "nginxSslParse",
		Usage: "扫描检查ssl证书过期时间",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "domain",
				Value:    "",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "folder",
				Value:    "",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "suffix",
				Value:    "conf",
				Required: false,
			},
			&cli.IntFlag{
				Name:     "day",
				Value:    30,
				Required: false,
			},
		},
	}

	app.Action = func(cliContext *cli.Context) error {
		if len(cliContext.String("domain")) > 0 && strings.HasPrefix(cliContext.String("domain"), "https://") {
			return domainChecker(cliContext.String("domain"))
		}

		if len(cliContext.String("folder")) == 0 || len(cliContext.String("suffix")) == 0 || strings.Contains(cliContext.String("suffix"), ".") == true {
			return cli.ShowAppHelp(cliContext)
		}

		return hostsScan(cliContext)
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
