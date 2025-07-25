package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tufanbarisyildirim/gonginx/parser"
	"github.com/urfave/cli/v2"
)

var Loc *time.Location = nil

func init() {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		log.Printf("初始化时区失败 %v", err)
		return
	}

	Loc = loc
}

func formatTimeToStr(time time.Time) string {
	if Loc == nil {
		return time.Format("2006-01-02 15:04:05")
	} else {
		return time.In(Loc).Format("2006-01-02 15:04:05")
	}
}

func parserSslFile(cliContext *cli.Context, wg *sync.WaitGroup, sslFile, host string) error {
	if wg != nil {
		defer wg.Done()
	}

	sslRaw, err := os.ReadFile(sslFile)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(sslRaw)
	if block == nil {
		return errors.New("pem decode failed")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	// 判断是否接近过期
	dayThreshold := time.Hour * 24 * time.Duration(cliContext.Int("day"))
	isWarning := cert.NotAfter.Before(time.Now().Add(dayThreshold))

	// 构造统一输出格式
	start := formatTimeToStr(cert.NotBefore)
	end := formatTimeToStr(cert.NotAfter)
	colorEnd := end
	if isWarning {
		colorEnd = "\033[0;31m" + end + "\033[0m"
	}

	// 构造输出主体
	target := sslFile
	if host != "" {
		target = "https://" + host
	}

	log.Printf("%s StartAt=%s, EndAt=%s\n", target, start, colorEnd)

	return nil
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

		config := parser.NewStringParser(string(confRaw)).Parse()

		directives := config.FindDirectives("ssl_certificate")
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

			host := config.FindDirectives("server_name")[0].GetParameters()[0]

			go parserSslFile(cliContext, &wg, sslFiles[0], host)
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
				Name:     "file",
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

		if len(cliContext.String("file")) > 0 {
			return parserSslFile(cliContext, nil, cliContext.String("file"), "")
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
