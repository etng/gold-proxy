package main

import (
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	goldProxy "github.com/etng/gold-proxy/proxy"
)

func DownloadFile(client *http.Client, remoteURI,
	saveFilename string) {
	// defer log.Printf("download done for %q to %q", remoteURI, saveFilename)
	req, _ := http.NewRequest(http.MethodGet, remoteURI, nil)
	var writer io.Writer = os.Stdout
	if saveFilename != "" {
		of, _ := os.Create(saveFilename)
		defer of.Close()
		writer = of
	}
	req.Header.Add("User-Agent", "curl/7.68.0")
	req.Header.Add("via", "gold-proxy-client")
	req.Header.Add("x-pp-area", "us")
	req.Header.Add("x-pp-refresh", "0")

	if resp, err := client.Do(req); err != nil {
		log.Printf("fail to do https request for %s", err)
	} else {
		log.Printf("client response: %s", resp.Status)
		resp.Header.Write(log.Writer())
		// log.Printf("encoding %q", resp.Header.Get("Content-Encoding"))
		defer resp.Body.Close()
		log.Printf("len: %s", resp.Header.Get("content-length"))
		log.Printf("te: %s", resp.Header.Get("Transfer-Encoding"))

		log.Printf("mime: %s", resp.Header.Get("content-type"))
		if resp.Header.Get("Content-Encoding") == "gzip" {
			reader, _ := gzip.NewReader(resp.Body)
			io.Copy(writer, reader)
		} else {
			io.Copy(writer, resp.Body)
		}
		// httputil.DumpResponse(resp, true)
	}
}

type ProxyGetter func(clientIP, host, areaName, refresh string) (proxyArea string, proxyURI string)

func main() {

	var caCert, _ = ioutil.ReadFile("./server.crt")

	var caKey, _ = ioutil.ReadFile("./server.key")

	logFilename := "data/logs/proxy.log"
	if logFilename != "" {
		os.MkdirAll(filepath.Dir(logFilename), 0777)
		if of, e := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); e == nil {
			log.SetOutput(of)
		} else {
			fmt.Printf("fail to open file %s to write log %s", logFilename, e)
			os.Exit(1)
		}
	}
	counter := goldProxy.NewCounter()
	go func() {
		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("stats:\n%s", counter.Print())
		}
	}()

	var proxyGetter ProxyGetter = func(clientIP, host, areaName, refresh string) (proxyArea string, proxyURI string) {
		log.Printf("getting proxy for ClientIP:%q, host:%q, area:%q, refresh:%q", clientIP, host, areaName, refresh)
		proxyArea = "random"
		proxyURI = "http://localhost:9192"
		proxyURI = "http://192.168.4.202:9192"
		log.Printf("got proxy to area:%q, uri:%q", proxyArea, proxyURI)
		return
	}
	go func() {
		goldProxy.StartHTTPProxyServer("0.0.0.0:9293", func(server *goldProxy.HTTPProxyServer) {
			server.GetProxyURL = func(r *http.Request) string {
				area := r.Header.Get("X-PP-AREA")
				refresh := r.Header.Get("X-PP-REFRESH")
				r.Header.Del("X-PP-AREA")
				r.Header.Del("X-PP-REFRESH")
				clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
				_, pu := proxyGetter(clientIP, r.Host, area, refresh)
				return pu
			}
			server.PeekHTTPS = true
			server.Verbose = true
			server.CACert = caCert
			server.CAKey = caKey
			server.OnSuccess = func(req *http.Request, resp *http.Response) {
				go counter.Incr(req.Host)
			}
			server.OnFail = func(cate string, req *http.Request, resp *http.Response) {
				go counter.Incr(req.Host)
				go counter.Incr(fmt.Sprintf("%s::%s", cate, req.Host))
				var reqB, respB []byte
				reqB, _ = httputil.DumpRequest(req, false)
				if resp != nil {
					respB, _ = httputil.DumpResponse(resp, false)
				}
				log.Printf("failed request %s %s %s", cate, reqB, respB)
			}
		})
	}()
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)
	proxyURL, _ := url.Parse("http://localhost:9293")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				// RootCAs: certPool,
				InsecureSkipVerify: false,
			},
		},
	}
	uris := []string{
		"https://golang.org/lib/godoc/images/go-logo-blue.svg",
		"https://golang.org/favicon.ico",
		"https://www.hoover.org/",
		"https://navbharattimes.indiatimes.com/photo/msid-81527709,imgsize-123/pic.jpg",
		"https://www.aljazeera.com/wp-content/uploads/2021/03/riz.jpg",
		"https://images.livemint.com/img/2021/03/08/600x338/uber3-kijB--621x414@LiveMint_1615213477687.JPG",
		"https://assets-news-bcdn.dailyhunt.in/cmd/resize/3600x1890_60/fetchdata16/images/3d/6f/d7/3d6fd7e71d2643fd17d1c396e27600dcaf80cb41234af1b9f74c2c83029029f1.jpg",
	}
	pattern := regexp.MustCompile(`^(www|images)\.`)
	os.MkdirAll("data/tmp", 0777)
	for _, uri := range uris {
		pu, _ := url.Parse(uri)
		domain := pattern.ReplaceAllString(pu.Host, "")
		for i := 0; i < 5; i++ {
			go DownloadFile(client, uri,
				fmt.Sprintf("data/tmp/%s_%d.jpg", domain, i+1))
		}
	}
	// go func(seq int) {
	// 	DownloadFile(client, "https://images.livemint.com/img/2021/03/08/600x338/uber3-kijB--621x414@LiveMint_1615213477687.JPG",
	// 		fmt.Sprintf("data/tmp/livemint_%d.jpg", seq))
	// }(i)
	// go func(seq int) {
	// 	DownloadFile(client, "https://navbharattimes.indiatimes.com/photo/msid-81461326,imgsize-123/pic.jpg",
	// 		fmt.Sprintf("data/tmp/navbharattimes_%d.jpg", seq))
	// }(i)

	time.Sleep(time.Hour * 100)
}
