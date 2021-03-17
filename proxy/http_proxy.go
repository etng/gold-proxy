package proxy

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HTTPProxyServer struct {
	NonProxyHandler http.Handler
	Logger          *log.Logger
	Tr              *http.Transport
	GetProxyURL     func() string
	Verbose         bool
	PeekHTTPS       bool
	CACert          []byte
	CAKey           []byte
	OnSuccess       func(req *http.Request, resp *http.Response)
	OnFail          func(cate string, req *http.Request, resp *http.Response)
}

func StartHTTPProxyServer(host string, options ...HTTPProxyServerOpt) {
	log.Fatal(http.ListenAndServe(host, NewHTTPProxyServer(options...)))
}
func NewHTTPProxyServer(optFuncs ...HTTPProxyServerOpt) *HTTPProxyServer {
	server := &HTTPProxyServer{
		Logger: log.New(os.Stderr, "", log.LstdFlags),
		NonProxyHandler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			http.Error(w, "This is a proxy server. Does not respond to non-proxy requests.", 500)
		}),
		PeekHTTPS: false,
		Tr: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		OnSuccess: func(req *http.Request, resp *http.Response) {},
		OnFail:    func(cate string, req *http.Request, resp *http.Response) {},
	}
	server.Tr.Proxy = func(r *http.Request) (*url.URL, error) {
		proxyURL := server.GetProxyURL()
		if proxyURL == "" {
			return nil, nil
		}
		return url.Parse(proxyURL)
	}
	for _, optFunc := range optFuncs {
		optFunc(server)
	}
	return server
}
func (server *HTTPProxyServer) Dial(network, addr string) (c net.Conn, err error) {
	if server.Tr.Dial != nil {
		return server.Tr.Dial(network, addr)
	}
	return net.Dial(network, addr)
}

func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

type halfClosable interface {
	net.Conn
	CloseWrite() error
	CloseRead() error
}

func copyAndClose(dst, src halfClosable) {
	if _, err := io.Copy(dst, src); err != nil {
		log.Printf("Error copying to client: %s", err)
	}

	dst.CloseWrite()
	src.CloseRead()
}
func copyOrWarn(dst io.Writer, src io.Reader, wg *sync.WaitGroup) {
	if _, err := io.Copy(dst, src); err != nil {
		log.Printf("Error copying to client: %s", err)
	}
	wg.Done()
}

var _ halfClosable = (*net.TCPConn)(nil)

func isEof(r *bufio.Reader) bool {
	_, err := r.Peek(1)
	if err == io.EOF {
		return true
	}
	return false
}

func hashSorted(lst []string) []byte {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	return h.Sum(nil)
}

func hashSortedBigInt(lst []string) *big.Int {
	rv := new(big.Int)
	rv.SetBytes(hashSorted(lst))
	return rv
}

var proxySignerVersion = ":http_proxy_v1"

func signHost(ca tls.Certificate, hosts []string) (cert *tls.Certificate, err error) {
	var x509ca *x509.Certificate

	// Use the provided ca and not the global GoproxyCa for certificate generation.
	if x509ca, err = x509.ParseCertificate(ca.Certificate[0]); err != nil {
		return
	}
	start := time.Unix(0, 0)
	end, err := time.Parse("2006-01-02", "2049-12-31")
	if err != nil {
		panic(err)
	}

	serial := big.NewInt(rand.Int63())
	template := x509.Certificate{
		SerialNumber: serial,
		Issuer:       x509ca.Subject,
		Subject: pkix.Name{
			Organization:       []string{"Proxied Org"},
			OrganizationalUnit: []string{"Proxied Org Unit"},
		},
		NotBefore: start,
		NotAfter:  end,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
			template.Subject.CommonName = h
		}
	}

	hash := hashSorted(append(hosts, proxySignerVersion, ":"+runtime.Version()))
	var csprng CounterEncryptorRand
	if csprng, err = NewCounterEncryptorRandFromKey(ca.PrivateKey, hash); err != nil {
		return
	}

	var certpriv crypto.Signer
	switch ca.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if certpriv, err = rsa.GenerateKey(&csprng, 2048); err != nil {
			return
		}
	case *ecdsa.PrivateKey:
		if certpriv, err = ecdsa.GenerateKey(elliptic.P256(), &csprng); err != nil {
			return
		}
	default:
		err = fmt.Errorf("unsupported key type %T", ca.PrivateKey)
	}

	var derBytes []byte
	if derBytes, err = x509.CreateCertificate(&csprng, &template, x509ca, certpriv.Public(), ca.PrivateKey); err != nil {
		return
	}
	return &tls.Certificate{
		Certificate: [][]byte{derBytes, ca.Certificate[0]},
		PrivateKey:  certpriv,
	}, nil
}

type CounterEncryptorRand struct {
	cipher  cipher.Block
	counter []byte
	rand    []byte
	ix      int
}

func NewCounterEncryptorRandFromKey(key interface{}, seed []byte) (r CounterEncryptorRand, err error) {
	var keyBytes []byte
	switch key := key.(type) {
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(key)
	case *ecdsa.PrivateKey:
		if keyBytes, err = x509.MarshalECPrivateKey(key); err != nil {
			return
		}
	default:
		err = errors.New("only RSA and ECDSA keys supported")
		return
	}
	h := sha256.New()
	if r.cipher, err = aes.NewCipher(h.Sum(keyBytes)[:aes.BlockSize]); err != nil {
		return
	}
	r.counter = make([]byte, r.cipher.BlockSize())
	if seed != nil {
		copy(r.counter, h.Sum(seed)[:r.cipher.BlockSize()])
	}
	r.rand = make([]byte, r.cipher.BlockSize())
	r.ix = len(r.rand)
	return
}

func (c *CounterEncryptorRand) Seed(b []byte) {
	if len(b) != len(c.counter) {
		panic("SetCounter: wrong counter size")
	}
	copy(c.counter, b)
}

func (c *CounterEncryptorRand) refill() {
	c.cipher.Encrypt(c.rand, c.counter)
	for i := 0; i < len(c.counter); i++ {
		if c.counter[i]++; c.counter[i] != 0 {
			break
		}
	}
	c.ix = 0
}

func (c *CounterEncryptorRand) Read(b []byte) (n int, err error) {
	if c.ix == len(c.rand) {
		c.refill()
	}
	if n = len(c.rand) - c.ix; n > len(b) {
		n = len(b)
	}
	copy(b, c.rand[c.ix:c.ix+n])
	c.ix += n
	return
}

func init() {
	// Avoid deterministic random numbers
	rand.Seed(time.Now().UnixNano())
}

var httpsRegexp = regexp.MustCompile(`^https:\/\/`)

func (server *HTTPProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hij, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}

	clientAgent, _, e := hij.Hijack()
	if e != nil {
		panic("[proxy][https] Cannot hijack connection " + e.Error())
	}
	host := r.URL.Host
	if !hasPort(host) {
		host += ":80"
	}
	if server.Verbose {
		// log.Printf("accept to %s", host)
	}
	if server.PeekHTTPS {
		clientAgent.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		hostname, _, _ := net.SplitHostPort(host)
		var ca, _ = tls.X509KeyPair(server.CACert, server.CAKey)
		var cert, _ = signHost(ca, []string{hostname})
		tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		go func() {
			tlsClientAgent := tls.Server(clientAgent, tlsConfig)
			if err := tlsClientAgent.Handshake(); err != nil {
				log.Printf("[proxy][https][mitm] tls handshake error %s", err)
				return
			}
			defer tlsClientAgent.Close()
			reader := bufio.NewReader(tlsClientAgent)
			var req *http.Request
			var resp *http.Response
			var err error
			for !isEof(reader) {
				if req, err = http.ReadRequest(reader); err != nil {
					if err == io.EOF {
						log.Printf("[proxy][https][mitm] https read eof from client")
					}

					return
				}
				// log.Printf("[proxy][https][mitm] remote address compare %q %q", req.RemoteAddr, r.RemoteAddr)
				req.RemoteAddr = r.RemoteAddr
				// log.Printf("[proxy][https][mitm] request url %q", req.URL)

				if !httpsRegexp.MatchString(req.URL.String()) {
					req.URL, err = url.Parse("https://" + r.Host + req.URL.String())
				}
				// log.Printf("[proxy][https][mitm] request url modified %q", req.URL)
				if d, e := httputil.DumpRequest(req, true); e == nil {
					log.Printf("[proxy][https][mitm][peek] requests is")
					log.Printf("%s", d)
				}
				if resp, err = server.Tr.RoundTrip(req); err != nil {
					log.Printf("[proxy][https][mitm] https req fail %s", err)
					server.OnFail("bad_net", req, resp)
					return
				}
				if resp.StatusCode >= 400 {
					server.OnFail("bad_resp", req, resp)
				} else {
					server.OnSuccess(req, resp)
				}
				// if d, e := httputil.DumpResponse(resp, true); e == nil {
				// 	log.Printf("response is %s", d)
				// }
				// resp.Header.Write(os.Stdout)
				log.Printf("[proxy][https][mitm][peek] response is")
				resp.Header.Write(log.Writer())
				mimeParts := strings.SplitN(strings.Split(resp.Header.Get("Content-type"), ";")[0], "/", 2)
				var writer io.WriteCloser
				if mimeParts[0] == "text" {
					log.Printf("[proxy][https][mitm] response is text %q", resp.Header.Get("Content-type"))
					writer = tlsClientAgent
				} else {
					resp.Header.Set("Transfer-Encoding", "chunked")
					resp.Header.Del("Content-Length")
					writer = httputil.NewChunkedWriter(tlsClientAgent)
				}

				text := resp.Status
				statusCode := strconv.Itoa(resp.StatusCode) + " "
				if strings.HasPrefix(text, statusCode) {
					text = text[len(statusCode):]
				}
				// Force connection close otherwise chrome will keep CONNECT tunnel open forever
				resp.Header.Set("Connection", "close")
				resp.Header.Set("X-MITM-PLAYER", "1.0")

				io.WriteString(tlsClientAgent, "HTTP/1.1"+" "+statusCode+text+"\r\n")
				// io.WriteString(tlsClientAgent, "response dropped")

				resp.Header.Write(tlsClientAgent)
				io.WriteString(tlsClientAgent, "\r\n")
				io.Copy(writer, resp.Body)
				writer.Close()
				io.WriteString(tlsClientAgent, "\r\n")
			}
		}()
	} else {
		upstream := server.GetProxyURL()
		serverAgent, err := server.ConnectDial("tcp", host, upstream)
		if err != nil {
			http.Error(w, fmt.Errorf("[proxy][https][accept] fail to do request for %s", err).Error(), 500)
			return
		}
		clientAgent.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))

		serverAgentTCP, serverOK := serverAgent.(halfClosable)
		clientAgentTCP, clientOK := clientAgent.(halfClosable)
		if serverOK && clientOK {
			go copyAndClose(serverAgentTCP, clientAgentTCP)
			go copyAndClose(clientAgentTCP, serverAgentTCP)
		} else {
			go func() {
				var wg sync.WaitGroup
				wg.Add(2)
				go copyOrWarn(serverAgent, clientAgent, &wg)
				go copyOrWarn(clientAgent, serverAgent, &wg)
				wg.Wait()
				clientAgent.Close()
				serverAgent.Close()

			}()
		}
	}
}
func removeProxyHeaders(r *http.Request) {
	r.RequestURI = "" // this must be reset when serving a request with the client
	// If no Accept-Encoding header exists, Transport will add the headers it can accept
	// and would wrap the response body with the relevant reader.
	r.Header.Del("Accept-Encoding")
	// curl can add that, see
	// https://jdebp.eu./FGA/web-proxy-connection-header.html
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")
	// Connection, Authenticate and Authorization are single hop Header:
	// http://www.w3.org/Protocols/rfc2616/rfc2616.txt
	// 14.10 Connection
	//   The Connection general-header field allows the sender to specify
	//   options that are desired for that particular connection and MUST NOT
	//   be communicated by proxies over further connections.

	// When server reads http request it sets req.Close to true if
	// "Connection" header contains "close".
	// https://github.com/golang/go/blob/master/src/net/http/request.go#L1080
	// Later, transfer.go adds "Connection: close" back when req.Close is true
	// https://github.com/golang/go/blob/master/src/net/http/transfer.go#L275
	// That's why tests that checks "Connection: close" removal fail
	if r.Header.Get("Connection") == "close" {
		r.Close = false
	}
	r.Header.Del("Connection")
}
func (server *HTTPProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if server.Verbose {
		server.Logger.Printf("handling request to %s from %s", r.URL, r.RemoteAddr)
	}
	if r.Method == "CONNECT" {
		server.handleHTTPS(w, r)
	} else {
		if !r.URL.IsAbs() {
			server.NonProxyHandler.ServeHTTP(w, r)
			return
		}
		var err error
		var resp *http.Response
		removeProxyHeaders(r)
		// reqD, _ := httputil.DumpRequest(r, false)
		// if server.Verbose {
		// 	server.Logger.Printf("request is %s", reqD)
		// }
		if resp, err = server.Tr.RoundTrip(r); err != nil {
			http.Error(w, fmt.Errorf("[proxy][http]fail to do request for %s", err).Error(), 500)
		}
		// respD, _ := httputil.DumpResponse(resp, false)
		// if server.Verbose {
		// 	server.Logger.Printf("response is %s", respD)
		// }
		for k, vs := range resp.Header {
			w.Header().Del(k)
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		resp.Body.Close()
	}
	if server.Verbose {
		server.Logger.Printf("handled request to %s from %s", r.URL, r.RemoteAddr)
	}
}

func (server *HTTPProxyServer) ConnectDial(network, addr string, proxyURL string) (net.Conn, error) {
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	var c net.Conn
	var err error
	if proxyURL != "" {
		u, _ := url.Parse(proxyURL)
		c, err = server.Dial(network, u.Host)
	} else {
		c, err = net.Dial(network, addr)
		return c, err
	}

	if err != nil {
		return nil, err
	}
	connectReq.Write(c)
	// Read response.
	// Okay to use and discard buffered reader here, because
	// TLS server will not speak until spoken to.
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		c.Close()
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		resp, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		c.Close()
		return nil, fmt.Errorf("proxy refused connection %s", resp)
	}
	return c, nil
}

type HTTPProxyServerOpt func(server *HTTPProxyServer)
