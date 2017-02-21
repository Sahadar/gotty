package app

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"flag"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"

	"github.com/braintree/manners"
	"github.com/elazarl/go-bindata-assetfs"
	"github.com/gorilla/websocket"
	"github.com/kr/pty"
	"github.com/yudai/hcl"
	"github.com/yudai/umutex"

	"github.com/Sahadar/logger-go"
	"github.com/tiny-libs/tiny-pubsub-golang"
)



var Emitter *pubsub.Pubsub
var log *logger.Logger

type InitMessage struct {
	Arguments string `json:"Arguments,omitempty"`
	AuthToken string `json:"AuthToken,omitempty"`
}

type App struct {
	options *Options

	upgrader *websocket.Upgrader
	server   *manners.GracefulServer

	titleTemplate *template.Template

	onceMutex *umutex.UnblockingMutex
}

type Subdomain struct {
	app *App

	subdomain string
	command []string
	// clientContext writes concurrently
	// Use atomic operations.
	connections *int64
}

type Options struct {
	Address             string                 `hcl:"address"`
	Port                string                 `hcl:"port"`
	PermitWrite         bool                   `hcl:"permit_write"`
	EnableBasicAuth     bool                   `hcl:"enable_basic_auth"`
	Credential          string                 `hcl:"credential"`
	EnableRandomUrl     bool                   `hcl:"enable_random_url"`
	RandomUrlLength     int                    `hcl:"random_url_length"`
	IndexFile           string                 `hcl:"index_file"`
	EnableTLS           bool                   `hcl:"enable_tls"`
	TLSCrtFile          string                 `hcl:"tls_crt_file"`
	TLSKeyFile          string                 `hcl:"tls_key_file"`
	EnableTLSClientAuth bool                   `hcl:"enable_tls_client_auth"`
	TLSCACrtFile        string                 `hcl:"tls_ca_crt_file"`
	TitleFormat         string                 `hcl:"title_format"`
	EnableReconnect     bool                   `hcl:"enable_reconnect"`
	ReconnectTime       int                    `hcl:"reconnect_time"`
	MaxConnection       int                    `hcl:"max_connection"`
	Once                bool                   `hcl:"once"`
	PermitArguments     bool                   `hcl:"permit_arguments"`
	CloseSignal         int                    `hcl:"close_signal"`
	Preferences         HtermPrefernces        `hcl:"preferences"`
	RawPreferences      map[string]interface{} `hcl:"preferences"`
	Width               int                    `hcl:"width"`
	Height              int                    `hcl:"height"`
}

var Version = "0.0.13"
var runningSubdomains map[string]*Subdomain
var appSingleton *App

func init() {
	log = logger.InitLogger()
	Emitter = pubsub.NewPubsub()
	flag.Parse()
	runningSubdomains = make(map[string]*Subdomain)
}

var DefaultOptions = Options{
	Address:             "",
	Port:                "8080",
	PermitWrite:         false,
	EnableBasicAuth:     false,
	Credential:          "",
	EnableRandomUrl:     false,
	RandomUrlLength:     8,
	IndexFile:           "",
	EnableTLS:           false,
	TLSCrtFile:          "~/.gotty.crt",
	TLSKeyFile:          "~/.gotty.key",
	EnableTLSClientAuth: false,
	TLSCACrtFile:        "~/.gotty.ca.crt",
	TitleFormat:         "GoTTY - {{ .Command }} ({{ .Hostname }})",
	EnableReconnect:     false,
	ReconnectTime:       10,
	MaxConnection:       0,
	Once:                false,
	CloseSignal:         1, // syscall.SIGHUP
	Preferences:         HtermPrefernces{},
	Width:               0,
	Height:              0,
}

func New(options *Options) (error) {
	titleTemplate, err := template.New("title").Parse(options.TitleFormat)
	if err != nil {
		return errors.New("Title format string syntax error")
	}

	if(appSingleton != nil) {
		log.Log("Application already running.")
		return nil
	}

	appSingleton = &App{
		options: options,

		upgrader: &websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			Subprotocols:    []string{"gotty"},
		},

		titleTemplate: titleTemplate,

		onceMutex:   umutex.New(),
	}

	if appSingleton.options.PermitWrite {
		log.Log("Permitting clients to write input to the PTY.")
	}

	if appSingleton.options.Once {
		log.Log("Once option is provided, accepting only one client")
	}

	path := ""
	if appSingleton.options.EnableRandomUrl {
		path += "/" + generateRandomString(appSingleton.options.RandomUrlLength)
	}

	endpoint := net.JoinHostPort(appSingleton.options.Address, appSingleton.options.Port)


	wsHandler := http.HandlerFunc(handleWS)
	customIndexHandler := http.HandlerFunc(appSingleton.handleCustomIndex)
	authTokenHandler := http.HandlerFunc(appSingleton.handleAuthToken)
	staticHandler := http.FileServer(
		&assetfs.AssetFS{Asset: Asset, AssetDir: AssetDir, Prefix: "static"},
	)

	var siteMux = http.NewServeMux()

	if appSingleton.options.IndexFile != "" {
		log.Log("Using index file at " + appSingleton.options.IndexFile)
		siteMux.Handle(path+"/", customIndexHandler)
	} else {
		siteMux.Handle(path+"/", http.StripPrefix(path+"/", staticHandler))
	}
	siteMux.Handle(path+"/auth_token.js", authTokenHandler)
	siteMux.Handle(path+"/js/", http.StripPrefix(path+"/", staticHandler))
	siteMux.Handle(path+"/favicon.png", http.StripPrefix(path+"/", staticHandler))

	siteHandler := http.Handler(siteMux)

	if appSingleton.options.EnableBasicAuth {
		log.Log("Using Basic Authentication")
		siteHandler = wrapBasicAuth(siteHandler, appSingleton.options.Credential)
	}

	siteHandler = wrapHeaders(siteHandler)

	wsMux := http.NewServeMux()
	wsMux.Handle("/", siteHandler)
	wsMux.Handle(path+"/ws", wsHandler)
	siteHandler = (http.Handler(wsMux))

	siteHandler = wrapLogger(siteHandler)

	scheme := "http"
	if appSingleton.options.EnableTLS {
		scheme = "https"
	}

	if appSingleton.options.Address != "" {
		log.Log(
			"URL: %s",
			(&url.URL{Scheme: scheme, Host: endpoint, Path: path + "/"}).String(),
		)
	} else {
		for _, address := range listAddresses() {
			log.Log(
				"URL: %s",
				(&url.URL{
					Scheme: scheme,
					Host:   net.JoinHostPort(address, appSingleton.options.Port),
					Path:   path + "/",
				}).String(),
			)
		}
	}

	server, err := appSingleton.makeServer(endpoint, &siteHandler)
	if err != nil {
		return errors.New("Failed to build server: " + err.Error())
	}
	appSingleton.server = manners.NewWithServer(
		server,
	)

	if appSingleton.options.EnableTLS {
		crtFile := ExpandHomeDir(appSingleton.options.TLSCrtFile)
		keyFile := ExpandHomeDir(appSingleton.options.TLSKeyFile)
		log.Log("TLS crt file: " + crtFile)
		log.Log("TLS key file: " + keyFile)

		err = appSingleton.server.ListenAndServeTLS(crtFile, keyFile)
	} else {
		err = appSingleton.server.ListenAndServe()
	}
	if err != nil {
		return err
	}

	log.Log("Exiting...")

	return nil
}

func ApplyConfigFile(options *Options, filePath string) error {
	filePath = ExpandHomeDir(filePath)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return err
	}

	fileString := []byte{}
	log.Log("Loading config file at: %s", filePath)
	fileString, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	if err := hcl.Decode(options, string(fileString)); err != nil {
		return err
	}

	return nil
}

func CheckConfig(options *Options) error {
	if options.EnableTLSClientAuth && !options.EnableTLS {
		return errors.New("TLS client authentication is enabled, but TLS is not enabled")
	}
	return nil
}

func Run(subdomain string, command []string) error {
	connections := int64(0)

	sub := &Subdomain{
		app : appSingleton,
		subdomain : subdomain,
		command : command,
		connections: &connections,
	}

	runningSubdomains[subdomain] = sub

	return nil
}

// func (app *App) handleSubdomain(subdomain string) (error) {
// 	return error.Error("sddsds")
// }

func (app *App) makeServer(addr string, handler *http.Handler) (*http.Server, error) {
	server := &http.Server{
		Addr:    addr,
		Handler: *handler,
	}

	if app.options.EnableTLSClientAuth {
		caFile := ExpandHomeDir(app.options.TLSCACrtFile)
		log.Log("CA file: " + caFile)
		caCert, err := ioutil.ReadFile(caFile)
		if err != nil {
			return nil, errors.New("Could not open CA crt file " + caFile)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("Could not parse CA crt file data in " + caFile)
		}
		tlsConfig := &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		}
		server.TLSConfig = tlsConfig
	}

	return server, nil
}

func handleWS(w http.ResponseWriter, request *http.Request) {

	domainParts := strings.Split(request.Host, ".")
	subdomain, ok := runningSubdomains[domainParts[0]]

	if( ok != true ) {
		log.Error("No such domain: ", domainParts[0])
		return
	}

	connections := atomic.AddInt64(subdomain.connections, 1)
	if int64(subdomain.app.options.MaxConnection) != 0 {
		if connections >= int64(subdomain.app.options.MaxConnection) {
			log.Log("Reached max connection: %d", subdomain.app.options.MaxConnection)
			return
		}
	}
	log.Log("New client connected: %s", request.RemoteAddr)

	if request.Method != "GET" {
		http.Error(w, "Method not allowed", 405)
		return
	}

	conn, err := subdomain.app.upgrader.Upgrade(w, request, nil)
	if err != nil {
		log.Error("Failed to upgrade connection: " + err.Error())
		return
	}

	_, stream, err := conn.ReadMessage()
	if err != nil {
		log.Error("Failed to authenticate websocket connection")
		conn.Close()
		return
	}
	var init InitMessage

	err = json.Unmarshal(stream, &init)
	if err != nil {
		log.Log("Failed to parse init message %v", err)
		conn.Close()
		return
	}
	if init.AuthToken != subdomain.app.options.Credential {
		log.Error("Failed to authenticate websocket connection")
		conn.Close()
		return
	}

	subdomain.app.server.StartRoutine()

	if subdomain.app.options.Once {
		if subdomain.app.onceMutex.TryLock() { // no unlock required, it will die soon
			log.Log("Last client accepted, closing the listener.")
			subdomain.app.server.Close()
		} else {
			log.Log("Server is already closing.")
			conn.Close()
			return
		}
	}

	cmd := exec.Command(subdomain.command[0], subdomain.command[1:]...)
	ptyIo, err := pty.Start(cmd)
	if err != nil {
		log.Error("Failed to execute command")
		return
	}

	if subdomain.app.options.MaxConnection != 0 {
		log.Log("Command is running for client %s with PID %d (args=%q), connections: %d/%d",
			request.RemoteAddr, cmd.Process.Pid, strings.Join(subdomain.command, " "), connections, subdomain.app.options.MaxConnection)
	} else {
		log.Log("Command is running for client %s with PID %d (args=%q), connections: %d",
			request.RemoteAddr, cmd.Process.Pid, strings.Join(subdomain.command, " "), connections)
	}

	context := &clientContext{
		app:        subdomain.app,
		subdomain : subdomain,
		request:    request,
		connection: conn,
		command:    cmd,
		pty:        ptyIo,
		writeMutex: &sync.Mutex{},
	}

	go func() {
		channel := context.goHandleClient()
		<-channel

		if( int64(*subdomain.connections) == 0 ) {
			Emitter.Publish("close", map[string]interface{}{
				"subdomain"  : subdomain.subdomain,
			})
		}
		log.Info("Connections: ", int64(*subdomain.connections))
	}()
}

func (app *App) handleCustomIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, ExpandHomeDir(app.options.IndexFile))
}

func (app *App) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.Write([]byte("var gotty_auth_token = '" + app.options.Credential + "';"))
}

func Exit() (firstCall bool) {
	if appSingleton.server != nil {
		firstCall = appSingleton.server.Close()
		if firstCall {
			log.Log("Received Exit command, waiting for all clients to close sessions...")
		}
		return firstCall
	}
	return true
}

func wrapLogger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseWrapper{w, 200}
		handler.ServeHTTP(rw, r)
		log.Info(r.RemoteAddr, rw.status, r.Method, r.URL.Path)
	})
}

func wrapHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "GoTTY/"+Version)
		handler.ServeHTTP(w, r)
	})
}

func wrapBasicAuth(handler http.Handler, credential string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		if len(token) != 2 || strings.ToLower(token[0]) != "basic" {
			w.Header().Set("WWW-Authenticate", `Basic realm="GoTTY"`)
			http.Error(w, "Bad Request", http.StatusUnauthorized)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(token[1])
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if credential != string(payload) {
			w.Header().Set("WWW-Authenticate", `Basic realm="GoTTY"`)
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		log.Log("Basic Authentication Succeeded: %s", r.RemoteAddr)
		handler.ServeHTTP(w, r)
	})
}

func generateRandomString(length int) string {
	const base = 36
	size := big.NewInt(base)
	n := make([]byte, length)
	for i, _ := range n {
		c, _ := rand.Int(rand.Reader, size)
		n[i] = strconv.FormatInt(c.Int64(), base)[0]
	}
	return string(n)
}

func listAddresses() (addresses []string) {
	ifaces, _ := net.Interfaces()

	addresses = make([]string, 0, len(ifaces))

	for _, iface := range ifaces {
		ifAddrs, _ := iface.Addrs()
		for _, ifAddr := range ifAddrs {
			switch v := ifAddr.(type) {
			case *net.IPNet:
				addresses = append(addresses, v.IP.String())
			case *net.IPAddr:
				addresses = append(addresses, v.IP.String())
			}
		}
	}

	return
}

func ExpandHomeDir(path string) string {
	if path[0:2] == "~/" {
		return os.Getenv("HOME") + path[1:]
	} else {
		return path
	}
}
