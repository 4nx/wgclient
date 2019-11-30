package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/sendgrid/rest"
	"github.com/sevlyar/go-daemon"
	"gopkg.in/yaml.v3"
)

const shortUsage = `Usage: wgclient [OPTION]:

Options:
  -config=/home/foo/config.yml   configuration file (default: /etc/wireguard/config.yml)
  -wgconfig=/opt/wg0.conf        wireguard config file (default: /etc/wireguard/wg0.conf)
  -help                          display this help text and exit
  -version                       display version information and exit
`

// validate instance of go-playground validator v10
var validate *validator.Validate

// Version of this program
var version = "v0.2-dev"

// Auth struct for login response
type Auth struct {
	SessionID string `json:"sessionID" validate:"required,uuid_rfc4122"`
	Username  string `json:"username" validate:"required,printascii,max=50"`
	Givenname string `json:"givenname" validate:"required,printascii,max=50"`
	Surname   string `json:"surname" validate:"required,printascii,max=50"`
}

// Config struct for configuration file
type Config struct {
	Server struct {
		Host         string `yaml:"host" validate:"required,ipv4|ipv6|hostname|fqdn"`
		Port         string `yaml:"port" validate:"required,numeric,min=2,max=5"`
		DNS          string `yaml:"dns" validate:"required,ipv4|ipv6"`
		AllowedIPs   string `yaml:"allowedIPs" validate:"required,ipv4|ipv6|cidrv4|cidrv6"`
		PrivateKey   string `yaml:"private_key" validate:"required,file"`
		PublicKey    string `yaml:"public_key" validate:"required,file`
		PresharedKey string `yaml:"preshared_key" validate:"required,file"`
	} `yaml:"server"`
	API struct {
		Host           string `yaml:"host" validate:"required,url"`
		User           string `yaml:"user" validate:"required,printascii,max=50"`
		Pass           string `yaml:"pass" validate:"required,printascii,max=50"`
		BasicUser      string `yaml:"basic_user" validate:"required,printascii,max=50"`
		BasicPass      string `yaml:"basic_pass" validate:"required,printascii,max=50"`
		QueryFrequency int    `yaml:"query_frequency" validate:"required,numeric,min=4,max=10`
	} `yaml:"api"`
	APIEndpoints struct {
		SessionCreate string `yaml:"session_create" validate:"required,uri"`
		KeypairList   string `yaml:"keypair_list" validate:"required,uri"`
	} `yaml:"api_endpoints"`
}

// Keys struct for holding keypairs
type Keys []struct {
	ID        string `json:"_id" validate:"required,hexadecimal,len=24"`
	UserID    string `json:"userID" validate:"required,printascii"`
	PublicKey string `json:"publicKey" validate:"required,printascii,len=44"`
	Caption   string `json:"caption" validate:"printascii,max=50"`
	IPAddr    string `json:"ipAddr" validate:"required,ipv4"`
}

// basicAuth returns the base64 encoded string of user and pass
func basicAuth(user, pass string) string {
	auth := user + ":" + pass
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// checkFilePermissions checks the permissions of given files
func checkFilePermission(path string) bool {
	info, _ := os.Stat(path)
	mode := info.Mode()
	if mode <= 0o600 {
		return true
	}
	log.Fatalf("ERROR: File permission to permissive (should be at least 600): %#o", mode)
	return false
}

// createSession calls the login API process to authenticate and requests the
// ID for further requests
func createSession(cfg *Config, headers map[string]string) *Auth {
	var k Auth
	// baseURL Buildings
	baseURL := cfg.API.Host + cfg.APIEndpoints.SessionCreate

	// method will be set to HTTP GET
	method := rest.Get

	// Build the query parameters
	queryParams := make(map[string]string)
	queryParams["username"] = cfg.API.User
	queryParams["password"] = cfg.API.Pass

	// Make the API call
	request := rest.Request{
		Method:      method,
		BaseURL:     baseURL,
		Headers:     headers,
		QueryParams: queryParams,
	}

	response, err := rest.Send(request)
	if err != nil {
		log.Fatalf("ERROR: API request failed: %s", err)
	}
	//fmt.Println(response.StatusCode)
	//fmt.Println(response.Body)
	//fmt.Println(response.Headers)

	err = json.Unmarshal([]byte(response.Body), &k)
	if err != nil {
		log.Fatalf("ERROR: Response body can not be unmarshalled: %s", err)
	}
	err = validate.Struct(k)
	if err != nil {
		log.Fatalf("ERROR: Input API validation error: %s", err)
	}

	return &k
}

// createWgConfig builds the configuration string
func createWgConfig(cfg *Config, keys *Keys) string {
	buf := bytes.Buffer{}
	buf.WriteString("[Interface]\n")
	buf.WriteString("Address = " + cfg.Server.Host + "\n")
	buf.WriteString("ListenPort = " + string(cfg.Server.Port) + "\n")
	buf.WriteString("PrivateKey = " + string(readPrivateKey(cfg.Server.PrivateKey)) + "\n")
	buf.WriteString("SaveConfig = true\n\n")

	for _, v := range *keys {
		buf.WriteString("[Peer]\n")
		buf.WriteString("# " + v.UserID + " (" + v.Caption + ")\n")
		buf.WriteString("PublicKey = " + v.PublicKey + "\n")
		buf.WriteString("AllowedIPs = " + v.IPAddr + "/32\n\n")
	}

	return buf.String()
}

// keypairList requests all wireguard public keys from the API
func keypairList(cfg *Config, headers map[string]string, sid string) *Keys {
	// Variable for the Keys struct
	var keys Keys

	// URL Buildings
	baseURL := cfg.API.Host + cfg.APIEndpoints.KeypairList

	// GET collection
	method := rest.Get

	queryParams := make(map[string]string)
	queryParams["sid"] = sid

	request := rest.Request{
		Method:      method,
		BaseURL:     baseURL,
		Headers:     headers,
		QueryParams: queryParams,
	}

	response, err := rest.Send(request)
	if err != nil {
		log.Fatalf("ERROR: API request failed: %s", err)
	}
	//fmt.Println(response.StatusCode)
	//fmt.Println(response.Body)
	//fmt.Println(response.Headers)

	err = json.Unmarshal([]byte(response.Body), &keys)
	if err != nil {
		log.Fatalf("ERROR: Response body can not be unmarshalled: %s", err)
	}
	for _, v := range keys {
		err = validate.Struct(v)
		if err != nil {
			log.Fatalf("ERROR: Input API validation error: %s", err)
		}
	}

	return &keys
}

// pathExists checks if the given file exists
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readConfig reads the yaml config from given path
func readConfig(cfg *Config, config string) {
	if pathExists(config) && checkFilePermission(config) {
		// Open the config file
		f, err := os.Open(config)
		if err != nil {
			log.Fatalf("ERROR: %s", err)
		}
		defer f.Close() // f.Close will run when we're finished.

		decoder := yaml.NewDecoder(f)
		err = decoder.Decode(&cfg)
		if err != nil {
			log.Fatalf("ERROR: yaml config has unknown format: %s", err)
		}
		err = validate.Struct(cfg)
		if err != nil {
			log.Fatalf("ERROR: config validation error: %s", err)
		}
	} else {
		log.Fatalf("ERROR: config file %s does not exist", config)
	}
}

// readPresharedKey reads the preshared key to write it to wireguard config
func readPresharedKey(presharedKeyFile string) []byte {
	// Open the preshared key file
	f, err := os.Open(presharedKeyFile)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
	defer f.Close() // f.Close will run when we're finished.
	p := bufio.NewReader(f)
	presharedKey, err := p.Peek(44)
	return presharedKey
}

// readPrivateKey reads the private key to write it to wireguard config
func readPrivateKey(privateKeyFile string) []byte {
	// Open the private key file
	f, err := os.Open(privateKeyFile)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
	defer f.Close() // f.Close will run when we're finished.
	p := bufio.NewReader(f)
	privateKey, err := p.Peek(44)
	return privateKey
}

// readPublicKey reads the public key
func readPublicKey(publicKeyFile string) []byte {
	// Open the public key file
	f, err := os.Open(publicKeyFile)
	if err != nil {
		log.Fatalf("ERROR: %s", err)
	}
	defer f.Close() // f.Close will run when we're finished.
	p := bufio.NewReader(f)
	publicKey, err := p.Peek(44)
	return publicKey
}

// writeWgConfig creates the wireguard wg0.conf file
func writeWgConfig(wgConfig string, wgConfigContent string) {
	if pathExists(wgConfig) {
		err := os.Remove(wgConfig)
		if err != nil {
			log.Fatalf("ERROR: %s", err)
		}
	}
	if !pathExists(wgConfig) {
		f, err := os.OpenFile(wgConfig, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("ERROR: %s", err)
		}
		defer f.Close() // f.Close will run when we're finished.

		w := bufio.NewWriter(f)
		_, err = fmt.Fprintf(w, "%s", wgConfigContent)
		w.Flush()
	}
}

func main() {
	validate = validator.New()
	// TODO: REMOVE THIS SHIT AS FAST AS POSSIBLE
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	var (
		configFlag   = flag.String("config", "config.yml", "")
		helpFlag     = flag.Bool("help", false, "")
		versionFlag  = flag.Bool("version", false, "")
		wgconfigFlag = flag.String("wgconfig", "wg0.conf", "")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
	}
	flag.Parse()
	if *helpFlag {
		fmt.Fprint(flag.CommandLine.Output(), shortUsage)
		return
	}
	if *versionFlag {
		fmt.Println(version)
		return
	}
	// Read config arguments
	var cfg Config
	readConfig(&cfg, *configFlag)

	// headers Basic Auth
	headers := make(map[string]string)
	headers["Authorization"] = "Basic " + basicAuth(cfg.API.BasicUser, cfg.API.BasicPass)

	cntxt := &daemon.Context{
		PidFileName: "wgclient.pid",
		PidFilePerm: 0644,
		LogFileName: "wgclient.log",
		LogFilePerm: 0640,
		WorkDir:     "./",
		Umask:       027,
		Args:        []string{"[go-daemon wgclient]"},
	}

	d, err := cntxt.Reborn()
	if err != nil {
		log.Fatal("Unable to run: ", err)
	}
	if d != nil {
		return
	}
	defer cntxt.Release()

	log.Print("- - - - - - - - - - - - - - -")
	log.Print("[wgclient daemon started]")

	for {
		// s will be set to session key
		s := createSession(&cfg, headers)
		keys := keypairList(&cfg, headers, s.SessionID)
		wgConfig := createWgConfig(&cfg, keys)
		writeWgConfig(*wgconfigFlag, wgConfig)
		time.Sleep(time.Second * time.Duration(cfg.API.QueryFrequency))
	}
}
