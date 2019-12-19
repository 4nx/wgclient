package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/sendgrid/rest"
	"github.com/sevlyar/go-daemon"
	log "github.com/sirupsen/logrus"
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
var version = "v0.1"

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
		Host             string `yaml:"host" validate:"required,ipv4|ipv6|hostname|fqdn"`
		Port             string `yaml:"port" validate:"required,numeric,min=2,max=5"`
		DNS              string `yaml:"dns" validate:"required,ipv4|ipv6"`
		InterfaceAddress string `yaml:"interface_address" validate:"required,cidrv4|cidrv6"`
		AllowedIPs       string `yaml:"allowedIPs" validate:"required,ipv4|ipv6|cidrv4|cidrv6"`
		PrivateKey       string `yaml:"private_key" validate:"required"`
		PublicKey        string `yaml:"public_key" validate:"required"`
		PresharedKey     string `yaml:"preshared_key" validate:"required"`
		LogFile          string `yaml:"log_file" validate:"required"`
	} `yaml:"server"`
	API struct {
		Host           string `yaml:"host" validate:"required,url"`
		User           string `yaml:"user" validate:"required,printascii,max=50"`
		Pass           string `yaml:"pass" validate:"required,printascii,max=50"`
		BasicUser      string `yaml:"basic_user" validate:"required,printascii,max=50"`
		BasicPass      string `yaml:"basic_pass" validate:"required,printascii,max=50"`
		QueryFrequency int    `yaml:"query_frequency" validate:"required,numeric,min=4,max=10"`
	} `yaml:"api"`
	APIEndpoints struct {
		ConfigUpdate  string `yaml:"config_update" validate:"required,uri"`
		KeypairList   string `yaml:"keypair_list" validate:"required,uri"`
		SessionCreate string `yaml:"session_create" validate:"required,uri"`
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
func getFilePermission(id string, path string) os.FileMode {
	log.WithFields(log.Fields{
		"session": id,
		"file":    path,
	}).Info("Check file permissions")

	info, err := os.Stat(path)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"file":    path,
			"error":   err,
		}).Fatal("Can not stat file")
	}
	mode := info.Mode()
	return mode
}

// createSession calls the login API process to authenticate and requests the
// ID for further requests
func createSession(id string, cfg *Config, headers map[string]string) *Auth {
	log.WithFields(log.Fields{
		"session": id,
	}).Info("Request session key")

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

	log.WithFields(log.Fields{
		"session": id,
		"url":     baseURL,
		"method":  method,
	}).Info("Sending request")

	response, err := rest.Send(request)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"error":   err,
		}).Error("Request failed")
		return nil
	}

	if response.StatusCode == 200 {
		err = json.Unmarshal([]byte(response.Body), &k)
		if err != nil {
			log.WithFields(log.Fields{
				"session": id,
				"error":   err,
			}).Error("Response body could not be unmarshalled")
			return nil
		}
		err = validate.Struct(k)
		if err != nil {
			log.WithFields(log.Fields{
				"session": id,
				"error":   err,
			}).Error("Input API validation error")
			return nil
		}
		return &k
	}
	log.WithFields(log.Fields{
		"session": id,
		"status":  response.StatusCode,
		"error":   http.StatusText(response.StatusCode),
	}).Error("Service not available")
	return nil
}

// createWgConfig builds the configuration string
func createWgConfig(id string, cfg *Config, keys *Keys) string {
	log.WithFields(log.Fields{
		"session": id,
	}).Info("Building new wireguard config file")

	buf := bytes.Buffer{}
	buf.WriteString("[Interface]\n")
	buf.WriteString("Address = " + cfg.Server.Host + "\n")
	buf.WriteString("ListenPort = " + string(cfg.Server.Port) + "\n")
	buf.WriteString("PrivateKey = " + string(readKey(id, cfg.Server.PrivateKey, os.FileMode(0400))) + "\n")
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
func keypairList(id string, cfg *Config, headers map[string]string, sid string) *Keys {
	log.WithFields(log.Fields{
		"session": id,
	}).Info("Request keypair list")

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

	log.WithFields(log.Fields{
		"session": id,
		"url":     baseURL,
		"method":  method,
	}).Info("Sending request")

	response, err := rest.Send(request)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"error":   err,
		}).Error("Request failed")
	}

	if response.StatusCode == 200 {
		err = json.Unmarshal([]byte(response.Body), &keys)
		if err != nil {
			log.WithFields(log.Fields{
				"session": id,
				"error":   err,
			}).Error("Response body could not be unmarshalled")
			return nil
		}
		for _, v := range keys {
			err = validate.Struct(v)
			if err != nil {
				log.WithFields(log.Fields{
					"session": id,
					"error":   err,
				}).Error("Input API validation error")
				return nil
			}
		}
		return &keys
	}
	log.WithFields(log.Fields{
		"session": id,
		"status":  response.StatusCode,
		"error":   http.StatusText(response.StatusCode),
	}).Error("Service not available")
	return nil
}

// pathExists checks if the given file exists
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readConfig reads the yaml config from given path
func readConfig(id string, cfg *Config, config string, mode os.FileMode) {
	log.WithFields(log.Fields{
		"session": id,
		"file":    config,
	}).Info("Read config file")

	fileMode := getFilePermission(id, config)
	if fileMode > mode {
		log.WithFields(log.Fields{
			"session": id,
			"file":    config,
		}).Fatalf("File permission to permissive (should be at least %s)", mode.String())
	}
	// Open the config file
	f, err := os.Open(config)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"file":    config,
			"error":   err,
		}).Fatal("Can not open config file")
	}
	defer f.Close() // f.Close will run when we're finished.

	decoder := yaml.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"file":    config,
			"error":   err,
		}).Fatal("Can not read YAML config file")
	}
	err = validate.Struct(cfg)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"file":    config,
			"error":   err,
		}).Fatal("YAML config validation error")
	}
}

// readKey reads all kind of wireguard keys (public, private, preshared) from files and returns it
func readKey(id string, keyFile string, mode os.FileMode) []byte {
	log.WithFields(log.Fields{
		"session": id,
		"file":    keyFile,
	}).Info("Read key file")

	fileMode := getFilePermission(id, keyFile)
	if fileMode > mode {
		log.WithFields(log.Fields{
			"session": id,
			"file":    keyFile,
		}).Fatalf("File permission to permissive (should be at least %s)", mode.String())
		return nil
	}

	f, err := os.Open(keyFile)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"file":    keyFile,
			"error":   err,
		}).Fatal("Can not open key file")
	}
	defer f.Close()

	p := bufio.NewReader(f)
	k, err := p.Peek(44)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"file":    keyFile,
			"error":   err,
		}).Fatal("Can not read key file")
	}
	return k
}

// sendConfig will send informations like host, port etc of the wireguard server to the API
func sendConfig(id string, cfg Config, headers map[string]string) {
	log.WithFields(log.Fields{
		"session": id,
	}).Info("Send config data to wgportal")

	// URL Buildings
	baseURL := cfg.API.Host + cfg.APIEndpoints.ConfigUpdate

	// GET collection
	method := rest.Post

	// Body struct for config data json
	type Body struct {
		Revision         string `json:"revision"`
		PeernetCidr      string `json:"peernetCidr"`
		PeernetRoutedIPs string `json:"peernetRoutedIPs"`
		WgDNS            string `json:"wgDNS"`
		WgHost           string `json:"wgHost"`
		WgPubkey         string `json:"wgPubkey"`
	}

	// Result struct for responses
	type Result struct {
		Result string `json:"result" validate:"required,printascii"`
	}

	var r Result

	// Take unix timestamp as revision
	now := time.Now()
	revision := strconv.FormatInt(now.Unix(), 10)

	// Get public key from file
	publicKey := string(readKey(id, cfg.Server.PublicKey, os.FileMode(0644)))

	// API need host and port combination
	host := cfg.Server.Host + ":" + cfg.Server.Port

	// encode json
	m := Body{revision, cfg.Server.InterfaceAddress, cfg.Server.AllowedIPs, cfg.Server.DNS, host, publicKey}
	body, err := json.Marshal(m)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"error":   err,
		}).Fatal("Body can not be marshalled")
	}

	// sid will be set to session key
	sid := createSession(id, &cfg, headers)
	if sid == nil {
		log.WithFields(log.Fields{
			"session": id,
		}).Fatal("Session creation failed")
	}

	queryParams := make(map[string]string)
	queryParams["sid"] = sid.SessionID

	request := rest.Request{
		Method:      method,
		BaseURL:     baseURL,
		Headers:     headers,
		QueryParams: queryParams,
		Body:        body,
	}

	log.WithFields(log.Fields{
		"session": id,
		"url":     baseURL,
		"method":  method,
	}).Info("Sending request")

	response, err := rest.Send(request)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"error":   err,
		}).Error("Request failed")
	}

	if response.StatusCode == 200 {
		err = json.Unmarshal([]byte(response.Body), &r)
		if err != nil {
			log.WithFields(log.Fields{
				"session": id,
				"error":   err,
			}).Fatalf("Response body could not be unmarshalled")
		}
		err = validate.Struct(r)
		if err != nil {
			log.WithFields(log.Fields{
				"session": id,
				"error":   err,
			}).Fatal("Input API validation error")
		}
		if r.Result != "success" {
			log.WithFields(log.Fields{
				"session": id,
				"error":   r.Result,
			}).Fatal("Request result unsuccessful")
		}
	} else {
		log.WithFields(log.Fields{
			"session": id,
			"status":  response.StatusCode,
			"error":   http.StatusText(response.StatusCode),
		}).Fatal("Service not available")
	}
}

// writeWgConfig creates the wireguard wg0.conf file
func writeWgConfig(id string, wgConfig string, wgConfigContent string) {
	log.WithFields(log.Fields{
		"session": id,
	}).Info("Write wireguard config file")

	f, err := os.OpenFile(wgConfig, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.WithFields(log.Fields{
			"session": id,
			"file":    wgConfig,
			"error":   err,
		}).Fatal("Can not open wireguard config file")
	}
	f.Truncate(0)
	f.Seek(0, 0)
	defer f.Close() // f.Close will run when we're finished.

	w := bufio.NewWriter(f)
	_, err = fmt.Fprintf(w, "%s", wgConfigContent)
	_ = err
	w.Flush()
}

func main() {
	var cfg Config

	var (
		configFlag   = flag.String("config", "config.yml", "")
		helpFlag     = flag.Bool("help", false, "")
		versionFlag  = flag.Bool("version", false, "")
		wgconfigFlag = flag.String("wgconfig", "wg0.conf", "")
	)
	id := uuid.New()

	validate = validator.New()
	// TODO: REMOVE THIS SHIT AS FAST AS POSSIBLE
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

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

	// read the config file
	readConfig(id.String(), &cfg, *configFlag, os.FileMode(0600))

	cntxt := &daemon.Context{
		PidFileName: "wgclient.pid",
		PidFilePerm: 0644,
		LogFileName: cfg.Server.LogFile,
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

	log.Print("-----------------------------")
	log.Print("[wgclient daemon started]")

	// TODO: REMOVE THIS SHIT AS FAST AS POSSIBLE
	// headers Basic Auth
	headers := make(map[string]string)
	headers["Authorization"] = "Basic " + basicAuth(cfg.API.BasicUser, cfg.API.BasicPass)

	sendConfig(id.String(), cfg, headers)

	for {
		id := uuid.New()

		// s will be set to session key
		s := createSession(id.String(), &cfg, headers)
		if s == nil {
			time.Sleep(time.Second * time.Duration(cfg.API.QueryFrequency))
			continue
		}

		keys := keypairList(id.String(), &cfg, headers, s.SessionID)
		if keys == nil {
			time.Sleep(time.Second * time.Duration(cfg.API.QueryFrequency))
			continue
		}

		wgConfig := createWgConfig(id.String(), &cfg, keys)
		writeWgConfig(id.String(), *wgconfigFlag, wgConfig)
		time.Sleep(time.Second * time.Duration(cfg.API.QueryFrequency))
	}
}
