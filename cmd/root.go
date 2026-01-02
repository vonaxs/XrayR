package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"strings"
	"syscall"
	"time"
    "bytes"
    "encoding/base64"
    "encoding/json"
    "net/http"
	"net/url"
	"strconv"
    "io"
    "net"

	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/XrayR-project/XrayR/panel"
)

type BootstrapConfig struct {
    Nodes []struct {
        ApiConfig struct {
            ApiHost string `mapstructure:"ApiHost"`
            ApiKey  string `mapstructure:"ApiKey"`
            NodeID  int    `mapstructure:"NodeID"`
        } `mapstructure:"ApiConfig"`
    } `mapstructure:"Nodes"`
}

var (
	cfgFile string
	rootCmd = &cobra.Command{
		Use: "XrayR",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(); err != nil {
				log.Fatal(err)
			}
		},
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file for XrayR.")
}

func getConfig() *viper.Viper {
	config := viper.New()

	// Set custom path and name
	if cfgFile != "" {
		configName := path.Base(cfgFile)
		configFileExt := path.Ext(cfgFile)
		configNameOnly := strings.TrimSuffix(configName, configFileExt)
		configPath := path.Dir(cfgFile)
		config.SetConfigName(configNameOnly)
		config.SetConfigType(strings.TrimPrefix(configFileExt, "."))
		config.AddConfigPath(configPath)
		// Set ASSET Path and Config Path for XrayR
		os.Setenv("XRAY_LOCATION_ASSET", configPath)
		os.Setenv("XRAY_LOCATION_CONFIG", configPath)
	} else {
		// Set default config path
		config.SetConfigName("config")
		config.SetConfigType("yml")
		config.AddConfigPath(".")

	}

	if err := config.ReadInConfig(); err != nil {
		log.Panicf("Config file error: %s \n", err)
	}

	return config
}

func run() error {
	showVersion()

	// Localized boot configuration, which is then garbage collected upon completion.
	var boot *BootstrapConfig
	{
		bootstrapViper := getConfig()
		boot = &BootstrapConfig{}
		if err := bootstrapViper.Unmarshal(boot); err != nil {
			return fmt.Errorf("parse bootstrap config failed: %s", err)
		}
		// Explicit cleanup
		bootstrapViper = nil
	}

	if len(boot.Nodes) == 0 {
		return fmt.Errorf("bootstrap config invalid: no nodes found")
	}

	api := boot.Nodes[0].ApiConfig
	if api.ApiHost == "" || api.ApiKey == "" || api.NodeID <= 0 {
		return fmt.Errorf("bootstrap config invalid: ApiConfig incomplete")
	}

    //Retrieve the complete config.yml file from API.
	var (
		yamlBytes []byte
		err       error
	)

	for i := 0; i < 3; i++ {
		yamlBytes, err = fetchRemoteConfig(boot)
		if err == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}

	if err != nil {
		return fmt.Errorf("unable to connect to the API server: %w", err)
	}

	// Parse YAML and clean up the original slice memory
	config := viper.New()
	config.SetConfigType("yml")

	if err := config.ReadConfig(bytes.NewReader(yamlBytes)); err != nil {
		return fmt.Errorf("load config failed: %s", err)
	}
	yamlBytes = nil 		// Explicitly release the raw byte array

    //The subsequent logic remains completely unchanged
	panelConfig := &panel.Config{}
	if err := config.Unmarshal(panelConfig); err != nil {
		return fmt.Errorf("Parse config file %v failed: %s \n", cfgFile, err)
	}

	if panelConfig.LogConfig.Level == "debug" {
		log.SetReportCaller(true)
	}

	p := panel.New(panelConfig)

	p.Start()
	defer p.Close()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	// Running backend
	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, os.Interrupt, os.Kill, syscall.SIGTERM)
	<-osSignals

	return nil
}

// Retrieve the node configuration file config.yml from the server.
func fetchRemoteConfig(boot *BootstrapConfig) ([]byte, error) {
	apiHost := boot.Nodes[0].ApiConfig.ApiHost

	// Force HTTPS
	if !strings.HasPrefix(apiHost, "https://") {
		return nil, fmt.Errorf("ApiHost must use HTTPS")
	}
	
	// Obtain a public IPv4
	nodeIPv4 := getPublicIP("https://ipv4.icanhazip.com")
	if nodeIPv4 == "" {
		log.Warnf("ipv4.icanhazip.com failed, try api.ipify.org")
		nodeIPv4 = getPublicIP("https://api.ipify.org")
	}
	
	// Construct the URL (must use net/url, IPv6 required, otherwise it will crash).
	u, err := url.Parse(strings.TrimRight(apiHost, "/") + "/api/getNodeConfig")
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("key", boot.Nodes[0].ApiConfig.ApiKey)
	q.Set("node_id", strconv.Itoa(boot.Nodes[0].ApiConfig.NodeID))

	if nodeIPv4 != "" {
		q.Set("node_ipv4", nodeIPv4)
	}

	u.RawQuery = q.Encode()

	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Ret    int    `json:"ret"`
		Msg    string `json:"msg"`
		Config string `json:"config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Ret != 1 {
		if result.Msg != "" {
			return nil, fmt.Errorf("server rejected: %s", result.Msg)
		}
		return nil, fmt.Errorf("server rejected")
	}

	yamlBytes, err := base64.StdEncoding.DecodeString(result.Config)
	if err != nil {
		return nil, err
	}

	return yamlBytes, nil
}

// Obtain public IP address
func getPublicIP(endpoint string) string {
    client := &http.Client{
        Timeout: 5 * time.Second,
    }

    resp, err := client.Get(endpoint)
    if err != nil {
        return ""
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return ""
    }

    // 1. Limit read length to prevent memory exhaustion.
    limitReader := io.LimitReader(resp.Body, 64) 
    body, err := io.ReadAll(limitReader)
    if err != nil {
        return ""
    }

    // 2. Clean the data (remove redundant characters, line breaks, etc.)
    ipStr := strings.TrimSpace(string(body))

    // 3. Strictly verify whether the IP address is in a valid format.
    // net.ParseIP filters out all malicious strings that are not in IP format.
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return ""
    }

    return ip.String()
}

func Execute() error {
	return rootCmd.Execute()
}
