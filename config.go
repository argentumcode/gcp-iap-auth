package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/imkira/gcp-iap-auth/jwt"
	"github.com/jessevdk/go-flags"
)

type Options struct {
	ListenAddr      string `long:"listen-addr" env:"GCP_IAP_AUTH_LISTEN_ADDR" description:"Listen address"`
	ListenPort      int    `long:"listen-port" default:"-1" env:"GCP_IAP_AUTH_LISTEN_PORT" description:"Listen port (default: 80 for HTTP or 443 for HTTPS)"`
	Audiences       string `long:"audiences" env:"GCP_IAP_AUTH_AUDIENCES" description:"Comma-separated list of JWT Audiences"`
	PublicKeysPath  string `long:"public-keys" env:"GCP_IAP_AUTH_PUBLIC_KEYS" description:"Path to public keys file (optional)"`
	TlsCertPath     string `long:"tls-cert" env:"GCP_IAP_AUTH_TLS_CERT" description:"Path to TLS server's, intermediate's and CA's PEM certificate (optional)"`
	TlsKeyPath      string `long:"tls-key" env:"GCP_IAP_AUTH_TLS_KEY" description:"Path to TLS server's PEM key file (optional)"`
	Backend         string `long:"backend" env:"GCP_IAP_AUTH_BACKEND" description:"Proxy authenticated requests to the specified URL (optional)"`
	BackendInsecure bool   `long:"backend-insecure" env:"GCP_IAP_AUTH_BACKEND_INSECURE" description:"Skip verification TLS certificate of backend (optional)"`
	EmailHeader     string `long:"email-header" env:"GCP_IAP_AUTH_EMAIL_HEADER" default:"X-WEBAUTH-USER" description:"In proxy mode, set the authenticated email address in the specified header"`
	PublicKeysUrl   string `long:"public-keys-url" env:"GCP_IAP_AUTH_PUBLIC_KEYS_URL" default:"https://www.gstatic.com/iap/verify/public_key" description:"URL to fetch public keys from (optional)"`
}

func initConfigByArgs(args []string) (*jwt.Config, *Options, error) {
	opts := &Options{}
	args, err := flags.NewParser(opts, flags.HelpFlag|flags.PassDoubleDash).ParseArgs(args)
	if err != nil {
		return nil, nil, err
	}
	if len(args) > 0 {
		return nil, nil, errors.New("extra arguments found")
	}
	opts.initServerPort()
	if opts.Audiences == "" {
		return nil, nil, errors.New("you must specify --audiences")
	}
	cfg := &jwt.Config{}
	if err := initAudiences(cfg, opts.Audiences); err != nil {
		return nil, nil, err
	}
	if err := initPublicKeys(cfg, opts.PublicKeysPath, opts.PublicKeysUrl); err != nil {
		return nil, nil, err
	}
	return cfg, opts, nil
}

func initConfig() (*jwt.Config, *Options, error) {
	return initConfigByArgs(os.Args[1:])
}

func (o *Options) initServerPort() {
	if o.ListenPort == -1 {
		if o.TlsCertPath != "" || o.TlsKeyPath != "" {
			o.ListenPort = 443
		} else {
			o.ListenPort = 80
		}
	}
}

func initAudiences(cfg *jwt.Config, audiences string) error {
	str, err := extractAudiencesRegexp(audiences)
	if err != nil {
		return err
	}
	re, err := regexp.Compile(str)
	if err != nil {
		return fmt.Errorf("Invalid audiences regular expression %q (%v)", str, err)
	}
	cfg.MatchAudiences = re
	return nil
}

func extractAudiencesRegexp(audiences string) (string, error) {
	var strs []string
	for _, audience := range strings.Split(audiences, ",") {
		str, err := extractAudienceRegexp(audience)
		if err != nil {
			return "", err
		}
		strs = append(strs, str)
	}
	return strings.Join(strs, "|"), nil
}

func extractAudienceRegexp(audience string) (string, error) {
	if strings.HasPrefix(audience, "/") && strings.HasSuffix(audience, "/") {
		if len(audience) < 3 {
			return "", fmt.Errorf("Invalid audiences regular expression %q", audience)
		}
		return audience[1 : len(audience)-1], nil
	}
	return parseRawAudience(audience)
}

func parseRawAudience(audience string) (string, error) {
	aud, err := jwt.ParseAudience(audience)
	if err != nil {
		return "", fmt.Errorf("Invalid audience %q (%v)", audience, err)
	}
	return fmt.Sprintf("^%s$", regexp.QuoteMeta((string)(*aud))), nil
}

func initPublicKeys(cfg *jwt.Config, filePath string, keyURL string) error {
	cfg.PublicKeys = jwt.NewKeyStore(filePath, keyURL)
	if err := cfg.PublicKeys.UpdateKeys(); err != nil {
		return err
	}
	return cfg.Validate()
}
