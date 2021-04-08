package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/carlpett/nginx-subrequest-auth-jwt/logger"

	"github.com/MicahParks/keyfunc"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/juliangruber/go-intersect"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
)

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of http requests handled",
	}, []string{"status"})
	validationTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "nginx_subrequest_auth_jwt_token_validation_time_seconds",
		Help:    "Number of seconds spent validating token",
		Buckets: prometheus.ExponentialBuckets(100*time.Nanosecond.Seconds(), 3, 6),
	})
)

const (
	claimsSourceStatic      = "static"
	claimsSourceQueryString = "queryString"
)

func init() {
	requestsTotal.WithLabelValues("200")
	requestsTotal.WithLabelValues("401")
	requestsTotal.WithLabelValues("405")
	requestsTotal.WithLabelValues("500")

	prometheus.MustRegister(
		requestsTotal,
		validationTime,
	)
}

type server struct {	
	Jwks 				keyfunc.JWKS
	Logger       		logger.Logger
	ClaimsSource 		string
	StaticClaims 		[]map[string][]string
}

func newServer(logger logger.Logger, configFilePath string) (*server, error) {
	cfg, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	var config config
	err = yaml.Unmarshal(cfg, &config)
	if err != nil {
		return nil, err
	}

	jwksUrl := config.JwksUrl;
	// Create the keyfunc options. Refresh the JWKS every hour and log errors.
	refreshInterval := time.Hour
	options := keyfunc.Options{
		RefreshInterval: &refreshInterval,
		RefreshErrorHandler: func(err error) {
			log.Printf("There was an error with the jwt.KeyFunc\nError: %s", err.Error())
		},
	}
	// Create the JWKS from the resource at the given URL.
	// jwks will be refreshed according to time interval set in options
	jwks, err := keyfunc.Get(jwksUrl, options)
	if err != nil {

		return nil, fmt.Errorf("failed to create JWKS from resource at the given URL.\nError: %s", err.Error())
	}


	//pubkey, err := jwt.ParseECPublicKeyFromPEM([]byte(config.ValidationKeys[0].KeyMaterial))
	// if err != nil {
	// 	return nil, err
	// }

	if !contains([]string{"static", "queryString"}, config.ClaimsSource) {
		return nil, fmt.Errorf("claimsSource parameter must be set and either 'static' or 'queryString'")
	}

	if config.ClaimsSource == claimsSourceStatic && len(config.StaticClaims) == 0 {
		return nil, fmt.Errorf("claims configuration is empty")
	}

	return &server{
		Jwks:         *jwks,
		Logger:       logger,
		ClaimsSource: config.ClaimsSource,
		StaticClaims: config.StaticClaims,
	}, nil
}

type validationKey struct {
	Type        string `yaml:"type"`
	KeyMaterial string `yaml:"key"`
}

type config struct {
	JwksUrl		   string 				 `yaml:"jwksUrl"`
	ValidationKeys []validationKey       `yaml:"validationKeys"`
	ClaimsSource   string                `yaml:"claimsSource"`
	StaticClaims   []map[string][]string `yaml:"claims"`
}

var (
	configFilePath = kingpin.Flag("config", "Path to configuration file").Default("config.yaml").ExistingFile()
	logLevel       = kingpin.Flag("log-level", "Log level").Default("info").Enum("debug", "info", "warn", "error", "fatal")

	tlsKey   = kingpin.Flag("tls-key", "Path to TLS key").ExistingFile()
	tlsCert  = kingpin.Flag("tls-cert", "Path to TLS cert").ExistingFile()
	bindAddr = kingpin.Flag("addr", "Address/port to serve traffic in TLS mode").Default(":8443").String()

	insecure         = kingpin.Flag("insecure", "Serve traffic unencrypted over http (default false)").Bool()
	insecureBindAddr = kingpin.Flag("insecure-addr", "Address/port to serve traffic in insecure mode").Default(":8080").String()
)

func main() {
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := logger.NewLogger(*logLevel)

	server, err := newServer(logger, *configFilePath)
	if err != nil {
		logger.Fatalw("Couldn't initialize server", "err", err)
	}

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/validate", server.validate)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "OK") })

	if *insecure {
		logger.Infow("Starting server", "addr", *insecureBindAddr)
		err = http.ListenAndServe(*insecureBindAddr, nil)
	} else {
		logger.Infow("Starting server", "addr", *bindAddr)
		if *tlsKey == "" || *tlsCert == "" {
			logger.Fatalw("tls-key and tls-cert are required in TLS mode")
		}
		err = http.ListenAndServeTLS(*bindAddr, *tlsCert, *tlsKey, nil)
	}
	if err != nil {
		logger.Fatalw("Error running server", "err", err)
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(b)
}

func (s *server) validate(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw}
	defer func() {
		if r := recover(); r != nil {
			s.Logger.Errorw("Recovered panic", "err", r)
			requestsTotal.WithLabelValues("500").Inc()
			w.WriteHeader(http.StatusInternalServerError)
		}
		s.Logger.Debugw("Handled validation request", "url", r.URL, "status", w.status, "method", r.Method, "userAgent", r.UserAgent())
	}()

	if r.Method != http.MethodGet {
		requestsTotal.WithLabelValues("405").Inc()
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if !s.validateDeviceToken(r) {
		requestsTotal.WithLabelValues("401").Inc()
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	requestsTotal.WithLabelValues("200").Inc()
	w.WriteHeader(http.StatusOK)
}


func (s *server) validateDeviceToken(r *http.Request) bool {
	t := time.Now()
	defer validationTime.Observe(time.Since(t).Seconds())

	jwtB64, err :=request.AuthorizationHeaderExtractor.ExtractToken(r);
	if err !=nil{
		s.Logger.Debugw("Failed to extract token from Autorization header", "err", err)
	}
	token ,err := jwt.Parse(jwtB64, s.Jwks.KeyFunc)

	// token, err := request.ParseFromRequestWithClaims(r, request.AuthorizationHeaderExtractor, &claims, func(token *jwt.Token) (interface{}, error) {
	
	// 	// TODO: Only supports EC for now
	// 	if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
	// 		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	// 	}
	// 	return s.ActivePublicKey, nil
	// })
	if err != nil {
		s.Logger.Debugw("Failed to parse token", "err", err)
		return false
	}
	if !token.Valid {
		s.Logger.Debugw("Invalid token", "token", token.Raw)
		return false
	}
	if err := token.Claims.Valid(); err != nil {
		s.Logger.Debugw("Got invalid claims", "err", err)
		return false
	}

	switch s.ClaimsSource {
	case claimsSourceStatic:
		return s.staticClaimValidator(token.Claims.(jwt.MapClaims))
	case claimsSourceQueryString:
		return s.queryStringClaimValidator(token.Claims.(jwt.MapClaims), r)
	default:
		s.Logger.Errorw("Configuration error: Unhandled claims source", "claimsSource", s.ClaimsSource)
		return false
	}
}

func (s *server) staticClaimValidator(claims jwt.MapClaims) bool {
	var valid bool
	for _, claimSet := range s.StaticClaims {
		valid = true
		for claimName, validValues := range claimSet {
			if !contains(validValues, claims[claimName].(string)) {
				valid = false
			}
		}
		if valid {
			break
		}
	}

	if !valid {
		s.Logger.Debugw("Token claims did not match required values", "validClaims", s.StaticClaims, "actualClaims", claims)
	}
	return valid
}

func (s *server) queryStringClaimValidator(claims jwt.MapClaims, r *http.Request) bool {
	validClaims := r.URL.Query()
	hasClaimsPrefixedKey := false
	for key := range validClaims {
		if strings.HasPrefix(key, "claims_") {
			hasClaimsPrefixedKey = true
		}
	}
	if len(validClaims) == 0 || !hasClaimsPrefixedKey {
		s.Logger.Warnw("No claims requirements sent, rejecting", "queryParams", validClaims)
		return false
	}
	s.Logger.Debugw("Validating claims from query string", "validClaims", validClaims)

	passedValidation := true
	for claimName, validValues := range validClaims {
		claimObj := claims[strings.TrimPrefix(claimName, "claims_")]

		switch claimVal := claimObj.(type) {
			case string:
				if  !contains(validValues, claimVal) {
					passedValidation = false
				}
			case []interface{}:
				actualClaims := make([]string, len(claimVal))
				for i, e := range claimVal {					
					claim := e.(string)
					actualClaims[i] = claim;
				}
				intersectResult :=intersect.Simple(validValues,actualClaims);
				// all required scopes from the query string must match 
				if len(intersectResult.([]interface{})) != len(validValues) {
					passedValidation = false
				}
			default:
				fmt.Errorf("I don't know how to handle claim object %T\n", claimObj)
		}

	}

	if !passedValidation {
		s.Logger.Debugw("Token claims did not match required values", "validClaims", validClaims, "actualClaims", claims)
	}
	return passedValidation
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
