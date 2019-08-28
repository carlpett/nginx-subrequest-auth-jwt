package main

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/carlpett/nginx-subrequest-auth-jwt/logger"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	PublicKey   *ecdsa.PublicKey
	Logger      logger.Logger
	ValidClaims []map[string][]string
}

func newServer(logger logger.Logger) (*server, error) {
	cfg, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return nil, err
	}

	var config config
	err = yaml.Unmarshal(cfg, &config)
	if err != nil {
		return nil, err
	}

	// TODO: Only supports a single EC PubKey for now
	pubkey, err := jwt.ParseECPublicKeyFromPEM([]byte(config.ValidationKeys[0].KeyMaterial))
	if err != nil {
		return nil, err
	}

	if len(config.Claims) == 0 {
		return nil, fmt.Errorf("Claims configuration is empty")
	}

	return &server{
		PublicKey:   pubkey,
		Logger:      logger,
		ValidClaims: config.Claims,
	}, nil
}

type validationKey struct {
	Type        string `yaml:"type"`
	KeyMaterial string `yaml:"key"`
}

type config struct {
	ValidationKeys []validationKey       `yaml:"validationKeys"`
	Claims         []map[string][]string `yaml:"claims"`
}

func main() {
	logger := logger.NewLogger(os.Getenv("LOG_LEVEL"))

	server, err := newServer(logger)
	if err != nil {
		logger.Fatalw("Couldn't initialize server", "err", err)
	}

	logger.Infow("Starting server on :8080")

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/validate", server.validate)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "OK") })
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		logger.Fatalw("Error serving http", "err", err)
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

	var claims jwt.MapClaims
	token, err := request.ParseFromRequestWithClaims(r, request.AuthorizationHeaderExtractor, &claims, func(token *jwt.Token) (interface{}, error) {
		// TODO: Only supports EC for now
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return s.PublicKey, nil
	})
	if err != nil {
		s.Logger.Debugw("Failed to parse token", "err", err)
		return false
	}
	if !token.Valid {
		s.Logger.Debugw("Invalid token", "token", token.Raw)
		return false
	}
	if err := claims.Valid(); err != nil {
		s.Logger.Debugw("Got invalid claims", "err", err)
		return false
	}

	var valid bool
	for _, claimSet := range s.ValidClaims {
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
		s.Logger.Debugw("Token claims did not match required values", "validClaims", s.ValidClaims, "actualClaims", claims)
		return false
	}

	return true
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
