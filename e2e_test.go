package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"crypto/ecdsa"

	"github.com/golang-jwt/jwt/v4"
)

// Mock public key server
type MockHttpServer struct {
	mtx      sync.Mutex
	response []byte
	server   *http.Server
	addr     string
}

func NewMockHttpServer(t *testing.T) *MockHttpServer {
	srv := &http.Server{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen mock http server: %+v", err)
	}
	ret := &MockHttpServer{
		mtx:      sync.Mutex{},
		response: make([]byte, 0),
		server:   srv,
		addr:     l.Addr().String(),
	}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ret.mtx.Lock()
		defer ret.mtx.Unlock()
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(ret.response); err != nil {
			t.Errorf("Failed to write response: %+v", err)
		}
	})
	go func() {
		if err := srv.Serve(l); err != nil {
			if err != http.ErrServerClosed {
				t.Errorf("Mock http server failed: %+v", err)
			}
		}
	}()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("Failed to close mock http server: %+v", err)
		}
	})

	return ret
}

func (m *MockHttpServer) Addr() string {
	return m.addr
}

func (m *MockHttpServer) SetResponse(r []byte) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.response = r
}

func toPublicKeyString(t *testing.T, key any) string {
	bytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %+v", err)
	}
	pemPub := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}
	return string(pem.EncodeToMemory(pemPub))
}

func TestHealthHandler(t *testing.T) {
	mockServer := NewMockHttpServer(t)
	// Setup key
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %+v", err)
	}
	j, err := json.Marshal(map[string]string{
		"key1": toPublicKeyString(t, &key1.PublicKey),
	})
	if err != nil {
		t.Fatalf("Failed to marshal json: %+v", err)
	}
	mockServer.SetResponse(j)

	audience := "/projects/1/locations/global/backendServices/1"

	server, err := NewServerWithArgs([]string{
		"--audiences",
		audience,
		"--listen-addr",
		"127.0.0.1",
		"--listen-port",
		"0",
		"--public-keys-url",
		fmt.Sprintf("http://%s/", mockServer.Addr()),
	})
	if err != nil {
		t.Fatalf("Failed to create server: %+v", err)
	}
	defer server.Close()
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			t.Errorf("Failed to start server: %+v", err)
		}
	}()

	client := http.DefaultClient

	resp, err := client.Get(fmt.Sprintf("http://%s/healthz", server.ListenAddress()))
	if err != nil {
		t.Fatalf("Failed to send request: %+v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Unexpected response status: %s", resp.Status)
	}
}

func TestAuthHandler(t *testing.T) {
	mockServer := NewMockHttpServer(t)
	// Setup key
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %+v", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %+v", err)
	}
	j, err := json.Marshal(map[string]string{
		"key1": toPublicKeyString(t, &key1.PublicKey),
	})
	if err != nil {
		t.Fatalf("Failed to marshal json: %+v", err)
	}
	mockServer.SetResponse(j)

	audience := "/projects/1/locations/global/backendServices/1"

	server, err := NewServerWithArgs([]string{
		"--audiences",
		audience,
		"--listen-addr",
		"127.0.0.1",
		"--listen-port",
		"0",
		"--public-keys-url",
		fmt.Sprintf("http://%s/", mockServer.Addr()),
	})
	if err != nil {
		t.Fatalf("Failed to create server: %+v", err)
	}
	defer server.Close()
	go func() {
		err := server.ListenAndServe()
		if err != nil {
			t.Errorf("Failed to start server: %+v", err)
		}
	}()

	client := http.DefaultClient

	tokenByClaimsAndKey := func(claims jwt.Claims, kid string, key *ecdsa.PrivateKey) string {
		accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		accessToken.Header["kid"] = kid
		accessTokenStr, err := accessToken.SignedString(key)
		if err != nil {
			t.Fatalf("Failed to sign token: %+v", err)
		}
		return accessTokenStr
	}

	tokenByClaims := func(claims jwt.Claims) string {
		return tokenByClaimsAndKey(claims, "key1", key1)
	}

	testCases := []struct {
		Name           string
		AccessToken    string
		ExpectedStatus int
	}{
		{
			Name: "ValidToken",
			AccessToken: tokenByClaims(jwt.MapClaims{
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
				"aud": audience,
				"iss": "https://cloud.google.com/iap"}),
			ExpectedStatus: http.StatusOK,
		},
		{
			Name:           "NoToken",
			AccessToken:    "",
			ExpectedStatus: http.StatusUnauthorized,
		},
		{
			Name:           "InvalidToken",
			AccessToken:    "invalid-token",
			ExpectedStatus: http.StatusUnauthorized,
		},
		{
			Name: "ExpiredToken",
			AccessToken: tokenByClaims(jwt.MapClaims{
				"exp": time.Now().Add(-1 * time.Hour).Unix(),
				"iat": time.Now().Add(-65 * time.Minute).Unix(),
				"aud": audience,
				"iss": "https://cloud.google.com/iap",
			}),
			ExpectedStatus: http.StatusUnauthorized,
		},
		{
			Name: "FutureToken",
			AccessToken: tokenByClaims(jwt.MapClaims{
				"exp": time.Now().Add(15 * time.Hour).Unix(),
				"iat": time.Now().Add(5 * time.Minute).Unix(),
				"aud": audience,
				"iss": "https://cloud.google.com/iap",
			}),
			ExpectedStatus: http.StatusUnauthorized,
		},
		{
			Name: "InvalidAudience",
			AccessToken: tokenByClaims(jwt.MapClaims{
				"exp": time.Now().Add(15 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
				"aud": "/projects/2/aaaa",
				"iss": "https://cloud.google.com/iap",
			}),
			ExpectedStatus: http.StatusUnauthorized,
		},
		{
			Name: "InvalidIssuer",
			AccessToken: tokenByClaims(jwt.MapClaims{
				"exp": time.Now().Add(15 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
				"aud": "/projects/2/aaaa",
				"iss": "https://cloud.google.com/not_iap",
			}),
			ExpectedStatus: http.StatusUnauthorized,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/auth", server.ListenAddress()), nil)
			if err != nil {
				t.Fatalf("Failed to create request: %+v", err)
			}
			req.Header.Add(
				"x-goog-iap-jwt-assertion", testCase.AccessToken,
			)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to send request: %+v", err)
			}
			if resp.StatusCode != testCase.ExpectedStatus {
				t.Errorf("Unexpected response status: %s", resp.Status)
			}
		})
	}
	t.Run("Email_And_Subject_Header", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/auth", server.ListenAddress()), nil)
		if err != nil {
			t.Fatalf("Failed to create request: %+v", err)
		}
		req.Header.Add(
			"x-goog-iap-jwt-assertion", tokenByClaims(jwt.MapClaims{
				"exp":   time.Now().Add(1 * time.Hour).Unix(),
				"iat":   time.Now().Unix(),
				"aud":   audience,
				"iss":   "https://cloud.google.com/iap",
				"email": "user@example.com",
				"sub":   "3318417895",
			}),
		)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %+v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Unexpected response status: %s", resp.Status)
		}
		headerSubject := resp.Header.Get("x-authenticated-subject")
		if headerSubject != "3318417895" {
			t.Errorf("Unexpected subject header: %s", headerSubject)
		}
		headerEmail := resp.Header.Get("x-authenticated-email")
		if headerEmail != "user@example.com" {
			t.Errorf("Unexpected email header: %s", headerEmail)
		}
	})
	t.Run("LoadNewPublicKeyFromServer", func(t *testing.T) {
		j, err := json.Marshal(map[string]string{
			"key1": toPublicKeyString(t, &key1.PublicKey),
			"key2": toPublicKeyString(t, &key2.PublicKey),
		})
		if err != nil {
			t.Fatalf("Failed to marshal json: %+v", err)
		}
		mockServer.SetResponse(j)

		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/auth", server.ListenAddress()), nil)
		if err != nil {
			t.Fatalf("Failed to create request: %+v", err)
		}
		req.Header.Add(
			"x-goog-iap-jwt-assertion", tokenByClaimsAndKey(jwt.MapClaims{
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
				"aud": audience,
				"iss": "https://cloud.google.com/iap"}, "key2", key2),
		)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %+v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Unexpected response status: %s", resp.Status)
		}
	})
	t.Run("BadPublicKeyId", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/auth", server.ListenAddress()), nil)
		if err != nil {
			t.Fatalf("Failed to create request: %+v", err)
		}
		req.Header.Add(
			"x-goog-iap-jwt-assertion", tokenByClaimsAndKey(jwt.MapClaims{
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
				"aud": audience,
				"iss": "https://cloud.google.com/iap"}, "bad_key", key1),
		)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to send request: %+v", err)
		}
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Unexpected response status: %s", resp.Status)
		}
	})
}
