package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	sigAlg  = "RS256"
	keyUse  = "sig"
	keyType = "RSA"
	keySize = 2048
)

type Keys struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	E   string `json:"e"`
	N   string `json:"n"`
}

var keyId = "key_id_1"

func main() {
	var key *rsa.PrivateKey
	key, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("Generated key, size:", keySize, "signature algorithm: ", sigAlg)

	loginHandler := func(w http.ResponseWriter, r *http.Request) {
		tokenString, _ := CreateToken("marek", key)
		payload := make(map[string]string)
		payload["access_token"] = tokenString

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	}

	keysHandler := func(w http.ResponseWriter, r *http.Request) {
		k1 := Key{
			Kid: keyId,
			Kty: keyType,
			Alg: sigAlg,
			Use: keyUse,
			E:   IntToBase64Url(key.PublicKey.E),
			N:   BigIntToBase64Url(key.PublicKey.N),
		}

		keys := Keys{
			Keys: []Key{k1},
		}
		b, err := json.Marshal(keys)
		if err != nil {
			fmt.Println(err)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprint(w, string(b))
	}

	m := mux.NewRouter()
	m.Handle("/oauth2/v1/keys", LogRequestMiddleware(http.HandlerFunc(keysHandler))).Methods("GET")
	m.Handle("/token", LogRequestMiddleware(http.HandlerFunc(loginHandler))).Methods("GET")

	fmt.Printf("GET /oauth2/v1/keys\nGET /token\n")

	log.Fatal(http.ListenAndServe("0.0.0.0:8080", m))
}

func LogRequestMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.URL)
		h.ServeHTTP(w, r)
	})
}

func CreateToken(sub string, key *rsa.PrivateKey) (string, error) {

	token := jwt.New(jwt.GetSigningMethod(sigAlg))
	token.Header["kid"] = keyId

	iat := time.Now()
	exp := time.Now().Add(time.Minute * 10)

	token.Claims = &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(iat),
		Subject:   sub,
		Issuer:    "go-idp-mock",
	}

	val, err := token.SignedString(key)
	if err != nil {

		return "", err
	}
	return val, nil
}

func IntToBase64Url(i int) string {
	var eBig big.Int
	eBig.SetUint64(uint64(i))
	return BigIntToBase64Url(&eBig)
}

func BigIntToBase64Url(b *big.Int) string {
	data := b.Bytes()
	s := base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(s, "=")
}