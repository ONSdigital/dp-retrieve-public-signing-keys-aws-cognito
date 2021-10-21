package api

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"

	"github.com/gorilla/mux"
)

type JsonKey struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

type JWKS struct {
	Keys []JsonKey `json:"keys"`
}

type CognitoErrResponse struct {
	Message string `json:"message"`
}

type ErrResponse struct {
	Error string
}

func UserPoolIdHandler(ctx context.Context) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		region := mux.Vars(req)["region"]
		userPoolId := mux.Vars(req)["userPoolId"]
		cognitoUrl := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolId)
		resp, err := http.Get(cognitoUrl)
		body, _ := ioutil.ReadAll(resp.Body)
		if err != nil {
			var cognitoErrResponse CognitoErrResponse
			json.Unmarshal(body, &cognitoErrResponse)
			var errResponse = ErrResponse{Error: cognitoErrResponse.Message}
			jsonResponse, err := json.Marshal(errResponse)
			if err != nil {
				log.Printf("Failed to convert error response object into json.\nError:%s\n", err.Error())
			}
			w.Write(jsonResponse)
			return
		}
		var jwks JWKS
		json.Unmarshal(body, &jwks)
		jsonResponse, err := convertJwksToRsaJsonResponse(jwks)
		if err != nil {
			errorMessage, _ := json.Marshal("Failed to retrieve RSA public key")
			w.Write(errorMessage)
			return
		}
		w.Write(jsonResponse)
	}
}

func convertJwksToRsaJsonResponse(jwks JWKS) ([]byte, error) {
	var response = make(map[string]string)
	var err error
	for _, jwk := range jwks.Keys {
		response[jwk.Kid], err = convertJwkToRsa(jwk)
		if err != nil {
			log.Println("Failed to retrieve RSA public key")
			return nil, err
		}
	}
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to convert Response object into json.\nError:%s\n", err.Error())
		return nil, err
	}

	return jsonResponse, nil
}

func convertJwkToRsa(jwk JsonKey) (string, error) {
	if jwk.Kty != "RSA" {
		log.Println("unsupported key type:", jwk.Kty)
		return "", errors.New("unsupported key type. Must be rsa key")
	}

	// decode the base64 bytes for n
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		log.Println(err)
		return "", errors.New("error decoding JWK")
	}

	e := 0
	// The default exponent is usually 65537, so just compare the
	// base64 for [1,0,1] or [0,1,0,1]
	if jwk.E == "AQAB" || jwk.E == "AAEAAQ" {
		e = 65537
	} else {
		// need to decode "e" as a big-endian int
		log.Println("need to decode e:", jwk.E)
		return "", errors.New("unexpected exponent: unable to decode JWK")
	}

	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}

	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		log.Println(err)
		return "", errors.New("unsupported key type. Must be rsa key")
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}

	var out bytes.Buffer
	err = pem.Encode(&out, block)
	if err != nil {
		log.Println("error writing RSA public key to out")
		return "", errors.New("error writing RSA public key to out")
	}
	return out.String(), nil
}
