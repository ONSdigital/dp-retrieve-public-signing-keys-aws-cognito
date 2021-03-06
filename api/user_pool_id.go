package api

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

type JWKSRetriever interface {
	RetrieveJWKS(region, userPoolId string) (io.ReadCloser, int, error)
}
type CognitoJWKSRetriever struct{}

func (cjr CognitoJWKSRetriever) RetrieveJWKS(region, userPoolId string) (io.ReadCloser, int, error) {
	cognitoUrl := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json", region, userPoolId)
	resp, err := http.Get(cognitoUrl)
	if err != nil {
		return nil, resp.StatusCode, errors.New("an error occurred whilst requesting JWKS from AWS Cognito")
	}
	return resp.Body, resp.StatusCode, nil
}

func UserPoolIdHandler(ctx context.Context, jr JWKSRetriever) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		region := mux.Vars(req)["region"]
		userPoolId := mux.Vars(req)["userPoolId"]
		jsonJwks, statusCode, err := jr.RetrieveJWKS(region, userPoolId)
		if err != nil {
			log.Println(err.Error())
			jsonResponse, err := json.Marshal(err.Error())
			if err != nil {
				log.Printf("Failed to convert error message into json.\nError:%s\n", err.Error())
			}
			w.Write(jsonResponse)
			return
		}
		if statusCode == 404 {
			errMessage := fmt.Sprintf("User pool %s in region %s not found. Try changing the region or user pool ID.", userPoolId, region)
			log.Println(errMessage)
			jsonResponse, err := json.Marshal(errMessage)
			if err != nil {
				log.Printf("Failed to convert error message into json.\nError:%s\n", err.Error())
			}
			w.Write(jsonResponse)
			return
		}
		body, err := ioutil.ReadAll(jsonJwks)
		if err != nil {
			log.Println(err.Error())
			return
		}
		var jwks JWKS
		json.Unmarshal(body, &jwks)
		jsonResponse, err := convertJwksToRsaJsonResponse(jwks)
		if err != nil {
			jsonResponse, err := json.Marshal("Failed to retrieve RSA public key")
			if err != nil {
				log.Printf("Failed to convert error message into json.\nError:%s\n", err.Error())
			}
			w.Write(jsonResponse)
			return
		}
		w.Write(jsonResponse)
	}
}

func convertJwksToRsaJsonResponse(jwks JWKS) ([]byte, error) {
	if len(jwks.Keys) == 0 {
		log.Println("Empty JWKS")
		return nil, errors.New("empty JWKS")
	}
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
	nb, err := b64.RawURLEncoding.DecodeString(jwk.N)
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
	}

	if err != nil {
		log.Println("error writing RSA public key to out")
		return "", errors.New("error writing RSA public key to out")
	}
	return b64.StdEncoding.EncodeToString(der), nil
}
