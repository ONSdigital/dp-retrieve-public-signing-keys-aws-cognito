package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

var validJWKS = JWKS{
	Keys: []JsonKey{
		{
			Alg: "RS256",
			E:   "AQAB",
			Kid: "j+diD4wBP/VZ4+X51XGRdI8Vi0CNV0OpEefKl1ge3A8=",
			Kty: "RSA",
			N:   "vBvi--N-F9MQO81xh71jIbkx81w4_sGhbztTJgIdhycV-lMzG6y3dMBWo9eRsFJuRs3MUFElmRrTVxc7EPWNQGQjUyPFW0_CnPPoGBCwgCyWtpNs5EHAkCHXsfryHb6LbJxH9LEbwOQCHR25_Bnqo_NeXSBJtvUabq3cTUgdOPc61Hskq-m19M1u7u1xu7b5DHD308Qyz3OhaEHx3cLL2za-mKxHe0VDe3sa5UfdaliTdBypFWJgNl6TsxF_G83fksgb3bVchzW45pu4dEhtNLqgXejH2-GwU8YRaAguKGW7dO_v-5uwLgDYQG9wgtAwLIMiXsFU7muig2pJEtlG2w",
			Use: "sig",
		},
		{
			Alg: "RS256",
			E:   "AQAB",
			Kid: "Oe/15Omy/K78yrUh2EI6xiQSRyeD5f8D/bcI/UphRR8=",
			Kty: "RSA",
			N:   "6MMhL-GcDj8LspuAes_ZycMTOYUkjURF-3z5vFtn0roie0LlcSgXN9i7VEsU7a-CTdqzBXhm_D4Yu9-RcVYJb8upyzWfrK53l4UoeNrQGhbjZlGKqnuQgU20lRqhKPqmHtAejm81XaW2T-z_bM2oL4U4RjOe5KaWLCpFe8IB92aTFZfXsPcfSodwQar7Po4TsRMg3iqqTk-jxySSYgj72XaCD5c3TojC6rdD_ll1dVub0LYjMESDnfFXDY4iCakk1l5MBwgEXDabJuNajfAotrFUN6svfb9DlXYSR9E_VYKxeDGdWB3QPIoieA_hpNhSM4nhWUApamxaCRC6g4dJjQ",
			Use: "sig",
		},
	},
}

func TestConvertJwksToRsaJsonResponse(t *testing.T) {
	Convey("Enter a valid JWKS - check expected response", t, func() {
		response, err := convertJwksToRsaJsonResponse(validJWKS)
		So(response, ShouldNotResemble, nil)
		So(err, ShouldEqual, nil)
	})
	Convey("Enter an empty JWKS - check expected error is returned", t, func() {
		emptyJWKS := JWKS{}
		response, err := convertJwksToRsaJsonResponse(emptyJWKS)
		So(response, ShouldEqual, nil)
		So(err.Error(), ShouldEqual, "empty JWKS")
	})
}

func TestConvertJwkToRsa(t *testing.T) {
	Convey("Enter a valid JWK - check expected response", t, func() {
		response, err := convertJwkToRsa(validJWKS.Keys[0])
		So(response, ShouldNotEqual, "")
		So(err, ShouldEqual, nil)
	})
	Convey("Enter an unsupported key type - check expected error is returned", t, func() {
		validJWKS.Keys[0].Kty = "ABC"
		response, err := convertJwkToRsa(validJWKS.Keys[0])
		So(response, ShouldEqual, "")
		So(err.Error(), ShouldEqual, "unsupported key type. Must be rsa key")
		validJWKS.Keys[0].Kty = "RSA"
	})
	Convey("Enter an invalid N value - check expected error is returned", t, func() {
		validJWKS.Keys[0].N = "!"
		response, err := convertJwkToRsa(validJWKS.Keys[0])
		So(response, ShouldEqual, "")
		So(err.Error(), ShouldEqual, "error decoding JWK")
		validJWKS.Keys[0].N = "vBvi--N-F9MQO81xh71jIbkx81w4_sGhbztTJgIdhycV-lMzG6y3dMBWo9eRsFJuRs3MUFElmRrTVxc7EPWNQGQjUyPFW0_CnPPoGBCwgCyWtpNs5EHAkCHXsfryHb6LbJxH9LEbwOQCHR25_Bnqo_NeXSBJtvUabq3cTUgdOPc61Hskq-m19M1u7u1xu7b5DHD308Qyz3OhaEHx3cLL2za-mKxHe0VDe3sa5UfdaliTdBypFWJgNl6TsxF_G83fksgb3bVchzW45pu4dEhtNLqgXejH2-GwU8YRaAguKGW7dO_v-5uwLgDYQG9wgtAwLIMiXsFU7muig2pJEtlG2w"
	})
	Convey("Enter an unsupported exponent value - check expected error is returned", t, func() {
		validJWKS.Keys[0].E = "ABC"
		response, err := convertJwkToRsa(validJWKS.Keys[0])
		So(response, ShouldEqual, "")
		So(err.Error(), ShouldEqual, "unexpected exponent: unable to decode JWK")
		validJWKS.Keys[0].E = "AQAB"
	})
}

type MockJWKSRetriever struct{}

func (mjr MockJWKSRetriever) RetrieveJWKS(region, userPoolId string) (io.ReadCloser, int, error) {
	resp := `{"keys": [{"alg":"RS256","e":"AQAB","kid":"j+diD4wBP/VZ4+X51XGRdI8Vi0CNV0OpEefKl1ge3A8=","kty":"RSA","n":"vBvi--N-F9MQO81xh71jIbkx81w4_sGhbztTJgIdhycV-lMzG6y3dMBWo9eRsFJuRs3MUFElmRrTVxc7EPWNQGQjUyPFW0_CnPPoGBCwgCyWtpNs5EHAkCHXsfryHb6LbJxH9LEbwOQCHR25_Bnqo_NeXSBJtvUabq3cTUgdOPc61Hskq-m19M1u7u1xu7b5DHD308Qyz3OhaEHx3cLL2za-mKxHe0VDe3sa5UfdaliTdBypFWJgNl6TsxF_G83fksgb3bVchzW45pu4dEhtNLqgXejH2-GwU8YRaAguKGW7dO_v-5uwLgDYQG9wgtAwLIMiXsFU7muig2pJEtlG2w","use":"sig"}]}`
	readCloserResp := io.NopCloser(strings.NewReader(resp))
	return readCloserResp, 200, nil
}

type JWKSRetrieverError struct{}

func (jre JWKSRetrieverError) RetrieveJWKS(region, userPoolId string) (io.ReadCloser, int, error) {
	resp := `{"message":"User pool eu-west-1_hfhty does not exist."}`
	readCloserResp := io.NopCloser(strings.NewReader(resp))
	return readCloserResp, 404, nil
}

var ctx = context.Background()

func TestUserPoolIdHandler(t *testing.T) {
	Convey("Given a user pool id handler", t, func() {
		Convey("Given a valid JWKS is retrieved, check expected response", func() {
			mjr := new(MockJWKSRetriever)
		    userPoolIdHandler := UserPoolIdHandler(ctx, mjr)
			req := httptest.NewRequest("GET", "http://localhost:25999/region/userPoolId", nil)
			resp := httptest.NewRecorder()
			expectedResponse := `{"j+diD4wBP/VZ4+X51XGRdI8Vi0CNV0OpEefKl1ge3A8=":"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvBvi++N+F9MQO81xh71jIbkx81w4/sGhbztTJgIdhycV+lMzG6y3dMBWo9eRsFJuRs3MUFElmRrTVxc7EPWNQGQjUyPFW0/CnPPoGBCwgCyWtpNs5EHAkCHXsfryHb6LbJxH9LEbwOQCHR25/Bnqo/NeXSBJtvUabq3cTUgdOPc61Hskq+m19M1u7u1xu7b5DHD308Qyz3OhaEHx3cLL2za+mKxHe0VDe3sa5UfdaliTdBypFWJgNl6TsxF/G83fksgb3bVchzW45pu4dEhtNLqgXejH2+GwU8YRaAguKGW7dO/v+5uwLgDYQG9wgtAwLIMiXsFU7muig2pJEtlG2wIDAQAB"}`

			userPoolIdHandler.ServeHTTP(resp, req)

			So(resp.Code, ShouldEqual, http.StatusOK)
			So(resp.Body.String(), ShouldResemble, expectedResponse)
		})

		Convey("Given an error message returned from cognito, check expected error message is returned to user", func() {
			jre := new(JWKSRetrieverError)
		    userPoolIdHandler := UserPoolIdHandler(ctx, jre)
			req := httptest.NewRequest("GET", "http://localhost:25999/region/userPoolId", nil)
			resp := httptest.NewRecorder()
			expectedResponse := `"User pool  in region  not found. Try changing the region or user pool ID."`

			userPoolIdHandler.ServeHTTP(resp, req)

			So(resp.Code, ShouldEqual, http.StatusOK)
			So(resp.Body.String(), ShouldResemble, expectedResponse)
		})
	})
}
