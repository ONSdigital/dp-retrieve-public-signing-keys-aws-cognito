package api

import (
	"encoding/json"
	"testing"
	. "github.com/smartystreets/goconvey/convey"
)

var testJWKS = JWKS{
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

func TestConvertKidToRsa(t *testing.T) {
	testJWKSSliceOfBytes, _ := json.Marshal(testJWKS)
	response := convertJwksToRsaJsonResponse(testJWKS)
	Convey("Given a valid JWKS we expect to receive a json response ", t, func() {
		So(response, ShouldEqual, testJWKSSliceOfBytes)
	})
}

// func TestConvertKidToRsa(t *testing.T) {
// 	t.Run("Given a valid JWKS we expect to receive a json response ", func(t *testing.T) {
// 		response := convertJwksToRsaJsonResponse(testJWKS)
// 		if reflect.TypeOf(response) != reflect.TypeOf([]uint8{}) {
// 			t.Errorf("the function failed to return the RSA public keys in the expected format, got %v want %v", response, reflect.TypeOf([]uint8{}))
// 		}
// 	})
// }
