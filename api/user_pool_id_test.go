package api

import (
	"fmt"
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
	response, err := convertJwksToRsaJsonResponse(validJWKS)
	Convey("Enter a valid JWKS - check expected response", t, func() {
		So(response, ShouldNotResemble, nil)
		So(err, ShouldEqual, nil)
	})
}

func TestConvertJwkToRsa(t *testing.T) {
	Convey("Enter a valid JWK - check expected response", t, func() {
		response, err := convertJwkToRsa(validJWKS.Keys[0])
		So(response, ShouldNotEqual, "")
		So(err, ShouldEqual, nil)
	})
	Convey("Enter an unsupported key type - check expected error is returned", t, func() {
		validJWKS.Keys[0].Kty="ABC"
		response, err := convertJwkToRsa(validJWKS.Keys[0])
		So(response, ShouldEqual, "")
		So(err.Error(), ShouldEqual, "unsupported key type. Must be rsa key")
		validJWKS.Keys[0].Kty = "RSA"
	})
	Convey("Enter an invalid N value - check expected error is returned", t, func() {
		validJWKS.Keys[0].N="!"
		response, err := convertJwkToRsa(validJWKS.Keys[0])
		So(response, ShouldEqual, "")
		So(err.Error(), ShouldEqual, "error decoding JWK")
		validJWKS.Keys[0].N="vBvi--N-F9MQO81xh71jIbkx81w4_sGhbztTJgIdhycV-lMzG6y3dMBWo9eRsFJuRs3MUFElmRrTVxc7EPWNQGQjUyPFW0_CnPPoGBCwgCyWtpNs5EHAkCHXsfryHb6LbJxH9LEbwOQCHR25_Bnqo_NeXSBJtvUabq3cTUgdOPc61Hskq-m19M1u7u1xu7b5DHD308Qyz3OhaEHx3cLL2za-mKxHe0VDe3sa5UfdaliTdBypFWJgNl6TsxF_G83fksgb3bVchzW45pu4dEhtNLqgXejH2-GwU8YRaAguKGW7dO_v-5uwLgDYQG9wgtAwLIMiXsFU7muig2pJEtlG2w"
	})
}
