package api

import (
	"context"

	"github.com/gorilla/mux"
)

//API provides a struct to wrap the api around
type API struct {
	Router *mux.Router
}

//Setup function sets up the api and returns an api
func Setup(ctx context.Context, r *mux.Router) *API {
	api := &API{
		Router: r,
	}
	cjr := CognitoJWKSRetriever{}
	r.HandleFunc("/{region}/{userPoolId}", UserPoolIdHandler(ctx,cjr)).Methods("GET")
	return api
}
