/*
 * REST API For Access To TURN Services
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 0.0.1
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package swagger_api_impl

import (
	"authhandler/response_generation"
	"net/http"
)

func GetIceAuth(w http.ResponseWriter, r *http.Request) {
	response_generation.HandleIceRequest(w, r)
}

func PostIceAuth(w http.ResponseWriter, r *http.Request) {
	response_generation.HandleIceRequest(w, r)
}
