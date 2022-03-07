package main

type TokenInfoResponse struct {
	AccessToken  string `json:"access_token"`
	Expires      int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

type FailedResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type ResourceResponse struct {
	AccessToken  string `json:"access_token"`
	ClientId     string `json:"client_id"`
	Username     string `json:"user_id"`
	Fullname     string `json:"full_name"`
	Npm          string `json:"npm"`
	Expires      int    `json:"expires"`
	RefreshToken string `json:"refresh_token"`
}
