package main

type createTokenRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	GrantType    string `json:"grant_type"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type createUserRequest struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	Fullname     string `json:"full_name"`
	Npm          string `json:"npm"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
