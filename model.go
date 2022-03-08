package main

import "time"

type User struct {
	Username     string `json:"username"`
	Password     string `json:"password"`
	Fullname     string `json:"full_name"`
	Npm          string `json:"npm"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type TokenInfo struct {
	ClientId             string    `json:"client_id"`
	ClientSecret         string    `json:"client_secret"`
	Username             string    `json:"username"`
	AccessToken          string    `json:"access_token"`
	RefreshToken         string    `json:"refresh_token"`
	AccessTokenExpireAt  time.Time `json:"access_token_expire"`
	RefreshTokenExpireAt time.Time `json:"refresh_token_expire"`
}

type RefreshTokenInfo struct {
	Username     string `json:"username"`
	AccessToken  string `json:"access_token"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
