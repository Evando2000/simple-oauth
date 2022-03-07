package main

import (
	"encoding/json"
	"log"
	"os"
	"time"
	docs "tm1-simple-goauth/docs"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
)

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func prepare(client redis.Client) {
	unicornPass := hashPassword("coba123")
	newUser := User{
		Username: "unicorn",
		Password: unicornPass,
		Fullname: "Budi Anduk",
		Npm:      "1406123456",
	}
	user, err := json.Marshal(newUser)
	if err != nil {
		log.Println(err)
	}

	err = client.Set(newUser.Username, user, time.Duration(UserExpire)).Err()
	if err != nil {
		log.Println(err)
	}

}

var tokenDB *redis.Client
var userDB *redis.Client

// var tokenDB = redis.NewClient(&redis.Options{
// 	Addr:     getEnv("REDIS_URL", "localhost:6379"),
// 	Password: getEnv("REDIS_PASSWORD", ""),
// 	DB:       0,
// })

// var userDB = redis.NewClient(&redis.Options{
// 	Addr:     getEnv("REDIS_URL", "localhost:6379"),
// 	Password: getEnv("REDIS_PASSWORD", ""),
// 	DB:       1,
// })

func main() {
	opt, errDB := redis.ParseURL(getEnv("REDIS_URL", "localhost:6379"))
	if errDB != nil {
		panic(errDB)
	}
	tokenDB = redis.NewClient(opt)
	userDB = redis.NewClient(opt)

	_, err := tokenDB.Ping().Result()
	if err != nil {
		log.Fatal(err)
	}

	_, err = userDB.Ping().Result()
	if err != nil {
		log.Fatal(err)
	}

	prepare(*userDB)

	router := gin.New()
	router.SetTrustedProxies([]string{"localhost", "infralabs.cs.ui.ac.id", "herokuapp.com"})

	// Simple group: OAuth
	oauth := router.Group("/oauth")
	{
		oauth.POST("/token", createTokenHandler)
		oauth.POST("/token/refresh", refreshTokenHandler)
		oauth.POST("/resource", getResourceHandler)
		oauth.POST("/user/register", createUserHandler)
	}

	docs.SwaggerInfo.BasePath = "/oauth"
	router.GET("/docs", ginSwagger.WrapHandler(swaggerfiles.Handler))
	port := getEnv("PORT", "8080")
	router.Run(":" + port)
}
