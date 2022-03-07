# Simple OAuth Service
## Identity
* Name: Evando Wihalim
* NPM: 1806205445
## Techstack
1. Golang
2. Gin Framework
3. Redis

## Endpoint:
1. [POST] /oauth/token
2. [POST] /oauth/token/refresh
3. [POST] /oauth/resource
4. [GET] /swagger/index.html
5. [POST] /oauth/user/register

## Port:
1. Web: 8080
2. DB: 6379

## How to run:
1. Copy this project and change workdir to the same level as ```docker-compose.yml``` file
2. Run this command on your terminal
    ```console 
    docker compose up -d --build
    ```
3. Hit the endpoint. Example: [localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)
4. For more info, check swagger (endpoint 4 or just click link above)
5. To exit, Run this command on your terminal
    ```console 
    docker compose down -v
    ```