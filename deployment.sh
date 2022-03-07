go mod tidy
go mod download

go get -u github.com/swaggo/swag/cmd/swag
swag init

go build -o main .
"./main"