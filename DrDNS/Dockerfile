FROM golang:1.23.4

WORKDIR /app
COPY . .

RUN go mod init drdns
RUN go mod tidy
RUN go build -o main_drdns maindns_v2.go

EXPOSE 8080
CMD ["./main_drdns"]



