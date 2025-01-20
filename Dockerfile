FROM golang:1.23.4

WORKDIR /app
COPY . .

RUN go mod tidy
RUN go build -o maindns .

EXPOSE 8080
CMD ["./maindns"]
