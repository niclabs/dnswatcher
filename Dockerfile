# Start from the latest golang base image
FROM golang:alpine

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64


WORKDIR /Observatorio

# Copy and download dependency using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Export necessary port
EXPOSE 5432


# Command to run when starting the container
CMD [ "go", "run", "main/main.go"]
