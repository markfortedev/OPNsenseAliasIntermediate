FROM golang:1.19-alpine
WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY *.go ./
RUN go build -o /opnsense_auth_server

ENV IGNORE_CERT=true

EXPOSE 12356
CMD [ "/opnsense_auth_server" ]