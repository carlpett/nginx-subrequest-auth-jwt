FROM golang:1.12 AS build
WORKDIR /src
COPY ["go.mod", "go.sum", "./"]
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -mod=readonly

FROM gcr.io/distroless/static:nonroot
COPY --from=build /src/nginx-subrequest-auth-jwt /
ENTRYPOINT ["/nginx-subrequest-auth-jwt"]
