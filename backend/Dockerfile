# ---- Build stage ----
FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Static, stripped binary; -trimpath removes local file paths from the binary.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/hmv .

# ---- Runtime stage ----
# Distroless: no shell, no package manager -> minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hmv /hmv
# Run as an unprivileged user (UID 65532).
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/hmv"]
