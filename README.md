# nginx-subrequest-auth-jwt
This project implements a simple JWT validation endpoint meant to be used with NGINX's [subrequest authentication](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/), and specifically work well with the Kubernetes [NGINX Ingress Controller](https://github.com/kubernetes/ingress-nginx) external auth annotations.

It validates a JWT token passed in the `Authorization` header against a configured public key, and further validates that the JWT contains appropriate claims.

## Limitations
The configuration format currently only supports a single elliptic curve public key for signature validation, and does not have a facility for rotating keys without restart. Basic support in the configuration format for supporting multiple active keys, and of different types, at once is in place but currently not used.

# Configuration
The service takes a configuration file in YAML format. For example:

```yaml
validationKeys:
  - type: ecPublicKey
    key: |
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
claims:
  - group:
      - developers
      - administrators
```

With this configuration, a JWT will be validated against the given public key, and the claims are then matched against the given structure, meaning there has to be a `group` claim, with either a `developers` or `administrators` value.

Multiple alternative allowed claims can be configured, for example:

```yaml
validationKeys:
  - type: ecPublicKey
    key: |
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
claims:
  - group:
      - developers
      - administrators
  - deviceClass:
      - server
      - networkEquipment
```

In this case, the token claims **either** needs to have the groups as per the previous example, **or** a `deviceClass` of `server` or `networkEquipment`.

There can also be multiple claims requirements, for example:

```yaml
validationKeys:
  - type: ecPublicKey
    key: |
      -----BEGIN PUBLIC KEY-----
      ...
      -----END PUBLIC KEY-----
claims:
  - group:
      - developers
      - administrators
    location:
      - hq
```

Here, the token claims must **both** have the groups as before, **and** a `location` of `hq`.

# NGINX Ingress Controller integration
To use with the NGINX Ingress Controller, first create a deployment and a service for this endpoint. Then on the ingress object you wish to authenticate, add this annotation:

```yaml
nginx.ingress.kubernetes.io/auth-url: http://nginx-jwt.default.svc.cluster.local:8080/validate
```

Change the url to match the name of the service and namespace you chose when deploying. All requests will now have their JWTs validated before getting passed to the upstream service.

# Metrics
This endpoint exposes [Prometheus](https://prometheus.io) metrics on `/metrics`:

- `http_requests_total{status="<status>"}` number of requests handled, by status code (counter)
- `nginx_subrequest_auth_jwt_token_validation_time_seconds` number of seconds spent validating tokens (histogram)
