# Frontend en S3 + CloudFront, separado de la API (ECS detrás del ALB).
#
# Un solo dominio (var.domain_name) para todo: CloudFront envía las páginas y sus recursos a S3 y
# las rutas de la API al ALB. Mismo origen a propósito: el `iss` de las credenciales emitidas, los
# QR y las ofertas OpenID4VCI ya apuntan a este dominio y no pueden cambiar, y el panel llama a la
# API sin CORS.
#
# Puesta en marcha en dos pasos (frontend_on_cloudfront):
#   1. false: se crean el bucket y la distribución; el pipeline publica el frontend en S3. El DNS
#      sigue apuntando al ALB y la API sigue sirviendo las páginas.
#   2. true: el DNS pasa a CloudFront, el ALB sólo acepta tráfico de CloudFront (lista de prefijos
#      + cabecera secreta de origen) y la API deja de servir páginas.

locals {
  cdn = var.frontend_on_cloudfront
  # Rutas que van a la API (todo lo demás es frontend). CloudFront: `*` incluye `/`.
  api_paths = [
    "/v1/*", "/public/*", "/oid4vci/*", "/oid4vp/*", "/.well-known/*", "/status-lists/*",
    "/claim-info/*", "/claim/*/*", "/issuer-info/*", "/wallet/*", "/openapi.json",
    "/healthz", "/readyz",
  ]
  site_auth_header = var.site_auth_secret_arn == "" ? "" : "Basic ${base64encode(data.aws_secretsmanager_secret_version.site_auth[0].secret_string)}"
  # La misma CSP que la API ponía en sus páginas (admin/router.py).
  csp      = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
  docs_cdn = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/"
  docs_csp = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' ${local.docs_cdn}; script-src 'self' ${local.docs_cdn}; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
}

# El acceso restringido temporal se comprueba en el borde con la misma credencial que la API.
data "aws_secretsmanager_secret_version" "site_auth" {
  count     = var.site_auth_secret_arn == "" ? 0 : 1
  secret_id = var.site_auth_secret_arn
}

# --- Bucket privado del frontend ------------------------------------------------------------
# trivy:ignore:AVD-AWS-0089 sin logs de acceso propios: CloudFront es el único lector
resource "aws_s3_bucket" "frontend" {
  bucket_prefix = "${local.name}-frontend-"
  force_destroy = true # contenido reproducible: lo publica el pipeline en cada despliegue
}

resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket                  = aws_s3_bucket.frontend.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  rule {
    id     = "old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# SSE-S3: el contenido es público por diseño (páginas del sitio); KMS no aporta y complica OAC.
# trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudFrontRead"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        # ListBucket: una clave inexistente da 404 (no 403).
        Action    = ["s3:GetObject", "s3:ListBucket"]
        Resource  = [aws_s3_bucket.frontend.arn, "${aws_s3_bucket.frontend.arn}/*"]
        Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.main.arn } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.frontend.arn, "${aws_s3_bucket.frontend.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

# --- CloudFront -------------------------------------------------------------------------------
resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "${local.name}-frontend"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_function" "pages" {
  name    = "${local.name}-pages"
  runtime = "cloudfront-js-2.0"
  comment = "URLs limpias del frontend y acceso restringido temporal"
  publish = true
  code = templatefile("${path.module}/cloudfront/viewer-request.js", {
    auth = local.site_auth_header
    docs = local.is_production ? "false" : "true"
  })
}

data "aws_cloudfront_cache_policy" "optimized" {
  name = "Managed-CachingOptimized"
}

data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

# Todo lo del visitante (Authorization, Idempotency-Key, consulta, cuerpo) más las cabeceras de
# CloudFront, entre ellas CloudFront-Viewer-Address (IP real para los límites por red).
data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewerAndCloudFrontHeaders-2022-06"
}

resource "aws_cloudfront_response_headers_policy" "site" {
  name = "${local.name}-site"
  security_headers_config {
    content_security_policy {
      content_security_policy = local.csp
      override                = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
  }
  dynamic "custom_headers_config" {
    for_each = local.site_auth_header == "" ? [] : [1]
    content {
      items {
        header   = "X-Robots-Tag"
        value    = "noindex, nofollow"
        override = true
      }
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "docs" {
  name = "${local.name}-docs"
  security_headers_config {
    content_security_policy {
      content_security_policy = local.docs_csp
      override                = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
  }
}

# La API pone sus propias cabeceras; aquí sólo HSTS.
resource "aws_cloudfront_response_headers_policy" "api" {
  name = "${local.name}-api"
  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
  }
}

# Secreto que CloudFront agrega al pedir al ALB; el ALB rechaza lo que no lo trae.
resource "random_password" "origin_verify" {
  length  = 48
  special = false
}

# Nombre del ALB como origen: la conexión TLS valida el certificado contra el Host del visitante
# (var.domain_name, que se reenvía), y el ALB ya lo tiene.
resource "aws_route53_record" "origin" {
  count   = var.route53_zone_id == "" ? 0 : 1
  zone_id = var.route53_zone_id
  name    = "origin.${var.domain_name}"
  type    = "A"
  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

# trivy:ignore:AVD-AWS-0010 sin logs estándar de CloudFront por ahora (los de la API quedan en el ALB)
# trivy:ignore:AVD-AWS-0011 sin WAF por ahora (límites por red en la aplicación)
resource "aws_cloudfront_distribution" "main" {
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${local.name}: frontend (S3) + API (ALB)"
  aliases         = [var.domain_name]
  price_class     = "PriceClass_All" # incluye Sudamérica
  http_version    = "http2and3"

  origin {
    origin_id                = "frontend"
    domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
  }

  origin {
    origin_id   = "api"
    domain_name = "origin.${var.domain_name}"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
      origin_read_timeout    = 30
    }
    custom_header {
      name  = "X-Origin-Verify"
      value = random_password.origin_verify.result
    }
  }

  default_cache_behavior {
    target_origin_id           = "frontend"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.site.id
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.pages.arn
    }
  }

  ordered_cache_behavior {
    path_pattern               = "/docs"
    target_origin_id           = "frontend"
    viewer_protocol_policy     = "redirect-to-https"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    compress                   = true
    cache_policy_id            = data.aws_cloudfront_cache_policy.optimized.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.docs.id
    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.pages.arn
    }
  }

  dynamic "ordered_cache_behavior" {
    for_each = local.api_paths
    content {
      path_pattern               = ordered_cache_behavior.value
      target_origin_id           = "api"
      viewer_protocol_policy     = "https-only"
      allowed_methods            = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
      cached_methods             = ["GET", "HEAD"]
      compress                   = true
      cache_policy_id            = data.aws_cloudfront_cache_policy.disabled.id
      origin_request_policy_id   = data.aws_cloudfront_origin_request_policy.all_viewer.id
      response_headers_policy_id = aws_cloudfront_response_headers_policy.api.id
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.api[0].certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# --- El ALB sólo atiende a CloudFront (paso 2) --------------------------------------------------
data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_vpc_security_group_ingress_rule" "alb_from_cloudfront" {
  count             = local.cdn ? 1 : 0
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS solo desde CloudFront"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront.id
}

resource "aws_lb_listener_rule" "from_cloudfront" {
  count        = local.cdn ? 1 : 0
  listener_arn = aws_lb_listener.https[0].arn
  priority     = 1
  condition {
    http_header {
      http_header_name = "X-Origin-Verify"
      values           = [random_password.origin_verify.result]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
