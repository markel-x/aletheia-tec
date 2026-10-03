# --- Logs de acceso del ALB ----------------------------------------------------------------
# trivy:ignore:AVD-AWS-0090 se habilita abajo con aws_s3_bucket_versioning (el escáner no lo enlaza)
resource "aws_s3_bucket" "alb_logs" {
  bucket_prefix = "${local.name}-alb-logs-"
  force_destroy = !local.is_production
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket                  = aws_s3_bucket.alb_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Los logs de acceso del ALB sólo admiten SSE-S3 (limitación de AWS).
# trivy:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  rule {
    id     = "expire"
    status = "Enabled"
    filter {}
    expiration {
      days = var.log_retention_days
    }
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

data "aws_elb_service_account" "main" {}

resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ElbLogDelivery"
        Effect    = "Allow"
        Principal = { AWS = data.aws_elb_service_account.main.arn }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.alb_logs.arn}/alb/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.alb_logs.arn, "${aws_s3_bucket.alb_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
}

# --- ALB --------------------------------------------------------------------------------------
# API pública por diseño (emisores, wallets y verificadores externos).
# trivy:ignore:AVD-AWS-0053
resource "aws_lb" "main" {
  name                       = local.name
  load_balancer_type         = "application"
  internal                   = false
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  enable_deletion_protection = local.is_production
  idle_timeout               = 30

  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb"
    enabled = true
  }

  depends_on = [aws_s3_bucket_policy.alb_logs]
}

resource "aws_lb_target_group" "api" {
  name                 = "${local.name}-api"
  port                 = 8000
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = aws_vpc.main.id
  deregistration_delay = 30

  health_check {
    path                = "/readyz"
    matcher             = "200"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

# Con HTTPS: el puerto 80 sólo redirige. Sin HTTPS (https_enabled = false, transitorio mientras el
# certificado espera su validación DNS): el puerto 80 sirve la API directamente.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = var.https_enabled ? "redirect" : "forward"
    target_group_arn = var.https_enabled ? null : aws_lb_target_group.api.arn
    dynamic "redirect" {
      for_each = var.https_enabled ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  count             = var.https_enabled ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.api[0].certificate_arn
  # Detrás de CloudFront, lo que no trae la cabecera secreta de origen se rechaza (frontend.tf).
  default_action {
    type             = local.cdn ? "fixed-response" : "forward"
    target_group_arn = local.cdn ? null : aws_lb_target_group.api.arn
    dynamic "fixed_response" {
      for_each = local.cdn ? [1] : []
      content {
        content_type = "text/plain"
        message_body = "Forbidden"
        status_code  = "403"
      }
    }
  }
}

# --- Certificado y DNS --------------------------------------------------------------------------
resource "aws_acm_certificate" "api" {
  domain_name       = var.domain_name
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = var.route53_zone_id == "" ? {} : {
    for o in aws_acm_certificate.api.domain_validation_options : o.domain_name => o
  }
  zone_id = var.route53_zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  ttl     = 300
}

# Sin zona: apply espera a que el registro de validación (output) se cree a mano.
resource "aws_acm_certificate_validation" "api" {
  count                   = var.https_enabled ? 1 : 0
  certificate_arn         = aws_acm_certificate.api.arn
  validation_record_fqdns = var.route53_zone_id == "" ? null : [for r in aws_route53_record.cert_validation : r.fqdn]
}

# El dominio público: CloudFront (frontend + API) o, antes del paso 2 de frontend.tf, el ALB.
resource "aws_route53_record" "api" {
  count   = var.route53_zone_id == "" ? 0 : 1
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"
  alias {
    name                   = local.cdn ? aws_cloudfront_distribution.main.domain_name : aws_lb.main.dns_name
    zone_id                = local.cdn ? aws_cloudfront_distribution.main.hosted_zone_id : aws_lb.main.zone_id
    evaluate_target_health = !local.cdn
  }
}

# IPv6 sólo con CloudFront (el ALB es IPv4).
resource "aws_route53_record" "api_ipv6" {
  count   = var.route53_zone_id != "" && local.cdn ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "AAAA"
  alias {
    name                   = aws_cloudfront_distribution.main.domain_name
    zone_id                = aws_cloudfront_distribution.main.hosted_zone_id
    evaluate_target_health = false
  }
}
