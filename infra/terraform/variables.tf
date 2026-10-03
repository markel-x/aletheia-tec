variable "aws_region" {
  description = "Región de despliegue (S7: us-east-1 de referencia; sa-east-1 para clientes en Uruguay)."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Entorno: staging o production."
  type        = string

  validation {
    condition     = contains(["staging", "production"], var.environment)
    error_message = "environment debe ser staging o production."
  }
}

variable "domain_name" {
  description = "Nombre DNS público de la API (p. ej. staging.aletheia.example). Define ALETHEIA_PUBLIC_BASE_URL."
  type        = string
}

variable "https_enabled" {
  description = "Listener HTTPS con el certificado ACM validado. false: la API se sirve por HTTP en el ALB mientras el certificado espera la validacion DNS (solo transitorio, nunca en production)."
  type        = bool
  default     = true

  validation {
    condition     = var.https_enabled || var.environment != "production"
    error_message = "production exige https_enabled = true."
  }
}

variable "route53_zone_id" {
  description = "Zona Route 53 para el alias y la validación ACM. Vacío: los registros se crean a mano (ver outputs)."
  type        = string
  default     = ""
}

variable "image_tag" {
  description = "Etiqueta inicial de la imagen aletheia:runtime en ECR. Los despliegues posteriores los hace el pipeline."
  type        = string
  default     = "bootstrap"
}

variable "vpc_cidr" {
  description = "CIDR de la VPC."
  type        = string
  default     = "10.40.0.0/16"
}

variable "api_desired_count" {
  description = "Tareas mínimas del servicio api (2 en producción: una por AZ)."
  type        = number
  default     = 2
}

variable "api_max_count" {
  description = "Tareas máximas del servicio api (autoescalado por CPU)."
  type        = number
  default     = 6
}

variable "api_cpu" {
  description = "CPU de la tarea api (unidades Fargate)."
  type        = number
  default     = 512
}

variable "api_memory" {
  description = "Memoria de la tarea api (MiB)."
  type        = number
  default     = 1024
}

variable "db_instance_class" {
  description = "Clase de instancia RDS."
  type        = string
  default     = "db.t4g.small"
}

variable "db_multi_az" {
  description = "RDS Multi-AZ (true en producción)."
  type        = bool
  default     = true
}

variable "db_backup_retention_days" {
  description = "Retención de backups automáticos de RDS (PITR, RPO 5 min)."
  type        = number
  default     = 7
}

variable "log_retention_days" {
  description = "Retención de CloudWatch Logs."
  type        = number
  default     = 90
}

variable "alarm_email" {
  description = "Correo suscrito a las alarmas (vacío: sin suscripción)."
  type        = string
  default     = ""
}

variable "site_auth_secret_arn" {
  description = "Secreto con usuario:contrasena para restringir temporalmente el sitio (HTTP Basic en las paginas para personas). Vacio: sitio abierto."
  type        = string
  default     = ""
}

variable "demo_organization" {
  description = "public_id (org_…) de la organización de demostración para «Pruébelo ahora» en la página de inicio. Vacío: sin demo."
  type        = string
  default     = ""
}

variable "google_wallet_issuer_id" {
  description = "Issuer ID de la consola de Google Pay & Wallet. Vacio: sin entrega por Google Wallet (ADR-0017)."
  type        = string
  default     = ""
}

variable "google_wallet_secret_arn" {
  description = "Secreto de Secrets Manager con el JSON de la clave de la cuenta de servicio de Google Wallet (ADR-0017)."
  type        = string
  default     = ""

  validation {
    condition     = (var.google_wallet_issuer_id == "") == (var.google_wallet_secret_arn == "")
    error_message = "google_wallet_issuer_id y google_wallet_secret_arn se definen juntos."
  }
}

variable "verifier_identity_secret_arn" {
  description = <<-EOT
    Secreto de Secrets Manager (JSON con key_pem y cert_chain_pem) con la clave P-256 y el
    certificado del verificador OID4VP (ADR-0015). Vacío: sólo solicitudes OID4VP sin firmar.
  EOT
  type        = string
  default     = ""
}

variable "github_repository" {
  description = "Repositorio autorizado a desplegar por OIDC (owner/repo)."
  type        = string
  default     = "markel-x/aletheia-tec"
}

variable "github_oidc_subject_prefix" {
  description = "Prefijo del claim sub con sujetos inmutables (repo:<owner>@<owner_id>/<repo>@<repo_id>); vacio si el repositorio usa el formato clasico. Ver GET /repos/{repo}/actions/oidc/customization/sub."
  type        = string
  default     = "repo:markel-x@189795038/aletheia-tec@1398694591"
}

variable "create_github_oidc_provider" {
  description = "Crear el proveedor OIDC de GitHub (sólo uno por cuenta)."
  type        = bool
  default     = true
}
