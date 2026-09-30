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

variable "image_tag" {
  description = "Etiqueta (o digest) de la imagen aletheia:runtime en ECR."
  type        = string
}

variable "public_base_url" {
  description = "Origen público de la API (ALETHEIA_PUBLIC_BASE_URL)."
  type        = string

  validation {
    condition     = startswith(var.public_base_url, "https://")
    error_message = "public_base_url debe usar https://."
  }
}

variable "api_desired_count" {
  description = "Tareas ECS del servicio api (2 en producción: una por AZ)."
  type        = number
  default     = 2
}

variable "db_multi_az" {
  description = "RDS Multi-AZ (true en producción)."
  type        = bool
  default     = true
}

variable "db_backup_retention_days" {
  description = "Retención de backups automáticos de RDS (PITR)."
  type        = number
  default     = 7
}

variable "log_retention_days" {
  description = "Retención de CloudWatch Logs."
  type        = number
  default     = 90
}
