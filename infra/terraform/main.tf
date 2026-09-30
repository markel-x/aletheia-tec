# Esqueleto de la infraestructura (docs/02 §6). Cada módulo se implementa en
# incrementos posteriores; aquí se fija la descomposición y el contrato entre ellos.
#
#   network   VPC, 2 AZ, subredes públicas (ALB) y privadas (ECS, RDS), endpoints
#   data      RDS PostgreSQL 16, Secrets Manager (credenciales gestionadas), KMS de datos
#   registry  ECR (inmutable, escaneo al subir)
#   compute   ECS Fargate: servicio api, tareas migrate y maintenance, EventBridge Scheduler
#   edge      ALB + ACM + Route 53 (opcional)
#   observe   CloudWatch (grupos de logs, alarmas), CloudTrail
#
# Reglas: sin claves permanentes (OIDC desde GitHub Actions); sólo el rol de la
# tarea api puede kms:Sign sobre las claves de emisor; RDS con deletion_protection.

locals {
  name = "aletheia-${var.environment}"

  container_env = {
    ALETHEIA_ENV             = var.environment
    ALETHEIA_PUBLIC_BASE_URL = var.public_base_url
    ALETHEIA_LOG_FORMAT      = "json"
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
