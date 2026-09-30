# Infraestructura de Aletheia (docs/02 §6). Un archivo por área:
#
#   network.tf   VPC en 2 AZ, subredes públicas (ALB) y privadas (ECS, RDS), NAT, grupos de seguridad
#   data.tf      RDS PostgreSQL 16, KMS (almacenamiento y claims pendientes), secretos
#   registry.tf  ECR inmutable con escaneo al subir
#   compute.tf   ECS Fargate: servicio api, tareas migrate y maintenance, autoescalado, EventBridge
#   edge.tf      ALB + ACM + Route 53 (opcional), logs de acceso en S3
#   observe.tf   Alarmas CloudWatch y SNS
#   ci.tf        OIDC de GitHub Actions y rol de despliegue (sin claves permanentes)
#
# Reglas: sólo el rol de la tarea api puede firmar (kms:Sign) con claves de emisor etiquetadas;
# RDS no es público y tiene deletion_protection; ningún secreto en variables ni en el estado
# salvo los generados aquí (el estado se cifra en S3).

locals {
  name            = "aletheia-${var.environment}"
  public_base_url = "https://${var.domain_name}"
  azs             = slice(data.aws_availability_zones.available.names, 0, 2)
  is_production   = var.environment == "production"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}
