# --- KMS -----------------------------------------------------------------------------
# storage: cifrado en reposo de RDS, secretos y logs. claims: envelope de claims pendientes
# (ADR-0009). Las claves de firma de cada emisor las crea la aplicación (ADR-0006).
data "aws_iam_policy_document" "storage_key" {
  statement {
    sid       = "AccountAdmin"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  statement {
    sid       = "CloudWatchAlarmsToSns"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
  }
  statement {
    sid       = "CloudWatchLogs"
    actions   = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:/aletheia/${var.environment}/*"]
    }
  }
}

resource "aws_kms_key" "storage" {
  description             = "${local.name} almacenamiento (RDS, secretos, logs)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.storage_key.json
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${local.name}-storage"
  target_key_id = aws_kms_key.storage.key_id
}

resource "aws_kms_key" "claims" {
  description             = "${local.name} claims pendientes (envelope, ADR-0009)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "claims" {
  name          = "alias/${local.name}-claims"
  target_key_id = aws_kms_key.claims.key_id
}

# --- Secretos generados --------------------------------------------------------------
resource "random_password" "app_db" {
  length  = 40
  special = false
}

resource "random_bytes" "tx_code_key" {
  length = 32
}

resource "aws_secretsmanager_secret" "app_db_password" {
  name                    = "${local.name}/app-db-password"
  description             = "Contraseña del rol aletheia_app (la fija la tarea migrate)"
  kms_key_id              = aws_kms_key.storage.arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "app_db_password" {
  secret_id     = aws_secretsmanager_secret.app_db_password.id
  secret_string = random_password.app_db.result
}

resource "aws_secretsmanager_secret" "tx_code_key" {
  name                    = "${local.name}/tx-code-key"
  description             = "Clave HMAC de los tx_code (ADR-0013)"
  kms_key_id              = aws_kms_key.storage.arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "tx_code_key" {
  secret_id = aws_secretsmanager_secret.tx_code_key.id
  # base64url sin relleno, como espera ALETHEIA_TX_CODE_KEY.
  secret_string = trimsuffix(replace(replace(random_bytes.tx_code_key.base64, "+", "-"), "/", "_"), "=")
}

# --- RDS PostgreSQL 16 -----------------------------------------------------------------
resource "aws_db_subnet_group" "main" {
  name       = local.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_parameter_group" "pg16" {
  name   = "${local.name}-pg16"
  family = "postgres16"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
  # Sin log_statement: los parámetros podrían contener datos personales cifrables en tránsito.
}

# Autenticación por contraseña en Secrets Manager (rotada por RDS para el propietario). IAM
# auth para el rol de la app requiere renovar tokens en el pool: pendiente (ADR-0012).
# trivy:ignore:AVD-AWS-0176
resource "aws_db_instance" "main" {
  identifier     = local.name
  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  db_name  = "aletheia"
  username = "aletheia_migrate"
  # Contraseña del propietario gestionada por RDS en Secrets Manager (rotación automática).
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.storage.arn

  allocated_storage     = 20
  max_allocated_storage = 200
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.storage.arn

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.pg16.name

  backup_retention_period             = var.db_backup_retention_days
  backup_window                       = "03:00-04:00"
  maintenance_window                  = "sun:04:30-sun:05:30"
  copy_tags_to_snapshot               = true
  deletion_protection                 = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "${local.name}-final"
  auto_minor_version_upgrade          = true
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.storage.arn
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  iam_database_authentication_enabled = false
}
