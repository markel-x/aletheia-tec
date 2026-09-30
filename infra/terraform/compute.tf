locals {
  image        = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
  db_host_port = "${aws_db_instance.main.address}:${aws_db_instance.main.port}"
  # Sin contraseñas en el DSN: se inyectan como ALETHEIA_DATABASE_PASSWORD desde Secrets Manager.
  app_dsn     = "postgresql+psycopg://aletheia_app@${local.db_host_port}/aletheia?sslmode=require"
  migrate_dsn = "postgresql+psycopg://aletheia_migrate@${local.db_host_port}/aletheia?sslmode=require"

  common_env = [
    { name = "ALETHEIA_ENV", value = var.environment },
    { name = "ALETHEIA_PUBLIC_BASE_URL", value = local.public_base_url },
    { name = "ALETHEIA_LOG_FORMAT", value = "json" },
    { name = "ALETHEIA_SIGNING_BACKEND", value = "aws_kms" },
    { name = "ALETHEIA_AWS_REGION", value = data.aws_region.current.region },
    { name = "ALETHEIA_KMS_DATA_KEY_ID", value = aws_kms_key.claims.arn },
  ]

  verifier_secrets = var.verifier_identity_secret_arn == "" ? [] : [
    { name = "ALETHEIA_VERIFIER_KEY_PEM", valueFrom = "${var.verifier_identity_secret_arn}:key_pem::" },
    { name = "ALETHEIA_VERIFIER_CERT_CHAIN_PEM", valueFrom = "${var.verifier_identity_secret_arn}:cert_chain_pem::" },
  ]

  container_hardening = {
    readonlyRootFilesystem = true
    user                   = "10001:10001"
    linuxParameters        = { capabilities = { drop = ["ALL"] }, initProcessEnabled = true }
  }

  log_config = {
    logDriver = "awslogs"
    options = {
      awslogs-group         = aws_cloudwatch_log_group.app.name
      awslogs-region        = data.aws_region.current.region
      awslogs-stream-prefix = "ecs"
    }
  }
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/aletheia/${var.environment}/app"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.storage.arn
}

resource "aws_ecs_cluster" "main" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enhanced"
  }
}

# --- IAM ---------------------------------------------------------------------------------
data "aws_iam_policy_document" "ecs_tasks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = concat([
          aws_secretsmanager_secret.app_db_password.arn,
          aws_secretsmanager_secret.tx_code_key.arn,
          aws_db_instance.main.master_user_secret[0].secret_arn,
        ], var.verifier_identity_secret_arn == "" ? [] : [var.verifier_identity_secret_arn])
      },
      { Effect = "Allow", Action = ["kms:Decrypt"], Resource = [aws_kms_key.storage.arn] },
    ]
  })
}

# Rol de la tarea api: firma con claves de emisor etiquetadas, crea sólo claves con las
# etiquetas y el tipo correctos (ADR-0006) y usa la clave de claims pendientes.
resource "aws_iam_role" "api_task" {
  name               = "${local.name}-api-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_tasks_assume.json
}

data "aws_iam_policy_document" "api_task" {
  statement {
    sid       = "UseIssuerKeys"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey", "kms:DisableKey"]
    resources = ["arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = ["aletheia"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Environment"
      values   = [var.environment]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Purpose"
      values   = ["issuer-signing"]
    }
  }
  statement {
    sid       = "CreateIssuerKeys"
    actions   = ["kms:CreateKey", "kms:TagResource"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Project"
      values   = ["aletheia"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Environment"
      values   = [var.environment]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/Purpose"
      values   = ["issuer-signing"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:KeySpec"
      values   = ["ECC_NIST_P256"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:KeyUsage"
      values   = ["SIGN_VERIFY"]
    }
  }
  statement {
    sid       = "PendingClaimsEnvelope"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [aws_kms_key.claims.arn]
  }
}

resource "aws_iam_role_policy" "api_task" {
  role   = aws_iam_role.api_task.id
  policy = data.aws_iam_policy_document.api_task.json
}

# --- Definiciones de tarea ------------------------------------------------------------------
resource "aws_ecs_task_definition" "api" {
  family                   = "${local.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.api_task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([merge(local.container_hardening, {
    name         = "api"
    image        = local.image
    essential    = true
    command      = ["api"]
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    environment  = concat(local.common_env, [{ name = "ALETHEIA_DATABASE_URL", value = local.app_dsn }])
    secrets = concat([
      { name = "ALETHEIA_DATABASE_PASSWORD", valueFrom = aws_secretsmanager_secret.app_db_password.arn },
      { name = "ALETHEIA_TX_CODE_KEY", valueFrom = aws_secretsmanager_secret.tx_code_key.arn },
    ], local.verifier_secrets)
    healthCheck = {
      command     = ["CMD", "python", "-c", "import sys,urllib.request as u; sys.exit(0 if u.urlopen('http://127.0.0.1:8000/readyz', timeout=2).status == 200 else 1)"]
      interval    = 15
      timeout     = 3
      retries     = 3
      startPeriod = 15
    }
    logConfiguration = local.log_config
  })])
}

resource "aws_ecs_task_definition" "migrate" {
  family                   = "${local.name}-migrate"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([merge(local.container_hardening, {
    name        = "migrate"
    image       = local.image
    essential   = true
    command     = ["migrate"]
    environment = concat(local.common_env, [{ name = "ALETHEIA_DATABASE_URL", value = local.migrate_dsn }])
    secrets = [
      { name = "ALETHEIA_DATABASE_PASSWORD", valueFrom = "${aws_db_instance.main.master_user_secret[0].secret_arn}:password::" },
      { name = "ALETHEIA_APP_DB_PASSWORD", valueFrom = aws_secretsmanager_secret.app_db_password.arn },
      { name = "ALETHEIA_TX_CODE_KEY", valueFrom = aws_secretsmanager_secret.tx_code_key.arn },
    ]
    logConfiguration = local.log_config
  })])
}

resource "aws_ecs_task_definition" "maintenance" {
  family                   = "${local.name}-maintenance"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([merge(local.container_hardening, {
    name        = "maintenance"
    image       = local.image
    essential   = true
    command     = ["maintenance"]
    environment = concat(local.common_env, [{ name = "ALETHEIA_DATABASE_URL", value = local.app_dsn }])
    secrets = [
      { name = "ALETHEIA_DATABASE_PASSWORD", valueFrom = aws_secretsmanager_secret.app_db_password.arn },
      { name = "ALETHEIA_TX_CODE_KEY", valueFrom = aws_secretsmanager_secret.tx_code_key.arn },
    ]
    logConfiguration = local.log_config
  })])
}

# --- Servicio api ----------------------------------------------------------------------------
resource "aws_ecs_service" "api" {
  name                              = "api"
  cluster                           = aws_ecs_cluster.main.id
  task_definition                   = aws_ecs_task_definition.api.arn
  desired_count                     = var.api_desired_count
  launch_type                       = "FARGATE"
  health_check_grace_period_seconds = 30
  propagate_tags                    = "SERVICE"
  enable_execute_command            = false

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.app.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  # El pipeline registra revisiones nuevas (imagen) y ajusta desired_count vía autoescalado.
  lifecycle {
    ignore_changes = [task_definition, desired_count]
  }

  depends_on = [aws_lb_listener.https]
}

# Autoescalado por CPU: la prueba de carga muestra que la API se satura por CPU (loadtest/README.md).
resource "aws_appautoscaling_target" "api" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.api_desired_count
  max_capacity       = var.api_max_count
}

resource "aws_appautoscaling_policy" "api_cpu" {
  name               = "${local.name}-api-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.api.service_namespace
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  target_tracking_scaling_policy_configuration {
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

# --- maintenance cada 15 minutos (ADR-0008) -----------------------------------------------------
resource "aws_iam_role" "scheduler" {
  name = "${local.name}-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id } }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = ["ecs:RunTask"]
        Resource  = ["${trimsuffix(aws_ecs_task_definition.maintenance.arn_without_revision, ":")}:*"]
        Condition = { ArnEquals = { "ecs:cluster" = aws_ecs_cluster.main.arn } }
      },
      { Effect = "Allow", Action = ["iam:PassRole"], Resource = [aws_iam_role.execution.arn] },
    ]
  })
}

resource "aws_scheduler_schedule" "maintenance" {
  name                = "${local.name}-maintenance"
  schedule_expression = "rate(15 minutes)"
  flexible_time_window {
    mode = "OFF"
  }
  target {
    arn      = aws_ecs_cluster.main.arn
    role_arn = aws_iam_role.scheduler.arn
    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.maintenance.arn_without_revision
      launch_type         = "FARGATE"
      network_configuration {
        subnets          = aws_subnet.private[*].id
        security_groups  = [aws_security_group.app.id]
        assign_public_ip = false
      }
    }
    retry_policy {
      maximum_retry_attempts = 1
    }
  }
}
