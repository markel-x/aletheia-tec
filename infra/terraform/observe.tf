# Alarmas ligadas a los objetivos de docs/00 §4 (disponibilidad 99,5 %, latencias p95).
resource "aws_sns_topic" "alarms" {
  name              = "${local.name}-alarms"
  kms_master_key_id = aws_kms_key.storage.arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alarm_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  alb_dimensions = { LoadBalancer = aws_lb.main.arn_suffix }
  tg_dimensions  = { LoadBalancer = aws_lb.main.arn_suffix, TargetGroup = aws_lb_target_group.api.arn_suffix }
  alarm_actions  = [aws_sns_topic.alarms.arn]
}

resource "aws_cloudwatch_metric_alarm" "target_5xx" {
  alarm_name          = "${local.name}-api-5xx"
  alarm_description   = "Respuestas 5xx de la API (runbook: docs/runbook.md#api-5xx)"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  dimensions          = local.tg_dimensions
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  alarm_name          = "${local.name}-api-unhealthy"
  alarm_description   = "Tareas api que no superan /readyz (runbook: docs/runbook.md#readyz)"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  dimensions          = local.tg_dimensions
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "latency_p95" {
  alarm_name          = "${local.name}-api-latency-p95"
  alarm_description   = "p95 de la API sobre 600 ms (objetivo del endpoint más lento, docs/00 §4)"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "TargetResponseTime"
  dimensions          = local.tg_dimensions
  extended_statistic  = "p95"
  period              = 300
  evaluation_periods  = 3
  threshold           = 0.6
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "api_cpu_at_max" {
  alarm_name          = "${local.name}-api-cpu-saturated"
  alarm_description   = "CPU alta sostenida: el autoescalado llegó al máximo o no reacciona"
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  dimensions          = { ClusterName = aws_ecs_cluster.main.name, ServiceName = aws_ecs_service.api.name }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  alarm_name          = "${local.name}-db-cpu"
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.main.identifier }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "db_storage" {
  alarm_name          = "${local.name}-db-free-storage"
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.main.identifier }
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 2 * 1024 * 1024 * 1024
  comparison_operator = "LessThanThreshold"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# La tarea de mantenimiento registra "maintenance finished"; si deja de hacerlo, se alarma.
resource "aws_cloudwatch_log_metric_filter" "maintenance_ok" {
  name           = "${local.name}-maintenance-finished"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "{ $.msg = \"maintenance finished\" }"
  metric_transformation {
    name      = "MaintenanceFinished"
    namespace = "Aletheia/${var.environment}"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "maintenance_missing" {
  alarm_name          = "${local.name}-maintenance-missing"
  alarm_description   = "La purga programada no terminó en la última hora (runbook: docs/runbook.md#maintenance)"
  namespace           = "Aletheia/${var.environment}"
  metric_name         = "MaintenanceFinished"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# «Pruébelo ahora»: el tope diario se alcanzó (abuso, o la demo funciona mejor de lo previsto).
# Los visitantes reales reciben 429 hasta el día siguiente; ver docs/runbook.md#demo.
resource "aws_cloudwatch_log_metric_filter" "demo_daily_limit" {
  name           = "${local.name}-demo-daily-limit"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = "{ $.msg = \"demo daily limit reached\" }"
  metric_transformation {
    name          = "DemoDailyLimitReached"
    namespace     = "CredoSeal/${var.environment}"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "demo_daily_limit" {
  alarm_name          = "${local.name}-demo-daily-limit"
  alarm_description   = "La demo de la página de inicio alcanzó su tope diario (runbook: docs/runbook.md#demo)"
  namespace           = "CredoSeal/${var.environment}"
  metric_name         = aws_cloudwatch_log_metric_filter.demo_daily_limit.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
}
