output "public_base_url" {
  value = local.public_base_url
}

output "alb_dns_name" {
  description = "Destino del registro DNS si no se usa Route 53."
  value       = aws_lb.main.dns_name
}

output "acm_validation_records" {
  description = "Registros DNS para validar el certificado (crear a mano si no hay route53_zone_id)."
  value = [for o in aws_acm_certificate.api.domain_validation_options : {
    name  = o.resource_record_name
    type  = o.resource_record_type
    value = o.resource_record_value
  }]
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "deploy_role_arn" {
  description = "Variable AWS_DEPLOY_ROLE_ARN del entorno de GitHub."
  value       = aws_iam_role.deploy.arn
}

output "deploy_config" {
  description = "Variables del entorno de GitHub para .github/workflows/deploy.yml."
  value = {
    AWS_REGION          = data.aws_region.current.region
    ECR_REPOSITORY      = aws_ecr_repository.app.name
    ECS_CLUSTER         = aws_ecs_cluster.main.name
    ECS_SERVICE         = aws_ecs_service.api.name
    API_TASK_FAMILY     = aws_ecs_task_definition.api.family
    MIGRATE_TASK_FAMILY = aws_ecs_task_definition.migrate.family
    MAINT_TASK_FAMILY   = aws_ecs_task_definition.maintenance.family
    PRIVATE_SUBNETS     = join(",", aws_subnet.private[*].id)
    APP_SECURITY_GROUP  = aws_security_group.app.id
    PUBLIC_BASE_URL     = local.public_base_url
    SMOKE_BASE_URL      = var.https_enabled ? local.public_base_url : "http://${aws_lb.main.dns_name}"
    FRONTEND_BUCKET     = aws_s3_bucket.frontend.id
    CDN_DISTRIBUTION_ID = aws_cloudfront_distribution.main.id
  }
}
