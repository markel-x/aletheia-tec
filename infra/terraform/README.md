# Infraestructura (Terraform)

Recursos de AWS para un entorno (`staging` o `production`) según [docs/02 §6](../../docs/02-arquitectura.md).
Un archivo por área: `network`, `data`, `registry`, `compute`, `edge`, `observe`, `ci` (ver `main.tf`).

**Estado: validado estáticamente, nunca aplicado.** `terraform validate` y Trivy (`config`, MEDIUM+)
pasan en CI; no se ha ejecutado `plan` ni `apply` contra una cuenta.

## Primer despliegue

```bash
# Estado remoto: bucket S3 tf-state-markel (us-west-2), una clave por entorno en env/<entorno>.s3.tfbackend.
terraform init -backend-config=env/staging.s3.tfbackend
terraform apply -var environment=staging -var domain_name=staging.aletheia.example \
  -var route53_zone_id=<zona> -var alarm_email=ops@example.org
```

1. Sin `route53_zone_id`, `apply` espera a que se creen a mano los registros de `acm_validation_records`
   y el CNAME/alias del dominio hacia `alb_dns_name`.
2. El servicio `api` arranca con `image_tag = "bootstrap"`, que no existe: la primera ejecución de
   `deploy.yml` publica la imagen y crea la primera revisión válida (ECS reintenta hasta entonces).
3. Copiar la salida `deploy_config` como variables del entorno de GitHub (y `deploy_role_arn` como
   `AWS_DEPLOY_ROLE_ARN`); en `production`, exigir revisores. Activar con la variable de
   **repositorio** `DEPLOY_ENABLED=true`.
4. Primera organización: tarea única `bootstrap` (ver `docs/runbook.md`).

## Decisiones y excepciones del escáner
Cada `trivy:ignore` lleva su justificación en línea: ALB público (es la API), logs del ALB con SSE-S3
(única opción de AWS), salida HTTPS a Internet (emisores externos), RDS sin IAM auth (contraseña en
Secrets Manager; ver ADR-0012).

`.terraform.lock.hcl` fija `hashicorp/aws` 6.67.0 y `hashicorp/random` 3.9.1.
