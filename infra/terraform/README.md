# Infraestructura (Terraform)

Estado: **esqueleto** (incremento 2). Proveedor y versiones fijados, variables y
descomposición en módulos definidas; ningún recurso se crea todavía.

```bash
terraform init -backend=false && terraform validate     # sin credenciales
terraform init -backend-config=env/staging.s3.tfbackend  # con OIDC desde CI (pendiente)
```

`.terraform.lock.hcl` fija la versión exacta del proveedor; se genera con `terraform init`
y se versiona.
