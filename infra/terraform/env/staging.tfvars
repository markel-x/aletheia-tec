# Valores de staging (nada secreto: la clave de Google vive en Secrets Manager).
# terraform apply -var-file=env/staging.tfvars
environment              = "staging"
domain_name              = "staging.credoseal.com"
route53_zone_id          = "Z10243122X6SJQ1QGU5B7" # credoseal.com (registrado en Route 53)
google_wallet_issuer_id  = "3388000000023209456"
google_wallet_secret_arn = "arn:aws:secretsmanager:us-east-1:851725538319:secret:aletheia-staging/google-wallet-ZSYa3R"
# Acceso restringido temporal (HTTP Basic) hasta el lanzamiento; vaciar para abrir el sitio.
site_auth_secret_arn = "arn:aws:secretsmanager:us-east-1:851725538319:secret:aletheia-staging/site-basic-auth-VFaXZH"
