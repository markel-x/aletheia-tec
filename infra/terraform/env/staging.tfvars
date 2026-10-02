# Valores de staging (nada secreto: la clave de Google vive en Secrets Manager).
# terraform apply -var-file=env/staging.tfvars
environment              = "staging"
domain_name              = "aletheia.soyuzlabs.com"
google_wallet_issuer_id  = "3388000000023209456"
google_wallet_secret_arn = "arn:aws:secretsmanager:us-east-1:851725538319:secret:aletheia-staging/google-wallet-ZSYa3R"
