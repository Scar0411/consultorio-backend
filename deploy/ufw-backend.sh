#!/bin/bash
# UFW del Backend: solo el Frontend (por su IP privada) puede entrar.
# Uso: sudo bash ufw-backend.sh 10.0.1.25     <- IP PRIVADA de la instancia Frontend
set -e
FRONT="$1"
[ -z "$FRONT" ] && { echo "Uso: sudo bash ufw-backend.sh <IP_privada_frontend>"; exit 1; }
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$FRONT" to any port 3000 proto tcp comment 'API solo desde Frontend'
ufw allow from "$FRONT" to any port 22 proto tcp comment 'SSH solo desde Frontend'
ufw --force enable
ufw status verbose
