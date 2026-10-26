#!/usr/bin/env bash
# =============================================================================
# generate-keys.sh — Génère la paire de clés RSA pour la signature JWT (RS256)
#
# Usage : ./scripts/generate-keys.sh
# Sortie : backend/src/main/resources/keys/private.pem
#          backend/src/main/resources/keys/public.pem
#
# [SEC] Ces clés NE DOIVENT PAS être commitées dans Git.
#       Le .gitignore exclut src/main/resources/keys/
# =============================================================================

set -euo pipefail

KEYS_DIR="backend/src/main/resources/keys"
mkdir -p "$KEYS_DIR"

echo "🔑 Génération des clés RSA 4096 bits pour JWT RS256..."

# Clé privée RSA 4096 bits (PKCS#8 — format attendu par JJWT)
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:4096 \
  -out "$KEYS_DIR/private.pem" 2>/dev/null

# Clé publique dérivée
openssl rsa \
  -pubout \
  -in "$KEYS_DIR/private.pem" \
  -out "$KEYS_DIR/public.pem" 2>/dev/null

# [SEC] Permissions restrictives : lecture seule par le propriétaire
chmod 600 "$KEYS_DIR/private.pem"
chmod 644 "$KEYS_DIR/public.pem"

echo "✅ Clés générées dans $KEYS_DIR/"
echo "   private.pem : $(wc -l < "$KEYS_DIR/private.pem") lignes (chmod 600)"
echo "   public.pem  : $(wc -l < "$KEYS_DIR/public.pem") lignes (chmod 644)"
echo ""
echo "⚠️  Ces fichiers sont dans .gitignore — ne jamais les commiter."
