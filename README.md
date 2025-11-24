# API Intermediarios - Cliente, Pago Buen Viaje Encriptado

Cliente de referencia para integración con el API de pagos de Buen Viaje.

## Inicio Rápido
```bash
# 1. Navegar a src folder
cd src
# 2. Instalar dependencias
npm install

# 3. Configurar credenciales (ver sección Configuración)
cp .env.example .env

# 4. Ejecutar
npm start
```

## Requisitos
- Node.js 18+
- Credenciales del API

## Configuración
Ver archivo `.env` para las variables requeridas.

## Flujo de Encriptación
1. Obtiene clave pública del servidor
2. Cifra datos de tarjeta con JWE (RSA-OAEP-256)
3. Firma el JWE con JWS (RS256)
4. Envía payload completo al API