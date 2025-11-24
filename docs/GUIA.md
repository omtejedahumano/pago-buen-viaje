# Guía de Integración: API de Pagos Encriptados - Buen Viaje

## Tabla de Contenidos
- [Introducción](#introducción)
- [Requisitos Previos](#requisitos-previos)
- [Conceptos Clave](#conceptos-clave)
- [Proceso Paso a Paso](#proceso-paso-a-paso)
  - [Paso 1: Generar Par de Claves RSA](#paso-1-generar-par-de-claves-rsa)
  - [Paso 2: Obtener Clave Pública del Servidor](#paso-2-obtener-clave-pública-del-servidor)
  - [Paso 3: Preparar Datos de Tarjeta](#paso-3-preparar-datos-de-tarjeta)
  - [Paso 4: Cifrar con JWE](#paso-4-cifrar-con-jwe)
  - [Paso 5: Firmar con JWS](#paso-5-firmar-con-jws)
  - [Paso 6: Construir Payload Completo](#paso-6-construir-payload-completo)
  - [Paso 7: Enviar Solicitud de Pago](#paso-7-enviar-solicitud-de-pago)
- [Ejemplos de Código](#ejemplos-de-código)
- [Solución de Problemas](#solución-de-problemas)
- [Seguridad](#seguridad)
- [Referencias](#referencias)

---

## Introducción

Esta guía explica cómo integrar tu aplicación con el **API de Pagos Encriptados de Buen Viaje** para procesar pagos de pólizas de seguros de forma segura.

### ¿Por qué cifrado?

Los datos de tarjetas de crédito son **extremadamente sensibles** y están sujetos a regulaciones como PCI-DSS. Este API implementa un sistema de **cifrado de extremo a extremo** que garantiza:

- ✅ Los datos de tarjeta **nunca viajan en texto plano**
- ✅ Solo el servidor puede descifrar la información sensible
- ✅ La integridad del mensaje está garantizada mediante firma digital
- ✅ Se previenen ataques de repetición (replay attacks)

### Flujo General

```
┌──────────────┐                                    ┌──────────────┐
│   Cliente    │                                    │  API Humano  │
│  (Tu App)    │                                    │ (Buen Viaje) │
└──────┬───────┘                                    └──────┬───────┘
       │                                                   │
       │ 1. GET /crypto/publickey/{kid}                   │
       │ ─────────────────────────────────────────────────>│
       │                                                   │
       │ 2. ← Clave pública RSA 3072 bits                 │
       │<──────────────────────────────────────────────────│
       │                                                   │
       │ 3. Cifra datos de tarjeta                        │
       │    usando JWE (RSA-OAEP-256 + A256GCM)          │
       │    ┌──────────────────────────────┐             │
       │    │ NumeroTarjeta                │             │
       │    │ FechaExpiracionTarjeta       │             │
       │    │ CVV                          │             │
       │    └──────────────────────────────┘             │
       │              ↓                                   │
       │    ┌──────────────────────────────┐             │
       │    │ JWE (cifrado)                │             │
       │    └──────────────────────────────┘             │
       │                                                   │
       │ 4. Firma el JWE con tu clave privada            │
       │    usando JWS (RS256)                            │
       │              ↓                                   │
       │    ┌──────────────────────────────┐             │
       │    │ JWS (firma digital)          │             │
       │    └──────────────────────────────┘             │
       │                                                   │
       │ 5. POST /pagos                                   │
       │    Body: { numeroFactura, monto,                │
       │             metodoPago: {                        │
       │               datosTarjetaCifrados: {           │
       │                 jwe: "...",                      │
       │                 firmaJws: "...",                 │
       │                 nonce: "uuid",                   │
       │                 timestamp: "..."                 │
       │               }                                  │
       │             }                                    │
       │           }                                      │
       │ ─────────────────────────────────────────────────>│
       │                                                   │
       │                              6. Valida firma JWS │
       │                              7. Valida nonce     │
       │                              8. Desencripta JWE  │
       │                              9. Procesa pago     │
       │                                                   │
       │ 10. ← 201 Created { resultado del pago }         │
       │<──────────────────────────────────────────────────│
       │                                                   │
```

---

## Requisitos Previos

### 1. Credenciales de Autenticación

Para usar el API, necesitas los siguientes headers proporcionados por el equipo de Humano Seguros:

| Header | Descripción | Ejemplo |
|--------|-------------|---------|
| `x-user-key` | Clave de usuario (Base64) | `<user_key>` |
| `x-codigo-mediador` | Código del mediador | `<codigo_mediador>` |
| `Ocp-Apim-Subscription-Key` | Subscription key del API Gateway | `<subscription_key>` |


### 2. Librerías de Criptografía

Necesitas una librería que soporte:
- **JWE (JSON Web Encryption)** - RFC 7516
- **JWS (JSON Web Signature)** - RFC 7515
- **RSA-OAEP-256** - Algoritmo de cifrado de clave
- **A256GCM** - Algoritmo de cifrado de contenido
- **RS256** - Algoritmo de firma digital

**Librerías recomendadas:**

| Lenguaje | Librería | Instalación |
|----------|----------|-------------|
| **Node.js** | [`jose`](https://github.com/panva/jose) | `npm install jose` |
| **C#** | [`Jose.JWT`](https://github.com/dvsekhvalnov/jose-jwt) o System.Security | `dotnet add package jose-jwt` |

### 3. Endpoints del API

| Ambiente | Base URL |
|----------|----------|
| **Desarrollo** | `https://devapi.humano.com.do` |
| **Producción** | `https://huapi.humano.com.do` |

**Endpoints específicos:**
- **Obtener clave pública**: `GET /api/v2/productos/buen-viaje/crypto/publickey/{kid}`
- **Procesar pago**: `POST /api/v2/productos/buen-viaje/pagos`

---

## Conceptos Clave

### JWE (JSON Web Encryption)

JWE es un estándar para cifrar datos JSON de forma segura. Utiliza **cifrado híbrido**:

1. **CEK (Content Encryption Key)**: Clave simétrica AES-256 generada aleatoriamente
2. **RSA-OAEP-256**: Cifra la CEK con la clave pública del servidor (3072 bits)
3. **A256GCM**: Cifra el contenido con la CEK (AES-256 en modo GCM)

**Estructura de un JWE (5 partes separadas por puntos):**

```
header.encryptedKey.iv.ciphertext.tag
```

**Ejemplo visual:**

```
┌─────────────────────────────────────────────────────┐
│                    JWE Compacto                      │
├─────────────────────────────────────────────────────┤
│ eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIi │ ← Header
│ wia2lkIjoiY3J0LXBhZ28tYnVlbi12aWFqZS1wdWIifQ      │
│ .                                                    │
│ K52M1b_MG...cifrada...con_RSA                       │ ← CEK cifrada
│ .                                                    │
│ 7xQcZmTi_FHsj90K                                    │ ← IV (vector inicial)
│ .                                                    │
│ 9fD_E8vN...datos...cifrados...con_AES               │ ← Datos cifrados
│ .                                                    │
│ Mf87Hs0qT_VnD4                                      │ ← Tag de autenticación
└─────────────────────────────────────────────────────┘
```

### JWS (JSON Web Signature)

JWS es un estándar para firmar datos digitalmente. Garantiza:

- ✅ **Integridad**: El mensaje no fue modificado
- ✅ **Autenticidad**: El mensaje proviene de quien dice ser
- ✅ **No repudio**: El emisor no puede negar haberlo enviado

**Algoritmo de firma: RS256**
- Usa **RSA** con **SHA-256**
- La firma se genera con tu **clave privada** (cliente)
- El servidor verifica con tu **clave pública** (cliente)

**Estructura de un JWS (3 partes):**

```
header.payload.signature
```

**En nuestro caso:**
- **Header**: `{"alg":"RS256","kid":"crt-pago-client-test-pub"}`
- **Payload**: El JWE completo (como string)
- **Signature**: Firma RSA-SHA256 del payload

### Anti-Replay Protection

Para evitar que un atacante "repita" una solicitud capturada, usamos:

1. **Nonce**: UUID único generado para cada solicitud
2. **Timestamp**: Fecha/hora ISO 8601 (`2025-01-24T15:30:00Z`)

El servidor:
- ✅ Rechaza nonces duplicados (ya consumidos)
- ✅ Rechaza timestamps fuera de ventana (±5 minutos)

---

## Proceso Paso a Paso

### Paso 1: Generar Par de Claves RSA

Necesitas tu propio par de claves RSA para firmar las solicitudes.

#### Especificaciones de las Claves

| Propiedad | Valor Requerido |
|-----------|-----------------|
| **Algoritmo** | RSA |
| **Tamaño** | 3072 bits |
| **Exponente público** | 65537 (0x010001) |
| **Formato privada** | PKCS#8 PEM (`.key`) |
| **Formato pública** | X.509 v3 DER (`.cer`) |
| **Algoritmo de hash** | SHA-256 |
| **Validez** | 10 años (desarrollo), 1-2 años (producción) |

#### Generar Claves con OpenSSL

**1. Generar clave privada RSA 3072 bits:**

```bash
openssl genrsa -out mi-app-prvt.key 3072
```

**Output esperado:**
```
Generating RSA private key, 3072 bit long modulus
.......................++
.....++
e is 65537 (0x010001)
```

**2. Generar certificado X.509 autofirmado (clave pública):**

```bash
openssl req -new -x509 -key mi-app-prvt.key \
  -out mi-app-pub.crt -days 3650 \
  -subj "/CN=mi-aplicacion" -sha256
```

**Parámetros explicados:**
- `-new -x509`: Crea un nuevo certificado X.509
- `-key mi-app-prvt.key`: Usa esta clave privada
- `-out mi-app-pub.crt`: Archivo de salida (formato PEM)
- `-days 3650`: Válido por 10 años
- `-subj "/CN=mi-aplicacion"`: Common Name del certificado
- `-sha256`: Usar SHA-256 para la firma

**3. Convertir certificado a formato DER (.cer):**

```bash
openssl x509 -in mi-app-pub.crt -outform DER -out mi-app-pub.cer
```

**4. Verificar el certificado:**

```bash
openssl x509 -in mi-app-pub.cer -inform DER -text -noout
```

**Output esperado:**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: ...
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=mi-aplicacion
        Validity
            Not Before: Jan 24 10:00:00 2025 GMT
            Not After : Jan 21 10:00:00 2035 GMT
        Subject: CN=mi-aplicacion
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (3072 bit)
```

#### ⚠️ Claves de Prueba Proporcionadas

Para pruebas iniciales, puedes usar estas claves **SOLO EN DESARROLLO**:

**`crt-pago-client-test-prvt.key` (Clave privada):**

```
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----
```

**Copia del certificado público ya registrado en el servidor:**
- **KID**: `crt-pago-client-test-pub`

⚠️ **IMPORTANTE**:
- Esta clave es **SOLO PARA PRUEBAS INICIALES** en ambiente de desarrollo
- **NUNCA** uses esta clave en producción
- Para producción, genera tus propias claves y envía el certificado público al equipo de Humano Seguros para registro.

#### Registrar tu Clave Pública

Una vez generado tu certificado público (`mi-app-pub.cer`), debes:

1. **Enviarlo al equipo de Humano Seguros** para que lo registren en el servidor
2. **Recibir un KID** (Key ID) único para tu certificado (ej: `mi-app-pub`)
3. **Usar ese KID** en el campo `firmaKid` de tus solicitudes

---

### Paso 2: Obtener Clave Pública del Servidor

Antes de cifrar, necesitas la clave pública del servidor con la que cifrarás los datos.

#### Endpoint

```
GET /api/v2/productos/buen-viaje/crypto/publickey/{kid}
```

**Parámetros:**
- `{kid}`: Key ID del certificado del servidor
  - **Desarrollo**: `crt-pago-buen-viaje-pub`
  - **Producción**: (proporcionado por el equipo)

#### Headers Requeridos

```http
x-user-key: <user_key>
x-codigo-mediador: <codigo_mediador>
Ocp-Apim-Subscription-Key: <subscription_key>
Cache-Control: no-cache
```

#### Ejemplo con cURL

```bash
curl -X GET \
  "https://devapi.humano.com.do/api/v2/productos/buen-viaje/crypto/publickey/crt-pago-buen-viaje-pub" \
  -H "x-user-key: <user_key>" \
  -H "x-codigo-mediador: <codigo_mediador>" \
  -H "Ocp-Apim-Subscription-Key: <subscription_key>" \
  -H "Cache-Control: no-cache"
```

#### Respuesta

**Status**: `200 OK`

**Body** (texto plano, formato PEM):

```
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA5dT87qKPKvAIhMIUn45w
4fqaZ09u1GS54Gvnj+t0J6kdq24Vyd91YYYZHMvIAjZagrnSH3OO7Zw6motrdulJ
kzgNCFM0818LZ4FdNiJCtGAt/6E73+cLkUnSrylhl9l/w3vBB1QmTo0GpnzUJF0j
Lo0Hb7URNUeSmPKIsG1lqKWcSu259ysG1l3bIDAUsR5O1uyosm1amG202Y/tSzvr
wnoZpmuj1cJ0M9ioKUba0x6oZwQ5/JmjlDEK5V1yl3qaEEO7ozvOt/4TmRlhNCuu
cLEDf7tNp36bwzStyb7+/0dhE39+W9GyPv1KWMdGgEPrRzdvUd/LnqFk8UGwnE66
C1CjxH1FuwWfn6G5XfF6oI5+Q1t7VfPF0IYPfuqucqCWWPlI90itR5g7ttFgZjAW
Soj3L3X1FpLnI1wP6yKFLWRSrNEdOAxBX1r/2SbI2pg+Y15cZ/iTbYX2/TgTBroM
mNkpC+B387fPSuT0Oh3EcFMfZB9JCNYn4l1GYpMR3HYXAgMBAAE=
-----END PUBLIC KEY-----
```

**Nota**: Esta clave es pública y no es sensible. Puedes cachearla localmente.

---

### Paso 3: Preparar Datos de Tarjeta

Construye el objeto JSON con los datos sensibles de la tarjeta:

```json
{
  "NumeroTarjeta": "4111111111111111",
  "FechaExpiracionTarjeta": "1228",
  "CVV": "123"
}
```

**Validaciones recomendadas:**

| Campo | Tipo | Formato | Validación |
|-------|------|---------|------------|
| `NumeroTarjeta` | string | 13-19 dígitos | Algoritmo de Luhn |
| `FechaExpiracionTarjeta` | string | `MMYY` | Fecha futura |
| `CVV` | string | 3-4 dígitos | Solo números |


---

### Paso 4: Cifrar con JWE

Cifra el objeto de tarjeta usando la clave pública del servidor.

#### Parámetros de Cifrado

```json
{
  "alg": "RSA-OAEP-256",
  "enc": "A256GCM",
  "kid": "crt-pago-buen-viaje-pub"
}
```

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| `alg` | `RSA-OAEP-256` | Algoritmo para cifrar la CEK |
| `enc` | `A256GCM` | Algoritmo para cifrar el contenido |
| `kid` | `crt-pago-buen-viaje-pub` | ID de la clave pública del servidor |

#### Ejemplo (Node.js con `jose`)

```javascript
import * as jose from 'jose';
import fs from 'fs';
import crypto from 'crypto';

// 1. Cargar clave pública del servidor (obtenida del Paso 2)
const publicKeyPem = fs.readFileSync('server-public-key.pem', 'utf8');
const publicKey = crypto.createPublicKey(publicKeyPem);

// 2. Datos de tarjeta a cifrar
const datosTarjeta = {
  NumeroTarjeta: '4111111111111111',
  FechaExpiracionTarjeta: '1228',
  CVV: '123'
};

// 3. Cifrar con JWE
const jwe = await new jose.CompactEncrypt(
  new TextEncoder().encode(JSON.stringify(datosTarjeta))
)
  .setProtectedHeader({
    alg: 'RSA-OAEP-256',
    enc: 'A256GCM',
    kid: 'crt-pago-buen-viaje-pub'
  })
  .encrypt(publicKey);

console.log('JWE:', jwe);
// Output: eyJhbGciOiJSU0EtT0FFUC0yNTYi...
```

#### Resultado

Un string largo de ~1500-2000 caracteres:

```
eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIiwia2lkIjoiY3J0LXBhZ28tYnVlbi12aWFqZS1wdWIifQ.K52M1b_MGaJW8hF...
```

---

### Paso 5: Firmar con JWS

Firma el JWE con tu clave privada para garantizar integridad y autenticidad.

#### Parámetros de Firma

```json
{
  "alg": "RS256",
  "kid": "crt-pago-client-test-pub"
}
```

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| `alg` | `RS256` | RSA con SHA-256 |
| `kid` | `crt-pago-client-test-pub` | ID de tu clave pública (cliente) |

#### Ejemplo (Node.js con `jose`)

```javascript
import * as jose from 'jose';
import fs from 'fs';
import crypto from 'crypto';

// 1. Cargar tu clave privada
const privateKeyPem = fs.readFileSync('mi-app-prvt.key', 'utf8');
const privateKey = crypto.createPrivateKey(privateKeyPem);

// 2. JWE generado en el paso anterior
const jwe = 'eyJhbGciOiJSU0EtT0FFUC0yNTYi...';

// 3. Firmar con JWS
const jws = await new jose.CompactSign(
  new TextEncoder().encode(jwe)
)
  .setProtectedHeader({
    alg: 'RS256',
    kid: 'crt-pago-client-test-pub'
  })
  .sign(privateKey);

console.log('JWS:', jws);
// Output: eyJhbGciOiJSUzI1NiIsImtpZCI6ImNydC1wYWdvLWNsaWVudC10ZXN0LXB1YiJ9...
```

---

### Paso 6: Construir Payload Completo

Construye el JSON completo de la solicitud de pago:

```json
{
  "numeroFactura": "FAC-2025-001",
  "monto": 100.50,
  "impuesto": 18.09,
  "moneda": "USD",
  "metodoPago": {
    "tipo": "tarjeta_credito",
    "detalles": {
      "datosTarjetaCifrados": {
        "jwe": "eyJhbGciOiJSU0EtT0FFUC0yNTYi...",
        "kid": "crt-pago-buen-viaje-pub",
        "nonce": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2025-01-24T15:30:00Z",
        "firmaJws": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNydC1wYWdvLWNsaWVudC10ZXN0LXB1YiJ9...",
        "firmaKid": "crt-pago-client-test-pub"
      }
    }
  },
  "metadatos": {
    "ipCliente": "192.168.1.100",
    "userAgent": "MiApp/1.0"
  }
}
```

#### Generar Nonce y Timestamp

**Nonce (UUID v4):**

```javascript
// Node.js
import { randomUUID } from 'crypto';
const nonce = randomUUID();
```

**Timestamp (ISO 8601 con UTC):**

```javascript
// Node.js
const timestamp = new Date().toISOString();
```

---

### Paso 7: Enviar Solicitud de Pago

Envía el payload completo al endpoint de pagos.

#### Endpoint

```
POST /api/v2/productos/buen-viaje/pagos
```

#### Headers Requeridos

```http
Content-Type: application/json
x-user-key: <user_key>
x-codigo-mediador: <codigo_mediador>
Ocp-Apim-Subscription-Key: <subscription_key>
Cache-Control: no-cache
```

#### Ejemplo con cURL

```bash
curl -X POST \
  "https://devapi.humano.com.do/api/v2/productos/buen-viaje/pagos" \
  -H "Content-Type: application/json" \
  -H "x-user-key: <user_key>" \
  -H "x-codigo-mediador: <codigo_mediador>" \
  -H "Ocp-Apim-Subscription-Key: <subscription_key>" \
  -H "Cache-Control: no-cache" \
  -d @payload.json
```

#### Ejemplo (Node.js con `fetch`)

```javascript
const response = await fetch(
  'https://devapi.humano.com.do/api/v2/productos/buen-viaje/pagos',
  {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-user-key': '<user_key>',
      'x-codigo-mediador': '<codigo_mediador>',
      'Ocp-Apim-Subscription-Key': '<subscription_key>',
      'Cache-Control': 'no-cache'
    },
    body: JSON.stringify(payload)
  }
);

const resultado = await response.json();
console.log('Resultado:', resultado);
```

#### Respuestas

**Éxito (201 Created):**

```json
{
  "transaccionId": "TXN-2025-00123456",
  "estado": "aprobado",
  "numeroFactura": "FAC-2025-001",
  "monto": 100.50,
  "moneda": "USD",
  "fechaProcesamiento": "2025-01-24T15:30:15Z",
  "autorizacion": {
    "codigo": "AUTH-789012",
    "mensaje": "Transacción aprobada"
  }
}
```

**Error de Validación (400 Bad Request):**

```json
{
  "error": "ValidationError",
  "mensaje": "Nonce ya fue consumido",
  "codigo": "NONCE_DUPLICATE"
}
```

**Error de Firma (401 Unauthorized):**

```json
{
  "error": "SecurityException",
  "mensaje": "Firma inválida",
  "codigo": "INVALID_SIGNATURE"
}
```

**Error de Descifrado (500 Internal Server Error):**

```json
{
  "error": "DecryptionError",
  "mensaje": "No se pudo desencriptar el JWE",
  "codigo": "JWE_DECRYPTION_FAILED"
}
```

---

## Ejemplos de Código

### Ejemplo Completo: Node.js

```javascript
import * as jose from 'jose';
import fetch from 'cross-fetch';
import fs from 'fs';
import crypto from 'crypto';
import { randomUUID } from 'crypto';

const CONFIG = {
  baseUrl: 'https://devapi.humano.com.do',
  kid: 'crt-pago-buen-viaje-pub',
  firmaKid: 'crt-pago-client-test-pub',
  clientKeyPath: './mi-app-prvt.key',
  headers: {
    'x-user-key': '<user_key>',
    'x-codigo-mediador': '<codigo_mediador>',
    'Ocp-Apim-Subscription-Key': '<subscription_key>'
  }
};

async function procesarPago() {
  // 1. Obtener clave pública del servidor
  const publicKeyRes = await fetch(
    `${CONFIG.baseUrl}/api/v2/productos/buen-viaje/crypto/publickey/${CONFIG.kid}`,
    { headers: CONFIG.headers }
  );
  const publicKeyPem = await publicKeyRes.text();
  const publicKey = crypto.createPublicKey(publicKeyPem);

  // 2. Cifrar datos de tarjeta con JWE
  const datosTarjeta = {
    NumeroTarjeta: '4111111111111111',
    FechaExpiracionTarjeta: '1228',
    CVV: '123'
  };

  const jwe = await new jose.CompactEncrypt(
    new TextEncoder().encode(JSON.stringify(datosTarjeta))
  )
    .setProtectedHeader({
      alg: 'RSA-OAEP-256',
      enc: 'A256GCM',
      kid: CONFIG.kid
    })
    .encrypt(publicKey);

  // 3. Firmar JWE con tu clave privada
  const privateKeyPem = fs.readFileSync(CONFIG.clientKeyPath, 'utf8');
  const privateKey = crypto.createPrivateKey(privateKeyPem);

  const jws = await new jose.CompactSign(
    new TextEncoder().encode(jwe)
  )
    .setProtectedHeader({
      alg: 'RS256',
      kid: CONFIG.firmaKid
    })
    .sign(privateKey);

  // 4. Construir payload completo
  const payload = {
    numeroFactura: `FAC-${Date.now()}`,
    monto: 100.50,
    impuesto: 18.09,
    moneda: 'USD',
    metodoPago: {
      tipo: 'tarjeta_credito',
      detalles: {
        datosTarjetaCifrados: {
          jwe: jwe,
          kid: CONFIG.kid,
          nonce: randomUUID(),
          timestamp: new Date().toISOString(),
          firmaJws: jws,
          firmaKid: CONFIG.firmaKid
        }
      }
    },
    metadatos: {
      ipCliente: '192.168.1.100',
      userAgent: 'MiApp/1.0'
    }
  };

  // 5. Enviar solicitud
  const response = await fetch(
    `${CONFIG.baseUrl}/api/v2/productos/buen-viaje/pagos`,
    {
      method: 'POST',
      headers: {
        ...CONFIG.headers,
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache'
      },
      body: JSON.stringify(payload)
    }
  );

  const resultado = await response.json();

  if (response.ok) {
    console.log('✅ Pago procesado:', resultado);
  } else {
    console.error('❌ Error:', resultado);
  }

  return resultado;
}

procesarPago().catch(console.error);
```



---

## Solución de Problemas

### Error: "Firma inválida" (401)

**Causa**: El servidor no pudo verificar la firma JWS.

**Soluciones**:
1. Verifica que el `firmaKid` corresponda a un certificado registrado en el servidor
2. Verifica que estás usando la clave privada correcta
3. Asegúrate de que el payload del JWS sea exactamente el JWE (sin espacios adicionales)
4. Verifica que el algoritmo sea `RS256`

### Error: "Nonce ya fue consumido" (400)

**Causa**: El mismo nonce fue enviado dos veces.

**Soluciones**:
1. Genera un nuevo UUID para cada solicitud
2. No reintentes la misma solicitud con el mismo nonce

### Error: "Timestamp fuera de ventana" (400)

**Causa**: El timestamp está a más de ±5 minutos del tiempo del servidor.

**Soluciones**:
1. Sincroniza el reloj de tu sistema
2. Usa `DateTime.UtcNow` (C#) o `new Date().toISOString()` (JS)
3. No cachees el timestamp, genera uno nuevo por solicitud

### Error: "No se pudo desencriptar el JWE" (500)

**Causa**: El servidor no puede descifrar el JWE.

**Soluciones**:
1. Verifica que el `kid` sea correcto (`crt-pago-buen-viaje-pub`)
2. Verifica que usaste la clave pública del servidor (no la tuya)
3. Verifica que los algoritmos sean:
   - `alg: RSA-OAEP-256`
   - `enc: A256GCM`
4. Verifica que el JWE esté bien formado (5 partes separadas por puntos)

### Error: "ASN1 corrupted data"

**Causa**: El certificado público no está en formato X.509 válido.

**Soluciones**:
1. Regenera el certificado usando el comando correcto:
   ```bash
   openssl req -new -x509 -key mi-app-prvt.key \
     -out mi-app-pub.crt -days 3650 \
     -subj "/CN=mi-aplicacion" -sha256
   openssl x509 -in mi-app-pub.crt -outform DER -out mi-app-pub.cer
   ```
2. Verifica el certificado:
   ```bash
   openssl x509 -in mi-app-pub.cer -inform DER -text -noout
   ```

### Error: "unable to verify the first certificate" (SSL)

**Causa**: El servidor usa un certificado SSL auto-firmado o no válido.

**Solución** (solo desarrollo):

```javascript
// Node.js
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Python
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
```

⚠️ **NUNCA** uses esto en producción.

---

## Seguridad

### Mejores Prácticas

1. **Claves Privadas**:
   - ✅ NUNCA compartas tu clave privada
   - ✅ NUNCA la subas a Git (usa `.gitignore`)
   - ✅ En producción, usa un gestor de secretos (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault)
   - ✅ Rota las claves periódicamente (cada 1-2 años)

2. **Validación de Datos**:
   - ✅ Valida números de tarjeta con algoritmo de Luhn
   - ✅ Valida fechas de expiración
   - ✅ Valida CVV (3-4 dígitos)
   - ✅ Nunca almacenes CVV en tu base de datos

3. **Logging**:
   - ✅ NUNCA loguees datos de tarjeta en texto plano
   - ✅ NUNCA loguees el JWE o JWS completo
   - ✅ Loguea solo: `nonce`, `timestamp`, `numeroFactura`, resultado

4. **Errores**:
   - ✅ No expongas detalles técnicos al usuario final
   - ✅ Loguea errores técnicos internamente para debugging
   - ✅ Muestra mensajes genéricos al usuario ("Error procesando pago")

### Cumplimiento PCI-DSS

Este sistema está diseñado para ayudar con PCI-DSS:

| Requisito | Cómo lo cumplimos |
|-----------|-------------------|
| **SAQ A-EP**: Datos de tarjeta no tocan tu servidor | ✅ Se cifran en el cliente antes de enviar |
| **Datos en tránsito**: Proteger datos en tránsito | ✅ HTTPS + JWE (doble cifrado) |
| **Datos en reposo**: No almacenar CVV | ✅ Solo el servidor final tiene acceso (temporalmente) |
| **Control de acceso**: Autenticar solicitudes | ✅ JWS garantiza autenticidad |

⚠️ **Importante**: Consulta con un QSA (Qualified Security Assessor) para validar tu cumplimiento completo de PCI-DSS.

---

## Referencias

### Estándares y RFCs

- [RFC 7516 - JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
- [RFC 7515 - JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 8017 - PKCS #1: RSA Cryptography Specifications](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 5280 - X.509 Public Key Infrastructure Certificate](https://datatracker.ietf.org/doc/html/rfc5280)

### Librerías

- [jose (Node.js)](https://github.com/panva/jose) - Implementación completa de JOSE
- [python-jose (Python)](https://github.com/mpdavis/python-jose) - JOSE para Python
- [jose-jwt (C#)](https://github.com/dvsekhvalnov/jose-jwt) - JOSE para .NET
- [Nimbus JOSE+JWT (Java)](https://connect2id.com/products/nimbus-jose-jwt) - JOSE para Java

### Herramientas

- [jwt.io](https://jwt.io/) - Debugger online para JWT/JWE/JWS
- [OpenSSL](https://www.openssl.org/) - Suite de herramientas criptográficas
- [PCI Security Standards](https://www.pcisecuritystandards.org/) - Cumplimiento PCI-DSS

---

## Contacto y Soporte

Para soporte técnico o preguntas sobre la integración:

- **Equipo de API Humano Seguros**: Alexander Cabral (acabral@humano.com.do)
- **Script de prueba**: https://github.com/omtejedahumano/pago-buen-viaje
- **Portal de desarrolladores**: https://devportal.humano.com.do