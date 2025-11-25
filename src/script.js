#!/usr/bin/env node

/**
 * ═══════════════════════════════════════════════════════════════
 * BUEN VIAJE API - CLIENTE DE PAGO ENCRIPTADO (REFERENCIA)
 * ═══════════════════════════════════════════════════════════════
 * 
 * Este script demuestra cómo:
 * 1. Obtener la clave pública del servidor
 * 2. Cifrar datos de tarjeta usando JWE (JSON Web Encryption)
 * 3. Firmar el payload con JWS (JSON Web Signature)
 * 4. Enviar el pago al API
 * 
 * NOTA: Este es un script para utilizar como referencia. Adapta según tus necesidades.
 * 
 * @version 1.0.0
 * @license MIT
 */

// ═══════════════════════════════════════════════════════════════
// IMPORTS
// ═══════════════════════════════════════════════════════════════

import { CompactEncrypt, importSPKI, CompactSign, importPKCS8, generateKeyPair, exportPKCS8 } from 'jose';
import fetch from 'cross-fetch';
import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

// Cargar variables de entorno desde .env
dotenv.config();

// Configurar crypto global (compatibilidad con JOSE)
if (!globalThis.crypto) {
  globalThis.crypto = crypto;
}

// ═══════════════════════════════════════════════════════════════
// CONFIGURACIÓN
// ═══════════════════════════════════════════════════════════════

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CONFIG = {
  // API Endpoints
  baseUrl: process.env.BASE_URL || '',
  
  // Key Identifiers
  serverKid: process.env.SERVER_KID || '',
  clientKid: process.env.CLIENT_KID || '',
  clientKeyPath: process.env.CLIENT_KEY_PATH || path.join(__dirname, ''),

  // Headers de autenticación
  headers: {
    'x-user-key': process.env.X_USER_KEY || '',
    'x-codigo-mediador': process.env.X_CODIGO_MEDIADOR || '',
    'Ocp-Apim-Subscription-Key': process.env.API_SUBSCRIPTION_KEY || '',
    'Cache-Control': 'no-cache'
  },

  // Datos de prueba de pago
  pago: {
    numeroFactura: '4670066',
    monto: 2878.65,
    impuesto: 0.00,
    moneda: 'DOP'
  },

  // Tarjeta de prueba (Visa test card - NO usar en producción)
  tarjetaPrueba: {
    numero: '4111111111111111',
    expiracion: '1228',  // MMYY
    cvv: '123'
  },

  // Modo desarrollo (desactiva SSL - solo para pruebas locales)
  development: {
    disableSSL: process.env.DISABLE_SSL === 'true' || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0',
    useLocalhost: process.env.USE_LOCALHOST === 'true'
  }
};

// Configurar SSL para desarrollo (si aplica)
if (CONFIG.development.disableSSL) {
  console.warn('\n  ADVERTENCIA: Verificación SSL desactivada (solo para desarrollo)');
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

// ═══════════════════════════════════════════════════════════════
// FUNCIÓN PRINCIPAL
// ═══════════════════════════════════════════════════════════════

async function main() {
  imprimirEncabezado();
  validarConfiguracion();

  try {
    // PASO 1: Preparar claves del cliente
    console.log('===> PASO 1: Preparando claves de firma del cliente');
    await generarClavesClienteSiNoExisten();
    const clavePrivadaCliente = await cargarClavePrivadaCliente();
    console.log('   ✓ Claves del cliente listas\n');

    // PASO 2: Obtener clave pública del servidor
    console.log('===> PASO 2: Obteniendo clave pública del servidor');
    const clavePublicaServidor = await obtenerClavePublicaServidor();
    console.log('   ✓ Clave pública del servidor obtenida\n');

    // PASO 3: Cifrar datos sensibles
    console.log('===> PASO 3: Cifrando datos de tarjeta');
    const datosTarjeta = {
      NumeroTarjeta: CONFIG.tarjetaPrueba.numero,
      FechaExpiracionTarjeta: CONFIG.tarjetaPrueba.expiracion,
      CVV: CONFIG.tarjetaPrueba.cvv
    };
    const jwe = await cifrarDatosTarjeta(datosTarjeta, clavePublicaServidor);
    console.log('   ✓ Datos cifrados con JWE\n');

    // PASO 4: Firmar el payload
    console.log('===> PASO 4: Firmando payload cifrado');
    const jws = await firmarJWE(jwe, clavePrivadaCliente);
    console.log('   ✓ Payload firmado con JWS\n');

    // PASO 5: Construir y enviar
    console.log('===> PASO 5: Enviando pago al servidor');
    const payload = construirPayloadPago(jwe, jws);
    const { response, responseText } = await enviarPago(payload);

    // PASO 6: Procesar respuesta
    console.log('\n===> PASO 6: Procesando respuesta\n');
    const exitCode = mostrarRespuesta(response, responseText);
    process.exit(exitCode);

  } catch (error) {
    manejarError(error);
  }
}

// Ejecutar
main();

// ═══════════════════════════════════════════════════════════════
// FUNCIONES DE CRIPTOGRAFÍA
// ═══════════════════════════════════════════════════════════════

/**
 * Cifra los datos de la tarjeta usando JWE (JSON Web Encryption)
 * Algoritmo: RSA-OAEP-256 con AES-256-GCM
 * 
 * @param {Object} datosTarjeta - Datos sensibles de la tarjeta
 * @param {CryptoKey} clavePublicaServidor - Clave pública del servidor
 * @returns {Promise<string>} JWE en formato compacto
 */
async function cifrarDatosTarjeta(datosTarjeta, clavePublicaServidor) {
  const payload = JSON.stringify(datosTarjeta);
  const encoder = new TextEncoder();

  const jwe = await new CompactEncrypt(encoder.encode(payload))
    .setProtectedHeader({
      alg: 'RSA-OAEP-256',  // Cifrado asimétrico para la clave
      enc: 'A256GCM',        // Cifrado simétrico para el contenido
      kid: CONFIG.serverKid   // Key ID del servidor
    })
    .encrypt(clavePublicaServidor);

  console.log(`   → JWE generado (${jwe.length} caracteres)`);
  console.log(`   → Preview: ${jwe.substring(0, 60)}...`);
  return jwe;
}

/**
 * Firma el JWE usando JWS (JSON Web Signature)
 * Algoritmo: RS256 (RSA con SHA-256)
 * 
 * @param {string} jwe - JWE a firmar
 * @param {CryptoKey} clavePrivadaCliente - Clave privada del cliente
 * @returns {Promise<string>} JWS en formato compacto
 */
async function firmarJWE(jwe, clavePrivadaCliente) {
  const encoder = new TextEncoder();

  const jws = await new CompactSign(encoder.encode(jwe))
    .setProtectedHeader({
      alg: 'RS256',          // Algoritmo de firma RSA
      kid: CONFIG.clientKid   // Key ID del cliente
    })
    .sign(clavePrivadaCliente);

  console.log(`   → JWS generado (${jws.length} caracteres)`);
  console.log(`   → Preview: ${jws.substring(0, 60)}...`);
  return jws;
}

// ═══════════════════════════════════════════════════════════════
// GESTIÓN DE CLAVES
// ═══════════════════════════════════════════════════════════════

/**
 * Genera un par de claves RSA para el cliente si no existen
 * Las claves son necesarias para firmar los payloads
 */
async function generarClavesClienteSiNoExisten() {
  if (fs.existsSync(CONFIG.clientKeyPath)) {
    console.log(`   → Usando clave privada existente: ${path.basename(CONFIG.clientKeyPath)}`);
    return;
  }

  console.log('   → No se encontró clave privada. Generando nueva...');

  const { privateKey } = await generateKeyPair('RS256', {
    modulusLength: 3072  // Tamaño de clave recomendado
  });

  const privateKeyPem = await exportPKCS8(privateKey);
  fs.writeFileSync(CONFIG.clientKeyPath, privateKeyPem, 'utf8');

  console.log(`   → Clave generada y guardada en: ${path.basename(CONFIG.clientKeyPath)}`);
  console.log('   → IMPORTANTE: Esta clave es solo para pruebas locales');
}

/**
 * Carga la clave privada del cliente desde el archivo
 * 
 * @returns {Promise<CryptoKey>} Clave privada importada
 */
async function cargarClavePrivadaCliente() {
  if (!fs.existsSync(CONFIG.clientKeyPath)) {
    throw new Error(`No se encontró la clave privada en: ${CONFIG.clientKeyPath}`);
  }

  const privateKeyPem = fs.readFileSync(CONFIG.clientKeyPath, 'utf8');
  return await importPKCS8(privateKeyPem, 'RS256');
}

// ═══════════════════════════════════════════════════════════════
// FUNCIONES DE RED
// ═══════════════════════════════════════════════════════════════

/**
 * Obtiene la clave pública del servidor para cifrar los datos
 * 
 * @returns {Promise<CryptoKey>} Clave pública del servidor
 */
async function obtenerClavePublicaServidor() {
  const endpoint = `${CONFIG.baseUrl}/api/v2/productos/buen-viaje/crypto/publickey/${CONFIG.serverKid}`;
  
  console.log(`   → Endpoint: ${endpoint}`);

  const response = await fetch(endpoint, {
    method: 'GET',
    headers: CONFIG.headers
  });

  if (!response.ok) {
    const texto = await response.text().catch(() => 'Sin detalles');
    throw new Error(
      `No se pudo obtener la clave pública del servidor.\n` +
      `   Status: ${response.status} ${response.statusText}\n` +
      `   Respuesta: ${texto.substring(0, 200)}`
    );
  }

  const pem = await response.text();
  console.log(`   → Formato: PEM (${pem.length} caracteres)`);
  console.log(`   → KID: ${CONFIG.serverKid}`);
  
  return await importSPKI(pem, 'RSA-OAEP-256');
}

/**
 * Envía el pago al servidor con todos los datos cifrados y firmados
 * 
 * @param {Object} payload - Payload completo del pago
 * @returns {Promise<{response: Response, responseText: string}>}
 */
async function enviarPago(payload) {
  const endpoint = `${CONFIG.baseUrl}/api/v2/productos/buen-viaje/pagos`;
  
  console.log(`   → Endpoint: ${endpoint}`);
  console.log(`   → Factura: ${payload.numeroFactura}`);
  console.log(`   → Monto: ${payload.monto.toFixed(2)}`);
  console.log(`   → Impuesto: ${payload.moneda} ${payload.impuesto.toFixed(2)}`);

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      ...CONFIG.headers,
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  const responseText = await response.text().catch(() => '');

  // Log para debugging (solo en desarrollo)
  if (CONFIG.development.useLocalhost || process.env.DEBUG === 'true') {
    console.log(`\n    Payload enviado:\n${JSON.stringify(payload, null, 2)}\n`);
  }

  return { response, responseText };
}

// ═══════════════════════════════════════════════════════════════
// CONSTRUCCIÓN DE PAYLOAD
// ═══════════════════════════════════════════════════════════════

/**
 * Construye el payload completo del pago con todos los campos requeridos
 * 
 * @param {string} jwe - Datos cifrados (JWE)
 * @param {string} jws - Firma del JWE (JWS)
 * @returns {Object} Payload completo
 */
function construirPayloadPago(jwe, jws) {
  const nonce = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  return {
    // Datos de la transacción
    numeroFactura: CONFIG.pago.numeroFactura,
    monto: CONFIG.pago.monto,
    impuesto: CONFIG.pago.impuesto,
    moneda: CONFIG.pago.moneda,

    // Método de pago con datos cifrados
    metodoPago: {
      tipo: 'tarjeta_credito',
      detalles: {
        datosTarjetaCifrados: {
          jwe: jwe,                    // Datos cifrados
          kid: CONFIG.serverKid,        // KID usado para cifrar
          nonce: nonce,                 // Número único de operación
          timestamp: timestamp,         // Marca de tiempo
          firmaJws: jws,               // Firma del JWE
          firmaKid: CONFIG.clientKid   // KID usado para firmar
        }
      }
    },

    // Metadatos adicionales (opcionales)
    metadatos: {
      origen: 'pago-buen-viaje-script.js',
      timestamp: timestamp,
      entorno: process.env.NODE_ENV || 'development',
      version: '1.0.0'
    }
  };
}

// ═══════════════════════════════════════════════════════════════
// UTILIDADES Y FORMATO
// ═══════════════════════════════════════════════════════════════

/**
 * Imprime el encabezado del script con información de configuración
 */
function imprimirEncabezado() {
  console.log('\n' + '═'.repeat(70));
  console.log('  BUEN VIAJE API - CLIENTE DE PAGO ENCRIPTADO v1.0');
  console.log('═'.repeat(70));
  console.log(`  Entorno: ${CONFIG.baseUrl}`);
  console.log(`  KID Servidor: ${CONFIG.serverKid}`);
  console.log(`  KID Cliente: ${CONFIG.clientKid}`);
  
  if (CONFIG.development.useLocalhost) {
    console.log('   Modo: Desarrollo (localhost)');
  }
  
  console.log('═'.repeat(70) + '\n');
}

/**
 * Valida que la configuración tenga todos los campos necesarios
 */
function validarConfiguracion() {
  const camposRequeridos = [
    { nombre: 'x-user-key', valor: CONFIG.headers['x-user-key'] },
    { nombre: 'x-codigo-mediador', valor: CONFIG.headers['x-codigo-mediador'] },
    { nombre: 'Ocp-Apim-Subscription-Key', valor: CONFIG.headers['Ocp-Apim-Subscription-Key'] },
    { nombre: 'SERVER_KID', valor: process.env.SERVER_KID },
    { nombre: 'CLIENT_KID', valor: process.env.CLIENT_KID },
    { nombre: 'CLIENT_KEY_PATH', valor: process.env.CLIENT_KEY_PATH }
  ];

  const faltantes = camposRequeridos.filter(campo => !campo.valor);
  
  if (faltantes.length > 0) {
    console.error('\n ERROR: Faltan variables requeridas:');
    faltantes.forEach(campo => console.error(`   - ${campo.nombre}`));
    console.error('\n Configura estas variables en el código o usando variables de entorno');
    process.exit(1);
  }
}

/**
 * Muestra la respuesta del servidor de forma legible
 * 
 * @param {Response} response - Respuesta HTTP
 * @param {string} responseText - Texto de la respuesta
 * @returns {number} Código de salida (0 = éxito, 1 = error)
 */
function mostrarRespuesta(response, responseText) {
  console.log('═'.repeat(70));
  console.log('  RESPUESTA DEL SERVIDOR');
  console.log('═'.repeat(70));
  console.log(`Content-Type: ${response.headers.get('content-type')}`);
  console.log('─'.repeat(70));

  // Intentar parsear como JSON
  if (response.headers.get('content-type')?.includes('application/json')) {
    try {
      const json = JSON.parse(responseText);
      console.log(JSON.stringify(json, null, 2));
    } catch {
      console.log(responseText);
    }
  } else {
    const preview = responseText.length > 1000 
      ? responseText.slice(0, 1000) + '\n... (respuesta truncada)' 
      : responseText;
    console.log(preview);
  }

  console.log('═'.repeat(70));

  if (response.ok) {
    return 0;
  } else {
    console.error(` Error procesando pago (${response.status})\n`);
    return 1;
  }
}

/**
 * Maneja errores de forma amigable con sugerencias útiles
 * 
 * @param {Error} error - Error capturado
 */
function manejarError(error) {
  console.error('\n' + '═'.repeat(70));
  console.error(' ERROR');
  console.error('═'.repeat(70));
  console.error(`${error.message}\n`);
  
  // Mostrar causa si existe
  if (error.cause) {
    console.error(' Causa raíz:');
    console.error(error.cause);
    console.error('');
  }
  
  // Sugerencias de solución
  console.error(' Posibles soluciones:');
  console.error('   1. Verifica que las credenciales del API sean correctas');
  console.error('   2. Confirma que el servidor esté accesible');
  console.error('   3. Revisa que los KIDs sean los correctos');
  
  // Stack trace en modo debug
  if (process.env.DEBUG === 'true' && error.stack) {
    console.error('\n Stack trace (DEBUG):');
    console.error(error.stack);
  }
  
  console.error('═'.repeat(70) + '\n');
  
  process.exit(1);
}