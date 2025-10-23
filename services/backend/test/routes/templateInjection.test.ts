/**
 * PRUEBAS DE MITIGACIÓN DE TEMPLATE INJECTION
 * 
 * Pruebas unitarias para validar las mitigaciones contra ataques de Template 
 * Injection en la funcionalidad de envío de correos durante la creación de usuarios.
 * 
 * CONTEXTO:
 * - Los campos first_name y last_name pueden contener código EJS malicioso
 * - Las mitigaciones incluyen: escapado automático, validación de tipos y longitud
 * 
 * COMPORTAMIENTO ESPERADO:
 * - Rama 'practico-2' (con mitigaciones): todas las pruebas PASAN
 * - Rama 'main' (sin mitigaciones): todas las pruebas FALLAN
 * 
 * VECTOR: AuthService.createUser() -> Template EJS para email de activación
 */

import AuthService from '../../src/services/authService';
import { User } from '../../src/types/user';
import nodemailer from 'nodemailer';
import db from '../../src/db';

// CONFIGURACIÓN DE MOCKS PARA AISLAMIENTO DE PRUEBAS

// Mock de la base de datos para evitar dependencias externas
jest.mock('../../src/db');
const mockedDb = db as jest.MockedFunction<typeof db>;

// Mock de nodemailer para capturar emails sin enviarlos realmente  
jest.mock('nodemailer');
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

// Mock del transporter SMTP para interceptar llamadas sendMail
const mockSendMail = jest.fn();
mockedNodemailer.createTransport = jest.fn().mockReturnValue({
  sendMail: mockSendMail,
});

// SUITE DE PRUEBAS PRINCIPALES

describe('Pruebas de Mitigación de Template Injection', () => {
  const OLD_ENV = process.env;
  
  beforeEach(() => {
    // Limpieza de mocks entre pruebas
    jest.resetModules();
    jest.clearAllMocks();
    
    // Configuración de variables de entorno para emails
    process.env = { ...OLD_ENV };
    process.env.FRONTEND_URL = 'http://localhost:3000';
    process.env.SMTP_HOST = 'localhost';
    process.env.SMTP_PORT = '1025';
    process.env.SMTP_USER = 'test';
    process.env.SMTP_PASS = 'test';
    
    // Mock de respuesta exitosa del envío de email
    mockSendMail.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    // Restauración del entorno original
    process.env = OLD_ENV;
  });

  describe('Prevención de Template Injection en createUser', () => {
    
    /**
     * TEST 1: Prevención de inyección EJS en campo first_name
     * 
     * Valida que el código JavaScript malicioso no se ejecute cuando se 
     * inyecta a través del campo first_name usando sintaxis EJS.
     * 
     * Payload: '<% eval("alert(1)") %>Attack'
     * - Rama vulnerable: ReferenceError (código se ejecuta)
     * - Rama mitigada: caracteres escapados como &lt;%
     */
    it('debería prevenir inyección de template EJS en el campo first_name', async () => {
      
      // Usuario con payload malicioso en first_name
      const usuarioMalicioso: User = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        first_name: '<% eval("alert(1)") %>Attack',  // Payload malicioso
        last_name: 'NormalLast'
      };

      // Configuración de mocks para flujo de base de datos exitoso
      const selectChain = {
        where: jest.fn().mockReturnThis(),
        orWhere: jest.fn().mockReturnThis(),
        first: jest.fn().mockResolvedValue(null)  // Usuario no existe
      };
      
      const insertChain = {
        insert: jest.fn().mockReturnThis(),
        returning: jest.fn().mockResolvedValue([usuarioMalicioso])  // Usuario creado
      };

      mockedDb
        .mockReturnValueOnce(selectChain as any)
        .mockReturnValueOnce(insertChain as any);

      // Ejecutar creación de usuario
      await AuthService.createUser(usuarioMalicioso);

      // Validaciones de seguridad
      expect(mockSendMail).toHaveBeenCalledTimes(1);
      const emailEnviado = mockSendMail.mock.calls[0][0];
      
      // El código malicioso NO debe ejecutarse
      expect(emailEnviado.html).not.toContain('eval("alert(1)")');
      expect(emailEnviado.html).not.toContain('<% eval');
      
      // Los caracteres deben aparecer escapados
      expect(emailEnviado.html).toContain('&lt;%');
      expect(emailEnviado.html).toMatch(/Attack/);
    });

    /**
     * TEST 2: Prevención de inyección EJS en campo last_name
     * 
     * Valida que las expresiones EJS no se evalúen cuando se inyectan
     * a través del campo last_name.
     * 
     * Payload: '<%= "injection" %>User'
     * - Rama vulnerable: se renderiza como "injectionUser"
     * - Rama mitigada: caracteres escapados, comillas como entidades HTML
     */
    it('debería prevenir inyección de template EJS en el campo last_name', async () => {
      
      // Usuario con expresión EJS maliciosa en last_name
      const usuarioMalicioso: User = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        first_name: 'NormalFirst',
        last_name: '<%= "injection" %>User'  // Expresión EJS maliciosa
      };

      // Configuración de mocks estándar
      const selectChain = {
        where: jest.fn().mockReturnThis(),
        orWhere: jest.fn().mockReturnThis(),
        first: jest.fn().mockResolvedValue(null)
      };
      
      const insertChain = {
        insert: jest.fn().mockReturnThis(),
        returning: jest.fn().mockResolvedValue([usuarioMalicioso])
      };

      mockedDb
        .mockReturnValueOnce(selectChain as any)
        .mockReturnValueOnce(insertChain as any);

      // Ejecutar creación de usuario
      await AuthService.createUser(usuarioMalicioso);

      // Validaciones de seguridad
      expect(mockSendMail).toHaveBeenCalledTimes(1);
      const emailEnviado = mockSendMail.mock.calls[0][0];
      
      // La expresión NO debe evaluarse
      expect(emailEnviado.html).not.toContain('"injection"');
      expect(emailEnviado.html).not.toContain('<%=');
      
      // Debe contener contenido escapado correctamente
      expect(emailEnviado.html).toContain('&lt;%=');
      expect(emailEnviado.html).toContain('&#34;injection&#34;');
      expect(emailEnviado.html).toMatch(/User/);
    });

    /**
     * TEST 3: Escapado automático contra expresiones complejas
     * 
     * Prueba la efectividad contra expresiones aritméticas y estructuras
     * de control EJS.
     * 
     * Payloads: '<%= 1+1 %>Evil' y '<% if(true) %>Bad'
     * - Rama vulnerable: "2Evil" y "Bad" (código ejecutado)
     * - Rama mitigada: expresiones escapadas completamente
     */
    it('debería demostrar que el escapado automático previene inyección de templates', async () => {
      
      // Usuario con múltiples tipos de expresiones EJS
      const usuarioConPayloadEJS: User = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        first_name: '<%= 1+1 %>Evil',      // Expresión aritmética
        last_name: '<% if(true) %>Bad'     // Estructura de control
      };

      // Configuración de mocks
      const selectChain = {
        where: jest.fn().mockReturnThis(),
        orWhere: jest.fn().mockReturnThis(),
        first: jest.fn().mockResolvedValue(null)
      };
      
      const insertChain = {
        insert: jest.fn().mockReturnThis(),
        returning: jest.fn().mockResolvedValue([usuarioConPayloadEJS])
      };

      mockedDb
        .mockReturnValueOnce(selectChain as any)
        .mockReturnValueOnce(insertChain as any);

      // Ejecutar creación de usuario
      await AuthService.createUser(usuarioConPayloadEJS);

      // Validaciones de seguridad
      expect(mockSendMail).toHaveBeenCalledTimes(1);
      const emailEnviado = mockSendMail.mock.calls[0][0];
      
      // Expresiones deben estar escapadas completamente
      expect(emailEnviado.html).toContain('&lt;%= 1+1 %&gt;');
      expect(emailEnviado.html).toContain('&lt;% if(true) %&gt;');
      
      // Código NO debe ejecutarse
      expect(emailEnviado.html).not.toContain('2Evil');  // 1+1 NO evaluado
      expect(emailEnviado.html).not.toContain('<%= 1+1 %>Evil');
      
      // Texto base debe estar presente
      expect(emailEnviado.html).toContain('Evil');
      expect(emailEnviado.html).toContain('Bad');
    });

    /**
      TEST 4: Validación de tipos para prevenir inyección
     * 
     * Valida que el sistema rechace datos con tipos incorrectos que
     * podrían bypasear las mitigaciones.
     * 
     * Vectores: first_name null, last_name array con payload EJS
     * Mitigación: validación estricta de tipos antes del procesamiento
     */
    it('debería validar tipos de entrada para prevenir inyección de templates', async () => {
      
      // Datos con tipos incorrectos intencionalmente
      const usuarioMalicioso = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        first_name: null,                    // Tipo incorrecto
        last_name: ['<% hack() %>']          // Tipo incorrecto con payload
      } as any;

      // Configuración de mock (no debería llegar a inserción)
      const selectChain = {
        where: jest.fn().mockReturnThis(),
        orWhere: jest.fn().mockReturnThis(),
        first: jest.fn().mockResolvedValue(null)
      };

      mockedDb.mockReturnValueOnce(selectChain as any);

      // Debe fallar con mensaje de validación específico
      await expect(AuthService.createUser(usuarioMalicioso))
        .rejects
        .toThrow(/First name is required and must be a string/);
      
      // NO debe enviar email con datos inválidos
      expect(mockSendMail).not.toHaveBeenCalled();
    });

    /**
     * TEST 5: Validación de longitud para prevenir payloads largos
     * 
     * Valida que el sistema implemente límites de longitud para prevenir
     * ataques con payloads extensos que intenten bypasear filtros.
     * 
     * Vector: payload >50 caracteres con código EJS
     * Mitigación: límites de longitud antes del procesamiento
     */
    it('debería validar longitud de entrada para prevenir payloads largos', async () => {
      
      // Payload extremadamente largo con template injection
      const payloadLargoMalicioso = '<% hack() %>' + 'A'.repeat(100);  // >50 caracteres
      
      const usuarioMalicioso: User = {
        username: 'testuser',
        email: 'test@example.com',
        password: 'password123',
        first_name: payloadLargoMalicioso,  // Payload largo + template injection
        last_name: 'NormalLast'
      };

      // Configuración de mock (no debería llegar a inserción)
      const selectChain = {
        where: jest.fn().mockReturnThis(),
        orWhere: jest.fn().mockReturnThis(),
        first: jest.fn().mockResolvedValue(null)
      };

      mockedDb.mockReturnValueOnce(selectChain as any);

      // Debe fallar por longitud excesiva
      await expect(AuthService.createUser(usuarioMalicioso))
        .rejects
        .toThrow(/First name must be 50 characters or less/);
      
      // NO debe procesar payload largo
      expect(mockSendMail).not.toHaveBeenCalled();
    });
  });
});