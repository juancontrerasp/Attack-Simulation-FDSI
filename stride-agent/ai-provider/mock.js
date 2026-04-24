/**
 * Proveedor mock - sin llamadas de red
 */

const MOCK_RESPONSE = {
  summary: 'Analisis STRIDE mock completado sobre arquitectura inferida de codigo fuente.',
  inferred_components: [
    'AttackEngine',
    'HttpUtil',
    'SqlInjectionAttack',
    'BruteForceAttack',
    'JwtTokenAttack',
    'XssAttack',
    'PathTraversalAttack',
    'InfoLeakAttack'
  ],
  threats: {
    Spoofing: [
      {
        component: 'JwtTokenAttack',
        description: 'Riesgo de suplantacion si el backend acepta tokens manipulados o alg=none.',
        evidence: 'Pruebas de token alterado y token con alg none contra /api/auth/me.',
        severity: 'Alta',
        mitigation: 'Validar firma, algoritmo esperado y claims del JWT en backend.'
      }
    ],
    Tampering: [
      {
        component: 'SqlInjectionAttack',
        description: 'Posible manipulacion de autenticacion via inyeccion SQL en login.',
        evidence: 'Payloads SQL contra /login y criterio de exito por respuesta.',
        severity: 'Alta',
        mitigation: 'Usar consultas parametrizadas y validacion de entrada.'
      }
    ],
    Repudiation: [
      {
        component: 'AttackEngine',
        description: 'No hay traza de auditoria persistente por actor/accion.',
        evidence: 'Salida principalmente en consola y archivo de resultados.',
        severity: 'Media',
        mitigation: 'Agregar logs estructurados con actor, accion y timestamp.'
      }
    ],
    InformationDisclosure: [
      {
        component: 'InfoLeakAttack',
        description: 'Diferencias de mensajes permiten enumeracion de usuarios.',
        evidence: 'Compara respuesta de usuarios validos e invalidos en /login.',
        severity: 'Media',
        mitigation: 'Unificar mensajes de error para credenciales invalidas.'
      }
    ],
    DenialOfService: [
      {
        component: 'BruteForceAttack',
        description: 'Ausencia de rate limiting puede permitir abuso sostenido.',
        evidence: 'Intentos consecutivos sobre /login sin bloqueo detectado.',
        severity: 'Alta',
        mitigation: 'Aplicar rate limiting y bloqueo temporal por intentos fallidos.'
      }
    ],
    ElevationOfPrivilege: [
      {
        component: 'WeakPasswordAttack',
        description: 'Politica debil de password facilita compromiso de cuentas.',
        evidence: 'Pruebas de passwords debiles en /register.',
        severity: 'Alta',
        mitigation: 'Exigir politicas robustas de complejidad y rotacion.'
      }
    ]
  }
};

const MOCK_FEEDBACK_RESPONSE = {
  artefact_type: 'repo',
  system_summary: 'Sistema de simulación de ataques STRIDE sobre arquitectura de referencia insegura. Expone endpoints de autenticación sin controles robustos para fines de prueba de seguridad.',
  whats_good: [
    {
      aspect: 'Separación de módulos de ataque por categoría STRIDE',
      why_it_matters: 'Facilita el análisis aislado de cada vector de amenaza y reduce el radio de impacto.',
      stride_impact: 'ElevationOfPrivilege'
    },
    {
      aspect: 'Uso de archivos de resultados en JSON estructurado',
      why_it_matters: 'Permite trazabilidad y auditoría de los resultados de ataques.',
      stride_impact: 'Repudiation'
    }
  ],
  what_to_fix: [
    {
      issue: 'Los endpoints de login no aplican rate limiting, permitiendo ataques de fuerza bruta ilimitados.',
      stride_category: 'DenialOfService',
      severity: 'Alta',
      how_to_fix: 'Implementar Bucket4j con límite de 5 intentos por minuto por IP en el endpoint /login.'
    },
    {
      issue: 'Las consultas SQL concatenan input del usuario directamente, exponiendo inyección SQL.',
      stride_category: 'Tampering',
      severity: 'Alta',
      how_to_fix: 'Reemplazar concatenación de strings por PreparedStatement con parámetros enlazados.'
    },
    {
      issue: 'Los mensajes de error diferencian usuarios válidos de inválidos, facilitando enumeración.',
      stride_category: 'InformationDisclosure',
      severity: 'Media',
      how_to_fix: 'Unificar el mensaje de error a "Credenciales inválidas" sin distinguir usuario o contraseña.'
    }
  ],
  what_to_add: [
    {
      missing_control: 'Autenticación JWT con validación de firma RS256',
      why_needed: 'Previene suplantación de identidad mediante tokens manipulados o algoritmo none.',
      stride_category: 'Spoofing',
      implementation_hint: 'Agregar JwtAuthenticationFilter y configurar parseClaimsJws() en SecurityConfig.'
    },
    {
      missing_control: 'Audit log persistente de eventos de autenticación',
      why_needed: 'Sin trazabilidad no es posible detectar ni investigar incidentes de seguridad.',
      stride_category: 'Repudiation',
      implementation_hint: 'Crear tabla audit_log en schema.sql y registrar cada intento de login con IP, usuario y resultado.'
    },
    {
      missing_control: 'Security headers HTTP (HSTS, CSP, X-Frame-Options)',
      why_needed: 'Protege contra clickjacking, XSS y downgrade de protocolo.',
      stride_category: 'InformationDisclosure',
      implementation_hint: 'Implementar SecurityHeadersFilter que inyecte los headers en cada respuesta.'
    }
  ],
  overall_security_score: 22
};

async function analyze() {
  return JSON.stringify(MOCK_RESPONSE);
}

async function analyzeFeedback() {
  return JSON.stringify(MOCK_FEEDBACK_RESPONSE);
}

module.exports = { analyze, analyzeFeedback };
