# Finanzas del hogar

Aplicación web para controlar el presupuesto del hogar y el plan de pago de deudas.
Se publica gratis con **GitHub Pages**. Las cuentas y los datos cifrados se guardan en un proyecto gratuito de **Supabase**.

## Seguridad

- **Acceso:** correo + contraseña + código de 6 dígitos de una app de autenticación (obligatorio para todos los usuarios).
- **Cifrado de extremo a extremo:** los datos se cifran en el navegador con AES-256-GCM, usando una clave derivada de la *clave del hogar* (PBKDF2-SHA-256, 600.000 iteraciones). Supabase y GitHub solo ven texto cifrado.
- **Base de datos cerrada:** ninguna tabla es accesible desde internet. Toda operación pasa por funciones que verifican la sesión, la verificación en dos pasos y la pertenencia al hogar.
- **Un solo hogar por instalación:** el primer usuario lo crea; los demás entran con un código de invitación de un solo uso que vence.
- **Página protegida:** política de seguridad de contenido estricta basada en hashes, sin código de terceros, protección contra el uso dentro de otra página y cierre de sesión automático por inactividad.

Este repositorio no contiene datos personales ni secretos. La clave publicable de Supabase que va en `config.json` está pensada para ser pública.

## Archivos

| Archivo | Para qué sirve |
| --- | --- |
| `index.html` | La aplicación completa |
| `config.json` | Dirección y clave publicable de tu proyecto de Supabase (lo único que debes editar) |
| `supabase/schema.sql` | Crea las tablas y reglas de seguridad (se ejecuta una vez en Supabase) |
| `supabase/utilidades.sql` | Consultas para el administrador (reiniciar dos pasos, ver usuarios, empezar de cero) |
| `.github/workflows/keepalive.yml` | Consulta mínima cada 3 días para que Supabase no pause el proyecto |

## Instalación (resumen)

1. Crea un proyecto gratuito en Supabase y ejecuta `supabase/schema.sql` en el SQL Editor.
2. En Authentication: activa la confirmación de correo, fija la contraseña mínima en 12 caracteres y configura la URL del sitio.
3. Pon la *Project URL* y la *publishable key* en `config.json`.
4. En GitHub: Settings › Pages › Deploy from a branch › `main` / root.
5. Abre la página, crea tu cuenta, activa la verificación en dos pasos y crea el hogar. Luego invita a tu familia desde **Usuarios y seguridad**.

La guía paso a paso completa está en el documento de instalación que acompaña a este repositorio.
