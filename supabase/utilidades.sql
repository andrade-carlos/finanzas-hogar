-- Utilidades para el administrador. Ejecuta SOLO el bloque que necesites en Supabase › SQL Editor.

-- 1) Alguien perdió el teléfono (reiniciar su verificación en dos pasos).
--    Cambia el correo. En su próximo ingreso deberá activar la verificación otra vez.
delete from auth.mfa_factors
 where user_id = (select id from auth.users where email = 'correo@ejemplo.com');

-- 2) Ver quién tiene cuenta y quién pertenece al hogar.
select u.email, u.created_at, u.last_sign_in_at, m.role
  from auth.users u left join public.household_members m on m.user_id = u.id
 order by u.created_at;

-- 3) EMPEZAR DE CERO (borra el hogar y TODOS sus datos cifrados).
--    Úsalo solo si se perdió la clave del hogar. Luego crea el hogar otra vez y
--    carga tu último respaldo .json. Quita los dos guiones de la línea siguiente para ejecutarlo:
-- delete from public.households;
