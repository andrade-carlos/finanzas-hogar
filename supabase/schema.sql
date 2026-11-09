-- =====================================================================
-- Libertad Financiera · Esquema seguro para Supabase
-- Ejecútalo COMPLETO una sola vez en: Supabase › SQL Editor › New query › Run
-- Se puede volver a ejecutar sin perder datos (crea solo lo que falta y
-- reemplaza las funciones por su versión más reciente).
--
-- Modelo de seguridad
--  * Los datos financieros se guardan CIFRADOS (AES-256-GCM) por el navegador.
--    La base de datos nunca recibe la "clave del hogar" ni los datos en claro.
--  * Ninguna tabla es accesible directamente desde internet: RLS activo,
--    sin políticas y sin permisos para los roles anon/authenticated.
--  * Todo acceso pasa por funciones que verifican: sesión iniciada,
--    verificación en dos pasos (aal2) y pertenencia al hogar.
--  * Solo puede existir UN hogar: el primer usuario lo crea y queda como
--    dueño; los demás solo entran con un código de invitación de un solo uso.
-- =====================================================================

create schema if not exists app_private;
revoke all on schema app_private from public;
do $$ begin
  execute 'revoke all on schema app_private from anon, authenticated';
exception when undefined_object then null; end $$;

-- ---------------------------------------------------------------------
-- Tablas
-- ---------------------------------------------------------------------
create table if not exists public.households (
  id              uuid primary key default gen_random_uuid(),
  name            text not null check (char_length(name) between 1 and 80),
  kdf_salt        text not null check (kdf_salt ~ '^[A-Za-z0-9+/=]{16,64}$'),
  kdf_iterations  integer not null check (kdf_iterations between 310000 and 5000000),
  key_check       text not null check (char_length(key_check) between 20 and 400),
  created_by      uuid references auth.users(id) on delete set null,
  created_at      timestamptz not null default now()
);

create table if not exists public.household_members (
  household_id  uuid not null references public.households(id) on delete cascade,
  user_id       uuid not null references auth.users(id) on delete cascade,
  role          text not null check (role in ('owner', 'member')),
  joined_at     timestamptz not null default now(),
  primary key (household_id, user_id),
  unique (user_id)
);

create table if not exists public.household_state (
  household_id  uuid primary key references public.households(id) on delete cascade,
  version       bigint not null default 1,
  iv            text not null check (iv ~ '^[A-Za-z0-9+/=]{16,24}$'),
  ciphertext    text not null check (char_length(ciphertext) <= 20000000),
  updated_at    timestamptz not null default now(),
  updated_by    uuid references auth.users(id) on delete set null
);

create table if not exists public.invites (
  code_hash     text primary key,
  household_id  uuid not null references public.households(id) on delete cascade,
  created_by    uuid references auth.users(id) on delete set null,
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  used_by       uuid references auth.users(id) on delete set null,
  used_at       timestamptz
);

create table if not exists public.activity_log (
  id            bigint generated always as identity primary key,
  household_id  uuid not null references public.households(id) on delete cascade,
  user_id       uuid references auth.users(id) on delete set null,
  action        text not null check (char_length(action) <= 40),
  at            timestamptz not null default now()
);
create index if not exists activity_log_household_at on public.activity_log (household_id, at desc);

create table if not exists app_private.invite_failures (
  user_id  uuid not null,
  at       timestamptz not null default now()
);
create index if not exists invite_failures_user_at on app_private.invite_failures (user_id, at desc);

-- RLS activo y SIN políticas = acceso directo denegado a todos los clientes.
alter table public.households        enable row level security;
alter table public.household_members enable row level security;
alter table public.household_state   enable row level security;
alter table public.invites           enable row level security;
alter table public.activity_log      enable row level security;

revoke all on public.households, public.household_members, public.household_state,
              public.invites, public.activity_log from public;
do $$ begin
  execute 'revoke all on public.households, public.household_members, public.household_state, public.invites, public.activity_log from anon, authenticated';
  execute 'revoke all on sequence public.activity_log_id_seq from anon, authenticated';
exception when undefined_object then null; end $$;

-- ---------------------------------------------------------------------
-- Funciones internas (no expuestas a internet)
-- ---------------------------------------------------------------------
create or replace function app_private.require_user()
returns uuid language plpgsql stable security definer set search_path = '' as $$
declare v_uid uuid := auth.uid();
begin
  if v_uid is null then
    raise exception 'not_authenticated' using errcode = '28000';
  end if;
  if coalesce(auth.jwt() ->> 'aal', '') <> 'aal2' then
    raise exception 'mfa_required' using errcode = '28000';
  end if;
  return v_uid;
end $$;

create or replace function app_private.membership(p_uid uuid, out household_id uuid, out role text)
language sql stable security definer set search_path = '' as $$
  select m.household_id, m.role from public.household_members m where m.user_id = p_uid;
$$;

create or replace function app_private.require_member(out uid uuid, out household_id uuid, out role text)
language plpgsql stable security definer set search_path = '' as $$
begin
  uid := app_private.require_user();
  select m.household_id, m.role into household_id, role from app_private.membership(uid) m;
  if household_id is null then
    raise exception 'not_a_member' using errcode = '42501';
  end if;
end $$;

create or replace function app_private.code_hash(p_code text)
returns text language sql immutable set search_path = '' as $$
  select encode(sha256(convert_to(upper(regexp_replace(coalesce(p_code, ''), '[^A-Za-z0-9]', '', 'g')), 'UTF8')), 'hex');
$$;

create or replace function app_private.log(p_household uuid, p_uid uuid, p_action text)
returns void language sql security definer set search_path = '' as $$
  insert into public.activity_log (household_id, user_id, action) values (p_household, p_uid, p_action);
$$;

revoke all on all functions in schema app_private from public;

-- ---------------------------------------------------------------------
-- Funciones públicas (API). Todas verifican sesión + aal2 + hogar.
-- ---------------------------------------------------------------------

-- Estado de la cuenta: hogar, rol y si todavía se puede crear el hogar.
create or replace function public.get_my_household()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v_uid uuid := app_private.require_user(); v_hh public.households; v_role text;
begin
  select m.role into v_role from public.household_members m where m.user_id = v_uid;
  if v_role is null then
    return jsonb_build_object('household', null, 'can_create', not exists (select 1 from public.households));
  end if;
  select h.* into v_hh from public.households h join public.household_members m on m.household_id = h.id where m.user_id = v_uid;
  return jsonb_build_object(
    'household', jsonb_build_object('id', v_hh.id, 'name', v_hh.name, 'kdf_salt', v_hh.kdf_salt,
                                    'kdf_iterations', v_hh.kdf_iterations, 'key_check', v_hh.key_check),
    'role', v_role, 'can_create', false);
end $$;

-- Crea el único hogar permitido. Quien lo crea queda como dueño.
create or replace function public.create_household(p_name text, p_kdf_salt text, p_kdf_iterations integer,
                                                   p_key_check text, p_iv text, p_ciphertext text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_uid uuid := app_private.require_user(); v_id uuid;
begin
  perform pg_advisory_xact_lock(hashtext('libertad_financiera_create_household'));
  if exists (select 1 from public.households) then
    raise exception 'household_exists' using errcode = '42501';
  end if;
  insert into public.households (name, kdf_salt, kdf_iterations, key_check, created_by)
    values (trim(p_name), p_kdf_salt, p_kdf_iterations, p_key_check, v_uid) returning id into v_id;
  insert into public.household_members (household_id, user_id, role) values (v_id, v_uid, 'owner');
  insert into public.household_state (household_id, version, iv, ciphertext, updated_by)
    values (v_id, 1, p_iv, p_ciphertext, v_uid);
  perform app_private.log(v_id, v_uid, 'crear_hogar');
  return jsonb_build_object('id', v_id, 'version', 1);
end $$;

-- El dueño genera un código de invitación de un solo uso (válido 1 a 168 horas).
create or replace function public.create_invite(p_hours integer default 72)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v record; v_code text; v_exp timestamptz;
begin
  select * into v from app_private.require_member();
  if v.role <> 'owner' then raise exception 'owner_only' using errcode = '42501'; end if;
  if (select count(*) from public.invites i where i.household_id = v.household_id and i.used_at is null and i.expires_at > now()) >= 5 then
    raise exception 'too_many_invites' using errcode = '54000';
  end if;
  v_code := upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8) || substr(replace(gen_random_uuid()::text, '-', ''), 1, 8));
  v_exp := now() + make_interval(hours => greatest(1, least(coalesce(p_hours, 72), 168)));
  insert into public.invites (code_hash, household_id, created_by, expires_at)
    values (app_private.code_hash(v_code), v.household_id, v.uid, v_exp);
  perform app_private.log(v.household_id, v.uid, 'crear_invitacion');
  return jsonb_build_object('code', substr(v_code, 1, 4) || '-' || substr(v_code, 5, 4) || '-' || substr(v_code, 9, 4) || '-' || substr(v_code, 13, 4),
                            'expires_at', v_exp);
end $$;

-- Un usuario nuevo se une al hogar con el código recibido.
create or replace function public.accept_invite(p_code text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v_uid uuid := app_private.require_user(); v_inv public.invites;
begin
  if exists (select 1 from public.household_members m where m.user_id = v_uid) then
    return jsonb_build_object('ok', false, 'error', 'already_member');
  end if;
  if (select count(*) from app_private.invite_failures f where f.user_id = v_uid and f.at > now() - interval '1 hour') >= 10 then
    return jsonb_build_object('ok', false, 'error', 'too_many_attempts');
  end if;
  select * into v_inv from public.invites i
   where i.code_hash = app_private.code_hash(p_code) and i.used_at is null and i.expires_at > now()
   for update;
  if v_inv.code_hash is null then
    insert into app_private.invite_failures (user_id) values (v_uid);
    return jsonb_build_object('ok', false, 'error', 'invalid_code');
  end if;
  insert into public.household_members (household_id, user_id, role) values (v_inv.household_id, v_uid, 'member');
  update public.invites set used_by = v_uid, used_at = now() where code_hash = v_inv.code_hash;
  perform app_private.log(v_inv.household_id, v_uid, 'unirse');
  return jsonb_build_object('ok', true);
end $$;

-- Miembros del hogar (correo, rol, último ingreso, si tienen verificación en dos pasos).
create or replace function public.list_members()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'user_id', m.user_id, 'email', u.email, 'role', m.role, 'joined_at', m.joined_at,
      'last_sign_in_at', u.last_sign_in_at, 'me', m.user_id = v.uid,
      'mfa', exists (select 1 from auth.mfa_factors f where f.user_id = m.user_id and f.status = 'verified'))
      order by m.role desc, m.joined_at)
    from public.household_members m join auth.users u on u.id = m.user_id
    where m.household_id = v.household_id), '[]'::jsonb);
end $$;

-- Invitaciones vigentes (sin los códigos, que solo se muestran al crearlas).
create or replace function public.list_invites()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  if v.role <> 'owner' then raise exception 'owner_only' using errcode = '42501'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('created_at', i.created_at, 'expires_at', i.expires_at) order by i.created_at desc)
    from public.invites i where i.household_id = v.household_id and i.used_at is null and i.expires_at > now()), '[]'::jsonb);
end $$;

-- Anula todas las invitaciones pendientes.
create or replace function public.revoke_invites()
returns integer language plpgsql security definer set search_path = '' as $$
declare v record; n integer;
begin
  select * into v from app_private.require_member();
  if v.role <> 'owner' then raise exception 'owner_only' using errcode = '42501'; end if;
  delete from public.invites i where i.household_id = v.household_id and i.used_at is null;
  get diagnostics n = row_count;
  perform app_private.log(v.household_id, v.uid, 'anular_invitaciones');
  return n;
end $$;

-- El dueño retira a un miembro del hogar.
create or replace function public.remove_member(p_user_id uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v record; n integer;
begin
  select * into v from app_private.require_member();
  if v.role <> 'owner' then raise exception 'owner_only' using errcode = '42501'; end if;
  if p_user_id = v.uid then raise exception 'cannot_remove_owner' using errcode = '42501'; end if;
  delete from public.household_members m where m.household_id = v.household_id and m.user_id = p_user_id;
  get diagnostics n = row_count;
  if n > 0 then perform app_private.log(v.household_id, v.uid, 'retirar_miembro'); end if;
  return jsonb_build_object('removed', n > 0);
end $$;

-- Datos cifrados del hogar.
create or replace function public.get_state()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  return (select jsonb_build_object('version', s.version, 'iv', s.iv, 'ciphertext', s.ciphertext,
                                    'updated_at', s.updated_at, 'updated_by', u.email)
          from public.household_state s left join auth.users u on u.id = s.updated_by
          where s.household_id = v.household_id);
end $$;

-- Versión actual (para detectar cambios hechos desde otro dispositivo).
create or replace function public.get_state_version()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  return (select jsonb_build_object('version', s.version, 'updated_at', s.updated_at, 'updated_by', u.email,
                                    'updated_by_me', s.updated_by = v.uid)
          from public.household_state s left join auth.users u on u.id = s.updated_by
          where s.household_id = v.household_id);
end $$;

-- Guarda solo si nadie más guardó mientras tanto (control de versión).
create or replace function public.save_state(p_expected_version bigint, p_iv text, p_ciphertext text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v record; v_new bigint; v_cur bigint;
begin
  select * into v from app_private.require_member();
  update public.household_state s
     set version = s.version + 1, iv = p_iv, ciphertext = p_ciphertext, updated_at = now(), updated_by = v.uid
   where s.household_id = v.household_id and s.version = p_expected_version
   returning s.version into v_new;
  if v_new is null then
    select s.version into v_cur from public.household_state s where s.household_id = v.household_id;
    return jsonb_build_object('ok', false, 'error', 'conflict', 'version', v_cur);
  end if;
  if not exists (select 1 from public.activity_log a where a.household_id = v.household_id and a.user_id = v.uid
                   and a.action = 'guardar' and a.at > now() - interval '30 minutes') then
    perform app_private.log(v.household_id, v.uid, 'guardar');
  end if;
  return jsonb_build_object('ok', true, 'version', v_new);
end $$;

-- El dueño cambia la clave del hogar: se guarda todo re-cifrado con la nueva clave.
create or replace function public.rotate_key(p_kdf_salt text, p_kdf_iterations integer, p_key_check text,
                                             p_expected_version bigint, p_iv text, p_ciphertext text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v record; v_new bigint;
begin
  select * into v from app_private.require_member();
  if v.role <> 'owner' then raise exception 'owner_only' using errcode = '42501'; end if;
  update public.household_state s
     set version = s.version + 1, iv = p_iv, ciphertext = p_ciphertext, updated_at = now(), updated_by = v.uid
   where s.household_id = v.household_id and s.version = p_expected_version
   returning s.version into v_new;
  if v_new is null then
    return jsonb_build_object('ok', false, 'error', 'conflict');
  end if;
  update public.households h set kdf_salt = p_kdf_salt, kdf_iterations = p_kdf_iterations, key_check = p_key_check
   where h.id = v.household_id;
  perform app_private.log(v.household_id, v.uid, 'cambiar_clave_hogar');
  return jsonb_build_object('ok', true, 'version', v_new);
end $$;

-- Registro de eventos (solo acciones conocidas).
create or replace function public.log_event(p_action text)
returns void language plpgsql security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  if p_action not in ('ingreso', 'salida', 'respaldo', 'importar', 'cerrar_mes', 'restaurar', 'procesar_correo') then
    raise exception 'invalid_action' using errcode = '22023';
  end if;
  perform app_private.log(v.household_id, v.uid, p_action);
end $$;

create or replace function public.list_activity(p_limit integer default 50)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  return coalesce((select jsonb_agg(x) from (
    select jsonb_build_object('at', a.at, 'action', a.action, 'email', u.email) as x
      from public.activity_log a left join auth.users u on u.id = a.user_id
     where a.household_id = v.household_id
     order by a.at desc limit greatest(1, least(coalesce(p_limit, 50), 200))) t), '[]'::jsonb);
end $$;

-- Señal de vida para evitar que el proyecto gratuito se pause por inactividad
-- (escribe una fila para que cuente como uso real de la base de datos).
create table if not exists app_private.heartbeat (id integer primary key, at timestamptz not null);
drop function if exists public.ping();
create or replace function public.ping()
returns text language plpgsql volatile security definer set search_path = '' as $$
begin
  insert into app_private.heartbeat (id, at) values (1, now()) on conflict (id) do update set at = excluded.at;
  return 'ok';
end $$;

-- =====================================================================
-- Automatización por correo (Gmail → app)
--  * La app genera un par de claves: la PÚBLICA se guarda aquí; la PRIVADA
--    solo existe dentro de los datos cifrados del hogar.
--  * El programa de Gmail cifra cada aviso bancario con la clave pública y lo
--    deja en la bandeja "inbox" usando un TOKEN de solo escritura.
--  * Con el token se puede escribir, pero nunca leer: ni el servidor ni quien
--    robe el token puede descifrar lo que hay en la bandeja.
-- =====================================================================
alter table public.households add column if not exists inbox_pk text check (inbox_pk is null or inbox_pk ~ '^[A-Za-z0-9+/]{43}=$');
alter table public.households add column if not exists summary_ct text check (summary_ct is null or char_length(summary_ct) <= 200000);
alter table public.households add column if not exists summary_at timestamptz;

create table if not exists public.ingest_tokens (
  id            uuid primary key default gen_random_uuid(),
  household_id  uuid not null references public.households(id) on delete cascade,
  label         text not null check (char_length(label) between 1 and 60),
  token_hash    text not null unique,
  created_by    uuid references auth.users(id) on delete set null,
  created_at    timestamptz not null default now(),
  last_used_at  timestamptz,
  last_error    text,
  revoked_at    timestamptz,
  day           date not null default current_date,
  day_items     integer not null default 0,
  day_bytes     bigint not null default 0
);
create table if not exists public.inbox (
  id            bigint generated always as identity primary key,
  household_id  uuid not null references public.households(id) on delete cascade,
  token_id      uuid references public.ingest_tokens(id) on delete set null,
  ext           text not null check (ext ~ '^[0-9a-f]{64}$'),
  kind          text not null check (kind in ('mail', 'pdf')),
  ct            text not null check (char_length(ct) <= 6000000),
  created_at    timestamptz not null default now(),
  unique (household_id, ext)
);
create index if not exists inbox_household_id on public.inbox (household_id, id);
create table if not exists app_private.inbox_seen (
  household_id uuid not null, ext text not null, at timestamptz not null default now(), primary key (household_id, ext)
);
alter table public.ingest_tokens enable row level security;
alter table public.inbox enable row level security;
revoke all on public.ingest_tokens, public.inbox from public;
do $$ begin
  execute 'revoke all on public.ingest_tokens, public.inbox from anon, authenticated';
  execute 'revoke all on sequence public.inbox_id_seq from anon, authenticated';
exception when undefined_object then null; end $$;

-- El dueño activa la automatización publicando la clave pública del hogar.
create or replace function public.set_inbox_key(p_pk text, p_force boolean default false)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v record; v_old text;
begin
  select * into v from app_private.require_member();
  if v.role <> 'owner' then raise exception 'owner_only' using errcode = '42501'; end if;
  select h.inbox_pk into v_old from public.households h where h.id = v.household_id;
  if v_old is not null and v_old <> p_pk and not coalesce(p_force, false)
     and exists (select 1 from public.inbox i where i.household_id = v.household_id) then
    raise exception 'inbox_not_empty' using errcode = '55000';
  end if;
  update public.households h set inbox_pk = p_pk where h.id = v.household_id;
  perform app_private.log(v.household_id, v.uid, 'activar_correo');
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.get_inbox_key()
returns text language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  return (select h.inbox_pk from public.households h where h.id = v.household_id);
end $$;

-- Crea un token de solo escritura para un buzón de Gmail (se muestra una sola vez).
create or replace function public.create_ingest_token(p_label text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v record; v_token text; v_id uuid;
begin
  select * into v from app_private.require_member();
  if v.role <> 'owner' then raise exception 'owner_only' using errcode = '42501'; end if;
  if (select inbox_pk from public.households where id = v.household_id) is null then raise exception 'inbox_not_enabled' using errcode = '55000'; end if;
  if (select count(*) from public.ingest_tokens t where t.household_id = v.household_id and t.revoked_at is null) >= 5 then
    raise exception 'too_many_tokens' using errcode = '54000';
  end if;
  v_token := 'lft_' || replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', '');
  insert into public.ingest_tokens (household_id, label, token_hash, created_by)
    values (v.household_id, trim(p_label), app_private.code_hash(v_token), v.uid) returning id into v_id;
  perform app_private.log(v.household_id, v.uid, 'crear_token_correo');
  return jsonb_build_object('id', v_id, 'token', v_token);
end $$;

create or replace function public.list_ingest_tokens()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  return coalesce((select jsonb_agg(jsonb_build_object('id', t.id, 'label', t.label, 'created_at', t.created_at, 'last_used_at', t.last_used_at,
      'last_error', t.last_error, 'revoked', t.revoked_at is not null) order by t.created_at)
    from public.ingest_tokens t where t.household_id = v.household_id), '[]'::jsonb);
end $$;

create or replace function public.revoke_ingest_token(p_id uuid)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare v record; n integer;
begin
  select * into v from app_private.require_member();
  if v.role <> 'owner' then raise exception 'owner_only' using errcode = '42501'; end if;
  update public.ingest_tokens t set revoked_at = now() where t.id = p_id and t.household_id = v.household_id and t.revoked_at is null;
  get diagnostics n = row_count;
  if n > 0 then perform app_private.log(v.household_id, v.uid, 'anular_token_correo'); end if;
  return jsonb_build_object('revoked', n > 0);
end $$;

-- Lo que llegó desde Gmail (cifrado). Solo miembros del hogar.
create or replace function public.inbox_list(p_after bigint default 0, p_limit integer default 40)
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  return coalesce((select jsonb_agg(x) from (
    select jsonb_build_object('id', i.id, 'ext', i.ext, 'kind', i.kind, 'ct', i.ct, 'at', i.created_at, 'label', t.label) as x
      from public.inbox i left join public.ingest_tokens t on t.id = i.token_id
     where i.household_id = v.household_id and i.id > coalesce(p_after, 0)
     order by i.id limit greatest(1, least(coalesce(p_limit, 40), 100))) q), '[]'::jsonb);
end $$;

create or replace function public.inbox_count()
returns jsonb language plpgsql stable security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  return jsonb_build_object('count', (select count(*) from public.inbox i where i.household_id = v.household_id),
                            'enabled', (select h.inbox_pk is not null from public.households h where h.id = v.household_id));
end $$;

-- Borra de la bandeja lo que ya quedó guardado (cifrado) en los datos del hogar.
create or replace function public.inbox_ack(p_ids bigint[])
returns integer language plpgsql security definer set search_path = '' as $$
declare v record; n integer;
begin
  select * into v from app_private.require_member();
  insert into app_private.inbox_seen (household_id, ext)
    select i.household_id, i.ext from public.inbox i where i.household_id = v.household_id and i.id = any(p_ids)
    on conflict do nothing;
  delete from public.inbox i where i.household_id = v.household_id and i.id = any(p_ids);
  get diagnostics n = row_count;
  delete from app_private.inbox_seen s where s.household_id = v.household_id and s.at < now() - interval '400 days';
  return n;
end $$;

-- Resumen cifrado para el correo semanal (lo escribe la app; lo lee el programa de Gmail).
create or replace function public.save_summary(p_ct text)
returns void language plpgsql security definer set search_path = '' as $$
declare v record;
begin
  select * into v from app_private.require_member();
  update public.households h set summary_ct = p_ct, summary_at = now() where h.id = v.household_id;
end $$;

-- ---- Llamadas del programa de Gmail (rol anónimo + token) ----
create or replace function app_private.token_household(p_token text)
returns public.ingest_tokens language plpgsql security definer set search_path = '' as $$
declare t public.ingest_tokens;
begin
  if p_token is null or p_token !~ '^lft_[0-9a-f]{64}$' then raise exception 'invalid_token' using errcode = '28000'; end if;
  select * into t from public.ingest_tokens x where x.token_hash = app_private.code_hash(p_token) and x.revoked_at is null for update;
  if t.id is null then raise exception 'invalid_token' using errcode = '28000'; end if;
  return t;
end $$;
revoke all on function app_private.token_household(text) from public;

create or replace function public.ingest_push(p_token text, p_items jsonb)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare t public.ingest_tokens; it jsonb; n_new integer := 0; n_dup integer := 0; v_bytes bigint := 0; v_n integer; v_pending integer;
begin
  t := app_private.token_household(p_token);
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) < 1 or jsonb_array_length(p_items) > 50 then
    raise exception 'invalid_items' using errcode = '22023';
  end if;
  if t.day <> current_date then
    update public.ingest_tokens set day = current_date, day_items = 0, day_bytes = 0 where id = t.id;
    t.day_items := 0; t.day_bytes := 0;
  end if;
  select count(*) into v_pending from public.inbox i where i.household_id = t.household_id;
  for it in select * from jsonb_array_elements(p_items) loop
    if (it ->> 'ext') !~ '^[0-9a-f]{64}$' or (it ->> 'kind') not in ('mail', 'pdf') or (it ->> 'ct') is null
       or (it ->> 'ct') !~ '^[A-Za-z0-9+/]+=*$' or char_length(it ->> 'ct') > 6000000 then
      raise exception 'invalid_item' using errcode = '22023';
    end if;
    v_bytes := v_bytes + char_length(it ->> 'ct');
  end loop;
  if t.day_items + jsonb_array_length(p_items) > 1500 or t.day_bytes + v_bytes > 60000000 or v_pending + jsonb_array_length(p_items) > 3000 then
    update public.ingest_tokens set last_error = 'limite_diario' where id = t.id;
    raise exception 'rate_limited' using errcode = '54000';
  end if;
  for it in select * from jsonb_array_elements(p_items) loop
    if exists (select 1 from app_private.inbox_seen s where s.household_id = t.household_id and s.ext = it ->> 'ext') then
      n_dup := n_dup + 1; continue;
    end if;
    insert into public.inbox (household_id, token_id, ext, kind, ct)
      values (t.household_id, t.id, it ->> 'ext', it ->> 'kind', it ->> 'ct')
      on conflict (household_id, ext) do nothing;
    get diagnostics v_n = row_count;
    if v_n > 0 then n_new := n_new + 1; else n_dup := n_dup + 1; end if;
  end loop;
  update public.ingest_tokens set last_used_at = now(), last_error = null, day_items = day_items + jsonb_array_length(p_items), day_bytes = day_bytes + v_bytes where id = t.id;
  return jsonb_build_object('inserted', n_new, 'duplicates', n_dup);
end $$;

-- El programa de Gmail comprueba su token y lee el resumen cifrado para el correo semanal.
create or replace function public.ingest_status(p_token text)
returns jsonb language plpgsql security definer set search_path = '' as $$
declare t public.ingest_tokens; h public.households;
begin
  t := app_private.token_household(p_token);
  select * into h from public.households x where x.id = t.household_id;
  update public.ingest_tokens set last_used_at = now() where id = t.id;
  return jsonb_build_object('label', t.label, 'pk', h.inbox_pk, 'summary', h.summary_ct, 'summary_at', h.summary_at,
                            'pending', (select count(*) from public.inbox i where i.household_id = t.household_id));
end $$;

create or replace function public.ingest_report(p_token text, p_error text)
returns void language plpgsql security definer set search_path = '' as $$
declare t public.ingest_tokens;
begin
  t := app_private.token_household(p_token);
  update public.ingest_tokens set last_error = left(p_error, 300), last_used_at = now() where id = t.id;
end $$;

-- ---------------------------------------------------------------------
-- Permisos de ejecución: nada para el público; solo lo necesario.
-- ---------------------------------------------------------------------
revoke all on function public.get_my_household(), public.create_household(text, text, integer, text, text, text), public.create_invite(integer), public.accept_invite(text), public.list_members(), public.list_invites(), public.revoke_invites(), public.remove_member(uuid), public.get_state(), public.get_state_version(), public.save_state(bigint, text, text), public.rotate_key(text, integer, text, bigint, text, text), public.log_event(text), public.list_activity(integer), public.set_inbox_key(text, boolean), public.get_inbox_key(), public.create_ingest_token(text), public.list_ingest_tokens(), public.revoke_ingest_token(uuid), public.inbox_list(bigint, integer), public.inbox_count(), public.inbox_ack(bigint[]), public.save_summary(text),
  public.ping(), public.ingest_push(text, jsonb), public.ingest_status(text), public.ingest_report(text, text) from public;
do $$ begin
  execute 'revoke all on all functions in schema app_private from anon, authenticated';
  execute 'revoke all on function public.get_my_household(), public.create_household(text, text, integer, text, text, text), public.create_invite(integer), public.accept_invite(text), public.list_members(), public.list_invites(), public.revoke_invites(), public.remove_member(uuid), public.get_state(), public.get_state_version(), public.save_state(bigint, text, text), public.rotate_key(text, integer, text, bigint, text, text), public.log_event(text), public.list_activity(integer), public.set_inbox_key(text, boolean), public.get_inbox_key(), public.create_ingest_token(text), public.list_ingest_tokens(), public.revoke_ingest_token(uuid), public.inbox_list(bigint, integer), public.inbox_count(), public.inbox_ack(bigint[]), public.save_summary(text) from anon';
  execute 'grant execute on function public.get_my_household(), public.create_household(text, text, integer, text, text, text), public.create_invite(integer), public.accept_invite(text), public.list_members(), public.list_invites(), public.revoke_invites(), public.remove_member(uuid), public.get_state(), public.get_state_version(), public.save_state(bigint, text, text), public.rotate_key(text, integer, text, bigint, text, text), public.log_event(text), public.list_activity(integer), public.set_inbox_key(text, boolean), public.get_inbox_key(), public.create_ingest_token(text), public.list_ingest_tokens(), public.revoke_ingest_token(uuid), public.inbox_list(bigint, integer), public.inbox_count(), public.inbox_ack(bigint[]), public.save_summary(text) to authenticated';
  execute 'grant execute on function public.ping(), public.ingest_push(text, jsonb), public.ingest_status(text), public.ingest_report(text, text) to anon, authenticated';
end $$;

-- Las funciones nuevas que alguien cree después no quedan expuestas por defecto.
alter default privileges in schema public revoke execute on functions from public;
do $$ begin
  execute 'alter default privileges in schema public revoke execute on functions from anon, authenticated';
exception when undefined_object then null; end $$;
