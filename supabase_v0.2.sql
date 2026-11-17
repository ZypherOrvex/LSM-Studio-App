-- =====================================================================
-- LSM Studio v0.2 - Cuentas, espacios, roles y permisos
-- Pega TODO este archivo en Supabase -> SQL Editor -> Run.
-- Se puede ejecutar más de una vez sin problema.
-- =====================================================================
create extension if not exists pgcrypto;

-- ---------- TABLAS ----------
create table if not exists profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default 'Usuario',
  avatar text,
  color text not null default '#8F7BFF',
  created_at timestamptz not null default now()
);

create table if not exists spaces(
  id uuid primary key default gen_random_uuid(),
  name text not null,
  icon text not null default '🏠',
  color text not null default '#8F7BFF',
  description text not null default '',
  owner_id uuid not null references profiles(id),
  tags jsonb not null default '[]',
  groups jsonb not null default '[]',
  kits jsonb not null default '[]',
  created_at timestamptz not null default now()
);

create table if not exists roles(
  id uuid primary key default gen_random_uuid(),
  space_id uuid not null references spaces(id) on delete cascade,
  name text not null,
  color text not null default '#9AA3B2',
  position int not null default 0,
  is_admin boolean not null default false,
  is_base boolean not null default false,
  perms jsonb not null default '{}'
);

create table if not exists members(
  space_id uuid not null references spaces(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  role_id uuid references roles(id) on delete set null,
  joined_at timestamptz not null default now(),
  primary key(space_id,user_id)
);

create table if not exists nodes(
  id uuid primary key,
  space_id uuid not null references spaces(id) on delete cascade,
  parent_id uuid references nodes(id) on delete cascade,
  type text not null check(type in ('folder','file')),
  name text not null,
  icon text not null default '📁',
  color text not null default '#9AA3B2',
  kit_id text,
  vis text not null default 'inherit' check(vis in ('inherit','public','semi','private')),
  tags jsonb not null default '[]',
  blocks jsonb not null default '[]',
  view_mode text not null default 'list',
  settings jsonb not null default '{}',
  created_by uuid references profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz
);
create index if not exists nodes_space_idx on nodes(space_id);
create index if not exists nodes_parent_idx on nodes(parent_id);
create index if not exists nodes_upd_idx on nodes(space_id,updated_at);

create table if not exists node_perms(
  id uuid primary key default gen_random_uuid(),
  space_id uuid not null,
  node_id uuid not null references nodes(id) on delete cascade,
  subject_type text not null check(subject_type in ('role','user')),
  subject_id text not null,
  perm text not null check(perm in ('view','comment','create','edit','move','delete','upload','download','manage_perms','approve')),
  effect text not null check(effect in ('allow','deny')),
  unique(node_id,subject_type,subject_id,perm)
);
create index if not exists node_perms_space_idx on node_perms(space_id);

create table if not exists invites(
  code text primary key,
  space_id uuid not null references spaces(id) on delete cascade,
  role_id uuid references roles(id) on delete set null,
  expires_at timestamptz,
  max_uses int,
  uses int not null default 0,
  created_by uuid references profiles(id),
  created_at timestamptz not null default now()
);

create table if not exists requests(
  id uuid primary key default gen_random_uuid(),
  space_id uuid not null references spaces(id) on delete cascade,
  node_id uuid references nodes(id) on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade,
  message text not null default '',
  status text not null default 'pending' check(status in ('pending','approved','rejected')),
  resolved_by uuid references profiles(id),
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);
create unique index if not exists requests_one_pending on requests(node_id,user_id) where status='pending';

create table if not exists log(
  id bigint generated always as identity primary key,
  space_id uuid not null references spaces(id) on delete cascade,
  node_id uuid,
  user_id uuid references profiles(id),
  action text not null,
  detail text not null default '',
  created_at timestamptz not null default now()
);
create index if not exists log_space_idx on log(space_id,created_at desc);
create index if not exists log_node_idx on log(node_id,created_at desc);

-- ---------- FUNCIONES DE PERMISOS ----------
create or replace function node_space(nid uuid) returns uuid
language sql stable security definer set search_path=public as $$
  select space_id from nodes where id = nid $$;

create or replace function is_member(sid uuid) returns boolean
language sql stable security definer set search_path=public as $$
  select exists(select 1 from members where space_id = sid and user_id = auth.uid()) $$;

create or replace function is_owner(sid uuid) returns boolean
language sql stable security definer set search_path=public as $$
  select exists(select 1 from spaces where id = sid and owner_id = auth.uid()) $$;

create or replace function is_admin(sid uuid) returns boolean
language sql stable security definer set search_path=public as $$
  select is_member(sid) and (
    is_owner(sid) or exists(
      select 1 from members m join roles r on r.id = m.role_id
      where m.space_id = sid and m.user_id = auth.uid() and r.is_admin)) $$;

-- permiso por rol (el rol de la persona + el rol base "Todos")
create or replace function role_perm(sid uuid, p text) returns boolean
language sql stable security definer set search_path=public as $$
  select is_member(sid) and (
    exists(select 1 from members m join roles r on r.id = m.role_id
           where m.space_id = sid and m.user_id = auth.uid()
             and coalesce((r.perms->>p)::boolean,false))
    or exists(select 1 from roles r where r.space_id = sid and r.is_base
              and coalesce((r.perms->>p)::boolean,false))) $$;

create or replace function space_perm(sid uuid, p text) returns boolean
language sql stable security definer set search_path=public as $$
  select is_admin(sid) or role_perm(sid,p) $$;

-- visibilidad efectiva (sube por las carpetas hasta encontrar una que no herede)
create or replace function eff_vis(nid uuid) returns text
language plpgsql stable security definer set search_path=public as $$
declare cur uuid := nid; v_vis text; v_par uuid; i int := 0;
begin
  loop
    select n.vis, n.parent_id into v_vis, v_par from nodes n where n.id = cur;
    if not found then return 'semi'; end if;
    if v_vis <> 'inherit' then return v_vis; end if;
    if v_par is null then return 'semi'; end if;
    cur := v_par; i := i + 1;
    if i > 60 then return 'semi'; end if;
  end loop;
end $$;

-- permiso explícito: true (permitir), false (denegar) o null (heredar)
-- gana lo más cercano; la persona gana sobre el rol; denegar gana sobre permitir
create or replace function explicit_perm(nid uuid, p text) returns boolean
language plpgsql stable security definer set search_path=public as $$
declare cur uuid := nid; v_sid uuid; v_rid uuid; v_brid uuid; v_eff text; v_par uuid;
        v_uid uuid := auth.uid(); i int := 0;
begin
  select n.space_id into v_sid from nodes n where n.id = nid;
  if v_sid is null then return null; end if;
  select m.role_id into v_rid from members m where m.space_id = v_sid and m.user_id = v_uid;
  select r.id into v_brid from roles r where r.space_id = v_sid and r.is_base limit 1;
  loop
    select np.effect into v_eff from node_perms np
      where np.node_id = cur and np.subject_type = 'user'
        and np.subject_id = v_uid::text and np.perm = p;
    if v_eff is not null then return v_eff = 'allow'; end if;
    if exists(select 1 from node_perms np where np.node_id = cur and np.subject_type = 'role'
        and np.subject_id in (coalesce(v_rid::text,''), coalesce(v_brid::text,''))
        and np.perm = p and np.effect = 'deny') then return false; end if;
    if exists(select 1 from node_perms np where np.node_id = cur and np.subject_type = 'role'
        and np.subject_id in (coalesce(v_rid::text,''), coalesce(v_brid::text,''))
        and np.perm = p and np.effect = 'allow') then return true; end if;
    select n.parent_id into v_par from nodes n where n.id = cur;
    if v_par is null then exit; end if;
    cur := v_par; i := i + 1;
    if i > 60 then exit; end if;
  end loop;
  return null;
end $$;

-- ver ESTE nodo (sin mirar a sus padres)
create or replace function view_one(nid uuid) returns boolean
language plpgsql stable security definer set search_path=public as $$
declare v_sid uuid; v_cb uuid; v_e boolean;
begin
  select n.space_id, n.created_by into v_sid, v_cb from nodes n where n.id = nid;
  if v_sid is null then return false; end if;
  if not is_member(v_sid) then return false; end if;
  if is_admin(v_sid) or v_cb = auth.uid() then return true; end if;
  v_e := explicit_perm(nid,'view');
  if v_e is not null then return v_e; end if;
  if eff_vis(nid) = 'public' then return role_perm(v_sid,'view'); end if;
  return false;
end $$;

-- ver el contenido: hay que poder ver el nodo y todas las carpetas de arriba
create or replace function can_view(nid uuid) returns boolean
language plpgsql stable security definer set search_path=public as $$
declare cur uuid := nid; v_par uuid; i int := 0;
begin
  loop
    if not view_one(cur) then return false; end if;
    select n.parent_id into v_par from nodes n where n.id = cur;
    if v_par is null then return true; end if;
    cur := v_par; i := i + 1;
    if i > 60 then return false; end if;
  end loop;
end $$;

-- saber que existe (nombre, ícono): público y semi público se ven; privado no
create or replace function can_see_exists(nid uuid) returns boolean
language plpgsql stable security definer set search_path=public as $$
declare v_sid uuid; v_cb uuid; v_par uuid; v_e boolean;
begin
  select n.space_id, n.created_by, n.parent_id into v_sid, v_cb, v_par from nodes n where n.id = nid;
  if v_sid is null or not is_member(v_sid) then return false; end if;
  if is_admin(v_sid) then return true; end if;
  if v_par is not null and not can_view(v_par) then return false; end if;
  if v_cb = auth.uid() then return true; end if;
  v_e := explicit_perm(nid,'view');
  if v_e is true then return true; end if;
  if v_e is false then return false; end if;
  return eff_vis(nid) in ('public','semi');
end $$;

-- hacer algo en un nodo (editar, mover, borrar, subir...)
create or replace function has_perm(nid uuid, p text) returns boolean
language plpgsql stable security definer set search_path=public as $$
declare v_sid uuid; v_cb uuid; v_e boolean;
begin
  select n.space_id, n.created_by into v_sid, v_cb from nodes n where n.id = nid;
  if v_sid is null then return false; end if;
  if is_admin(v_sid) then return true; end if;
  if not can_view(nid) then return false; end if;
  if v_cb = auth.uid() then return true; end if;
  v_e := explicit_perm(nid,p);
  if v_e is not null then return v_e; end if;
  return role_perm(v_sid,p);
end $$;

-- ---------- VISTA: lista de nodos que existen para mí (sin contenido) ----------
create or replace view node_index as
  select id, space_id, parent_id, type, name, icon, color, kit_id, vis, tags,
         created_by, created_at, updated_at, deleted_at
  from nodes
  where can_see_exists(id);

-- ---------- TRIGGERS ----------
create or replace function nodes_before_insert() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  new.created_by := auth.uid();
  new.created_at := now();
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists trg_nodes_ins on nodes;
create trigger trg_nodes_ins before insert on nodes for each row execute function nodes_before_insert();

create or replace function nodes_guard() returns trigger
language plpgsql security definer set search_path=public as $$
declare v_sid uuid := old.space_id;
begin
  if new.id <> old.id or new.space_id <> old.space_id or new.created_by is distinct from old.created_by then
    raise exception 'Campo protegido';
  end if;
  if (old.settings->>'locked') = 'true' and not (is_admin(v_sid) or has_perm(old.id,'manage_perms')) then
    raise exception 'Este elemento está bloqueado (solo lectura)';
  end if;
  if new.name is distinct from old.name or new.icon is distinct from old.icon
     or new.color is distinct from old.color or new.kit_id is distinct from old.kit_id
     or new.tags is distinct from old.tags or new.blocks is distinct from old.blocks
     or new.view_mode is distinct from old.view_mode then
    if not has_perm(old.id,'edit') then raise exception 'No tienes permiso para editar'; end if;
  end if;
  if new.parent_id is distinct from old.parent_id then
    if old.parent_id is null then raise exception 'No se puede mover la raíz'; end if;
    if new.parent_id is null or node_space(new.parent_id) is distinct from v_sid then
      raise exception 'Destino no válido';
    end if;
    if not has_perm(old.id,'move') or not has_perm(new.parent_id,'create') then
      raise exception 'No tienes permiso para mover aquí';
    end if;
  end if;
  if new.deleted_at is distinct from old.deleted_at then
    if old.parent_id is null then raise exception 'No se puede borrar la raíz del espacio'; end if;
    if not has_perm(old.id,'delete') then raise exception 'No tienes permiso para borrar'; end if;
  end if;
  if new.vis is distinct from old.vis or new.settings is distinct from old.settings then
    if not has_perm(old.id,'manage_perms') then raise exception 'No tienes permiso para cambiar permisos o visibilidad'; end if;
  end if;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists trg_nodes_guard on nodes;
create trigger trg_nodes_guard before update on nodes for each row execute function nodes_guard();

create or replace function node_perms_before_insert() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  new.space_id := node_space(new.node_id);
  return new;
end $$;
drop trigger if exists trg_np_ins on node_perms;
create trigger trg_np_ins before insert on node_perms for each row execute function node_perms_before_insert();

create or replace function spaces_guard() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  if coalesce(current_setting('lsm.bypass', true),'') = '1' then return new; end if;
  if new.owner_id <> old.owner_id then raise exception 'Usa la opción de transferir'; end if;
  if (new.name is distinct from old.name or new.icon is distinct from old.icon
      or new.color is distinct from old.color or new.description is distinct from old.description)
     and not is_admin(old.id) then raise exception 'Solo un administrador puede cambiar esto'; end if;
  if (new.tags is distinct from old.tags or new.groups is distinct from old.groups)
     and not space_perm(old.id,'manage_tags') then raise exception 'No tienes permiso para gestionar etiquetas'; end if;
  if new.kits is distinct from old.kits and not space_perm(old.id,'manage_kits') then
    raise exception 'No tienes permiso para gestionar kits'; end if;
  return new;
end $$;
drop trigger if exists trg_spaces_guard on spaces;
create trigger trg_spaces_guard before update on spaces for each row execute function spaces_guard();

create or replace function roles_guard() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  if tg_op = 'INSERT' then
    new.is_base := false;
    if new.is_admin and not is_admin(new.space_id) then raise exception 'Solo un administrador puede crear roles de administrador'; end if;
  else
    if new.is_base is distinct from old.is_base then raise exception 'El rol base no se puede cambiar'; end if;
    if new.space_id <> old.space_id then raise exception 'Campo protegido'; end if;
    if new.is_admin is distinct from old.is_admin and not is_admin(old.space_id) then
      raise exception 'Solo un administrador puede cambiar eso'; end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_roles_guard on roles;
create trigger trg_roles_guard before insert or update on roles for each row execute function roles_guard();

-- perfil automático al registrarse
create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  insert into profiles(id,name,avatar)
  values (new.id,
          coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', split_part(new.email,'@',1), 'Usuario'),
          new.raw_user_meta_data->>'avatar_url')
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

-- ---------- RPC (acciones que el cliente llama) ----------
create or replace function create_space(p_name text, p_icon text, p_color text, p_tags jsonb, p_groups jsonb)
returns uuid language plpgsql security definer set search_path=public as $$
declare v_sid uuid; v_admin uuid; v_root uuid := gen_random_uuid();
        v_icon text := coalesce(nullif(p_icon,''),'🏠'); v_color text := coalesce(nullif(p_color,''),'#8F7BFF');
begin
  if auth.uid() is null then raise exception 'Inicia sesión'; end if;
  if coalesce(trim(p_name),'') = '' then raise exception 'Ponle nombre al espacio'; end if;
  insert into profiles(id) values (auth.uid()) on conflict (id) do nothing;
  insert into spaces(name,icon,color,owner_id,tags,groups)
  values (trim(p_name), v_icon, v_color, auth.uid(), coalesce(p_tags,'[]'::jsonb), coalesce(p_groups,'[]'::jsonb))
  returning id into v_sid;
  insert into roles(space_id,name,color,position,is_admin,perms)
  values (v_sid,'Administrador','#FF6B8A',100,true,'{}'::jsonb) returning id into v_admin;
  insert into roles(space_id,name,color,position,perms) values
   (v_sid,'Responsable','#F2C94C',80,'{"view":true,"comment":true,"create":true,"edit":true,"move":true,"delete":true,"upload":true,"download":true,"manage_perms":true,"approve":true,"invite":true,"manage_tags":true,"manage_kits":true}'::jsonb),
   (v_sid,'Miembro','#5EA8FF',50,'{"view":true,"comment":true,"create":true,"edit":true,"upload":true,"download":true}'::jsonb),
   (v_sid,'Lector','#9AA3B2',20,'{"view":true}'::jsonb);
  insert into roles(space_id,name,color,position,is_base,perms)
  values (v_sid,'Todos','#6C6896',0,true,'{"view":true,"comment":true}'::jsonb);
  insert into members(space_id,user_id,role_id) values (v_sid, auth.uid(), v_admin);
  insert into nodes(id,space_id,parent_id,type,name,icon,color,vis,created_by)
  values (v_root, v_sid, null, 'folder', trim(p_name), v_icon, v_color, 'public', auth.uid());
  insert into log(space_id,node_id,user_id,action,detail) values (v_sid, v_root, auth.uid(), 'Creó el espacio', trim(p_name));
  return v_sid;
end $$;

create or replace function list_members(p_space uuid) returns jsonb
language sql stable security definer set search_path=public as $$
  select coalesce(jsonb_agg(jsonb_build_object(
      'user_id', m.user_id, 'name', p.name, 'avatar', p.avatar, 'color', p.color,
      'role_id', m.role_id, 'joined_at', m.joined_at, 'owner', (s.owner_id = m.user_id)
    ) order by m.joined_at), '[]'::jsonb)
  from members m
  join profiles p on p.id = m.user_id
  join spaces s on s.id = m.space_id
  where m.space_id = p_space and is_member(p_space) $$;

create or replace function create_invite(p_space uuid, p_role uuid, p_days int, p_max int)
returns text language plpgsql security definer set search_path=public as $$
declare v_code text;
begin
  if not (is_admin(p_space) or space_perm(p_space,'invite')) then raise exception 'Sin permiso para invitar'; end if;
  if p_role is not null then
    if not exists(select 1 from roles where id = p_role and space_id = p_space) then raise exception 'Rol no válido'; end if;
    if exists(select 1 from roles where id = p_role and is_admin) and not is_admin(p_space) then
      raise exception 'Solo un administrador puede invitar como administrador'; end if;
  end if;
  v_code := substr(md5(random()::text || clock_timestamp()::text), 1, 8);
  insert into invites(code,space_id,role_id,expires_at,max_uses,created_by)
  values (v_code, p_space, p_role,
          case when coalesce(p_days,0) > 0 then now() + make_interval(days => p_days) else null end,
          nullif(p_max,0), auth.uid());
  return v_code;
end $$;

create or replace function join_with_code(p_code text) returns uuid
language plpgsql security definer set search_path=public as $$
declare v_inv invites%rowtype; v_role uuid;
begin
  if auth.uid() is null then raise exception 'Inicia sesión'; end if;
  insert into profiles(id) values (auth.uid()) on conflict (id) do nothing;
  select * into v_inv from invites where code = lower(trim(p_code)) for update;
  if not found then raise exception 'Código no válido'; end if;
  if v_inv.expires_at is not null and v_inv.expires_at < now() then raise exception 'El código venció'; end if;
  if v_inv.max_uses is not null and v_inv.uses >= v_inv.max_uses then raise exception 'El código ya no tiene usos'; end if;
  if exists(select 1 from members where space_id = v_inv.space_id and user_id = auth.uid()) then
    return v_inv.space_id;
  end if;
  v_role := v_inv.role_id;
  if v_role is null then
    select id into v_role from roles where space_id = v_inv.space_id and name = 'Miembro' limit 1;
  end if;
  insert into members(space_id,user_id,role_id) values (v_inv.space_id, auth.uid(), v_role);
  update invites set uses = uses + 1 where code = v_inv.code;
  insert into log(space_id,user_id,action,detail) values (v_inv.space_id, auth.uid(), 'Se unió al espacio', 'con código');
  return v_inv.space_id;
end $$;

create or replace function request_access(p_node uuid, p_msg text) returns uuid
language plpgsql security definer set search_path=public as $$
declare v_sid uuid; v_id uuid;
begin
  v_sid := node_space(p_node);
  if v_sid is null or not can_see_exists(p_node) then raise exception 'No existe'; end if;
  if can_view(p_node) then raise exception 'Ya tienes acceso'; end if;
  insert into requests(space_id,node_id,user_id,message) values (v_sid, p_node, auth.uid(), coalesce(p_msg,''))
  returning id into v_id;
  insert into log(space_id,node_id,user_id,action,detail) values (v_sid, p_node, auth.uid(), 'Solicitó acceso', coalesce(p_msg,''));
  return v_id;
exception when unique_violation then
  raise exception 'Ya enviaste una solicitud para esto';
end $$;

create or replace function resolve_request(p_req uuid, p_approve boolean, p_level text default 'view')
returns void language plpgsql security definer set search_path=public as $$
declare r requests%rowtype; v_perms text[];
begin
  select * into r from requests where id = p_req for update;
  if not found or r.status <> 'pending' then raise exception 'Solicitud no disponible'; end if;
  if not (is_admin(r.space_id) or (r.node_id is not null and (has_perm(r.node_id,'approve') or has_perm(r.node_id,'manage_perms')))) then
    raise exception 'Sin permiso para resolver esta solicitud';
  end if;
  if p_approve then
    v_perms := case p_level
      when 'edit' then array['view','comment','create','edit','upload','download']
      when 'admin' then array['view','comment','create','edit','move','delete','upload','download','manage_perms','approve']
      else array['view','comment'] end;
    insert into node_perms(space_id,node_id,subject_type,subject_id,perm,effect)
      select r.space_id, r.node_id, 'user', r.user_id::text, x, 'allow' from unnest(v_perms) x
    on conflict (node_id,subject_type,subject_id,perm) do update set effect = 'allow';
  end if;
  update requests set status = case when p_approve then 'approved' else 'rejected' end,
         resolved_by = auth.uid(), resolved_at = now() where id = p_req;
  insert into log(space_id,node_id,user_id,action,detail)
  values (r.space_id, r.node_id, auth.uid(), case when p_approve then 'Aprobó una solicitud' else 'Rechazó una solicitud' end, p_level);
end $$;

create or replace function set_member_role(p_space uuid, p_user uuid, p_role uuid) returns void
language plpgsql security definer set search_path=public as $$
begin
  if not (is_admin(p_space) or space_perm(p_space,'manage_roles')) then raise exception 'Sin permiso para cambiar roles'; end if;
  if exists(select 1 from spaces where id = p_space and owner_id = p_user) then raise exception 'No se puede cambiar el rol del propietario'; end if;
  if not exists(select 1 from roles where id = p_role and space_id = p_space and not is_base) then raise exception 'Rol no válido'; end if;
  if exists(select 1 from roles where id = p_role and is_admin) and not is_admin(p_space) then
    raise exception 'Solo un administrador puede dar ese rol'; end if;
  if exists(select 1 from members m join roles r on r.id = m.role_id where m.space_id = p_space and m.user_id = p_user and r.is_admin)
     and not is_admin(p_space) then raise exception 'Solo un administrador puede cambiar a otro administrador'; end if;
  update members set role_id = p_role where space_id = p_space and user_id = p_user;
  insert into log(space_id,user_id,action,detail) values (p_space, auth.uid(), 'Cambió un rol', p_user::text);
end $$;

create or replace function remove_member(p_space uuid, p_user uuid) returns void
language plpgsql security definer set search_path=public as $$
begin
  if not is_admin(p_space) then raise exception 'Solo un administrador puede quitar personas'; end if;
  if exists(select 1 from spaces where id = p_space and owner_id = p_user) then raise exception 'No se puede quitar al propietario'; end if;
  delete from members where space_id = p_space and user_id = p_user;
  insert into log(space_id,user_id,action,detail) values (p_space, auth.uid(), 'Quitó a una persona', p_user::text);
end $$;

create or replace function leave_space(p_space uuid) returns void
language plpgsql security definer set search_path=public as $$
begin
  if exists(select 1 from spaces where id = p_space and owner_id = auth.uid()) then
    raise exception 'El propietario no puede salir: transfiere el espacio o elimínalo'; end if;
  delete from members where space_id = p_space and user_id = auth.uid();
end $$;

create or replace function transfer_space(p_space uuid, p_user uuid) returns void
language plpgsql security definer set search_path=public as $$
declare v_admin uuid;
begin
  if not is_owner(p_space) then raise exception 'Solo el propietario puede transferir'; end if;
  if not exists(select 1 from members where space_id = p_space and user_id = p_user) then raise exception 'Esa persona no es miembro'; end if;
  select id into v_admin from roles where space_id = p_space and is_admin limit 1;
  perform set_config('lsm.bypass','1',true);
  update spaces set owner_id = p_user where id = p_space;
  update members set role_id = v_admin where space_id = p_space and user_id = p_user;
  insert into log(space_id,user_id,action,detail) values (p_space, auth.uid(), 'Transfirió el espacio', p_user::text);
end $$;

create or replace function delete_space(p_space uuid) returns void
language plpgsql security definer set search_path=public as $$
begin
  if not is_owner(p_space) then raise exception 'Solo el propietario puede eliminar el espacio'; end if;
  delete from spaces where id = p_space;
end $$;

-- ---------- SEGURIDAD (RLS) ----------
alter table profiles   enable row level security;
alter table spaces     enable row level security;
alter table roles      enable row level security;
alter table members    enable row level security;
alter table nodes      enable row level security;
alter table node_perms enable row level security;
alter table invites    enable row level security;
alter table requests   enable row level security;
alter table log        enable row level security;

drop policy if exists profiles_sel on profiles;
create policy profiles_sel on profiles for select to authenticated using (
  id = auth.uid() or exists(
    select 1 from members a join members b on a.space_id = b.space_id
    where a.user_id = auth.uid() and b.user_id = profiles.id));
drop policy if exists profiles_ins on profiles;
create policy profiles_ins on profiles for insert to authenticated with check (id = auth.uid());
drop policy if exists profiles_upd on profiles;
create policy profiles_upd on profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists spaces_sel on spaces;
create policy spaces_sel on spaces for select to authenticated using (is_member(id));
drop policy if exists spaces_upd on spaces;
create policy spaces_upd on spaces for update to authenticated using (is_member(id)) with check (is_member(id));

drop policy if exists roles_sel on roles;
create policy roles_sel on roles for select to authenticated using (is_member(space_id));
drop policy if exists roles_ins on roles;
create policy roles_ins on roles for insert to authenticated with check (space_perm(space_id,'manage_roles'));
drop policy if exists roles_upd on roles;
create policy roles_upd on roles for update to authenticated using (space_perm(space_id,'manage_roles')) with check (space_perm(space_id,'manage_roles'));
drop policy if exists roles_del on roles;
create policy roles_del on roles for delete to authenticated using (space_perm(space_id,'manage_roles') and not is_base);

drop policy if exists members_sel on members;
create policy members_sel on members for select to authenticated using (is_member(space_id));

drop policy if exists nodes_sel on nodes;
create policy nodes_sel on nodes for select to authenticated using (can_view(id));
drop policy if exists nodes_ins on nodes;
create policy nodes_ins on nodes for insert to authenticated with check (
  is_member(space_id) and parent_id is not null
  and node_space(parent_id) = space_id and has_perm(parent_id,'create'));
drop policy if exists nodes_upd on nodes;
create policy nodes_upd on nodes for update to authenticated using (can_view(id)) with check (is_member(space_id));
drop policy if exists nodes_del on nodes;
create policy nodes_del on nodes for delete to authenticated using (deleted_at is not null and has_perm(id,'delete'));

drop policy if exists np_sel on node_perms;
create policy np_sel on node_perms for select to authenticated using (
  has_perm(node_id,'manage_perms')
  or (subject_type = 'user' and subject_id = auth.uid()::text)
  or (subject_type = 'role' and subject_id in (
        select role_id::text from members where space_id = node_perms.space_id and user_id = auth.uid()
        union select id::text from roles where space_id = node_perms.space_id and is_base)));
drop policy if exists np_ins on node_perms;
create policy np_ins on node_perms for insert to authenticated with check (has_perm(node_id,'manage_perms'));
drop policy if exists np_upd on node_perms;
create policy np_upd on node_perms for update to authenticated using (has_perm(node_id,'manage_perms')) with check (has_perm(node_id,'manage_perms'));
drop policy if exists np_del on node_perms;
create policy np_del on node_perms for delete to authenticated using (has_perm(node_id,'manage_perms'));

drop policy if exists inv_sel on invites;
create policy inv_sel on invites for select to authenticated using (is_admin(space_id) or space_perm(space_id,'invite'));
drop policy if exists inv_del on invites;
create policy inv_del on invites for delete to authenticated using (is_admin(space_id) or space_perm(space_id,'invite'));

drop policy if exists req_sel on requests;
create policy req_sel on requests for select to authenticated using (
  user_id = auth.uid() or is_admin(space_id)
  or (node_id is not null and (has_perm(node_id,'approve') or has_perm(node_id,'manage_perms'))));

drop policy if exists log_sel on log;
create policy log_sel on log for select to authenticated using (
  is_admin(space_id) or user_id = auth.uid() or (node_id is not null and can_view(node_id)));
drop policy if exists log_ins on log;
create policy log_ins on log for insert to authenticated with check (is_member(space_id) and user_id = auth.uid());

-- el historial solo se agrega: nadie lo edita ni lo borra
revoke update, delete on log from authenticated, anon;

-- sin sesión no se ve nada
revoke all on all tables in schema public from anon;
grant select on node_index to authenticated;
revoke all on node_index from anon;

-- Listo.
