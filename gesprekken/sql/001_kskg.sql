-- KSK De Jeugd Lovendegem: afspraken voor evaluatiegesprekken, voor alle jeugdploegen.
-- Draait op het Sjotter Supabase-project, maar volledig los van Sjotter (tabellen kskg_*).
-- Geen rechtstreekse toegang tot de tabellen: alles loopt via de functies hieronder.
--   ouders  : publieke ploegcode (?p=...) + eigen afspraaktoken (blijft op hun gsm)
--   coach   : beheerlink per ploeg (?b=...)
--   admin   : één adminlink (?a=...) voor alle ploegen
-- Veilig om opnieuw uit te voeren.

create table if not exists public.kskg_instelling (
  id int primary key default 1 check (id = 1),
  admin_hash text not null
);

create table if not exists public.kskg_ploeg (
  id            uuid primary key default gen_random_uuid(),
  naam          text not null check (char_length(naam) between 1 and 40),
  code          text not null unique,
  beheer_token  text not null unique,
  titel         text not null default 'Evaluatiegesprekken' check (char_length(titel) <= 60),
  datum         date,
  start         time not null default '17:30',
  duur_min      int not null default 15 check (duur_min between 5 and 60),
  aantal_slots  int not null default 12 check (aantal_slots between 1 and 60),
  tafel_namen   text[] not null default '{Coach}' check (array_length(tafel_namen, 1) between 1 and 6),
  wijzig_tot    date,
  open          boolean not null default false,
  info          text check (info is null or char_length(info) <= 500),
  aangemaakt    timestamptz not null default now()
);

create table if not exists public.kskg_speler (
  id        uuid primary key default gen_random_uuid(),
  ploeg_id  uuid not null references public.kskg_ploeg(id) on delete cascade,
  naam      text not null check (char_length(naam) between 1 and 60),
  volgorde  int not null default 0
);
create index if not exists kskg_speler_ploeg on public.kskg_speler(ploeg_id);

create table if not exists public.kskg_boeking (
  id          uuid primary key default gen_random_uuid(),
  ploeg_id    uuid not null references public.kskg_ploeg(id) on delete cascade,
  speler_id   uuid not null unique references public.kskg_speler(id) on delete cascade,
  slot        int not null check (slot >= 0),
  tafel       int not null check (tafel >= 1),
  token_hash  text,
  door_coach  boolean not null default false,
  gemaakt     timestamptz not null default now(),
  gewijzigd   timestamptz,
  unique (ploeg_id, slot, tafel)
);

alter table public.kskg_instelling enable row level security;
alter table public.kskg_ploeg enable row level security;
alter table public.kskg_speler enable row level security;
alter table public.kskg_boeking enable row level security;
revoke all on public.kskg_instelling, public.kskg_ploeg, public.kskg_speler, public.kskg_boeking from anon, authenticated;

-- ---------- hulpfuncties ----------
create or replace function public.kskg_hash(t text) returns text
language sql immutable set search_path = public, extensions as $$ select encode(extensions.digest(coalesce(t, ''), 'sha256'), 'hex') $$;

create or replace function public.kskg_token(n int default 18) returns text
language sql volatile set search_path = public, extensions as $$
  select translate(encode(extensions.gen_random_bytes(n), 'base64'), '+/=', '-_')
$$;

create or replace function public.kskg_is_admin(p_token text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from kskg_instelling where admin_hash = kskg_hash(p_token)) and coalesce(length(p_token), 0) >= 20
$$;

-- welke ploeg mag dit token beheren? beheertoken van de ploeg, of admintoken + ploeg-id
create or replace function public.kskg_ploeg_voor(p_token text, p_ploeg uuid default null) returns uuid
language plpgsql stable security definer set search_path = public as $$
declare v uuid;
begin
  if coalesce(length(p_token), 0) < 20 then raise exception 'Deze link werkt niet.'; end if;
  select id into v from kskg_ploeg where beheer_token = p_token;
  if v is not null then return v; end if;
  if p_ploeg is not null and kskg_is_admin(p_token) and exists (select 1 from kskg_ploeg where id = p_ploeg) then return p_ploeg; end if;
  raise exception 'Deze link werkt niet.';
end $$;

create or replace function public.kskg_kan_wijzigen(p kskg_ploeg) returns boolean
language sql stable as $$ select p.open and (p.wijzig_tot is null or (now() at time zone 'Europe/Brussels')::date <= p.wijzig_tot) $$;

-- vrije tafel voor een tijdslot (laagste nummer), of null
create or replace function public.kskg_vrije_tafel(p_ploeg uuid, p_slot int, p_behalve uuid default null) returns int
language sql stable security definer set search_path = public as $$
  select t from kskg_ploeg p, generate_series(1, array_length(p.tafel_namen, 1)) t
  where p.id = p_ploeg and not exists (select 1 from kskg_boeking b where b.ploeg_id = p_ploeg and b.slot = p_slot and b.tafel = t and b.id is distinct from p_behalve)
  order by t limit 1
$$;

-- ---------- ouders ----------
create or replace function public.kskg_info(p_code text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare p kskg_ploeg;
begin
  select * into p from kskg_ploeg where code = lower(trim(p_code));
  if not found then return null; end if;
  if not p.open or p.datum is null then return jsonb_build_object('gesloten', true, 'naam', p.naam, 'titel', p.titel); end if;
  return jsonb_build_object(
    'naam', p.naam, 'titel', p.titel, 'datum', p.datum, 'start', to_char(p.start, 'HH24:MI'), 'duur', p.duur_min,
    'slots', p.aantal_slots, 'tafels', array_length(p.tafel_namen, 1), 'tafel_namen', to_jsonb(p.tafel_namen),
    'wijzig_tot', p.wijzig_tot, 'kan_wijzigen', kskg_kan_wijzigen(p), 'info', p.info,
    'spelers', coalesce((select jsonb_agg(jsonb_build_object('id', s.id, 'naam', s.naam,
        'geboekt', exists (select 1 from kskg_boeking b where b.speler_id = s.id)) order by s.volgorde, s.naam)
      from kskg_speler s where s.ploeg_id = p.id), '[]'),
    'bezet', coalesce((select jsonb_object_agg(slot, n) from (select slot, count(*) n from kskg_boeking where ploeg_id = p.id group by slot) x), '{}'));
end $$;

create or replace function public.kskg_boek(p_code text, p_speler uuid, p_slot int) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare p kskg_ploeg; v_tafel int; v_token text := kskg_token();
begin
  select * into p from kskg_ploeg where code = lower(trim(p_code)) for update;
  if not found or not p.open or p.datum is null then raise exception 'Inschrijven is gesloten.'; end if;
  if not exists (select 1 from kskg_speler where id = p_speler and ploeg_id = p.id) then raise exception 'Kies een speler.'; end if;
  if exists (select 1 from kskg_boeking where speler_id = p_speler) then raise exception 'Voor deze speler is al een afspraak gemaakt. Wil je wijzigen? Doe het met de gsm waarmee je de afspraak maakte, of contacteer de coach.'; end if;
  if p_slot is null or p_slot < 0 or p_slot >= p.aantal_slots then raise exception 'Kies een tijdstip.'; end if;
  v_tafel := kskg_vrije_tafel(p.id, p_slot);
  if v_tafel is null then raise exception 'Dit tijdstip is net volzet. Kies een ander tijdstip.'; end if;
  insert into kskg_boeking (ploeg_id, speler_id, slot, tafel, token_hash) values (p.id, p_speler, p_slot, v_tafel, kskg_hash(v_token));
  return jsonb_build_object('token', v_token, 'slot', p_slot, 'tafel', v_tafel);
end $$;

create or replace function public.kskg_mijn(p_code text, p_token text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('speler_id', b.speler_id, 'naam', s.naam, 'slot', b.slot, 'tafel', b.tafel)
  from kskg_boeking b join kskg_speler s on s.id = b.speler_id join kskg_ploeg p on p.id = b.ploeg_id
  where p.code = lower(trim(p_code)) and b.token_hash = kskg_hash(p_token) and coalesce(length(p_token), 0) >= 20
$$;

create or replace function public.kskg_wijzig(p_code text, p_token text, p_slot int) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare p kskg_ploeg; b kskg_boeking; v_tafel int;
begin
  select * into p from kskg_ploeg where code = lower(trim(p_code)) for update;
  if not found then raise exception 'Deze link werkt niet.'; end if;
  select * into b from kskg_boeking where ploeg_id = p.id and token_hash = kskg_hash(p_token) and coalesce(length(p_token), 0) >= 20;
  if not found then raise exception 'Afspraak niet gevonden.'; end if;
  if not kskg_kan_wijzigen(p) then raise exception 'Wijzigen kan niet meer. Contacteer de coach.'; end if;
  if p_slot is null then delete from kskg_boeking where id = b.id; return jsonb_build_object('geannuleerd', true); end if;
  if p_slot < 0 or p_slot >= p.aantal_slots then raise exception 'Kies een tijdstip.'; end if;
  v_tafel := kskg_vrije_tafel(p.id, p_slot, b.id);
  if v_tafel is null then raise exception 'Dit tijdstip is net volzet. Kies een ander tijdstip.'; end if;
  update kskg_boeking set slot = p_slot, tafel = v_tafel, gewijzigd = now() where id = b.id;
  return jsonb_build_object('slot', p_slot, 'tafel', v_tafel);
end $$;

-- ---------- coach (beheerlink) en admin ----------
create or replace function public.kskg_beheer(p_token text, p_ploeg uuid default null) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare v uuid := kskg_ploeg_voor(p_token, p_ploeg); p kskg_ploeg;
begin
  select * into p from kskg_ploeg where id = v;
  return jsonb_build_object(
    'id', p.id, 'naam', p.naam, 'code', p.code, 'titel', p.titel, 'datum', p.datum, 'start', to_char(p.start, 'HH24:MI'),
    'duur', p.duur_min, 'slots', p.aantal_slots, 'tafel_namen', to_jsonb(p.tafel_namen), 'wijzig_tot', p.wijzig_tot,
    'open', p.open, 'info', p.info, 'admin', kskg_is_admin(p_token),
    'spelers', coalesce((select jsonb_agg(jsonb_build_object('id', s.id, 'naam', s.naam) order by s.volgorde, s.naam) from kskg_speler s where s.ploeg_id = p.id), '[]'),
    'boekingen', coalesce((select jsonb_agg(jsonb_build_object('speler_id', b.speler_id, 'slot', b.slot, 'tafel', b.tafel, 'door_coach', b.door_coach, 'gemaakt', b.gemaakt, 'gewijzigd', b.gewijzigd)) from kskg_boeking b where b.ploeg_id = p.id), '[]'));
end $$;

create or replace function public.kskg_beheer_bewaar(p_token text, p_ploeg uuid, p jsonb) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare v uuid := kskg_ploeg_voor(p_token, p_ploeg); v_slots int; v_tafels text[]; v_namen text[]; i int;
begin
  perform 1 from kskg_ploeg where id = v for update;
  v_slots := coalesce((p->>'slots')::int, (select aantal_slots from kskg_ploeg where id = v));
  v_tafels := coalesce((select array_agg(left(trim(x), 30)) from jsonb_array_elements_text(p->'tafel_namen') x where trim(x) <> ''), (select tafel_namen from kskg_ploeg where id = v));
  if exists (select 1 from kskg_boeking where ploeg_id = v and (slot >= v_slots or tafel > array_length(v_tafels, 1))) then
    raise exception 'Er zijn nog afspraken op tijdstippen of bij coaches die je wil schrappen. Verplaats of verwijder die eerst.';
  end if;
  update kskg_ploeg set
    naam = coalesce(nullif(left(trim(p->>'naam'), 40), ''), naam),
    titel = coalesce(nullif(left(trim(p->>'titel'), 60), ''), titel),
    datum = case when p ? 'datum' then nullif(p->>'datum', '')::date else datum end,
    start = coalesce(nullif(p->>'start', '')::time, start),
    duur_min = coalesce((p->>'duur')::int, duur_min),
    aantal_slots = v_slots, tafel_namen = v_tafels,
    wijzig_tot = case when p ? 'wijzig_tot' then nullif(p->>'wijzig_tot', '')::date else wijzig_tot end,
    open = coalesce((p->>'open')::boolean, open),
    info = case when p ? 'info' then nullif(left(trim(p->>'info'), 500), '') else info end
  where id = v;
  -- spelers: lijst met namen (bestaande namen behouden hun afspraak)
  if p ? 'spelers' then
    v_namen := coalesce((select array_agg(n order by ord) from (select distinct on (lower(trim(x))) left(trim(x), 60) n, ord from jsonb_array_elements_text(p->'spelers') with ordinality t(x, ord) where trim(x) <> '' order by lower(trim(x)), ord) q), '{}');
    if array_length(v_namen, 1) > 60 then raise exception 'Maximaal 60 spelers.'; end if;
    delete from kskg_speler where ploeg_id = v and lower(naam) <> all (select lower(x) from unnest(v_namen) x);
    for i in 1 .. coalesce(array_length(v_namen, 1), 0) loop
      update kskg_speler set volgorde = i, naam = v_namen[i] where ploeg_id = v and lower(naam) = lower(v_namen[i]);
      if not found then insert into kskg_speler (ploeg_id, naam, volgorde) values (v, v_namen[i], i); end if;
    end loop;
  end if;
  return kskg_beheer(p_token, v);
end $$;

-- coach zet, verplaatst of schrapt een afspraak (p_slot null = schrappen)
create or replace function public.kskg_beheer_zet(p_token text, p_ploeg uuid, p_speler uuid, p_slot int, p_tafel int) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare v uuid := kskg_ploeg_voor(p_token, p_ploeg); p kskg_ploeg; b kskg_boeking;
begin
  select * into p from kskg_ploeg where id = v for update;
  if not exists (select 1 from kskg_speler where id = p_speler and ploeg_id = v) then raise exception 'Speler niet gevonden.'; end if;
  select * into b from kskg_boeking where speler_id = p_speler;
  if p_slot is null then delete from kskg_boeking where speler_id = p_speler; return kskg_beheer(p_token, v); end if;
  if p_slot < 0 or p_slot >= p.aantal_slots or p_tafel < 1 or p_tafel > array_length(p.tafel_namen, 1) then raise exception 'Ongeldig tijdstip.'; end if;
  if exists (select 1 from kskg_boeking where ploeg_id = v and slot = p_slot and tafel = p_tafel and speler_id <> p_speler) then raise exception 'Daar staat al iemand ingepland.'; end if;
  if b.id is null then
    insert into kskg_boeking (ploeg_id, speler_id, slot, tafel, door_coach) values (v, p_speler, p_slot, p_tafel, true);
  else
    update kskg_boeking set slot = p_slot, tafel = p_tafel, gewijzigd = now() where id = b.id;
  end if;
  return kskg_beheer(p_token, v);
end $$;

create or replace function public.kskg_admin(p_token text) returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if not kskg_is_admin(p_token) then raise exception 'Deze link werkt niet.'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', p.id, 'naam', p.naam, 'code', p.code, 'beheer_token', p.beheer_token,
      'datum', p.datum, 'open', p.open, 'tafel_namen', to_jsonb(p.tafel_namen),
      'spelers', (select count(*) from kskg_speler s where s.ploeg_id = p.id),
      'geboekt', (select count(*) from kskg_boeking b where b.ploeg_id = p.id)) order by p.naam)
    from kskg_ploeg p), '[]');
end $$;

create or replace function public.kskg_admin_nieuw(p_token text, p_naam text) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
declare v_code text;
begin
  if not kskg_is_admin(p_token) then raise exception 'Deze link werkt niet.'; end if;
  if coalesce(trim(p_naam), '') = '' then raise exception 'Geef een naam.'; end if;
  loop
    v_code := lower(regexp_replace(left(trim(p_naam), 12), '[^a-zA-Z0-9]+', '', 'g')) || '-' || substr(md5(random()::text), 1, 4);
    exit when not exists (select 1 from kskg_ploeg where code = v_code);
  end loop;
  insert into kskg_ploeg (naam, code, beheer_token) values (left(trim(p_naam), 40), v_code, kskg_token(24));
  return kskg_admin(p_token);
end $$;

create or replace function public.kskg_admin_verwijder(p_token text, p_ploeg uuid) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
begin
  if not kskg_is_admin(p_token) then raise exception 'Deze link werkt niet.'; end if;
  delete from kskg_ploeg where id = p_ploeg;
  return kskg_admin(p_token);
end $$;

-- nieuwe beheerlink (de oude werkt dan niet meer)
create or replace function public.kskg_admin_nieuwe_link(p_token text, p_ploeg uuid) returns jsonb
language plpgsql volatile security definer set search_path = public as $$
begin
  if not kskg_is_admin(p_token) then raise exception 'Deze link werkt niet.'; end if;
  update kskg_ploeg set beheer_token = kskg_token(24) where id = p_ploeg;
  return kskg_admin(p_token);
end $$;

do $$ declare f text; begin
  foreach f in array array['kskg_hash(text)','kskg_token(int)','kskg_is_admin(text)','kskg_ploeg_voor(text,uuid)','kskg_kan_wijzigen(kskg_ploeg)','kskg_vrije_tafel(uuid,int,uuid)'] loop
    execute format('revoke all on function public.%s from public, anon, authenticated', f);
  end loop;
  foreach f in array array['kskg_info(text)','kskg_boek(text,uuid,int)','kskg_mijn(text,text)','kskg_wijzig(text,text,int)','kskg_beheer(text,uuid)','kskg_beheer_bewaar(text,uuid,jsonb)','kskg_beheer_zet(text,uuid,uuid,int,int)','kskg_admin(text)','kskg_admin_nieuw(text,text)','kskg_admin_verwijder(text,uuid)','kskg_admin_nieuwe_link(text,uuid)'] loop
    execute format('revoke all on function public.%s from public', f);
    execute format('grant execute on function public.%s to anon, authenticated', f);
  end loop;
end $$;

-- ---------- veiligheid: logboek van elke wijziging + momentopname elke 30 minuten ----------
-- (zelfde opzet als cs_gesprek_log / cs_gesprek_snapshot in Sjotter; tabellen kskg_log en kskg_snapshot,
--  trigger kskg_log_t op kskg_boeking, pg_cron-job 'kskg-snapshot' die kskg_snapshot_maak() oproept)

-- ---------- tweede dag (optioneel) ----------
-- kskg_ploeg.dag2_datum, dag2_start, dag2_slots: de laatste dag2_slots tijdstippen vallen op dag 2.
-- Zie migratie 'kskg_tweede_dag' (kskg_slot_uur, kskg_info, kskg_beheer, kskg_beheer_bewaar, kskg_snapshot_maak).
