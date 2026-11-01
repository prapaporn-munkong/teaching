-- Run in Supabase SQL Editor. Bootstrap first admin manually after user creation.
create extension if not exists pgcrypto;
create table public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 full_name text not null, role text not null default 'teacher' check(role in ('teacher','reviewer','admin')),
 department text, active boolean not null default true, created_at timestamptz default now()
);
create table public.education_levels (id smallint primary key, name text not null);
insert into public.education_levels values (1,'มัธยมศึกษาตอนต้น'),(2,'ประกาศนียบัตรวิชาชีพ'),(3,'ปริญญาตรี') on conflict do nothing;
create table public.academic_terms (id uuid primary key default gen_random_uuid(), academic_year int not null, term int not null check(term between 1 and 3), starts_on date not null, ends_on date not null, is_active boolean default false, unique(academic_year,term));
create table public.courses (id uuid primary key default gen_random_uuid(), code text not null, name text not null, level_id smallint not null references public.education_levels(id), course_type text default 'ทฤษฎี', unique(code,level_id));
create table public.class_groups (id uuid primary key default gen_random_uuid(), level_id smallint not null references public.education_levels(id), name text not null, department text);
create table public.teaching_schedules (
 id uuid primary key default gen_random_uuid(), term_id uuid not null references public.academic_terms(id), course_id uuid not null references public.courses(id), group_id uuid not null references public.class_groups(id),
 scheduled_start timestamptz not null, scheduled_end timestamptz not null, room text,
 cancelled boolean not null default false, created_at timestamptz not null default now(),
 constraint valid_schedule_interval check (scheduled_end>scheduled_start)
);
create table public.schedule_teachers (
 schedule_id uuid not null references public.teaching_schedules(id) on delete cascade,
 teacher_id uuid not null references public.profiles(id), workload_minutes int,
 primary key(schedule_id,teacher_id), check(workload_minutes is null or workload_minutes>=0)
);
create table public.attendance_records (
 id uuid primary key default gen_random_uuid(), schedule_id uuid not null unique references public.teaching_schedules(id),
 status text not null check(status in ('taught','partial','absent')),
 actual_start timestamptz, actual_end timestamptz,
 actual_minutes int not null default 0 check(actual_minutes>=0),
 topic text, notes text, confirmed_by uuid not null references public.profiles(id), confirmed_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 constraint actual_interval check(actual_end is null or actual_start is null or actual_end>=actual_start)
);
create table public.attendance_adjustments (
 id uuid primary key default gen_random_uuid(), schedule_id uuid not null references public.teaching_schedules(id),
 requested_by uuid not null references public.profiles(id), kind text not null check(kind in ('correction','substitution','makeup','cancellation')),
 reason text not null, status text not null default 'pending' check(status in ('pending','approved','rejected')),
 reviewed_by uuid references public.profiles(id), reviewed_at timestamptz, created_at timestamptz default now()
);
create table public.audit_logs (
 id bigint generated always as identity primary key, actor_id uuid references public.profiles(id), schedule_id uuid references public.teaching_schedules(id), action text not null,
 before_data jsonb, after_data jsonb, occurred_at timestamptz not null default now()
);
create index on public.schedule_teachers(teacher_id);
create index on public.teaching_schedules(scheduled_start);
create index on public.teaching_schedules(term_id);
create index on public.attendance_adjustments(schedule_id);
create index on public.audit_logs(schedule_id);

create schema if not exists private;
create or replace function private.my_role() returns text language sql stable security definer set search_path='' as $$
 select role from public.profiles where id=(select auth.uid()) and active=true
$$;
create or replace function private.is_assigned(p_schedule uuid) returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from public.schedule_teachers where schedule_id=p_schedule and teacher_id=(select auth.uid()))
$$;
revoke all on function private.my_role() from public;
revoke all on function private.is_assigned(uuid) from public;
grant usage on schema private to authenticated;
grant execute on function private.my_role(),private.is_assigned(uuid) to authenticated;

alter table public.profiles enable row level security;
alter table public.education_levels enable row level security;
alter table public.academic_terms enable row level security;
alter table public.courses enable row level security;
alter table public.class_groups enable row level security;
alter table public.teaching_schedules enable row level security;
alter table public.schedule_teachers enable row level security;
alter table public.attendance_records enable row level security;
alter table public.attendance_adjustments enable row level security;
alter table public.audit_logs enable row level security;

create policy profiles_read on public.profiles for select to authenticated using (id=(select auth.uid()) or (select private.my_role()) in ('reviewer','admin') or exists(select 1 from public.schedule_teachers st where st.teacher_id=profiles.id and (select private.is_assigned(st.schedule_id))));
create policy levels_read on public.education_levels for select to authenticated using ((select private.my_role()) is not null);
create policy terms_read on public.academic_terms for select to authenticated using ((select private.my_role()) is not null);
create policy courses_read on public.courses for select to authenticated using ((select private.my_role()) is not null);
create policy groups_read on public.class_groups for select to authenticated using ((select private.my_role()) is not null);
create policy schedules_read on public.teaching_schedules for select to authenticated using ((select private.my_role()) in ('reviewer','admin') or (select private.is_assigned(id)));
create policy assigned_read on public.schedule_teachers for select to authenticated using ((select private.my_role()) in ('reviewer','admin') or (select private.is_assigned(schedule_id)));
create policy attendance_read on public.attendance_records for select to authenticated using ((select private.my_role()) in ('reviewer','admin') or (select private.is_assigned(schedule_id)));
create policy adjustments_read on public.attendance_adjustments for select to authenticated using ((select private.my_role()) in ('reviewer','admin') or (select private.is_assigned(schedule_id)));
create policy audits_read on public.audit_logs for select to authenticated using ((select private.my_role()) in ('reviewer','admin') or (schedule_id is not null and (select private.is_assigned(schedule_id))));

-- No direct writes from browser to protected tables; use vetted RPCs.
revoke insert,update,delete on public.profiles,public.education_levels,public.academic_terms,public.courses,public.class_groups,public.teaching_schedules,public.schedule_teachers,public.attendance_records,public.attendance_adjustments,public.audit_logs from anon,authenticated;

create or replace function public.confirm_teaching(p_schedule uuid, p_status text, p_actual_start timestamptz, p_actual_end timestamptz, p_topic text default null, p_notes text default null)
returns public.attendance_records
language plpgsql security definer set search_path = '' as $$
declare v_s public.teaching_schedules%rowtype; v_result public.attendance_records%rowtype; v_minutes integer;
begin
 if (select auth.uid()) is null then raise exception 'กรุณาเข้าสู่ระบบ'; end if;
 if not (select private.is_assigned(p_schedule)) and (select private.my_role()) not in ('reviewer','admin') then raise exception 'ไม่มีสิทธิ์ยืนยันรายการนี้'; end if;
 if p_status not in ('taught','partial','absent') then raise exception 'สถานะไม่ถูกต้อง'; end if;
 select * into v_s from public.teaching_schedules where id=p_schedule for update;
 if not found or v_s.cancelled then raise exception 'ไม่พบรายการหรือรายการถูกยกเลิก'; end if;
 if v_s.scheduled_start > now() then raise exception 'ยังไม่ถึงเวลาสอน'; end if;
 if p_status='absent' then
   if (select private.my_role()) not in ('reviewer','admin') then raise exception 'สถานะไม่เข้าสอนต้องผ่านการตรวจสอบ'; end if;
   v_minutes:=0;
 else
   if p_actual_start is null or p_actual_end is null or p_actual_end <= p_actual_start then raise exception 'ระบุเวลาเริ่มและสิ้นสุดจริงให้ถูกต้อง'; end if;
   if p_actual_start > now() or p_actual_end > now() then raise exception 'ไม่สามารถบันทึกเวลาสอนในอนาคต'; end if;
   v_minutes := floor(extract(epoch from p_actual_end-p_actual_start)/60);
   if v_minutes > floor(extract(epoch from v_s.scheduled_end-v_s.scheduled_start)/60) then raise exception 'เวลาสอนจริงมากกว่าเวลาในตาราง กรุณาใช้รายการปรับแก้'; end if;
   if (p_status='taught' and v_minutes <> floor(extract(epoch from v_s.scheduled_end-v_s.scheduled_start)/60)) or (p_status='partial' and v_minutes >= floor(extract(epoch from v_s.scheduled_end-v_s.scheduled_start)/60)) then raise exception 'สถานะไม่สอดคล้องกับชั่วโมงสอนจริง'; end if;
 end if;
 insert into public.attendance_records(schedule_id,status,actual_start,actual_end,actual_minutes,topic,notes,confirmed_by)
 values (p_schedule,p_status,p_actual_start,p_actual_end,v_minutes,nullif(trim(p_topic),''),nullif(trim(p_notes),''),(select auth.uid()))
 on conflict(schedule_id) do nothing returning * into v_result;
 if not found then raise exception 'รายการนี้มีผู้ยืนยันแล้ว กรุณารีเฟรชข้อมูล'; end if;
 insert into public.audit_logs(actor_id,schedule_id,action,after_data) values((select auth.uid()),p_schedule,'confirm',to_jsonb(v_result));
 return v_result;
end $$;
revoke all on function public.confirm_teaching(uuid,text,timestamptz,timestamptz,text,text) from public;
grant execute on function public.confirm_teaching(uuid,text,timestamptz,timestamptz,text,text) to authenticated;

create or replace function public.request_attendance_correction(p_schedule uuid,p_reason text)
returns uuid language plpgsql security definer set search_path='' as $$
declare v_id uuid;
begin
 if not ((select private.is_assigned(p_schedule)) or (select private.my_role()) in ('reviewer','admin')) then raise exception 'ไม่มีสิทธิ์'; end if;
 if length(trim(coalesce(p_reason,''))) < 5 then raise exception 'กรุณาระบุเหตุผลอย่างน้อย 5 ตัวอักษร'; end if;
 insert into public.attendance_adjustments(schedule_id,requested_by,kind,reason) values(p_schedule,(select auth.uid()),'correction',p_reason) returning id into v_id;
 insert into public.audit_logs(actor_id,schedule_id,action,after_data) values((select auth.uid()),p_schedule,'request_correction',jsonb_build_object('adjustment_id',v_id,'reason',p_reason));
 return v_id;
end $$;
revoke all on function public.request_attendance_correction(uuid,text) from public;
grant execute on function public.request_attendance_correction(uuid,text) to authenticated;

-- Safe admin bootstrap: After creating the first Auth user, run with its UUID (never expose admin privileges via browser).
-- insert into public.profiles(id,full_name,role) values ('YOUR_AUTH_USER_UUID','ผู้ดูแลระบบ','admin');
-- Subsequent user provisioning and schedule imports are performed via SQL Editor or trusted server scripts.
