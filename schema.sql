-- TCE v2.2 — Neon PostgreSQL
-- Execute uma vez no SQL Editor do Neon. Não contém contas ou dados pessoais fictícios.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gist;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(150) NOT NULL CHECK (length(trim(name)) >= 2),
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role VARCHAR(30) NOT NULL CHECK (role IN ('coordenador','vice_coordenador','contribuinte','escola')),
  cargo_detalhado VARCHAR(120),
  contributor_id UUID,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
  session_version INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS contributors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  full_name VARCHAR(150) NOT NULL,
  birth_date DATE,
  email VARCHAR(254) NOT NULL UNIQUE,
  address TEXT,
  cpf VARCHAR(11) UNIQUE,
  photo_url TEXT,
  document_url TEXT,
  status VARCHAR(20) NOT NULL DEFAULT 'Ativo' CHECK (status IN ('Ativo','Inativo','Desligado')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_contributor_id_fkey;
ALTER TABLE users ADD CONSTRAINT users_contributor_id_fkey FOREIGN KEY (contributor_id) REFERENCES contributors(id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS suppliers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  legal_name VARCHAR(150) NOT NULL,
  trade_name VARCHAR(150),
  cnpj VARCHAR(14) UNIQUE,
  general_contact TEXT,
  seller_name VARCHAR(120),
  seller_contact VARCHAR(120),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS financial_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  description VARCHAR(200) NOT NULL,
  type VARCHAR(10) NOT NULL CHECK (type IN ('pagar','receber')),
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  due_date DATE NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pendente' CHECK (status IN ('pendente','pago','recebido','cancelado')),
  counterparty VARCHAR(150) NOT NULL,
  invoice_number VARCHAR(100),
  receipt_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS purchases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  supplier_id UUID REFERENCES suppliers(id) ON DELETE RESTRICT,
  item TEXT NOT NULL,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  access_key VARCHAR(44),
  invoice_number VARCHAR(100),
  purchase_date DATE NOT NULL,
  notes TEXT,
  receipt_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS announcements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(180) NOT NULL,
  content TEXT NOT NULL,
  category VARCHAR(60) NOT NULL DEFAULT 'Geral',
  author_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS service_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  requester_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  requester_name VARCHAR(150) NOT NULL,
  sector VARCHAR(150) NOT NULL,
  activity_name VARCHAR(180) NOT NULL,
  event_date DATE NOT NULL,
  support_type VARCHAR(100) NOT NULL,
  description TEXT NOT NULL,
  status VARCHAR(25) NOT NULL DEFAULT 'Pendente' CHECK (status IN ('Pendente','Em análise','Aprovada','Rejeitada','Concluída')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS tasks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(180) NOT NULL,
  description TEXT,
  assigned_to UUID REFERENCES contributors(id) ON DELETE SET NULL,
  due_date DATE NOT NULL,
  priority VARCHAR(20) NOT NULL DEFAULT 'Média' CHECK (priority IN ('Baixa','Média','Alta','Urgente')),
  status VARCHAR(20) NOT NULL DEFAULT 'pendente' CHECK (status IN ('pendente','em_andamento','concluida','cancelada')),
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS declared_hours (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  contributor_id UUID NOT NULL REFERENCES contributors(id) ON DELETE RESTRICT,
  task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
  work_date DATE NOT NULL,
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  hours NUMERIC(5,2) NOT NULL CHECK (hours > 0 AND hours <= 16),
  activity VARCHAR(180) NOT NULL,
  notes TEXT,
  status VARCHAR(30) NOT NULL DEFAULT 'Pendente Aprovação Escola' CHECK (status IN ('Pendente Aprovação Escola','Aprovado Escola','Rejeitado')),
  reviewed_by UUID REFERENCES users(id) ON DELETE RESTRICT,
  reviewed_at TIMESTAMPTZ,
  review_note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (end_time > start_time)
);
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(80) NOT NULL,
  entity VARCHAR(80) NOT NULL,
  entity_id TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip_address INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_tasks_assigned_to ON tasks(assigned_to);
CREATE INDEX IF NOT EXISTS idx_hours_contributor_date ON declared_hours(contributor_id, work_date DESC);
CREATE INDEX IF NOT EXISTS idx_hours_status ON declared_hours(status);
CREATE INDEX IF NOT EXISTS idx_requests_status ON service_requests(status);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);

-- Bloqueia sobreposição de períodos declarados para o mesmo contribuinte.
ALTER TABLE declared_hours DROP CONSTRAINT IF EXISTS declared_hours_no_overlap;
ALTER TABLE declared_hours ADD CONSTRAINT declared_hours_no_overlap EXCLUDE USING gist (contributor_id WITH =, work_date WITH =, tsrange(work_date + start_time, work_date + end_time, '[)') WITH &&) WHERE (status <> 'Rejeitado');

-- Migração segura para instalações que já executaram versões anteriores do schema.
ALTER TABLE purchases ADD COLUMN IF NOT EXISTS access_key VARCHAR(44);
ALTER TABLE purchases ALTER COLUMN invoice_number DROP NOT NULL;


-- Modelos de documentos cadastráveis pela coordenação.
CREATE TABLE IF NOT EXISTS document_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(180) NOT NULL,
  description TEXT,
  category VARCHAR(80) NOT NULL DEFAULT 'Geral',
  model_url TEXT NOT NULL,
  tags JSONB NOT NULL DEFAULT '[]'::jsonb,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_document_templates_active ON document_templates(active, name);
