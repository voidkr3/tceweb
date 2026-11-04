-- Migração da versão 2.3: biblioteca de modelos de documentos Word.
-- Execute no SQL Editor do Neon antes de publicar a versão 2.3.
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
