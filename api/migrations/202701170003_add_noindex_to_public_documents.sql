-- Add noindex column to public_documents table
-- Default is true (noindex = prevent search engine indexing)

ALTER TABLE public_documents
ADD COLUMN IF NOT EXISTS noindex BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN public_documents.noindex IS 'If true, adds noindex meta tag to prevent search engine indexing';
