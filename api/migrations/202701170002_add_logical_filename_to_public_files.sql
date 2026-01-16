-- Add logical_filename column to public_document_files
-- This stores the filename as it appears in markdown references (e.g., "image.png" from "./attachments/image.png")
-- Used to lookup files when serving public documents

ALTER TABLE public_document_files
ADD COLUMN IF NOT EXISTS logical_filename TEXT;

-- Update existing rows to use original_filename as logical_filename
UPDATE public_document_files
SET logical_filename = original_filename
WHERE logical_filename IS NULL;

-- Make it NOT NULL after populating
ALTER TABLE public_document_files
ALTER COLUMN logical_filename SET NOT NULL;

-- Index for efficient lookup by document and logical filename
CREATE INDEX IF NOT EXISTS idx_public_document_files_logical_filename
    ON public_document_files(document_id, logical_filename);
