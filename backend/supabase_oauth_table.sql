-- Create oauth_tokens table for storing OAuth2 tokens
CREATE TABLE IF NOT EXISTS oauth_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    token_type VARCHAR(50) DEFAULT 'Bearer',
    expires_in INTEGER,
    scope TEXT,
    expires_at BIGINT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Ensure one row per user per provider
    UNIQUE(user_id, provider)
);

-- Add RLS (Row Level Security) policies
ALTER TABLE oauth_tokens ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own tokens
CREATE POLICY "Users can view own tokens" ON oauth_tokens
    FOR SELECT USING (auth.uid()::text = user_id);

-- Policy: Users can insert own tokens
CREATE POLICY "Users can insert own tokens" ON oauth_tokens
    FOR INSERT WITH CHECK (auth.uid()::text = user_id);

-- Policy: Users can update own tokens
CREATE POLICY "Users can update own tokens" ON oauth_tokens
    FOR UPDATE USING (auth.uid()::text = user_id);

-- Policy: Users can delete own tokens
CREATE POLICY "Users can delete own tokens" ON oauth_tokens
    FOR DELETE USING (auth.uid()::text = user_id);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_user_provider
ON oauth_tokens(user_id, provider);
