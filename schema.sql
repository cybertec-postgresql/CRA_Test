CREATE TABLE IF NOT EXISTS assets (
    id          bigserial PRIMARY KEY,
    name        text        NOT NULL,
    criticality text        NOT NULL
                CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS assets_criticality_idx ON assets (criticality);
