-- Edge node metadata for Geo/ISP scheduling (Phase 1)

ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS public_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS isp TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS country TEXT NOT NULL DEFAULT 'CN';
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS province TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS city TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS weight INT NOT NULL DEFAULT 100;
ALTER TABLE edge_nodes ADD COLUMN IF NOT EXISTS max_bandwidth_mbps INT NOT NULL DEFAULT 0;

COMMENT ON COLUMN edge_nodes.public_ip IS 'Public IP returned by GeoDNS';
COMMENT ON COLUMN edge_nodes.isp IS 'telecom | unicom | mobile | bgp | ...';
COMMENT ON COLUMN edge_nodes.weight IS 'Scheduling weight (higher = preferred)';
COMMENT ON COLUMN edge_nodes.max_bandwidth_mbps IS '0 = unlimited';
