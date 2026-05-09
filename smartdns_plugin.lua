-- ============================================================================
-- SMARTDNS COMPATIBILITY PLUGIN FOR DNSDIST 2.x
-- Menyediakan fungsi: smartdns_ip_set, smartdns_domain_set, 
--                     smartdns_cname, smartdns_ip_rules_alias
-- ============================================================================

-- Variabel penampung untuk NetmaskGroup (ip-set) dan SuffixMatchNode (domain-set)
smartdns_nmg = {}
smartdns_smn = {}

-- ============================================================================
-- HELPER: Konversi IPv6 string ke 16 byte
-- ============================================================================
function _ipv6_to_bytes(str)
    local left, right
    local groups = {}

    if str:find("::") then
        left, right = str:match("^(.-)::(.-)$")
        local lg, rg = {}, {}
        if left ~= "" then
            for g in left:gmatch("[^:]+") do lg[#lg + 1] = g end
        end
        if right ~= "" then
            for g in right:gmatch("[^:]+") do rg[#rg + 1] = g end
        end
        local missing = 8 - #lg - #rg
        for _, g in ipairs(lg) do groups[#groups + 1] = g end
        for _ = 1, missing do groups[#groups + 1] = "0" end
        for _, g in ipairs(rg) do groups[#groups + 1] = g end
    else
        for g in str:gmatch("[^:]+") do groups[#groups + 1] = g end
    end

    local bytes = {}
    for _, g in ipairs(groups) do
        local val = tonumber(g, 16)
        bytes[#bytes + 1] = math.floor(val / 256)
        bytes[#bytes + 1] = val % 256
    end
    return bytes
end

-- ============================================================================
-- HELPER: Baca 16 byte IPv6 dari paket sebagai string
-- ============================================================================
function _bytes_to_ipv6(pkt, offset)
    local groups = {}
    for i = 0, 7 do
        local val = pkt:byte(offset + i * 2 + 1) * 256 + pkt:byte(offset + i * 2 + 2)
        groups[#groups + 1] = string.format("%x", val)
    end
    return table.concat(groups, ":")
end

-- ============================================================================
-- Meniru fungsi: ip-set -name [nama] -file [file]
-- ============================================================================
function smartdns_ip_set(name, filepath)
    smartdns_nmg[name] = newNMG()
    local file = io.open(filepath, "r")
    if file then
        for line in file:lines() do
            local mask = line:match("^%s*(.-)%s*$")
            if mask ~= "" and not mask:find("^#") then 
                smartdns_nmg[name]:addMask(mask) 
            end
        end
        file:close()
        infolog("smartdns: Loaded ip-set '" .. name .. "' from " .. filepath)
    else
        errlog("smartdns: Gagal membuka file ip-set untuk " .. name .. ": " .. filepath)
    end
end

-- ============================================================================
-- Meniru fungsi: domain-set -name [nama] -file [file]
-- ============================================================================
function smartdns_domain_set(name, filepath)
    smartdns_smn[name] = newSuffixMatchNode()
    local file = io.open(filepath, "r")
    if file then
        for line in file:lines() do
            local domain = line:match("^%s*(.-)%s*$")
            if domain ~= "" and not domain:find("^#") then 
                -- Hapus prefix *. jika user menuliskannya secara manual
                domain = domain:gsub("^%*%.", "")
                smartdns_smn[name]:add(newDNSName(domain)) 
            end
        end
        file:close()
        infolog("smartdns: Loaded domain-set '" .. name .. "' from " .. filepath)
    else
        errlog("smartdns: Gagal membuka file domain-set untuk " .. name .. ": " .. filepath)
    end
end

-- ============================================================================
-- Meniru fungsi: cname /domain/target
-- ============================================================================
function smartdns_cname(domain_pattern, target_cname)
    -- Menghapus prefix wildcard "-." atau "." khas SmartDNS jika disertakan oleh user
    local clean_domain = domain_pattern
    if clean_domain:sub(1, 2) == "-." then
        clean_domain = clean_domain:sub(3)
    elseif clean_domain:sub(1, 1) == "." then
        clean_domain = clean_domain:sub(2)
    end
    addAction(SuffixMatchNodeRule(clean_domain), SpoofCNAMEAction(target_cname))
    infolog("smartdns: CNAME rule added: *." .. clean_domain .. " -> " .. target_cname)
end

-- ============================================================================
-- Meniru fungsi: ip-rules ip-set:[ip_set] -ip-alias [target_ip(s)]
--
-- target_ips bisa berupa:
--   - String tunggal:  "172.64.87.224"
--   - Tabel/array:     {"172.64.52.159", "172.64.87.224"}
--
-- Otomatis mendeteksi IPv4 (A record) atau IPv6 (AAAA record) dari format IP.
-- ============================================================================
function smartdns_ip_rules_alias(ip_set_name, target_ips, exclude_domain_set)
    -- Pastikan ip-set sudah dideklarasikan
    if not smartdns_nmg[ip_set_name] then
        errlog("smartdns: Error - ip-set '" .. ip_set_name .. "' belum dibuat.")
        return
    end

    -- Normalisasi: jika string tunggal, bungkus dalam tabel
    if type(target_ips) == "string" then
        target_ips = {target_ips}
    end

    -- Deteksi IPv4 vs IPv6 berdasarkan format target IP pertama
    local is_ipv6 = target_ips[1]:find(":") ~= nil
    local dns_qtype = is_ipv6 and DNSQType.AAAA or DNSQType.A
    local record_len = is_ipv6 and 16 or 4

    -- Pre-parse semua target IP ke bentuk byte
    local targets_bytes = {}
    for _, ip in ipairs(target_ips) do
        if is_ipv6 then
            targets_bytes[#targets_bytes + 1] = _ipv6_to_bytes(ip)
        else
            local bytes = {}
            for octet in ip:gmatch("%d+") do
                bytes[#bytes + 1] = tonumber(octet)
            end
            targets_bytes[#targets_bytes + 1] = bytes
        end
    end

    local ip_type_str = is_ipv6 and "IPv6/AAAA" or "IPv4/A"
    infolog("smartdns: ip-rules alias [" .. ip_type_str .. "] ip-set:" .. ip_set_name 
            .. " -> " .. table.concat(target_ips, ", "))

    -- Rule Response: Inspeksi response dari upstream, rewrite jika cocok
    addResponseAction(AllRule(), LuaResponseAction(function(dr)
        -- Filter berdasarkan tipe query (A untuk IPv4, AAAA untuk IPv6)
        if dr.qtype ~= dns_qtype then 
            return DNSResponseAction.None, "" 
        end
        
        -- EXCLUDE LOGIC: domain di daftar exclude tidak di-alias
        if exclude_domain_set and smartdns_smn[exclude_domain_set] then
            if smartdns_smn[exclude_domain_set]:check(dr.qname) then
                return DNSResponseAction.None, ""
            end
        end

        -- Parse paket response
        local pkt = dr:getContent()
        local overlay = newDNSPacketOverlay(pkt)
        local record_count = overlay:getRecordsCountInSection(DNSSection.Answer)

        -- Fase 1: Cek apakah ada record yang cocok dengan ip-set
        local needs_rewrite = false
        for i = 0, record_count - 1 do
            local rec = overlay:getRecord(i)
            if rec.type == dns_qtype and rec.contentLength == record_len then
                local ip_str
                if is_ipv6 then
                    ip_str = _bytes_to_ipv6(pkt, rec.contentOffset)
                else
                    ip_str = string.format("%d.%d.%d.%d", 
                        pkt:byte(rec.contentOffset + 1), 
                        pkt:byte(rec.contentOffset + 2), 
                        pkt:byte(rec.contentOffset + 3), 
                        pkt:byte(rec.contentOffset + 4))
                end
                
                local addr = newCA(ip_str)
                if addr and smartdns_nmg[ip_set_name]:match(addr) then
                    needs_rewrite = true
                    break
                end
            end
        end

        -- Fase 2: Jika ada yang cocok, rewrite semua record yang matching
        if needs_rewrite then
            -- Konversi paket ke tabel byte untuk diedit
            local pkt_bytes = {pkt:byte(1, #pkt)}
            local target_idx = 1  -- Round-robin index untuk multiple targets
            
            for i = 0, record_count - 1 do
                local rec = overlay:getRecord(i)
                if rec.type == dns_qtype and rec.contentLength == record_len then
                    -- Pilih target IP (round-robin jika lebih dari 1)
                    local tb = targets_bytes[target_idx]
                    
                    -- Tulis ulang byte-byte IP di paket
                    for b = 1, record_len do
                        pkt_bytes[rec.contentOffset + b] = tb[b]
                    end
                    
                    -- Maju ke target berikutnya (round-robin)
                    target_idx = target_idx + 1
                    if target_idx > #targets_bytes then
                        target_idx = 1
                    end
                end
            end
            
            -- Rebuild paket dari byte array
            local parts = {}
            for _, b in ipairs(pkt_bytes) do
                parts[#parts + 1] = string.char(b)
            end
            dr:setContent(table.concat(parts))
        end
        
        return DNSResponseAction.None, ""
    end))
end
