-- ============================================================================
-- SMARTDNS COMPATIBILITY PLUGIN FOR DNSDIST 2.x
-- Menyediakan fungsi: smartdns_ip_set, smartdns_domain_set,
--                     smartdns_cname, smartdns_ip_rules_alias
-- Speed Check: Asynchronous TCP probing untuk semua domain (ala SmartDNS)
-- ============================================================================

-- Variabel penampung untuk NetmaskGroup (ip-set) dan SuffixMatchNode (domain-set)
smartdns_nmg = {}
smartdns_smn = {}

-- ============================================================================
-- SPEED CHECK MODULE (Asynchronous, All Domains)
-- Membutuhkan: lua-socket (apt install lua-socket / yum install lua-socket)
-- Jika tidak terinstal, speed check dinonaktifkan secara otomatis (graceful)
-- ============================================================================
local _has_socket, _socket = pcall(require, "socket")

-- Cache hasil speed check: { domain = { ip, expires_at } }
local _speed_cache = {}
-- Antrian probing: { { domain, ips[], timestamp } }
local _probe_queue = {}
-- Sesi socket aktif (non-blocking): { { sock, ip, domain, start_time } }
local _active_sockets = {}

-- Konfigurasi Speed Check (dapat di-override di dnsdist.conf sebelum dofile())
SPEEDCHECK_ENABLED     = true       -- Aktifkan/nonaktifkan fitur ini
SPEEDCHECK_MODE        = "fastest-ip" -- "fastest-ip" (reorder) atau "fastest-response" (overwrite)
SPEEDCHECK_TIMEOUT_MS  = 200        -- Timeout TCP connect (milidetik)
SPEEDCHECK_PORTS       = {80, 443}  -- Port yang diuji
SPEEDCHECK_MAX_IPS     = 6          -- Maks IP yang dites per domain
SPEEDCHECK_MAX_RESPONSE= 2          -- Maksimal jumlah IP Juara yang dikembalikan (digunakan oleh fastest-response)
SPEEDCHECK_CACHE_TTL   = 300        -- Detik menyimpan hasil di memori
SPEEDCHECK_QUEUE_LIMIT = 200        -- Maks antrian domain sekaligus

-- Konfigurasi Parallel Upstream Aggregation
PARALLEL_UPSTREAMS     = {}         -- Array IP upstream, contoh: {"8.8.8.8", "1.1.1.1"}
local _parallel_queue = {}          -- Antrian domain yang perlu diresolve paralel
local _parallel_sockets = {}        -- Socket UDP aktif untuk query DNS

if not _has_socket then
    warnlog("[SmartDist] lua-socket tidak ditemukan! Speed Check DINONAKTIFKAN.")
    warnlog("[SmartDist] Install: apt-get install lua-socket  (atau yum install lua-socket)")
    SPEEDCHECK_ENABLED = false
else
    infolog("[SmartDist] lua-socket OK. Speed Check AKTIF untuk semua domain.")
end

-- Helper: Generate Raw DNS A Query Packet (UDP)
local function _build_dns_a_query(domain)
    local id = math.random(0, 65535)
    local packet = string.char(math.floor(id / 256), id % 256) ..
                   string.char(0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    for part in domain:gmatch("[^%.]+") do
        packet = packet .. string.char(#part) .. part
    end
    packet = packet .. string.char(0, 0, 1, 0, 1) -- QTYPE A(1), QCLASS IN(1)
    return packet, id
end

-- Helper: waktu sekarang dalam detik
local function _now()
    if _has_socket then return _socket.gettime() end
    return os.time()
end

-- Ambil cached IP tercepat untuk sebuah domain (nil jika belum ada/expired)
local function _get_fastest(domain)
    local entry = _speed_cache[domain]
    if entry and _now() < entry.expires_at then
        return entry.ips
    end
    _speed_cache[domain] = nil
    return nil
end

-- Tambahkan domain ke antrian probing jika belum ada
local function _enqueue(domain, ips)
    if not SPEEDCHECK_ENABLED then return end
    if #_probe_queue >= SPEEDCHECK_QUEUE_LIMIT then return end
    -- Cek duplikat
    for _, item in ipairs(_probe_queue) do
        if item.domain == domain then return end
    end
    -- Batasi jumlah IP
    local limited = {}
    for i = 1, math.min(#ips, SPEEDCHECK_MAX_IPS) do
        limited[i] = ips[i]
    end
    table.insert(_probe_queue, { domain = domain, ips = limited })
end

-- Fungsi maintenance() dijalankan DnsDist setiap ~1 detik
-- Ini adalah "background worker" kita
function maintenance()
    if not SPEEDCHECK_ENABLED then return end

    local timeout_sec = SPEEDCHECK_TIMEOUT_MS / 1000
    local now = _now()

    -- [1] Periksa socket aktif: siapa yang sudah konek?
    local still_active = {}
    for _, sess in ipairs(_active_sockets) do
        if (now - sess.start_time) > timeout_sec then
            -- Timeout: buang
            pcall(function() sess.sock:close() end)
        else
            local res, err = sess.sock:connect(sess.ip, sess.port)
            -- luasocket mengembalikan 1 saat koneksi non-blocking berhasil
            if res == 1 or (not err) or err == "already connected" then
                -- MENANG! IP ini cepat! Masukkan ke array IP pemenang.
                local latency_ms = math.floor((now - sess.start_time) * 1000)
                local entry = _speed_cache[sess.domain]
                if not entry then
                    entry = { ips = {}, expires_at = now + SPEEDCHECK_CACHE_TTL }
                    _speed_cache[sess.domain] = entry
                end
                
                local is_dup = false
                for _, existing_ip in ipairs(entry.ips) do
                    if existing_ip == sess.ip then is_dup = true break end
                end
                
                if not is_dup and #entry.ips < (SPEEDCHECK_MAX_RESPONSE or 2) then
                    table.insert(entry.ips, sess.ip)
                    infolog(string.format("[SmartDist] Fastest Rank #%d for %s -> %s (%dms)",
                        #entry.ips, sess.domain, sess.ip, latency_ms))
                end
                pcall(function() sess.sock:close() end)
            else
                -- Masih menunggu (TIMEOUT atau belum selesai)
                still_active[#still_active + 1] = sess
            end
        end
    end
    _active_sockets = still_active

    -- [2] Ambil item dari antrian, buka socket non-blocking baru
    if #_probe_queue > 0 then
        local item = table.remove(_probe_queue, 1)
        for _, ip in ipairs(item.ips) do
            for _, port in ipairs(SPEEDCHECK_PORTS) do
                local ok, sock = pcall(function()
                    local s = _socket.tcp()
                    s:settimeout(0)  -- NON-BLOCKING
                    s:connect(ip, port)
                    return s
                end)
                if ok and sock then
                    table.insert(_active_sockets, {
                        sock = sock,
                        ip = ip,
                        port = port,
                        domain = item.domain,
                        start_time = now
                    })
                end
            end
        end
    end

    -- [3] PARALLEL UPSTREAM AGGREGATION: Cek response UDP DNS
    local still_parallel = {}
    for _, sess in ipairs(_parallel_sockets) do
        if (now - sess.start_time) > 1 then -- 1 sec timeout for DNS
            pcall(function() sess.sock:close() end)
        else
            local data, err = sess.sock:receive()
            if data then
                -- Parse DNS Response secara manual menggunakan DnsDist Overlay
                pcall(function()
                    local overlay = newDNSPacketOverlay(data)
                    local count = overlay:getRecordsCountInSection(DNSSection.Answer)
                    local ips = {}
                    for i = 0, count - 1 do
                        local rec = overlay:getRecord(i)
                        if rec.type == DNSQType.A and rec.contentLength == 4 then
                            local ip_str = string.format("%d.%d.%d.%d",
                                data:byte(rec.contentOffset + 1), data:byte(rec.contentOffset + 2),
                                data:byte(rec.contentOffset + 3), data:byte(rec.contentOffset + 4))
                            ips[#ips + 1] = ip_str
                        end
                    end
                    if #ips > 0 then
                        -- Gabungkan IP dari upstream ini ke dalam antrian speedcheck!
                        _enqueue(sess.domain, ips)
                        infolog(string.format("[SmartDist] Parallel Upstream %s returned %d IPs for %s", sess.upstream, #ips, sess.domain))
                    end
                end)
                pcall(function() sess.sock:close() end)
            else
                still_parallel[#still_parallel + 1] = sess
            end
        end
    end
    _parallel_sockets = still_parallel

    -- [4] PARALLEL UPSTREAM AGGREGATION: Kirim UDP Query
    if #_parallel_queue > 0 then
        local domain = table.remove(_parallel_queue, 1)
        local query_pkt, id = _build_dns_a_query(domain)
        for _, upstream in ipairs(PARALLEL_UPSTREAMS) do
            local ok, sock = pcall(function()
                local s = _socket.udp()
                s:settimeout(0)
                s:setpeername(upstream, 53)
                s:send(query_pkt)
                return s
            end)
            if ok and sock then
                table.insert(_parallel_sockets, {
                    sock = sock,
                    domain = domain,
                    upstream = upstream,
                    start_time = now
                })
            end
        end
    end
end

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
    addAction(SuffixMatchNodeRule(clean_domain), SpoofCNAMEAction(target_cname), {name="CNAME: " .. target_cname})
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

    -- Siapkan fungsi helper untuk membangun targets_bytes
    local function build_targets_bytes(ips)
        local is_ipv6 = ips[1]:find(":") ~= nil
        local bytes_list = {}
        for _, ip in ipairs(ips) do
            if is_ipv6 then
                bytes_list[#bytes_list + 1] = _ipv6_to_bytes(ip)
            else
                local bytes = {}
                for octet in ip:gmatch("%d+") do
                    bytes[#bytes + 1] = tonumber(octet)
                end
                bytes_list[#bytes_list + 1] = bytes
            end
        end
        return bytes_list
    end

    -- Deteksi IPv4 vs IPv6 berdasarkan format target IP pertama
    local is_ipv6 = target_ips[1]:find(":") ~= nil
    local dns_qtype = is_ipv6 and DNSQType.AAAA or DNSQType.A
    local record_len = is_ipv6 and 16 or 4

    -- Pre-parse semua target IP default ke bentuk byte
    local default_targets_bytes = build_targets_bytes(target_ips)

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
            local active_targets_bytes = default_targets_bytes

            for i = 0, record_count - 1 do
                local rec = overlay:getRecord(i)
                if rec.type == dns_qtype and rec.contentLength == record_len then
                    -- Pilih target IP (round-robin jika lebih dari 1)
                    local tb = active_targets_bytes[target_idx]
                    
                    -- Tulis ulang byte-byte IP di paket
                    for b = 1, record_len do
                        pkt_bytes[rec.contentOffset + b] = tb[b]
                    end
                    
                    -- Maju ke target berikutnya (round-robin)
                    target_idx = target_idx + 1
                    if target_idx > #active_targets_bytes then
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
    end), {name="IP Alias: " .. ip_set_name .. " (" .. (is_ipv6 and "IPv6" or "IPv4") .. ")"})
end

-- ============================================================================
-- SPEED CHECK: Global Response Hook untuk SEMUA Domain
-- Panggil fungsi ini SATU KALI di bagian akhir dnsdist.conf Anda:
--   smartdns_enable_speedcheck()
-- ============================================================================
function smartdns_enable_speedcheck()
    if not SPEEDCHECK_ENABLED then
        warnlog("[SmartDist] Speed Check tidak aktif (lua-socket tidak tersedia).")
        return
    end

    -- Auto-populate PARALLEL_UPSTREAMS dari newServer() jika kosong
    if PARALLEL_UPSTREAMS == nil or #PARALLEL_UPSTREAMS == 0 then
        PARALLEL_UPSTREAMS = {}
        local srvs = getServers()
        for _, s in ipairs(srvs) do
            -- s:getName() usually returns something like "8.8.8.8:53" or "8.8.8.8"
            local name = s:getName()
            local ip = name:match("^([^:]+)") -- Ambil IP saja sebelum titik dua
            if ip then table.insert(PARALLEL_UPSTREAMS, ip) end
        end
        infolog("[SmartDist] Auto-loaded " .. #PARALLEL_UPSTREAMS .. " upstreams for parallel aggregation.")
    end

    addResponseAction(AllRule(), LuaResponseAction(function(dr)
        if dr.qtype ~= DNSQType.A and dr.qtype ~= DNSQType.AAAA then
            return DNSResponseAction.None, ""
        end

        local domain = dr.qname:toString():gsub("%.$", "")
        local pkt = dr:getContent()
        local overlay = newDNSPacketOverlay(pkt)
        local record_count = overlay:getRecordsCountInSection(DNSSection.Answer)

        -- Kumpulkan semua IP dari response
        local ips = {}
        local record_len = (dr.qtype == DNSQType.AAAA) and 16 or 4
        for i = 0, record_count - 1 do
            local rec = overlay:getRecord(i)
            if rec.type == dr.qtype and rec.contentLength == record_len then
                local ip_str
                if dr.qtype == DNSQType.AAAA then
                    ip_str = _bytes_to_ipv6(pkt, rec.contentOffset)
                else
                    ip_str = string.format("%d.%d.%d.%d",
                        pkt:byte(rec.contentOffset + 1),
                        pkt:byte(rec.contentOffset + 2),
                        pkt:byte(rec.contentOffset + 3),
                        pkt:byte(rec.contentOffset + 4))
                end
                if ip_str then ips[#ips + 1] = ip_str end
            end
        end

        -- Jika hanya 1 IP, tidak perlu speedcheck
        if #ips < 2 then return DNSResponseAction.None, "" end

        local fastest_ips = _get_fastest(domain)
        if fastest_ips and #fastest_ips > 0 then
            -- Ada cached fastest IPs: rewrite DNS packet
            local pkt_bytes = {pkt:byte(1, #pkt)}
            
            -- Convert IPs ke array of byte arrays
            local target_bytes_list = {}
            for _, fip in ipairs(fastest_ips) do
                local tbytes = {}
                if dr.qtype == DNSQType.AAAA then
                    tbytes = _ipv6_to_bytes(fip)
                else
                    for octet in fip:gmatch("%d+") do
                        tbytes[#tbytes + 1] = tonumber(octet)
                    end
                end
                table.insert(target_bytes_list, tbytes)
            end

            if SPEEDCHECK_MODE == "fastest-ip" then
                -- Mode fastest-ip: Reorder (Tukar IP tercepat #1 ke urutan paling atas)
                local first_rec_offset = nil
                local fastest_rec_offset = nil
                local top_target = target_bytes_list[1]
                
                for i = 0, record_count - 1 do
                    local rec = overlay:getRecord(i)
                    if rec.type == dr.qtype and rec.contentLength == record_len then
                        if not first_rec_offset then first_rec_offset = rec.contentOffset end
                        
                        -- Cek apakah record ini adalah IP tercepat #1 kita
                        local is_match = true
                        for b = 1, record_len do
                            if pkt_bytes[rec.contentOffset + b] ~= top_target[b] then
                                is_match = false break
                            end
                        end
                        if is_match then fastest_rec_offset = rec.contentOffset end
                    end
                end

                -- Lakukan Swap Bytes
                if first_rec_offset and fastest_rec_offset and first_rec_offset ~= fastest_rec_offset then
                    for b = 1, record_len do
                        local temp = pkt_bytes[first_rec_offset + b]
                        pkt_bytes[first_rec_offset + b] = pkt_bytes[fastest_rec_offset + b]
                        pkt_bytes[fastest_rec_offset + b] = temp
                    end
                end
            else
                -- Mode fastest-response: Overwrite semua record dengan IP terbaik secara Round-Robin
                local fip_index = 1
                for i = 0, record_count - 1 do
                    local rec = overlay:getRecord(i)
                    if rec.type == dr.qtype and rec.contentLength == record_len then
                        local current_target = target_bytes_list[fip_index]
                        for b = 1, record_len do
                            pkt_bytes[rec.contentOffset + b] = current_target[b]
                        end
                        -- Round robin ke IP juara berikutnya
                        fip_index = fip_index + 1
                        if fip_index > #target_bytes_list then fip_index = 1 end
                    end
                end
            end

            local parts = {}
            for _, b in ipairs(pkt_bytes) do parts[#parts + 1] = string.char(b) end
            dr:setContent(table.concat(parts))
        else
            -- Belum ada cache: lempar ke antrian probing background
            _enqueue(domain, ips)
            
            -- Jika Parallel Upstreams diaktifkan, lempar juga ke antrian resolusi paralel!
            if PARALLEL_UPSTREAMS and #PARALLEL_UPSTREAMS > 0 then
                -- Cek apakah sudah ada di queue untuk mencegah duplikasi
                local exists = false
                for _, d in ipairs(_parallel_queue) do
                    if d == domain then exists = true break end
                end
                if not exists then table.insert(_parallel_queue, domain) end
            end
        end

        return DNSResponseAction.None, ""
    end), {name="SmartDist Speed Check Hook"})

    infolog("[SmartDist] Speed Check hook aktif untuk SEMUA domain.")
end
