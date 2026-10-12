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
local _probe_queue      = {}
local _probe_queue_set  = {} -- O(1) lookup
local _probe_pending    = {} -- domain -> daftar IP kandidat yang menunggu digabung

-- Domain yang sudah di-rewrite oleh ip_rules_alias.
local _aliased_domains = {}

-- State untuk Garbage Collection
local _sweep_key = nil
local _last_alias_clear = 0

-- Konfigurasi Speed Check (dapat di-override di dnsdist.conf sebelum dofile())
SPEEDCHECK_ENABLED     = true       -- Aktifkan/nonaktifkan fitur ini
SPEEDCHECK_MODE        = "fastest-ip" -- "fastest-ip" (reorder) atau "fastest-response" (overwrite)
SPEEDCHECK_TIMEOUT_MS  = 200        -- Timeout TCP connect (milidetik)
SPEEDCHECK_PORTS       = {80, 443}  -- Port yang diuji
SPEEDCHECK_MAX_IPS     = 6          -- Maks IP yang dites per domain
SPEEDCHECK_MAX_RESPONSE= 2          -- Maksimal jumlah IP Juara yang dikembalikan (digunakan oleh fastest-response)
SPEEDCHECK_CACHE_TTL   = 300        -- Detik menyimpan hasil di memori
SPEEDCHECK_QUEUE_LIMIT = 200        -- Maks antrian domain sekaligus
SPEEDCHECK_PROBE_WINDOW_MS = 50     -- Jendela ukur TCP per domain per tick (ms). maintenance() dipanggil ~1x/detik.
SPEEDCHECK_MAX_MEMORY_MB= 50        -- Batas maksimal RAM (Megabyte) untuk plugin Lua sebelum membuang cache lama

-- Konfigurasi Parallel Upstream Aggregation
-- Secara default SmartDist menggunakan newServer() yang sudah dikonfigurasi,
-- tetapi HANYA memilih server yang CEPAT (latency di bawah threshold).
-- Jika ingin menentukan upstream secara manual, isi array ini:
--   PARALLEL_UPSTREAMS = {"8.8.8.8", "1.1.1.1"}
-- Jika kosong, akan auto-detect dari newServer() dengan filter latency.
PARALLEL_UPSTREAMS             = {}    -- Kosong = auto dari newServer()
PARALLEL_UPSTREAM_MAX_LATENCY  = 300   -- Skip upstream jika latency > ms ini
PARALLEL_UPSTREAM_REFRESH_SEC  = 30    -- Seberapa sering rebuild list upstream (detik)
PARALLEL_MAX_UPSTREAMS         = 5     -- Maks jumlah upstream yang dipakai sekaligus
SPEEDCHECK_MAX_PAR_SOCKETS    = 30    -- Batas socket UDP parallel
local _parallel_queue      = {}        -- Antrian domain yang perlu diresolve paralel
local _parallel_queue_set  = {}        -- Hash map O(1) untuk duplikat
local _parallel_sockets    = {}        -- Socket UDP aktif untuk query DNS
local _active_upstreams    = {}        -- List upstream aktif setelah filter latency
local _last_upstream_refresh = -1e18   -- -inf efektif: paksa refresh pertama di tick pertama

if not _has_socket then
    warnlog("[SmartDist] lua-socket tidak ditemukan! Speed Check DINONAKTIFKAN.")
    warnlog("[SmartDist] Install: apt-get install lua-socket  (atau yum install lua-socket)")
    SPEEDCHECK_ENABLED = false
else
    infolog("[SmartDist] lua-socket OK. Speed Check AKTIF untuk semua domain.")
end

-- ============================================================================
-- REKAM ADDRESS newServer().
-- PENTING: getName() mengembalikan NAME server, bukan IP. Memakai name untuk
-- setpeername/connect memicu DNS lookup BLOCKING di main thread dnsdist
-- (terukur ~4 detik per nama) dan membuat query macet. Kita bungkus
-- newServer() untuk menangkap address asli.
-- ============================================================================
_ns_addr_by_name  = {}
_ns_addr_by_index = {}
do
    local _origNewServer = newServer
    if type(_origNewServer) == "function" then
        newServer = function(...)
            local a = ...
            local addr, nm
            if type(a) == "string" then
                addr = a
            elseif type(a) == "table" then
                addr = a.address
                nm = a.name
            end
            local r = _origNewServer(...)
            if addr then
                -- Buang bracket IPv6 dan port
                local host = addr:match("^%[([^%]]+)%]") or addr:match("^([^:]+)")
                if host then
                    table.insert(_ns_addr_by_index, { name = nm or "", ip = host })
                    if nm and nm ~= "" then _ns_addr_by_name[nm] = host end
                end
            end
            return r
        end
    end
end

-- Resolusi IP server: name-map dulu, lalu positional (dengan validasi nama).
local function _resolve_server_ip(s, idx)
    local nm = s:getName()
    if nm and nm ~= "" and _ns_addr_by_name[nm] then
        return _ns_addr_by_name[nm]
    end
    local rec = _ns_addr_by_index[idx]
    if rec and rec.name == (nm or "") then return rec.ip end
    return nil
end

-- Hanya izinkan literal IP (IPv4/IPv6). Hostname akan memicu DNS blocking.
local function _is_ip_literal(v)
    if type(v) ~= "string" then return false end
    if v:match("^%d+%.%d+%.%d+%.%d+$") then return true end
    if v:find(":") and v:match("^[0-9a-fA-F:]+$") then return true end
    return false
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
    if entry then
        if _now() < entry.expires_at then
            return entry.ips
        else
            _speed_cache[domain] = nil
        end
    end
    return nil
end

-- Tambahkan domain ke antrian probing. Jika domain SUDAH menunggu, IP baru
-- digabungkan ke kandidat yang ada (hasil dari beberapa recursor sekaligus).
local function _enqueue(domain, ips)
    if not SPEEDCHECK_ENABLED then return end

    -- Merge: gabungkan kandidat dari semua recursor, dedup, batasi jumlah.
    local pend = _probe_pending[domain]
    if pend then
        for _, ip in ipairs(ips) do
            if #pend >= SPEEDCHECK_MAX_IPS then break end
            local dup = false
            for _, e in ipairs(pend) do
                if e == ip then dup = true break end
            end
            if not dup then pend[#pend + 1] = ip end
        end
        return
    end

    if #_probe_queue >= SPEEDCHECK_QUEUE_LIMIT then return end

    -- Batasi jumlah IP
    local limited = {}
    for i = 1, math.min(#ips, SPEEDCHECK_MAX_IPS) do
        limited[i] = ips[i]
    end

    _probe_pending[domain] = limited
    table.insert(_probe_queue, { domain = domain })
    _probe_queue_set[domain] = true
end

-- Fungsi maintenance() dijalankan DnsDist setiap ~1 detik
-- Ini adalah "background worker" kita
-- PENTING: Harus cepat! DnsDist memblokir pemrosesan query saat ini berjalan.
local _MAINTENANCE_BUDGET_SEC = 0.030  -- Maks 30ms per tick

function maintenance()
    if not SPEEDCHECK_ENABLED then return end

    local timeout_sec = SPEEDCHECK_TIMEOUT_MS / 1000
    local now = _now()
    local budget_start = now

    local function over_budget()
        return (_now() - budget_start) > _MAINTENANCE_BUDGET_SEC
    end

    -- [0] SMART UPSTREAM REFRESH: Rebuild list upstream dari newServer() secara berkala.
    -- Hanya upstream yang UP dan latency-nya di bawah threshold yang dipilih.
    if (now - _last_upstream_refresh) >= (PARALLEL_UPSTREAM_REFRESH_SEC or 30) then
        _last_upstream_refresh = now
        local max_lat = PARALLEL_UPSTREAM_MAX_LATENCY or 300
        local max_up  = PARALLEL_MAX_UPSTREAMS or 5

        -- Jika user sudah set manual, pakai itu
        if PARALLEL_UPSTREAMS and #PARALLEL_UPSTREAMS > 0 then
            _active_upstreams = PARALLEL_UPSTREAMS
        else
            -- Auto dari newServer(): ambil semua yang UP, sort by latency, ambil top N
            local candidates = {}
            local ok, srvs = pcall(getServers)
            if ok and srvs then
                for idx, s in ipairs(srvs) do
                    local lat = s:getLatency()
                    local up  = s:isUp()
                    -- Terima server yang UP. Latency 0 = belum terukur (mis. saat warmup);
                    -- jangan dibuang, hanya diurutkan ke belakang, agar agregasi tidak
                    -- menunggu satu siklus refresh penuh.
                    if up and lat <= max_lat then
                        local ip = _resolve_server_ip(s, idx)
                        if ip and _is_ip_literal(ip) then
                            table.insert(candidates, { ip = ip, lat = lat })
                        end
                    end
                end
            end
            -- Sort ascending by latency. lat==0 (belum terukur) dianggap paling lambat,
            -- supaya server yang sudah terbukti cepat tetap diprioritaskan.
            table.sort(candidates, function(a, b)
                local la = (a.lat > 0) and a.lat or math.huge
                local lb = (b.lat > 0) and b.lat or math.huge
                return la < lb
            end)
            -- Ambil hanya top N
            _active_upstreams = {}
            for i = 1, math.min(#candidates, max_up) do
                table.insert(_active_upstreams, candidates[i].ip)
            end
            if #_active_upstreams > 0 then
                local names = table.concat(_active_upstreams, ", ")
                infolog(string.format("[SmartDist] Parallel: %d upstream aktif (lat <=%.0fms): %s",
                    #_active_upstreams, max_lat, names))
            else
                -- Belum ada upstream UP (warmup awal / semua server down).
                -- Paksa percobaan refresh di tick berikutnya, jangan tunggu siklus penuh.
                _last_upstream_refresh = -1e18
            end
        end
    end

    -- Cek budget sebelum mulai [1] yang berat
    if over_budget() then return end

    -- [1] TCP PROBE (selesai dalam satu tick)
    -- PENTING: dnsdist memanggil maintenance() hanya ~1x per detik, sehingga
    -- socket non-blocking lintas-tick SELALU dibuang sebagai timeout sebelum
    -- sempat di-poll. Pengukuran harus selesai dalam tick ini, memakai
    -- socket.select() dengan slice 1ms. Kandidat yang terkoneksi lebih dulu
    -- dianggap lebih cepat.
    local probe_window = math.min(timeout_sec, (SPEEDCHECK_PROBE_WINDOW_MS or 50) / 1000)
    local probed_domains = 0
    while #_probe_queue > 0 and probed_domains < 2 and not over_budget() do
        probed_domains = probed_domains + 1
        local item = table.remove(_probe_queue, 1)
        _probe_queue_set[item.domain] = nil
        local ips = _probe_pending[item.domain] or {}
        _probe_pending[item.domain] = nil

        -- Buka socket untuk semua kandidat IP:port sekaligus
        local probe_start = _now()
        local pending = {}
        for _, ip in ipairs(ips) do
            for _, port in ipairs(SPEEDCHECK_PORTS) do
                pcall(function()
                    local s = _socket.tcp()
                    s:settimeout(0)
                    s:connect(ip, port)
                    pending[#pending + 1] = { sock = s, ip = ip }
                end)
            end
        end

        -- Tunggu koneksi selesai: slice 1ms, dibatasi probe_window
        local wait_until = probe_start + probe_window
        while #pending > 0 and _now() < wait_until do
            local wset = {}
            for i = 1, #pending do wset[i] = pending[i].sock end
            local ok_sel, _, writable = pcall(_socket.select, nil, wset, 0.001)
            if ok_sel and writable then
                for _, sready in ipairs(writable) do
                    for i = #pending, 1, -1 do
                        local p = pending[i]
                        if p.sock == sready then
                            -- getpeername() memastikan ini koneksi sukses,
                            -- bukan writable karena koneksi ditolak.
                            local ok_peer, peer = pcall(function() return p.sock:getpeername() end)
                            if ok_peer and peer then
                                local latency_ms = math.floor((_now() - probe_start) * 1000)
                                local entry = _speed_cache[item.domain]
                                if not entry then
                                    -- CEK HARD LIMIT MEMORY (Berdasarkan RAM sesungguhnya)
                                    -- collectgarbage("count") mengembalikan ukuran RAM Lua dalam Kilobyte
                                    if (collectgarbage("count") / 1024) > (SPEEDCHECK_MAX_MEMORY_MB or 50) then
                                        -- Eviction: buang 1 elemen pseudo-acak dari memori untuk memberi ruang
                                        local k, _ = next(_speed_cache)
                                        if k then _speed_cache[k] = nil end
                                    end
                                    entry = { ips = {}, expires_at = _now() + SPEEDCHECK_CACHE_TTL }
                                    _speed_cache[item.domain] = entry
                                end

                                local is_dup = false
                                for _, existing_ip in ipairs(entry.ips) do
                                    if existing_ip == p.ip then is_dup = true break end
                                end

                                if not is_dup and #entry.ips < (SPEEDCHECK_MAX_RESPONSE or 2) then
                                    table.insert(entry.ips, p.ip)
                                    infolog(string.format("[SmartDist] Fastest Rank #%d for %s -> %s (%dms)",
                                        #entry.ips, item.domain, p.ip, latency_ms))
                                    -- PERHATIAN: DnsDist expungeByName() TIDAK BOLEH digunakan di sini.
                                    -- expungeByName melakukan iterasi (O(N)) ke SEMUA isi cache.
                                    -- Jika cache ada jutaan, ini akan membuat DnsDist FREEZE selama
                                    -- beberapa detik sehingga SEMUA health check ping akan timeout serentak!
                                end
                            end
                            pcall(function() p.sock:close() end)
                            table.remove(pending, i)
                        end
                    end
                end
            end
        end

        -- Sisa yang tidak terkoneksi dalam window: tutup
        for _, p in ipairs(pending) do
            pcall(function() p.sock:close() end)
        end
    end

    -- [3] PARALLEL UPSTREAM AGGREGATION: Cek response UDP DNS
    -- Hanya berjalan jika ada upstream aktif (setelah filter latency)
    if #_active_upstreams > 0 then
        local still_parallel = {}
        for _, sess in ipairs(_parallel_sockets) do
            -- Baca dulu, baru cek timeout: data bisa tiba tepat di tick yang
            -- sama ketika socket melewati batas umur. Menutup sebelum membaca
            -- membuat balasan recursor hilang.
            local data, err = sess.sock:receive()
            if data then
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
                        _enqueue(sess.domain, ips)
                    end
                end)
                pcall(function() sess.sock:close() end)
            elseif (now - sess.start_time) > 2 then
                pcall(function() sess.sock:close() end)
            else
                still_parallel[#still_parallel + 1] = sess
            end
        end
        _parallel_sockets = still_parallel

        -- [4] Kirim UDP Query ke upstream aktif (max 1 domain per tick, max cap socket)
        if #_parallel_queue > 0 and #_parallel_sockets < (SPEEDCHECK_MAX_PAR_SOCKETS or 30) then
            local domain = table.remove(_parallel_queue, 1)
            if domain then
                _parallel_queue_set[domain] = nil
                local query_pkt = _build_dns_a_query(domain)
                for _, upstream in ipairs(_active_upstreams) do
                    -- SANITY: hanya literal IP. Hostname memicu DNS lookup blocking.
                    if _is_ip_literal(upstream) then
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
        end
    end

    -- [5] MEMORY GARBAGE COLLECTION
    -- 5a. Hapus cache speed check yang sudah basi (Sweep 50 entry per tick agar tidak blokir thread)
    local sweep_count = 0
    while sweep_count < 50 do
        local k, v = next(_speed_cache, _sweep_key)
        if k == nil then
            _sweep_key = nil -- Ulang dari awal tabel jika sudah mencapai akhir
            break
        end
        local next_k = k
        if now > v.expires_at then
            _speed_cache[k] = nil
        end
        _sweep_key = next_k
        sweep_count = sweep_count + 1
    end

    -- 5b. Bersihkan tabel _aliased_domains setiap 1 jam sekali agar tidak melembung
    if (now - _last_alias_clear) > 3600 then
        _aliased_domains = {}
        _last_alias_clear = now
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
-- HELPER: Sisipkan record A/AAAA agregasi sesudah section Answer.
-- Aman hanya jika: NSCOUNT==0, Additional kosong/hanya OPT (type 41),
-- dan Answer tidak memuat CNAME/DNAME (owner record bukan lagi qname).
-- Di luar kondisi itu, mengembalikan nil supaya paket tidak rusak.
-- Mengembalikan pkt_bytes baru, atau nil.
-- ============================================================================
function _smartdns_append_answer_records(pkt, pkt_bytes, qtype, record_len, ips, max_add)
    local ok, overlay = pcall(newDNSPacketOverlay, pkt)
    if not ok or overlay == nil then return nil end
    local an_count = overlay:getRecordsCountInSection(DNSSection.Answer)
    if an_count == 0 then return nil end

    -- Header counts (1-based): ANCOUNT 7-8, NSCOUNT 9-10, ARCOUNT 11-12
    local nscount = pkt:byte(9) * 256 + pkt:byte(10)
    if nscount ~= 0 then return nil end
    local arcount = pkt:byte(11) * 256 + pkt:byte(12)

    -- Additional hanya boleh OPT
    for i = an_count, an_count + arcount - 1 do
        local rec = overlay:getRecord(i)
        if rec == nil or rec.type ~= 41 then return nil end
    end

    local present = {}
    local end_ans = 12
    for i = 0, an_count - 1 do
        local rec = overlay:getRecord(i)
        if rec.type == 5 or rec.type == 39 then return nil end -- CNAME/DNAME
        local e = rec.contentOffset + rec.contentLength
        if e > end_ans then end_ans = e end
        if rec.type == qtype and rec.contentLength == record_len then
            local key
            if qtype == DNSQType.AAAA then
                key = _bytes_to_ipv6(pkt, rec.contentOffset)
            else
                key = string.format("%d.%d.%d.%d",
                    pkt:byte(rec.contentOffset + 1), pkt:byte(rec.contentOffset + 2),
                    pkt:byte(rec.contentOffset + 3), pkt:byte(rec.contentOffset + 4))
            end
            if key then present[key] = true end
        end
    end

    local extra = {}
    local added = 0
    for _, fip in ipairs(ips) do
        if added >= (max_add or 2) then break end
        if not present[fip] then
            local tb = {}
            if qtype == DNSQType.AAAA then
                tb = _ipv6_to_bytes(fip)
            else
                for octet in fip:gmatch("%d+") do tb[#tb + 1] = tonumber(octet) end
            end
            if #tb == record_len then
                -- name ptr(2) type(2) class(2) ttl(4) rdlength(2) rdata(len)
                local rec_bytes = {0xC0, 0x0C, 0x00, qtype, 0x00, 0x01,
                                   0x00, 0x00, 0x00, 0x3C, 0x00, record_len}
                for b = 1, record_len do rec_bytes[#rec_bytes + 1] = tb[b] end
                for b = 1, #rec_bytes do extra[#extra + 1] = rec_bytes[b] end
                present[fip] = true
                added = added + 1
            end
        end
    end

    if added == 0 then return nil end

    local out = {}
    for i = 1, end_ans do out[i] = pkt_bytes[i] end
    for i = 1, #extra do out[end_ans + i] = extra[i] end
    for i = end_ans + 1, #pkt_bytes do out[#out + 1] = pkt_bytes[i] end

    local ancount = out[7] * 256 + out[8] + added
    out[7] = math.floor(ancount / 256)
    out[8] = ancount % 256

    return out
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
-- EXCLUDE GLOBAL: domain yang tidak di-redirect (CNAME, ip-alias, speed-check).
-- Prioritas: api-allow > api-exclude > heuristik label "api".
-- Isi set via: smartdns_domain_set(EXCLUDE_DOMAIN_SET, "<file>") di dnsdist.conf.
-- ============================================================================
EXCLUDE_DOMAIN_SET = EXCLUDE_DOMAIN_SET or "api-exclude"
API_ALLOW_SET      = API_ALLOW_SET or "api-allow"
if EXCLUDE_API_LIKE == nil then EXCLUDE_API_LIKE = true end

_excluded_logged = {}
_rewrite_logged = {}

-- Heuristik "berbau api": label domain sama dengan "api", diawali "api-",
-- diakhiri "-api", atau "api" + angka (api2). Contoh: api.x.com, x.api.com,
-- api-v2.x.com, x-api.com, api2.x.com.
function smartdns_is_api_like(s)
    for label in s:gmatch("[^%.]+") do
        if label == "api" or label:match("^api%-") or label:match("%-api$") or label:match("^api%d+$") then
            return true
        end
    end
    return false
end

function smartdns_is_excluded(qname)
    local s = qname:toString():lower()
    local allow = smartdns_smn[API_ALLOW_SET]
    if allow and allow:check(qname) then
        return false
    end
    local excluded = false
    local set = smartdns_smn[EXCLUDE_DOMAIN_SET]
    if (set and set:check(qname)) or (EXCLUDE_API_LIKE and smartdns_is_api_like(s)) then
        excluded = true
    end
    if excluded and not _excluded_logged[s] then
        _excluded_logged[s] = true
        infolog("smartdns: excluded from redirect: " .. s)
    end
    return excluded
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
    -- Gunakan QNAME Flattening: Ubah query ke target_cname, biarkan upstream meresolve,
    -- lalu DnsDist otomatis mengembalikan A record-nya ke klien dengan nama awal.
    addAction(SuffixMatchNodeRule(clean_domain), LuaAction(function(dq)
        if smartdns_is_excluded(dq.qname) then
            return DNSAction.None
        end
        dq.qname = newDNSName(target_cname)
        return DNSAction.None
    end))
    infolog("smartdns: CNAME rule added: *." .. clean_domain .. " -> (Flattened) " .. target_cname)
end

-- ============================================================================
-- Meniru fungsi: address /domain/ip  (override) dan address /domain/#  (NXDOMAIN)
-- Dipasang sebagai SuffixMatchNodeRule: domain + seluruh sub-domain.
-- ip = "#" -> NXDOMAIN. Pola exclude API tidak berlaku (ini perintah eksplisit).
-- ============================================================================
function smartdns_address(domain_pattern, ip)
    local clean = domain_pattern:gsub("^%-%.", ""):gsub("^%.", ""):gsub("^%*%.", "")
    local suffix = SuffixMatchNodeRule(clean)
    if ip == "#" then
        addAction(suffix, RCodeAction(DNSRCode.NXDOMAIN))
    else
        local qtype = ip:find(":") and DNSQType.AAAA or DNSQType.A
        addAction(AndRule({suffix, QTypeRule(qtype)}), SpoofAction(ip))
    end
    infolog("smartdns: address /" .. clean .. "/" .. ip)
end

-- ============================================================================
-- Meniru fungsi: nameserver /domain/group  (routing domain ke upstream tertentu)
-- group = nama pool dari newPoolAction / newServer({pool="..."}) di dnsdist.conf.
-- ============================================================================
function smartdns_nameserver(domain_pattern, pool_name)
    local clean = domain_pattern:gsub("^%-%.", ""):gsub("^%.", ""):gsub("^%*%.", "")
    addAction(SuffixMatchNodeRule(clean), PoolAction(pool_name))
    infolog("smartdns: nameserver /" .. clean .. "/ -> pool " .. pool_name)
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

        -- Exclude global (api-exclude + heuristik label api, kecuali api-allow)
        if smartdns_is_excluded(dr.qname) then
            return DNSResponseAction.None, ""
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

            -- Audit: catat domain yang di-rewrite (sekali per domain/proses)
            local rw = dr.qname:toString():lower()
            if not _rewrite_logged[rw] then
                _rewrite_logged[rw] = true
                infolog("smartdns: ip-rules rewrite applied: " .. rw)
            end

            -- Tandai domain ini sebagai "aliased" agar SmartDist speedcheck
            -- tidak menimpa rewrite ip_rules_alias dengan IP dari speed_cache.
            local aliased_domain = dr.qname:toString():gsub("%.$", "")
            if not _aliased_domains[aliased_domain] then
                if (collectgarbage("count") / 1024) > (SPEEDCHECK_MAX_MEMORY_MB or 50) then
                    local k, _ = next(_aliased_domains)
                    if k then _aliased_domains[k] = nil end
                end
                _aliased_domains[aliased_domain] = true
            end
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

    -- Info parallel aggregation
    if PARALLEL_UPSTREAMS and #PARALLEL_UPSTREAMS > 0 then
        infolog(string.format("[SmartDist] Parallel aggregation: %d upstream manual ditentukan.", #PARALLEL_UPSTREAMS))
        _active_upstreams = PARALLEL_UPSTREAMS
    else
        infolog(string.format("[SmartDist] Parallel aggregation: auto-select newServer() lat<=%.0fms, top %d.",
            PARALLEL_UPSTREAM_MAX_LATENCY or 300, PARALLEL_MAX_UPSTREAMS or 5))
    end

    addResponseAction(AllRule(), LuaResponseAction(function(dr)
        if dr.qtype ~= DNSQType.A and dr.qtype ~= DNSQType.AAAA then
            return DNSResponseAction.None, ""
        end

        -- EXCLUDE GLOBAL: domain exclude tidak boleh di-rewrite sama sekali
        if smartdns_is_excluded(dr.qname) then
            return DNSResponseAction.None, ""
        end

        local domain = dr.qname:toString():gsub("%.$", "")

        -- BUG FIX #1: FAST PATH — cek hal-hal murah SEBELUM parsing paket yang mahal.
        -- Jika domain sudah ada di antrian probe, tidak ada yang perlu dilakukan.
        if _probe_queue_set[domain] then
            return DNSResponseAction.None, ""
        end

        -- Jika domain sudah di-handle ip_rules_alias (IP sudah fixed), skip rewrite.
        -- SmartDist tetap bisa probe IP-nya, tapi tidak perlu reorder/overwrite.
        local is_aliased = _aliased_domains[domain]

        -- Jika ada cache hit, langsung masuk ke rewrite tanpa parse dulu.
        -- Kecuali domain aliased — untuk domain aliased, cache hit tetap dilanjutkan
        -- ke bawah agar bisa probe (tp tidak rewrite).
        local fastest_ips = _get_fastest(domain)

        -- Jika tidak ada cache dan tidak ada di antrian, kita perlu parse paket
        -- untuk mengumpulkan IP-IP yang akan di-probe.
        if not fastest_ips then
            local pkt_raw = dr:getContent()
            local overlay = newDNSPacketOverlay(pkt_raw)
            local record_count = overlay:getRecordsCountInSection(DNSSection.Answer)
            local record_len = (dr.qtype == DNSQType.AAAA) and 16 or 4
            local ips = {}
            for i = 0, record_count - 1 do
                local rec = overlay:getRecord(i)
                if rec.type == dr.qtype and rec.contentLength == record_len then
                    local ip_str
                    if dr.qtype == DNSQType.AAAA then
                        ip_str = _bytes_to_ipv6(pkt_raw, rec.contentOffset)
                    else
                        ip_str = string.format("%d.%d.%d.%d",
                            pkt_raw:byte(rec.contentOffset + 1),
                            pkt_raw:byte(rec.contentOffset + 2),
                            pkt_raw:byte(rec.contentOffset + 3),
                            pkt_raw:byte(rec.contentOffset + 4))
                    end
                    if ip_str then ips[#ips + 1] = ip_str end
                end
            end

            -- Domain dengan SATU IP tetap diagregasi: banyak domain (mis. facebook.com)
            -- hanya memberi 1 A record per resolver, dan IP-nya berbeda antar resolver.
            -- Tanpa ini, gabungan dari beberapa upstream tidak pernah terkumpul.
            if #ips == 0 then return DNSResponseAction.None, "" end

            -- Masukkan ke antrian probe background
            _enqueue(domain, ips)

            -- Masukkan ke antrian parallel upstream juga
            if #_active_upstreams > 0 then
                if #_parallel_queue < SPEEDCHECK_QUEUE_LIMIT and not _parallel_queue_set[domain] then
                    table.insert(_parallel_queue, domain)
                    _parallel_queue_set[domain] = true
                end
            end

            -- Untuk query pertama, kembalikan paket asli tanpa diubah
            return DNSResponseAction.None, ""
        end

        -- Ada cache hit: lakukan rewrite paket
        -- SKIP rewrite jika domain sudah di-handle ip_rules_alias (IP sudah fixed)
        if is_aliased then
            return DNSResponseAction.None, ""
        end

        -- Wrap seluruh rewrite dalam pcall untuk mencegah crash diam-diam
        -- yang bisa menyebabkan DnsDist men-cache response kosong/rusak
        local rewrite_ok, rewrite_err = pcall(function()
            local pkt = dr:getContent()
            local overlay = newDNSPacketOverlay(pkt)
            local record_count = overlay:getRecordsCountInSection(DNSSection.Answer)
            local record_len = (dr.qtype == DNSQType.AAAA) and 16 or 4

            if record_count == 0 then return end

            -- Convert fastest IPs ke byte arrays
            local pkt_bytes = {pkt:byte(1, #pkt)}
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
                if #tbytes == record_len then
                    table.insert(target_bytes_list, tbytes)
                end
            end

            if #target_bytes_list == 0 then return end

            if SPEEDCHECK_MODE == "fastest-ip" then
                -- Mode fastest-ip: Reorder agar Top N IP tercepat berada di urutan teratas
                -- 1. Kumpulkan semua offset record A/AAAA yang valid
                local record_offsets = {}
                for i = 0, record_count - 1 do
                    local rec = overlay:getRecord(i)
                    if rec.type == dr.qtype and rec.contentLength == record_len then
                        table.insert(record_offsets, rec.contentOffset)
                    end
                end

                -- 2. Tukar posisi IP tercepat secara berurutan
                for k, target_bytes in ipairs(target_bytes_list) do
                    if k > #record_offsets then break end
                    
                    local found_idx = nil
                    -- Cari IP target ini mulai dari posisi ke-k ke bawah
                    for m = k, #record_offsets do
                        local is_match = true
                        local offset_m = record_offsets[m]
                        for b = 1, record_len do
                            if pkt_bytes[offset_m + b] ~= target_bytes[b] then
                                is_match = false break
                            end
                        end
                        if is_match then
                            found_idx = m
                            break
                        end
                    end

                    -- Jika ditemukan, tukar dengan record di posisi ke-k
                    if found_idx and found_idx ~= k then
                        local offset_k = record_offsets[k]
                        local offset_m = record_offsets[found_idx]
                        for b = 1, record_len do
                            local temp = pkt_bytes[offset_k + b]
                            pkt_bytes[offset_k + b] = pkt_bytes[offset_m + b]
                            pkt_bytes[offset_m + b] = temp
                        end
                    end
                end
            else
                -- Mode fastest-response: Overwrite record dengan top N IP (Round-Robin)
                local fip_index = 1
                for i = 0, record_count - 1 do
                    local rec = overlay:getRecord(i)
                    if rec.type == dr.qtype and rec.contentLength == record_len then
                        local current_target = target_bytes_list[fip_index]
                        for b = 1, record_len do
                            pkt_bytes[rec.contentOffset + b] = current_target[b]
                        end
                        fip_index = fip_index + 1
                        if fip_index > #target_bytes_list then fip_index = 1 end
                    end
                end
            end

            -- GABUNGKAN IP agregasi dari beberapa recursor (mode fastest-ip):
            -- sisipkan record A/AAAA baru dari cache speed check.
            if SPEEDCHECK_MODE == "fastest-ip" then
                local merged = _smartdns_append_answer_records(
                    pkt, pkt_bytes, dr.qtype, record_len, fastest_ips, SPEEDCHECK_MAX_RESPONSE)
                if merged then pkt_bytes = merged end
            end

            local parts = {}
            for _, b in ipairs(pkt_bytes) do parts[#parts + 1] = string.char(b) end
            dr:setContent(table.concat(parts))
        end)

        if not rewrite_ok then
            warnlog("[SmartDist] Rewrite error untuk " .. domain .. ": " .. tostring(rewrite_err))
            -- Hapus cache entry yang mungkin bermasalah
            _speed_cache[domain] = nil
        end

        return DNSResponseAction.None, ""
    end), {name="SmartDist Speed Check Hook"})

    infolog("[SmartDist] Speed Check hook aktif untuk SEMUA domain.")
end
