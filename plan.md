# Rencana Implementasi: Replikasi `ip-rules` SmartDNS di DnsDist

## Latar Belakang & Tujuan
Tujuan dari rencana ini adalah untuk meniru perilaku fitur SmartDNS berikut di dalam lingkungan **DnsDist**:
```text
ip-rules ip-set:cloudflare-ipv4 -ip-alias 172.64.87.224
```
**Fungsi Asli di SmartDNS:** Jika hasil resolusi DNS (DNS response) mengandung IP Address yang termasuk dalam kelompok IP `cloudflare-ipv4` (ip-set), maka IP asli tersebut diabaikan dan diganti (di-alias) menjadi `172.64.87.224`. Fungsi ini umumnya dipakai untuk CDN routing / custom routing.

## Pendekatan Konseptual di DnsDist
Berbeda dengan SmartDNS yang merupakan full resolver/forwarder, DnsDist adalah **DNS Load Balancer** berkinerja tinggi. Oleh karena itu, DnsDist sangat menghindari parsing/perubahan isi payload paket secara langsung di tengah jalan karena berisiko memecahkan kompresi paket DNS dan memakan banyak CPU.

Untuk mencapai hal ini di DnsDist, kita perlu menggunakan pola **"Inspect -> Tag -> Restart/Spoof"** atau menggunakan **Lua FFI**. Berikut adalah alur kerjanya:

### Langkah 1: Mendefinisikan `ip-set` dengan `NetmaskGroup`
Di DnsDist, konsep `ip-set` setara dengan `NetmaskGroup` (NMG). Kita akan mengumpulkan subnet Cloudflare ke dalam sebuah grup.
```lua
-- Membuat NMG untuk target Cloudflare IPv4
cloudflare_ipv4 = newNMG()

-- Membuat SuffixMatchNode (SMN) untuk daftar domain yang di-exclude (domain-set)
cf_exclude_accel = newSMN()

-- Fungsi memuat list IP ke NMG
local function loadNetmasksFromFile(filename, nmg)
    local file = io.open(filename, "r")
    if file then
        for line in file:lines() do
            local mask = line:match("^%s*(.-)%s*$")
            if mask ~= "" and not mask:find("^#") then nmg:addMask(mask) end
        end
        file:close()
    end
end

-- Fungsi memuat list Domain ke SMN
local function loadDomainsFromFile(filename, smn)
    local file = io.open(filename, "r")
    if file then
        for line in file:lines() do
            local domain = line:match("^%s*(.-)%s*$")
            if domain ~= "" and not domain:find("^#") then smn:add(newDNSName(domain)) end
        end
        file:close()
    end
end

-- Memuat data dari file (sesuai configurasi SmartDNS)
loadNetmasksFromFile("/etc/smartdns/cdn-ips/cloudflare/ipv4.txt", cloudflare_ipv4)
loadDomainsFromFile("/etc/smartdns/cdn-ips/cloudflare/exclude.txt", cf_exclude_accel)
```

### Langkah 2: Membuat Aturan Spoofing Awal (The Alias)
Kita membuat aturan `addAction` dengan filter `TagRule`. Jika sebuah request ditandai bahwa itu akan menuju Cloudflare, kita langsung membalas (spoof) dengan alias yang diinginkan, tanpa perlu meneruskannya ke backend.
```lua
-- Jika request punya tag 'spoof_cloudflare', langsung jawab dengan 172.64.87.224
addAction(TagRule("spoof_cloudflare"), SpoofAction("172.64.87.224"))
```

### Langkah Ekstra: Replikasi Fitur CNAME Mapping (Wildcard)
Anda menyebutkan adanya fitur pengubahan domain ke CNAME seperti:
`cname /-.api.x.com/api.x.com.cdn.cloudflare.net`

Di DnsDist, pemetaan *wildcard* subdomain sangat mudah dilakukan di fase awal query menggunakan `SuffixMatchNodeRule` dan `SpoofCNAMEAction`.
```lua
-- SuffixMatchNodeRule secara otomatis mencakup domain "api.x.com" dan SEMUA subdomainnya (*.api.x.com).
-- Request tersebut akan langsung dijawab dengan CNAME yang dituju tanpa diteruskan ke resolver.
addAction(SuffixMatchNodeRule("api.x.com."), SpoofCNAMEAction("api.x.com.cdn.cloudflare.net."))
```


### Langkah 3: Menginspeksi IP dari Upstream (Response Inspection)
Langkah tersulit adalah mendeteksi apakah IP tersebut bagian dari Cloudflare jika kita tidak tahu persis nama domainnya. Kita menggunakan `addLuaResponseAction` untuk mengecek balasan dari backend:
```lua
local function inspectResponseForCloudflare(dr)
    local qtype = dr.dq.qtype
    -- Hanya proses query tipe A (IPv4)
    if qtype ~= DNSQType.A then
        return DNSResponseAction.None, ""
    end
    
    -- Cek jika nama domain yang di-query masuk dalam daftar domain exclude (cf-exclude-accel)
    -- Jika iya (seperti rule -no-ip-alias), kita langsung kembalikan response aslinya
    if cf_exclude_accel:check(dr.dq.qname) then
        return DNSResponseAction.None, ""
    end

    local packet = dr:getContent()
    local overlay = newDNSPacketOverlay(packet)
    local count = overlay:getCount()
    
    -- Looping semua record dari response
    for i = 0, count - 1 do
        local record = overlay:getRecord(i)
        if record.type == DNSQType.A then
            local addr = parseARecord(packet, record)
            -- Cek apakah IP masuk dalam NMG target
            if addr and cloudflare_ipv4:match(addr) then
                -- Jika cocok, pasang tag.
                dr.dq:setTag("spoof_cloudflare", "true")
                -- Tergantung versi DnsDist, Anda dapat memanggil restart query
                -- atau melakukan drop dan memaksa client melakukan retrying
                -- sehingga pada retry berikutnya akan terkena SpoofAction.
                return DNSResponseAction.Drop, "" 
            end
        end
    end
    
    return DNSResponseAction.None, ""
end

-- Terapkan response action untuk semua query
addLuaResponseAction(AllRule(), inspectResponseForCloudflare)
```

## Evaluasi & Alternatif
- **Kelebihan:** Pola ini cukup aman karena kita tidak merusak binary packet RDATA secara manual. Kita menggunakan fitur Spoofing bawaan yang sudah teruji aman untuk panjang string packet.
- **Kekurangan:** Jika mengandalkan Drop/Restart, ini akan menambah sedikit latency karena membutuhkan eksekusi ulang atau retry dari client.

### Alternatif dengan Lua FFI (Lebih Ekstrem)
Jika performa sangat kritikal, kita bisa menggunakan `LuaFFIResponseAction`. Namun, ini membutuhkan manipulasi pointer C dan FFI yang mana DnsDist *tidak* memiliki method spesifik yang simpel seperti `replaceResponseRecord`. Mengubah panjang paket akibat mengganti IP bisa merusak korupsi memori DnsDist jika tidak dihandle struktur paketnya (pointer offset) dengan benar. Oleh sebab itu, metode Inspect -> Tag -> Spoof adalah jalan paling "DnsDist-native".

## Kesimpulan
Anda dapat mengimplementasikan fitur mirip `ip-rules ip-alias` dengan menggabungkan komponen `NetmaskGroup` (sebagai ip-set), `DNSPacketOverlay` (untuk parse respon IP), `TagRule`, dan `SpoofAction` (sebagai ip-alias).

---

## Bagian Tambahan: Membuat Wrapper (Agar Konfigurasi Semudah SmartDNS)
Meskipun secara internal DnsDist harus menggunakan Lua, Anda tidak perlu menuliskannya berulang kali. Anda bisa membuat fungsi "wrapper" (pembungkus) agar penulisan konfigurasinya menjadi deklaratif dan persis seperti di SmartDNS.

Anda cukup menempatkan kode fungsi pembantu ini di bagian atas file `dnsdist.conf`:

```lua
-- ==========================================
-- SMARTDNS COMPATIBILITY WRAPPER UNTUK DNSDIST
-- ==========================================
local smartdns_nmg = {}
local smartdns_smn = {}

-- Meniru: ip-set -name [nama] -file [file]
function smartdns_ip_set(name, filepath)
    smartdns_nmg[name] = newNMG()
    local file = io.open(filepath, "r")
    if file then
        for line in file:lines() do
            local mask = line:match("^%s*(.-)%s*$")
            if mask ~= "" and not mask:find("^#") then smartdns_nmg[name]:addMask(mask) end
        end
        file:close()
    end
end

-- Meniru: domain-set -name [nama] -file [file]
function smartdns_domain_set(name, filepath)
    smartdns_smn[name] = newSMN()
    local file = io.open(filepath, "r")
    if file then
        for line in file:lines() do
            local domain = line:match("^%s*(.-)%s*$")
            if domain ~= "" and not domain:find("^#") then smartdns_smn[name]:add(newDNSName(domain)) end
        end
        file:close()
    end
end

-- Meniru: cname /domain/target
function smartdns_cname(domain_pattern, target_cname)
    -- Menghapus prefix wildcard "-." khas SmartDNS jika ada
    local clean_domain = domain_pattern:gsub("^%-%.-", "")
    addAction(SuffixMatchNodeRule(clean_domain), SpoofCNAMEAction(target_cname))
end

-- Meniru: ip-rules ip-set:[ip_set] -ip-alias [target] (Termasuk pengecualian domain)
function smartdns_ip_rules_alias(ip_set_name, target_ip, exclude_domain_set)
    -- 1. Buat rule spoof di awal berdasarkan Tag
    addAction(TagRule("spoof_" .. ip_set_name), SpoofAction(target_ip))
    
    -- 2. Buat response rule untuk inspeksi paket
    addLuaResponseAction(AllRule(), function(dr)
        if dr.dq.qtype ~= DNSQType.A then return DNSResponseAction.None, "" end
        
        -- Cek pengecualian domain jika diset (ekuivalen dengan -no-ip-alias)
        if exclude_domain_set and smartdns_smn[exclude_domain_set] then
            if smartdns_smn[exclude_domain_set]:check(dr.dq.qname) then
                return DNSResponseAction.None, ""
            end
        end

        local pkt = dr:getContent()
        local overlay = newDNSPacketOverlay(pkt)
        for i = 0, overlay:getCount() - 1 do
            local rec = overlay:getRecord(i)
            if rec.type == DNSQType.A then
                local addr = parseARecord(pkt, rec)
                if addr and smartdns_nmg[ip_set_name] and smartdns_nmg[ip_set_name]:match(addr) then
                    dr.dq:setTag("spoof_" .. ip_set_name, "true")
                    return DNSResponseAction.Drop, ""
                end
            end
        end
        return DNSResponseAction.None, ""
    end)
end
```

### Cara Penggunaan Wrapper
Setelah Anda mendefinisikan blok fungsi di atas, konfigurasi `dnsdist` utama Anda sekarang akan terlihat **sangat rapi, bersih, dan sangat mirip dengan SmartDNS**:

```lua
-- ==========================================
-- KONFIGURASI UTAMA DNSDIST ANDA
-- ==========================================

-- 1. Muat IP set dan Domain set dari file
smartdns_ip_set("cloudflare-ipv4", "/etc/smartdns/cdn-ips/cloudflare/ipv4.txt")
smartdns_domain_set("cf-exclude-accel", "/etc/smartdns/cdn-ips/cloudflare/exclude.txt")

-- 2. Terapkan CNAME mapping (wildcard sudah otomatis tertangani)
smartdns_cname("-.api.x.com", "api.x.com.cdn.cloudflare.net.")

-- 3. Terapkan IP rules alias (sertakan nama set pengecualian sebagai parameter ke-3)
-- Meniru: ip-rules ip-set:[NAME-RULE] -ip-alias [TARGET-IP]
smartdns_ip_rules_alias("NAME-RULE", "172.64.87.224", "cf-exclude-accel")

-- (Sebagai contoh untuk Cloudflare, Anda tinggal memasukkan nama set-nya)
-- smartdns_ip_rules_alias("cloudflare-ipv4", "172.64.87.224", "cf-exclude-accel")
```
