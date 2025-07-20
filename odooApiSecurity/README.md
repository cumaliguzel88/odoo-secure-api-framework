# Odoo API Güvenlik Sistemi

## Proje Hakkında

Bu repository, Odoo'nun RESTful API ve XML-RPC ile harici sistemlere açılırken uygulanabilecek kapsamlı güvenlik önlemlerini içermektedir. Token tabanlı erişim, kullanıcı bazlı yetkilendirme, rate-limiting ve diğer koruma katmanlarının pratik implementasyonları sunulmaktadır.

## Özellikler

- Token tabanlı authentication sistemleri
- OAuth2 implementasyonu
- Rate limiting ve DDoS koruması
- Kullanıcı bazlı yetkilendirme
- CSRF ve XSS koruması
- API güvenlik monitoring
- Nginx/Apache konfigürasyonları
- Güvenlik test araçları

## Proje Yapısı

```
odoo-api-security/
├── README.md                      # Bu dosya
├── modules/                       # Odoo modülleri
│   ├── token_auth/                # Token tabanlı authentication
│   │   ├── __manifest__.py
│   │   ├── models/
│   │   ├── controllers/
│   │   └── security/
│   ├── rate_limiter/              # Rate limiting sistemi
│   │   ├── __manifest__.py
│   │   ├── models/
│   │   ├── controllers/
│   │   └── security/
│   └── api_security/              # Kapsamlı API güvenlik modülü
│       ├── __manifest__.py
│       ├── models/
│       ├── controllers/
│       └── security/
├── examples/                      # Kullanım örnekleri
│   ├── xml_rpc_secure/           # Güvenli XML-RPC implementasyonları
│   ├── rest_api_examples/        # RESTful API örnekleri
│   └── nginx_configs/            # Nginx güvenlik konfigürasyonları
├── tests/                        # Test dosyaları
│   ├── security_tests/
│   ├── performance_tests/
│   └── integration_tests/
└── docs/                         # Dokümantasyon
    ├── installation.md
    ├── configuration.md
    └── troubleshooting.md
```

## Kurulum

### Gereksinimler

- Odoo 17.0 veya üzeri
- Python 3.8+
- PostgreSQL 12+
- Redis (opsiyonel, token storage için)
- Nginx/Apache (production için)

### Hızlı Başlangıç

1. Repository'yi klonlayın:
```bash
git clone https://github.com/username/odoo-api-security.git
cd odoo-api-security
```

2. Modülleri Odoo addons dizinine kopyalayın:
```bash
cp -r modules/* /path/to/odoo/custom-addons/
```

3. Odoo'yu restart edin ve modülleri yükleyin:
```bash
./odoo-bin -u token_auth,rate_limiter,api_security -d your_database
```

## Modül Açıklamaları

### Token Authentication Modülü

XML-RPC ve RESTful API'lar için token tabanlı authentication sistemi sağlar.

Özellikler:
- JWT token generation ve validation
- API key management
- User-specific token assignment
- Token expiry ve refresh mechanisms
- Scope-based access control

### Rate Limiter Modülü

API isteklerini sınırlayan ve DDoS saldırılarını önleyen sistem.

Özellikler:
- Token bucket algorithm implementasyonu
- Per-user ve per-IP limiting
- Configurable rate limits
- Redis entegrasyonu
- Real-time monitoring

### API Security Modülü

Kapsamlı API güvenlik çözümü.

Özellikler:
- CSRF protection enhancement
- XSS prevention
- Input validation ve sanitization
- Security audit logging
- Anomaly detection

## Kullanım Örnekleri

### Token Authentication

```python
# Token generation
token = api_auth.generate_token(user_id=1, scope='read,write')

# API request with token
headers = {'Authorization': f'Bearer {token}'}
response = requests.get('http://localhost:8069/api/v1/partners', headers=headers)
```

### Rate Limiting Konfigürasyonu

```python
# Rate limit ayarları
rate_limiter.configure({
    'requests_per_minute': 60,
    'requests_per_hour': 1000,
    'burst_allowance': 10
})
```

## Güvenlik Konfigürasyonu

### Nginx Konfigürasyonu

```nginx
# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

location /api/ {
    limit_req zone=api burst=20 nodelay;
    proxy_pass http://odoo_backend;
}
```

### Odoo Konfigürasyonu

```ini
[options]
# API güvenlik ayarları
xmlrpc_interface = 127.0.0.1
proxy_mode = True
list_db = False

# Custom modules
server_wide_modules = base,web,token_auth,rate_limiter
```

## Test Etme

### Güvenlik Testleri

```bash
# Token authentication testi
python tests/security_tests/test_token_auth.py

# Rate limiting testi
python tests/security_tests/test_rate_limiting.py

# SQL injection testi
python tests/security_tests/test_sql_injection.py
```

### Performance Testleri

```bash
# Load testing
python tests/performance_tests/load_test.py

# Rate limit performance
python tests/performance_tests/rate_limit_benchmark.py
```

## Güvenlik Best Practices

### Authentication
- Token tabanlı authentication kullanın
- Kısa süreli access token'lar tercih edin
- Refresh token mechanism uygulayın
- Strong secret key'ler kullanın

### Authorization
- Least privilege principle uygulayın
- Role-based access control kullanın
- Regular permission audit yapın
- Temporary access için expiry mechanism

### Rate Limiting
- Multi-level rate limiting uygulayın
- User, IP ve endpoint bazlı limiting
- Real-time monitoring ekleyin
- Adaptive limits kullanın

### Network Security
- HTTPS only communication
- IP whitelisting trusted sources için
- Reverse proxy güvenlik kuralları
- Access log monitoring

## Troubleshooting

### Yaygın Sorunlar

**Problem:** Token validation başarısız
**Çözüm:** Secret key konfigürasyonunu kontrol edin

**Problem:** Rate limit çok agresif
**Çözüm:** Burst allowance değerini artırın

**Problem:** CSRF token hatası
**Çözüm:** External API için csrf=False kullanın

### Log Analizi

```bash
# API error logları
grep "API_ERROR" /var/log/odoo/odoo-server.log

# Rate limit violations
grep "RATE_LIMIT" /var/log/odoo/odoo-server.log

# Security events
grep "SECURITY" /var/log/odoo/odoo-server.log
```

## Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/yeni-ozellik`)
3. Değişikliklerinizi commit edin (`git commit -am 'Yeni özellik eklendi'`)
4. Branch'inizi push edin (`git push origin feature/yeni-ozellik`)
5. Pull Request oluşturun

## Güvenlik Bildirimi

Güvenlik açığı bulursanız, lütfen public issue açmak yerine doğrudan iletişime geçin.

## Lisans

MIT License - Detaylar için LICENSE dosyasını inceleyın.

## Kaynaklar

- [Odoo External API Documentation](https://www.odoo.com/documentation/18.0/developer/reference/external_api.html)
- [OAuth2 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)

## Destek

Sorularınız için:
- GitHub Issues kullanın
- Dokümantasyonu kontrol edin
- Community forumlarına başvurun

## Versiyon Geçmişi

- v1.0.0 - İlk release, temel token authentication
- v1.1.0 - Rate limiting eklendi
- v1.2.0 - OAuth2 support
- v1.3.0 - Enhanced security monitoring

Bu repository Odoo API güvenliği için production-ready çözümler sunmaktadır. Tüm implementasyonlar real-world senaryolar için test edilmiştir.