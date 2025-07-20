# Odoo API Security Framework

Bu repository, Odoo'nun RESTful API ve XML-RPC ile harici sistemlere açılırken uygulanabilecek kapsamlı güvenlik önlemlerini içermektedir. Token tabanlı erişim, kullanıcı bazlı yetkilendirme, rate-limiting ve diğer koruma katmanlarının production-ready implementasyonları sunulmaktadır.

## Proje Hakkında

Modern enterprise sistemlerde API güvenliği kritik önem taşır. Bu framework, Odoo sistemlerinin güvenli şekilde external API erişimine açılması için gerekli tüm bileşenleri sağlar.

### Temel Özellikler

- **Token Authentication**: JWT tabanlı güvenli authentication sistemi
- **API Key Management**: Kapsamlı API key yönetimi ve kontrolü
- **Rate Limiting**: DDoS koruması ve istek sınırlama
- **Request Logging**: Detaylı API erişim logları ve monitoring
- **IP Whitelisting**: IP tabanlı erişim kontrolü
- **Scope Management**: Granular permission sistemi
- **Security Monitoring**: Anomali detection ve güvenlik alertleri

### Mimari Bileşenler

#### Token Authentication Module
- JWT token generation ve validation
- Refresh token mechanism
- User-specific token assignment
- Configurable token expiry

#### Rate Limiter Module
- Token bucket algorithm
- Per-user ve per-IP limiting
- Redis integration support
- Real-time monitoring

#### API Security Module
- CSRF protection enhancement
- XSS prevention
- Input validation ve sanitization
- Security audit logging

## Kurulum

### Gereksinimler

- Odoo 17.0+
- Python 3.8+
- PostgreSQL 12+
- Redis (opsiyonel)

### Hızlı Kurulum

```bash
# Repository'yi klonlayın
git clone https://github.com/your-username/odoo-api-security.git
cd odoo-api-security

# Modülleri Odoo addons dizinine kopyalayın
cp -r modules/* /path/to/odoo/addons/

# Odoo'yu restart edin ve modülleri yükleyin
./odoo-bin -u token_auth,rate_limiter,api_security -d your_database
```

## Kullanım

### Token Authentication

```python
# Token generation
POST /api/v1/auth/token
{
    "api_key": "ak_your_api_key",
    "username": "user@example.com", 
    "password": "password",
    "scope": "read,write"
}

# API request with token
GET /api/v1/partners
Authorization: Bearer your_jwt_token_here
```

### XML-RPC Secure Client

```python
from examples.xml_rpc_secure.secure_client import SecureOdooClient

client = SecureOdooClient(
    url='https://your-odoo.com',
    database='production_db',
    username='api_user',
    password='secure_password'
)

partners = client.search_read('res.partner', [('is_company', '=', True)])
```

### REST API Client

```python
from examples.rest_api_examples.token_client import OdooTokenClient

client = OdooTokenClient(
    base_url='https://your-odoo.com',
    api_key='ak_your_api_key',
    username='api_user',
    password='secure_password'
)

result = client.search_records('res.partner', limit=10)
```

## Konfigürasyon

### Nginx Production Setup

```bash
# Production nginx konfigürasyonunu kopyalayın
cp examples/nginx_configs/production.conf /etc/nginx/sites-available/odoo-api
ln -s /etc/nginx/sites-available/odoo-api /etc/nginx/sites-enabled/

# SSL sertifikalarınızı yapılandırın
# Rate limiting parametrelerini ayarlayın
# Nginx'i restart edin
sudo systemctl restart nginx
```

### Odoo Configuration

```ini
[options]
# API güvenlik ayarları
server_wide_modules = base,web,token_auth,rate_limiter,api_security
xmlrpc_interface = 127.0.0.1
proxy_mode = True
list_db = False
```

## Güvenlik Özellikleri

### Authentication Layers
- Multi-factor authentication support
- IP-based access restrictions
- User agent validation
- Geographic access controls

### Rate Limiting
- Configurable request limits per minute/hour/day
- Burst allowance with sustained rate limits
- Different limits for read/write operations
- Automatic blocking on limit exceed

### Monitoring & Alerting
- Real-time security event detection
- Anomaly pattern recognition
- Automated incident response
- Comprehensive audit trails

### Input Validation
- SQL injection prevention
- XSS attack mitigation
- Parameter sanitization
- Request size limitations

## Production Deployment

### Güvenlik Checklist

- [ ] SSL/TLS certificates configured (A+ rating)
- [ ] Rate limiting enabled and tested
- [ ] IP whitelisting configured
- [ ] Log monitoring setup
- [ ] Backup and disaster recovery plan
- [ ] Security incident response plan
- [ ] Regular security audits scheduled

### Performance Considerations

- Token validation: 2-5ms overhead per request
- Rate limiting: 1-3ms overhead per request
- Logging: 5-10ms overhead (configurable)
- Redis caching recommended for high-load scenarios

## Lisans

MIT License - Detaylar için LICENSE dosyasını inceleyin.

## Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/new-security-feature`)
3. Değişikliklerinizi commit edin (`git commit -am 'Add new security feature'`)
4. Branch'inizi push edin (`git push origin feature/new-security-feature`)
5. Pull Request oluşturun

## Güvenlik Bildirimi

Güvenlik açığı keşfederseniz, lütfen public issue açmak yerine doğrudan security@yourdomain.com adresine bildiriniz.

## Destek

- GitHub Issues: Bug reports ve feature requests
- Documentation: Wiki sayfalarında detaylı dokümantasyon
- Community: Discussions sekmesinde topluluk desteği

## Kaynaklar

- [Odoo External API Documentation](https://www.odoo.com/documentation/18.0/developer/reference/external_api.html)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OAuth2 RFC 6749](https://tools.ietf.org/html/rfc6749)

---

**Not**: Bu framework production environments için tasarlanmıştır. Development ortamında kullanmadan önce güvenlik ayarlarını test ortamına uygun şekilde yapılandırın.
