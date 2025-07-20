import jwt
import time
import secrets
import hashlib
import hmac
from datetime import datetime, timedelta
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError, AccessDenied
import logging

_logger = logging.getLogger(__name__)


class APIToken(models.Model):
    _name = 'api.token'
    _description = 'API Token Management'
    _order = 'create_date desc'
    _rec_name = 'name'

    name = fields.Char(
        string='Token Name',
        required=True,
        help='Human readable token identifier'
    )
    
    token = fields.Char(
        string='Access Token',
        readonly=True,
        help='JWT access token'
    )
    
    refresh_token = fields.Char(
        string='Refresh Token',
        readonly=True,
        help='Token for refreshing access token'
    )
    
    user_id = fields.Many2one(
        'res.users',
        string='User',
        required=True,
        ondelete='cascade'
    )
    
    api_key_id = fields.Many2one(
        'api.key',
        string='API Key',
        required=True,
        ondelete='cascade'
    )
    
    active = fields.Boolean(
        default=True,
        help='Set to false to disable token'
    )
    
    scope = fields.Selection([
        ('read', 'Read Only'),
        ('write', 'Read/Write'),
        ('admin', 'Full Access')
    ], default='read', required=True)
    
    expires_at = fields.Datetime(
        string='Expires At',
        required=True,
        help='Token expiration time'
    )
    
    issued_at = fields.Datetime(
        string='Issued At',
        default=fields.Datetime.now,
        readonly=True
    )
    
    last_used = fields.Datetime(
        string='Last Used',
        readonly=True
    )
    
    usage_count = fields.Integer(
        string='Usage Count',
        default=0,
        readonly=True
    )
    
    allowed_ips = fields.Text(
        string='Allowed IP Addresses',
        help='Comma-separated list of allowed IP addresses. Leave empty for any IP.'
    )
    
    user_agent = fields.Char(
        string='User Agent',
        readonly=True,
        help='User agent of the last request'
    )
    
    # Computed fields
    is_expired = fields.Boolean(
        string='Is Expired',
        compute='_compute_is_expired',
        store=False
    )
    
    days_until_expiry = fields.Integer(
        string='Days Until Expiry',
        compute='_compute_days_until_expiry',
        store=False
    )

    @api.depends('expires_at')
    def _compute_is_expired(self):
        now = fields.Datetime.now()
        for token in self:
            token.is_expired = token.expires_at < now

    @api.depends('expires_at')
    def _compute_days_until_expiry(self):
        now = fields.Datetime.now()
        for token in self:
            if token.expires_at > now:
                delta = token.expires_at - now
                token.days_until_expiry = delta.days
            else:
                token.days_until_expiry = 0

    @api.model
    def create(self, vals):
        if not vals.get('expires_at'):
            # Default expiry: 30 days
            vals['expires_at'] = fields.Datetime.now() + timedelta(days=30)
        
        token = super().create(vals)
        token._generate_tokens()
        return token

    def _generate_tokens(self):
        """Generate JWT access token and refresh token"""
        secret_key = self.api_key_id.secret_key
        if not secret_key:
            raise ValidationError(_('API Key secret not found'))

        # Access token payload
        access_payload = {
            'user_id': self.user_id.id,
            'token_id': self.id,
            'scope': self.scope,
            'iss': 'odoo-api',
            'iat': int(time.time()),
            'exp': int(self.expires_at.timestamp()),
            'type': 'access'
        }

        # Refresh token payload (longer expiry)
        refresh_payload = {
            'user_id': self.user_id.id,
            'token_id': self.id,
            'iss': 'odoo-api',
            'iat': int(time.time()),
            'exp': int((self.expires_at + timedelta(days=7)).timestamp()),
            'type': 'refresh'
        }

        try:
            # Generate tokens
            access_token = jwt.encode(access_payload, secret_key, algorithm='HS256')
            refresh_token = jwt.encode(refresh_payload, secret_key, algorithm='HS256')
            
            self.write({
                'token': access_token,
                'refresh_token': refresh_token
            })
            
            _logger.info(f'Token generated for user {self.user_id.login}')
            
        except Exception as e:
            _logger.error(f'Token generation failed: {str(e)}')
            raise ValidationError(_('Failed to generate token: %s') % str(e))

    @api.model
    def validate_token(self, token, ip_address=None, user_agent=None):
        """Validate JWT token and return user context"""
        try:
            # Find token record
            token_record = self.search([('token', '=', token)], limit=1)
            if not token_record:
                return {'valid': False, 'reason': 'Token not found'}

            if not token_record.active:
                return {'valid': False, 'reason': 'Token is inactive'}

            # Decode and validate JWT
            secret_key = token_record.api_key_id.secret_key
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            
            # Check token type
            if payload.get('type') != 'access':
                return {'valid': False, 'reason': 'Invalid token type'}

            # Check expiry
            if payload['exp'] < time.time():
                return {'valid': False, 'reason': 'Token expired'}

            # IP address validation
            if token_record.allowed_ips and ip_address:
                allowed_ips = [ip.strip() for ip in token_record.allowed_ips.split(',')]
                if ip_address not in allowed_ips:
                    _logger.warning(f'IP {ip_address} not allowed for token {token_record.name}')
                    return {'valid': False, 'reason': 'IP address not allowed'}

            # Update usage statistics
            token_record.write({
                'last_used': fields.Datetime.now(),
                'usage_count': token_record.usage_count + 1,
                'user_agent': user_agent or ''
            })

            # Log access
            self.env['api.log'].create({
                'token_id': token_record.id,
                'user_id': token_record.user_id.id,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'action': 'token_validation',
                'result': 'success'
            })

            return {
                'valid': True,
                'user_id': payload['user_id'],
                'token_id': payload['token_id'],
                'scope': payload['scope'],
                'user': token_record.user_id
            }

        except jwt.ExpiredSignatureError:
            return {'valid': False, 'reason': 'Token expired'}
        except jwt.InvalidTokenError as e:
            _logger.warning(f'Invalid token: {str(e)}')
            return {'valid': False, 'reason': 'Invalid token'}
        except Exception as e:
            _logger.error(f'Token validation error: {str(e)}')
            return {'valid': False, 'reason': 'Validation error'}

    def refresh_access_token(self):
        """Refresh access token using refresh token"""
        if not self.refresh_token:
            raise ValidationError(_('No refresh token available'))

        try:
            secret_key = self.api_key_id.secret_key
            payload = jwt.decode(self.refresh_token, secret_key, algorithms=['HS256'])
            
            if payload.get('type') != 'refresh':
                raise ValidationError(_('Invalid refresh token type'))

            if payload['exp'] < time.time():
                raise ValidationError(_('Refresh token expired'))

            # Generate new access token
            self._generate_tokens()
            
            _logger.info(f'Token refreshed for user {self.user_id.login}')
            return True

        except Exception as e:
            _logger.error(f'Token refresh failed: {str(e)}')
            raise ValidationError(_('Failed to refresh token: %s') % str(e))

    def revoke_token(self):
        """Revoke token by deactivating it"""
        self.write({'active': False})
        
        # Log revocation
        self.env['api.log'].create({
            'token_id': self.id,
            'user_id': self.user_id.id,
            'action': 'token_revocation',
            'result': 'success'
        })
        
        _logger.info(f'Token revoked for user {self.user_id.login}')

    @api.model
    def cleanup_expired_tokens(self):
        """Cron job to cleanup expired tokens"""
        expired_tokens = self.search([
            ('expires_at', '<', fields.Datetime.now()),
            ('active', '=', True)
        ])
        
        for token in expired_tokens:
            token.write({'active': False})
        
        _logger.info(f'Cleaned up {len(expired_tokens)} expired tokens')
        return len(expired_tokens)

    @api.model
    def get_usage_statistics(self, user_id=None, days=30):
        """Get token usage statistics"""
        domain = []
        if user_id:
            domain.append(('user_id', '=', user_id))
        
        start_date = fields.Datetime.now() - timedelta(days=days)
        
        logs = self.env['api.log'].search([
            ('create_date', '>=', start_date)
        ] + domain)
        
        stats = {
            'total_requests': len(logs),
            'unique_tokens': len(logs.mapped('token_id')),
            'unique_users': len(logs.mapped('user_id')),
            'success_rate': len(logs.filtered(lambda l: l.result == 'success')) / len(logs) * 100 if logs else 0
        }
        
        return stats

    def action_regenerate_token(self):
        """Action to regenerate token"""
        self.ensure_one()
        self._generate_tokens()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Success'),
                'message': _('Token has been regenerated successfully'),
                'type': 'success'
            }
        }

    def action_revoke_token(self):
        """Action to revoke token"""
        self.ensure_one()
        self.revoke_token()
        return {
            'type': 'ir.actions.client',
            'tag': 'display_notification',
            'params': {
                'title': _('Success'),
                'message': _('Token has been revoked successfully'),
                'type': 'success'
            }
        }

    @api.constrains('allowed_ips')
    def _check_allowed_ips(self):
        """Validate IP address format"""
        for record in self:
            if record.allowed_ips:
                ips = [ip.strip() for ip in record.allowed_ips.split(',')]
                for ip in ips:
                    if not self._is_valid_ip(ip):
                        raise ValidationError(_('Invalid IP address format: %s') % ip)

    def _is_valid_ip(self, ip):
        """Simple IP validation"""
        import re
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False