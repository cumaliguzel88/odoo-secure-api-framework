import secrets
import string
import hashlib
from odoo import models, fields, api, _
from odoo.exceptions import ValidationError
import logging

_logger = logging.getLogger(__name__)


class APIKey(models.Model):
    _name = 'api.key'
    _description = 'API Key Management'
    _order = 'create_date desc'
    _rec_name = 'name'

    name = fields.Char(
        string='Key Name',
        required=True,
        help='Human readable API key identifier'
    )
    
    key = fields.Char(
        string='API Key',
        readonly=True,
        help='Public API key identifier'
    )
    
    secret_key = fields.Char(
        string='Secret Key',
        readonly=True,
        help='Secret key for token signing'
    )
    
    user_id = fields.Many2one(
        'res.users',
        string='Owner',
        required=True,
        ondelete='cascade'
    )
    
    active = fields.Boolean(
        default=True,
        help='Set to false to disable API key'
    )
    
    description = fields.Text(
        string='Description',
        help='Description of API key usage'
    )
    
    # Rate limiting settings
    rate_limit_enabled = fields.Boolean(
        string='Enable Rate Limiting',
        default=True
    )
    
    requests_per_minute = fields.Integer(
        string='Requests per Minute',
        default=60,
        help='Maximum requests per minute'
    )
    
    requests_per_hour = fields.Integer(
        string='Requests per Hour',
        default=1000,
        help='Maximum requests per hour'
    )
    
    requests_per_day = fields.Integer(
        string='Requests per Day',
        default=10000,
        help='Maximum requests per day'
    )
    
    # IP restrictions
    ip_whitelist = fields.Text(
        string='IP Whitelist',
        help='Comma-separated list of allowed IP addresses. Leave empty for any IP.'
    )
    
    # Scope and permissions
    allowed_models = fields.Text(
        string='Allowed Models',
        help='Comma-separated list of allowed model names. Leave empty for all models.'
    )
    
    allowed_methods = fields.Selection([
        ('read', 'Read Only'),
        ('write', 'Read/Write'),
        ('all', 'All Operations')
    ], default='read', required=True)
    
    # Usage tracking
    total_requests = fields.Integer(
        string='Total Requests',
        default=0,
        readonly=True
    )
    
    last_used = fields.Datetime(
        string='Last Used',
        readonly=True
    )
    
    created_date = fields.Datetime(
        string='Created Date',
        default=fields.Datetime.now,
        readonly=True
    )
    
    expires_at = fields.Datetime(
        string='Expires At',
        help='API key expiration date'
    )
    
    # Related fields
    token_ids = fields.One2many(
        'api.token',
        'api_key_id',
        string='Tokens'
    )
    
    token_count = fields.Integer(
        string='Active Tokens',
        compute='_compute_token_count',
        store=False
    )
    
    # Computed fields
    is_expired = fields.Boolean(
        string='Is Expired',
        compute='_compute_is_expired',
        store=False
    )

    @api.depends('token_ids')
    def _compute_token_count(self):
        for key in self:
            key.token_count = len(key.token_ids.filtered('active'))

    @api.depends('expires_at')
    def _compute_is_expired(self):
        now = fields.Datetime.now()
        for key in self:
            key.is_expired = key.expires_at and key.expires_at < now

    @api.model
    def create(self, vals):
        # Generate API key and secret
        vals['key'] = self._generate_api_key()
        vals['secret_key'] = self._generate_secret_key()
        
        api_key = super().create(vals)
        
        _logger.info(f'API Key created: {api_key.name} for user {api_key.user_id.login}')
        
        return api_key

    def _generate_api_key(self):
        """Generate public API key"""
        return 'ak_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

    def _generate_secret_key(self):
        """Generate secret key for token signing"""
        return secrets.token_urlsafe(64)

    def regenerate_secret(self):
        """Regenerate secret key"""
        self.ensure_one()
        old_secret = self.secret_key
        new_secret = self._generate_secret_key()
        
        self.write({'secret_key': new_