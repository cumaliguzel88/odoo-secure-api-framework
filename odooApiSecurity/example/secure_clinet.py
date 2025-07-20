#!/usr/bin/env python3
"""
Secure XML-RPC Client for Odoo
===============================

Bu örnek, Odoo XML-RPC API'sını güvenli şekilde kullanmak için
geliştirilmiş client implementasyonunu gösterir.

Özellikler:
- Connection pooling
- Request retry mechanism
- Rate limiting
- Error handling
- Logging
- Session management
"""

import xmlrpc.client
import ssl
import time
import logging
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List
import hashlib
import hmac


class SecureOdooClient:
    """Güvenli Odoo XML-RPC Client"""
    
    def __init__(self, url: str, database: str, username: str, password: str,
                 timeout: int = 30, max_retries: int = 3):
        """
        Secure Odoo client initialization
        
        Args:
            url: Odoo server URL
            database: Database name
            username: Username
            password: Password
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self.url = url
        self.database = database
        self.username = username
        self.password = password
        self.timeout = timeout
        self.max_retries = max_retries
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # SSL context for secure connections
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        
        # Initialize connections
        self._init_connections()
        
        # Authentication
        self.uid = None
        self._authenticate()
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1  # 100ms between requests
        
    def _init_connections(self):
        """Initialize XML-RPC connections"""
        try:
            # Common endpoint for authentication
            self.common = xmlrpc.client.ServerProxy(
                f'{self.url}/xmlrpc/2/common',
                timeout=self.timeout,
                context=self.ssl_context,
                allow_none=True
            )
            
            # Object endpoint for model operations
            self.models = xmlrpc.client.ServerProxy(
                f'{self.url}/xmlrpc/2/object',
                timeout=self.timeout,
                context=self.ssl_context,
                allow_none=True
            )
            
            self.logger.info(f'Initialized connections to {self.url}')
            
        except Exception as e:
            self.logger.error(f'Connection initialization failed: {str(e)}')
            raise
    
    def _authenticate(self):
        """Authenticate with Odoo server"""
        try:
            # Get server version first
            version_info = self._execute_with_retry(
                self.common.version
            )
            self.logger.info(f'Connected to Odoo {version_info.get("server_version", "unknown")}')
            
            # Authenticate
            self.uid = self._execute_with_retry(
                self.common.authenticate,
                self.database, self.username, self.password, {}
            )
            
            if not self.uid:
                raise Exception('Authentication failed')
                
            self.logger.info(f'Authenticated as user ID: {self.uid}')
            
        except Exception as e:
            self.logger.error(f'Authentication failed: {str(e)}')
            raise
    
    def _execute_with_retry(self, func, *args, **kwargs):
        """Execute function with retry mechanism"""
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                # Rate limiting
                self._rate_limit()
                
                # Execute request
                result = func(*args, **kwargs)
                
                if attempt > 0:
                    self.logger.info(f'Request succeeded on attempt {attempt + 1}')
                
                return result
                
            except Exception as e:
                last_exception = e
                self.logger.warning(f'Attempt {attempt + 1} failed: {str(e)}')
                
                if attempt < self.max_retries - 1:
                    # Exponential backoff
                    wait_time = (2 ** attempt) + 0.1
                    time.sleep(wait_time)
                    
        raise last_exception
    
    def _rate_limit(self):
        """Apply rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def execute_kw(self, model: str, method: str, args: List = None, 
                   kwargs: Dict = None) -> Any:
        """
        Execute model method with security checks
        
        Args:
            model: Model name (e.g., 'res.partner')
            method: Method name (e.g., 'search', 'read')
            args: Positional arguments
            kwargs: Keyword arguments
            
        Returns:
            Method execution result
        """
        if args is None:
            args = []
        if kwargs is None:
            kwargs = {}
        
        try:
            # Validate model access
            self._validate_model_access(model, method)
            
            # Execute request
            result = self._execute_with_retry(
                self.models.execute_kw,
                self.database, self.uid, self.password,
                model, method, args, kwargs
            )
            
            self.logger.debug(f'Executed {model}.{method} successfully')
            return result
            
        except Exception as e:
            self.logger.error(f'Error executing {model}.{method}: {str(e)}')
            raise
    
    def _validate_model_access(self, model: str, method: str):
        """Validate if user has access to model and method"""
        try:
            # Check if user can access the model
            access_result = self.execute_kw(
                model, 'check_access_rights',
                [method], {'raise_exception': False}
            )
            
            if not access_result:
                raise PermissionError(f'No {method} access to model {model}')
                
        except Exception as e:
            if 'check_access_rights' not in str(e):
                raise
    
    def search(self, model: str, domain: List = None, limit: int = None,
               offset: int = 0, order: str = None) -> List[int]:
        """
        Search records
        
        Args:
            model: Model name
            domain: Search domain
            limit: Maximum number of records
            offset: Number of records to skip
            order: Sort order
            
        Returns:
            List of record IDs
        """
        if domain is None:
            domain = []
        
        kwargs = {'offset': offset}
        if limit:
            kwargs['limit'] = limit
        if order:
            kwargs['order'] = order
        
        return self.execute_kw(model, 'search', [domain], kwargs)
    
    def read(self, model: str, ids: List[int], fields: List[str] = None) -> List[Dict]:
        """
        Read records
        
        Args:
            model: Model name
            ids: Record IDs to read
            fields: Fields to read
            
        Returns:
            List of record dictionaries
        """
        kwargs = {}
        if fields:
            kwargs['fields'] = fields
        
        return self.execute_kw(model, 'read', [ids], kwargs)
    
    def search_read(self, model: str, domain: List = None, fields: List[str] = None,
                    limit: int = None, offset: int = 0, order: str = None) -> List[Dict]:
        """
        Search and read records in one call
        
        Args:
            model: Model name
            domain: Search domain
            fields: Fields to read
            limit: Maximum number of records
            offset: Number of records to skip
            order: Sort order
            
        Returns:
            List of record dictionaries
        """
        if domain is None:
            domain = []
        
        kwargs = {'offset': offset}
        if fields:
            kwargs['fields'] = fields
        if limit:
            kwargs['limit'] = limit
        if order:
            kwargs['order'] = order
        
        return self.execute_kw(model, 'search_read', [domain], kwargs)
    
    def create(self, model: str, vals: Dict) -> int:
        """
        Create record
        
        Args:
            model: Model name
            vals: Values dictionary
            
        Returns:
            Created record ID
        """
        # Sanitize input data
        sanitized_vals = self._sanitize_data(vals)
        
        return self.execute_kw(model, 'create', [sanitized_vals])
    
    def write(self, model: str, ids: List[int], vals: Dict) -> bool:
        """
        Update records
        
        Args:
            model: Model name
            ids: Record IDs to update
            vals: Values dictionary
            
        Returns:
            True if successful
        """
        # Sanitize input data
        sanitized_vals = self._sanitize_data(vals)
        
        return self.execute_kw(model, 'write', [ids, sanitized_vals])
    
    def unlink(self, model: str, ids: List[int]) -> bool:
        """
        Delete records
        
        Args:
            model: Model name
            ids: Record IDs to delete
            
        Returns:
            True if successful
        """
        return self.execute_kw(model, 'unlink', [ids])
    
    def _sanitize_data(self, data: Dict) -> Dict:
        """
        Sanitize input data to prevent injection attacks
        
        Args:
            data: Input data dictionary
            
        Returns:
            Sanitized data dictionary
        """
        sanitized = {}
        
        for key, value in data.items():
            # Sanitize key
            if not isinstance(key, str) or not key.replace('_', '').isalnum():
                self.logger.warning(f'Skipping suspicious field name: {key}')
                continue
            
            # Sanitize value
            if isinstance(value, str):
                # Remove potential SQL injection patterns
                dangerous_patterns = [
                    '--', ';', 'DROP', 'DELETE', 'UPDATE', 'INSERT',
                    'UNION', 'SELECT', '<script>', '</script>'
                ]
                
                sanitized_value = value
                for pattern in dangerous_patterns:
                    if pattern.lower() in value.lower():
                        self.logger.warning(f'Potential injection attempt in field {key}')
                        sanitized_value = value.replace(pattern, '')
                
                # Limit string length
                if len(sanitized_value) > 10000:
                    sanitized_value = sanitized_value[:10000]
                
                sanitized[key] = sanitized_value
            else:
                sanitized[key] = value
        
        return sanitized
    
    def get_model_fields(self, model: str) -> Dict:
        """
        Get model field definitions
        
        Args:
            model: Model name
            
        Returns:
            Dictionary of field definitions
        """
        return self.execute_kw(model, 'fields_get')
    
    def check_access_rights(self, model: str, operation: str) -> bool:
        """
        Check if user has access rights for operation
        
        Args:
            model: Model name
            operation: Operation (read, write, create, unlink)
            
        Returns:
            True if user has access
        """
        return self.execute_kw(
            model, 'check_access_rights',
            [operation], {'raise_exception': False}
        )
    
    def test_connection(self) -> Dict:
        """
        Test connection and return server info
        
        Returns:
            Server information dictionary
        """
        try:
            version_info = self.common.version()
            
            # Test a simple read operation
            self.search('res.users', [('id', '=', self.uid)], limit=1)
            
            return {
                'status': 'connected',
                'server_version': version_info.get('server_version'),
                'protocol_version': version_info.get('protocol_version'),
                'user_id': self.uid,
                'database': self.database
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }


def example_usage():
    """Example usage of SecureOdooClient"""
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configuration
    config = {
        'url': 'https://your-odoo-server.com',
        'database': 'your_database',
        'username': 'your_username',
        'password': 'your_password'
    }
    
    try:
        # Create secure client
        client = SecureOdooClient(**config)
        
        # Test connection
        connection_info = client.test_connection()
        print(f"Connection test: {connection_info}")
        
        # Search partners
        partner_ids = client.search(
            'res.partner',
            [('is_company', '=', True)],
            limit=5
        )
        print(f"Found {len(partner_ids)} companies")
        
        # Read partner data
        if partner_ids:
            partners = client.read(
                'res.partner',
                partner_ids[:3],
                ['name', 'email', 'phone']
            )
            
            for partner in partners:
                print(f"Company: {partner.get('name')}")
        
        # Create a new partner (example)
        new_partner_data = {
            'name': 'Test Company via API',
            'is_company': True,
            'email': 'test@example.com'
        }
        
        # Uncomment to create (be careful in production!)
        # new_partner_id = client.create('res.partner', new_partner_data)
        # print(f"Created partner with ID: {new_partner_id}")
        
        # Get model fields
        partner_fields = client.get_model_fields('res.partner')
        print(f"Partner model has {len(partner_fields)} fields")
        
        # Check access rights
        can_write = client.check_access_rights('res.partner', 'write')
        print(f"Can write partners: {can_write}")
        
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == '__main__':
    example_usage()