#!/usr/bin/env python3
"""
Token-based REST API Client for Odoo
=====================================

Bu örnek, Odoo Token Authentication modülü ile REST API
kullanımını gösterir.

Özellikler:
- Token-based authentication
- Automatic token refresh
- Rate limiting compliance
- Error handling
- Request logging
"""

import requests
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import jwt


class OdooTokenClient:
    """Token tabanlı Odoo REST API Client"""
    
    def __init__(self, base_url: str, api_key: str, username: str, password: str):
        """
        Initialize Token Client
        
        Args:
            base_url: Odoo server base URL
            api_key: API key from token_auth module
            username: Username
            password: Password
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.username = username
        self.password = password
        
        # Token storage
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        
        # Session for connection reuse
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'OdooTokenClient/1.0'
        })
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1  # 100ms between requests
        
        # Authentication
        self._authenticate()
    
    def _authenticate(self):
        """Authenticate and get access token"""
        auth_url = f'{self.base_url}/api/v1/auth/token'
        
        auth_data = {
            'api_key': self.api_key,
            'username': self.username,
            'password': self.password,
            'scope': 'write'
        }
        
        try:
            response = self.session.post(auth_url, json=auth_data, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            
            if token_data.get('status') == 'success':
                data = token_data['data']
                self.access_token = data['access_token']
                self.refresh_token = data['refresh_token']
                
                # Calculate expiry time
                expires_in = data.get('expires_in', 3600)
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)  # 60s buffer
                
                # Update session headers
                self.session.headers.update({
                    'Authorization': f'Bearer {self.access_token}'
                })
                
                self.logger.info('Authentication successful')
                
            else:
                raise Exception(f"Authentication failed: {token_data.get('message')}")
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f'Authentication request failed: {str(e)}')
            raise
        except Exception as e:
            self.logger.error(f'Authentication error: {str(e)}')
            raise
    
    def _refresh_access_token(self):
        """Refresh access token using refresh token"""
        if not self.refresh_token:
            self.logger.warning('No refresh token available, re-authenticating')
            self._authenticate()
            return
        
        refresh_url = f'{self.base_url}/api/v1/auth/refresh'
        refresh_data = {'refresh_token': self.refresh_token}
        
        try:
            # Temporarily remove Authorization header for refresh
            auth_header = self.session.headers.pop('Authorization', None)
            
            response = self.session.post(refresh_url, json=refresh_data, timeout=30)
            response.raise_for_status()
            
            token_data = response.json()
            
            if token_data.get('status') == 'success':
                data = token_data['data']
                self.access_token = data['access_token']
                
                # Update expiry time
                expires_in = data.get('expires_in', 3600)
                self.token_expires_at = datetime.now() + timedelta(seconds=expires_in - 60)
                
                # Update session headers
                self.session.headers.update({
                    'Authorization': f'Bearer {self.access_token}'
                })
                
                self.logger.info('Token refreshed successfully')
                
            else:
                self.logger.warning('Token refresh failed, re-authenticating')
                self._authenticate()
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f'Token refresh request failed: {str(e)}')
            self._authenticate()
        except Exception as e:
            self.logger.error(f'Token refresh error: {str(e)}')
            self._authenticate()
    
    def _ensure_valid_token(self):
        """Ensure we have a valid access token"""
        if not self.access_token:
            self._authenticate()
            return
        
        if self.token_expires_at and datetime.now() >= self.token_expires_at:
            self.logger.info('Token expired, refreshing')
            self._refresh_access_token()
    
    def _rate_limit(self):
        """Apply rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """
        Make HTTP request with token management
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            **kwargs: Request parameters
            
        Returns:
            Response data
        """
        self._ensure_valid_token()
        self._rate_limit()
        
        url = f'{self.base_url}{endpoint}'
        
        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            
            # Handle token expiry
            if response.status_code == 401:
                self.logger.info('Received 401, refreshing token')
                self._refresh_access_token()
                
                # Retry request with new token
                response = self.session.request(method, url, timeout=30, **kwargs)
            
            # Handle rate limiting
            if response.status_code == 429:
                retry_after = int(response.headers.get('Retry-After', 60))
                self.logger.warning(f'Rate limited, waiting {retry_after} seconds')
                time.sleep(retry_after)
                
                # Retry request
                response = self.session.request(method, url, timeout=30, **kwargs)
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            self.logger.error(f'HTTP error for {method} {endpoint}: {str(e)}')
            if hasattr(e.response, 'text'):
                self.logger.error(f'Response: {e.response.text}')
            raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f'Request error for {method} {endpoint}: {str(e)}')
            raise
    
    def get(self, endpoint: str, params: Dict = None) -> Dict:
        """Make GET request"""
        return self._make_request('GET', endpoint, params=params)
    
    def post(self, endpoint: str, data: Dict = None) -> Dict:
        """Make POST request"""
        return self._make_request('POST', endpoint, json=data)
    
    def put(self, endpoint: str, data: Dict = None) -> Dict:
        """Make PUT request"""
        return self._make_request('PUT', endpoint, json=data)
    
    def delete(self, endpoint: str) -> Dict:
        """Make DELETE request"""
        return self._make_request('DELETE', endpoint)
    
    # Convenience methods for common operations
    
    def search_records(self, model: str, domain: List = None, limit: int = None,
                      offset: int = 0, order: str = None) -> Dict:
        """
        Search records
        
        Args:
            model: Model name
            domain: Search domain
            limit: Maximum records
            offset: Records to skip
            order: Sort order
            
        Returns:
            Search results
        """
        params = {}
        if domain:
            params['domain'] = json.dumps(domain)
        if limit:
            params['limit'] = limit
        if offset:
            params['offset'] = offset
        if order:
            params['order'] = order
        
        return self.get(f'/api/v1/{model}', params=params)
    
    def get_record(self, model: str, record_id: int, fields: List[str] = None) -> Dict:
        """
        Get single record
        
        Args:
            model: Model name
            record_id: Record ID
            fields: Fields to fetch
            
        Returns:
            Record data
        """
        params = {}
        if fields:
            params['fields'] = ','.join(fields)
        
        return self.get(f'/api/v1/{model}/{record_id}', params=params)
    
    def create_record(self, model: str, data: Dict) -> Dict:
        """
        Create record
        
        Args:
            model: Model name
            data: Record data
            
        Returns:
            Created record info
        """
        return self.post(f'/api/v1/{model}', data=data)
    
    def update_record(self, model: str, record_id: int, data: Dict) -> Dict:
        """
        Update record
        
        Args:
            model: Model name
            record_id: Record ID
            data: Update data
            
        Returns:
            Update result
        """
        return self.put(f'/api/v1/{model}/{record_id}', data=data)
    
    def delete_record(self, model: str, record_id: int) -> Dict:
        """
        Delete record
        
        Args:
            model: Model name
            record_id: Record ID
            
        Returns:
            Delete result
        """
        return self.delete(f'/api/v1/{model}/{record_id}')
    
    def get_user_info(self) -> Dict:
        """Get current user information"""
        return self.get('/api/v1/user/me')
    
    def get_model_info(self, model: str) -> Dict:
        """Get model field information"""
        return self.get(f'/api/v1/model/{model}/fields')
    
    def revoke_token(self):
        """Revoke current access token"""
        if self.access_token:
            try:
                self.post('/api/v1/auth/revoke', data={'token': self.access_token})
                self.logger.info('Token revoked successfully')
            except Exception as e:
                self.logger.warning(f'Token revocation failed: {str(e)}')
            finally:
                self.access_token = None
                self.refresh_token = None
                self.token_expires_at = None
                self.session.headers.pop('Authorization', None)


def example_usage():
    """Example usage of OdooTokenClient"""
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configuration
    config = {
        'base_url': 'https://your-odoo-server.com',
        'api_key': 'ak_your_api_key_here',
        'username': 'your_username',
        'password': 'your_password'
    }
    
    try:
        # Create token client
        client = OdooTokenClient(**config)
        
        # Get user info
        user_info = client.get_user_info()
        print(f"Logged in as: {user_info}")
        
        # Search partners
        partners_result = client.search_records(
            'res.partner',
            domain=[('is_company', '=', True)],
            limit=5
        )
        
        if partners_result.get('status') == 'success':
            partners = partners_result['data']
            print(f"Found {len(partners)} companies")
            
            # Get detailed info for first partner
            if partners:
                partner_detail = client.get_record(
                    'res.partner',
                    partners[0]['id'],
                    fields=['name', 'email', 'phone', 'city']
                )
                print(f"Partner detail: {partner_detail}")
        
        # Create a new contact
        new_contact_data = {
            'name': 'Test Contact via Token API',
            'email': 'test.token@example.com',
            'phone': '+1234567890',
            'is_company': False
        }
        
        # Uncomment to create (be careful in production!)
        # create_result = client.create_record('res.partner', new_contact_data)
        # print(f"Created contact: {create_result}")
        
        # Get model info
        model_info = client.get_model_info('res.partner')
        if model_info.get('status') == 'success':
            fields = model_info['data']
            print(f"Partner model has {len(fields)} fields")
        
        # Revoke token when done
        client.revoke_token()
        print("Token revoked")
        
    except Exception as e:
        print(f"Error: {str(e)}")


if __name__ == '__main__':
    example_usage()