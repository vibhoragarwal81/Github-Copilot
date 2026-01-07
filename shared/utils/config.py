"""
Configuration management for IAMCloud
Handles loading and managing configuration from various sources
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigManager:
    """
    Configuration manager for IAMCloud components.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self.config_file = config_file
        self.config_data = {}
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file and environment variables."""
        # Load from file if specified
        if self.config_file and Path(self.config_file).exists():
            try:
                with open(self.config_file, 'r') as f:
                    if self.config_file.endswith('.yaml') or self.config_file.endswith('.yml'):
                        self.config_data = yaml.safe_load(f) or {}
                    else:
                        # Assume JSON for other formats
                        import json
                        self.config_data = json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load config file {self.config_file}: {e}")
        
        # Override with environment variables
        self._load_env_variables()
    
    def _load_env_variables(self):
        """Load environment variables into configuration."""
        env_mapping = {
            'AWS_DEFAULT_REGION': 'aws.default_region',
            'AWS_ROLE_ARN': 'aws.role_arn',
            'AWS_ACCESS_KEY_ID': 'aws.access_key_id',
            'AWS_SECRET_ACCESS_KEY': 'aws.secret_access_key',
            'AWS_SESSION_TOKEN': 'aws.session_token',
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value:
                self._set_nested_config(config_key, value)
    
    def _set_nested_config(self, key: str, value: Any):
        """Set a nested configuration value using dot notation."""
        keys = key.split('.')
        current = self.config_data
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
        
        current[keys[-1]] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key: Configuration key (e.g., 'aws.default_region')
            default: Default value if key not found
        
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        current = self.config_data
        
        try:
            for k in keys:
                current = current[k]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation.
        
        Args:
            key: Configuration key
            value: Value to set
        """
        self._set_nested_config(key, value)
    
    def get_aws_config(self) -> Dict[str, Any]:
        """
        Get AWS-specific configuration.
        
        Returns:
            Dictionary with AWS configuration
        """
        return self.config_data.get('aws', {})
    
    def get_scanning_config(self) -> Dict[str, Any]:
        """
        Get scanning-specific configuration.
        
        Returns:
            Dictionary with scanning configuration
        """
        return self.config_data.get('scanning', {})
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Get entire configuration as dictionary.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config_data.copy()


def load_repo_variables(config_file: str = None) -> Dict[str, Any]:
    """
    Load repository variables from .github-config.yaml.
    
    Args:
        config_file: Path to config file (optional)
    
    Returns:
        Dictionary of variables
    """
    if not config_file:
        # Look for .github-config.yaml in standard locations
        possible_paths = [
            Path.cwd() / '.github-config.yaml',
            Path.cwd() / 'shared' / 'config' / '.github-config.yaml',
            Path.cwd().parent / '.github-config.yaml',
        ]
        
        for path in possible_paths:
            if path.exists():
                config_file = str(path)
                break
    
    if not config_file or not Path(config_file).exists():
        return {}
    
    try:
        with open(config_file, 'r') as f:
            data = yaml.safe_load(f) or {}
            return data.get('variables', {})
    except Exception:
        return {}