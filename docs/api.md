# API Reference

!!! info "Overview"
    This document provides comprehensive API documentation for the Coverage Analyzer's core components: StellarCyberAPI, StellarMitre, and StreamlitCoverageAnalyzer.

## StellarCyberAPI

The `StellarCyberAPI` class provides a Python interface for interacting with the Stellar Cyber API. It handles authentication, request management, and provides methods for retrieving various types of data from the platform.

### Key Features

- Automatic token management and refresh
- Cached HTTP requests for improved performance
- Support for multiple Stellar Cyber platform versions
- Methods for retrieving tenants, connectors, detections, and data sources
- Elasticsearch query interface
- Comprehensive data source analytics

### Usage Examples

```python
# Initialize the API client
api = StellarCyberAPI(
    host="https://example.stellarcyber.cloud",
    username="user@example.com",
    api_key="your-api-key",
    version="5.2.x"
)

# Get list of tenants
tenants = api.get_tenants()

# Get detections for a specific tenant
detections = api.get_detections(tenant_id="tenant-id")

# Get data sources for a date range
from datetime import date
sources = api.get_connector_log_data_sources(
    start_date=date(2023, 1, 1),
    end_date=date(2023, 12, 31),
    tenant="tenant-name"
)
```

### Error Handling

The API client handles various types of errors:
- HTTPError: For HTTP-level errors (4xx, 5xx responses)
- ConnectionError: For network connectivity issues
- Timeout: For request timeouts
- RequestException: For general request handling errors

### Version Compatibility

The client supports multiple Stellar Cyber platform versions:
- 4.3.0
- 4.3.1
- 4.3.7
- 5.1.x
- 5.2.x
- 5.3.x

## StellarMitre

The `StellarMitre` class provides functionality for interacting with the MITRE ATT&CK framework and Stellar Cyber's detection data.

### Key Features

- MITRE ATT&CK Integration: Automatic download and caching of MITRE ATT&CK STIX files
- Tactics & Techniques: Methods for retrieving MITRE tactics and techniques with detailed metadata
- Detection Integration: Integration with Stellar Cyber's detection data sources and mappings
- Version Support: Support for multiple Stellar Cyber platform versions
- Performance: Cached HTTP requests for improved performance

### Usage Examples

```python
# Initialize the MITRE interface
mitre = StellarMitre()

# Get all MITRE tactics
tactics = mitre.get_tactics()

# Get all MITRE techniques
techniques = mitre.get_techniques()

# Get techniques for specific tactic
tactic_techniques = mitre.get_techniques_by_tactic("initial-access")

# Get combined tactics and techniques
tactics_and_techniques = mitre.get_tactics_and_techniques()

# Get Stellar Cyber detection data sources
datasources = mitre.get_detections_datasources()
```

## StreamlitCoverageAnalyzer

The `StreamlitCoverageAnalyzer` class provides a Streamlit-optimized interface for analyzing security coverage data.

### Key Features

- Streamlit Integration: Built-in caching optimized for Streamlit applications
- Coverage Analysis: Comprehensive MITRE ATT&CK coverage analysis
- Data Source Tracking: Detailed data source usage tracking and statistics
- Alert Analysis: In-depth alert type analysis and statistics
- Multi-tenant Support: Support for analyzing multiple tenants
- Cache Configuration: Configurable cache TTL for performance optimization

### Usage Examples

```python
# Initialize analyzer
analyzer = StreamlitCoverageAnalyzer(
    name="My Instance",
    host="https://example.stellarcyber.cloud",
    username="user@example.com",
    api_key="your-api-key",
    version="5.2.x",
    cache_ttl="15m"  # 15 minute cache
)

# Get comprehensive coverage statistics
stats = analyzer.compile_stats(
    data_sources=selected_sources,
    start_date=start_date,
    end_date=end_date,
    tenant_name=tenant
)

# Access different aspects
tactics = stats["tactics"]
techniques = stats["techniques"]
alerts = stats["alert_types"]

# Get detailed data source statistics
ds_stats = analyzer.get_datasource_stats(selected_sources)
```

### Statistics Output Format

The `compile_stats()` method returns a comprehensive dictionary:

```python
{
    "tactics": {
        "tactic_stats": {...},
        "tactics_covered": int,
        "tactics_triggered": int,
        "tactics_available": int,
        "tactics_covered_per": float
    },
    "techniques": {
        "technique_stats": {...},
        "techniques_covered": int,
        "techniques_triggered": int,
        "techniques_available": int,
        "techniques_covered_per": float
    },
    "alert_types": {
        "alert_type_stats": {...},
        "alert_types_covered": int,
        "alert_types_triggered": int,
        "alert_types_available": int,
        "alert_types_covered_per": float
    }
}
```

### Caching

The class uses Streamlit's caching mechanisms:

Cache Type | Usage
---|---
@cache_data | For data that changes frequently
@cache_resource | For resources that should persist across reruns

The default cache TTL is 15 minutes but can be configured during initialization.
