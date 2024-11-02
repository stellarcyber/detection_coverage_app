# Testing Guide

## Overview

This guide outlines testing strategies and best practices for the Coverage Analyzer application. It covers unit testing, integration testing, performance testing, and security testing.

## Test Structure

```
tests/
├── unit/
│   ├── test_mitre.py
│   ├── test_stellar.py
│   ├── test_plots.py
│   └── test_streamlit.py
├── integration/
│   ├── test_api_integration.py
│   └── test_data_flow.py
├── performance/
│   ├── test_data_processing.py
│   └── test_visualization.py
└── conftest.py
```

## Unit Testing

### MITRE Integration Tests

```python
def test_get_tactics():
    mitre = StellarMitre()
    tactics = mitre.get_tactics()
    assert isinstance(tactics, list)
    assert all(isinstance(t, dict) for t in tactics)
    assert all("name" in t for t in tactics)

def test_get_techniques():
    mitre = StellarMitre()
    techniques = mitre.get_techniques()
    assert isinstance(techniques, list)
    assert all(isinstance(t, dict) for t in techniques)
    assert all("name" in t for t in techniques)
```

### API Client Tests

```python
def test_api_authentication():
    api = StellarCyberAPI(host="test", username="test", api_key="test")
    with pytest.raises(HTTPError):
        api.get_token()

def test_token_refresh():
    api = StellarCyberAPI(host="test", username="test", api_key="test")
    api.token = {"access_token": "test", "exp": 0}
    assert api._get_token() != "test"
```

### Data Processing Tests

```python
def test_prepare_coverage_data():
    test_data = pl.DataFrame({
        "tactic": ["test"],
        "technique": ["test"],
        "covered": [True],
        "triggered": [False]
    })
    result = prepare_coverage_data(test_data)
    assert isinstance(result, pl.DataFrame)
    assert "coverage_ratio" in result.columns
```

## Integration Testing

### API Integration

```python
def test_full_data_flow():
    analyzer = StreamlitCoverageAnalyzer(
        name="test",
        host="test",
        username="test",
        api_key="test"
    )
    stats = analyzer.compile_stats(
        data_sources=["test"],
        start_date=date.today(),
        end_date=date.today()
    )
    assert isinstance(stats, dict)
    assert "tactics" in stats
    assert "techniques" in stats
```

### Data Pipeline Tests

```python
def test_data_pipeline():
    # Test data flow from API to visualization
    data = get_test_data()
    processed = process_data(data)
    visualized = create_visualization(processed)
    assert visualized is not None
```

## Performance Testing

### Data Processing Performance

```python
def test_large_dataset_performance():
    large_data = generate_large_dataset()
    start_time = time.time()
    result = process_large_dataset(large_data)
    end_time = time.time()
    assert end_time - start_time < 5.0  # Should process in under 5 seconds
```

### Memory Usage Tests

```python
def test_memory_usage():
    import psutil
    process = psutil.Process()
    initial_memory = process.memory_info().rss
    process_large_dataset()
    final_memory = process.memory_info().rss
    assert (final_memory - initial_memory) / 1024 / 1024 < 100  # Less than 100MB increase
```

## Load Testing

### API Load Tests

```python
def test_api_load():
    import asyncio
    async def make_requests():
        tasks = [api_request() for _ in range(100)]
        return await asyncio.gather(*tasks)
    
    results = asyncio.run(make_requests())
    assert all(r.status_code == 200 for r in results)
```

### Concurrent User Tests

```python
def test_concurrent_users():
    import threading
    users = [threading.Thread(target=simulate_user) for _ in range(10)]
    for user in users:
        user.start()
    for user in users:
        user.join()
```

## Security Testing

### Input Validation Tests

```python
def test_input_validation():
    with pytest.raises(ValueError):
        process_data({"malicious": "input"})
    
    with pytest.raises(ValueError):
        process_data({"sql": "DROP TABLE users"})
```

### Authentication Tests

```python
def test_authentication():
    with pytest.raises(HTTPError):
        api.get_token(invalid_credentials=True)
    
    assert api.get_token(valid_credentials=True) is not None
```

## Test Configuration

### pytest Configuration

```python
# conftest.py
import pytest

@pytest.fixture
def test_data():
    return {
        "tactics": ["test_tactic"],
        "techniques": ["test_technique"]
    }

@pytest.fixture
def mock_api():
    return MockAPI()
```

### Environment Setup

```python
# test_environment.py
import os

os.environ["TEST_MODE"] = "true"
os.environ["MOCK_API"] = "true"
```

## Continuous Integration

### GitHub Actions

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: |
          python -m pip install poetry
          poetry install
      - name: Run tests
        run: |
          poetry run pytest
```

## Test Coverage

### Coverage Configuration

```ini
# .coveragerc
[run]
source = coverage_analyzer
omit = tests/*

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    raise NotImplementedError
```

### Coverage Reporting

```python
# Run tests with coverage
poetry run pytest --cov=coverage_analyzer --cov-report=term-missing
```

## Best Practices

1. Test Organization
   - Group related tests
   - Use meaningful names
   - Follow consistent patterns
   - Maintain test independence

2. Test Data
   - Use fixtures
   - Mock external services
   - Clean up test data
   - Use realistic samples

3. Assertions
   - Be specific
   - Check edge cases
   - Validate types
   - Test error conditions

4. Performance
   - Profile tests
   - Monitor memory usage
   - Check execution time
   - Optimize slow tests

## Maintenance

1. Regular Tasks
   - Run all tests
   - Update test data
   - Check coverage
   - Review failures

2. Updates
   - Add new tests
   - Update existing tests
   - Remove obsolete tests
   - Update documentation

3. Monitoring
   - Test execution time
   - Coverage metrics
   - Failure patterns
   - Resource usage
