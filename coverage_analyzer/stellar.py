import time
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Literal

from packaging.version import Version
# from tenacity import retry, stop_after_attempt, wait_exponential

from coverage_analyzer.vars import (
    APP_DIR,
    BearerTokenAuth,
    CacheSession,
    ConnectionError,
    HTTPBasicAuth,
    HTTPError,
    RequestException,
    StellarVersion,
    Timeout,
    logger,
    DETECTION_VERSIONS,
)

__version__ = "0.0.1"


class StellarCyberAPI:
    """
    StellarCyberAPI is a client for interacting with the Stellar Cyber API.

    Parameters:
        host: Stellar Cyber host URL (e.g. https://example.stellarcyber.cloud)
        username: Stellar Cyber username (Generally an email address)
        api_key: Stellar Cyber API key
        version: Stellar Cyber Platform version, defaults to "5.2.x"
        verify_ssl: Boolean to verify SSL of Stellar Cyber Host, defaults to True
    """

    HTTP_CACHE: str = APP_DIR + "/.stellar_http_cache"
    headers: dict[str, str] = {
        "Content-type": "application/json",
    }

    def __init__(
        self,
        host: str,
        username: str,
        api_key: str,
        version: Literal[
            "4.3.0", "4.3.1", "4.3.7", "5.1.x", "5.2.x", "5.3.x"
        ] = "5.2.x",
        verify_ssl: bool | None = None,
        # max_retries: int = 3,
        # retry_delay: float = 1.0,
    ):
        host = host.replace("https://", "").strip().strip("/")
        self.api_base_url: str = "https://" + host + "/connect/api/"
        self.username: str = username
        self.api_key: str = api_key
        self.version: StellarVersion = StellarVersion(version)
        self.verify_ssl: bool | None = verify_ssl
        # self.max_retries: int = max_retries
        # self.retry_delay: float = retry_delay
        self.token: dict[str, Any] = {"access_token": "", "exp": 0}
        Path(APP_DIR).mkdir(exist_ok=True)
        self._session: CacheSession = CacheSession(
            cache_name=self.HTTP_CACHE,
            expire_after=timedelta(hours=1),
            stale_if_error=True,
            retries=3,
            # cache_control=True,
        )

    # @retry(
    #     stop=stop_after_attempt(3),
    #     wait=wait_exponential(multiplier=1, min=4, max=10),
    #     reraise=True,
    # )
    def _http_request(
        self,
        method: str,
        api_endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        auth: HTTPBasicAuth | BearerTokenAuth | None = None,
        timeout: tuple[int, int] | None = None,
    ) -> dict[str, Any]:
        """
        Private method to make HTTP requests to the Stellar Cyber API.
        Implements retry logic with exponential backoff.

        Parameters:
            method: HTTP method to use (GET, POST, PUT, DELETE).
            api_endpoint: API endpoint URL.
            params: Request parameters dictionary. Defaults to None.
            data: Request JSON dictionary. Defaults to None.
            auth: Either Basic or Bearer auth object. Defaults to None.
            timeout: Custom timeout tuple (connect timeout, read timeout). Defaults to (15, 45).

        Returns:
            Response JSON dictionary.

        Raises:
            HTTPError: If the API request fails after all retries
            ConnectionError: If connection cannot be established
            Timeout: If request times out
            RequestException: For other request-related errors
        """
        start_time = time.time()
        try:
            response = self._session.request(
                method,
                url=self.api_base_url + api_endpoint,
                auth=auth,
                params=params,
                json=data,
                # headers=StellarCyberAPI.headers,
                verify=self.verify_ssl,
                # timeout=timeout or (15, 45),  # Use custom timeout if provided, otherwise default
            )
            response.raise_for_status()

            # Log response time for monitoring
            elapsed = time.time() - start_time
            logger.debug(f"API request to {api_endpoint} completed in {elapsed:.2f}s")

            return response.json()

        except HTTPError as e:
            elapsed = time.time() - start_time
            logger.exception(
                f"HTTP error occurred calling {api_endpoint} after {elapsed:.2f}s: {str(e)}"
            )
            if e.response is not None:
                logger.exception(f"Response status code: {e.response.status_code}")
                logger.exception(f"Response body: {e.response.text}")
            raise
        except ConnectionError as e:
            elapsed = time.time() - start_time
            logger.exception(
                f"Connection error occurred calling {api_endpoint} after {elapsed:.2f}s: {str(e)}"
            )
            raise
        except Timeout as e:
            elapsed = time.time() - start_time
            logger.exception(
                f"Request timed out calling {api_endpoint} after {elapsed:.2f}s: {str(e)}"
            )
            raise
        except RequestException as e:
            elapsed = time.time() - start_time
            logger.exception(
                f"Request exception occurred calling {api_endpoint} after {elapsed:.2f}s: {str(e)}"
            )
            raise

    def _refresh_token(self) -> dict[str, Any]:
        """
        Private method to generate new access token from Stellar Cyber API.
        Implements retry logic via _http_request.

        Returns:
            Response JSON dictionary containing new access token.
        """
        return self._http_request(
            method="POST",
            api_endpoint="v1/access_token",
            auth=HTTPBasicAuth(username=self.username, password=self.api_key),
        )

    def _get_token(self) -> str:
        """
        Private method to return the current access token string, refreshing if necessary.
        Includes token expiration handling.

        Returns:
            Access token string.
        """
        # Add buffer time to prevent token expiration during request
        if self.token["exp"] > int(time.time()) + 30:
            return self.token["access_token"]
        else:
            self.token = self._refresh_token()
            return self.token["access_token"]

    def _get_data(
        self,
        api_endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        timeout: tuple[int, int] | None = None,
    ) -> dict[str, Any]:
        """
        Private GET request method to Stellar Cyber API using Bearer token auth.
        Implements retry logic via _http_request.

        Parameters:
            api_endpoint: API endpoint path.
            params: Request parameters dictionary. Defaults to None.
            data: Request JSON dictionary. Defaults to None.
            timeout: Custom timeout tuple. Defaults to None.

        Returns:
            Response JSON dictionary.
        """
        return self._http_request(
            "GET",
            api_endpoint=api_endpoint,
            params=params,
            data=data,
            auth=BearerTokenAuth(self._get_token()),
            timeout=timeout,
        )

    def _post_data(
        self,
        api_endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Private POST request method to Stellar Cyber API using Bearer token auth.
        Implements retry logic via _http_request.

        Parameters:
            api_endpoint: API endpoint path.
            params: Request parameters dictionary. Defaults to None.
            data: Request JSON dictionary. Defaults to None.

        Returns:
            Response JSON dictionary.
        """
        return self._http_request(
            "POST",
            api_endpoint=api_endpoint,
            params=params,
            data=data,
            auth=BearerTokenAuth(self._get_token()),
        )

    def get_token(self) -> str:
        """
        Public method to return the current access token as string.

        Returns:
            Access token string.
        """
        return self._get_token()

    def get_tenants(
        self, as_options: bool | None = None
    ) -> list[str] | list[dict[str, Any]]:
        """
        Public method to return a list of tenants from the Stellar Cyber API.

        Parameters:
            as_options: Return just tenant names as sorted list. Defaults to False.

        Returns:
            List of tenants as dictionaries or names.
        """
        tenants = self._get_data("v1/tenants").get("data", [])
        if as_options and len(tenants) > 0:
            return sorted([i["cust_name"] for i in tenants], key=str.lower)
        return tenants

    def es_search(self, index: str, query: dict) -> dict[str, Any]:
        """
        Public method to query Stellar Cyber Elasticsearch index with query.

        Parameters:
            index: Elasticsearch index name.
            query: Query dictionary.

        Returns:
            Response JSON dictionary.
        """
        return self._get_data(f"data/{index}/_search", data=query)

    def get_connectors(self, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """
        Public method to return a list of connectors from the Stellar Cyber API.

        Args:
            tenant_id: Supply a tenant_id to restrict to a single tenant. Defaults to None.

        Returns:
            List of connectors as dictionaries.
        """
        return self._get_data(
            api_endpoint="v1/connectors",
            params={"cust_id": tenant_id} if tenant_id else None,
        ).get("data", [])

    def get_detections(
        self,
        tenant_id: str | None = None,
        only_builtin: bool | None = None,
        only_custom: bool | None = None,
    ) -> list[dict[str, Any]]:
        """
        Public method to return a list of detections from the Stellar Cyber API. Either all, only built-in, or only custom.

        Args:
            tenant_id: Supply a tenant_id to restrict to a single tenant. Defaults to None.
            only_builtin: Return only built-in detections. Defaults to False.
            only_custom: Return only custom detections. Defaults to False.

        Returns:
            List of detections as dictionaries.
        """
        detections: list = []
        if Version(DETECTION_VERSIONS[self.version.value]) < Version(
            DETECTION_VERSIONS[StellarVersion.V5_2_X.value]
        ):
            return detections
        # Use extended timeout for this endpoint since it can return large amounts of data
        detections = self._get_data(
            api_endpoint="v1/custom_security_events",
            params={"cust_id": tenant_id} if tenant_id else None,
            # timeout=(15, 120),  # 15s connect timeout, 120s read timeout
        ).get("data", [])
        if only_builtin:
            return [d for d in detections if d["built_in"]]
        if only_custom:
            return [d for d in detections if not d["built_in"]]
        return detections

    def get_connector_log_data_sources(
        self, start_date: date, end_date: date, tenant: str | None = None
    ) -> list[str]:
        """
        Public method to return a list of connector log data sources.

        Args:
            start_date: Start date object for query.
            end_date: End date object for query.
            tenant: Tenant to restrict to single tenant. Defaults to None.

        Returns:
            List of connector log data sources.
        """
        if not isinstance(start_date, date) or not isinstance(end_date, date):
            raise TypeError("start_date and end_date must be date objects.")
        if start_date > end_date:
            raise ValueError("start_date must be before end_date.")

        index = "aella-ade-*"
        tenant_filter = {
            "bool": {
                "should": [{"match_phrase": {"tenant_name": tenant}}],
                "minimum_should_match": 1,
            }
        }
        log_msgtype_filter = {
            "bool": {"should": [{"match": {"msgtype": 39}}], "minimum_should_match": 1}
        }
        connector_msgtype_filter = {
            "bool": {"should": [{"match": {"msgtype": 40}}], "minimum_should_match": 1}
        }
        date_filter = {
            "range": {
                "timestamp": {
                    "gte": start_date.strftime("%Y-%m-%d"),
                    "lte": end_date.strftime("%Y-%m-%d"),
                    "format": "strict_date_optional_time",
                }
            }
        }
        if tenant:
            log_bool_filter = {"bool": {"filter": [tenant_filter, log_msgtype_filter]}}
            connector_bool_filter = {
                "bool": {"filter": [tenant_filter, connector_msgtype_filter]}
            }
        else:
            log_bool_filter = log_msgtype_filter
            connector_bool_filter = connector_msgtype_filter

        log_query_filter = [log_bool_filter, date_filter]

        log_query = {
            "aggs": {
                "log": {
                    "terms": {
                        "field": "stage_output.msg_origin_source.keyword",
                        "order": {"_count": "desc"},
                        "size": 1000,
                    }
                }
            },
            "size": 0,
            "query": {
                "bool": {
                    "must": [],
                    "filter": log_query_filter,
                    "should": [],
                    "must_not": [],
                }
            },
        }
        response = self.es_search(index, log_query)
        logs = []
        for b in response["aggregations"]["log"]["buckets"]:
            logs.append(b["key"])

        connector_query_filter = [connector_bool_filter, date_filter]

        connector_query = {
            "aggs": {
                "connector": {
                    "terms": {
                        "field": "msg_origin.source.keyword",
                        "order": {"_count": "desc"},
                        "size": 1000,
                    }
                }
            },
            "size": 0,
            "query": {
                "bool": {
                    "must": [],
                    "filter": connector_query_filter,
                    "should": [],
                    "must_not": [],
                }
            },
        }
        response = self.es_search(index, connector_query)
        connectors = []
        for b in response["aggregations"]["connector"]["buckets"]:
            connectors.append(b["key"])

        return logs + connectors

    def get_sensor_sources(
        self, start_date: date, end_date: date, tenant: str | None = None
    ) -> list[str]:
        """
        Public method to return a list of sensor sources.

        Args:
            start_date: Start date object for query.
            end_date: End date object for query.
            tenant: Tenant to restrict to single tenant. Defaults to None.

        Returns:
            List of sensor sources.
        """
        if not isinstance(start_date, date) or not isinstance(end_date, date):
            raise TypeError("start_date and end_date must be date objects.")
        if start_date > end_date:
            raise ValueError("start_date must be before end_date.")

        index = "aella-ade-*"
        sensor_types = []
        sensor_queries = [
            {
                "type": "linux_sensor",
                "sensor_type_filter": {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "filter": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"feature": "ds"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"mode": "agent"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                            {
                                "bool": {
                                    "filter": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {
                                                        "match_phrase": {
                                                            "feature": "modular"
                                                        }
                                                    }
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"mode": "agent"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "msgtype_filter": {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "should": [{"match": {"msgtype": 37}}],
                                    "minimum_should_match": 1,
                                }
                            },
                            {
                                "bool": {
                                    "should": [{"match": {"msgtype": 34}}],
                                    "minimum_should_match": 1,
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
            },
            {
                "type": "windows_sensor",
                "sensor_type_filter": {
                    "bool": {
                        "should": [{"match": {"feature": "wds"}}],
                        "minimum_should_match": 1,
                    }
                },
                "msgtype_filter": {
                    "bool": {
                        "should": [{"match": {"msgtype": 35}}],
                        "minimum_should_match": 1,
                    }
                },
            },
            {
                "type": "network_sensor",
                "sensor_type_filter": {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "filter": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"feature": "ds"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"mode": "device"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                            {
                                "bool": {
                                    "filter": [
                                        {
                                            "bool": {
                                                "should": [
                                                    {
                                                        "match_phrase": {
                                                            "feature": "modular"
                                                        }
                                                    }
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                        {
                                            "bool": {
                                                "should": [
                                                    {"match_phrase": {"mode": "device"}}
                                                ],
                                                "minimum_should_match": 1,
                                            }
                                        },
                                    ]
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "msgtype_filter": {
                    "bool": {
                        "should": [{"match": {"msgtype": 37}}],
                        "minimum_should_match": 1,
                    }
                },
            },
            {
                "type": "security_sensor",
                "sensor_type_filter": {
                    "bool": {
                        "should": [{"match": {"feature": "sds"}}],
                        "minimum_should_match": 1,
                    }
                },
                "msgtype_filter": {
                    "bool": {
                        "should": [
                            {
                                "bool": {
                                    "should": [{"match": {"msgtype": 37}}],
                                    "minimum_should_match": 1,
                                }
                            },
                            {
                                "bool": {
                                    "should": [{"match": {"msgtype": 33}}],
                                    "minimum_should_match": 1,
                                }
                            },
                        ],
                        "minimum_should_match": 1,
                    }
                },
            },
        ]

        for sensor_query in sensor_queries:
            tenant_filter = {
                "bool": {
                    "should": [{"match_phrase": {"tenant_name": tenant}}],
                    "minimum_should_match": 1,
                }
            }

            sensor_type_filter = sensor_query["sensor_type_filter"]
            msgtype_filter = sensor_query["msgtype_filter"]

            date_filter = {
                "range": {
                    "timestamp": {
                        "gte": start_date.strftime("%Y-%m-%d"),
                        "lte": end_date.strftime("%Y-%m-%d"),
                        "format": "strict_date_optional_time",
                    }
                }
            }

            if tenant:
                bool_filter = {
                    "bool": {
                        "filter": [tenant_filter, sensor_type_filter, msgtype_filter]
                    }
                }
            else:
                bool_filter = {"bool": {"filter": [sensor_type_filter, msgtype_filter]}}

            query_filter = [bool_filter, date_filter]

            timeseries_query = {
                "aggs": {
                    "date": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "1d",
                            "time_zone": "+00:00",
                            "min_doc_count": 0,
                            "extended_bounds": {
                                "min": start_date.strftime("%Y-%m-%d"),
                                "max": end_date.strftime("%Y-%m-%d"),
                            },
                        },
                        "aggs": {
                            "out_bytes_delta_total": {
                                "sum": {"field": "out_bytes_delta"}
                            }
                        },
                    }
                },
                "size": 0,
                "query": {
                    "bool": {
                        "must": [],
                        "filter": query_filter,
                        "should": [],
                        "must_not": [],
                    }
                },
            }

            response = self.es_search(index, timeseries_query)
            sensor_stats = {
                "volume_per_day": {"date": [], "volume": []},
                "cumulative_volume": 0,
                "unique_sensors": 0,
            }
            for b in response["aggregations"]["date"]["buckets"]:
                sensor_stats["volume_per_day"]["date"].append(b["key_as_string"][0:10])
                sensor_stats["volume_per_day"]["volume"].append(
                    b["out_bytes_delta_total"]["value"]
                )
                sensor_stats["cumulative_volume"] = sum(
                    sensor_stats["volume_per_day"]["volume"]
                )
            if sensor_stats["cumulative_volume"] > 0:
                sensor_types.append(sensor_query["type"])

        return sensor_types

    def alert_stats(
        self, start_date: date, end_date: date, tenant: str | None = None
    ) -> dict[str, Any]:
        """
        Public method to return alert statistics for a given date range.

        Args:
            start_date: Start date object for query.
            end_date: End date object for query.
            tenant: Tenant to restrict to single tenant. Defaults to None.

        Returns:
            Alert statistics dictionary.
        """
        if not isinstance(start_date, date) or not isinstance(end_date, date):
            raise TypeError("start_date and end_date must be date objects.")
        if start_date > end_date:
            raise ValueError("start_date must be before end_date.")

        alert_stats = {"unique_alert_types": {}}

        index = "aella-ser-*"

        # Unique alert type count
        tenant_filter = {
            "bool": {
                "should": [{"match_phrase": {"tenant_name": tenant}}],
                "minimum_should_match": 1,
            }
        }

        date_filter = {
            "range": {
                "timestamp": {
                    "gte": start_date.strftime("%Y-%m-%d"),
                    "lte": end_date.strftime("%Y-%m-%d"),
                    "format": "strict_date_optional_time",
                }
            }
        }

        base_count_query = {
            "aggs": {
                "alert_type": {
                    "terms": {
                        "field": "xdr_event.display_name.keyword",
                        "order": {"_count": "desc"},
                        "size": 10000,
                    }
                }
            },
            "size": 0,
            "query": {
                "bool": {
                    "must": [],
                    "filter": [tenant_filter, date_filter] if tenant else date_filter,
                    "should": [],
                    "must_not": [],
                }
            },
        }

        count_response = self.es_search(index, base_count_query)
        alert_type_hits = {}
        for a in count_response["aggregations"]["alert_type"]["buckets"]:
            alert_type_hits[a["key"]] = a["doc_count"]
        alert_stats["alert_type_hits"] = alert_type_hits

        return alert_stats
