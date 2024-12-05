from datetime import timedelta
from pathlib import Path
from typing import Any, Literal, TypedDict

import json
from loguru import logger
from mitreattack.stix20 import MitreAttackData, Tactic

from coverage_analyzer.vars import APP_DIR, DETECTION_VERSIONS, CacheSession

BaseDict = dict[str, Any]


class TacticDict(TypedDict, total=False):
    name: str
    shortname: str
    external_id: str


class TechniqueDict(TypedDict, total=False):
    name: str
    external_id: str
    description: str


class TacticWithTechniques(TacticDict, total=False):
    techniques: list[TechniqueDict]


class DataSourceDict(TypedDict, total=False):
    _id: str
    name: str
    additional_fields: dict[str, Any]


class DetectionDict(TypedDict, total=False):
    data_sources_required: list[str]
    data_sources_dependency: list[str]
    data_sources_recommended: list[str]
    data_sources_default: list[str]
    data_sources_optional: list[str]
    data_sources_combined: list[str]
    additional_fields: dict[str, Any]


class StellarMitre:
    """
    This class handles interactions with the MITRE ATT&CK framework.
    Implements caching, efficient data processing, and error handling.
    """

    FILE_DIR = APP_DIR + "/mitre_files/"
    HTTP_CACHE = APP_DIR + "/.mitre_http_cache"
    ENTERPRISE_ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    # CACHE_SIZE = 1024  # LRU cache size for frequently accessed data

    def __init__(self) -> None:
        """Initialize StellarMitre with optimized caching and file handling."""
        try:
            Path(APP_DIR).mkdir(exist_ok=True)
            self._session = CacheSession(
                cache_name=self.HTTP_CACHE,
                expire_after=timedelta(hours=1),
                stale_if_error=True,
                retries=3,
                # cache_control=True,
            )
            self._init_files()
            self.enterprise_attack = self._load_enterprise_attack()
        except Exception as e:
            logger.error(f"Error initializing StellarMitre: {str(e)}")
            raise

    def _init_files(self) -> None:
        """Initialize MITRE ATT&CK STIX files with optimized download and error handling."""
        try:
            Path(self.FILE_DIR).mkdir(parents=True, exist_ok=True)
            file_path = Path(self.FILE_DIR + "enterprise-attack.json")

            if not file_path.is_file():
                logger.info("Downloading MITRE ATT&CK STIX file...")
                with self._session as session:
                    response = session.get(self.ENTERPRISE_ATTACK_URL, timeout=(5, 30))
                response.raise_for_status()

                if response.content:
                    with Path(file_path).open("wb") as file:
                        for chunk in response.iter_content(chunk_size=8192):
                            if chunk:
                                file.write(chunk)
                    logger.info("Successfully downloaded MITRE ATT&CK STIX file")
                else:
                    raise Exception(
                        "Empty response when downloading MITRE ATT&CK STIX file"
                    )

        except Exception as e:
            logger.error(f"Failed to initialize MITRE files: {str(e)}")
            raise

    def _load_enterprise_attack(self) -> MitreAttackData:
        """Load enterprise attack data with error handling and validation."""
        try:
            file_path = self.FILE_DIR + "enterprise-attack.json"
            return MitreAttackData(file_path)
        except Exception as e:
            logger.error(f"Failed to load enterprise attack data: {str(e)}")
            raise

    def get_tactics(self) -> list[dict[str, Any]]:
        """Return a cached list of tactics from the MITRE ATT&CK framework."""
        try:
            all_tactics: list[Tactic] = self.enterprise_attack.get_tactics()
            tactics: list[dict[str, Any]] = []

            for tactic in all_tactics:
                ext_id = next(
                    (
                        ext_ref.external_id
                        for ext_ref in tactic.external_references
                        if ext_ref.source_name == "mitre-attack"
                    ),
                    "",
                )
                tactics.append(
                    {
                        "name": tactic.name,
                        "shortname": tactic.x_mitre_shortname,
                        "external_id": ext_id,
                    }
                )
            if not Path(APP_DIR + "/mitre_tactics.json").exists():
                with Path(APP_DIR + "/mitre_tactics.json").open("w") as file:
                    json.dump(tactics, file)
            return tactics
        except Exception as e:
            logger.error(f"Error getting tactics: {str(e)}")
            raise

    def get_techniques(self) -> list[dict[str, Any]]:
        """Return a cached list of techniques from the MITRE ATT&CK framework."""
        try:
            all_techniques = self.enterprise_attack.get_techniques(
                include_subtechniques=False
            )
            techniques: list[dict[str, Any]] = []

            for technique in all_techniques:
                ext_id = next(
                    (
                        ext_ref.external_id
                        for ext_ref in technique.external_references
                        if ext_ref.source_name == "mitre-attack"
                    ),
                    "",
                )
                techniques.append(
                    {
                        "name": technique.name,
                        "description": technique.description,
                        "external_id": ext_id,
                    }
                )
            if not Path(APP_DIR + "/mitre_techniques.json").exists():
                with Path(APP_DIR + "/mitre_techniques.json").open("w") as file:
                    json.dump(techniques, file)
            return techniques
        except Exception as e:
            logger.error(f"Error getting techniques: {str(e)}")
            raise

    def get_techniques_by_tactic(self, tactic: str) -> list[dict[str, Any]]:
        """Return a cached list of techniques by tactic."""
        try:
            techniques = self.enterprise_attack.get_techniques_by_tactic(
                tactic, domain="enterprise-attack"
            )
            new_techniques: list[dict[str, Any]] = []

            for technique in techniques:
                if not technique.x_mitre_is_subtechnique:
                    ext_id = next(
                        (
                            ext_ref.external_id
                            for ext_ref in technique.external_references
                            if ext_ref.source_name == "mitre-attack"
                        ),
                        "",
                    )
                    new_techniques.append(
                        {"name": technique.name, "external_id": ext_id}
                    )

            return new_techniques
        except Exception as e:
            logger.error(f"Error getting techniques by tactic: {str(e)}")
            raise

    def get_tactics_and_techniques(self) -> list[dict[str, Any]]:
        """Return a list of tactics with their associated techniques."""
        try:
            tactics = self.get_tactics()
            result: list[dict[str, Any]] = []

            for tactic in tactics:
                tactic_with_techniques = dict(tactic)
                tactic_with_techniques["techniques"] = self.get_techniques_by_tactic(
                    tactic["shortname"]
                )
                result.append(tactic_with_techniques)
            if not Path(APP_DIR + "/mitre_tactics_and_techniques.json").exists():
                with Path(APP_DIR + "/mitre_tactics_and_techniques.json").open(
                    "w"
                ) as file:
                    json.dump(result, file)
            return result
        except Exception as e:
            logger.error(f"Error getting tactics and techniques: {str(e)}")
            raise

    def get_detections_datasources(
        self, as_options: bool | None = None
    ) -> list[str] | list[dict[str, Any]]:
        """Return a list of data sources from detections.stellarcyber.ai"""
        try:
            with self._session as session:
                response = session.get(
                    "https://detections-api.herokuapp.com/get-data-sources/",
                    timeout=(5, 30),
                )
            response.raise_for_status()
            datasources = response.json().get("data_sources", [])

            if as_options:
                return sorted([ds["_id"] for ds in datasources], key=str.lower)
            return [{"_id": ds["_id"], "name": ds["name"]} for ds in datasources]
        except Exception as e:
            logger.error(f"Error getting detection datasources: {str(e)}")
            raise

    def _parse_ds_recommendations(
        self, ds_recommendations: list[str] | str | None
    ) -> list[str]:
        """Parse data source recommendations efficiently."""
        try:
            if ds_recommendations is None:
                return []
            if isinstance(ds_recommendations, str):
                return [tr for tr in ds_recommendations.split(",") if tr]
            if isinstance(ds_recommendations, list):
                return [r for r in ds_recommendations if r is not None]
            return []
        except Exception as e:
            logger.error(f"Error parsing DS recommendations: {str(e)}")
            return []

    def get_detections(
        self,
        version: Literal[
            "4.3.0", "4.3.1", "4.3.7", "5.1.x", "5.2.x", "5.3.x"
        ] = "5.2.x",
    ) -> list[dict[str, Any]]:
        """Return a list of detections from detections.stellarcyber.ai"""
        try:
            with self._session as session:
                response = session.post(
                    "https://detections-api.herokuapp.com/get-all-detections",
                    data={"version": DETECTION_VERSIONS[version]},
                    timeout=(5, 30),
                )
            response.raise_for_status()

            detections = response.json().get("detections", [])
            ds_fields = [
                "data_sources_required",
                "data_sources_dependency",
                "data_sources_recommended",
                "data_sources_default",
                "data_sources_optional",
            ]

            processed_detections: list[dict[str, Any]] = []
            for detection in detections:
                processed_detection: dict[str, Any] = {}
                combined_recs: list[str] = []
                for key in dict(detection):
                    if key in ds_fields:
                        combined_recs.extend(
                            self._parse_ds_recommendations(detection[key])
                        )
                    else:
                        processed_detection[key] = detection[key]

                processed_detection["data_sources_combined"] = list(set(combined_recs))
                processed_detections.append(processed_detection)
            if not Path(APP_DIR + "/web_detections.json").exists():
                with Path(APP_DIR + "/web_detections.json").open("w") as file:
                    json.dump(processed_detections, file)
            return processed_detections
        except Exception as e:
            logger.error(f"Error getting detections: {str(e)}")
            raise

    def generate_navigator_layer(
        self,
        name: str,
        techniques_with_scores: dict[str, float],
        description: str | None = None,
    ) -> dict[str, Any]:
        """Generate a MITRE ATT&CK Navigator layer file.

        Args:
            name: Name of the layer
            techniques_with_scores: Dictionary mapping technique IDs to scores (0-100)
            description: Optional description of the layer

        Returns:
            Dictionary containing the ATT&CK Navigator layer data
        """
        try:
            # # Validate technique IDs against known techniques
            # valid_techniques = {
            #     t["external_id"]: t["name"] for t in self.get_techniques()
            # }

            # Filter out invalid technique IDs
            valid_techniques_with_scores = dict(techniques_with_scores.items())

            if not valid_techniques_with_scores:
                raise ValueError("No valid technique IDs provided")

            # Build techniques list for layer
            techniques_list = []
            for tid, score in valid_techniques_with_scores.items():
                # Ensure score is between 0-100
                normalized_score = max(0, min(100, float(score)))

                technique = {
                    "techniqueID": tid,
                    "score": normalized_score,
                    # "color": "",
                    "comment": "",
                    "enabled": True,
                    "metadata": [],
                    "showSubtechniques": False,
                }
                techniques_list.append(technique)

            # Build layer structure
            layer = {
                "name": name,
                "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
                "domain": "enterprise-attack",
                "description": description or "",
                "filters": {
                    "platforms": [
                        "Linux",
                        "macOS",
                        "Windows",
                        "Network",
                        "Containers",
                        "Office 365",
                        "SaaS",
                        "IaaS",
                        "Google Workspace",
                    ]
                },
                "sorting": 1,
                "layout": {
                    "layout": "flat",
                    "aggregateFunction": "sum",
                    "showID": True,
                    "showName": True,
                    "showAggregateScores": True,
                    "countUnscored": False,
                },
                "hideDisabled": True,
                "techniques": techniques_list,
                "gradient": {
                    "colors": [
                        "#ff6666",  # Red for low scores
                        "#ffcb2f",  # Yellow for medium scores
                        "#8ec843",  # Green for high scores
                    ],
                    "minValue": 0,
                    "maxValue": 100,
                },
                "metadata": [],
                "showTacticRowBackground": False,
                "tacticRowBackground": "#dddddd",
                "selectTechniquesAcrossTactics": True,
                "selectSubtechniquesWithParent": False,
            }

            return layer

        except Exception as e:
            logger.error(f"Error generating navigator layer: {str(e)}")
            raise
