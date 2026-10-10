class DetectionEngineError(Exception):
    """Base exception for detection-engine failures."""

class SchemaValidationError(DetectionEngineError, ValueError):
    """Input data violates an explicit schema or physical range."""

class InferenceInputError(DetectionEngineError, ValueError):
    """Inference input violates the strict feature contract."""

class ModelArtifactError(DetectionEngineError):
    """Persisted model artifact is unavailable or invalid."""
