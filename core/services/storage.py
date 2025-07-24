"""
Global Azure Storage Service
Handles all file uploads, storage, and management in Azure Blob Storage.
Designed to be used across all apps for any file type.
"""

import base64
import binascii
import logging
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from azure.core.exceptions import AzureError
from azure.storage.blob import (
    BlobSasPermissions,
    BlobServiceClient,
    ContentSettings,
    generate_blob_sas,
)
from django.conf import settings
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)


class AzureStorageError(APIException):
    """Custom exception for Azure Storage errors."""

    status_code = 503
    default_detail = "Azure Storage service temporarily unavailable."
    default_code = "azure_storage_error"


class FileType(Enum):
    """Supported file types with their configurations."""

    PROFILE_PICTURE = {
        "container": "media",  # Use single container from settings
        "path_template": "profile-pictures/users/{user_id}/{filename}",
        "max_size_mb": 5,
        "allowed_extensions": [".jpg", ".jpeg", ".png", ".gif", ".webp"],
        "content_types": {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp",
        },
    }

    DOCUMENT = {
        "container": "media",  # Use single container from settings
        "path_template": "documents/{user_id}/{document_type}/{filename}",
        "max_size_mb": 10,
        "allowed_extensions": [".pdf", ".doc", ".docx", ".txt"],
        "content_types": {
            ".pdf": "application/pdf",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".txt": "text/plain",
        },
    }

    GENERAL_IMAGE = {
        "container": "media",  # Use single container from settings
        "path_template": "images/{category}/{filename}",
        "max_size_mb": 10,
        "allowed_extensions": [
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".webp",
            ".bmp",
            ".tiff",
        ],
        "content_types": {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp",
            ".bmp": "image/bmp",
            ".tiff": "image/tiff",
        },
    }


class AzureStorageService:
    """
    Global service class for Azure Blob Storage operations.
    Handles all file types with configurable containers and paths.
    """

    def __init__(self):
        self.connection_string = getattr(
            settings, "AZURE_STORAGE_CONNECTION_STRING", None
        )
        self.account_name = getattr(settings, "AZURE_STORAGE_ACCOUNT_NAME", None)
        self.account_key = getattr(settings, "AZURE_STORAGE_ACCOUNT_KEY", None)
        self.default_container = getattr(settings, "AZURE_STORAGE_CONTAINER", "media")

        # Initialize blob service client
        self.blob_service_client: BlobServiceClient | None = None
        if self.connection_string:
            self.blob_service_client = BlobServiceClient.from_connection_string(
                self.connection_string
            )
        elif self.account_name and self.account_key:
            self.blob_service_client = BlobServiceClient(
                account_url=f"https://{self.account_name}.blob.core.windows.net",
                credential=self.account_key,
            )
        else:
            logger.warning("Azure Storage credentials not configured")

    def _ensure_container_exists(self, container_name: str) -> None:
        """Ensure the container exists, create if it doesn't."""
        if not self.blob_service_client:
            raise AzureStorageError("Azure Storage not configured")

        try:
            container_client = self.blob_service_client.get_container_client(
                container_name
            )
            if not container_client.exists():
                # Create private container (no public access)
                container_client.create_container()
                logger.info(f"Created private container: {container_name}")
        except AzureError as e:
            logger.error(f"Error ensuring container exists: {str(e)}")
            raise AzureStorageError(
                f"Failed to access storage container: {str(e)}"
            ) from e

    def _generate_sas_url(self, container_name: str, blob_name: str) -> str:
        """Generate a SAS URL for secure access to a private blob."""
        if not self.account_name or not self.account_key:
            raise AzureStorageError(
                "Azure Storage credentials required for SAS URL generation"
            )

        # Generate SAS token with read permissions, valid for 1 year
        sas_token = generate_blob_sas(
            account_name=self.account_name,
            container_name=container_name,
            blob_name=blob_name,
            account_key=self.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(days=365),
        )

        # Construct the full SAS URL
        blob_url = f"https://{self.account_name}.blob.core.windows.net/{container_name}/{blob_name}"
        return f"{blob_url}?{sas_token}"

    def _validate_base64_data(self, base64_data: str, file_type: FileType) -> bytes:
        """
        Validate and decode base64 data.

        Args:
            base64_data: Base64 encoded file string
            file_type: FileType enum with validation rules

        Returns:
            Decoded file bytes

        Raises:
            AzureStorageError: If file data is invalid
        """
        try:
            # Remove data URL prefix if present (e.g., "data:image/jpeg;base64,")
            if base64_data.startswith("data:"):
                base64_data = base64_data.split(",", 1)[1]

            # Validate base64 format
            file_data = base64.b64decode(base64_data, validate=True)

            # Basic validation - check file size
            config = file_type.value
            max_size_mb = config["max_size_mb"]
            if not isinstance(max_size_mb, int | float):
                raise ValueError("Invalid max_size_mb configuration")
            max_size_bytes = int(max_size_mb * 1024 * 1024)
            if len(file_data) < 100:  # Too small to be a valid file
                raise ValueError("File data too small")
            if len(file_data) > max_size_bytes:
                raise ValueError(
                    f"File data too large (max {file_type.value['max_size_mb']}MB)"
                )

            return file_data

        except (ValueError, binascii.Error) as e:
            logger.warning(f"Invalid base64 file data: {str(e)}")
            raise AzureStorageError(f"Invalid file data: {str(e)}") from e

    def _get_file_extension_from_base64(
        self, base64_data: str, file_type: FileType
    ) -> str:
        """
        Determine file extension from base64 data URL or file headers.

        Args:
            base64_data: Base64 encoded file string
            file_type: FileType enum with allowed extensions

        Returns:
            File extension (e.g., '.jpg', '.pdf')
        """
        # Check if there's a data URL prefix with MIME type
        if base64_data.startswith("data:"):
            mime_type = base64_data.split(";")[0].split("/")[1]

            # Map common MIME types to extensions
            mime_to_ext = {
                "jpeg": ".jpg",
                "jpg": ".jpg",
                "png": ".png",
                "gif": ".gif",
                "webp": ".webp",
                "pdf": ".pdf",
                "msword": ".doc",
                "plain": ".txt",
            }

            extension = mime_to_ext.get(mime_type, f".{mime_type}")
            config = file_type.value
            allowed_extensions = config["allowed_extensions"]
            if isinstance(allowed_extensions, list) and extension in allowed_extensions:
                return extension

        # Try to detect from file headers for images
        if file_type == FileType.PROFILE_PICTURE or file_type == FileType.GENERAL_IMAGE:
            try:
                file_data = base64.b64decode(base64_data.split(",")[-1], validate=True)

                # Check common image headers
                if file_data.startswith(b"\xff\xd8\xff"):
                    return ".jpg"
                elif file_data.startswith(b"\x89PNG\r\n\x1a\n"):
                    return ".png"
                elif file_data.startswith(b"GIF8"):
                    return ".gif"
                elif file_data.startswith(b"RIFF") and b"WEBP" in file_data[:12]:
                    return ".webp"
                elif file_data.startswith(b"%PDF"):
                    return ".pdf"

            except Exception:
                pass

        # Default fallback based on file type
        defaults = {
            FileType.PROFILE_PICTURE: ".jpg",
            FileType.GENERAL_IMAGE: ".jpg",
            FileType.DOCUMENT: ".pdf",
        }
        return defaults.get(file_type, ".bin")

    def upload_file(
        self,
        base64_data: str,
        file_type: FileType,
        path_params: dict[str, str],
        filename: str | None = None,
    ) -> str:
        """
        Upload a file to Azure Blob Storage.

        Args:
            base64_data: Base64 encoded file data
            file_type: FileType enum specifying storage configuration
            path_params: Parameters for path template (e.g., {"user_id": "123", "category": "avatars"})
            filename: Optional custom filename (will generate UUID if not provided)

        Returns:
            Public URL of the uploaded file

        Raises:
            AzureStorageError: If upload fails
        """
        if not self.blob_service_client:
            raise AzureStorageError("Azure Storage not configured")

        try:
            config = file_type.value
            # Use default container from settings instead of config
            container_name = self.default_container

            # Ensure container exists
            self._ensure_container_exists(container_name)

            # Validate and decode file
            file_data = self._validate_base64_data(base64_data, file_type)

            # Generate filename if not provided
            if not filename:
                file_extension = self._get_file_extension_from_base64(
                    base64_data, file_type
                )
                filename = f"{uuid.uuid4()}{file_extension}"

            # Validate file extension
            file_extension = (
                "." + filename.split(".")[-1].lower() if "." in filename else ""
            )
            allowed_extensions = config["allowed_extensions"]
            if (
                not isinstance(allowed_extensions, list)
                or file_extension not in allowed_extensions
            ):
                raise AzureStorageError(
                    f"File type {file_extension} not allowed for {file_type.name}"
                )

            # Generate blob path using template
            path_template = config["path_template"]
            if not isinstance(path_template, str):
                raise AzureStorageError("Invalid path template configuration")
            blob_path = path_template.format(filename=filename, **path_params)

            # Upload to blob storage
            blob_client = self.blob_service_client.get_blob_client(
                container=container_name, blob=blob_path
            )

            # Set content type
            content_types = config["content_types"]
            if not isinstance(content_types, dict):
                raise AzureStorageError("Invalid content types configuration")
            content_type = content_types.get(file_extension, "application/octet-stream")

            blob_client.upload_blob(
                file_data,
                overwrite=True,
                content_settings=ContentSettings(
                    content_type=content_type,
                    cache_control="public, max-age=31536000",  # 1 year cache
                ),
            )

            # Generate SAS URL for secure access to private blob
            sas_url = self._generate_sas_url(container_name, blob_path)

            logger.info(f"Successfully uploaded {file_type.name} file: {blob_path}")
            return sas_url

        except AzureError as e:
            logger.error(f"Azure Storage error uploading {file_type.name}: {str(e)}")
            raise AzureStorageError(f"Failed to upload file: {str(e)}") from e
        except Exception as e:
            logger.error(f"Unexpected error uploading {file_type.name}: {str(e)}")
            raise AzureStorageError(f"Failed to upload file: {str(e)}") from e

    def delete_file(self, blob_url: str) -> bool:
        """
        Delete a file from Azure Blob Storage.

        Args:
            blob_url: Full URL of the blob to delete

        Returns:
            True if deleted successfully, False otherwise
        """
        if not self.blob_service_client or not blob_url:
            return False

        try:
            # Extract container and blob name from URL
            # URL format: https://account.blob.core.windows.net/container/blob_path
            url_parts = blob_url.split("/")
            if len(url_parts) < 5:
                logger.warning(f"Invalid blob URL format: {blob_url}")
                return False

            container_name = url_parts[3]
            blob_path = "/".join(url_parts[4:])

            blob_client = self.blob_service_client.get_blob_client(
                container=container_name, blob=blob_path
            )

            blob_client.delete_blob(delete_snapshots="include")

            logger.info(f"Successfully deleted file: {blob_path}")
            return True

        except AzureError as e:
            logger.error(f"Azure Storage error deleting file {blob_url}: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting file {blob_url}: {str(e)}")
            return False

    def update_file(
        self,
        current_url: str | None,
        new_base64_data: str,
        file_type: FileType,
        path_params: dict[str, str],
        filename: str | None = None,
    ) -> str:
        """
        Update a file by deleting the old one and uploading a new one.

        Args:
            current_url: Current file URL (will be deleted)
            new_base64_data: New base64 encoded file data
            file_type: FileType enum specifying storage configuration
            path_params: Parameters for path template
            filename: Optional custom filename

        Returns:
            Public URL of the new uploaded file
        """
        # Upload new file first
        new_url = self.upload_file(new_base64_data, file_type, path_params, filename)

        # Delete old file if it exists
        if current_url:
            self.delete_file(current_url)

        return new_url

    def get_file_info(self, blob_url: str) -> dict[str, Any] | None:
        """
        Get file information from Azure Blob Storage.

        Args:
            blob_url: Full URL of the blob

        Returns:
            Dictionary with file info or None if not found
        """
        if not self.blob_service_client or not blob_url:
            return None

        try:
            # Extract container and blob name from URL
            url_parts = blob_url.split("/")
            if len(url_parts) < 5:
                return None

            container_name = url_parts[3]
            blob_path = "/".join(url_parts[4:])

            blob_client = self.blob_service_client.get_blob_client(
                container=container_name, blob=blob_path
            )

            properties = blob_client.get_blob_properties()

            return {
                "name": blob_path.split("/")[-1],
                "size": properties.size,
                "content_type": properties.content_settings.content_type,
                "last_modified": properties.last_modified,
                "url": blob_url,
            }

        except AzureError as e:
            logger.error(f"Error getting file info for {blob_url}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting file info for {blob_url}: {str(e)}")
            return None


# Convenience functions for common operations
def upload_profile_picture(user_id: str, base64_image: str) -> str:
    """Upload a user profile picture."""
    service = AzureStorageService()
    return service.upload_file(
        base64_image, FileType.PROFILE_PICTURE, {"user_id": user_id}
    )


def update_profile_picture(
    user_id: str, current_url: str | None, base64_image: str
) -> str:
    """Update a user profile picture."""
    service = AzureStorageService()
    return service.update_file(
        current_url, base64_image, FileType.PROFILE_PICTURE, {"user_id": user_id}
    )


def delete_profile_picture(blob_url: str) -> bool:
    """Delete a user profile picture."""
    service = AzureStorageService()
    return service.delete_file(blob_url)
