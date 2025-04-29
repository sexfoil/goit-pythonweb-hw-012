import pytest
from unittest.mock import patch, MagicMock
from app.services.cloudinary import upload_avatar


@patch("app.services.cloudinary.cloudinary.uploader.upload")
def test_upload_avatar_success(mock_upload):
    mock_response = {
        "secure_url": "https://res.cloudinary.com/demo/image/upload/v1/avatars/avatar.jpg"
    }
    mock_upload.return_value = mock_response

    result = upload_avatar("fake_path.jpg", "avatar")
    assert result == mock_response["secure_url"]
    mock_upload.assert_called_once_with(
        "fake_path.jpg",
        public_id="avatars/avatar",
        overwrite=True,
        folder="avatars",
        transformation=[{"width": 400, "height": 400, "crop": "fill"}],
    )


@patch("app.services.cloudinary.cloudinary.uploader.upload")
def test_upload_avatar_failure(mock_upload):
    mock_upload.side_effect = Exception("Upload failed")

    with pytest.raises(Exception) as exc_info:
        upload_avatar("invalid_path.jpg", "avatar")

    assert "Cloudinary upload error: Upload failed" in str(exc_info.value)
