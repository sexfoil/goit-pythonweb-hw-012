import os
from dotenv import load_dotenv
import cloudinary
import cloudinary.uploader


load_dotenv()

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
)


def upload_avatar(file_path: str, public_id: str):
    """
    Uploads a user avatar to Cloudinary with resizing and cropping applied.

    Args:
        file_path (str): Local path to the avatar image file.
        public_id (str): Unique identifier for the uploaded avatar.

    Returns:
        str: Secure URL of the uploaded avatar on Cloudinary.

    Raises:
        Exception: If the upload fails, raises an exception with an error message.
    """
    try:
        response = cloudinary.uploader.upload(
            file_path,
            public_id=f"avatars/{public_id}",
            overwrite=True,
            folder="avatars",
            transformation=[{"width": 400, "height": 400, "crop": "fill"}],
        )
        return response["secure_url"]
    except Exception as e:
        raise Exception(f"Cloudinary upload error: {str(e)}")
