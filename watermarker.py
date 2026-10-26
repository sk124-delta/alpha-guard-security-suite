import cv2
import numpy as np
from imwatermark import WatermarkEncoder
from PIL import Image

def embed_alpha_guard_watermark(image_path, output_path, watermark_payload="AlphaGuard-Protected"):
    """
    Sanitizes image metadata and embeds a frequency-domain steganographic watermark 
    to protect e-commerce product catalogs against image scraping and cloning.
    """
    # 1. Load image using OpenCV
    img = cv2.imread(image_path)
    if img is None:
        raise ValueError(f"Could not load image at {image_path}")

    # 2. Embed steganographic watermark in the frequency domain (DCT)
    encoder = WatermarkEncoder()
    encoder.set_watermark('bytes', watermark_payload.encode('utf-8'))
    
    # imwatermark operates on BGR/RGB numpy arrays
    watermarked_img = encoder.encode(img, 'dwtDct') # Discrete Wavelet Transform + Discrete Cosine Transform

    # 3. Save the protected asset
    cv2.imwrite(output_path, watermarked_img)
    print(f"Success: Protected asset saved to {output_path}")

# Example execution test
if __name__ == "__main__":
    # Test with a local product sample image
    # embed_alpha_guard_watermark("sample_product.jpg", "protected_product.jpg")
    pass