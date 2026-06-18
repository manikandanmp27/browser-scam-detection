import base64
import os

# A 1x1 transparent PNG base64 string
placeholder_base64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
img_data = base64.b64decode(placeholder_base64)

os.makedirs("frontend/public/icons", exist_ok=True)

for size in [16, 48, 128]:
    path = f"frontend/public/icons/icon{size}.png"
    with open(path, "wb") as f:
        f.write(img_data)
    print(f"Created placeholder icon: {path}")
