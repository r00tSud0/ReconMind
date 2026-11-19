"""Build the MORVAIN-X0 animation maps from the approved portrait.

Build tool only, not part of the app and not installed by install.sh:
    python3 -m venv /tmp/rigenv && /tmp/rigenv/bin/pip install rembg onnxruntime opencv-python-headless pillow numpy
    /tmp/rigenv/bin/python build_rig.py MORVAIN-X0_SELECTED_CHARACTER.png reconmind/web/static/img/morvain-x0.png reconmind/web/static/img/morvain

The app animates the approved portrait itself (morvain-x0.png) as one surface
that bends (a mesh warp), so nothing is redrawn and nothing can come apart.
These maps tell the warp and the lights what is where:

  morvain-off.webp      the portrait with every red light on the robot turned off
  morvain-masks.png     R eyes, G head lights, B body lights, A the robot's outline
  morvain-weights.png   R how much each pixel follows the head, G the breath,
                        B how strongly it shimmers when lights flicker (unused: 0)

The robot is separated from its background with rembg (two models, merged).
"""
import json
import sys

import cv2
import numpy as np
from PIL import Image

SRC, PORTRAIT, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
W, H = 640, 800
EYES = [(0.30, 0.46, 0.265, 0.345), (0.555, 0.715, 0.265, 0.345)]  # x0, x1, y0, y1
NECK_TOP, SHOULDERS = 0.56, 0.70      # the head's pull fades from full to none between these


def robot_alpha(path):
    from rembg import new_session, remove
    full = Image.open(path).convert("RGB")
    masks = []
    for model in ("isnet-general-use", "u2net"):
        m = remove(full, session=new_session(model), only_mask=True)
        masks.append(np.asarray(m.convert("L").resize((W, H), Image.LANCZOS)).astype(np.float32) / 255)
    return np.clip((np.maximum(*masks) - 0.08) / 0.84, 0, 1)


portrait = Image.open(PORTRAIT).convert("RGB")
assert portrait.size == (W, H), "the app portrait must be 640x800"
rgb = np.asarray(portrait).astype(np.float32) / 255
alpha = robot_alpha(SRC)
r, g, b = rgb[..., 0], rgb[..., 1], rgb[..., 2]
ys = np.repeat((np.arange(H) / H)[:, None], W, 1).astype(np.float32)

# ---- the robot's red lights --------------------------------------------------
redness = np.clip(r - np.maximum(g, b), 0, 1)
lamp = np.clip((redness - 0.04) / 0.16, 0, 1)
lum = 0.30 * r + 0.59 * g + 0.11 * b
lamp = np.maximum(lamp, np.clip((lum - 0.42) / 0.2, 0, 1) * ((r - b) > 0.04))  # white hot centres
lamp *= (alpha > 0.2)
lamp = cv2.GaussianBlur(cv2.dilate(lamp, np.ones((3, 3), np.uint8)), (0, 0), 0.7)

off_val = np.clip(lum * 0.22, 0, 0.11)
off_rgb = np.stack([off_val * 0.92, off_val * 0.95, off_val], -1)
off = rgb * (1 - lamp[..., None]) + off_rgb * lamp[..., None]
Image.fromarray((np.clip(off, 0, 1) * 255).astype(np.uint8)).save(OUT + "/morvain-off.webp", quality=92, method=6)

eye_box = np.zeros((H, W), np.float32)
for x0, x1, y0, y1 in EYES:
    eye_box[int(y0 * H):int(y1 * H), int(x0 * W):int(x1 * W)] = 1
eye_box = cv2.GaussianBlur(eye_box, (0, 0), 3)
on_head = ys < 0.64
eyes = lamp * eye_box * on_head
head_lights = lamp * (1 - eye_box) * on_head
body_lights = lamp * (1 - on_head)
masks = np.dstack([eyes, head_lights, body_lights, alpha])
Image.fromarray((np.clip(masks, 0, 1) * 255).astype(np.uint8), "RGBA").save(OUT + "/morvain-masks.png", optimize=True)

# ---- how each pixel moves ----------------------------------------------------
# Head: full above the neck, easing to nothing at the shoulders, and spread a
# little past the outline so the air next to the head bends with it instead
# of tearing. Breath: the whole robot, strongest across the chest and shoulders.
def smoothstep(e0, e1, x):
    t = np.clip((x - e0) / (e1 - e0), 0, 1)
    return t * t * (3 - 2 * t)


xs = np.repeat((np.arange(W) / W)[None, :], H, 0).astype(np.float32)
neck_column = 1 - smoothstep(0.15, 0.24, np.abs(xs - 0.5))   # the neck, not the shoulders
head = alpha * (1 - smoothstep(NECK_TOP, SHOULDERS, ys)) * neck_column
head = cv2.GaussianBlur(head, (0, 0), 14)
head = np.maximum(head, alpha * (ys < NECK_TOP))
head = cv2.GaussianBlur(np.clip(head, 0, 1), (0, 0), 6)
breath = cv2.GaussianBlur(alpha, (0, 0), 18) * (0.35 + 0.65 * smoothstep(0.45, 0.80, ys))
breath = np.clip(breath / max(breath.max(), 1e-6), 0, 1)
weights = np.dstack([head, breath, np.zeros_like(head)])
Image.fromarray((np.clip(weights, 0, 1) * 255).astype(np.uint8), "RGB").save(OUT + "/morvain-weights.png", optimize=True)

print(json.dumps({"pivot": [0.5, 0.64], "size": [W, H]}))
