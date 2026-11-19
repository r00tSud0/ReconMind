"""
Render MORVAIN-X0's animation loops ahead of time.

The app plays these loops as ordinary animated images, so MORVAIN-X0 moves the
same way in every browser and window (Firefox, Chrome, Edge, the desktop
window, a VM), with no WebGL and no graphics card needed. This script does the
mesh warp once, here, from the same portrait and maps:

    off        lights black, breathing, the head drifting a little
    working    red lights, steam puffing from behind the shoulders every few
               seconds, breathing, the head looking across the target
    answering  yellow lights, sparks bursting from behind the shoulders,
               breathing, the head tipped as it thinks

Every motion repeats exactly once per loop (LOOP_SECONDS), so each loop plays
without a seam. The robot is warped as one surface (head, neck and chest
together) and laid over a clean copy of the background with the robot painted
out. That background is saved once as its own still image, under the loops,
so it never moves or shimmers.

    python docs/design/morvain-rig/render_loops.py reconmind/web/static/img

Needs numpy, opencv-python (or opencv-python-headless) and Pillow with WebP.
Writes img/morvain/loops/background.webp (the still background), the loops
that play over it ({off,working,answering}.webp) and a still first frame of
each ({name}-still.webp).
"""

import math
import os
import sys

import cv2
import numpy as np
from PIL import Image

W, H = 640, 800                 # portrait pixels
OUT_W, OUT_H = 420, 525         # loop size (shown at about 280 x 350 CSS pixels)
FPS = 20
QUALITY = 75
LOOP_SECONDS = 8.0
FRAMES = int(FPS * LOOP_SECONDS)
PIVOT = (320.0, 512.0)          # base of the neck
YELLOW = np.array([1.0, 0.82, 0.28], np.float32)
TAU = 2 * math.pi


def periodic(t, seed, amp=1.0):
    """Smooth organic drift that repeats exactly once per loop."""
    u = TAU * t / LOOP_SECONDS
    return amp * (0.5 * math.sin(u + seed) + 0.3 * math.sin(2 * u + seed * 2.1)
                  + 0.2 * math.sin(3 * u + seed * 3.7))


def breath_curve(t, per_loop):
    """A breath rises a little faster than it falls; per_loop breaths per loop."""
    ph = TAU * per_loop * t / LOOP_SECONDS
    return (math.sin(ph) + 0.25 * math.sin(2 * ph - 0.6)) / 1.2


STATES = {
    # light: eyes, head lights, body lights. breath in portrait pixels at the top of a breath.
    "off": dict(light=(0, 0, 0), glow=0.0, tint=0.0, breath=5.0, breaths=2, head="rest",
                steam=False, sparks=False),
    "working": dict(light=(1, 1, 1), glow=0.22, tint=0.0, breath=6.0, breaths=3, head="scan",
                    steam=True, sparks=False),
    "answering": dict(light=(1, 1, 0.95), glow=0.25, tint=1.0, breath=5.5, breaths=2,
                      head="think", steam=False, sparks=True),
}


def head_pose(t, mode):
    u = TAU * t / LOOP_SECONDS
    if mode == "scan":       # looks across the target and back, easing at each end
        s = math.sin(u)
        return 0.022 * s + periodic(t, 3, 0.004), 6.0 * s, -0.8 + 0.8 * abs(s), -0.004 * abs(s)
    if mode == "think":      # tips the head as it weighs things up
        return (-0.028 + periodic(t, 1, 0.007), -3.0 + periodic(t, 2, 1.2), 1.5,
                0.004 + periodic(t, 5, 0.002))
    return periodic(t, 7, 0.008), periodic(t, 8, 2.0), periodic(t, 9, 1.2), 0.0


def load(path, mode="RGB"):
    return np.asarray(Image.open(path).convert(mode).resize((W, H), Image.LANCZOS),
                      np.float32) / 255.0


def clean_plate(off, alpha):
    """The background with the robot painted out, so revealed edges show background."""
    hole = (alpha > 0.04).astype(np.uint8)
    hole = cv2.dilate(hole, np.ones((5, 5), np.uint8), iterations=5)
    img = (off * 255).astype(np.uint8)
    plate = cv2.inpaint(img, hole * 255, 9, cv2.INPAINT_TELEA)
    return plate.astype(np.float32) / 255.0


def value_noise_tex(size=256, seed=7):
    rng = np.random.default_rng(seed)
    return rng.random((size, size)).astype(np.float32)


def noise(tex, x, y):
    n = tex.shape[0]
    xi, yi = np.floor(x), np.floor(y)
    fx, fy = x - xi, y - yi
    fx, fy = fx * fx * (3 - 2 * fx), fy * fy * (3 - 2 * fy)
    x0, y0 = xi.astype(int) % n, yi.astype(int) % n
    x1, y1 = (x0 + 1) % n, (y0 + 1) % n
    a, b = tex[y0, x0], tex[y0, x1]
    c, d = tex[y1, x0], tex[y1, x1]
    return (a + (b - a) * fx) * (1 - fy) + (c + (d - c) * fx) * fy


def fbm(tex, x, y):
    v, a = 0.0, 0.5
    for _ in range(4):
        v = v + a * noise(tex, x, y)
        x, y, a = x * 2.03, y * 2.03, a * 0.5
    return v


STEAM_SECONDS = 3.2
PUFFS = (0.0, 2.7, 5.4)          # puff starts; each lasts STEAM_SECONDS, wrapping round the loop
SW, SH = W // 2, H // 2          # steam is soft, so it is worked out at half size


def steam_density(t, tex):
    ys, xs = np.mgrid[0:SH, 0:SW].astype(np.float32)
    px, py = xs * 2 + 1, ys * 2 + 1
    total = np.zeros((SH, SW), np.float32)
    for k, start in enumerate(PUFFS):
        age = (t - start) % LOOP_SECONDS
        s = age / STEAM_SECONDS
        if s >= 1:
            continue
        dens = np.zeros_like(total)
        for side in (-1.0, 1.0):
            vx, vy = W * (0.5 + side * 0.34), H * 0.60
            rx, ry = (px - vx) / W, (vy - py) / W
            height = 0.08 + 0.66 * s
            width = 0.03 + 0.24 * np.maximum(ry, 0) + 0.05 * s
            shape = (np.exp(-(rx * rx) / (2 * width * width))
                     * np.clip((ry + 0.02) / 0.06, 0, 1)
                     * (1 - np.clip((ry - height * 0.55) / (height * 0.45), 0, 1)))
            n = fbm(tex, rx * 8 + side * 3.7 + k * 11.0, ry * 5 - age * 1.3 + k * 5.0)
            dens += shape * np.clip((n - 0.28) / 0.47, 0, 1)
        env = min(1.0, s / 0.12) * (1 - max(0.0, (s - 0.42) / 0.58))
        total += dens * env
    return cv2.resize(np.clip(total, 0, 1.6), (W, H), interpolation=cv2.INTER_LINEAR)


SPARKS = 28


def sparks_layer(t):
    layer = np.zeros((H, W, 3), np.float32)
    rng_hash = lambda a, b: (math.sin(a * 127.1 + b * 311.7) * 43758.5453) % 1.0
    for i in range(SPARKS):
        side = -1 if i % 2 == 0 else 1
        n_cycles = 6 + int(rng_hash(i, 3.1) * 5)            # cycles per loop: repeats exactly
        period = LOOP_SECONDS / n_cycles
        tt = t / period + rng_hash(i, 7.7)
        cyc = int(math.floor(tt)) % n_cycles
        life = tt - math.floor(tt)
        if rng_hash(i, cyc + 0.5) < 0.35:
            continue
        ox = W * (0.5 + side * (0.29 + 0.07 * rng_hash(cyc, i)))
        oy = H * (0.55 + 0.07 * rng_hash(i, cyc + 1))
        vx = side * (90 + 210 * rng_hash(cyc, i + 2))
        vy = -(170 + 280 * rng_hash(i + 5, cyc))
        age = life * period * 0.85
        x, y = ox + vx * age, oy + vy * age + 430 * age * age
        tx, ty = x - vx * 0.07, y - (vy + 860 * age) * 0.07
        fade = (1 - life) ** 1.5
        hot = np.array([1.0, 0.95 - 0.4 * life, 0.7 - 0.58 * life], np.float32) * fade
        p0, p1 = (int(tx * 4), int(ty * 4)), (int(x * 4), int(y * 4))
        glow = np.zeros((H, W), np.float32)
        cv2.line(glow, p0, p1, 0.35, 9, cv2.LINE_AA, shift=2)
        cv2.line(glow, p0, p1, 1.6, 3, cv2.LINE_AA, shift=2)
        layer += glow[..., None] * hot
    return cv2.GaussianBlur(layer, (0, 0), 1.2)


def render_frame(t, state, src):
    cfg = STATES[state]
    breath = cfg["breath"] * breath_curve(t, cfg["breaths"])
    rot, hx, hy, nod = head_pose(t, cfg["head"])

    wh, wb = src["wh"], src["wb"]
    X, Y = src["X"], src["Y"]
    dx = (X - W * 0.5) * 0.0012 * breath * wb
    dy = -breath * np.maximum(wb, wh * 0.9)
    qx, qy = X - PIVOT[0], Y - PIVOT[1]
    c, s = math.cos(rot), math.sin(rot)
    mx = c * qx - s * qy + PIVOT[0] + hx
    my = (s * qx + c * qy) * (1 + nod) + PIVOT[1] + hy
    dx += (mx - X) * wh
    dy += (my - Y) * wh
    map_x, map_y = (X - dx).astype(np.float32), (Y - dy).astype(np.float32)
    warp = lambda img: cv2.remap(img, map_x, map_y, cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE)
    lit, off, mask = warp(src["lit"]), warp(src["off"]), warp(src["mask"])

    u = TAU * t / LOOP_SECONDS
    light = list(cfg["light"])
    if state == "working":     # the body lights pulse as it works
        light[1] *= 0.85 + 0.15 * (0.5 + 0.5 * math.sin(4 * u))
        light[2] *= 0.8 + 0.2 * (0.5 + 0.5 * math.sin(4 * u + 1.3))
    if state == "answering":   # a quick restless flicker while it answers
        light = [v * (0.82 + 0.18 * (0.5 + 0.5 * math.sin(10 * u + i * 1.7))) for i, v in enumerate(light)]
    k = np.clip(mask[..., 0] * light[0] + mask[..., 1] * light[1] + mask[..., 2] * light[2], 0, 1)[..., None]
    diff = (lit - off) * k
    yellow = np.maximum(diff, 0).max(axis=2, keepdims=True) * YELLOW
    glow_light = diff * (1 - cfg["tint"]) + yellow * cfg["tint"]
    robot = off + glow_light * (1 + cfg["glow"])

    a = mask[..., 3:4]
    col = src["plate"] * (1 - a) + robot * a
    behind = 1 - 0.75 * a
    if cfg["steam"]:
        d = steam_density(t, src["tex"])[..., None]
        vapour = np.array([0.76, 0.76, 0.81], np.float32)
        amt = np.clip(d * behind * 1.15, 0, 0.8)
        col = col * (1 - amt) + vapour * amt
    if cfg["sparks"]:
        col = col + sparks_layer(t) * (1 - 0.85 * a)
    out = np.clip(col, 0, 1)
    out = cv2.resize(out, (OUT_W, OUT_H), interpolation=cv2.INTER_AREA)
    return (out * 255 + 0.5).astype(np.uint8)


def main(img_dir):
    rig = os.path.join(img_dir, "morvain")
    src = {"lit": load(os.path.join(img_dir, "morvain-x0.png")),
           "off": load(os.path.join(rig, "morvain-off.webp")),
           "mask": load(os.path.join(rig, "morvain-masks.png"), "RGBA")}
    weights = load(os.path.join(rig, "morvain-weights.png"), "RGBA")
    src["wh"], src["wb"] = weights[..., 0], weights[..., 1]
    src["Y"], src["X"] = np.mgrid[0:H, 0:W].astype(np.float32)
    src["plate"] = clean_plate(src["off"], src["mask"][..., 3])
    src["tex"] = value_noise_tex()
    out_dir = os.path.join(rig, "loops")
    os.makedirs(out_dir, exist_ok=True)
    # The still background is its own image, under the loops, so it never
    # shimmers or moves. Each loop frame keeps only the pixels that differ
    # from it (the robot, the steam, the sparks) and is clear everywhere else.
    plate = cv2.resize(src["plate"], (OUT_W, OUT_H), interpolation=cv2.INTER_AREA)
    plate8 = (plate * 255 + 0.5).astype(np.uint8)
    Image.fromarray(plate8).save(os.path.join(out_dir, "background.webp"), quality=90)
    near = np.ones((3, 3), np.uint8)
    for state in STATES:
        frames = []
        for f in range(FRAMES):
            rgb = render_frame(f / FPS, state, src)
            differs = (np.abs(rgb.astype(int) - plate8.astype(int)).max(axis=2) > 1).astype(np.uint8)
            alpha = cv2.dilate(differs, near) * 255
            frames.append(Image.fromarray(np.dstack([rgb, alpha]), "RGBA"))
        frames[0].convert("RGB").save(os.path.join(out_dir, state + "-still.webp"), quality=86)
        target = os.path.join(out_dir, state + ".webp")
        frames[0].save(target, save_all=True, append_images=frames[1:], duration=int(1000 / FPS),
                       loop=0, lossless=False, quality=QUALITY, alpha_quality=100, method=4,
                       kmin=FRAMES - 1, kmax=FRAMES)
        print("{s}: {n} frames, {k} KB".format(s=state, n=FRAMES, k=os.path.getsize(target) // 1024))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "reconmind/web/static/img")
