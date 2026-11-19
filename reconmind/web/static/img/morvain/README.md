# MORVAIN-X0 animation maps

These files let `js/morvain_gl.js` bring the approved portrait
(`img/morvain-x0.png`) to life. The portrait is drawn as one surface that
bends (a mesh warp, the same idea as Live2D or a puppet warp), so the head,
neck and chest always move as one body. Nothing is cut out, and the
background is never animated.

| File | What it holds |
| --- | --- |
| `morvain-off.webp` | The portrait with every red light on the robot turned to dark metal (powered down). |
| `morvain-masks.png` | Where the lights are. Red: eyes. Green: head lights. Blue: body lights. Alpha: the robot's outline (steam is drawn behind it). |
| `morvain-weights.png` | How much each pixel moves. Red: follows the head (full on the head, easing out down the neck, none on the shoulders). Green: rises with the breath (chest and shoulders). |

All three are made from the portrait by
`docs/design/morvain-rig/build_rig.py`:

```
python docs/design/morvain-rig/build_rig.py SOURCE.png reconmind/web/static/img/morvain-x0.png reconmind/web/static/img/morvain
```

`SOURCE.png` is the full size original of the approved portrait. The script
needs `numpy`, `opencv-python`, `Pillow` and `rembg`. The head turns about a
pivot at the base of the neck (x 50%, y 64%).
