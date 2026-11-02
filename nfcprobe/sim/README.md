# uisim: the nfcprobe UI on the PC

Renders every nfcprobe screen without a 3DS and checks the text layout. The real UI code
(`source/app.c`, the family screens, `ui.c`, and the card logic in `mfc.c`/`mfu.c`/`desfire.c`)
builds for the host against fake libctru / citro2d headers (`include/`). There's no NFC chip, so
the scenes in `scenes.c` put mock cards, dumps and job results straight into the screens' state
(`hook_*.c` include the UI files to reach their statics) and press keys through the real `appRun`
loop. A shot writes that frame's draw list. `render.py` draws it as a PNG and checks it.

    make run               # -> out/<shot>.png, out/report.txt
    python3 sheet.py out   # -> out/sheets/NN.png, 8 shots per sheet

Needs a 32-bit gcc (`-m32`: `long` is 32 bits, as on the ARM11), Pillow and NanumGothic
(`SIM_FONT=...` for another path).

Font: the 3DS system font isn't available here, so NanumGothic at 26.8 px stands in for it. On real
screenshots its text widths came within ~5% of the system font, with digits set to the system font's
17. `gen_metrics.py` writes the per-glyph advances to `metrics.h`. Within that margin the report
says "tight", not "ok":

- offscreen: text past the screen edge (any side)
- clipped: text partly or wholly under a rect drawn after it on the same layer (the footer, a panel)
- overflow: text running out of the panel, bar or box it starts on
- overlap: two visible texts on top of each other (dialogs and toasts are a layer of their own)
- tight: the same within the font error

Wrapped (`uiTextWrap`) and fitted (`uiFit`, headers, file names) text is measured on the console
with the real font, so "tight" on those is expected and fine.

The scene list is a single script (`script[]` in `scenes.c`): `KEYS(...)` presses buttons for one
frame, `SHOT("name")` captures a frame, `CALL(fn)` sets up state in between.
