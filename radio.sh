#/bin/bash
rtl_fm -f $1 -M wbfm -s 1.15m -r 48000 -g 12 - | aplay -r 48000 -f S16_LE -t raw
