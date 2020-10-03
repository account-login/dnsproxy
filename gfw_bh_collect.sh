
for v in `seq 1000000`; do
    dig @114.114.114.114 g$v.facebook.com +timeout=1
done |grep --line-buffered -w A |grep --line-buffered -Po '\d+\.\d+\.\d+\.\d+'
