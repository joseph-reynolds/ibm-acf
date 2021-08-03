#!/usr/bin/bash
libloc=$(whereis $1 | cut -d' ' -f3 -s)
wordcount=$(echo $libloc | wc -c)
if [[ $wordcount -gt 1 ]] && [[ $(echo $libpam | grep -q "so") -eq 0 ]]
then
    echo $libloc
else
    exit 1
fi
