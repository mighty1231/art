#! /bin/bash

DIR=$( pushd $(dirname $BASH_SOURCE[0]) >> /dev/null && pwd -P && popd >> /dev/null  )


    

find $DIR \
    -name "*.S" -print -o \
    -name "*.cc" -print -o \
    -name "*.[ch]" -print -o \
    -name "*.[ch]pp" -print  > ${DIR}/cscope.files

cscope -b -q -k

