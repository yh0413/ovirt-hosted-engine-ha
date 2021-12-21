#!/bin/bash -xe
[[ -d exported-artifacts ]] \
|| mkdir -p exported-artifacts

[[ -d tmp.repos ]] \
|| mkdir -p tmp.repos


if [ -x /usr/bin/python3 ] ; then
export PYTHON=/usr/bin/python3
fi

./autogen.sh --system
make dist
yum-builddep ovirt-hosted-engine-ha.spec
rpmbuild \
    -D "_topdir $PWD/tmp.repos" \
    -ta ovirt-hosted-engine-ha-*.tar.gz

mv *.tar.gz exported-artifacts
find \
    "$PWD/tmp.repos" \
    -iname \*.rpm \
    -exec mv {} exported-artifacts/ \;
