#
# ovirt-hosted-engine-ha -- ovirt hosted engine high availability
# Copyright (C) 2015 Red Hat, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#

from ..env import config
from ..env import config_constants as const
from ..env import constants
from ..env import path as env_path
from ovirt_hosted_engine_ha.lib import exceptions as ex
from ovirt_hosted_engine_ha.lib import util
import logging
import os
import re
import subprocess
import uuid

from . import log_filter

from vdsm.client import ServerError


logger = logging.getLogger(__name__)


class StorageServer(object):

    def __init__(self):
        self._log = logging.getLogger("%s.StorageServer" % __name__)
        self._log.addFilter(log_filter.get_intermittent_filter())
        self._config = config.Config(logger=self._log)
        self._domain_type = self._config.get(config.ENGINE, const.DOMAIN_TYPE)
        self._spUUID = self._config.get(config.ENGINE, const.SP_UUID)
        self._sdUUID = self._config.get(config.ENGINE, const.SD_UUID)
        self._storage = self._config.get(config.ENGINE, const.STORAGE)
        self._connectionUUID = self._config.get(
            config.ENGINE,
            const.CONNECTIONUUID
        )

        self._iqn = self._config.get(config.ENGINE, const.ISCSI_IQN)
        self._portal = self._config.get(config.ENGINE, const.ISCSI_PORTAL)
        self._user = self._config.get(config.ENGINE, const.ISCSI_USER)
        self._password = self._config.get(config.ENGINE, const.ISCSI_PASSWORD)
        self._port = self._config.get(config.ENGINE, const.ISCSI_PORT)
        self._mnt_options = None
        try:
            self._mnt_options = self._config.get(
                config.ENGINE,
                const.MNT_OPTIONS
            )
        except (KeyError, ValueError):
            pass
        self._nfs_version = None
        try:
            self._nfs_version = self._config.get(
                config.ENGINE,
                const.NFS_VERSION
            )
        except (KeyError, ValueError):
            pass
        self._iscsi_paths_blacklist = []
        try:
            iscsi_paths_blacklist_str = self._config.get(
                config.ENGINE,
                const.ISCSI_MPATHS_BLACKLIST
            )
            if iscsi_paths_blacklist_str is not None:
                for t in iscsi_paths_blacklist_str.strip().split(','):
                    iface_portal = t.split('<>')
                    self._iscsi_paths_blacklist.append(
                        (iface_portal[0], iface_portal[1])
                    )
        except (KeyError, ValueError):
            pass

    def _get_conlist_nfs_gluster(self):
        conDict = {
            'connection': self._storage,
            'user': 'kvm',
            'id': self._connectionUUID,
        }
        storageType = None
        if self._domain_type == constants.DOMAIN_TYPE_NFS:
            storageType = constants.STORAGE_TYPE_NFS
            if not self._nfs_version:
                conDict['protocol_version'] = 'auto'
            else:
                conDict['protocol_version'] = self._nfs_version.replace(
                    'v', ''
                ).replace(
                    '_', '.'
                )
        elif self._domain_type == constants.DOMAIN_TYPE_NFS3:
            storageType = constants.STORAGE_TYPE_NFS
            conDict['protocol_version'] = '3'
        elif self._domain_type == constants.DOMAIN_TYPE_NFS4:
            storageType = constants.STORAGE_TYPE_NFS
            conDict['protocol_version'] = '4'
        elif self._domain_type == constants.DOMAIN_TYPE_POSIXFS:
             storageType = constants.STORAGE_TYPE_POSIXFS
             conDict['vfs_type'] = 'ceph'
        elif self._domain_type == constants.DOMAIN_TYPE_GLUSTERFS:
            storageType = constants.STORAGE_TYPE_GLUSTERFS
            conDict['vfs_type'] = 'glusterfs'
        conList = [conDict]
        return conList, storageType

    def _fix_filebased_connection_path(self):
        path = os.path.normpath(self._storage)
        if path != self._storage:
            self._log.warning(
                (
                    "Fixing path syntax: "
                    "replacing '{original}' with '{fixed}'"
                ).format(
                    original=self._storage,
                    fixed=path,
                )
            )
        return path

    def _validate_pre_connected_path(self, cli, path):
        """
        On 3.5 we allow the user to deploy on 'server:/path/' allowing a
        trailing '/' and in that case VDSM simply mounts on a different path
        with a trailing '_'. Now, since the engine is going to re-mount it
        without the trailing '/', we have also to canonize that path but,
        in this way, we are going to mount twice if that NFS storage server
        has been already mounted on the wrong path by a previous run of
        old code. This method, if the hosted-engine storage domain is already
        available, checks what we expect against the actual mount path and,
        if they differ, raises
        hosted_engine.DuplicateStorageConnectionException
        See rhbz#1300749
        :param cli:  a vdsm.client instance
        :param path: the path (without the trailing '/') to be validated
                     against already connected storage server
        :raise       hosted_engine.DuplicateStorageConnectionException on error
                     to prevent connecting twice the hosted-engine storage
                     server
        """
        try:
            cli.StorageDomain.getInfo(storagedomainID=self._sdUUID)
        except ServerError:
            self._log.debug(
                'Storage domain {sd} is not available'.format(sd=self._sdUUID)
            )
            return

        # verifying only if the storage domain is already connected
        canonical_path = env_path.canonize_file_path(
            self._domain_type,
            path,
            self._sdUUID,
        )
        effective_path = env_path.get_domain_path(self._config)
        if effective_path != canonical_path:
            msg = (
                "The hosted-engine storage domain is already "
                "mounted on '{effective_path}' with a path that is "
                "not supported anymore: the right path should be "
                "'{canonical_path}'."
            ).format(
                canonical_path=canonical_path,
                effective_path=effective_path,
            )
            self._log.error(msg)
            raise ex.DuplicateStorageConnectionException(msg)

    def _get_iscsi_ifaces(self):
        self._log.debug("Detecting iSCSI interface")
        _RESERVED_INTERFACES = ("default", "iser")
        iscsi_bond_ifaces = []

        command = subprocess.Popen(
            [
                'sudo',
                'iscsiadm',
                '-m',
                'iface'
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        output = command.communicate()
        stdout = output[0].decode()
        stderr = output[1].decode()
        rc = command.wait()
        self._log.debug('rc:\n' + str(rc))
        self._log.debug('stdout:\n' + str(stdout))
        self._log.debug('stderr:\n' + str(stderr))
        if rc == 0:
            # <iscsi_ifacename> <transport_name>,<hwaddress>,<ipaddress>,\
            # <net_ifacename>,<initiatorname>
            iscsiadm_re = re.compile(
                "^(?P<iscsi_ifacename>.*) "
                "tcp,"
                "(?P<hwaddress>.*),"
                "(?P<ipaddress>.*),"
                "(?P<net_ifacename>.*),"
                "(?P<initiatorname>.*)$"
            )
            for line in stdout.splitlines():
                ifacematch = iscsiadm_re.match(line)
                if ifacematch is not None:
                    ifaceName = ifacematch.group('iscsi_ifacename')
                    netIfaceName = ifacematch.group('net_ifacename')
                    if (
                        ifaceName not in _RESERVED_INTERFACES and
                        netIfaceName != '<empty>'
                    ):
                        iscsi_bond_ifaces.append({
                            'ifaceName': ifaceName,
                            'netIfaceName': netIfaceName
                        })
        else:
            self._log.warning(
                'Failed fetching iSCSI interface list: {e}'.format(e=stderr)
            )

        if not iscsi_bond_ifaces:
            self._log.info(
                'Unable to get iSCSI multipath configuration, '
                'please check it from the engine'
            )
            iscsi_bond_ifaces.append({
                'ifaceName': None,
                'netIfaceName': None
            })
        self._log.debug(
            'iSCSI interfaces: {i}'.format(i=iscsi_bond_ifaces)
        )
        return iscsi_bond_ifaces

    def _get_conlist_iscsi(self):
        storageType = constants.STORAGE_TYPE_ISCSI
        conList = []
        _iscsi_bond_ifaces = self._get_iscsi_ifaces()
        # When we originally added support for iscsi multipath,
        # we allowed multiple IP addresses and ports, but only
        # a single iqn. The IP addresses and ports were "zipped"
        # together - first IP + first port, then second IP + second
        # port, etc., and not a full cartesian product.
        # For backwards compatibility, I separate two cases:
        # 1. Only a single iqn is provided (meaning, no commas).
        # In this case, old behavior is retained.
        # 2. Multiple iqns are provided, separated by commas.
        # Then, we zip also the iqns - again, not a full cartesian product,
        # and also expect command-separated, multiple tpgt, user, password
        # values, and zip them.
        # Please note that on multiple-iqn, this means we also split the
        # password on commas - this means that the individual passwords
        # can't include commas, or the split will get them wrong.
        if ',' in self._iqn:
            ip_port_iqn_list = [
                {
                    'ip': x[0],
                    'port': x[1],
                    'iqn': x[2],
                    'tpgt': x[3],
                    'user': x[4],
                    'password': x[5],
                } for x in zip(
                    self._storage.split(','),
                    self._port.split(','),
                    self._iqn.split(','),
                    self._portal.split(','),
                    self._user.split(','),
                    self._password.split(','),
                )
            ]
            for i in _iscsi_bond_ifaces:
                for x in ip_port_iqn_list:
                    con = {
                        'connection': x['ip'],
                        'iqn': x['iqn'],
                        'tpgt': x['tpgt'],
                        'user': x['user'],
                        'password': x['password'],
                        'id': str(uuid.uuid4()),
                        'port': x['port'],
                    }
                    if (
                        i['netIfaceName'] is not None and
                        i['ifaceName'] is not None
                    ):
                        con['netIfaceName'] = i['netIfaceName']
                        con['ifaceName'] = i['ifaceName']
                        if (
                            con['ifaceName'], con['connection']
                        ) in self._iscsi_paths_blacklist:
                            continue
                    conList.append(con)
        else:
            # Just a single iqn provided
            ip_port_list = [
                {'ip': x[0], 'port': x[1]} for x in zip(
                    self._storage.split(','),
                    self._port.split(',')
                )
            ]
            for i in _iscsi_bond_ifaces:
                for x in ip_port_list:
                    con = {
                        'connection': x['ip'],
                        'iqn': self._iqn,
                        'tpgt': self._portal,
                        'user': self._user,
                        'password': self._password,
                        'id': str(uuid.uuid4()),
                        'port': x['port'],
                    }
                    if (
                        i['netIfaceName'] is not None and
                        i['ifaceName'] is not None
                    ):
                        con['netIfaceName'] = i['netIfaceName']
                        con['ifaceName'] = i['ifaceName']
                        if (
                            con['ifaceName'], con['connection']
                        ) in self._iscsi_paths_blacklist:
                            continue
                    conList.append(con)
        return conList, storageType

    def _get_conlist_fc(self):
        storageType = constants.STORAGE_TYPE_FC
        conList = []
        return conList, storageType

    def _get_conlist(self, cli, normalize_path):
        """
        helper method to get conList parameter for connectStorageServer and
        disconnectStorageServer
        :param cli a vscli instance
        :param normalize_path True to force path normalization
        """
        conList = None
        storageType = None
        if self._domain_type in (
                constants.DOMAIN_TYPE_NFS,
                constants.DOMAIN_TYPE_NFS3,
                constants.DOMAIN_TYPE_NFS4,
                constants.DOMAIN_TYPE_GLUSTERFS,
        ):
            conList, storageType = self._get_conlist_nfs_gluster()
            if normalize_path:
                path = self._fix_filebased_connection_path()
                conList[0]['connection'] = path
                self._validate_pre_connected_path(cli, path)
        elif self._domain_type == constants.DOMAIN_TYPE_POSIXFS:
            conList, storageType = self._get_conlist_nfs_gluster()
            if normalize_path:
                path = self._fix_filebased_connection_path()
                conList[0]['connection'] = path
                self._validate_pre_connected_path(cli, path)
            target_path = env_path.get_mount_target(self._config)
            if target_path is None:
                conList[0]['connection'] = self._storage
            else:
                conList[0]['connection'] = env_path.get_mount_target(self._config)[0]
        elif self._domain_type == constants.DOMAIN_TYPE_ISCSI:
            conList, storageType = self._get_conlist_iscsi()
        elif self._domain_type == constants.DOMAIN_TYPE_FC:
            conList, storageType = self._get_conlist_fc()
        else:
            self._log.error(
                "Storage type not supported: '%s'" % self._domain_type
            )
            raise RuntimeError(
                "Storage type not supported: '%s'" % self._domain_type
            )
        if self._mnt_options and conList:
            conList[0]['mnt_options'] = self._mnt_options
        return conList, storageType

    def validate_storage_server(self):
        """
        Checks the hosted-engine storage domain availability
        :return: True if available, False otherwise
        """
        self._log.info("Validating storage server")
        cli = util.connect_vdsm_json_rpc(
            logger=self._log,
            timeout=constants.VDSCLI_SSL_TIMEOUT
        )
        try:
            status = cli.Host.getStorageRepoStats(domains=[self._sdUUID])
        except ServerError as e:
            self._log.error(str(e))
            return False

        try:
            valid = status[self._sdUUID]['valid']
            delay = float(status[self._sdUUID]['delay'])
            if valid and delay <= constants.LOOP_DELAY:
                return True
        except Exception:
            self._log.warn("Hosted-engine storage domain is in invalid state")
        return False

    def connect_storage_server(self, timeout=constants.VDSCLI_SSL_TIMEOUT):
        """
        Connect the hosted-engine domain storage server
        """
        self._log.info("Connecting storage server")
        cli = util.connect_vdsm_json_rpc(
            logger=self._log,
            timeout=timeout,
        )
        conList, storageType = self._get_conlist(cli, normalize_path=True)
        if conList:
            self._log.info("Connecting storage server")
            try:
                connections = cli.StoragePool.connectStorageServer(
                    storagepoolID=self._spUUID,
                    domainType=storageType,
                    connectionParams=conList,
                )
                self._log.debug(connections)
            except ServerError as e:
                raise RuntimeError(
                    'Connection to storage server failed: %s' %
                    str(e)
                )

            connected = False
            failed_paths = []
            for con in connections:
                if con['status'] == 0:
                    connected = True
                else:
                    if len(connections) > 1:
                        con_details = {}
                        for ce in conList:
                            if con['id'] == ce['id']:
                                con_details = ce
                        self._log.warning(
                            (
                                'A connection path to the storage server is '
                                'not active, details: {con_details}'
                            ).format(
                                con_details=con_details,
                            )
                        )
                        failed_paths.append(con_details)
            if not connected:
                raise RuntimeError(
                    'Connection to storage server failed'
                )
            if len(
                failed_paths
            ) > 1 and storageType == constants.STORAGE_TYPE_ISCSI:
                bl_example = ','.join([
                    fp['ifaceName'] + '<>' + fp['connection']
                    for fp in failed_paths
                    if 'ifaceName' in fp and 'connection' in fp
                ])
                if bl_example:
                    self._log.warning((
                        'Many paths of your iSCSI multipath configurations '
                        'are failing, if it\'s by design you can blacklist '
                        'them setting "{k}={v}" in the hosted-engine '
                        'configuration.'
                    ).format(
                        k=const.ISCSI_MPATHS_BLACKLIST,
                        v=bl_example,
                    ))

        self._log.info("Refreshing the storage domain")
        # calling getStorageDomainStats has the side effect of
        # causing a Storage Domain refresh including
        # all its tree under /rhev/data-center/...
        try:
            cli.StorageDomain.getStats(storagedomainID=self._sdUUID)
        except ServerError as e:
            self._log.debug("Error refreshing storage domain: %s", str(e))

    def disconnect_storage_server(self, timeout=constants.VDSCLI_SSL_TIMEOUT):
        """
        Disconnect the hosted-engine domain storage server
        """
        self._log.info("Disconnecting storage server")
        cli = util.connect_vdsm_json_rpc(
            logger=self._log,
            timeout=timeout,
        )
        # normalize_path=False since we want to be sure we really disconnect
        # from where we were connected also if its path was wrong
        conList, storageType = self._get_conlist(cli, normalize_path=False)
        if conList:
            try:
                status = cli.StoragePool.disconnectStorageServer(
                    storagepoolID=self._spUUID,
                    domainType=storageType,
                    connectionParams=conList,
                )
                self._log.debug(status)
            except ServerError as e:
                raise RuntimeError(
                    (
                        'Disconnection to storage server failed, unable '
                        'to recover: {message} - Please try rebooting the '
                        'host to reach a consistent status'
                    ).format(
                        message=str(e)
                    )
                )
