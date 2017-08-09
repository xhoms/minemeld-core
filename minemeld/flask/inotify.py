# based on inotify_simple:
# Copyright (c) 2016, Chris Billington
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met: 
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided wi6h the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import sys
import collections
import struct
import ctypes
import enum
import re
from errno import EINTR
from termios import FIONREAD
from fcntl import ioctl

from gevent import sleep, spawn
from gevent.select import select

from .logger import LOG


# For Python 2, we work with bytestrings. If the user passes in a unicode
# string, it will be encoded with the filesystem encoding before use:
_fsencoding = sys.getfilesystemencoding()
_fsencode = lambda s: s.encode(_fsencoding)
# And we will not decode bytestrings in inotify events, we will simply
# give the user bytestrings back:
_fsdecode = lambda s: s
# In 32-bit Python < 3 the inotify constants don't fit in an IntEnum and
# will cause an OverflowError. Overwiting the IntEnum with a LongEnum
# fixes this problem.
class LongEnum(long, enum.Enum): pass
_EnumType = LongEnum

__all__ = ['flags', 'masks', 'parse_events', 'INotify', 'Event']

_libc = ctypes.cdll.LoadLibrary('libc.so.6')
_libc.__errno_location.restype = ctypes.POINTER(ctypes.c_int)

def _libc_call(function, *args):
    """Wrapper which raises errors and retries on EINTR."""
    while True:
        rc = function(*args)
        if rc == -1:
            errno = _libc.__errno_location().contents.value
            if errno  == EINTR:
                # retry
                continue
            else:
                raise OSError(errno, os.strerror(errno))
        return rc


class INotify(object):
    def __init__(self):
        """Object wrapper around ``inotify_init()`` which stores the inotify file
        descriptor. Raises an OSError on failure. :func:`~inotify_simple.INotify.close`
        should be called when no longer needed. Can be used as a context manager
        to ensure it is closed."""
        #: The inotify file descriptor returned by ``inotify_init()``. You are
        #: free to use it directly with ``os.read`` if you'd prefer not to call
        #: :func:`~inotify_simple.INotify.read` for some reason.
        self.fd = _libc_call(_libc.inotify_init)

    def add_watch(self, path, mask):
        """Wrapper around ``inotify_add_watch()``. Returns the watch
        descriptor or raises an OSError on failure.

        Args:
            path (py3 str or bytes, py2 unicode or str): The path to watch.
                If ``str`` in python3 or ``unicode`` in python2, will be encoded with
                the filesystem encoding before being passed to
                ``inotify_add_watch()``. Note that ``pathlib.Path`` objects are
                sufficiently stringlike to be passed to this method as-is.

            mask (int): The mask of events to watch for. Can be constructed by
                bitwise-ORing :class:`~inotify_simple.flags` together.

        Returns:
            int: watch descriptor"""
        if not isinstance(path, bytes):
            path = _fsencode(path)
        return _libc_call(_libc.inotify_add_watch, self.fd, path, mask)

    def rm_watch(self, wd):
        """Wrapper around ``inotify_rm_watch()``. Raises OSError on failure.

        Args:
            wd (int): The watch descriptor to remove"""
        _libc_call(_libc.inotify_rm_watch, self.fd, wd)

    def read(self, timeout=None, read_delay=None):
        """Read the inotify file descriptor and return the resulting list of
        :attr:`~inotify_simple.Event` namedtuples (wd, mask, cookie, name).

        Args:
            timeout (int): The time in milliseconds to wait for events if
                there are none. If `negative or `None``, block until there are
                events.

            read_delay (int): The time in milliseconds to wait after the first
                event arrives before reading the buffer. This allows further
                events to accumulate before reading, which allows the kernel
                to consolidate like events and can enhance performance when
                there are many similar events.

        Returns:
            list: list of :attr:`~inotify_simple.Event` namedtuples"""
        # Wait for the first event:
        pending, _, _ = select([self.fd], [], [], timeout=timeout)
        if not pending:
            # Timed out, no events
            return []
        if read_delay is not None:
            # Wait for more events to accumulate:
            sleep(read_delay/1000.0)
        # How much data is available to read?
        bytes_avail = ctypes.c_int()
        ioctl(self.fd, FIONREAD, bytes_avail)
        buffer_size = bytes_avail.value
        # Read and parse it:
        data = os.read(self.fd, buffer_size)
        events = parse_events(data)
        return events

    def close(self):
        """Close the inotify file descriptor"""
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


#: A ``namedtuple`` (wd, mask, cookie, name) for an inotify event.
#: ``namedtuple`` objects are very lightweight to instantiate and access, whilst
#: being human readable when printed, which is useful for debugging and
#: logging. For best performance, note that element access by index is about
#: four times faster than by name. Note: in Python 2, name is a bytestring,
#: not a unicode string. In Python 3 it is a string decoded with ``os.fsdecode()``.
Event = collections.namedtuple('Event', ['wd', 'mask', 'cookie', 'name'])

_EVENT_STRUCT_FORMAT = 'iIII'
_EVENT_STRUCT_SIZE = struct.calcsize(_EVENT_STRUCT_FORMAT)


def parse_events(data):
    """Parse data read from an inotify file descriptor into list of
    :attr:`~inotify_simple.Event` namedtuples (wd, mask, cookie, name). This
    function can be used if you have decided to call ``os.read()`` on the
    inotify file descriptor yourself, instead of calling
    :func:`~inotify_simple.INotify.read`.

    Args:
        data (bytes): A bytestring as read from an inotify file descriptor
    Returns:
        list: list of :attr:`~inotify_simple.Event` namedtuples"""
    events = []
    offset = 0
    buffer_size = len(data)
    while offset < buffer_size:
        wd, mask, cookie, namesize = struct.unpack_from(_EVENT_STRUCT_FORMAT, data, offset)
        offset += _EVENT_STRUCT_SIZE
        name = _fsdecode(ctypes.c_buffer(data[offset:offset + namesize], namesize).value)
        offset += namesize
        events.append(Event(wd, mask, cookie, name))
    return events


class flags(_EnumType):
    """Inotify flags as defined in ``inotify.h`` but with ``IN_`` prefix
    omitted. Includes a convenience method for extracting flags from a mask.
    """
    ACCESS = 0x00000001  #: File was accessed
    MODIFY = 0x00000002  #: File was modified
    ATTRIB = 0x00000004  #: Metadata changed
    CLOSE_WRITE = 0x00000008  #: Writable file was closed
    CLOSE_NOWRITE = 0x00000010  #: Unwritable file closed
    OPEN = 0x00000020  #: File was opened
    MOVED_FROM = 0x00000040  #: File was moved from X
    MOVED_TO  = 0x00000080  #: File was moved to Y
    CREATE = 0x00000100  #: Subfile was created
    DELETE = 0x00000200  #: Subfile was deleted
    DELETE_SELF = 0x00000400  #: Self was deleted
    MOVE_SELF = 0x00000800  #: Self was moved

    UNMOUNT = 0x00002000  #: Backing fs was unmounted
    Q_OVERFLOW = 0x00004000  #: Event queue overflowed
    IGNORED = 0x00008000  #: File was ignored

    ONLYDIR = 0x01000000  #: only watch the path if it is a directory
    DONT_FOLLOW = 0x02000000  #: don't follow a sym link
    EXCL_UNLINK = 0x04000000  #: exclude events on unlinked objects
    MASK_ADD = 0x20000000  #: add to the mask of an already existing watch
    ISDIR = 0x40000000  #: event occurred against dir
    ONESHOT = 0x80000000  #: only send event once

    @classmethod
    def from_mask(cls, mask):
        """Convenience method. Return a list of every flag in a mask."""
        return [flag for flag in cls.__members__.values() if flag & mask]


class masks(_EnumType):
    """Convenience masks as defined in ``inotify.h`` but with ``IN_`` prefix
    omitted."""
    #: helper event mask equal to ``flags.CLOSE_WRITE | flags.CLOSE_NOWRITE``
    CLOSE = (flags.CLOSE_WRITE | flags.CLOSE_NOWRITE)
    #: helper event mask equal to ``flags.MOVED_FROM | flags.MOVED_TO``
    MOVE = (flags.MOVED_FROM | flags.MOVED_TO)

    #: bitwise-OR of all the events that can be passed to
    #: :func:`~inotify_simple.INotify.add_watch`
    ALL_EVENTS  = (flags.ACCESS | flags.MODIFY | flags.ATTRIB | flags.CLOSE_WRITE |
                   flags.CLOSE_NOWRITE | flags.OPEN | flags.MOVED_FROM |
                   flags.MOVED_TO | flags.DELETE | flags.CREATE | flags.DELETE_SELF |
                   flags.MOVE_SELF)


class MonitoredPaths(object):
    def __init__(self):
        self._next_id = 0
        self.paths = collections.defaultdict(list)

    def add_listener(self, path, listener, args=None, match=None):
        if match is not None:
            match = re.compile(match)

        if args is None:
            args = []

        self.paths[path].append((self._next_id, listener, args, match))
        self._next_id += 1


def _monitor(paths):
    mask = flags.DELETE | flags.CLOSE_WRITE

    with INotify() as inotify:
        watchers = {}

        for path in paths.keys():
            watchers[inotify.add_watch(path, mask)] = path

        while True:
            tb_notified = {}
            for event in inotify.read(read_delay=1):
                path = watchers.get(event[0], None)

                if path is None:
                    LOG.error('Event for unkown watcher: {!r}'.format(event))
                    continue

                for listener in paths.get(path, []):
                    if listener[0] in tb_notified:
                        continue

                    if listener[3] is not None:
                        if listener[3].match(event[3]) is None:
                            continue

                    tb_notified[listener[0]] = listener

            for listener in tb_notified.values():
                listener[1](*listener[2])


def start_monitor(paths):
    spawn(_monitor, paths.paths)
