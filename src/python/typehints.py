#!/usr/bin/env python3

import datetime

from typing import (
    Dict,
    Union,
    Any,
    List,
    Optional,
    Callable,
    Awaitable,
    NewType,
    AsyncIterable,
    AsyncGenerator,
    AsyncContextManager,
    AsyncIterator,
    Tuple,
    Type,
    Set,
    TypeVar,
    TYPE_CHECKING,
    FrozenSet,
    Coroutine,
    Generator,
    Iterable,
    Iterator,
  )

GenericType1 = TypeVar('GenericType1')

#from collections.abc import Coroutine

from types import TracebackType

#from asyncio import CancelledError, Future, Task

NoneType = type(None)

JSONType = Union[str, int, float, bool, NoneType, Dict[str, Any], List[Any]]

JSONDictType = Dict[str, JSONType]

#Timestamp = NewType('Timestamp', datetime.datetime)  #: A UTC timestamp

#Futureable = Union[Future, Coroutine, Awaitable] #: an object that can be passed to ensure_future
