# Copyright (c) 2017-2018 Samsung Electronics Co., Ltd All Rights Reserved
#
# Contact: Lukasz Pawelczyk <l.pawelczyk@samsung.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License


class YacaError(Exception):
    """Base class for YACA exceptions."""
    pass


class InvalidParameterError(YacaError):
    """Invalid parameter exception"""
    def __init__(self, message):
        YacaError.__init__(self, message)
        self.message = message


class OutOfMemoryError(YacaError):
    """Out of memory exception"""
    def __init__(self, message):
        YacaError.__init__(self, message)
        self.message = message


class InternalError(YacaError):
    """Internal exception"""
    def __init__(self, message):
        YacaError.__init__(self, message)
        self.message = message


class InvalidPasswordError(YacaError):
    """Invalid password exception"""
    def __init__(self, message):
        YacaError.__init__(self, message)
        self.message = message
