#  Copyright 2015-2017 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from flask import jsonify

from .aaa import MMBlueprint

import minemeld.schemas

__all__ = ['BLUEPRINT']


BLUEPRINT = MMBlueprint('schema', __name__, url_prefix='')


@BLUEPRINT.route('/schema', read_write=False)
def get_schema():
    return jsonify(result=minemeld.schemas.get())
