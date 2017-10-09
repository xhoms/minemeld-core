import logging

__all__ = ['get']


LOG = logging.getLogger(__name__)


def _load_schemas(sdirectory):
    import os.path
    import yaml
    import ujson as json

    try:
        with open(os.path.join(sdirectory, 'nodes.yml')) as f:
            nodes = yaml.safe_load(f)

    except:
        LOG.exception('Error loading nodes.yml from {}'.format(sdirectory))
        return []

    if not isinstance(nodes, list):
        LOG.error('Invalid nodes.yml format in {}'.format(sdirectory))
        return []

    for node in nodes:
        id_ = node.get('id', None)
        if id_ is None:
            LOG.error('No id in node schema {!r}'.format(node))
            continue

        config_schema = node.get('config_schema', None)
        if config_schema is None:
            LOG.info('No config schema for node schema {!r}'.format(node))
            continue

        try:
            with open(os.path.join(sdirectory, os.path.basename(config_schema))) as f:
                node['config_schema'] = json.load(f)
            if not isinstance(node['config_schema'], dict):
                LOG.error('Wrong schema format in node schema {!r}'.format(node))

        except:
            LOG.exception('Error loading config schema for node schema {!r}'.format(node))
            node.pop('config_schema', None)

    return nodes


def _add_lreferences(path, schema, dgraph):
    LOG.debug('lreference for {!r}'.format(path))
    for key, value in schema.iteritems():
        if key == '$ref' and value.startswith('#'):
            LOG.debug('found {!r} -> {!r}'.format(
                value,
                '#/{}'.format('/'.join(path))
            ))
            dgraph.add_edge(
                value,
                '#/{}'.format('/'.join(path))
            )
            return

        if not isinstance(value, dict):
            continue

        path.append(key)
        _add_lreferences(
            path=path,
            schema=value,
            dgraph=dgraph
        )
        path.pop()


def _get_element(ref, schema):
    path = ref.split('/')
    path.pop(0)

    co = schema
    while True:
        component = path.pop(0)

        if component not in co:
            raise RuntimeError('Ref {} not found'.format(ref))

        co = co[component]

        if len(path) == 0:
            return co


def _ldereference_config_schema(node):
    import networkx

    schema = node['config_schema']

    dep_graph = networkx.DiGraph()

    _add_lreferences(
        path=[],
        schema=schema,
        dgraph=dep_graph
    )

    for src_ref in networkx.topological_sort(dep_graph):
        src = _get_element(src_ref, schema)
        for dst_ref in dep_graph.neighbors(src_ref):
            LOG.debug('dst {!r}'.format(dst_ref))
            dst = _get_element(dst_ref, schema)
            dst.clear()
            dst.update(src)


def _interpolate_config_schema(nodes):
    import networkx

    inheritance_graph = networkx.DiGraph()

    for nodeid, node in nodes.iteritems():
        if 'config_schema' not in node:
            continue

        cs = node['config_schema']
        if '$extends' not in cs:
            continue

        if 'type' not in cs or cs['type'] != 'object':
            raise RuntimeError('$extends requires type object in {} config schema'.format(nodeid))

        extends = cs['$extends']
        if 'base' not in extends:
            raise RuntimeError('$extends requires a base object in {} config schema'.format(nodeid))
        base = extends['base']
        if '$ref' not in base:
            continue

        inheritance_graph.add_edge(base['$ref'][:-1], nodeid)

    for nodeid in networkx.topological_sort(inheritance_graph):
        node = nodes[nodeid]
        LOG.debug(node)
        cs = node['config_schema']

        if not '$extends' in cs:
            continue

        base = cs['$extends']['base']
        if '$ref' in base:
            baseid = base['$ref'][:-1]
            base = nodes[baseid]['config_schema']

        new_config_schema = {}
        new_config_schema.update(base)
        new_config_schema.update(cs)
        new_config_schema.pop('$extends')
        new_config_schema['properties'] = {}
        new_config_schema['properties'].update(base.get('properties', {}))
        new_config_schema['properties'].update(cs.get('properties', {}))

        node['config_schema'] = new_config_schema


def get(directory=None):
    import os.path

    nodes = {}

    if directory is None:
        directory = os.path.dirname(__file__)
    schema_directories = [directory]

    # load the node metadata with the config schemas
    for sdirectory in schema_directories:
        LOG.debug('Loading schemas from {}'.format(sdirectory))
        for node in _load_schemas(sdirectory):
            nodes[node['id']] = node

    # dereference local $refs
    for nodeid, node in nodes.iteritems():
        if 'config_schema' in node:
            try:
                _ldereference_config_schema(node)

            except:
                LOG.exception('Exception analyzing config schema for {}'.format(nodeid))
                node.pop('config_schema')
                continue

    # interpolate $extends
    try:
        _interpolate_config_schema(nodes)
    except:
        LOG.exception('Error interpolating config schemas')
        return []

    return nodes.values()
