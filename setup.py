"""常规 CPython extension 构建；包元数据和 src 布局仍由 pyproject.toml 定义。"""
import json
import os
import sysconfig

from setuptools import Extension, setup

flags = ' '.join(filter(None, (sysconfig.get_config_var('CFLAGS'),
                              os.environ.get('CFLAGS'), '-std=c11')))
setup(ext_modules=[Extension(
    'merkle_commitment._sha3_c',
    sources=['src/merkle_commitment/_sha3_c.c'],
    extra_compile_args=['-std=c11'],
    define_macros=[('MTC_BUILD_FLAGS', json.dumps(flags))],
)])
